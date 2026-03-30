from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.models import Finding, Severity
from codesentinelx_engine.scanner.dependency_auth import build_dependency_inventory, build_dependency_usage_map


class NativeDependencyScanner:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.enabled = bool(config.use_native_dependency_analysis)
        self.ecosystems = {item.strip().lower() for item in config.native_dependency_ecosystems if item.strip()}
        self.max_findings = max(1, config.native_dependency_max_findings)

    def scan_project(self, root: Path) -> list[Finding]:
        if not self.enabled or not root.exists():
            return []

        findings: list[Finding] = []
        inventory = build_dependency_inventory(root)
        usage_map = build_dependency_usage_map(root)

        if "npm" in self.ecosystems:
            findings.extend(self._scan_npm(root, inventory, usage_map))
        if "python" in self.ecosystems:
            findings.extend(self._scan_python(root, inventory, usage_map))

        return findings[: self.max_findings]

    def _scan_npm(
        self,
        root: Path,
        inventory: dict[str, dict[str, object]],
        usage_map: dict[str, list[str]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for package_json in root.rglob("package.json"):
            if any(part in {"node_modules", ".git", "dist", "build", ".toolchain"} for part in package_json.parts):
                continue
            relative = self._relative(package_json, root)
            try:
                payload = json.loads(package_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            lock_candidates = [
                package_json.with_name("package-lock.json"),
                package_json.with_name("yarn.lock"),
                package_json.with_name("pnpm-lock.yaml"),
            ]
            lock_present = any(candidate.exists() for candidate in lock_candidates)
            if not lock_present:
                findings.append(
                    self._finding(
                        file_path=relative,
                        line_number=1,
                        vulnerability_type="Missing Dependency Lockfile",
                        severity=Severity.MEDIUM,
                        business_impact="Dependency resolution may drift between environments and reduce supply-chain reproducibility.",
                        recommendation="Commit a package-lock.json, yarn.lock, or pnpm-lock.yaml for every production package manifest.",
                        reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                        description="A JavaScript package manifest was found without a colocated lockfile.",
                        rule_id="NATIVE-DEP-NPM-LOCK-001",
                        cwe="CWE-1104",
                        evidence=relative,
                    )
                )

            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                deps = payload.get(section)
                if not isinstance(deps, dict):
                    continue
                for name, raw_spec in deps.items():
                    spec = str(raw_spec or "").strip()
                    if not spec:
                        continue
                    line_number = self._find_line_number(package_json, f'"{name}"')
                    evidence = f"{name}:{spec}"
                    usage_note = self._usage_note(name, usage_map)
                    if self._is_external_source_spec(spec):
                        findings.append(
                            self._finding(
                                file_path=relative,
                                line_number=line_number,
                                vulnerability_type="External Source Dependency",
                                severity=Severity.HIGH,
                                business_impact="Dependencies fetched from external sources reduce integrity guarantees and complicate provenance review.",
                                recommendation="Prefer registry-published immutable versions and verify provenance before allowing VCS/URL/file-based dependencies.",
                                reference="https://cwe.mitre.org/data/definitions/494.html",
                                description=f"Dependency {name} is sourced from a non-registry location. {usage_note}".strip(),
                                rule_id="NATIVE-DEP-NPM-SOURCE-001",
                                cwe="CWE-494",
                                evidence=evidence,
                            )
                        )
                    elif self._is_unpinned_npm_spec(spec):
                        findings.append(
                            self._finding(
                                file_path=relative,
                                line_number=line_number,
                                vulnerability_type="Unpinned Dependency Version",
                                severity=Severity.MEDIUM,
                                business_impact="Broad version ranges can introduce unreviewed package updates and make builds less reproducible.",
                                recommendation="Pin direct dependencies to reviewed versions and rely on lockfiles to control transitive updates.",
                                reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                                description=f"Dependency {name} uses a broad version selector `{spec}`. {usage_note}".strip(),
                                rule_id="NATIVE-DEP-NPM-PIN-001",
                                cwe="CWE-1104",
                                evidence=evidence,
                            )
                        )

                    normalized = re.sub(r"[-_.]+", "-", name.lower())
                    inventory_row = inventory.get(normalized, {})
                    has_lock = bool(inventory_row.get("lockfile_paths"))
                    if lock_present and not has_lock:
                        findings.append(
                            self._finding(
                                file_path=relative,
                                line_number=line_number,
                                vulnerability_type="Dependency Manifest/Lock Drift",
                                severity=Severity.MEDIUM,
                                business_impact="Declared dependencies missing from lockfiles can bypass review and create inconsistent deploys.",
                                recommendation="Refresh the lockfile and ensure every declared package is represented before release.",
                                reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                                description=f"Dependency {name} is declared in package.json but no matching lockfile entry was found. {usage_note}".strip(),
                                rule_id="NATIVE-DEP-NPM-DRIFT-001",
                                cwe="CWE-1104",
                                evidence=evidence,
                            )
                        )
        return findings

    def _scan_python(
        self,
        root: Path,
        inventory: dict[str, dict[str, object]],
        usage_map: dict[str, list[str]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for requirements_path in root.rglob("requirements*.txt"):
            if any(part in {".git", "dist", "build", ".toolchain", ".venv", "venv"} for part in requirements_path.parts):
                continue
            relative = self._relative(requirements_path, root)
            for line_number, raw_line in enumerate(
                requirements_path.read_text(encoding="utf-8", errors="ignore").splitlines(),
                start=1,
            ):
                line = raw_line.split("#", 1)[0].strip()
                if not line or line.startswith(("-r", "--")):
                    continue
                name, spec = self._split_python_dep(line)
                if not name:
                    continue
                evidence = f"{name}:{spec or line}"
                usage_note = self._usage_note(name, usage_map)
                if self._is_external_source_spec(line):
                    findings.append(
                        self._finding(
                            file_path=relative,
                            line_number=line_number,
                            vulnerability_type="External Source Dependency",
                            severity=Severity.HIGH,
                            business_impact="Dependencies pulled from VCS/URL sources reduce provenance guarantees and make incident response harder.",
                            recommendation="Use reviewed registry releases and pin exact versions instead of direct VCS/URL references.",
                            reference="https://cwe.mitre.org/data/definitions/494.html",
                            description=f"Dependency {name} is sourced from a non-index location. {usage_note}".strip(),
                            rule_id="NATIVE-DEP-PY-SOURCE-001",
                            cwe="CWE-494",
                            evidence=evidence,
                        )
                    )
                elif spec and not spec.startswith("=="):
                    findings.append(
                        self._finding(
                            file_path=relative,
                            line_number=line_number,
                            vulnerability_type="Unpinned Dependency Version",
                            severity=Severity.MEDIUM,
                            business_impact="Loose Python dependency ranges can drift between environments and weaken release reproducibility.",
                            recommendation="Pin direct production dependencies with exact versions and update them through reviewed change control.",
                            reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                            description=f"Dependency {name} uses a non-exact specifier `{spec}`. {usage_note}".strip(),
                            rule_id="NATIVE-DEP-PY-PIN-001",
                            cwe="CWE-1104",
                            evidence=evidence,
                        )
                    )

        for pyproject in root.rglob("pyproject.toml"):
            if any(part in {".git", "dist", "build", ".toolchain", ".venv", "venv"} for part in pyproject.parts):
                continue
            relative = self._relative(pyproject, root)
            if tomllib is None:
                continue
            try:
                payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except Exception:
                continue

            poetry_deps = (((payload.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
            project_deps = (payload.get("project") or {}).get("dependencies") or []
            uses_poetry = isinstance(poetry_deps, dict) and bool(poetry_deps)
            if uses_poetry and not pyproject.with_name("poetry.lock").exists():
                findings.append(
                    self._finding(
                        file_path=relative,
                        line_number=1,
                        vulnerability_type="Missing Dependency Lockfile",
                        severity=Severity.MEDIUM,
                        business_impact="Without poetry.lock, dependency resolution can differ between machines and releases.",
                        recommendation="Commit poetry.lock alongside pyproject.toml for every releasable service.",
                        reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                        description="A Poetry-managed pyproject.toml was found without a poetry.lock file.",
                        rule_id="NATIVE-DEP-PY-LOCK-001",
                        cwe="CWE-1104",
                        evidence=relative,
                    )
                )

            dep_items: list[tuple[str, str, int]] = []
            if isinstance(project_deps, list):
                for entry in project_deps:
                    name, spec = self._split_python_dep(str(entry))
                    if name:
                        dep_items.append((name, spec, self._find_line_number(pyproject, name)))
            if isinstance(poetry_deps, dict):
                for name, raw_spec in poetry_deps.items():
                    if name == "python":
                        continue
                    spec = raw_spec if isinstance(raw_spec, str) else json.dumps(raw_spec, sort_keys=True)
                    dep_items.append((name, str(spec), self._find_line_number(pyproject, name)))

            for name, spec, line_number in dep_items:
                evidence = f"{name}:{spec}"
                usage_note = self._usage_note(name, usage_map)
                if self._is_external_source_spec(spec):
                    findings.append(
                        self._finding(
                            file_path=relative,
                            line_number=line_number,
                            vulnerability_type="External Source Dependency",
                            severity=Severity.HIGH,
                            business_impact="Direct VCS/path dependencies weaken provenance guarantees and make incident response harder.",
                            recommendation="Prefer reviewed package index releases and immutable version pins for release builds.",
                            reference="https://cwe.mitre.org/data/definitions/494.html",
                            description=f"Dependency {name} uses an external/path source specifier. {usage_note}".strip(),
                            rule_id="NATIVE-DEP-PY-SOURCE-001",
                            cwe="CWE-494",
                            evidence=evidence,
                        )
                    )
                elif spec and not spec.startswith("=="):
                    findings.append(
                        self._finding(
                            file_path=relative,
                            line_number=line_number,
                            vulnerability_type="Unpinned Dependency Version",
                            severity=Severity.MEDIUM,
                            business_impact="Broad dependency ranges reduce build reproducibility and increase unexpected package drift.",
                            recommendation="Pin direct dependencies to reviewed versions and update them through explicit release review.",
                            reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                            description=f"Dependency {name} uses a non-exact specifier `{spec}`. {usage_note}".strip(),
                            rule_id="NATIVE-DEP-PY-PIN-001",
                            cwe="CWE-1104",
                            evidence=evidence,
                        )
                    )

        return findings

    def _usage_note(self, package_name: str, usage_map: dict[str, list[str]]) -> str:
        hits = usage_map.get(re.sub(r"[-_.]+", "-", package_name.lower()), [])
        if not hits:
            return "No direct source import evidence was found in scanned first-party code."
        return f"Direct import evidence found in {', '.join(hits[:3])}."

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            return path.name

    @staticmethod
    def _find_line_number(path: Path, token: str) -> int:
        try:
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                if token in line:
                    return number
        except OSError:
            return 1
        return 1

    @staticmethod
    def _split_python_dep(raw: str) -> tuple[str, str]:
        value = raw.strip().strip('"').strip("'")
        if not value:
            return "", ""
        if " @ " in value:
            name, _, spec = value.partition(" @ ")
            return name.strip(), spec.strip()
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[.*\])?\s*([<>=!~].+)?$", value)
        if not match:
            return value, ""
        return match.group(1), (match.group(2) or "").strip()

    @staticmethod
    def _is_unpinned_npm_spec(spec: str) -> bool:
        normalized = spec.strip().lower()
        if not normalized:
            return False
        if NativeDependencyScanner._is_external_source_spec(normalized):
            return False
        return (
            normalized in {"*", "latest"}
            or normalized.startswith(("^", "~", ">", "<"))
            or "||" in normalized
            or "x" in normalized
        )

    @staticmethod
    def _is_external_source_spec(spec: str) -> bool:
        normalized = spec.strip().lower()
        return normalized.startswith(
            (
                "git+",
                "github:",
                "file:",
                "link:",
                "workspace:",
                "http://",
                "https://",
                "ssh://",
                "git://",
            )
        ) or " @ " in normalized

    @staticmethod
    def _finding(
        *,
        file_path: str,
        line_number: int,
        vulnerability_type: str,
        severity: Severity,
        business_impact: str,
        recommendation: str,
        reference: str,
        description: str,
        rule_id: str,
        evidence: str,
        cwe: str | None,
    ) -> Finding:
        return Finding(
            vulnerability_type=vulnerability_type,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            business_impact=business_impact,
            recommendation=recommendation,
            reference=reference,
            owasp_category="A06:2021 - Vulnerable and Outdated Components",
            description=description,
            rule_id=rule_id,
            cwe=cwe,
            evidence=evidence,
            origin="native_dependency",
            provenance={
                "source": "native_dependency",
                "ecosystems": ["npm", "python"],
                "rule_id": rule_id,
            },
        )

