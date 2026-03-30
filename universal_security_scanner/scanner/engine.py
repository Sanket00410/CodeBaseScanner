from __future__ import annotations

import logging
import os
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from universal_security_scanner.config import ScannerConfig
from universal_security_scanner.models import Finding, SEVERITY_ORDER, ScanResult
from universal_security_scanner.plugins import load_builtin_language_plugins
from universal_security_scanner.scanner.controls import ExistingSecurityMeasuresAnalyzer
from universal_security_scanner.scanner.external import (
    discover_toolchain,
    external_tool_names,
    prepare_toolchain,
    run_external_tool,
    supported_runner_tools,
    tool_metadata,
)
from universal_security_scanner.scanner.file_discovery import discover_files
from universal_security_scanner.scanner.native_analysis import NativeCodeScanner
from universal_security_scanner.scanner.native_dependency_analysis import NativeDependencyScanner
from universal_security_scanner.scanner.role_scope import role_allows_tool, resolve_role_scope
from universal_security_scanner.scanner.quality_benchmark import evaluate_quality_benchmark
from universal_security_scanner.scanner.scan_cache import FileScanCache, content_sha256
from universal_security_scanner.scanner.scan_control import honor_pause_control
from universal_security_scanner.scanner.rules.registry import build_file_rules, build_project_rules

LOGGER = logging.getLogger(__name__)

ProgressCallback = Callable[[float, str, str | None, str | None], None]

ALWAYS_RELEVANT_TOOLS = {"semgrep", "gitleaks"}
TOOL_FILE_HINTS: dict[str, dict[str, set[str]]] = {
    "bandit": {"extensions": {".py"}, "files": {"requirements.txt", "pyproject.toml", "poetry.lock", "pipfile"}},
    "brakeman": {"extensions": {".rb", ".erb"}, "files": {"gemfile", "gemfile.lock"}},
    "checkov": {"extensions": {".tf", ".yaml", ".yml", ".json"}, "files": {"dockerfile", "docker-compose.yml"}},
    "clair": {"extensions": {".yaml", ".yml", ".json"}, "files": {"dockerfile", "containerfile"}},
    "codeql": {
        "extensions": {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".rb", ".cs", ".cpp", ".c", ".h"},
        "files": {"package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod", "cargo.toml", ".sln"},
    },
    "eslint-security": {"extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}, "files": {"package.json"}},
    "gosec": {"extensions": {".go"}, "files": {"go.mod", "go.sum"}},
    "govulncheck": {"extensions": {".go"}, "files": {"go.mod", "go.sum"}},
    "hadolint": {"extensions": set(), "files": {"dockerfile", "containerfile"}},
    "infer": {"extensions": {".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".java"}, "files": {"compile_commands.json"}},
    "tfsec": {"extensions": {".tf"}, "files": {"main.tf", "versions.tf"}},
    "grype": {
        "extensions": {".json", ".yaml", ".yml", ".lock"},
        "files": {"package-lock.json", "yarn.lock", "poetry.lock", "pipfile.lock", "go.sum", "cargo.lock"},
    },
    "osv-scanner": {
        "extensions": {".json", ".lock", ".mod"},
        "files": {"package-lock.json", "yarn.lock", "poetry.lock", "pipfile.lock", "go.mod", "cargo.lock"},
    },
}

_DEPENDENCY_TOOLS = {
    "grype",
    "osv-scanner",
    "govulncheck",
}

_DEEP_TOOLS = {"codeql"}

_DEPENDENCY_TOOL_PRIORITIES: dict[str, tuple[str, ...]] = {
    "python": ("osv-scanner", "grype"),
    "javascript": ("osv-scanner", "grype"),
    "go": ("govulncheck", "osv-scanner", "grype"),
    "java": ("osv-scanner", "grype"),
    "ruby": ("osv-scanner", "grype"),
    "php": ("osv-scanner", "grype"),
    "dotnet": ("osv-scanner", "grype"),
    "rust": ("osv-scanner", "grype"),
    "generic": ("osv-scanner", "grype"),
}


def _collect_target_signals(files: list[Path]) -> tuple[set[str], set[str]]:
    extensions: set[str] = set()
    filenames: set[str] = set()
    for item in files:
        extensions.add(item.suffix.lower())
        filenames.add(item.name.lower())
    return extensions, filenames


def _is_tool_relevant(tool_name: str, extensions: set[str], filenames: set[str]) -> bool:
    normalized = tool_name.strip().lower()
    if normalized in ALWAYS_RELEVANT_TOOLS:
        return True
    hints = TOOL_FILE_HINTS.get(normalized)
    if not hints:
        return True
    extension_hints = hints.get("extensions", set())
    file_hints = hints.get("files", set())
    if extension_hints and extensions.intersection(extension_hints):
        return True
    if file_hints and filenames.intersection(file_hints):
        return True
    if not extension_hints and not file_hints:
        return True
    return False


def _detect_dependency_ecosystems(extensions: set[str], filenames: set[str]) -> set[str]:
    ecosystems: set[str] = set()
    if filenames.intersection({"requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock"}):
        ecosystems.add("python")
    if filenames.intersection({"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}):
        ecosystems.add("javascript")
    if filenames.intersection({"go.mod", "go.sum"}):
        ecosystems.add("go")
    if filenames.intersection({"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}):
        ecosystems.add("java")
    if filenames.intersection({"gemfile", "gemfile.lock"}):
        ecosystems.add("ruby")
    if filenames.intersection({"composer.json", "composer.lock"}):
        ecosystems.add("php")
    if filenames.intersection({"cargo.toml", "cargo.lock"}):
        ecosystems.add("rust")
    if filenames.intersection({"packages.lock.json", "nuget.config"}) or ".csproj" in extensions or ".sln" in extensions:
        ecosystems.add("dotnet")
    return ecosystems


def _allow_dependency_corroboration(role: str, scan_preset: str) -> bool:
    if os.getenv("USS_DEPENDENCY_CORROBORATION", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    normalized_role = role.strip().lower()
    return normalized_role in {"admin", "administrator"} and scan_preset.strip().lower() == "deep"


def _select_primary_dependency_tools(
    dependency_tools: set[str],
    ecosystems: set[str],
) -> set[str]:
    if not dependency_tools:
        return set()
    selected: set[str] = set()
    resolved_ecosystems = ecosystems or {"generic"}
    for ecosystem in sorted(resolved_ecosystems):
        for candidate in _DEPENDENCY_TOOL_PRIORITIES.get(ecosystem, _DEPENDENCY_TOOL_PRIORITIES["generic"]):
            if candidate in dependency_tools:
                selected.add(candidate)
                break
    if not selected:
        for candidate in _DEPENDENCY_TOOL_PRIORITIES["generic"]:
            if candidate in dependency_tools:
                selected.add(candidate)
                break
    return selected


def _apply_tool_execution_strategy(
    selected_tools: list[str],
    *,
    extensions: set[str],
    filenames: set[str],
    role: str,
    scan_preset: str,
) -> tuple[list[str], dict[str, str]]:
    retained: list[str] = []
    skipped_reasons: dict[str, str] = {}
    allow_deep_tools = role.strip().lower() in {"admin", "administrator"} or scan_preset.strip().lower() == "deep"

    for tool_name in selected_tools:
        normalized = tool_name.strip().lower()
        if normalized in _DEEP_TOOLS and not allow_deep_tools:
            skipped_reasons[tool_name] = (
                "Skipped by execution policy: deep analyzer is restricted to Admin role or deep scan preset."
            )
            continue
        if not _is_tool_relevant(tool_name, extensions, filenames):
            skipped_reasons[tool_name] = (
                "Skipped for speed optimization: no relevant language/manifests detected for this analyzer."
            )
            continue
        retained.append(tool_name)

    dependency_candidates = {tool.strip().lower() for tool in retained if tool.strip().lower() in _DEPENDENCY_TOOLS}
    if dependency_candidates and not _allow_dependency_corroboration(role, scan_preset):
        ecosystems = _detect_dependency_ecosystems(extensions, filenames)
        primary = _select_primary_dependency_tools(dependency_candidates, ecosystems)
        if primary:
            ecosystem_label = ", ".join(sorted(ecosystems)) if ecosystems else "generic"
            filtered: list[str] = []
            for tool_name in retained:
                normalized = tool_name.strip().lower()
                if normalized in _DEPENDENCY_TOOLS and normalized not in primary:
                    skipped_reasons[tool_name] = (
                        "Skipped dependency overlap for cleaner output: "
                        f"primary scanner selected for {ecosystem_label} ecosystem(s)."
                    )
                    continue
                filtered.append(tool_name)
            retained = filtered

    return retained, skipped_reasons


class ScanEngine:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.role_scope = resolve_role_scope(config.scan_role)
        self.file_rules = build_file_rules()
        self.project_rules = build_project_rules()
        self.plugins = load_builtin_language_plugins()
        self.native_scanner = NativeCodeScanner(config)
        self.native_dependency_scanner = NativeDependencyScanner(config)

    def _normalize_finding(
        self,
        finding: Finding,
        *,
        target: Path,
        default_origin: str,
        provenance: dict[str, object] | None = None,
    ) -> Finding:
        normalized_path = finding.file_path
        try:
            normalized_path = str(Path(finding.file_path).resolve().relative_to(target))
        except Exception:
            pass
        merged_provenance = dict(finding.provenance or {})
        if provenance:
            merged_provenance.update(provenance)
        return Finding(
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            file_path=normalized_path,
            line_number=finding.line_number,
            business_impact=finding.business_impact,
            recommendation=finding.recommendation,
            reference=finding.reference,
            owasp_category=finding.owasp_category,
            description=finding.description,
            rule_id=finding.rule_id,
            cwe=finding.cwe,
            evidence=finding.evidence,
            origin=finding.origin or default_origin,
            provenance=merged_provenance,
        )

    def _scan_file_payload(
        self,
        *,
        target: Path,
        path: Path,
        control_analyzer: ExistingSecurityMeasuresAnalyzer,
        scan_cache: FileScanCache,
    ) -> dict[str, object]:
        relative_path = path.relative_to(target)
        relative_key = str(relative_path).replace("\\", "/")
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return {
                "relative_path": relative_key,
                "error": f"Unable to read {relative_key}: {exc}",
                "findings": [],
                "control_observations": {},
                "cached": False,
            }

        digest = content_sha256(content)
        cached = scan_cache.get(relative_key, digest)
        if cached is not None:
            cached_findings, cached_observations = cached
            return {
                "relative_path": relative_key,
                "error": None,
                "findings": cached_findings,
                "control_observations": cached_observations,
                "cached": True,
                "content_hash": digest,
            }

        findings: list[Finding] = []
        if self.native_scanner.enabled:
            try:
                findings.extend(self.native_scanner.scan_file(relative_path, content))
            except Exception as exc:  # pragma: no cover - defensive branch
                return {
                    "relative_path": relative_key,
                    "error": f"Native code analysis failed on {relative_key}: {exc}",
                    "findings": [],
                    "control_observations": {},
                    "cached": False,
                }
        for rule in self.file_rules:
            try:
                findings.extend(rule.scan_file(relative_path, content))
            except Exception as exc:  # pragma: no cover - defensive branch
                return {
                    "relative_path": relative_key,
                    "error": f"Rule {rule.metadata.rule_id} failed on {relative_key}: {exc}",
                    "findings": [],
                    "control_observations": {},
                    "cached": False,
                }
        for plugin in self.plugins:
            if plugin.supports(relative_path):
                try:
                    findings.extend(plugin.scan_file(relative_path, content))
                except Exception as exc:  # pragma: no cover - defensive branch
                    return {
                        "relative_path": relative_key,
                        "error": f"Plugin {plugin.metadata.plugin_id} failed on {relative_key}: {exc}",
                        "findings": [],
                        "control_observations": {},
                        "cached": False,
                    }

        control_observations = control_analyzer.collect_observations(relative_path, content)
        return {
            "relative_path": relative_key,
            "error": None,
            "findings": findings,
            "control_observations": control_observations,
            "cached": False,
            "content_hash": digest,
        }

    def _run_external_tool_payload(
        self,
        *,
        tool_name: str,
        target: Path,
        status: dict[str, object],
        file_extensions: set[str],
        file_names: set[str],
    ) -> dict[str, object]:
        if not bool(status.get("available", False)):
            return {
                "tool_name": tool_name,
                "status_payload": {
                    "execution": {
                        "attempted": False,
                        "status": "unavailable",
                        "duration_ms": 0,
                        "findings_count": 0,
                        "errors": [str(status.get("message") or "Tool unavailable for this scan.")],
                        "evidence": [],
                    }
                },
                "findings": [],
                "errors": [],
            }

        if not _is_tool_relevant(tool_name, file_extensions, file_names):
            return {
                "tool_name": tool_name,
                "status_payload": {
                    "message": "Skipped for speed optimization: no relevant files/manifests were detected for this target.",
                    "execution": {
                        "attempted": False,
                        "status": "skipped_irrelevant",
                        "duration_ms": 0,
                        "findings_count": 0,
                        "errors": [],
                        "evidence": [],
                    },
                },
                "findings": [],
                "errors": [],
            }

        tool_findings, tool_errors, tool_execution = run_external_tool(
            tool_name,
            target_root=target,
            config=self.config,
            command=str(status.get("command") or tool_name),
        )
        normalized = [
            self._normalize_finding(
                finding,
                target=target,
                default_origin="external_tool",
                provenance={"source": "external_tool", "tool_name": tool_name},
            )
            for finding in tool_findings
        ]
        return {
            "tool_name": tool_name,
            "status_payload": {"execution": tool_execution},
            "findings": normalized,
            "errors": [f"[{tool_name}] {error}" for error in tool_errors],
        }

    def scan(self, target_path: str | Path, progress_callback: ProgressCallback | None = None) -> ScanResult:
        target = Path(target_path).expanduser().resolve()
        if not target.exists() or not target.is_dir():
            raise FileNotFoundError(f"Target path does not exist or is not a directory: {target}")

        started_at = datetime.now(timezone.utc)
        files = discover_files(target, self.config)
        file_extensions, file_names = _collect_target_signals(files)
        findings: list[Finding] = []
        errors: list[str] = []
        seen: set[tuple[str, str, int, str | None]] = set()
        active_external_tools = [
            tool
            for tool in external_tool_names(self.config, target_mode="codebase")
            if role_allows_tool(self.role_scope.role, tool)
        ]
        catalog_tools = [
            tool
            for tool in external_tool_names(self.config, target_mode="codebase", include_catalog=True)
            if role_allows_tool(self.role_scope.role, tool)
        ]
        runner_supported = set(supported_runner_tools("codebase"))
        selected_runner_tools = [tool for tool in active_external_tools if tool in runner_supported]
        selected_runner_tools, tool_strategy_skips = _apply_tool_execution_strategy(
            selected_runner_tools,
            extensions=file_extensions,
            filenames=file_names,
            role=self.role_scope.role,
            scan_preset=self.config.scan_preset,
        )
        control_analyzer = ExistingSecurityMeasuresAnalyzer()
        scan_cache = FileScanCache.from_config(self.config)
        toolchain_status: dict[str, dict[str, object]] = {}
        findings_limit = self.config.max_findings

        def findings_limit_reached() -> bool:
            return findings_limit > 0 and len(findings) >= findings_limit

        def append_finding(candidate: Finding) -> None:
            dedupe_key = (
                candidate.rule_id,
                candidate.file_path,
                candidate.line_number,
                candidate.evidence,
            )
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)
            findings.append(candidate)

        toolchain_prepare_steps = 1 if active_external_tools or catalog_tools else 0
        project_rule_steps = len(self.project_rules) if self.config.use_project_rules else 0
        native_dependency_steps = 1 if self.native_dependency_scanner.enabled else 0
        total_steps = max(1, len(files) + project_rule_steps + len(selected_runner_tools) + toolchain_prepare_steps + native_dependency_steps)
        completed_steps = 0

        if progress_callback:
            progress_callback(0.0, "discovering", None, f"Discovered {len(files)} files")

        file_workers = max(1, int(self.config.file_scan_workers or 1))
        if file_workers == 1:
            for index, path in enumerate(files, start=1):
                relative_path = path.relative_to(target)
                progress = round(((completed_steps + 1) / total_steps) * 100.0, 2)
                honor_pause_control(
                    progress_callback=progress_callback,
                    progress=progress,
                    stage="scanning_files",
                    current_file=str(relative_path),
                )
                payload = self._scan_file_payload(
                    target=target,
                    path=path,
                    control_analyzer=control_analyzer,
                    scan_cache=scan_cache,
                )
                completed_steps += 1
                progress = round((completed_steps / total_steps) * 100.0, 2)
                if progress_callback:
                    cache_note = " (cache hit)" if payload.get("cached") else ""
                    progress_callback(
                        progress,
                        "scanning_files",
                        str(relative_path),
                        f"Scanned file {index}/{len(files)}{cache_note}",
                    )
                error = payload.get("error")
                if error:
                    LOGGER.warning(str(error))
                    errors.append(str(error))
                    continue
                control_observations = payload.get("control_observations") or {}
                if not payload.get("cached"):
                    scan_cache.put(
                        str(relative_path).replace("\\", "/"),
                        content_hash=str(payload.get("content_hash") or ""),
                        findings=list(payload.get("findings") or []),
                        control_observations=control_observations,
                    )
                control_analyzer.merge_observations(control_observations)
                for finding in payload.get("findings") or []:
                    append_finding(finding)
                if findings_limit_reached():
                    errors.append("Maximum findings limit reached; remaining file checks skipped.")
                    break
        else:
            file_iter = iter(enumerate(files, start=1))
            pending: dict[object, tuple[int, Path]] = {}
            with ThreadPoolExecutor(max_workers=file_workers) as executor:
                while len(pending) < file_workers:
                    try:
                        index, path = next(file_iter)
                    except StopIteration:
                        break
                    pending[
                        executor.submit(
                            self._scan_file_payload,
                            target=target,
                            path=path,
                            control_analyzer=control_analyzer,
                            scan_cache=scan_cache,
                        )
                    ] = (index, path.relative_to(target))

                while pending:
                    progress = round((completed_steps / total_steps) * 100.0, 2)
                    honor_pause_control(
                        progress_callback=progress_callback,
                        progress=progress,
                        stage="scanning_files",
                        current_file=str(next(iter(pending.values()))[1]) if pending else None,
                    )
                    done, _ = wait(tuple(pending), timeout=0.2, return_when=FIRST_COMPLETED)
                    if not done:
                        continue

                    for future in done:
                        index, relative_path = pending.pop(future)
                        completed_steps += 1
                        progress = round((completed_steps / total_steps) * 100.0, 2)
                        try:
                            payload = future.result()
                        except Exception as exc:  # pragma: no cover - defensive branch
                            LOGGER.exception("Parallel file scan failed for %s", relative_path)
                            errors.append(f"Parallel file scan failed on {relative_path}: {exc}")
                            payload = {"error": "parallel file failure", "findings": [], "control_observations": {}, "cached": False}
                        if progress_callback:
                            cache_note = " (cache hit)" if payload.get("cached") else ""
                            progress_callback(
                                progress,
                                "scanning_files",
                                str(relative_path),
                                f"Scanned file {index}/{len(files)}{cache_note}",
                            )
                        error = payload.get("error")
                        if error:
                            LOGGER.warning(str(error))
                            errors.append(str(error))
                        else:
                            control_observations = payload.get("control_observations") or {}
                            if not payload.get("cached"):
                                scan_cache.put(
                                    str(relative_path).replace("\\", "/"),
                                    content_hash=str(payload.get("content_hash") or ""),
                                    findings=list(payload.get("findings") or []),
                                    control_observations=control_observations,
                                )
                            control_analyzer.merge_observations(control_observations)
                            for finding in payload.get("findings") or []:
                                append_finding(finding)

                        if findings_limit_reached():
                            errors.append("Maximum findings limit reached; remaining file checks skipped.")
                            for pending_future in pending:
                                pending_future.cancel()
                            pending.clear()
                            break

                        try:
                            next_index, next_path = next(file_iter)
                        except StopIteration:
                            continue
                        pending[
                            executor.submit(
                                self._scan_file_payload,
                                target=target,
                                path=next_path,
                                control_analyzer=control_analyzer,
                                scan_cache=scan_cache,
                            )
                        ] = (next_index, next_path.relative_to(target))

                    if findings_limit_reached():
                        break

        if self.config.use_project_rules:
            for project_rule in self.project_rules:
                completed_steps += 1
                progress = round((completed_steps / total_steps) * 100.0, 2)
                honor_pause_control(
                    progress_callback=progress_callback,
                    progress=progress,
                    stage="scanning_dependencies",
                    current_file=str(target),
                )
                if progress_callback:
                    progress_callback(
                        progress,
                        "scanning_dependencies",
                        str(target),
                        f"Running {project_rule.metadata.rule_id}",
                    )

                try:
                    project_findings = project_rule.scan_project(target)
                except Exception as exc:  # pragma: no cover - defensive branch
                    error = f"Project rule {project_rule.metadata.rule_id} failed: {exc}"
                    LOGGER.exception(error)
                    errors.append(error)
                    continue

                for finding in project_findings:
                    append_finding(
                        self._normalize_finding(
                            finding,
                            target=target,
                            default_origin="project_rule",
                            provenance={"source": "project_rule"},
                        )
                    )
        elif progress_callback:
            progress_callback(
                round((completed_steps / total_steps) * 100.0, 2),
                "scanning_dependencies",
                str(target),
                "Project rules skipped for this role preset",
            )

        if self.native_dependency_scanner.enabled:
            completed_steps += 1
            progress = round((completed_steps / total_steps) * 100.0, 2)
            honor_pause_control(
                progress_callback=progress_callback,
                progress=progress,
                stage="scanning_native_dependencies",
                current_file=str(target),
            )
            if progress_callback:
                progress_callback(
                    progress,
                    "scanning_native_dependencies",
                    str(target),
                    "Running native dependency authenticity analysis",
                )
            try:
                native_dependency_findings = self.native_dependency_scanner.scan_project(target)
            except Exception as exc:  # pragma: no cover - defensive branch
                error = f"Native dependency analysis failed: {exc}"
                LOGGER.exception(error)
                errors.append(error)
                native_dependency_findings = []

            for finding in native_dependency_findings:
                append_finding(
                    self._normalize_finding(
                        finding,
                        target=target,
                        default_origin="native_dependency",
                        provenance={"source": "native_dependency"},
                    )
                )

        if active_external_tools or catalog_tools:
            completed_steps += 1
            progress = round((completed_steps / total_steps) * 100.0, 2)
            honor_pause_control(
                progress_callback=progress_callback,
                progress=progress,
                stage="preparing_toolchain",
                current_file=str(target),
            )
            if progress_callback:
                progress_callback(
                    progress,
                    "preparing_toolchain",
                    str(target),
                    "Preparing external scanning toolchain",
                )

            discovered_toolchain = discover_toolchain(self.config, catalog_tools, Path.cwd())
            selected_toolchain = prepare_toolchain(
                self.config,
                active_external_tools,
                Path.cwd(),
                allow_bootstrap=self.config.auto_bootstrap_tools,
            )

            merged_tools = sorted(set(catalog_tools) | set(active_external_tools))
            for tool_name in merged_tools:
                discovered_status = discovered_toolchain.get(tool_name)
                selected_status = selected_toolchain.get(tool_name)
                chosen_status = selected_status or discovered_status
                metadata = tool_metadata(tool_name)

                status_payload: dict[str, object]
                if chosen_status:
                    status_payload = chosen_status.to_dict()
                else:
                    status_payload = {
                        "name": tool_name,
                        "available": False,
                        "command": tool_name,
                        "source": "missing",
                        "message": "Tool was not evaluated for this scan profile.",
                    }
                status_payload.update(metadata)
                status_payload["selected"] = tool_name in active_external_tools
                status_payload["runner_available"] = tool_name in runner_supported

                if tool_name in tool_strategy_skips:
                    status_payload["message"] = tool_strategy_skips[tool_name]
                    status_payload["execution"] = {
                        "attempted": False,
                        "status": "skipped_strategy",
                        "duration_ms": 0,
                        "findings_count": 0,
                        "errors": [],
                        "evidence": [],
                    }

                if (
                    tool_name in active_external_tools
                    and tool_name in runner_supported
                    and selected_status
                    and not selected_status.available
                    and tool_name not in tool_strategy_skips
                ):
                    errors.append(f"[{tool_name}] {selected_status.message}")
                if tool_name in active_external_tools and tool_name not in runner_supported and tool_name not in tool_strategy_skips:
                    status_payload["message"] = (
                        "Tool discovered in catalog, but normalized finding ingestion is not implemented yet."
                    )

                toolchain_status[tool_name] = status_payload

        if findings_limit_reached():
            errors.append("Maximum findings limit reached; external checks skipped.")
        elif selected_runner_tools:
            external_workers = max(1, int(self.config.external_tool_workers or 1))
            with ThreadPoolExecutor(max_workers=external_workers) as executor:
                future_map = {
                    executor.submit(
                        self._run_external_tool_payload,
                        tool_name=tool_name,
                        target=target,
                        status=dict(toolchain_status.get(tool_name, {})),
                        file_extensions=file_extensions,
                        file_names=file_names,
                    ): tool_name
                    for tool_name in selected_runner_tools
                }
                while future_map:
                    progress = round((completed_steps / total_steps) * 100.0, 2)
                    honor_pause_control(
                        progress_callback=progress_callback,
                        progress=progress,
                        stage="scanning_external",
                        current_file=str(target),
                    )
                    done, _ = wait(tuple(future_map), timeout=0.2, return_when=FIRST_COMPLETED)
                    if not done:
                        continue
                    for future in done:
                        tool_name = future_map.pop(future)
                        completed_steps += 1
                        progress = round((completed_steps / total_steps) * 100.0, 2)
                        if progress_callback:
                            progress_callback(
                                progress,
                                "scanning_external",
                                str(target),
                                f"Completed external analyzer: {tool_name}",
                            )
                        try:
                            payload = future.result()
                        except Exception as exc:  # pragma: no cover - defensive branch
                            LOGGER.exception("Parallel external analyzer failed for %s", tool_name)
                            errors.append(f"[{tool_name}] Parallel external execution failed: {exc}")
                            payload = {"status_payload": {}, "findings": [], "errors": []}
                        status = toolchain_status.get(tool_name, {})
                        status.update(payload.get("status_payload") or {})
                        execution = status.get("execution") if isinstance(status.get("execution"), dict) else {}
                        exec_status = str(execution.get("status") or "").strip().lower()
                        exec_errors = [str(item) for item in execution.get("errors", []) if str(item).strip()]
                        if exec_status in {"failed", "partial_success"}:
                            status["message"] = (
                                exec_errors[0]
                                if exec_errors
                                else f"Analyzer execution {exec_status}."
                            )
                        elif exec_status in {"success", "skipped", "skipped_irrelevant", "skipped_strategy"} and status.get("message"):
                            # Keep bootstrap/discovery message for ready/successful states only.
                            pass
                        for error in payload.get("errors") or []:
                            errors.append(str(error))
                        for finding in payload.get("findings") or []:
                            append_finding(finding)

        findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.file_path, item.line_number))
        scan_cache.save()

        completed_at = datetime.now(timezone.utc)
        quality_benchmark = evaluate_quality_benchmark(
            [item.to_dict() for item in findings],
            benchmark_file=self.config.quality_benchmark_file,
            enabled=bool(self.config.quality_benchmark_enabled),
            min_precision=float(self.config.quality_benchmark_min_precision),
            min_recall=float(self.config.quality_benchmark_min_recall),
            min_f1=float(self.config.quality_benchmark_min_f1),
            strict_scope=bool(self.config.quality_benchmark_strict_scope),
        )
        if progress_callback:
            progress_callback(100.0, "completed", None, "Scan completed")

        return ScanResult(
            target_path=str(target),
            started_at=started_at,
            completed_at=completed_at,
            files_scanned=len(files),
            scan_role=self.role_scope.role,
            findings=findings,
            errors=errors,
            existing_security_measures=control_analyzer.finalize(total_files=len(files)),
            toolchain_status=toolchain_status,
            quality_benchmark=quality_benchmark,
        )
