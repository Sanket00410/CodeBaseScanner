from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import extract_cwe, normalize_path, run_command, safe_json_loads, to_severity


def _discover_requirements_files(target_root: Path) -> list[Path]:
    matches: list[Path] = []
    for path in target_root.rglob("*"):
        if not path.is_file():
            continue
        lower = path.name.lower()
        if lower.startswith("requirements") and lower.endswith(".txt"):
            matches.append(path)
    return sorted(matches)


def _to_reference(vuln_id: str, aliases: list[str]) -> str:
    for alias in aliases:
        if alias.upper().startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{alias.upper()}"
    if vuln_id:
        return f"https://osv.dev/vulnerability/{vuln_id}"
    return "https://github.com/pypa/pip-audit"


def parse_pip_audit_output(data: dict, target_root: Path, source_path: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    dependencies = data.get("dependencies") or []
    if not isinstance(dependencies, list):
        return findings

    source = normalize_path(target_root, str(source_path)) if source_path else "requirements.txt"
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("name") or "dependency")
        version = str(dependency.get("version") or "")
        vulns = dependency.get("vulns") or []
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id") or "UNKNOWN")
            aliases = [str(item) for item in (vuln.get("aliases") or []) if isinstance(item, str)]
            fix_versions = [str(item) for item in (vuln.get("fix_versions") or []) if isinstance(item, str)]
            recommendation = (
                f"Upgrade {name} to a fixed version (e.g. {fix_versions[0]})." if fix_versions else f"Upgrade {name} and pin a non-vulnerable version."
            )

            findings.append(
                Finding(
                    vulnerability_type="Python Dependency Vulnerability",
                    severity=to_severity("high" if any(alias.startswith("CVE-") for alias in aliases) else "medium"),
                    file_path=source,
                    line_number=1,
                    business_impact="Known vulnerable Python package can expose exploitable application paths.",
                    recommendation=recommendation,
                    reference=_to_reference(vuln_id, aliases),
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=str(vuln.get("description") or f"{name} matched vulnerability {vuln_id}"),
                    rule_id=f"PIP-AUDIT-{vuln_id}",
                    cwe=extract_cwe([vuln.get("description"), *aliases]) or "CWE-1104",
                    evidence=f"{name} {version}".strip(),
                )
            )
    return findings


def run_pip_audit_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "pip-audit",
) -> tuple[list[Finding], list[str]]:
    requirement_files = _discover_requirements_files(target_root)
    findings: list[Finding] = []
    errors: list[str] = []

    if not requirement_files:
        command = [binary, str(target_root), "--format", "json"]
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            return [], ["pip-audit not found in PATH/toolchain. Install or bootstrap pip-audit for Python SCA coverage."]
        except Exception as exc:
            return [], [f"pip-audit execution failed: {exc}"]

        if return_code not in {0, 1}:
            short_error = " | ".join((stderr or "").strip().splitlines()[:3])
            return [], [f"pip-audit returned code {return_code}: {short_error}"]

        payload = safe_json_loads(stdout)
        if not isinstance(payload, dict):
            short_error = " | ".join((stderr or "").strip().splitlines()[:2])
            return [], [f"pip-audit produced non-JSON output. {short_error}".strip()]
        return parse_pip_audit_output(payload, target_root, None), []

    for requirement_file in requirement_files:
        command = [binary, "-r", str(requirement_file), "--format", "json"]
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            return [], ["pip-audit not found in PATH/toolchain. Install or bootstrap pip-audit for Python SCA coverage."]
        except Exception as exc:
            errors.append(f"{requirement_file.name}: {exc}")
            continue

        if return_code not in {0, 1}:
            short_error = " | ".join((stderr or "").strip().splitlines()[:3])
            errors.append(f"{requirement_file.name}: pip-audit returned code {return_code}: {short_error}")
            continue

        payload = safe_json_loads(stdout)
        if not isinstance(payload, dict):
            continue
        findings.extend(parse_pip_audit_output(payload, target_root, requirement_file))

    return findings, errors
