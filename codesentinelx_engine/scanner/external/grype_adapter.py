from __future__ import annotations

from pathlib import Path

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import extract_cwe, first_reference, normalize_path, run_command, safe_json_loads, to_severity


def parse_grype_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for match in data.get("matches", []) or []:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}

        vuln_id = str(vulnerability.get("id") or "UNKNOWN")
        severity = to_severity(str(vulnerability.get("severity") or "medium"))
        package_name = str(artifact.get("name") or "dependency")
        package_version = str(artifact.get("version") or "")

        locations = artifact.get("locations") or []
        raw_path = "dependencies"
        if isinstance(locations, list) and locations:
            first_location = locations[0] if isinstance(locations[0], dict) else {}
            raw_path = str(first_location.get("path") or raw_path)
        file_path = normalize_path(target_root, raw_path)

        reference = first_reference(vulnerability.get("urls"), f"https://nvd.nist.gov/vuln/detail/{vuln_id}")
        cwe = extract_cwe(vulnerability.get("cwes")) or "CWE-1104"
        fix = vulnerability.get("fix") or {}
        fix_versions = fix.get("versions") if isinstance(fix, dict) else []
        if isinstance(fix_versions, list) and fix_versions:
            recommendation = f"Upgrade {package_name} to a fixed version (e.g. {fix_versions[0]})."
        else:
            recommendation = f"Upgrade or replace vulnerable dependency {package_name} and validate transitive risk."

        findings.append(
            Finding(
                vulnerability_type="Dependency Vulnerability",
                severity=severity,
                file_path=file_path,
                line_number=1,
                business_impact="Known vulnerable package can expose exploitable CVEs in application supply chain.",
                recommendation=recommendation,
                reference=reference,
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                description=str(vulnerability.get("description") or f"{package_name} matched vulnerability {vuln_id}"),
                rule_id=f"GRYPE-{vuln_id}",
                cwe=cwe,
                evidence=f"{package_name} {package_version}".strip(),
            )
        )
    return findings


def run_grype_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "grype",
) -> tuple[list[Finding], list[str]]:
    command = [
        binary,
        f"dir:{target_root}",
        "-o",
        "json",
        "--quiet",
    ]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["Grype not found in PATH/toolchain. Install or bootstrap Grype for dependency vulnerability scanning."]
    except Exception as exc:
        return [], [f"Grype execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"Grype returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["Grype produced non-JSON output."]

    return parse_grype_output(payload, target_root), []

