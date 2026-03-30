from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import extract_cwe, first_reference, normalize_path, run_command, safe_json_loads, to_severity


def _vuln_severity(vulnerability: dict[str, Any], groups: list[dict[str, Any]]) -> str:
    database = vulnerability.get("database_specific") if isinstance(vulnerability, dict) else None
    if isinstance(database, dict):
        severity = database.get("severity")
        if isinstance(severity, str) and severity.strip():
            return severity
    for group in groups:
        if not isinstance(group, dict):
            continue
        max_severity = str(group.get("max_severity") or "").strip()
        if max_severity:
            return max_severity
    return "medium"


def parse_osv_scanner_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        source_path = normalize_path(target_root, str(source.get("path") or "dependencies"))

        for package_item in result.get("packages", []) or []:
            if not isinstance(package_item, dict):
                continue

            package = package_item.get("package") or {}
            package_name = str(package.get("name") or "dependency")
            package_version = str(package.get("version") or "")
            vulnerabilities = package_item.get("vulnerabilities") or []
            groups = package_item.get("groups") or []
            if not isinstance(vulnerabilities, list):
                continue

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                vuln_id = str(vulnerability.get("id") or "UNKNOWN")
                aliases = vulnerability.get("aliases") or []
                references = vulnerability.get("references") or []
                reference_urls = []
                if isinstance(references, list):
                    for entry in references:
                        if not isinstance(entry, dict):
                            continue
                        url = entry.get("url")
                        if isinstance(url, str) and url.strip():
                            reference_urls.append(url.strip())

                reference = first_reference(reference_urls, f"https://osv.dev/vulnerability/{vuln_id}")
                cwe = extract_cwe(vulnerability.get("database_specific", {}).get("cwe_ids")) or extract_cwe(aliases) or "CWE-1104"

                findings.append(
                    Finding(
                        vulnerability_type="Dependency Vulnerability",
                        severity=to_severity(_vuln_severity(vulnerability, groups if isinstance(groups, list) else [])),
                        file_path=source_path,
                        line_number=1,
                        business_impact="Vulnerable dependency detected in project dependency graph.",
                        recommendation=f"Upgrade {package_name} to a fixed version and validate transitive dependencies.",
                        reference=reference,
                        owasp_category="A06:2021 - Vulnerable and Outdated Components",
                        description=str(
                            vulnerability.get("summary")
                            or vulnerability.get("details")
                            or f"{package_name} matched vulnerability {vuln_id}"
                        ),
                        rule_id=f"OSV-{vuln_id}",
                        cwe=cwe,
                        evidence=f"{package_name} {package_version}".strip(),
                    )
                )
    return findings


def run_osv_scanner_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "osv-scanner",
) -> tuple[list[Finding], list[str]]:
    with tempfile.NamedTemporaryFile(prefix="osv-scan-", suffix=".json", delete=False) as tmp_file:
        output_path = tmp_file.name
    command = [
        binary,
        "scan",
        "source",
        "--recursive",
        "--allow-no-lockfiles",
        "--verbosity",
        "error",
        "--format",
        "json",
        "--output",
        output_path,
        str(target_root),
    ]

    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["OSV-Scanner not found in PATH/toolchain. Install or bootstrap osv-scanner for dependency CVE mapping."]
    except Exception as exc:
        return [], [f"OSV-Scanner execution failed: {exc}"]

    raw_payload = ""
    try:
        payload_path = Path(output_path)
        if payload_path.exists():
            raw_payload = payload_path.read_text(encoding="utf-8", errors="ignore")
            payload_path.unlink(missing_ok=True)
    except Exception:
        raw_payload = ""

    if return_code not in {0, 1, 128}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"OSV-Scanner returned code {return_code}: {short_error}"]

    payload = safe_json_loads(raw_payload or stdout)
    if not isinstance(payload, dict):
        if return_code == 128:
            return [], []
        return [], ["OSV-Scanner produced non-JSON output."]

    return parse_osv_scanner_output(payload, target_root), []

