from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import extract_cwe, first_reference, normalize_path, run_command, safe_json_loads, to_severity


def parse_tfsec_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        if not isinstance(item, dict):
            continue

        rule_id = str(item.get("rule_id") or "UNKNOWN")
        long_id = str(item.get("long_id") or rule_id)
        title = str(item.get("rule_description") or item.get("description") or f"tfsec rule {rule_id}")
        impact = str(item.get("impact") or "Infrastructure misconfiguration may increase exploitability.")
        resolution = str(item.get("resolution") or "Apply secure IaC configuration and re-run checks.")
        links = item.get("links") or []
        reference = first_reference(links, f"https://aquasecurity.github.io/tfsec/latest/checks/{long_id}/")

        location = item.get("location") or {}
        file_path = normalize_path(target_root, str(location.get("filename") or "unknown"))
        line_number = int(location.get("start_line") or 1)

        findings.append(
            Finding(
                vulnerability_type="IaC Misconfiguration",
                severity=to_severity(str(item.get("severity") or "medium")),
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact=impact,
                recommendation=resolution,
                reference=reference,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=title,
                rule_id=f"TFSEC-{rule_id}",
                cwe=extract_cwe(links) or "CWE-16",
                evidence=str(item.get("description") or item.get("warning") or "")[:240] or None,
            )
        )

    return findings


def run_tfsec_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "tfsec",
) -> tuple[list[Finding], list[str]]:
    command = [
        binary,
        str(target_root),
        "--format",
        "json",
        "--no-color",
        "--soft-fail",
    ]

    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["tfsec not found in PATH/toolchain. Install or bootstrap tfsec for Terraform security checks."]
    except Exception as exc:
        return [], [f"tfsec execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"tfsec returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["tfsec produced non-JSON output."]

    return parse_tfsec_output(payload, target_root), []
