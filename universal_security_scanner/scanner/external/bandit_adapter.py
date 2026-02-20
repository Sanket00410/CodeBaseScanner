from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import (
    extract_cwe,
    normalize_path,
    run_command,
    safe_json_loads,
    to_severity,
)


def parse_bandit_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        issue_text = str(item.get("issue_text") or "Bandit security issue")
        confidence = str(item.get("issue_confidence") or "MEDIUM")
        severity = to_severity(str(item.get("issue_severity") or "medium"))
        file_path = normalize_path(target_root, str(item.get("filename") or "unknown"))
        line_number = int(item.get("line_number") or 1)
        cwe = extract_cwe((item.get("issue_cwe") or {}).get("id")) or "CWE-20"
        test_id = str(item.get("test_id") or "UNKNOWN")

        findings.append(
            Finding(
                vulnerability_type="Python Security Anti-pattern",
                severity=severity,
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact=f"Bandit flagged a Python security issue with {confidence} confidence.",
                recommendation="Refactor to secure APIs and validate inputs around the flagged call path.",
                reference="https://bandit.readthedocs.io/en/latest/",
                owasp_category="A03:2021 - Injection",
                description=issue_text,
                rule_id=f"BANDIT-{test_id}",
                cwe=cwe,
                evidence=str(item.get("code") or issue_text)[:240],
            )
        )
    return findings


def run_bandit_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "bandit",
) -> tuple[list[Finding], list[str]]:
    binary_name = Path(binary).name.lower()
    if binary_name in {"python", "python.exe", "python3", "python3.exe"}:
        command = [binary, "-m", "bandit", "-r", str(target_root), "-f", "json", "-q"]
    else:
        command = [binary, "-r", str(target_root), "-f", "json", "-q"]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["Bandit not found in PATH."]
    except Exception as exc:
        return [], [f"Bandit execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join(stderr.strip().splitlines()[:2])
        return [], [f"Bandit returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["Bandit produced non-JSON output."]
    return parse_bandit_output(payload, target_root), []
