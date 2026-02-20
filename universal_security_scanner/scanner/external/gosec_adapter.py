from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import extract_cwe, normalize_path, run_command, safe_json_loads, to_severity


def parse_gosec_output(data: dict, target_root: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    golang_errors = data.get("Golang errors") or {}
    if isinstance(golang_errors, dict):
        for pkg, pkg_errors in golang_errors.items():
            if not isinstance(pkg_errors, list):
                continue
            for entry in pkg_errors:
                if not isinstance(entry, dict):
                    continue
                message = str(entry.get("error") or "").strip()
                if message:
                    errors.append(f"{pkg}: {message}")

    for issue in data.get("Issues", []) or []:
        if not isinstance(issue, dict):
            continue
        rule_id = str(issue.get("rule_id") or "UNKNOWN")
        details = str(issue.get("details") or f"gosec rule {rule_id} triggered.")
        file_path = normalize_path(target_root, str(issue.get("file") or "unknown"))
        line_number = int(issue.get("line") or 1)
        cwe = extract_cwe([issue.get("cwe"), issue.get("details")]) or "CWE-20"

        findings.append(
            Finding(
                vulnerability_type="Go Security Anti-pattern",
                severity=to_severity(str(issue.get("severity") or "medium")),
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Insecure Go coding pattern may create exploitable behavior in runtime paths.",
                recommendation="Refactor flagged code using secure APIs and validate untrusted data flows.",
                reference="https://github.com/securego/gosec#available-rules",
                owasp_category="A03:2021 - Injection",
                description=details,
                rule_id=f"GOSEC-{rule_id}",
                cwe=cwe,
                evidence=str(issue.get("code") or details)[:240],
            )
        )

    return findings, errors


def _contains_go_files(target_root: Path) -> bool:
    for path in target_root.rglob("*.go"):
        if path.is_file():
            return True
    return False


def run_gosec_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "gosec",
) -> tuple[list[Finding], list[str]]:
    if not _contains_go_files(target_root):
        return [], []

    command = [binary, "-fmt=json", "./..."]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds, cwd=target_root)
    except FileNotFoundError:
        return [], ["gosec not found in PATH/toolchain. Install or bootstrap gosec for Go SAST coverage."]
    except Exception as exc:
        return [], [f"gosec execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"gosec returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["gosec produced non-JSON output."]

    return parse_gosec_output(payload, target_root)
