from __future__ import annotations

import os
import tempfile
from pathlib import Path

from universal_security_scanner.models import Finding, Severity
from universal_security_scanner.scanner.external.common import normalize_path, run_command, safe_json_loads, to_severity


def parse_gitleaks_output(data: list[dict], target_root: Path) -> list[Finding]:
    findings: list[Finding] = []

    for leak in data:
        rule = str(leak.get("RuleID") or "UNKNOWN")
        description = str(leak.get("Description") or "Potential secret leaked in source code")
        file_path = normalize_path(target_root, str(leak.get("File") or "unknown"))
        line_number = int(leak.get("StartLine") or 1)
        match = str(leak.get("Match") or leak.get("Secret") or "")[:240]

        severity_raw = str(leak.get("Severity") or "High")
        severity = to_severity(severity_raw)
        if severity == Severity.MEDIUM and severity_raw.lower() == "high":
            severity = Severity.HIGH

        findings.append(
            Finding(
                vulnerability_type="Hardcoded Secrets / Credentials",
                severity=severity,
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Leaked credentials can grant unauthorized access to production assets.",
                recommendation="Rotate exposed credential, purge history where needed, and migrate secret to vault.",
                reference="https://github.com/gitleaks/gitleaks",
                owasp_category="A02:2021 - Cryptographic Failures",
                description=description,
                rule_id=f"GITLEAKS-{rule}",
                cwe="CWE-798",
                evidence=match or None,
            )
        )

    return findings


def run_gitleaks_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "gitleaks",
) -> tuple[list[Finding], list[str]]:
    with tempfile.NamedTemporaryFile(prefix="gitleaks_", suffix=".json", delete=False) as temp_file:
        report_path = Path(temp_file.name)

    command = [
        binary,
        "detect",
        "--source",
        str(target_root),
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-banner",
        "--timeout",
        str(max(60, int(timeout_seconds))),
        "--max-target-megabytes",
        str(int(os.getenv("USS_GITLEAKS_MAX_TARGET_MB", "8"))),
        "--max-archive-depth",
        str(int(os.getenv("USS_GITLEAKS_MAX_ARCHIVE_DEPTH", "0"))),
        "--max-decode-depth",
        str(int(os.getenv("USS_GITLEAKS_MAX_DECODE_DEPTH", "1"))),
    ]

    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        report_path.unlink(missing_ok=True)
        return [], ["Gitleaks not found in PATH. Install Gitleaks for enterprise secret scanning coverage."]
    except Exception as exc:
        report_path.unlink(missing_ok=True)
        return [], [f"Gitleaks execution failed: {exc}"]

    if return_code not in {0, 1}:
        report_path.unlink(missing_ok=True)
        short_stderr = stderr.strip().splitlines()[:2]
        return [], [f"Gitleaks returned code {return_code}: {' | '.join(short_stderr)}"]

    raw = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else "[]"
    report_path.unlink(missing_ok=True)
    payload = safe_json_loads(raw)

    if not isinstance(payload, list):
        return [], ["Gitleaks produced non-JSON output."]

    return parse_gitleaks_output(payload, target_root), []
