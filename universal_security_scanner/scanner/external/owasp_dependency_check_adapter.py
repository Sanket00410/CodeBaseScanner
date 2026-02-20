from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from universal_security_scanner.models import Finding, Severity
from universal_security_scanner.scanner.external.common import extract_cwe, first_reference, normalize_path, run_command, safe_json_loads, to_severity


def _severity_from_cvss(vulnerability: dict[str, Any]) -> Severity:
    cvssv3 = vulnerability.get("cvssv3") if isinstance(vulnerability, dict) else None
    if isinstance(cvssv3, dict):
        score = cvssv3.get("baseScore")
        try:
            numeric = float(score)
            if numeric >= 9.0:
                return Severity.CRITICAL
            if numeric >= 7.0:
                return Severity.HIGH
            if numeric >= 4.0:
                return Severity.MEDIUM
            if numeric > 0:
                return Severity.LOW
        except Exception:
            pass

    severity = str(vulnerability.get("severity") or vulnerability.get("sourceSeverity") or "").strip()
    if severity:
        return to_severity(severity)
    return Severity.MEDIUM


def parse_owasp_dependency_check_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    dependencies = data.get("dependencies") or []
    if not isinstance(dependencies, list):
        return findings

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        file_name = str(dependency.get("fileName") or dependency.get("filePath") or "dependency")
        file_path = normalize_path(target_root, file_name)
        vulnerabilities = dependency.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            vuln_id = str(vulnerability.get("name") or vulnerability.get("vulnerabilityName") or "UNKNOWN")
            references = []
            refs = vulnerability.get("references") or []
            if isinstance(refs, list):
                for ref in refs:
                    if not isinstance(ref, dict):
                        continue
                    url = ref.get("url")
                    if isinstance(url, str) and url.strip():
                        references.append(url.strip())

            reference = first_reference(references, f"https://nvd.nist.gov/vuln/detail/{vuln_id}")
            cwe = extract_cwe(vulnerability.get("cwes")) or "CWE-1104"
            description = str(vulnerability.get("description") or f"Dependency-Check matched vulnerability {vuln_id}")

            findings.append(
                Finding(
                    vulnerability_type="Dependency Vulnerability",
                    severity=_severity_from_cvss(vulnerability),
                    file_path=file_path,
                    line_number=1,
                    business_impact="Known vulnerable component may be exploitable through public CVE attack paths.",
                    recommendation="Upgrade vulnerable component and transitive dependencies to patched versions.",
                    reference=reference,
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=description,
                    rule_id=f"ODC-{vuln_id}",
                    cwe=cwe,
                    evidence=file_name,
                )
            )
    return findings


def run_owasp_dependency_check_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "dependency-check",
) -> tuple[list[Finding], list[str]]:
    with tempfile.TemporaryDirectory(prefix="odc_") as temp_dir_raw:
        output_dir = Path(temp_dir_raw)
        command = [
            binary,
            "--scan",
            str(target_root),
            "--format",
            "JSON",
            "--out",
            str(output_dir),
            "--project",
            "CodeSentinelX",
            "--disableVersionCheck",
            "--noupdate",
        ]

        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            return [], [
                "OWASP Dependency-Check not found in PATH/toolchain. Install or bootstrap dependency-check for SCA coverage."
            ]
        except Exception as exc:
            return [], [f"OWASP Dependency-Check execution failed: {exc}"]

        report_file = output_dir / "dependency-check-report.json"
        if return_code not in {0, 1} and not report_file.exists():
            combined = "\n".join([stdout.strip(), stderr.strip()]).lower()
            if "database does not exist" in combined:
                return [], ["OWASP Dependency-Check skipped: local vulnerability DB is not initialized."]
            short_error = " | ".join((stderr or stdout or "").strip().splitlines()[:3])
            return [], [f"OWASP Dependency-Check returned code {return_code}: {short_error}"]

        if not report_file.exists():
            return [], []

        payload = safe_json_loads(report_file.read_text(encoding="utf-8", errors="ignore"))
        if not isinstance(payload, dict):
            return [], ["OWASP Dependency-Check produced non-JSON output."]

        return parse_owasp_dependency_check_output(payload, target_root), []
