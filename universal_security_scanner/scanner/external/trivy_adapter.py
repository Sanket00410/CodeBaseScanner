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


def parse_trivy_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []

    for result in data.get("Results", []):
        target = normalize_path(target_root, str(result.get("Target", "unknown")))

        for vuln in result.get("Vulnerabilities", []) or []:
            vuln_id = str(vuln.get("VulnerabilityID") or vuln.get("ID") or "UNKNOWN")
            package_name = str(vuln.get("PkgName") or "dependency")
            installed = str(vuln.get("InstalledVersion") or "")
            title = str(vuln.get("Title") or f"Vulnerable Dependency: {package_name}")
            reference = str(vuln.get("PrimaryURL") or f"https://nvd.nist.gov/vuln/detail/{vuln_id}")

            findings.append(
                Finding(
                    vulnerability_type="Dependency Vulnerability",
                    severity=to_severity(str(vuln.get("Severity") or "medium")),
                    file_path=target,
                    line_number=1,
                    business_impact="Known vulnerable component may allow exploitation through known attack vectors.",
                    recommendation=f"Upgrade {package_name} to a fixed version and verify transitive dependencies.",
                    reference=reference,
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=title,
                    rule_id=f"TRIVY-VULN-{vuln_id}",
                    cwe=extract_cwe(vuln.get("CweIDs")) or "CWE-1104",
                    evidence=f"{package_name} {installed}".strip(),
                )
            )

        for misconfig in result.get("Misconfigurations", []) or []:
            mis_id = str(misconfig.get("ID") or "UNKNOWN")
            cause = misconfig.get("CauseMetadata") or {}
            line_number = int(cause.get("StartLine") or 1)
            title = str(misconfig.get("Title") or f"Misconfiguration {mis_id}")

            findings.append(
                Finding(
                    vulnerability_type="Security Misconfiguration",
                    severity=to_severity(str(misconfig.get("Severity") or "medium")),
                    file_path=target,
                    line_number=max(1, line_number),
                    business_impact=str(
                        misconfig.get("Message")
                        or "Insecure configuration can increase attack surface and weaken controls."
                    ),
                    recommendation=str(
                        misconfig.get("Resolution")
                        or "Apply secure configuration baseline and hardening recommendations."
                    ),
                    reference=str(misconfig.get("PrimaryURL") or "https://trivy.dev/latest/docs/"),
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=title,
                    rule_id=f"TRIVY-MISCONF-{mis_id}",
                    cwe=extract_cwe(misconfig.get("CWE")) or "CWE-16",
                    evidence=str(misconfig.get("Message") or "")[:240] or None,
                )
            )

        for secret in result.get("Secrets", []) or []:
            rule_id = str(secret.get("RuleID") or "UNKNOWN")
            line_number = int(secret.get("StartLine") or 1)
            title = str(secret.get("Title") or "Potential Secret Exposure")

            findings.append(
                Finding(
                    vulnerability_type="Hardcoded Secrets / Credentials",
                    severity=to_severity(str(secret.get("Severity") or "high")),
                    file_path=target,
                    line_number=max(1, line_number),
                    business_impact="Exposed credentials can lead to unauthorized environment access.",
                    recommendation="Remove secret from source, rotate the secret, and use a secret manager.",
                    reference="https://trivy.dev/latest/docs/scanner/secret/",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    description=title,
                    rule_id=f"TRIVY-SECRET-{rule_id}",
                    cwe="CWE-798",
                    evidence=str(secret.get("Match") or "")[:240] or None,
                )
            )

    return findings


def run_trivy_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "trivy",
) -> tuple[list[Finding], list[str]]:
    command = [
        binary,
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig,secret",
        "--quiet",
        str(target_root),
    ]

    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["Trivy not found in PATH. Install Trivy for dependency, misconfiguration, and secret scans."]
    except Exception as exc:
        return [], [f"Trivy execution failed: {exc}"]

    if return_code != 0:
        short_stderr = stderr.strip().splitlines()[:2]
        return [], [f"Trivy returned code {return_code}: {' | '.join(short_stderr)}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["Trivy produced non-JSON output."]

    return parse_trivy_output(payload, target_root), []
