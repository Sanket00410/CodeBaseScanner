from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding, Severity
from universal_security_scanner.plugins.sdk.interfaces import BaseLanguagePlugin, PluginMetadata, PluginRule
from universal_security_scanner.plugins.sdk.utils import matched_line_numbers


class GoSecurityPlugin(BaseLanguagePlugin):
    metadata = PluginMetadata(
        plugin_id="builtin-go",
        name="Go Security Plugin",
        language="go",
        version="1.0.0",
    )

    _rules: list[tuple[PluginRule, list[str]]] = [
        (
            PluginRule(
                rule_id="GO-A03-SQLI-001",
                vulnerability_type="SQL Injection",
                severity=Severity.CRITICAL,
                description="String-built SQL queries can permit injection.",
                business_impact="Database exfiltration and tampering risk.",
                recommendation="Use parameterized query placeholders.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-89",
            ),
            [r"db\.Query\s*\(.*\+.*\)", r"fmt\.Sprintf\s*\(\s*\"\s*SELECT"],
        ),
        (
            PluginRule(
                rule_id="GO-A03-CMDI-001",
                vulnerability_type="Command Injection",
                severity=Severity.HIGH,
                description="Constructing shell commands with user input is dangerous.",
                business_impact="Potential command execution on service host.",
                recommendation="Use exec.Command with literal args and strict validation.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-78",
            ),
            [r"exec\.Command\s*\(\s*\"sh\"\s*,\s*\"-c\""],
        ),
        (
            PluginRule(
                rule_id="GO-A02-CRYPTO-001",
                vulnerability_type="Weak Cryptography Usage",
                severity=Severity.MEDIUM,
                description="Deprecated or weak cryptography primitives reduce confidentiality.",
                business_impact="Weakens protection of sensitive data and tokens.",
                recommendation="Use modern crypto suites (AES-GCM, SHA-256+, Ed25519).",
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                owasp_category="A02:2021 - Cryptographic Failures",
                cwe="CWE-327",
            ),
            [r"md5\.New\s*\(", r"sha1\.New\s*\("],
        ),
    ]

    @property
    def supported_extensions(self) -> set[str]:
        return {".go"}

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule, patterns in self._rules:
            for line_number, evidence in matched_line_numbers(content, patterns):
                findings.append(
                    self.build_finding(
                        rule=rule,
                        file_path=file_path,
                        line_number=line_number,
                        evidence=evidence,
                    )
                )
        return findings
