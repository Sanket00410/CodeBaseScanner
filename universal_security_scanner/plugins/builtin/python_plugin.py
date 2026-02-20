from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding, Severity
from universal_security_scanner.plugins.sdk.interfaces import BaseLanguagePlugin, PluginMetadata, PluginRule
from universal_security_scanner.plugins.sdk.utils import matched_line_numbers


class PythonSecurityPlugin(BaseLanguagePlugin):
    metadata = PluginMetadata(
        plugin_id="builtin-python",
        name="Python Security Plugin",
        language="python",
        version="1.0.0",
    )

    _rules: list[tuple[PluginRule, list[str]]] = [
        (
            PluginRule(
                rule_id="PY-A03-CMDI-001",
                vulnerability_type="Command Injection",
                severity=Severity.CRITICAL,
                description="Untrusted input to shell execution may allow arbitrary command execution.",
                business_impact="Potential remote command execution and system compromise.",
                recommendation="Use subprocess with list args and avoid shell=True.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-78",
            ),
            [
                r"subprocess\.(run|Popen|call)\s*\(.*shell\s*=\s*True",
                r"os\.system\s*\(",
            ],
        ),
        (
            PluginRule(
                rule_id="PY-A08-DESER-001",
                vulnerability_type="Insecure Deserialization",
                severity=Severity.HIGH,
                description="Unsafe deserialization of untrusted input can execute arbitrary code.",
                business_impact="Attackers may execute code or alter application behavior.",
                recommendation="Use safe serializers and schema validation.",
                reference="https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                cwe="CWE-502",
            ),
            [r"pickle\.loads\s*\(", r"yaml\.load\s*\("],
        ),
        (
            PluginRule(
                rule_id="PY-A02-CRYPTO-001",
                vulnerability_type="Weak Cryptography Usage",
                severity=Severity.MEDIUM,
                description="Legacy hashing algorithms provide inadequate collision resistance.",
                business_impact="May enable credential compromise and integrity bypass.",
                recommendation="Use SHA-256/512 or modern password hashing (Argon2/bcrypt).",
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                owasp_category="A02:2021 - Cryptographic Failures",
                cwe="CWE-327",
            ),
            [r"hashlib\.(md5|sha1)\s*\("],
        ),
    ]

    @property
    def supported_extensions(self) -> set[str]:
        return {".py"}

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
