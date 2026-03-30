from __future__ import annotations

from pathlib import Path

from codesentinelx_engine.models import Finding, Severity
from codesentinelx_engine.plugins.sdk.interfaces import BaseLanguagePlugin, PluginMetadata, PluginRule
from codesentinelx_engine.plugins.sdk.utils import matched_line_numbers
from codesentinelx_engine.scanner.source_analysis import analyze_family


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
                rule_id="PY-A03-SQLI-FLOW-001",
                vulnerability_type="SQL Injection",
                severity=Severity.CRITICAL,
                description="Request-controlled data reaches SQL execution through dynamic query construction.",
                business_impact="Attackers may read, modify, or delete sensitive database records.",
                recommendation="Use parameterized queries and keep user input out of query string construction.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-89",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="PY-A03-CMDI-FLOW-001",
                vulnerability_type="Command Injection",
                severity=Severity.CRITICAL,
                description="Request-controlled data reaches a shell execution sink.",
                business_impact="Potential remote command execution and host compromise.",
                recommendation="Avoid shell=True and pass fixed command arguments explicitly.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-78",
            ),
            [],
        ),
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
                rule_id="PY-A08-DESER-FLOW-001",
                vulnerability_type="Insecure Deserialization",
                severity=Severity.HIGH,
                description="Request-controlled data reaches an unsafe deserialization sink.",
                business_impact="Attackers may execute code or alter application behavior.",
                recommendation="Use safe loaders and validate data before deserialization.",
                reference="https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                cwe="CWE-502",
            ),
            [],
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
        (
            PluginRule(
                rule_id="PY-A01-PATHTRAV-FLOW-001",
                vulnerability_type="Path Traversal",
                severity=Severity.HIGH,
                description="Request-controlled path data reaches a filesystem sink without strong confinement.",
                business_impact="Sensitive files may be exposed or overwritten.",
                recommendation="Validate file paths against a fixed base directory and reject traversal sequences.",
                reference="https://owasp.org/www-community/attacks/Path_Traversal",
                owasp_category="A01:2021 - Broken Access Control",
                cwe="CWE-22",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="PY-A10-SSRF-FLOW-001",
                vulnerability_type="Server-Side Request Forgery (SSRF)",
                severity=Severity.HIGH,
                description="Request-controlled URL data reaches an outbound HTTP client sink.",
                business_impact="Attackers may pivot to internal services or access trusted metadata endpoints.",
                recommendation="Allowlist outbound destinations and validate URLs before making requests.",
                reference="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                owasp_category="A10:2021 - Server-Side Request Forgery",
                cwe="CWE-918",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="PY-A01-OPENREDIRECT-FLOW-001",
                vulnerability_type="Open Redirect",
                severity=Severity.MEDIUM,
                description="Request-controlled redirect destinations are returned to the client.",
                business_impact="Attackers may phish users or bounce trusted traffic to malicious destinations.",
                recommendation="Allowlist redirect targets and reject absolute or external URLs.",
                reference="https://cwe.mitre.org/data/definitions/601.html",
                owasp_category="A01:2021 - Broken Access Control",
                cwe="CWE-601",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="PY-A03-SSTI-FLOW-001",
                vulnerability_type="Server-Side Template Injection",
                severity=Severity.HIGH,
                description="Request-controlled template content reaches a server-side rendering sink.",
                business_impact="Attackers may execute template expressions, expose server data, or achieve code execution.",
                recommendation="Do not render untrusted template strings. Use fixed templates and pass user data as context values only.",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-1336",
            ),
            [],
        ),
    ]

    @property
    def supported_extensions(self) -> set[str]:
        return {".py"}

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule, patterns in self._rules:
            if not patterns:
                family = {
                    "PY-A03-SQLI-FLOW-001": "sql-injection",
                    "PY-A03-CMDI-FLOW-001": "command-injection",
                    "PY-A08-DESER-FLOW-001": "insecure-deserialization",
                    "PY-A03-CMDI-001": "command-injection",
                    "PY-A08-DESER-001": "insecure-deserialization",
                    "PY-A01-PATHTRAV-FLOW-001": "path-traversal",
                    "PY-A10-SSRF-FLOW-001": "server-side-request-forgery",
                    "PY-A01-OPENREDIRECT-FLOW-001": "open-redirect",
                    "PY-A03-SSTI-FLOW-001": "template-injection",
                }.get(rule.rule_id)
                if family:
                    for match in analyze_family(content, file_path.suffix, family):
                        findings.append(
                            self.build_finding(
                                rule=rule,
                                file_path=file_path,
                                line_number=match.line_number,
                                evidence=match.evidence_summary(),
                            )
                        )
                continue
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

