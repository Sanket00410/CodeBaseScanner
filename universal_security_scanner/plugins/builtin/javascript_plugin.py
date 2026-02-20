from __future__ import annotations

from pathlib import Path

from universal_security_scanner.models import Finding, Severity
from universal_security_scanner.plugins.sdk.interfaces import BaseLanguagePlugin, PluginMetadata, PluginRule
from universal_security_scanner.plugins.sdk.utils import matched_line_numbers


class JavaScriptSecurityPlugin(BaseLanguagePlugin):
    metadata = PluginMetadata(
        plugin_id="builtin-javascript",
        name="JavaScript Security Plugin",
        language="javascript",
        version="1.0.0",
    )

    _rules: list[tuple[PluginRule, list[str]]] = [
        (
            PluginRule(
                rule_id="JS-A03-XSS-001",
                vulnerability_type="Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                description="Unsafe HTML insertion can execute attacker-controlled scripts.",
                business_impact="Session hijacking and account takeover risk.",
                recommendation="Use safe DOM APIs and output encoding.",
                reference="https://owasp.org/www-community/attacks/xss/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-79",
            ),
            [r"innerHTML\s*=", r"document\.write\s*\(", r"dangerouslySetInnerHTML"],
        ),
        (
            PluginRule(
                rule_id="JS-A03-EVAL-001",
                vulnerability_type="Unsafe eval usage",
                severity=Severity.HIGH,
                description="Dynamic code execution can run untrusted payloads.",
                business_impact="Client-side RCE-like behavior and security boundary bypass.",
                recommendation="Use strict parser logic and explicit allowlists.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-95",
            ),
            [r"\beval\s*\(", r"new\s+Function\s*\("],
        ),
        (
            PluginRule(
                rule_id="JS-A05-MISCONFIG-001",
                vulnerability_type="Security Misconfiguration",
                severity=Severity.MEDIUM,
                description="Overly permissive CORS can expose sensitive APIs to any origin.",
                business_impact="Increased risk of unauthorized cross-origin data access.",
                recommendation="Restrict CORS origins to trusted domains.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                owasp_category="A05:2021 - Security Misconfiguration",
                cwe="CWE-16",
            ),
            [r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"]"],
        ),
    ]

    @property
    def supported_extensions(self) -> set[str]:
        return {".js", ".jsx", ".ts", ".tsx"}

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
