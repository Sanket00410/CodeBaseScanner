from __future__ import annotations

from pathlib import Path

from codesentinelx_engine.models import Finding, Severity
from codesentinelx_engine.plugins.sdk.interfaces import BaseLanguagePlugin, PluginMetadata, PluginRule
from codesentinelx_engine.plugins.sdk.utils import matched_line_numbers
from codesentinelx_engine.scanner.source_analysis import analyze_family


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
                rule_id="JS-A03-XSS-FLOW-001",
                vulnerability_type="Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                description="Request or user-controlled content reaches an unsafe DOM rendering sink.",
                business_impact="Attackers may execute script in victim browsers and steal session context.",
                recommendation="Use safe text rendering APIs or sanitize before HTML insertion.",
                reference="https://owasp.org/www-community/attacks/xss/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-79",
            ),
            [],
        ),
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
                rule_id="JS-A03-EVAL-FLOW-001",
                vulnerability_type="Unsafe eval usage",
                severity=Severity.HIGH,
                description="Request or user-controlled content reaches dynamic JavaScript execution.",
                business_impact="Client-side code execution can bypass expected security boundaries.",
                recommendation="Replace eval/new Function with strict parsing and explicit dispatch.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-95",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="JS-A03-SQLI-FLOW-001",
                vulnerability_type="SQL Injection",
                severity=Severity.CRITICAL,
                description="Request-controlled data reaches a database query sink through dynamic SQL construction.",
                business_impact="Attackers may read or modify sensitive records in backend services.",
                recommendation="Use parameterized queries or safe ORM bindings instead of string-built SQL.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-89",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="JS-A03-CMDI-FLOW-001",
                vulnerability_type="Command Injection",
                severity=Severity.CRITICAL,
                description="Request-controlled data reaches a child-process execution sink.",
                business_impact="Attackers may execute arbitrary commands on the application host.",
                recommendation="Avoid shell execution and pass fixed argument arrays to child_process APIs.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-78",
            ),
            [],
        ),
        (
            PluginRule(
                rule_id="JS-A01-PATHTRAV-FLOW-001",
                vulnerability_type="Path Traversal",
                severity=Severity.HIGH,
                description="Request-controlled path data reaches a filesystem access sink.",
                business_impact="Attackers may read or overwrite files outside intended application boundaries.",
                recommendation="Constrain filesystem paths to a fixed base directory and reject traversal segments.",
                reference="https://owasp.org/www-community/attacks/Path_Traversal",
                owasp_category="A01:2021 - Broken Access Control",
                cwe="CWE-22",
            ),
            [],
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
                rule_id="JS-A08-POLLUTION-FLOW-001",
                vulnerability_type="Prototype Pollution Risk",
                severity=Severity.HIGH,
                description="Untrusted object data reaches a deep-merge sink that can mutate prototypes.",
                business_impact="Application behavior can be altered and chained into privilege escalation.",
                recommendation="Block dangerous keys and avoid merging untrusted objects directly.",
                reference="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                cwe="CWE-1321",
            ),
            [],
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
            if not patterns:
                family = {
                    "JS-A03-XSS-FLOW-001": "xss",
                    "JS-A03-EVAL-FLOW-001": "unsafe-eval",
                    "JS-A08-POLLUTION-FLOW-001": "prototype-pollution",
                    "JS-A03-SQLI-FLOW-001": "sql-injection",
                    "JS-A03-CMDI-FLOW-001": "command-injection",
                    "JS-A01-PATHTRAV-FLOW-001": "path-traversal",
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

