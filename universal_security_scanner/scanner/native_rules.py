from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from universal_security_scanner.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class NativeFlowRule:
    language: str
    family: str
    rule_id: str
    vulnerability_type: str
    severity: Severity
    description: str
    business_impact: str
    recommendation: str
    reference: str
    owasp_category: str
    supported_extensions: tuple[str, ...]
    cwe: str | None = None

    def build_finding(self, *, file_path: Path, line_number: int, evidence: str | None = None) -> Finding:
        return Finding(
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            file_path=str(file_path),
            line_number=line_number,
            business_impact=self.business_impact,
            recommendation=self.recommendation,
            reference=self.reference,
            owasp_category=self.owasp_category,
            description=self.description,
            rule_id=self.rule_id,
            cwe=self.cwe,
            evidence=evidence,
            origin="native_code",
            provenance={
                "source": "native_code",
                "language": self.language,
                "family": self.family,
                "rule_id": self.rule_id,
            },
        )


PYTHON_NATIVE_FLOW_RULES: tuple[NativeFlowRule, ...] = (
    NativeFlowRule(
        language="python",
        family="sql-injection",
        rule_id="PY-A03-SQLI-FLOW-001",
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        description="Request-controlled data reaches SQL execution through dynamic query construction.",
        business_impact="Attackers may read, modify, or delete sensitive database records.",
        recommendation="Use parameterized queries and keep user input out of query string construction.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-89",
        supported_extensions=(".py",),
    ),
    NativeFlowRule(
        language="python",
        family="command-injection",
        rule_id="PY-A03-CMDI-FLOW-001",
        vulnerability_type="Command Injection",
        severity=Severity.CRITICAL,
        description="Request-controlled data reaches a shell execution sink.",
        business_impact="Potential remote command execution and host compromise.",
        recommendation="Avoid shell=True and pass fixed command arguments explicitly.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-78",
        supported_extensions=(".py",),
    ),
    NativeFlowRule(
        language="python",
        family="insecure-deserialization",
        rule_id="PY-A08-DESER-FLOW-001",
        vulnerability_type="Insecure Deserialization",
        severity=Severity.HIGH,
        description="Request-controlled data reaches an unsafe deserialization sink.",
        business_impact="Attackers may execute code or alter application behavior.",
        recommendation="Use safe loaders and validate data before deserialization.",
        reference="https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
        owasp_category="A08:2021 - Software and Data Integrity Failures",
        cwe="CWE-502",
        supported_extensions=(".py",),
    ),
    NativeFlowRule(
        language="python",
        family="path-traversal",
        rule_id="PY-A01-PATHTRAV-FLOW-001",
        vulnerability_type="Path Traversal",
        severity=Severity.HIGH,
        description="Request-controlled path data reaches a filesystem sink without strong confinement.",
        business_impact="Sensitive files may be exposed or overwritten.",
        recommendation="Validate file paths against a fixed base directory and reject traversal sequences.",
        reference="https://owasp.org/www-community/attacks/Path_Traversal",
        owasp_category="A01:2021 - Broken Access Control",
        cwe="CWE-22",
        supported_extensions=(".py",),
    ),
    NativeFlowRule(
        language="python",
        family="server-side-request-forgery",
        rule_id="PY-A10-SSRF-FLOW-001",
        vulnerability_type="Server-Side Request Forgery (SSRF)",
        severity=Severity.HIGH,
        description="Request-controlled URL data reaches an outbound HTTP client sink.",
        business_impact="Attackers may pivot to internal services or access trusted metadata endpoints.",
        recommendation="Allowlist outbound destinations and validate URLs before making requests.",
        reference="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        owasp_category="A10:2021 - Server-Side Request Forgery",
        cwe="CWE-918",
        supported_extensions=(".py",),
    ),
    NativeFlowRule(
        language="python",
        family="open-redirect",
        rule_id="PY-A01-OPENREDIRECT-FLOW-001",
        vulnerability_type="Open Redirect",
        severity=Severity.MEDIUM,
        description="Request-controlled redirect destinations are returned to the client.",
        business_impact="Attackers may phish users or bounce trusted traffic to malicious destinations.",
        recommendation="Allowlist redirect targets and reject absolute or external URLs.",
        reference="https://cwe.mitre.org/data/definitions/601.html",
        owasp_category="A01:2021 - Broken Access Control",
        cwe="CWE-601",
        supported_extensions=(".py",),
    ),
    NativeFlowRule(
        language="python",
        family="template-injection",
        rule_id="PY-A03-SSTI-FLOW-001",
        vulnerability_type="Server-Side Template Injection",
        severity=Severity.HIGH,
        description="Request-controlled template content reaches a server-side rendering sink.",
        business_impact="Attackers may execute template expressions, expose server data, or achieve code execution.",
        recommendation="Do not render untrusted template strings. Use fixed templates and pass user data as context values only.",
        reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-1336",
        supported_extensions=(".py",),
    ),
)


JAVASCRIPT_NATIVE_FLOW_RULES: tuple[NativeFlowRule, ...] = (
    NativeFlowRule(
        language="javascript",
        family="xss",
        rule_id="JS-A03-XSS-FLOW-001",
        vulnerability_type="Cross-Site Scripting (XSS)",
        severity=Severity.HIGH,
        description="Request or user-controlled content reaches an unsafe DOM rendering sink.",
        business_impact="Attackers may execute script in victim browsers and steal session context.",
        recommendation="Use safe text rendering APIs or sanitize before HTML insertion.",
        reference="https://owasp.org/www-community/attacks/xss/",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-79",
        supported_extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    NativeFlowRule(
        language="javascript",
        family="unsafe-eval",
        rule_id="JS-A03-EVAL-FLOW-001",
        vulnerability_type="Unsafe eval usage",
        severity=Severity.HIGH,
        description="Request or user-controlled content reaches dynamic JavaScript execution.",
        business_impact="Client-side code execution can bypass expected security boundaries.",
        recommendation="Replace eval/new Function with strict parsing and explicit dispatch.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-95",
        supported_extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    NativeFlowRule(
        language="javascript",
        family="prototype-pollution",
        rule_id="JS-A08-POLLUTION-FLOW-001",
        vulnerability_type="Prototype Pollution Risk",
        severity=Severity.HIGH,
        description="Untrusted object data reaches a deep-merge sink that can mutate prototypes.",
        business_impact="Application behavior can be altered and chained into privilege escalation.",
        recommendation="Block dangerous keys and avoid merging untrusted objects directly.",
        reference="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        owasp_category="A08:2021 - Software and Data Integrity Failures",
        cwe="CWE-1321",
        supported_extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    NativeFlowRule(
        language="javascript",
        family="sql-injection",
        rule_id="JS-A03-SQLI-FLOW-001",
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        description="Request-controlled data reaches a database query sink through dynamic SQL construction.",
        business_impact="Attackers may read or modify sensitive records in backend services.",
        recommendation="Use parameterized queries or safe ORM bindings instead of string-built SQL.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-89",
        supported_extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    NativeFlowRule(
        language="javascript",
        family="command-injection",
        rule_id="JS-A03-CMDI-FLOW-001",
        vulnerability_type="Command Injection",
        severity=Severity.CRITICAL,
        description="Request-controlled data reaches a child-process execution sink.",
        business_impact="Attackers may execute arbitrary commands on the application host.",
        recommendation="Avoid shell execution and pass fixed argument arrays to child_process APIs.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        cwe="CWE-78",
        supported_extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
    NativeFlowRule(
        language="javascript",
        family="path-traversal",
        rule_id="JS-A01-PATHTRAV-FLOW-001",
        vulnerability_type="Path Traversal",
        severity=Severity.HIGH,
        description="Request-controlled path data reaches a filesystem access sink.",
        business_impact="Attackers may read or overwrite files outside intended application boundaries.",
        recommendation="Constrain filesystem paths to a fixed base directory and reject traversal segments.",
        reference="https://owasp.org/www-community/attacks/Path_Traversal",
        owasp_category="A01:2021 - Broken Access Control",
        cwe="CWE-22",
        supported_extensions=(".js", ".jsx", ".ts", ".tsx"),
    ),
)


NATIVE_FLOW_RULES: tuple[NativeFlowRule, ...] = PYTHON_NATIVE_FLOW_RULES + JAVASCRIPT_NATIVE_FLOW_RULES


def iter_native_flow_rules(
    *,
    languages: set[str] | None = None,
    families: set[str] | None = None,
    file_suffix: str | None = None,
) -> list[NativeFlowRule]:
    normalized_languages = {item.strip().lower() for item in languages or set() if item.strip()}
    normalized_families = {item.strip().lower() for item in families or set() if item.strip()}
    suffix = file_suffix.lower() if file_suffix else None

    selected: list[NativeFlowRule] = []
    for rule in NATIVE_FLOW_RULES:
        if normalized_languages and rule.language not in normalized_languages:
            continue
        if normalized_families and rule.family not in normalized_families:
            continue
        if suffix and suffix not in rule.supported_extensions:
            continue
        selected.append(rule)
    return selected
