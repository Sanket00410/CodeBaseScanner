from __future__ import annotations

from universal_security_scanner.models import Severity
from universal_security_scanner.scanner.rules.base import RegexFileRule, RuleMetadata


CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".php",
    ".go",
    ".rb",
    ".cs",
    ".scala",
    ".kt",
    ".swift",
    ".sql",
    ".sh",
}

WEB_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".php", ".vue"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".ini", ".conf", ".env", ".py", ".js"}


def build_builtin_file_rules() -> list[RegexFileRule]:
    return [
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A03-SQLI-001",
                vulnerability_type="SQL Injection",
                severity=Severity.CRITICAL,
                description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
                business_impact="Attackers may read, modify, or delete sensitive business and customer data.",
                recommendation="Use parameterized queries / prepared statements and strict input validation.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-89",
            ),
            patterns=[
                r"(cursor|statement)\.execute\s*\(.*\+.*\)",
                r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|\.format\(|f\"|f\')",
                r"sequelize\.query\s*\(.*\+.*\)",
            ],
            file_extensions=CODE_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A03-XSS-001",
                vulnerability_type="Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                description="Unsafely rendering user-controlled HTML/JS can execute attacker scripts in user browsers.",
                business_impact="Session hijacking, data theft, and unauthorized user actions can occur.",
                recommendation="Use output encoding, CSP, and framework-safe rendering APIs.",
                reference="https://owasp.org/www-community/attacks/xss/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-79",
            ),
            patterns=[
                r"innerHTML\s*=",
                r"document\.write\s*\(",
                r"dangerouslySetInnerHTML",
                r"v-html\s*=",
            ],
            file_extensions=WEB_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A03-CMDI-001",
                vulnerability_type="Command Injection",
                severity=Severity.CRITICAL,
                description="Passing untrusted input to OS command execution APIs may allow arbitrary command execution.",
                business_impact="Remote code execution may lead to full server compromise and lateral movement.",
                recommendation="Avoid shell execution with untrusted input and use safe API arguments.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-78",
            ),
            patterns=[
                r"os\.system\s*\(",
                r"subprocess\.(run|Popen|call)\s*\(.*shell\s*=\s*True",
                r"Runtime\.getRuntime\(\)\.exec\s*\(",
                r"child_process\.exec\s*\(",
            ],
            file_extensions=CODE_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A01-PATHTRAV-001",
                vulnerability_type="Path Traversal",
                severity=Severity.HIGH,
                description="User-controlled file paths can enable unauthorized file read/write access.",
                business_impact="Sensitive files and credentials may be exposed, modified, or destroyed.",
                recommendation="Normalize and validate paths against an allowlisted base directory.",
                reference="https://owasp.org/www-community/attacks/Path_Traversal",
                owasp_category="A01:2021 - Broken Access Control",
                cwe="CWE-22",
            ),
            patterns=[
                r"send_file\s*\(\s*request\.(args|form|values)",
                r"open\s*\(\s*request\.(args|form|values)",
                r"fs\.(readFile|readFileSync|createReadStream)\s*\(\s*req\.(query|params|body)",
                r"\.\./",
            ],
            file_extensions=CODE_EXTENSIONS | WEB_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A02-SECRETS-001",
                vulnerability_type="Hardcoded Secrets / Credentials",
                severity=Severity.HIGH,
                description="Embedded credentials can be extracted and reused by attackers.",
                business_impact="Credential leakage can enable unauthorized environment access and data breach.",
                recommendation="Move secrets to a managed secret store and rotate exposed credentials.",
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                owasp_category="A02:2021 - Cryptographic Failures",
                cwe="CWE-798",
            ),
            patterns=[
                r"\b(password|passwd|secret|api[_-]?key|token|client_secret)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                r"AKIA[0-9A-Z]{16}",
                r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            ],
            file_extensions=CODE_EXTENSIONS | CONFIG_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A08-DESER-001",
                vulnerability_type="Insecure Deserialization",
                severity=Severity.HIGH,
                description="Deserializing untrusted data can lead to arbitrary code execution.",
                business_impact="Attackers may execute code, alter application state, or escalate privileges.",
                recommendation="Use safe serializers and enforce strict schema validation.",
                reference="https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                owasp_category="A08:2021 - Software and Data Integrity Failures",
                cwe="CWE-502",
            ),
            patterns=[
                r"pickle\.loads\s*\(",
                r"yaml\.load\s*\(",
                r"ObjectInputStream",
                r"BinaryFormatter",
            ],
            file_extensions=CODE_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A03-EVAL-001",
                vulnerability_type="Unsafe eval usage",
                severity=Severity.HIGH,
                description="Dynamic code execution primitives can execute attacker-controlled payloads.",
                business_impact="Potential remote code execution and complete application compromise.",
                recommendation="Replace eval/exec patterns with strict parsing and safe dispatch logic.",
                reference="https://owasp.org/Top10/A03_2021-Injection/",
                owasp_category="A03:2021 - Injection",
                cwe="CWE-95",
            ),
            patterns=[
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"new\s+Function\s*\(",
                r"setTimeout\s*\(\s*['\"]",
            ],
            file_extensions=CODE_EXTENSIONS | WEB_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A01-AUTH-001",
                vulnerability_type="Authentication / Authorization Flaw",
                severity=Severity.HIGH,
                description="Bypass flags and weak authorization controls can expose protected operations.",
                business_impact="Unauthorized users may access privileged functionality or sensitive data.",
                recommendation="Enforce centralized authz checks and remove bypass toggles from production paths.",
                reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                owasp_category="A01:2021 - Broken Access Control",
                cwe="CWE-285",
            ),
            patterns=[
                r"\b(skip_auth|auth_disabled|disable_auth|allow_anonymous|permitAll)\b",
                r"jwt\.decode\s*\(.*verify\s*=\s*False",
                r"csrf\s*=\s*False",
                r"@PermitAll",
            ],
            file_extensions=CODE_EXTENSIONS,
        ),
        RegexFileRule(
            metadata=RuleMetadata(
                rule_id="OWASP-A05-MISCONFIG-001",
                vulnerability_type="Security Misconfiguration",
                severity=Severity.MEDIUM,
                description="Insecure defaults can expose sensitive internals and weaken defense layers.",
                business_impact="Increases attack surface and often enables chained exploitation.",
                recommendation="Harden runtime config, disable debug modes, and enforce secure defaults.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                owasp_category="A05:2021 - Security Misconfiguration",
                cwe="CWE-16",
            ),
            patterns=[
                r"debug\s*=\s*True",
                r"FLASK_ENV\s*=\s*['\"]development['\"]",
                r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
                r"Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"]",
                r"ssl_verify\s*=\s*False",
            ],
            file_extensions=CODE_EXTENSIONS | CONFIG_EXTENSIONS,
        ),
    ]
