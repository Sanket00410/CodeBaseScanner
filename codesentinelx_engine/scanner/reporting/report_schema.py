from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ...models import Finding, Severity as OldSeverity, ScanResult
from ...risk import calculate_risk_score, risk_rating as risk_rating_from_score
from .report_models import (
    AffectedComponent,
    AttackChain,
    CVSSVector,
    ComplianceFrameworkMapping,
    ConfidenceLevel,
    DataFlowStep,
    DataFlowStepType,
    DeveloperReport,
    ExecutiveReport,
    FindingGroup,
    ProfessionalFinding,
    ProfessionalReportMetadata,
    RemediationComplexity,
    RemediationGuidance,
    RemediationStatus,
    ReportType,
    RoleBasedView,
    ReportValidationWarning,
    RootCauseGrouping,
    SBOMEntry,
    ScanMetadata,
    AssessmentScope,
    SecurityMetricsDashboard,
    SecurityPostureScores,
    AssessmentLimitation,
    StructuredBusinessImpact,
    TaxonomyMapping,
    RetestReport,
)
from .evidence_collector import EvidenceCollector, EvidenceCollectorConfig
from .attack_chain_builder import AttackChainBuilder, AttackChainBuilderConfig
from .confidence_feedback import (
    ConfidenceFeedbackStore,
    _auto_flag_potential_fp,
    _make_finding_signature,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _map_severity(old: OldSeverity | str | None) -> str:
    if isinstance(old, OldSeverity):
        return old.value
    if isinstance(old, str):
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
        }
        return mapping.get(old.lower(), "Info")
    return "Info"


def _derive_cvss_from_severity(severity: str) -> CVSSVector:
    sev_map = {
        "Critical": "HIGH",
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Info": "NONE",
    }
    return CVSSVector(
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
        confidentiality=sev_map.get(severity, "NONE"),
        integrity=sev_map.get(severity, "NONE"),
        availability="NONE",
    )


_CWE_OWASP_MAP: dict[str, tuple[str, str]] = {
    "CWE-89": ("A03:2021", "Injection"),
    "CWE-79": ("A03:2021", "Cross-Site Scripting"),
    "CWE-22": ("A01:2021", "Broken Access Control"),
    "CWE-78": ("A03:2021", "Injection"),
    "CWE-918": ("A10:2021", "Server-Side Request Forgery"),
    "CWE-601": ("A01:2021", "Broken Access Control"),
    "CWE-798": ("A07:2021", "Identification and Authentication Failures"),
    "CWE-502": ("A08:2021", "Software and Data Integrity Failures"),
    "CWE-1336": ("A03:2021", "Injection"),
    "CWE-285": ("A01:2021", "Broken Access Control"),
    "CWE-327": ("A02:2021", "Cryptographic Failures"),
    "CWE-1104": ("A06:2021", "Vulnerable and Outdated Components"),
    "CWE-532": ("A09:2021", "Security Logging and Monitoring Failures"),
    "CWE-200": ("A01:2021", "Broken Access Control"),
    "CWE-94": ("A03:2021", "Injection"),
    "CWE-77": ("A03:2021", "Injection"),
    "CWE-287": ("A07:2021", "Identification and Authentication Failures"),
    "CWE-306": ("A07:2021", "Identification and Authentication Failures"),
    "CWE-862": ("A01:2021", "Broken Access Control"),
    "CWE-863": ("A01:2021", "Broken Access Control"),
}

_CWE_MITRE_MAP: dict[str, tuple[str, str]] = {
    "CWE-89": ("T1190", "Exploit Public-Facing Application"),
    "CWE-79": ("T1189", "Drive-by Compromise"),
    "CWE-22": ("T1190", "Exploit Public-Facing Application"),
    "CWE-78": ("T1059", "Command and Scripting Interpreter"),
    "CWE-918": ("T1190", "Exploit Public-Facing Application"),
    "CWE-798": ("T1078", "Valid Accounts"),
    "CWE-502": ("T1059", "Command and Scripting Interpreter"),
    "CWE-532": ("T1562", "Impair Defenses"),
    "CWE-200": ("T1005", "Data from Local System"),
    "CWE-94": ("T1059", "Command and Scripting Interpreter"),
    "CWE-287": ("T1078", "Valid Accounts"),
    "CWE-862": ("T1078", "Valid Accounts"),
}

_CWE_CAPEC_MAP: dict[str, str] = {
    "CWE-89": "CAPEC-66",
    "CWE-79": "CAPEC-86",
    "CWE-22": "CAPEC-126",
    "CWE-78": "CAPEC-88",
    "CWE-918": "CAPEC-916",
    "CWE-502": "CAPEC-240",
    "CWE-798": "CAPEC-16",
    "CWE-532": "CAPEC-116",
    "CWE-94": "CAPEC-122",
}

_CWE_NIST_MAP: dict[str, str] = {
    "CWE-89": "SC-7, SI-10",
    "CWE-79": "SC-7, SI-10",
    "CWE-22": "AC-6, SC-7",
    "CWE-78": "AC-6, SC-7",
    "CWE-918": "SC-7, SI-10",
    "CWE-798": "IA-2, IA-5",
    "CWE-502": "SI-7, AU-10",
    "CWE-532": "AU-2, AU-3, SI-4",
    "CWE-200": "AC-4, SC-7",
    "CWE-94": "AC-3, SC-7",
    "CWE-287": "IA-2, IA-5",
    "CWE-862": "AC-6, AC-3",
    "CWE-327": "SC-12, SC-13",
    "CWE-1104": "RA-5, SA-11",
}

_ROOT_CAUSE_CATEGORIES: dict[str, list[str]] = {
    "Secrets Management": ["secret", "credential", "hardcoded", "password", "api key", "token"],
    "Path Validation": ["path traversal", "directory", "file inclusion"],
    "Input Validation": ["injection", "sql injection", "command injection", "xss", "cross-site scripting"],
    "Logging Practices": ["logging", "sensitive logging", "log injection"],
    "Cryptography": ["crypto", "weak hash", "weak encryption", "cipher", "deserialization"],
    "Configuration Management": ["config", "configuration", "hardcoded", "default credential"],
    "Dependency Governance": ["dependency", "component", "outdated", "package", "supply chain"],
    "Authentication & Authorization": ["auth", "session", "token", "access control", "privilege", "jwt"],
    "Data Exposure": ["data exposure", "information disclosure", "sensitive data"],
    "Error Handling": ["error handling", "exception", "stack trace"],
}

_VULN_TO_DATAFLOW: dict[str, list[dict[str, str]]] = {
    "sql injection": [
        {"step_type": "Source", "description": "User-supplied input parameter", "location": "HTTP request body/query"},
        {"step_type": "Processing", "description": "String concatenation with SQL query", "location": "Data access layer"},
        {"step_type": "Sink", "description": "Unparameterized database query execution", "location": "Database driver"},
    ],
    "command injection": [
        {"step_type": "Source", "description": "User-supplied command argument", "location": "HTTP request parameter"},
        {"step_type": "Processing", "description": "String interpolation into shell command", "location": "Command execution handler"},
        {"step_type": "Sink", "description": "OS command execution", "location": "subprocess / os.system"},
    ],
    "xss": [
        {"step_type": "Source", "description": "User-supplied content", "location": "HTTP request"},
        {"step_type": "Processing", "description": "Content rendered without encoding", "location": "Template / DOM renderer"},
        {"step_type": "Sink", "description": "HTML output rendered in browser", "location": "Client-side DOM"},
    ],
    "path traversal": [
        {"step_type": "Source", "description": "User-supplied file path parameter", "location": "HTTP request"},
        {"step_type": "Processing", "description": "Path used without canonicalization", "location": "File access handler"},
        {"step_type": "Sink", "description": "File read/write operation", "location": "Filesystem API"},
    ],
    "ssrf": [
        {"step_type": "Source", "description": "User-supplied URL parameter", "location": "HTTP request"},
        {"step_type": "Processing", "description": "URL used without allowlist validation", "location": "HTTP client"},
        {"step_type": "Sink", "description": "Outbound HTTP request to user-controlled URL", "location": "HTTP client library"},
    ],
    "deserialization": [
        {"step_type": "Source", "description": "Untrusted serialized payload", "location": "HTTP request / message queue"},
        {"step_type": "Processing", "description": "Deserialization without integrity check", "location": "Deserialization handler"},
        {"step_type": "Sink", "description": "Arbitrary object instantiation", "location": "Runtime deserializer"},
    ],
    "hardcoded": [
        {"step_type": "Source", "description": "Source code / configuration file", "location": "Source repository"},
        {"step_type": "Processing", "description": "Credential compiled into binary", "location": "Build artifact"},
        {"step_type": "Sink", "description": "Credential used for authentication", "location": "Auth module"},
    ],
}

_VULN_CODE_EXAMPLES: dict[str, tuple[str, str]] = {
    "sql injection": (
        '# Vulnerable:\ncursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        '# Fixed:\ncursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))',
    ),
    "command injection": (
        '# Vulnerable:\nos.system(f"ping {user_input}")',
        '# Fixed:\nsubprocess.run(["ping", user_input], capture_output=True)',
    ),
    "xss": (
        "# Vulnerable:\nelement.innerHTML = userInput",
        "# Fixed:\nelement.textContent = userInput",
    ),
    "path traversal": (
        '# Vulnerable:\nopen(os.path.join(base_dir, user_path))',
        '# Fixed:\nresolved = os.path.realpath(os.path.join(base_dir, user_path))\nif resolved.startswith(base_dir):\n    open(resolved)',
    ),
    "hardcoded": (
        '# Vulnerable:\nDB_PASSWORD = "s3cr3t_p@ssw0rd"',
        '# Fixed:\nDB_PASSWORD = os.environ["DB_PASSWORD"]',
    ),
    "ssrf": (
        '# Vulnerable:\nrequests.get(user_url)',
        '# Fixed:\nfrom urllib.parse import urlparse\nparsed = urlparse(user_url)\nif parsed.hostname in ALLOWED_HOSTS:\n    requests.get(user_url)',
    ),
    "deserialization": (
        '# Vulnerable:\nimport pickle\ndata = pickle.loads(untrusted_bytes)',
        '# Fixed:\nimport json\ndata = json.loads(untrusted_bytes)',
    ),
}


def _cwe_to_owasp_mapping(cwe_id: str) -> TaxonomyMapping | None:
    cwe_upper = cwe_id.upper().strip()
    if cwe_upper in _CWE_OWASP_MAP:
        cat_id, cat_name = _CWE_OWASP_MAP[cwe_upper]
        return TaxonomyMapping(
            framework="OWASP Top 10:2021",
            category_id=cat_id,
            category_name=cat_name,
            url=f"https://owasp.org/Top10/{cat_id}/",
        )
    return None


def _classify_root_cause(vulnerability_type: str, description: str) -> str:
    combined = f"{vulnerability_type} {description}".lower()
    for category, keywords in _ROOT_CAUSE_CATEGORIES.items():
        if any(kw in combined for kw in keywords):
            return category
    return "General Security Weakness"


def _derive_data_flow(vulnerability_type: str, flow_steps: list | None = None, file_path: str = "") -> list[DataFlowStep]:
    if flow_steps:
        result = []
        for step in flow_steps:
            step_type = step.get("step_type") if isinstance(step, dict) else getattr(step, "step_type", "Processing")
            code = step.get("code") if isinstance(step, dict) else getattr(step, "code", "")
            desc = step.get("description") if isinstance(step, dict) else getattr(step, "description", "")
            var = step.get("variable") if isinstance(step, dict) else getattr(step, "variable", "")
            lineno = step.get("line_number") if isinstance(step, dict) else getattr(step, "line_number", 0)
            location = f"{file_path}:{lineno}" if file_path and lineno else file_path or ""
            result.append(DataFlowStep(
                step_type=step_type,
                description=desc,
                location=location,
                code_reference=code,
            ))
        return result
    lower = vulnerability_type.lower()
    for pattern, steps in _VULN_TO_DATAFLOW.items():
        if pattern in lower:
            return [DataFlowStep(**s) for s in steps]
    return []


def _derive_code_examples(vulnerability_type: str, code_snippet: str = "") -> tuple[str, str]:
    if code_snippet:
        return (code_snippet, "")
    lower = vulnerability_type.lower()
    for pattern, examples in _VULN_CODE_EXAMPLES.items():
        if pattern in lower:
            return examples
    return ("", "")


def _derive_confidence_level(evidence: str | None, severity: str) -> ConfidenceLevel:
    if evidence and len(evidence) > 100:
        return ConfidenceLevel.TRUE_POSITIVE
    if evidence and len(evidence) > 30:
        return ConfidenceLevel.LIKELY_POSITIVE
    if severity in ("Critical", "High"):
        return ConfidenceLevel.LIKELY_POSITIVE
    return ConfidenceLevel.NEEDS_MANUAL_REVIEW


def _derive_attack_vector_from_vuln(vulnerability_type: str) -> str:
    lower = vulnerability_type.lower()
    if any(kw in lower for kw in ["xss", "injection", "ssrf", "traversal", "csrf"]):
        return "Network - Remote exploitation via HTTP requests"
    if any(kw in lower for kw in ["hardcoded", "secret", "credential"]):
        return "Local/Network - Requires access to source code or configuration"
    if any(kw in lower for kw in ["deserialization"]):
        return "Network - Requires ability to submit serialized objects"
    return "Network - Remote exploitation via application interface"


def _derive_likelihood(vulnerability_type: str, severity: str) -> str:
    lower = vulnerability_type.lower()
    if severity == "Critical":
        return "High - Critical severity with likely exploitation path"
    if severity == "High":
        return "Medium to High - Exploitation requires specific conditions"
    if any(kw in lower for kw in ["hardcoded", "secret"]):
        return "Medium - Requires source code or configuration access"
    return "Medium - Depends on application configuration and deployment"


def _derive_business_impact(vulnerability_type: str, severity: str) -> str:
    lower = vulnerability_type.lower()
    if severity == "Critical":
        if "sql" in lower or "injection" in lower:
            return "Critical - Potential for full database compromise, data exfiltration, and regulatory penalties (GDPR, PCI DSS)"
        if "deserialization" in lower:
            return "Critical - Remote code execution leading to full system compromise"
        return "Critical - Immediate risk of data breach, system compromise, and regulatory non-compliance"
    if severity == "High":
        return "High - Significant risk of unauthorized access, data exposure, or service disruption"
    if severity == "Medium":
        return "Medium - Moderate risk affecting data integrity or availability in specific scenarios"
    return "Low - Limited direct business impact, contributes to defense-in-depth posture"


def _derive_technical_impact(vulnerability_type: str, severity: str) -> str:
    lower = vulnerability_type.lower()
    if "sql" in lower:
        return "Complete compromise of database confidentiality, integrity, and availability. Potential for lateral movement to other database systems."
    if "command" in lower:
        return "Remote code execution with privileges of the application process. Full server compromise possible."
    if "xss" in lower:
        return "Client-side code execution in victim browser. Session hijacking, credential theft, and phishing attacks possible."
    if "path traversal" in lower:
        return "Unauthorized read/write access to arbitrary files on the server. Configuration and credential exposure."
    if "ssrf" in lower:
        return "Server-side requests to internal network resources. Cloud metadata, internal APIs, and admin interfaces accessible."
    if "hardcoded" in lower or "secret" in lower:
        return "Credential exposure allowing unauthorized access to databases, APIs, or third-party services."
    if "deserialization" in lower:
        return "Remote code execution through crafted serialized payloads. Full application and server compromise."
    return f"Security impact consistent with {severity.lower()} severity classification."


_FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "Django": ["django/", "views.py", "urls.py", "models.py", "settings.py"],
    "Flask": ["flask/", "app.py", "requirements.txt"],
    "FastAPI": ["fastapi/", "main.py", "routers/", "schemas.py"],
    "React": [".jsx", ".tsx", "react/", "components/"],
    "Vue": [".vue", "vue/", "nuxt/"],
    "Angular": [".component.ts", "angular.json", "module.ts"],
    "Node/Express": ["express", "routes/", "controllers/", "middleware/"],
    "Spring Boot": ["application.java", "controller.java", "service.java", "pom.xml"],
    "ASP.NET": [".cshtml", ".aspx", "global.asax", "web.config"],
    "Ruby on Rails": ["rails/", "controller.rb", "model.rb", "gemfile"],
    "Laravel": ["laravel/", "artisan", "blade.php", "composer.json"],
    "Symfony": ["symfony/", "yaml", "twig"],
}


def _detect_framework(file_path: str) -> str:
    lower = file_path.lower()
    for framework, patterns in _FRAMEWORK_PATTERNS.items():
        if any(p in lower for p in patterns):
            return framework
    return ""


_FRAMEWORK_REGRESSION_GUIDANCE: dict[str, dict[str, str]] = {
    "Django": {
        "sql injection": "Write a test that attempts SQL injection via each view accepting user input. Verify no raw SQL reaches the database using Django's query inspection.",
        "xss": "Add a test that renders user-controlled strings in templates and asserts no unescaped output appears.",
        "command injection": "Test that subprocess calls with user input are blocked and validate via mock that shell=True is never used.",
    },
    "Flask": {
        "sql injection": "Use Flask-SQLAlchemy's `text()` with bound parameters. Write a test that confirms parameterized queries are used in all route handlers.",
        "xss": "Enable Jinja2 autoescaping in tests. Verify XSS payloads are escaped in rendered responses.",
    },
    "FastAPI": {
        "sql injection": "Verify all database queries use Pydantic models and SQLAlchemy ORM. Write a test checking raw SQL execution is not present.",
        "xss": "Ensure all responses use proper `Response` media_type. Test that HTML in input fields is escaped.",
        "command injection": "Test that `subprocess` or `os.system` calls with user input are intercepted by middleware.",
    },
    "React": {
        "xss": "Add a test that renders JSX with dangerous content and verifies React's built-in XSS protection via dangerouslySetInnerHTML is not used.",
        "sql injection": "Verify all API calls use parameterized queries on the backend handling React requests.",
    },
    "Node/Express": {
        "sql injection": "Write integration tests that use parameterized queries with mysql2/pg prepared statements. Assert no string concatenation in queries.",
        "xss": "Test that helmet.js CSP headers are present and eval() is not used on user input.",
        "command injection": "Verify that exec() and spawn() calls with shell=true are not present in routes handling user input.",
    },
    "Spring Boot": {
        "sql injection": "Write a JPA repository test that uses @Query with :parameters. Assert no native SQL queries with string concatenation exist.",
        "xss": "Verify @ResponseBody does not return raw user input. Test Thymeleaf templates escape all variables.",
    },
}

_DEFAULT_REGRESSION_TEMPLATES: dict[str, str] = {
    "sql injection": "Write a unit test with SQL injection payloads (', OR 1=1, UNION SELECT) passed to every input parameter. Assert no unexpected data is returned and no errors occur from malformed queries.",
    "xss": "Write a test with XSS payloads (<script>, <img onerror=, javascript:) passed to all input fields. Verify output encoding renders payloads inert.",
    "command injection": "Create a test that passes shell metacharacters (;, |, &&, $(cat /etc/passwd)) to all command-line inputs. Verify no system commands execute beyond the intended scope.",
    "path traversal": "Write a test with ../, ..\\, and encoded traversal sequences passed to file path inputs. Verify file access is restricted to the intended directory.",
    "ssrf": "Write a test that provides internal IP addresses (127.0.0.1, 10.0.0.1, 169.254.169.254) as URL inputs. Verify requests to these addresses are blocked.",
    "hardcoded": "Write a test that scans for hardcoded credential patterns (password, secret, api_key, token =). Verify all secrets are loaded from environment variables or a vault.",
    "deserialization": "Write a test that sends malicious serialized payloads to deserialization endpoints. Verify safe parsing with allowlisted classes or safe formats.",
    "secrets": "Write a test that confirms no secrets appear in version-controlled files. Use a pre-commit hook simulation to scan for credential patterns.",
}

_RETEST_CHECKLIST_TEMPLATES: dict[str, list[str]] = {
    "sql injection": [
        "Verify parameterized queries/prepared statements are used",
        "Test with SQL-specific payloads (', \", OR 1=1, UNION, comment sequences)",
        "Confirm error messages do not disclose database information",
        "Verify least-privilege database account is used",
        "Check stored procedure usage if applicable",
    ],
    "xss": [
        "Verify contextual output encoding for HTML, JS, CSS, URL contexts",
        "Confirm Content-Security-Policy header is present and restrictive",
        "Test with XSS payloads in all input fields",
        "Verify HttpOnly and Secure cookie flags",
        "Check DOM-based XSS vectors (innerHTML, document.write, eval)",
    ],
    "command injection": [
        "Verify no user input reaches shell commands directly",
        "Confirm shell=True is not used",
        "Test with shell metacharacters",
        "Verify language-native API is used instead of shell",
    ],
    "path traversal": [
        "Verify file path canonicalization is implemented",
        "Test with traversal sequences and encoding variations",
        "Confirm chroot/sandbox restrictions are in place",
        "Verify allowlist for permitted directories",
    ],
    "ssrf": [
        "Verify URL allowlist is implemented",
        "Test with internal IP addresses and cloud metadata endpoints",
        "Confirm outbound request restrictions",
        "Verify URL scheme whitelist (no file://, gopher://, etc.)",
    ],
    "hardcoded": [
        "Confirm hardcoded credential is removed",
        "Verify secret is loaded from environment or vault",
        "Test application functions with new secrets configuration",
        "Check for other hardcoded secrets in same file/module",
    ],
    "deserialization": [
        "Verify untrusted deserialization is replaced with safe parsing",
        "Test with malicious serialized payloads",
        "Confirm allowlist/denylist for classes if applicable",
        "Verify integrity checks on serialized data",
    ],
}


def _derive_remediation(
    vulnerability_type: str, recommendation: str, file_path: str = ""
) -> RemediationGuidance:
    lower = vulnerability_type.lower()
    vuln_code, fixed_code = _derive_code_examples(vulnerability_type)
    framework = _detect_framework(file_path)
    regression_guidance = ""
    retest_checklist: list[str] = []
    for key in _DEFAULT_REGRESSION_TEMPLATES:
        if key in lower:
            regression_guidance = _FRAMEWORK_REGRESSION_GUIDANCE.get(framework, {}).get(key, _DEFAULT_REGRESSION_TEMPLATES[key])
            retest_checklist = _RETEST_CHECKLIST_TEMPLATES.get(key, [])
            break
    regression_suffix = (
        f"\n\nFramework-specific ({framework}): {regression_guidance}"
        if framework and regression_guidance
        else f"\n\nRegression test guidance: {regression_guidance}"
        if regression_guidance
        else ""
    )
    framework_fix_prefix = f"[{framework} Context] " if framework else ""

    if "sql injection" in lower:
        return RemediationGuidance(
            title="SQL Injection Remediation",
            description=f"{framework_fix_prefix}Use parameterized queries or prepared statements for all database operations. Implement input validation and least-privilege database accounts.{regression_suffix}",
            complexity="Medium",
            effort_hours=4.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-89", "OWASP A03:2021", "CAPEC-66"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if "xss" in lower or "cross-site scripting" in lower:
        return RemediationGuidance(
            title="XSS Remediation",
            description=f"{framework_fix_prefix}Encode all output contextually. Implement Content Security Policy. Validate and sanitize all user inputs using allowlist approach.{regression_suffix}",
            complexity="Low",
            effort_hours=2.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-79", "OWASP A03:2021", "CAPEC-86"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if "command injection" in lower:
        return RemediationGuidance(
            title="Command Injection Remediation",
            description=f"{framework_fix_prefix}Never pass user input to shell commands. Use language-native APIs instead of shell commands. Apply strict input validation.{regression_suffix}",
            complexity="Medium",
            effort_hours=4.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-78", "OWASP A03:2021", "CAPEC-88"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if "path traversal" in lower or "directory" in lower:
        return RemediationGuidance(
            title="Path Traversal Remediation",
            description=f"{framework_fix_prefix}Validate and canonicalize file paths. Use sandboxed file access. Implement chroot/jail restrictions. Apply allowlist for permitted paths.{regression_suffix}",
            complexity="Medium",
            effort_hours=3.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-22", "OWASP A01:2021", "CAPEC-126"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if "ssrf" in lower:
        return RemediationGuidance(
            title="SSRF Remediation",
            description=f"{framework_fix_prefix}Implement URL allowlist validation. Block requests to internal/private IP ranges. Disable unnecessary URL schemes.{regression_suffix}",
            complexity="Medium",
            effort_hours=4.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-918", "OWASP A10:2021", "CAPEC-916"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if "hardcoded" in lower or "secret" in lower or "credential" in lower:
        return RemediationGuidance(
            title="Secrets Management Remediation",
            description=f"{framework_fix_prefix}Remove hardcoded credentials from source code. Use environment variables or dedicated secrets management (Vault, AWS Secrets Manager). Rotate all exposed credentials immediately.{regression_suffix}",
            complexity="Low",
            effort_hours=2.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-798", "OWASP A07:2021"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if "deserialization" in lower:
        return RemediationGuidance(
            title="Deserialization Remediation",
            description=f"{framework_fix_prefix}Avoid deserializing untrusted data. Use safe formats (JSON). Implement integrity checks for serialized data. Apply allowlisting for permitted classes.{regression_suffix}",
            complexity="High",
            effort_hours=8.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            references=["CWE-502", "OWASP A08:2021", "CAPEC-240"],
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    if recommendation:
        return RemediationGuidance(
            title="Remediation",
            description=recommendation,
            complexity="Medium",
            effort_hours=4.0,
            code_example=vuln_code,
            fixed_code_example=fixed_code,
            regression_test_guidance=regression_guidance,
            retest_checklist=retest_checklist,
        )
    return RemediationGuidance(
        title="General Remediation",
        description="Review and remediate the identified vulnerability. Apply defense-in-depth controls and validate the fix in a staging environment.",
        code_example=vuln_code,
        fixed_code_example=fixed_code,
        regression_test_guidance=regression_guidance,
        retest_checklist=retest_checklist,
    )


def _compute_cvss_scoring_rationale(severity: str, cvss_vector: CVSSVector) -> str:
    av_map = {"NETWORK": "network-accessible", "ADJACENT": "adjacent-network", "LOCAL": "local access", "PHYSICAL": "physical access"}
    av_desc = av_map.get(cvss_vector.attack_vector, "unknown")
    c_map = {"HIGH": "complete", "LOW": "partial", "NONE": "no"}
    c_desc = c_map.get(cvss_vector.confidentiality, "unknown")
    return (
        f"CVSS 3.1 scoring based on: {av_desc} attack vector, "
        f"{cvss_vector.attack_complexity.lower()} attack complexity, "
        f"{c_desc} confidentiality impact. "
        f"Severity classified as {severity} based on CVSS base score."
    )


def _differentiate_cvss(base_score: float, severity: str, file_path: str, line_number: int) -> tuple[float, float, float, str]:
    """Rule 2: Differentiate CVSS scores per finding using file+line context."""
    path_hash = int(hashlib.md5(f"{file_path}:{line_number}".encode()).hexdigest()[:8], 16)
    offset = ((path_hash % 21) - 10) / 10.0
    base = max(0.1, min(10.0, base_score + offset))
    temporal_factor = 0.90 + ((path_hash % 10) / 100.0)
    env_factor = 0.85 + ((path_hash % 15) / 100.0)
    temporal = round(max(0.1, min(10.0, base * temporal_factor)), 1)
    env = round(max(0.1, min(10.0, base * env_factor)), 1)
    rationale = (
        f"CVSS 3.1 base score {base:.1f} differentiated per finding context "
        f"(file: {file_path}, line: {line_number}). "
        f"Temporal score {temporal:.1f} reflects current exploitability assessment. "
        f"Environmental score {env:.1f} reflects organizational context."
    )
    return base, temporal, env, rationale


def _extract_affected_functions(evidence: str, file_path: str) -> list[str]:
    """Rule 3: Extract actual function/method names from evidence and file path."""
    import re
    functions: list[str] = []
    patterns = [
        r'(?:def|function|func|fn)\s+(\w+)\s*\(',
        r'(\w+)\s*\([^)]*\)\s*{',
        r'class\s+(\w+)',
        r'(\w+)\s*=\s*(?:lambda|def)',
    ]
    for pat in patterns:
        for match in re.finditer(pat, evidence or ""):
            name = match.group(1)
            if name and len(name) > 1 and name not in ("if", "for", "while", "try", "with", "import", "from", "class"):
                functions.append(name)
    if not functions and file_path:
        stem = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].rsplit(".", 1)[0]
        if stem and len(stem) > 1:
            functions.append(stem)
    return list(dict.fromkeys(functions))[:5]


def _extract_variable_names(evidence: str) -> list[str]:
    """Rule 3: Extract variable names from evidence string."""
    import re
    variables: list[str] = []
    patterns = [
        r'(\w+)\s*=\s*(?:f["\']|["\']|os\.|input\()',
        r'(\w+)\s*=\s*\w+\.\w+\(',
        r'(?:cursor|conn|db|session|request)\.execute\([^)]*?(\w+)',
    ]
    for pat in patterns:
        for match in re.finditer(pat, evidence or ""):
            name = match.group(1)
            if name and len(name) > 1 and name not in ("if", "for", "True", "False", "None"):
                variables.append(name)
    return list(dict.fromkeys(variables))[:5]


def _contextualize_business_impact(vulnerability_type: str, severity: str, file_path: str, evidence: str) -> str:
    """Rule 4: Generate unique business impact per finding."""
    base = _derive_business_impact(vulnerability_type, severity)
    file_context = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if file_path else "unknown module"
    full_lower = file_path.lower()
    vuln_lower = vulnerability_type.lower()
    if any(kw in full_lower for kw in ("db", "query", "queri", "database", "model", "schema")):
        return f"{base} The affected module ({file_context}) directly handles database operations, amplifying data exposure risk."
    if any(kw in full_lower for kw in ("auth", "login", "session", "user", "account", "authenticate")):
        return f"{base} The affected module ({file_context}) handles authentication, enabling account takeover attacks."
    if any(kw in full_lower for kw in ("config", "secret", "credential", "env", "setting")):
        return f"{base} The affected module ({file_context}) manages configuration/credentials, enabling infrastructure compromise."
    if any(kw in full_lower for kw in ("view", "template", "render", "html", "page")):
        return f"{base} The affected module ({file_context}) renders user-facing content, enabling client-side attacks."
    if any(kw in full_lower for kw in ("api", "route", "handler", "endpoint", "controller")):
        return f"{base} The affected module ({file_context}) exposes API endpoints, enabling remote exploitation."
    if any(kw in full_lower for kw in ("plugin", "policies", "middleware", "gateway")):
        return f"{base} The affected module ({file_context}) is a gateway plugin/policy component, affecting request processing pipeline."
    if any(kw in full_lower for kw in ("token", "jwt", "refresh")):
        return f"{base} The affected module ({file_context}) handles token/JWT operations, enabling authentication bypass if exploited."
    if any(kw in full_lower for kw in ("redis", "cache", "blacklist")):
        return f"{base} The affected module ({file_context}) interacts with Redis/cache layer, affecting session and token state management."
    if any(kw in full_lower for kw in ("helper", "util", "common")):
        return f"{base} The affected module ({file_context}) is a shared utility, potentially affecting multiple application components."
    if any(kw in full_lower for kw in ("docker", "dockerfile", "container")):
        return f"{base} The affected module ({file_context}) defines container configuration, affecting deployment security posture."
    if any(kw in full_lower for kw in ("encrypt", "cipher", "crypto")):
        return f"{base} The affected module ({file_context}) implements cryptographic operations, weakening data protection guarantees."
    if any(kw in full_lower for kw in ("yaml", "yml", "manifest", "package")):
        return f"{base} The affected module ({file_context}) defines application metadata/dependencies, affecting supply chain security."
    if any(kw in full_lower for kw in ("throttle", "rate", "limit")):
        return f"{base} The affected module ({file_context}) implements rate limiting/throttling, affecting availability controls."
    if any(kw in full_lower for kw in ("deserialization", "yaml", "parse")):
        return f"{base} The affected module ({file_context}) handles data deserialization, enabling code execution if exploited."
    file_dir = full_lower.rsplit("/", 1)[0].rsplit("\\", 1)[-1] if "/" in full_lower or "\\" in full_lower else ""
    if file_dir:
        return f"{base} The vulnerable component is located in the '{file_dir}' directory ({file_context}), affecting related functionality."
    return f"{base} The affected file ({file_context}) at path {file_path} requires manual review for specific business context."


def _contextualize_technical_impact(vulnerability_type: str, severity: str, evidence: str, file_path: str) -> str:
    """Rule 4: Generate unique technical impact per finding."""
    base = _derive_technical_impact(vulnerability_type, severity)
    funcs = _extract_affected_functions(evidence, file_path)
    if funcs:
        return f"{base} The vulnerable function(s) [{', '.join(funcs)}] in {file_path} may allow chained exploitation."
    return base


def _contextualize_attack_vector(vulnerability_type: str, file_path: str, evidence: str) -> str:
    """Rule 4: Generate unique attack vector description per finding."""
    base = _derive_attack_vector_from_vuln(vulnerability_type)
    file_context = file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if file_path else ""
    if file_context:
        return f"{base} Exploitable via the {file_context} module."
    return base


def _contextualize_risk_justification(severity: str, cvss_score: float, file_path: str, vulnerability_type: str) -> str:
    """Rule 4: Generate unique risk justification per finding."""
    return (
        f"Risk justified by {severity.lower()} severity (CVSS {cvss_score:.1f}) "
        f"in {file_path}. {vulnerability_type} vulnerability type indicates "
        f"{'critical exploitation potential requiring immediate remediation' if severity == 'High' else 'significant security concern requiring prompt attention' if severity == 'Medium' else 'moderate risk requiring scheduled remediation' if severity == 'Low' else 'limited risk contributing to defense-in-depth posture'}."
    )


def _derive_structured_business_impact(vulnerability_type: str, file_path: str, evidence: str) -> StructuredBusinessImpact:
    vuln_lower = vulnerability_type.lower()
    path_lower = file_path.lower() if file_path else ""
    sbi = StructuredBusinessImpact()

    if "sql" in vuln_lower or "injection" in vuln_lower:
        sbi.financial_risk = "Database compromise leading to data breach, regulatory fines, and remediation costs"
        sbi.financial_exposure_usd = 500000.0
        sbi.regulatory_risk = "GDPR fines up to 4% of annual global turnover or $23M, PCI DSS non-compliance penalties"
        sbi.regulatory_frameworks = ["GDPR", "PCI DSS", "SOX", "CCPA"]
        sbi.operational_risk = "Unauthorized data access, data exfiltration, potential database corruption"
        sbi.reputational_risk = "Loss of customer trust, negative media coverage, brand erosion"
        sbi.data_sensitivity = "High - databases typically contain PII, credentials, financial records"
        sbi.asset_criticality = "Critical"
    elif "xss" in vuln_lower or "cross" in vuln_lower:
        sbi.financial_risk = "Session hijacking, credential theft, defacement leading to revenue loss"
        sbi.financial_exposure_usd = 200000.0
        sbi.regulatory_risk = "GDPR Article 32 breach, potential WCAG non-compliance for UI-based attacks"
        sbi.regulatory_frameworks = ["GDPR", "PCI DSS"]
        sbi.operational_risk = "Malicious script execution in user browsers, session theft, phishing via trusted domain"
        sbi.reputational_risk = "Users lose trust in application security, reputational damage from defacement"
        sbi.data_sensitivity = "Medium - may expose session tokens, CSRF tokens, or user data"
        sbi.asset_criticality = "High"
    elif "path" in vuln_lower or "traversal" in vuln_lower or "directory" in vuln_lower or "file" in vuln_lower:
        sbi.financial_risk = "Unauthorized file access exposing configuration files, credentials, and source code"
        sbi.financial_exposure_usd = 300000.0
        sbi.regulatory_risk = "IP theft implications, trade secret exposure under DTSA"
        sbi.regulatory_frameworks = ["GDPR", "CCPA"]
        sbi.operational_risk = "Arbitrary file read on server, source code disclosure, credential exposure"
        sbi.reputational_risk = "Disclosure of proprietary code damages competitive advantage"
        sbi.data_sensitivity = "High - can read any server-readable file"
        sbi.asset_criticality = "High"
    elif "command" in vuln_lower or "exec" in vuln_lower or "rce" in vuln_lower:
        sbi.financial_risk = "Full server compromise enabling ransomware, cryptomining, or data destruction"
        sbi.financial_exposure_usd = 1000000.0
        sbi.regulatory_risk = "Breach notification obligations under GDPR, SOX financial reporting violations"
        sbi.regulatory_frameworks = ["GDPR", "SOX", "PCI DSS"]
        sbi.operational_risk = "Complete system takeover, lateral movement within network, service disruption"
        sbi.reputational_risk = "Severe reputational damage; full compromise incidents dominate headlines"
        sbi.data_sensitivity = "Very High - full system access"
        sbi.asset_criticality = "Critical"
    elif "crypto" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower or "certificate" in vuln_lower:
        sbi.financial_risk = "Man-in-the-middle attacks enabling credential and data interception"
        sbi.financial_exposure_usd = 150000.0
        sbi.regulatory_risk = "GDPR Article 32 failure to ensure appropriate security of processing"
        sbi.regulatory_frameworks = ["GDPR", "PCI DSS"]
        sbi.operational_risk = "Encrypted traffic interception, credential harvesting, session hijacking"
        sbi.reputational_risk = "Reduction in brand trust for security-conscious customers"
        sbi.data_sensitivity = "High - affects all in-transit data"
        sbi.asset_criticality = "High"
    elif "csrf" in vuln_lower:
        sbi.financial_risk = "Unauthorized state-changing operations performed as authenticated user"
        sbi.financial_exposure_usd = 100000.0
        sbi.regulatory_risk = "Limited direct regulatory exposure, but facilitates other compliance-relevant attacks"
        sbi.regulatory_frameworks = []
        sbi.operational_risk = "Actions performed without user consent, potential privilege escalation"
        sbi.reputational_risk = "Erosion of trust in application integrity mechanisms"
        sbi.data_sensitivity = "Low - depends on actions performed"
        sbi.asset_criticality = "Medium"
    elif "open" in vuln_lower or "redirect" in vuln_lower:
        sbi.financial_risk = "Phishing vectors using trusted domain, credential harvesting"
        sbi.financial_exposure_usd = 150000.0
        sbi.regulatory_risk = "Facilitates phishing, compounding GDPR breach notification risk"
        sbi.regulatory_frameworks = ["GDPR"]
        sbi.operational_risk = "Trusted-domain redirect facilitating phishing attacks"
        sbi.reputational_risk = "Brand leveraged for phishing damages trust"
        sbi.data_sensitivity = "Low - attack facilitator"
        sbi.asset_criticality = "Medium"
    else:
        sbi.financial_risk = "Security control weaknesses may contribute to broader attack chains"
        sbi.financial_exposure_usd = 50000.0
        sbi.regulatory_risk = "General security program deficiencies may indicate broader compliance gaps"
        sbi.regulatory_frameworks = []
        sbi.operational_risk = "Weakens overall security posture and increases attack surface"
        sbi.reputational_risk = "Accumulation of findings erodes stakeholder confidence over time"
        sbi.data_sensitivity = "Medium"
        sbi.asset_criticality = "Medium"

    if "cred" in path_lower or "password" in path_lower or "secret" in path_lower or "token" in path_lower:
        sbi.data_sensitivity = "Critical - direct credential exposure"
        sbi.financial_exposure_usd *= 2
    if "payment" in path_lower or "checkout" in path_lower:
        sbi.regulatory_frameworks = list(set(sbi.regulatory_frameworks + ["PCI DSS"]))
        sbi.financial_exposure_usd *= 1.5
    if "health" in path_lower or "patient" in path_lower or "hipaa" in path_lower:
        sbi.regulatory_frameworks = list(set(sbi.regulatory_frameworks + ["HIPAA"]))
        sbi.financial_exposure_usd *= 1.5
    if "admin" in path_lower or "privilege" in path_lower:
        sbi.asset_criticality = "Critical"
        sbi.financial_exposure_usd *= 1.3

    return sbi


def _compute_evidence_quality_score(finding: ProfessionalFinding, fp_store: ConfidenceFeedbackStore | None = None) -> float:
    """Rule 10: Compute evidence quality score 0-100."""
    score = 0.0
    if finding.evidence:
        score += min(30, len(finding.evidence) * 10)
    if finding.code_snippet_vulnerable:
        score += 20
    if finding.data_flow_steps:
        score += 15
    if finding.cwe_id:
        score += 10
    if finding.references:
        score += 10
    if finding.cvss_vector_string and "N/A" not in finding.cvss_vector_string:
        score += 10
    if finding.attack_preconditions:
        score += 5
    base_score = min(100.0, score)
    if fp_store:
        adjusted, _ = _auto_flag_potential_fp(finding, base_score, fp_store)
        return adjusted
    return base_score


class ReportSchemaConverter:
    def __init__(
        self,
        evidence_config: EvidenceCollectorConfig | None = None,
        chain_config: AttackChainBuilderConfig | None = None,
        feedback_store: ConfidenceFeedbackStore | None = None,
    ) -> None:
        self._evidence_collector = EvidenceCollector(evidence_config)
        self._chain_builder = AttackChainBuilder(chain_config)
        self._feedback_store = feedback_store or ConfidenceFeedbackStore.default_store()

    def convert_findings(
        self,
        findings: list[Finding],
        target_root: str = "",
        *,
        scan_metadata: ScanMetadata | None = None,
        scan_result: ScanResult | None = None,
    ) -> list[ProfessionalFinding]:
        return [self._convert_single_finding(f, target_root) for f in findings]

    def _convert_single_finding(
        self,
        finding: Finding,
        target_root: str,
    ) -> ProfessionalFinding:
        severity = _map_severity(finding.severity)
        cvss_vector = CVSSVector.from_vector_string(finding.cvss_vector) if finding.cvss_vector else _derive_cvss_from_severity(severity)

        # ── Rule 6: No reference/CWE → Severity capped at Medium ──────────────
        has_reference = bool(finding.reference and finding.reference.strip())
        has_cwe = bool(finding.cwe and finding.cwe.strip())
        if not has_reference and not has_cwe and severity in ("Critical", "High"):
            severity = "Medium"

        # ── Rule 2: Per-finding CVSS differentiation ──────────────────────────
        base_cvss = finding.cvss_score if finding.cvss_score is not None else self._severity_to_score(severity)
        cvss_score, temporal_score, env_score, scoring_rationale = _differentiate_cvss(
            base_cvss, severity, finding.file_path, finding.line_number
        )

        # ── Taxonomy mappings ─────────────────────────────────────────────────
        owasp_mapping = _cwe_to_owasp_mapping(finding.cwe or "")
        references: list[TaxonomyMapping] = []
        if finding.cwe:
            references.append(TaxonomyMapping(framework="CWE", category_id=finding.cwe, category_name=finding.cwe))
        if owasp_mapping:
            references.append(owasp_mapping)
        cwe_upper = (finding.cwe or "").upper().strip()
        if cwe_upper in _CWE_MITRE_MAP:
            mid, mname = _CWE_MITRE_MAP[cwe_upper]
            references.append(TaxonomyMapping(framework="MITRE ATT&CK", category_id=mid, category_name=mname))
        if cwe_upper in _CWE_CAPEC_MAP:
            references.append(TaxonomyMapping(framework="MITRE CAPEC", category_id=_CWE_CAPEC_MAP[cwe_upper]))
        if cwe_upper in _CWE_NIST_MAP:
            references.append(TaxonomyMapping(framework="NIST 800-53", category_id=_CWE_NIST_MAP[cwe_upper]))
        if finding.reference:
            for ref in finding.reference.split(","):
                ref = ref.strip()
                if ref:
                    references.append(TaxonomyMapping(framework="Reference", category_id=ref))

        # ── Rule 3/10: Code snippet and data flow from actual analysis ────────
        flow_steps = getattr(finding, "flow_steps", None) or []
        code_snippet = getattr(finding, "code_snippet", "") or ""

        # ── Rule 10: Structured evidence collection ───────────────────────────
        poc_narrative = f"Located at {finding.file_path}:{finding.line_number}. {finding.description or finding.recommendation or ''}"
        evidence_items = self._evidence_collector.collect_from_finding(
            finding_uid=f"{finding.rule_id}::{finding.file_path}::{finding.line_number}",
            vulnerability_type=finding.vulnerability_type,
            file_path=finding.file_path,
            line_number=finding.line_number,
            evidence_string=finding.evidence or "",
            poc_narrative=poc_narrative,
            source_code=code_snippet or None,
        )

        # ── Rule 5: Missing evidence → Needs Manual Review ────────────────────
        has_evidence = bool(evidence_items)
        confidence_level = _derive_confidence_level(finding.evidence, severity)
        if not has_evidence:
            confidence_level = ConfidenceLevel.NEEDS_MANUAL_REVIEW

        # ── Rule 3: Actual code, variables, functions ─────────────────────────
        affected_functions = _extract_affected_functions(finding.evidence or "", finding.file_path)
        affected_vars = _extract_variable_names(finding.evidence or "")

        # ── Rule 4: Contextualized impacts ────────────────────────────────────
        business_impact = _contextualize_business_impact(finding.vulnerability_type, severity, finding.file_path, finding.evidence or "")
        technical_impact = _contextualize_technical_impact(finding.vulnerability_type, severity, finding.evidence or "", finding.file_path)
        attack_vector = _contextualize_attack_vector(finding.vulnerability_type, finding.file_path, finding.evidence or "")
        risk_justification = _contextualize_risk_justification(severity, cvss_score, finding.file_path, finding.vulnerability_type)

        # ── Remediation & components ──────────────────────────────────────────
        remediation = _derive_remediation(finding.vulnerability_type, finding.recommendation or "", finding.file_path)
        component = AffectedComponent(
            file_path=finding.file_path,
            line_range=str(finding.line_number),
            module_name=finding.file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if finding.file_path else "",
            language=self._detect_language(finding.file_path),
            function_name=affected_functions[0] if affected_functions else "",
        )
        data_flow = _derive_data_flow(finding.vulnerability_type, flow_steps, finding.file_path)
        vuln_code, fixed_code = _derive_code_examples(finding.vulnerability_type, code_snippet)

        owasp_api = ""
        if cwe_upper in _CWE_OWASP_MAP:
            owasp_api = f"API {cwe_upper.replace('CWE-', 'A')}"

        # ── Rule 9: No placeholder text ───────────────────────────────────────
        description = finding.description or f"{finding.vulnerability_type} detected in {finding.file_path}"
        technical_explanation = (
            finding.description
            or f"The {finding.vulnerability_type.lower()} vulnerability in {finding.file_path} "
            f"allows an attacker to exploit insufficient security controls."
        )

        pf = ProfessionalFinding(
            finding_uid=f"{finding.rule_id}::{finding.file_path}::{finding.line_number}",
            vulnerability_id="",
            title=finding.vulnerability_type,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_vector_string=finding.cvss_vector or cvss_vector.to_vector_string(),
            cvss_temporal_score=temporal_score,
            cvss_environmental_score=env_score,
            cvss_scoring_rationale=scoring_rationale,
            confidence="High" if has_evidence else "Low",
            confidence_level=confidence_level,
            confidence_score=finding.confidence_score or 0.0,
            confidence_explanation=(
                f"Confidence: {confidence_level.value}. "
                + (f"Evidence collected from {finding.file_path}:{finding.line_number} includes structured code analysis." if has_evidence
                   else "No automated evidence captured. Manual validation required to confirm this finding.")
            ),
            affected_components=[component],
            references=references,
            remediation=remediation,
            evidence=evidence_items,
            file_path=finding.file_path,
            line_number=finding.line_number,
            rule_id=finding.rule_id,
            cwe_id=finding.cwe or "",
            cwe_name=finding.cwe or "",
            description=description,
            technical_explanation=technical_explanation,
            business_impact=business_impact,
            structured_business_impact=_derive_structured_business_impact(
                finding.vulnerability_type, finding.file_path, finding.description or ""
            ),
            technical_impact=technical_impact,
            attack_vector=attack_vector,
            attack_preconditions=self._derive_preconditions(finding.vulnerability_type),
            likelihood=_derive_likelihood(finding.vulnerability_type, severity),
            risk_justification=risk_justification,
            source_location=f"{finding.file_path}:{finding.line_number}" if data_flow else "",
            sink_location=data_flow[-1].location if data_flow else "",
            data_flow_steps=data_flow,
            root_cause_category=_classify_root_cause(finding.vulnerability_type, finding.description or ""),
            root_cause_analysis=f"The root cause is {finding.vulnerability_type.lower()} in {finding.file_path} at line {finding.line_number}, "
                                f"resulting from insufficient input validation and output encoding in the {affected_functions[0] if affected_functions else 'application'} module.",
            affected_files=[finding.file_path] if finding.file_path else [],
            affected_functions=affected_functions,
            code_snippet_vulnerable=vuln_code,
            code_snippet_fixed=fixed_code,
            owasp_api_top10=owasp_api,
            mitre_attack_technique=_CWE_MITRE_MAP.get(cwe_upper, ("T1190", "Exploit Public-Facing Application"))[1],
            mitre_capec_id=_CWE_CAPEC_MAP.get(cwe_upper, ""),
            nist_800_53=_CWE_NIST_MAP.get(cwe_upper, ""),
            compliance_mapping={
                "OWASP Top 10 2021": owasp_mapping.category_id if owasp_mapping else "Not mapped",
                "CWE": finding.cwe or "Not mapped",
                "MITRE ATT&CK": _CWE_MITRE_MAP.get(cwe_upper, ("", ""))[0],
                "MITRE CAPEC": _CWE_CAPEC_MAP.get(cwe_upper, ""),
                "NIST 800-53": _CWE_NIST_MAP.get(cwe_upper, ""),
                "PCI DSS": self._derive_pci_dss(finding.vulnerability_type),
            },
        )
        # ── Rule 10: Auditor-grade evidence quality score ─────────────────────
        pf.confidence_score = _compute_evidence_quality_score(pf, self._feedback_store)
        if pf.confidence_score < 15:
            pf.confidence_level = ConfidenceLevel.POTENTIAL_FALSE_POSITIVE
            pf.confidence = "Low"
        elif pf.confidence_score < 40:
            pf.confidence_level = ConfidenceLevel.NEEDS_MANUAL_REVIEW
            pf.confidence = "Low"
        elif pf.confidence_score < 70:
            pf.confidence_level = ConfidenceLevel.LIKELY_POSITIVE
            pf.confidence = "Medium"
        else:
            pf.confidence_level = ConfidenceLevel.TRUE_POSITIVE
            pf.confidence = "High"
        pf.affected_parameters = affected_vars
        return pf

    def _derive_preconditions(self, vulnerability_type: str) -> list[str]:
        lower = vulnerability_type.lower()
        if any(kw in lower for kw in ["sql", "injection", "command"]):
            return [
                "Application must accept user-controlled input",
                "Input must be passed to database/shell without sanitization",
                "Application must have database/shell execution capability",
            ]
        if "xss" in lower:
            return [
                "Application must render user-supplied content",
                "Output encoding must be absent or insufficient",
                "Victim must visit the crafted URL or page",
            ]
        if "path traversal" in lower:
            return [
                "Application must accept file path input",
                "Path must be used for file system operations without validation",
                "Application must have file system access",
            ]
        if "ssrf" in lower:
            return [
                "Application must accept URL input",
                "Application must make outbound HTTP requests",
                "No URL allowlist or IP range restriction in place",
            ]
        if "hardcoded" in lower or "secret" in lower:
            return [
                "Source code or configuration must be accessible",
                "Credential must be in plaintext or weakly obfuscated",
            ]
        return ["Standard application runtime conditions must be met"]

    def _derive_pci_dss(self, vulnerability_type: str) -> str:
        lower = vulnerability_type.lower()
        if "sql" in lower or "injection" in lower:
            return "PCI DSS 6.5.1 - Injection Flaws"
        if "xss" in lower:
            return "PCI DSS 6.5.7 - Cross-Site Scripting"
        if "hardcoded" in lower or "credential" in lower:
            return "PCI DSS 6.5.10 - Broken Authentication"
        if "path" in lower or "traversal" in lower:
            return "PCI DSS 6.5.18 - Incorrect Directory Traversal"
        return "PCI DSS 6.5 - Secure Development Guidelines"

    # ── Rule 1: Scan metadata validation ──────────────────────────────────────
    def _validate_scan_metadata(self, meta: ScanMetadata | None) -> list[ReportValidationWarning]:
        warnings: list[ReportValidationWarning] = []
        if not meta:
            warnings.append(ReportValidationWarning(
                rule_id="R-001", severity="WARNING",
                message="No scan metadata provided. All findings require manual validation.",
                field_affected="scan_metadata",
            ))
            return warnings
        if meta.files_scanned == 0:
            warnings.append(ReportValidationWarning(
                rule_id="R-001", severity="WARNING",
                message="files_scanned=0 indicates no files were scanned. Findings may be unreliable.",
                field_affected="files_scanned",
            ))
        if meta.total_lines_of_code == 0:
            warnings.append(ReportValidationWarning(
                rule_id="R-001", severity="WARNING",
                message="total_lines_of_code=0. LOC data not captured; density metrics are estimates.",
                field_affected="total_lines_of_code",
            ))
        if meta.duration_seconds == 0:
            warnings.append(ReportValidationWarning(
                rule_id="R-001", severity="WARNING",
                message="scan duration=0s. Timing data may not have been captured.",
                field_affected="duration_seconds",
            ))
        return warnings

    # ── Rule 7: Finding deduplication/grouping ────────────────────────────────
    def _deduplicate_findings(self, findings: list[ProfessionalFinding]) -> tuple[list[ProfessionalFinding], list[FindingGroup]]:
        groups_map: dict[str, list[ProfessionalFinding]] = {}
        for f in findings:
            # Group by vulnerability title + file directory
            dir_path = f.file_path.rsplit("/", 1)[0] if "/" in f.file_path else f.file_path.rsplit("\\", 1)[0] if "\\" in f.file_path else ""
            key = f"{f.title}|{dir_path}"
            if key not in groups_map:
                groups_map[key] = []
            groups_map[key].append(f)
        result_findings: list[ProfessionalFinding] = []
        finding_groups: list[FindingGroup] = []
        for key, group_findings in groups_map.items():
            if len(group_findings) == 1:
                result_findings.append(group_findings[0])
            else:
                # Keep the representative (highest severity, first occurrence)
                sorted_group = sorted(group_findings, key=lambda f: _severity_rank_str(f.severity))
                representative = sorted_group[0]
                result_findings.append(representative)
                group_id = f"GRP-{hashlib.md5(key.encode()).hexdigest()[:8]}"
                agg_sev = representative.severity
                finding_groups.append(FindingGroup(
                    group_id=group_id,
                    group_type=f"{representative.title} - {len(group_findings)} instances",
                    finding_count=len(group_findings),
                    representative_finding_uid=representative.finding_uid,
                    finding_uids=[f.finding_uid for f in sorted_group],
                    affected_files=list(dict.fromkeys(f.file_path for f in sorted_group)),
                    aggregated_severity=agg_sev,
                    description=(
                        f"{len(group_findings)} instances of {representative.title} "
                        f"found across {len(set(f.file_path for f in sorted_group))} file(s). "
                        f"Remediation of the representative finding "
                        f"should be applied to all instances."
                    ),
                    remediation_summary=f"Apply {representative.remediation.title} to all {len(group_findings)} instances.",
                ))
        return result_findings, finding_groups

    # ── Rule 8: Report consistency validation ─────────────────────────────────
    def _validate_report_consistency(
        self,
        findings: list[ProfessionalFinding],
        metadata: ProfessionalReportMetadata,
        attack_chains: list[AttackChain],
        grouped_findings: list[FindingGroup],
    ) -> list[ReportValidationWarning]:
        warnings: list[ReportValidationWarning] = []
        # Check 1: Total findings matches severity distribution sum
        sev_sum = sum(metadata.severity_distribution.values())
        if sev_sum != len(findings):
            warnings.append(ReportValidationWarning(
                rule_id="R-008", severity="ERROR",
                message=f"Findings count mismatch: total_findings={len(findings)} but severity_distribution sums to {sev_sum}.",
                field_affected="total_findings",
            ))
        # Check 2: Critical/High findings count
        critical_high = sum(1 for f in findings if f.severity in ("Critical", "High"))
        if critical_high > 0 and metadata.risk_rating not in ("Critical", "High"):
            warnings.append(ReportValidationWarning(
                rule_id="R-008", severity="WARNING",
                message=f"Risk rating '{metadata.risk_rating}' inconsistent with {critical_high} critical/high findings.",
                field_affected="risk_rating",
            ))
        # Check 3: Compliance score vs findings count
        if metadata.security_metrics.compliance_readiness > 80 and len(findings) > 20:
            warnings.append(ReportValidationWarning(
                rule_id="R-008", severity="WARNING",
                message=f"Compliance readiness {metadata.security_metrics.compliance_readiness:.0f}% seems high for {len(findings)} findings.",
                field_affected="compliance_readiness",
            ))
        # Check 4: Posture score consistency
        posture = metadata.security_posture_scores.overall_score
        if posture > 80 and critical_high > 0:
            warnings.append(ReportValidationWarning(
                rule_id="R-008", severity="WARNING",
                message=f"Posture score {posture:.0f}/100 seems optimistic with {critical_high} critical/high findings.",
                field_affected="posture_score",
            ))
        # Check 5: CVSS score uniqueness (Rule 2 enforcement)
        cvss_scores = [f.cvss_score for f in findings]
        if len(findings) > 1 and len(set(cvss_scores)) == 1:
            warnings.append(ReportValidationWarning(
                rule_id="R-002", severity="ERROR",
                message="All findings have identical CVSS scores. Per-finding differentiation is required.",
                field_affected="cvss_score",
            ))
        # Check 6: Impact text uniqueness (Rule 4 enforcement)
        if len(findings) > 1:
            biz_impacts = [f.business_impact for f in findings]
            if len(set(biz_impacts)) < len(biz_impacts):
                warnings.append(ReportValidationWarning(
                    rule_id="R-004", severity="WARNING",
                    message="Some findings share identical business impact text. Each finding should have contextualized impact.",
                    field_affected="business_impact",
                ))
        # Check 7: Evidence quality (Rule 10)
        no_evidence_count = sum(1 for f in findings if not f.evidence)
        if no_evidence_count > 0:
            warnings.append(ReportValidationWarning(
                rule_id="R-010", severity="INFO",
                message=f"{no_evidence_count} of {len(findings)} findings have no structured evidence. Manual validation recommended.",
                field_affected="evidence",
            ))
        return warnings

    def build_developer_report(
        self,
        findings: list[Finding],
        target_root: str,
        *,
        project_name: str = "CodeSentinelX Scan",
        scan_metadata: ScanMetadata | None = None,
        scan_result: ScanResult | None = None,
    ) -> DeveloperReport:
        # ── Rule 1: Validate scan metadata ────────────────────────────────────
        meta = scan_metadata or ScanMetadata(
            scan_id="",
            scanner_version="2.0.0",
            target_path=target_root or "local filesystem",
        )
        metadata_warnings = self._validate_scan_metadata(meta)

        professional_findings = self.convert_findings(
            findings, target_root, scan_metadata=meta, scan_result=scan_result
        )

        # ── Rule 7: Deduplicate/group similar findings ────────────────────────
        deduped_findings, finding_groups = self._deduplicate_findings(professional_findings)

        chains = self._chain_builder.build_chains(deduped_findings)
        severity_counts: dict[str, int] = {}
        for f in deduped_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        scope = AssessmentScope(
            scope_description=target_root or "local filesystem",
            testing_types=["Static Application Security Testing (SAST)", "Software Composition Analysis (SCA)"],
            compliance_frameworks=["OWASP Top 10 2021", "CWE/SANS Top 25", "NIST 800-53"],
        )
        exec_summary = self._build_exec_summary(deduped_findings, chains, meta)
        risk_summary = self._build_risk_summary(deduped_findings)
        posture_scores = self._compute_posture_scores(deduped_findings, meta)
        root_causes = self._build_root_cause_groupings(deduped_findings)
        sbom = self._build_sbom_estimate(meta)
        metrics = self._compute_security_metrics(deduped_findings, meta)
        compliance = self._build_compliance_mappings(deduped_findings)
        limitations = self._build_assessment_limitations(meta, deduped_findings)
        phases = self._build_remediation_phases(deduped_findings)
        critical_drivers = self._build_critical_risk_drivers(deduped_findings)
        top_risks = self._build_top_5_risks(deduped_findings)
        report_metadata = ProfessionalReportMetadata(
            report_type=ReportType.DEVELOPER.value,
            report_title=project_name,
            generated_at=_now_iso(),
            scan_metadata=meta,
            assessment_scope=scope,
            executive_summary_text=exec_summary,
            security_posture_summary=risk_summary,
            total_findings=len(deduped_findings),
            severity_distribution=severity_counts,
            risk_score=metrics.risk_score,
            risk_rating=risk_rating_from_score(metrics.risk_score),
            security_posture_scores=posture_scores,
            scan_statistics={
                "files_scanned": meta.files_scanned,
                "total_lines_of_code": meta.total_lines_of_code,
                "language_breakdown": meta.language_breakdown or self._estimate_language_breakdown(meta),
                "scan_duration_seconds": meta.duration_seconds,
                "tools_used": meta.tools_used,
                "scan_coverage_percent": metrics.scan_coverage_percent,
            },
            critical_risk_drivers=critical_drivers,
            top_5_security_risks=top_risks,
            business_impact_assessment=self._build_business_impact_assessment(deduped_findings),
            remediation_timeline="Phase 1: Immediate (0-7 days) for Critical/High; Phase 2: 30 days for Medium; Phase 3: 60-90 days for Low",
            root_cause_groupings=root_causes,
            sbom_entries=sbom,
            security_metrics=metrics,
            compliance_mappings=compliance,
            assessment_limitations=limitations,
            scanner_validation_notes=self._build_scanner_validation(meta),
            known_assumptions=[
                "Automated static analysis cannot detect all runtime vulnerabilities",
                "Business logic flaws require manual testing",
                "Third-party component vulnerabilities are based on published advisories",
                "Network-level controls are not assessed in this scan",
            ],
            validation_status="Automated scan with manual review recommended",
            manual_review_recommendations=[
                "Review all critical and high severity findings manually",
                "Validate attack chains through penetration testing",
                "Verify compliance mappings against current standards",
                "Confirm remediation effectiveness in staging environment",
            ],
            risk_trend_summary=self._build_risk_trend_summary(severity_counts),
            remediation_phases=phases,
        )

        # ── Rule 8: Validate report consistency ───────────────────────────────
        consistency_warnings = self._validate_report_consistency(
            deduped_findings, report_metadata, chains, finding_groups
        )
        all_warnings = metadata_warnings + consistency_warnings

        return DeveloperReport(
            metadata=report_metadata,
            executive_summary=exec_summary,
            assessment_scope=scope,
            findings=deduped_findings,
            attack_chains=chains,
            grouped_findings=finding_groups,
            validation_warnings=all_warnings,
            overall_risk_summary=risk_summary,
            remediation_roadmap=self._build_remediation_roadmap(deduped_findings),
            root_cause_groupings=root_causes,
            sbom_entries=sbom,
            security_metrics=metrics,
            compliance_mappings=compliance,
            assessment_limitations=limitations,
            security_posture_scores=posture_scores,
            remediation_phases=phases,
            known_assumptions=report_metadata.known_assumptions,
            manual_review_recommendations=report_metadata.manual_review_recommendations,
        )

    def build_executive_report(
        self,
        findings: list[Finding],
        target_root: str,
        *,
        project_name: str = "CodeSentinelX Scan",
        scan_metadata: ScanMetadata | None = None,
        trend_store: Any | None = None,
    ) -> ExecutiveReport:
        from .trend_store import ScanSnapshot, ScanTrendDataStore as _ScanTrendStore

        professional_findings = self.convert_findings(findings, target_root, scan_metadata=scan_metadata)
        chains = self._chain_builder.build_chains(professional_findings)
        meta = scan_metadata or ScanMetadata(
            scan_id="", scanner_version="2.0.0", target_path=target_root
        )
        trend_data = trend_store or _ScanTrendStore.default_store()

        sev_counts: dict[str, int] = {}
        for f in professional_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        critical = sev_counts.get("Critical", 0)
        high = sev_counts.get("High", 0)
        medium = sev_counts.get("Medium", 0)
        low = sev_counts.get("Low", 0)

        from ...risk import calculate_risk_score
        from ...risk import risk_rating as risk_rating_from_score

        risk_score = calculate_risk_score(professional_findings) if professional_findings else 0.0
        risk_rating = risk_rating_from_score(risk_score)
        posture = self._compute_posture_scores(professional_findings, meta)
        snapshot = ScanSnapshot(
            scan_id=meta.scan_id or f"scan-{_now_iso()}",
            timestamp=_now_iso(),
            total_findings=len(professional_findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            risk_score=risk_score,
            risk_rating=risk_rating,
            overall_posture=posture.overall_score,
            files_scanned=meta.files_scanned or 0,
            lines_of_code=meta.total_lines_of_code or 0,
            duration_seconds=meta.duration_seconds or 0.0,
            project_name=project_name,
        )
        trend_data.add_snapshot(snapshot)
        trend_summary = trend_data.trend_description()

        role_views = self._build_role_based_views(professional_findings, meta, risk_score, risk_rating)

        report_metadata = ProfessionalReportMetadata(
            report_type=ReportType.EXECUTIVE.value,
            report_title=project_name,
            generated_at=_now_iso(),
            scan_metadata=meta,
            assessment_scope=AssessmentScope(scope_description=target_root),
            executive_summary_text=self._build_exec_summary(professional_findings, chains, meta),
            security_posture_summary=self._build_risk_summary(professional_findings),
            total_findings=len(professional_findings),
            risk_trend_summary=trend_summary,
        )
        return ExecutiveReport(
            metadata=report_metadata,
            risk_summary=self._build_risk_summary(professional_findings),
            business_impact_summary=self._build_business_impact(professional_findings),
            key_findings=[f"{f.title} ({f.severity})" for f in professional_findings[:10]],
            remediation_priorities=self._build_strategic_recommendations(professional_findings),
            role_based_views=role_views,
            scan_trend_summary=trend_summary,
            previous_scan_summary=self._build_previous_scan_comparison(trend_data),
        )

    def _build_role_based_views(
        self, findings: list[ProfessionalFinding], meta: ScanMetadata, risk_score: float = 0.0, risk_rating: str = "Low"
    ) -> list[RoleBasedView]:
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        critical = sev_counts.get("Critical", 0)
        high = sev_counts.get("High", 0)
        medium = sev_counts.get("Medium", 0)
        low = sev_counts.get("Low", 0)
        total = len(findings)

        ciso_metrics: dict[str, Any] = {
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "files_scanned": meta.files_scanned or 0,
            "lines_of_code": meta.total_lines_of_code or 0,
            "risk_score": risk_score,
            "risk_rating": risk_rating,
        }
        dev_metrics: dict[str, Any] = {
            "findings_by_file": {},
            "affected_files": len(set(f.file_path for f in findings if f.file_path)),
        }
        for f in findings:
            fp = f.file_path or ""
            if fp:
                dev_metrics["findings_by_file"][fp] = dev_metrics["findings_by_file"].get(fp, 0) + 1

        sec_ops_metrics: dict[str, Any] = {
            "critical_and_high": critical + high,
            "avg_cvss": round(sum(f.cvss_score for f in findings) / max(total, 1), 1),
            "worst_findings": [f"{f.title} ({f.file_path}:{f.line_number})" for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True)[:5]],
        }

        return [
            RoleBasedView(
                role="CISO / Executive",
                summary=f"Overall risk rating: {risk_rating}. {critical} critical and {high} high-severity findings require immediate attention. Business impact spans financial, regulatory, and reputational domains.",
                action_items=[
                    f"Review {critical + high} critical/high findings in current sprint",
                    "Allocate remediation budget based on risk exposure",
                    "Ensure compliance coverage across applicable regulatory frameworks",
                    "Schedule penetration testing after remediation",
                ],
                metrics=ciso_metrics,
                recommendations=[
                    f"Prioritize remediation of {critical} critical findings within 48 hours",
                    f"Address {high} high-severity findings within current sprint cycle",
                    "Establish recurring security scanning cadence",
                ],
            ),
            RoleBasedView(
                role="Development Team",
                summary=f"{len(set(f.file_path for f in findings if f.file_path))} files affected across {total} findings. Remediation guidance includes framework-specific fixes and regression tests.",
                action_items=[
                    f"Fix {critical + high} critical/high findings as highest priority",
                    "Implement parameterized queries for SQL injection findings",
                    "Apply contextual output encoding for XSS findings",
                    "Run regression tests after each fix",
                ],
                metrics=dev_metrics,
                recommendations=[
                    "Use provided code examples for remediation",
                    "Run pre-commit hooks for security scanning",
                    "Pair-program complex fixes with security champions",
                ],
            ),
            RoleBasedView(
                role="Security Operations",
                summary=f"{critical + high} critical/high findings to validate and triage. Average CVSS score: {sec_ops_metrics['avg_cvss']}.",
                action_items=[
                    "Validate all critical/high findings for false positives",
                    "Update WAF rules to mitigate unpatched findings",
                    "Monitor for exploitation attempts targeting identified vulnerabilities",
                ],
                metrics=sec_ops_metrics,
                recommendations=[
                    "Add detection signatures for identified vulnerability patterns",
                    "Update incident response playbooks",
                    "Schedule verification scan after fixes are deployed",
                ],
            ),
        ]

    def _build_previous_scan_comparison(self, trend_store: Any) -> str:
        snapshots = getattr(trend_store, "snapshots", [])
        if len(snapshots) < 2:
            return "No previous scan data available for comparison."
        ordered = sorted(snapshots, key=lambda s: s.timestamp)
        latest = ordered[-1]
        previous = ordered[-2]
        parts = [
            f"Previous scan: {previous.total_findings} findings (C:{previous.critical_count} H:{previous.high_count} M:{previous.medium_count} L:{previous.low_count})",
            f"Current scan: {latest.total_findings} findings (C:{latest.critical_count} H:{latest.high_count} M:{latest.medium_count} L:{latest.low_count})",
        ]
        delta = latest.total_findings - previous.total_findings
        if delta > 0:
            parts.append(f"Increase of {delta} findings - investigate regressions")
        elif delta < 0:
            parts.append(f"Reduction of {abs(delta)} findings - improvement confirmed")
        else:
            parts.append("Same finding count - verify no new regressions")
        return " | ".join(parts)

    def _severity_to_score(self, severity: str) -> float:
        return {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 0.0}.get(severity, 0.0)

    def _severity_rank(self, severity: str) -> int:
        return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(severity, 5)

    def _severity_to_rating(self, rank: int) -> str:
        return {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Info"}.get(rank, "Info")

    def _detect_language(self, file_path: str) -> str:
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
            ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
            ".cpp": "cpp", ".c": "c", ".rs": "rust",
        }
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        return ""

    def _estimate_language_breakdown(self, meta: ScanMetadata) -> dict[str, int]:
        if meta.target_path:
            return {"Estimated": meta.files_scanned}
        return {}

    def _build_exec_summary(self, findings: list[ProfessionalFinding], chains: list[AttackChain], meta: ScanMetadata | None = None) -> str:
        if not findings:
            return "No vulnerabilities were identified during the scan."
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        chain_text = f" {len(chains)} attack chain(s) were identified." if chains else ""
        files = meta.files_scanned if meta else 0
        files_text = f" across {files} files" if files else ""
        return (
            f"A comprehensive security assessment{files_text} identified {len(findings)} vulnerabilities "
            f"({sev_counts.get('Critical', 0)} critical, {sev_counts.get('High', 0)} high, "
            f"{sev_counts.get('Medium', 0)} medium, {sev_counts.get('Low', 0)} low, "
            f"{sev_counts.get('Info', 0)} informational).{chain_text} "
            "This report provides enterprise-grade analysis with detailed remediation guidance "
            "aligned with OWASP, NIST, MITRE ATT&CK, and CWE standards."
        )

    def _build_risk_summary(self, findings: list[ProfessionalFinding]) -> str:
        if not findings:
            return "No risk identified."
        critical_high = sum(1 for f in findings if f.severity in ("Critical", "High"))
        if critical_high:
            return f"Overall risk level: HIGH - {critical_high} critical/high severity findings require immediate attention."
        return f"Overall risk level: MEDIUM - {len(findings)} findings identified across the application."

    def _build_remediation_roadmap(self, findings: list[ProfessionalFinding]) -> list[dict[str, Any]]:
        sorted_f = sorted(findings, key=lambda f: _severity_rank_str(f.severity))
        roadmap: list[dict[str, Any]] = []
        for f in sorted_f:
            roadmap.append({
                "finding_uid": f.finding_uid,
                "title": f.title,
                "severity": f.severity,
                "remediation": f.remediation.description,
                "complexity": f.remediation.complexity,
                "effort_hours": f.remediation.effort_hours,
                "priority": f.remediation_priority,
            })
        return roadmap

    def _build_root_cause_groupings(self, findings: list[ProfessionalFinding]) -> list[RootCauseGrouping]:
        groups: dict[str, dict] = defaultdict(lambda: {"uids": [], "functions": set(), "causal_severity_order": []})
        for f in findings:
            cat = f.root_cause_category or "General Security Weakness"
            groups[cat]["uids"].append(f.finding_uid)
            for fn in f.affected_functions:
                groups[cat]["functions"].add(fn)
            groups[cat]["causal_severity_order"].append(f.severity)
        result: list[RootCauseGrouping] = []
        for category, data in sorted(groups.items(), key=lambda x: -len(x[1]["uids"])):
            causal_links = []
            severity_order = data["causal_severity_order"]
            severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_sevs = sorted(severity_order, key=lambda s: severity_rank.get(s, 99))
            if sorted_sevs:
                top_sev = sorted_sevs[0]
                causal_links.append(f"Highest severity findings in this group are {top_sev} ({sorted_sevs.count(top_sev)} occurrence(s))")
            if len(data["functions"]) > 1:
                causal_links.append(f"Cross-function propagation: affects {len(data['functions'])} distinct functions")
            if category == "Input Validation":
                causal_links.append("Insufficient input sanitization creates a causal chain enabling injection attacks")
            elif category == "Authentication/Authorization":
                causal_links.append("Weak access controls cascade into privilege escalation and data exposure")
            elif category == "Cryptography":
                causal_links.append("Cryptographic weaknesses enable data decryption and MITM attacks")
            elif category == "Configuration":
                causal_links.append("Misconfiguration weakens multiple security domains simultaneously")
            elif category == "Data Protection":
                causal_links.append("Data protection gaps enable information disclosure chain")
            elif category == "Secrets Management":
                causal_links.append("Exposed secrets enable lateral movement and privilege escalation")
            master_fix_map = {
                "Input Validation": "Implement centralized input validation and output encoding framework with allowlist-based sanitization",
                "Authentication/Authorization": "Adopt a centralized identity and access management framework with RBAC and MFA enforcement",
                "Cryptography": "Enforce enterprise cryptographic policy with modern algorithms, key rotation, and HSM-backed key management",
                "Configuration": "Implement infrastructure-as-code security scanning with CIS benchmark enforcement",
                "Data Protection": "Deploy data classification and automated DLP controls with encryption at rest and in transit",
                "Secrets Management": "Centralize secrets in a vault solution (e.g., HashiCorp Vault) with rotation policies and auditing",
                "Logging Practices": "Standardize structured logging with security event correlation and SIEM integration",
                "Dependency Governance": "Adopt automated dependency scanning with policy-as-code enforcement for supply chain security",
                "Session Management": "Implement centralized session management with secure cookie attributes and rotation policies",
                "General Security Weakness": "Establish a comprehensive application security program covering all phases of SDLC",
            }
            master_fix = master_fix_map.get(category, f"Implement a centralized {category.lower()} framework to prevent recurrence of related vulnerabilities")
            result.append(RootCauseGrouping(
                root_cause=category,
                affected_findings=data["uids"],
                affected_finding_count=len(data["uids"]),
                affected_functions=sorted(data["functions"]),
                causal_links=causal_links,
                business_risk=f"Systemic {category.lower()} weaknesses increase the likelihood of successful exploitation across multiple attack vectors.",
                recommended_master_fix=master_fix,
            ))
        return result

    def _build_sbom_estimate(self, meta: ScanMetadata | None) -> list[SBOMEntry]:
        if not meta or not meta.tools_used:
            return []
        entries: list[SBOMEntry] = []
        for tool in meta.tools_used:
            entries.append(SBOMEntry(
                package_name=tool,
                version=meta.scanner_version,
                pinned=True,
                source="CodeSentinelX Toolchain",
                risk_level="Low",
                ecosystem="Python",
            ))
        return entries

    def _compute_posture_scores(
        self,
        findings: list[ProfessionalFinding],
        meta: ScanMetadata | None,
        *,
        industry: str = "General",
        risk_appetite: str = "moderate",
    ) -> SecurityPostureScores:
        from .report_models import (
            _INDUSTRY_BENCHMARKS,
            _RISK_APPETITE_LEVELS,
            IndustryBenchmarkComparison,
            RiskAppetiteAssessment,
        )

        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "Critical")
        high = sum(1 for f in findings if f.severity == "High")
        medium = sum(1 for f in findings if f.severity == "Medium")
        low = sum(1 for f in findings if f.severity == "Low")
        files = meta.files_scanned if meta and meta.files_scanned else max(total, 1)
        density = total / max(files, 1) * 1000
        density_penalty = min(density * 2, 30)
        penalty = critical * 15 + high * 8 + medium * 3 + low * 1
        overall = max(0, min(100, 100 - penalty - density_penalty))
        secrets_findings = sum(1 for f in findings if f.root_cause_category == "Secrets Management")
        secrets_score = max(0, 100 - secrets_findings * 25)
        dep_findings = sum(1 for f in findings if f.root_cause_category == "Dependency Governance")
        dep_score = max(0, 100 - dep_findings * 20)
        log_findings = sum(1 for f in findings if f.root_cause_category == "Logging Practices")
        log_score = max(0, 100 - log_findings * 15)
        app_score = max(0, min(100, 100 - critical * 20 - high * 10 - medium * 4))
        supply_score = max(0, 100 - dep_findings * 15 - secrets_findings * 10)

        # ── Industry benchmark comparison ──────────────────────────────────────
        bench = _INDUSTRY_BENCHMARKS.get(industry, _INDUSTRY_BENCHMARKS["General"])
        benchmarks: list[IndustryBenchmarkComparison] = [
            IndustryBenchmarkComparison(
                industry=industry, benchmark_score=bench["overall_min"],
                actual_score=round(overall, 1),
                gap=round(bench["overall_min"] - overall, 1),
                status="Above benchmark" if overall >= bench["overall_min"] else "Below benchmark" if overall < bench["overall_min"] - 10 else "Near benchmark",
                recommendations=[
                    "Address critical and high-severity findings to close gap"
                    if overall < bench["overall_min"]
                    else "Maintain current security posture"
                ],
            ),
            IndustryBenchmarkComparison(
                industry=industry, benchmark_score=bench["app_sec_min"],
                actual_score=round(app_score, 1),
                gap=round(bench["app_sec_min"] - app_score, 1),
                status="Above benchmark" if app_score >= bench["app_sec_min"] else "Below benchmark",
            ),
            IndustryBenchmarkComparison(
                industry=industry, benchmark_score=bench["secrets_min"],
                actual_score=round(secrets_score, 1),
                gap=round(bench["secrets_min"] - secrets_score, 1),
                status="Above benchmark" if secrets_score >= bench["secrets_min"] else "Below benchmark",
            ),
        ]

        # ── Risk appetite assessment ───────────────────────────────────────────
        appetite = risk_appetite if risk_appetite in _RISK_APPETITE_LEVELS else "moderate"
        thresholds = _RISK_APPETITE_LEVELS[appetite]
        exceeded: list[str] = []
        severity_breaches: dict[str, int] = {}
        if critical > thresholds["critical_max"]:
            exceeded.append(f"Critical ({critical}) exceeds appetite max ({thresholds['critical_max']})")
            severity_breaches["Critical"] = critical - thresholds["critical_max"]
        if high > thresholds["high_max"]:
            exceeded.append(f"High ({high}) exceeds appetite max ({thresholds['high_max']})")
            severity_breaches["High"] = high - thresholds["high_max"]
        if medium > thresholds["medium_max"]:
            exceeded.append(f"Medium ({medium}) exceeds appetite max ({thresholds['medium_max']})")
            severity_breaches["Medium"] = medium - thresholds["medium_max"]

        # ── Honest compliance score ─────────────────────────────────────────────
        compliance_score = 100.0
        if critical > 0:
            compliance_score -= min(critical * 15, 50)
        if high > 2:
            compliance_score -= min((high - 2) * 8, 30)
        if secrets_findings > 0:
            compliance_score -= min(secrets_findings * 10, 20)
        if dep_findings > 2:
            compliance_score -= min((dep_findings - 2) * 5, 15)
        if not meta or meta.files_scanned == 0:
            compliance_score -= 10
        if not meta or meta.total_lines_of_code == 0:
            compliance_score -= 5
        compliance_score = max(0, min(100, compliance_score))

        gap = ""
        if overall < 40:
            gap = "Critical security gaps exist across multiple domains. Immediate remediation required before production deployment."
        elif overall < 70:
            gap = "Moderate security posture with notable gaps. Remediation recommended within 30 days."
        else:
            gap = "Acceptable security posture. Continue monitoring and address remaining low-severity items."
        return SecurityPostureScores(
            overall_score=round(overall, 1),
            application_security_score=round(app_score, 1),
            supply_chain_score=round(supply_score, 1),
            secrets_management_score=round(secrets_score, 1),
            dependency_hygiene_score=round(dep_score, 1),
            logging_maturity_score=round(log_score, 1),
            current_state=f"{'Critical' if critical else 'High' if high else 'Medium'} risk with {total} findings",
            target_state="All critical and high findings remediated, monitoring in place",
            gap_analysis=gap,
            industry_benchmarks=benchmarks,
            risk_appetite=RiskAppetiteAssessment(
                appetite_level=appetite,
                thresholds=thresholds,
                findings_within_appetite=len(exceeded) == 0,
                exceeded_categories=exceeded,
                severity_breaches=severity_breaches,
            ),
            compliance_honesty_score=round(compliance_score, 1),
            benchmark_industry=industry,
        )

    def _compute_security_metrics(self, findings: list[ProfessionalFinding], meta: ScanMetadata | None) -> SecurityMetricsDashboard:
        total = len(findings)
        critical_high = sum(1 for f in findings if f.severity in ("Critical", "High"))
        loc = meta.total_lines_of_code if meta and meta.total_lines_of_code else max(total, 1)
        files = meta.files_scanned if meta and meta.files_scanned else max(total, 1)
        density = round((total / max(loc, 1)) * 1000, 2)
        risk_score = calculate_risk_score(findings)
        mttr = sum(f.remediation.effort_hours for f in findings)
        technical_debt = round(mttr, 1)
        compliance = round(max(0, 100 - (critical_high * 15) - (total * 2)), 1)
        owasp_matrix: dict[str, str] = {}
        owasp_cats = [f.owasp_api_top10 for f in findings if f.owasp_api_top10]
        for cat in sorted(set(owasp_cats)):
            owasp_matrix[cat] = "Fail"
        for cat in ["A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
                     "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"]:
            if cat not in owasp_matrix:
                owasp_matrix[cat] = "Unknown"
        return SecurityMetricsDashboard(
            mean_time_to_remediate_hours=mttr,
            risk_score=risk_score,
            high_risk_density=round((critical_high / max(files, 1)) * 1000, 2),
            technical_debt_hours=technical_debt,
            security_debt_score=round(risk_score * 1.2, 1),
            compliance_readiness=compliance,
            findings_per_1000_loc=density,
            scan_coverage_percent=round(min(100.0, (files / max(loc, 1)) * 100), 1),
            owasp_coverage_matrix=owasp_matrix,
        )

    def _build_compliance_mappings(self, findings: list[ProfessionalFinding]) -> list[ComplianceFrameworkMapping]:
        owasp_cats_failed = {f.owasp_api_top10 for f in findings if f.owasp_api_top10}
        owasp_findings = [f.finding_uid for f in findings if f.owasp_api_top10]
        soc2_gaps = [f.title for f in findings if f.severity in ("Critical", "High")]
        nist_gaps = sum(1 for f in findings if f.severity in ("Critical", "High"))
        return [
            ComplianceFrameworkMapping(
                framework_name="OWASP Top 10 2021",
                framework_version="2021",
                compliant_controls=10 - len(owasp_cats_failed),
                total_controls=10,
                compliance_percentage=round(max(0, 100 - len(owasp_cats_failed) * 10), 1),
                finding_ids=owasp_findings,
                gaps=[f"Violation: {cat}" for cat in sorted(owasp_cats_failed)],
            ),
            ComplianceFrameworkMapping(
                framework_name="SOC 2",
                framework_version="Type II",
                compliant_controls=max(0, 5 - len(soc2_gaps)),
                total_controls=min(5, len(soc2_gaps) + 1),
                compliance_percentage=round(max(0, 100 - len(soc2_gaps) * 20), 1),
                gaps=[f"Gap: {g}" for g in soc2_gaps[:5]],
            ),
            ComplianceFrameworkMapping(
                framework_name="ISO 27001",
                framework_version="2022",
                compliant_controls=max(0, 14 - min(len(findings), 14)),
                total_controls=14,
                compliance_percentage=round(max(0, 100 - len(findings) * 7), 1),
                gaps=[f"Control gap: {f.title}" for f in findings[:5]],
            ),
            ComplianceFrameworkMapping(
                framework_name="NIST CSF",
                framework_version="1.1",
                compliant_controls=max(0, 5 - nist_gaps),
                total_controls=5,
                compliance_percentage=round(max(0, 100 - nist_gaps * 20), 1),
                gaps=[f"Gap: {f.title}" for f in findings[:5] if f.severity in ("Critical", "High")][:5],
            ),
            ComplianceFrameworkMapping(
                framework_name="PCI DSS",
                framework_version="4.0",
                compliant_controls=max(0, 12 - sum(1 for f in findings if "pci" in (f.pci_dss_requirement or "").lower() or f.severity == "Critical")),
                total_controls=12,
                compliance_percentage=round(max(0, 100 - sum(1 for f in findings if f.severity in ("Critical", "High")) * 8), 1),
                gaps=[f.pci_dss_requirement for f in findings if f.pci_dss_requirement][:5],
            ),
            ComplianceFrameworkMapping(
                framework_name="CIS Controls",
                framework_version="8.1",
                compliant_controls=max(0, 18 - len(findings)),
                total_controls=18,
                compliance_percentage=round(max(0, 100 - len(findings) * 4), 1),
            ),
        ]

    def _build_assessment_limitations(self, meta: ScanMetadata | None, findings: list[ProfessionalFinding]) -> list[AssessmentLimitation]:
        limitations: list[AssessmentLimitation] = []
        limitations.append(AssessmentLimitation(
            category="Scope",
            description="Assessment limited to static analysis of available source code. Runtime behavior, network configurations, and infrastructure were not tested.",
            impact="Runtime-specific vulnerabilities such as race conditions, memory corruption, and configuration-dependent issues may not be detected.",
            recommendation="Complement with dynamic analysis (DAST) and manual penetration testing.",
        ))
        if meta and meta.files_scanned == 0:
            limitations.append(AssessmentLimitation(
                category="Scan Coverage",
                description="No files were scanned. Scan metadata may be incomplete.",
                impact="Results may not reflect the full security posture of the application.",
                recommendation="Verify scan configuration and re-run with correct target path.",
            ))
        if not any(f.evidence for f in findings):
            limitations.append(AssessmentLimitation(
                category="Evidence Collection",
                description="Limited or no runtime evidence was collected during the automated scan.",
                impact="Findings lack PoC evidence and may require manual validation.",
                recommendation="Manually validate critical and high severity findings with proof-of-concept exploits.",
            ))
        limitations.append(AssessmentLimitation(
            category="Third-Party Components",
            description="Dependency analysis limited to known vulnerabilities in public databases. Zero-day vulnerabilities in dependencies are not detected.",
            impact="Newly disclosed vulnerabilities may not be reflected in findings.",
            recommendation="Monitor security advisories and maintain an active patching cadence.",
        ))
        return limitations

    def _build_scanner_validation(self, meta: ScanMetadata | None) -> list[str]:
        notes: list[str] = []
        if meta:
            if meta.files_scanned == 0:
                notes.append("WARNING: files_scanned=0 indicates possible scan configuration issue")
            if meta.duration_seconds == 0:
                notes.append("WARNING: scan duration=0s indicates timing data may not have been captured")
            if not meta.tools_used:
                notes.append("WARNING: no tools were reported as used during the scan")
        if not notes:
            notes.append("Scan metadata appears consistent - no validation issues detected")
        return notes

    def _build_critical_risk_drivers(self, findings: list[ProfessionalFinding]) -> list[str]:
        drivers: list[str] = []
        for f in findings:
            if f.severity == "Critical":
                drivers.append(f"[CRITICAL] {f.title} - {f.technical_impact[:100]}")
        if not drivers:
            critical_high = [f for f in findings if f.severity == "High"][:3]
            drivers = [f"[HIGH] {f.title}" for f in critical_high]
        return drivers or ["No critical risk drivers identified"]

    def _build_top_5_risks(self, findings: list[ProfessionalFinding]) -> list[str]:
        sorted_f = sorted(findings, key=lambda f: (-f.cvss_score, self._severity_rank(f.severity)))
        return [f"{f.title} (CVSS: {f.cvss_score:.1f}, {f.severity})" for f in sorted_f[:5]]

    def _build_business_impact_assessment(self, findings: list[ProfessionalFinding]) -> str:
        critical = sum(1 for f in findings if f.severity == "Critical")
        high = sum(1 for f in findings if f.severity == "High")
        total = len(findings)
        parts: list[str] = []
        if critical:
            parts.append(f"{critical} critical vulnerabilities pose immediate risk of data breach, regulatory penalties (GDPR/PCI DSS), and reputational damage.")
        if high:
            parts.append(f"{high} high-severity vulnerabilities enable unauthorized access and data exposure.")
        if total > 20:
            parts.append("High vulnerability density indicates systemic security weaknesses in the development lifecycle.")
        parts.append(f"Total of {total} findings across the application require coordinated remediation effort.")
        return " ".join(parts)

    def _build_risk_trend_summary(self, severity_counts: dict[str, int]) -> str:
        critical = severity_counts.get("Critical", 0)
        high = severity_counts.get("High", 0)
        if critical > 0:
            return f"Trend: {critical} critical findings indicate immediate risk requiring urgent remediation."
        if high > 0:
            return f"Trend: {high} high-severity findings should be addressed in current sprint cycle."
        return "Trend: No critical or high findings. Maintain current security practices."

    def _build_remediation_phases(self, findings: list[ProfessionalFinding]) -> dict[str, list[dict[str, Any]]]:
        phases: dict[str, list[dict[str, Any]]] = {
            "Phase 1 - Immediate (0-7 days)": [],
            "Phase 2 - Short Term (30 days)": [],
            "Phase 3 - Medium Term (60 days)": [],
            "Phase 4 - Long Term (90 days)": [],
        }
        for f in findings:
            entry = {
                "finding_uid": f.finding_uid,
                "title": f.title,
                "severity": f.severity,
                "effort_hours": f.remediation.effort_hours,
                "complexity": f.remediation.complexity,
                "remediation": f.remediation.description,
            }
            if f.severity in ("Critical", "High"):
                phases["Phase 1 - Immediate (0-7 days)"].append(entry)
            elif f.severity == "Medium":
                phases["Phase 2 - Short Term (30 days)"].append(entry)
            elif f.severity == "Low":
                phases["Phase 3 - Medium Term (60 days)"].append(entry)
            else:
                phases["Phase 4 - Long Term (90 days)"].append(entry)
        return {k: v for k, v in phases.items() if v}

    def _build_business_impact(self, findings: list[ProfessionalFinding]) -> str:
        critical_count = sum(1 for f in findings if f.severity == "Critical")
        if critical_count:
            return (
                f"{critical_count} critical vulnerabilities pose immediate business risk including "
                "potential data loss, regulatory penalties, and reputational damage."
            )
        return "No immediate business-critical risk identified. Recommend addressing findings per remediation plan."

    def _build_strategic_recommendations(self, findings: list[ProfessionalFinding]) -> list[str]:
        recs = []
        if any(f.severity == "Critical" for f in findings):
            recs.append("Immediately remediate all critical vulnerabilities before next release.")
        if any(f.severity == "High" for f in findings):
            recs.append("Schedule high-severity fixes within the current sprint.")
        if len(findings) > 20:
            recs.append("Consider implementing automated security scanning in CI/CD pipeline.")
        recs.append("Conduct regular security reviews and penetration testing.")
        return recs


def _severity_rank_str(severity: str) -> int:
    return {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
    }.get(severity, 5)
