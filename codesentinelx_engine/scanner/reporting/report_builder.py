from __future__ import annotations

from collections import Counter
from contextlib import suppress
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory

from codesentinelx_engine.models import Finding, ScanResult, SecurityControl
from codesentinelx_engine.poc_verify import ValidationContext, verify_finding
from codesentinelx_engine.risk import risk_rating
from codesentinelx_engine.scanner.kev_catalog import find_kev_matches, load_kev_catalog, normalize_cve_id
from codesentinelx_engine.scanner.ai_provider import (
    build_provider_status,
    generate_grounded_remediation,
    generate_prioritization_plan,
    load_ai_provider_config,
)
from codesentinelx_engine.scanner.dependency_auth import advisory_identity, build_dependency_inventory, build_dependency_usage_map, normalize_package_name
from codesentinelx_engine.scanner.native_triage import annotate_findings
from codesentinelx_engine.scanner.role_scope import (
    normalize_role,
    role_runs_active_poc,
    role_runs_fix_verification,
    scope_findings_for_role,
    scope_report_for_role,
)
from codesentinelx_engine.scanner.reporting.compliance_profiles import (
    build_profile_compliance,
    normalize_owasp_top10_label,
)


SEVERITY_RANK = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}

SEVERITY_WEIGHT = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Info": 0,
}


def _normalize_severity_label(raw: object) -> str:
    if isinstance(raw, dict):
        for key in ("value", "label", "name", "severity", "level", "text", "display", "code"):
            candidate = raw.get(key)
            if candidate:
                raw = candidate
                break
    value = str(getattr(raw, "value", getattr(raw, "name", raw)) or "").strip().lower()
    value = value.replace("severity.", "").replace("severity_", "").replace("severity-", "")
    value = re.sub(r"[^a-z]+", " ", value).strip()
    if re.search(r"\bcritical\b|\berror\b", value):
        return "Critical"
    if re.search(r"\bhigh\b", value):
        return "High"
    if re.search(r"\bmedium\b|\bwarning\b", value):
        return "Medium"
    if re.search(r"\blow\b|\bnote\b", value):
        return "Low"
    if re.search(r"\binfo\b|\binformational\b", value):
        return "Info"
    return "Info"


def _top_vulnerability_types(findings: list[dict], limit: int = 10) -> list[dict[str, int | str]]:
    counts = Counter(str(item.get("vulnerability_title") or item.get("vulnerability_type") or "Unknown") for item in findings)
    return [{"type": vuln_type, "count": count} for vuln_type, count in counts.most_common(limit)]


def _top_owasp_categories(findings: list[dict], limit: int = 10) -> list[dict[str, int | str]]:
    counts = Counter(normalize_owasp_top10_label(str(item.get("owasp_mapping") or item.get("owasp_category") or "N/A")) for item in findings)
    return [{"owasp_category": category, "count": count} for category, count in counts.most_common(limit)]


def _severity_cvss(severity: str) -> float:
    mapping = {
        "Critical": 9.8,
        "High": 8.2,
        "Medium": 6.1,
        "Low": 3.7,
        "Info": 0.0,
    }
    return mapping.get(severity, 5.0)


def _confidence_label(score: float | None) -> str:
    numeric = float(score or 0.0)
    if numeric >= 0.82:
        return "High"
    if numeric >= 0.58:
        return "Medium"
    return "Low"


def _active_poc_status(entry: dict | None) -> str:
    return str((entry or {}).get("status") or "not_applicable").strip().lower()


def _build_validation_narrative(finding: dict, active_poc: dict) -> str:
    location = f"{finding.get('file_path', 'unknown')}:{int(finding.get('line_number', 1) or 1)}"
    lines = [
        f"Scope: {location}",
        f"Validation Basis: {active_poc.get('verification_basis') or 'Deterministic source validation executed against recorded code evidence.'}",
        f"Replay Command: {active_poc.get('command') or 'N/A'}",
        f"Observed Result: {active_poc.get('status') or 'not_applicable'}",
    ]
    output = str(active_poc.get("output") or "").strip()
    if output:
        lines.append("Execution Output:")
        lines.extend(output.splitlines()[:10])
    return "\n".join(lines)


def _build_ai_summary(finding: dict, active_poc: dict) -> str:
    status = _active_poc_status(active_poc)
    location = f"{finding.get('file_path', 'unknown')}:{int(finding.get('line_number', 1) or 1)}"
    title = _resolved_vulnerability_title(finding)
    recommendation = str(finding.get("recommendation") or "").strip()
    if status == "verified":
        prefix = f"{title} is source-verified at {location} and should be remediated with priority."
    elif status == "inconclusive":
        prefix = f"{title} has partial source validation at {location}; remediation is still recommended, but manual review should confirm exploitability."
    else:
        prefix = f"{title} is present in the recorded source path {location} based on CodeSentinelX evidence."
    return f"{prefix} {recommendation}".strip()


def _build_ai_validation_steps(active_poc: dict) -> str:
    command = str(active_poc.get("command") or "").strip()
    steps = [
        "1. Review the affected source line and surrounding code shown in this report.",
        "2. Apply the recommended remediation and update any related tests or guards.",
        f"3. Re-run the deterministic validation command: {command}" if command else "3. Re-run the deterministic validation step for this finding.",
        "4. Close the finding only if the validation result no longer confirms the unsafe pattern.",
    ]
    return "\n".join(steps)


def _plain_language_security_brief(finding: dict) -> dict[str, str]:
    title = _resolved_vulnerability_title(finding)
    lower = " ".join(
        str(finding.get(key) or "").lower()
        for key in (
            "vulnerability_title",
            "vulnerability_type",
            "cwe_id",
            "cwe",
            "rule_id",
            "description",
            "recommendation",
            "original_code",
            "vulnerable_code_snippet",
            "evidence",
        )
    )
    original_code = str(finding.get("original_code") or finding.get("vulnerable_code_snippet") or "").strip()
    recommendation = str(finding.get("recommendation") or "").strip()

    if any(token in lower for token in ("weak cryptography", "cwe-327", "3des", "des-ede3-cbc", "tripledes")):
        return {
            "title": "Weak Cryptography Usage",
            "what_is_happening": "The code is using a legacy cipher or weak cryptographic pattern to protect data. In practice, that means the application is relying on an older encryption mode or primitive that modern standards no longer treat as a strong default.",
            "why_it_is_weak": "Legacy cryptography can be easier to attack, is often slower, and may not provide built-in authenticity. CBC-mode encryption also needs careful IV handling, and older ciphers can become risky when large amounts of data are processed.",
            "what_to_use_instead": "Prefer an authenticated modern mode such as AES-GCM. If the application must interoperate with a legacy system, keep the weak path only as a short-lived compatibility exception and plan a migration to stronger primitives.",
            "summary": "In short: retire the legacy cipher, move to modern authenticated encryption, and rotate any data or keys that were protected by the weaker algorithm.",
            "code_example": original_code or "Use a modern authenticated cipher such as crypto.createCipheriv('aes-256-gcm', key, iv).",
            "recommendation": recommendation or "Migrate to AES-GCM and rotate any keys or data tied to the legacy cipher.",
        }

    if any(token in lower for token in ("sql injection", "cwe-89")):
        return {
            "title": "SQL Injection",
            "what_is_happening": "Untrusted input is reaching a database query in a way that lets the input change the structure of the SQL statement.",
            "why_it_is_weak": "When user input is concatenated into SQL, an attacker can alter filters, bypass checks, or read and modify data they should not access.",
            "what_to_use_instead": "Use parameterized queries or prepared statements, and keep input validation strict but separate from query construction.",
            "summary": "In short: never build SQL by string concatenation; bind parameters instead.",
            "code_example": original_code or "Use parameterized execution such as cursor.execute(query, params).",
            "recommendation": recommendation or "Switch to prepared statements / parameterized queries.",
        }

    if any(token in lower for token in ("cross-site scripting", "xss", "cwe-79")):
        return {
            "title": "Cross-Site Scripting (XSS)",
            "what_is_happening": "User-controlled data is reaching a browser rendering sink without enough escaping or context-aware encoding.",
            "why_it_is_weak": "That can let attacker-supplied script or markup execute in another user’s browser and expose sessions, data, or actions.",
            "what_to_use_instead": "Use framework templating, output encoding, and safe DOM APIs instead of directly injecting HTML or script content.",
            "summary": "In short: encode on output and avoid unsafe HTML rendering paths.",
            "code_example": original_code or "Render trusted markup only and escape untrusted values before display.",
            "recommendation": recommendation or "Escape untrusted output and avoid direct HTML injection.",
        }

    if any(token in lower for token in ("hardcoded", "secret", "credential", "cwe-798")):
        return {
            "title": "Hardcoded Secrets / Credentials",
            "what_is_happening": "Sensitive credentials or tokens are present in code or nearby artifacts where anyone with repo or build access could read them.",
            "why_it_is_weak": "Hardcoded secrets are easy to leak, hard to rotate safely, and often remain valid far longer than they should.",
            "what_to_use_instead": "Move secrets into a managed vault or secret manager, rotate the exposed value, and load credentials at runtime instead of embedding them in source.",
            "summary": "In short: remove secrets from code, store them in a vault, and rotate anything already exposed.",
            "code_example": original_code or "Use environment-backed secret retrieval instead of storing the secret inline.",
            "recommendation": recommendation or "Move the secret to a vault and rotate it immediately.",
        }

    if any(token in lower for token in ("path traversal", "cwe-22", "directory traversal")):
        return {
            "title": "Path Traversal",
            "what_is_happening": "A path or filename is influenced by user input without enough normalization or allowlisting.",
            "why_it_is_weak": "An attacker can steer the application outside the intended folder and read or write files it should not touch.",
            "what_to_use_instead": "Normalize the path, enforce an allowlist, and join paths with safe helpers that keep the final location inside the approved base directory.",
            "summary": "In short: never trust raw file paths from input; keep them constrained to the intended directory tree.",
            "code_example": original_code or "Use safe path-join helpers and validate the resolved path before access.",
            "recommendation": recommendation or "Normalize and constrain file paths before reading or writing.",
        }

    if any(token in lower for token in ("command injection", "cwe-78", "shell")):
        return {
            "title": "Command Injection",
            "what_is_happening": "User-controlled data is reaching a shell command or command string.",
            "why_it_is_weak": "If the shell interprets special characters, the attacker can append new commands or change the meaning of the original one.",
            "what_to_use_instead": "Avoid shell execution when possible, pass arguments as an array, and use strict allowlists for any input that must influence command behavior.",
            "summary": "In short: do not build shell commands from raw input.",
            "code_example": original_code or "Invoke commands without shell interpolation and with allowlisted arguments only.",
            "recommendation": recommendation or "Avoid shell concatenation and use safe argument passing.",
        }

    if any(token in lower for token in ("dependency vulnerability", "cwe-1104", "vulnerable and outdated components", "cve", "ghsa", "osv")):
        return {
            "title": "Dependency Vulnerability",
            "what_is_happening": "The application depends on a package or component version that has a known advisory or fixed version available.",
            "why_it_is_weak": "Even if the code looks fine, a vulnerable library can expose the application through the dependency chain, especially when the package is reachable at runtime.",
            "what_to_use_instead": "Upgrade to the fixed version, verify whether the vulnerable path is actually reachable in this application, and keep the dependency source of truth tied to an advisory record.",
            "summary": "In short: update the package to a safe version and keep the advisory evidence attached to the finding.",
            "code_example": original_code or "Upgrade to the vendor-fixed package version and re-run verification.",
            "recommendation": recommendation or "Upgrade the affected dependency to the fixed version.",
        }

    if any(token in lower for token in ("deserialization", "cwe-502")):
        return {
            "title": "Insecure Deserialization",
            "what_is_happening": "The code is turning untrusted serialized data back into objects without enough validation or structure checking.",
            "why_it_is_weak": "Unsafe deserialization can let attacker-controlled payloads trigger unexpected behavior, object graph abuse, or even code execution in some stacks.",
            "what_to_use_instead": "Use safe serializers, strict schemas, and reject data that is not explicitly expected by the application.",
            "summary": "In short: never deserialize untrusted data with a permissive parser.",
            "code_example": original_code or "Use schema-validated parsing instead of generic object deserialization.",
            "recommendation": recommendation or "Switch to safe serialization and validate input schemas.",
        }

    if any(token in lower for token in ("ssrf", "cwe-918")):
        return {
            "title": "Server-Side Request Forgery (SSRF)",
            "what_is_happening": "The application can be persuaded to make server-side requests to attacker-chosen destinations.",
            "why_it_is_weak": "That can expose internal services, metadata endpoints, or trusted network-only resources that should not be reachable externally.",
            "what_to_use_instead": "Apply destination allowlists, block internal ranges, and validate URLs before the application issues outbound requests.",
            "summary": "In short: strictly control where the server is allowed to connect.",
            "code_example": original_code or "Validate and allowlist outbound destinations before making the request.",
            "recommendation": recommendation or "Allowlist outbound destinations and block internal ranges.",
        }

    if any(token in lower for token in ("broken access control", "bopla", "bola", "idor", "object level authorization", "access control")):
        return {
            "title": "Broken Access Control",
            "what_is_happening": "The code is making an authorization decision on a user, object, or property, but the check is incomplete or depends on attacker-influenced request data.",
            "why_it_is_weak": "That can let a user read, change, or delete records that belong to another user, tenant, or account if the ownership check is missing or only applied in one code path.",
            "what_to_use_instead": "Perform a server-side object-level authorization check on every access path, using trusted identity and ownership metadata rather than request parameters.",
            "summary": recommendation or "Add object-level authorization checks and verify ownership before returning or mutating data.",
            "code_example": original_code or "if not is_authorized(user, resource): raise ForbiddenError()",
            "recommendation": recommendation or "Enforce server-side object-level authorization for every access path.",
        }

    if any(token in lower for token in ("auth", "authorization", "session", "privilege")):
        return {
            "title": title,
            "what_is_happening": "The code path affects authentication, authorization, or session handling and needs stricter control than ordinary application logic.",
            "why_it_is_weak": "Mistakes in auth or session boundaries often turn into privilege escalation, confused-deputy behavior, or account takeover.",
            "what_to_use_instead": "Enforce the check on the server side, keep session and identity state centralized, and avoid relying on client-controlled values for access decisions.",
            "summary": "In short: treat auth and session decisions as security-critical and enforce them in trusted server code.",
            "code_example": original_code or "Use server-side access checks and trusted session state.",
            "recommendation": recommendation or "Enforce authorization on the server side and do not trust client-controlled identity data.",
        }

    scenario, impact, _, safer = _scenario_for(title)
    return {
        "title": title,
        "what_is_happening": scenario,
        "why_it_is_weak": impact,
        "what_to_use_instead": safer,
        "summary": recommendation or f"{title} should be remediated using the safer code path shown elsewhere in this report.",
        "code_example": original_code or "See the affected source line in the report for the exact code path.",
        "recommendation": recommendation or "Follow the report guidance and remediate the unsafe pattern.",
    }


def _risk_priority_score(item: dict) -> float:
    base = float(item.get("cvss_score", 0.0)) * 8.0
    severity_bonus = {
        "Critical": 18.0,
        "High": 10.0,
        "Medium": 5.0,
        "Low": 2.0,
        "Info": 0.0,
    }.get(str(item.get("severity", "Info")), 0.0)
    poc_status = _active_poc_status(item.get("active_poc"))
    poc_bonus = {
        "verified": 10.0,
        "inconclusive": 4.0,
        "not_applicable": 0.0,
        "error": 0.0,
    }.get(poc_status, 0.0)
    title = str(item.get("vulnerability_title") or "").lower()
    family_bonus = 0.0
    if any(token in title for token in ("sql injection", "command injection", "hardcoded secrets", "credential", "authentication", "authorization")):
        family_bonus = 6.0
    reachability = item.get("dependency_reachability") or {}
    reachability_bonus = 0.0
    if isinstance(reachability, dict):
        reachability_bonus = float(reachability.get("priority_factor", 1.0) or 1.0) * 4.0 - 4.0
    return round(min(100.0, base + severity_bonus + poc_bonus + family_bonus + reachability_bonus), 2)


def _module_name(file_path: str) -> str:
    normalized = file_path.replace("\\", "/").strip("./")
    if normalized.startswith("http://") or normalized.startswith("https://") or normalized.startswith("ssh://"):
        without_scheme = normalized.split("://", 1)[1]
        host, _, rest = without_scheme.partition("/")
        if not rest:
            return host
        first = rest.split("/", 1)[0]
        return first or host
    if not normalized:
        return "root"
    parts = PurePosixPath(normalized).parts
    if len(parts) <= 1:
        return parts[0] if parts else "root"
    return parts[0]


def _scenario_for(vulnerability_type: str) -> tuple[str, str, str, str]:
    lowered = vulnerability_type.lower()
    if "sql injection" in lowered:
        return (
            "Attacker supplies crafted input into query-building parameters to alter SQL logic.",
            "Inject payload to bypass filters and dump sensitive tables.",
            "Use `' OR 1=1 --` style payload in affected input field and observe expanded result set.",
            "Use prepared statements with strict parameter binding.",
        )
    if "xss" in lowered:
        return (
            "Attacker injects executable script into rendered page content.",
            "Steal session tokens via script exfiltration in victim browser.",
            "Submit `<script>alert(document.domain)</script>` to vulnerable rendering sink.",
            "Escape output and avoid unsafe DOM assignment APIs.",
        )
    if "command injection" in lowered:
        return (
            "Attacker-controlled input reaches shell/command execution boundary.",
            "Execute arbitrary OS commands on application host.",
            "Inject command separator like `; whoami` in user parameter consumed by shell call.",
            "Remove shell invocation and enforce allowlisted arguments.",
        )
    if "deserialization" in lowered:
        return (
            "Untrusted serialized payload is processed with unsafe deserializer.",
            "Trigger gadget chains for remote code execution.",
            "Submit crafted serialized object and observe unauthorized execution path.",
            "Use safe serializers and validate strict schema contracts.",
        )
    if "hardcoded" in lowered or "secret" in lowered:
        return (
            "Credential material is exposed in source and reachable by repo readers/build artifacts.",
            "Reuse leaked key to access protected APIs and data.",
            "Use extracted token from repository to authenticate against target service endpoint.",
            "Rotate leaked secret and move to managed secret vault.",
        )
    if "weak cryptography" in lowered:
        return (
            "Outdated cryptographic algorithm is used in data protection workflow.",
            "Attackers exploit weaker primitive for integrity or confidentiality bypass.",
            "Demonstrate collision/weakness behavior using known MD5/SHA1 examples against signed payloads.",
            "Upgrade to modern algorithms and key sizes (e.g., SHA-256+, AES-GCM).",
        )
    return (
        "Input and trust boundaries are not sufficiently constrained in this code path.",
        "An attacker can chain this weakness with other flaws for unauthorized outcomes.",
        "Reproduce by supplying crafted untrusted input to vulnerable path and validate unexpected behavior.",
        "Apply defense-in-depth controls with strict validation and least privilege.",
    )


def _resolved_vulnerability_title(item: dict) -> str:
    raw = str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").strip()
    lower = raw.lower()
    if raw and lower not in {
        "security",
        "security issue",
        "security finding",
        "vulnerability",
        "issue",
        "finding",
        "external analyzer finding",
        "analyzer finding",
    }:
        return raw

    cwe = str(item.get("cwe_id") or item.get("cwe") or "").upper()
    cwe_map = {
        "CWE-20": "Improper Input Validation",
        "CWE-22": "Path Traversal",
        "CWE-78": "Command Injection",
        "CWE-79": "Cross-Site Scripting (XSS)",
        "CWE-89": "SQL Injection",
        "CWE-95": "Unsafe Eval Usage",
        "CWE-250": "Improper Privilege Management",
        "CWE-319": "Cleartext Transmission of Sensitive Data",
        "CWE-327": "Weak Cryptography Usage",
        "CWE-330": "Insufficient Randomness",
        "CWE-502": "Insecure Deserialization",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-704": "Unsafe Type Handling / Conversion",
        "CWE-798": "Hardcoded Secrets / Credentials",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-1104": "Dependency Vulnerability",
    }
    if cwe in cwe_map:
        return cwe_map[cwe]

    blob = " ".join(
        str(item.get(key) or "").lower()
        for key in (
            "rule_id",
            "owasp_mapping",
            "description",
            "business_impact",
            "vulnerable_code_snippet",
            "original_code",
            "recommendation",
        )
    )
    hints = [
        ("sql injection", "SQL Injection"),
        ("command injection", "Command Injection"),
        ("cross-site scripting", "Cross-Site Scripting (XSS)"),
        ("xss", "Cross-Site Scripting (XSS)"),
        ("path traversal", "Path Traversal"),
        ("hardcoded", "Hardcoded Secrets / Credentials"),
        ("secret", "Hardcoded Secrets / Credentials"),
        ("credential", "Hardcoded Secrets / Credentials"),
        ("deserial", "Insecure Deserialization"),
        ("weak crypto", "Weak Cryptography Usage"),
        ("dependency", "Dependency Vulnerability"),
        ("input validation", "Improper Input Validation"),
        ("authorization", "Authentication / Authorization Flaw"),
        ("auth", "Authentication / Authorization Flaw"),
        ("session", "Session Security Misconfiguration"),
        ("misconfig", "Security Misconfiguration"),
        ("ssrf", "Server-Side Request Forgery (SSRF)"),
        ("xxe", "XML External Entity (XXE)"),
        ("cleartext", "Cleartext Transmission of Sensitive Data"),
        ("eval(", "Unsafe Eval Usage"),
    ]
    for token, label in hints:
        if token in blob:
            return label
    return "Unclassified Security Finding"


def _normalize_snippet(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip())


def _normalize_rule_id(raw: str | None) -> str:
    value = str(raw or "").strip().upper()
    if not value:
        return ""
    value = value.replace(" ", "-").replace("_", "-")
    value = re.sub(r"-{2,}", "-", value)
    return value


def _tool_from_rule_id(rule_id: str | None) -> str:
    normalized = _normalize_rule_id(rule_id)
    if not normalized:
        return ""
    head = normalized.split("-", 1)[0].strip().lower()
    return {"osv": "osv-scanner"}.get(head, head)


def _source_reliability(item: dict) -> int:
    candidates: set[str] = set()
    tool = str(item.get("tool") or "").strip().lower()
    if tool:
        candidates.add(tool)
    origin = str(item.get("origin") or "").strip().lower()
    if origin:
        candidates.add(origin)
    candidates.add(_tool_from_rule_id(item.get("rule_id")))
    for source in item.get("evidence_sources", []) or []:
        candidates.add(_tool_from_rule_id(source))
    return max((_SOURCE_RELIABILITY_RANK.get(name, 0) for name in candidates if name), default=0)


def _is_sast_overlap_candidate(item: dict) -> bool:
    tool = _tool_from_rule_id(item.get("rule_id"))
    if tool in {"bandit", "gosec", "checkov", "tfsec"}:
        return True
    source_tools = {_tool_from_rule_id(source) for source in (item.get("evidence_sources") or [])}
    return bool(source_tools.intersection({"bandit", "gosec", "checkov", "tfsec"}))


def _canonical_sast_family(item: dict) -> str:
    cwe = str(item.get("cwe_id") or item.get("cwe") or "").strip().upper()
    owasp = normalize_owasp_top10_label(str(item.get("owasp_mapping") or item.get("owasp_category") or ""))
    title = str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").strip().lower()
    if cwe:
        return f"cwe:{cwe}"
    if owasp and owasp != "N/A":
        return f"owasp:{owasp.lower()}"
    if "sql injection" in title:
        return "family:sql-injection"
    if "command injection" in title:
        return "family:command-injection"
    if "path traversal" in title:
        return "family:path-traversal"
    if "cross-site scripting" in title or "xss" in title:
        return "family:xss"
    return f"title:{title or 'generic'}"


PY_KEYWORDS = {
    "and",
    "as",
    "assert",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "false",
    "finally",
    "for",
    "from",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "none",
    "nonlocal",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "true",
    "try",
    "while",
    "with",
    "yield",
}

SQL_KEYWORDS = {
    "select",
    "from",
    "where",
    "and",
    "or",
    "insert",
    "into",
    "update",
    "delete",
    "join",
    "on",
    "values",
    "set",
    "limit",
    "group",
    "order",
    "by",
}


def _extract_identifiers(snippet: str, max_items: int = 4) -> list[str]:
    candidates = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", snippet or "")
    picked: list[str] = []
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in PY_KEYWORDS or lowered in SQL_KEYWORDS:
            continue
        if lowered.startswith(("cursor", "query", "sql", "execute", "subprocess", "system", "path", "self")):
            continue
        if candidate.isupper():
            continue
        if candidate not in picked:
            picked.append(candidate)
        if len(picked) >= max_items:
            break
    return picked


def _normalize_sql_query_from_snippet(snippet: str) -> str:
    fragments = re.findall(r'"([^"]+)"|\'([^\']+)\'', snippet or "")
    text_parts = ["".join(fragment).strip() for fragment in fragments if "".join(fragment).strip()]
    query = " ".join(text_parts).strip()
    if not query:
        query = "SELECT * FROM table WHERE id = %s"
    query = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "%s", query)
    query = re.sub(r"\s+", " ", query).strip()
    return query


def _extract_dependency_metadata(evidence: str, description: str, recommendation: str, reference: str) -> dict[str, object]:
    combined = " ".join([evidence or "", description or "", recommendation or "", reference or ""])
    cves = sorted(set(match.upper() for match in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", combined, flags=re.IGNORECASE)))
    ghsas = sorted(set(match.upper() for match in re.findall(r"\bGHSA-[a-z0-9-]+\b", combined, flags=re.IGNORECASE)))
    package_name = ""
    package_version = ""
    if "==" in (evidence or ""):
        package_name, package_version = [part.strip() for part in evidence.split("==", 1)]
    elif ":" in (evidence or ""):
        package_name, package_version = [part.strip() for part in evidence.split(":", 1)]
    advisory_ids = sorted(set(cves + ghsas))
    return {
        "dependency_name": package_name or None,
        "dependency_version": package_version or None,
        "dependency_id": advisory_ids[0] if advisory_ids else None,
        "cve_ids": cves,
        "advisory_ids": advisory_ids,
    }


def _is_dependency_finding_payload(item: dict) -> bool:
    vuln_type = str(item.get("vulnerability_type") or item.get("vulnerability_title") or "").lower()
    owasp = str(item.get("owasp_category") or item.get("owasp_mapping") or "").lower()
    cwe = str(item.get("cwe") or item.get("cwe_id") or "").upper()
    rule_id = str(item.get("rule_id") or "").upper()
    return (
        "dependency" in vuln_type
        or "a06:2021" in owasp
        or cwe == "CWE-1104"
        or rule_id.startswith("NATIVE-DEP-")
    )


def _build_sql_fix(snippet: str) -> str:
    params = _extract_identifiers(snippet, max_items=3)
    if not params:
        params = ["user_input"]
    tuple_expr = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
    query = _normalize_sql_query_from_snippet(snippet)
    return "\n".join(
        [
            f'query = "{query}"',
            f"params = {tuple_expr}",
            "cursor.execute(query, params)",
        ]
    )


def _build_command_fix(snippet: str) -> str:
    args = _extract_identifiers(snippet, max_items=2)
    user_arg = args[0] if args else "user_input"
    command_match = re.search(r"""['"]([A-Za-z0-9_./-]+)['"]""", snippet or "")
    base_command = command_match.group(1) if command_match else "/usr/bin/tool"
    return "\n".join(
        [
            "import shlex",
            f"safe_args = shlex.split(str({user_arg}))",
            f"subprocess.run([{base_command!r}, *safe_args], check=True, shell=False)",
        ]
    )


def _build_path_fix(snippet: str) -> str:
    vars_found = _extract_identifiers(snippet, max_items=2)
    file_var = vars_found[0] if vars_found else "user_path"
    return "\n".join(
        [
            "from pathlib import Path",
            "base_dir = Path('/app/data').resolve()",
            f"requested = str({file_var}).lstrip('/\\\\')",
            "safe_path = (base_dir / requested).resolve()",
            "if base_dir not in safe_path.parents and safe_path != base_dir:",
            "    raise ValueError('Invalid path')",
        ]
    )


def _build_xss_fix(snippet: str) -> str:
    sink_match = re.search(r"=\s*([A-Za-z_][A-Za-z0-9_]*)", snippet or "")
    payload_var = sink_match.group(1) if sink_match else "user_input"
    return "\n".join(
        [
            "from markupsafe import escape",
            f"safe_output = escape(str({payload_var}))",
            "target_element.textContent = safe_output",
        ]
    )


def _build_eval_fix(snippet: str) -> str:
    vars_found = _extract_identifiers(snippet, max_items=1)
    expr_var = vars_found[0] if vars_found else "expression"
    return "\n".join(
        [
            "import ast",
            f"tree = ast.parse(str({expr_var}), mode='eval')",
            "validate_allowed_nodes(tree)",
            "result = evaluate_safe_ast(tree)",
        ]
    )


def _fix_artifacts(vulnerability_type: str, evidence: str | None, recommendation: str, file_path: str) -> tuple[str, str, str, str]:
    lowered = vulnerability_type.lower()
    original = evidence.strip() if evidence else ""
    fixed = recommendation.strip()
    confidence = "Medium"
    snippet = original or recommendation or ""

    if "sql injection" in lowered:
        fixed = _build_sql_fix(snippet)
        confidence = "High"
    elif "xss" in lowered:
        fixed = _build_xss_fix(snippet)
        confidence = "High"
    elif "command injection" in lowered:
        fixed = _build_command_fix(snippet)
        confidence = "High"
    elif "path traversal" in lowered:
        fixed = _build_path_fix(snippet)
        confidence = "High"
    elif "secret" in lowered or "hardcoded" in lowered:
        vars_found = _extract_identifiers(snippet, max_items=1)
        key_name = vars_found[0].upper() if vars_found else "API_KEY"
        value_name = vars_found[0] if vars_found else "secret_value"
        fixed = "import os\n" + f"{value_name} = os.environ[{key_name!r}]  # managed by vault/secret manager"
        confidence = "High"
    elif "weak cryptography" in lowered:
        fixed = (
            "import hashlib\n"
            "digest = hashlib.sha256(payload).hexdigest()"
        )
        confidence = "High"
    elif "deserialization" in lowered:
        fixed = (
            "payload = json.loads(input_data)\n"
            "validate_schema(payload)"
        )
        confidence = "Medium"
    elif "unsafe eval" in lowered:
        fixed = _build_eval_fix(snippet)
        confidence = "High"
    elif "race condition" in lowered:
        fixed = (
            "with file_lock:\n"
            "    update_shared_resource()"
        )
        confidence = "Medium"
    elif "memory safety" in lowered:
        fixed = (
            "if index < 0 or index >= buffer_length:\n"
            "    return ERROR_OUT_OF_BOUNDS;"
        )
        confidence = "Medium"
    elif "authentication" in lowered or "authorization" in lowered:
        fixed = (
            "if not current_user.has_permission('resource:write'):\n"
            "    raise PermissionDenied()"
        )
        confidence = "Medium"
    elif recommendation:
        fixed = recommendation.strip()
        if original:
            fixed = (
                "# Context-aware remediation required for this exact code path.\n"
                f"# Original: {original[:180]}\n"
                f"# Guidance: {recommendation.strip()}"
            )
        confidence = "Low"

    if not original:
        original = "# Source snippet unavailable from CodeSentinelX evidence."
    if not fixed:
        fixed = "# Manual remediation required."

    patch_preview = "\n".join(
        [
            f"--- {file_path}",
            f"+++ {file_path}",
            f"- {original}",
            f"+ {fixed}",
        ]
    )

    return original, fixed, patch_preview, confidence


def _enriched_findings(findings: list[Finding]) -> list[dict]:
    enriched: list[dict] = []
    for finding in findings:
        base = finding.to_dict()
        base["rule_id"] = _normalize_rule_id(base.get("rule_id"))
        attack_scenario, exploitation_example, proof_of_concept_template, secure_fix_example = _scenario_for(
            finding.vulnerability_type
        )
        original_code, fixed_code, patch_preview, autofix_confidence = _fix_artifacts(
            finding.vulnerability_type,
            finding.evidence,
            finding.recommendation,
            finding.file_path,
        )
        base["cvss_score"] = _severity_cvss(base["severity"])
        base["vulnerability_title"] = finding.vulnerability_type
        base["cwe_id"] = finding.cwe or "N/A"
        normalized_owasp = normalize_owasp_top10_label(finding.owasp_category)
        base["owasp_mapping"] = normalized_owasp
        if normalized_owasp != finding.owasp_category:
            base["owasp_mapping_legacy"] = finding.owasp_category
        base["vulnerability_title"] = _resolved_vulnerability_title(base)
        base["attack_scenario"] = attack_scenario
        base["exploitation_example"] = exploitation_example
        base["proof_of_concept_template"] = proof_of_concept_template
        base["proof_of_concept"] = proof_of_concept_template
        base["secure_code_example"] = secure_fix_example
        base["affected_module"] = _module_name(finding.file_path)
        base["vulnerable_code_snippet"] = finding.evidence or ""
        base["original_code"] = original_code
        base["fixed_code"] = fixed_code
        base["patch_preview"] = patch_preview
        base["autofix_confidence"] = autofix_confidence
        base["finding_uid"] = f"{base.get('rule_id', '')}::{base.get('file_path', '')}::{base.get('line_number', 0)}"
        base["evidence_sources"] = [str(base.get("rule_id", ""))]
        base["evidence_origins"] = [str(base.get("origin") or "rule_engine")]
        if _is_dependency_finding_payload(base):
            base.update(
                _extract_dependency_metadata(
                    finding.evidence or "",
                    finding.description or "",
                    finding.recommendation or "",
                    finding.reference or "",
                )
            )
        enriched.append(base)
    return enriched


def _deduplicate_enriched_findings(findings: list[dict]) -> list[dict]:
    unique: dict[tuple[str, int, str, str], dict] = {}
    for item in findings:
        normalized_path = str(item.get("file_path", "")).replace("\\", "/").lower()
        line_number = int(item.get("line_number", 0) or 0)
        line_block = max(1, line_number // 5) if line_number > 0 else 0
        advisory_tokens = sorted(
            {
                token
                for token in (
                    normalize_cve_id(value)
                    for value in list(item.get("cve_ids") or [])
                )
                if token
            }
            | {
                str(value).strip().upper()
                for value in list(item.get("advisory_ids") or [])
                if str(value).strip()
            }
            | ({str(item.get("dependency_id")).strip().upper()} if item.get("dependency_id") else set())
        )
        is_dependency = _is_dependency_finding_payload(item)
        if is_dependency and advisory_tokens:
            key = (
                normalized_path,
                0,
                f"dependency::{str(item.get('dependency_name') or '').strip().lower()}::{str(item.get('dependency_version') or '').strip().lower()}",
                "|".join(advisory_tokens),
            )
        elif _is_sast_overlap_candidate(item):
            key = (
                normalized_path,
                line_block,
                f"sast::{_canonical_sast_family(item)}",
                _normalize_snippet(str(item.get("vulnerable_code_snippet", "") or item.get("original_code", ""))).lower(),
            )
        else:
            key = (
                normalized_path,
                line_number,
                str(item.get("vulnerability_title", item.get("vulnerability_type", ""))).strip().lower(),
                _normalize_snippet(str(item.get("original_code", "") or item.get("vulnerable_code_snippet", ""))).lower(),
            )
        current = unique.get(key)
        if current is None:
            unique[key] = item
            continue

        existing_rank = SEVERITY_RANK.get(str(current.get("severity", "Info")), 99)
        incoming_rank = SEVERITY_RANK.get(str(item.get("severity", "Info")), 99)

        incoming_reliability = _source_reliability(item)
        existing_reliability = _source_reliability(current)
        incoming_wins = incoming_rank < existing_rank or (incoming_rank == existing_rank and incoming_reliability > existing_reliability)
        if incoming_wins:
            merged = item
            merged_sources = set(current.get("evidence_sources", [])) | {str(item.get("rule_id", ""))}
            merged["evidence_sources"] = sorted(source for source in merged_sources if source)
            merged_origins = set(current.get("evidence_origins", [])) | {str(item.get("origin") or "rule_engine")}
            merged["evidence_origins"] = sorted(origin for origin in merged_origins if origin)
            merged["cve_ids"] = sorted(
                {
                    str(token).strip().upper()
                    for token in list(current.get("cve_ids") or []) + list(item.get("cve_ids") or [])
                    if str(token).strip()
                }
            )
            merged["advisory_ids"] = sorted(
                {
                    str(token).strip().upper()
                    for token in list(current.get("advisory_ids") or []) + list(item.get("advisory_ids") or [])
                    if str(token).strip()
                }
            )
            unique[key] = merged
        else:
            merged_sources = set(current.get("evidence_sources", [])) | {str(item.get("rule_id", ""))}
            current["evidence_sources"] = sorted(source for source in merged_sources if source)
            merged_origins = set(current.get("evidence_origins", [])) | {str(item.get("origin") or "rule_engine")}
            current["evidence_origins"] = sorted(origin for origin in merged_origins if origin)
            current["cve_ids"] = sorted(
                {
                    str(token).strip().upper()
                    for token in list(current.get("cve_ids") or []) + list(item.get("cve_ids") or [])
                    if str(token).strip()
                }
            )
            current["advisory_ids"] = sorted(
                {
                    str(token).strip().upper()
                    for token in list(current.get("advisory_ids") or []) + list(item.get("advisory_ids") or [])
                    if str(token).strip()
                }
            )
            if not current.get("recommendation") and item.get("recommendation"):
                current["recommendation"] = item["recommendation"]
            if not current.get("fixed_code") and item.get("fixed_code"):
                current["fixed_code"] = item["fixed_code"]

    deduped = list(unique.values())
    deduped.sort(
        key=lambda entry: (
            SEVERITY_RANK.get(str(entry.get("severity", "Info")), 99),
            -float(entry.get("cvss_score", 0.0)),
            str(entry.get("file_path", "")),
            int(entry.get("line_number", 0)),
        )
    )
    return deduped


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return slug[:96] if slug else "alert"


def _annotate_alert_grouping(findings: list[dict]) -> list[dict]:
    title_groups: dict[str, list[dict]] = {}
    full_groups: dict[tuple[str, str, str], list[dict]] = {}

    for item in findings:
        title = _resolved_vulnerability_title(item)
        cwe = str(item.get("cwe_id") or item.get("cwe") or "N/A").strip() or "N/A"
        owasp = normalize_owasp_top10_label(str(item.get("owasp_mapping") or item.get("owasp_category") or "N/A"))
        title_key = title.strip().lower() or "issue"
        full_key = (title_key, cwe.lower(), owasp.lower())
        title_groups.setdefault(title_key, []).append(item)
        full_groups.setdefault(full_key, []).append(item)

    def sort_key(item: dict) -> tuple[int, float, str, int, str]:
        return (
            SEVERITY_RANK.get(_normalize_severity_label(item.get("severity")), 99),
            -float(item.get("cvss_score", 0.0)),
            str(item.get("file_path", "")),
            int(item.get("line_number", 0) or 0),
            str(item.get("finding_uid", "")),
        )

    for title_key, group in title_groups.items():
        group_uid = _slugify(title_key)
        ordered = sorted(group, key=sort_key)
        for index, item in enumerate(ordered, start=1):
            item["alert_title_group_uid"] = group_uid
            item["alert_title_group_title"] = _resolved_vulnerability_title(item)
            item["alert_title_group_instance_index"] = index
            item["alert_title_group_instance_count"] = len(ordered)
            item["alert_title_group_anchor"] = f"alert-title-{group_uid}"

    for (title_key, cwe_key, owasp_key), group in full_groups.items():
        group_uid = _slugify(f"{title_key}::{cwe_key}::{owasp_key}")
        ordered = sorted(group, key=sort_key)
        for index, item in enumerate(ordered, start=1):
            item["alert_group_uid"] = group_uid
            item["alert_group_title"] = _resolved_vulnerability_title(item)
            item["alert_group_cwe"] = str(item.get("cwe_id") or item.get("cwe") or "N/A")
            item["alert_group_owasp"] = normalize_owasp_top10_label(str(item.get("owasp_mapping") or item.get("owasp_category") or "N/A"))
            item["alert_group_instance_index"] = index
            item["alert_group_instance_count"] = len(ordered)
            item["alert_group_anchor"] = f"alert-group-{group_uid}"
    return findings


_REPORT_NOISE_SEGMENTS = {
    ".venv",
    "venv",
    "env",
    "virtualenv",
    "site-packages",
    "node_modules",
    "bower_components",
    "vendor",
    "third_party",
    "external",
    "deps",
    ".toolchain",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    "coverage",
    "reports",
    "artifacts",
    "tmp",
    "temp",
    "logs",
    "packages",
}

_SOURCE_RELIABILITY_RANK = {
    "grype": 4,
    "osv": 3,
    "osv-scanner": 3,
    "codeql": 3,
    "semgrep": 3,
    "bandit": 2,
    "gosec": 2,
    "checkov": 2,
    "tfsec": 2,
}


def _normalized_report_path(value: str) -> str:
    return str(value or "").replace("\\", "/").strip().strip("/")


def _is_report_noise_finding(item: dict) -> bool:
    normalized = _normalized_report_path(str(item.get("file_path") or "")).lower()
    if not normalized:
        return False

    parts = [part for part in normalized.split("/") if part]
    if any(part in _REPORT_NOISE_SEGMENTS for part in parts):
        return True

    if any(part in {"tests", "test", "spec", "__tests__", "fixtures", "testdata", "mocks", "snapshots"} for part in parts):
        return True

    basename = parts[-1] if parts else normalized
    if basename.endswith((".min.js", ".min.css", ".bundle.js", ".chunk.js")):
        return True

    return False


def _filter_report_noise(findings: list[dict]) -> tuple[list[dict], int]:
    filtered = [item for item in findings if not _is_report_noise_finding(item)]
    return filtered, max(0, len(findings) - len(filtered))


def _severity_distribution_from_enriched(findings: list[dict]) -> dict[str, int]:
    counts = Counter(_normalize_severity_label(item.get("severity")) for item in findings)
    return {
        "Critical": counts.get("Critical", 0),
        "High": counts.get("High", 0),
        "Medium": counts.get("Medium", 0),
        "Low": counts.get("Low", 0),
        "Info": counts.get("Info", 0),
    }


def _severity_distribution_from_scan_findings(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(_normalize_severity_label(getattr(item, "severity", None)) for item in findings)
    return {
        "Critical": counts.get("Critical", 0),
        "High": counts.get("High", 0),
        "Medium": counts.get("Medium", 0),
        "Low": counts.get("Low", 0),
        "Info": counts.get("Info", 0),
    }


def _risk_score_from_distribution(distribution: dict[str, int]) -> float:
    total = sum(distribution.values())
    if total == 0:
        return 0.0

    weighted_sum = sum(distribution.get(level, 0) * SEVERITY_WEIGHT.get(level, 0) for level in SEVERITY_WEIGHT)
    max_weighted_sum = total * SEVERITY_WEIGHT["Critical"]
    severity_factor = (weighted_sum / max_weighted_sum) * 60.0
    count_factor = min(total / 50.0, 1.0) * 40.0
    return round(min(100.0, severity_factor + count_factor), 2)


def _affected_modules(findings: list[dict], limit: int = 10) -> list[dict[str, int | str]]:
    module_counter: Counter[str] = Counter()
    critical_counter: Counter[str] = Counter()
    high_counter: Counter[str] = Counter()
    for item in findings:
        module = str(item.get("affected_module", "root"))
        module_counter[module] += 1
        sev = _normalize_severity_label(item.get("severity"))
        if sev == "Critical":
            critical_counter[module] += 1
        if sev == "High":
            high_counter[module] += 1

    rows: list[dict[str, int | str]] = []
    for module, count in module_counter.most_common(limit):
        rows.append(
            {
                "module": module,
                "count": count,
                "critical": critical_counter.get(module, 0),
                "high": high_counter.get(module, 0),
            }
        )
    return rows


def _folder_name(file_path: str) -> str:
    normalized = file_path.replace("\\", "/").strip()
    if not normalized:
        return "."
    if normalized.startswith("http://") or normalized.startswith("https://"):
        scheme, _, rest = normalized.partition("://")
        host, _, path = rest.partition("/")
        if not path:
            return f"{scheme}://{host}"
        folder = path.rsplit("/", 1)[0] if "/" in path else ""
        if not folder:
            return f"{scheme}://{host}"
        return f"{scheme}://{host}/{folder}"
    if normalized.startswith("ssh://"):
        without_scheme = normalized.split("://", 1)[1]
        host, _, remote = without_scheme.partition("/")
        if not remote:
            return f"ssh://{host}"
        folder = remote.rsplit("/", 1)[0] if "/" in remote else ""
        if not folder:
            return f"ssh://{host}"
        return f"ssh://{host}/{folder}"
    if "/" not in normalized:
        return "."
    return normalized.rsplit("/", 1)[0] or "."


def _affected_files(findings: list[dict], limit: int = 40) -> list[dict[str, int | str]]:
    file_counter: Counter[str] = Counter()
    critical_counter: Counter[str] = Counter()
    high_counter: Counter[str] = Counter()
    for item in findings:
        file_path = str(item.get("file_path", "unknown"))
        file_counter[file_path] += 1
        sev = _normalize_severity_label(item.get("severity"))
        if sev == "Critical":
            critical_counter[file_path] += 1
        if sev == "High":
            high_counter[file_path] += 1

    rows: list[dict[str, int | str]] = []
    for file_path, count in file_counter.most_common(limit):
        rows.append(
            {
                "file": file_path,
                "folder": _folder_name(file_path),
                "count": count,
                "critical": critical_counter.get(file_path, 0),
                "high": high_counter.get(file_path, 0),
            }
        )
    return rows


def _affected_folders(findings: list[dict], limit: int = 20) -> list[dict[str, int | str]]:
    folder_counter: Counter[str] = Counter()
    critical_counter: Counter[str] = Counter()
    high_counter: Counter[str] = Counter()
    for item in findings:
        folder = _folder_name(str(item.get("file_path", "unknown")))
        folder_counter[folder] += 1
        sev = _normalize_severity_label(item.get("severity"))
        if sev == "Critical":
            critical_counter[folder] += 1
        if sev == "High":
            high_counter[folder] += 1

    rows: list[dict[str, int | str]] = []
    for folder, count in folder_counter.most_common(limit):
        rows.append(
            {
                "folder": folder,
                "count": count,
                "critical": critical_counter.get(folder, 0),
                "high": high_counter.get(folder, 0),
            }
        )
    return rows


def _build_action_plan(distribution: dict[str, int], findings: list[dict]) -> list[str]:
    plan: list[str] = []

    if distribution.get("Critical", 0) > 0:
        plan.append("Immediately remediate Critical findings that allow remote compromise or data exfiltration.")
    if distribution.get("High", 0) > 0:
        plan.append("Prioritize High findings in current sprint and enforce code-owner verification before release.")
    if distribution.get("Medium", 0) > 0:
        plan.append("Schedule Medium findings for upcoming hardening cycle and add regression tests.")
    if distribution.get("Low", 0) > 0:
        plan.append("Track Low findings in backlog and resolve during maintenance windows.")

    ranked_findings = sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK.get(_normalize_severity_label(item.get("severity")), 99),
            -float(item.get("cvss_score", 0.0)),
        ),
    )
    top_specific: list[dict] = []
    seen_specific: set[tuple[str, str, str, str]] = set()
    for item in ranked_findings:
        severity = _normalize_severity_label(item.get("severity"))
        if severity not in {"Critical", "High", "Medium"}:
            continue
        title = str(item.get("vulnerability_title") or item.get("vulnerability_type") or "Issue").strip()
        cwe = str(item.get("cwe_id") or item.get("cwe") or "").strip().upper()
        owasp = str(item.get("owasp_mapping") or item.get("owasp_category") or "").strip()
        file_path = str(item.get("file_path") or "unknown").replace("\\", "/").strip()
        dedup_key = (severity, title.lower(), cwe or "N/A", file_path.lower())
        if dedup_key in seen_specific:
            continue
        seen_specific.add(dedup_key)
        top_specific.append(
            {
                "severity": severity,
                "title": title,
                "cwe": cwe or "N/A",
                "owasp": owasp or "N/A",
                "file_path": file_path,
                "line": int(item.get("line_number", 1) or 1),
            }
        )
        if len(top_specific) >= 5:
            break
    for idx, finding in enumerate(top_specific, start=1):
        plan.append(
            f"Top-{idx} {finding['severity']} focus: {finding['title']} ({finding['cwe']} / {finding['owasp']}) at {finding['file_path']}:{finding['line']}."
        )

    text_blob = " ".join(
        " ".join(
            [
                str(item.get("vulnerability_title") or item.get("vulnerability_type") or ""),
                str(item.get("owasp_mapping") or item.get("owasp_category") or ""),
                str(item.get("cwe_id") or item.get("cwe") or ""),
                str(item.get("description") or ""),
            ]
        )
        for item in findings
    ).lower()
    dependency_findings = sum(
        1
        for item in findings
        if str(item.get("dependency_name") or "").strip()
        or "dependency" in str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").lower()
        or str(item.get("owasp_mapping") or "").upper().startswith("A06:")
    )
    secret_findings = sum(
        1
        for item in findings
        if "secret" in str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").lower()
        or "credential" in str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").lower()
        or "api key" in str(item.get("description") or "").lower()
    )
    auth_findings = sum(
        1
        for item in findings
        if "auth" in str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").lower()
        or "session" in str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").lower()
        or str(item.get("owasp_mapping") or "").upper().startswith(("A01:", "A07:"))
    )

    if dependency_findings > 0:
        plan.append(
            f"Prioritize dependency remediation for {dependency_findings} advisory-backed finding(s), starting with runtime-reachable packages."
        )
    if secret_findings > 0:
        plan.append(
            f"Rotate and revoke exposed credentials/secrets ({secret_findings} finding(s)); enforce secret scanning and pre-commit protections."
        )
    if auth_findings > 0:
        plan.append(
            f"Strengthen authorization/session controls for {auth_findings} auth-related finding(s), including object-level access checks and session hardening."
        )
    if any(token in text_blob for token in ("sql injection", "cwe-89", "command injection", "cwe-78", "xss", "cwe-79", "path traversal", "cwe-22")):
        plan.append(
            "Add targeted regression tests for injection/path-traversal classes and enforce parameterized queries + strict input validation."
        )
    if any(token in text_blob for token in ("misconfig", "cwe-16", "dockerfile", "terraform", "kubernetes", "checkov", "tfsec")):
        plan.append(
            "Harden infrastructure/config baselines in CI (IaC policy checks, container hardening rules, and mandatory review gates)."
        )
    if not plan:
        plan.append("Maintain secure coding guardrails in CI and verify remediation through targeted validation runs.")

    return list(dict.fromkeys(plan))


def _controls_summary(controls: list[SecurityControl]) -> dict:
    category_counts = Counter(control.category for control in controls)
    mapping_counts: Counter[str] = Counter()
    coverage_counts = Counter(control.coverage_level for control in controls)

    for control in controls:
        for mapping in control.standard_mappings:
            mapping_counts[mapping] += 1

    return {
        "implemented_controls": len(controls),
        "category_distribution": dict(category_counts),
        "standards_coverage": dict(mapping_counts),
        "coverage_levels": dict(coverage_counts),
    }


def _compliance_matrix(controls_summary: dict) -> list[dict[str, str | int]]:
    standards = controls_summary.get("standards_coverage", {})
    matrix: list[dict[str, str | int]] = []
    for standard, count in sorted(standards.items(), key=lambda item: (-item[1], item[0])):
        status = "covered"
        if count < 2:
            status = "partial"
        matrix.append(
            {
                "standard": standard,
                "control_count": int(count),
                "status": status,
            }
        )
    return matrix


def _autofix_recommendations(enriched_findings: list[dict], limit: int = 80) -> list[dict]:
    scored = sorted(
        enriched_findings,
        key=lambda item: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(str(item.get("severity", "Info")), 9),
            -float(item.get("cvss_score", 0.0)),
        ),
    )

    recommendations: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for item in scored:
        key = (
            str(item.get("rule_id", "")),
            str(item.get("file_path", "")),
            int(item.get("line_number", 0)),
        )
        if key in seen:
            continue
        seen.add(key)

        recommendations.append(
            {
                "priority": item.get("severity", "Medium"),
                "cvss_score": item.get("cvss_score", 0.0),
                "vulnerability_title": item.get("vulnerability_title", item.get("vulnerability_type", "Issue")),
                "file_path": item.get("file_path"),
                "line_number": item.get("line_number"),
                "recommended_fix": item.get("recommendation"),
                "secure_code_example": item.get("secure_code_example"),
                "original_code": item.get("original_code"),
                "fixed_code": item.get("fixed_code"),
                "patch_preview": item.get("patch_preview"),
                "autofix_confidence": item.get("autofix_confidence", "Medium"),
                "automation_hint": "Open a remediation PR with unit tests for the vulnerable path.",
            }
        )

        if len(recommendations) >= limit:
            break

    return recommendations


def _active_poc_summary(findings: list[dict]) -> dict[str, int]:
    summary = {
        "executed": 0,
        "verified": 0,
        "failed": 0,
        "inconclusive": 0,
        "skipped": 0,
    }
    for item in findings:
        active = item.get("active_poc") or {}
        if active.get("executed"):
            summary["executed"] += 1
        status = _active_poc_status(active)
        if status == "verified":
            summary["verified"] += 1
        elif status == "inconclusive":
            summary["inconclusive"] += 1
        elif status in {"error", "failed"}:
            summary["failed"] += 1
        else:
            summary["skipped"] += 1
    return summary


def _build_fix_window_plan(findings: list[dict]) -> dict[str, list[dict[str, object]]]:
    ranked = sorted(findings, key=lambda item: -float(item.get("risk_priority_score", item.get("cvss_score", 0.0))))
    windows = {"8_hours": 2, "24_hours": 6, "72_hours": 12}
    plan: dict[str, list[dict[str, object]]] = {}
    for window, limit in windows.items():
        rows: list[dict[str, object]] = []
        for item in ranked[:limit]:
            rows.append(
                {
                    "finding_uid": item.get("finding_uid"),
                    "title": item.get("vulnerability_title", item.get("vulnerability_type", "Security Finding")),
                    "severity": item.get("severity", "Info"),
                    "file_path": item.get("file_path", ""),
                    "line_number": int(item.get("line_number", 1) or 1),
                    "priority_score": float(item.get("risk_priority_score", item.get("cvss_score", 0.0))),
                    "why_first": item.get("ai_remediation_summary", item.get("recommendation", "")),
                    "recommended_fix": item.get("ai_suggested_fix", item.get("fixed_code", item.get("recommendation", ""))),
                    "validation_command": (item.get("active_poc") or {}).get("command", ""),
                    "fix_confidence_label": item.get("ai_fix_confidence_label", "Medium"),
                    "fix_confidence_score": float(item.get("ai_fix_confidence_score", 0.6)),
                }
            )
        plan[window] = rows
    return plan


def _overlay_provider_plan(findings: list[dict], base_plan: dict[str, list[dict[str, object]]], provider_plan: dict[str, list[dict[str, object]]] | None) -> dict[str, list[dict[str, object]]]:
    if not provider_plan:
        return base_plan
    by_uid = {str(item.get("finding_uid") or ""): item for item in findings}
    merged = {key: list(value) for key, value in base_plan.items()}
    for window, rows in provider_plan.items():
        hydrated: list[dict[str, object]] = []
        for row in rows:
            uid = str(row.get("finding_uid") or "").strip()
            finding = by_uid.get(uid)
            if not finding:
                continue
            hydrated.append(
                {
                    "finding_uid": uid,
                    "title": finding.get("vulnerability_title", finding.get("vulnerability_type", "Security Finding")),
                    "severity": finding.get("severity", "Info"),
                    "file_path": finding.get("file_path", ""),
                    "line_number": int(finding.get("line_number", 1) or 1),
                    "priority_score": float(row.get("priority_score") or finding.get("risk_priority_score", finding.get("cvss_score", 0.0))),
                    "why_first": row.get("why_first") or finding.get("ai_remediation_summary", finding.get("recommendation", "")),
                    "recommended_fix": finding.get("ai_suggested_fix", finding.get("fixed_code", finding.get("recommendation", ""))),
                    "validation_command": (finding.get("active_poc") or {}).get("command", ""),
                    "fix_confidence_label": finding.get("ai_fix_confidence_label", "Medium"),
                    "fix_confidence_score": float(row.get("fix_confidence_score") or finding.get("ai_fix_confidence_score", 0.6)),
                }
            )
        if hydrated:
            merged[window] = hydrated
    return merged


def _run_workspace_command(command: str, cwd: Path, timeout_sec: int = 180) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "command": command,
            "status": "failed",
            "exit_code": 1,
            "output": str(exc),
        }
    output = "\n".join(part for part in [completed.stdout.strip(), completed.stderr.strip()] if part).strip()
    return {
        "command": command,
        "status": "success" if completed.returncode == 0 else "failed",
        "exit_code": completed.returncode,
        "output": output,
    }


def _run_fix_verification(item: dict, target_path: str) -> dict[str, object]:
    active_poc = item.get("active_poc") or {}
    target_root = Path(target_path).expanduser().resolve()
    relative_file = Path(str(item.get("file_path", "")))
    source_path = target_root / relative_file
    if not source_path.exists():
        return {"performed": False, "result": "not_applicable", "reason": "Source file not available for post-fix verification."}

    if not str(item.get("fixed_code") or "").strip():
        return {"performed": False, "result": "not_applicable", "reason": "No concrete fix artifact available for post-fix verification."}

    if _active_poc_status(active_poc) not in {"verified", "inconclusive"}:
        return {"performed": False, "result": "skipped", "reason": "Pre-fix validation did not produce reusable verification context."}

    try:
        original_text = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {"performed": False, "result": "skipped", "reason": "Unable to read source file for verification."}

    lines = original_text.splitlines()
    line_number = int(item.get("line_number", 1) or 1)
    if line_number < 1 or line_number > max(1, len(lines)):
        return {"performed": False, "result": "not_applicable", "reason": "Finding line is outside the current source file bounds."}

    replacement_lines = str(item.get("fixed_code") or "").splitlines() or [str(item.get("fixed_code") or "")]
    modified_lines = lines[: line_number - 1] + replacement_lines + lines[line_number:]
    modified_text = "\n".join(modified_lines)

    suffix = source_path.suffix.lower()
    syntax_reason = "Syntax verification unavailable for this file type."
    if suffix == ".py":
        try:
            compile(modified_text, str(source_path), "exec")
            syntax_reason = "Python syntax compiled successfully in temp workspace."
        except SyntaxError as exc:
            return {
                "performed": True,
                "result": "verification_failed",
                "reason": f"Candidate fix does not compile as Python: {exc.msg} (line {exc.lineno}).",
                "pre_fix_status": _active_poc_status(active_poc),
                "post_fix_status": "verification_failed",
                "post_fix_execution": {"command": "python-compile", "status": "failed", "exit_code": 1, "output": str(exc)},
            }

    build_command = str((os.environ.get("USS_FIX_VERIFY_BUILD_COMMAND") or "")).strip()
    test_command = str((os.environ.get("USS_FIX_VERIFY_TEST_COMMAND") or "")).strip()
    command_timeout = max(30, int((os.environ.get("USS_FIX_VERIFY_COMMAND_TIMEOUT_SEC") or "180")))

    with TemporaryDirectory(prefix="codesentinelx-fix-verify-") as tmp_dir:
        temp_root = Path(tmp_dir)
        if build_command or test_command:
            workspace = temp_root / "workspace"
            shutil.copytree(
                target_root,
                workspace,
                ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__", ".toolchain", "dist", "build", "exports", "CodeSentinelX_Reports"),
            )
            temp_target = workspace / relative_file
            temp_target.parent.mkdir(parents=True, exist_ok=True)
        else:
            workspace = temp_root
            temp_target = temp_root / source_path.name
        temp_target.write_text(modified_text, encoding="utf-8")

        build_verification = _run_workspace_command(build_command, workspace, command_timeout) if build_command else None
        if build_verification and build_verification.get("status") != "success":
            return {
                "performed": True,
                "result": "verification_failed",
                "reason": "Candidate fix failed workspace build verification.",
                "pre_fix_status": _active_poc_status(active_poc),
                "post_fix_status": "verification_failed",
                "post_fix_execution": build_verification,
                "build_verification": build_verification,
            }

        test_verification = _run_workspace_command(test_command, workspace, command_timeout) if test_command else None
        if test_verification and test_verification.get("status") != "success":
            return {
                "performed": True,
                "result": "verification_failed",
                "reason": "Candidate fix failed workspace test verification.",
                "pre_fix_status": _active_poc_status(active_poc),
                "post_fix_status": "verification_failed",
                "post_fix_execution": test_verification,
                "build_verification": build_verification,
                "test_verification": test_verification,
            }

        rerun = verify_finding(
            ValidationContext(
                target_root=str(workspace),
                file_path=str(temp_target.relative_to(workspace)).replace("\\", "/"),
                line_number=line_number,
                vulnerability_type=str(item.get("vulnerability_title") or item.get("vulnerability_type") or ""),
                rule_id=str(item.get("rule_id", "")),
                cwe_id=str(item.get("cwe_id", "")),
                evidence=str(item.get("vulnerable_code_snippet") or item.get("original_code") or ""),
            )
        ).to_dict()

    post_status = _active_poc_status(rerun)
    if post_status in {"not_applicable", "error"}:
        result = "verified_fixed"
        reason = f"Post-fix rerun no longer confirmed the vulnerable pattern. {syntax_reason}"
    elif post_status == "inconclusive" and _active_poc_status(active_poc) == "verified":
        result = "manual_review_required"
        reason = "Post-fix rerun reduced confidence but did not fully eliminate the finding; manual review is required."
    else:
        result = "still_vulnerable"
        reason = "Post-fix rerun still confirms the vulnerable pattern."

    return {
        "performed": True,
        "result": result,
        "reason": reason,
        "pre_fix_status": _active_poc_status(active_poc),
        "post_fix_status": post_status,
        "post_fix_execution": {
            "command": rerun.get("command"),
            "status": rerun.get("status"),
            "exit_code": rerun.get("exit_code"),
            "output": rerun.get("output"),
        },
        "build_verification": build_verification,
        "test_verification": test_verification,
    }


def _fix_verification_summary(findings: list[dict]) -> dict[str, int]:
    summary = {
        "performed": 0,
        "verified_fixed": 0,
        "verification_failed": 0,
        "inconclusive": 0,
        "not_applicable": 0,
        "skipped": 0,
        "build_verified": 0,
        "build_failed": 0,
        "test_verified": 0,
        "test_failed": 0,
    }
    for item in findings:
        verification = item.get("fix_verification") or {}
        if verification.get("performed"):
            summary["performed"] += 1
        result = str(verification.get("result") or "not_applicable").strip().lower()
        if result == "verified_fixed":
            summary["verified_fixed"] += 1
        elif result in {"verification_failed", "still_vulnerable"}:
            summary["verification_failed"] += 1
        elif result in {"manual_review_required", "inconclusive"}:
            summary["inconclusive"] += 1
        elif result == "skipped":
            summary["skipped"] += 1
        else:
            summary["not_applicable"] += 1
        build_verification = verification.get("build_verification") or {}
        if str(build_verification.get("status") or "").lower() == "success":
            summary["build_verified"] += 1
        elif build_verification:
            summary["build_failed"] += 1
        test_verification = verification.get("test_verification") or {}
        if str(test_verification.get("status") or "").lower() == "success":
            summary["test_verified"] += 1
        elif test_verification:
            summary["test_failed"] += 1
    return summary


def _dependency_reachability(findings: list[dict], target_path: str) -> None:
    root = Path(target_path).expanduser().resolve()
    if not root.exists():
        return
    inventory = build_dependency_inventory(root)
    usage_map = build_dependency_usage_map(root)

    for item in findings:
        package_name = str(item.get("dependency_name") or "").strip()
        advisory_meta = advisory_identity(
            list(item.get("advisory_ids") or []) + list(item.get("cve_ids") or []) + ([str(item.get("dependency_id"))] if item.get("dependency_id") else [])
        )
        if not package_name:
            continue
        normalized_name = normalize_package_name(package_name)
        dependency_row = inventory.get(normalized_name, {})
        aliases = sorted({package_name, *[str(alias) for alias in dependency_row.get("package_aliases", set()) if str(alias).strip()]})
        hits: list[str] = []
        for alias in aliases:
            hits.extend(usage_map.get(normalize_package_name(alias), []))
        hits = list(dict.fromkeys(hits))
        manifest_paths = sorted(str(path) for path in dependency_row.get("manifest_paths", set()))
        lockfile_paths = sorted(str(path) for path in dependency_row.get("lockfile_paths", set()))
        declared_versions = sorted(str(version) for version in dependency_row.get("declared_versions", set()) if str(version).strip())
        locked_versions = sorted(str(version) for version in dependency_row.get("locked_versions", set()) if str(version).strip())
        manifest_present = bool(manifest_paths)
        lockfile_present = bool(lockfile_paths)
        if hits:
            status = "reachable_in_code"
            score = 0.92
            priority_factor = 1.3
        elif lockfile_present:
            status = "installed_locked"
            score = 0.72
            priority_factor = 1.0
        elif manifest_present:
            status = "declared_only"
            score = 0.46
            priority_factor = 0.78
        else:
            status = "unverified_dependency"
            score = 0.18
            priority_factor = 0.45
        source_hint = (
            f"Imported in code: {', '.join(hits[:3])}."
            if hits
            else "No direct code import/use evidence found in scanned application sources."
        )
        manifest_hint = (
            f"Manifest entries: {', '.join(manifest_paths[:3])}."
            if manifest_present
            else "No matching manifest entry was found locally."
        )
        lockfile_hint = (
            f"Lockfile entries: {', '.join(lockfile_paths[:3])}."
            if lockfile_present
            else "No matching lockfile entry was found locally."
        )
        advisory_hint = (
            f"Advisory IDs verified: {', '.join(advisory_meta['advisory_ids'][:4])}."
            if advisory_meta["advisory_verified"]
            else "Advisory ID was not locally verifiable from the finding payload."
        )
        reasoning = " ".join([source_hint, manifest_hint, lockfile_hint, advisory_hint]).strip()
        item["dependency_reachability"] = {
            "status": status,
            "score": score,
            "priority_factor": priority_factor,
            "package_candidates": aliases[:6],
            "import_evidence": hits[:5],
            "manifest_present": manifest_present,
            "lockfile_present": lockfile_present,
            "manifest_paths": manifest_paths[:5],
            "lockfile_paths": lockfile_paths[:5],
            "declared_versions": declared_versions[:5],
            "locked_versions": locked_versions[:5],
            "advisory_ids": list(advisory_meta["advisory_ids"])[:10],
            "advisory_verified": bool(advisory_meta["advisory_verified"]),
            "reasoning": reasoning,
        }


def _apply_kev_correlation(findings: list[dict]) -> dict[str, object]:
    kev_ids, kev_meta = load_kev_catalog()
    matched_findings = 0
    matched_cves = 0
    for item in findings:
        cve_ids = [
            normalized
            for normalized in (normalize_cve_id(cve) for cve in (item.get("cve_ids") or []))
            if normalized
        ]
        matches = find_kev_matches(cve_ids, kev_ids)
        item["known_exploited"] = bool(matches)
        item["known_exploited_cves"] = matches
        item["kev_catalog_source"] = kev_meta.get("source") or "official_cisa"
        item["kev_catalog_version"] = kev_meta.get("catalog_version")
        item["kev_catalog_retrieved_at"] = kev_meta.get("retrieved_at")
        if matches:
            matched_findings += 1
            matched_cves += len(matches)
    return {
        "known_exploited_findings": matched_findings,
        "known_exploited_cves": matched_cves,
        "kev_catalog_source": kev_meta.get("source") or "official_cisa",
        "kev_catalog_version": kev_meta.get("catalog_version"),
        "kev_catalog_retrieved_at": kev_meta.get("retrieved_at"),
        "kev_catalog_count": len(kev_ids),
    }


def _folder_name(file_path: str) -> str:
    normalized = str(file_path or "").replace("\\", "/").strip("./")
    if not normalized or "/" not in normalized:
        return "."
    return normalized.rsplit("/", 1)[0] or "."


def _release_gate_action(item: dict) -> str:
    severity = str(item.get("severity") or "Info")
    poc_status = _active_poc_status(item.get("active_poc") or {})
    if severity == "Critical":
        return "Block release"
    if severity == "High":
        return "Fix before prod" if poc_status == "verified" else "Scheduled fix"
    if severity == "Medium":
        return "Scheduled fix"
    return "Track"


def _severity_sla_hours(severity: str) -> int:
    return {
        "Critical": 8,
        "High": 24,
        "Medium": 72,
        "Low": 168,
        "Info": 336,
    }.get(severity, 168)


def _estimate_financial_exposure(distribution: dict[str, int]) -> dict[str, object]:
    weighted = (
        distribution.get("Critical", 0) * 185000
        + distribution.get("High", 0) * 62000
        + distribution.get("Medium", 0) * 18000
        + distribution.get("Low", 0) * 5000
    )
    if weighted <= 0:
        return {"available": False}
    return {
        "available": True,
        "best_case_usd": round(weighted * 0.65),
        "most_likely_usd": round(weighted),
        "worst_case_usd": round(weighted * 1.85),
    }


def _estimate_downtime(distribution: dict[str, int]) -> dict[str, object]:
    weighted = (
        distribution.get("Critical", 0) * 7.5
        + distribution.get("High", 0) * 3.0
        + distribution.get("Medium", 0) * 1.25
        + distribution.get("Low", 0) * 0.4
    )
    if weighted <= 0:
        return {"available": False}
    return {
        "available": True,
        "best_case_hours": round(weighted * 0.6, 1),
        "most_likely_hours": round(weighted, 1),
        "worst_case_hours": round(weighted * 1.7, 1),
    }


def _build_toolchain_execution_summary(toolchain_status: dict[str, dict[str, object]]) -> dict[str, object]:
    selected_rows = [
        (tool_name, payload)
        for tool_name, payload in sorted(toolchain_status.items())
        if bool(payload.get("selected"))
    ]
    total_tools = len(toolchain_status)
    selected_tools = len(selected_rows)
    available_tools = sum(1 for _tool_name, payload in selected_rows if bool(payload.get("available")))
    integrated_tools = sum(1 for _tool_name, payload in selected_rows if bool(payload.get("integrated")))
    runner_available_tools = sum(1 for _tool_name, payload in selected_rows if bool(payload.get("runner_available", True)))
    unavailable_tools = sum(1 for _tool_name, payload in selected_rows if not bool(payload.get("available")))
    no_runner_tools = sum(1 for _tool_name, payload in selected_rows if not bool(payload.get("runner_available", True)))

    status_distribution: Counter[str] = Counter()
    failures: list[dict[str, object]] = []
    slowest_tools: list[dict[str, object]] = []
    timing_breakdown: list[dict[str, object]] = []
    attempted_tools = 0
    successful_tools = 0
    failed_tools = 0
    skipped_tools = 0
    total_attempted_duration_ms = 0

    for tool_name, payload in selected_rows:
        execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
        attempted = bool(execution.get("attempted"))
        available = bool(payload.get("available"))
        runner_available = bool(payload.get("runner_available", True))
        findings_count = int(execution.get("findings_count") or 0)
        error_rows = [str(item) for item in execution.get("errors", []) if str(item).strip()]
        duration_ms = int(execution.get("duration_ms") or 0)
        status = str(execution.get("status") or "").strip().lower()
        if not status:
            if not available:
                status = "unavailable"
            elif not runner_available:
                status = "no_runner"
            elif attempted:
                status = "success" if not error_rows else "failed"
            else:
                status = "skipped"

        status_distribution[status] += 1
        if attempted:
            attempted_tools += 1
            total_attempted_duration_ms += duration_ms
            if status in {"success", "partial_success"}:
                successful_tools += 1
            elif status in {"skipped", "skipped_irrelevant", "skipped_strategy", "unavailable", "no_runner"}:
                skipped_tools += 1
            else:
                failed_tools += 1
        else:
            skipped_tools += 1

        if status not in {"success", "partial_success", "skipped", "skipped_irrelevant", "skipped_strategy", "unavailable", "no_runner"} and (
            error_rows or attempted or not available or not runner_available
        ):
            failures.append(
                {
                    "tool": tool_name,
                    "status": status,
                    "message": str(payload.get("message") or "Analyzer did not complete successfully."),
                    "errors": error_rows[:6],
                }
            )

        timing_breakdown.append(
            {
                "tool": tool_name,
                "selected": True,
                "available": available,
                "runner_available": runner_available,
                "attempted": attempted,
                "status": status,
                "duration_ms": duration_ms,
                "findings_count": findings_count,
                "errors_count": len(error_rows),
                "avg_ms_per_finding": round(duration_ms / findings_count, 2) if findings_count else None,
            }
        )

        if attempted:
            slowest_tools.append(
                {
                    "tool": tool_name,
                    "duration_ms": duration_ms,
                    "findings_count": findings_count,
                    "status": status,
                }
            )

    average_attempted_duration_ms = round(total_attempted_duration_ms / attempted_tools, 2) if attempted_tools else 0.0
    success_rate_percent = round((successful_tools / attempted_tools) * 100.0, 2) if attempted_tools else 0.0

    return {
        "total_tools": total_tools,
        "selected_tools": selected_tools,
        "available_tools": available_tools,
        "integrated_tools": integrated_tools,
        "runner_available_tools": runner_available_tools,
        "attempted_tools": attempted_tools,
        "successful_tools": successful_tools,
        "failed_tools": failed_tools,
        "unavailable_tools": unavailable_tools,
        "no_runner_tools": no_runner_tools,
        "skipped_tools": skipped_tools,
        "success_rate_percent": success_rate_percent,
        "status_distribution": dict(status_distribution),
        "failures": failures[:12],
        "slowest_tools": sorted(slowest_tools, key=lambda item: -int(item["duration_ms"]))[:8],
        "total_attempted_duration_ms": total_attempted_duration_ms,
        "average_attempted_duration_ms": average_attempted_duration_ms,
        "timing_breakdown": timing_breakdown,
    }


def _build_risk_intelligence(findings: list[dict]) -> dict[str, object]:
    findings_with_cve = 0
    findings_cvss_ge_7 = 0
    known_exploited_findings = 0
    for item in findings:
        if item.get("cve_ids") or item.get("advisory_ids") or item.get("dependency_id"):
            findings_with_cve += 1
        if float(item.get("cvss_score", 0.0) or 0.0) >= 7.0:
            findings_cvss_ge_7 += 1
        if bool(item.get("known_exploited")):
            known_exploited_findings += 1
    return {
        "findings_with_cve": findings_with_cve,
        "findings_cvss_ge_7": findings_cvss_ge_7,
        "known_exploited_findings": known_exploited_findings,
    }


def _build_enterprise_assurance(
    findings: list[dict],
    toolchain_status: dict[str, dict[str, object]],
    toolchain_execution: dict[str, object],
    scan_profile: str,
    quality_benchmark: dict[str, object] | None = None,
) -> dict[str, object]:
    benchmark = quality_benchmark or {}
    selected_required = [
        tool_name
        for tool_name, payload in toolchain_status.items()
        if bool(payload.get("selected")) and bool(payload.get("runner_available", True))
    ]
    required_tools_total = len(selected_required)
    required_tools_ready = sum(
        1 for tool_name in selected_required if bool(toolchain_status.get(tool_name, {}).get("available"))
    )
    required_tools_attempted = sum(
        1
        for tool_name in selected_required
        if bool((toolchain_status.get(tool_name, {}).get("execution") or {}).get("attempted"))
    )
    required_tools_coverage_percent = (
        round((required_tools_attempted / required_tools_total) * 100.0, 2) if required_tools_total else 0.0
    )
    critical_count = sum(1 for item in findings if _normalize_severity_label(item.get("severity")) == "Critical")
    high_count = sum(1 for item in findings if _normalize_severity_label(item.get("severity")) == "High")
    blockers: list[str] = []
    advisories: list[str] = []
    if critical_count:
        blockers.append(f"{critical_count} critical finding(s) still require remediation before release.")
    if required_tools_total and required_tools_attempted == 0:
        advisories.append("Selected analyzers did not produce execution evidence for this scan.")
    for failure in (toolchain_execution.get("failures") or [])[:6]:
        if not isinstance(failure, dict):
            continue
        tool_name = str(failure.get("tool", "analyzer"))
        status_label = str(failure.get("status", "failed"))
        message = str(failure.get("message", "Analyzer did not complete successfully."))
        advisory_message = (
            f"{tool_name} status={status_label}: {message}"
        )
        lower_message = advisory_message.lower()
        if any(
            token in lower_message
            for token in (
                "non-json output",
                "query pack",
                "not found in path/toolchain",
                "install or bootstrap",
                "skipped by execution policy",
                "skipped for speed optimization",
                "skipped dependency overlap",
            )
        ):
            advisories.append(advisory_message)
            continue
        advisories.append(advisory_message)

    benchmark_status = str(benchmark.get("benchmark_status") or "").strip().lower()
    benchmark_advisories: list[str] = []
    benchmark_cases_total = int(benchmark.get("cases_total") or 0)
    benchmark_has_cases = bool(benchmark.get("configured")) and benchmark_cases_total > 0
    if benchmark:
        benchmark_name = str(benchmark.get("benchmark_name") or "CodeSentinelX quality benchmark")
        precision = float(benchmark.get("precision_percent") or 0.0)
        recall = float(benchmark.get("recall_percent") or 0.0)
        f1 = float(benchmark.get("f1_percent") or 0.0)
        if benchmark_has_cases and benchmark_status == "blocked":
            blockers.append(
                f"{benchmark_name} fell below quality thresholds (precision={precision:.2f}%, recall={recall:.2f}%, f1={f1:.2f}%)."
            )
        elif benchmark_has_cases and benchmark_status == "warning":
            benchmark_advisories.append(
                f"{benchmark_name} is configured but incomplete; precision={precision:.2f}%, recall={recall:.2f}%, f1={f1:.2f}%."
            )
        elif benchmark_has_cases and benchmark_status == "not_configured":
            benchmark_advisories.append("Scanner quality benchmark file is not configured; quality proof remains optional.")
        elif benchmark_has_cases:
            benchmark_advisories.append(
                f"{benchmark_name} passed quality thresholds with precision={precision:.2f}%, recall={recall:.2f}%, f1={f1:.2f}%."
            )

    tool_success_rate_percent = float(toolchain_execution.get("success_rate_percent") or 0.0)
    benchmark_bonus = 0.0
    if benchmark_has_cases and benchmark_status == "ready":
        benchmark_bonus = min(12.0, (float(benchmark.get("precision_percent") or 0.0) + float(benchmark.get("recall_percent") or 0.0) + float(benchmark.get("f1_percent") or 0.0)) / 30.0)
    elif benchmark_has_cases and benchmark_status == "warning":
        benchmark_bonus = -4.0
    elif benchmark_has_cases and benchmark_status == "blocked":
        benchmark_bonus = -12.0
    readiness_score = round(
        max(
            0.0,
            min(
                100.0,
                required_tools_coverage_percent * 0.4
                + tool_success_rate_percent * 0.35
                + max(0.0, 25.0 - critical_count * 7.0 - high_count * 2.0)
                + benchmark_bonus,
            ),
        ),
        2,
    )
    status = "ready"
    if blockers:
        status = "blocked"
    elif required_tools_total and (required_tools_coverage_percent < 100 or tool_success_rate_percent < 80):
        status = "warning"
    elif benchmark_has_cases and benchmark_status in {"blocked", "warning"}:
        status = "blocked" if benchmark_status == "blocked" else "warning"
    elif advisories:
        status = "warning"

    recommendation = "Release criteria met with current analyzer coverage."
    if status == "blocked":
        recommendation = "Resolve critical findings and failed analyzer coverage before relying on this report for release sign-off."
    elif status == "warning":
        recommendation = "Increase analyzer coverage and resolve high-priority findings before production deployment."
    if advisories and not blockers:
        recommendation = f"{recommendation} Review the coverage notes for analyzer setup or execution issues."
    if any("codeql" in str(item).lower() or "query pack" in str(item).lower() for item in advisories):
        recommendation = (
            f"{recommendation} CodeQL coverage is currently incomplete; install the repository-specific packs or point CodeQL at the correct search path before rerunning. "
            "Management should treat this as reduced confidence in language coverage, and developers should treat it as a tool-setup issue rather than a product defect."
        )
    if benchmark_has_cases and benchmark_status == "blocked" and benchmark_advisories:
        recommendation = f"{recommendation} Scanner quality benchmark requires attention before sign-off."
    advisories = benchmark_advisories + advisories
    if benchmark_has_cases and status == "warning" and benchmark_status == "warning" and not benchmark_advisories:
        advisories.append("Scanner quality benchmark is partially configured.")

    return {
        "status": status,
        "is_enterprise_ready": status == "ready",
        "scan_profile": scan_profile,
        "required_tools": selected_required,
        "required_tools_total": required_tools_total,
        "required_tools_ready": required_tools_ready,
        "required_tools_coverage_percent": required_tools_coverage_percent,
        "recommended_tools": [],
        "recommended_tools_total": 0,
        "recommended_tools_ready": 0,
        "recommended_tools_coverage_percent": 0.0,
        "toolchain_success_rate_percent": tool_success_rate_percent,
        "toolchain_attempted_tools": int(toolchain_execution.get("attempted_tools") or 0),
        "toolchain_failed_tools": int(toolchain_execution.get("failed_tools") or 0),
        "toolchain_unavailable_tools": int(toolchain_execution.get("unavailable_tools") or 0),
        "toolchain_no_runner_tools": int(toolchain_execution.get("no_runner_tools") or 0),
        "readiness_score": readiness_score,
        "blockers": blockers,
        "advisories": advisories,
        "recommendation": recommendation,
        "quality_benchmark": benchmark if benchmark_has_cases else None,
    }


def _is_auth_abuse_finding(item: dict) -> bool:
    combined = " ".join(
        [
            str(item.get("vulnerability_title") or item.get("vulnerability_type") or ""),
            str(item.get("owasp_mapping") or item.get("owasp_category") or ""),
            str(item.get("description") or ""),
        ]
    ).lower()
    tokens = (
        "auth",
        "authorization",
        "broken access",
        "bola",
        "bopla",
        "permission",
        "privilege",
        "session",
        "cookie",
        "token",
        "brute force",
        "user enumeration",
        "credential",
        "account takeover",
    )
    return any(token in combined for token in tokens)


def _build_auth_abuse_session_security(findings: list[dict]) -> dict[str, object] | None:
    scoped = [item for item in findings if _is_auth_abuse_finding(item)]
    if not scoped:
        return None

    severity_distribution = _severity_distribution_from_enriched(scoped)
    mapping_counter: Counter[tuple[str, str, str]] = Counter()
    severity_counter: dict[tuple[str, str, str], Counter[str]] = {}
    for item in scoped:
        issue_type = str(item.get("vulnerability_title") or item.get("vulnerability_type") or "Issue")
        file_path = str(item.get("file_path") or "unknown")
        folder = _folder_name(file_path)
        key = (issue_type, file_path, folder)
        mapping_counter[key] += 1
        severity_counter.setdefault(key, Counter())[str(item.get("severity") or "Info")] += 1

    issue_file_mapping = [
        {
            "issue_type": issue_type,
            "file": file_path,
            "folder": folder,
            "count": count,
            "critical": severity_counter[(issue_type, file_path, folder)].get("Critical", 0),
            "high": severity_counter[(issue_type, file_path, folder)].get("High", 0),
        }
        for (issue_type, file_path, folder), count in mapping_counter.most_common(40)
    ]

    return {
        "total_findings": len(scoped),
        "severity_distribution": severity_distribution,
        "top_vulnerability_types": _top_vulnerability_types(scoped, limit=10),
        "affected_modules": _affected_modules(scoped, limit=15),
        "affected_files": _affected_files(scoped, limit=20),
        "issue_file_mapping": issue_file_mapping,
    }


def _build_false_positive_report(findings: list[dict]) -> dict[str, object] | None:
    default_owner = str(os.getenv("USS_SUPPRESSION_DEFAULT_OWNER", "security-triage").strip() or "security-triage")
    candidates: list[dict[str, object]] = []
    for item in findings:
        active_poc = item.get("active_poc") or {}
        status = _active_poc_status(active_poc)
        if not bool(item.get("suppression_candidate")) and status not in {"inconclusive", "error"}:
            continue
        candidates.append(
            {
                "finding_uid": item.get("finding_uid"),
                "vulnerability_title": item.get("vulnerability_title", item.get("vulnerability_type", "Issue")),
                "severity": item.get("severity", "Medium"),
                "file_path": item.get("file_path"),
                "line_number": item.get("line_number"),
                "reason_summary": str(item.get("suppression_reason") or "Validation requires analyst review"),
                "reason_detail": str(
                    item.get("suppression_detail")
                    or active_poc.get("verification_basis")
                    or "Deterministic validation did not fully confirm exploitability in this code path."
                ),
                "confidence": float(item.get("rule_confidence") or active_poc.get("confidence") or 0.0),
                "owner": str(item.get("triage_owner") or item.get("suppression_owner") or default_owner),
                "review_by": str(item.get("suppression_review_by") or ""),
                "requires_expiry": bool(item.get("suppression_requires_expiry")),
                "verification_steps": [str(item.get("ai_validation_steps") or "").splitlines()[0]] if str(item.get("ai_validation_steps") or "").strip() else [],
            }
        )
    if not candidates:
        return None
    return {
        "policy_note": "Only low-confidence, non-production-context, or incompletely validated candidates are listed for analyst suppression review.",
        "candidate_count": len(candidates),
        "candidates": candidates[:80],
    }


def _build_data_quality(
    findings: list[dict],
    raw_total: int,
    deduplicated_total: int,
    duplicate_reduction: int,
    confidence: str,
    toolchain_execution: dict[str, object],
    false_positive_report: dict[str, object] | None,
    quality_benchmark: dict[str, object] | None = None,
) -> dict[str, object]:
    unknown_rule_count = 0
    unknown_cwe_count = 0
    unknown_owasp_count = 0
    unknown_taxonomy_count = 0
    origin_counts: Counter[str] = Counter()
    corroborated_findings = 0
    for item in findings:
        rule_id = str(item.get("rule_id") or "").strip()
        cwe = str(item.get("cwe_id") or item.get("cwe") or "").strip()
        owasp = str(item.get("owasp_mapping") or item.get("owasp_category") or "").strip()
        origin = str(item.get("finding_origin") or item.get("origin") or "rule_engine")
        origin_counts[origin] += 1
        if bool(item.get("corroborated")):
            corroborated_findings += 1
        if not rule_id:
            unknown_rule_count += 1
        if not cwe:
            unknown_cwe_count += 1
        if not owasp:
            unknown_owasp_count += 1
        if not rule_id or not cwe or not owasp:
            unknown_taxonomy_count += 1
    suppressed_findings = int((false_positive_report or {}).get("candidate_count") or 0)
    coverage_confidence_score = {"High": 85.0, "Medium": 65.0, "Low": 40.0}.get(confidence, 55.0)
    payload = {
        "raw_findings": raw_total,
        "deduplicated_findings": deduplicated_total,
        "duplicate_findings_removed": duplicate_reduction,
        "dedup_ratio_percent": round((duplicate_reduction / max(1, raw_total)) * 100.0, 2),
        "suppressed_findings": suppressed_findings,
        "suppression_rate_percent": round((suppressed_findings / max(1, deduplicated_total + suppressed_findings)) * 100.0, 2),
        "tool_success_rate_percent": float(toolchain_execution.get("success_rate_percent") or 0.0),
        "tool_attempted_count": int(toolchain_execution.get("attempted_tools") or 0),
        "coverage_confidence": confidence,
        "coverage_confidence_score": coverage_confidence_score,
        "unknown_rule_count": unknown_rule_count,
        "unknown_cwe_count": unknown_cwe_count,
        "unknown_owasp_count": unknown_owasp_count,
        "unknown_taxonomy_count": unknown_taxonomy_count,
        "finding_origin_distribution": dict(origin_counts.most_common()),
        "corroborated_findings": corroborated_findings,
    }
    if quality_benchmark:
        payload["quality_benchmark"] = quality_benchmark
    return payload


def _build_cto_board_view(findings: list[dict], risk_score: float) -> dict[str, object]:
    distribution = _severity_distribution_from_enriched(findings)
    ranked = sorted(findings, key=lambda item: -float(item.get("risk_priority_score", item.get("cvss_score", 0.0))))
    top_urgent = [
        {
            "title": item.get("vulnerability_title", item.get("vulnerability_type", "Risk")),
            "severity": item.get("severity", "Info"),
            "priority_score": float(item.get("risk_priority_score", item.get("cvss_score", 0.0))),
            "business_impact": item.get("business_impact", "N/A"),
        }
        for item in ranked[:5]
    ]
    ai_summary = [
        f"{entry['title']} is currently a {entry['severity'].lower()}-severity risk with priority {float(entry['priority_score']):.2f}."
        for entry in top_urgent[:3]
    ]
    return {
        "business_risk_exposure_score": round(risk_score, 2),
        "trend": {
            "available": False,
            "direction": "stable",
            "delta_points": 0,
        },
        "financial_exposure_usd": _estimate_financial_exposure(distribution),
        "downtime_estimate": _estimate_downtime(distribution),
        "top_5_urgent_risks": top_urgent,
        "ai_executive_summary": ai_summary,
    }


def _build_ciso_security_view(findings: list[dict]) -> dict[str, object]:
    ranked = sorted(findings, key=lambda item: -float(item.get("risk_priority_score", item.get("cvss_score", 0.0))))
    rows = []
    for item in ranked[:24]:
        rows.append(
            {
                "title": item.get("vulnerability_title", item.get("vulnerability_type", "Issue")),
                "severity": item.get("severity", "Info"),
                "cvss": round(float(item.get("cvss_score", 0.0) or 0.0), 1),
                "exploitability": _active_poc_status(item.get("active_poc") or {}),
                "business_impact": item.get("business_impact", "N/A"),
                "priority_score": float(item.get("risk_priority_score", item.get("cvss_score", 0.0))),
                "active_exploit": "Yes" if bool(item.get("known_exploited")) else "No",
                "release_gate": _release_gate_action(item),
                "sla_hours": _severity_sla_hours(str(item.get("severity") or "Info")),
            }
        )
    return {
        "attack_chain_example": "External attacker -> service/API -> lateral movement -> critical asset impact",
        "vulnerability_operational_table": rows,
    }


def _build_developer_devops_view(findings: list[dict]) -> dict[str, object]:
    ranked = sorted(findings, key=lambda item: -float(item.get("risk_priority_score", item.get("cvss_score", 0.0))))
    return {
        "tactical_remediation_table": [
            {
                "title": item.get("vulnerability_title", item.get("vulnerability_type", "Issue")),
                "severity": item.get("severity", "Info"),
                "location": f"{item.get('file_path', 'unknown')}:{int(item.get('line_number', 1) or 1)}",
                "cwe": item.get("cwe_id", item.get("cwe", "N/A")),
                "owasp": item.get("owasp_mapping", item.get("owasp_category", "N/A")),
                "secure_fix_snippet": item.get("ai_suggested_fix", item.get("fixed_code", item.get("recommendation", "N/A"))),
            }
            for item in ranked[:28]
        ]
    }


def _build_risk_story_mode(findings: list[dict]) -> dict[str, object]:
    ranked = sorted(findings, key=lambda item: -float(item.get("risk_priority_score", item.get("cvss_score", 0.0))))
    if not ranked:
        return {
            "scenario_title": "N/A",
            "narrative": "No chained attack story generated.",
            "likely_outcome": {},
        }
    chain = [str(item.get("vulnerability_title") or item.get("vulnerability_type") or "Issue") for item in ranked[:3]]
    distribution = _severity_distribution_from_enriched(ranked[:12])
    return {
        "scenario_title": "Priority risk chain",
        "narrative": f"If attackers chain {' -> '.join(chain)}, they can move from initial weakness to broader service impact.",
        "likely_outcome": {
            "critical_findings_in_chain": distribution.get("Critical", 0),
            "high_findings_in_chain": distribution.get("High", 0),
            "likely_release_action": _release_gate_action(ranked[0]),
        },
    }


def _build_security_maturity_scoring(
    controls_summary: dict[str, object],
    toolchain_execution: dict[str, object],
    profile_compliance: dict[str, object],
) -> dict[str, float]:
    implemented_controls = int(controls_summary.get("implemented_controls", 0) or 0)
    standards_coverage = controls_summary.get("standards_coverage", {}) or {}
    standards_average = 0.0
    if isinstance(standards_coverage, dict) and standards_coverage:
        values = [float(value or 0.0) for value in standards_coverage.values()]
        standards_average = sum(values) / len(values)
    tool_success_rate = float(toolchain_execution.get("success_rate_percent") or 0.0)
    profile_depth = 85.0 if str(profile_compliance.get("scan_profile") or "standard") == "deep" else 65.0
    overall = round(min(100.0, implemented_controls * 6.5 + standards_average * 0.35 + tool_success_rate * 0.3 + profile_depth * 0.2), 2)
    return {
        "overall_score": overall,
        "controls_implemented_score": round(min(100.0, implemented_controls * 8.0), 2),
        "standards_coverage_score": round(min(100.0, standards_average), 2),
        "tool_reliability_score": round(min(100.0, tool_success_rate), 2),
        "scan_depth_score": round(profile_depth, 2),
    }


def _apply_validation_and_ai(findings: list[dict], target_path: str, scan_role: str | None) -> tuple[list[dict], dict[str, object]]:
    _dependency_reachability(findings, target_path)
    provider_config = load_ai_provider_config()
    allow_active_poc = role_runs_active_poc(scan_role)
    allow_fix_verification = role_runs_fix_verification(scan_role)
    for item in findings:
        item["risk_priority_score"] = _risk_priority_score(item)
        if allow_active_poc:
            validation = verify_finding(
                ValidationContext(
                    target_root=target_path,
                    file_path=str(item.get("file_path", "")),
                    line_number=int(item.get("line_number", 1) or 1),
                    vulnerability_type=str(item.get("vulnerability_title") or item.get("vulnerability_type") or ""),
                    rule_id=str(item.get("rule_id", "")),
                    cwe_id=str(item.get("cwe_id", "")),
                    evidence=str(item.get("vulnerable_code_snippet") or item.get("evidence") or item.get("original_code") or ""),
                )
            ).to_dict()
            item["active_poc"] = validation
            item["proof_of_concept"] = _build_validation_narrative(item, validation)
            item["ai_remediation_summary"] = _build_ai_summary(item, validation)
            item["ai_validation_steps"] = _build_ai_validation_steps(validation)
            item["ai_fix_source"] = "local-evidence-driven:deterministic-validation-v1"
            item["ai_fix_confidence_score"] = float(validation.get("confidence") or 0.0)
            item["ai_fix_confidence_label"] = _confidence_label(float(validation.get("confidence") or 0.0))
            item["ai_fix_grounded"] = bool(validation.get("executed")) and _active_poc_status(validation) != "error"
            item["ai_grounding_notes"] = str(validation.get("verification_basis") or "")
            if _active_poc_status(validation) != "verified":
                item["fix_artifact_kind"] = "guidance"
                item["fix_artifact_label"] = "Remediation Guidance"
            else:
                item["fix_artifact_kind"] = "exact_patch"
                item["fix_artifact_label"] = "Suggested Fix"
            if allow_fix_verification:
                item["fix_verification"] = _run_fix_verification(item, target_path)
            else:
                item.pop("fix_verification", None)
        else:
            for key in (
                "active_poc",
                "proof_of_concept",
                "ai_remediation_summary",
                "ai_validation_steps",
                "ai_fix_source",
                "ai_fix_confidence_score",
                "ai_fix_confidence_label",
                "ai_fix_grounded",
                "ai_grounding_notes",
                "fix_verification",
            ):
                item.pop(key, None)
        item["plain_language_security_brief"] = _plain_language_security_brief(item)

    provider_applied = 0
    provider_errors: list[str] = []
    if provider_config.enabled and allow_active_poc:
        provider_candidates = sorted(
            (item for item in findings if bool(item.get("ai_fix_grounded"))),
            key=lambda entry: -float(entry.get("risk_priority_score", entry.get("cvss_score", 0.0))),
        )[: provider_config.remediation_max_findings]
        for item in provider_candidates:
            try:
                enriched = generate_grounded_remediation(item, target_path, provider_config)
            except Exception as exc:  # noqa: BLE001
                provider_errors.append(str(exc))
                continue
            if not enriched:
                continue
            item["ai_remediation_summary"] = enriched.get("remediation_summary") or item.get("ai_remediation_summary")
            item["ai_validation_steps"] = enriched.get("validation_steps") or item.get("ai_validation_steps")
            item["ai_fix_confidence_score"] = float(enriched.get("fix_confidence_score") or item.get("ai_fix_confidence_score") or 0.0)
            item["ai_fix_confidence_label"] = enriched.get("fix_confidence_label") or _confidence_label(float(item.get("ai_fix_confidence_score") or 0.0))
            item["ai_fix_source"] = f"{provider_config.provider}:{provider_config.model}"
            item["ai_fix_grounded"] = True
            grounding_notes = str(enriched.get("grounding_notes") or "").strip()
            if grounding_notes:
                item["ai_grounding_notes"] = grounding_notes
            suggested_fix = str(enriched.get("suggested_fix") or "").strip()
            if suggested_fix:
                item["ai_suggested_fix"] = suggested_fix
            if enriched.get("manual_review_required"):
                item["fix_artifact_kind"] = "guidance"
                item["fix_artifact_label"] = "Remediation Guidance"
            provider_applied += 1

    base_fix_window_plan = _build_fix_window_plan(findings)
    provider_plan = None
    if provider_config.enabled:
        try:
            provider_plan = generate_prioritization_plan(findings, provider_config)
        except Exception as exc:  # noqa: BLE001
            provider_errors.append(str(exc))
            provider_plan = None

    ai_solution_engine = build_provider_status(
        provider_config,
        ready=(provider_applied > 0 or provider_plan is not None or not provider_config.enabled),
        detail=(
            f"Parser-and-flow validation enriches each finding with replayable source evidence, post-fix rerun hooks, and grounded remediation guidance. "
            f"Provider-applied findings: {provider_applied}."
            + (f" Provider notes: {' | '.join(provider_errors[:3])}" if provider_errors else "")
        ),
    )
    return findings, {
        "ai_solution_engine": ai_solution_engine,
        "what_should_i_fix_first_ai": _overlay_provider_plan(findings, base_fix_window_plan, provider_plan),
    }


def build_report(scan_result: ScanResult) -> dict:
    scan_role = normalize_role(getattr(scan_result, "scan_role", None))
    raw_enriched_all = _enriched_findings(scan_result.findings)
    raw_enriched, noise_filtered_count = _filter_report_noise(raw_enriched_all)
    enriched_findings = _deduplicate_enriched_findings(raw_enriched)
    enriched_findings, advanced_features = _apply_validation_and_ai(enriched_findings, scan_result.target_path, scan_role)
    enriched_findings, suppression_lifecycle = annotate_findings(enriched_findings)
    enriched_findings = _annotate_alert_grouping(enriched_findings)
    suppression_lifecycle["generated_at"] = scan_result.completed_at.isoformat()
    scoped_findings = scope_findings_for_role(enriched_findings, scan_role)
    duplicate_reduction = max(0, len(raw_enriched) - len(enriched_findings))
    distribution = _severity_distribution_from_enriched(enriched_findings)
    scoped_distribution = _severity_distribution_from_enriched(scoped_findings)
    if sum(distribution.values()) <= 0 and scan_result.findings:
        distribution = _severity_distribution_from_scan_findings(scan_result.findings)
    if sum(scoped_distribution.values()) <= 0 and scoped_findings:
        scoped_distribution = _severity_distribution_from_enriched(raw_enriched)
    summary_findings = enriched_findings if scan_role == "Management" else scoped_findings
    summary_distribution = distribution if scan_role == "Management" else scoped_distribution
    risk_score = _risk_score_from_distribution(distribution)
    impacted_files = len({item["file_path"] for item in summary_findings})
    active_risk_count = summary_distribution.get("Critical", 0) + summary_distribution.get("High", 0)
    active_poc_summary = _active_poc_summary(summary_findings)
    fix_verification_summary = _fix_verification_summary(summary_findings)

    confidence = str(suppression_lifecycle.get("average_rule_confidence_label") or "Medium")
    if len(scan_result.errors) > 5 and confidence == "High":
        confidence = "Medium"
    if len(scan_result.errors) > 15:
        confidence = "Low"

    controls = scan_result.existing_security_measures
    controls_payload = [item.to_dict() for item in controls]
    controls_summary = _controls_summary(controls)
    compliance_matrix = _compliance_matrix(controls_summary)
    profile_compliance = build_profile_compliance(scan_result.target_path, summary_findings, controls_payload)
    autofix = _autofix_recommendations(summary_findings)
    toolchain_execution = _build_toolchain_execution_summary(scan_result.toolchain_status)
    kev_catalog = _apply_kev_correlation(summary_findings)
    risk_intelligence = _build_risk_intelligence(summary_findings)
    risk_intelligence.update(
        {
            "kev_catalog_source": kev_catalog.get("kev_catalog_source"),
            "kev_catalog_version": kev_catalog.get("kev_catalog_version"),
            "kev_catalog_retrieved_at": kev_catalog.get("kev_catalog_retrieved_at"),
            "kev_catalog_count": kev_catalog.get("kev_catalog_count"),
        }
    )
    auth_abuse_session_security = _build_auth_abuse_session_security(summary_findings)
    false_positive_report = _build_false_positive_report(summary_findings)
    data_quality = _build_data_quality(
        summary_findings,
        raw_total=len(raw_enriched),
        deduplicated_total=len(summary_findings),
        duplicate_reduction=duplicate_reduction,
        confidence=confidence,
        toolchain_execution=toolchain_execution,
        false_positive_report=false_positive_report,
        quality_benchmark=getattr(scan_result, "quality_benchmark", None) or None,
    )
    data_quality["noise_filtered_findings"] = noise_filtered_count
    enterprise_assurance = _build_enterprise_assurance(
        summary_findings,
        scan_result.toolchain_status,
        toolchain_execution,
        scan_profile=profile_compliance["scan_profile"],
        quality_benchmark=getattr(scan_result, "quality_benchmark", None) or None,
    )
    cto_board_view = _build_cto_board_view(summary_findings, risk_score)
    ciso_security_view = _build_ciso_security_view(summary_findings)
    developer_devops_view = _build_developer_devops_view(summary_findings)
    risk_story_mode = _build_risk_story_mode(summary_findings)
    advanced_features["security_maturity_scoring"] = _build_security_maturity_scoring(
        controls_summary,
        toolchain_execution,
        profile_compliance,
    )

    executive_summary = {
        "target_path": scan_result.target_path,
        "generated_at": scan_result.completed_at.isoformat(),
        "files_scanned": scan_result.files_scanned,
        "total_vulnerabilities": len(raw_enriched),
        "deduplicated_vulnerabilities": len(summary_findings),
        "duplicate_findings_removed": max(0, len(raw_enriched) - len(summary_findings)),
        "noise_filtered_findings": noise_filtered_count,
        "total_files_impacted": impacted_files,
        "active_risk_findings": summary_distribution.get("Critical", 0) + summary_distribution.get("High", 0),
        "assessment_confidence": confidence,
        "severity_distribution": summary_distribution,
        "severity_distribution_raw": distribution,
        "risk_score": risk_score,
        "risk_rating": risk_rating(risk_score),
        "top_vulnerability_types": _top_vulnerability_types(summary_findings),
        "top_owasp_categories": _top_owasp_categories(summary_findings),
        "affected_modules": _affected_modules(summary_findings),
        "affected_files": _affected_files(summary_findings),
        "affected_folders": _affected_folders(summary_findings),
        "recommended_action_plan": _build_action_plan(summary_distribution, summary_findings),
        "implemented_controls": controls_summary["implemented_controls"],
        "scan_profile": profile_compliance["scan_profile"],
        "scan_profile_label": profile_compliance["scan_profile_label"],
        "framework_versions": profile_compliance["framework_versions"],
        "finding_origin_distribution": suppression_lifecycle.get("finding_origins", {}),
        "toolchain_execution": toolchain_execution,
        "enterprise_assurance": enterprise_assurance,
        "data_quality": data_quality,
        "suppression_lifecycle": suppression_lifecycle,
        "deterministic_replay": None,
        "report_integrity_chain": None,
    }

    management_summary = {
        "total_findings": len(summary_findings),
        "deduplicated_vulnerabilities": len(summary_findings),
        "active_risk_findings": summary_distribution.get("Critical", 0) + summary_distribution.get("High", 0),
        "severity_distribution": summary_distribution,
        "severity_distribution_raw": distribution,
        "top_vulnerability_types": _top_vulnerability_types(summary_findings),
        "top_owasp_categories": _top_owasp_categories(summary_findings),
        "affected_modules": _affected_modules(summary_findings),
        "affected_files": _affected_files(summary_findings),
        "affected_folders": _affected_folders(summary_findings),
        "risk_score": risk_score,
        "risk_rating": risk_rating(risk_score),
    }
    executive_summary["management_summary"] = management_summary

    technical_report = {
        "scan_window": {
            "started_at": scan_result.started_at.isoformat(),
            "completed_at": scan_result.completed_at.isoformat(),
            "duration_seconds": scan_result.duration_seconds,
        },
        "findings": scoped_findings,
        "errors": scan_result.errors,
        "scan_role": scan_role,
    }

    existing_security_measures = {
        "summary": controls_summary,
        "controls": controls_payload,
        "compliance_matrix": compliance_matrix,
        "profile_compliance": profile_compliance,
    }

    vulnerability_findings = {
        "summary": {
            "total": len(summary_findings),
            "raw_total": len(raw_enriched),
            "duplicate_reduction": max(0, len(raw_enriched) - len(summary_findings)),
            "severity_distribution": summary_distribution,
            "top_vulnerability_types": _top_vulnerability_types(summary_findings),
            "scan_profile": profile_compliance["scan_profile"],
            "noise_filtered_findings": noise_filtered_count,
        },
        "findings": scoped_findings,
        "toolchain_status": scan_result.toolchain_status,
    }

    existing_implementation_report = {
        "report_type": "existing_implementation",
        "title": "Existing Security Implementation Report",
        "target_path": scan_result.target_path,
        "generated_at": scan_result.completed_at.isoformat(),
        "summary": {
            "implemented_controls": controls_summary.get("implemented_controls", 0),
            "category_distribution": controls_summary.get("category_distribution", {}),
            "coverage_levels": controls_summary.get("coverage_levels", {}),
            "standards_coverage": controls_summary.get("standards_coverage", {}),
        },
        "controls": controls_payload,
        "compliance_matrix": compliance_matrix,
        "profile_compliance": profile_compliance,
    }

    vulnerability_fixed_code_report = {
        "report_type": "vulnerability_fixed_code",
        "title": "Vulnerability and Fixed-Code Report",
        "target_path": scan_result.target_path,
        "generated_at": scan_result.completed_at.isoformat(),
        "summary": {
            "total_findings": len(summary_findings),
            "raw_findings_total": len(raw_enriched),
            "duplicate_findings_removed": max(0, len(raw_enriched) - len(summary_findings)),
            "noise_filtered_findings": noise_filtered_count,
            "severity_distribution": summary_distribution,
            "risk_score": risk_score,
            "risk_rating": risk_rating(risk_score),
            "active_risk_findings": summary_distribution.get("Critical", 0) + summary_distribution.get("High", 0),
            "files_impacted": impacted_files,
            "top_vulnerability_types": _top_vulnerability_types(summary_findings),
            "top_owasp_categories": _top_owasp_categories(summary_findings),
            "affected_modules": _affected_modules(summary_findings),
            "affected_files": _affected_files(summary_findings),
            "affected_folders": _affected_folders(summary_findings),
            "scan_profile": profile_compliance["scan_profile"],
            "release_gate_distribution": dict(Counter(_release_gate_action(item) for item in summary_findings)),
            "risk_intelligence": risk_intelligence,
            "auth_abuse_session_security": auth_abuse_session_security,
            "toolchain_execution": toolchain_execution,
            "active_poc": active_poc_summary,
            "fix_verification": fix_verification_summary,
            "enterprise_assurance": enterprise_assurance,
            "false_positive_candidates": int((false_positive_report or {}).get("candidate_count") or 0),
            "data_quality": data_quality,
            "suppression_lifecycle": suppression_lifecycle,
            "finding_origin_distribution": suppression_lifecycle.get("finding_origins", {}),
            "management_summary": management_summary,
            "deterministic_replay": None,
            "report_integrity_chain": None,
        },
        "findings": scoped_findings,
        "auto_fix_recommendations": autofix,
        "toolchain_status": scan_result.toolchain_status,
    }

    role_aware_report = {
        "cto_board_view": cto_board_view,
        "ciso_security_view": ciso_security_view,
        "developer_devops_view": developer_devops_view,
        "risk_story_mode": risk_story_mode,
        "advanced_features": advanced_features,
        "enterprise_assurance": enterprise_assurance,
        "false_positive_report": false_positive_report,
    }
    vulnerability_fixed_code_report["role_aware_report"] = role_aware_report
    if false_positive_report:
        vulnerability_fixed_code_report["false_positive_report"] = false_positive_report

    report = {
        "scanner": {
            "name": "CodeSentinelX",
            "version": "1.0.0",
        },
        "executive_summary": executive_summary,
        "existing_implementation_report": existing_implementation_report,
        "vulnerability_fixed_code_report": vulnerability_fixed_code_report,
        "existing_security_measures": existing_security_measures,
        "vulnerability_findings": vulnerability_findings,
        "auto_fix_recommendations": autofix,
        "technical_report": technical_report,
        "profile_compliance": profile_compliance,
        "false_positive_report": false_positive_report,
        "role_aware_report": role_aware_report,
    }
    return scope_report_for_role(report, scan_role)


