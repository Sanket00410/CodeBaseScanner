from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


LATEST_FRAMEWORK_VERSIONS = {
    "owasp_top_10": "2025",
    "owasp_api_top_10": "2023",
    "asvs": "5.0.0",
    "wstg": "4.2",
}

PROFILE_LABELS = {
    "codebase": "Codebase",
    "website": "Website",
    "localhost": "Localhost Runtime",
    "ip": "IP / Network Runtime",
}

PROFILE_APPLICABLE_FRAMEWORKS = {
    "codebase": {"owasp_top_10_2025", "asvs_5_0_0"},
    "website": {"owasp_top_10_2025", "owasp_api_top_10_2023", "asvs_5_0_0", "wstg_4_2"},
    "localhost": {"owasp_top_10_2025", "owasp_api_top_10_2023", "asvs_5_0_0", "wstg_4_2"},
    "ip": {"owasp_top_10_2025", "owasp_api_top_10_2023", "wstg_4_2"},
}


OWASP_TOP_10_2025 = [
    {"id": "A01", "title": "Broken Access Control"},
    {"id": "A02", "title": "Cryptographic Failures"},
    {"id": "A03", "title": "Injection"},
    {"id": "A04", "title": "Insecure Design"},
    {"id": "A05", "title": "Security Misconfiguration"},
    {"id": "A06", "title": "Software Supply Chain Failures"},
    {"id": "A07", "title": "Identification and Authentication Failures"},
    {"id": "A08", "title": "Software and Data Integrity Failures"},
    {"id": "A09", "title": "Security Logging and Monitoring Failures"},
    {"id": "A10", "title": "Server-Side Request Forgery (SSRF)"},
]


OWASP_API_TOP_10_2023 = [
    {"id": "API1", "title": "Broken Object Level Authorization"},
    {"id": "API2", "title": "Broken Authentication"},
    {"id": "API3", "title": "Broken Object Property Level Authorization"},
    {"id": "API4", "title": "Unrestricted Resource Consumption"},
    {"id": "API5", "title": "Broken Function Level Authorization"},
    {"id": "API6", "title": "Unrestricted Access to Sensitive Business Flows"},
    {"id": "API7", "title": "Server Side Request Forgery"},
    {"id": "API8", "title": "Security Misconfiguration"},
    {"id": "API9", "title": "Improper Inventory Management"},
    {"id": "API10", "title": "Unsafe Consumption of APIs"},
]


ASVS_5_0_0 = [
    {"id": "V1", "title": "Architecture, Design and Threat Modeling"},
    {"id": "V2", "title": "Authentication"},
    {"id": "V3", "title": "Session Management"},
    {"id": "V4", "title": "Access Control"},
    {"id": "V5", "title": "Validation, Sanitization and Encoding"},
    {"id": "V6", "title": "Stored Cryptography"},
    {"id": "V7", "title": "Error Handling and Logging"},
    {"id": "V8", "title": "Data Protection"},
    {"id": "V9", "title": "Communication Security"},
    {"id": "V10", "title": "Malicious Code Prevention"},
    {"id": "V11", "title": "Business Logic"},
    {"id": "V12", "title": "Files and Resources"},
    {"id": "V13", "title": "API and Web Service"},
    {"id": "V14", "title": "Configuration"},
    {"id": "V15", "title": "Secure Build and Deployment"},
    {"id": "V16", "title": "Security Verification"},
    {"id": "V17", "title": "Supply Chain"},
]


WSTG_4_2 = [
    {"id": "WSTG-INFO", "title": "Information Gathering"},
    {"id": "WSTG-CONF", "title": "Configuration and Deployment Management Testing"},
    {"id": "WSTG-IDNT", "title": "Identity Management Testing"},
    {"id": "WSTG-ATHN", "title": "Authentication Testing"},
    {"id": "WSTG-ATHZ", "title": "Authorization Testing"},
    {"id": "WSTG-SESS", "title": "Session Management Testing"},
    {"id": "WSTG-INPV", "title": "Input Validation Testing"},
    {"id": "WSTG-ERRH", "title": "Error Handling Testing"},
    {"id": "WSTG-CRYP", "title": "Cryptography Testing"},
    {"id": "WSTG-BUSL", "title": "Business Logic Testing"},
    {"id": "WSTG-CLNT", "title": "Client-Side Testing"},
    {"id": "WSTG-APIT", "title": "API Testing"},
]


_OWASP_TOP10_LABEL_BY_ID = {item["id"]: f"{item['id']}:{LATEST_FRAMEWORK_VERSIONS['owasp_top_10']} - {item['title']}" for item in OWASP_TOP_10_2025}
_OWASP_TOP10_TITLE_KEYWORDS = {
    "A01": ("broken access control", "authorization", "idor", "path traversal"),
    "A02": ("cryptographic", "encryption", "cipher", "hash", "secret", "tls"),
    "A03": ("injection", "sql injection", "command injection", "xss", "unsafe eval"),
    "A04": ("insecure design", "design flaw", "threat model"),
    "A05": ("misconfiguration", "security header", "cors", "debug endpoint", "actuator"),
    "A06": ("dependency", "supply chain", "outdated component", "vulnerable component"),
    "A07": ("authentication", "credential", "login", "session token", "mfa"),
    "A08": ("integrity", "deserialization", "unsigned", "tamper"),
    "A09": ("logging", "monitoring", "audit trail", "alerting"),
    "A10": ("ssrf", "server-side request forgery"),
}


def detect_scan_profile(target_path: str) -> str:
    target = (target_path or "").strip()
    if not target:
        return "codebase"

    if target.lower().startswith("ssh://"):
        return "codebase"

    if _looks_like_local_path(target):
        return "codebase"

    candidate = target if "://" in target else f"http://{target}"
    try:
        parsed = urlparse(candidate)
    except Exception:
        return "codebase"

    host = (parsed.hostname or "").strip().lower()
    if host == "localhost":
        return "localhost"
    if _is_ip(host):
        return "ip"
    if host:
        return "website"

    if re.match(r"^localhost(:\d+)?(?:/.*)?$", target, flags=re.IGNORECASE):
        return "localhost"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/.*)?$", target):
        return "ip"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", target, flags=re.IGNORECASE):
        return "website"
    return "codebase"


def normalize_owasp_top10_label(raw_value: str | None) -> str:
    raw = str(raw_value or "").strip()
    if not raw:
        return "N/A"

    code_match = re.match(r"^\s*(A\d{2})\s*:\s*(\d{4})", raw, flags=re.IGNORECASE)
    if code_match:
        code = code_match.group(1).upper()
        mapped = _OWASP_TOP10_LABEL_BY_ID.get(code)
        if mapped:
            return mapped
        return raw

    lowered = raw.lower()
    for code, keywords in _OWASP_TOP10_TITLE_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return _OWASP_TOP10_LABEL_BY_ID[code]

    if re.search(r"\bapi\s*10\b", lowered):
        return "OWASP API Security Top 10 finding"

    return raw


def build_profile_compliance(
    target_path: str,
    findings: list[dict],
    controls: list[dict],
) -> dict:
    profile = detect_scan_profile(target_path)
    applicable = PROFILE_APPLICABLE_FRAMEWORKS.get(profile, PROFILE_APPLICABLE_FRAMEWORKS["codebase"])

    owasp_counts = _count_owasp_top10(findings)
    api_counts = _count_api_top10(findings)
    asvs_counts = _count_asvs(controls, findings)
    wstg_counts = _count_wstg(findings)

    frameworks = [
        _framework_payload(
            framework_id="owasp_top_10_2025",
            framework_name="OWASP Top 10",
            version=LATEST_FRAMEWORK_VERSIONS["owasp_top_10"],
            applicable=framework_is_applicable("owasp_top_10_2025", applicable),
            catalog=OWASP_TOP_10_2025,
            counts=owasp_counts,
            prefix="A",
        ),
        _framework_payload(
            framework_id="owasp_api_top_10_2023",
            framework_name="OWASP API Security Top 10",
            version=LATEST_FRAMEWORK_VERSIONS["owasp_api_top_10"],
            applicable=framework_is_applicable("owasp_api_top_10_2023", applicable),
            catalog=OWASP_API_TOP_10_2023,
            counts=api_counts,
            prefix="API",
        ),
        _framework_payload(
            framework_id="asvs_5_0_0",
            framework_name="OWASP ASVS",
            version=LATEST_FRAMEWORK_VERSIONS["asvs"],
            applicable=framework_is_applicable("asvs_5_0_0", applicable),
            catalog=ASVS_5_0_0,
            counts=asvs_counts,
            prefix="V",
        ),
        _framework_payload(
            framework_id="wstg_4_2",
            framework_name="OWASP WSTG",
            version=LATEST_FRAMEWORK_VERSIONS["wstg"],
            applicable=framework_is_applicable("wstg_4_2", applicable),
            catalog=WSTG_4_2,
            counts=wstg_counts,
            prefix="WSTG",
        ),
    ]

    summary = {
        "frameworks_total": len(frameworks),
        "frameworks_applicable": sum(1 for item in frameworks if item["applicable"]),
        "items_covered": sum(item["summary"]["covered"] for item in frameworks),
        "items_gap": sum(item["summary"]["gap"] for item in frameworks),
        "items_not_applicable": sum(item["summary"]["not_applicable"] for item in frameworks),
        "mapped_findings_total": sum(item["summary"]["mapped_findings"] for item in frameworks),
        "mapped_controls_total": sum(item["summary"]["mapped_controls"] for item in frameworks),
    }

    return {
        "scan_profile": profile,
        "scan_profile_label": PROFILE_LABELS.get(profile, "Codebase"),
        "framework_versions": dict(LATEST_FRAMEWORK_VERSIONS),
        "applicable_framework_ids": sorted(applicable),
        "frameworks": frameworks,
        "summary": summary,
    }


def framework_is_applicable(framework_id: str, applicable_set: set[str]) -> bool:
    return framework_id in applicable_set


def _framework_payload(
    framework_id: str,
    framework_name: str,
    version: str,
    applicable: bool,
    catalog: list[dict[str, str]],
    counts: dict[str, dict[str, int]],
    prefix: str,
) -> dict:
    rows: list[dict[str, str | int]] = []
    covered = 0
    gap = 0
    not_applicable = 0
    mapped_findings = 0
    mapped_controls = 0

    for item in catalog:
        item_id = item["id"]
        count_obj = counts.get(item_id, {"findings": 0, "controls": 0})
        findings_count = int(count_obj.get("findings", 0))
        controls_count = int(count_obj.get("controls", 0))
        total_count = findings_count + controls_count

        if not applicable:
            status = "not_applicable"
            not_applicable += 1
        elif total_count > 0:
            status = "covered"
            covered += 1
        else:
            status = "gap"
            gap += 1

        mapped_findings += findings_count
        mapped_controls += controls_count
        rows.append(
            {
                "id": item_id,
                "title": item["title"],
                "status": status,
                "finding_count": findings_count,
                "control_count": controls_count,
                "count": total_count,
            }
        )

    return {
        "framework_id": framework_id,
        "framework_name": framework_name,
        "version": version,
        "label": f"{framework_name} {version}",
        "prefix": prefix,
        "applicable": applicable,
        "summary": {
            "covered": covered,
            "gap": gap,
            "not_applicable": not_applicable,
            "mapped_findings": mapped_findings,
            "mapped_controls": mapped_controls,
        },
        "rows": rows,
    }


def _count_owasp_top10(findings: list[dict]) -> dict[str, dict[str, int]]:
    counts = {item["id"]: {"findings": 0, "controls": 0} for item in OWASP_TOP_10_2025}
    label_to_code = {label: code for code, label in _OWASP_TOP10_LABEL_BY_ID.items()}

    for finding in findings:
        normalized = normalize_owasp_top10_label(str(finding.get("owasp_mapping") or finding.get("owasp_category") or "N/A"))
        code = label_to_code.get(normalized)
        if code:
            counts[code]["findings"] += 1

    return counts


def _count_api_top10(findings: list[dict]) -> dict[str, dict[str, int]]:
    counts = {item["id"]: {"findings": 0, "controls": 0} for item in OWASP_API_TOP_10_2023}
    for finding in findings:
        api_code = _map_api_category(finding)
        if api_code and api_code in counts:
            counts[api_code]["findings"] += 1
    return counts


def _count_asvs(controls: list[dict], findings: list[dict]) -> dict[str, dict[str, int]]:
    counts = {item["id"]: {"findings": 0, "controls": 0} for item in ASVS_5_0_0}

    for control in controls:
        for mapping in control.get("standard_mappings", []) or []:
            match = re.search(r"ASVS\s*V(\d+)", str(mapping), flags=re.IGNORECASE)
            if not match:
                continue
            code = f"V{match.group(1)}"
            if code in counts:
                counts[code]["controls"] += 1

    for finding in findings:
        code = _map_asvs_category(finding)
        if code and code in counts:
            counts[code]["findings"] += 1

    return counts


def _count_wstg(findings: list[dict]) -> dict[str, dict[str, int]]:
    counts = {item["id"]: {"findings": 0, "controls": 0} for item in WSTG_4_2}
    for finding in findings:
        code = _map_wstg_category(finding)
        if code and code in counts:
            counts[code]["findings"] += 1
    return counts


def _map_api_category(finding: dict) -> str | None:
    text = _finding_text(finding)
    owasp = normalize_owasp_top10_label(str(finding.get("owasp_mapping") or finding.get("owasp_category") or ""))

    if "ssrf" in text:
        return "API7"
    if _contains_any(text, ("idor", "object level authorization", "broken object level", "bola")):
        return "API1"
    if _contains_any(text, ("mass assignment", "object property", "excessive data exposure", "property level authorization", "bopla")):
        return "API3"
    if _contains_any(text, ("function level authorization", "privilege escalation", "admin endpoint")):
        return "API5"
    if _contains_any(text, ("authentication", "login", "jwt", "token", "credential")):
        return "API2"
    if _contains_any(text, ("resource consumption", "rate limit", "denial of service", "brute force")):
        return "API4"
    if _contains_any(text, ("business flow", "workflow abuse", "business logic")):
        return "API6"
    if _contains_any(text, ("inventory", "swagger", "openapi", "undocumented endpoint", "api version")):
        return "API9"
    if _contains_any(text, ("misconfiguration", "debug", "cors", "header", "actuator", ".env", ".git/config")):
        return "API8"
    if _contains_any(text, ("unsafe consumption", "third-party api", "external api")):
        return "API10"

    if owasp.startswith("A01:"):
        return "API1"
    if owasp.startswith("A05:"):
        return "API8"
    if owasp.startswith("A10:"):
        return "API7"

    return None


def _map_asvs_category(finding: dict) -> str | None:
    text = _finding_text(finding)
    if _contains_any(text, ("architecture", "design flaw", "insecure design")):
        return "V1"
    if _contains_any(text, ("authentication", "login", "credential", "mfa", "password")):
        return "V2"
    if _contains_any(text, ("session", "cookie", "jwt", "token")):
        return "V3"
    if _contains_any(text, ("authorization", "access control", "idor", "privilege")):
        return "V4"
    if _contains_any(text, ("validation", "xss", "sql injection", "command injection", "injection", "unsafe eval", "path traversal")):
        return "V5"
    if _contains_any(text, ("cryptography", "encryption", "hash", "secret", "key")):
        return "V6"
    if _contains_any(text, ("logging", "monitoring", "audit")):
        return "V7"
    if _contains_any(text, ("data exposure", "sensitive data", "pii")):
        return "V8"
    if _contains_any(text, ("tls", "certificate", "https", "transport security")):
        return "V9"
    if _contains_any(text, ("deserialization", "rce", "malicious code")):
        return "V10"
    if "business logic" in text:
        return "V11"
    if _contains_any(text, ("file upload", "filesystem", "path traversal")):
        return "V12"
    if _contains_any(text, ("api", "endpoint", "graphql", "rest")):
        return "V13"
    if _contains_any(text, ("misconfiguration", "config")):
        return "V14"
    if _contains_any(text, ("build", "deployment", "pipeline", "ci/cd")):
        return "V15"
    if _contains_any(text, ("security verification", "test coverage", "regression test")):
        return "V16"
    if _contains_any(text, ("dependency", "supply chain", "outdated component", "package")):
        return "V17"
    return None


def _map_wstg_category(finding: dict) -> str | None:
    text = _finding_text(finding)
    if _contains_any(text, ("inventory", "enumeration", "discovery", "amass")):
        return "WSTG-INFO"
    if _contains_any(text, ("misconfiguration", "debug endpoint", "security header", "server banner", "directory listing")):
        return "WSTG-CONF"
    if _contains_any(text, ("identity management", "user enumeration")):
        return "WSTG-IDNT"
    if _contains_any(text, ("authentication", "password", "login", "credential")):
        return "WSTG-ATHN"
    if _contains_any(text, ("authorization", "access control", "idor", "admin endpoint")):
        return "WSTG-ATHZ"
    if _contains_any(text, ("session", "cookie", "jwt", "token")):
        return "WSTG-SESS"
    if _contains_any(text, ("xss", "sql injection", "command injection", "injection", "path traversal", "unsafe eval")):
        return "WSTG-INPV"
    if _contains_any(text, ("error handling", "stack trace", "verbose error")):
        return "WSTG-ERRH"
    if _contains_any(text, ("cryptography", "encryption", "tls", "certificate", "hash")):
        return "WSTG-CRYP"
    if "business logic" in text:
        return "WSTG-BUSL"
    if _contains_any(text, ("xss", "dom", "csp", "client-side")):
        return "WSTG-CLNT"
    if _contains_any(text, ("api", "swagger", "openapi", "graphql", "endpoint")):
        return "WSTG-APIT"
    return None


def _finding_text(finding: dict) -> str:
    return " ".join(
        str(
            finding.get(key)
            or ""
        )
        for key in (
            "vulnerability_title",
            "vulnerability_type",
            "description",
            "business_impact",
            "recommendation",
            "owasp_mapping",
            "cwe_id",
            "file_path",
        )
    ).lower()


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(item in text for item in needles)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_like_local_path(value: str) -> bool:
    if re.match(r"^[a-zA-Z]:[\\/]", value):
        return True
    if value.startswith("./") or value.startswith("../") or value.startswith(".\\") or value.startswith("..\\"):
        return True
    if "\\" in value:
        return True
    if value.startswith("/"):
        return True
    return False
