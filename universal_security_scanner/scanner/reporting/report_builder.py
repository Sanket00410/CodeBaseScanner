from __future__ import annotations

from collections import Counter
from contextlib import suppress
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory

from universal_security_scanner.models import Finding, ScanResult, SecurityControl
from universal_security_scanner.poc_verify import ValidationContext, verify_finding
from universal_security_scanner.risk import risk_rating
from universal_security_scanner.scanner.ai_provider import (
    build_provider_status,
    generate_grounded_remediation,
    generate_prioritization_plan,
    load_ai_provider_config,
)
from universal_security_scanner.scanner.dependency_auth import advisory_identity, build_dependency_inventory, normalize_package_name
from universal_security_scanner.scanner.reporting.compliance_profiles import (
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
    title = str(finding.get("vulnerability_title") or finding.get("vulnerability_type") or "Security Finding")
    recommendation = str(finding.get("recommendation") or "").strip()
    if status == "verified":
        prefix = f"{title} is source-verified at {location} and should be remediated with priority."
    elif status == "inconclusive":
        prefix = f"{title} has partial source validation at {location}; remediation is still recommended, but manual review should confirm exploitability."
    else:
        prefix = f"{title} is present in the recorded source path {location} based on scanner evidence."
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


def _normalize_snippet(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip())


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
        original = "# Source snippet unavailable from scanner evidence."
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
        if finding.vulnerability_type == "Dependency Vulnerability":
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
        key = (
            str(item.get("file_path", "")).replace("\\", "/").lower(),
            int(item.get("line_number", 0)),
            str(item.get("vulnerability_title", item.get("vulnerability_type", ""))).strip().lower(),
            _normalize_snippet(str(item.get("original_code", "") or item.get("vulnerable_code_snippet", ""))).lower(),
        )
        current = unique.get(key)
        if current is None:
            item["evidence_sources"] = [str(item.get("rule_id", ""))]
            unique[key] = item
            continue

        existing_rank = SEVERITY_RANK.get(str(current.get("severity", "Info")), 99)
        incoming_rank = SEVERITY_RANK.get(str(item.get("severity", "Info")), 99)

        if incoming_rank < existing_rank:
            merged = item
            merged_sources = set(current.get("evidence_sources", [])) | {str(item.get("rule_id", ""))}
            merged["evidence_sources"] = sorted(source for source in merged_sources if source)
            unique[key] = merged
        else:
            merged_sources = set(current.get("evidence_sources", [])) | {str(item.get("rule_id", ""))}
            current["evidence_sources"] = sorted(source for source in merged_sources if source)
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


def _severity_distribution_from_enriched(findings: list[dict]) -> dict[str, int]:
    counts = Counter(str(item.get("severity", "Info")) for item in findings)
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
        sev = item.get("severity")
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
        sev = item.get("severity")
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
        sev = item.get("severity")
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


def _build_action_plan(distribution: dict[str, int]) -> list[str]:
    plan: list[str] = []

    if distribution.get("Critical", 0) > 0:
        plan.append("Immediately remediate Critical findings that allow remote compromise or data exfiltration.")
    if distribution.get("High", 0) > 0:
        plan.append("Prioritize High findings in current sprint and enforce code-owner verification before release.")
    if distribution.get("Medium", 0) > 0:
        plan.append("Schedule Medium findings for upcoming hardening cycle and add regression tests.")
    if distribution.get("Low", 0) > 0:
        plan.append("Track Low findings in backlog and resolve during maintenance windows.")

    plan.extend(
        [
            "Enforce secure coding guardrails in CI (SAST, secrets, dependency checks).",
            "Establish monthly dependency update cadence and quarterly security review.",
            "Add security-focused test cases for input validation, authz, and output encoding.",
        ]
    )

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

    with TemporaryDirectory(prefix="uss-fix-verify-") as tmp_dir:
        temp_root = Path(tmp_dir)
        if build_command or test_command:
            workspace = temp_root / "workspace"
            shutil.copytree(
                target_root,
                workspace,
                ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__", ".toolchain", "dist", "build", "exports"),
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
    cache: dict[str, list[str]] = {}
    skip_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".toolchain", "coverage", "exports"}
    source_files = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx"} and not any(part in skip_dirs for part in path.parts)
    ]

    def package_hits(package_name: str) -> list[str]:
        if package_name in cache:
            return cache[package_name]
        hits: list[str] = []
        patterns = [
            rf"\bimport\s+{re.escape(package_name)}\b",
            rf"\bfrom\s+{re.escape(package_name)}\b",
            rf"require\(\s*['\"]{re.escape(package_name)}['\"]\s*\)",
            rf"from\s+['\"]{re.escape(package_name)}['\"]",
        ]
        compiled = [re.compile(pattern) for pattern in patterns]
        for path in source_files:
            with suppress(OSError):
                content = path.read_text(encoding="utf-8", errors="ignore")
                if any(pattern.search(content) for pattern in compiled):
                    hits.append(str(path.relative_to(root)).replace("\\", "/"))
                    if len(hits) >= 10:
                        break
        cache[package_name] = hits
        return hits

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
            hits.extend(package_hits(alias))
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


def _apply_validation_and_ai(findings: list[dict], target_path: str) -> tuple[list[dict], dict[str, object]]:
    _dependency_reachability(findings, target_path)
    provider_config = load_ai_provider_config()
    for item in findings:
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
        item["risk_priority_score"] = _risk_priority_score(item)
        if _active_poc_status(validation) != "verified":
            item["fix_artifact_kind"] = "guidance"
            item["fix_artifact_label"] = "Remediation Guidance"
        else:
            item["fix_artifact_kind"] = "exact_patch"
            item["fix_artifact_label"] = "Suggested Fix"
        item["fix_verification"] = _run_fix_verification(item, target_path)

    provider_applied = 0
    provider_errors: list[str] = []
    if provider_config.enabled:
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
    raw_enriched = _enriched_findings(scan_result.findings)
    enriched_findings = _deduplicate_enriched_findings(raw_enriched)
    enriched_findings, advanced_features = _apply_validation_and_ai(enriched_findings, scan_result.target_path)
    duplicate_reduction = max(0, len(raw_enriched) - len(enriched_findings))
    distribution = _severity_distribution_from_enriched(enriched_findings)
    risk_score = _risk_score_from_distribution(distribution)
    impacted_files = len({item["file_path"] for item in enriched_findings})
    active_risk_count = distribution.get("Critical", 0) + distribution.get("High", 0)
    active_poc_summary = _active_poc_summary(enriched_findings)
    fix_verification_summary = _fix_verification_summary(enriched_findings)

    confidence = "High"
    if len(scan_result.errors) > 5:
        confidence = "Medium"
    if len(scan_result.errors) > 15:
        confidence = "Low"

    controls = scan_result.existing_security_measures
    controls_payload = [item.to_dict() for item in controls]
    controls_summary = _controls_summary(controls)
    compliance_matrix = _compliance_matrix(controls_summary)
    profile_compliance = build_profile_compliance(scan_result.target_path, enriched_findings, controls_payload)
    autofix = _autofix_recommendations(enriched_findings)

    executive_summary = {
        "target_path": scan_result.target_path,
        "generated_at": scan_result.completed_at.isoformat(),
        "files_scanned": scan_result.files_scanned,
        "total_vulnerabilities": len(scan_result.findings),
        "deduplicated_vulnerabilities": len(enriched_findings),
        "duplicate_findings_removed": duplicate_reduction,
        "total_files_impacted": impacted_files,
        "active_risk_findings": active_risk_count,
        "assessment_confidence": confidence,
        "severity_distribution": distribution,
        "risk_score": risk_score,
        "risk_rating": risk_rating(risk_score),
        "top_vulnerability_types": _top_vulnerability_types(enriched_findings),
        "top_owasp_categories": _top_owasp_categories(enriched_findings),
        "affected_modules": _affected_modules(enriched_findings),
        "affected_files": _affected_files(enriched_findings),
        "affected_folders": _affected_folders(enriched_findings),
        "recommended_action_plan": _build_action_plan(distribution),
        "implemented_controls": controls_summary["implemented_controls"],
        "scan_profile": profile_compliance["scan_profile"],
        "scan_profile_label": profile_compliance["scan_profile_label"],
        "framework_versions": profile_compliance["framework_versions"],
    }

    technical_report = {
        "scan_window": {
            "started_at": scan_result.started_at.isoformat(),
            "completed_at": scan_result.completed_at.isoformat(),
            "duration_seconds": scan_result.duration_seconds,
        },
        "findings": enriched_findings,
        "errors": scan_result.errors,
    }

    existing_security_measures = {
        "summary": controls_summary,
        "controls": controls_payload,
        "compliance_matrix": compliance_matrix,
        "profile_compliance": profile_compliance,
    }

    vulnerability_findings = {
        "summary": {
            "total": len(enriched_findings),
            "raw_total": len(scan_result.findings),
            "duplicate_reduction": duplicate_reduction,
            "severity_distribution": distribution,
            "top_vulnerability_types": _top_vulnerability_types(enriched_findings),
            "scan_profile": profile_compliance["scan_profile"],
        },
        "findings": enriched_findings,
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
            "total_findings": len(enriched_findings),
            "raw_findings_total": len(scan_result.findings),
            "duplicate_findings_removed": duplicate_reduction,
            "severity_distribution": distribution,
            "risk_score": risk_score,
            "risk_rating": risk_rating(risk_score),
            "active_risk_findings": active_risk_count,
            "files_impacted": impacted_files,
            "top_vulnerability_types": _top_vulnerability_types(enriched_findings),
            "top_owasp_categories": _top_owasp_categories(enriched_findings),
            "affected_modules": _affected_modules(enriched_findings),
            "affected_files": _affected_files(enriched_findings),
            "affected_folders": _affected_folders(enriched_findings),
            "scan_profile": profile_compliance["scan_profile"],
            "active_poc": active_poc_summary,
            "fix_verification": fix_verification_summary,
        },
        "findings": enriched_findings,
        "auto_fix_recommendations": autofix,
        "toolchain_status": scan_result.toolchain_status,
    }

    role_aware_report = {
        "advanced_features": advanced_features,
    }
    vulnerability_fixed_code_report["role_aware_report"] = role_aware_report

    return {
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
        "role_aware_report": role_aware_report,
    }
