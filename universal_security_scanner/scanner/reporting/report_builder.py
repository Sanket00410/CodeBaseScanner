from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
import re

from universal_security_scanner.models import Finding, ScanResult, SecurityControl
from universal_security_scanner.risk import risk_rating
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


def _fix_artifacts(vulnerability_type: str, evidence: str | None, recommendation: str, file_path: str) -> tuple[str, str, str, str]:
    lowered = vulnerability_type.lower()
    original = evidence.strip() if evidence else ""
    fixed = recommendation.strip()
    confidence = "Medium"

    if "sql injection" in lowered:
        fixed = (
            'query = "SELECT * FROM users WHERE id = %s"\n'
            "cursor.execute(query, (user_id,))"
        )
        confidence = "High"
    elif "xss" in lowered:
        fixed = (
            "const safeContent = sanitize(userInput);\n"
            "targetElement.textContent = safeContent;"
        )
        confidence = "High"
    elif "command injection" in lowered:
        fixed = (
            "subprocess.run([\"/usr/bin/tool\", user_arg], check=True, shell=False)"
        )
        confidence = "High"
    elif "path traversal" in lowered:
        fixed = (
            "safe_base = Path('/app/data').resolve()\n"
            "safe_path = (safe_base / user_file).resolve()\n"
            "if not str(safe_path).startswith(str(safe_base)):\n"
            "    raise ValueError('Invalid path')"
        )
        confidence = "High"
    elif "secret" in lowered or "hardcoded" in lowered:
        fixed = (
            "import os\n"
            "api_key = os.environ['API_KEY']  # managed by vault/secret manager"
        )
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
        fixed = (
            "ALLOWED_ACTIONS = {'sum': safe_sum, 'avg': safe_avg}\n"
            "result = ALLOWED_ACTIONS[action](payload)"
        )
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
        attack_scenario, exploitation_example, proof_of_concept, secure_fix_example = _scenario_for(
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
        base["proof_of_concept"] = proof_of_concept
        base["secure_code_example"] = secure_fix_example
        base["affected_module"] = _module_name(finding.file_path)
        base["vulnerable_code_snippet"] = finding.evidence or ""
        base["original_code"] = original_code
        base["fixed_code"] = fixed_code
        base["patch_preview"] = patch_preview
        base["autofix_confidence"] = autofix_confidence
        base["finding_uid"] = f"{base.get('rule_id', '')}::{base.get('file_path', '')}::{base.get('line_number', 0)}"
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


def build_report(scan_result: ScanResult) -> dict:
    raw_enriched = _enriched_findings(scan_result.findings)
    enriched_findings = _deduplicate_enriched_findings(raw_enriched)
    duplicate_reduction = max(0, len(raw_enriched) - len(enriched_findings))
    distribution = _severity_distribution_from_enriched(enriched_findings)
    risk_score = _risk_score_from_distribution(distribution)
    impacted_files = len({item["file_path"] for item in enriched_findings})
    active_risk_count = distribution.get("Critical", 0) + distribution.get("High", 0)

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
        },
        "findings": enriched_findings,
        "auto_fix_recommendations": autofix,
        "toolchain_status": scan_result.toolchain_status,
    }

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
    }
