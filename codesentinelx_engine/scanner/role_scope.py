from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


_ROLE_ALIASES = {
    "admin": "Admin",
    "administrator": "Admin",
    "security analyst": "Security Analyst",
    "securityanalyst": "Security Analyst",
    "developer": "Developer",
    "auditor": "Auditor",
    "management": "Management",
    "manager": "Management",
    "board": "Management",
}

_ROLE_DEFAULT_SCAN_PRESETS = {
    "Admin": "deep",
    "Security Analyst": "standard",
    "Developer": "fast",
    "Auditor": "fast",
    "Management": "fast",
}


@dataclass(frozen=True, slots=True)
class RoleScope:
    role: str
    tool_allowlist: frozenset[str]
    run_external_tools: bool
    run_file_findings: bool
    run_project_rules: bool
    run_native_code_analysis: bool
    run_native_dependency_analysis: bool
    run_active_poc: bool
    run_fix_verification: bool
    redact_findings: bool
    findings_empty: bool
    report_sections: frozenset[str]
    summary_keys_to_keep: frozenset[str]
    role_aware_keys: frozenset[str]


_ALL_CODEBASE_TOOLS = {
    "bandit",
    "brakeman",
    "checkov",
    "clair",
    "codeql",
    "eslint-security",
    "gitleaks",
    "gosec",
    "govulncheck",
    "grype",
    "hadolint",
    "infer",
    "osv-scanner",
    "semgrep",
    "tfsec",
}

_STANDARD_CODEBASE_TOOLS = {
    "bandit",
    "brakeman",
    "checkov",
    "eslint-security",
    "gitleaks",
    "gosec",
    "govulncheck",
    "grype",
    "hadolint",
    "infer",
    "osv-scanner",
    "semgrep",
    "tfsec",
}

_FAST_CODEBASE_TOOLS = {
    "bandit",
    "checkov",
    "gitleaks",
    "semgrep",
}

_ROLE_TOOL_ALLOWLIST = {
    "Admin": frozenset(_ALL_CODEBASE_TOOLS),
    "Security Analyst": frozenset(_STANDARD_CODEBASE_TOOLS),
    "Developer": frozenset(
        {
            "bandit",
            "checkov",
            "eslint-security",
            "gitleaks",
            "gosec",
            "govulncheck",
            "hadolint",
            "infer",
            "semgrep",
            "tfsec",
        }
    ),
    "Auditor": frozenset(
        {
            "checkov",
            "hadolint",
            "osv-scanner",
            "tfsec",
        }
    ),
    "Management": frozenset(),
}

_ROLE_SCOPES = {
    "Admin": RoleScope(
        role="Admin",
        tool_allowlist=_ROLE_TOOL_ALLOWLIST["Admin"],
        run_external_tools=True,
        run_file_findings=True,
        run_project_rules=True,
        run_native_code_analysis=True,
        run_native_dependency_analysis=True,
        run_active_poc=True,
        run_fix_verification=True,
        redact_findings=False,
        findings_empty=False,
        report_sections=frozenset({"all"}),
        summary_keys_to_keep=frozenset({"all"}),
        role_aware_keys=frozenset({"all"}),
    ),
    "Security Analyst": RoleScope(
        role="Security Analyst",
        tool_allowlist=_ROLE_TOOL_ALLOWLIST["Security Analyst"],
        run_external_tools=True,
        run_file_findings=True,
        run_project_rules=True,
        run_native_code_analysis=True,
        run_native_dependency_analysis=True,
        run_active_poc=True,
        run_fix_verification=True,
        redact_findings=False,
        findings_empty=False,
        report_sections=frozenset({"ciso_security_view", "developer_devops_view", "risk_story_mode", "advanced_features", "enterprise_assurance", "false_positive_report"}),
        summary_keys_to_keep=frozenset({"all"}),
        role_aware_keys=frozenset({"ciso_security_view", "developer_devops_view", "risk_story_mode", "advanced_features", "enterprise_assurance", "false_positive_report"}),
    ),
    "Developer": RoleScope(
        role="Developer",
        tool_allowlist=_ROLE_TOOL_ALLOWLIST["Developer"],
        run_external_tools=True,
        run_file_findings=True,
        run_project_rules=True,
        run_native_code_analysis=True,
        run_native_dependency_analysis=True,
        run_active_poc=True,
        run_fix_verification=True,
        redact_findings=False,
        findings_empty=False,
        report_sections=frozenset({"developer_devops_view", "risk_story_mode", "advanced_features"}),
        summary_keys_to_keep=frozenset(
            {
                "all",
            }
        ),
        role_aware_keys=frozenset({"developer_devops_view", "risk_story_mode", "advanced_features"}),
    ),
    "Auditor": RoleScope(
        role="Auditor",
        tool_allowlist=_ROLE_TOOL_ALLOWLIST["Auditor"],
        run_external_tools=True,
        run_file_findings=False,
        run_project_rules=False,
        run_native_code_analysis=False,
        run_native_dependency_analysis=False,
        run_active_poc=False,
        run_fix_verification=False,
        redact_findings=True,
        findings_empty=False,
        report_sections=frozenset({"enterprise_assurance", "false_positive_report"}),
        summary_keys_to_keep=frozenset({"all"}),
        role_aware_keys=frozenset({"enterprise_assurance", "false_positive_report"}),
    ),
    "Management": RoleScope(
        role="Management",
        tool_allowlist=_ROLE_TOOL_ALLOWLIST["Management"],
        run_external_tools=False,
        run_file_findings=False,
        run_project_rules=False,
        run_native_code_analysis=False,
        run_native_dependency_analysis=False,
        run_active_poc=False,
        run_fix_verification=False,
        redact_findings=True,
        findings_empty=True,
        report_sections=frozenset({"cto_board_view", "risk_story_mode", "enterprise_assurance"}),
        summary_keys_to_keep=frozenset(
            {
                "all",
            }
        ),
        role_aware_keys=frozenset({"cto_board_view", "risk_story_mode", "enterprise_assurance"}),
    ),
}


def normalize_role(role: str | None) -> str:
    label = str(role or "Security Analyst").strip()
    if not label:
        return "Security Analyst"
    lower = label.lower()
    return _ROLE_ALIASES.get(lower, label if label in _ROLE_SCOPES else "Security Analyst")


def resolve_role_scope(role: str | None) -> RoleScope:
    normalized = normalize_role(role)
    return _ROLE_SCOPES.get(normalized, _ROLE_SCOPES["Security Analyst"])


def role_allows_tool(role: str | None, tool_name: str) -> bool:
    scope = resolve_role_scope(role)
    return tool_name.strip().lower() in {tool.lower() for tool in scope.tool_allowlist}


def role_runs_active_poc(role: str | None) -> bool:
    return resolve_role_scope(role).run_active_poc


def role_runs_fix_verification(role: str | None) -> bool:
    return resolve_role_scope(role).run_fix_verification


def role_default_scan_preset(role: str | None) -> str:
    normalized = normalize_role(role)
    return _ROLE_DEFAULT_SCAN_PRESETS.get(normalized, "standard")


def _redact_finding_for_audit(finding: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "finding_uid",
        "alert_group_uid",
        "alert_group_title",
        "alert_group_cwe",
        "alert_group_owasp",
        "alert_group_instance_index",
        "alert_group_instance_count",
        "alert_group_anchor",
        "alert_title_group_uid",
        "alert_title_group_title",
        "alert_title_group_instance_index",
        "alert_title_group_instance_count",
        "alert_title_group_anchor",
        "vulnerability_title",
        "vulnerability_type",
        "severity",
        "cvss_score",
        "cwe_id",
        "owasp_mapping",
        "file_path",
        "line_number",
        "business_impact",
        "recommendation",
        "rule_id",
        "dependency_reachability",
        "attack_scenario",
        "exploitation_example",
        "proof_of_concept_template",
        "cve_ids",
        "advisory_ids",
        "dependency_name",
        "dependency_version",
        "dependency_id",
        "known_exploited",
        "exploit_maturity",
        "exploitability_context",
        "release_gate_action",
        "code_owner",
        "rule_confidence",
        "rule_confidence_label",
        "finding_origin",
        "finding_origin_label",
        "corroboration_sources",
        "corroboration_labels",
        "corroboration_count",
        "corroborated",
        "suppression_candidate",
        "suppression_reason",
        "suppression_detail",
        "suppression_tags",
        "triage_owner",
        "suppression_owner",
        "suppression_review_by",
        "suppression_requires_expiry",
        "suppression_governance_state",
        "evidence_replay_pack",
    }
    redacted = {key: deepcopy(value) for key, value in finding.items() if key in allowed_keys}
    redacted.pop("proof_of_concept", None)
    redacted.pop("original_code", None)
    redacted.pop("fixed_code", None)
    redacted.pop("ai_suggested_fix", None)
    redacted.pop("ai_remediation_summary", None)
    redacted.pop("ai_validation_steps", None)
    redacted.pop("ai_fix_source", None)
    redacted.pop("ai_fix_confidence_label", None)
    redacted.pop("ai_fix_confidence_score", None)
    redacted.pop("ai_fix_grounded", None)
    redacted.pop("ai_grounding_notes", None)
    redacted.pop("patch_preview", None)
    redacted.pop("active_poc", None)
    redacted.pop("fix_verification", None)
    return redacted


def scope_findings_for_role(findings: list[dict[str, Any]], role: str | None) -> list[dict[str, Any]]:
    scope = resolve_role_scope(role)
    if scope.findings_empty:
        return []
    visible = [item for item in findings if item is not None]
    if not scope.redact_findings:
        return deepcopy(visible)
    return [_redact_finding_for_audit(item) for item in visible]


def scope_report_for_role(report: dict[str, Any], role: str | None) -> dict[str, Any]:
    scoped = deepcopy(report)
    scope = resolve_role_scope(role)
    report_role = scope.role
    visible_sections = set(scope.role_aware_keys)

    executive_summary = scoped.get("executive_summary")
    if isinstance(executive_summary, dict):
        executive_summary["scan_role"] = report_role

    existing = scoped.get("existing_implementation_report")
    if isinstance(existing, dict):
        existing["scan_role"] = report_role

    vuln = scoped.get("vulnerability_fixed_code_report")
    if isinstance(vuln, dict):
        vuln["scan_role"] = report_role
        summary = vuln.get("summary")
        if isinstance(summary, dict):
            summary["scan_role"] = report_role
            if report_role in {"Auditor", "Management"}:
                summary.pop("active_poc", None)
                summary.pop("fix_verification", None)
            if report_role == "Management":
                summary.pop("toolchain_execution", None)
                summary.pop("false_positive_candidates", None)
                summary.pop("deterministic_replay", None)
                summary.pop("report_integrity_chain", None)
                summary.pop("suppression_lifecycle", None)
        findings = vuln.get("findings")
        if isinstance(findings, list):
            if scope.findings_empty:
                vuln["findings"] = []
            elif scope.redact_findings:
                vuln["findings"] = [_redact_finding_for_audit(item) for item in findings if isinstance(item, dict)]

    technical_report = scoped.get("technical_report")
    if isinstance(technical_report, dict):
        if scope.findings_empty:
            technical_report["findings"] = []
        else:
            technical_findings = technical_report.get("findings")
            if isinstance(technical_findings, list) and scope.redact_findings:
                technical_report["findings"] = [_redact_finding_for_audit(item) for item in technical_findings if isinstance(item, dict)]

    if scope.findings_empty:
        scoped["auto_fix_recommendations"] = []
        scoped["false_positive_report"] = None

    role_aware = scoped.get("role_aware_report")
    if isinstance(role_aware, dict):
        role_aware["metadata"] = {
            "scan_role": report_role,
            "role_scope": {
                "active_poc": scope.run_active_poc,
                "fix_verification": scope.run_fix_verification,
                "redact_findings": scope.redact_findings,
                "findings_empty": scope.findings_empty,
            },
            "allowed_sections": sorted(scope.role_aware_keys),
        }
        if "all" not in scope.role_aware_keys:
            for key in list(role_aware.keys()):
                if key in {"metadata", "visualization_hints"}:
                    continue
                if key not in scope.role_aware_keys:
                    role_aware.pop(key, None)

    if "all" not in visible_sections:
        for section_key in (
            "cto_board_view",
            "ciso_security_view",
            "developer_devops_view",
            "risk_story_mode",
            "advanced_features",
            "enterprise_assurance",
            "false_positive_report",
        ):
            if section_key not in visible_sections:
                scoped.pop(section_key, None)

    if report_role == "Management":
        data_quality = scoped.get("executive_summary", {}).get("data_quality") if isinstance(scoped.get("executive_summary"), dict) else None
        if isinstance(data_quality, dict):
            data_quality.pop("quality_benchmark", None)
        executive_summary = scoped.get("executive_summary")
        if isinstance(executive_summary, dict):
            executive_summary.pop("data_quality", None)
        enterprise_assurance = scoped.get("executive_summary", {}).get("enterprise_assurance") if isinstance(scoped.get("executive_summary"), dict) else None
        if isinstance(enterprise_assurance, dict):
            enterprise_assurance.pop("quality_benchmark", None)
        vuln_summary = scoped.get("vulnerability_fixed_code_report", {}).get("summary") if isinstance(scoped.get("vulnerability_fixed_code_report"), dict) else None
        if isinstance(vuln_summary, dict):
            data_quality = vuln_summary.get("data_quality")
            if isinstance(data_quality, dict):
                data_quality.pop("quality_benchmark", None)
        role_aware = scoped.get("role_aware_report")
        if isinstance(role_aware, dict):
            enterprise_assurance = role_aware.get("enterprise_assurance")
            if isinstance(enterprise_assurance, dict):
                enterprise_assurance.pop("quality_benchmark", None)
        scoped.pop("false_positive_report", None)
        scoped.pop("deterministic_replay", None)
        scoped.pop("report_integrity_chain", None)

    return scoped
