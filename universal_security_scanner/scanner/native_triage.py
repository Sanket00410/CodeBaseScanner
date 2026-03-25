from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import os
from typing import Any

_GENERIC_TITLES = {
    "security",
    "security issue",
    "security finding",
    "vulnerability",
    "issue",
    "finding",
    "external analyzer finding",
    "analyzer finding",
    "unclassified security finding",
}

_VENDOR_SEGMENTS = {
    "node_modules",
    "vendor",
    "third_party",
    "external",
    "deps",
    ".toolchain",
    "site-packages",
}
_TEST_SEGMENTS = {"tests", "test", "spec", "__tests__", "fixtures", "testdata", "mocks", "snapshots", "__snapshots__"}
_DOC_SEGMENTS = {"docs", "documentation", "wiki", "guides", "examples", "samples", "tutorials", "demo"}
_GENERATED_HINTS = {"dist", "build", "coverage", "reports", "artifacts", "tmp", "temp", "logs", "__pycache__"}


def _confidence_label(score: float) -> str:
    if score >= 0.82:
        return "High"
    if score >= 0.58:
        return "Medium"
    return "Low"


def _normalized_path(value: str) -> str:
    return str(value or "").replace("\\", "/").strip().strip("/")


def _path_tags(file_path: str) -> list[str]:
    parts = [part.lower() for part in _normalized_path(file_path).split("/") if part]
    tags: list[str] = []
    if any(part in _VENDOR_SEGMENTS for part in parts):
        tags.append("vendor-code")
    if any(part in _TEST_SEGMENTS for part in parts):
        tags.append("test-artifact")
    if any(part in _DOC_SEGMENTS for part in parts):
        tags.append("docs-example")
    if any(part in _GENERATED_HINTS for part in parts):
        tags.append("generated-build")
    return tags


def _status(item: dict[str, Any]) -> str:
    return str(((item.get("active_poc") or {}).get("status") or "not_applicable")).strip().lower()


def _origin_from_rule(rule_id: str) -> str:
    normalized = rule_id.strip().upper()
    if normalized.startswith("NATIVE-DEP-"):
        return "native_dependency"
    if normalized.startswith(("PY-A", "JS-A")) and "FLOW" in normalized:
        return "native_code"
    if normalized.startswith(("OWASP-", "BUILTIN-", "RULE-")):
        return "rule_engine"
    if normalized.startswith(
        (
            "SEMGREP-",
            "TRIVY-",
            "GITLEAKS-",
            "CODEQL-",
            "BANDIT-",
            "CHECKOV-",
            "PIP-AUDIT-",
            "GRYPE-",
            "OSV-",
            "HADOLINT-",
            "TFSEC-",
            "GOSEC-",
            "SNYK-",
            "SAFETY-",
            "NPM-AUDIT-",
            "SPOTBUGS-",
            "FINDBUGS-",
            "FINDBEBUGS-",
            "FLAWFINDER-",
            "CPP-",
            "ESLINT-",
        )
    ):
        return "external_tool"
    return "rule_engine"


def _origin_label(origin: str) -> str:
    return {
        "native_code": "Native Code Engine",
        "native_dependency": "Native Dependency Engine",
        "builtin_plugin": "Builtin Language Plugin",
        "external_tool": "External Tool Corroboration",
        "project_rule": "Project Rule",
        "rule_engine": "Rule Engine",
    }.get(origin, "Rule Engine")


def _annotate_provenance(item: dict[str, Any]) -> dict[str, Any]:
    primary = str(item.get("origin") or "").strip().lower() or _origin_from_rule(str(item.get("rule_id") or ""))
    evidence_origins = [str(value).strip().lower() for value in (item.get("evidence_origins") or []) if str(value).strip()]
    if not evidence_origins:
        evidence_origins = [primary]
    normalized_origins = sorted(dict.fromkeys(origin or _origin_from_rule(str(item.get("rule_id") or "")) for origin in evidence_origins))
    corroborated = len(normalized_origins) > 1
    return {
        "primary_origin": primary,
        "primary_origin_label": _origin_label(primary),
        "corroboration_sources": normalized_origins,
        "corroboration_labels": [_origin_label(origin) for origin in normalized_origins],
        "corroboration_count": len(normalized_origins),
        "corroborated": corroborated,
    }


def _score_finding(item: dict[str, Any]) -> float:
    rule_id = str(item.get("rule_id") or "").upper()
    title = str(item.get("vulnerability_title") or item.get("vulnerability_type") or "").strip().lower()
    evidence = str(item.get("vulnerable_code_snippet") or item.get("evidence") or item.get("original_code") or "").strip()
    cwe = str(item.get("cwe_id") or item.get("cwe") or "").strip().upper()
    owasp = str(item.get("owasp_mapping") or item.get("owasp_category") or "").strip().upper()
    active_poc = item.get("active_poc") or {}
    dep = item.get("dependency_reachability") or {}
    evidence_sources = item.get("evidence_sources") or []

    score = 0.45
    if rule_id.startswith(("PY-A", "JS-A", "GO-A", "NATIVE-")):
        score += 0.12
    if rule_id.startswith("NATIVE-DEP-"):
        score += 0.08
    if evidence:
        score += 0.08
    if cwe and cwe != "N/A":
        score += 0.05
    if owasp and owasp != "N/A":
        score += 0.05
    if evidence_sources:
        score += min(0.08, max(0, len(evidence_sources) - 1) * 0.03)
    provenance = _annotate_provenance(item)
    if provenance["corroborated"]:
        score += min(0.1, 0.04 * int(provenance["corroboration_count"]))

    poc_confidence = active_poc.get("confidence")
    try:
        if poc_confidence is not None:
            score = max(score, min(0.98, score * 0.55 + float(poc_confidence) * 0.45))
    except Exception:
        pass

    poc_status = _status(item)
    if poc_status == "verified":
        score += 0.14
    elif poc_status == "inconclusive":
        score += 0.02
    elif poc_status in {"error", "failed"}:
        score -= 0.10

    if dep:
        dep_status = str(dep.get("status") or "").strip().lower()
        if dep_status == "reachable_in_code":
            score += 0.15
        elif dep_status == "installed_locked":
            score += 0.08
        elif dep_status == "declared_only":
            score -= 0.05
        elif dep_status == "unverified_dependency":
            score -= 0.16
        if dep.get("advisory_verified"):
            score += 0.08
        if dep.get("import_evidence"):
            score += 0.05

    if bool(item.get("ai_fix_grounded")):
        score += 0.02
    if title in _GENERIC_TITLES:
        score -= 0.14

    for tag in _path_tags(str(item.get("file_path") or "")):
        if tag == "vendor-code":
            score -= 0.18
        elif tag == "test-artifact":
            score -= 0.16
        elif tag == "docs-example":
            score -= 0.14
        elif tag == "generated-build":
            score -= 0.12

    return round(max(0.05, min(0.99, score)), 2)


def _suppression_decision(item: dict[str, Any], score: float) -> dict[str, Any]:
    severity = str(item.get("severity") or "Info")
    title = str(item.get("vulnerability_title") or item.get("vulnerability_type") or "Issue")
    dep = item.get("dependency_reachability") or {}
    tags = _path_tags(str(item.get("file_path") or ""))
    reasons: list[str] = []

    if "vendor-code" in tags:
        reasons.append("Finding is located in vendor/third-party code rather than first-party application code.")
    if "test-artifact" in tags:
        reasons.append("Finding is located in tests, fixtures, or mock data and should be reviewed before entering the main queue.")
    if "docs-example" in tags:
        reasons.append("Finding is located in documentation/examples and may not represent production behavior.")
    if "generated-build" in tags:
        reasons.append("Finding is located in generated/build output and should be traced back to source before triage.")

    dep_status = str(dep.get("status") or "").strip().lower()
    if dep and dep_status in {"declared_only", "unverified_dependency"} and not dep.get("advisory_verified"):
        reasons.append("Dependency issue has weak authenticity evidence: no lockfile/reachability/advisory verification yet.")
    if _status(item) in {"error", "inconclusive"} and score < 0.72:
        reasons.append("Validation did not fully confirm exploitability, so analyst review is recommended before escalation.")
    if title.strip().lower() in _GENERIC_TITLES and score < 0.6:
        reasons.append("Finding title/classification is still generic and needs analyst confirmation.")
    if score < 0.38 and severity in {"Info", "Low", "Medium"}:
        reasons.append("Overall confidence is low relative to severity, so this should enter suppression review instead of the primary queue.")

    candidate = bool(reasons)
    if candidate and dep and dep_status:
        tags.append(f"dependency:{dep_status}")
    return {
        "candidate": candidate,
        "reason_summary": reasons[0] if reasons else "",
        "reason_detail": " ".join(reasons).strip(),
        "tags": sorted(dict.fromkeys(tags)),
    }


def annotate_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    default_owner = os.getenv("USS_SUPPRESSION_DEFAULT_OWNER", "security-triage").strip() or "security-triage"
    try:
        review_days = max(1, int(os.getenv("USS_SUPPRESSION_REVIEW_DAYS", "30")))
    except ValueError:
        review_days = 30
    require_expiry = os.getenv("USS_SUPPRESSION_REQUIRE_EXPIRY", "1").strip().lower() not in {"0", "false", "no", "off"}
    review_by = (datetime.now(timezone.utc) + timedelta(days=review_days)).date().isoformat()
    tag_counter: Counter[str] = Counter()
    owner_counter: Counter[str] = Counter()
    origin_counter: Counter[str] = Counter()
    candidate_count = 0
    low_confidence_count = 0
    confidence_total = 0.0
    expiry_required_count = 0

    for item in findings:
        provenance = _annotate_provenance(item)
        item["finding_origin"] = provenance["primary_origin"]
        item["finding_origin_label"] = provenance["primary_origin_label"]
        item["corroboration_sources"] = provenance["corroboration_sources"]
        item["corroboration_labels"] = provenance["corroboration_labels"]
        item["corroboration_count"] = provenance["corroboration_count"]
        item["corroborated"] = provenance["corroborated"]
        score = _score_finding(item)
        label = _confidence_label(score)
        decision = _suppression_decision(item, score)
        item["rule_confidence"] = score
        item["rule_confidence_label"] = label
        item["suppression_candidate"] = decision["candidate"]
        item["suppression_reason"] = decision["reason_summary"]
        item["suppression_detail"] = decision["reason_detail"]
        item["suppression_tags"] = decision["tags"]
        item["suppression_owner"] = default_owner if decision["candidate"] else ""
        item["suppression_review_by"] = review_by if decision["candidate"] else ""
        item["suppression_requires_expiry"] = bool(decision["candidate"] and require_expiry)
        item["suppression_governance_state"] = "review_required" if decision["candidate"] else "not_applicable"
        confidence_total += score
        if score < 0.58:
            low_confidence_count += 1
        origin_counter[item["finding_origin"]] += 1
        if decision["candidate"]:
            candidate_count += 1
            owner_counter[default_owner] += 1
            if require_expiry:
                expiry_required_count += 1
            for tag in decision["tags"]:
                tag_counter[tag] += 1

    average_confidence = round(confidence_total / max(1, len(findings)), 2)
    return findings, {
        "generated_at": None,
        "candidate_count": candidate_count,
        "low_confidence_findings": low_confidence_count,
        "average_rule_confidence": average_confidence,
        "average_rule_confidence_label": _confidence_label(average_confidence),
        "candidate_tags": dict(tag_counter.most_common()),
        "suppression_drift_score": 0.0,
        "default_owner": default_owner,
        "review_window_days": review_days,
        "review_by": review_by,
        "expiry_required_count": expiry_required_count,
        "candidate_by_owner": dict(owner_counter.most_common()),
        "finding_origins": dict(origin_counter.most_common()),
    }
