from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _starter_benchmark_path() -> Path:
    return Path(__file__).resolve().parents[1] / "resources" / "benchmark_truth_set.json"


def _resolve_benchmark_file(benchmark_file: str | Path) -> Path:
    benchmark_path = Path(benchmark_file)
    if benchmark_path.exists():
        return benchmark_path
    starter_path = _starter_benchmark_path()
    if starter_path.exists():
        return starter_path
    return benchmark_path


def _normalize_text(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def _normalize_path(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/").lower()
    text = text.split("?", 1)[0].split("#", 1)[0]
    text = re.sub(r"/+", "/", text)
    return text.strip("/")


def _path_matches(expected: str, actual: str) -> bool:
    if not expected or not actual:
        return False
    expected_norm = _normalize_path(expected)
    actual_norm = _normalize_path(actual)
    if not expected_norm or not actual_norm:
        return False
    if expected_norm == actual_norm:
        return True
    expected_name = expected_norm.rsplit("/", 1)[-1]
    actual_name = actual_norm.rsplit("/", 1)[-1]
    if expected_name and expected_name == actual_name:
        return True
    return actual_norm.endswith(f"/{expected_norm}") or expected_norm.endswith(f"/{actual_norm}")


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _benchmark_cases(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_cases = payload.get("cases")
    if isinstance(raw_cases, list):
        candidates = raw_cases
    elif isinstance(raw_cases, dict):
        candidates = []
        for bucket_name, expected_present in (
            ("present", True),
            ("expected_present", True),
            ("positives", True),
            ("absent", False),
            ("expected_absent", False),
            ("negatives", False),
        ):
            bucket = raw_cases.get(bucket_name)
            if isinstance(bucket, list):
                for item in bucket:
                    if isinstance(item, dict):
                        item = dict(item)
                        item.setdefault("expected_present", expected_present)
                        candidates.append(item)
    else:
        candidates = []
        for bucket_name, expected_present in (
            ("present", True),
            ("expected_present", True),
            ("positives", True),
            ("absent", False),
            ("expected_absent", False),
            ("negatives", False),
        ):
            bucket = payload.get(bucket_name)
            if isinstance(bucket, list):
                for item in bucket:
                    if isinstance(item, dict):
                        item = dict(item)
                        item.setdefault("expected_present", expected_present)
                        candidates.append(item)
    normalized: list[dict[str, Any]] = []
    for index, case in enumerate(candidates):
        if not isinstance(case, dict):
            continue
        expectation = case.get("expected_present")
        if expectation is None:
            expectation = case.get("expected")
        if isinstance(expectation, str):
            expectation = expectation.strip().lower() not in {"false", "0", "no", "absent", "negative"}
        expectation = bool(expectation)
        normalized.append(
            {
                "case_id": str(
                    case.get("case_id")
                    or case.get("id")
                    or case.get("finding_uid")
                    or case.get("uid")
                    or f"case-{index + 1}"
                ),
                "expected_present": expectation,
                "file_path": str(case.get("file_path") or case.get("path") or case.get("source_file") or "").strip(),
                "rule_id": str(case.get("rule_id") or case.get("rule") or "").strip(),
                "title": str(
                    case.get("vulnerability_title")
                    or case.get("vulnerability_type")
                    or case.get("title")
                    or case.get("issue")
                    or ""
                ).strip(),
                "cwe": str(case.get("cwe") or case.get("cwe_id") or "").strip(),
                "owasp": str(case.get("owasp") or case.get("owasp_category") or case.get("owasp_mapping") or "").strip(),
                "severity": str(case.get("severity") or "").strip(),
                "line_number": _coerce_int(case.get("line_number") or case.get("line") or 0, 0),
            }
        )
    return normalized


def _finding_payload(finding: Any, index: int) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        try:
            raw = finding.to_dict()
        except Exception:  # pragma: no cover - defensive guard
            raw = dict(finding) if isinstance(finding, dict) else {}
    elif isinstance(finding, dict):
        raw = dict(finding)
    else:
        raw = {}
    return {
        "finding_id": str(
            raw.get("finding_uid")
            or raw.get("finding_id")
            or raw.get("uid")
            or f"finding-{index + 1}"
        ),
        "file_path": str(raw.get("file_path") or raw.get("source_file") or "").strip(),
        "rule_id": str(raw.get("rule_id") or raw.get("rule") or "").strip(),
        "title": str(
            raw.get("vulnerability_title")
            or raw.get("vulnerability_type")
            or raw.get("title")
            or raw.get("issue")
            or ""
        ).strip(),
        "cwe": str(raw.get("cwe") or raw.get("cwe_id") or "").strip(),
        "owasp": str(raw.get("owasp_mapping") or raw.get("owasp_category") or raw.get("owasp") or "").strip(),
        "severity": str(raw.get("severity") or "").strip(),
        "line_number": _coerce_int(raw.get("line_number") or raw.get("line") or 0, 0),
        "raw": raw,
    }


def _match_score(case: dict[str, Any], finding: dict[str, Any]) -> int:
    score = 0
    if case.get("file_path") and finding.get("file_path"):
        if _path_matches(str(case["file_path"]), str(finding["file_path"])):
            score += 5
        else:
            return 0
    if case.get("rule_id") and finding.get("rule_id"):
        if _normalize_text(case["rule_id"]) == _normalize_text(finding["rule_id"]):
            score += 4
    if case.get("title") and finding.get("title"):
        if _normalize_text(case["title"]) == _normalize_text(finding["title"]):
            score += 3
    if case.get("cwe") and finding.get("cwe"):
        if _normalize_text(case["cwe"]) == _normalize_text(finding["cwe"]):
            score += 2
    if case.get("owasp") and finding.get("owasp"):
        if _normalize_text(case["owasp"]) == _normalize_text(finding["owasp"]):
            score += 2
    if case.get("severity") and finding.get("severity"):
        if _normalize_text(case["severity"]) == _normalize_text(finding["severity"]):
            score += 1
    case_line = int(case.get("line_number") or 0)
    finding_line = int(finding.get("line_number") or 0)
    if case_line and finding_line and case_line == finding_line:
        score += 1
    return score


def _case_label(case: dict[str, Any]) -> str:
    parts = [case.get("case_id") or "case"]
    if case.get("file_path"):
        parts.append(str(case["file_path"]))
    if case.get("rule_id"):
        parts.append(str(case["rule_id"]))
    if case.get("title"):
        parts.append(str(case["title"]))
    return " | ".join(str(part) for part in parts if str(part).strip())


def _finding_label(finding: dict[str, Any]) -> str:
    parts = [finding.get("finding_id") or "finding"]
    if finding.get("file_path"):
        parts.append(str(finding["file_path"]))
    if finding.get("rule_id"):
        parts.append(str(finding["rule_id"]))
    if finding.get("title"):
        parts.append(str(finding["title"]))
    return " | ".join(str(part) for part in parts if str(part).strip())


def evaluate_quality_benchmark(
    findings: list[dict[str, Any]] | list[Any],
    benchmark_file: str | Path,
    *,
    enabled: bool = True,
    min_precision: float = 90.0,
    min_recall: float = 85.0,
    min_f1: float = 88.0,
    strict_scope: bool = True,
) -> dict[str, Any]:
    benchmark_path = _resolve_benchmark_file(benchmark_file)
    base_payload: dict[str, Any] = {
        "enabled": bool(enabled),
        "configured": False,
        "benchmark_status": "disabled" if not enabled else "not_configured",
        "benchmark_name": "CodeSentinelX quality benchmark",
        "benchmark_file": str(benchmark_path),
        "benchmark_description": "",
        "cases_total": 0,
        "expected_present": 0,
        "expected_absent": 0,
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
        "precision_percent": 0.0,
        "recall_percent": 0.0,
        "f1_percent": 0.0,
        "false_positive_rate_percent": 0.0,
        "threshold_precision_percent": float(min_precision),
        "threshold_recall_percent": float(min_recall),
        "threshold_f1_percent": float(min_f1),
        "matched_case_ids": [],
        "missing_case_ids": [],
        "unexpected_finding_ids": [],
        "gate_blockers": [],
        "gate_advisories": [],
        "strict_scope": bool(strict_scope),
    }
    if not enabled:
        base_payload["gate_advisories"] = ["CodeSentinelX quality benchmark evaluation is disabled."]
        return base_payload
    if not benchmark_path.exists():
        base_payload["gate_advisories"] = [f"CodeSentinelX quality benchmark file not found: {benchmark_path}"]
        return base_payload

    payload = _read_json(benchmark_path)
    if not payload:
        base_payload["gate_advisories"] = [f"CodeSentinelX quality benchmark file could not be parsed: {benchmark_path}"]
        return base_payload

    benchmark_name = str(payload.get("benchmark_name") or payload.get("name") or "CodeSentinelX quality benchmark").strip() or "CodeSentinelX quality benchmark"
    benchmark_description = str(
        payload.get("benchmark_description")
        or payload.get("description")
        or payload.get("summary")
        or ""
    ).strip()
    cases = _benchmark_cases(payload)
    base_payload["configured"] = True
    base_payload["benchmark_name"] = benchmark_name
    base_payload["benchmark_description"] = benchmark_description
    base_payload["cases_total"] = len(cases)
    base_payload["expected_present"] = sum(1 for case in cases if bool(case.get("expected_present")))
    base_payload["expected_absent"] = sum(1 for case in cases if not bool(case.get("expected_present")))

    if not cases:
        base_payload["benchmark_status"] = "warning"
        base_payload["gate_advisories"] = [
            f"{benchmark_name} is configured but contains no benchmark cases.",
        ]
        return base_payload

    normalized_findings = [_finding_payload(finding, index) for index, finding in enumerate(findings or [])]
    matched_finding_indexes: set[int] = set()
    matched_case_ids: list[str] = []
    missing_case_ids: list[str] = []
    unexpected_finding_ids: list[str] = []
    false_positive_case_ids: list[str] = []

    minimum_score = 4 if strict_scope else 3

    for case in [item for item in cases if bool(item.get("expected_present"))]:
        best_index = -1
        best_score = 0
        for index, finding in enumerate(normalized_findings):
            if index in matched_finding_indexes:
                continue
            score = _match_score(case, finding)
            if score > best_score:
                best_score = score
                best_index = index
        if best_index >= 0 and best_score >= minimum_score:
            matched_finding_indexes.add(best_index)
            matched_case_ids.append(_case_label(case))
        else:
            missing_case_ids.append(_case_label(case))

    for case in [item for item in cases if not bool(item.get("expected_present"))]:
        best_index = -1
        best_score = 0
        for index, finding in enumerate(normalized_findings):
            if index in matched_finding_indexes:
                continue
            score = _match_score(case, finding)
            if score > best_score:
                best_score = score
                best_index = index
        if best_index >= 0 and best_score >= minimum_score:
            matched_finding_indexes.add(best_index)
            false_positive_case_ids.append(_case_label(case))

    if strict_scope:
        for index, finding in enumerate(normalized_findings):
            if index not in matched_finding_indexes:
                unexpected_finding_ids.append(_finding_label(finding))

    true_positives = len(matched_case_ids)
    false_negatives = len(missing_case_ids)
    false_positives = len(dict.fromkeys(false_positive_case_ids + unexpected_finding_ids))
    true_negatives = max(0, base_payload["expected_absent"] - len(false_positive_case_ids))

    precision = (true_positives / (true_positives + false_positives) * 100.0) if (true_positives + false_positives) else 100.0
    recall = (true_positives / (true_positives + false_negatives) * 100.0) if (true_positives + false_negatives) else 100.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    false_positive_rate = (
        false_positives / (false_positives + true_negatives) * 100.0
        if (false_positives + true_negatives)
        else 0.0
    )

    gate_blockers: list[str] = []
    if precision < min_precision:
        gate_blockers.append(
            f"Precision {precision:.2f}% is below the required threshold of {float(min_precision):.2f}%."
        )
    if recall < min_recall:
        gate_blockers.append(f"Recall {recall:.2f}% is below the required threshold of {float(min_recall):.2f}%.")
    if f1 < min_f1:
        gate_blockers.append(f"F1 {f1:.2f}% is below the required threshold of {float(min_f1):.2f}%.")
    if strict_scope and unexpected_finding_ids:
        gate_blockers.append(
            f"{len(unexpected_finding_ids)} unexpected finding(s) fell outside the benchmark scope."
        )

    gate_advisories: list[str] = []
    if missing_case_ids:
        gate_advisories.append(f"{len(missing_case_ids)} expected present benchmark case(s) were not matched.")
    if false_positive_case_ids:
        gate_advisories.append(f"{len(false_positive_case_ids)} expected-absent benchmark case(s) matched a finding.")
    if strict_scope and not base_payload["expected_present"] and not base_payload["expected_absent"]:
        gate_advisories.append("Benchmark file is configured, but no evaluation cases were defined.")

    if gate_blockers:
        benchmark_status = "blocked"
    elif false_positive_case_ids or missing_case_ids:
        benchmark_status = "warning"
    else:
        benchmark_status = "ready"

    return {
        **base_payload,
        "benchmark_status": benchmark_status,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "precision_percent": round(precision, 2),
        "recall_percent": round(recall, 2),
        "f1_percent": round(f1, 2),
        "false_positive_rate_percent": round(false_positive_rate, 2),
        "matched_case_ids": matched_case_ids,
        "missing_case_ids": missing_case_ids,
        "unexpected_finding_ids": list(dict.fromkeys(unexpected_finding_ids)),
        "gate_blockers": gate_blockers,
        "gate_advisories": gate_advisories,
    }
