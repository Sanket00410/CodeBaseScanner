from __future__ import annotations

from collections import Counter
from typing import Any

from codesentinelx_engine.models import Finding, Severity

SEVERITY_WEIGHT: dict[Severity | str, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Info": 0,
}


def _resolve_serverity(severity: Any) -> Any:
    if isinstance(severity, Severity):
        return severity
    if isinstance(severity, str):
        sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "informational": "Info"}
        return sev_map.get(severity.lower(), "Info")
    return Severity.INFO


def severity_distribution(findings: list[Finding]) -> dict[str, int]:
    counter: Counter[Severity] = Counter(item.severity for item in findings)
    return {
        Severity.CRITICAL.value: counter.get(Severity.CRITICAL, 0),
        Severity.HIGH.value: counter.get(Severity.HIGH, 0),
        Severity.MEDIUM.value: counter.get(Severity.MEDIUM, 0),
        Severity.LOW.value: counter.get(Severity.LOW, 0),
        Severity.INFO.value: counter.get(Severity.INFO, 0),
    }


def calculate_risk_score(findings: list) -> float:
    if not findings:
        return 0.0

    weighted_sum = sum(SEVERITY_WEIGHT[_resolve_serverity(item.severity)] for item in findings)
    max_weighted_sum = len(findings) * SEVERITY_WEIGHT[Severity.CRITICAL]

    severity_factor = (weighted_sum / max_weighted_sum) * 60.0
    count_factor = min(len(findings) / 50.0, 1.0) * 40.0

    return round(min(100.0, severity_factor + count_factor), 2)


def risk_rating(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"

