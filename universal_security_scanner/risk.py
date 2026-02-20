from __future__ import annotations

from collections import Counter

from universal_security_scanner.models import Finding, Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def severity_distribution(findings: list[Finding]) -> dict[str, int]:
    counter: Counter[Severity] = Counter(item.severity for item in findings)
    return {
        Severity.CRITICAL.value: counter.get(Severity.CRITICAL, 0),
        Severity.HIGH.value: counter.get(Severity.HIGH, 0),
        Severity.MEDIUM.value: counter.get(Severity.MEDIUM, 0),
        Severity.LOW.value: counter.get(Severity.LOW, 0),
        Severity.INFO.value: counter.get(Severity.INFO, 0),
    }


def calculate_risk_score(findings: list[Finding]) -> float:
    if not findings:
        return 0.0

    weighted_sum = sum(SEVERITY_WEIGHT[item.severity] for item in findings)
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
