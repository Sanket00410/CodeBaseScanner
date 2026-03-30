from datetime import datetime, timezone

from codesentinelx_engine.models import Finding, Severity
from codesentinelx_engine.risk import calculate_risk_score, risk_rating, severity_distribution


def _finding(severity: Severity) -> Finding:
    return Finding(
        vulnerability_type="Test",
        severity=severity,
        file_path="sample.py",
        line_number=1,
        business_impact="Impact",
        recommendation="Fix",
        reference="https://example.com",
        owasp_category="A03",
        description="desc",
        rule_id="RULE-1",
    )


def test_severity_distribution() -> None:
    findings = [_finding(Severity.CRITICAL), _finding(Severity.HIGH), _finding(Severity.HIGH)]
    distribution = severity_distribution(findings)

    assert distribution["Critical"] == 1
    assert distribution["High"] == 2


def test_risk_score_and_rating() -> None:
    findings = [
        _finding(Severity.CRITICAL),
        _finding(Severity.HIGH),
        _finding(Severity.MEDIUM),
        _finding(Severity.LOW),
    ]
    score = calculate_risk_score(findings)

    assert score > 0
    assert risk_rating(score) in {"Low", "Medium", "High", "Critical"}

