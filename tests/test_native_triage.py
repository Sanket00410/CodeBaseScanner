from datetime import datetime, timezone
from pathlib import Path

from codesentinelx_engine.models import Finding, ScanResult, Severity
from codesentinelx_engine.scanner.native_triage import annotate_findings
from codesentinelx_engine.scanner.reporting.report_builder import build_report


def test_native_triage_scores_verified_flow_finding_high_confidence() -> None:
    findings, summary = annotate_findings(
        [
            {
                "rule_id": "PY-A03-SQLI-FLOW-001",
                "vulnerability_title": "SQL Injection",
                "severity": "Critical",
                "file_path": "app.py",
                "line_number": 10,
                "cwe_id": "CWE-89",
                "owasp_mapping": "A03:2021 - Injection",
                "vulnerable_code_snippet": "cursor.execute(query)",
                "active_poc": {"status": "verified", "confidence": 0.94},
                "dependency_reachability": {},
                "evidence_sources": ["PY-A03-SQLI-FLOW-001"],
                "evidence_origins": ["native_code", "external_tool"],
                "origin": "native_code",
            }
        ]
    )
    assert findings[0]["rule_confidence_label"] == "High"
    assert findings[0]["suppression_candidate"] is False
    assert findings[0]["finding_origin"] == "native_code"
    assert findings[0]["corroborated"] is True
    assert findings[0]["corroboration_count"] == 2
    assert summary["average_rule_confidence_label"] == "High"


def test_native_triage_marks_test_artifact_for_suppression_review() -> None:
    findings, summary = annotate_findings(
        [
            {
                "rule_id": "JS-A03-XSS-001",
                "vulnerability_title": "Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "file_path": "tests/fixtures/bad.js",
                "line_number": 4,
                "cwe_id": "CWE-79",
                "owasp_mapping": "A03:2021 - Injection",
                "vulnerable_code_snippet": "el.innerHTML = userHtml",
                "active_poc": {"status": "inconclusive", "confidence": 0.41},
                "dependency_reachability": {},
                "evidence_sources": ["JS-A03-XSS-001"],
            }
        ]
    )
    assert findings[0]["suppression_candidate"] is True
    assert "test-artifact" in findings[0]["suppression_tags"]
    assert findings[0]["suppression_owner"] == summary["default_owner"]
    assert findings[0]["triage_owner"] == summary["default_owner"]
    assert bool(findings[0]["suppression_review_by"]) is True
    assert findings[0]["suppression_requires_expiry"] is True
    assert summary["candidate_count"] == 1
    assert summary["expiry_required_count"] == 1


def test_native_triage_assigns_default_triage_owner_for_all_findings() -> None:
    findings, summary = annotate_findings(
        [
            {
                "rule_id": "PY-A01-INP-001",
                "vulnerability_title": "Input Validation",
                "severity": "Low",
                "file_path": "app.py",
                "line_number": 1,
                "cwe_id": "CWE-20",
                "owasp_mapping": "A01:2021 - Broken Access Control",
                "vulnerable_code_snippet": "value = request.args.get('id')",
                "active_poc": {"status": "not_applicable", "confidence": 0.2},
                "dependency_reachability": {},
                "evidence_sources": ["PY-A01-INP-001"],
            }
        ]
    )
    assert findings[0]["triage_owner"] == summary["default_owner"]
    assert findings[0]["suppression_owner"] == ""


def test_build_report_populates_rule_confidence_and_suppression_lifecycle(tmp_path: Path) -> None:
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "fixture.py").write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="service/fixture.py",
        line_number=2,
        business_impact="Database compromise",
        recommendation="Use parameterized queries.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
        rule_id="PY-A03-SQLI-FLOW-001",
        cwe="CWE-89",
        evidence='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    )
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=1,
            findings=[finding],
            errors=[],
            existing_security_measures=[],
            toolchain_status={},
        )
    )
    enriched = report["vulnerability_fixed_code_report"]["findings"][0]
    lifecycle = report["vulnerability_fixed_code_report"]["summary"]["suppression_lifecycle"]
    assert isinstance(enriched["rule_confidence"], float)
    assert enriched["rule_confidence_label"] in {"High", "Medium", "Low"}
    assert enriched["finding_origin"] == "native_code"
    assert "average_rule_confidence" in lifecycle
    assert "finding_origins" in lifecycle
    assert report["executive_summary"]["assessment_confidence"] in {"High", "Medium", "Low"}

