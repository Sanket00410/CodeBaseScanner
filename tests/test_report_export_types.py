from datetime import datetime, timezone

import pytest

from codesentinelx_engine.models import Finding, ScanResult, SecurityControl, Severity
from codesentinelx_engine.scanner.reporting.exporters import ReportExporter
from codesentinelx_engine.scanner.reporting.report_builder import build_report


def _sample_report():
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="src/auth.py",
        line_number=21,
        business_impact="Data exposure",
        recommendation="Use parameterized queries",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Unsafe SQL concatenation",
        rule_id="TEST-SQL-1",
        cwe="CWE-89",
        evidence='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    )
    control = SecurityControl(
        control_id="CTRL-VALIDATION",
        name="Input Validation Implemented",
        category="Application Input Security",
        description="Validation layer detected",
        status="Implemented",
        coverage_level="Medium",
        standard_mappings=["OWASP ASVS V5"],
    )
    scan_result = ScanResult(
        target_path="C:/repo",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        files_scanned=5,
        findings=[finding],
        existing_security_measures=[control],
    )
    return build_report(scan_result)


def test_export_json_existing_report_type(tmp_path) -> None:
    report = _sample_report()
    exporter = ReportExporter(tmp_path)

    path = exporter.export(report, "json", tmp_path / "existing.json", report_type="existing")
    content = path.read_text(encoding="utf-8")

    assert "existing_implementation_report" in content
    assert "vulnerability_fixed_code_report" not in content


def test_export_json_vulnerability_report_type(tmp_path) -> None:
    report = _sample_report()
    exporter = ReportExporter(tmp_path)

    path = exporter.export(report, "json", tmp_path / "vulnerability.json", report_type="vulnerability")
    content = path.read_text(encoding="utf-8")

    assert "vulnerability_fixed_code_report" in content
    assert "existing_implementation_report" not in content


def test_export_existing_sarif_rejected(tmp_path) -> None:
    report = _sample_report()
    exporter = ReportExporter(tmp_path)
    with pytest.raises(ValueError):
        exporter.export(report, "sarif", tmp_path / "bad.sarif", report_type="existing")

