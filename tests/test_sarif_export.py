from datetime import datetime, timezone

from codesentinelx_engine.models import Finding, ScanResult, Severity
from codesentinelx_engine.scanner.reporting.exporters import ReportExporter
from codesentinelx_engine.scanner.reporting.report_builder import build_report


def test_sarif_export(tmp_path) -> None:
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=11,
        business_impact="Data compromise",
        recommendation="Use parameterized query",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Unsafe SQL string building",
        rule_id="TEST-SQLI-1",
        cwe="CWE-89",
        evidence="cursor.execute(query + user_input)",
    )

    result = ScanResult(
        target_path="/tmp/project",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        files_scanned=1,
        findings=[finding],
    )

    report = build_report(result)
    exporter = ReportExporter(tmp_path)
    path = exporter.export(report, "sarif", tmp_path / "report.sarif")

    data = path.read_text(encoding="utf-8")
    assert "TEST-SQLI-1" in data
    assert "version" in data

