from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from universal_security_scanner.models import Finding, ScanResult, Severity
from universal_security_scanner.scanner.quality_benchmark import evaluate_quality_benchmark
from universal_security_scanner.scanner.reporting.report_builder import build_report


def _sample_benchmark_payload() -> dict:
    return {
        "benchmark_name": "Local Scanner Quality Benchmark",
        "benchmark_description": "Truth-set used to measure precision and recall for report quality gates.",
        "cases": [
            {
                "case_id": "sqli-present",
                "expected_present": True,
                "file_path": "src/app/auth.py",
                "rule_id": "USS-SQLI",
                "title": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03: Injection",
                "severity": "Critical",
                "line_number": 42,
            },
            {
                "case_id": "xss-absent",
                "expected_present": False,
                "file_path": "src/app/views.py",
                "rule_id": "USS-XSS",
                "title": "Cross-Site Scripting (XSS)",
                "cwe": "CWE-79",
                "owasp": "A03: Injection",
                "severity": "High",
                "line_number": 11,
            },
        ],
    }


def test_quality_benchmark_metrics_and_gate_status(tmp_path: Path) -> None:
    benchmark_file = tmp_path / "benchmark_truth_set.json"
    benchmark_file.write_text(json.dumps(_sample_benchmark_payload()), encoding="utf-8")

    findings = [
        {
            "finding_id": "finding-sqli",
            "file_path": "src/app/auth.py",
            "rule_id": "USS-SQLI",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "owasp": "A03: Injection",
            "severity": "Critical",
            "line_number": 42,
        },
        {
            "finding_id": "finding-xss",
            "file_path": "src/app/views.py",
            "rule_id": "USS-XSS",
            "title": "Cross-Site Scripting (XSS)",
            "cwe": "CWE-79",
            "owasp": "A03: Injection",
            "severity": "High",
            "line_number": 11,
        },
    ]

    benchmark = evaluate_quality_benchmark(
        findings,
        benchmark_file,
        min_precision=90.0,
        min_recall=85.0,
        min_f1=88.0,
        strict_scope=True,
    )

    assert benchmark["configured"] is True
    assert benchmark["benchmark_status"] == "blocked"
    assert benchmark["cases_total"] == 2
    assert benchmark["expected_present"] == 1
    assert benchmark["expected_absent"] == 1
    assert benchmark["true_positives"] == 1
    assert benchmark["false_positives"] == 1
    assert benchmark["false_negatives"] == 0
    assert benchmark["precision_percent"] < 90.0
    assert benchmark["recall_percent"] == 100.0
    assert benchmark["gate_blockers"]


def test_quality_benchmark_disabled_and_missing_file(tmp_path: Path) -> None:
    findings: list[dict] = []
    missing = tmp_path / "does-not-exist.json"

    disabled = evaluate_quality_benchmark(findings, missing, enabled=False)
    assert disabled["benchmark_status"] == "disabled"
    assert disabled["gate_advisories"]

    not_configured = evaluate_quality_benchmark(findings, missing, enabled=True)
    assert not_configured["benchmark_status"] == "not_configured"
    assert not_configured["gate_advisories"]


def test_build_report_surfaces_quality_benchmark(tmp_path: Path) -> None:
    target_dir = tmp_path / "sample-project"
    target_dir.mkdir()
    source_file = target_dir / "src" / "app" / "auth.py"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text("def auth(user):\n    return user\n", encoding="utf-8")

    benchmark_file = tmp_path / "benchmark_truth_set.json"
    benchmark_file.write_text(json.dumps(_sample_benchmark_payload()), encoding="utf-8")
    benchmark = evaluate_quality_benchmark(
        [
            {
                "finding_id": "finding-sqli",
                "file_path": "src/app/auth.py",
                "rule_id": "USS-SQLI",
                "title": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03: Injection",
                "severity": "Critical",
                "line_number": 42,
            }
        ],
        benchmark_file,
        min_precision=90.0,
        min_recall=85.0,
        min_f1=88.0,
        strict_scope=True,
    )

    scan_result = ScanResult(
        target_path=str(target_dir),
        started_at=datetime(2026, 3, 25, 0, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 3, 25, 0, 5, 0, tzinfo=timezone.utc),
        files_scanned=1,
        findings=[
            Finding(
                vulnerability_type="SQL Injection",
                severity=Severity.CRITICAL,
                file_path=str(source_file),
                line_number=1,
                business_impact="Potential SQL injection path",
                recommendation="Use parameterized queries.",
                reference="https://example.test",
                owasp_category="A03: Injection",
                description="User input reaches a database sink.",
                rule_id="USS-SQLI",
                cwe="CWE-89",
                evidence="x = user_input",
                origin="native_code",
            )
        ],
        quality_benchmark=benchmark,
    )

    report = build_report(scan_result)
    data_quality = report["executive_summary"]["data_quality"]
    enterprise = report["executive_summary"]["enterprise_assurance"]

    assert data_quality["quality_benchmark"]["benchmark_status"] == benchmark["benchmark_status"]
    assert data_quality["quality_benchmark"]["precision_percent"] == benchmark["precision_percent"]
    assert enterprise["quality_benchmark"]["benchmark_name"] == benchmark["benchmark_name"]
