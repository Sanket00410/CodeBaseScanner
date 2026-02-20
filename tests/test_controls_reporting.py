from datetime import datetime, timezone

from universal_security_scanner.models import Finding, ScanResult, SecurityControl, Severity
from universal_security_scanner.scanner.controls.analyzer import ExistingSecurityMeasuresAnalyzer
from universal_security_scanner.scanner.reporting.report_builder import build_report


def test_controls_analyzer_detects_existing_controls() -> None:
    analyzer = ExistingSecurityMeasuresAnalyzer()
    analyzer.observe_file(
        file_path="app.py",
        content="""
from pydantic import BaseModel
import bcrypt

class LoginRequest(BaseModel):
    username: str
    password: str
""",
    )

    controls = analyzer.finalize(total_files=3)
    names = {item.name for item in controls}

    assert "Input Validation Implemented" in names
    assert "Password Hardening" in names


def test_report_has_distinct_sections() -> None:
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="src/repo.py",
        line_number=44,
        business_impact="Sensitive data compromise",
        recommendation="Use parameterized query",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Unsafe query concatenation",
        rule_id="RULE-SQL-1",
        cwe="CWE-89",
        evidence="query = 'SELECT * FROM users WHERE id=' + user_id",
    )

    control = SecurityControl(
        control_id="CTRL-AUTHN",
        name="Authentication Controls Present",
        category="Identity and Access",
        description="JWT verification code present",
        status="Implemented",
        coverage_level="Medium",
        standard_mappings=["OWASP ASVS V2"],
        evidence=[{"file_path": "auth.py", "line_number": 10, "snippet": "jwt.verify(token, key)"}],
    )

    scan = ScanResult(
        target_path="C:/repo",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        files_scanned=10,
        findings=[finding],
        existing_security_measures=[control],
        toolchain_status={
            "semgrep": {
                "name": "semgrep",
                "available": True,
                "command": "semgrep",
                "source": "system",
                "message": "Tool found in PATH",
            }
        },
    )

    report = build_report(scan)

    assert "existing_implementation_report" in report
    assert "vulnerability_fixed_code_report" in report
    assert "existing_security_measures" in report
    assert "vulnerability_findings" in report
    assert "auto_fix_recommendations" in report
    assert report["existing_security_measures"]["summary"]["implemented_controls"] == 1
    assert report["existing_implementation_report"]["summary"]["implemented_controls"] == 1
    assert report["vulnerability_fixed_code_report"]["summary"]["total_findings"] == 1
    assert len(report["auto_fix_recommendations"]) >= 1
    assert "fixed_code" in report["vulnerability_fixed_code_report"]["findings"][0]
    assert "patch_preview" in report["vulnerability_fixed_code_report"]["findings"][0]
    assert report["vulnerability_findings"]["toolchain_status"].get("semgrep") is not None
    assert report["vulnerability_fixed_code_report"]["findings"][0]["owasp_mapping"].startswith("A03:2025")
    assert report["executive_summary"]["scan_profile"] == "codebase"
    assert report["existing_implementation_report"]["profile_compliance"]["scan_profile"] == "codebase"
    assert "owasp_top_10_2025" in report["existing_implementation_report"]["profile_compliance"]["applicable_framework_ids"]
