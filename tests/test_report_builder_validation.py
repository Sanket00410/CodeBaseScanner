from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from codesentinelx_engine.models import Finding, ScanResult, Severity
from codesentinelx_engine.scanner.reporting import report_builder
from codesentinelx_engine.scanner.reporting.exporters import ReportExporter
from codesentinelx_engine.scanner.reporting.report_builder import build_report
from codesentinelx_engine.scanner.role_scope import scope_findings_for_role


def test_report_builder_populates_active_poc_and_fix_verification(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=2,
        business_impact="Database compromise",
        recommendation="Use parameterized queries / prepared statements and strict input validation.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
        rule_id="OWASP-A03-SQLI-001",
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
    assert enriched["active_poc"]["status"] == "verified"
    assert enriched["fix_verification"]["performed"] is True
    assert report["vulnerability_fixed_code_report"]["summary"]["active_poc"]["verified"] == 1
    assert report["role_aware_report"]["advanced_features"]["ai_solution_engine"]["status"] == "ready"

    exporter = ReportExporter(tmp_path)
    html_path = exporter.export_html(report, tmp_path / "fixes.html", "fixes")
    html = html_path.read_text(encoding="utf-8")
    assert "Execution Overview" in html
    assert "execution-results-full" in html
    assert "Example Fix Pattern" in html


def test_report_builder_enriches_findings_with_confidence_cvss_and_poc_details(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=2,
        business_impact="Database compromise",
        recommendation="Use parameterized queries / prepared statements and strict input validation.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
        rule_id="OWASP-A03-SQLI-001",
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
    assert enriched["confidence"] == "High"
    assert enriched["cvss_score"] == 9.8
    assert enriched["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N"
    assert enriched["cwe_id"] == "CWE-89"
    assert enriched["poc_details"]["affected_endpoint"].endswith("app.py:2")
    assert "OR 1=1" in enriched["poc_details"]["attack_example"]
    assert enriched["poc_details"]["risk"]
    assert enriched["real_code_evidence"]["code_snippet"].startswith("cursor.execute")
    assert enriched["real_code_evidence"]["fix_snippet"]
    assert enriched["occurrence_count"] == 1
    assert enriched["affected_locations"] == ["app.py:2"]

    html_output = ReportExporter(tmp_path).export_html(report, tmp_path / "report.html", "fixes")
    html = html_output.read_text(encoding="utf-8")
    assert "Confidence" in html
    assert "CVSS" in html
    assert "Affected Endpoint" in html


def test_report_builder_uses_provider_backed_ai_when_configured(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("USS_AI_REMEDIATION_PROVIDER", "ollama")
    monkeypatch.setenv("USS_AI_OLLAMA_MODEL", "unit-test-model")
    monkeypatch.setattr(
        report_builder,
        "generate_grounded_remediation",
        lambda finding, target_root, config: {
            "remediation_summary": "Provider-backed remediation summary.",
            "suggested_fix": "cursor.execute(query, params)",
            "validation_steps": "1. Apply fix\n2. Re-run validation",
            "fix_confidence_score": 0.91,
            "fix_confidence_label": "High",
            "grounding_notes": "Grounded on source-to-sink flow.",
            "manual_review_required": False,
        },
    )
    monkeypatch.setattr(
        report_builder,
        "generate_prioritization_plan",
        lambda findings, config: {
            "8_hours": [
                {
                    "finding_uid": findings[0]["finding_uid"],
                    "why_first": "Touches a verified database sink in a hot code path.",
                    "priority_score": 96.0,
                    "fix_confidence_score": 0.91,
                }
            ]
        },
    )

    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=2,
        business_impact="Database compromise",
        recommendation="Use parameterized queries / prepared statements and strict input validation.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
        rule_id="OWASP-A03-SQLI-001",
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
    engine = report["role_aware_report"]["advanced_features"]["ai_solution_engine"]
    plan = report["role_aware_report"]["advanced_features"]["what_should_i_fix_first_ai"]
    assert engine["provider"] == "ollama"
    assert engine["model"] == "unit-test-model"
    assert engine["status"] == "ready"
    assert enriched["ai_fix_source"] == "ollama:unit-test-model"
    assert enriched["ai_remediation_summary"] == "Provider-backed remediation summary."
    assert enriched["ai_fix_confidence_label"] == "High"
    assert plan["8_hours"][0]["why_first"] == "Touches a verified database sink in a hot code path."


def test_report_builder_adds_plain_language_brief_for_weak_crypto(tmp_path: Path) -> None:
    (tmp_path / "crypto.js").write_text(
        "const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="Weak Cryptography Usage",
        severity=Severity.HIGH,
        file_path="crypto.js",
        line_number=1,
        business_impact="Legacy cipher exposure",
        recommendation="Use AES-GCM and rotate the legacy secret material.",
        reference="https://cwe.mitre.org/data/definitions/327.html",
        owasp_category="A02:2021 - Cryptographic Failures",
        description="The application uses a legacy 3DES cipher.",
        rule_id="CODEQL-JS-WEAK-CRYPTO",
        cwe="CWE-327",
        evidence="const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);",
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
    brief = enriched["plain_language_security_brief"]
    assert brief["title"] == "Weak Cryptography Usage"
    assert "3DES" in brief["what_is_happening"] or "legacy" in brief["what_is_happening"].lower()
    assert "AES-GCM" in brief["what_to_use_instead"]


def test_report_builder_adds_tailored_brief_for_broken_access_control(tmp_path: Path) -> None:
    (tmp_path / "admin_service.py").write_text(
        "if current_user.id == request.args.get('user_id'):\n    return load_profile()\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="Broken Object Property Level Authorization (BOPLA)",
        severity=Severity.HIGH,
        file_path="admin_service.py",
        line_number=1,
        business_impact="User data exposure",
        recommendation="Perform server-side object-level authorization checks for every access path.",
        reference="https://owasp.org/Top10/A01_2021-Broken-Access-Control/",
        owasp_category="A01:2021 - Broken Access Control",
        description="Object-level access control relies on attacker-controlled request input.",
        rule_id="CODEQL-PY-BROKEN-ACCESS-CTRL",
        cwe="CWE-862",
        evidence="current_user.id == request.args.get('user_id')",
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
    brief = enriched["plain_language_security_brief"]
    assert brief["title"] == "Broken Access Control"
    assert "object-level authorization" in brief["what_to_use_instead"].lower()
    assert "ownership" in brief["why_it_is_weak"].lower()


def test_fix_verification_can_run_optional_workspace_commands(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app.py").write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("USS_FIX_VERIFY_BUILD_COMMAND", "python -c \"print('build ok')\"")
    monkeypatch.setenv("USS_FIX_VERIFY_TEST_COMMAND", "python -c \"print('test ok')\"")

    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=2,
        business_impact="Database compromise",
        recommendation="Use parameterized queries / prepared statements and strict input validation.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
        rule_id="OWASP-A03-SQLI-001",
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
    assert enriched["fix_verification"]["performed"] is True
    assert enriched["fix_verification"]["build_verification"]["status"] == "success"
    assert enriched["fix_verification"]["test_verification"]["status"] == "success"


def test_dependency_reachability_includes_manifest_lockfile_and_advisory_data(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"^4.17.15"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"name":"demo","lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.15"}},"node_modules/lodash":{"version":"4.17.15","name":"lodash"}}}',
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text(
        "const lodash = require('lodash');\nconsole.log(lodash.VERSION);\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="Dependency Vulnerability",
        severity=Severity.HIGH,
        file_path="package-lock.json",
        line_number=1,
        business_impact="Supply-chain risk",
        recommendation="Upgrade lodash to a fixed version.",
        reference="https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
        description="Lodash vulnerable advisory.",
        rule_id="TRIVY-VULN-GHSA-35JH-R3H4-6JHM",
        cwe="CWE-1104",
        evidence="lodash:4.17.15",
    )
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=3,
            findings=[finding],
            errors=[],
            existing_security_measures=[],
            toolchain_status={},
        )
    )

    enriched = report["vulnerability_fixed_code_report"]["findings"][0]
    reachability = enriched["dependency_reachability"]
    assert reachability["status"] == "reachable_in_code"
    assert reachability["manifest_present"] is True
    assert reachability["lockfile_present"] is True
    assert "package.json" in reachability["manifest_paths"][0]
    assert "package-lock.json" in reachability["lockfile_paths"][0]
    assert reachability["advisory_verified"] is True


def test_enterprise_assurance_keeps_semgrep_parse_noise_out_of_blockers(tmp_path: Path) -> None:
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=0,
            findings=[],
            errors=[],
            existing_security_measures=[],
            toolchain_status={
                "semgrep": {
                    "selected": True,
                    "available": True,
                    "runner_available": True,
                    "execution": {
                        "attempted": True,
                        "status": "failed",
                        "duration_ms": 120,
                        "findings_count": 0,
                        "errors": ["Semgrep produced non-JSON output."],
                        "evidence": [],
                    },
                }
            },
        )
    )

    enterprise = report["executive_summary"]["enterprise_assurance"]
    assert enterprise["status"] == "warning"
    assert enterprise["blockers"] == []
    assert any("semgrep" in advisory.lower() for advisory in enterprise["advisories"])


def test_report_builder_annotates_stable_alert_grouping_and_preserves_it_for_audit_scope(tmp_path: Path) -> None:
    findings = [
        Finding(
            vulnerability_type="SQL Injection",
            severity=Severity.CRITICAL,
            file_path="src/app.py",
            line_number=10,
            business_impact="Database compromise",
            recommendation="Use parameterized queries",
            reference="https://owasp.org/Top10/A03_2021-Injection/",
            owasp_category="A03:2021 - Injection",
            description="Unsafe SQL concatenation",
            rule_id="TEST-SQL-1",
            cwe="CWE-89",
            evidence='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        ),
        Finding(
            vulnerability_type="SQL Injection",
            severity=Severity.HIGH,
            file_path="src/service.py",
            line_number=44,
            business_impact="Query manipulation",
            recommendation="Use parameterized queries",
            reference="https://owasp.org/Top10/A03_2021-Injection/",
            owasp_category="A03:2021 - Injection",
            description="Unsafe SQL concatenation",
            rule_id="TEST-SQL-2",
            cwe="CWE-89",
            evidence='db.query("SELECT * FROM orders WHERE id = " + order_id)',
        ),
    ]
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=2,
            findings=findings,
            errors=[],
            existing_security_measures=[],
            toolchain_status={},
        )
    )

    scoped = report["vulnerability_fixed_code_report"]["findings"]
    assert len(scoped) == 2
    group_uids = {item["alert_group_uid"] for item in scoped}
    title_group_uids = {item["alert_title_group_uid"] for item in scoped}
    assert len(group_uids) == 1
    assert len(title_group_uids) == 1
    assert scoped[0]["alert_group_instance_count"] == 2
    assert scoped[0]["alert_title_group_instance_count"] == 2

    audit_scope = scope_findings_for_role(scoped, "Auditor")
    assert audit_scope
    assert audit_scope[0]["alert_group_uid"] == scoped[0]["alert_group_uid"]
    assert audit_scope[0]["alert_title_group_uid"] == scoped[0]["alert_title_group_uid"]


def test_role_scoped_findings_preserve_canonical_severity_for_non_management_roles(tmp_path: Path) -> None:
    findings = [
        Finding(
            vulnerability_type="Cross-Site Scripting",
            severity=Severity.LOW,
            file_path="ui.js",
            line_number=8,
            business_impact="UI trust boundary exposure",
            recommendation="Escape output",
            reference="https://owasp.org/",
            owasp_category="A03:2021 - Injection",
            description="Untrusted data reaches render sink",
            rule_id="TEST-XSS-LOW",
            cwe="CWE-79",
            evidence="element.innerHTML = input",
        ),
        Finding(
            vulnerability_type="SQL Injection",
            severity=Severity.CRITICAL,
            file_path="api.py",
            line_number=19,
            business_impact="Database compromise",
            recommendation="Use parameterized queries",
            reference="https://owasp.org/",
            owasp_category="A03:2021 - Injection",
            description="Unsafe SQL concatenation",
            rule_id="TEST-SQL-CRIT",
            cwe="CWE-89",
            evidence='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        ),
    ]
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=2,
            findings=findings,
            errors=[],
            existing_security_measures=[],
            toolchain_status={},
        )
    )

    scoped = report["vulnerability_fixed_code_report"]["findings"]
    for role in ["Admin", "Security Analyst", "Developer", "Auditor"]:
        scoped_role = scope_findings_for_role(scoped, role)
        assert [item["severity"] for item in scoped_role] == [item["severity"] for item in scoped]

    management_scope = scope_findings_for_role(scoped, "Management")
    assert management_scope == []


def test_management_report_strips_quality_benchmark_noise(tmp_path: Path) -> None:
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=0,
            findings=[],
            errors=[],
            existing_security_measures=[],
            toolchain_status={},
            quality_benchmark={
                "configured": True,
                "cases_total": 3,
                "benchmark_name": "CodeSentinelX quality benchmark",
                "benchmark_status": "warning",
                "precision_percent": 0.0,
                "recall_percent": 0.0,
                "f1_percent": 0.0,
            },
            scan_role="Management",
        )
    )

    executive = report["executive_summary"]
    assert "data_quality" not in executive
    assert "enterprise_assurance" in executive
    assert "quality_benchmark" not in executive["enterprise_assurance"]


def test_fix_report_queue_rows_link_to_detail_cards(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )
    finding = Finding(
        vulnerability_type="SQL Injection",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=2,
        business_impact="Database compromise",
        recommendation="Use parameterized queries / prepared statements and strict input validation.",
        reference="https://owasp.org/Top10/A03_2021-Injection/",
        owasp_category="A03:2021 - Injection",
        description="Dynamic SQL query construction can allow attacker-controlled query manipulation.",
        rule_id="OWASP-A03-SQLI-001",
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

    html_output = ReportExporter(tmp_path)._render_fixes_html(report)

    assert "<th>Details</th>" in html_output
    assert "fix-card-1" in html_output
    assert "href='#fix-card-1'" in html_output

