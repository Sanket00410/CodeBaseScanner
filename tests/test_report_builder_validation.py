from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from codesentinelx_engine.models import Finding, ScanResult, Severity
from codesentinelx_engine.scanner.reporting import report_builder
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

