from __future__ import annotations

from pathlib import Path

from universal_security_scanner.poc_verify import ValidationContext, verify_finding


def test_sql_injection_validator_confirms_dynamic_query(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "user_id = request.args.get('id')\n"
        "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
        encoding="utf-8",
    )

    result = verify_finding(
        ValidationContext(
            target_root=str(tmp_path),
            file_path="app.py",
            line_number=2,
            vulnerability_type="SQL Injection",
            rule_id="OWASP-A03-SQLI-001",
            cwe_id="CWE-89",
            evidence='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        )
    )

    assert result.status == "verified"
    assert result.family == "sql-injection"
    assert result.executed is True
    assert "dynamic SQL query construction" in result.verification_basis


def test_sql_injection_validator_does_not_confirm_frontend_template_literal(tmp_path: Path) -> None:
    component = tmp_path / "component.tsx"
    component.write_text(
        "const label = `${selectedLabel}`;\n"
        "return <div>{label}</div>;\n",
        encoding="utf-8",
    )

    result = verify_finding(
        ValidationContext(
            target_root=str(tmp_path),
            file_path="component.tsx",
            line_number=1,
            vulnerability_type="SQL Injection",
            rule_id="OWASP-A03-SQLI-001",
            cwe_id="CWE-89",
            evidence="const label = `${selectedLabel}`;",
        )
    )

    assert result.status != "verified"
    assert result.family == "sql-injection"
