from pathlib import Path

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.scanner.engine import ScanEngine
from codesentinelx_engine.scanner.native_analysis import NativeCodeScanner


def test_native_code_scanner_detects_python_flow_issue() -> None:
    scanner = NativeCodeScanner(ScannerConfig())
    findings = scanner.scan_file(
        Path("service.py"),
        "user_id = request.args.get('id')\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)\n",
    )
    assert any(item.rule_id == "PY-A03-SQLI-FLOW-001" for item in findings)


def test_native_code_scanner_detects_javascript_flow_issue() -> None:
    scanner = NativeCodeScanner(ScannerConfig())
    findings = scanner.scan_file(
        Path("index.js"),
        "const payload = req.body;\nObject.assign({}, payload);\n",
    )
    assert any(item.rule_id == "JS-A08-POLLUTION-FLOW-001" for item in findings)


def test_engine_adds_native_findings_without_duplicate_flow_rows(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text(
        "user_id = request.args.get('id')\n"
        "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "cursor.execute(query)\n",
        encoding="utf-8",
    )

    config = ScannerConfig(
        use_external_tools=False,
        use_native_code_analysis=True,
        native_analysis_languages=["python"],
        native_analysis_families=["sql-injection"],
    )
    result = ScanEngine(config).scan(tmp_path)
    sqli_rows = [item for item in result.findings if item.rule_id == "PY-A03-SQLI-FLOW-001"]
    assert len(sqli_rows) == 1

