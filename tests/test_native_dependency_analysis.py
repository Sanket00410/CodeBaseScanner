from datetime import datetime, timezone
from pathlib import Path

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.models import ScanResult
from codesentinelx_engine.scanner.engine import ScanEngine
from codesentinelx_engine.scanner.native_dependency_analysis import NativeDependencyScanner
from codesentinelx_engine.scanner.reporting.report_builder import build_report


def test_native_dependency_scanner_flags_missing_lockfile_and_unpinned_npm(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"^4.17.21"}}',
        encoding="utf-8",
    )
    findings = NativeDependencyScanner(ScannerConfig()).scan_project(tmp_path)
    rule_ids = {item.rule_id for item in findings}
    assert "NATIVE-DEP-NPM-LOCK-001" in rule_ids
    assert "NATIVE-DEP-NPM-PIN-001" in rule_ids


def test_native_dependency_scanner_flags_external_python_dependency(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "private-lib @ git+https://github.com/example/private-lib.git\n",
        encoding="utf-8",
    )
    findings = NativeDependencyScanner(ScannerConfig()).scan_project(tmp_path)
    assert any(item.rule_id == "NATIVE-DEP-PY-SOURCE-001" for item in findings)


def test_engine_adds_native_dependency_findings(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"^4.17.21"}}',
        encoding="utf-8",
    )
    result = ScanEngine(
        ScannerConfig(
            use_external_tools=False,
            use_native_code_analysis=False,
            use_native_dependency_analysis=True,
            native_dependency_ecosystems=["npm"],
        )
    ).scan(tmp_path)
    assert any(item.rule_id == "NATIVE-DEP-NPM-LOCK-001" for item in result.findings)


def test_report_builder_enriches_native_dependency_findings_with_reachability(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"^4.17.21"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        '{"name":"demo","lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.21"}},"node_modules/lodash":{"version":"4.17.21","name":"lodash"}}}',
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text(
        "const lodash = require('lodash');\nconsole.log(lodash.VERSION);\n",
        encoding="utf-8",
    )
    findings = NativeDependencyScanner(ScannerConfig()).scan_project(tmp_path)
    target = next(item for item in findings if item.rule_id == "NATIVE-DEP-NPM-PIN-001")
    report = build_report(
        ScanResult(
            target_path=str(tmp_path),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            files_scanned=3,
            findings=[target],
            errors=[],
            existing_security_measures=[],
            toolchain_status={},
        )
    )
    enriched = report["vulnerability_fixed_code_report"]["findings"][0]
    assert enriched["dependency_name"] == "lodash"
    assert enriched["dependency_reachability"]["status"] == "reachable_in_code"

