from __future__ import annotations

from pathlib import Path

import pytest

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.scanner.engine import ScanEngine
from codesentinelx_engine.scanner.reporting.report_builder import build_report
from codesentinelx_engine.scanner.role_scope import resolve_role_scope, scope_report_for_role


@pytest.mark.parametrize(
    ("role", "expected_preset", "required_tool", "forbidden_tool", "project_rules"),
    [
        ("Admin", "deep", "codeql", None, True),
        ("Security Analyst", "standard", "gosec", "codeql", True),
        ("Developer", "fast", "bandit", "codeql", False),
        ("Auditor", "fast", "semgrep", "codeql", False),
        ("Management", "fast", "gitleaks", "codeql", False),
    ],
)
def test_role_defaults_drive_scan_preset(monkeypatch: pytest.MonkeyPatch, role: str, expected_preset: str, required_tool: str, forbidden_tool: str | None, project_rules: bool) -> None:
    monkeypatch.delenv("USS_SCAN_PRESET", raising=False)
    monkeypatch.delenv("USS_CODEBASE_TOOLS", raising=False)
    monkeypatch.delenv("USS_EXTERNAL_TOOLS", raising=False)

    config = ScannerConfig.from_env(role)

    assert config.scan_role == role
    assert config.scan_preset == expected_preset
    assert config.use_project_rules is project_rules
    assert required_tool in config.codebase_external_tools
    if forbidden_tool:
        assert forbidden_tool not in config.codebase_external_tools


@pytest.mark.parametrize("role", ["Admin", "Security Analyst", "Developer", "Auditor", "Management"])
def test_role_defaults_exclude_removed_noise_tools(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    monkeypatch.delenv("USS_SCAN_PRESET", raising=False)
    monkeypatch.delenv("USS_CODEBASE_TOOLS", raising=False)
    monkeypatch.delenv("USS_EXTERNAL_TOOLS", raising=False)

    config = ScannerConfig.from_env(role)
    removed_tools = {
        "pip-audit",
        "npm-audit",
        "safety",
        "owasp-dependency-check",
        "snyk",
        "findsecbugs",
        "spotbugs",
        "cppcheck",
        "flawfinder",
        "trivy",
        "sonarqube",
    }

    assert not removed_tools.intersection({tool.lower() for tool in config.codebase_external_tools})


def test_management_role_scans_as_summary_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "app.py").write_text(
        "def handler(user_input):\n"
        "    return eval(user_input)\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("USS_SCAN_PRESET", raising=False)
    monkeypatch.delenv("USS_CODEBASE_TOOLS", raising=False)
    monkeypatch.delenv("USS_EXTERNAL_TOOLS", raising=False)

    scope = resolve_role_scope("Management")
    assert scope.run_external_tools
    assert scope.run_file_findings
    assert not scope.run_project_rules
    assert scope.run_native_code_analysis
    assert scope.run_native_dependency_analysis

    engine = ScanEngine(ScannerConfig.from_env("Management"))
    result = engine.scan(tmp_path)
    report = build_report(result)
    scoped_report = scope_report_for_role(report, "Management")

    assert result.scan_role == "Management"
    assert result.findings
    assert report["executive_summary"]["deduplicated_vulnerabilities"] > 0
    assert scoped_report["vulnerability_fixed_code_report"]["findings"] == []

