from __future__ import annotations

import pytest

from codesentinelx_engine.config import ScannerConfig


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

