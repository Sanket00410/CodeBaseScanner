from __future__ import annotations

import pytest

from universal_security_scanner.config import ScannerConfig


@pytest.mark.parametrize(
    ("role", "expected_preset", "required_tool", "forbidden_tool"),
    [
        ("Admin", "deep", "codeql", None),
        ("Security Analyst", "standard", "gosec", "codeql"),
        ("Developer", "fast", "bandit", "codeql"),
        ("Auditor", "fast", "semgrep", "codeql"),
        ("Management", "fast", "gitleaks", "codeql"),
    ],
)
def test_role_defaults_drive_scan_preset(monkeypatch: pytest.MonkeyPatch, role: str, expected_preset: str, required_tool: str, forbidden_tool: str | None) -> None:
    monkeypatch.delenv("USS_SCAN_PRESET", raising=False)
    monkeypatch.delenv("USS_CODEBASE_TOOLS", raising=False)
    monkeypatch.delenv("USS_EXTERNAL_TOOLS", raising=False)

    config = ScannerConfig.from_env(role)

    assert config.scan_role == role
    assert config.scan_preset == expected_preset
    assert required_tool in config.codebase_external_tools
    if forbidden_tool:
        assert forbidden_tool not in config.codebase_external_tools
