from pathlib import Path

import pytest

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.models import Severity
from codesentinelx_engine.scanner.external import codeql_adapter
from codesentinelx_engine.scanner.external import semgrep_adapter
from codesentinelx_engine.scanner.external import osv_scanner_adapter
from codesentinelx_engine.scanner.external.gitleaks_adapter import parse_gitleaks_output
from codesentinelx_engine.scanner.external.registry import external_tool_names
from codesentinelx_engine.scanner.external.semgrep_adapter import parse_semgrep_output
from codesentinelx_engine.scanner.external.trivy_adapter import parse_trivy_output


def test_external_tool_names_deduplicates_and_respects_switch() -> None:
    config = ScannerConfig(use_external_tools=True, codebase_external_tools=["Semgrep", "trivy", "semgrep", "gitleaks"])
    assert external_tool_names(config, target_mode="codebase") == ["semgrep", "trivy", "gitleaks"]

    disabled = ScannerConfig(use_external_tools=False)
    assert external_tool_names(disabled) == []


def test_parse_semgrep_output() -> None:
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.exec",
                "path": "src/app.py",
                "start": {"line": 22},
                "extra": {
                    "severity": "ERROR",
                    "message": "Detected use of exec().",
                    "lines": "exec(user_input)",
                    "metadata": {
                        "category": "Unsafe eval usage",
                        "impact": "May execute attacker input",
                        "fix": "Avoid exec and use strict dispatch",
                        "references": ["https://semgrep.dev/r/python.lang.security.audit.exec"],
                        "cwe": ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"],
                        "owasp": ["A03:2021 - Injection"],
                    },
                },
            }
        ]
    }

    findings = parse_semgrep_output(payload, Path("C:/repo"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].cwe == "CWE-95"
    assert findings[0].vulnerability_type == "Unsafe eval usage"


def test_semgrep_scan_uses_semgrep_executable(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run_command(command, timeout_seconds, cwd=None, env_overrides=None):  # type: ignore[no-untyped-def]
        captured["command"] = list(command)
        return 0, '{"results":[]}', ""

    monkeypatch.setattr(semgrep_adapter, "run_command", fake_run_command)

    findings, errors = semgrep_adapter.run_semgrep_scan(Path("C:/repo"), 30, binary="semgrep")

    assert findings == []
    assert errors == []
    assert captured["command"][0] == "semgrep"
    assert "-m" not in captured["command"]
    assert "semgrep.__main__" not in captured["command"]


def test_semgrep_scan_includes_local_config_when_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run_command(command, timeout_seconds, cwd=None, env_overrides=None):  # type: ignore[no-untyped-def]
        captured["command"] = list(command)
        return 0, '{"results":[]}', ""

    monkeypatch.setattr(semgrep_adapter, "run_command", fake_run_command)

    target_root = tmp_path / "repo"
    target_root.mkdir()
    (target_root / ".semgrep.yml").write_text("rules: []", encoding="utf-8")

    findings, errors = semgrep_adapter.run_semgrep_scan(target_root, 30, binary="semgrep")

    assert findings == []
    assert errors == []
    assert "--config" in captured["command"]
    assert str((target_root / ".semgrep.yml").resolve()) in captured["command"]


def test_osv_scan_skips_without_manifests(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(osv_scanner_adapter, "build_dependency_inventory", lambda root: {})  # type: ignore[arg-type]

    target_root = tmp_path / "repo"
    target_root.mkdir()

    findings, errors = osv_scanner_adapter.run_osv_scanner_scan(target_root, 30, binary="osv-scanner")

    assert findings == []
    assert any("no supported dependency manifests" in error.lower() for error in errors)


def test_codeql_scan_skips_when_query_packs_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, int] = {"calls": 0}

    def fake_run_command(command, timeout_seconds, cwd=None, env_overrides=None):  # type: ignore[no-untyped-def]
        captured["calls"] += 1
        return 0, "", ""

    monkeypatch.setattr(codeql_adapter, "run_command", fake_run_command)

    target_root = tmp_path / "repo"
    target_root.mkdir()
    (target_root / "app.py").write_text("print('hello')", encoding="utf-8")
    codeql_binary = tmp_path / "codeql.exe"
    codeql_binary.write_text("", encoding="utf-8")

    findings, errors = codeql_adapter.run_codeql_scan(target_root, 1, binary=str(codeql_binary))

    assert findings == []
    assert any("CodeQL skipped" in error for error in errors)
    assert captured["calls"] == 1


def test_codeql_bootstraps_from_local_mirror(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "app.py").write_text("print('hello')", encoding="utf-8")

    tool_root = tmp_path / ".toolchain" / "codeql"
    codeql_dir = tool_root / "codeql"
    codeql_dir.mkdir(parents=True)
    codeql_binary = codeql_dir / "codeql.exe"
    codeql_binary.write_text("", encoding="utf-8")

    mirror = tmp_path / "mirror"
    suite = mirror / "python" / "ql" / "src" / "codeql-suites" / "python-security-and-quality.qls"
    suite.parent.mkdir(parents=True, exist_ok=True)
    suite.write_text("queries: []", encoding="utf-8")

    def fake_run_command(command, timeout_seconds, cwd=None, env_overrides=None):  # type: ignore[no-untyped-def]
        command_text = " ".join(str(item) for item in command)
        if "database create" in command_text:
            return 0, "", ""
        if "database analyze" in command_text:
            output_path = None
            for item in command:
                if isinstance(item, str) and item.startswith("--output="):
                    output_path = item.split("=", 1)[1]
                    break
            assert output_path is not None
            Path(output_path).write_text('{"version":"2.1.0","runs":[{"results":[]}]}', encoding="utf-8")
            return 0, "", ""
        return 0, "", ""

    monkeypatch.setattr(codeql_adapter, "run_command", fake_run_command)
    monkeypatch.setenv("USS_CODEQL_PACK_MIRROR", str(mirror))
    monkeypatch.setenv("USS_AUTO_BOOTSTRAP_TOOLS", "1")

    findings, errors = codeql_adapter.run_codeql_scan(repo_root, 30, binary=str(codeql_binary))

    assert findings == []
    assert errors == []


def test_parse_trivy_output() -> None:
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.19",
                        "Title": "Prototype Pollution",
                        "Severity": "HIGH",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                        "CweIDs": ["CWE-1321"],
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0001",
                        "Title": "Public S3 bucket",
                        "Severity": "MEDIUM",
                        "Message": "S3 bucket allows public access",
                        "Resolution": "Disable public ACL",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/aws/s3_public_access",
                        "CauseMetadata": {"StartLine": 12},
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Title": "AWS Access Key",
                        "Severity": "HIGH",
                        "StartLine": 5,
                        "Match": "AKIAIOSFODNN7EXAMPLE",
                    }
                ],
            }
        ]
    }

    findings = parse_trivy_output(payload, Path("C:/repo"))
    assert len(findings) == 3
    assert any(item.vulnerability_type == "Dependency Vulnerability" for item in findings)
    assert any(item.vulnerability_type == "Security Misconfiguration" for item in findings)
    assert any(item.vulnerability_type == "Hardcoded Secrets / Credentials" for item in findings)


def test_parse_gitleaks_output() -> None:
    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "src/config.py",
            "StartLine": 8,
            "Match": "api_key = '1234567890abcdef'",
            "Severity": "high",
        }
    ]

    findings = parse_gitleaks_output(payload, Path("C:/repo"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].cwe == "CWE-798"

