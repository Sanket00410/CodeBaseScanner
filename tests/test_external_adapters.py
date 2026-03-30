from pathlib import Path

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.models import Severity
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

