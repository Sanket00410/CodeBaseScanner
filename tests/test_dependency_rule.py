import json

from codesentinelx_engine.scanner.rules.dependency_rules import DependencyVulnerabilityRule


def test_dependency_rule_detects_vulnerable_dependencies(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("django==2.2.10\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.19"}}),
        encoding="utf-8",
    )

    rule = DependencyVulnerabilityRule()
    findings = rule.scan_project(tmp_path)

    assert any("django" in (item.evidence or "") for item in findings)
    assert any("lodash" in (item.evidence or "") for item in findings)

