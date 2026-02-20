from __future__ import annotations

from universal_security_scanner.scanner.rules.base import BaseFileRule, BaseProjectRule
from universal_security_scanner.scanner.rules.builtin_rules import build_builtin_file_rules
from universal_security_scanner.scanner.rules.dependency_rules import DependencyVulnerabilityRule


def build_file_rules() -> list[BaseFileRule]:
    return list(build_builtin_file_rules())


def build_project_rules() -> list[BaseProjectRule]:
    return [DependencyVulnerabilityRule()]
