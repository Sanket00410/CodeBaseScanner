from __future__ import annotations

from codesentinelx_engine.scanner.rules.base import BaseFileRule, BaseProjectRule
from codesentinelx_engine.scanner.rules.builtin_rules import build_builtin_file_rules
from codesentinelx_engine.scanner.rules.dependency_rules import DependencyVulnerabilityRule


def build_file_rules() -> list[BaseFileRule]:
    return list(build_builtin_file_rules())


def build_project_rules() -> list[BaseProjectRule]:
    return [DependencyVulnerabilityRule()]

