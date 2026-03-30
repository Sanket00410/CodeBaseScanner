from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from codesentinelx_engine.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class PluginMetadata:
    plugin_id: str
    name: str
    language: str
    version: str


@dataclass(frozen=True, slots=True)
class PluginRule:
    rule_id: str
    vulnerability_type: str
    severity: Severity
    description: str
    business_impact: str
    recommendation: str
    reference: str
    owasp_category: str
    cwe: str | None = None


class BaseLanguagePlugin(ABC):
    metadata: PluginMetadata

    @property
    @abstractmethod
    def supported_extensions(self) -> set[str]:
        raise NotImplementedError

    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self.supported_extensions

    @abstractmethod
    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        raise NotImplementedError

    def build_finding(
        self,
        *,
        rule: PluginRule,
        file_path: Path,
        line_number: int,
        evidence: str | None = None,
    ) -> Finding:
        return Finding(
            vulnerability_type=rule.vulnerability_type,
            severity=rule.severity,
            file_path=str(file_path),
            line_number=line_number,
            business_impact=rule.business_impact,
            recommendation=rule.recommendation,
            reference=rule.reference,
            owasp_category=rule.owasp_category,
            description=rule.description,
            rule_id=rule.rule_id,
            cwe=rule.cwe,
            evidence=evidence,
            origin="builtin_plugin",
            provenance={
                "source": "builtin_plugin",
                "plugin_id": self.metadata.plugin_id,
                "plugin_name": self.metadata.name,
                "language": self.metadata.language,
            },
        )

