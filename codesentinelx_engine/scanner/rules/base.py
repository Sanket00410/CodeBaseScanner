from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from codesentinelx_engine.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    vulnerability_type: str
    severity: Severity
    description: str
    business_impact: str
    recommendation: str
    reference: str
    owasp_category: str
    cwe: str | None = None


class BaseFileRule(ABC):
    metadata: RuleMetadata
    file_extensions: set[str] | None

    def supports(self, file_path: Path) -> bool:
        if self.file_extensions is None:
            return True
        return file_path.suffix.lower() in self.file_extensions

    @abstractmethod
    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        raise NotImplementedError

    def _build_finding(self, file_path: Path, line_number: int, evidence: str | None = None) -> Finding:
        return Finding(
            vulnerability_type=self.metadata.vulnerability_type,
            severity=self.metadata.severity,
            file_path=str(file_path),
            line_number=line_number,
            business_impact=self.metadata.business_impact,
            recommendation=self.metadata.recommendation,
            reference=self.metadata.reference,
            owasp_category=self.metadata.owasp_category,
            description=self.metadata.description,
            rule_id=self.metadata.rule_id,
            cwe=self.metadata.cwe,
            evidence=evidence,
        )


class RegexFileRule(BaseFileRule):
    def __init__(
        self,
        metadata: RuleMetadata,
        patterns: list[str],
        file_extensions: set[str] | None = None,
        flags: int = re.IGNORECASE,
    ) -> None:
        self.metadata = metadata
        self.patterns = [re.compile(pattern, flags) for pattern in patterns]
        self.file_extensions = file_extensions

    def scan_file(self, file_path: Path, content: str) -> list[Finding]:
        if not self.supports(file_path):
            return []

        findings: list[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            for pattern in self.patterns:
                if pattern.search(line):
                    findings.append(
                        self._build_finding(
                            file_path=file_path,
                            line_number=line_number,
                            evidence=line.strip()[:240],
                        )
                    )
                    break
        return findings


class BaseProjectRule(ABC):
    metadata: RuleMetadata

    @abstractmethod
    def scan_project(self, project_root: Path) -> list[Finding]:
        raise NotImplementedError

    def _build_finding(
        self,
        file_path: Path,
        line_number: int,
        *,
        description: str | None = None,
        business_impact: str | None = None,
        recommendation: str | None = None,
        reference: str | None = None,
        owasp_category: str | None = None,
        cwe: str | None = None,
        severity: Severity | None = None,
        evidence: str | None = None,
    ) -> Finding:
        return Finding(
            vulnerability_type=self.metadata.vulnerability_type,
            severity=severity or self.metadata.severity,
            file_path=str(file_path),
            line_number=line_number,
            business_impact=business_impact or self.metadata.business_impact,
            recommendation=recommendation or self.metadata.recommendation,
            reference=reference or self.metadata.reference,
            owasp_category=owasp_category or self.metadata.owasp_category,
            description=description or self.metadata.description,
            rule_id=self.metadata.rule_id,
            cwe=cwe or self.metadata.cwe,
            evidence=evidence,
        )

