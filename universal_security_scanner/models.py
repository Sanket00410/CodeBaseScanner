from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(slots=True)
class Finding:
    vulnerability_type: str
    severity: Severity
    file_path: str
    line_number: int
    business_impact: str
    recommendation: str
    reference: str
    owasp_category: str
    description: str
    rule_id: str
    cwe: str | None = None
    evidence: str | None = None
    origin: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Finding":
        severity_raw = str(payload.get("severity") or Severity.INFO.value)
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.INFO
        provenance = payload.get("provenance")
        if not isinstance(provenance, dict):
            provenance = {}
        return cls(
            vulnerability_type=str(payload.get("vulnerability_type") or ""),
            severity=severity,
            file_path=str(payload.get("file_path") or ""),
            line_number=int(payload.get("line_number") or 0),
            business_impact=str(payload.get("business_impact") or ""),
            recommendation=str(payload.get("recommendation") or ""),
            reference=str(payload.get("reference") or ""),
            owasp_category=str(payload.get("owasp_category") or ""),
            description=str(payload.get("description") or ""),
            rule_id=str(payload.get("rule_id") or ""),
            cwe=str(payload.get("cwe") or "") or None,
            evidence=str(payload.get("evidence") or "") or None,
            origin=str(payload.get("origin") or ""),
            provenance=provenance,
        )


@dataclass(slots=True)
class SecurityControl:
    control_id: str
    name: str
    category: str
    description: str
    status: str
    coverage_level: str
    standard_mappings: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target_path: str
    started_at: datetime
    completed_at: datetime
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    existing_security_measures: list[SecurityControl] = field(default_factory=list)
    toolchain_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    quality_benchmark: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        return round((self.completed_at - self.started_at).total_seconds(), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_path": self.target_path,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "findings": [item.to_dict() for item in self.findings],
            "errors": self.errors,
            "existing_security_measures": [item.to_dict() for item in self.existing_security_measures],
            "toolchain_status": self.toolchain_status,
            "quality_benchmark": self.quality_benchmark,
        }


@dataclass(slots=True)
class ScanProgress:
    scan_id: str
    status: str
    stage: str
    progress_percent: float
    current_file: str | None = None
    message: str | None = None


class StartScanRequest(BaseModel):
    target_path: str = Field(..., description="Absolute or relative path to target project")


class StartScanResponse(BaseModel):
    scan_id: str
    status: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    stage: str
    progress_percent: float
    current_file: str | None = None
    message: str | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
