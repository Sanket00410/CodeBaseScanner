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

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


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
