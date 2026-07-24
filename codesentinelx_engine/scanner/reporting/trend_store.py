from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TREND_DATA_DIR = Path.home() / ".codesentinelx"
TREND_DATA_FILE = TREND_DATA_DIR / "scan_trend_data.json"


@dataclass(slots=True)
class ScanSnapshot:
    scan_id: str = ""
    timestamp: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = 0.0
    risk_rating: str = "Low"
    overall_posture: float = 0.0
    files_scanned: int = 0
    lines_of_code: int = 0
    duration_seconds: float = 0.0
    project_name: str = ""


@dataclass(slots=True)
class ScanTrendDataStore:
    snapshots: list[ScanSnapshot] = field(default_factory=list)
    max_snapshots: int = 50

    def load(self, path: str | Path | None = None) -> None:
        filepath = Path(path) if path else TREND_DATA_FILE
        if filepath.exists():
            try:
                raw = json.loads(filepath.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    self.snapshots = [ScanSnapshot(**s) for s in raw if isinstance(s, dict)]
            except (json.JSONDecodeError, OSError):
                self.snapshots = []

    def save(self, path: str | Path | None = None) -> None:
        filepath = Path(path) if path else TREND_DATA_FILE
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps([asdict(s) for s in self.snapshots], indent=2), encoding="utf-8")

    def add_snapshot(self, snapshot: ScanSnapshot) -> None:
        self.snapshots.append(snapshot)
        if len(self.snapshots) > self.max_snapshots:
            self.snapshots = self.snapshots[-self.max_snapshots:]
        self.save()

    def trend_description(self) -> str:
        if len(self.snapshots) < 2:
            return "Insufficient scan history for trend analysis. Run at least 2 scans to establish a baseline."

        ordered = sorted(self.snapshots, key=lambda s: s.timestamp)
        latest = ordered[-1]
        previous = ordered[-2]

        parts: list[str] = []
        findings_delta = latest.total_findings - previous.total_findings
        if findings_delta > 0:
            parts.append(f"Findings increased by {findings_delta} (+{((findings_delta/previous.total_findings)*100):.0f}%)")
        elif findings_delta < 0:
            parts.append(f"Findings decreased by {abs(findings_delta)} ({((abs(findings_delta)/previous.total_findings)*100):.0f}% reduction)")
        else:
            parts.append("Finding count unchanged")

        critical_delta = latest.critical_count - previous.critical_count
        if critical_delta > 0:
            parts.append(f"critical findings up by {critical_delta}")
        elif critical_delta < 0:
            parts.append(f"critical findings down by {abs(critical_delta)}")

        posture_delta = latest.overall_posture - previous.overall_posture
        if posture_delta > 5:
            parts.append(f"posture score improved by {posture_delta:.1f} points")
        elif posture_delta < -5:
            parts.append(f"posture score declined by {abs(posture_delta):.1f} points")
        else:
            parts.append("posture score stable")

        return " | ".join(parts)

    @classmethod
    def default_store(cls) -> ScanTrendDataStore:
        store = cls()
        store.load()
        return store
