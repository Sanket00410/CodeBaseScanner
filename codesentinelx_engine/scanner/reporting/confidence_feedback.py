from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIDENCE_FEEDBACK_DIR = Path.home() / ".codesentinelx"
CONFIDENCE_FEEDBACK_FILE = CONFIDENCE_FEEDBACK_DIR / "confidence_feedback.json"


@dataclass(slots=True)
class ConfidenceFeedbackEntry:
    finding_signature: str = ""
    rule_id: str = ""
    file_path: str = ""
    vulnerability_type: str = ""
    is_false_positive: bool = False
    reported_by: str = "auto"
    created_at: str = ""
    notes: str = ""


@dataclass(slots=True)
class ConfidenceFeedbackStore:
    entries: list[ConfidenceFeedbackEntry] = field(default_factory=list)

    def load(self, path: str | Path | None = None) -> None:
        filepath = Path(path) if path else CONFIDENCE_FEEDBACK_FILE
        if filepath.exists():
            try:
                raw = json.loads(filepath.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    self.entries = [ConfidenceFeedbackEntry(**e) for e in raw if isinstance(e, dict)]
            except (json.JSONDecodeError, OSError):
                self.entries = []

    def save(self, path: str | Path | None = None) -> None:
        filepath = Path(path) if path else CONFIDENCE_FEEDBACK_FILE
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps([asdict(e) for e in self.entries], indent=2), encoding="utf-8")

    def add_feedback(
        self,
        finding_signature: str,
        rule_id: str,
        file_path: str,
        vulnerability_type: str,
        is_false_positive: bool,
        reported_by: str = "user",
        notes: str = "",
    ) -> ConfidenceFeedbackEntry:
        entry = ConfidenceFeedbackEntry(
            finding_signature=finding_signature,
            rule_id=rule_id,
            file_path=file_path,
            vulnerability_type=vulnerability_type,
            is_false_positive=is_false_positive,
            reported_by=reported_by,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            notes=notes,
        )
        self.entries.append(entry)
        self.save()
        return entry

    def is_known_false_positive(self, rule_id: str, file_path: str) -> bool:
        return any(
            e.rule_id == rule_id and e.file_path == file_path and e.is_false_positive
            for e in self.entries
        )

    def false_positive_ratio(self, rule_id: str) -> float:
        matching = [e for e in self.entries if e.rule_id == rule_id]
        if not matching:
            return 0.0
        fps = sum(1 for e in matching if e.is_false_positive)
        return fps / len(matching)

    def is_high_fp_rule(self, rule_id: str, threshold: float = 0.3) -> bool:
        return self.false_positive_ratio(rule_id) >= threshold

    @classmethod
    def default_store(cls) -> ConfidenceFeedbackStore:
        store = cls()
        store.load()
        return store


def _make_finding_signature(rule_id: str, file_path: str, vulnerability_type: str) -> str:
    return f"{rule_id}::{file_path}::{vulnerability_type}"


def _auto_flag_potential_fp(
    finding: Any,
    confidence_score: float,
    fp_store: ConfidenceFeedbackStore,
) -> tuple[float, str]:
    score = confidence_score
    reasons = []

    rule_id = getattr(finding, "rule_id", "") or ""
    file_path = getattr(finding, "file_path", "") or ""
    vulnerability_type = getattr(finding, "title", "") or getattr(finding, "vulnerability_type", "")

    if fp_store.is_known_false_positive(rule_id, file_path):
        score = max(score * 0.3, 5.0)
        reasons.append("Known false positive for this exact finding location")

    if fp_store.is_high_fp_rule(rule_id):
        score = max(score * 0.6, 10.0)
        reasons.append(f"Rule {rule_id} has high historical false-positive ratio ({fp_store.false_positive_ratio(rule_id):.0%})")

    no_evidence = not getattr(finding, "evidence", None) and not getattr(finding, "code_snippet_vulnerable", None)
    if no_evidence:
        score = max(score * 0.7, 15.0)
        reasons.append("No evidence captured; manually verify")

    if getattr(finding, "confidence_score", 0) < 20:
        reasons.append("Low confidence score from analysis")

    if not reasons:
        reasons.append("No FP history; flagging for manual review as precaution")

    return min(score, 100.0), "; ".join(reasons)
