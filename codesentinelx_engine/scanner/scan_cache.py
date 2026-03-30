from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from codesentinelx_engine.config import ScannerConfig
from codesentinelx_engine.models import Finding

SCAN_CACHE_SCHEMA = "phase4-file-cache-v1"


def content_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def config_signature(config: ScannerConfig) -> str:
    payload = {
        "schema": SCAN_CACHE_SCHEMA,
        "native_code": bool(config.use_native_code_analysis),
        "native_languages": list(config.native_analysis_languages),
        "native_families": list(config.native_analysis_families),
        "native_max_findings_per_file": int(config.native_max_findings_per_file),
        "native_dependency": bool(config.use_native_dependency_analysis),
        "native_dependency_ecosystems": list(config.native_dependency_ecosystems),
        "framework_modeling": bool(config.enable_framework_modeling),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class FileScanCache:
    path: Path
    enabled: bool
    max_files: int
    signature: str
    _entries: dict[str, dict[str, object]] = field(init=False, default_factory=dict, repr=False)
    _dirty: bool = field(init=False, default=False, repr=False)

    def __post_init__(self) -> None:
        if self.enabled:
            self._load()

    @classmethod
    def from_config(cls, config: ScannerConfig) -> "FileScanCache":
        return cls(
            path=config.scan_cache_file,
            enabled=bool(config.scan_cache_enabled),
            max_files=max(1000, int(config.scan_cache_max_files)),
            signature=config_signature(config),
        )

    def get(self, relative_path: str, content_hash: str) -> tuple[list[Finding], dict[str, list[dict[str, str | int]]]] | None:
        if not self.enabled:
            return None
        payload = self._entries.get(relative_path)
        if not payload:
            return None
        if payload.get("schema") != SCAN_CACHE_SCHEMA or payload.get("signature") != self.signature:
            return None
        if payload.get("content_sha256") != content_hash:
            return None
        findings = [Finding.from_dict(item) for item in payload.get("findings", []) if isinstance(item, dict)]
        observations_raw = payload.get("control_observations") or {}
        observations: dict[str, list[dict[str, str | int]]] = {}
        if isinstance(observations_raw, dict):
            for key, value in observations_raw.items():
                if isinstance(value, list):
                    observations[str(key)] = [entry for entry in value if isinstance(entry, dict)]
        return findings, observations

    def put(
        self,
        relative_path: str,
        *,
        content_hash: str,
        findings: list[Finding],
        control_observations: dict[str, list[dict[str, str | int]]],
    ) -> None:
        if not self.enabled:
            return
        self._entries[relative_path] = {
            "schema": SCAN_CACHE_SCHEMA,
            "signature": self.signature,
            "content_sha256": content_hash,
            "findings": [item.to_dict() for item in findings],
            "control_observations": control_observations,
            "last_used": int(self._entries.get(relative_path, {}).get("last_used") or 0) + 1,
        }
        self._dirty = True

    def save(self) -> None:
        if not self.enabled or not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if len(self._entries) > self.max_files:
            ranked = sorted(
                self._entries.items(),
                key=lambda item: int((item[1] or {}).get("last_used") or 0),
                reverse=True,
            )
            self._entries = dict(ranked[: self.max_files])
        temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temp_path.write_text(
            json.dumps(
                {
                    "schema": SCAN_CACHE_SCHEMA,
                    "entries": self._entries,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temp_path.replace(self.path)
        self._dirty = False

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self._entries = {}
            return
        if not isinstance(payload, dict) or payload.get("schema") != SCAN_CACHE_SCHEMA:
            self._entries = {}
            return
        entries = payload.get("entries")
        if not isinstance(entries, dict):
            self._entries = {}
            return
        self._entries = {str(key): value for key, value in entries.items() if isinstance(value, dict)}

