from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from universal_security_scanner.models import Severity


_COMMAND_TRACE = threading.local()


def clear_command_trace() -> None:
    _COMMAND_TRACE.records = []


def consume_command_trace() -> list[dict[str, Any]]:
    records = list(getattr(_COMMAND_TRACE, "records", []))
    _COMMAND_TRACE.records = []
    return records


def _record_command_trace(record: dict[str, Any]) -> None:
    records = getattr(_COMMAND_TRACE, "records", None)
    if records is None:
        records = []
        _COMMAND_TRACE.records = records
    records.append(record)


def _coerce_output_text(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="ignore")
    return str(raw)


def _hash_text(value: str) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def run_command(
    command: list[str],
    timeout_seconds: int,
    cwd: Path | None = None,
    env_overrides: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env.setdefault("USS_WRAPPER_PYTHON", sys.executable)
    if env_overrides:
        env.update(env_overrides)

    cwd_value = str(cwd) if cwd else None
    started = time.perf_counter()
    timestamp = datetime.now(timezone.utc).isoformat()
    command_text = subprocess.list2cmdline([str(part) for part in command])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=cwd_value,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce_output_text(exc.stdout)
        stderr = _coerce_output_text(exc.stderr)
        _record_command_trace(
            {
                "timestamp": timestamp,
                "command": command_text,
                "cwd": cwd_value,
                "exit_code": None,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "stdout_sha256": _hash_text(stdout),
                "stderr_sha256": _hash_text(stderr or str(exc)),
                "stdout_bytes": len(stdout.encode("utf-8", errors="ignore")),
                "stderr_bytes": len(stderr.encode("utf-8", errors="ignore")),
                "stdout_preview": stdout[:600],
                "stderr_preview": (stderr or str(exc))[:600],
                "status": "timeout",
            }
        )
        raise
    except FileNotFoundError as exc:
        stderr = str(exc)
        _record_command_trace(
            {
                "timestamp": timestamp,
                "command": command_text,
                "cwd": cwd_value,
                "exit_code": None,
                "duration_ms": int((time.perf_counter() - started) * 1000),
                "stdout_sha256": None,
                "stderr_sha256": _hash_text(stderr),
                "stdout_bytes": 0,
                "stderr_bytes": len(stderr.encode("utf-8", errors="ignore")),
                "stdout_preview": "",
                "stderr_preview": stderr[:600],
                "status": "not_found",
            }
        )
        raise

    duration_ms = int((time.perf_counter() - started) * 1000)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    _record_command_trace(
        {
            "timestamp": timestamp,
            "command": command_text,
            "cwd": cwd_value,
            "exit_code": completed.returncode,
            "duration_ms": duration_ms,
            "stdout_sha256": _hash_text(stdout),
            "stderr_sha256": _hash_text(stderr),
            "stdout_bytes": len(stdout.encode("utf-8", errors="ignore")),
            "stderr_bytes": len(stderr.encode("utf-8", errors="ignore")),
            "stdout_preview": stdout[:600],
            "stderr_preview": stderr[:600],
            "status": "success" if completed.returncode == 0 else "failed",
        }
    )
    return completed.returncode, stdout, stderr


def safe_json_loads(raw: str) -> Any | None:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def to_severity(raw: str | None) -> Severity:
    value = (raw or "").strip().lower()
    if value in {"critical", "error"}:
        return Severity.CRITICAL
    if value in {"high"}:
        return Severity.HIGH
    if value in {"medium", "warning"}:
        return Severity.MEDIUM
    if value in {"low", "note"}:
        return Severity.LOW
    if value in {"info", "informational"}:
        return Severity.INFO
    return Severity.MEDIUM


def normalize_path(target_root: Path, raw_path: str | None) -> str:
    if not raw_path:
        return "unknown"

    path = Path(raw_path)
    if path.is_absolute():
        try:
            return str(path.resolve().relative_to(target_root))
        except Exception:
            return str(path)

    return raw_path.replace("\\", "/")


def first_reference(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return default


def extract_cwe(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        match = re.search(r"CWE-\d+", value, flags=re.IGNORECASE)
        return match.group(0).upper() if match else None

    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                match = re.search(r"CWE-\d+", item, flags=re.IGNORECASE)
                if match:
                    return match.group(0).upper()

    return None
