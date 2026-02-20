from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from universal_security_scanner.models import Severity


def run_command(command: list[str], timeout_seconds: int, cwd: Path | None = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    env.setdefault("USS_WRAPPER_PYTHON", sys.executable)
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        cwd=str(cwd) if cwd else None,
        env=env,
    )
    return completed.returncode, completed.stdout, completed.stderr


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
