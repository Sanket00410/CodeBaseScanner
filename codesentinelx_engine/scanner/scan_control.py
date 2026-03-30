from __future__ import annotations

import json
import os
import time
from pathlib import Path
from collections.abc import Callable

ProgressCallback = Callable[[float, str, str | None, str | None], None]


_CACHE_TTL_SECONDS = 0.2
_STATE_CACHE: dict[str, object] = {
    "path": "",
    "last_read_at": 0.0,
    "state": "running",
}

class ScanStoppedByUser(RuntimeError):
    """Raised when stop is requested through scan control."""


def honor_pause_control(
    *,
    progress_callback: ProgressCallback | None = None,
    progress: float = 0.0,
    stage: str = "running",
    current_file: str | None = None,
    message: str = "Scan paused by user.",
) -> None:
    state = _read_control_state(force=False)
    if state == "stopped":
        raise ScanStoppedByUser("Scan stopped by user.")

    while state == "paused":
        if progress_callback:
            progress_callback(progress, "paused", current_file, message)
        time.sleep(0.35)
        state = _read_control_state(force=True)
        if state == "stopped":
            raise ScanStoppedByUser("Scan stopped by user.")


def _read_control_state(*, force: bool) -> str:
    control_file = os.getenv("USS_SCAN_CONTROL_FILE", "").strip()
    if not control_file:
        return "running"

    now = time.monotonic()
    cached_path = str(_STATE_CACHE.get("path") or "")
    cached_state = str(_STATE_CACHE.get("state") or "running")
    cached_read_at = float(_STATE_CACHE.get("last_read_at") or 0.0)

    if not force and cached_path == control_file and (now - cached_read_at) <= _CACHE_TTL_SECONDS:
        return cached_state

    state = "running"
    try:
        payload = json.loads(Path(control_file).read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            candidate = str(payload.get("state") or "running").strip().lower()
            if candidate in {"running", "paused", "stopped"}:
                state = candidate
    except Exception:
        state = "running"

    _STATE_CACHE["path"] = control_file
    _STATE_CACHE["last_read_at"] = now
    _STATE_CACHE["state"] = state
    return state
