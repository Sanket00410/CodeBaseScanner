from __future__ import annotations

import csv
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_KEV_CACHE: tuple[set[str], dict[str, Any]] | None = None


def normalize_cve_id(value: object) -> str | None:
    if value is None:
        return None
    match = _CVE_PATTERN.search(str(value))
    return match.group(0).upper() if match else None


def _collect_cve_ids(payload: Any) -> set[str]:
    ids: set[str] = set()
    if isinstance(payload, dict):
        for key in ("cveID", "cve_id", "cveId", "cve"):
            normalized = normalize_cve_id(payload.get(key))
            if normalized:
                ids.add(normalized)
        vulnerabilities = payload.get("vulnerabilities")
        if isinstance(vulnerabilities, list):
            for entry in vulnerabilities:
                ids.update(_collect_cve_ids(entry))
        for value in payload.values():
            if isinstance(value, (dict, list, str)):
                ids.update(_collect_cve_ids(value))
    elif isinstance(payload, list):
        for entry in payload:
            ids.update(_collect_cve_ids(entry))
    elif isinstance(payload, str):
        for match in _CVE_PATTERN.findall(payload):
            ids.add(match.upper())
    return ids


def _local_cache_path() -> Path:
    return Path(os.getenv("USS_KEV_CACHE_FILE", "CodeSentinelX_Reports/export/.integrity/cisa_kev_catalog.json"))


def _read_catalog_file(path: Path) -> tuple[set[str], dict[str, Any]]:
    raw_text = path.read_text(encoding="utf-8", errors="ignore")
    suffix = path.suffix.lower()
    if suffix == ".csv":
        ids: set[str] = set()
        reader = csv.reader(raw_text.splitlines())
        for row in reader:
            for cell in row:
                normalized = normalize_cve_id(cell)
                if normalized:
                    ids.add(normalized)
        return ids, {
            "source": "local_csv",
            "source_path": str(path),
            "catalog_version": None,
            "date_released": None,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "count": len(ids),
        }
    if suffix in {".json", ".jsonl", ".ndjson"}:
        payload = json.loads(raw_text)
        ids = _collect_cve_ids(payload)
        metadata: dict[str, Any] = {
            "source": "local_json",
            "source_path": str(path),
            "catalog_version": None,
            "date_released": None,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "count": len(ids),
        }
        if isinstance(payload, dict):
            metadata["catalog_version"] = payload.get("catalogVersion") or payload.get("catalog_version")
            metadata["date_released"] = payload.get("dateReleased") or payload.get("date_released")
        return ids, metadata
    ids = _collect_cve_ids(raw_text)
    return ids, {
        "source": "local_text",
        "source_path": str(path),
        "catalog_version": None,
        "date_released": None,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "count": len(ids),
    }


def _read_cached_catalog(cache_path: Path, max_age_hours: int) -> tuple[set[str], dict[str, Any]] | None:
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    retrieved_at = str(payload.get("retrieved_at") or "").strip()
    if retrieved_at:
        try:
            parsed = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
            age_hours = (datetime.now(timezone.utc) - parsed).total_seconds() / 3600.0
            if age_hours > max_age_hours:
                return None
        except ValueError:
            pass
    ids = _collect_cve_ids(payload)
    if not ids:
        return None
    return ids, {
        "source": str(payload.get("source") or "cache"),
        "source_path": str(cache_path),
        "catalog_version": payload.get("catalog_version") or payload.get("catalogVersion"),
        "date_released": payload.get("date_released") or payload.get("dateReleased"),
        "retrieved_at": retrieved_at or payload.get("retrieved_at") or datetime.now(timezone.utc).isoformat(),
        "count": len(ids),
    }


def _write_cached_catalog(cache_path: Path, cves: set[str], metadata: dict[str, Any]) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_payload = {
            "source": metadata.get("source") or "official_cisa",
            "source_url": metadata.get("source_url") or KEV_FEED_URL,
            "catalog_version": metadata.get("catalog_version"),
            "date_released": metadata.get("date_released"),
            "retrieved_at": metadata.get("retrieved_at") or datetime.now(timezone.utc).isoformat(),
            "count": len(cves),
            "vulnerabilities": [{"cveID": cve} for cve in sorted(cves)],
        }
        cache_path.write_text(json.dumps(cache_payload, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _fetch_official_catalog() -> tuple[set[str], dict[str, Any]]:
    url = os.getenv("USS_KEV_FEED_URL", KEV_FEED_URL).strip() or KEV_FEED_URL
    request = urllib.request.Request(url, headers={"User-Agent": "CodeSentinelX/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    ids = _collect_cve_ids(payload)
    metadata: dict[str, Any] = {
        "source": "official_cisa",
        "source_url": url,
        "catalog_version": payload.get("catalogVersion") if isinstance(payload, dict) else None,
        "date_released": payload.get("dateReleased") if isinstance(payload, dict) else None,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "count": len(ids),
    }
    return ids, metadata


def load_kev_catalog(
    override_path: str | Path | None = None,
    *,
    cache_path: str | Path | None = None,
    cache_ttl_hours: int = 24,
) -> tuple[set[str], dict[str, Any]]:
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE

    cache_file = Path(cache_path or _local_cache_path())
    override_value = override_path if override_path is not None else os.getenv("USS_KEV_CVE_PATH", "")
    override = Path(override_value).expanduser() if str(override_value).strip() else None
    if override and override.exists():
        loaded = _read_catalog_file(override)
        if loaded[0]:
            metadata = dict(loaded[1])
            metadata["source"] = "local_override"
            metadata["source_path"] = str(override)
            metadata["count"] = len(loaded[0])
            _write_cached_catalog(cache_file, loaded[0], metadata)
            _KEV_CACHE = (loaded[0], metadata)
            return _KEV_CACHE

    cached = _read_cached_catalog(cache_file, max_age_hours=cache_ttl_hours)
    if cached:
        _KEV_CACHE = cached
        return _KEV_CACHE

    try:
        loaded = _fetch_official_catalog()
        _write_cached_catalog(cache_file, loaded[0], loaded[1])
        _KEV_CACHE = loaded
        return _KEV_CACHE
    except (urllib.error.URLError, TimeoutError, ValueError, OSError, json.JSONDecodeError):
        if cache_file.exists():
            cached = _read_cached_catalog(cache_file, max_age_hours=10_000)
            if cached:
                _KEV_CACHE = cached
                return _KEV_CACHE
        _KEV_CACHE = (
            set(),
            {
                "source": "unavailable",
                "source_path": str(cache_file),
                "catalog_version": None,
                "date_released": None,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "count": 0,
            },
        )
        return _KEV_CACHE


def find_kev_matches(cve_ids: Iterable[object], catalog: set[str] | None = None) -> list[str]:
    resolved_catalog = catalog if catalog is not None else load_kev_catalog()[0]
    normalized = {normalized_cve for normalized_cve in (normalize_cve_id(cve) for cve in cve_ids) if normalized_cve}
    return sorted(normalized & resolved_catalog)
