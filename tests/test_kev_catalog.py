from __future__ import annotations

import json

from universal_security_scanner.scanner import kev_catalog


def test_load_kev_catalog_from_local_override(tmp_path, monkeypatch):
    kev_catalog._KEV_CACHE = None
    override_file = tmp_path / "kev.json"
    override_file.write_text(
        json.dumps(
            {
                "catalogVersion": "2026.03.20",
                "dateReleased": "2026-03-20T00:00:00Z",
                "vulnerabilities": [
                    {"cveID": "CVE-2026-1234"},
                    {"cveID": "CVE-2026-5678"},
                ],
            }
        ),
        encoding="utf-8",
    )
    cache_file = tmp_path / "cache.json"
    monkeypatch.setenv("USS_KEV_CVE_PATH", str(override_file))
    monkeypatch.setenv("USS_KEV_CACHE_FILE", str(cache_file))

    catalog, metadata = kev_catalog.load_kev_catalog(cache_path=cache_file)

    assert catalog == {"CVE-2026-1234", "CVE-2026-5678"}
    assert metadata["source"] == "local_override"
    assert metadata["catalog_version"] == "2026.03.20"
    assert metadata["count"] == 2
    assert kev_catalog.find_kev_matches(["cve-2026-1234", "CVE-2026-9999"], catalog) == ["CVE-2026-1234"]
    kev_catalog._KEV_CACHE = None


def test_normalize_cve_id_handles_noise():
    assert kev_catalog.normalize_cve_id("CVE-2026-0001 (critical)") == "CVE-2026-0001"
    assert kev_catalog.normalize_cve_id("not a cve") is None
