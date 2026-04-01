from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.dependency_auth import build_dependency_inventory, build_dependency_usage_map, normalize_package_name
from codesentinelx_engine.scanner.external.common import extract_cwe, first_reference, normalize_path, run_command, safe_json_loads, to_severity


def _vuln_severity(vulnerability: dict[str, Any], groups: list[dict[str, Any]]) -> str:
    database = vulnerability.get("database_specific") if isinstance(vulnerability, dict) else None
    if isinstance(database, dict):
        severity = database.get("severity")
        if isinstance(severity, str) and severity.strip():
            return severity
    for group in groups:
        if not isinstance(group, dict):
            continue
        max_severity = str(group.get("max_severity") or "").strip()
        if max_severity:
            return max_severity
    return "medium"


def _reachability_label(
    package_name: str,
    *,
    inventory_row: dict[str, object] | None,
    usage_map: dict[str, list[str]],
) -> tuple[str, list[str]]:
    normalized = normalize_package_name(package_name)
    usage_paths = list(usage_map.get(normalized, []))
    manifest_paths = sorted({str(item) for item in (inventory_row or {}).get("manifest_paths", set())})
    lockfile_paths = sorted({str(item) for item in (inventory_row or {}).get("lockfile_paths", set())})
    if usage_paths:
        return "reachable", usage_paths
    if manifest_paths and lockfile_paths:
        return "declared_and_locked", []
    if lockfile_paths:
        return "lockfile_only", []
    if manifest_paths:
        return "declared_only", []
    return "unmapped", []


def parse_osv_scanner_output(
    data: dict,
    target_root: Path,
    *,
    inventory: dict[str, dict[str, object]] | None = None,
    usage_map: dict[str, list[str]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    inventory = inventory or {}
    usage_map = usage_map or {}
    for result in data.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        source_path = normalize_path(target_root, str(source.get("path") or "dependencies"))

        for package_item in result.get("packages", []) or []:
            if not isinstance(package_item, dict):
                continue

            package = package_item.get("package") or {}
            package_name = str(package.get("name") or "dependency")
            package_version = str(package.get("version") or "")
            vulnerabilities = package_item.get("vulnerabilities") or []
            groups = package_item.get("groups") or []
            if not isinstance(vulnerabilities, list):
                continue

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                vuln_id = str(vulnerability.get("id") or "UNKNOWN")
                aliases = vulnerability.get("aliases") or []
                references = vulnerability.get("references") or []
                reference_urls = []
                if isinstance(references, list):
                    for entry in references:
                        if not isinstance(entry, dict):
                            continue
                        url = entry.get("url")
                        if isinstance(url, str) and url.strip():
                            reference_urls.append(url.strip())

                reference = first_reference(reference_urls, f"https://osv.dev/vulnerability/{vuln_id}")
                cwe = extract_cwe(vulnerability.get("database_specific", {}).get("cwe_ids")) or extract_cwe(aliases) or "CWE-1104"
                inventory_row = inventory.get(normalize_package_name(package_name))
                reachability, usage_paths = _reachability_label(package_name, inventory_row=inventory_row, usage_map=usage_map)
                manifest_paths = sorted({str(item) for item in (inventory_row or {}).get("manifest_paths", set())})
                lockfile_paths = sorted({str(item) for item in (inventory_row or {}).get("lockfile_paths", set())})
                declared_versions = sorted({str(item) for item in (inventory_row or {}).get("declared_versions", set()) if str(item).strip()})
                locked_versions = sorted({str(item) for item in (inventory_row or {}).get("locked_versions", set()) if str(item).strip()})
                advisory_ids = sorted(
                    {
                        str(item).strip().upper()
                        for item in ([vuln_id, *aliases] if isinstance(aliases, list) else [vuln_id])
                        if str(item).strip()
                    }
                )

                findings.append(
                    Finding(
                        vulnerability_type="Dependency Vulnerability",
                        severity=to_severity(_vuln_severity(vulnerability, groups if isinstance(groups, list) else [])),
                        file_path=source_path,
                        line_number=1,
                        business_impact=(
                            "Vulnerable dependency detected in project dependency graph."
                            if reachability == "reachable"
                            else "Vulnerable dependency detected in the declared or locked dependency graph."
                        ),
                        recommendation=f"Upgrade {package_name} to a fixed version and validate transitive dependencies.",
                        reference=reference,
                        owasp_category="A06:2021 - Vulnerable and Outdated Components",
                        description=str(
                            vulnerability.get("summary")
                            or vulnerability.get("details")
                            or f"{package_name} matched vulnerability {vuln_id}"
                        ),
                        rule_id=f"OSV-{vuln_id}",
                        cwe=cwe,
                        evidence=f"{package_name} {package_version} | {reachability}".strip(),
                        provenance={
                            "dependency_name": package_name,
                            "dependency_version": package_version,
                            "dependency_manifest_paths": manifest_paths,
                            "dependency_lockfile_paths": lockfile_paths,
                            "dependency_declared_versions": declared_versions,
                            "dependency_locked_versions": locked_versions,
                            "dependency_usage_paths": usage_paths,
                            "dependency_reachability": reachability,
                            "advisory_ids": advisory_ids,
                            "advisory_verified": any(
                                str(item).startswith(("CVE-", "GHSA-")) for item in advisory_ids
                            ),
                        },
                    )
                )
    return findings


def run_osv_scanner_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "osv-scanner",
) -> tuple[list[Finding], list[str]]:
    inventory = build_dependency_inventory(target_root)
    if not inventory:
        return [], [
            "OSV-Scanner skipped: no supported dependency manifests or lockfiles were detected in this target."
        ]
    usage_map = build_dependency_usage_map(target_root)

    with tempfile.NamedTemporaryFile(prefix="osv-scan-", suffix=".json", delete=False) as tmp_file:
        output_path = tmp_file.name
    command = [
        binary,
        "scan",
        "source",
        "--recursive",
        "--allow-no-lockfiles",
        "--verbosity",
        "error",
        "--format",
        "json",
        "--output",
        output_path,
        str(target_root),
    ]

    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["OSV-Scanner not found in PATH/toolchain. Install or bootstrap osv-scanner for dependency CVE mapping."]
    except Exception as exc:
        return [], [f"OSV-Scanner execution failed: {exc}"]

    raw_payload = ""
    try:
        payload_path = Path(output_path)
        if payload_path.exists():
            raw_payload = payload_path.read_text(encoding="utf-8", errors="ignore")
            payload_path.unlink(missing_ok=True)
    except Exception:
        raw_payload = ""

    if return_code not in {0, 1, 128}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"OSV-Scanner returned code {return_code}: {short_error}"]

    payload = safe_json_loads(raw_payload or stdout)
    if not isinstance(payload, dict):
        if return_code == 128:
            return [], []
        return [], ["OSV-Scanner produced non-JSON output."]

    return parse_osv_scanner_output(payload, target_root, inventory=inventory, usage_map=usage_map), []

