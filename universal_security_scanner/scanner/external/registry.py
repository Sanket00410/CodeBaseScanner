from __future__ import annotations

from pathlib import Path

from universal_security_scanner.config import ScannerConfig
from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.bandit_adapter import run_bandit_scan
from universal_security_scanner.scanner.external.checkov_adapter import run_checkov_scan
from universal_security_scanner.scanner.external.catalog import (
    active_tools_for_target,
    get_tool_entry,
    tool_names_for_target,
)
from universal_security_scanner.scanner.external.codeql_adapter import run_codeql_scan
from universal_security_scanner.scanner.external.additional_codebase_adapters import (
    run_brakeman_scan,
    run_clair_scan,
    run_cppcheck_scan,
    run_eslint_security_scan,
    run_findsecbugs_scan,
    run_flawfinder_scan,
    run_govulncheck_scan,
    run_infer_scan,
    run_npm_audit_scan,
    run_safety_scan,
    run_snyk_scan,
    run_sonarqube_scan,
    run_spotbugs_scan,
)
from universal_security_scanner.scanner.external.additional_runtime_adapters import (
    run_amass_runtime_scan,
    run_ffuf_runtime_scan,
    run_kube_bench_runtime_scan,
    run_kube_hunter_runtime_scan,
    run_sqlmap_runtime_scan,
    run_wapiti_runtime_scan,
)
from universal_security_scanner.scanner.external.gitleaks_adapter import run_gitleaks_scan
from universal_security_scanner.scanner.external.gosec_adapter import run_gosec_scan
from universal_security_scanner.scanner.external.grype_adapter import run_grype_scan
from universal_security_scanner.scanner.external.hadolint_adapter import run_hadolint_scan
from universal_security_scanner.scanner.external.osv_scanner_adapter import run_osv_scanner_scan
from universal_security_scanner.scanner.external.owasp_dependency_check_adapter import run_owasp_dependency_check_scan
from universal_security_scanner.scanner.external.pip_audit_adapter import run_pip_audit_scan
from universal_security_scanner.scanner.external.runtime_adapters import (
    run_nikto_runtime_scan,
    run_nmap_runtime_scan,
    run_nuclei_runtime_scan,
    run_zap_baseline_runtime_scan,
)
from universal_security_scanner.scanner.external.semgrep_adapter import run_semgrep_scan
from universal_security_scanner.scanner.external.tfsec_adapter import run_tfsec_scan
from universal_security_scanner.scanner.external.trivy_adapter import run_trivy_scan


def external_tool_names(config: ScannerConfig, target_mode: str = "codebase", include_catalog: bool = False) -> list[str]:
    if not config.use_external_tools:
        return []

    normalized_target = target_mode.strip().lower()
    configured: list[str]
    if normalized_target == "runtime":
        configured = list(config.runtime_external_tools or [])
    elif normalized_target == "remote-codebase":
        configured = list(config.codebase_external_tools or [])
    else:
        configured = list(config.codebase_external_tools or config.external_tools or [])

    if not configured:
        configured = active_tools_for_target(normalized_target)

    if include_catalog:
        configured.extend(tool_names_for_target(normalized_target))

    names: list[str] = []
    seen: set[str] = set()
    for item in configured:
        normalized = item.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        names.append(normalized)
    return names


def supported_runner_tools(target_mode: str = "codebase") -> list[str]:
    normalized_target = target_mode.strip().lower()
    if normalized_target == "runtime":
        return sorted(_RUNTIME_RUNNERS.keys())
    return sorted(_CODEBASE_RUNNERS.keys())


def run_external_tool(
    tool_name: str,
    *,
    target_root: Path,
    config: ScannerConfig,
    command: str | None = None,
) -> tuple[list[Finding], list[str]]:
    runner = _CODEBASE_RUNNERS.get(tool_name.lower())
    if runner is None:
        return [], [
            (
                f"No integrated parser for '{tool_name}'. Tool is cataloged and visible in Toolchain status, "
                "but normalized finding ingestion is not wired yet."
            )
        ]

    findings, errors = runner(
        target_root=target_root,
        timeout_seconds=config.external_tool_timeout_seconds,
        binary=command or tool_name,
    )
    return findings, errors


def run_external_runtime_tool(
    tool_name: str,
    *,
    target_url: str,
    config: ScannerConfig,
    command: str | None = None,
) -> tuple[list[Finding], list[str]]:
    runner = _RUNTIME_RUNNERS.get(tool_name.lower())
    if runner is None:
        return [], [
            (
                f"No integrated runtime parser for '{tool_name}'. Tool is cataloged and shown in Toolchain status only."
            )
        ]

    findings, errors = runner(
        target_url=target_url,
        timeout_seconds=config.external_tool_timeout_seconds,
        binary=command or tool_name,
    )
    return findings, errors


def tool_metadata(tool_name: str) -> dict[str, object]:
    info = get_tool_entry(tool_name)
    if info is None:
        return {
            "display_name": tool_name,
            "description": "No metadata available for this tool.",
            "category": "Unknown",
            "target_modes": [],
            "vulnerability_classes": [],
            "homepage": "",
            "integrated": False,
        }
    return {
        "display_name": info.display_name,
        "description": info.description,
        "category": info.category,
        "target_modes": list(info.target_modes),
        "vulnerability_classes": list(info.vulnerability_classes),
        "homepage": info.homepage,
        "integrated": info.integrated,
        "recommended_command": info.command,
    }


_CODEBASE_RUNNERS = {
    "semgrep": run_semgrep_scan,
    "trivy": run_trivy_scan,
    "gitleaks": run_gitleaks_scan,
    "codeql": run_codeql_scan,
    "bandit": run_bandit_scan,
    "checkov": run_checkov_scan,
    "pip-audit": run_pip_audit_scan,
    "grype": run_grype_scan,
    "osv-scanner": run_osv_scanner_scan,
    "hadolint": run_hadolint_scan,
    "tfsec": run_tfsec_scan,
    "gosec": run_gosec_scan,
    "owasp-dependency-check": run_owasp_dependency_check_scan,
    "brakeman": run_brakeman_scan,
    "clair": run_clair_scan,
    "cppcheck": run_cppcheck_scan,
    "eslint-security": run_eslint_security_scan,
    "findsecbugs": run_findsecbugs_scan,
    "flawfinder": run_flawfinder_scan,
    "govulncheck": run_govulncheck_scan,
    "infer": run_infer_scan,
    "npm-audit": run_npm_audit_scan,
    "safety": run_safety_scan,
    "snyk": run_snyk_scan,
    "sonarqube": run_sonarqube_scan,
    "spotbugs": run_spotbugs_scan,
}


_RUNTIME_RUNNERS = {
    "nuclei": run_nuclei_runtime_scan,
    "nikto": run_nikto_runtime_scan,
    "nmap": run_nmap_runtime_scan,
    "zap-baseline": run_zap_baseline_runtime_scan,
    "amass": run_amass_runtime_scan,
    "ffuf": run_ffuf_runtime_scan,
    "kube-bench": run_kube_bench_runtime_scan,
    "kube-hunter": run_kube_hunter_runtime_scan,
    "sqlmap": run_sqlmap_runtime_scan,
    "wapiti": run_wapiti_runtime_scan,
}
