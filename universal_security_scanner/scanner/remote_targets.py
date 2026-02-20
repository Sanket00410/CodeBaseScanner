from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from collections import deque
import ipaddress
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import socket
import stat
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urljoin, urlparse
from urllib.request import Request, urlopen

from universal_security_scanner.config import ScannerConfig
from universal_security_scanner.models import Finding, ScanResult, SecurityControl, Severity
from universal_security_scanner.scanner.external import (
    discover_toolchain,
    external_tool_names,
    prepare_toolchain,
    run_external_runtime_tool,
    supported_runner_tools,
    tool_metadata,
)
from universal_security_scanner.scanner.engine import ProgressCallback, ScanEngine
from universal_security_scanner.scanner.scan_control import honor_pause_control


HTTP_PROBES = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger.json",
    "/openapi.json",
    "/actuator/health",
    "/actuator/env",
    "/.env",
    "/.git/config",
    "/admin",
    "/debug",
]

_STATIC_PATH_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
)


@dataclass(slots=True)
class RemoteSSHSpec:
    host: str
    username: str
    port: int
    remote_path: str
    password: str | None = None
    key_path: str | None = None

    @property
    def target_label(self) -> str:
        return f"ssh://{self.username}@{self.host}:{self.port}{self.remote_path}"


def scan_target(
    target: str,
    config: ScannerConfig,
    progress_callback: ProgressCallback | None = None,
) -> ScanResult:
    local_path = Path(target).expanduser()
    if local_path.exists() and local_path.is_dir():
        engine = ScanEngine(config)
        return engine.scan(local_path, progress_callback=progress_callback)

    if is_ssh_target(target):
        return scan_remote_ssh_target(target, config, progress_callback=progress_callback)

    if is_http_target(target):
        return scan_runtime_http_target(target, config=config, progress_callback=progress_callback)

    raise FileNotFoundError(f"Target path does not exist, and target is not a supported remote address: {target}")


def is_ssh_target(target: str) -> bool:
    parsed = urlparse(target)
    return parsed.scheme.lower() == "ssh"


def is_http_target(target: str) -> bool:
    normalized = target.strip()
    if not normalized:
        return False

    parsed = urlparse(normalized)
    if parsed.scheme.lower() in {"http", "https"}:
        return True

    if _is_ipv4_with_optional_port(normalized):
        return True

    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(/.*)?$", normalized, flags=re.IGNORECASE):
        return True
    if re.match(r"^localhost(:\d+)?(/.*)?$", normalized, flags=re.IGNORECASE):
        return True

    return False


def scan_runtime_http_target(
    target: str,
    config: ScannerConfig | None = None,
    progress_callback: ProgressCallback | None = None,
) -> ScanResult:
    if config is None:
        config = ScannerConfig.from_env()

    started = datetime.now(timezone.utc)
    normalized_base, initial_path = _normalize_http_target(target)
    findings: list[Finding] = []
    errors: list[str] = []
    controls: list[SecurityControl] = []
    responses_by_url: dict[str, dict[str, Any]] = {}
    toolchain_status: dict[str, dict[str, Any]] = {}
    discovered_candidates: set[str] = set()
    auth_context = _runtime_auth_context()

    runtime_active_tools = [tool for tool in external_tool_names(config, target_mode="runtime") if tool != "runtime_http_probe"]
    runtime_catalog_tools = [
        tool for tool in external_tool_names(config, target_mode="runtime", include_catalog=True) if tool != "runtime_http_probe"
    ]
    runtime_runner_supported = set(supported_runner_tools("runtime"))
    runtime_selected_runner_tools = [tool for tool in runtime_active_tools if tool in runtime_runner_supported]

    max_runtime_urls = _read_positive_int("USS_RUNTIME_MAX_URLS", 140)
    max_crawl_depth = _read_positive_int("USS_RUNTIME_CRAWL_DEPTH", 2)
    max_crawl_pages = _read_positive_int("USS_RUNTIME_CRAWL_MAX_PAGES", 90)

    seed_paths = set(HTTP_PROBES)
    if initial_path and initial_path != "/":
        seed_paths.add(initial_path)
        parent = str(PurePosixPath(initial_path).parent)
        if parent and parent != "." and parent != "/":
            seed_paths.add(parent if parent.startswith("/") else f"/{parent}")

    candidate_urls = _build_seed_urls(normalized_base, sorted(seed_paths))
    queued = deque((url, 0) for url in sorted(candidate_urls))
    visited: set[str] = set()

    toolchain_prepare_steps = 1 if runtime_active_tools or runtime_catalog_tools else 0
    total_steps = max(
        1,
        min(max_runtime_urls, len(candidate_urls) + max_crawl_pages) + 2 + toolchain_prepare_steps + len(runtime_selected_runner_tools),
    )
    completed_steps = 0

    if progress_callback:
        progress_callback(0.0, "runtime_discovery", normalized_base, "Starting runtime web/API discovery")

    if auth_context["enabled"]:
        controls.append(
            SecurityControl(
                control_id="CTRL-RUNTIME-AUTHENTICATED-CRAWL",
                name="Authenticated Runtime Crawl Enabled",
                category="Identity and Access",
                description="Runtime scanner used provided auth material for endpoint/API discovery.",
                status="Implemented",
                coverage_level="High",
                standard_mappings=["OWASP WSTG-ATHN", "OWASP API Top 10", "NIST AC-6"],
                evidence=[
                    {
                        "file_path": f"{normalized_base}/",
                        "line_number": 1,
                        "snippet": auth_context["summary"],
                    }
                ],
            )
        )

    while queued and len(visited) < max_runtime_urls and len(visited) < max_crawl_pages:
        honor_pause_control(
            progress_callback=progress_callback,
            progress=round((completed_steps / total_steps) * 100.0, 2),
            stage="runtime_discovery",
            current_file=normalized_base,
        )
        current_url, depth = queued.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)
        completed_steps += 1
        progress = round((completed_steps / total_steps) * 100.0, 2)
        if progress_callback:
            progress_callback(progress, "runtime_discovery", current_url, f"Discovering endpoint {len(visited)}")

        try:
            response = _http_probe_url(current_url)
            responses_by_url[current_url] = response
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"[runtime_probe] {current_url}: {exc}")
            continue

        discovered = _extract_discovered_urls(
            base_url=normalized_base,
            current_url=current_url,
            response=response,
        )
        for url in discovered:
            if len(candidate_urls) >= max_runtime_urls:
                break
            if url in candidate_urls:
                continue
            if not _same_origin(normalized_base, url):
                continue
            candidate_urls.add(url)
            discovered_candidates.add(url)
            if depth + 1 <= max_crawl_depth:
                queued.append((url, depth + 1))

    if progress_callback and discovered_candidates:
        progress_callback(
            round((completed_steps / total_steps) * 100.0, 2),
            "runtime_discovery",
            normalized_base,
            f"Discovered {len(discovered_candidates)} additional runtime/API endpoints",
        )

    path_responses = _responses_by_path(responses_by_url, normalized_base)
    root = path_responses.get("/")
    if not root:
        findings.append(
            Finding(
                vulnerability_type="Runtime Target Unreachable",
                severity=Severity.CRITICAL,
                file_path=normalized_base,
                line_number=1,
                business_impact="Runtime target was unreachable; security posture cannot be verified.",
                recommendation="Verify host reachability, DNS, routing, and service availability before scanning.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                owasp_category="A05:2021 - Security Misconfiguration",
                description="No baseline response was obtained from target root path.",
                rule_id="RUNTIME-UNREACHABLE-001",
                cwe="CWE-16",
                evidence=f"Unable to fetch {normalized_base}/",
            )
        )
    else:
        _evaluate_http_responses(normalized_base, path_responses, findings, controls)

    _evaluate_discovered_runtime_endpoints(normalized_base, responses_by_url, findings, controls)

    completed_steps += 1
    if progress_callback:
        progress_callback(round((completed_steps / total_steps) * 100.0, 2), "runtime_analysis", normalized_base, "Analyzing runtime/API probe results")

    runtime_probe_meta = tool_metadata("runtime_http_probe")
    toolchain_status["runtime_http_probe"] = {
        "name": "runtime_http_probe",
        "available": True,
        "source": "builtin",
        "message": f"Runtime probe checked {len(responses_by_url)} endpoints with {len(errors)} warning(s)",
        "command": "builtin",
        "selected": True,
        "runner_available": True,
        **runtime_probe_meta,
    }

    if runtime_active_tools or runtime_catalog_tools:
        completed_steps += 1
        if progress_callback:
            progress_callback(
                round((completed_steps / total_steps) * 100.0, 2),
                "preparing_toolchain",
                normalized_base,
                "Preparing runtime scanning toolchain",
            )

        discovered_toolchain = discover_toolchain(config, runtime_catalog_tools, Path.cwd())
        selected_toolchain = prepare_toolchain(
            config,
            runtime_active_tools,
            Path.cwd(),
            allow_bootstrap=config.auto_bootstrap_tools,
        )

        merged_tools = sorted(set(runtime_catalog_tools) | set(runtime_active_tools))
        for tool_name in merged_tools:
            discovered_status = discovered_toolchain.get(tool_name)
            selected_status = selected_toolchain.get(tool_name)
            chosen_status = selected_status or discovered_status
            metadata = tool_metadata(tool_name)

            if chosen_status:
                payload: dict[str, Any] = chosen_status.to_dict()
            else:
                payload = {
                    "name": tool_name,
                    "available": False,
                    "source": "missing",
                    "command": tool_name,
                    "message": "Tool was not evaluated for this scan profile.",
                }

            payload.update(metadata)
            payload["selected"] = tool_name in runtime_active_tools
            payload["runner_available"] = tool_name in runtime_runner_supported
            if tool_name in runtime_active_tools and tool_name in runtime_runner_supported and selected_status and not selected_status.available:
                errors.append(f"[{tool_name}] {selected_status.message}")
            if tool_name in runtime_active_tools and tool_name not in runtime_runner_supported:
                payload["message"] = "Tool discovered in catalog, but runtime finding normalization is not implemented yet."

            toolchain_status[tool_name] = payload

        for tool_name in runtime_selected_runner_tools:
            status = toolchain_status.get(tool_name, {})
            completed_steps += 1
            if progress_callback:
                progress_callback(
                    round((completed_steps / total_steps) * 100.0, 2),
                    "runtime_external",
                    normalized_base,
                    f"Running runtime analyzer: {tool_name}",
                )

            honor_pause_control(
                progress_callback=progress_callback,
                progress=round((completed_steps / total_steps) * 100.0, 2),
                stage="runtime_external",
                current_file=normalized_base,
            )

            if not bool(status.get("available", False)):
                continue

            runtime_targets = _runtime_targets_for_tooling(normalized_base, responses_by_url)
            tool_findings, tool_errors = run_external_runtime_tool(
                tool_name,
                target_url=normalized_base,
                target_urls=runtime_targets,
                config=config,
                command=str(status.get("command") or tool_name),
            )
            for error in tool_errors:
                errors.append(f"[{tool_name}] {error}")
            findings.extend(tool_findings)

    completed = datetime.now(timezone.utc)
    if progress_callback:
        progress_callback(100.0, "completed", normalized_base, "Runtime scan completed")

    return ScanResult(
        target_path=normalized_base,
        started_at=started,
        completed_at=completed,
        files_scanned=len(responses_by_url),
        findings=findings,
        errors=errors,
        existing_security_measures=controls,
        toolchain_status=toolchain_status,
    )


def scan_remote_ssh_target(
    target: str,
    config: ScannerConfig,
    progress_callback: ProgressCallback | None = None,
) -> ScanResult:
    started = datetime.now(timezone.utc)
    spec = _parse_ssh_target(target)
    errors: list[str] = []
    synced_count = 0
    temp_root = Path(tempfile.mkdtemp(prefix="uss-remote-sync-"))

    if progress_callback:
        progress_callback(0.0, "remote_connect", spec.target_label, "Connecting to remote host")

    try:
        try:
            import paramiko  # type: ignore
        except ModuleNotFoundError as exc:  # pragma: no cover - dependency branch
            raise RuntimeError(
                "SSH scanning requires 'paramiko'. Install with: pip install paramiko"
            ) from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_args: dict[str, Any] = {
            "hostname": spec.host,
            "port": spec.port,
            "username": spec.username,
            "timeout": 12,
            "banner_timeout": 12,
            "auth_timeout": 12,
        }
        if spec.key_path:
            connect_args["key_filename"] = spec.key_path
        if spec.password:
            connect_args["password"] = spec.password

        client.connect(**connect_args)
        sftp = client.open_sftp()

        remote_files = _list_remote_files(sftp, spec.remote_path, config)
        if not remote_files:
            raise RuntimeError("No eligible files found in remote target path.")

        total = len(remote_files)
        for index, (remote_file, relative_path) in enumerate(remote_files, start=1):
            honor_pause_control(
                progress_callback=progress_callback,
                progress=round((index / max(1, total)) * 35.0, 2),
                stage="remote_sync",
                current_file=relative_path,
            )
            local_file = temp_root / relative_path
            local_file.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote_file, str(local_file))
            synced_count += 1
            if progress_callback and (index == 1 or index == total or index % 10 == 0):
                mapped = round((index / total) * 35.0, 2)
                progress_callback(
                    mapped,
                    "remote_sync",
                    relative_path,
                    f"Downloaded {index}/{total} files from remote host",
                )

        sftp.close()
        client.close()

        engine = ScanEngine(config)

        def _relay(progress: float, stage: str, current_file: str | None, message: str | None) -> None:
            if not progress_callback:
                return
            mapped = round(35.0 + ((progress / 100.0) * 64.0), 2)
            remote_file = _prefix_remote_file(spec, current_file) if current_file else spec.target_label
            progress_callback(mapped, f"remote_{stage}", remote_file, message)

        scan_result = engine.scan(temp_root, progress_callback=_relay if progress_callback else None)
        scan_result.target_path = spec.target_label
        _rewrite_result_paths(scan_result, spec)
        if synced_count > 0:
            scan_result.toolchain_status["remote_ssh_sync"] = {
                "available": True,
                "source": "builtin",
                "message": f"Synchronized {synced_count} remote file(s) prior to scan",
                "command": "paramiko-sftp",
            }
        scan_result.errors.extend(errors)
        scan_result.started_at = started
        scan_result.completed_at = datetime.now(timezone.utc)

        if progress_callback:
            progress_callback(100.0, "completed", spec.target_label, "Remote SSH scan completed")

        return scan_result
    except Exception as exc:
        if progress_callback:
            progress_callback(100.0, "failed", spec.target_label, str(exc))
        raise
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _evaluate_http_responses(
    base_url: str,
    responses: dict[str, dict[str, Any]],
    findings: list[Finding],
    controls: list[SecurityControl],
) -> None:
    root = responses["/"]
    headers = root.get("headers", {})
    root_body = root.get("body", "")
    root_status = int(root.get("status", 0))

    if base_url.startswith("http://"):
        findings.append(
            Finding(
                vulnerability_type="Insecure Transport (HTTP)",
                severity=Severity.HIGH,
                file_path=f"{base_url}/",
                line_number=1,
                business_impact="Plain HTTP can expose sessions, credentials, and sensitive data in transit.",
                recommendation="Enforce HTTPS end-to-end and redirect all HTTP traffic to TLS endpoints.",
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                owasp_category="A02:2021 - Cryptographic Failures",
                description="Target responded over non-TLS transport.",
                rule_id="RUNTIME-TRANSPORT-001",
                cwe="CWE-319",
                evidence=f"Root endpoint returned HTTP {root_status} over HTTP",
            )
        )
    else:
        controls.append(
            SecurityControl(
                control_id="CTRL-TLS-ENFORCED",
                name="TLS / HTTPS in Use",
                category="Network Security",
                description="Target endpoint responded over HTTPS.",
                status="Implemented",
                coverage_level="High",
                standard_mappings=["OWASP ASVS V9", "NIST SC-8", "ISO 27001 A.13"],
                evidence=[{"file_path": f"{base_url}/", "line_number": 1, "snippet": "HTTPS endpoint responded"}],
            )
        )

    required_headers: list[tuple[str, Severity, str, str, str, str, str]] = [
        (
            "content-security-policy",
            Severity.MEDIUM,
            "Missing Content-Security-Policy Header",
            "CWE-693",
            "A05:2021 - Security Misconfiguration",
            "Missing CSP increases risk of script injection and unsafe resource loading.",
            "Set strict Content-Security-Policy tailored to allowed resources.",
        ),
        (
            "x-frame-options",
            Severity.MEDIUM,
            "Missing X-Frame-Options Header",
            "CWE-1021",
            "A05:2021 - Security Misconfiguration",
            "Missing frame restrictions can expose users to clickjacking.",
            "Set X-Frame-Options to DENY or SAMEORIGIN.",
        ),
        (
            "x-content-type-options",
            Severity.LOW,
            "Missing X-Content-Type-Options Header",
            "CWE-16",
            "A05:2021 - Security Misconfiguration",
            "Browser MIME sniffing can increase exploitability of content-type confusion attacks.",
            "Set X-Content-Type-Options to nosniff.",
        ),
        (
            "referrer-policy",
            Severity.LOW,
            "Missing Referrer-Policy Header",
            "CWE-359",
            "A01:2021 - Broken Access Control",
            "Referrer leakage may expose sensitive URLs or tokens to third-party origins.",
            "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
        ),
    ]

    for header, severity, vuln_name, cwe, owasp, impact, recommendation in required_headers:
        header_value = headers.get(header)
        if header_value:
            controls.append(
                SecurityControl(
                    control_id=f"CTRL-{header.upper().replace('-', '_')}",
                    name=f"HTTP Header Control: {header}",
                    category="Web Security Hardening",
                    description=f"Security header '{header}' is present.",
                    status="Implemented",
                    coverage_level="Medium",
                    standard_mappings=["OWASP ASVS V14", "NIST SC-7"],
                    evidence=[{"file_path": f"{base_url}/", "line_number": 1, "snippet": f"{header}: {header_value}"}],
                )
            )
        else:
            findings.append(
                Finding(
                    vulnerability_type=vuln_name,
                    severity=severity,
                    file_path=f"{base_url}/",
                    line_number=1,
                    business_impact=impact,
                    recommendation=recommendation,
                    reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    owasp_category=owasp,
                    description=f"Header '{header}' is not present in root response.",
                    rule_id=f"RUNTIME-HEADER-{header.upper().replace('-', '_')}",
                    cwe=cwe,
                    evidence=f"{header} header missing",
                )
            )

    hsts = headers.get("strict-transport-security")
    if base_url.startswith("https://"):
        if hsts:
            controls.append(
                SecurityControl(
                    control_id="CTRL-HSTS",
                    name="HSTS Enforced",
                    category="Web Security Hardening",
                    description="Strict-Transport-Security header is configured.",
                    status="Implemented",
                    coverage_level="High",
                    standard_mappings=["OWASP ASVS V9", "NIST SC-8"],
                    evidence=[{"file_path": f"{base_url}/", "line_number": 1, "snippet": f"strict-transport-security: {hsts}"}],
                )
            )
        else:
            findings.append(
                Finding(
                    vulnerability_type="Missing HSTS Header",
                    severity=Severity.MEDIUM,
                    file_path=f"{base_url}/",
                    line_number=1,
                    business_impact="Without HSTS, clients can be downgraded to insecure transport paths.",
                    recommendation="Set Strict-Transport-Security with adequate max-age and includeSubDomains.",
                    reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    description="HTTPS endpoint did not return strict-transport-security header.",
                    rule_id="RUNTIME-HEADER-HSTS-001",
                    cwe="CWE-319",
                    evidence="strict-transport-security header missing",
                )
            )

    if headers.get("access-control-allow-origin") == "*":
        allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        severity = Severity.HIGH if allow_credentials else Severity.MEDIUM
        findings.append(
            Finding(
                vulnerability_type="Overly Permissive CORS Policy",
                severity=severity,
                file_path=f"{base_url}/",
                line_number=1,
                business_impact="Overly broad CORS can expose sensitive APIs to untrusted web origins.",
                recommendation="Restrict Access-Control-Allow-Origin to explicit trusted origins and avoid wildcard with credentials.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                owasp_category="A05:2021 - Security Misconfiguration",
                description="CORS policy allows wildcard origin on root endpoint.",
                rule_id="RUNTIME-CORS-001",
                cwe="CWE-942",
                evidence=f"access-control-allow-origin=* allow-credentials={allow_credentials}",
            )
        )

    tech_banner = headers.get("server") or headers.get("x-powered-by")
    if tech_banner:
        findings.append(
            Finding(
                vulnerability_type="Technology Stack Disclosure",
                severity=Severity.LOW,
                file_path=f"{base_url}/",
                line_number=1,
                business_impact="Technology and version disclosure can help attackers target known exploits.",
                recommendation="Suppress server and framework banner headers in production.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                owasp_category="A05:2021 - Security Misconfiguration",
                description="Server banner disclosed technology details.",
                rule_id="RUNTIME-INFO-DISCLOSURE-001",
                cwe="CWE-200",
                evidence=tech_banner,
            )
        )

    if re.search(r"index of\s*/", root_body, flags=re.IGNORECASE):
        findings.append(
            Finding(
                vulnerability_type="Directory Listing Exposed",
                severity=Severity.MEDIUM,
                file_path=f"{base_url}/",
                line_number=1,
                business_impact="Directory listing may disclose sensitive files and application structure.",
                recommendation="Disable directory listing at web server and reverse proxy levels.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                owasp_category="A05:2021 - Security Misconfiguration",
                description="Root response body indicates directory listing output.",
                rule_id="RUNTIME-DIRLIST-001",
                cwe="CWE-548",
                evidence="Found 'Index of /' pattern in response body",
            )
        )

    endpoint_rules: list[tuple[str, Severity, str, str, str, str, str]] = [
        (
            "/swagger.json",
            Severity.MEDIUM,
            "Open API Schema Exposed",
            "CWE-200",
            "A05:2021 - Security Misconfiguration",
            "Public API schema exposure can reveal internal endpoints and data models.",
            "Restrict API schema endpoints to authenticated internal users or disable in production.",
        ),
        (
            "/openapi.json",
            Severity.MEDIUM,
            "Open API Schema Exposed",
            "CWE-200",
            "A05:2021 - Security Misconfiguration",
            "Public API schema exposure can reveal internal endpoints and data models.",
            "Restrict API schema endpoints to authenticated internal users or disable in production.",
        ),
        (
            "/actuator/health",
            Severity.MEDIUM,
            "Actuator Endpoint Exposed",
            "CWE-200",
            "A05:2021 - Security Misconfiguration",
            "Operational endpoints can reveal service metadata useful to attackers.",
            "Protect actuator endpoints behind authentication and network controls.",
        ),
        (
            "/actuator/env",
            Severity.HIGH,
            "Sensitive Actuator Endpoint Exposed",
            "CWE-200",
            "A05:2021 - Security Misconfiguration",
            "Environment endpoints may expose credentials and internal configuration.",
            "Disable environment actuator endpoint in production or restrict strictly.",
        ),
        (
            "/.env",
            Severity.CRITICAL,
            "Environment File Exposure",
            "CWE-200",
            "A02:2021 - Cryptographic Failures",
            "Exposed .env files can leak secrets, database credentials, and tokens.",
            "Block .env access at web server layer and rotate any exposed credentials.",
        ),
        (
            "/.git/config",
            Severity.HIGH,
            "Git Metadata Exposure",
            "CWE-200",
            "A05:2021 - Security Misconfiguration",
            "Exposed .git metadata can leak repository structure and sensitive commit data.",
            "Block .git access from public interfaces and review server routing rules.",
        ),
        (
            "/admin",
            Severity.MEDIUM,
            "Admin Endpoint Publicly Reachable",
            "CWE-284",
            "A01:2021 - Broken Access Control",
            "Publicly reachable admin surfaces increase risk of brute-force or privilege abuse attacks.",
            "Restrict admin endpoints by authentication, MFA, and network allowlists.",
        ),
        (
            "/debug",
            Severity.MEDIUM,
            "Debug Endpoint Exposed",
            "CWE-489",
            "A05:2021 - Security Misconfiguration",
            "Debug endpoints may expose stack traces and internals exploitable by attackers.",
            "Disable debug routes in production builds.",
        ),
    ]

    for endpoint, severity, vuln_name, cwe, owasp, impact, recommendation in endpoint_rules:
        response = responses.get(endpoint)
        if not response:
            continue
        if 200 <= int(response.get("status", 0)) < 300:
            findings.append(
                Finding(
                    vulnerability_type=vuln_name,
                    severity=severity,
                    file_path=f"{base_url}{endpoint}",
                    line_number=1,
                    business_impact=impact,
                    recommendation=recommendation,
                    reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    owasp_category=owasp,
                    description=f"Endpoint {endpoint} is reachable from runtime target.",
                    rule_id=f"RUNTIME-ENDPOINT-{endpoint.replace('/', '_').replace('.', '_').upper()}",
                    cwe=cwe,
                    evidence=f"HTTP {response.get('status')} at {base_url}{endpoint}",
                )
            )


def _parse_ssh_target(target: str) -> RemoteSSHSpec:
    parsed = urlparse(target)
    if parsed.scheme.lower() != "ssh":
        raise ValueError(f"Unsupported SSH target format: {target}")

    host = parsed.hostname or ""
    if not host:
        raise ValueError("SSH target must include host/IP.")

    username = parsed.username or os.getenv("USS_REMOTE_SSH_USER", "")
    if not username:
        raise ValueError("SSH target must include username (ssh://user@host/path) or USS_REMOTE_SSH_USER.")

    remote_path = parsed.path or os.getenv("USS_REMOTE_SSH_PATH", "")
    if not remote_path:
        raise ValueError("SSH target must include remote path (ssh://user@host/path).")

    query = parse_qs(parsed.query or "")
    password = (query.get("password") or [None])[0] or os.getenv("USS_REMOTE_SSH_PASSWORD")
    key_path = (query.get("key") or [None])[0] or os.getenv("USS_REMOTE_SSH_KEY_PATH")
    port = parsed.port or int(os.getenv("USS_REMOTE_SSH_PORT", "22"))

    return RemoteSSHSpec(
        host=host,
        username=username,
        port=port,
        remote_path=remote_path,
        password=password,
        key_path=key_path,
    )


def _list_remote_files(
    sftp: Any,
    base_path: str,
    config: ScannerConfig,
) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    max_size = config.max_file_size_kb * 1024
    stack = [base_path]

    while stack:
        current = stack.pop()
        for entry in sftp.listdir_attr(current):
            name = entry.filename
            remote_item = posixpath.join(current, name)
            relative = posixpath.relpath(remote_item, base_path)
            if stat.S_ISDIR(entry.st_mode):
                if name in config.exclude_dirs or name.startswith(".scanner-cache"):
                    continue
                stack.append(remote_item)
                continue

            if not _is_supported_remote_file(name, config):
                continue
            if int(entry.st_size or 0) > max_size:
                continue
            files.append((remote_item, relative))

    files.sort(key=lambda item: item[1])
    return files


def _is_supported_remote_file(file_name: str, config: ScannerConfig) -> bool:
    if file_name in config.special_files:
        return True
    suffix = PurePosixPath(file_name).suffix.lower()
    return suffix in config.include_extensions


def _rewrite_result_paths(scan_result: ScanResult, spec: RemoteSSHSpec) -> None:
    for finding in scan_result.findings:
        finding.file_path = _prefix_remote_file(spec, finding.file_path)
    for control in scan_result.existing_security_measures:
        for evidence in control.evidence:
            file_path = evidence.get("file_path")
            if isinstance(file_path, str) and file_path:
                evidence["file_path"] = _prefix_remote_file(spec, file_path)


def _prefix_remote_file(spec: RemoteSSHSpec, relative_path: str | None) -> str:
    if not relative_path:
        return spec.target_label
    normalized = str(relative_path).replace("\\", "/").lstrip("/")
    if normalized.startswith("ssh://"):
        return normalized
    quoted_parts = "/".join(quote(part) for part in normalized.split("/") if part)
    remote_root = spec.remote_path.rstrip("/")
    return f"ssh://{spec.username}@{spec.host}:{spec.port}{remote_root}/{quoted_parts}"


def _normalize_http_target(target: str) -> tuple[str, str]:
    candidate = target.strip()
    if re.match(r"^https?://", candidate, flags=re.IGNORECASE):
        parsed = urlparse(candidate)
        netloc = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if not netloc:
            raise ValueError(f"Invalid HTTP target: {target}")
        base = f"{parsed.scheme.lower()}://{netloc}"
        normalized_path = "/" if not path else (path if path.startswith("/") else f"/{path}")
        return base.rstrip("/"), normalized_path.rstrip("/") or "/"

    if _is_ipv4_with_optional_port(candidate) or re.match(
        r"^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(/.*)?$",
        candidate,
        flags=re.IGNORECASE,
    ):
        parsed = urlparse(f"http://{candidate.rstrip('/')}")
        base = f"http://{parsed.netloc or parsed.path}"
        normalized_path = parsed.path or "/"
        return base.rstrip("/"), normalized_path.rstrip("/") or "/"
    if re.match(r"^localhost(:\d+)?(/.*)?$", candidate, flags=re.IGNORECASE):
        parsed = urlparse(f"http://{candidate.rstrip('/')}")
        base = f"http://{parsed.netloc or parsed.path}"
        normalized_path = parsed.path or "/"
        return base.rstrip("/"), normalized_path.rstrip("/") or "/"

    raise ValueError(f"Unsupported HTTP target: {target}")


def _is_ipv4_with_optional_port(value: str) -> bool:
    raw = value.strip()
    host_part = raw.split("/", 1)[0]
    host, _, port = host_part.partition(":")
    try:
        ipaddress.IPv4Address(host)
    except Exception:
        return False
    if port and not port.isdigit():
        return False
    return True


def _http_probe(base_url: str, endpoint: str) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{endpoint}"
    return _http_probe_url(url)


def _http_probe_url(url: str) -> dict[str, Any]:
    request = Request(url, method="GET", headers=_runtime_request_headers())
    timeout_seconds = float(os.getenv("USS_REMOTE_HTTP_TIMEOUT_SECONDS", "6"))

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(8192).decode("utf-8", errors="ignore")
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {
                "status": int(response.status),
                "headers": headers,
                "body": body,
                "url": url,
            }
    except HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {}
        body = ""
        try:
            body = exc.read(8192).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {
            "status": int(exc.code),
            "headers": headers,
            "body": body,
            "url": url,
        }
    except (URLError, socket.timeout) as exc:
        raise RuntimeError(f"HTTP probe failed for {url}: {exc}") from exc


def _runtime_request_headers() -> dict[str, str]:
    headers: dict[str, str] = {
        "User-Agent": "CodeSentinelX-RemoteProbe/1.0",
    }
    context = _runtime_auth_context()
    for name, value in context["headers"].items():
        headers[name] = value
    return headers


def _runtime_auth_context() -> dict[str, Any]:
    token = os.getenv("USS_RUNTIME_AUTH_TOKEN", "").strip()
    cookie = os.getenv("USS_RUNTIME_AUTH_COOKIE", "").strip()
    header_name = os.getenv("USS_RUNTIME_AUTH_HEADER_NAME", "").strip()
    header_value = os.getenv("USS_RUNTIME_AUTH_HEADER_VALUE", "").strip()

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    if header_name and header_value and re.match(r"^[A-Za-z0-9-]{1,120}$", header_name):
        headers[header_name] = header_value

    summary_parts = [
        f"token={'yes' if bool(token) else 'no'}",
        f"cookie={'yes' if bool(cookie) else 'no'}",
        f"custom_header={header_name if header_name else 'none'}",
    ]

    return {
        "enabled": bool(headers),
        "headers": headers,
        "summary": ", ".join(summary_parts),
    }


def _read_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    return value if value > 0 else default


def _build_seed_urls(base_url: str, endpoints: list[str]) -> set[str]:
    seeds: set[str] = {base_url.rstrip("/")}
    for endpoint in endpoints:
        candidate = endpoint.strip()
        if not candidate:
            continue
        if candidate.startswith("http://") or candidate.startswith("https://"):
            seeds.add(candidate.rstrip("/"))
            continue
        if not candidate.startswith("/"):
            candidate = f"/{candidate}"
        seeds.add(f"{base_url.rstrip('/')}{candidate}")
    return seeds


def _responses_by_path(responses_by_url: dict[str, dict[str, Any]], base_url: str) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    base_prefix = base_url.rstrip("/")
    for url, payload in responses_by_url.items():
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        path = parsed.path or "/"
        mapped[path] = payload
        if url == base_prefix:
            mapped["/"] = payload
    return mapped


def _extract_discovered_urls(
    *,
    base_url: str,
    current_url: str,
    response: dict[str, Any],
) -> set[str]:
    discovered: set[str] = set()
    body = str(response.get("body") or "")
    content_type = str((response.get("headers") or {}).get("content-type") or "").lower()

    for candidate in _extract_urls_from_text(body):
        normalized = _normalize_candidate_url(base_url, current_url, candidate)
        if normalized:
            discovered.add(normalized)

    if "json" in content_type:
        for candidate in _extract_openapi_urls(base_url, body):
            discovered.add(candidate)

    if "xml" in content_type and ("sitemap" in current_url or "<urlset" in body.lower()):
        for candidate in _extract_sitemap_urls(base_url, body):
            discovered.add(candidate)

    return discovered


def _extract_urls_from_text(body: str) -> set[str]:
    found: set[str] = set()
    for match in re.finditer(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", body, flags=re.IGNORECASE):
        found.add(match.group(1))
    for match in re.finditer(r"""["'](/[^"'?#\s]{1,220}(?:\?[^"'\s]{0,160})?)["']""", body):
        found.add(match.group(1))
    for match in re.finditer(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,220}""", body):
        found.add(match.group(0))
    return found


def _extract_openapi_urls(base_url: str, body: str) -> set[str]:
    urls: set[str] = set()
    try:
        import json

        payload = json.loads(body)
    except Exception:
        return urls

    if not isinstance(payload, dict):
        return urls

    paths = payload.get("paths")
    if isinstance(paths, dict):
        for key in paths.keys():
            if isinstance(key, str) and key.startswith("/"):
                urls.add(f"{base_url.rstrip('/')}{key}")
    return urls


def _extract_sitemap_urls(base_url: str, body: str) -> set[str]:
    urls: set[str] = set()
    for match in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", body, flags=re.IGNORECASE):
        candidate = match.group(1).strip()
        normalized = _normalize_candidate_url(base_url, base_url, candidate)
        if normalized:
            urls.add(normalized)
    return urls


def _normalize_candidate_url(base_url: str, current_url: str, candidate: str) -> str | None:
    raw = (candidate or "").strip()
    if not raw:
        return None
    if raw.startswith("#"):
        return None
    if raw.lower().startswith(("mailto:", "javascript:", "tel:")):
        return None

    absolute = urljoin(current_url, raw)
    if not _same_origin(base_url, absolute):
        return None

    parsed = urlparse(absolute)
    path = parsed.path or "/"
    lower_path = path.lower()
    if any(lower_path.endswith(ext) for ext in _STATIC_PATH_SUFFIXES):
        return None
    if len(path) > 240:
        return None

    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    return normalized.rstrip("/")


def _same_origin(base_url: str, candidate_url: str) -> bool:
    try:
        base = urlparse(base_url)
        candidate = urlparse(candidate_url)
    except Exception:
        return False
    return (
        base.scheme.lower() == candidate.scheme.lower()
        and (base.hostname or "").lower() == (candidate.hostname or "").lower()
        and (base.port or _default_port(base.scheme)) == (candidate.port or _default_port(candidate.scheme))
    )


def _default_port(scheme: str) -> int:
    return 443 if str(scheme).lower() == "https" else 80


def _runtime_targets_for_tooling(base_url: str, responses_by_url: dict[str, dict[str, Any]]) -> list[str]:
    targets = [base_url.rstrip("/")]
    for url, response in responses_by_url.items():
        status = int(response.get("status") or 0)
        if status < 200 or status >= 500:
            continue
        path = (urlparse(url).path or "/").lower()
        if path.startswith("/api") or "graphql" in path or "swagger" in path or "openapi" in path:
            targets.append(url.rstrip("/"))
    deduped = list(dict.fromkeys(targets))
    max_targets = _read_positive_int("USS_RUNTIME_TOOL_TARGET_LIMIT", 80)
    return deduped[:max_targets]


def _evaluate_discovered_runtime_endpoints(
    base_url: str,
    responses_by_url: dict[str, dict[str, Any]],
    findings: list[Finding],
    controls: list[SecurityControl],
) -> None:
    discovered_count = 0
    api_count = 0
    for url, response in responses_by_url.items():
        status = int(response.get("status") or 0)
        if status <= 0:
            continue
        discovered_count += 1

        headers = response.get("headers", {}) or {}
        content_type = str(headers.get("content-type") or "").lower()
        body = str(response.get("body") or "")
        path = urlparse(url).path or "/"
        lower_path = path.lower()

        is_api = lower_path.startswith("/api") or "graphql" in lower_path or "openapi" in lower_path or "swagger" in lower_path
        if is_api:
            api_count += 1

        if is_api and 200 <= status < 300:
            auth_header = str(headers.get("www-authenticate") or "")
            if not auth_header:
                findings.append(
                    Finding(
                        vulnerability_type="Potential Unauthenticated API Endpoint",
                        severity=Severity.MEDIUM,
                        file_path=url,
                        line_number=1,
                        business_impact="Reachable API endpoints without visible auth challenge can increase unauthorized data access risk.",
                        recommendation="Require strong authentication/authorization for sensitive API routes and validate access controls.",
                        reference="https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                        owasp_category="A01:2021 - Broken Access Control",
                        description=f"API-like endpoint responded with HTTP {status} and no WWW-Authenticate header.",
                        rule_id="RUNTIME-API-AUTH-001",
                        cwe="CWE-306",
                        evidence=f"{url} -> HTTP {status}",
                    )
                )

        if is_api and "json" in content_type and re.search(
            r'"(?:password|passwd|secret|token|api[_-]?key|authorization)"\s*:',
            body,
            flags=re.IGNORECASE,
        ):
            findings.append(
                Finding(
                    vulnerability_type="Sensitive Data Pattern in API Response",
                    severity=Severity.HIGH,
                    file_path=url,
                    line_number=1,
                    business_impact="Sensitive fields in API response payloads can expose credentials or session artifacts.",
                    recommendation="Remove sensitive fields from responses, mask secrets, and enforce least-privilege data serialization.",
                    reference="https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    description="Detected sensitive key pattern in API JSON response body.",
                    rule_id="RUNTIME-API-DATA-001",
                    cwe="CWE-200",
                    evidence=body[:240],
                )
            )

    controls.append(
        SecurityControl(
            control_id="CTRL-RUNTIME-ENDPOINT-INVENTORY",
            name="Runtime Endpoint Inventory",
            category="Runtime Attack Surface",
            description="CodeSentinelX performed endpoint and API discovery across runtime target.",
            status="Implemented",
            coverage_level="Medium" if discovered_count > 0 else "Low",
            standard_mappings=["OWASP ASVS V13", "OWASP WSTG-INFO", "NIST CA-7"],
            evidence=[
                {
                    "file_path": f"{base_url}/",
                    "line_number": 1,
                    "snippet": f"Discovered endpoints={discovered_count}, api_endpoints={api_count}",
                }
            ],
        )
    )
