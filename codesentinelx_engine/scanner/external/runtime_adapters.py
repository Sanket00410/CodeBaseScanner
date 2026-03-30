from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
import urllib.request
from urllib.parse import urlparse

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import extract_cwe, run_command, safe_json_loads, to_severity

BUILTIN_RUNTIME_COMPAT_COMMAND = "builtin-runtime-compat"


def run_nuclei_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "nuclei",
    target_urls: list[str] | None = None,
) -> tuple[list[Finding], list[str]]:
    normalized_targets = [str(item).strip() for item in (target_urls or []) if str(item).strip()]
    if not normalized_targets:
        normalized_targets = [target_url]
    normalized_targets = list(dict.fromkeys(normalized_targets))

    max_targets_raw = os.getenv("USS_RUNTIME_NUCLEI_MAX_TARGETS", "80").strip()
    try:
        max_targets = max(1, int(max_targets_raw))
    except Exception:
        max_targets = 80
    normalized_targets = normalized_targets[:max_targets]

    adaptive_timeout = timeout_seconds
    min_timeout_raw = os.getenv("USS_RUNTIME_NUCLEI_TIMEOUT_SECONDS", "600").strip()
    try:
        min_timeout = max(120, int(min_timeout_raw))
    except Exception:
        min_timeout = 600
    adaptive_timeout = max(adaptive_timeout, min(min_timeout + (len(normalized_targets) * 5), 1800))

    with tempfile.TemporaryDirectory(prefix="nuclei_targets_") as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        targets_file = temp_dir / "targets.txt"
        targets_file.write_text("\n".join(normalized_targets), encoding="utf-8")

        if _is_docker_binary(binary):
            command = [
                binary,
                "run",
                "--rm",
                "-v",
                _docker_volume_arg(temp_dir, "/scan"),
                "projectdiscovery/nuclei:latest",
                "-l",
                "/scan/targets.txt",
                "-jsonl",
                "-silent",
                "-no-color",
            ]
        else:
            command = [binary, "-l", str(targets_file), "-jsonl", "-silent", "-no-color"]
        for header in _runtime_http_headers_from_env():
            command.extend(["-H", header])
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=adaptive_timeout)
        except FileNotFoundError:
            return [], ["Nuclei not found in PATH."]
        except Exception as exc:
            return [], [f"Nuclei execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join(stderr.strip().splitlines()[:2])
        return [], [f"Nuclei returned code {return_code}: {short_error}"]

    findings: list[Finding] = []
    for line in stdout.splitlines():
        record = safe_json_loads(line.strip())
        if not isinstance(record, dict):
            continue
        info = record.get("info") or {}
        template_id = str(record.get("template-id") or record.get("templateID") or "unknown")
        severity = to_severity(str(info.get("severity") or "medium"))
        name = str(info.get("name") or template_id or "Nuclei Finding")
        description = str(info.get("description") or "Nuclei template matched target endpoint.")
        classification = info.get("classification") or {}
        cwe = extract_cwe(classification.get("cwe-id")) or extract_cwe(classification.get("cwe"))
        cve = str(classification.get("cve-id") or "")
        reference = ""
        refs = info.get("reference") or []
        if isinstance(refs, list) and refs:
            reference = str(refs[0])
        if not reference and cve:
            reference = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if not reference:
            reference = "https://nuclei.projectdiscovery.io/"

        findings.append(
            Finding(
                vulnerability_type="Runtime Vulnerability (Nuclei)",
                severity=severity,
                file_path=str(record.get("matched-at") or target_url),
                line_number=1,
                business_impact="Runtime endpoint matched a known vulnerability or exposure pattern.",
                recommendation="Validate finding context, patch affected component, and harden exposed endpoint.",
                reference=reference,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=name,
                rule_id=f"NUCLEI-{template_id}",
                cwe=cwe or "CWE-16",
                evidence=f"{description[:180]} | targets={len(normalized_targets)}",
            )
        )
    return findings, []


def run_nmap_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "nmap",
) -> tuple[list[Finding], list[str]]:
    if _is_builtin_compat(binary):
        return _run_builtin_runtime_compat_scan(
            tool_name="nmap",
            target_url=target_url,
            default_reference="https://nmap.org/",
        )

    host = _extract_host(target_url)
    if _is_docker_binary(binary):
        command = [binary, "run", "--rm", "instrumentisto/nmap:latest", "-Pn", "-sV", "--script", "vuln", host]
    else:
        command = [binary, "-Pn", "-sV", "--script", "vuln", host]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["Nmap not found in PATH."]
    except Exception as exc:
        return [], [f"Nmap execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join(stderr.strip().splitlines()[:2])
        return [], [f"Nmap returned code {return_code}: {short_error}"]

    findings: list[Finding] = []
    current_service = ""
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        port_match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+([^\s]+)", text, flags=re.IGNORECASE)
        if port_match:
            current_service = f"{port_match.group(1)}/{port_match.group(2)} {port_match.group(3)}"
            continue
        if "VULNERABLE" in text or re.search(r"CVE-\d{4}-\d+", text, flags=re.IGNORECASE):
            cve_match = re.search(r"CVE-\d{4}-\d+", text, flags=re.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else ""
            findings.append(
                Finding(
                    vulnerability_type="Network Service Vulnerability",
                    severity=to_severity("high"),
                    file_path=target_url,
                    line_number=1,
                    business_impact="An exposed runtime service appears vulnerable to known attack vectors.",
                    recommendation="Patch service versions, reduce exposed ports, and apply segmentation controls.",
                    reference=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "https://nmap.org/nsedoc/",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=f"Nmap NSE vulnerability match on {current_service or 'service'}",
                    rule_id=f"NMAP-{(cve or 'VULN').replace('-', '_')}",
                    cwe="CWE-16",
                    evidence=text[:240],
                )
            )
    return findings, []


def run_nikto_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "nikto",
) -> tuple[list[Finding], list[str]]:
    if _is_builtin_compat(binary):
        return _run_builtin_runtime_compat_scan(
            tool_name="nikto",
            target_url=target_url,
            default_reference="https://cirt.net/Nikto2",
        )

    with tempfile.TemporaryDirectory(prefix="nikto_") as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        report_path = temp_dir / "nikto_report.json"
        if _is_docker_binary(binary):
            command = [
                binary,
                "run",
                "--rm",
                "-v",
                _docker_volume_arg(temp_dir, "/scan"),
                "sullo/nikto:latest",
                "-h",
                target_url,
                "-Format",
                "json",
                "-output",
                "/scan/nikto_report.json",
            ]
        else:
            command = [binary, "-h", target_url, "-Format", "json", "-output", str(report_path)]
        try:
            return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            return [], ["Nikto not found in PATH."]
        except Exception as exc:
            return [], [f"Nikto execution failed: {exc}"]

        if return_code not in {0, 1}:
            short_error = " | ".join(stderr.strip().splitlines()[:2])
            return [], [f"Nikto returned code {return_code}: {short_error}"]

        raw = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else "{}"
        payload = safe_json_loads(raw)
        if not isinstance(payload, dict):
            return [], []

        findings: list[Finding] = []
        vulnerabilities = payload.get("vulnerabilities") or payload.get("item") or []
        if isinstance(vulnerabilities, dict):
            vulnerabilities = [vulnerabilities]

        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                continue
            uri = str(entry.get("url") or entry.get("uri") or target_url)
            message = str(entry.get("msg") or entry.get("description") or "Nikto identified a runtime issue")
            references = entry.get("references") or []
            reference = ""
            if isinstance(references, list) and references:
                reference = str(references[0])
            if not reference:
                reference = "https://cirt.net/Nikto2"

            findings.append(
                Finding(
                    vulnerability_type="Runtime Misconfiguration (Nikto)",
                    severity=to_severity(str(entry.get("severity") or "medium")),
                    file_path=uri,
                    line_number=1,
                    business_impact="Web server exposure may enable reconnaissance or direct exploitation.",
                    recommendation="Review server hardening baseline and remove exposed risky behavior.",
                    reference=reference,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=message,
                    rule_id=f"NIKTO-{str(entry.get('id') or 'FINDING')}",
                    cwe="CWE-16",
                    evidence=message[:240],
                )
            )
        return findings, []


def run_zap_baseline_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "zap-baseline.py",
) -> tuple[list[Finding], list[str]]:
    if _is_builtin_compat(binary):
        return _run_builtin_runtime_compat_scan(
            tool_name="zap-baseline",
            target_url=target_url,
            default_reference="https://www.zaproxy.org/docs/docker/baseline-scan/",
        )

    with tempfile.TemporaryDirectory(prefix="zap_") as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        report_path = temp_dir / "zap_report.json"
        if _is_docker_binary(binary):
            command = [
                binary,
                "run",
                "--rm",
                "-v",
                _docker_volume_arg(temp_dir, "/scan"),
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t",
                target_url,
                "-J",
                "/scan/zap_report.json",
                "-m",
                "3",
            ]
        else:
            command = [binary, "-t", target_url, "-J", str(report_path), "-m", "3"]
        try:
            return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            return [], ["OWASP ZAP baseline script not found in PATH."]
        except Exception as exc:
            return [], [f"OWASP ZAP baseline execution failed: {exc}"]

        if return_code not in {0, 1, 2}:
            short_error = " | ".join(stderr.strip().splitlines()[:2])
            return [], [f"OWASP ZAP baseline returned code {return_code}: {short_error}"]

        raw = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else "{}"
        payload = safe_json_loads(raw)
        if not isinstance(payload, dict):
            return [], []

        findings: list[Finding] = []
        for site in payload.get("site", []) or []:
            alerts = site.get("alerts", []) if isinstance(site, dict) else []
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                risk = str(alert.get("riskdesc") or alert.get("risk") or "medium")
                risk_token = risk.split()[0].lower()
                cwe = extract_cwe(alert.get("cweid")) or "CWE-16"
                owasp = str(alert.get("wascid") or "A05:2021 - Security Misconfiguration")
                name = str(alert.get("name") or "OWASP ZAP Alert")
                desc = str(alert.get("desc") or "ZAP baseline identified a web security issue.")
                uri = str(alert.get("url") or target_url)
                reference = str(alert.get("reference") or "https://www.zaproxy.org/docs/docker/baseline-scan/")

                findings.append(
                    Finding(
                        vulnerability_type="Runtime Web Security Finding (OWASP ZAP)",
                        severity=to_severity(risk_token),
                        file_path=uri,
                        line_number=1,
                        business_impact="Passive web security checks detected a potentially exploitable condition.",
                        recommendation=str(alert.get("solution") or "Apply remediation guidance and retest with ZAP."),
                        reference=reference,
                        owasp_category=owasp,
                        description=name,
                        rule_id=f"ZAP-{slug(name)}",
                        cwe=cwe,
                        evidence=desc[:240],
                    )
                )
        return findings, []


def _extract_host(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return target_url.split("/", 1)[0].split(":", 1)[0]


def slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_")
    return text[:64] if text else "FINDING"


def _is_docker_binary(binary: str) -> bool:
    name = Path(binary).name.lower()
    return name in {"docker", "docker.exe"}


def _is_builtin_compat(binary: str) -> bool:
    return str(binary or "").strip().lower() == BUILTIN_RUNTIME_COMPAT_COMMAND


def _docker_volume_arg(host_path: Path, container_path: str) -> str:
    resolved = str(host_path.resolve())
    if os.name == "nt":
        resolved = resolved.replace("\\", "/")
    return f"{resolved}:{container_path}"


def _normalize_runtime_target(target_url: str) -> str:
    value = (target_url or "").strip()
    if not value:
        return "http://localhost"
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"http://{value}"


def _run_builtin_runtime_compat_scan(tool_name: str, target_url: str, default_reference: str) -> tuple[list[Finding], list[str]]:
    normalized = _normalize_runtime_target(target_url)
    request_headers = {"User-Agent": "CodeSentinelX-runtime-compat/1.0"}
    for header in _runtime_http_headers_from_env():
        if ":" not in header:
            continue
        name, value = header.split(":", 1)
        request_headers[name.strip()] = value.strip()
    request = urllib.request.Request(
        normalized,
        headers=request_headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    except Exception as exc:
        return [], [f"{tool_name} compatibility probe failed: {exc}"]

    findings: list[Finding] = []
    missing_headers: list[tuple[str, str]] = [
        ("strict-transport-security", "Missing HSTS header"),
        ("content-security-policy", "Missing CSP header"),
        ("x-content-type-options", "Missing X-Content-Type-Options header"),
    ]
    for header_name, message in missing_headers:
        if header_name in headers:
            continue
        findings.append(
            Finding(
                vulnerability_type=f"Runtime Header Hardening Gap ({tool_name})",
                severity=to_severity("medium"),
                file_path=normalized,
                line_number=1,
                business_impact="Missing browser/runtime hardening headers increase exploitability.",
                recommendation="Add secure HTTP response headers at gateway/application layer and retest.",
                reference=default_reference,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=message,
                rule_id=f"{slug(tool_name.upper())}_HEADER_{slug(header_name)}",
                cwe="CWE-693",
                evidence=f"{header_name} not observed in response headers.",
            )
        )

    for noisy_header in ("server", "x-powered-by"):
        if noisy_header not in headers:
            continue
        findings.append(
            Finding(
                vulnerability_type=f"Technology Disclosure ({tool_name})",
                severity=to_severity("low"),
                file_path=normalized,
                line_number=1,
                business_impact="Server technology disclosure can aid targeted exploitation and reconnaissance.",
                recommendation="Remove or sanitize identifying response headers in production.",
                reference=default_reference,
                owasp_category="A05:2021 - Security Misconfiguration",
                description=f"Response header `{noisy_header}` discloses runtime fingerprint.",
                rule_id=f"{slug(tool_name.upper())}_DISCLOSE_{slug(noisy_header)}",
                cwe="CWE-200",
                evidence=f"{noisy_header}: {headers[noisy_header][:180]}",
            )
        )

    return findings, []


def _runtime_http_headers_from_env() -> list[str]:
    headers: list[str] = []
    token = os.getenv("USS_RUNTIME_AUTH_TOKEN", "").strip()
    cookie = os.getenv("USS_RUNTIME_AUTH_COOKIE", "").strip()
    custom_name = os.getenv("USS_RUNTIME_AUTH_HEADER_NAME", "").strip()
    custom_value = os.getenv("USS_RUNTIME_AUTH_HEADER_VALUE", "").strip()

    if token:
        headers.append(f"Authorization: Bearer {token}")
    if cookie:
        headers.append(f"Cookie: {cookie}")
    if custom_name and custom_value and re.match(r"^[A-Za-z0-9-]{1,120}$", custom_name):
        headers.append(f"{custom_name}: {custom_value}")
    return headers

