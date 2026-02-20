from __future__ import annotations

import ipaddress
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import safe_json_loads, run_command, to_severity


def _normalize_runtime_target(target_url: str) -> str:
    value = (target_url or "").strip()
    if not value:
        return "http://localhost"
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"http://{value}"


def _extract_host(target_url: str) -> str:
    normalized = _normalize_runtime_target(target_url)
    parsed = urlparse(normalized)
    return parsed.hostname or normalized


def _is_ip_or_localhost(host: str) -> bool:
    candidate = (host or "").strip().lower()
    if candidate in {"localhost", "127.0.0.1"}:
        return True
    try:
        ipaddress.ip_address(candidate)
        return True
    except Exception:
        return False


def _looks_like_kubernetes_target(target_url: str) -> bool:
    normalized = _normalize_runtime_target(target_url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = (parsed.path or "").lower()
    if any(token in host for token in ("k8s", "kube", "cluster", "eks", "aks", "gke")):
        return True
    if port in {443, 6443, 10250, 10255, 2379, 2380}:
        return True
    if any(token in path for token in ("k8s", "kube", "cluster")):
        return True
    return False


def run_amass_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "amass",
) -> tuple[list[Finding], list[str]]:
    host = _extract_host(target_url)
    if _is_ip_or_localhost(host):
        return [], []

    with tempfile.NamedTemporaryFile(prefix="amass_", suffix=".json", delete=False) as temp_file:
        output_path = Path(temp_file.name)

    command = [binary, "enum", "-passive", "-d", host, "-json", str(output_path)]
    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        output_path.unlink(missing_ok=True)
        return [], ["Amass not found in PATH/toolchain. Install or bootstrap amass for asset exposure discovery."]
    except Exception as exc:
        output_path.unlink(missing_ok=True)
        return [], [f"Amass execution failed: {exc}"]

    if return_code not in {0, 1}:
        output_path.unlink(missing_ok=True)
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"Amass returned code {return_code}: {short_error}"]

    findings: list[Finding] = []
    if output_path.exists():
        for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            record = safe_json_loads(line)
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "").strip()
            if not name:
                continue
            findings.append(
                Finding(
                    vulnerability_type="Exposed Asset Discovery",
                    severity=to_severity("low"),
                    file_path=name,
                    line_number=1,
                    business_impact="Expanded external attack surface increases reconnaissance and targeting opportunities.",
                    recommendation="Inventory discovered assets, apply hardening, and reduce unnecessary public exposure.",
                    reference="https://owasp.org/www-project-amass/",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    description=f"Discovered externally visible asset: {name}",
                    rule_id="AMASS-ASSET-DISCOVERY",
                    cwe="CWE-200",
                    evidence=str(record.get("addresses") or "")[:240] or None,
                )
            )
            if len(findings) >= 300:
                break
    output_path.unlink(missing_ok=True)
    return findings, []


def run_ffuf_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "ffuf",
) -> tuple[list[Finding], list[str]]:
    base = _normalize_runtime_target(target_url).rstrip("/")
    with tempfile.NamedTemporaryFile(prefix="ffuf_wordlist_", suffix=".txt", delete=False) as words_file:
        words_path = Path(words_file.name)
    words_path.write_text(
        "\n".join(
            [
                "admin",
                "login",
                "api",
                "api/v1",
                "debug",
                "internal",
                ".env",
                ".git",
                "swagger",
                "openapi.json",
                "actuator",
                "actuator/health",
            ]
        ),
        encoding="utf-8",
    )
    with tempfile.NamedTemporaryFile(prefix="ffuf_", suffix=".json", delete=False) as output_file:
        output_path = Path(output_file.name)

    command = [
        binary,
        "-u",
        f"{base}/FUZZ",
        "-w",
        str(words_path),
        "-of",
        "json",
        "-o",
        str(output_path),
        "-mc",
        "all",
        "-timeout",
        "5",
        "-maxtime",
        "40",
    ]
    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=min(timeout_seconds, 240))
    except FileNotFoundError:
        words_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
        return [], ["ffuf not found in PATH/toolchain. Install or bootstrap ffuf for endpoint fuzz discovery."]
    except Exception as exc:
        words_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
        return [], [f"ffuf execution failed: {exc}"]

    words_path.unlink(missing_ok=True)
    if return_code not in {0, 1}:
        output_path.unlink(missing_ok=True)
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"ffuf returned code {return_code}: {short_error}"]

    payload = safe_json_loads(output_path.read_text(encoding="utf-8", errors="ignore")) if output_path.exists() else None
    output_path.unlink(missing_ok=True)
    if not isinstance(payload, dict):
        return [], []

    findings: list[Finding] = []
    for entry in payload.get("results", []) or []:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or base)
        status = int(entry.get("status") or 0)
        lowered = url.lower()
        severe_keywords = ("admin", "internal", "debug", ".env", ".git")
        if any(token in lowered for token in severe_keywords) and status in {200, 401, 403}:
            severity = to_severity("high")
        elif status in {200, 401, 403}:
            severity = to_severity("medium")
        else:
            severity = to_severity("low")

        findings.append(
            Finding(
                vulnerability_type="Exposed Endpoint Discovery",
                severity=severity,
                file_path=url,
                line_number=1,
                business_impact="Exposed or hidden endpoints increase attack surface and possible unauthorized access paths.",
                recommendation="Review discovered endpoints, enforce authz, and disable non-essential routes.",
                reference="https://github.com/ffuf/ffuf",
                owasp_category="A05:2021 - Security Misconfiguration",
                description=f"Endpoint discovered by ffuf with HTTP status {status}",
                rule_id=f"FFUF-{status}",
                cwe="CWE-200",
                evidence=f"length={entry.get('length')} words={entry.get('words')}",
            )
        )
    return findings, []


def run_kube_bench_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "kube-bench",
) -> tuple[list[Finding], list[str]]:
    if not _looks_like_kubernetes_target(target_url):
        return [], []

    command = [binary, "--json"]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=min(timeout_seconds, 240))
    except FileNotFoundError:
        return [], ["kube-bench not found in PATH/toolchain. Install or bootstrap kube-bench for CIS Kubernetes checks."]
    except Exception as exc:
        return [], [f"kube-bench execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"kube-bench returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], []

    findings: list[Finding] = []
    for control in payload.get("Controls", []) or []:
        if not isinstance(control, dict):
            continue
        for test in control.get("tests", []) or []:
            if not isinstance(test, dict):
                continue
            for result in test.get("results", []) or []:
                if not isinstance(result, dict):
                    continue
                status = str(result.get("status") or "").upper()
                if status not in {"FAIL", "WARN"}:
                    continue
                severity = to_severity("high" if status == "FAIL" else "medium")
                desc = str(result.get("test_desc") or result.get("test_number") or "Kubernetes benchmark issue")
                findings.append(
                    Finding(
                        vulnerability_type="Kubernetes Hardening Gap",
                        severity=severity,
                        file_path=target_url,
                        line_number=1,
                        business_impact="Kubernetes benchmark failures indicate cluster hardening weaknesses.",
                        recommendation=str(result.get("remediation") or "Apply CIS benchmark remediation and revalidate cluster posture."),
                        reference="https://github.com/aquasecurity/kube-bench",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        description=desc,
                        rule_id=f"KUBE-BENCH-{result.get('test_number') or 'TEST'}",
                        cwe="CWE-16",
                        evidence=str(result.get("audit") or "")[:240] or None,
                    )
                )
    return findings, []


def run_kube_hunter_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "kube-hunter",
) -> tuple[list[Finding], list[str]]:
    if not _looks_like_kubernetes_target(target_url):
        return [], []

    host = _extract_host(target_url)
    command = [binary, "--remote", host, "--report", "json"]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=min(timeout_seconds, 240))
    except FileNotFoundError:
        return [], ["kube-hunter not found in PATH/toolchain. Install or bootstrap kube-hunter for Kubernetes exposure checks."]
    except Exception as exc:
        return [], [f"kube-hunter execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"kube-hunter returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], []

    findings: list[Finding] = []
    for vuln in payload.get("vulnerabilities", []) or []:
        if not isinstance(vuln, dict):
            continue
        severity = to_severity(str(vuln.get("severity") or "medium"))
        desc = str(vuln.get("description") or vuln.get("vulnerability") or "Kubernetes exposure identified")
        findings.append(
            Finding(
                vulnerability_type="Kubernetes Exposure",
                severity=severity,
                file_path=target_url,
                line_number=1,
                business_impact="Exposed Kubernetes control-plane or workload weakness may enable cluster compromise.",
                recommendation="Restrict Kubernetes attack surface and apply recommended kube-hunter remediation controls.",
                reference="https://github.com/aquasecurity/kube-hunter",
                owasp_category="A05:2021 - Security Misconfiguration",
                description=desc,
                rule_id=f"KUBE-HUNTER-{vuln.get('vid') or 'VULN'}",
                cwe="CWE-284",
                evidence=str(vuln.get("location") or "")[:240] or None,
            )
        )
    return findings, []


def run_sqlmap_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "sqlmap",
) -> tuple[list[Finding], list[str]]:
    command = [
        binary,
        "-u",
        _normalize_runtime_target(target_url),
        "--batch",
        "--crawl=1",
        "--level=1",
        "--risk=1",
        "--threads=1",
        "--smart",
        "--timeout=8",
        "--retries=0",
    ]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=min(timeout_seconds, 300))
    except FileNotFoundError:
        return [], ["sqlmap not found in PATH/toolchain. Install or bootstrap sqlmap for SQL injection validation."]
    except Exception as exc:
        return [], [f"sqlmap execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"sqlmap returned code {return_code}: {short_error}"]

    combined = f"{stdout}\n{stderr}".lower()
    findings: list[Finding] = []
    if "is vulnerable" in combined or "sql injection" in combined or "injectable" in combined:
        findings.append(
            Finding(
                vulnerability_type="SQL Injection",
                severity=to_severity("critical"),
                file_path=target_url,
                line_number=1,
                business_impact="Input points may be exploitable for unauthorized database access and data exfiltration.",
                recommendation="Use parameterized queries, strict input validation, and least-privilege DB accounts.",
                reference="https://owasp.org/www-community/attacks/SQL_Injection",
                owasp_category="A03:2021 - Injection",
                description="sqlmap reported potential SQL injection behavior on tested runtime target.",
                rule_id="SQLMAP-SQLI",
                cwe="CWE-89",
                evidence="\n".join((stdout or "").splitlines()[-8:])[:240] or None,
            )
        )
    return findings, []


def run_wapiti_runtime_scan(
    target_url: str,
    timeout_seconds: int,
    binary: str = "wapiti",
) -> tuple[list[Finding], list[str]]:
    with tempfile.NamedTemporaryFile(prefix="wapiti_", suffix=".json", delete=False) as temp_file:
        output_path = Path(temp_file.name)

    attempts = [
        [binary, "-u", _normalize_runtime_target(target_url), "-f", "json", "-o", str(output_path), "--scope", "domain"],
        [binary, "-u", _normalize_runtime_target(target_url), "-f", "json", "-o", str(output_path)],
    ]
    payload = None
    last_error = ""
    for command in attempts:
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=min(timeout_seconds, 300))
        except FileNotFoundError:
            output_path.unlink(missing_ok=True)
            return [], ["Wapiti not found in PATH/toolchain. Install or bootstrap wapiti for runtime web security checks."]
        except Exception as exc:
            last_error = str(exc)
            continue
        if return_code not in {0, 1}:
            last_error = " | ".join((stderr or "").strip().splitlines()[:2])
            continue
        if output_path.exists():
            payload = safe_json_loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        if payload is None:
            payload = safe_json_loads(stdout)
        if payload is not None:
            break
    output_path.unlink(missing_ok=True)

    if payload is None:
        if last_error:
            return [], [f"Wapiti run failed: {last_error}"]
        return [], []

    findings: list[Finding] = []
    if isinstance(payload, dict):
        vulnerabilities = payload.get("vulnerabilities") or {}
        if isinstance(vulnerabilities, dict):
            for vuln_type, entries in vulnerabilities.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    target = str(entry.get("path") or entry.get("url") or target_url)
                    parameter = str(entry.get("parameter") or "")
                    message = str(entry.get("info") or entry.get("description") or vuln_type)
                    findings.append(
                        Finding(
                            vulnerability_type=f"Runtime Web Finding ({vuln_type})",
                            severity=to_severity(str(entry.get("level") or "medium")),
                            file_path=target,
                            line_number=1,
                            business_impact="Runtime web weakness may allow unauthorized data access or application abuse.",
                            recommendation="Apply input validation/output encoding and patch vulnerable web components.",
                            reference="https://wapiti-scanner.github.io/",
                            owasp_category="A03:2021 - Injection",
                            description=message,
                            rule_id=f"WAPITI-{vuln_type}",
                            cwe="CWE-20",
                            evidence=parameter[:240] or None,
                        )
                    )
    return findings, []
