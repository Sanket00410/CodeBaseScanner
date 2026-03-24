from __future__ import annotations

import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import (
    extract_cwe,
    first_reference,
    normalize_path,
    run_command,
    safe_json_loads,
    to_severity,
)


def _to_owasp_from_text(text: str) -> str:
    value = (text or "").lower()
    if any(token in value for token in ("sql", "injection", "command", "eval")):
        return "A03:2021 - Injection"
    if any(token in value for token in ("xss", "cross-site", "script")):
        return "A03:2021 - Injection"
    if any(token in value for token in ("auth", "permission", "access", "rbac", "privilege")):
        return "A01:2021 - Broken Access Control"
    if any(token in value for token in ("crypto", "cipher", "tls", "ssl", "hash")):
        return "A02:2021 - Cryptographic Failures"
    if any(token in value for token in ("dependency", "package", "vulnerab", "cve", "supply chain")):
        return "A06:2021 - Vulnerable and Outdated Components"
    if any(token in value for token in ("config", "misconfig", "hardening", "policy")):
        return "A05:2021 - Security Misconfiguration"
    return "Security Best Practices"


def _discover_files(target_root: Path, names: set[str] | None = None, suffixes: set[str] | None = None) -> list[Path]:
    names = {item.lower() for item in (names or set())}
    suffixes = {item.lower() for item in (suffixes or set())}
    matches: list[Path] = []
    for path in target_root.rglob("*"):
        if not path.is_file():
            continue
        lowered = path.name.lower()
        if names and lowered in names:
            matches.append(path)
            continue
        if suffixes and path.suffix.lower() in suffixes:
            matches.append(path)
    return sorted(matches)


def run_brakeman_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "brakeman",
) -> tuple[list[Finding], list[str]]:
    if not (target_root / "Gemfile").exists():
        return [], []

    with tempfile.NamedTemporaryFile(prefix="brakeman_", suffix=".json", delete=False) as temp_file:
        report_path = Path(temp_file.name)

    command = [binary, "-q", "-f", "json", "-o", str(report_path), str(target_root)]
    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        report_path.unlink(missing_ok=True)
        return [], ["Brakeman not found in PATH/toolchain. Install or bootstrap brakeman for Rails security scanning."]
    except Exception as exc:
        report_path.unlink(missing_ok=True)
        return [], [f"Brakeman execution failed: {exc}"]

    if return_code not in {0, 1, 3}:
        report_path.unlink(missing_ok=True)
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"Brakeman returned code {return_code}: {short_error}"]

    payload = safe_json_loads(report_path.read_text(encoding="utf-8", errors="ignore")) if report_path.exists() else None
    report_path.unlink(missing_ok=True)
    if not isinstance(payload, dict):
        return [], ["Brakeman produced non-JSON output."]

    findings: list[Finding] = []
    for warning in payload.get("warnings", []) or []:
        if not isinstance(warning, dict):
            continue
        warning_type = str(warning.get("warning_type") or "Brakeman Warning")
        confidence = str(warning.get("confidence") or "Medium").lower()
        confidence_to_severity = {
            "high": "high",
            "medium": "medium",
            "weak": "low",
        }
        severity = to_severity(confidence_to_severity.get(confidence, "medium"))
        file_path = normalize_path(target_root, str(warning.get("file") or "unknown"))
        line_number = int(warning.get("line") or 1)
        message = str(warning.get("message") or warning.get("warning_code") or warning_type)
        check_name = str(warning.get("check_name") or warning_type)

        findings.append(
            Finding(
                vulnerability_type=warning_type,
                severity=severity,
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Rails web-layer weakness may permit unauthorized actions or data compromise.",
                recommendation="Apply Brakeman remediation guidance and enforce secure Rails coding patterns.",
                reference="https://brakemanscanner.org/docs/warning_types/",
                owasp_category=_to_owasp_from_text(f"{warning_type} {message}"),
                description=message,
                rule_id=f"BRAKEMAN-{re.sub(r'[^A-Za-z0-9]+', '_', check_name).strip('_') or 'WARNING'}",
                cwe=extract_cwe([warning.get("cwe_id"), message]) or "CWE-20",
                evidence=message[:240],
            )
        )
    return findings, []


def run_cppcheck_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "cppcheck",
) -> tuple[list[Finding], list[str]]:
    native_sources = _discover_files(target_root, suffixes={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
    if not native_sources:
        return [], []

    command = [
        binary,
        "--xml",
        "--xml-version=2",
        "--enable=warning,style,performance,portability,information",
        "--inconclusive",
        str(target_root),
    ]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["Cppcheck not found in PATH/toolchain. Install or bootstrap cppcheck for native-code analysis."]
    except Exception as exc:
        return [], [f"Cppcheck execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or stdout or "").strip().splitlines()[:2])
        return [], [f"Cppcheck returned code {return_code}: {short_error}"]

    xml_text = (stderr or stdout or "").strip()
    if not xml_text:
        return [], []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [], ["Cppcheck output could not be parsed as XML."]

    severity_map = {
        "error": "high",
        "warning": "medium",
        "style": "low",
        "performance": "low",
        "portability": "medium",
        "information": "info",
    }
    findings: list[Finding] = []
    for error in root.findall(".//error"):
        severity_raw = str(error.attrib.get("severity") or "medium").lower()
        severity = to_severity(severity_map.get(severity_raw, severity_raw))
        message = str(error.attrib.get("msg") or error.attrib.get("verbose") or "Cppcheck finding")
        rule_id = str(error.attrib.get("id") or "UNKNOWN")
        cwe_attr = str(error.attrib.get("cwe") or "").strip()
        cwe = f"CWE-{cwe_attr}" if cwe_attr.isdigit() else extract_cwe(cwe_attr)

        location = error.find("location")
        if location is not None:
            raw_file = str(location.attrib.get("file") or "unknown")
            line_number = int(location.attrib.get("line") or 1)
        else:
            raw_file = "unknown"
            line_number = 1

        findings.append(
            Finding(
                vulnerability_type="Native Code Security Issue",
                severity=severity,
                file_path=normalize_path(target_root, raw_file),
                line_number=max(1, line_number),
                business_impact="Native code defect may enable memory corruption, crashes, or undefined runtime behavior.",
                recommendation="Refactor unsafe operations and enforce secure memory and bounds handling.",
                reference="https://cppcheck.sourceforge.io/manual.pdf",
                owasp_category=_to_owasp_from_text(message),
                description=message,
                rule_id=f"CPPCHECK-{rule_id}",
                cwe=cwe or "CWE-119",
                evidence=message[:240],
            )
        )
    return findings, []


def run_eslint_security_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "eslint",
) -> tuple[list[Finding], list[str]]:
    js_files = _discover_files(target_root, suffixes={".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx"})
    if not js_files:
        return [], []

    selected = [str(path) for path in js_files[:180]]
    base_rules = [
        "--plugin",
        "security",
        "--rule",
        "security/detect-eval-with-expression:error",
        "--rule",
        "security/detect-child-process:error",
        "--rule",
        "security/detect-non-literal-fs-filename:warn",
        "--rule",
        "security/detect-object-injection:warn",
    ]
    binary_candidates: list[list[str]] = []
    binary_path = Path(str(binary))
    if binary_path.exists():
        binary_candidates.append([str(binary_path)])
    else:
        tool_root = Path(__file__).resolve().parents[3] / ".toolchain" / "eslint-security"
        wrapper = tool_root / "eslint-security_embedded_wrapper.py"
        if wrapper.exists():
            binary_candidates.append([sys.executable, str(wrapper)])
        for candidate in (
            tool_root / "eslint.cmd",
            tool_root / "eslint.exe",
            tool_root / "node_modules" / ".bin" / "eslint.cmd",
            tool_root / "node_modules" / ".bin" / "eslint",
        ):
            if candidate.exists():
                binary_candidates.append([str(candidate)])
    if not binary_candidates:
        binary_candidates.append([binary])

    attempts: list[list[str]] = []
    chunk_size = 45
    selected_chunks = [selected[index : index + chunk_size] for index in range(0, len(selected), chunk_size)] or [[]]
    for prefix in binary_candidates:
        for chunk in selected_chunks:
            attempts.extend(
                [
                    [*prefix, "--no-error-on-unmatched-pattern", "--format", "json", "--no-config-lookup", *base_rules, *chunk],
                    [*prefix, "--no-error-on-unmatched-pattern", "--format", "json", "--no-eslintrc", *base_rules, *chunk],
                ]
            )

    last_error = ""
    payloads: list[dict] = []
    saw_success = False
    for command in attempts:
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            last_error = "ESLint executable was not found."
            continue
        except Exception as exc:
            last_error = str(exc)
            continue

        if return_code in {0, 1}:
            saw_success = True
            payload = safe_json_loads(stdout)
            if isinstance(payload, list):
                payloads.extend(item for item in payload if isinstance(item, dict))
                continue
        last_error = " | ".join((stderr or stdout or "").strip().splitlines()[:2])
    if not payloads and last_error:
        return [], [f"ESLint security run failed: {last_error}"]
    if saw_success:
        return [], []
    if not payloads and not last_error:
        return [], ["ESLint not found in PATH/toolchain. Install or bootstrap eslint-security integration."]

    findings: list[Finding] = []
    for file_result in payloads:
        if not isinstance(file_result, dict):
            continue
        file_path = normalize_path(target_root, str(file_result.get("filePath") or "unknown"))
        for message in file_result.get("messages", []) or []:
            if not isinstance(message, dict):
                continue
            rule_id = str(message.get("ruleId") or "eslint-security")
            severity_num = int(message.get("severity") or 1)
            severity = to_severity("high" if severity_num >= 2 else "medium")
            text = str(message.get("message") or "ESLint security rule triggered")
            line_number = int(message.get("line") or 1)
            findings.append(
                Finding(
                    vulnerability_type="JavaScript Security Anti-pattern",
                    severity=severity,
                    file_path=file_path,
                    line_number=max(1, line_number),
                    business_impact="JavaScript runtime behavior may be exploitable through unsafe APIs or untrusted input handling.",
                    recommendation="Apply secure ESLint rule guidance and validate user-controlled data before sink usage.",
                    reference="https://github.com/eslint-community/eslint-plugin-security",
                    owasp_category=_to_owasp_from_text(text),
                    description=text,
                    rule_id=f"ESLINT-SECURITY-{rule_id}",
                    cwe=extract_cwe(text) or "CWE-20",
                    evidence=text[:240],
                )
            )
    return findings, []


def _discover_bytecode_artifacts(target_root: Path) -> list[str]:
    artifacts = _discover_files(target_root, suffixes={".class", ".jar", ".war", ".ear"})
    return [str(path) for path in artifacts[:400]]


def _parse_spotbugs_like_xml(xml_payload: str, target_root: Path, prefix: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_payload)
    except ET.ParseError:
        return findings

    for bug in root.findall(".//BugInstance"):
        bug_type = str(bug.attrib.get("type") or "BUG")
        priority = int(bug.attrib.get("priority") or 3)
        if priority <= 1:
            sev = to_severity("high")
        elif priority == 2:
            sev = to_severity("medium")
        else:
            sev = to_severity("low")

        short_message = (bug.findtext("ShortMessage") or bug.findtext("LongMessage") or bug_type).strip()
        source_line = bug.find(".//SourceLine")
        if source_line is not None:
            raw_file = str(source_line.attrib.get("sourcepath") or source_line.attrib.get("sourcefile") or "unknown")
            line_number = int(source_line.attrib.get("start") or 1)
        else:
            raw_file = "unknown"
            line_number = 1

        findings.append(
            Finding(
                vulnerability_type="JVM Security Finding",
                severity=sev,
                file_path=normalize_path(target_root, raw_file),
                line_number=max(1, line_number),
                business_impact="Bytecode-level weakness may expose exploitable JVM security defects.",
                recommendation="Refactor vulnerable patterns and re-run JVM security analyzers after rebuild.",
                reference="https://spotbugs.readthedocs.io/",
                owasp_category=_to_owasp_from_text(short_message),
                description=short_message,
                rule_id=f"{prefix}-{bug_type}",
                cwe=extract_cwe(short_message) or "CWE-20",
                evidence=short_message[:240],
            )
        )
    return findings


def run_spotbugs_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "spotbugs",
) -> tuple[list[Finding], list[str]]:
    artifacts = _discover_bytecode_artifacts(target_root)
    if not artifacts:
        return [], []

    with tempfile.NamedTemporaryFile(prefix="spotbugs_", suffix=".xml", delete=False) as temp_file:
        report_path = Path(temp_file.name)

    command = [binary, "-textui", "-xml:withMessages", "-output", str(report_path), *artifacts]
    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        report_path.unlink(missing_ok=True)
        return [], ["SpotBugs not found in PATH/toolchain. Install or bootstrap spotbugs for JVM static analysis."]
    except Exception as exc:
        report_path.unlink(missing_ok=True)
        return [], [f"SpotBugs execution failed: {exc}"]

    if return_code not in {0, 1}:
        report_path.unlink(missing_ok=True)
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"SpotBugs returned code {return_code}: {short_error}"]

    payload = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else ""
    report_path.unlink(missing_ok=True)
    return _parse_spotbugs_like_xml(payload, target_root, "SPOTBUGS"), []


def run_findsecbugs_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "findsecbugs",
) -> tuple[list[Finding], list[str]]:
    artifacts = _discover_bytecode_artifacts(target_root)
    if not artifacts:
        return [], []

    with tempfile.NamedTemporaryFile(prefix="findsecbugs_", suffix=".xml", delete=False) as temp_file:
        report_path = Path(temp_file.name)

    command = [binary, "-textui", "-xml:withMessages", "-output", str(report_path), *artifacts]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        report_path.unlink(missing_ok=True)
        return [], ["FindSecBugs not found in PATH/toolchain. Install or bootstrap findsecbugs for JVM security analysis."]
    except Exception as exc:
        report_path.unlink(missing_ok=True)
        return [], [f"FindSecBugs execution failed: {exc}"]

    if return_code not in {0, 1} and not report_path.exists():
        short_error = " | ".join((stderr or stdout or "").strip().splitlines()[:2])
        report_path.unlink(missing_ok=True)
        return [], [f"FindSecBugs returned code {return_code}: {short_error}"]

    payload = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else (stdout or "")
    report_path.unlink(missing_ok=True)
    findings = _parse_spotbugs_like_xml(payload, target_root, "FINDSECBUGS")
    if not findings and "Unknown option" in (stderr or ""):
        return [], ["FindSecBugs command options were incompatible with installed binary wrapper."]
    return findings, []


def run_flawfinder_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "flawfinder",
) -> tuple[list[Finding], list[str]]:
    native_sources = _discover_files(target_root, suffixes={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
    if not native_sources:
        return [], []

    command = [binary, "--dataonly", "--quiet", str(target_root)]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["Flawfinder not found in PATH/toolchain. Install or bootstrap flawfinder for C/C++ risky API checks."]
    except Exception as exc:
        return [], [f"Flawfinder execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"Flawfinder returned code {return_code}: {short_error}"]

    findings: list[Finding] = []
    pattern = re.compile(r"^(.*?):(\d+):\s*\[(\d+)\]\s*\(([^)]+)\)\s*(.+)$")
    for line in (stdout or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        raw_file, raw_line, raw_level, category, message = match.groups()
        level = int(raw_level)
        if level >= 5:
            sev = to_severity("critical")
        elif level >= 4:
            sev = to_severity("high")
        elif level >= 3:
            sev = to_severity("medium")
        elif level >= 2:
            sev = to_severity("low")
        else:
            sev = to_severity("info")
        findings.append(
            Finding(
                vulnerability_type=f"Native Risky API Usage ({category})",
                severity=sev,
                file_path=normalize_path(target_root, raw_file),
                line_number=max(1, int(raw_line)),
                business_impact="Potentially unsafe native API usage can expose memory corruption or injection paths.",
                recommendation="Replace insecure APIs with safer alternatives and validate boundary conditions.",
                reference="https://dwheeler.com/flawfinder/",
                owasp_category=_to_owasp_from_text(f"{category} {message}"),
                description=message,
                rule_id=f"FLAWFINDER-{level}",
                cwe=extract_cwe(message) or "CWE-676",
                evidence=message[:240],
            )
        )
    return findings, []


def run_govulncheck_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "govulncheck",
) -> tuple[list[Finding], list[str]]:
    go_files = _discover_files(target_root, suffixes={".go"})
    if not go_files:
        return [], []

    command = [binary, "-json", "./..."]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds, cwd=target_root)
    except FileNotFoundError:
        return [], ["govulncheck not found in PATH/toolchain. Install or bootstrap govulncheck for Go vulnerability reachability."]
    except Exception as exc:
        return [], [f"govulncheck execution failed: {exc}"]

    if return_code not in {0, 1, 3}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"govulncheck returned code {return_code}: {short_error}"]

    osv_by_id: dict[str, dict[str, Any]] = {}
    findings: list[Finding] = []
    errors: list[str] = []
    for line in (stdout or "").splitlines():
        record = safe_json_loads(line)
        if not isinstance(record, dict):
            continue
        if "osv" in record and isinstance(record.get("osv"), dict):
            osv = record["osv"]
            osv_by_id[str(osv.get("id") or "")] = osv
            continue
        if "finding" in record and isinstance(record.get("finding"), dict):
            finding = record["finding"]
            osv_id = str(finding.get("osv") or "")
            osv = osv_by_id.get(osv_id, {})
            trace = finding.get("trace") or []
            raw_file = "go.mod"
            line_number = 1
            if isinstance(trace, list) and trace:
                for step in trace:
                    if not isinstance(step, dict):
                        continue
                    pos = step.get("position") or {}
                    if not isinstance(pos, dict):
                        continue
                    candidate = str(pos.get("filename") or "")
                    if candidate:
                        raw_file = candidate
                        line_number = int(pos.get("line") or 1)
                        break
            aliases = osv.get("aliases") if isinstance(osv, dict) else []
            if not isinstance(aliases, list):
                aliases = []
            severity = to_severity("high" if any(str(item).upper().startswith("CVE-") for item in aliases) else "medium")
            reference = f"https://pkg.go.dev/vuln/{osv_id}" if osv_id else "https://pkg.go.dev/vuln/"
            description = str(osv.get("summary") or osv.get("details") or f"Go vulnerability {osv_id or 'finding'}")
            findings.append(
                Finding(
                    vulnerability_type="Go Reachable Vulnerability",
                    severity=severity,
                    file_path=normalize_path(target_root, raw_file),
                    line_number=max(1, line_number),
                    business_impact="Reachable vulnerable Go package/function can expose real exploit paths in runtime.",
                    recommendation="Upgrade vulnerable modules and remove vulnerable call paths identified by reachability analysis.",
                    reference=reference,
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=description,
                    rule_id=f"GOVULNCHECK-{osv_id or 'FINDING'}",
                    cwe=extract_cwe(aliases) or "CWE-1104",
                    evidence=description[:240],
                )
            )
    for line in (stderr or "").splitlines():
        lower = line.lower()
        if "error" in lower or "failed" in lower:
            errors.append(line.strip())
    return findings, errors


def run_infer_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "infer",
) -> tuple[list[Finding], list[str]]:
    del timeout_seconds, binary  # ingestion-based adapter
    report_candidates = [
        target_root / "infer-out" / "report.json",
        target_root / ".infer" / "report.json",
    ]
    report_path = next((item for item in report_candidates if item.exists()), None)
    if not report_path:
        return [], []

    payload = safe_json_loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(payload, list):
        return [], []

    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        bug_type = str(item.get("bug_type") or "Infer Finding")
        message = str(item.get("qualifier") or bug_type)
        line_number = int(item.get("line") or 1)
        file_path = normalize_path(target_root, str(item.get("file") or "unknown"))
        findings.append(
            Finding(
                vulnerability_type="Advanced Static Analysis Finding",
                severity=to_severity(str(item.get("severity") or "medium")),
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Interprocedural analysis identified a defect with potential security impact.",
                recommendation="Review Infer report context and fix root-cause code path before release.",
                reference="https://fbinfer.com/docs/checker-overview",
                owasp_category=_to_owasp_from_text(message),
                description=message,
                rule_id=f"INFER-{bug_type}",
                cwe=extract_cwe(message) or "CWE-20",
                evidence=message[:240],
            )
        )
    return findings, []


def run_npm_audit_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "npm",
) -> tuple[list[Finding], list[str]]:
    package_json = target_root / "package.json"
    if not package_json.exists():
        return [], []

    command = [binary, "audit", "--json", "--audit-level=low", "--prefix", str(target_root)]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        return [], ["npm not found in PATH. Install Node/npm for npm-audit dependency vulnerability checks."]
    except Exception as exc:
        return [], [f"npm audit execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:2])
        return [], [f"npm audit returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["npm audit produced non-JSON output."]

    vulnerabilities = payload.get("vulnerabilities") or {}
    if not isinstance(vulnerabilities, dict):
        return [], []

    findings: list[Finding] = []
    dedupe: set[tuple[str, str]] = set()
    for package_name, meta in vulnerabilities.items():
        if not isinstance(meta, dict):
            continue
        package_severity = to_severity(str(meta.get("severity") or "medium"))
        via_entries = meta.get("via") or []
        if not isinstance(via_entries, list):
            via_entries = [via_entries]
        for entry in via_entries:
            vuln_id = ""
            message = ""
            reference = "https://docs.npmjs.com/cli/v10/commands/npm-audit"
            cwe = "CWE-1104"
            severity = package_severity
            if isinstance(entry, str):
                message = entry
                vuln_id = re.sub(r"[^A-Za-z0-9]+", "_", entry).strip("_")[:64] or "ADVISORY"
            elif isinstance(entry, dict):
                message = str(entry.get("title") or entry.get("name") or entry.get("url") or "npm advisory")
                vuln_id = str(entry.get("source") or entry.get("name") or "ADVISORY")
                reference = str(entry.get("url") or reference)
                cwe = extract_cwe(entry.get("cwe")) or cwe
                sev_raw = str(entry.get("severity") or "")
                if sev_raw:
                    severity = to_severity(sev_raw)
            key = (package_name, vuln_id)
            if key in dedupe:
                continue
            dedupe.add(key)
            findings.append(
                Finding(
                    vulnerability_type="JavaScript Dependency Vulnerability",
                    severity=severity,
                    file_path="package.json",
                    line_number=1,
                    business_impact="Vulnerable npm dependency can expose known exploit vectors in application code paths.",
                    recommendation=f"Update package {package_name} to a secure version and verify lockfile integrity.",
                    reference=reference,
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=message,
                    rule_id=f"NPM-AUDIT-{vuln_id}",
                    cwe=cwe,
                    evidence=package_name,
                )
            )
    return findings, []


def run_safety_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "safety",
) -> tuple[list[Finding], list[str]]:
    requirements = _discover_files(target_root, names={"requirements.txt"}, suffixes={".txt"})
    requirements = [path for path in requirements if path.name.lower().startswith("requirements")]
    if not requirements:
        return [], []

    findings: list[Finding] = []
    errors: list[str] = []
    for req in requirements[:30]:
        attempts = [
            [binary, "check", "--json", "-r", str(req)],
            [binary, "check", "-r", str(req), "--output", "json"],
        ]
        payload: Any | None = None
        attempt_error = ""
        for command in attempts:
            try:
                return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
            except FileNotFoundError:
                return [], ["Safety not found in PATH/toolchain. Install or bootstrap safety for Python dependency checks."]
            except Exception as exc:
                attempt_error = str(exc)
                continue

            if return_code not in {0, 1}:
                attempt_error = " | ".join((stderr or "").strip().splitlines()[:2])
                continue
            payload = safe_json_loads(stdout)
            if payload is not None:
                break
            attempt_error = "Safety produced non-JSON output."

        if payload is None:
            if attempt_error:
                errors.append(f"{req.name}: {attempt_error}")
            continue

        entries: list[dict[str, Any]] = []
        if isinstance(payload, list):
            entries = [item for item in payload if isinstance(item, dict)]
        elif isinstance(payload, dict):
            vulns = payload.get("vulnerabilities") or payload.get("issues") or []
            if isinstance(vulns, list):
                entries = [item for item in vulns if isinstance(item, dict)]

        for item in entries:
            vuln_id = str(item.get("vulnerability_id") or item.get("id") or item.get("CVE") or "UNKNOWN")
            package_name = str(item.get("package_name") or item.get("package") or "dependency")
            affected = str(item.get("analyzed_version") or item.get("affected_version") or "")
            advisory = str(item.get("advisory") or item.get("description") or "Safety vulnerability advisory")
            findings.append(
                Finding(
                    vulnerability_type="Python Dependency Vulnerability",
                    severity=to_severity(str(item.get("severity") or "high")),
                    file_path=normalize_path(target_root, str(req)),
                    line_number=1,
                    business_impact="Known vulnerable Python dependency may expose exploit paths in application runtime.",
                    recommendation=f"Upgrade {package_name} to a safe version and verify transitive dependency chain.",
                    reference=f"https://pyup.io/v/{vuln_id}",
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=advisory,
                    rule_id=f"SAFETY-{vuln_id}",
                    cwe=extract_cwe([advisory, vuln_id]) or "CWE-1104",
                    evidence=f"{package_name} {affected}".strip(),
                )
            )
    return findings, errors


def run_snyk_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "snyk",
) -> tuple[list[Finding], list[str]]:
    manifest_names = {
        "package.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "go.mod",
        "cargo.toml",
        "gemfile",
    }
    manifests = _discover_files(target_root, names=manifest_names)
    if not manifests:
        return [], []

    command = [binary, "test", "--json", "--all-projects"]
    try:
        return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds, cwd=target_root)
    except FileNotFoundError:
        return [], ["Snyk CLI not found in PATH/toolchain. Install or bootstrap snyk for dependency/app vulnerability checks."]
    except Exception as exc:
        return [], [f"Snyk execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"Snyk returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if payload is None:
        return [], ["Snyk produced non-JSON output."]

    documents: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        documents = [payload]
    elif isinstance(payload, list):
        documents = [item for item in payload if isinstance(item, dict)]

    findings: list[Finding] = []
    for doc in documents:
        target_file = str(doc.get("displayTargetFile") or doc.get("targetFile") or "dependency-manifest")
        vulnerabilities = doc.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id") or "UNKNOWN")
            title = str(vuln.get("title") or f"Snyk vulnerability {vuln_id}")
            identifiers = vuln.get("identifiers") or {}
            cwes = identifiers.get("CWE") if isinstance(identifiers, dict) else None
            cve = ""
            if isinstance(identifiers, dict):
                cves = identifiers.get("CVE") or []
                if isinstance(cves, list) and cves:
                    cve = str(cves[0])
            reference = f"https://security.snyk.io/vuln/{vuln_id}"
            if cve:
                reference = f"https://nvd.nist.gov/vuln/detail/{cve}"
            findings.append(
                Finding(
                    vulnerability_type="Dependency Vulnerability",
                    severity=to_severity(str(vuln.get("severity") or "medium")),
                    file_path=normalize_path(target_root, target_file),
                    line_number=1,
                    business_impact="Snyk identified a known vulnerability that can impact production security posture.",
                    recommendation=str(vuln.get("remediation") or "Upgrade vulnerable package or apply vendor patch guidance."),
                    reference=reference,
                    owasp_category="A06:2021 - Vulnerable and Outdated Components",
                    description=title,
                    rule_id=f"SNYK-{vuln_id}",
                    cwe=extract_cwe(cwes) or "CWE-1104",
                    evidence=str(vuln.get("packageName") or vuln.get("name") or "")[:240] or None,
                )
            )
    return findings, []


def run_sonarqube_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "sonar-scanner",
) -> tuple[list[Finding], list[str]]:
    del timeout_seconds, binary  # ingestion-first adapter
    report_candidates = [
        target_root / "sonarqube-report.json",
        target_root / "sonar-report.json",
        target_root / "sonar_issues.json",
        target_root / "issues.json",
    ]
    report_path = next((item for item in report_candidates if item.exists()), None)
    if not report_path:
        return [], []

    payload = safe_json_loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    if payload is None:
        return [], []
    issues: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        raw_issues = payload.get("issues") or payload.get("hotspots") or []
        if isinstance(raw_issues, list):
            issues = [item for item in raw_issues if isinstance(item, dict)]
    elif isinstance(payload, list):
        issues = [item for item in payload if isinstance(item, dict)]

    severity_map = {
        "blocker": "critical",
        "critical": "high",
        "major": "medium",
        "minor": "low",
        "info": "info",
    }
    findings: list[Finding] = []
    for issue in issues:
        severity_raw = str(issue.get("severity") or "major").lower()
        severity = to_severity(severity_map.get(severity_raw, severity_raw))
        component = str(issue.get("component") or "source")
        if ":" in component:
            component = component.split(":", 1)[1]
        message = str(issue.get("message") or issue.get("rule") or "SonarQube issue")
        rule_id = str(issue.get("rule") or "SONAR")
        line_number = int(issue.get("line") or 1)
        findings.append(
            Finding(
                vulnerability_type="Static Code Analysis Finding",
                severity=severity,
                file_path=normalize_path(target_root, component),
                line_number=max(1, line_number),
                business_impact="Static analyzer identified a code weakness that can weaken security controls.",
                recommendation="Apply Sonar remediation guidance and enforce secure quality gates in CI.",
                reference=f"https://rules.sonarsource.com/",
                owasp_category=_to_owasp_from_text(message),
                description=message,
                rule_id=f"SONAR-{rule_id}",
                cwe=extract_cwe(message) or "CWE-20",
                evidence=message[:240],
            )
        )
    return findings, []


def run_clair_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "clairctl",
) -> tuple[list[Finding], list[str]]:
    del timeout_seconds, binary  # report ingestion adapter
    report_candidates = [
        target_root / "clair-report.json",
        target_root / "clair_report.json",
        target_root / "clair-results.json",
    ]
    report_path = next((item for item in report_candidates if item.exists()), None)
    if not report_path:
        return [], []

    payload = safe_json_loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    if payload is None:
        return [], []

    findings: list[Finding] = []
    entries: list[dict[str, Any]] = []
    if isinstance(payload, list):
        entries = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        vulns = payload.get("vulnerabilities") or payload.get("features") or []
        if isinstance(vulns, list):
            entries = [item for item in vulns if isinstance(item, dict)]

    for item in entries:
        name = str(item.get("Name") or item.get("name") or item.get("vulnerability") or "UNKNOWN")
        description = str(item.get("Description") or item.get("description") or "Container vulnerability advisory.")
        severity = to_severity(str(item.get("Severity") or item.get("severity") or "medium"))
        links = item.get("Links") or item.get("links") or []
        reference = first_reference(links, "https://quay.github.io/clair/")
        findings.append(
            Finding(
                vulnerability_type="Container Vulnerability",
                severity=severity,
                file_path="container-image",
                line_number=1,
                business_impact="Vulnerable container layer/package can be exploited in deployed environments.",
                recommendation="Patch base image and vulnerable packages, then rebuild and redeploy image.",
                reference=reference,
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                description=description,
                rule_id=f"CLAIR-{name}",
                cwe=extract_cwe(description) or "CWE-1104",
                evidence=str(item.get("Package") or item.get("featureName") or "")[:240] or None,
            )
        )
    return findings, []
