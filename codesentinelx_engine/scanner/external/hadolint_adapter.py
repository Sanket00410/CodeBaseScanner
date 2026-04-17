from __future__ import annotations

from pathlib import Path

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import iter_files, normalize_path, run_command, safe_json_loads, to_severity


def _discover_dockerfiles(target_root: Path) -> list[Path]:
    matches: list[Path] = []
    for path in iter_files(target_root):
        lower_name = path.name.lower()
        if lower_name == "dockerfile" or lower_name.startswith("dockerfile.") or path.suffix.lower() == ".dockerfile":
            matches.append(path)
    return sorted(matches)


def parse_hadolint_output(data: list[dict], target_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        code = str(item.get("code") or "UNKNOWN")
        level = str(item.get("level") or "warning").lower()
        level_mapping = {
            "error": "high",
            "warning": "medium",
            "info": "low",
            "style": "info",
        }
        severity = to_severity(level_mapping.get(level, level))
        file_path = normalize_path(target_root, str(item.get("file") or "Dockerfile"))
        line_number = int(item.get("line") or 1)
        message = str(item.get("message") or f"Hadolint rule {code} triggered.")

        findings.append(
            Finding(
                vulnerability_type="Container Build Misconfiguration",
                severity=severity,
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Insecure Dockerfile directives can increase attack surface and container supply-chain risk.",
                recommendation="Update Dockerfile to satisfy secure build guidance and least-privilege runtime controls.",
                reference=f"https://github.com/hadolint/hadolint/wiki/{code}",
                owasp_category="A05:2021 - Security Misconfiguration",
                description=message,
                rule_id=f"HADOLINT-{code}",
                cwe="CWE-16",
                evidence=message[:240],
            )
        )
    return findings


def run_hadolint_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "hadolint",
) -> tuple[list[Finding], list[str]]:
    dockerfiles = _discover_dockerfiles(target_root)
    if not dockerfiles:
        return [], []

    findings: list[Finding] = []
    errors: list[str] = []
    per_file_timeout = max(30, min(timeout_seconds, 120))

    for dockerfile in dockerfiles:
        command = [binary, "-f", "json", str(dockerfile)]
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=per_file_timeout)
        except FileNotFoundError:
            return [], ["Hadolint not found in PATH/toolchain. Install or bootstrap hadolint for Dockerfile hardening checks."]
        except Exception as exc:
            errors.append(f"{dockerfile.name}: {exc}")
            continue

        if return_code not in {0, 1}:
            short_error = " | ".join((stderr or "").strip().splitlines()[:2])
            errors.append(f"{dockerfile.name}: hadolint returned code {return_code}: {short_error}")
            continue

        payload = safe_json_loads(stdout)
        if not isinstance(payload, list):
            continue
        findings.extend(parse_hadolint_output(payload, target_root))

    return findings, errors

