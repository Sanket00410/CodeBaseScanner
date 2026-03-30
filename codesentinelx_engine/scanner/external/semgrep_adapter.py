from __future__ import annotations

from pathlib import Path

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import (
    extract_cwe,
    first_reference,
    normalize_path,
    run_command,
    safe_json_loads,
    to_severity,
)


def _semgrep_command_candidates(binary: str, target_root: Path) -> list[list[str]]:
    binary_path = Path(str(binary))
    candidates: list[list[str]] = []

    if binary_path.name.lower().startswith("semgrep-core"):
        seen_semgrep: set[str] = set()
        for parent in (binary_path.parent, *binary_path.parents):
            for sibling in (
                parent / "semgrep.exe",
                parent / "semgrep.cmd",
                parent / "semgrep",
                parent / "pysemgrep.exe",
                parent / "pysemgrep.cmd",
                parent / "pysemgrep",
                parent / "Scripts" / "semgrep.exe",
                parent / "Scripts" / "semgrep.cmd",
                parent / "Scripts" / "pysemgrep.exe",
                parent / "Scripts" / "pysemgrep.cmd",
            ):
                if sibling.exists() and sibling.is_file():
                    resolved = str(sibling.resolve())
                    if resolved not in seen_semgrep:
                        candidates.append(
                            [
                                resolved,
                                "scan",
                                "--config",
                                "auto",
                                "--json",
                                "--quiet",
                                "--disable-version-check",
                                str(target_root),
                            ]
                        )
                        seen_semgrep.add(resolved)

            python_candidate = parent / "Scripts" / "python.exe"
            if python_candidate.exists() and python_candidate.is_file():
                candidates.append(
                    [
                        str(python_candidate.resolve()),
                        "-m",
                        "semgrep.__main__",
                        "scan",
                        "--config",
                        "auto",
                        "--json",
                        "--quiet",
                        "--disable-version-check",
                        str(target_root),
                    ]
                )

    if not binary_path.name.lower().startswith("semgrep-core"):
        candidates.append(
            [binary, "scan", "--config", "auto", "--json", "--quiet", "--disable-version-check", str(target_root)]
        )
    return candidates


def parse_semgrep_output(data: dict, target_root: Path) -> list[Finding]:
    findings: list[Finding] = []

    for result in data.get("results", []):
        check_id = str(result.get("check_id", "unknown"))
        path = normalize_path(target_root, str(result.get("path", "unknown")))
        start = result.get("start") or {}
        line_number = int(start.get("line") or 1)

        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}

        cwe = extract_cwe(metadata.get("cwe"))
        owasp_value = metadata.get("owasp")
        if isinstance(owasp_value, list) and owasp_value:
            owasp = str(owasp_value[0])
        elif isinstance(owasp_value, str) and owasp_value.strip():
            owasp = owasp_value
        else:
            owasp = "Security Best Practices"

        vuln_type = metadata.get("category")
        if isinstance(vuln_type, list) and vuln_type:
            vulnerability_type = str(vuln_type[0])
        elif isinstance(vuln_type, str) and vuln_type.strip():
            vulnerability_type = vuln_type
        else:
            vulnerability_type = "External Analyzer Finding"

        description = str(extra.get("message") or "Semgrep rule triggered")
        evidence = str(extra.get("lines") or "").strip()[:240] or None
        reference = first_reference(metadata.get("references"), f"https://semgrep.dev/r/{check_id}")

        findings.append(
            Finding(
                vulnerability_type=vulnerability_type,
                severity=to_severity(str(extra.get("severity") or "medium")),
                file_path=path,
                line_number=max(1, line_number),
                business_impact=str(
                    metadata.get("impact")
                    or "Potential exploitable code path identified by static analysis."
                ),
                recommendation=str(
                    metadata.get("fix")
                    or metadata.get("remediation")
                    or "Review the rule guidance and refactor to secure coding pattern."
                ),
                reference=reference,
                owasp_category=owasp,
                description=description,
                rule_id=f"SEMGREP-{check_id}",
                cwe=cwe,
                evidence=evidence,
            )
        )

    return findings


def run_semgrep_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "semgrep",
) -> tuple[list[Finding], list[str]]:
    last_error = ""
    for command in _semgrep_command_candidates(binary, target_root):
        try:
            return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
        except FileNotFoundError:
            last_error = "Semgrep executable was not found."
            continue
        except Exception as exc:
            last_error = f"Semgrep execution failed: {exc}"
            continue

        if return_code not in {0, 1}:
            short_stderr = " | ".join(stderr.strip().splitlines()[:2])
            last_error = f"Semgrep returned code {return_code}: {short_stderr}"
            if "unknown option '--config'" in short_stderr.lower():
                continue
            return [], [last_error]

        payload = safe_json_loads(stdout)
        if not isinstance(payload, dict):
            last_error = "Semgrep produced non-JSON output."
            continue

        return parse_semgrep_output(payload, target_root), []

    if last_error:
        return [], [last_error]
    return [], ["Semgrep not found in PATH/toolchain. Install Semgrep for broad multi-language rule coverage."]

