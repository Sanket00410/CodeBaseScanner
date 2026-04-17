from __future__ import annotations

import tempfile
from pathlib import Path

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import (
    extract_cwe,
    first_reference,
    iter_files,
    normalize_path,
    run_command,
    safe_json_loads,
    to_severity,
)


_SEMGRPE_CONFIG_FILENAMES = (
    ".semgrep.yml",
    ".semgrep.yaml",
    "semgrep.yml",
    "semgrep.yaml",
)


def _semgrep_fallback_config() -> Path:
    return Path(__file__).resolve().parents[2] / "resources" / "semgrep_fallback.yml"


def _discover_local_semgrep_configs(target_root: Path) -> list[str]:
    configs: list[str] = []
    seen: set[str] = set()
    for filename in _SEMGRPE_CONFIG_FILENAMES:
        candidate = target_root / filename
        if candidate.exists() and candidate.is_file():
            resolved = str(candidate.resolve())
            if resolved not in seen:
                seen.add(resolved)
                configs.append(resolved)

    semgrep_dir = target_root / ".semgrep"
    if semgrep_dir.exists() and semgrep_dir.is_dir():
        for candidate in sorted(path for path in iter_files(semgrep_dir) if path.suffix.lower() in {".yml", ".yaml"}):
            if candidate.is_file():
                resolved = str(candidate.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    configs.append(resolved)

    return configs


def _semgrep_launcher_candidates(binary: str) -> list[list[str]]:
    binary_path = Path(str(binary))
    candidates: list[list[str]] = []
    seen: set[tuple[str, str]] = set()

    def add_candidate(python_executable: Path, pysemgrep_script: Path) -> None:
        if not python_executable.exists() or not pysemgrep_script.exists():
            return
        key = (str(python_executable.resolve()), str(pysemgrep_script.resolve()))
        if key in seen:
            return
        seen.add(key)
        candidates.append([str(python_executable.resolve()), str(pysemgrep_script.resolve())])

    def add_fallback(executable: Path) -> None:
        resolved = str(executable.resolve()) if executable.exists() else str(executable)
        if (resolved, "") in seen:
            return
        seen.add((resolved, ""))
        candidates.append([resolved])

    if binary_path.name.lower().startswith("semgrep-core"):
        for parent in (binary_path.parent, *binary_path.parents):
            venv_root = parent.parent if parent.name.lower() == "scripts" else parent
            add_candidate(
                venv_root / "python.exe",
                venv_root / "Lib" / "site-packages" / "semgrep" / "console_scripts" / "pysemgrep.py",
            )
            add_candidate(
                venv_root / "Scripts" / "python.exe",
                venv_root / "Lib" / "site-packages" / "semgrep" / "console_scripts" / "pysemgrep.py",
            )
        if not candidates:
            add_fallback(binary_path)
        return candidates

    for parent in (binary_path.parent, *binary_path.parents):
        venv_root = parent.parent if parent.name.lower() == "scripts" else parent
        add_candidate(
            venv_root / "python.exe",
            venv_root / "Lib" / "site-packages" / "semgrep" / "console_scripts" / "pysemgrep.py",
        )
        add_candidate(
            venv_root / "Scripts" / "python.exe",
            venv_root / "Lib" / "site-packages" / "semgrep" / "console_scripts" / "pysemgrep.py",
        )

    add_fallback(binary_path)
    return candidates


def _read_semgrep_payload(stdout: str, output_path: Path | None) -> dict | None:
    if output_path and output_path.exists():
        payload = safe_json_loads(output_path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(payload, dict):
            return payload
    payload = safe_json_loads(stdout)
    if isinstance(payload, dict):
        return payload
    return None


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
    fallback_config = _semgrep_fallback_config()
    local_configs = _discover_local_semgrep_configs(target_root)
    config_sets: list[list[str]] = []
    registry_configs = ["--config", "auto"]
    for config_path in local_configs:
        registry_configs.extend(["--config", config_path])
    config_sets.append(registry_configs)
    if fallback_config.exists():
        config_sets.append(["--config", str(fallback_config)])

    for prefix in _semgrep_launcher_candidates(binary):
        for config_args in config_sets:
            output_path: Path | None = None
            if prefix and "pysemgrep.py" in prefix[-1].lower():
                handle = tempfile.NamedTemporaryFile(delete=False, suffix=".codesentinelx-semgrep.json")
                handle.close()
                output_path = Path(handle.name)
            command = [*prefix, "scan", *config_args, "--json"]
            if output_path is not None:
                command.extend(["--output", str(output_path)])
            command.extend(["--disable-version-check", str(target_root)])
            try:
                return_code, stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
            except FileNotFoundError:
                last_error = "Semgrep executable was not found."
                continue
            except Exception as exc:
                last_error = f"Semgrep execution failed: {exc}"
                continue

            payload = _read_semgrep_payload(stdout, output_path)
            if output_path is not None:
                try:
                    output_path.unlink(missing_ok=True)
                except Exception:
                    pass

            if isinstance(payload, dict) and return_code in {0, 1}:
                return parse_semgrep_output(payload, target_root), []

            short_stderr = " | ".join(stderr.strip().splitlines()[:3])
            if return_code not in {0, 1}:
                last_error = f"Semgrep returned code {return_code}: {short_stderr}".strip()
            else:
                last_error = f"Semgrep did not produce JSON output. {short_stderr}".strip()
            continue

    if last_error:
        return [], [last_error]
    return [], ["Semgrep not found in PATH/toolchain. Install Semgrep for broad multi-language rule coverage."]

