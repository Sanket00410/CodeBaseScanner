from __future__ import annotations

import tempfile
from pathlib import Path

from universal_security_scanner.models import Finding
from universal_security_scanner.scanner.external.common import extract_cwe, normalize_path, run_command, safe_json_loads, to_severity


LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".rb": "ruby",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
}

INTERPRETED_LANGUAGES = {"python", "javascript", "ruby"}

QUERY_SUITES = {
    "python": [
        "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
        "codeql/python-queries:codeql-suites/python-code-scanning.qls",
        "codeql/python-queries",
    ],
    "javascript": [
        "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
        "codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls",
        "codeql/javascript-queries",
    ],
    "ruby": [
        "codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls",
        "codeql/ruby-queries:codeql-suites/ruby-code-scanning.qls",
        "codeql/ruby-queries",
    ],
}


def _detect_languages(target_root: Path) -> list[str]:
    detected: set[str] = set()
    for path in target_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", "node_modules", ".venv", "venv", "dist", "build"} for part in path.parts):
            continue
        lang = LANGUAGE_MAP.get(path.suffix.lower())
        if lang:
            detected.add(lang)
    return sorted(detected)


def _parse_sarif(raw: str, target_root: Path) -> list[Finding]:
    payload = safe_json_loads(raw)
    if not isinstance(payload, dict):
        return []

    runs = payload.get("runs", [])
    findings: list[Finding] = []

    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {item.get("id"): item for item in driver.get("rules", []) if isinstance(item, dict)}

        for result in run.get("results", []) or []:
            rule_id = str(result.get("ruleId") or "CODEQL-UNKNOWN")
            rule = rules.get(rule_id, {})

            level = str(result.get("level") or "warning")
            message = (result.get("message") or {}).get("text") or "CodeQL identified a potential vulnerability."

            locations = result.get("locations") or []
            physical = ((locations[0] if locations else {}).get("physicalLocation") or {})
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}

            file_path = normalize_path(target_root, str(artifact.get("uri") or "unknown"))
            line_number = int(region.get("startLine") or 1)

            tags = (rule.get("properties") or {}).get("tags") or []
            cwe = extract_cwe(tags)

            owasp = "Security Best Practices"
            for tag in tags:
                if isinstance(tag, str) and "owasp" in tag.lower():
                    owasp = tag
                    break

            short_description = (rule.get("shortDescription") or {}).get("text")
            if not short_description:
                short_description = "CodeQL Finding"

            recommendation = (rule.get("help") or {}).get("text") or "Review CodeQL guidance and apply secure refactoring."
            reference = str(rule.get("helpUri") or "https://codeql.github.com/docs/")

            findings.append(
                Finding(
                    vulnerability_type=str(short_description),
                    severity=to_severity(level),
                    file_path=file_path,
                    line_number=max(1, line_number),
                    business_impact=str(message),
                    recommendation=str(recommendation),
                    reference=reference,
                    owasp_category=owasp,
                    description=str(message),
                    rule_id=f"CODEQL-{rule_id}",
                    cwe=cwe,
                    evidence=str(message)[:240],
                )
            )

    return findings


def _download_query_pack(binary: str, language: str, timeout_seconds: int) -> tuple[bool, str]:
    pack_name = f"codeql/{language}-queries"
    command = [binary, "pack", "download", pack_name]
    try:
        code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return False, f"CodeQL query pack download failed ({language}): {exc}"
    if code != 0:
        short_error = " | ".join(stderr.strip().splitlines()[:2])
        return False, f"CodeQL query pack download failed ({language}): {short_error}"
    return True, f"Downloaded query pack {pack_name}"


def run_codeql_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "codeql",
) -> tuple[list[Finding], list[str]]:
    languages = _detect_languages(target_root)
    if not languages:
        return [], ["CodeQL skipped: no supported source language detected."]

    selected = [lang for lang in languages if lang in INTERPRETED_LANGUAGES]
    if not selected:
        return [], [
            "CodeQL skipped: detected languages require build-specific CodeQL configuration; "
            "supported in this mode: python/javascript/ruby."
        ]

    findings: list[Finding] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="codeql_db_") as db_root:
        root = Path(db_root)

        for lang in selected:
            db_dir = root / f"db_{lang}"
            sarif_path = root / f"results_{lang}.sarif"

            create_cmd = [
                binary,
                "database",
                "create",
                str(db_dir),
                f"--language={lang}",
                f"--source-root={target_root}",
                "--overwrite",
                "--quiet",
            ]

            try:
                create_code, _create_stdout, create_stderr = run_command(create_cmd, timeout_seconds=timeout_seconds)
            except FileNotFoundError:
                return [], ["CodeQL CLI not found in PATH. Enable auto bootstrap or install CodeQL CLI."]
            except Exception as exc:
                errors.append(f"CodeQL database create failed ({lang}): {exc}")
                continue

            if create_code != 0:
                short_stderr = create_stderr.strip().splitlines()[:2]
                errors.append(f"CodeQL database create failed ({lang}): {' | '.join(short_stderr)}")
                continue

            downloaded, download_message = _download_query_pack(binary, lang, timeout_seconds)
            if not downloaded:
                errors.append(download_message)

            suites = QUERY_SUITES.get(lang, [f"codeql/{lang}-queries"])
            analyze_errors: list[str] = []
            analyze_success = False
            for suite in suites:
                analyze_cmd = [
                    binary,
                    "database",
                    "analyze",
                    str(db_dir),
                    suite,
                    "--format=sarif-latest",
                    f"--output={sarif_path}",
                    "--quiet",
                ]
                try:
                    analyze_code, _analyze_stdout, analyze_stderr = run_command(analyze_cmd, timeout_seconds=timeout_seconds)
                except Exception as exc:
                    analyze_errors.append(f"{suite}: {exc}")
                    continue

                if analyze_code == 0:
                    analyze_success = True
                    break

                short_stderr = " | ".join(analyze_stderr.strip().splitlines()[:2])
                analyze_errors.append(f"{suite}: {short_stderr}")

            if not analyze_success:
                joined = " || ".join(analyze_errors[:3])
                errors.append(f"CodeQL analyze failed ({lang}): {joined}")
                continue

            if not sarif_path.exists():
                errors.append(f"CodeQL analyze produced no SARIF output for {lang}.")
                continue

            raw = sarif_path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(_parse_sarif(raw, target_root))

    return findings, errors
