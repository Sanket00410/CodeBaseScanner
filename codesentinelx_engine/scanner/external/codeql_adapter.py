from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import extract_cwe, normalize_path, run_command, safe_json_loads, to_severity


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
        "python/ql/src/codeql-suites/python-security-and-quality.qls",
        "python/ql/src/codeql-suites/python-code-scanning.qls",
    ],
    "javascript": [
        "javascript/ql/src/codeql-suites/javascript-security-and-quality.qls",
        "javascript/ql/src/codeql-suites/javascript-code-scanning.qls",
    ],
    "ruby": [
        "ruby/ql/src/codeql-suites/ruby-security-and-quality.qls",
        "ruby/ql/src/codeql-suites/ruby-code-scanning.qls",
    ],
}

CODEQL_PACK_SPECS = {
    "python": ("codeql/python-queries",),
    "javascript": ("codeql/javascript-queries",),
    "ruby": ("codeql/ruby-queries",),
}


def _auto_codeql_search_path(binary: str, explicit_search_path: str) -> str:
    if explicit_search_path.strip():
        return explicit_search_path.strip()
    binary_path = Path(binary)
    if not binary_path.is_absolute():
        return ""
    candidates: list[Path] = []
    tool_root = binary_path.parent.parent  # .../.toolchain/codeql
    candidates.append(tool_root / "packs")
    candidates.append(tool_root / "codeql-repo")
    candidates.append(tool_root / "codeql-main")
    candidates.append(binary_path.parent)  # .../.toolchain/codeql/codeql
    valid = [str(path) for path in candidates if path.exists()]
    if not valid:
        return ""
    return os.pathsep.join(valid)


def _candidate_query_suites(search_path: str, language: str) -> list[str]:
    if not search_path.strip():
        return []

    candidates: list[str] = []
    seen: set[str] = set()
    for root_text in search_path.split(os.pathsep):
        root = Path(root_text).expanduser()
        if not root.exists():
            continue
        for relative in QUERY_SUITES.get(language, []):
            suite_path = root / relative
            if suite_path.exists():
                resolved = str(suite_path.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    candidates.append(resolved)
        for suite_name in QUERY_SUITES.get(language, []):
            alt = root / "codeql" / f"{language}-queries" / "codeql-suites" / Path(suite_name).name
            if alt.exists():
                resolved = str(alt.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    candidates.append(resolved)
        for suite_name in QUERY_SUITES.get(language, []):
            for discovered in root.rglob(Path(suite_name).name):
                if discovered.is_file():
                    resolved = str(discovered.resolve())
                    if resolved not in seen:
                        seen.add(resolved)
                        candidates.append(resolved)
    return candidates


def _codeql_pack_root(binary: str) -> Path | None:
    binary_path = Path(binary)
    if not binary_path.is_absolute():
        return None
    return binary_path.parent.parent / "packs"


def _bootstrap_codeql_packs(
    binary: str,
    target_languages: list[str],
    *,
    search_path: str,
    timeout_seconds: int,
) -> tuple[bool, str]:
    pack_root = _codeql_pack_root(binary)
    if pack_root is None:
        return False, "CodeQL pack bootstrap skipped: binary path is not absolute."

    if any(_candidate_query_suites(search_path, language) for language in target_languages):
        return True, "CodeQL packs already available in the configured search path."

    mirror_path_value = str(os.getenv("USS_CODEQL_PACK_MIRROR") or os.getenv("CODEQL_PACK_MIRROR") or "").strip()
    if mirror_path_value:
        mirror_path = Path(mirror_path_value)
        if mirror_path.exists() and mirror_path.is_dir():
            try:
                pack_root.mkdir(parents=True, exist_ok=True)
                for item in mirror_path.iterdir():
                    destination = pack_root / item.name
                    if item.is_dir():
                        shutil.copytree(item, destination, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, destination)
                return True, f"Copied CodeQL packs from local mirror: {mirror_path}"
            except Exception as exc:
                return False, f"CodeQL local mirror bootstrap failed: {exc}"

    auto_bootstrap = str(os.getenv("USS_AUTO_BOOTSTRAP_TOOLS") or "").strip().lower() in {"1", "true", "yes", "on"}
    if not auto_bootstrap:
        return False, "CodeQL pack bootstrap skipped: auto bootstrap is disabled and no local mirror was configured."

    specs: list[str] = []
    seen_specs: set[str] = set()
    for language in target_languages:
        for spec in CODEQL_PACK_SPECS.get(language, ()):
            if spec not in seen_specs:
                seen_specs.add(spec)
                specs.append(spec)
    if not specs:
        return False, "CodeQL pack bootstrap skipped: no supported query packs map to the detected languages."

    command = [binary, "pack", "download", "-d", str(pack_root)]
    if search_path.strip():
        command.extend(["--search-path", search_path])
    command.append("--")
    command.extend(specs)

    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return False, f"CodeQL pack bootstrap failed: {exc}"

    if return_code != 0:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return False, f"CodeQL pack bootstrap failed: {short_error}"

    if not any(_candidate_query_suites(search_path, language) for language in target_languages):
        return False, "CodeQL pack bootstrap completed, but query suites were still not discoverable in the search path."

    return True, f"Bootstrapped CodeQL query packs into {pack_root}"


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
    explicit_search_path = str(os.getenv("USS_CODEQL_SEARCH_PATH") or os.getenv("CODEQL_SEARCH_PATH") or "").strip()
    search_path = _auto_codeql_search_path(binary, explicit_search_path)

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

            suites = _candidate_query_suites(search_path, lang)
            if not suites:
                bootstrapped, bootstrap_message = _bootstrap_codeql_packs(
                    binary,
                    [lang],
                    search_path=search_path,
                    timeout_seconds=timeout_seconds,
                )
                if bootstrapped:
                    search_path = _auto_codeql_search_path(binary, explicit_search_path)
                    suites = _candidate_query_suites(search_path, lang)
                    if not suites:
                        errors.append(
                            f"CodeQL skipped: query packs for {lang} were still not discoverable after bootstrap. "
                            f"{bootstrap_message}"
                        )
                        continue
                else:
                    errors.append(
                        f"CodeQL skipped: query packs for {lang} were not found in the configured search path. "
                        f"{bootstrap_message} Install the matching CodeQL packs or point USS_CODEQL_SEARCH_PATH to a pack repository before rerunning."
                    )
                    continue
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
                if search_path:
                    analyze_cmd.insert(4, f"--search-path={search_path}")
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

