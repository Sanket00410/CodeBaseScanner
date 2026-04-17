from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from codesentinelx_engine.models import Finding, Severity
from codesentinelx_engine.scanner.external.common import iter_files, normalize_path, run_command, safe_json_loads, to_severity


_GITLEAKS_NOISE_SEGMENTS = {
    ".git",
    ".github",
    ".gitlab",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "third_party",
    "external",
    "deps",
    "packages",
    "bower_components",
    "pods",
    ".venv",
    "venv",
    "env",
    "virtualenv",
    "site-packages",
    "build",
    "dist",
    "target",
    "out",
    "release",
    "debug",
    "bin",
    "obj",
    "compiled",
    ".cache",
    ".parcel-cache",
    ".next",
    ".nuxt",
    ".gradle",
    ".m2",
    "coverage",
    "reports",
    "artifacts",
    "tmp",
    "temp",
    "logs",
    "docs",
    "documentation",
    "wiki",
    "guides",
    "examples",
    "samples",
    "tutorials",
    "demo",
    "fixtures",
    "testdata",
    "mocks",
    "stubs",
    "snapshots",
    "__snapshots__",
    "assets",
    "images",
    "img",
    "fonts",
    "media",
    "public",
    "static",
    "datasets",
    "data",
    "models",
    "checkpoints",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".toolchain",
}

_GITLEAKS_ALLOWED_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".swift",
    ".rs",
    ".scala",
    ".sh",
    ".ps1",
    ".psm1",
    ".cmd",
    ".bat",
    ".sql",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".xml",
    ".properties",
    ".env",
    ".tf",
    ".tfvars",
    ".dockerfile",
    ".gradle",
    ".lock",
    ".txt",
    ".md",
}

_GITLEAKS_ALLOWED_FILENAMES = {
    ".env",
    ".env.example",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".dockerconfigjson",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements.lock",
    "requirements-dev.lock",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "packages.config",
    "global.json",
    "nuget.config",
    "gemfile",
    "gemfile.lock",
    "cargo.toml",
    "cargo.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "makefile",
}


def _is_text_candidate(path: Path) -> bool:
    lower_name = path.name.lower()
    if lower_name in _GITLEAKS_ALLOWED_FILENAMES:
        return True
    if lower_name.startswith(".env"):
        return True
    suffix = path.suffix.lower()
    if suffix in _GITLEAKS_ALLOWED_SUFFIXES:
        return True
    if "." not in lower_name:
        return lower_name in {"makefile", "jenkinsfile", "procfile"}
    return False


def _should_stage_for_gitleaks(target_root: Path, candidate: Path) -> bool:
    try:
        relative = candidate.resolve().relative_to(target_root.resolve())
    except Exception:
        try:
            relative = candidate.relative_to(target_root)
        except Exception:
            relative = candidate
    parts = [part.lower() for part in relative.parts]
    if any(part in _GITLEAKS_NOISE_SEGMENTS for part in parts[:-1]):
        return False
    if any(part in {"tests", "test", "spec", "__tests__", "fixtures", "testdata", "mocks", "snapshots"} for part in parts[:-1]):
        return False
    if not _is_text_candidate(candidate):
        return False
    max_file_bytes = max(64 * 1024, int(float(os.getenv("USS_GITLEAKS_MAX_FILE_MB", "2")) * 1024 * 1024))
    try:
        if candidate.stat().st_size > max_file_bytes:
            return False
        with candidate.open("rb") as handle:
            sample = handle.read(4096)
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    return True


def _prepare_gitleaks_workspace(target_root: Path) -> tuple[Path, Path]:
    workspace_parent = None
    try:
        anchor = Path(target_root.anchor)
        if anchor.exists() and anchor.is_dir():
            workspace_parent = str(anchor)
    except OSError:
        workspace_parent = None
    workspace = Path(tempfile.mkdtemp(prefix="gl_", dir=workspace_parent))
    staged_root = workspace / "source"
    staged_root.mkdir(parents=True, exist_ok=True)
    staged_files = 0
    for candidate in iter_files(target_root):
        if not _should_stage_for_gitleaks(target_root, candidate):
            continue
        try:
            relative = candidate.resolve().relative_to(target_root.resolve())
        except Exception:
            try:
                relative = candidate.relative_to(target_root)
            except Exception:
                relative = Path(candidate.name)
        destination = staged_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            continue
        try:
            os.link(candidate, destination)
        except OSError:
            shutil.copy2(candidate, destination)
        staged_files += 1
    if staged_files == 0:
        return target_root, workspace
    return staged_root, workspace


def parse_gitleaks_output(data: list[dict], target_root: Path, scan_root: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []

    for leak in data:
        rule = str(leak.get("RuleID") or "UNKNOWN")
        description = str(leak.get("Description") or "Potential secret leaked in source code")
        raw_file = str(leak.get("File") or "unknown")
        if scan_root:
            try:
                reported_path = Path(raw_file)
                relative = reported_path.resolve().relative_to(scan_root.resolve())
                raw_file = str(target_root / relative)
            except Exception:
                pass
        file_path = normalize_path(target_root, raw_file)
        line_number = int(leak.get("StartLine") or 1)
        match = str(leak.get("Match") or leak.get("Secret") or "")[:240]

        severity_raw = str(leak.get("Severity") or "High")
        severity = to_severity(severity_raw)
        if severity == Severity.MEDIUM and severity_raw.lower() == "high":
            severity = Severity.HIGH

        findings.append(
            Finding(
                vulnerability_type="Hardcoded Secrets / Credentials",
                severity=severity,
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Leaked credentials can grant unauthorized access to production assets.",
                recommendation="Rotate exposed credential, purge history where needed, and migrate secret to vault.",
                reference="https://github.com/gitleaks/gitleaks",
                owasp_category="A02:2021 - Cryptographic Failures",
                description=description,
                rule_id=f"GITLEAKS-{rule}",
                cwe="CWE-798",
                evidence=match or None,
            )
        )

    return findings


def run_gitleaks_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "gitleaks",
) -> tuple[list[Finding], list[str]]:
    scan_root, workspace = _prepare_gitleaks_workspace(target_root)
    with tempfile.NamedTemporaryFile(prefix="gitleaks_", suffix=".json", delete=False) as temp_file:
        report_path = Path(temp_file.name)

    command = [
        binary,
        "detect",
        "--source",
        str(scan_root),
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-banner",
        "--timeout",
        str(max(60, int(timeout_seconds))),
        "--max-target-megabytes",
        str(int(os.getenv("USS_GITLEAKS_MAX_TARGET_MB", "8"))),
        "--max-archive-depth",
        str(int(os.getenv("USS_GITLEAKS_MAX_ARCHIVE_DEPTH", "0"))),
        "--max-decode-depth",
        str(int(os.getenv("USS_GITLEAKS_MAX_DECODE_DEPTH", "1"))),
    ]

    try:
        return_code, _stdout, stderr = run_command(command, timeout_seconds=timeout_seconds)
    except FileNotFoundError:
        report_path.unlink(missing_ok=True)
        shutil.rmtree(workspace, ignore_errors=True)
        return [], ["Gitleaks not found in PATH. Install Gitleaks for enterprise secret scanning coverage."]
    except Exception as exc:
        report_path.unlink(missing_ok=True)
        shutil.rmtree(workspace, ignore_errors=True)
        return [], [f"Gitleaks execution failed: {exc}"]

    if return_code not in {0, 1}:
        report_path.unlink(missing_ok=True)
        shutil.rmtree(workspace, ignore_errors=True)
        short_stderr = stderr.strip().splitlines()[:2]
        return [], [f"Gitleaks returned code {return_code}: {' | '.join(short_stderr)}"]

    raw = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else "[]"
    report_path.unlink(missing_ok=True)
    shutil.rmtree(workspace, ignore_errors=True)
    payload = safe_json_loads(raw)

    if not isinstance(payload, list):
        return [], ["Gitleaks produced non-JSON output."]

    return parse_gitleaks_output(payload, target_root, scan_root=scan_root), []

