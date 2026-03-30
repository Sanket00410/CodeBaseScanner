from __future__ import annotations

import json
import os
import platform
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlopen

from codesentinelx_engine.models import Finding
from codesentinelx_engine.scanner.external.common import extract_cwe, normalize_path, run_command, safe_json_loads, to_severity

_GO_RUNTIME_CACHE: str | None = None
_GO_RUNTIME_FAILURE: str | None = None


def parse_gosec_output(data: dict, target_root: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    golang_errors = data.get("Golang errors") or {}
    if isinstance(golang_errors, dict):
        seen: set[str] = set()
        for pkg, pkg_errors in golang_errors.items():
            if not isinstance(pkg_errors, list):
                continue
            for entry in pkg_errors:
                if not isinstance(entry, dict):
                    continue
                message = str(entry.get("error") or "").strip()
                if not message:
                    continue
                compact = f"{pkg}: {message}"
                if compact in seen:
                    continue
                seen.add(compact)
                errors.append(compact)
                if len(errors) >= 12:
                    errors.append("Additional Go package loader errors truncated.")
                    break
            if len(errors) >= 13:
                break

    for issue in data.get("Issues", []) or []:
        if not isinstance(issue, dict):
            continue
        rule_id = str(issue.get("rule_id") or "UNKNOWN")
        details = str(issue.get("details") or f"gosec rule {rule_id} triggered.")
        file_path = normalize_path(target_root, str(issue.get("file") or "unknown"))
        line_number = int(issue.get("line") or 1)
        cwe = extract_cwe([issue.get("cwe"), issue.get("details")]) or "CWE-20"

        findings.append(
            Finding(
                vulnerability_type="Go Security Anti-pattern",
                severity=to_severity(str(issue.get("severity") or "medium")),
                file_path=file_path,
                line_number=max(1, line_number),
                business_impact="Insecure Go coding pattern may create exploitable behavior in runtime paths.",
                recommendation="Refactor flagged code using secure APIs and validate untrusted data flows.",
                reference="https://github.com/securego/gosec#available-rules",
                owasp_category="A03:2021 - Injection",
                description=details,
                rule_id=f"GOSEC-{rule_id}",
                cwe=cwe,
                evidence=str(issue.get("code") or details)[:240],
            )
        )

    return findings, errors


def _contains_go_files(target_root: Path) -> bool:
    for path in target_root.rglob("*.go"):
        if path.is_file():
            return True
    return False


def _tools_dir() -> Path:
    configured = os.getenv("USS_TOOLS_DIR", "").strip()
    if configured:
        return Path(configured)
    return Path.cwd() / ".toolchain"


def _go_executable_name() -> str:
    return "go.exe" if platform.system().lower().startswith("win") else "go"


def _find_local_go_runtime() -> str | None:
    executable = _go_executable_name()
    tools_dir = _tools_dir()
    candidates = [
        tools_dir / "go-runtime" / "bin" / executable,
        tools_dir / "go-runtime" / "go" / "bin" / executable,
        tools_dir / "go" / "bin" / executable,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate.resolve())
    return None


def _platform_triplet() -> tuple[str, str]:
    os_name = platform.system().lower()
    if os_name.startswith("win"):
        os_name = "windows"
    elif os_name.startswith("darwin"):
        os_name = "darwin"
    else:
        os_name = "linux"

    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        arch = "amd64"
    return os_name, arch


def _select_go_download_asset(releases: list[dict], os_name: str, arch: str) -> tuple[str, str] | None:
    for release in releases:
        if not isinstance(release, dict):
            continue
        if not bool(release.get("stable", True)):
            continue
        files = release.get("files") or []
        if not isinstance(files, list):
            continue
        for asset in files:
            if not isinstance(asset, dict):
                continue
            if asset.get("os") != os_name:
                continue
            if asset.get("arch") != arch:
                continue
            if asset.get("kind") != "archive":
                continue
            filename = str(asset.get("filename") or "")
            if not filename:
                continue
            return f"https://go.dev/dl/{filename}", filename
    return None


def _extract_go_archive(archive_path: Path, tools_dir: Path) -> str:
    tools_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir = tools_dir / "go-runtime"

    with tempfile.TemporaryDirectory(prefix="go-runtime-") as temp_dir:
        temp_root = Path(temp_dir)
        if archive_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(temp_root)
        else:
            with tarfile.open(archive_path, "r:gz") as tar_ref:
                tar_ref.extractall(temp_root)

        extracted = temp_root / "go"
        if not extracted.exists():
            raise RuntimeError("Downloaded Go archive did not contain expected 'go' directory.")

        if runtime_dir.exists():
            shutil.rmtree(runtime_dir, ignore_errors=True)
        shutil.move(str(extracted), str(runtime_dir))

    executable = _go_executable_name()
    candidate = runtime_dir / "bin" / executable
    if candidate.exists() and candidate.is_file():
        return str(candidate.resolve())
    raise RuntimeError("Go runtime extracted but executable was not found.")


def _ensure_local_go_runtime(timeout_seconds: int) -> tuple[str | None, str | None]:
    global _GO_RUNTIME_CACHE, _GO_RUNTIME_FAILURE

    if _GO_RUNTIME_CACHE and Path(_GO_RUNTIME_CACHE).exists():
        return _GO_RUNTIME_CACHE, None
    if _GO_RUNTIME_FAILURE:
        return None, _GO_RUNTIME_FAILURE

    existing = _find_local_go_runtime()
    if existing:
        _GO_RUNTIME_CACHE = existing
        return existing, None

    os_name, arch = _platform_triplet()

    try:
        with urlopen("https://go.dev/dl/?mode=json", timeout=max(20, min(timeout_seconds, 60))) as response:
            metadata = json.loads(response.read().decode("utf-8", errors="ignore"))
        if not isinstance(metadata, list):
            raise RuntimeError("Unexpected Go release metadata format.")

        selected = _select_go_download_asset(metadata, os_name, arch)
        if not selected:
            raise RuntimeError(f"No Go binary archive found for platform {os_name}/{arch}.")

        download_url, filename = selected
        with tempfile.TemporaryDirectory(prefix="go-download-") as temp_dir:
            archive_path = Path(temp_dir) / filename
            with urlopen(download_url, timeout=max(20, min(timeout_seconds, 120))) as response:
                archive_path.write_bytes(response.read())
            runtime = _extract_go_archive(archive_path, _tools_dir())

        _GO_RUNTIME_CACHE = runtime
        return runtime, None
    except Exception as exc:  # pragma: no cover - network/platform dependent
        _GO_RUNTIME_FAILURE = f"Go runtime bootstrap failed: {exc}"
        return None, _GO_RUNTIME_FAILURE


def run_gosec_scan(
    target_root: Path,
    timeout_seconds: int,
    binary: str = "gosec",
) -> tuple[list[Finding], list[str]]:
    if not _contains_go_files(target_root):
        return [], []

    command = [binary, "-fmt=json", "./..."]
    env_overrides: dict[str, str] = {}

    if not shutil.which("go"):
        runtime_go, runtime_error = _ensure_local_go_runtime(timeout_seconds)
        if runtime_go:
            go_bin = str(Path(runtime_go).parent)
            env_overrides["PATH"] = f"{go_bin}{os.pathsep}{os.getenv('PATH', '')}"
            env_overrides["GOROOT"] = str(Path(runtime_go).parent.parent)
        elif runtime_error:
            return [], [f"gosec requires Go toolchain. {runtime_error}"]

    try:
        return_code, stdout, stderr = run_command(
            command,
            timeout_seconds=timeout_seconds,
            cwd=target_root,
            env_overrides=env_overrides or None,
        )
    except FileNotFoundError:
        return [], ["gosec not found in PATH/toolchain. Install or bootstrap gosec for Go SAST coverage."]
    except Exception as exc:
        return [], [f"gosec execution failed: {exc}"]

    if return_code not in {0, 1}:
        short_error = " | ".join((stderr or "").strip().splitlines()[:3])
        return [], [f"gosec returned code {return_code}: {short_error}"]

    payload = safe_json_loads(stdout)
    if not isinstance(payload, dict):
        return [], ["gosec produced non-JSON output."]

    return parse_gosec_output(payload, target_root)

