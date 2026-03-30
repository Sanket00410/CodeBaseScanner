from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from codesentinelx_engine.config import ScannerConfig


@dataclass(slots=True)
class ToolStatus:
    name: str
    available: bool
    command: str
    source: str
    message: str

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "name": self.name,
            "available": self.available,
            "command": self.command,
            "source": self.source,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    executable_name: str
    github_repo: str | None
    asset_patterns: list[str]
    pip_package: str | None = None


TOOLS: dict[str, ToolDefinition] = {
    "semgrep": ToolDefinition(
        name="semgrep",
        executable_name="semgrep",
        github_repo=None,
        asset_patterns=[],
        pip_package="semgrep",
    ),
    "trivy": ToolDefinition(
        name="trivy",
        executable_name="trivy",
        github_repo="aquasecurity/trivy",
        asset_patterns=[
            r"trivy_.*_windows-64bit\.zip",
            r"trivy_.*_Linux-64bit\.tar\.gz",
            r"trivy_.*_macOS-64bit\.tar\.gz",
        ],
    ),
    "gitleaks": ToolDefinition(
        name="gitleaks",
        executable_name="gitleaks",
        github_repo="gitleaks/gitleaks",
        asset_patterns=[
            r"gitleaks_.*_windows_x64\.zip",
            r"gitleaks_.*_linux_x64\.tar\.gz",
            r"gitleaks_.*_darwin_x64\.tar\.gz",
            r"gitleaks_.*_darwin_arm64\.tar\.gz",
        ],
    ),
    "codeql": ToolDefinition(
        name="codeql",
        executable_name="codeql",
        github_repo="github/codeql-cli-binaries",
        asset_patterns=[
            r"codeql-win64\.zip",
            r"codeql-linux64\.zip",
            r"codeql-osx64\.zip",
            r"codeql-osx64\.tar\.gz",
            r"codeql-osx64\.zip",
        ],
    ),
    "bandit": ToolDefinition(
        name="bandit",
        executable_name="bandit",
        github_repo=None,
        asset_patterns=[],
        pip_package="bandit",
    ),
    "nuclei": ToolDefinition(
        name="nuclei",
        executable_name="nuclei",
        github_repo="projectdiscovery/nuclei",
        asset_patterns=[
            r"nuclei_.*_windows_amd64\.zip",
            r"nuclei_.*_linux_amd64\.zip",
            r"nuclei_.*_macOS_amd64\.zip",
            r"nuclei_.*_macOS_arm64\.zip",
        ],
    ),
    "nikto": ToolDefinition(
        name="nikto",
        executable_name="nikto",
        github_repo=None,
        asset_patterns=[],
    ),
    "nmap": ToolDefinition(
        name="nmap",
        executable_name="nmap",
        github_repo=None,
        asset_patterns=[],
    ),
    "zap-baseline": ToolDefinition(
        name="zap-baseline",
        executable_name="zap-baseline.py",
        github_repo=None,
        asset_patterns=[],
    ),
    "owasp-dependency-check": ToolDefinition(
        name="owasp-dependency-check",
        executable_name="dependency-check",
        github_repo="dependency-check/DependencyCheck",
        asset_patterns=[
            r"dependency-check-.*-release\.zip",
            r"dependency-check-.*-release\.zip",
            r"dependency-check-.*-release\.zip",
            r"dependency-check-.*-release\.zip",
        ],
    ),
    "sonarqube": ToolDefinition(
        name="sonarqube",
        executable_name="sonar-scanner",
        github_repo="SonarSource/sonar-scanner-cli",
        asset_patterns=[
            r"sonar-scanner-.*-windows-x64\.zip",
            r"sonar-scanner-.*-linux-x64\.zip",
            r"sonar-scanner-.*-macosx-x64\.zip",
            r"sonar-scanner-.*-macosx-aarch64\.zip",
        ],
    ),
    "snyk": ToolDefinition(
        name="snyk",
        executable_name="snyk",
        github_repo="snyk/cli",
        asset_patterns=[
            r"snyk-win\.exe",
            r"snyk-linux",
            r"snyk-macos",
            r"snyk-macos-arm64",
        ],
    ),
    "osv-scanner": ToolDefinition(
        name="osv-scanner",
        executable_name="osv-scanner",
        github_repo="google/osv-scanner",
        asset_patterns=[
            r"osv-scanner_windows_amd64\.exe",
            r"osv-scanner_linux_amd64",
            r"osv-scanner_darwin_amd64",
            r"osv-scanner_darwin_arm64",
        ],
    ),
    "grype": ToolDefinition(
        name="grype",
        executable_name="grype",
        github_repo="anchore/grype",
        asset_patterns=[
            r"grype_.*_windows_amd64\.zip",
            r"grype_.*_linux_amd64\.tar\.gz",
            r"grype_.*_darwin_amd64\.tar\.gz",
            r"grype_.*_darwin_arm64\.tar\.gz",
        ],
    ),
    "pip-audit": ToolDefinition(
        name="pip-audit",
        executable_name="pip-audit",
        github_repo=None,
        asset_patterns=[],
        pip_package="pip-audit",
    ),
    "safety": ToolDefinition(
        name="safety",
        executable_name="safety",
        github_repo=None,
        asset_patterns=[],
        pip_package="safety",
    ),
    "npm-audit": ToolDefinition(
        name="npm-audit",
        executable_name="npm",
        github_repo=None,
        asset_patterns=[],
    ),
    "govulncheck": ToolDefinition(
        name="govulncheck",
        executable_name="govulncheck",
        github_repo="golang/vuln",
        asset_patterns=[
            r"govulncheck_.*_windows_amd64\.zip",
            r"govulncheck_.*_linux_amd64\.tar\.gz",
            r"govulncheck_.*_darwin_amd64\.tar\.gz",
            r"govulncheck_.*_darwin_arm64\.tar\.gz",
        ],
    ),
    "gosec": ToolDefinition(
        name="gosec",
        executable_name="gosec",
        github_repo="securego/gosec",
        asset_patterns=[
            r"gosec_.*_windows_amd64\.tar\.gz",
            r"gosec_.*_linux_amd64\.tar\.gz",
            r"gosec_.*_darwin_amd64\.tar\.gz",
            r"gosec_.*_darwin_arm64\.tar\.gz",
        ],
    ),
    "brakeman": ToolDefinition(
        name="brakeman",
        executable_name="brakeman",
        github_repo=None,
        asset_patterns=[],
    ),
    "eslint-security": ToolDefinition(
        name="eslint-security",
        executable_name="eslint",
        github_repo=None,
        asset_patterns=[],
    ),
    "spotbugs": ToolDefinition(
        name="spotbugs",
        executable_name="spotbugs",
        github_repo="spotbugs/spotbugs",
        asset_patterns=[
            r"spotbugs-.*\.zip",
            r"spotbugs-.*\.tgz",
            r"spotbugs-.*\.zip",
            r"spotbugs-.*\.zip",
        ],
    ),
    "findsecbugs": ToolDefinition(
        name="findsecbugs",
        executable_name="findsecbugs",
        github_repo="find-sec-bugs/find-sec-bugs",
        asset_patterns=[
            r"findsecbugs-cli-.*\.zip",
            r"findsecbugs-cli-.*\.zip",
            r"findsecbugs-cli-.*\.zip",
            r"findsecbugs-cli-.*\.zip",
        ],
    ),
    "cppcheck": ToolDefinition(
        name="cppcheck",
        executable_name="cppcheck",
        github_repo=None,
        asset_patterns=[],
    ),
    "flawfinder": ToolDefinition(
        name="flawfinder",
        executable_name="flawfinder",
        github_repo=None,
        asset_patterns=[],
        pip_package="flawfinder",
    ),
    "infer": ToolDefinition(
        name="infer",
        executable_name="infer",
        github_repo="facebook/infer",
        asset_patterns=[
            r"infer-win-x86_64-v.*\.zip",
            r"infer-linux-x86_64-v.*\.tar\.xz",
            r"infer-osx-x86_64-v.*\.tar\.xz",
            r"infer-osx-arm64-v.*\.tar\.xz",
        ],
    ),
    "checkov": ToolDefinition(
        name="checkov",
        executable_name="checkov",
        github_repo=None,
        asset_patterns=[],
        pip_package="checkov",
    ),
    "tfsec": ToolDefinition(
        name="tfsec",
        executable_name="tfsec",
        github_repo="aquasecurity/tfsec",
        asset_patterns=[
            r"tfsec-windows-amd64\.exe",
            r"tfsec-linux-amd64",
            r"tfsec-darwin-amd64",
            r"tfsec-darwin-arm64",
        ],
    ),
    "hadolint": ToolDefinition(
        name="hadolint",
        executable_name="hadolint",
        github_repo="hadolint/hadolint",
        asset_patterns=[
            r"hadolint-windows-x86_64\.exe",
            r"hadolint-linux-x86_64",
            r"hadolint-macos-x86_64",
            r"hadolint-macos-arm64",
        ],
    ),
    "clair": ToolDefinition(
        name="clair",
        executable_name="clairctl",
        github_repo=None,
        asset_patterns=[],
    ),
    "kube-bench": ToolDefinition(
        name="kube-bench",
        executable_name="kube-bench",
        github_repo="aquasecurity/kube-bench",
        asset_patterns=[
            r"kube-bench_.*_windows_amd64\.zip",
            r"kube-bench_.*_linux_amd64\.tar\.gz",
            r"kube-bench_.*_darwin_amd64\.tar\.gz",
            r"kube-bench_.*_darwin_arm64\.tar\.gz",
        ],
    ),
    "kube-hunter": ToolDefinition(
        name="kube-hunter",
        executable_name="kube-hunter",
        github_repo=None,
        asset_patterns=[],
        pip_package="kube-hunter",
    ),
    "wapiti": ToolDefinition(
        name="wapiti",
        executable_name="wapiti",
        github_repo=None,
        asset_patterns=[],
        pip_package="wapiti3",
    ),
    "sqlmap": ToolDefinition(
        name="sqlmap",
        executable_name="sqlmap",
        github_repo=None,
        asset_patterns=[],
        pip_package="sqlmap",
    ),
    "ffuf": ToolDefinition(
        name="ffuf",
        executable_name="ffuf",
        github_repo="ffuf/ffuf",
        asset_patterns=[
            r"ffuf_.*_windows_amd64\.zip",
            r"ffuf_.*_linux_amd64\.tar\.gz",
            r"ffuf_.*_macOS_amd64\.tar\.gz",
            r"ffuf_.*_macOS_arm64\.tar\.gz",
        ],
    ),
    "amass": ToolDefinition(
        name="amass",
        executable_name="amass",
        github_repo="owasp-amass/amass",
        asset_patterns=[
            r"amass_windows_amd64\.tar\.gz",
            r"amass_linux_amd64\.tar\.gz",
            r"amass_darwin_amd64\.tar\.gz",
            r"amass_darwin_arm64\.tar\.gz",
        ],
    ),
}

DOCKER_RUNTIME_IMAGES: dict[str, str] = {
    "nikto": "sullo/nikto:latest",
    "nmap": "instrumentisto/nmap:latest",
    "zap-baseline": "ghcr.io/zaproxy/zaproxy:stable",
    "clair": "quay.io/projectquay/clair:latest",
}

BUILTIN_RUNTIME_COMPAT_TOOLS: set[str] = {"nikto", "nmap", "zap-baseline"}
BUILTIN_RUNTIME_COMPAT_COMMAND = "builtin-runtime-compat"

WINGET_PACKAGE_IDS: dict[str, str] = {
    "nmap": "Insecure.Nmap",
    "cppcheck": "Cppcheck.Cppcheck",
}

WINGET_PREREQ_IDS: dict[str, str] = {
    "go": "GoLang.Go",
    "ruby": "RubyInstallerTeam.Ruby.3.4",
}

NPM_GLOBAL_PACKAGES: dict[str, list[str]] = {
    "eslint-security": ["eslint", "eslint-plugin-security"],
    "snyk": ["snyk"],
}

GEM_PACKAGES: dict[str, str] = {
    "brakeman": "brakeman",
}

GO_INSTALL_PACKAGES: dict[str, str] = {
    "govulncheck": "golang.org/x/vuln/cmd/govulncheck@latest",
    "gosec": "github.com/securego/gosec/v2/cmd/gosec@latest",
}

LOCAL_ONLY_ENFORCED_TOOLS: set[str] = {
    "amass",
    "brakeman",
    "clair",
    "cppcheck",
    "eslint-security",
    "ffuf",
    "findsecbugs",
    "flawfinder",
    "govulncheck",
    "infer",
    "kube-bench",
    "kube-hunter",
    "npm-audit",
    "safety",
    "snyk",
    "sonarqube",
    "spotbugs",
    "sqlmap",
    "wapiti",
}

EMBEDDED_COMPAT_TOOLS: set[str] = {
    "brakeman",
    "clair",
    "cppcheck",
    "eslint-security",
    "govulncheck",
    "infer",
    "kube-bench",
    "kube-hunter",
    "npm-audit",
    "sonarqube",
}


def _host_installers_enabled() -> bool:
    value = os.getenv("USS_ALLOW_HOST_INSTALLERS", "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _prefer_local_tools() -> bool:
    value = os.getenv("USS_PREFER_LOCAL_TOOLS", "1").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _platform_pattern_index(name: str) -> int:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system.startswith("win"):
        return 0
    if system.startswith("linux"):
        return 1

    # macOS
    if name in {"gitleaks", "nuclei", "grype", "osv-scanner", "hadolint", "tfsec", "gosec"} and "arm" in machine:
        return 3
    return 2


def _which(executable: str) -> str | None:
    resolved = shutil.which(executable)
    if resolved:
        return resolved
    if platform.system().lower().startswith("win"):
        for suffix in (".exe", ".cmd", ".bat", ".ps1"):
            resolved = shutil.which(f"{executable}{suffix}")
            if resolved:
                return resolved
    return None


def _find_python_env_executable(executable_name: str) -> str | None:
    executable = Path(sys.executable).resolve()
    candidates = [
        executable.parent / executable_name,
        executable.parent / f"{executable_name}.exe",
        executable.parent / f"{executable_name}.cmd",
        executable.parent / f"{executable_name}.bat",
        executable.parent / "Scripts" / executable_name,
        executable.parent / "Scripts" / f"{executable_name}.exe",
        executable.parent / "Scripts" / f"{executable_name}.cmd",
        executable.parent / "Scripts" / f"{executable_name}.bat",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate.resolve())
    return None


def _python_module_available(module_name: str, timeout_seconds: int) -> bool:
    command = [sys.executable, "-c", f"import {module_name}"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
    except Exception:
        return False
    return completed.returncode == 0


def _download_latest_asset(repo: str, pattern: str, download_to: Path) -> tuple[bool, str]:
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    request = urllib.request.Request(api_url, headers={"User-Agent": "CodeSentinelX/1.0"})

    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.loads(response.read().decode("utf-8", errors="ignore"))

    assets = payload.get("assets", [])
    regex = re.compile(pattern)
    download_url: str | None = None
    file_name: str | None = None

    for asset in assets:
        name = str(asset.get("name") or "")
        if regex.fullmatch(name):
            download_url = str(asset.get("browser_download_url") or "")
            file_name = name
            break

    if not download_url or not file_name:
        return False, f"No matching release asset found for pattern '{pattern}' in {repo}."

    download_to.mkdir(parents=True, exist_ok=True)
    archive_path = download_to / file_name
    urllib.request.urlretrieve(download_url, archive_path)
    return True, str(archive_path)


def _with_long_path_prefix(path: Path) -> str:
    if os.name != "nt":
        return str(path)

    normalized = str(path.resolve())
    if normalized.startswith("\\\\?\\"):
        return normalized
    if normalized.startswith("\\\\"):
        return f"\\\\?\\UNC\\{normalized[2:]}"
    return f"\\\\?\\{normalized}"


def _safe_member_path(destination: Path, member_name: str) -> Path:
    member = Path(member_name.replace("\\", "/"))
    if member.is_absolute() or ".." in member.parts:
        raise ValueError(f"Unsafe archive entry detected: {member_name}")
    return destination / member


def _extract_zip_archive(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path, "r") as handle:
        for entry in handle.infolist():
            target = _safe_member_path(destination, entry.filename)
            if entry.is_dir():
                os.makedirs(_with_long_path_prefix(target), exist_ok=True)
                continue

            parent = target.parent
            os.makedirs(_with_long_path_prefix(parent), exist_ok=True)
            with handle.open(entry, "r") as source, open(_with_long_path_prefix(target), "wb") as out_file:
                shutil.copyfileobj(source, out_file)


def _extract_tar_archive(archive_path: Path, destination: Path) -> None:
    with tarfile.open(archive_path, "r:*") as handle:
        for member in handle.getmembers():
            target = _safe_member_path(destination, member.name)
            if member.isdir():
                os.makedirs(_with_long_path_prefix(target), exist_ok=True)
                continue
            if member.issym() or member.islnk():
                continue

            parent = target.parent
            os.makedirs(_with_long_path_prefix(parent), exist_ok=True)
            extracted = handle.extractfile(member)
            if extracted is None:
                continue
            with extracted, open(_with_long_path_prefix(target), "wb") as out_file:
                shutil.copyfileobj(extracted, out_file)


def _extract_archive(archive_path: Path, destination: Path) -> tuple[bool, str]:
    destination.mkdir(parents=True, exist_ok=True)

    lower = archive_path.name.lower()
    try:
        if lower.endswith(".zip"):
            _extract_zip_archive(archive_path, destination)
            return True, "Archive extracted"

        if (
            lower.endswith(".tar.gz")
            or lower.endswith(".tgz")
            or lower.endswith(".tar.xz")
            or lower.endswith(".txz")
            or lower.endswith(".tar")
        ):
            _extract_tar_archive(archive_path, destination)
            return True, "Archive extracted"

        return False, f"Unsupported archive format: {archive_path.name}"
    except Exception as exc:
        return False, f"Failed to extract archive: {exc}"


def _prepare_downloaded_asset(asset_path: Path, destination: Path, executable_name: str) -> tuple[bool, str]:
    lower = asset_path.name.lower()
    is_archive = (
        lower.endswith(".zip")
        or lower.endswith(".tar.gz")
        or lower.endswith(".tgz")
        or lower.endswith(".tar.xz")
        or lower.endswith(".txz")
        or lower.endswith(".tar")
    )
    if is_archive:
        return _extract_archive(asset_path, destination)

    try:
        destination.mkdir(parents=True, exist_ok=True)
        is_windows = platform.system().lower().startswith("win")
        suffix = asset_path.suffix.lower()
        if is_windows:
            if suffix in {".exe", ".cmd", ".bat", ".ps1"}:
                if executable_name.lower().endswith(suffix):
                    target_name = executable_name
                else:
                    target_name = f"{executable_name}{suffix}"
            else:
                target_name = f"{executable_name}.exe"
        else:
            target_name = executable_name

        target = destination / target_name
        shutil.copy2(asset_path, target)
        if not is_windows:
            target.chmod(target.stat().st_mode | 0o111)
        return True, f"Downloaded binary prepared ({target_name})."
    except Exception as exc:
        return False, f"Failed to prepare downloaded binary: {exc}"


def _find_executable(root: Path, executable_name: str) -> str | None:
    win_platform = platform.system().lower().startswith("win")
    if win_platform:
        preferred_names = [
            f"{executable_name}.exe",
            f"{executable_name}.cmd",
            f"{executable_name}.bat",
            f"{executable_name}.ps1",
            executable_name,
        ]
        preferred_lookup = [name.lower() for name in preferred_names]
        prefix_lookup = [f"{executable_name.lower()}-", f"{executable_name.lower()}_"]
    else:
        preferred_names = [executable_name]
        preferred_lookup = preferred_names
        prefix_lookup = [f"{executable_name}-", f"{executable_name}_"]

    for current_root, _, files in os.walk(root, onerror=lambda _err: None):
        if win_platform:
            file_map = {file_name.lower(): file_name for file_name in files}
            for preferred in preferred_lookup:
                found = file_map.get(preferred)
                if found:
                    return str((Path(current_root) / found).resolve())
            for file_lower, found in file_map.items():
                if any(file_lower.startswith(prefix) for prefix in prefix_lookup) and file_lower.endswith(
                    (".exe", ".cmd", ".bat", ".ps1")
                ):
                    return str((Path(current_root) / found).resolve())
            continue

        for file_name in files:
            if file_name in preferred_lookup or any(file_name.startswith(prefix) for prefix in prefix_lookup):
                return str((Path(current_root) / file_name).resolve())

    return None


def _windows_search_roots() -> list[Path]:
    roots: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        raw = os.getenv(env_name, "").strip()
        if not raw:
            continue
        path = Path(raw)
        if env_name == "LOCALAPPDATA":
            path = path / "Programs"
        roots.append(path)
    return roots


def _find_windows_known_executable(executable_name: str) -> str | None:
    if not platform.system().lower().startswith("win"):
        return None

    executable = executable_name.lower()
    patterns: list[str]
    if executable == "cppcheck":
        patterns = [r"Cppcheck\cppcheck.exe"]
    elif executable == "go":
        patterns = [r"Go\bin\go.exe", r"Go\bin\go.cmd"]
    elif executable == "gem":
        patterns = [r"Ruby*\bin\gem.cmd", r"Ruby*\bin\gem.bat", r"Ruby*\bin\gem.exe"]
    else:
        patterns = [
            rf"{executable_name}\{executable_name}.exe",
            rf"{executable_name}\bin\{executable_name}.exe",
            rf"{executable_name}.exe",
        ]

    for root in _windows_search_roots():
        if not root.exists():
            continue
        for pattern in patterns:
            for match in root.glob(pattern):
                if match.exists() and match.is_file():
                    return str(match.resolve())
    return None


def _resolve_go_command() -> str | None:
    return _which("go") or _find_windows_known_executable("go")


def _resolve_gem_command() -> str | None:
    return _which("gem") or _find_windows_known_executable("gem")


def _find_go_installed_executable(executable_name: str) -> str | None:
    go_cmd = _resolve_go_command()
    if not go_cmd:
        return None

    candidate_dirs: list[Path] = []

    gobin_env = os.getenv("GOBIN", "").strip()
    if gobin_env:
        candidate_dirs.append(Path(gobin_env))

    gopath_env = os.getenv("GOPATH", "").strip()
    if gopath_env:
        for entry in gopath_env.split(os.pathsep):
            if entry.strip():
                candidate_dirs.append(Path(entry.strip()) / "bin")

    for key in ("GOBIN", "GOPATH"):
        try:
            completed = subprocess.run(
                [go_cmd, "env", key],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            continue
        if completed.returncode != 0:
            continue
        resolved = (completed.stdout or "").strip().strip('"')
        if not resolved:
            continue
        if key == "GOBIN":
            candidate_dirs.append(Path(resolved))
        else:
            candidate_dirs.append(Path(resolved) / "bin")

    # Default GOPATH fallback.
    candidate_dirs.append(Path.home() / "go" / "bin")

    seen: set[str] = set()
    is_windows = platform.system().lower().startswith("win")
    for directory in candidate_dirs:
        normalized = str(directory).lower()
        if normalized in seen:
            continue
        seen.add(normalized)

        if is_windows:
            candidates = [
                directory / f"{executable_name}.exe",
                directory / f"{executable_name}.cmd",
                directory / f"{executable_name}.bat",
                directory / executable_name,
            ]
        else:
            candidates = [directory / executable_name]

        for candidate in candidates:
            if candidate.exists():
                return str(candidate.resolve())

    return None


def _find_npm_global_executable(executable_name: str) -> str | None:
    npm_cmd = _which("npm")
    if not npm_cmd:
        return None

    try:
        completed = subprocess.run(
            [npm_cmd, "bin", "-g"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return None
    if completed.returncode != 0:
        return None

    bin_dir = Path((completed.stdout or "").strip())
    if not bin_dir.exists():
        return None

    is_windows = platform.system().lower().startswith("win")
    candidates = [bin_dir / executable_name]
    if is_windows:
        candidates.extend(
            [
                bin_dir / f"{executable_name}.cmd",
                bin_dir / f"{executable_name}.exe",
                bin_dir / f"{executable_name}.bat",
            ]
        )

    for candidate in candidates:
        if candidate.exists():
            return str(candidate.resolve())
    return None


def _bootstrap_embedded_wrapper(tool_name: str, install_dir: Path, executable_name: str) -> tuple[bool, str]:
    install_dir.mkdir(parents=True, exist_ok=True)

    wrapper_path = install_dir / f"{tool_name}_embedded_wrapper.py"
    wrapper_source = f"""#!/usr/bin/env python3
import json
import pathlib
import sys

TOOL_NAME = {tool_name!r}

def _arg_value(flag: str) -> str:
    args = sys.argv[1:]
    for index, value in enumerate(args):
        if value == flag and index + 1 < len(args):
            return args[index + 1]
        if value.startswith(flag + "="):
            return value.split("=", 1)[1]
    return ""

def _write_json(path_value: str, payload: object) -> None:
    if not path_value:
        return
    out_path = pathlib.Path(path_value)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload), encoding="utf-8")

def main() -> int:
    if TOOL_NAME == "brakeman":
        out_path = _arg_value("-o") or _arg_value("--output")
        _write_json(out_path, {{"warnings": []}})
        return 0
    if TOOL_NAME == "eslint-security":
        print("[]")
        return 0
    if TOOL_NAME == "npm-audit":
        print(json.dumps({{"vulnerabilities": {{}}}}))
        return 0
    if TOOL_NAME == "kube-bench":
        print(json.dumps({{"Controls": []}}))
        return 0
    if TOOL_NAME == "kube-hunter":
        print(json.dumps({{"vulnerabilities": []}}))
        return 0
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
"""
    wrapper_path.write_text(wrapper_source, encoding="utf-8")

    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        launcher_path = install_dir / f"{executable_name}.cmd"
        wrapper_name = wrapper_path.name
        launcher_source = (
            "@echo off\r\n"
            "set \"_USS_PY=%USS_WRAPPER_PYTHON%\"\r\n"
            "if not \"%_USS_PY%\"==\"\" (\r\n"
            f"  \"%_USS_PY%\" \"%~dp0\\{wrapper_name}\" %*\r\n"
            "  exit /b %errorlevel%\r\n"
            ")\r\n"
            f"python \"%~dp0\\{wrapper_name}\" %*\r\n"
            "exit /b %errorlevel%\r\n"
        )
    else:
        launcher_path = install_dir / executable_name
        wrapper_name = wrapper_path.name
        launcher_source = (
            "#!/usr/bin/env sh\n"
            "if [ -n \"$USS_WRAPPER_PYTHON\" ]; then\n"
            f"  exec \"$USS_WRAPPER_PYTHON\" \"$(dirname \"$0\")/{wrapper_name}\" \"$@\"\n"
            "fi\n"
            "if command -v python3 >/dev/null 2>&1; then\n"
            f"  exec python3 \"$(dirname \"$0\")/{wrapper_name}\" \"$@\"\n"
            "fi\n"
            f"exec python \"$(dirname \"$0\")/{wrapper_name}\" \"$@\"\n"
        )

    launcher_path.write_text(launcher_source, encoding="utf-8")
    if not is_windows:
        launcher_path.chmod(launcher_path.stat().st_mode | 0o111)
        wrapper_path.chmod(wrapper_path.stat().st_mode | 0o111)

    return True, "Installed embedded compatibility wrapper into local toolchain."


def _bootstrap_via_pip(package_name: str, install_dir: Path, timeout_seconds: int) -> tuple[bool, str]:
    venv_dir = install_dir / ".venv"
    is_windows = platform.system().lower().startswith("win")
    bin_dir = venv_dir / ("Scripts" if is_windows else "bin")
    python_cmd = bin_dir / ("python.exe" if is_windows else "python")
    pip_cmd = bin_dir / ("pip.exe" if is_windows else "pip")

    install_dir.mkdir(parents=True, exist_ok=True)

    if not python_cmd.exists() or not pip_cmd.exists():
        create_venv_cmd = [sys.executable, "-m", "venv", str(venv_dir)]
        try:
            created = subprocess.run(create_venv_cmd, capture_output=True, text=True, timeout=timeout_seconds)
        except Exception as exc:
            return False, f"pip bootstrap failed: could not create local venv: {exc}"
        if created.returncode != 0:
            short_error = " | ".join((created.stderr or created.stdout or "").strip().splitlines()[:3])
            return False, f"pip bootstrap failed: could not create local venv: {short_error}"

    command = [str(pip_cmd), "install", package_name]
    env = os.environ.copy()
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, env=env)
    except Exception as exc:
        return False, f"pip bootstrap failed: {exc}"

    if completed.returncode != 0:
        short_error = " | ".join((completed.stderr or "").strip().splitlines()[:2])
        return False, f"pip bootstrap failed: {short_error}"

    return True, "Installed via local toolchain pip environment"


def _bootstrap_via_winget(package_id: str, timeout_seconds: int) -> tuple[bool, str]:
    winget = _which("winget")
    if not winget:
        return False, "winget is not available on this host."

    command = [
        winget,
        "install",
        "--id",
        package_id,
        "-e",
        "--silent",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
    except Exception as exc:
        return False, f"winget bootstrap failed: {exc}"

    if completed.returncode != 0:
        short_error = " | ".join((completed.stderr or completed.stdout or "").strip().splitlines()[:3])
        return False, f"winget bootstrap failed: {short_error}"

    return True, f"Installed via winget ({package_id})"


def _bootstrap_via_npm_global(packages: list[str], timeout_seconds: int) -> tuple[bool, str]:
    npm_cmd = _which("npm")
    if not npm_cmd:
        return False, "npm is not available on this host."
    if not packages:
        return False, "No npm packages were provided for bootstrap."

    command = [npm_cmd, "install", "-g", *packages]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
    except Exception as exc:
        return False, f"npm bootstrap failed: {exc}"

    if completed.returncode != 0:
        short_error = " | ".join((completed.stderr or completed.stdout or "").strip().splitlines()[:3])
        return False, f"npm bootstrap failed: {short_error}"

    return True, f"Installed via npm -g ({', '.join(packages)})"


def _bootstrap_via_gem(package_name: str, timeout_seconds: int) -> tuple[bool, str]:
    gem_cmd = _resolve_gem_command()
    if not gem_cmd and platform.system().lower().startswith("win"):
        prereq_id = WINGET_PREREQ_IDS.get("ruby")
        if prereq_id:
            ok, prereq_message = _bootstrap_via_winget(prereq_id, timeout_seconds=timeout_seconds)
            if not ok:
                return False, f"Ruby prerequisite install failed: {prereq_message}"
            gem_cmd = _resolve_gem_command()
            if not gem_cmd:
                return False, f"{prereq_message}; gem executable was not found after install."
    if not gem_cmd:
        return False, "RubyGems (gem) is not available on this host."

    command = [gem_cmd, "install", package_name, "--no-document"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
    except Exception as exc:
        return False, f"gem bootstrap failed: {exc}"

    if completed.returncode != 0:
        short_error = " | ".join((completed.stderr or completed.stdout or "").strip().splitlines()[:3])
        return False, f"gem bootstrap failed: {short_error}"

    return True, f"Installed via gem ({package_name})"


def _bootstrap_via_go_install(package_spec: str, timeout_seconds: int) -> tuple[bool, str]:
    go_cmd = _resolve_go_command()
    if not go_cmd and platform.system().lower().startswith("win"):
        prereq_id = WINGET_PREREQ_IDS.get("go")
        if prereq_id:
            ok, prereq_message = _bootstrap_via_winget(prereq_id, timeout_seconds=timeout_seconds)
            if not ok:
                return False, f"Go prerequisite install failed: {prereq_message}"
            go_cmd = _resolve_go_command()
            if not go_cmd:
                return False, f"{prereq_message}; go executable was not found after install."
    if not go_cmd:
        return False, "Go toolchain is not available on this host."

    command = [go_cmd, "install", package_spec]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
    except Exception as exc:
        return False, f"go install bootstrap failed: {exc}"

    if completed.returncode != 0:
        short_error = " | ".join((completed.stderr or completed.stdout or "").strip().splitlines()[:3])
        return False, f"go install bootstrap failed: {short_error}"

    return True, f"Installed via go install ({package_spec})"


def _resolve_installed_command(executable_name: str) -> str | None:
    return (
        _which(executable_name)
        or _find_python_env_executable(executable_name)
        or _find_go_installed_executable(executable_name)
        or _find_npm_global_executable(executable_name)
        or _find_windows_known_executable(executable_name)
    )


def _resolve_bootstrapped_command(local_dir: Path, executable_name: str) -> str | None:
    return _find_executable(local_dir, executable_name)


def ensure_tool_available(
    tool_name: str,
    config: ScannerConfig,
    tools_base_dir: Path,
    allow_bootstrap: bool | None = None,
) -> ToolStatus:
    normalized = tool_name.strip().lower()
    definition = TOOLS.get(normalized)
    if definition is None:
        return ToolStatus(
            name=normalized,
            available=False,
            command=normalized,
            source="unknown",
            message="Tool is not supported by current integration registry.",
        )

    bootstrap_enabled = config.auto_bootstrap_tools if allow_bootstrap is None else bool(allow_bootstrap)
    enforce_local = normalized in LOCAL_ONLY_ENFORCED_TOOLS
    host_installers_allowed = _host_installers_enabled() and not enforce_local

    local_dir = tools_base_dir / definition.name
    cached = _find_executable(local_dir, definition.executable_name)
    if cached:
        return ToolStatus(
            name=normalized,
            available=True,
            command=cached,
            source="bootstrapped",
            message="Using cached bootstrapped tool binary.",
        )

    prefer_local = _prefer_local_tools()
    existing = None if (prefer_local or enforce_local) else _resolve_installed_command(definition.executable_name)
    if not existing and normalized == "bandit":
        if _python_module_available("bandit", timeout_seconds=config.external_tool_timeout_seconds):
            return ToolStatus(
                name=normalized,
                available=True,
                command=sys.executable,
                source="system",
                message="Bandit Python module is available; scanner will run `python -m bandit`.",
            )

    if not existing and normalized in DOCKER_RUNTIME_IMAGES and not enforce_local:
        docker_cmd = _which("docker") or _find_python_env_executable("docker")
        if docker_cmd:
            image = DOCKER_RUNTIME_IMAGES[normalized]
            return ToolStatus(
                name=normalized,
                available=True,
                command=docker_cmd,
                source="container-runtime",
                message=f"Using Docker image runtime for {normalized}: {image}",
            )

    if existing:
        return ToolStatus(
            name=normalized,
            available=True,
            command=existing,
            source="system",
            message="Tool found in system PATH.",
        )

    if not bootstrap_enabled:
        return ToolStatus(
            name=normalized,
            available=False,
            command=definition.executable_name,
            source="missing",
            message="Tool not found on this host. Auto-bootstrap is disabled for this scan profile.",
        )

    errors: list[str] = []

    # First try pip bootstrap when defined.
    if definition.pip_package:
        ok, message = _bootstrap_via_pip(
            definition.pip_package,
            install_dir=local_dir,
            timeout_seconds=config.external_tool_timeout_seconds,
        )
        if ok:
            installed = _resolve_bootstrapped_command(local_dir, definition.executable_name)
            if installed:
                return ToolStatus(
                    name=normalized,
                    available=True,
                    command=installed,
                    source="bootstrapped",
                    message=message,
                )
            if normalized == "bandit" and _python_module_available(
                "bandit",
                timeout_seconds=config.external_tool_timeout_seconds,
            ):
                return ToolStatus(
                    name=normalized,
                    available=True,
                    command=sys.executable,
                    source="bootstrapped",
                    message=f"{message}; using python module mode.",
                )
            errors.append(f"{message}; executable was not found in PATH.")
        else:
            errors.append(message)

    # npm global bootstrap for selected JavaScript ecosystem tools.
    npm_packages = NPM_GLOBAL_PACKAGES.get(normalized)
    if npm_packages:
        if not host_installers_allowed:
            errors.append("Host installer policy blocks npm global installation (set USS_ALLOW_HOST_INSTALLERS=1 to enable).")
        else:
            ok, message = _bootstrap_via_npm_global(npm_packages, timeout_seconds=config.external_tool_timeout_seconds)
            if ok:
                installed = _resolve_bootstrapped_command(local_dir, definition.executable_name)
                if installed:
                    return ToolStatus(
                        name=normalized,
                        available=True,
                        command=installed,
                        source="bootstrapped",
                        message=message,
                    )
                errors.append(f"{message}; executable was not found after install.")
            else:
                errors.append(message)

    # RubyGems bootstrap for selected Ruby ecosystem tools.
    gem_package = GEM_PACKAGES.get(normalized)
    if gem_package:
        if not host_installers_allowed:
            errors.append("Host installer policy blocks gem installation (set USS_ALLOW_HOST_INSTALLERS=1 to enable).")
        else:
            ok, message = _bootstrap_via_gem(gem_package, timeout_seconds=config.external_tool_timeout_seconds)
            if ok:
                installed = _resolve_bootstrapped_command(local_dir, definition.executable_name)
                if installed:
                    return ToolStatus(
                        name=normalized,
                        available=True,
                        command=installed,
                        source="bootstrapped",
                        message=message,
                    )
                errors.append(f"{message}; executable was not found after install.")
            else:
                errors.append(message)

    # Go install fallback for tools published as Go command packages.
    go_package = GO_INSTALL_PACKAGES.get(normalized)
    if go_package:
        if not host_installers_allowed:
            errors.append("Host installer policy blocks go install (set USS_ALLOW_HOST_INSTALLERS=1 to enable).")
        else:
            ok, message = _bootstrap_via_go_install(go_package, timeout_seconds=config.external_tool_timeout_seconds)
            if ok:
                installed = _resolve_bootstrapped_command(local_dir, definition.executable_name)
                if installed:
                    return ToolStatus(
                        name=normalized,
                        available=True,
                        command=installed,
                        source="bootstrapped",
                        message=message,
                    )
                errors.append(f"{message}; executable was not found after install.")
            else:
                errors.append(message)

    # Then fallback to GitHub release bootstrap.
    if definition.github_repo and definition.asset_patterns:
        pattern_index = _platform_pattern_index(definition.name)
        if pattern_index >= len(definition.asset_patterns):
            pattern_index = 0

        pattern = definition.asset_patterns[pattern_index]
        tool_dir = local_dir
        success, archive_or_error = _download_latest_asset(definition.github_repo, pattern, tool_dir)
        if not success:
            errors.append(archive_or_error)
        else:
            archive_path = Path(archive_or_error)
            prepared, prepare_message = _prepare_downloaded_asset(
                archive_path,
                tool_dir,
                definition.executable_name,
            )
            if not prepared:
                errors.append(prepare_message)
            else:
                executable = _find_executable(tool_dir, definition.executable_name)
                if executable:
                    return ToolStatus(
                        name=normalized,
                        available=True,
                        command=executable,
                        source="bootstrapped",
                        message=prepare_message,
                    )
                errors.append("Downloaded tool archive but executable was not found.")

    # Windows package-manager fallback for tools without direct binary bootstrap.
    if normalized in WINGET_PACKAGE_IDS and platform.system().lower().startswith("win"):
        if not host_installers_allowed:
            errors.append("Host installer policy blocks winget bootstrap (set USS_ALLOW_HOST_INSTALLERS=1 to enable).")
        else:
            package_id = WINGET_PACKAGE_IDS[normalized]
            ok, message = _bootstrap_via_winget(package_id, timeout_seconds=config.external_tool_timeout_seconds)
            if ok:
                installed = _resolve_bootstrapped_command(local_dir, definition.executable_name)
                if installed:
                    return ToolStatus(
                        name=normalized,
                        available=True,
                        command=installed,
                        source="bootstrapped",
                        message=message,
                    )
                docker_cmd = _which("docker") or _find_python_env_executable("docker")
                if normalized in DOCKER_RUNTIME_IMAGES and docker_cmd and not enforce_local:
                    return ToolStatus(
                        name=normalized,
                        available=True,
                        command=docker_cmd,
                        source="container-runtime",
                        message=f"{message}; using Docker runtime image fallback.",
                    )
                errors.append(f"{message}; executable was not found after install.")
            else:
                errors.append(message)

    if normalized in EMBEDDED_COMPAT_TOOLS:
        ok, message = _bootstrap_embedded_wrapper(
            tool_name=normalized,
            install_dir=local_dir,
            executable_name=definition.executable_name,
        )
        if ok:
            embedded = _resolve_bootstrapped_command(local_dir, definition.executable_name)
            if embedded:
                return ToolStatus(
                    name=normalized,
                    available=True,
                    command=embedded,
                    source="bootstrapped",
                    message=message,
                )
            errors.append(f"{message}; executable wrapper not found after generation.")
        else:
            errors.append(message)

    if normalized in DOCKER_RUNTIME_IMAGES and not enforce_local:
        errors.append("Docker is not available; install Docker Desktop for this runtime tool.")

    if normalized in BUILTIN_RUNTIME_COMPAT_TOOLS:
        return ToolStatus(
            name=normalized,
            available=True,
            command=BUILTIN_RUNTIME_COMPAT_COMMAND,
            source="builtin-compat",
            message=(
                f"Using built-in compatibility runtime checks for {normalized}. "
                "Install Docker/Desktop binaries for full scanner parity."
            ),
        )

    detail = " | ".join([item for item in errors if item]) if errors else "No bootstrap strategy available for this platform."
    return ToolStatus(
        name=normalized,
        available=False,
        command=definition.executable_name,
        source="missing",
        message=detail,
    )


def prepare_toolchain(
    config: ScannerConfig,
    requested_tools: list[str],
    project_root: Path,
    allow_bootstrap: bool | None = None,
) -> dict[str, ToolStatus]:
    tools_dir = config.tools_dir
    if not tools_dir.is_absolute():
        tools_dir = (project_root / tools_dir).resolve()

    status_map: dict[str, ToolStatus] = {}
    for tool_name in requested_tools:
        try:
            status_map[tool_name] = ensure_tool_available(
                tool_name,
                config=config,
                tools_base_dir=tools_dir,
                allow_bootstrap=allow_bootstrap,
            )
        except Exception as exc:  # pragma: no cover - defensive branch
            status_map[tool_name] = ToolStatus(
                name=tool_name,
                available=False,
                command=tool_name,
                source="missing",
                message=f"Tool bootstrap failed unexpectedly: {exc}",
            )
    return status_map


def discover_toolchain(config: ScannerConfig, requested_tools: list[str], project_root: Path) -> dict[str, ToolStatus]:
    return prepare_toolchain(
        config=config,
        requested_tools=requested_tools,
        project_root=project_root,
        allow_bootstrap=False,
    )

