from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "node_modules",
    "dist",
    "build",
    "target",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".next",
    ".nuxt",
    "coverage",
}

DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".php",
    ".go",
    ".rb",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".scala",
    ".kt",
    ".swift",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".ini",
    ".conf",
    ".xml",
    ".html",
    ".htm",
    ".sql",
    ".sh",
    ".ps1",
}

SPECIAL_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
}


def _default_codebase_tools() -> list[str]:
    return [
        "bandit",
        "brakeman",
        "checkov",
        "clair",
        "codeql",
        "cppcheck",
        "eslint-security",
        "findsecbugs",
        "flawfinder",
        "gitleaks",
        "gosec",
        "govulncheck",
        "grype",
        "hadolint",
        "infer",
        "npm-audit",
        "osv-scanner",
        "owasp-dependency-check",
        "pip-audit",
        "safety",
        "semgrep",
        "snyk",
        "sonarqube",
        "spotbugs",
        "tfsec",
        "trivy",
    ]


def _default_runtime_tools() -> list[str]:
    return [
        "runtime_http_probe",
        "amass",
        "ffuf",
        "kube-bench",
        "kube-hunter",
        "nikto",
        "nmap",
        "nuclei",
        "sqlmap",
        "wapiti",
        "zap-baseline",
    ]


def _read_int(name: str, default: int, *, allow_zero: bool = False) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    if allow_zero:
        return parsed if parsed >= 0 else default
    return parsed if parsed > 0 else default


def _read_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _read_csv(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None or not value.strip():
        return list(default)
    return [item.strip().lower() for item in value.split(",") if item.strip()]


@dataclass(slots=True)
class ScannerConfig:
    max_file_size_kb: int = 1024
    max_findings: int = 0
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    include_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    special_files: set[str] = field(default_factory=lambda: set(SPECIAL_FILES))
    export_dir: Path = Path("exports")
    log_level: str = "INFO"
    use_external_tools: bool = True
    external_tools: list[str] = field(default_factory=_default_codebase_tools)
    codebase_external_tools: list[str] = field(default_factory=_default_codebase_tools)
    runtime_external_tools: list[str] = field(default_factory=_default_runtime_tools)
    external_tool_timeout_seconds: int = 300
    auto_bootstrap_tools: bool = True
    tools_dir: Path = Path(".toolchain")

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
        user_excludes = os.getenv("USS_EXCLUDE_DIRS", "")
        if user_excludes.strip():
            exclude_dirs.update({part.strip() for part in user_excludes.split(",") if part.strip()})

        export_dir = Path(os.getenv("USS_EXPORT_DIR", "exports"))
        log_level = os.getenv("USS_LOG_LEVEL", "INFO").upper()

        return cls(
            max_file_size_kb=_read_int("USS_MAX_FILE_SIZE_KB", 1024),
            max_findings=_read_int("USS_MAX_FINDINGS", 0, allow_zero=True),
            exclude_dirs=exclude_dirs,
            include_extensions=set(DEFAULT_EXTENSIONS),
            special_files=set(SPECIAL_FILES),
            export_dir=export_dir,
            log_level=log_level,
            use_external_tools=_read_bool("USS_USE_EXTERNAL_TOOLS", True),
            external_tools=_read_csv("USS_EXTERNAL_TOOLS", _default_codebase_tools()),
            codebase_external_tools=_read_csv(
                "USS_CODEBASE_TOOLS",
                _default_codebase_tools(),
            ),
            runtime_external_tools=_read_csv(
                "USS_RUNTIME_TOOLS",
                _default_runtime_tools(),
            ),
            external_tool_timeout_seconds=_read_int("USS_EXTERNAL_TOOL_TIMEOUT_SECONDS", 300),
            auto_bootstrap_tools=_read_bool("USS_AUTO_BOOTSTRAP_TOOLS", True),
            tools_dir=Path(os.getenv("USS_TOOLS_DIR", ".toolchain")),
        )
