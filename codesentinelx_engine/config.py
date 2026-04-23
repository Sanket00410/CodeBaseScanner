from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from codesentinelx_engine.scanner.role_scope import role_default_scan_preset

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
    "exports",
    ".integrity",
    ".scanner-cache",
    ".toolchain",
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
        "semgrep",
        "gitleaks",
        "checkov",
        "hadolint",
        "osv-scanner",
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


def _default_codebase_tools_for_preset(preset: str) -> list[str]:
    normalized = preset.strip().lower()
    presets: dict[str, list[str]] = {
        "fast": [
            "semgrep",
            "gitleaks",
            "checkov",
            "hadolint",
            "osv-scanner",
        ],
        "standard": [
            "semgrep",
            "gitleaks",
            "checkov",
            "hadolint",
            "osv-scanner",
        ],
        "deep": [
            "semgrep",
            "gitleaks",
            "checkov",
            "hadolint",
            "osv-scanner",
        ],
    }
    return list(presets.get(normalized, _default_codebase_tools()))


def _default_native_families_for_preset(preset: str) -> list[str]:
    normalized = preset.strip().lower()
    presets: dict[str, list[str]] = {
        "fast": [
            "semgrep",
            "gitleaks",
            "checkov",
            "hadolint",
            "osv-scanner",
        ],
        "standard": [
            "semgrep",
            "gitleaks",
            "checkov",
            "hadolint",
            "osv-scanner",
        ],
        "deep": [
            "semgrep",
            "gitleaks",
            "checkov",
            "hadolint",
            "osv-scanner",
        ],
    }
    return list(presets.get(normalized, []))


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


def _read_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


@dataclass(slots=True)
class ScannerConfig:
    max_file_size_kb: int = 1024
    max_findings: int = 0
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    include_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    special_files: set[str] = field(default_factory=lambda: set(SPECIAL_FILES))
    export_dir: Path = Path.home() / "Documents" / "CodeSentinelX_Reports" / "export"
    log_level: str = "INFO"
    use_external_tools: bool = True
    external_tools: list[str] = field(default_factory=_default_codebase_tools)
    codebase_external_tools: list[str] = field(default_factory=_default_codebase_tools)
    runtime_external_tools: list[str] = field(default_factory=_default_runtime_tools)
    external_tool_timeout_seconds: int = 300
    auto_bootstrap_tools: bool = True
    tools_dir: Path = Path(".toolchain")
    use_native_code_analysis: bool = True
    native_analysis_languages: list[str] = field(default_factory=lambda: ["python", "javascript"])
    native_analysis_families: list[str] = field(default_factory=list)
    native_max_findings_per_file: int = 50
    use_native_dependency_analysis: bool = True
    native_dependency_ecosystems: list[str] = field(default_factory=lambda: ["python", "npm"])
    native_dependency_max_findings: int = 100
    enable_framework_modeling: bool = True
    file_scan_workers: int = field(default_factory=lambda: max(1, min(8, os.cpu_count() or 4)))
    external_tool_workers: int = field(default_factory=lambda: max(1, min(6, os.cpu_count() or 4)))
    scan_cache_enabled: bool = True
    scan_cache_file: Path = Path.home() / "Documents" / "CodeSentinelX_Reports" / "export" / ".integrity" / "scan_cache.json"
    scan_cache_max_files: int = 50000
    scan_preset: str = "standard"
    suppression_review_days: int = 30
    use_project_rules: bool = True
    suppression_default_owner: str = "security-triage"
    suppression_require_expiry: bool = True
    quality_benchmark_enabled: bool = True
    quality_benchmark_file: Path = Path.home() / "Documents" / "CodeSentinelX_Reports" / "export" / ".integrity" / "benchmark_truth_set.json"
    quality_benchmark_min_precision: float = 90.0
    quality_benchmark_min_recall: float = 85.0
    quality_benchmark_min_f1: float = 88.0
    quality_benchmark_strict_scope: bool = True
    scan_role: str = "Security Analyst"

    @classmethod
    def from_env(cls, scan_role: str | None = None) -> "ScannerConfig":
        exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
        user_excludes = os.getenv("USS_EXCLUDE_DIRS", "")
        if user_excludes.strip():
            exclude_dirs.update({part.strip() for part in user_excludes.split(",") if part.strip()})

        export_dir = Path(os.getenv("USS_EXPORT_DIR", str(Path.home() / "Documents" / "CodeSentinelX_Reports" / "export")))
        log_level = os.getenv("USS_LOG_LEVEL", "INFO").upper()
        resolved_role = (scan_role or os.getenv("USS_SCAN_ROLE", "Security Analyst")).strip() or "Security Analyst"
        resolved_scan_preset = (os.getenv("USS_SCAN_PRESET", "").strip().lower() or role_default_scan_preset(resolved_role)).strip()
        if resolved_scan_preset not in {"fast", "standard", "deep"}:
            resolved_scan_preset = role_default_scan_preset(resolved_role)
        default_codebase_tools = _default_codebase_tools_for_preset(resolved_scan_preset)
        default_native_families = _default_native_families_for_preset(resolved_scan_preset)

        return cls(
            max_file_size_kb=_read_int("USS_MAX_FILE_SIZE_KB", 1024),
            max_findings=_read_int("USS_MAX_FINDINGS", 0, allow_zero=True),
            exclude_dirs=exclude_dirs,
            include_extensions=set(DEFAULT_EXTENSIONS),
            special_files=set(SPECIAL_FILES),
            export_dir=export_dir,
            log_level=log_level,
            use_external_tools=_read_bool("USS_USE_EXTERNAL_TOOLS", True),
            external_tools=_read_csv("USS_EXTERNAL_TOOLS", default_codebase_tools),
            codebase_external_tools=_read_csv(
                "USS_CODEBASE_TOOLS",
                default_codebase_tools,
            ),
            runtime_external_tools=_read_csv(
                "USS_RUNTIME_TOOLS",
                _default_runtime_tools(),
            ),
            external_tool_timeout_seconds=_read_int("USS_EXTERNAL_TOOL_TIMEOUT_SECONDS", 300),
            auto_bootstrap_tools=_read_bool("USS_AUTO_BOOTSTRAP_TOOLS", True),
            tools_dir=Path(os.getenv("USS_TOOLS_DIR", ".toolchain")),
            use_native_code_analysis=_read_bool("USS_USE_NATIVE_CODE_ANALYSIS", True),
            native_analysis_languages=_read_csv(
                "USS_NATIVE_ANALYSIS_LANGUAGES",
                ["python", "javascript"],
            ),
            native_analysis_families=_read_csv("USS_NATIVE_ANALYSIS_FAMILIES", default_native_families),
            native_max_findings_per_file=_read_int("USS_NATIVE_MAX_FINDINGS_PER_FILE", 50),
            use_native_dependency_analysis=_read_bool(
                "USS_USE_NATIVE_DEPENDENCY_ANALYSIS",
                resolved_scan_preset != "fast",
            ),
            native_dependency_ecosystems=_read_csv(
                "USS_NATIVE_DEPENDENCY_ECOSYSTEMS",
                ["python", "npm"],
            ),
            native_dependency_max_findings=_read_int("USS_NATIVE_DEPENDENCY_MAX_FINDINGS", 100),
            enable_framework_modeling=_read_bool("USS_ENABLE_FRAMEWORK_MODELING", True),
            file_scan_workers=_read_int("USS_FILE_SCAN_WORKERS", max(1, min(8, os.cpu_count() or 4))),
            external_tool_workers=_read_int(
                "USS_EXTERNAL_TOOL_WORKERS",
                _read_int("USS_TOOL_WORKERS", max(1, min(6, os.cpu_count() or 4))),
            ),
            scan_cache_enabled=_read_bool("USS_SCAN_CACHE_ENABLED", True),
            scan_cache_file=Path(os.getenv("USS_SCAN_CACHE_FILE", str(Path.home() / "Documents" / "CodeSentinelX_Reports" / "export" / ".integrity" / "scan_cache.json"))),
            scan_cache_max_files=_read_int("USS_SCAN_CACHE_MAX_FILES", 50000),
            suppression_review_days=_read_int("USS_SUPPRESSION_REVIEW_DAYS", 30),
            use_project_rules=_read_bool("USS_USE_PROJECT_RULES", resolved_scan_preset != "fast"),
            suppression_default_owner=os.getenv("USS_SUPPRESSION_DEFAULT_OWNER", "security-triage").strip() or "security-triage",
            suppression_require_expiry=_read_bool("USS_SUPPRESSION_REQUIRE_EXPIRY", True),
            quality_benchmark_enabled=_read_bool("USS_QUALITY_BENCHMARK_ENABLED", True),
            quality_benchmark_file=Path(os.getenv("USS_QUALITY_BENCHMARK_FILE", str(Path.home() / "Documents" / "CodeSentinelX_Reports" / "export" / ".integrity" / "benchmark_truth_set.json"))),
            quality_benchmark_min_precision=_read_float("USS_QUALITY_BENCHMARK_MIN_PRECISION", 90.0),
            quality_benchmark_min_recall=_read_float("USS_QUALITY_BENCHMARK_MIN_RECALL", 85.0),
            quality_benchmark_min_f1=_read_float("USS_QUALITY_BENCHMARK_MIN_F1", 88.0),
            quality_benchmark_strict_scope=_read_bool("USS_QUALITY_BENCHMARK_STRICT_SCOPE", True),
            scan_preset=resolved_scan_preset,
            scan_role=resolved_role,
        )

