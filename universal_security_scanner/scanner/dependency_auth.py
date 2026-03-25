from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


def normalize_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip().lower())


def build_dependency_inventory(root: Path) -> dict[str, dict[str, object]]:
    inventory: dict[str, dict[str, object]] = {}
    if not root.exists():
        return inventory

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lowered = path.name.lower()
        relative = _relpath(path, root)
        if lowered == "package.json":
            _merge_inventory(inventory, _parse_package_json(path, relative))
        elif lowered == "package-lock.json":
            _merge_inventory(inventory, _parse_package_lock(path, relative))
        elif lowered == "yarn.lock":
            _merge_inventory(inventory, _parse_yarn_lock(path, relative))
        elif lowered == "pnpm-lock.yaml":
            _merge_inventory(inventory, _parse_pnpm_lock(path, relative))
        elif lowered == "pyproject.toml":
            _merge_inventory(inventory, _parse_pyproject(path, relative))
        elif lowered == "requirements.txt" or lowered.endswith("requirements-dev.txt") or lowered.endswith(".requirements.txt"):
            _merge_inventory(inventory, _parse_requirements(path, relative))
        elif lowered in {"poetry.lock", "pipfile.lock"}:
            _merge_inventory(inventory, _parse_python_lock(path, relative))
    return inventory


def build_dependency_usage_map(root: Path) -> dict[str, list[str]]:
    usage: dict[str, list[str]] = defaultdict(list)
    if not root.exists():
        return {}

    skip_dirs = {
        ".git",
        "node_modules",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".toolchain",
        "coverage",
        "exports",
    }
    source_suffixes = {".py", ".js", ".jsx", ".ts", ".tsx"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in source_suffixes:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        relative = _relpath(path, root)
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for package in _extract_dependency_imports(content, path.suffix.lower()):
            row = usage[normalize_package_name(package)]
            if relative not in row:
                row.append(relative)
    return {key: value[:10] for key, value in usage.items()}


def advisory_identity(findings_ids: list[str]) -> dict[str, object]:
    normalized = sorted({str(item).strip().upper() for item in findings_ids if str(item).strip()})
    return {
        "advisory_ids": normalized,
        "advisory_verified": any(re.match(r"^(CVE-\d{4}-\d{4,7}|GHSA-[A-Z0-9-]+)$", item, re.IGNORECASE) for item in normalized),
    }


def _extract_dependency_imports(content: str, suffix: str) -> set[str]:
    imports: set[str] = set()
    if suffix == ".py":
        for match in re.finditer(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_\.]*)", content, flags=re.MULTILINE):
            imports.add(match.group(1).split(".", 1)[0])
        for match in re.finditer(r"^\s*from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import\b", content, flags=re.MULTILINE):
            imports.add(match.group(1).split(".", 1)[0])
    elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
        for match in re.finditer(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", content):
            spec = match.group(1).strip()
            if not spec.startswith((".", "/")):
                imports.add(_top_level_js_package(spec))
        for match in re.finditer(r"from\s+['\"]([^'\"]+)['\"]", content):
            spec = match.group(1).strip()
            if not spec.startswith((".", "/")):
                imports.add(_top_level_js_package(spec))
        for match in re.finditer(r"^\s*import\s+['\"]([^'\"]+)['\"]", content, flags=re.MULTILINE):
            spec = match.group(1).strip()
            if not spec.startswith((".", "/")):
                imports.add(_top_level_js_package(spec))
    return {item for item in imports if item}


def _top_level_js_package(spec: str) -> str:
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return spec.split("/", 1)[0]


def _ensure_row(inventory: dict[str, dict[str, object]], package_name: str) -> dict[str, object]:
    key = normalize_package_name(package_name)
    return inventory.setdefault(
        key,
        {
            "package_name": package_name,
            "manifest_paths": set(),
            "lockfile_paths": set(),
            "declared_versions": set(),
            "locked_versions": set(),
            "package_aliases": {package_name},
        },
    )


def _merge_inventory(inventory: dict[str, dict[str, object]], parsed: dict[str, dict[str, object]]) -> None:
    for key, row in parsed.items():
        target = inventory.setdefault(
            key,
            {
                "package_name": row.get("package_name", key),
                "manifest_paths": set(),
                "lockfile_paths": set(),
                "declared_versions": set(),
                "locked_versions": set(),
                "package_aliases": set(),
            },
        )
        for field in ("manifest_paths", "lockfile_paths", "declared_versions", "locked_versions", "package_aliases"):
            target[field] = set(target.get(field, set())) | set(row.get(field, set()))
        if not target.get("package_name"):
            target["package_name"] = row.get("package_name", key)


def _parse_package_json(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return parsed
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = payload.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            row = _ensure_row(parsed, name)
            row["manifest_paths"].add(relative)
            if version:
                row["declared_versions"].add(str(version))
    return parsed


def _parse_package_lock(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return parsed
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            name = str(meta.get("name") or "").strip()
            if not name and package_path.startswith("node_modules/"):
                name = package_path.split("node_modules/", 1)[1]
            if not name:
                continue
            row = _ensure_row(parsed, name)
            row["lockfile_paths"].add(relative)
            version = str(meta.get("version") or "").strip()
            if version:
                row["locked_versions"].add(version)
    deps = payload.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            row = _ensure_row(parsed, name)
            row["lockfile_paths"].add(relative)
            if isinstance(meta, dict):
                version = str(meta.get("version") or "").strip()
                if version:
                    row["locked_versions"].add(version)
    return parsed


def _parse_yarn_lock(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return parsed
    current_names: list[str] = []
    for raw in lines:
        if raw and not raw.startswith(" ") and raw.endswith(":"):
            current_names = []
            header = raw.rstrip(":")
            for token in header.split(","):
                pkg = token.strip().strip('"').strip("'")
                if "@" in pkg:
                    if pkg.startswith("@"):
                        name = pkg.split("@", 2)[0] + "@" + pkg.split("@", 2)[1]
                    else:
                        name = pkg.rsplit("@", 1)[0]
                else:
                    name = pkg
                if name:
                    current_names.append(name)
                    row = _ensure_row(parsed, name)
                    row["lockfile_paths"].add(relative)
        elif current_names and raw.strip().startswith("version "):
            version = raw.strip().split(" ", 1)[1].strip().strip('"')
            for name in current_names:
                _ensure_row(parsed, name)["locked_versions"].add(version)
    return parsed


def _parse_pnpm_lock(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return parsed
    for match in re.finditer(r"^\s{2,}([^:\s]+):\s*$", text, flags=re.MULTILINE):
        name = match.group(1).strip()
        if not name or name in {"dependencies", "packages"}:
            continue
        row = _ensure_row(parsed, name)
        row["lockfile_paths"].add(relative)
    for match in re.finditer(r"^\s{4,}version:\s+([^\s]+)\s*$", text, flags=re.MULTILINE):
        version = match.group(1).strip().strip("'\"")
        for row in parsed.values():
            row["locked_versions"].add(version)
    return parsed


def _parse_pyproject(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    if tomllib is None:
        return parsed
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):  # type: ignore[attr-defined]
        return parsed

    def add_dep(entry: str) -> None:
        name, version = _split_dep_spec(entry)
        if not name:
            return
        row = _ensure_row(parsed, name)
        row["manifest_paths"].add(relative)
        if version:
            row["declared_versions"].add(version)

    for entry in payload.get("project", {}).get("dependencies", []) or []:
        add_dep(str(entry))

    poetry_deps = (((payload.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    if isinstance(poetry_deps, dict):
        for name, version in poetry_deps.items():
            if name == "python":
                continue
            row = _ensure_row(parsed, name)
            row["manifest_paths"].add(relative)
            if isinstance(version, str) and version:
                row["declared_versions"].add(version)
    return parsed


def _parse_requirements(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return parsed
    for line in lines:
        clean = line.split("#", 1)[0].strip()
        if not clean or clean.startswith(("-r", "--")):
            continue
        name, version = _split_dep_spec(clean)
        if not name:
            continue
        row = _ensure_row(parsed, name)
        row["manifest_paths"].add(relative)
        if version:
            row["declared_versions"].add(version)
    return parsed


def _parse_python_lock(path: Path, relative: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return parsed
    for match in re.finditer(r'name\s*=\s*"([^"]+)"[\s\S]{0,160}?version\s*=\s*"([^"]+)"', text):
        row = _ensure_row(parsed, match.group(1))
        row["lockfile_paths"].add(relative)
        row["locked_versions"].add(match.group(2))
    return parsed


def _split_dep_spec(raw: str) -> tuple[str, str]:
    value = raw.strip().strip('"').strip("'")
    if not value:
        return "", ""
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[.*\])?\s*([<>=!~].+)?$", value)
    if not match:
        return value, ""
    return match.group(1), (match.group(2) or "").strip()


def _relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name
