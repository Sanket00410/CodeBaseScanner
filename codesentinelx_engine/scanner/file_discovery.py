from __future__ import annotations

import os
import logging
import stat
from pathlib import Path

from codesentinelx_engine.config import ScannerConfig

LOGGER = logging.getLogger(__name__)

_MAX_SYMLINK_DEPTH = 20
_SEEN_SYMLINK_TARGETS: set[Path] = set()


def _is_supported_file(path: Path, config: ScannerConfig) -> bool:
    if path.name in config.special_files:
        return True
    return path.suffix.lower() in config.include_extensions


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except PermissionError:
        LOGGER.debug("Permission denied: %s", path)
        return None
    except OSError as exc:
        LOGGER.debug("Cannot stat %s: %s", path, exc)
        return None


def _resolve_symlink(path: Path, depth: int = 0) -> Path | None:
    if depth > _MAX_SYMLINK_DEPTH:
        LOGGER.warning("Symlink depth exceeded for %s", path)
        return None
    try:
        resolved = path.resolve()
        if resolved in _SEEN_SYMLINK_TARGETS:
            return None
        _SEEN_SYMLINK_TARGETS.add(resolved)
        return resolved
    except (OSError, RuntimeError):
        return None


def _walk_safe(
    root: Path,
    config: ScannerConfig,
    follow_symlinks: bool = False,
) -> list[Path]:
    files: list[Path] = []
    max_size_bytes = config.max_file_size_kb * 1024
    try:
        scandir_iter = os.scandir(root)
    except PermissionError:
        LOGGER.debug("Permission denied scanning directory: %s", root)
        return files
    except OSError as exc:
        LOGGER.debug("Cannot scan directory %s: %s", root, exc)
        return files

    with scandir_iter as entries:
        dirs_to_recurse: list[Path] = []
        for entry in entries:
            try:
                entry_path = Path(entry.path)
                if entry.is_symlink():
                    target = _resolve_symlink(entry_path)
                    if target is None:
                        continue
                    if follow_symlinks:
                        entry_path = target
                    else:
                        continue
                if entry.is_dir(follow_symlinks=False):
                    dir_name = entry.name
                    if dir_name.startswith(".") and dir_name not in config.include_hidden:
                        continue
                    if dir_name in config.exclude_dirs or dir_name.startswith(".scanner-cache"):
                        continue
                    dirs_to_recurse.append(entry_path)
                elif entry.is_file(follow_symlinks=False):
                    if not _is_supported_file(entry_path, config):
                        continue
                    st = _safe_stat(entry_path)
                    if st is None:
                        continue
                    if st.st_size > max_size_bytes:
                        continue
                    files.append(entry_path)
            except PermissionError:
                LOGGER.debug("Permission denied accessing %s", entry.path)
                continue
            except OSError:
                continue

        for subdir in dirs_to_recurse:
            files.extend(_walk_safe(subdir, config, follow_symlinks))

    return files


def discover_files(project_root: Path, config: ScannerConfig) -> list[Path]:
    _SEEN_SYMLINK_TARGETS.clear()
    if project_root.is_file():
        if not _is_supported_file(project_root, config):
            return []
        st = _safe_stat(project_root)
        if st is None:
            return []
        if st.st_size > config.max_file_size_kb * 1024:
            return []
        return [project_root]

    return _walk_safe(project_root, config, follow_symlinks=False)


def discover_files_batch(
    project_root: Path,
    config: ScannerConfig,
    batch_size: int = 500,
) -> list[list[Path]]:
    all_files = discover_files(project_root, config)
    return [all_files[i:i + batch_size] for i in range(0, len(all_files), batch_size)]


def estimate_file_count(project_root: Path, config: ScannerConfig) -> int:
    count = 0
    max_size_bytes = config.max_file_size_kb * 1024
    try:
        for current_root, dirs, filenames in os.walk(project_root):
            dirs[:] = [d for d in dirs if d not in config.exclude_dirs and not d.startswith(".")]
            for file_name in filenames:
                path = Path(current_root) / file_name
                if not _is_supported_file(path, config):
                    continue
                st = _safe_stat(path)
                if st is None:
                    continue
                if st.st_size > max_size_bytes:
                    continue
                count += 1
    except Exception:
        pass
    return count
