from __future__ import annotations

import os
from pathlib import Path

from universal_security_scanner.config import ScannerConfig


def _is_supported_file(path: Path, config: ScannerConfig) -> bool:
    if path.name in config.special_files:
        return True
    return path.suffix.lower() in config.include_extensions


def discover_files(project_root: Path, config: ScannerConfig) -> list[Path]:
    files: list[Path] = []
    max_size_bytes = config.max_file_size_kb * 1024

    for current_root, dirs, filenames in os.walk(project_root):
        dirs[:] = [
            item for item in dirs if item not in config.exclude_dirs and not item.startswith(".scanner-cache")
        ]

        for file_name in filenames:
            path = Path(current_root) / file_name
            if not _is_supported_file(path, config):
                continue

            try:
                if path.stat().st_size > max_size_bytes:
                    continue
            except OSError:
                continue

            files.append(path)

    return sorted(files)
