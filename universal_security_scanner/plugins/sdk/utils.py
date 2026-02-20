from __future__ import annotations

import re


def matched_line_numbers(content: str, patterns: list[str], flags: int = re.IGNORECASE) -> list[tuple[int, str]]:
    compiled = [re.compile(pattern, flags) for pattern in patterns]
    matches: list[tuple[int, str]] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for regex in compiled:
            if regex.search(line):
                matches.append((line_number, line.strip()[:240]))
                break

    return matches
