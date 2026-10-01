"""Match the gitignore-style path patterns used in ``.tollgate.yml``."""

from __future__ import annotations

import re


def matches_any(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    return any(_match(normalized, pattern) for pattern in patterns)


def _match(path: str, pattern: str) -> bool:
    source = pattern.replace("\\", "/").strip()
    if not source or source.startswith("#"):
        return False
    if source.startswith("/"):
        source = source[1:]
    parts: list[str] = []
    if source.startswith("**/"):
        parts.append(r"(?:.+/)?")
        source = source[3:]
    elif "/" not in source:
        # A slashless pattern matches in any directory, as in gitignore.
        parts.append(r"(?:.+/)?")
    index = 0
    while index < len(source):
        char = source[index]
        if char == "*":
            if source.startswith("**", index):
                parts.append(".*")
                index += 2
                if index < len(source) and source[index] == "/":
                    index += 1
                continue
            parts.append(r"[^/]*")
        elif char == "?":
            parts.append(r"[^/]")
        else:
            parts.append(re.escape(char))
        index += 1
    return re.fullmatch("".join(parts), path) is not None
