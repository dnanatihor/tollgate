"""±30-line windows for languages without a grammar (SPEC.md §7.4)."""

from __future__ import annotations

from tollgate.models import Hunk


def fallback_context(source: str, hunks: tuple[Hunk, ...]) -> str:
    lines = source.splitlines()
    if not lines:
        lines = [line.text for hunk in hunks for line in hunk.lines if line.kind != "-"]
    head = lines[:40]
    sections = ["first 40 lines:", *head]
    for hunk in hunks:
        if not lines:
            break
        anchor = hunk.new_start or 1
        start = max(1, anchor - 30)
        end = min(len(lines), anchor + max(hunk.new_lines, 1) + 29)
        window = lines[start - 1 : end]
        sections.append(f"window {start}-{end}:")
        sections.extend(window)
    return "\n".join(sections)
