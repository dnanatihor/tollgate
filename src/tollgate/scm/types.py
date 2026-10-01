"""Shared provider shapes from SPEC.md §11.1."""

from __future__ import annotations

import re
from dataclasses import dataclass

from tollgate.models import Finding


@dataclass(frozen=True, slots=True)
class ExistingComment:
    id: int
    body: str


@dataclass(frozen=True, slots=True)
class InlineComment:
    path: str
    line: int
    body: str
    start_line: int | None = None


@dataclass(frozen=True, slots=True)
class PostResult:
    posted: tuple[str, ...]
    failed: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProviderLimits:
    comment_chars: int = 65000
    annotations_per_call: int = 50


@dataclass(frozen=True, slots=True)
class PRRef:
    owner: str
    repo: str
    number: str


def inline_for(finding: Finding, *, eligible_lines: set[int] | None = None) -> InlineComment | None:
    """Inline comments attach only to new-side lines that appear in the diff."""
    if finding.file is None or finding.start_line is None or finding.status != "active":
        return None
    if eligible_lines is not None and finding.start_line not in eligible_lines:
        return None
    return InlineComment(
        path=finding.file,
        line=finding.end_line or finding.start_line,
        start_line=_start(finding),
        body=comment_body(finding),
    )


def _start(finding: Finding) -> int | None:
    if finding.end_line and finding.start_line and finding.end_line != finding.start_line:
        return finding.start_line
    return None


def comment_body(finding: Finding) -> str:
    lines = [neutralize(finding.title), "", neutralize(finding.explanation)]
    if finding.recommendation:
        lines.extend(["", neutralize(finding.recommendation)])
    if finding.suggested_patch:
        lines.extend(["", "```suggestion", finding.suggested_patch.rstrip("\n"), "```"])
    return "\n".join(lines)


def neutralize(text: str) -> str:
    """Strip raw HTML and wrap @mentions so they cannot notify people."""
    stripped = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"(?<![`])@([A-Za-z0-9][A-Za-z0-9-]*)", r"`@\1`", stripped)
