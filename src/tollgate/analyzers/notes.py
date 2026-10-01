"""Coverage notes for analyzers that did not run."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from tollgate.models import Finding


@dataclass(frozen=True, slots=True)
class CoverageNote:
    analyzer: str
    status: Literal["ran", "missing", "skipped"]
    detail: str


@dataclass(frozen=True, slots=True)
class Analysis:
    findings: tuple[Finding, ...]
    coverage: tuple[CoverageNote, ...]
    retrieved: tuple[str, ...] = ()


def binary_note(
    name: str,
    mode: str,
    *,
    which: Callable[[str], str | None] = shutil.which,
) -> CoverageNote | None:
    """A missing or disabled binary is a coverage note, never a failure."""
    if mode == "off":
        return CoverageNote(name, "skipped", "disabled in configuration")
    if which(name) is None:
        return CoverageNote(name, "missing", "binary not found")
    return None
