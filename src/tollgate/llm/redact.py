"""Mask secrets before any prompt text is built (SPEC.md §7.4)."""

from __future__ import annotations

import re

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|secret|token|authorization)\b\s*[:=]\s*\S+"
)
_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def mask_secrets(text: str) -> str:
    text = _PEM.sub("«secret»", text)
    text = _AWS.sub("«secret»", text)
    return _ASSIGNMENT.sub("«secret»", text)
