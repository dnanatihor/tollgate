"""Structural context for five languages and a fallback language."""

from __future__ import annotations

import pytest

from tollgate.context.treesitter import structural_context
from tollgate.models import Hunk

SAMPLES = {
    "python": (
        "import os\n\ndef charge(order_id):\n    return order_id\n",
        4,
        ("import os", "def charge"),
    ),
    "javascript": (
        'import x from "y";\nfunction total(n) {\n  return n;\n}\n',
        3,
        ('import x from "y"', "function total"),
    ),
    "typescript": (
        'import x from "y";\nfunction total(n: number) {\n  return n;\n}\n',
        3,
        ('import x from "y"', "function total"),
    ),
    "java": (
        "import java.util.List;\nclass Orders {\n  int total() {\n    return 1;\n  }\n}\n",
        4,
        ("import java.util.List", "int total"),
    ),
    "go": (
        'package pay\n\nimport "fmt"\n\nfunc Total(n int) int {\n\treturn n\n}\n',
        6,
        ('import "fmt"', "func Total"),
    ),
    "csharp": (
        "using System;\nclass Orders {\n  int Total() {\n    return 1;\n  }\n}\n",
        4,
        ("using System", "int Total"),
    ),
}


@pytest.mark.parametrize("language", list(SAMPLES))
def test_enclosing_symbol_and_imports(language: str) -> None:
    source, line, needles = SAMPLES[language]
    hunk = Hunk(old_start=line, old_lines=1, new_start=line, new_lines=1, lines=())
    context = structural_context(language, source, (hunk,))
    for needle in needles:
        assert needle in context


def test_unsupported_language_falls_back_without_error() -> None:
    source = "IDENTIFICATION DIVISION.\nPROGRAM-ID. PAY.\n" + "\n".join(
        f"       DISPLAY {index}." for index in range(80)
    )
    hunk = Hunk(old_start=2, old_lines=1, new_start=2, new_lines=1, lines=())
    context = structural_context("cobol", source, (hunk,))
    assert "PROGRAM-ID. PAY" in context
    assert "window" in context
