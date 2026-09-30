"""Finding model shape from SPEC.md §10."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tollgate.models import Finding


def test_finding_is_frozen_and_bounded() -> None:
    finding = Finding(
        fingerprint="ab" * 8,
        lens="security",
        title="SQL injection",
        severity="high",
        confidence="high",
        file="app/orders.py",
        start_line=42,
        end_line=44,
        evidence='query = "SELECT"',
        explanation="The query concatenates a request value.",
        recommendation="Use a parameterised query.",
        standards=("OWASP-WEB-2025:A05", "CWE-89"),
        sources=("llm:security",),
        corroborated=False,
        status="active",
    )
    with pytest.raises(ValidationError):
        finding.title = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Finding(
            fingerprint="short",
            lens="security",
            title="t",
            severity="high",
            confidence="high",
            file=None,
            start_line=None,
            end_line=None,
            evidence="",
            explanation="",
            recommendation="",
            standards=(),
            sources=(),
            corroborated=False,
            status="active",
        )
