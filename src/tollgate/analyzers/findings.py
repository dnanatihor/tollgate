"""Build verified-by-construction findings from deterministic rules."""

from __future__ import annotations

from tollgate.models import Confidence, Finding, LensName, Severity
from tollgate.verify import fingerprint


def rule_finding(
    *,
    title: str,
    severity: Severity,
    confidence: Confidence,
    file: str,
    start_line: int,
    end_line: int,
    evidence: str,
    explanation: str,
    recommendation: str,
    standards: tuple[str, ...],
    source: str,
    lens: LensName = "architecture",
) -> Finding:
    return Finding(
        fingerprint=fingerprint(lens, file, evidence, standards[0]),
        lens=lens,
        title=title[:90],
        severity=severity,
        confidence=confidence,
        file=file,
        start_line=start_line,
        end_line=end_line,
        evidence=evidence[:600],
        explanation=explanation[:600],
        recommendation=recommendation[:400],
        standards=standards,
        sources=(source,),
        corroborated=True,
        status="active",
    )
