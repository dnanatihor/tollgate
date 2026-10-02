"""Anchor and standards checks. The model does not decide what is published."""

from __future__ import annotations

import hashlib

from tollgate.llm.schemas import ProposedFinding
from tollgate.models import Finding, LensName
from tollgate.standards import CatalogEntry

_PRIMARY: dict[str, tuple[str, ...]] = {
    "security": ("OWASP-WEB-", "OWASP-API-", "CWE-"),
    "llm_security": ("OWASP-LLM-",),
    "architecture": ("TG-ARCH-", "ORG:"),
    "performance": ("TG-PERF-",),
}


def fingerprint(lens: str, file: str | None, evidence: str, primary: str) -> str:
    material = "|".join((lens, file or "", _normalise(evidence), primary))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def annotated_lines(annotated: str) -> set[int]:
    numbers: set[int] = set()
    for line in annotated.splitlines():
        if not line.startswith("L"):
            continue
        number, _, _rest = line[1:].partition(" ")
        if number.isdigit():
            numbers.add(int(number))
    return numbers


def verify_finding(
    proposed: ProposedFinding,
    *,
    lens: LensName,
    path: str,
    annotated: str,
    file_text: str,
    known_ids: set[str],
    web_prefix: str,
    corroborated: bool = False,
    critic_upheld: bool | None = None,
) -> Finding | None:
    """Return a publishable finding, or None when it must be dropped."""
    if proposed.start_line not in annotated_lines(annotated):
        return None
    if proposed.end_line not in annotated_lines(annotated):
        return None
    if proposed.end_line < proposed.start_line:
        return None
    span = _anchor(proposed.evidence, proposed.start_line, proposed.end_line, file_text)
    if span is None:
        return None
    start, end = span
    standards = _standards(proposed.standards, lens, known_ids, web_prefix)
    if not standards:
        return None
    patch = proposed.suggested_patch
    expected = end - start + 1
    if patch is not None and len(patch.splitlines()) != expected:
        patch = None
    severity = proposed.severity
    if severity == "critical" and not corroborated and critic_upheld is not True:
        severity = "high"
    primary = standards[0]
    return Finding(
        fingerprint=fingerprint(lens, path, proposed.evidence, primary),
        lens=lens,
        title=proposed.title[:90],
        severity=severity,
        confidence=proposed.confidence,
        file=path,
        start_line=start,
        end_line=end,
        evidence=proposed.evidence,
        explanation=proposed.explanation[:600],
        recommendation=proposed.recommendation[:400],
        suggested_patch=patch,
        standards=standards,
        sources=(f"llm:{lens}",),
        corroborated=corroborated,
        status="active",
    )


def known_ids_from_catalogs(
    catalogs: dict[str, tuple[CatalogEntry, ...]],
    organisation: tuple[str, ...],
) -> set[str]:
    ids = {entry.qualified_id for entries in catalogs.values() for entry in entries}
    ids.update(organisation)
    return ids


def _canonical(raw: str, known: set[str]) -> str | None:
    """Accept an ID even when the model appends the catalog name."""
    if raw in known:
        return raw
    chosen = ""
    for known_id in known:
        if len(known_id) <= len(chosen):
            continue
        if raw.startswith(known_id) and raw[len(known_id) : len(known_id) + 1] in {" ", "\t", ":"}:
            chosen = known_id
    return chosen or None


def _standards(
    raw: list[str],
    lens: LensName,
    known: set[str],
    web_prefix: str,
) -> tuple[str, ...]:
    valid = tuple(
        item
        for item in (_canonical(entry, known) for entry in raw)
        if item is not None
    )
    prefixes = _PRIMARY[lens]
    if lens == "security":
        prefixes = (web_prefix, "OWASP-API-", "CWE-")
    primary = [item for item in valid if item.startswith(prefixes)]
    if not primary:
        return ()
    rest = [item for item in valid if item not in primary]
    return tuple(primary + rest)


def _anchor(evidence: str, start: int, end: int, file_text: str) -> tuple[int, int] | None:
    lines = file_text.splitlines()
    if _matches(evidence, lines, start, end):
        return start, end
    wanted = _normalise(evidence)
    width = max(1, len(evidence.splitlines()))
    hits: list[tuple[int, int]] = []
    for index in range(0, max(len(lines) - width + 1, 0)):
        window = lines[index : index + width]
        if _normalise("\n".join(window)) == wanted:
            hits.append((index + 1, index + width))
    if len(hits) == 1:
        return hits[0]
    return None


def _matches(evidence: str, lines: list[str], start: int, end: int) -> bool:
    if start < 1 or end > len(lines) or end < start:
        return False
    excerpt = "\n".join(lines[start - 1 : end])
    return _normalise(excerpt) == _normalise(evidence)


def _normalise(text: str) -> str:
    return " ".join(text.split())
