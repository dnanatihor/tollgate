"""Baseline fingerprints and inline ``tollgate-ignore`` comments (SPEC.md §10.1)."""

from __future__ import annotations

import json
import re

from tollgate.config import TollgateConfig
from tollgate.models import Finding

_ORDER = ("info", "low", "medium", "high", "critical")
_IGNORE = re.compile(r"tollgate-ignore:\s*(\S+)\s+(\S.*)$")


def baseline_fingerprints(payload: str) -> set[str]:
    if not payload.strip():
        return set()
    loaded = json.loads(payload)
    if not isinstance(loaded, dict):
        return set()
    raw = loaded.get("fingerprints", [])
    if not isinstance(raw, list):
        return set()
    return {item for item in raw if isinstance(item, str)}


def apply_suppressions(
    findings: list[Finding],
    *,
    head_texts: dict[str, str],
    base_texts: dict[str, str],
    baseline: set[str],
    config: TollgateConfig,
) -> list[Finding]:
    updated: list[Finding] = []
    for finding in findings:
        if finding.status != "active":
            updated.append(finding)
            continue
        if finding.fingerprint in baseline:
            updated.append(
                finding.model_copy(update={"status": "suppressed", "status_reason": "baseline"})
            )
            continue
        ignore = _ignore(finding, head_texts, base_texts)
        if ignore is None:
            updated.append(finding)
            continue
        if ignore == "base":
            updated.append(
                finding.model_copy(update={"status": "suppressed", "status_reason": "baseline"})
            )
            continue
        if not _within(finding.severity, config.suppressions.allow_new_in_pr_max_severity):
            updated.append(finding)
            continue
        updated.append(
            finding.model_copy(
                update={"status": "suppressed", "status_reason": "suppressed in this PR"}
            )
        )
    return updated


def _ignore(
    finding: Finding,
    head_texts: dict[str, str],
    base_texts: dict[str, str],
) -> str | None:
    """Return ``base`` when the comment is already on the base ref, else ``new``."""
    if finding.file is None or finding.start_line is None:
        return None
    head = head_texts.get(finding.file, "").splitlines()
    base = base_texts.get(finding.file, "").splitlines()
    for number in (finding.start_line - 1, finding.start_line):
        if number < 1 or number > len(head):
            continue
        text = head[number - 1]
        match = _IGNORE.search(text)
        if match is None or match.group(1) not in finding.standards:
            continue
        base_text = base[number - 1] if number <= len(base) else ""
        if base_text == text:
            return "base"
        return "new"
    return None


def _within(severity: str, cap: str) -> bool:
    return _ORDER.index(severity) <= _ORDER.index(cap)
