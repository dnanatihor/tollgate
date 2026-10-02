"""Dedupe, score, and cap inline comments."""

from __future__ import annotations

from dataclasses import dataclass

from tollgate.config import TollgateConfig
from tollgate.models import Finding

_SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_CONFIDENCE = {"low": 1, "medium": 2, "high": 3}
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_CONFIDENCE_ORDER = ("low", "medium", "high")


@dataclass(frozen=True, slots=True)
class Ranked:
    findings: tuple[Finding, ...]
    inline: tuple[Finding, ...]
    summary_only: tuple[Finding, ...]
    dismissed: tuple[Finding, ...] = ()
    suppressed_in_pr: tuple[Finding, ...] = ()


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: list[Finding] = []
    for finding in findings:
        partner = next((item for item in merged if _same(item, finding)), None)
        if partner is None:
            merged.append(finding)
            continue
        merged[merged.index(partner)] = _merge(partner, finding)
    return merged


def rank_findings(findings: list[Finding], config: TollgateConfig) -> Ranked:
    dismissed = tuple(
        item for item in findings if item.status in {"dismissed_by_critic", "dismissed_by_triage"}
    )
    suppressed = tuple(
        item
        for item in findings
        if item.status == "suppressed" and item.status_reason == "suppressed in this PR"
    )
    active = [item for item in dedupe(findings) if item.status == "active"]
    ordered = sorted(active, key=score, reverse=True)
    inline: list[Finding] = []
    rest: list[Finding] = []
    for finding in ordered:
        eligible = _at_least(finding.severity, config.min_inline.severity, _SEVERITY_ORDER) and (
            _at_least(finding.confidence, config.min_inline.confidence, _CONFIDENCE_ORDER)
        )
        if eligible and len(inline) < config.max_inline_comments:
            inline.append(finding)
        else:
            rest.append(finding)
    return Ranked(
        findings=tuple(ordered),
        inline=tuple(inline),
        summary_only=tuple(rest),
        dismissed=dismissed,
        suppressed_in_pr=suppressed,
    )


def score(finding: Finding) -> float:
    value = float(_SEVERITY[finding.severity] * _CONFIDENCE[finding.confidence])
    if finding.corroborated:
        value *= 1.2
    return value


def _same(left: Finding, right: Finding) -> bool:
    if left.fingerprint == right.fingerprint:
        return True
    if left.file is None or left.file != right.file:
        return False
    if not left.standards or not right.standards or left.standards[0] != right.standards[0]:
        return False
    return _overlaps(left, right)


def _overlaps(left: Finding, right: Finding) -> bool:
    if left.start_line is None or right.start_line is None:
        return False
    left_end = left.end_line if left.end_line is not None else left.start_line
    right_end = right.end_line if right.end_line is not None else right.start_line
    return left.start_line <= right_end and right.start_line <= left_end


def _merge(left: Finding, right: Finding) -> Finding:
    winner = left if _SEVERITY[left.severity] >= _SEVERITY[right.severity] else right
    standards = tuple(dict.fromkeys((*left.standards, *right.standards)))
    sources = tuple(dict.fromkeys((*left.sources, *right.sources)))
    return winner.model_copy(
        update={
            "standards": standards,
            "sources": sources,
            "corroborated": left.corroborated or right.corroborated,
        }
    )


def _at_least(value: str, minimum: str, order: tuple[str, ...]) -> bool:
    return order.index(value) >= order.index(minimum)
