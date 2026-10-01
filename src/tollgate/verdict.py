"""Deterministic verdict. The model never approves a pull request."""

from __future__ import annotations

from tollgate.config import TollgateConfig
from tollgate.models import Finding, Verdict

_ORDER = ("info", "low", "medium", "high", "critical")


def decide(findings: list[Finding], config: TollgateConfig) -> Verdict:
    active = [item for item in findings if item.status == "active"]
    blocking = tuple(
        item.fingerprint
        for item in active
        if _at_least(item.severity, config.fail_on) and _at_least(item.confidence, "medium")
    )
    if blocking:
        return Verdict(outcome="block", blocking=blocking)
    concern_floor = "medium" if config.fail_on == "high" else "high"
    if any(_at_least(item.severity, concern_floor) for item in active):
        return Verdict(outcome="concerns")
    return Verdict(outcome="pass")


def _at_least(value: str, minimum: str) -> bool:
    return _ORDER.index(value) >= _ORDER.index(minimum)
