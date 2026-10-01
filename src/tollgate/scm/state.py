"""Summary marker and incremental review state (SPEC.md §11.5)."""

from __future__ import annotations

import base64
import re

from pydantic import ValidationError

from tollgate.models import Finding, ReviewState, StateFinding

SUMMARY_MARKER = "<!-- tollgate:summary -->"
_STATE = re.compile(r"<!-- tollgate:state ([A-Za-z0-9+/=_-]+) -->")
_MAX_FINDINGS = 200


def decode_state(body: str) -> ReviewState | None:
    match = _STATE.search(body)
    if match is None:
        return None
    try:
        raw = base64.b64decode(match.group(1))
        return ReviewState.model_validate_json(raw)
    except (ValueError, ValidationError):
        return None


def encode_state(state: ReviewState) -> str:
    token = base64.b64encode(state.model_dump_json().encode()).decode("ascii")
    return f"<!-- tollgate:state {token} -->"


def summary_body(markdown: str, state: ReviewState, resolved: tuple[str, ...]) -> str:
    text = markdown if SUMMARY_MARKER in markdown else f"{SUMMARY_MARKER}\n{markdown}"
    if resolved:
        lines = "\n".join(f"- {title}" for title in resolved)
        text = f"{text.rstrip()}\n\n## Resolved since last review\n\n{lines}\n"
    return f"{text.rstrip()}\n\n{encode_state(state)}\n"


def build_state(
    *,
    head_sha: str,
    config_hash: str,
    findings: tuple[Finding, ...],
) -> tuple[ReviewState, bool]:
    """Returns the stored state and whether incremental mode must be disabled."""
    selected = findings[:_MAX_FINDINGS]
    state = ReviewState(
        last_reviewed_head=head_sha,
        config_hash=config_hash,
        findings=tuple(_item(item) for item in selected),
    )
    return state, len(findings) > _MAX_FINDINGS


def new_fingerprints(
    findings: tuple[Finding, ...],
    previous: ReviewState | None,
) -> tuple[Finding, ...]:
    posted = set() if previous is None else {item.fp for item in previous.findings}
    return tuple(
        item for item in findings if item.status == "active" and item.fingerprint not in posted
    )


def resolved_titles(findings: tuple[Finding, ...], previous: ReviewState | None) -> tuple[str, ...]:
    if previous is None:
        return ()
    current = {item.fingerprint for item in findings}
    return tuple(item.title for item in previous.findings if item.fp not in current)


def files_for_incremental(
    changed: set[str],
    previous: ReviewState | None,
    *,
    enabled: bool,
    config_hash: str,
    force_full: bool,
) -> set[str] | None:
    """None means review every file. Otherwise review only the returned paths."""
    if force_full or not enabled or previous is None or previous.config_hash != config_hash:
        return None
    return set(changed)


def _item(finding: Finding) -> StateFinding:
    return StateFinding(
        fp=finding.fingerprint,
        file=finding.file,
        line=finding.start_line,
        severity=finding.severity,
        title=finding.title,
        standards=finding.standards,
        status=finding.status,
    )
