"""Parse gitleaks JSON. Secret values are masked before they are stored."""

from __future__ import annotations

import json

from tollgate.analyzers.findings import rule_finding
from tollgate.models import DiffFile, Finding


def parse_gitleaks(payload: str, diffs: tuple[DiffFile, ...]) -> tuple[Finding, ...]:
    loaded = json.loads(payload or "[]")
    if not isinstance(loaded, list):
        return ()
    changed = {diff.path: _changed(diff) for diff in diffs}
    findings: list[Finding] = []
    for item in loaded:
        if not isinstance(item, dict):
            continue
        path = str(item.get("File") or item.get("file") or "")
        start = item.get("StartLine") or item.get("startLine")
        if not isinstance(start, int) or start not in changed.get(path, set()):
            continue
        findings.append(
            rule_finding(
                lens="security",
                title="Secret committed in the diff",
                severity="critical",
                confidence="high",
                file=path,
                start_line=start,
                end_line=start,
                evidence="«secret»",
                explanation="gitleaks found a secret on a changed line. The value is masked.",
                recommendation="Remove the secret and rotate it.",
                standards=("OWASP-WEB-2025:A04",),
                source="gitleaks",
            )
        )
    return tuple(findings)


def _changed(diff: DiffFile) -> set[int]:
    return {
        line.new_line
        for hunk in diff.hunks
        for line in hunk.lines
        if line.kind == "+" and line.new_line is not None
    }
