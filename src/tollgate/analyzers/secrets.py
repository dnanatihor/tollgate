"""Built-in secret patterns used when gitleaks is not available."""

from __future__ import annotations

import re

from tollgate.analyzers.findings import rule_finding
from tollgate.models import DiffFile, Finding

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|secret|token|authorization)\b\s*[:=]\s*(\S+)"
)
_AWS = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")


def builtin_secret_findings(
    diffs: tuple[DiffFile, ...],
    head_texts: dict[str, str],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for diff in diffs:
        text = head_texts.get(diff.path, "")
        added = {
            line.new_line
            for hunk in diff.hunks
            for line in hunk.lines
            if line.kind == "+" and line.new_line is not None
        }
        for number, line in enumerate(text.splitlines(), start=1):
            if number not in added:
                continue
            if _ASSIGNMENT.search(line) is None and _AWS.search(line) is None:
                continue
            findings.append(
                rule_finding(
                    lens="security",
                    title="Hard-coded secret",
                    severity="critical",
                    confidence="high",
                    file=diff.path,
                    start_line=number,
                    end_line=number,
                    evidence="«secret»",
                    explanation="A secret appears in a changed line. The value is masked.",
                    recommendation="Remove the secret and load it from the environment.",
                    standards=("OWASP-WEB-2025:A04",),
                    source="gitleaks",
                )
            )
    return tuple(findings)
