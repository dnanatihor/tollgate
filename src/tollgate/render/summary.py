"""Local Markdown and JSON review reports."""

from __future__ import annotations

import json

from tollgate.models import Finding, Verdict
from tollgate.rank import Ranked


def render_markdown(
    ranked: Ranked,
    verdict: Verdict,
    coverage: tuple[object, ...] = (),
) -> str:
    lines = [
        "# Tollgate",
        "",
        f"Verdict: **{verdict.outcome}**",
        "",
        "## Findings",
        "",
        "| Severity | File | Line | Title | Standards |",
        "|---|---|---|---|---|",
    ]
    if not ranked.findings:
        lines.append("| | | | No findings | |")
    for finding in ranked.findings:
        line = "" if finding.start_line is None else str(finding.start_line)
        standards = ", ".join(finding.standards)
        row = (
            f"| {finding.severity} | {finding.file or ''} | {line} "
            f"| {finding.title} | {standards} |"
        )
        lines.append(row)
    if ranked.inline:
        lines.extend(["", "## Inline", ""])
        for finding in ranked.inline:
            lines.append(
                f"- `{finding.file}:{finding.start_line}` {finding.title} "
                f"({', '.join(finding.standards)})"
            )
    if coverage:
        lines.extend(["", "## Coverage", ""])
        for note in coverage:
            analyzer = getattr(note, "analyzer", "analyzer")
            detail = getattr(note, "detail", "")
            lines.append(f"- {analyzer}: {detail}")
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding], verdict: Verdict) -> str:
    payload = {
        "verdict": verdict.outcome,
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    return json.dumps(payload, indent=2) + "\n"
