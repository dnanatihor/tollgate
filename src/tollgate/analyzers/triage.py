"""SAST triage. Rejected findings never block."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tollgate.llm.structured import ChatBackend, structured_output
from tollgate.models import Finding
from tollgate.prompting import render_named


class TriageDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    decision: str
    reason: str


class TriageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decisions: list[TriageDecision] = Field(default_factory=list)


async def triage_semgrep(
    findings: tuple[Finding, ...],
    *,
    model: ChatBackend,
    annotated: dict[str, str],
) -> tuple[Finding, ...]:
    pending = [item for item in findings if item.sources and item.sources[0].startswith("semgrep:")]
    kept = [item for item in findings if item not in pending]
    if not pending:
        return tuple(kept)
    payload = [
        {
            "fingerprint": item.fingerprint,
            "file": item.file,
            "line": item.start_line,
            "title": item.title,
            "standards": list(item.standards),
        }
        for item in pending
    ]
    system, user = render_named(
        "sast_triage",
        {
            "allowed_ids": "CWE-89",
            "path": pending[0].file or "",
            "annotated_hunks": annotated.get(pending[0].file or "", ""),
            "analyzer_results_json": str(payload),
        },
    )
    output = await structured_output(
        model,
        system=system,
        user=user,
        schema=TriageOutput,
        mode="native",
    )
    if not isinstance(output, TriageOutput):
        output = TriageOutput.model_validate(output)
    reasons = {item.fingerprint: item for item in output.decisions}
    for finding in pending:
        decision = reasons.get(finding.fingerprint)
        if decision is not None and decision.decision == "reject":
            kept.append(
                finding.model_copy(
                    update={
                        "status": "dismissed_by_triage",
                        "status_reason": decision.reason[:400],
                    }
                )
            )
            continue
        kept.append(finding)
    return tuple(kept)
