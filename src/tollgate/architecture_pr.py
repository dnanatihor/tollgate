"""PR-level architecture assessment (SPEC.md §7.6). Paths that do not exist are dropped."""

from __future__ import annotations

import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from tollgate.globs import matches_any
from tollgate.llm.structured import ChatBackend, structured_output
from tollgate.prompting import render_named

_QUESTION_CAP = 3


class SignificantChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    files: list[str] = Field(default_factory=list)
    trigger: str = ""


class AdrConflict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adr_path: str
    explanation: str


class AdrAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required: bool = False
    present_in_pr: bool = False
    conflicts: list[AdrConflict] = Field(default_factory=list)


class PrincipleConcern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    standard: str
    explanation: str
    files: list[str] = Field(default_factory=list)


class ArchitectureAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str = ""
    significant_changes: list[SignificantChange] = Field(default_factory=list)
    adr: AdrAssessment = Field(default_factory=AdrAssessment)
    principle_concerns: list[PrincipleConcern] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    questions_for_author: list[str] = Field(default_factory=list)


def keep_known_paths(
    assessment: ArchitectureAssessment,
    *,
    files: set[str],
    documents: set[str],
) -> ArchitectureAssessment:
    """Drop file and ADR paths that are neither in the pull request nor in the repository."""
    known = files | documents
    kept_changes: list[SignificantChange] = []
    for change in assessment.significant_changes:
        kept_files = [path for path in change.files if path in files]
        if kept_files:
            kept_changes.append(change.model_copy(update={"files": kept_files}))
    conflicts = [conflict for conflict in assessment.adr.conflicts if conflict.adr_path in known]
    concerns: list[PrincipleConcern] = []
    for concern in assessment.principle_concerns:
        kept = [path for path in concern.files if path in files]
        if kept:
            concerns.append(concern.model_copy(update={"files": kept}))
    return assessment.model_copy(
        update={
            "significant_changes": kept_changes,
            "adr": assessment.adr.model_copy(update={"conflicts": conflicts}),
            "principle_concerns": concerns,
            "questions_for_author": assessment.questions_for_author[:_QUESTION_CAP],
        }
    )


def load_documents(
    root: Path,
    ref: str,
    patterns: list[str],
) -> tuple[tuple[str, str], ...]:
    """Read ADR and architecture documents from the base ref."""
    if not patterns:
        return ()
    listed = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        return ()
    documents: list[tuple[str, str]] = []
    for path in listed.stdout.splitlines():
        if not matches_any(path, patterns):
            continue
        shown = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if shown.returncode == 0 and shown.stdout.strip():
            documents.append((path, shown.stdout[:4000]))
        if len(documents) >= 20:
            break
    return tuple(documents)


def render_assessment(assessment: ArchitectureAssessment) -> str:
    lines = [assessment.intent] if assessment.intent else []
    if assessment.questions_for_author:
        lines.append("Questions:")
        lines.extend(f"- {item}" for item in assessment.questions_for_author)
    if assessment.risks:
        lines.append("Risks:")
        lines.extend(f"- {item}" for item in assessment.risks)
    return "\n".join(lines)


async def assess_pull_request(
    model: ChatBackend,
    *,
    title: str,
    description: str,
    files: list[str],
    triggers: str,
    retrieved: list[str],
    allowed_ids: str,
    known_files: set[str],
    known_documents: set[str],
    mode: str = "auto",
) -> ArchitectureAssessment:
    system, user = render_named(
        "architecture_pr",
        {
            "allowed_ids": allowed_ids,
            "pr_title": title,
            "pr_description": description,
            "files": "\n".join(files),
            "triggers": triggers,
            "retrieved": "\n".join(retrieved),
        },
    )
    parsed = await structured_output(
        model,
        system=system,
        user=user,
        schema=ArchitectureAssessment,
        mode=mode,
    )
    assessment = (
        parsed
        if isinstance(parsed, ArchitectureAssessment)
        else ArchitectureAssessment.model_validate(parsed)
    )
    return keep_known_paths(assessment, files=known_files, documents=known_documents)
