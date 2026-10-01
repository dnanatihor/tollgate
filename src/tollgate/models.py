"""Shared review models from SPEC.md §10 and the pipeline types they depend on.

Publishing fields are carried here so later phases share one schema. Phase 0
validates the shapes; it does not produce findings.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
LensName = Literal["security", "llm_security", "architecture", "performance"]
FindingStatus = Literal[
    "active",
    "suppressed",
    "dismissed_by_critic",
    "dismissed_by_triage",
    "resolved",
]
VerdictOutcome = Literal["pass", "concerns", "block"]
FileRole = Literal[
    "source",
    "test",
    "config",
    "infrastructure_as_code",
    "database_migration",
    "api_contract",
    "dependency_manifest",
    "ci_pipeline",
    "container",
    "documentation",
]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DiffLine(_Frozen):
    """One line of a hunk. ``new_line`` is None for deletions."""

    kind: Literal["+", "-", " "]
    text: str
    old_line: int | None = None
    new_line: int | None = None


class Hunk(_Frozen):
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    lines: tuple[DiffLine, ...]


class DiffFile(_Frozen):
    path: str
    old_path: str | None = None
    status: Literal["added", "modified", "deleted", "renamed", "binary"]
    hunks: tuple[Hunk, ...] = ()
    binary: bool = False


class PullRequest(_Frozen):
    platform: Literal["github", "bitbucket_cloud", "bitbucket_dc", "local"]
    repo: str
    number: str
    title: str
    description: str
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    author: str
    is_fork: bool = False


class ReviewUnit(_Frozen):
    path: str
    language: str
    role: FileRole
    risk_signals: tuple[str, ...] = ()
    llm_signals: tuple[str, ...] = ()
    annotated_hunks: str = ""
    structural_context: str = ""
    lenses: tuple[str, ...] = ()
    estimated_tokens: int = 0


class Finding(_Frozen):
    fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    lens: LensName
    title: str = Field(max_length=90)
    severity: Severity
    confidence: Confidence
    file: str | None
    start_line: int | None
    end_line: int | None
    evidence: str
    explanation: str = Field(max_length=600)
    recommendation: str = Field(max_length=400)
    suggested_patch: str | None = None
    standards: tuple[str, ...]
    sources: tuple[str, ...]
    corroborated: bool
    status: FindingStatus
    status_reason: str | None = None


class Verdict(_Frozen):
    outcome: VerdictOutcome
    blocking: tuple[str, ...] = ()


class StateFinding(_Frozen):
    fp: str
    file: str | None
    line: int | None
    severity: Severity
    title: str
    standards: tuple[str, ...]
    status: FindingStatus


class ReviewState(_Frozen):
    """Hidden marker stored on the summary comment (SPEC.md §11.5)."""

    v: int = 1
    last_reviewed_head: str
    config_hash: str
    findings: tuple[StateFinding, ...] = Field(default=(), max_length=200)
