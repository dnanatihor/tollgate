"""Schemas the lenses must return. Extra fields are rejected so output is verified."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProposedFinding(_Model):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    start_line: int
    end_line: int
    evidence: str
    explanation: str
    recommendation: str
    suggested_patch: str | None = None
    standards: list[str] = Field(default_factory=list)


class LensOutput(_Model):
    findings: list[ProposedFinding] = Field(default_factory=list)


class SignificantChange(_Model):
    description: str
    files: list[str] = Field(default_factory=list)
    trigger: str


class AdrConflict(_Model):
    adr_path: str
    explanation: str


class AdrAssessment(_Model):
    required: bool = False
    present_in_pr: bool = False
    conflicts: list[AdrConflict] = Field(default_factory=list)


class PrincipleConcern(_Model):
    standard: str
    explanation: str
    files: list[str] = Field(default_factory=list)


class ArchitectureAssessment(_Model):
    intent: str
    significant_changes: list[SignificantChange] = Field(default_factory=list)
    adr: AdrAssessment = Field(default_factory=AdrAssessment)
    principle_concerns: list[PrincipleConcern] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    questions_for_author: list[str] = Field(default_factory=list)


class Probe(_Model):
    ok: bool
