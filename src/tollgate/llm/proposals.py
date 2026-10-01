"""Schemas the lenses must return. The model does not set verdicts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from tollgate.models import Confidence, Severity


class ProposedFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str
    severity: Severity
    confidence: Confidence
    start_line: int
    end_line: int
    evidence: str
    explanation: str
    recommendation: str
    suggested_patch: str | None = None
    standards: list[str] = Field(default_factory=list)


class LensResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    findings: list[ProposedFinding] = Field(default_factory=list)


class SignificantChange(BaseModel):
    model_config = ConfigDict(extra="ignore")

    description: str
    files: list[str] = Field(default_factory=list)
    trigger: str


class AdrAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")

    required: bool = False
    present_in_pr: bool = False
    conflicts: list[dict[str, str]] = Field(default_factory=list)


class PrincipleConcern(BaseModel):
    model_config = ConfigDict(extra="ignore")

    standard: str
    explanation: str
    files: list[str] = Field(default_factory=list)


class ArchitectureAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")

    intent: str = ""
    significant_changes: list[SignificantChange] = Field(default_factory=list)
    adr: AdrAssessment = Field(default_factory=AdrAssessment)
    principle_concerns: list[PrincipleConcern] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    questions_for_author: list[str] = Field(default_factory=list)


class CriticResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    decision: Literal["uphold", "downgrade", "reject"]
    reason: str
