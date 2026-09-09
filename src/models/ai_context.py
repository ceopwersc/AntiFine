"""Typed, sanitized-at-the-boundary context supplied to the AI assistant."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


AIContextSource = Literal[
    "finding",
    "scan",
    "dashboard",
    "compliance",
    "remediation",
    "general",
]


class AIFindingContext(BaseModel):
    """A lightweight API representation of a finding.

    This intentionally does not replace the canonical scanner ``Finding``
    dataclass; it accepts UI context fields that are not part of that model.
    """

    rule_id: str | None = None
    title: str | None = None
    severity: str | None = None
    technology: str | None = None
    file: str | None = None
    line: int | None = None
    frameworks: list[str] = Field(default_factory=list)
    status: str | None = None
    description: str | None = None
    remediation: str | None = None


class AIScanContext(BaseModel):
    target_path: str | None = None
    scan_type: str | None = None
    findings: list[AIFindingContext] = Field(default_factory=list)


class AIComplianceContext(BaseModel):
    framework: str | None = None
    controls: list[str] = Field(default_factory=list)
    status: str | None = None
    findings: list[AIFindingContext] = Field(default_factory=list)


class AIRemediationContext(BaseModel):
    finding_id: str | None = None
    rule_id: str | None = None
    action: str | None = None
    path: str | None = None
    diff: str | None = None
    status: str | None = None


class AIContext(BaseModel):
    source: AIContextSource
    finding: AIFindingContext | None = None
    scan: AIScanContext | None = None
    compliance: AIComplianceContext | None = None
    remediation: AIRemediationContext | None = None
    selected_file: str | None = None
