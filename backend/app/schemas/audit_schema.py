"""Pydantic schemas for the AegisGemma audit report contract.

These double as the structured-output schema handed to Gemma 4 (and the
JSON schema used for validation on the way back), so every field name and
constraint is enforced by one definition.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.cvss import calculate_base_score, severity_from_score

CVSS_VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$"
)


class Severity(str, Enum):
    """Qualitative severity rating, aligned with CVSS v3.1 bands."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        return cls(severity_from_score(score))


_SEVERITY_BANDS = {
    Severity.NONE: (0.0, 0.0),
    Severity.LOW: (0.1, 3.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.HIGH: (7.0, 8.9),
    Severity.CRITICAL: (9.0, 10.0),
}


class CvssVectorModel(BaseModel):
    """A CVSS v3.1 base vector plus its base score.

    The score is always recomputed from the vector, so a model can never
    hand AegisGemma a vector/score pair that contradicts the spec.
    """

    vector: str = Field(
        ...,
        description="CVSS v3.1 base vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    score: float = Field(
        default=0.0, ge=0.0, le=10.0, description="CVSS v3.1 base score"
    )

    @field_validator("vector")
    @classmethod
    def _validate_vector(cls, value: str) -> str:
        if not CVSS_VECTOR_RE.match(value.strip()):
            raise ValueError(f"Invalid CVSS v3.1 vector: {value!r}")
        return value.strip()

    @model_validator(mode="after")
    def _score_matches_vector(self) -> "CvssVectorModel":
        computed = calculate_base_score(self.vector)
        if self.score and abs(self.score - computed) > 0.05:
            raise ValueError(
                f"CVSS score {self.score} does not match vector {self.vector} "
                f"(computed {computed})"
            )
        object.__setattr__(self, "score", computed)
        return self


class Location(BaseModel):
    file: str
    line: int = Field(..., ge=1)
    column: int | None = Field(default=None, ge=1)
    function: str | None = None


class PoC(BaseModel):
    """A non-destructive proof-of-concept for a finding."""

    kind: Literal["curl", "python", "payload", "manual", "bash"]
    title: str
    command: str
    destructive: bool = Field(
        default=False,
        description="Always False — AegisGemma only emits non-destructive verification steps.",
    )
    expected_observation: str

    @model_validator(mode="after")
    def _no_destructive_pocs(self) -> "PoC":
        if self.destructive:
            raise ValueError("AegisGemma refuses to emit destructive PoCs")
        return self


class RemediationPatch(BaseModel):
    """A unified diff that remediates a finding."""

    file: str
    diff: str
    rationale: str
    applied: bool = False

    @field_validator("diff")
    @classmethod
    def _validate_diff(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped.startswith("--- "):
            raise ValueError("Patch must be a unified diff starting with '--- '")
        if "\n+++ " not in stripped:
            raise ValueError("Patch must contain a '+++ ' target header")
        if "@@" not in stripped:
            raise ValueError("Patch must contain at least one hunk header '@@'")
        return value


class Finding(BaseModel):
    """A single vulnerability finding."""

    id: str
    title: str
    category: str = "General"
    severity: Severity
    cvss: CvssVectorModel
    cwe_id: str = Field(..., pattern=r"^CWE-\d+$")
    owasp_category: str
    location: Location
    description: str
    evidence: str = ""
    exploit_scenario: str = ""
    remediation: str = ""
    poc: PoC | None = None
    patch: RemediationPatch | None = None

    @model_validator(mode="after")
    def _severity_matches_score(self) -> "Finding":
        low, high = _SEVERITY_BANDS[self.severity]
        score = self.cvss.score
        if not (low <= score <= high):
            raise ValueError(
                f"Severity {self.severity} is inconsistent with CVSS score {score}"
            )
        return self


class AttackSurfaceNode(BaseModel):
    id: str
    label: str
    kind: Literal["entrypoint", "service", "data", "dependency", "identity", "config"]
    severity: Severity | None = None
    children: list["AttackSurfaceNode"] = Field(default_factory=list)


AttackSurfaceNode.model_rebuild()


class TargetSummary(BaseModel):
    file_count: int = Field(default=0, ge=0)
    languages: dict[str, int] = Field(default_factory=dict)
    total_lines: int = Field(default=0, ge=0)
    entrypoints: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    """Top-level audit report — the structured output Gemma 4 must produce."""

    target: str
    risk_index: int = Field(..., ge=0, le=100)
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    attack_surface: list[AttackSurfaceNode] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    target_summary: TargetSummary | None = None
    engine_status: Literal["ok", "degraded"] = "ok"
    model: str | None = None
    reasoning_summary: str | None = None

    @field_validator("summary")
    @classmethod
    def _non_empty_summary(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must not be empty")
        return value.strip()


# Schema handed to the model provider for structured JSON output.
def audit_report_schema() -> dict[str, Any]:
    """Return a JSON schema usable for provider-side structured output."""
    return AuditReport.model_json_schema()


def gemma_instruction(target: str, code_payload: str, target_type: str) -> str:
    """System instruction used for the Gemma 4 security reasoning call."""
    return f"""
You are AegisGemma, a Principal Offensive Security Engineer and Code Auditor.
Analyze the provided input for critical vulnerabilities (OWASP Top 10 and CWE
top categories). Perform multi-step threat modeling inside your internal
thinking buffer.

Target name: {target}
Target type: {target_type}

Rules:
- Only report findings that are evidenced by the supplied content.
- Every finding MUST carry a valid CVSS v3.1 base vector and a base score that
  matches the stated severity band.
- Proof-of-concept steps MUST be non-destructive and verification-only.
  Never include destructive commands (rm, DROP, mkfs, shutdown, fork bombs).
- Remediations MUST be expressed as unified diffs that apply to the listed file.
- risk_index is an aggregate 0-100 score: 0 = clean, 100 = immediately critical.

Content to analyze:
{code_payload}
""".strip()
