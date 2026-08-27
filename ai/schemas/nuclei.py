from __future__ import annotations

from pydantic import BaseModel, Field


class NucleiDecision(BaseModel):
    cve_id: str

    decision: str
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    reason: str

    protocol: list[str] = Field(
        default_factory=list
    )

    http_detectable: bool = False

    version_required: bool = True

    exploit_evidence: str = "unknown"

    detection_requirements: list[str] = Field(
        default_factory=list
    )