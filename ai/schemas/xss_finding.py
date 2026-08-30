from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class XSSFinding(BaseModel):
    """
    Evidence-backed XSS finding.

    This represents the final assessment, not merely
    a reflected-input observation.
    """

    finding_id: str

    case_id: str

    target: str
    endpoint: str

    method: str

    parameter: str | None = None
    parameter_location: str | None = None

    xss_type: str
    # reflected / stored / dom / mutation

    context_type: str

    status: str
    # CONFIRMED
    # POTENTIAL
    # NOT_VULNERABLE
    # INCONCLUSIVE

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    payload_reference: str | None = None

    verification_mode: str | None = None
    # http_reflection / browser_execution / None

    attempt_id: str | None = None
    # Deterministic SHA-256-based identifier of the
    # VerificationAttempt that produced this finding.
    # Traces the finding back to the exact attempt that
    # ran. None when the finding is constructed without a
    # verifier attempt (e.g. legacy fixtures).

    reflection_evidence: list[str] = Field(
        default_factory=list
    )

    verification_evidence: list[str] = Field(
        default_factory=list
    )

    browser_verified: bool = False

    waf_observations: list[str] = Field(
        default_factory=list
    )

    knowledge_references: list[str] = Field(
        default_factory=list
    )

    remediation_notes: list[str] = Field(
        default_factory=list
    )

    created_at: str = Field(
        default_factory=lambda:
        datetime.now(
            timezone.utc
        ).isoformat()
    )