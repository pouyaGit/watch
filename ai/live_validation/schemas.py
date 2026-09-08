"""Typed output boundary for the live validation lane (Phase 5K-live).

No verdict, finding, confirmed, not_vulnerable, severity, exploited,
confidence, verdict, or LLM text fields. ``extra="forbid"`` enforced.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

# ------------------------------------------------------------------
# Closed vocabularies
# ------------------------------------------------------------------

LiveValidationMode = Literal["dry_run", "live"]
LiveValidationStatus = Literal["BLOCKED", "NO_MATCH", "MATCH_UNVERIFIED", "VERIFIED"]
GateDecision = Literal["PASS", "BLOCK", "NOT_PERFORMED"]


class GateResult(BaseModel):
    """Deterministic per-gate record (first failure blocks)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    gate: str
    decision: GateDecision
    reason: str = ""


class LiveValidationEvidence(BaseModel):
    """Sealed execution evidence metadata (no verdict)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_id: str
    evidence_id: str
    authorization_id: str
    outcome: str
    error_code: str | None = None
    error_detail: str = ""
    template_id: str = ""
    template_hash: str = ""
    argv_digest: str = ""
    exit_code: int | None = None
    finding_like_text_present: bool = False
    evidence_bindings_hash: str | None = None
    evidence_observations_hash: str | None = None
    evidence_content_hash: str | None = None


class VerificationFacts(BaseModel):
    """Deterministic verifier outcome record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verifier_version: str
    rule_id: str
    outcome: str
    outcome_detail: str = ""
    result_hash: str | None = None
    reason_code: str = ""
    finding_eligible: bool = False


class LiveValidationResult(BaseModel):
    """Final lane output (verdict-free, no authority).

    ``authoritative`` is always False (5J is never touched).
    ``research_only`` is True for dry_run mode.
    ``live_validation`` is True by construction.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # -- identity --
    cve_id: str
    target: str | None = None
    mode: LiveValidationMode
    status: LiveValidationStatus

    # -- gate chain --
    gates: tuple[GateResult, ...] = ()
    blocked_reason: str | None = None

    # -- authority discipline --
    authoritative: Literal[False] = False
    research_only: bool
    live_validation: Literal[True] = True

    # -- evidence --
    execution: LiveValidationEvidence | None = None
    verification: VerificationFacts | None = None

    # -- determinism --
    result_hash: str = ""

    @field_validator("cve_id")
    @classmethod
    def _cve_id(cls, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("CVE-"):
            raise ValueError(f"invalid cve_id: {value!r}")
        return value
