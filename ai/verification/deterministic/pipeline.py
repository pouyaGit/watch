"""5I verifier entry point: sealed handoff in, classification out.

``verify_handoff`` is the sole orchestration path:

    VerifierInput
      -> integrity/provenance gate (exact frozen order, first failure wins)
      -> typed sealed observation + deterministic classifier
      -> immutable hashed ClassificationResult

Gate failures are blocked/rejected states carrying a closed reason —
never CONFIRMED/POTENTIAL and never a negative security result. The
verifier consumes consumed authorization as PROVENANCE only
(``AUTHZ_VALID_FOR_PROVENANCE``) and never enables any execution.
Audit events are appended via the injected sink; audit failure never
mutates evidence or classification.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.schemas import evidence as ev

from ai.verification.deterministic.classifier import classify_evidence
from ai.verification.deterministic.gate import (
    VERIFIED,
    GateOutcome,
    verify_handoff_evidence,
)
from ai.verification.deterministic.models import (
    OUTCOME_UNKNOWN,
    VerifierAuditEvent,
    VerifierInput,
    emit_audit,
)
from ai.verification.deterministic.result import (
    ClassificationResult,
    compute_result_hash,
)

__all__ = ["VerificationOutcome", "verify_handoff"]


@dataclass(frozen=True)
class VerificationOutcome:
    """Deterministic verification outcome (result or blocked state)."""

    accepted: bool
    reason: str
    result: ClassificationResult | None = None
    gate: GateOutcome | None = None
    result_hash: str | None = None


def verify_handoff(
    verifier_input: VerifierInput,
    seam: object,
    *,
    audit: object = None,
) -> VerificationOutcome:
    """Run the full 5I verification pipeline for one handoff.

    Idempotent: the same ``VerifierInput`` (byte-identical envelope +
    pinned versions) yields a byte-identical result and hash.
    """
    outcome = verify_handoff_evidence(verifier_input, seam, audit=audit)
    if outcome.blocked or outcome.record is None:
        reason = outcome.reason or "HANDOFF_MALFORMED"
        return VerificationOutcome(
            accepted=False, reason=reason, gate=outcome
        )
    record = outcome.record
    try:
        result = classify_evidence(
            record,
            authorization=outcome.authorization,
            seam=seam,
        )
    except Exception:
        # Classifier invariant breach (incl. NOT_VULNERABLE targeting)
        # is never converted into a verdict: fail closed to UNKNOWN.
        return VerificationOutcome(
            accepted=False,
            reason="classification_invariant_violation",
            gate=outcome,
        )
    event = (
        VerifierAuditEvent(
            event="CLASSIFICATION_COMPLETED",
            evidence_id=record.evidence_id,
            execution_id=record.execution_id,
            authorization_id=record.authorization_id,
            program_name=record.program_name,
            host=record.target.host,
            reason_code=result.reason_code,
            outcome=result.outcome,
            result_hash=compute_result_hash(result),
        )
        if result.outcome != OUTCOME_UNKNOWN
        else VerifierAuditEvent(
            event="CLASSIFICATION_BLOCKED_UNKNOWN",
            evidence_id=record.evidence_id,
            execution_id=record.execution_id,
            authorization_id=record.authorization_id,
            program_name=record.program_name,
            host=record.target.host,
            reason_code=result.reason_code,
            outcome=result.outcome,
            result_hash=compute_result_hash(result),
        )
    )
    emit_audit(audit, event)
    return VerificationOutcome(
        accepted=True,
        reason=result.reason_code,
        result=result,
        gate=outcome,
        result_hash=compute_result_hash(result),
    )
