"""5J finding eligibility gate (Phase 5J, deterministic, versioned).

Pinned policy ``5j-eligibility-policy/v1`` — the ONLY production
eligibility rule in this build::

    CONFIRMED + finding_eligible=true  -> ELIGIBLE
    CONFIRMED + finding_eligible=false -> INELIGIBLE (flag false)
    POTENTIAL / UNKNOWN                -> INELIGIBLE (outcome)
    NOT_VULNERABLE                     -> invariant violation, fail closed

There is deliberately NO configuration flag, NO caller override, and
NO promotion path for POTENTIAL / UNKNOWN / INCONCLUSIVE. (INCONCLUSIVE
is not even representable: the frozen 5I ``Outcome`` literal has no
such member, so it fails 5I validation before 5J ever sees it.)

5I's broader ``FINDING_ELIGIBLE_OUTCOMES`` set is a classifier-internal
ceiling, NOT production eligibility; this gate narrows it, and the
narrowing itself is version-pinned and audited.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.verification.deterministic.result import (
    OUTCOME_CONFIRMED,
    OUTCOME_NOT_VULNERABLE,
    ClassificationResult,
)

__all__ = [
    "ELIGIBILITY_POLICY_VERSION",
    "ELIGIBLE",
    "OUTCOME_NOT_FINDING_ELIGIBLE",
    "FINDING_ELIGIBLE_FLAG_FALSE",
    "ELIGIBILITY_INVARIANT_VIOLATION",
    "EligibilityDecision",
    "check_eligibility",
]

#: Pinned eligibility policy version (the ONLY version this build
#: implements; stamped on every finding and hashed into its identity).
ELIGIBILITY_POLICY_VERSION = "5j-eligibility-policy/v1"

ELIGIBLE = "ELIGIBLE"
OUTCOME_NOT_FINDING_ELIGIBLE = "OUTCOME_NOT_FINDING_ELIGIBLE"
FINDING_ELIGIBLE_FLAG_FALSE = "FINDING_ELIGIBLE_FLAG_FALSE"
ELIGIBILITY_INVARIANT_VIOLATION = "ELIGIBILITY_INVARIANT_VIOLATION"


@dataclass(frozen=True)
class EligibilityDecision:
    """Deterministic eligibility outcome (never a verdict)."""

    eligible: bool
    reason: str


def check_eligibility(
    classification: ClassificationResult,
) -> EligibilityDecision:
    """Apply the pinned v1 eligibility table (pure, deterministic).

    Raises ``TypeError`` for non-``ClassificationResult`` input (a
    programming error, never a security decision). ``NOT_VULNERABLE``
    can never be produced by 5I; reaching it here is an invariant
    violation and fails closed to INELIGIBLE (never a finding, never
    a negative verdict — just refusal).
    """
    if not isinstance(classification, ClassificationResult):
        raise TypeError(
            "eligibility accepts only ClassificationResult, "
            f"not {type(classification).__name__}"
        )
    if classification.outcome == OUTCOME_NOT_VULNERABLE:
        return EligibilityDecision(False, ELIGIBILITY_INVARIANT_VIOLATION)
    if classification.outcome != OUTCOME_CONFIRMED:
        return EligibilityDecision(False, OUTCOME_NOT_FINDING_ELIGIBLE)
    if not classification.finding_eligible:
        return EligibilityDecision(False, FINDING_ELIGIBLE_FLAG_FALSE)
    return EligibilityDecision(True, ELIGIBLE)
