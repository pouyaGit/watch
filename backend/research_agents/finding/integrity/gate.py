"""Evidence Gate hardening (EPIC11 §6, §7, §8).

Turns a :class:`ClaimEvaluation` into the *authoritative* finding decision.
This module is the only place that may answer "is this a confirmed
vulnerability?" — and it answers from persisted evidence types, never from
the runtime's generic ">= N rows at high confidence" rule, never from an
LLM, never from a parameter name.

Fail-closed mapping (§5 ladder, §6 reasons):

    confirmation claim SUPPORTED            -> VERIFIED_ELIGIBLE -> VERIFIED
    contradictions at the claim's stages    -> REJECTED
    only authorization missing              -> BLOCKED
    anything else missing                   -> VERIFICATION_PENDING

``VERIFICATION_PENDING`` is a first-class outcome: the candidate and the
verification are parked honestly with the exact missing evidence attached,
and no human-facing artifact may present it as confirmed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.integrity import claims as cl
from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import taxonomy as tx

GATE_RULE_VERSION = "epic11-integrity-gate-1"

# integrity outcome -> the existing closed verification vocabulary
VERIFIED = "VERIFIED"
VERIFICATION_PENDING = "VERIFICATION_PENDING"
BLOCKED = "BLOCKED"
REJECTED = "REJECTED"

INTEGRITY_STATES: tuple[str, ...] = (
    VERIFIED, VERIFICATION_PENDING, BLOCKED, REJECTED)

# verification-objective vocabulary is the existing closed set
_VERIFICATION_STATE: dict[str, str] = {
    VERIFIED: "VERIFIED",
    VERIFICATION_PENDING: "INCONCLUSIVE",
    BLOCKED: "BLOCKED",
    REJECTED: "REJECTED",
}

BLOCKER_MISSING_AUTHORIZATION = "verification_not_authorized"
BLOCKER_UNSUPPORTED_CLAIMS = "unsupported_claims"
BLOCKER_GATE_NOT_AUTHORITATIVE = "runtime_gate_not_authoritative"
BLOCKER_CONTRADICTED = "contradicted_by_evidence"


@dataclass
class IntegrityDecision:
    """Authoritative decision + the full claim/evidence basis."""

    authoritative_state: str
    verification_state: str
    candidate_state: str
    gate_reason: str
    claim_integrity: dict[str, Any] = field(default_factory=dict)
    missing_evidence: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    stage_reached: int = 0
    missing_evidence_types: list[str] = field(default_factory=list)
    missing_reasons: list[str] = field(default_factory=list)
    malformed_evidence: list[str] = field(default_factory=list)
    confirmation_evidence_ids: list[str] = field(default_factory=list)
    runtime_gate_reason: str = ""
    runtime_gate_claimed_case: bool = False
    limitations: list[str] = field(default_factory=list)
    rule_version: str = GATE_RULE_VERSION
    # ---- EPIC14 trust boundary -------------------------------------------
    #: rows whose declared evidence type disagreed with the authoritative
    #: classification of their signal (§5)
    evidence_mismatches: list[dict[str, Any]] = field(default_factory=list)
    #: EPIC16 §21/§23: cross-class rows quarantined from this class's claim
    class_quarantine: list[dict[str, Any]] = field(default_factory=list)
    #: the vulnerability class this decision was made for
    evaluated_class: str = ""
    #: confirmation-capable rows excluded from authoritative support (§17)
    excluded_evidence: list[dict[str, Any]] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.authoritative_state == VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "authoritative_state": self.authoritative_state,
            "verification_state": self.verification_state,
            "candidate_state": self.candidate_state,
            "gate_reason": self.gate_reason,
            "claim_integrity": dict(self.claim_integrity),
            "missing_evidence": list(self.missing_evidence),
            "blockers": list(self.blockers),
            "contradictions": list(self.contradictions),
            "stage_reached": self.stage_reached,
            "confirmation_evidence_ids":
                list(self.confirmation_evidence_ids),
            "runtime_gate_reason": self.runtime_gate_reason,
            "runtime_gate_claimed_case": self.runtime_gate_claimed_case,
            "limitations": list(self.limitations),
            "rule_version": self.rule_version,
            "evidence_mismatches": list(self.evidence_mismatches),
            "class_quarantine": list(self.class_quarantine),
            "evaluated_class": self.evaluated_class,
            "excluded_evidence": list(self.excluded_evidence),
        }


def evaluate_integrity(
    *,
    vulnerability_class: Any,
    rows: Iterable[dict[str, Any]],
    authorization: ct.AuthorizationContext | None = None,
    runtime_gate_reason: str = "",
    runtime_gate_claimed_case: bool = False,
) -> IntegrityDecision:
    """Authoritative claim-contract evaluation over persisted evidence."""
    evaluation = cl.evaluate_rows(
        vulnerability_class, rows, authorization=authorization)
    return decide(evaluation, runtime_gate_reason=runtime_gate_reason,
                  runtime_gate_claimed_case=runtime_gate_claimed_case)


def decide(
    evaluation: cl.ClaimEvaluation,
    *,
    runtime_gate_reason: str = "",
    runtime_gate_claimed_case: bool = False,
) -> IntegrityDecision:
    confirmation = evaluation.confirmation_claim
    confirmation_ids = list(confirmation.supporting_evidence_ids) \
        if confirmation else []
    blockers: list[str] = []

    if evaluation.status == cl.STATE_VERIFIED_ELIGIBLE:
        state = VERIFIED
        reason = "claim_supported"
    elif evaluation.status == cl.STATE_REJECTED:
        state = REJECTED
        reason = evaluation.gate_reason
        blockers.append(BLOCKER_CONTRADICTED)
    elif evaluation.status == cl.STATE_BLOCKED:
        state = BLOCKED
        reason = evaluation.gate_reason
        blockers.append(BLOCKER_MISSING_AUTHORIZATION)
    else:
        state = VERIFICATION_PENDING
        reason = evaluation.gate_reason
        blockers.append(BLOCKER_UNSUPPORTED_CLAIMS)
        if evaluation.unsupported_claims:
            blockers.append(
                f"unsupported:{','.join(evaluation.unsupported_claims[:6])}")

    limitations = list(evaluation.limitations)
    mismatches = list(evaluation.evidence_mismatches)
    excluded = list(evaluation.excluded_evidence)
    if mismatches:
        limitations.append(
            "the gate classified evidence from its signals, not from the "
            f"rows' declared evidence types: {len(mismatches)} mismatch(es) "
            "recorded and excluded from authoritative support")
    if state == VERIFICATION_PENDING:
        limitations.append(
            "authoritative Evidence Gate outcome is VERIFICATION_PENDING: "
            "the claim contract is not satisfied by persisted evidence")
    if runtime_gate_claimed_case and state != VERIFIED:
        limitations.append(
            "the runtime evidence gate claimed a case "
            f"(reason={runtime_gate_reason or 'unrecorded'}) but the "
            "class claim contract is not satisfied — the claim remains "
            "unverified")

    return IntegrityDecision(
        authoritative_state=state,
        verification_state=_VERIFICATION_STATE[state],
        candidate_state=state,
        gate_reason=reason,
        claim_integrity={
            **evaluation.to_dict(),
            "authoritative_state": state,
            "gate_rule_version": GATE_RULE_VERSION,
        },
        missing_evidence=list(evaluation.missing_evidence_types),
        missing_evidence_types=list(evaluation.missing_evidence_types),
        missing_reasons=list(evaluation.missing_evidence),
        malformed_evidence=list(evaluation.malformed_evidence),
        blockers=blockers,
        contradictions=list(evaluation.contradictions),
        stage_reached=evaluation.stage_reached,
        confirmation_evidence_ids=confirmation_ids[:10],
        runtime_gate_reason=runtime_gate_reason,
        runtime_gate_claimed_case=runtime_gate_claimed_case,
        limitations=limitations,
        evidence_mismatches=mismatches[:40],
        class_quarantine=list(evaluation.class_quarantine)[:40],
        evaluated_class=evaluation.evaluated_class,
        excluded_evidence=excluded[:40],
    )


EXPLICIT_GATE_REASONS: frozenset[str] = frozenset(
    {"claim_supported", ct.R_NO_EVIDENCE, ct.R_UNCLASSIFIED_ONLY,
     ct.R_DUPLICATE_ONLY, cl.REASON_NOT_TESTED,
     cl.REASON_TOO_FEW_OBSERVATIONS})


def claim_integrity_supported(payload: Any) -> bool:
    """True ONLY for a fully confirmed claim set.

    This is the single predicate the store trusts before persisting any
    VERIFIED transition.  Absent, malformed or partial payloads are all
    ``False`` (fail closed).
    """
    if not isinstance(payload, dict) or not payload:
        return False
    if payload.get("claim_confirmed") is True:
        return True
    confirmation = str(payload.get("confirmation_status") or "")
    return (payload.get("authoritative_state") == VERIFIED
            and confirmation == cl.CLAIM_SUPPORTED)


def gate_reason_is_explicit(reason: str) -> bool:
    """A persisted gate reason must be from the closed vocabulary."""
    text = str(reason or "")
    return ct.is_known_gate_reason(text) or text in EXPLICIT_GATE_REASONS


__all__ = [
    "BLOCKED", "BLOCKER_CONTRADICTED", "BLOCKER_GATE_NOT_AUTHORITATIVE",
    "BLOCKER_MISSING_AUTHORIZATION", "BLOCKER_UNSUPPORTED_CLAIMS",
    "GATE_RULE_VERSION", "INTEGRITY_STATES", "IntegrityDecision", "REJECTED",
    "VERIFICATION_PENDING", "VERIFIED", "claim_integrity_supported",
    "decide", "evaluate_integrity",
    "gate_reason_is_explicit",
]
