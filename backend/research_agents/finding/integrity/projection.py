"""Re-assessment of PERSISTED finding state under the EPIC11 contract.

History is never rewritten.  A record that was persisted as ``VERIFIED``
before the claim contract existed stays exactly as it was written; this
module re-reads it, re-evaluates the evidence that backs it and reports
the corrected *current* authoritative view side by side with the
historical one.

This is the honest answer to "the persisted state is already inconsistent
with the new contract" (§16): preserve the record, correct the
projection, surface the contradiction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.integrity import claims as cl
from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import gate as ig

PROJECTION_RULE_VERSION = "epic11-integrity-projection-1"

PERSISTED_STATES: tuple[str, ...] = (
    "VERIFIED", "READY_FOR_REVIEW", "HANDED_OFF")

INTEGRITY_OK = "CONSISTENT"
INTEGRITY_UNSUPPORTED = "UNSUPPORTED_VERIFIED"
INTEGRITY_CONTRADICTION = "CONTRADICTION"


@dataclass
class IntegrityProjection:
    """Current authoritative view of a persisted finding record."""

    candidate_id: str
    vulnerability_class: str
    persisted_state: str
    integrity_state: str
    authoritative_state: str
    gate_reason: str
    stage_reached: int = 0
    missing_evidence: list[str] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    claim_evidence_matrix: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    evaluation: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    # §22: the historical LLM advisory is reported SEPARATELY, with its
    # own recorded state and timestamp, and is never authoritative.
    advisory_state: str = ""
    advisory_authoritative: bool = False
    advisory_recorded_at: str = ""
    # this module is read-only: the persisted evidence is never rewritten
    persisted_evidence_preserved: bool = True
    rule_version: str = PROJECTION_RULE_VERSION

    @property
    def consistent(self) -> bool:
        return self.integrity_state == INTEGRITY_OK

    @property
    def confirmed(self) -> bool:
        return self.authoritative_state == ig.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "vulnerability_class": self.vulnerability_class,
            "persisted_state": self.persisted_state,
            "integrity_state": self.integrity_state,
            "authoritative_state": self.authoritative_state,
            "gate_reason": self.gate_reason,
            "stage_reached": self.stage_reached,
            "missing_evidence": list(self.missing_evidence),
            "unsupported_claims": list(self.unsupported_claims),
            "claim_evidence_matrix": list(self.claim_evidence_matrix),
            "contradictions": list(self.contradictions),
            "evaluation": dict(self.evaluation),
            "limitations": list(self.limitations),
            "advisory_state": self.advisory_state,
            "advisory_authoritative": self.advisory_authoritative,
            "advisory_recorded_at": self.advisory_recorded_at,
            "persisted_evidence_preserved": self.persisted_evidence_preserved,
            "confirmed": self.confirmed,
            "rule_version": self.rule_version,
        }


def project(
    *,
    candidate: Any,
    verification: Any = None,
    evidence_rows: Iterable[dict[str, Any]] = (),
    persisted_state: str = "",
    historical_advisory: dict[str, Any] | None = None,
) -> IntegrityProjection:
    """Re-evaluate a persisted candidate against its persisted evidence."""
    if isinstance(candidate, dict):
        vulnerability_class = str(candidate.get("vulnerability_class") or "")
        candidate_id = str(candidate.get("candidate_id") or "")
        state = persisted_state or str(candidate.get("lifecycle_state") or "")
        scope_ref = str(candidate.get("scope_ref") or "")
        authorization_ref = str(candidate.get("authorization_ref") or "")
    else:
        vulnerability_class = str(
            getattr(candidate, "vulnerability_class", "") or "")
        candidate_id = str(getattr(candidate, "candidate_id", ""))
        state = persisted_state or str(getattr(candidate, "lifecycle_state",
                                                 "") or "")
        scope_ref = str(getattr(candidate, "scope_ref", "") or "")
        authorization_ref = str(getattr(candidate, "authorization_ref", "")
                                or scope_ref)

    authorization_ids: tuple[str, ...] = ()
    execution_mode = ""
    if verification is not None:
        authorization_ids = tuple(
            str(x) for x in (getattr(verification, "authorization_ids", ())
                             or ()))
        execution_mode = str(getattr(verification, "provenance", {})
                             .get("execution_mode") or "")

    decision = ig.evaluate_integrity(
        vulnerability_class=vulnerability_class,
        rows=list(evidence_rows or []),
        authorization=ct.AuthorizationContext(
            scope_ref=scope_ref,
            authorization_ref=authorization_ref or scope_ref,
            authorization_ids=authorization_ids,
            execution_mode=execution_mode,
            provenance={"source": "persisted_projection"}),
    )

    if state in PERSISTED_STATES and decision.authoritative_state != \
            ig.VERIFIED:
        integrity_state = (
            INTEGRITY_CONTRADICTION if decision.contradictions
            else INTEGRITY_UNSUPPORTED)
    elif state in PERSISTED_STATES:
        integrity_state = INTEGRITY_OK
    else:
        integrity_state = INTEGRITY_OK

    limitations = list(decision.limitations)
    if integrity_state != INTEGRITY_OK:
        limitations.insert(
            0, f"persisted state {state} is NOT supported by the persisted "
               f"evidence under the current claim contract "
               f"({decision.gate_reason}); the persisted record is "
               f"preserved as history and is not re-presented as verified")

    advisory = dict(historical_advisory or {})
    advisory_state = str(advisory.get("advisory_state")
                         or advisory.get("state") or "")
    advisory_at = str(advisory.get("recorded_at") or "")
    if advisory_state and advisory_state != decision.authoritative_state:
        limitations.insert(0,
                           "historical advisory recorded "
                           f"'{advisory_state}' at "
                           f"{advisory_at or 'unrecorded time'} while the "
                           f"current authoritative state is "
                           f"{decision.authoritative_state}; the advisory "
                           f"is preserved verbatim and is ADVISORY ONLY")

    return IntegrityProjection(
        candidate_id=candidate_id,
        vulnerability_class=vulnerability_class,
        persisted_state=state,
        integrity_state=integrity_state,
        authoritative_state=decision.authoritative_state,
        gate_reason=decision.gate_reason,
        stage_reached=decision.stage_reached,
        missing_evidence=list(decision.missing_evidence),
        unsupported_claims=list(
            decision.claim_integrity.get("unsupported_claims") or []),
        claim_evidence_matrix=list(
            decision.claim_integrity.get("claim_evidence_matrix") or []),
        contradictions=list(decision.contradictions),
        evaluation=dict(decision.claim_integrity),
        limitations=limitations,
        advisory_state=advisory_state,
        advisory_authoritative=False,
        advisory_recorded_at=advisory_at,
        persisted_evidence_preserved=True,
    )


__all__ = [
    "INTEGRITY_CONTRADICTION", "INTEGRITY_OK", "INTEGRITY_UNSUPPORTED",
    "IntegrityProjection", "PERSISTED_STATES", "PROJECTION_RULE_VERSION",
    "project",
]
