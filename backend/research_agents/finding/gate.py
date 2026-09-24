"""Verification gate (Phase 8) — the decision layer.

Built ON the existing Evidence Gate primitives: the authoritative signal
is the job's persisted ``structured["evidence_gate"]`` record plus the
capability evidence requirements that produced it.  This module adds the
CANDIDATE-level decision vocabulary:

    VERIFIED | REJECTED | INCONCLUSIVE | BLOCKED   (+ FAILED for job loss)

Rules (non-negotiable 5-9):
- VERIFIED requires the authoritative gate record to say
  ``evidence_rules_met`` with a claimed case, AND at least one
  direct supporting evidence row linked to the verification job, AND
  (EPIC11) the class claim contract to be satisfied by persisted,
  non-duplicate evidence of the required types.
- REJECTED requires contradictory or disqualifying evidence.
- INCONCLUSIVE = evidence remains insufficient to decide; the candidate
  is parked at ``VERIFICATION_PENDING`` with the exact missing evidence.
- BLOCKED = verification could not safely proceed (hunt/auth/authorization).
- The LLM is NEVER read here: no advisor argument exists in ``decide()``;
  "LLM confidence = high" can never become VERIFIED.

EPIC11 note: the runtime's generic rule (">= N rows of storage type
``observation`` at high confidence") is NOT sufficient to confirm a
vulnerability.  ``parameter inventory exists`` can no longer become
``XSS exists``: the claim contract in ``finding.integrity`` decides, and
its outcome is persisted alongside every decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.integrity import contracts as _ict
from backend.research_agents.finding.integrity import gate as _igate

VERIFICATION_RULE_VERSION = "finding-gate-2"


@dataclass
class VerificationDecision:
    verification_state: str      # VERIFIED|REJECTED|INCONCLUSIVE|BLOCKED|FAILED
    candidate_state: str         # same set (BLOCKED for job loss)
    reason: str
    detail: str = ""
    gate_reason: str = ""
    gate_confidence: str = ""
    gate_authoritative: bool = False
    created_case: bool = False
    case_id: str = ""
    evidence_used: list[str] = field(default_factory=list)
    contradicting: list[str] = field(default_factory=list)
    rule_version: str = VERIFICATION_RULE_VERSION
    # -- EPIC11 claim/evidence integrity (authoritative) -----------------
    authoritative_state: str = ""
    claim_integrity: dict[str, Any] = field(default_factory=dict)
    claim_integrity_status: str = ""
    missing_evidence: list[str] = field(default_factory=list)
    stage_reached: int = 0
    blockers: list[str] = field(default_factory=list)
    limitations: str = ("authoritative decision from the Evidence Gate + "
                        "deterministic claim/evidence contract; LLM output "
                        "is never consulted by this gate")

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_state": self.verification_state,
            "candidate_state": self.candidate_state,
            "reason": self.reason,
            "detail": self.detail,
            "gate_reason": self.gate_reason,
            "gate_confidence": self.gate_confidence,
            "gate_authoritative": self.gate_authoritative,
            "created_case": self.created_case,
            "case_id": self.case_id,
            "evidence_used": list(self.evidence_used),
            "contradicting": list(self.contradicting),
            "rule_version": self.rule_version,
            "authoritative_state": self.authoritative_state,
            "claim_integrity": dict(self.claim_integrity),
            "claim_integrity_status": self.claim_integrity_status,
            "missing_evidence": list(self.missing_evidence),
            "stage_reached": self.stage_reached,
            "blockers": list(self.blockers),
            "limitations": self.limitations,
        }


def gate_record(structured: dict[str, Any]) -> dict[str, Any]:
    """The authoritative Evidence Gate record from a persisted result.

    Production shape: structured["evidence_gate"] (authoritative flag,
    reason, created_case, confidence) — the Campaign epic fixed extraction
    to this record; lineage gate fields are accepted only as legacy
    fallback when the authoritative record is absent.
    """
    if not isinstance(structured, dict):
        return {}
    record = structured.get("evidence_gate")
    if isinstance(record, dict) and record.get("authoritative") is True:
        return record
    lineage = structured.get("research_lineage")
    if isinstance(lineage, dict) and str(lineage.get("gate_reason") or ""):
        return {"authoritative": False,        # legacy fallback: not primary
                "reason": str(lineage.get("gate_reason") or ""),
                "created_case": bool(lineage.get("case_id")),
                "confidence": str(lineage.get("gate_confidence") or "")}
    return {}


def decide(
    *,
    candidate: Any,
    verification: Any,
    job_status: str,
    job_error: str = "",
    structured: dict[str, Any] | None = None,
    quality_rows: list[dict[str, Any]] | None = None,
    hunt: dict[str, Any] | None = None,
    runtime_case_id: str = "",
    evidence_rows: Iterable[dict[str, Any]] | None = None,
    authorization: Any = None,
) -> VerificationDecision:
    """Candidate-level verification decision.  No advisor parameter — by
    construction the LLM cannot reach this function (rule 7)."""
    structured = structured or {}
    hunt = hunt if isinstance(hunt, dict) else {}
    quality_rows = quality_rows or []
    scope_candidate = str(getattr(candidate, "scope_ref", "") or "")
    scope_verification = str(getattr(verification, "scope_ref", "") or "")
    ver_job = str(getattr(verification, "job_id", "") or "")

    # EPIC11: the authoritative claim-contract evaluation over the REAL
    # persisted evidence rows (prior + verification).  Computed once and
    # attached to every outcome so missing evidence and stage are always
    # persisted, never inferred downstream.
    integrity = _igate.evaluate_integrity(
        vulnerability_class=getattr(candidate, "vulnerability_class", ""),
        rows=list(evidence_rows or []),
        authorization=(authorization if authorization is not None
                       else _default_authorization(candidate, verification)),
        runtime_gate_reason=str(
            gate_record(structured).get("reason") or ""),
        runtime_gate_claimed_case=bool(
            gate_record(structured).get("created_case")),
    )

    def _both(verification_state: str, reason: str, detail: str = "",
              **kw: Any) -> VerificationDecision:
        # candidate and verification share terminal vocabulary, except
        # FAILED which exists only on the verification objective.
        candidate_state = ("BLOCKED" if verification_state == "FAILED"
                           else verification_state)
        return VerificationDecision(
            verification_state=verification_state,
            candidate_state=candidate_state,
            reason=reason, detail=detail,
            authoritative_state=integrity.authoritative_state,
            claim_integrity=dict(integrity.claim_integrity),
            claim_integrity_status=str(
                integrity.claim_integrity.get("status") or ""),
            missing_evidence=list(integrity.missing_evidence),
            stage_reached=integrity.stage_reached,
            blockers=list(integrity.blockers),
            **kw)

    # -- 0. scope must still match (defensive; store enforces it too) ------
    if scope_candidate and scope_verification and \
            scope_candidate != scope_verification:
        return _both("REJECTED", "scope_mismatch",
                     f"{scope_verification} != {scope_candidate}")

    # -- 1. job did not finish: honest non-decision ------------------------
    status = str(job_status or "")
    if status != "COMPLETED":
        if status:
            return _both("FAILED", f"job_{status.lower()}",
                         _bounded(job_error, 200))
        return _both("BLOCKED", "verification_job_absent",
                     "no verification job recorded")

    # -- 2. hunt blocked the path: verification could not proceed ----------
    if isinstance(hunt, dict) and str(hunt.get("state") or "") == "BLOCKED":
        return _both("BLOCKED",
                     _bounded(hunt.get("termination_reason")
                              or "hunt_blocked", 120),
                     "hunt could not reduce uncertainty safely")

    # -- 3. authoritative gate record ---------------------------------------
    record = gate_record(structured)
    if not record:
        return _both("INCONCLUSIVE", "gate_record_absent",
                     "completed job carried no Evidence Gate record")
    gate_reason = str(record.get("reason") or "")
    created_case = bool(record.get("created_case"))
    confidence = str(record.get("confidence") or "")
    authoritative = record.get("authoritative") is True

    supporting = [q for q in quality_rows
                  if q.get("verification_relevance") == "verification"
                  and q.get("direct") is True
                  and q.get("stance") == "supporting"]
    contradicting = [q for q in quality_rows
                     if q.get("verification_relevance") == "verification"
                     and q.get("direct") is True
                     and q.get("stance") == "contradicting"]

    # -- 4a. VERIFIED: runtime gate + direct support + CLAIM CONTRACT ------
    if gate_reason == "evidence_rules_met" and created_case:
        if not authoritative:
            return _both("INCONCLUSIVE", "gate_not_authoritative",
                         "evidence_rules_met without authoritative flag")
        if not supporting:
            return _both("INCONCLUSIVE",
                         "gate_met_without_direct_supporting_evidence",
                         "case claimed but no direct supporting row for "
                         "this candidate")
        # EPIC11 — the authoritative claim contract decides.  A runtime
        # gate claim of ``evidence_rules_met`` can NO LONGER confirm a
        # vulnerability on its own.
        if integrity.authoritative_state == _igate.VERIFIED:
            return _both(
                "VERIFIED", "evidence_rules_met",
                f"confidence={confidence} supporting="
                f"{len(supporting)} case={runtime_case_id or 'claimed'} "
                f"stage={integrity.stage_reached} contract="
                f"{integrity.claim_integrity.get('contract_id')}",
                gate_reason=gate_reason, gate_confidence=confidence,
                gate_authoritative=True, created_case=True,
                case_id=runtime_case_id,
                evidence_used=[str(q.get("evidence_id") or "")
                               for q in supporting[:10]])
        return _integrity_outcome(
            integrity, _both, gate_reason=gate_reason,
            confidence=confidence, authoritative=authoritative,
            created_case=created_case, verification_job=ver_job,
            supporting=supporting)

    # -- 4b. REJECTED: contradictory or disqualifying evidence -------------
    if contradicting:
        first = str(contradicting[0].get("evidence_id") or "")
        return _both("REJECTED", f"contradicting_evidence:{first}",
                     f"count={len(contradicting)}",
                     gate_reason=gate_reason, gate_confidence=confidence,
                     gate_authoritative=authoritative,
                     created_case=created_case,
                     contradicting=[str(q.get("evidence_id") or "")
                                    for q in contradicting[:10]])
    if gate_reason == "no_hypothesis":
        return _both("REJECTED", "disqualifying:no_hypothesis",
                     "gate found no hypothesis to verify",
                     gate_reason=gate_reason, gate_confidence=confidence,
                     gate_authoritative=authoritative)

    # -- 4c. BLOCKED already handled; everything else = INCONCLUSIVE -------
    integrity_reason = integrity.gate_reason
    if integrity.authoritative_state == _igate.REJECTED:
        return _both("REJECTED",
                     f"contradicting_evidence:"
                     f"{integrity_reason.split(':', 1)[-1]}",
                     "claim contract rejected by persisted evidence",
                     gate_reason=gate_reason, gate_confidence=confidence,
                     gate_authoritative=authoritative,
                     created_case=created_case)
    return _both("INCONCLUSIVE", f"evidence_insufficient:{gate_reason or 'unknown'}",
                 "evidence remains insufficient to decide",
                 gate_reason=gate_reason, gate_confidence=confidence,
                 gate_authoritative=authoritative,
                 created_case=created_case)


def _default_authorization(candidate: Any, verification: Any) -> Any:
    """Recorded authorization lineage (never invented, never expanded)."""
    scope_ref = str(getattr(candidate, "scope_ref", "") or "")
    provenance = getattr(verification, "provenance", {}) or {}
    return _ict.AuthorizationContext(
        scope_ref=scope_ref,
        authorization_ref=str(getattr(candidate, "authorization_ref", "")
                              or scope_ref),
        authorization_ids=tuple(
            str(x) for x in (getattr(verification, "authorization_ids", ())
                             or ())),
        execution_mode=str(provenance.get("execution_mode") or ""),
        provenance={"source": "finding_gate_recorded_lineage"},
    )


def _integrity_outcome(integrity: Any, both: Any, *, gate_reason: str,
                       confidence: str, authoritative: bool,
                       created_case: bool, verification_job: str,
                       supporting: list[dict[str, Any]]
                       ) -> VerificationDecision:
    """Map a non-VERIFIED claim contract outcome onto the finding states.

    ``VERIFICATION_PENDING`` is preserved as the CANDIDATE state (the
    brief's honest outcome) while the verification objective — whose
    vocabulary has no PENDING terminal — parks at INCONCLUSIVE.
    """
    state = integrity.authoritative_state
    reason = integrity.gate_reason
    detail = ("claim contract not satisfied: "
              + ",".join(integrity.missing_evidence[:6])
              if integrity.missing_evidence else integrity.gate_reason)
    if state == _igate.BLOCKED:
        return both("BLOCKED", reason, detail, gate_reason=gate_reason,
                    gate_confidence=confidence, gate_authoritative=authoritative,
                    created_case=created_case)
    if state == _igate.REJECTED:
        return both("REJECTED", reason, detail, gate_reason=gate_reason,
                    gate_confidence=confidence, gate_authoritative=authoritative,
                    created_case=created_case)
    decision = both("INCONCLUSIVE",
                    f"{_igate.VERIFICATION_PENDING}:{reason}", detail,
                    gate_reason=gate_reason, gate_confidence=confidence,
                    gate_authoritative=authoritative,
                    created_case=created_case)
    # candidate parks at VERIFICATION_PENDING with the missing evidence
    if getattr(decision, "authoritative_state", "") == \
            _igate.VERIFICATION_PENDING:
        decision.candidate_state = _igate.VERIFICATION_PENDING
    decision.gate_reason = reason
    decision.evidence_used = [str(q.get("evidence_id") or "")
                              for q in supporting[:10]]
    return decision


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]
