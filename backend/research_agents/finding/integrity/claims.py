"""Claim evaluation (EPIC11 §3, §4, §10, §11, §13).

Every substantive security statement in a report is a *claim*.  A claim is
``SUPPORTED`` only when persisted, non-duplicate evidence of the required
types is present; otherwise it is ``UNSUPPORTED`` with an explicit reason,
``CONTRADICTED`` by real negative evidence, or ``NOT_TESTED`` when the
pipeline explicitly never attempted it.

Nothing in this module reads model output.  There is no confidence
parameter and no advisor argument: an LLM cannot reach claim evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import taxonomy as tx

CLAIM_RULE_VERSION = "epic11-claim-integrity-1"

CLAIM_SUPPORTED = "SUPPORTED"
CLAIM_UNSUPPORTED = "UNSUPPORTED"
CLAIM_CONTRADICTED = "CONTRADICTED"
CLAIM_NOT_TESTED = "NOT_TESTED"

CLAIM_STATUSES: tuple[str, ...] = (
    CLAIM_SUPPORTED, CLAIM_UNSUPPORTED, CLAIM_CONTRADICTED, CLAIM_NOT_TESTED)

# evaluation-level status of the whole claim set
STATE_VERIFIED_ELIGIBLE = "VERIFIED_ELIGIBLE"
STATE_VERIFICATION_PENDING = "VERIFICATION_PENDING"
STATE_BLOCKED = "BLOCKED"
STATE_REJECTED = "REJECTED"

# unreported/unreachable claims are reported as MISSING in the matrix
MATRIX_MISSING = "MISSING"

# negative signal -> the evidence type it speaks about (never invents one)
NEGATIVE_TARGET_TYPE: dict[str, str] = {
    "reflection_not_observed": tx.REFLECTION_OBSERVED,
    "reflection_absent": tx.REFLECTION_OBSERVED,
    "no_reflection": tx.REFLECTION_OBSERVED,
    "dom_sink_not_identified": tx.DOM_SINK_IDENTIFIED,
    "payload_execution_not_observed": tx.PAYLOAD_EXECUTION,
    "exploitability_not_established": tx.EXPLOITABILITY_ESTABLISHED,
    "impact_not_established": tx.IMPACT_ESTABLISHED,
    "severity_not_assessed": tx.IMPACT_ESTABLISHED,
}

REASON_NOT_TESTED = "not_tested"
REASON_CONTRADICTED = "contradicting_evidence"
REASON_TOO_FEW_OBSERVATIONS = "insufficient_unique_observations"


@dataclass
class ClaimResult:
    claim_id: str
    claim_type: str
    statement: str
    status: str
    stage: int
    required_evidence_types: tuple[str, ...] = ()
    supporting_evidence_ids: list[str] = field(default_factory=list)
    unsupported_reason: str = ""
    contradicting_evidence_ids: list[str] = field(default_factory=list)
    unique_observations: int = 0
    impact_claim: bool = False
    requires_authorization: bool = False
    provenance: dict[str, Any] = field(default_factory=dict)
    rule_version: str = CLAIM_RULE_VERSION

    @property
    def matrix_status(self) -> str:
        """Matrix cell: SUPPORTED, MISSING (nothing observed) or the
        explicit CONTRADICTED / NOT_TESTED verdict — a contradiction is
        never flattened into "missing" (§15)."""
        if self.status == CLAIM_SUPPORTED:
            return self.status
        if self.status == CLAIM_UNSUPPORTED:
            return MATRIX_MISSING
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "statement": self.statement,
            "status": self.status,
            "matrix_status": self.matrix_status,
            "stage": self.stage,
            "stage_label": tx.STAGE_LABELS.get(self.stage, "auxiliary"),
            "required_evidence_types": list(self.required_evidence_types),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "unsupported_reason": self.unsupported_reason,
            "contradicting_evidence_ids":
                list(self.contradicting_evidence_ids),
            "unique_observations": self.unique_observations,
            "impact_claim": self.impact_claim,
            "requires_authorization": self.requires_authorization,
            "provenance": dict(self.provenance),
            "rule_version": self.rule_version,
        }

    def matrix_row(self) -> dict[str, Any]:
        return {
            "claim": self.statement,
            "claim_type": self.claim_type,
            "claim_id": self.claim_id,
            "evidence": (self.supporting_evidence_ids[:3]
                         if self.supporting_evidence_ids else []),
            "evidence_ids": list(self.supporting_evidence_ids),
            "status": self.matrix_status,
            "unsupported_reason": self.unsupported_reason,
            "stage": self.stage,
        }


@dataclass
class ClaimEvaluation:
    """The authoritative claim/evidence outcome for one candidate."""

    vulnerability_class: str
    contract_id: str
    status: str
    gate_reason: str
    claims: list[ClaimResult] = field(default_factory=list)
    stage_reached: int = 0
    missing_evidence: list[str] = field(default_factory=list)
    missing_evidence_types: list[str] = field(default_factory=list)
    malformed_evidence: list[str] = field(default_factory=list)
    negative_evidence: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    unique_observations: int = 0
    duplicate_events: int = 0
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    authorization: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    rule_version: str = CLAIM_RULE_VERSION

    @property
    def confirmed(self) -> bool:
        return self.status == STATE_VERIFIED_ELIGIBLE

    @property
    def confirmation_claim(self) -> ClaimResult | None:
        for claim in self.claims:
            if claim.claim_type == "vulnerability_confirmed":
                return claim
        return None

    def claim(self, claim_type: str) -> ClaimResult | None:
        for claim in self.claims:
            if claim.claim_type == claim_type:
                return claim
        return None

    def claim_matrix(self) -> list[dict[str, Any]]:
        return [c.matrix_row() for c in self.claims]

    def to_dict(self) -> dict[str, Any]:
        confirmation = self.confirmation_claim
        return {
            "vulnerability_class": self.vulnerability_class,
            "contract_id": self.contract_id,
            "status": self.status,
            "claim_confirmed": self.status == STATE_VERIFIED_ELIGIBLE,
            "confirmation_status": (confirmation.status if confirmation
                                    else CLAIM_UNSUPPORTED),
            "confirmation_claim_id": (confirmation.claim_id if confirmation
                                      else ""),
            "gate_reason": self.gate_reason,
            "stage_reached": self.stage_reached,
            "stage_label": tx.STAGE_LABELS.get(self.stage_reached,
                                               "no evidence"),
            "claims": [c.to_dict() for c in self.claims],
            "claim_evidence_matrix": self.claim_matrix(),
            "missing_evidence": list(self.missing_evidence),
            "missing_evidence_types": list(self.missing_evidence_types),
            "malformed_evidence": list(self.malformed_evidence),
            "negative_evidence": list(self.negative_evidence),
            "contradictions": list(self.contradictions),
            "unsupported_claims": list(self.unsupported_claims),
            "unique_observations": self.unique_observations,
            "duplicate_events": self.duplicate_events,
            "evidence_items": list(self.evidence_items),
            "authorization": dict(self.authorization),
            "limitations": list(self.limitations),
            "rule_version": self.rule_version,
            "advisory_only_fields_used": [],
        }


def _target_type(item: tx.EvidenceItem) -> str:
    return NEGATIVE_TARGET_TYPE.get(item.raw_signal, "")


def _claim_status(
    spec: ct.ClaimSpec,
    *,
    items: list[tx.EvidenceItem],
    negatives: list[tx.EvidenceItem],
    authorization_satisfied: bool,
) -> tuple[str, list[str], list[str], int, str]:
    """(status, supporting_ids, contradicting_ids, unique_obs, reason)."""
    wanted = set(spec.required_evidence_types)
    supporting = [i for i in items
                  if i.evidence_type in wanted and i.stage > 0
                  and i.evidence_type not in (tx.NEGATIVE_EVIDENCE,
                                              tx.KNOWLEDGE_REFERENCE)]
    if spec.claim_type == "knowledge_correlation":
        supporting = [i for i in items
                      if i.evidence_type == tx.KNOWLEDGE_REFERENCE]
    supporting_ids = [i.evidence_id for i in supporting if i.evidence_id]
    observations = {i.observation_key() for i in supporting}

    contradicting: list[tx.EvidenceItem] = []
    not_tested: list[tx.EvidenceItem] = []
    for neg in negatives:
        if neg.duplicate_of:
            continue
        target = _target_type(neg)
        applies = (target in wanted)
        if not target and spec.claim_type == "vulnerability_confirmed":
            applies = neg.negative_kind == tx.NOT_TESTED
        if not applies:
            continue
        if neg.negative_kind == tx.NOT_TESTED:
            not_tested.append(neg)
        else:
            contradicting.append(neg)

    if contradicting:
        ids = [n.evidence_id for n in contradicting if n.evidence_id]
        return (CLAIM_CONTRADICTED, supporting_ids, ids, len(observations),
                f"{REASON_CONTRADICTED}:{ids[0] if ids else 'negative'}")

    missing_group: tuple[str, ...] | None = None
    for group in spec.required_groups:
        if authorization_satisfied and group == (
                tx.AUTHORIZATION_CONFIRMED,):
            # recorded authorization lineage counts as the confirmation
            # of authorization; a persisted AUTHORIZATION_CONFIRMED row
            # is the other, stricter form (both are auditable)
            continue
        if not any(i.evidence_type in group for i in supporting):
            missing_group = group
            break
    if missing_group is None and len(observations) < \
            max(1, spec.min_unique_observations):
        return (CLAIM_UNSUPPORTED, supporting_ids, [], len(observations),
                REASON_TOO_FEW_OBSERVATIONS)
    if missing_group is not None:
        if spec.requires_authorization and not authorization_satisfied \
                and not supporting:
            return (CLAIM_UNSUPPORTED, supporting_ids, [], len(observations),
                    ct.R_MISSING_AUTHORIZATION)
        if not_tested and not supporting:
            return (CLAIM_UNSUPPORTED, supporting_ids, [], len(observations),
                    REASON_NOT_TESTED)
        return (CLAIM_UNSUPPORTED, supporting_ids, [], len(observations),
                ct.reason_for_type(missing_group[0]))
    if spec.requires_authorization and not authorization_satisfied:
        return (CLAIM_UNSUPPORTED, supporting_ids, [], len(observations),
                ct.R_MISSING_AUTHORIZATION)
    return (CLAIM_SUPPORTED, supporting_ids, [], len(observations), "")


def evaluate_contract(
    contract: ct.VulnerabilityContract,
    rows: Iterable[dict[str, Any]],
    *,
    authorization: ct.AuthorizationContext | None = None,
    evidence_confirmed_authorization: bool = False,
) -> ClaimEvaluation:
    """Evaluate the whole claim set for one candidate's evidence.

    ``rows`` are the raw persisted evidence rows for the candidate's
    source job AND its verification job (the caller decides the set; this
    function never reaches outside what it is given).
    """
    items = tx.classify_rows(list(rows or []))
    unique = tx.unique_items(items)
    duplicates = len(items) - len(unique)
    auth = authorization or ct.AuthorizationContext()

    auth_type_items = [i for i in unique
                       if i.evidence_type == tx.AUTHORIZATION_CONFIRMED]
    authorization_satisfied = bool(
        auth.confirmed or auth_type_items or evidence_confirmed_authorization
        or auth.present)

    negatives = [i for i in items if i.is_negative]
    results: list[ClaimResult] = []
    missing_reasons: list[str] = []
    unsupported: list[str] = []
    for spec in contract.claims:
        status, supporting_ids, contradicting_ids, obs, reason = \
            _claim_status(spec, items=unique, negatives=negatives,
                          authorization_satisfied=authorization_satisfied)
        result = ClaimResult(
            claim_id=spec.claim_id,
            claim_type=spec.claim_type,
            statement=spec.statement,
            status=status,
            stage=spec.stage,
            required_evidence_types=spec.required_evidence_types,
            supporting_evidence_ids=supporting_ids[:20],
            unsupported_reason=reason,
            contradicting_evidence_ids=contradicting_ids[:10],
            unique_observations=obs,
            impact_claim=spec.impact_claim,
            requires_authorization=spec.requires_authorization,
            provenance={
                "source": "claim_contract_evaluation",
                "contract_id": contract.contract_id,
                "evidence_jobs": sorted({i.job_id for i in unique
                                         if i.job_id})[:8],
                "authorization_present": auth.present,
            },
        )
        results.append(result)
        if result.status == CLAIM_SUPPORTED:
            continue
        unsupported.append(result.claim_id)
        if result.unsupported_reason and \
                result.unsupported_reason not in missing_reasons:
            missing_reasons.append(result.unsupported_reason)

    confirmation = next((r for r in results
                         if r.claim_type == "vulnerability_confirmed"), None)
    stage = tx.stage_reached(items)
    unclassified_only = bool(unique) and all(
        i.evidence_type == tx.UNCLASSIFIED_OBSERVATION for i in unique)

    reason = ""
    status = STATE_VERIFICATION_PENDING
    if confirmation is not None and confirmation.status == CLAIM_SUPPORTED:
        status = STATE_VERIFIED_ELIGIBLE
        reason = "claim_supported"
    elif confirmation is not None and \
            confirmation.status == CLAIM_CONTRADICTED:
        status = STATE_REJECTED
        reason = confirmation.unsupported_reason or REASON_CONTRADICTED
    elif not unique:
        status = STATE_VERIFICATION_PENDING
        reason = ct.R_NO_EVIDENCE
    elif unclassified_only:
        status = STATE_VERIFICATION_PENDING
        reason = ct.R_UNCLASSIFIED_ONLY
    elif not any(i.is_stage_evidence for i in unique) and duplicates:
        status = STATE_VERIFICATION_PENDING
        reason = ct.R_DUPLICATE_ONLY
    else:
        # explicit authorization denial blocks; otherwise the shortest
        # unmet requirement is the honest pending reason
        auth_blocked = any(
            r.unsupported_reason == ct.R_MISSING_AUTHORIZATION
            for r in results if r.stage >= tx.STAGE_REFLECTION)
        if auth_blocked:
            status = STATE_BLOCKED
            reason = ct.R_MISSING_AUTHORIZATION
        else:
            status = STATE_VERIFICATION_PENDING
            reason = (confirmation.unsupported_reason if confirmation
                      else ct.insufficient_reason(contract.vulnerability_class))
            if reason in (REASON_NOT_TESTED, REASON_TOO_FEW_OBSERVATIONS):
                reason = ct.insufficient_reason(
                    contract.vulnerability_class)
            elif reason.startswith(REASON_CONTRADICTED):
                reason = reason

    if not reason:
        reason = ct.insufficient_reason(contract.vulnerability_class)
    if reason.startswith(REASON_CONTRADICTED + ":"):
        status = STATE_REJECTED

    contradictions = []
    for result in results:
        if result.contradicting_evidence_ids:
            contradictions.append({
                "claim_id": result.claim_id,
                "kind": "evidence_contradicts_claim",
                "evidence_ids": list(result.contradicting_evidence_ids),
                "detail": f"{result.claim_type} contradicted by persisted "
                          f"negative evidence",
            })

    limitations = list(contract.limitations) + [
        "evidence stages reached: "
        f"{tx.STAGE_LABELS.get(stage, 'none')}",
        "duplicate evidence events are collapsed before support is "
        "counted",
    ]
    if confirmation is not None and confirmation.status != CLAIM_SUPPORTED:
        limitations.append(
            "not a confirmed vulnerability: "
            f"{confirmation.unsupported_reason or reason}")

    present_types = {i.evidence_type for i in unique}
    missing_types: list[str] = []
    if confirmation is not None:
        missing_types = sorted(
            t for t in confirmation.required_evidence_types
            if t not in present_types)
    malformed = sorted({i.unclassified_reason
                        for i in items
                        if i.evidence_type == tx.MALFORMED_EVIDENCE})
    if malformed:
        limitations.append(
            "malformed evidence rows cannot support any claim: "
            + ",".join(malformed[:4]))

    return ClaimEvaluation(
        vulnerability_class=contract.vulnerability_class,
        contract_id=contract.contract_id,
        status=status,
        gate_reason=reason,
        claims=results,
        stage_reached=stage,
        missing_evidence=missing_reasons,
        missing_evidence_types=missing_types,
        malformed_evidence=malformed,
        negative_evidence=tx.negative_evidence(items),
        contradictions=contradictions,
        unsupported_claims=unsupported,
        unique_observations=len(unique),
        duplicate_events=duplicates,
        evidence_items=[i.to_dict() for i in unique][:60],
        authorization=auth.to_dict(),
        limitations=limitations,
    )


def evaluate_rows(
    vulnerability_class: Any,
    rows: Iterable[dict[str, Any]],
    *,
    authorization: ct.AuthorizationContext | None = None,
    evidence_confirmed_authorization: bool = False,
) -> ClaimEvaluation:
    """Convenience wrapper: class -> contract -> evaluation."""
    return evaluate_contract(
        ct.contract_for(vulnerability_class), rows,
        authorization=authorization,
        evidence_confirmed_authorization=evidence_confirmed_authorization)


__all__ = [
    "CLAIM_CONTRADICTED", "CLAIM_NOT_TESTED", "CLAIM_RULE_VERSION",
    "CLAIM_STATUSES", "CLAIM_SUPPORTED", "CLAIM_UNSUPPORTED", "ClaimEvaluation",
    "ClaimResult", "MATRIX_MISSING", "NEGATIVE_TARGET_TYPE",
    "REASON_CONTRADICTED", "REASON_NOT_TESTED",
    "REASON_TOO_FEW_OBSERVATIONS", "STATE_BLOCKED", "STATE_REJECTED",
    "STATE_VERIFICATION_PENDING", "STATE_VERIFIED_ELIGIBLE",
    "evaluate_contract", "evaluate_rows",
]
