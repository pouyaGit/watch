"""Lifecycle hops (EPIC 3 Part 1): pure transitions over CaseRecord.

Each hop checks the record type, the current state, and the input's
identity binding (case ids must match; gate decisions must allow and name
the attached plan). Inputs are accepted as component objects or their
plain-data round-trips. Nothing is mutated; every success appends exactly
one history event with a deterministic reason.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from aec.authorization_gate import AuthorizationGateDecision
from aec.evidence.models import EvidenceGapState, STATES as EVIDENCE_STATES
from aec.models import CaseRef
from aec.observation_plan import ObservationPlanDraft
from aec.orchestrator.models import (
    REFUSAL_CODES,
    STATES,
    CaseRecord,
    LifecycleEvent,
    TransitionResult,
)


def _refuse(code: str, detail: str) -> TransitionResult:
    assert code in REFUSAL_CODES, f"outside closed vocabulary: {code!r}"
    return TransitionResult(
        ok=False, record=None, refusal_code=code, refusal_detail=detail
    )


def _hop(record: CaseRecord, current: str, reason: str, **updates: Any) -> TransitionResult:
    event = LifecycleEvent(
        seq=len(record.history) + 1,
        previous=record.state,
        current=current,
        reason=reason,
    )
    return TransitionResult(
        ok=True,
        record=replace(
            record, state=current, history=tuple(list(record.history) + [event]), **updates
        ),
        refusal_code=None,
    )


def _require_record(record: object, state: str) -> CaseRecord | TransitionResult:
    if not isinstance(record, CaseRecord):
        return _refuse("INVALID_RECORD", f"expected CaseRecord, got {type(record).__name__}")
    if record.state != state:
        return _refuse(
            "INVALID_TRANSITION",
            f"case {record.case_id!r} is {record.state}, hop requires {state}",
        )
    return record


def intake(case: object) -> CaseRecord:
    """Admit a research case into the lifecycle as NEW."""
    if not isinstance(case, CaseRef):
        raise TypeError(f"intake accepts CaseRef, got {type(case).__name__}")
    if not case.case_id.strip():
        raise ValueError("intake requires a non-empty case_id")
    event = LifecycleEvent(seq=1, previous="", current="NEW", reason=f"case:{case.case_id}")
    return CaseRecord(case_id=case.case_id, state="NEW", history=(event,))


def mark_selected(record: object, order: object) -> TransitionResult:
    """NEW → SELECTED with the selector's ordering number."""
    checked = _require_record(record, "NEW")
    if isinstance(checked, TransitionResult):
        return checked
    if not isinstance(order, int) or isinstance(order, bool) or order <= 0:
        return _refuse("MISSING_INPUT", f"selection order must be a positive int, got {order!r}")
    return _hop(checked, "SELECTED", f"order:{order}", selection_order=order)


def _plan_document(plan: object) -> Mapping[str, Any] | None:
    if isinstance(plan, ObservationPlanDraft):
        return plan.to_dict()
    if isinstance(plan, Mapping):
        return plan
    return None


def attach_plan(record: object, plan: object) -> TransitionResult:
    """SELECTED → PLANNED, binding the observation plan to the case."""
    checked = _require_record(record, "SELECTED")
    if isinstance(checked, TransitionResult):
        return checked
    document = _plan_document(plan)
    if document is None:
        return _refuse("MISSING_INPUT", "no observation plan supplied")
    if document.get("case_id") != checked.case_id or not document.get("plan_id"):
        return _refuse(
            "STALE_INPUT",
            f"plan {document.get('plan_id')!r} does not belong to case {checked.case_id!r}",
        )
    return _hop(
        checked, "PLANNED", f"plan:{document.get('plan_id')}",
        plan_id=str(document.get("plan_id")),
    )


def _decision_document(decision: object) -> Mapping[str, Any] | None:
    if isinstance(decision, AuthorizationGateDecision):
        return decision.to_dict()
    if isinstance(decision, Mapping):
        return decision
    return None


def record_authorized(record: object, decision: object) -> TransitionResult:
    """PLANNED → AUTHORIZED_PLAN on an ALLOW gate decision for our plan."""
    checked = _require_record(record, "PLANNED")
    if isinstance(checked, TransitionResult):
        return checked
    document = _decision_document(decision)
    if document is None:
        return _refuse("MISSING_INPUT", "no gate decision supplied")
    if document.get("decision") != "ALLOW":
        return _refuse(
            "INVALID_TRANSITION",
            f"gate did not allow plan {checked.plan_id!r}",
        )
    if document.get("plan_id") != checked.plan_id:
        return _refuse(
            "STALE_INPUT",
            f"decision names {document.get('plan_id')!r}, case holds {checked.plan_id!r}",
        )
    return _hop(
        checked,
        "AUTHORIZED_PLAN",
        f"gate:{document.get('reason_code')}",
        gate_plan_hash=str(document.get("timestamp", "")),
    )


def _gap_document(gap: object) -> Mapping[str, Any] | None:
    if isinstance(gap, EvidenceGapState):
        return gap.to_dict()
    if isinstance(gap, Mapping):
        return gap
    return None


def route_evidence(record: object, gap: object) -> TransitionResult:
    """AUTHORIZED_PLAN → the gap's evidence state (forward only)."""
    checked = _require_record(record, "AUTHORIZED_PLAN")
    if isinstance(checked, TransitionResult):
        return checked
    document = _gap_document(gap)
    if document is None:
        return _refuse("MISSING_INPUT", "no gap state supplied")
    if document.get("case_id") != checked.case_id:
        return _refuse(
            "STALE_INPUT",
            f"gap belongs to {document.get('case_id')!r}, not {checked.case_id!r}",
        )
    state = str(document.get("state", ""))
    if state not in EVIDENCE_STATES:
        return _refuse("STALE_INPUT", f"unknown gap state {state!r}")
    current_index = STATES.index("AUTHORIZED_PLAN")
    if STATES.index(state) < current_index:
        return _refuse("INVALID_TRANSITION", f"evidence would move {checked.case_id!r} backward")
    return _hop(checked, state, f"gap:{state}", evidence_state=state)


def submit_review(record: object, note: object) -> TransitionResult:
    """EVIDENCE_READY → REVIEW_REQUIRED with an operator triage note."""
    checked = _require_record(record, "EVIDENCE_READY")
    if isinstance(checked, TransitionResult):
        return checked
    if not isinstance(note, str):
        return _refuse("MISSING_INPUT", "review note must be text")
    return _hop(checked, "REVIEW_REQUIRED", "operator-triage", review_note=note)


def serialize_record(record: CaseRecord) -> str:
    """Stable bytes for one case record."""
    return json.dumps(record.to_dict(), sort_keys=True)


__all__ = [
    "attach_plan",
    "intake",
    "mark_selected",
    "record_authorized",
    "route_evidence",
    "serialize_record",
    "submit_review",
]
