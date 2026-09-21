"""Frozen models for the case orchestrator (EPIC 3 Part 1). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Lifecycle order. Hops move exactly one step forward; several tests pin
#: this tuple, so any reordering is a deliberate, reviewed change.
#: EVIDENCE_PARTIAL extends the brief's list: the evidence layer reports
#: three gap states and the record must be able to hold the middle one.
STATES = (
    "NEW",
    "SELECTED",
    "PLANNED",
    "AUTHORIZED_PLAN",
    "WAITING_EVIDENCE",
    "EVIDENCE_PARTIAL",
    "EVIDENCE_READY",
    "REVIEW_REQUIRED",
)

#: Closed refusal vocabulary for lifecycle hops.
REFUSAL_CODES = frozenset({
    "INVALID_RECORD",
    "INVALID_TRANSITION",
    "STALE_INPUT",
    "MISSING_INPUT",
})


@dataclass(frozen=True)
class LifecycleEvent:
    """One audit entry: sequence, hop, and deterministic reason."""

    seq: int
    previous: str
    current: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "previous": self.previous,
            "current": self.current,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CaseRecord:
    """One case's position in the lifecycle plus its audit history."""

    case_id: str
    state: str
    selection_order: int = 0
    plan_id: str = ""
    gate_plan_hash: str = ""
    evidence_state: str = ""
    review_note: str = ""
    history: tuple[LifecycleEvent, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "state": self.state,
            "selection_order": self.selection_order,
            "plan_id": self.plan_id,
            "gate_plan_hash": self.gate_plan_hash,
            "evidence_state": self.evidence_state,
            "review_note": self.review_note,
            "history": [e.to_dict() for e in self.history],
        }


@dataclass(frozen=True)
class TransitionResult:
    """Outcome of one lifecycle hop: a new record or a refusal."""

    ok: bool
    record: CaseRecord | None
    refusal_code: str | None
    refusal_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "record": self.record.to_dict() if self.record is not None else None,
            "refusal_code": self.refusal_code,
            "refusal_detail": self.refusal_detail,
        }


__all__ = [
    "REFUSAL_CODES",
    "STATES",
    "CaseRecord",
    "LifecycleEvent",
    "TransitionResult",
]
