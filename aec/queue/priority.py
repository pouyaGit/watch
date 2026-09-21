"""Priority rubric, snapshots, and retry tracking (EPIC 3 Part 2).

Score: ``risk_weight + state_weight − planned_cost``. Higher risk classes
sort first; near-complete evidence (PARTIAL) sorts before untouched
cases so almost-ready work drains; cheaper plans win ties in effect;
remaining ties break by selection order, then case id. All weights are
pinned constants — the rubric is reviewable data, not judgment.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from aec.queue.models import QueueSnapshot, RetryCase, RetryTracker, ScoredEntry

#: Triage rubric: inherent risk class → scheduling weight.
RISK_WEIGHTS = {
    "R5_ACCESS_CONTROL": 50,
    "R1_OBJECT_REFERENCE": 40,
    "R2_SERVER_FETCH": 30,
    "R3_REFLECTION": 20,
    "R4_CONTENT_HANDLING": 10,
    "R0_UNCLASSIFIED": 0,
}

#: Triage rubric: evidence state → scheduling weight.
STATE_WEIGHTS = {
    "EVIDENCE_PARTIAL": 30,
    "WAITING_EVIDENCE": 20,
    "EVIDENCE_READY": 10,
    "REVIEW_REQUIRED": 0,
}

#: Attempts granted per case before it rests.
MAX_RETRIES = 3

_REQUIRED_ITEM_KEYS = ("case_id", "risk_category", "evidence_state", "planned_cost", "selection_order")


def _text(value: object) -> str:
    return str(value or "").strip()


def score_breakdown(item: Mapping[str, Any]) -> dict[str, int]:
    """Explainable score parts for one queue item."""
    risk = RISK_WEIGHTS.get(_text(item.get("risk_category")), 0)
    state = STATE_WEIGHTS.get(_text(item.get("evidence_state")), 0)
    cost = item.get("planned_cost")
    if not isinstance(cost, int) or isinstance(cost, bool) or cost < 0:
        raise ValueError(f"planned_cost must be a non-negative int, got {cost!r}")
    return {"risk": risk, "state": state, "cost": cost, "total": risk + state - cost}


def score_item(item: Mapping[str, Any]) -> int:
    """Deterministic priority score for one queue item."""
    return score_breakdown(item)["total"]


def _validated(items: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
        raise ValueError("queue items must be a sequence of mappings")
    seen: set[str] = set()
    valid: list[Mapping[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError(f"queue item must be a mapping, got {type(item).__name__}")
        missing = [k for k in _REQUIRED_ITEM_KEYS if k not in item]
        if missing:
            raise ValueError(f"queue item is missing keys: {missing}")
        case_id = _text(item.get("case_id"))
        if not case_id:
            raise ValueError("queue item needs a non-empty case_id")
        if case_id in seen:
            raise ValueError(f"duplicate case_id in queue: {case_id!r}")
        seen.add(case_id)
        score_breakdown(item)  # validates cost shape
        valid.append(item)
    return valid


def build_queue(items: Sequence[Mapping[str, Any]]) -> QueueSnapshot:
    """Order queue items by score (desc), selection order, case id."""
    valid = _validated(items)
    ranked = sorted(
        valid,
        key=lambda i: (-score_item(i), int(i["selection_order"]), _text(i["case_id"])),
    )
    entries = tuple(
        ScoredEntry(case_id=_text(i["case_id"]), score=score_item(i), rank=n)
        for n, i in enumerate(ranked, start=1)
    )
    entry_dicts = [e.to_dict() for e in entries]
    snapshot_id = "queue:" + hashlib.sha256(
        json.dumps(entry_dicts, sort_keys=True).encode()
    ).hexdigest()[:12]
    return QueueSnapshot(
        snapshot_id=snapshot_id,
        entries=entries,
        generated_from=tuple(sorted(_text(i["case_id"]) for i in valid)),
        total=len(entries),
    )


def serialize_snapshot(snapshot: QueueSnapshot) -> str:
    """Stable bytes for one queue snapshot."""
    return json.dumps(snapshot.to_dict(), sort_keys=True)


def empty_tracker() -> RetryTracker:
    """A retry tracker with no attempts recorded."""
    return RetryTracker()


def _find(tracker: RetryTracker, case_id: str) -> RetryCase | None:
    for entry in tracker.cases:
        if entry.case_id == case_id:
            return entry
    return None


def _store(tracker: RetryTracker, updated: RetryCase) -> RetryTracker:
    cases = tuple(
        updated if entry.case_id == updated.case_id else entry
        for entry in tracker.cases
    )
    if _find(tracker, updated.case_id) is None:
        cases = tuple(list(cases) + [updated])
    return replace(tracker, cases=cases)


def record_attempt(tracker: RetryTracker, case_id: str) -> RetryTracker:
    """Spend one attempt for a case."""
    found = _find(tracker, case_id)
    if found is None:
        return _store(tracker, RetryCase(case_id=case_id, attempts=1, last_reason=None))
    return _store(
        tracker,
        RetryCase(
            case_id=case_id, attempts=found.attempts + 1, last_reason=found.last_reason
        ),
    )


def record_refusal(tracker: RetryTracker, case_id: str, reason: str) -> RetryTracker:
    """Record a refusal (which also spends one attempt)."""
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("refusal reason must be non-empty text")
    tracker = record_attempt(tracker, case_id)
    found = _find(tracker, case_id)
    assert found is not None
    return _store(tracker, RetryCase(case_id=case_id, attempts=found.attempts, last_reason=reason))


def attempt_count(tracker: RetryTracker, case_id: str) -> int:
    """Attempts spent for a case (0 for unknown cases)."""
    found = _find(tracker, case_id)
    return found.attempts if found else 0


def last_reason(tracker: RetryTracker, case_id: str) -> str | None:
    """Last refusal reason for a case (None when unknown)."""
    found = _find(tracker, case_id)
    return found.last_reason if found else None


def retries_left(tracker: RetryTracker, case_id: str) -> int:
    """Remaining attempts for a case, never negative."""
    return max(0, MAX_RETRIES - attempt_count(tracker, case_id))


def serialize_tracker(tracker: RetryTracker) -> str:
    """Stable bytes for one retry tracker."""
    return json.dumps(tracker.to_dict(), sort_keys=True)


__all__ = [
    "MAX_RETRIES",
    "RISK_WEIGHTS",
    "STATE_WEIGHTS",
    "attempt_count",
    "build_queue",
    "empty_tracker",
    "last_reason",
    "record_attempt",
    "record_refusal",
    "retries_left",
    "score_breakdown",
    "score_item",
    "serialize_snapshot",
    "serialize_tracker",
]
