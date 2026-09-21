"""Review queue construction (EPIC 5 Part 7). Pure builders."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from aec.review.models import (
    REVIEW_ACTIONS,
    REVIEW_REASONS,
    ReviewItem,
    ReviewQueue,
)

#: Reason → recommended next action. Unknown reasons triage to a human.
_RECOMMENDATIONS = {
    "EVIDENCE_INCOMPLETE": "COLLECT_FIRST_OBSERVATION",
    "AUTHORIZATION_REFUSED": "RESOLVE_REFUSAL",
    "DRAFT_INVALID": "HUMAN_TRIAGE",
    "PLAN_INVALID": "REPLAN_OBSERVATION",
    "DUPLICATE_OBSERVED": "DEDUPE_CONFIRM",
}


def recommend_for(reason: Any) -> str:
    """Deterministic next action for a review reason."""
    if isinstance(reason, str):
        action = _RECOMMENDATIONS.get(reason)
        if action is not None:
            return action
    return "HUMAN_TRIAGE"


def build_review_item(fields: Any) -> ReviewItem:
    """Validate a mapping into a ReviewItem, deriving the action."""
    if not isinstance(fields, Mapping):
        raise ValueError("review item fields must be a mapping")
    case_id = fields.get("case_id", "")
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("review item needs a non-empty case_id")
    reason = fields.get("reason", "")
    if reason not in REVIEW_REASONS:
        raise ValueError(f"unknown review reason: {reason!r}")
    missing = fields.get("missing_evidence", ())
    if isinstance(missing, (list, tuple)):
        missing_items = tuple(sorted({
            str(item) for item in missing if str(item)
        }))
    else:
        missing_items = ()
    history = fields.get("research_history", {})
    history = dict(history) if isinstance(history, Mapping) else {}
    action = fields.get("recommended_next_action", "")
    if action not in REVIEW_ACTIONS:
        action = recommend_for(reason)
    evidence_state = fields.get("evidence_state", "")
    current_state = fields.get("current_state", "")
    return ReviewItem(
        case_id=case_id.strip(),
        reason=str(reason),
        current_state=str(current_state or ""),
        evidence_state=str(evidence_state or ""),
        missing_evidence=missing_items,
        research_history=history,
        recommended_next_action=str(action),
    )


def build_review_queue(items: Sequence[Any]) -> ReviewQueue:
    """Order validated items by case id under a content-hash queue id."""
    built = sorted(
        (build_review_item(fields) for fields in items),
        key=lambda item: item.case_id,
    )
    canonical = json.dumps(
        [item.to_dict() for item in built],
        sort_keys=True, separators=(",", ":"),
    )
    queue_id = "review:" + hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return ReviewQueue(
        queue_id=queue_id, items=tuple(built), total=len(built))


def serialize_queue(queue: ReviewQueue) -> str:
    """Stable JSON for a review queue."""
    return json.dumps(queue.to_dict(), sort_keys=True, separators=(",", ":"))
