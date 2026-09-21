"""Frozen models for the review queue (EPIC 5 Part 7). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Closed review-reason vocabulary.
REVIEW_REASONS = (
    "DRAFT_INVALID",
    "PLAN_INVALID",
    "AUTHORIZATION_REFUSED",
    "EVIDENCE_INCOMPLETE",
    "DUPLICATE_OBSERVED",
)

#: Closed next-action vocabulary.
REVIEW_ACTIONS = (
    "COLLECT_FIRST_OBSERVATION",
    "RESOLVE_REFUSAL",
    "HUMAN_TRIAGE",
    "DEDUPE_CONFIRM",
    "REPLAN_OBSERVATION",
)


@dataclass(frozen=True)
class ReviewItem:
    """One case awaiting human review, with its full offline context."""

    case_id: str
    reason: str
    current_state: str
    evidence_state: str
    missing_evidence: tuple[str, ...]
    research_history: dict[str, Any]
    recommended_next_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "reason": self.reason,
            "current_state": self.current_state,
            "evidence_state": self.evidence_state,
            "missing_evidence": list(self.missing_evidence),
            "research_history": dict(self.research_history),
            "recommended_next_action": self.recommended_next_action,
        }


@dataclass(frozen=True)
class ReviewQueue:
    """Deterministic queue of review items (ordered by case id)."""

    queue_id: str
    items: tuple[ReviewItem, ...]
    total: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "queue_id": self.queue_id,
            "items": [item.to_dict() for item in self.items],
            "total": int(self.total),
        }
