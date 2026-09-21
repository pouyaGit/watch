"""Frozen models for the research coordinator (EPIC 5 Part 2). Pure data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Closed run-failure vocabulary. Every failure names its stage.
FAILURE_KINDS = (
    "MALFORMED_CANDIDATE",
    "DUPLICATE_CANDIDATE",
    "UNSUPPORTED_CATEGORY",
    "MISSING_GAP",
    "INVALID_DRAFT",
    "INVALID_PLAN",
    "GATE_REFUSAL",
    "QUEUE_FAILURE",
    "MEMORY_FAILURE",
    "SERIALIZATION_FAILURE",
)

#: Closed skip vocabulary (skips are recorded, never silent).
SKIP_REASONS = (
    "DUPLICATE_CANDIDATE",
    "PRIOR_RESEARCH",
)

#: Gate states recorded per case.
GATE_STATES = ("ALLOW", "REFUSE")


@dataclass(frozen=True)
class ResearchRun:
    """One deterministic pass over an input snapshot."""

    run_id: str
    input_snapshot: str
    candidates_processed: int
    cases_created: tuple[str, ...]
    cases_skipped: tuple[dict[str, str], ...]
    cases: tuple[dict[str, Any], ...]
    assignments: tuple[dict[str, Any], ...]
    plans_generated: tuple[str, ...]
    authorization_states: dict[str, str]
    evidence_states: dict[str, str]
    review_items: tuple[dict[str, Any], ...]
    failures: tuple[dict[str, str], ...]
    state_reasons: tuple[dict[str, str], ...]
    queue_snapshot: dict[str, Any] | None
    completion_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "input_snapshot": self.input_snapshot,
            "candidates_processed": int(self.candidates_processed),
            "cases_created": list(self.cases_created),
            "cases_skipped": [dict(item) for item in self.cases_skipped],
            "cases": [dict(item) for item in self.cases],
            "assignments": [dict(item) for item in self.assignments],
            "plans_generated": list(self.plans_generated),
            "authorization_states": dict(self.authorization_states),
            "evidence_states": dict(self.evidence_states),
            "review_items": [dict(item) for item in self.review_items],
            "failures": [dict(item) for item in self.failures],
            "state_reasons": [dict(item) for item in self.state_reasons],
            "queue_snapshot": (
                None if self.queue_snapshot is None else dict(self.queue_snapshot)
            ),
            "completion_summary": dict(self.completion_summary),
        }
