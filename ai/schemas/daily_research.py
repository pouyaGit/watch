"""Daily research workflow schema (Stage R26.3).

A :class:`DailyWorkflow` is a derived, read-only presentation of the existing
R26.2 Action Queue (which itself composes R26.1 / R25.5 / R25.7). It answers
*"What should I work on today?"* and *"What changed since the previous
research state?"* — without a new numeric score, without writing anything and
without executing security testing.

Hard boundaries encoded here:

- closed change-type vocabulary (NEW / REMOVED / CLASS_CHANGED /
  ACTION_CHANGED / MONEY_CHANGED / CONFIDENCE_CHANGED / EVIDENCE_CHANGED /
  SESSION_CHANGED / OUTCOME_CHANGED).
- no payout / bounty / reward / target URL / IP / domain / credential /
  exploit-command / execution-command / production-finding fields exist;
  unknown fields are rejected (``extra="forbid"``).
- ``workflow_version`` is fixed to ``r26-3``; ``research_only`` is forced.
- no persistence: the workflow is an in-memory/derived projection. Snapshots
  are external inputs supplied by the caller (CLI ``workflow diff``).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

WORKFLOW_VERSION = "r26-3"

CHANGE_TYPES: tuple[str, ...] = (
    "NEW",
    "REMOVED",
    "CLASS_CHANGED",
    "ACTION_CHANGED",
    "MONEY_CHANGED",
    "CONFIDENCE_CHANGED",
    "EVIDENCE_CHANGED",
    "SESSION_CHANGED",
    "OUTCOME_CHANGED",
)

CHANGE_TYPE_ORDER: dict[str, int] = {
    name: index for index, name in enumerate(CHANGE_TYPES)
}

MAX_ITEMS = 200
MAX_RECOMMENDATIONS = 16


class WorkflowChange(BaseModel):
    """One deterministic workflow change entry (no clock, no randomness)."""

    model_config = ConfigDict(extra="forbid")

    lead_id: str
    cve_id: str = ""
    program: str = ""
    change_type: str
    before: Any = None
    after: Any = None
    reason: str = ""

    @field_validator("change_type")
    @classmethod
    def _valid_change_type(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in CHANGE_TYPES:
            raise ValueError(f"invalid change_type: {value!r}")
        return text


class DailyWorkflow(BaseModel):
    """Derived, read-only daily research workflow (research-only)."""

    model_config = ConfigDict(extra="forbid")

    workflow_version: str = WORKFLOW_VERSION
    total_opportunities: int = 0
    ready: int = 0
    blocked: int = 0
    in_progress: int = 0
    deferred: int = 0
    completed: int = 0

    top_actions: list[dict] = []
    top_opportunities: list[dict] = []
    blocked_items: list[dict] = []
    in_progress_items: list[dict] = []
    changed_items: list[dict] = []
    recommendations: list[str] = []

    # Full ranked item list used for deterministic comparison/diff. Not a
    # snapshot: it is derived on demand and never persisted by this layer.
    items: list[dict] = []

    research_only: bool = True

    @field_validator("workflow_version")
    @classmethod
    def _fixed_version(cls, value: str) -> str:
        return WORKFLOW_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("daily workflows are research-only")
        return True

    @field_validator("top_actions", "top_opportunities", "blocked_items",
                     "in_progress_items", "changed_items", "items")
    @classmethod
    def _bounded_items(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(item)
            if len(out) >= MAX_ITEMS:
                break
        return out

    @field_validator("recommendations")
    @classmethod
    def _bounded_recommendations(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_RECOMMENDATIONS:
                break
        return out


def daily_workflow_projection(value: DailyWorkflow) -> dict:
    """Serialize one workflow deterministically."""

    return value.model_dump(mode="json")
