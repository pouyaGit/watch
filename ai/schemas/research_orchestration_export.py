"""Research orchestration export schema (Stage R35.4).

A :class:`ResearchOrchestrationExportPlan` is the final deterministic,
read-only export over the R35.1 role plan, R35.2 workflow graph and R35.3
coordination plan. It answers the owner's personal-research question:

    "What conceptual orchestration intelligence is ready?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``. No agent runtime, worker
  queue, scheduler or dispatch exists.
- Closed vocabularies: limitation codes are a closed set; embedded plan
  vocabularies remain owned by R35.1-R35.3.
- Bounded, privacy-safe: embedded plans are projected onto fixed, closed key
  sets and sanitized.
- No Money Score, no R29 modification, no persistence.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_coordination import sanitize_agent_coordination_plan
from ai.schemas.agent_role_plan import sanitize_agent_role_plan
from ai.schemas.research_workflow_graph import (
    sanitize_research_workflow_graph_plan,
)

RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION = "r35-4"
RULE_VERSION = RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_UNKNOWN_STRATEGY = "UNKNOWN_STRATEGY"
LIMITATION_LOW_CONFIDENCE = "LOW_CONFIDENCE"
LIMITATION_DEFERRED_STRATEGY = "DEFERRED_STRATEGY"
LIMITATION_UNKNOWN_COORDINATION = "UNKNOWN_COORDINATION"
LIMITATION_EMPTY_WORKFLOW = "EMPTY_WORKFLOW"

LIMITATION_CODES: tuple[str, ...] = (
    LIMITATION_UNKNOWN_STRATEGY,
    LIMITATION_LOW_CONFIDENCE,
    LIMITATION_DEFERRED_STRATEGY,
    LIMITATION_UNKNOWN_COORDINATION,
    LIMITATION_EMPTY_WORKFLOW,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_LIMITATIONS = 8
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchOrchestrationExportPlan(BaseModel):
    """Final deterministic research orchestration export object (R35.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION
    ready: bool
    roles: dict = Field(default_factory=dict)
    workflow: dict = Field(default_factory=dict)
    coordination: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION

    @field_validator("roles")
    @classmethod
    def _bounded_roles(cls, value: object) -> dict:
        return sanitize_agent_role_plan(value)

    @field_validator("workflow")
    @classmethod
    def _bounded_workflow(cls, value: object) -> dict:
        return sanitize_research_workflow_graph_plan(value)

    @field_validator("coordination")
    @classmethod
    def _bounded_coordination(cls, value: object) -> dict:
        return sanitize_agent_coordination_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(value, LIMITATION_CODES, MAX_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research orchestration exports are research-only"
            )
        return True


def research_orchestration_export_plan_projection(
    value: ResearchOrchestrationExportPlan,
) -> dict:
    """Serialize an orchestration export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_ORCHESTRATION_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "LIMITATION_CODES",
    "LIMITATION_UNKNOWN_STRATEGY",
    "LIMITATION_LOW_CONFIDENCE",
    "LIMITATION_DEFERRED_STRATEGY",
    "LIMITATION_UNKNOWN_COORDINATION",
    "LIMITATION_EMPTY_WORKFLOW",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ResearchOrchestrationExportPlan",
    "research_orchestration_export_plan_projection",
]
