"""Research audit event schema (Stage R37.3).

A :class:`ResearchAuditEventPlan` is an immutable conceptual audit record for
one governance event. It answers the audit question:

    "What governance event occurred, from which source, and is the record
     internally valid?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  represented or created. Nothing is stored.
- No runtime timestamps and no external ids: the event is derived purely from
  closed inputs; repeated evaluation is byte-identical.
- Bounded, privacy-safe, JSON serializable: only closed codes and bounded
  identifiers are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
)

RESEARCH_AUDIT_EVENT_RULE_VERSION = "r37-3"
RULE_VERSION = RESEARCH_AUDIT_EVENT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

EVENT_STRATEGY_CREATED = "STRATEGY_CREATED"
EVENT_WORKFLOW_CREATED = "WORKFLOW_CREATED"
EVENT_AUTHORIZATION_DECIDED = "AUTHORIZATION_DECIDED"
EVENT_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
EVENT_BLOCK_APPLIED = "BLOCK_APPLIED"
EVENT_UNKNOWN = "UNKNOWN"

AUDIT_EVENT_TYPES: tuple[str, ...] = (
    EVENT_STRATEGY_CREATED,
    EVENT_WORKFLOW_CREATED,
    EVENT_AUTHORIZATION_DECIDED,
    EVENT_APPROVAL_REQUIRED,
    EVENT_BLOCK_APPLIED,
    EVENT_UNKNOWN,
)

SOURCE_STRATEGY = "STRATEGY"
SOURCE_ORCHESTRATION = "ORCHESTRATION"
SOURCE_AUTHORIZATION = "AUTHORIZATION"
SOURCE_GOVERNANCE = "GOVERNANCE"
SOURCE_UNKNOWN = "UNKNOWN"

AUDIT_EVENT_SOURCES: tuple[str, ...] = (
    SOURCE_STRATEGY,
    SOURCE_ORCHESTRATION,
    SOURCE_AUTHORIZATION,
    SOURCE_GOVERNANCE,
    SOURCE_UNKNOWN,
)

SUMMARY_STRATEGY = "STRATEGY_RECORDED"
SUMMARY_WORKFLOW = "WORKFLOW_RECORDED"
SUMMARY_AUTHORIZATION = "AUTHORIZATION_RECORDED"
SUMMARY_APPROVAL = "APPROVAL_GATE_RECORDED"
SUMMARY_BLOCK = "BLOCK_RECORDED"
SUMMARY_UNKNOWN = "UNKNOWN"

AUDIT_EVENT_SUMMARIES: tuple[str, ...] = (
    SUMMARY_STRATEGY,
    SUMMARY_WORKFLOW,
    SUMMARY_AUTHORIZATION,
    SUMMARY_APPROVAL,
    SUMMARY_BLOCK,
    SUMMARY_UNKNOWN,
)

AUDIT_VALID = "VALID"
AUDIT_INVALID = "INVALID"
AUDIT_UNKNOWN = "UNKNOWN"

AUDIT_STATES: tuple[str, ...] = (
    AUDIT_VALID,
    AUDIT_INVALID,
    AUDIT_UNKNOWN,
)

MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def sanitize_research_audit_event_plan(value: object) -> dict:
    """Project an R37.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "event_type": "",
            "event_source": "",
            "event_summary": "",
            "related_strategy": "",
            "related_authorization": "",
            "audit_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "event_type": _safe_text(value.get("event_type")),
        "event_source": _safe_text(value.get("event_source")),
        "event_summary": _safe_text(value.get("event_summary")),
        "related_strategy": _safe_text(value.get("related_strategy")),
        "related_authorization": _safe_text(
            value.get("related_authorization")
        ),
        "audit_state": _safe_text(value.get("audit_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchAuditEventPlan(BaseModel):
    """Deterministic immutable audit event record (R37.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_AUDIT_EVENT_RULE_VERSION
    event_type: str
    event_source: str
    event_summary: str
    related_strategy: str = ""
    related_authorization: str = ""
    audit_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_AUDIT_EVENT_RULE_VERSION

    @field_validator("event_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUDIT_EVENT_TYPES:
            raise ValueError(f"invalid event_type: {value!r}")
        return text

    @field_validator("event_source")
    @classmethod
    def _valid_source(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUDIT_EVENT_SOURCES:
            raise ValueError(f"invalid event_source: {value!r}")
        return text

    @field_validator("event_summary")
    @classmethod
    def _valid_summary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUDIT_EVENT_SUMMARIES:
            raise ValueError(f"invalid event_summary: {value!r}")
        return text

    @field_validator("related_strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("related_authorization")
    @classmethod
    def _valid_authorization(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_DECISIONS:
            raise ValueError(f"invalid related_authorization: {value!r}")
        return text

    @field_validator("audit_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUDIT_STATES:
            raise ValueError(f"invalid audit_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research audit events are research-only")
        return True


def research_audit_event_plan_projection(
    value: ResearchAuditEventPlan,
) -> dict:
    """Serialize an audit event plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_AUDIT_EVENT_RULE_VERSION",
    "RULE_VERSION",
    "AUDIT_EVENT_TYPES",
    "AUDIT_EVENT_SOURCES",
    "AUDIT_EVENT_SUMMARIES",
    "AUDIT_STATES",
    "EVENT_STRATEGY_CREATED",
    "EVENT_WORKFLOW_CREATED",
    "EVENT_AUTHORIZATION_DECIDED",
    "EVENT_APPROVAL_REQUIRED",
    "EVENT_BLOCK_APPLIED",
    "EVENT_UNKNOWN",
    "SOURCE_STRATEGY",
    "SOURCE_ORCHESTRATION",
    "SOURCE_AUTHORIZATION",
    "SOURCE_GOVERNANCE",
    "SOURCE_UNKNOWN",
    "SUMMARY_STRATEGY",
    "SUMMARY_WORKFLOW",
    "SUMMARY_AUTHORIZATION",
    "SUMMARY_APPROVAL",
    "SUMMARY_BLOCK",
    "SUMMARY_UNKNOWN",
    "AUDIT_VALID",
    "AUDIT_INVALID",
    "AUDIT_UNKNOWN",
    "MAX_VALUE_LEN",
    "ResearchAuditEventPlan",
    "sanitize_research_audit_event_plan",
    "research_audit_event_plan_projection",
]
