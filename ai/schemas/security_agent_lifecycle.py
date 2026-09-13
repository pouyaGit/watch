"""Security agent lifecycle schema (Stage R38.4).

A :class:`SecurityAgentLifecyclePlan` defines the conceptual lifecycle states
of a future security specialist agent. It answers the framework question:

    "Where is this agent in its conceptual lifecycle, and which transitions
     are allowed?"

Hard boundaries encoded here:

- Framework/model only: states are conceptual labels; there is no runtime,
  execution, scheduling, persistence, queue or autonomous loop.
- No timestamps and no persistence: repeated evaluation is byte-identical.
- Closed vocabularies: lifecycle states, previous state and validation state
  are closed sets; only legal transitions are allowed.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

SECURITY_AGENT_LIFECYCLE_RULE_VERSION = "r38-4"
RULE_VERSION = SECURITY_AGENT_LIFECYCLE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATE_CREATED = "CREATED"
STATE_PLANNED = "PLANNED"
STATE_ANALYZING = "ANALYZING"
STATE_WAITING_EVIDENCE = "WAITING_EVIDENCE"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"
STATE_UNKNOWN = "UNKNOWN"

LIFECYCLE_STATES: tuple[str, ...] = (
    STATE_CREATED,
    STATE_PLANNED,
    STATE_ANALYZING,
    STATE_WAITING_EVIDENCE,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_UNKNOWN,
)

PREVIOUS_NONE = "NONE"

LIFECYCLE_VALID = "VALID"
LIFECYCLE_INVALID = "INVALID"
LIFECYCLE_UNKNOWN = "UNKNOWN"

LIFECYCLE_VALIDATIONS: tuple[str, ...] = (
    LIFECYCLE_VALID,
    LIFECYCLE_INVALID,
    LIFECYCLE_UNKNOWN,
)

MAX_TRANSITIONS = 4
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_states(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in LIFECYCLE_STATES and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_states(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in LIFECYCLE_STATES:
            raise ValueError(f"invalid lifecycle state: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_security_agent_lifecycle_plan(value: object) -> dict:
    """Project an R38.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "current_state": "",
            "previous_state": "",
            "allowed_transitions": [],
            "lifecycle_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "current_state": _safe_text(value.get("current_state")),
        "previous_state": _safe_text(value.get("previous_state")),
        "allowed_transitions": _bounded_states(
            value.get("allowed_transitions"), MAX_TRANSITIONS
        ),
        "lifecycle_state": _safe_text(value.get("lifecycle_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentLifecyclePlan(BaseModel):
    """Deterministic conceptual agent lifecycle (R38.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_LIFECYCLE_RULE_VERSION
    current_state: str
    previous_state: str = PREVIOUS_NONE
    allowed_transitions: list[str] = Field(default_factory=list)
    lifecycle_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_LIFECYCLE_RULE_VERSION

    @field_validator("current_state")
    @classmethod
    def _valid_current(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LIFECYCLE_STATES:
            raise ValueError(f"invalid current_state: {value!r}")
        return text

    @field_validator("previous_state")
    @classmethod
    def _valid_previous(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LIFECYCLE_STATES + (PREVIOUS_NONE,):
            raise ValueError(f"invalid previous_state: {value!r}")
        return text

    @field_validator("allowed_transitions")
    @classmethod
    def _valid_transitions(cls, value: list) -> list[str]:
        return _require_states(value, MAX_TRANSITIONS)

    @field_validator("lifecycle_state")
    @classmethod
    def _valid_lifecycle(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LIFECYCLE_VALIDATIONS:
            raise ValueError(f"invalid lifecycle_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("security agent lifecycles are research-only")
        return True


def security_agent_lifecycle_plan_projection(
    value: SecurityAgentLifecyclePlan,
) -> dict:
    """Serialize a lifecycle plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_LIFECYCLE_RULE_VERSION",
    "RULE_VERSION",
    "LIFECYCLE_STATES",
    "LIFECYCLE_VALIDATIONS",
    "PREVIOUS_NONE",
    "STATE_CREATED",
    "STATE_PLANNED",
    "STATE_ANALYZING",
    "STATE_WAITING_EVIDENCE",
    "STATE_COMPLETED",
    "STATE_FAILED",
    "STATE_UNKNOWN",
    "LIFECYCLE_VALID",
    "LIFECYCLE_INVALID",
    "LIFECYCLE_UNKNOWN",
    "MAX_TRANSITIONS",
    "MAX_VALUE_LEN",
    "SecurityAgentLifecyclePlan",
    "sanitize_security_agent_lifecycle_plan",
    "security_agent_lifecycle_plan_projection",
]
