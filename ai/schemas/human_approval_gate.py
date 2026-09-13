"""Human approval gate schema (Stage R36.5).

A :class:`HumanApprovalGatePlan` is the deterministic human-approval state
model for one research candidate:

    "Is human approval required, pending, approved, rejected or expired?"

Hard boundaries encoded here:

- State/planning model only: this is NOT an approval service, database, API,
  UI, notification system or persistence layer. Nothing is stored or sent.
- No execution runtime, worker queue, scheduler, dispatch, subprocess, shell
  command, browser, network, Mongo persistence or LLM call is represented or
  created.
- Bounded, privacy-safe, JSON serializable: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

HUMAN_APPROVAL_GATE_RULE_VERSION = "r36-5"
RULE_VERSION = HUMAN_APPROVAL_GATE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

APPROVAL_NOT_REQUIRED = "NOT_REQUIRED"
APPROVAL_PENDING = "PENDING"
APPROVAL_APPROVED = "APPROVED"
APPROVAL_REJECTED = "REJECTED"
APPROVAL_EXPIRED = "EXPIRED"
APPROVAL_UNKNOWN = "UNKNOWN"

APPROVAL_STATES: tuple[str, ...] = (
    APPROVAL_NOT_REQUIRED,
    APPROVAL_PENDING,
    APPROVAL_APPROVED,
    APPROVAL_REJECTED,
    APPROVAL_EXPIRED,
    APPROVAL_UNKNOWN,
)

REASON_POLICY_REQUIRES = "POLICY_REQUIRES_APPROVAL"
REASON_PENDING = "APPROVAL_PENDING"
REASON_APPROVED = "APPROVAL_APPROVED"
REASON_REJECTED = "APPROVAL_REJECTED"
REASON_EXPIRED = "APPROVAL_EXPIRED"
REASON_RESEARCH_NOT_REQUIRED = "RESEARCH_ONLY_NOT_REQUIRED"
REASON_AUTHORIZED_NOT_REQUIRED = "AUTHORIZED_NOT_REQUIRED"
REASON_BLOCKED_NO_ACTION = "BLOCKED_NO_ACTION"
REASON_UNKNOWN_CONTEXT = "UNKNOWN_CONTEXT"

APPROVAL_REASONS: tuple[str, ...] = (
    REASON_POLICY_REQUIRES,
    REASON_PENDING,
    REASON_APPROVED,
    REASON_REJECTED,
    REASON_EXPIRED,
    REASON_RESEARCH_NOT_REQUIRED,
    REASON_AUTHORIZED_NOT_REQUIRED,
    REASON_BLOCKED_NO_ACTION,
    REASON_UNKNOWN_CONTEXT,
)

DETERMINABLE_STATES: tuple[str, ...] = (
    APPROVAL_PENDING,
    APPROVAL_APPROVED,
    APPROVAL_REJECTED,
    APPROVAL_EXPIRED,
)

MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def sanitize_human_approval_gate_plan(value: object) -> dict:
    """Project an R36.5 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "approval_state": "",
            "approval_reason": "",
            "required": False,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "approval_state": _safe_text(value.get("approval_state")),
        "approval_reason": _safe_text(value.get("approval_reason")),
        "required": bool(value.get("required")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class HumanApprovalGatePlan(BaseModel):
    """Deterministic human approval state model (R36.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HUMAN_APPROVAL_GATE_RULE_VERSION
    approval_state: str
    approval_reason: str
    required: bool = False
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HUMAN_APPROVAL_GATE_RULE_VERSION

    @field_validator("approval_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in APPROVAL_STATES:
            raise ValueError(f"invalid approval_state: {value!r}")
        return text

    @field_validator("approval_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in APPROVAL_REASONS:
            raise ValueError(f"invalid approval_reason: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("human approval gates are research-only")
        return True


def human_approval_gate_plan_projection(
    value: HumanApprovalGatePlan,
) -> dict:
    """Serialize a human approval gate plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "HUMAN_APPROVAL_GATE_RULE_VERSION",
    "RULE_VERSION",
    "APPROVAL_STATES",
    "APPROVAL_REASONS",
    "DETERMINABLE_STATES",
    "APPROVAL_NOT_REQUIRED",
    "APPROVAL_PENDING",
    "APPROVAL_APPROVED",
    "APPROVAL_REJECTED",
    "APPROVAL_EXPIRED",
    "APPROVAL_UNKNOWN",
    "REASON_POLICY_REQUIRES",
    "REASON_PENDING",
    "REASON_APPROVED",
    "REASON_REJECTED",
    "REASON_EXPIRED",
    "REASON_RESEARCH_NOT_REQUIRED",
    "REASON_AUTHORIZED_NOT_REQUIRED",
    "REASON_BLOCKED_NO_ACTION",
    "REASON_UNKNOWN_CONTEXT",
    "MAX_VALUE_LEN",
    "HumanApprovalGatePlan",
    "sanitize_human_approval_gate_plan",
    "human_approval_gate_plan_projection",
]
