"""Governance rule trace schema (Stage R37.2).

A :class:`GovernanceRuleTracePlan` is the deterministic, read-only explanation
of which governance rules produced an authorization decision. It answers the
audit question:

    "Which explicit rules fired, which were rejected, and in what precedence?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  represented or created.
- No hidden decision logic: every applied/rejected rule is a closed code and
  the precedence order is explicit.
- Bounded, privacy-safe, JSON serializable: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

GOVERNANCE_RULE_TRACE_RULE_VERSION = "r37-2"
RULE_VERSION = GOVERNANCE_RULE_TRACE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

RULE_CONTEXT_VALIDATION = "CONTEXT_VALIDATION_FIRST"
RULE_POLICY_BLOCK = "POLICY_BLOCK_TERMINAL"
RULE_HUMAN_APPROVAL = "HUMAN_APPROVAL_MANDATORY"
RULE_RESEARCH_ONLY = "RESEARCH_ONLY_LIMIT"
RULE_PASSIVE_ONLY = "PASSIVE_ONLY_LIMIT"
RULE_ACTIVE_ALLOWED = "ACTIVE_ALLOWED_VALID"
RULE_SCOPE_GATE = "SCOPE_GATE"
RULE_SCOPE_UNKNOWN = "SCOPE_UNKNOWN_CONSERVATIVE"
RULE_APPROVAL_GATE = "APPROVAL_GATE"
RULE_RISK_NOT_PERMISSION = "RISK_NOT_PERMISSION"
RULE_BOUNDARY = "BOUNDARY_PRECEDENCE"
RULE_UNKNOWN = "UNKNOWN_CONTEXT"

GOVERNANCE_RULES: tuple[str, ...] = (
    RULE_CONTEXT_VALIDATION,
    RULE_POLICY_BLOCK,
    RULE_HUMAN_APPROVAL,
    RULE_RESEARCH_ONLY,
    RULE_PASSIVE_ONLY,
    RULE_ACTIVE_ALLOWED,
    RULE_SCOPE_GATE,
    RULE_SCOPE_UNKNOWN,
    RULE_APPROVAL_GATE,
    RULE_RISK_NOT_PERMISSION,
    RULE_BOUNDARY,
    RULE_UNKNOWN,
)

# Fixed, explicit governance precedence (documented and always emitted).
PRECEDENCE_ORDER: tuple[str, ...] = (
    RULE_CONTEXT_VALIDATION,
    RULE_POLICY_BLOCK,
    RULE_HUMAN_APPROVAL,
    RULE_RESEARCH_ONLY,
    RULE_PASSIVE_ONLY,
    RULE_ACTIVE_ALLOWED,
    RULE_SCOPE_GATE,
    RULE_APPROVAL_GATE,
    RULE_RISK_NOT_PERMISSION,
    RULE_BOUNDARY,
)

TRACE_COMPLETE = "COMPLETE"
TRACE_PARTIAL = "PARTIAL"
TRACE_UNKNOWN = "UNKNOWN"

TRACE_STATES: tuple[str, ...] = (
    TRACE_COMPLETE,
    TRACE_PARTIAL,
    TRACE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_RULES = 8
MAX_PRECEDENCE = 10
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_rules(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in GOVERNANCE_RULES and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_rules(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in GOVERNANCE_RULES:
            raise ValueError(f"invalid governance rule: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_governance_rule_trace_plan(value: object) -> dict:
    """Project an R37.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "applied_rules": [],
            "rejected_rules": [],
            "precedence_order": [],
            "trace_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "applied_rules": _bounded_rules(
            value.get("applied_rules"), MAX_RULES
        ),
        "rejected_rules": _bounded_rules(
            value.get("rejected_rules"), MAX_RULES
        ),
        "precedence_order": _bounded_rules(
            value.get("precedence_order"), MAX_PRECEDENCE
        ),
        "trace_state": _safe_text(value.get("trace_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class GovernanceRuleTracePlan(BaseModel):
    """Deterministic governance rule trace (R37.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = GOVERNANCE_RULE_TRACE_RULE_VERSION
    applied_rules: list[str] = Field(default_factory=list)
    rejected_rules: list[str] = Field(default_factory=list)
    precedence_order: list[str] = Field(default_factory=list)
    trace_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return GOVERNANCE_RULE_TRACE_RULE_VERSION

    @field_validator("applied_rules", "rejected_rules")
    @classmethod
    def _valid_rules(cls, value: list) -> list[str]:
        return _require_rules(value, MAX_RULES)

    @field_validator("precedence_order")
    @classmethod
    def _valid_precedence(cls, value: list) -> list[str]:
        return _require_rules(value, MAX_PRECEDENCE)

    @field_validator("trace_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TRACE_STATES:
            raise ValueError(f"invalid trace_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("governance rule traces are research-only")
        return True


def governance_rule_trace_plan_projection(
    value: GovernanceRuleTracePlan,
) -> dict:
    """Serialize a governance rule trace to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "GOVERNANCE_RULE_TRACE_RULE_VERSION",
    "RULE_VERSION",
    "GOVERNANCE_RULES",
    "PRECEDENCE_ORDER",
    "TRACE_STATES",
    "RULE_CONTEXT_VALIDATION",
    "RULE_POLICY_BLOCK",
    "RULE_HUMAN_APPROVAL",
    "RULE_RESEARCH_ONLY",
    "RULE_PASSIVE_ONLY",
    "RULE_ACTIVE_ALLOWED",
    "RULE_SCOPE_GATE",
    "RULE_SCOPE_UNKNOWN",
    "RULE_APPROVAL_GATE",
    "RULE_RISK_NOT_PERMISSION",
    "RULE_BOUNDARY",
    "RULE_UNKNOWN",
    "TRACE_COMPLETE",
    "TRACE_PARTIAL",
    "TRACE_UNKNOWN",
    "MAX_RULES",
    "MAX_PRECEDENCE",
    "MAX_VALUE_LEN",
    "GovernanceRuleTracePlan",
    "sanitize_governance_rule_trace_plan",
    "governance_rule_trace_plan_projection",
]
