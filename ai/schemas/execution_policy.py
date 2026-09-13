"""Execution policy schema (Stage R36.1).

An :class:`ExecutionPolicyPlan` is the deterministic, explicit execution
authorization policy for one research candidate. It is the top of the R36
execution-safety boundary:

    "What execution policy applies to this candidate?"

Hard boundaries encoded here:

- Planning/authorization only: the policy is a closed planning label. No
  execution runtime, worker queue, scheduler, dispatch, subprocess, shell
  command, browser, network, Mongo persistence or LLM call is represented or
  created.
- No free-form permissions: only the closed policy vocabulary exists; unknown
  or malformed policy values are represented as ``UNKNOWN`` and never become
  permissive.
- Bounded, privacy-safe, JSON serializable: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXECUTION_POLICY_RULE_VERSION = "r36-1"
RULE_VERSION = EXECUTION_POLICY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

POLICY_RESEARCH_ONLY = "RESEARCH_ONLY"
POLICY_PASSIVE_ONLY = "PASSIVE_ONLY"
POLICY_ACTIVE_ALLOWED = "ACTIVE_ALLOWED"
POLICY_HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
POLICY_BLOCKED = "BLOCKED"
POLICY_UNKNOWN = "UNKNOWN"

EXECUTION_POLICIES: tuple[str, ...] = (
    POLICY_RESEARCH_ONLY,
    POLICY_PASSIVE_ONLY,
    POLICY_ACTIVE_ALLOWED,
    POLICY_HUMAN_APPROVAL_REQUIRED,
    POLICY_BLOCKED,
    POLICY_UNKNOWN,
)

REASON_RESEARCH_DEFAULT = "RESEARCH_DEFAULT"
REASON_PASSIVE_RESEARCH = "PASSIVE_RESEARCH"
REASON_ACTIVE_EXPLICIT = "ACTIVE_EXPLICIT_AUTHORIZATION"
REASON_HUMAN_MANDATED = "HUMAN_APPROVAL_MANDATED"
REASON_BLOCKED_MANDATED = "BLOCKED_MANDATED"
REASON_UNKNOWN = "UNKNOWN_POLICY"

EXECUTION_POLICY_REASONS: tuple[str, ...] = (
    REASON_RESEARCH_DEFAULT,
    REASON_PASSIVE_RESEARCH,
    REASON_ACTIVE_EXPLICIT,
    REASON_HUMAN_MANDATED,
    REASON_BLOCKED_MANDATED,
    REASON_UNKNOWN,
)

CONSTRAINT_NO_TARGET_INTERACTION = "NO_TARGET_INTERACTION"
CONSTRAINT_PASSIVE_OBSERVATION = "PASSIVE_OBSERVATION_ONLY"
CONSTRAINT_AUTHORIZED_SCOPE_ONLY = "AUTHORIZED_SCOPE_ONLY"
CONSTRAINT_HUMAN_APPROVAL_MANDATORY = "HUMAN_APPROVAL_MANDATORY"
CONSTRAINT_NO_ACTION_PERMITTED = "NO_ACTION_PERMITTED"
CONSTRAINT_UNKNOWN_NO_ACTION = "UNKNOWN_NO_ACTION"

POLICY_CONSTRAINTS: tuple[str, ...] = (
    CONSTRAINT_NO_TARGET_INTERACTION,
    CONSTRAINT_PASSIVE_OBSERVATION,
    CONSTRAINT_AUTHORIZED_SCOPE_ONLY,
    CONSTRAINT_HUMAN_APPROVAL_MANDATORY,
    CONSTRAINT_NO_ACTION_PERMITTED,
    CONSTRAINT_UNKNOWN_NO_ACTION,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_CONSTRAINTS = 4
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


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


def sanitize_execution_policy_plan(value: object) -> dict:
    """Project an R36.1 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "policy": "",
            "policy_reason": "",
            "constraints": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "policy": _safe_text(value.get("policy")),
        "policy_reason": _safe_text(value.get("policy_reason")),
        "constraints": _bounded_codes(
            value.get("constraints"), POLICY_CONSTRAINTS, MAX_CONSTRAINTS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ExecutionPolicyPlan(BaseModel):
    """Deterministic explicit execution policy (R36.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EXECUTION_POLICY_RULE_VERSION
    policy: str
    policy_reason: str
    constraints: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EXECUTION_POLICY_RULE_VERSION

    @field_validator("policy")
    @classmethod
    def _valid_policy(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_POLICIES:
            raise ValueError(f"invalid policy: {value!r}")
        return text

    @field_validator("policy_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_POLICY_REASONS:
            raise ValueError(f"invalid policy_reason: {value!r}")
        return text

    @field_validator("constraints")
    @classmethod
    def _valid_constraints(cls, value: list) -> list[str]:
        return _require_codes(value, POLICY_CONSTRAINTS, MAX_CONSTRAINTS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("execution policies are research-only")
        return True


def execution_policy_plan_projection(value: ExecutionPolicyPlan) -> dict:
    """Serialize an execution policy plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EXECUTION_POLICY_RULE_VERSION",
    "RULE_VERSION",
    "EXECUTION_POLICIES",
    "EXECUTION_POLICY_REASONS",
    "POLICY_CONSTRAINTS",
    "POLICY_RESEARCH_ONLY",
    "POLICY_PASSIVE_ONLY",
    "POLICY_ACTIVE_ALLOWED",
    "POLICY_HUMAN_APPROVAL_REQUIRED",
    "POLICY_BLOCKED",
    "POLICY_UNKNOWN",
    "REASON_RESEARCH_DEFAULT",
    "REASON_PASSIVE_RESEARCH",
    "REASON_ACTIVE_EXPLICIT",
    "REASON_HUMAN_MANDATED",
    "REASON_BLOCKED_MANDATED",
    "REASON_UNKNOWN",
    "CONSTRAINT_NO_TARGET_INTERACTION",
    "CONSTRAINT_PASSIVE_OBSERVATION",
    "CONSTRAINT_AUTHORIZED_SCOPE_ONLY",
    "CONSTRAINT_HUMAN_APPROVAL_MANDATORY",
    "CONSTRAINT_NO_ACTION_PERMITTED",
    "CONSTRAINT_UNKNOWN_NO_ACTION",
    "MAX_CONSTRAINTS",
    "MAX_VALUE_LEN",
    "ExecutionPolicyPlan",
    "sanitize_execution_policy_plan",
    "execution_policy_plan_projection",
]
