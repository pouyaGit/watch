"""Execution boundary schema (Stage R36.6).

An :class:`ExecutionBoundaryPlan` defines the explicit, deterministic boundary
between R35 research orchestration, R36 authorization and any future
execution layer:

    "Where exactly is the execution boundary for this candidate?"

Hard boundaries encoded here:

- Planning/authorization only: the boundary is a closed planning label. No
  execution runtime, worker queue, scheduler, dispatch, subprocess, shell
  command, browser, network, Mongo persistence or LLM call is represented or
  created.
- R36 performs no execution: ``execution_performed`` is forced ``False``.
  ``execution_permitted`` is a forward-looking authorization eligibility flag
  only and never performs or schedules anything.
- Bounded, privacy-safe, JSON serializable: only closed codes and bounded
  sanitized orchestration snapshots are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.execution_authorization_plan import (
    AUTHORIZATION_DECISIONS,
    sanitize_source_orchestration_export,
)
from ai.schemas.execution_policy import POLICY_CONSTRAINTS
from ai.schemas.execution_risk import RISK_LEVELS
from ai.schemas.scope_capability_gate import (
    GATE_CONSTRAINTS,
    RESEARCH_CAPABILITIES,
    SCOPE_VALUES,
)

EXECUTION_BOUNDARY_RULE_VERSION = "r36-6"
RULE_VERSION = EXECUTION_BOUNDARY_RULE_VERSION

# Bounded union of policy and scope-gate constraint vocabularies.
BOUNDARY_CONSTRAINTS: tuple[str, ...] = tuple(
    sorted(set(POLICY_CONSTRAINTS) | set(GATE_CONSTRAINTS))
)

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

BOUNDARY_RESEARCH_ONLY = "RESEARCH_ONLY"
BOUNDARY_AUTHORIZED = "AUTHORIZED"
BOUNDARY_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
BOUNDARY_BLOCKED = "BLOCKED"
BOUNDARY_UNKNOWN = "UNKNOWN"

BOUNDARY_STATES: tuple[str, ...] = (
    BOUNDARY_RESEARCH_ONLY,
    BOUNDARY_AUTHORIZED,
    BOUNDARY_HUMAN_REVIEW_REQUIRED,
    BOUNDARY_BLOCKED,
    BOUNDARY_UNKNOWN,
)

BLOCKED_POLICY = "POLICY_BLOCKED"
BLOCKED_MISSING_SCOPE = "MISSING_SCOPE"
BLOCKED_APPROVAL_PENDING = "HUMAN_APPROVAL_PENDING"
BLOCKED_APPROVAL_REJECTED = "HUMAN_APPROVAL_REJECTED"
BLOCKED_APPROVAL_EXPIRED = "HUMAN_APPROVAL_EXPIRED"
BLOCKED_INVALID_WORKFLOW = "INVALID_WORKFLOW"
BLOCKED_UNKNOWN_CONTEXT = "UNKNOWN_CONTEXT"

BLOCKED_CONDITIONS: tuple[str, ...] = (
    BLOCKED_POLICY,
    BLOCKED_MISSING_SCOPE,
    BLOCKED_APPROVAL_PENDING,
    BLOCKED_APPROVAL_REJECTED,
    BLOCKED_APPROVAL_EXPIRED,
    BLOCKED_INVALID_WORKFLOW,
    BLOCKED_UNKNOWN_CONTEXT,
)

BOUNDARY_LIMITATION_PLAN_ONLY = "PLAN_ONLY_NO_EXECUTION"
BOUNDARY_LIMITATION_AUTHORIZATION_ONLY = "AUTHORIZATION_ONLY"
BOUNDARY_LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY_BOUNDARY"
BOUNDARY_LIMITATION_HUMAN_APPROVAL = "HUMAN_APPROVAL_REQUIRED"
BOUNDARY_LIMITATION_BLOCKED = "BLOCKED_NO_ACTION"
BOUNDARY_LIMITATION_UNKNOWN = "UNKNOWN_CONTEXT"

BOUNDARY_LIMITATIONS: tuple[str, ...] = (
    BOUNDARY_LIMITATION_PLAN_ONLY,
    BOUNDARY_LIMITATION_AUTHORIZATION_ONLY,
    BOUNDARY_LIMITATION_RESEARCH_ONLY,
    BOUNDARY_LIMITATION_HUMAN_APPROVAL,
    BOUNDARY_LIMITATION_BLOCKED,
    BOUNDARY_LIMITATION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_CAPABILITIES = 4
MAX_CONSTRAINTS = 6
MAX_CONDITIONS = 6
MAX_LIMITATIONS = 6
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


def sanitize_execution_boundary_plan(value: object) -> dict:
    """Project an R36.6 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "boundary_state": "",
            "authorization_result": "",
            "allowed_capabilities": [],
            "scope": "",
            "human_approval_required": False,
            "risk_level": "",
            "constraints": [],
            "blocked_conditions": [],
            "source_strategy": "",
            "source_orchestration": {},
            "limitations": [],
            "execution_permitted": False,
            "execution_performed": False,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "boundary_state": _safe_text(value.get("boundary_state")),
        "authorization_result": _safe_text(
            value.get("authorization_result")
        ),
        "allowed_capabilities": _bounded_codes(
            value.get("allowed_capabilities"), RESEARCH_CAPABILITIES,
            MAX_CAPABILITIES,
        ),
        "scope": _safe_text(value.get("scope")),
        "human_approval_required": bool(
            value.get("human_approval_required")
        ),
        "risk_level": _safe_text(value.get("risk_level")),
        "constraints": _bounded_codes(
            value.get("constraints"), BOUNDARY_CONSTRAINTS, MAX_CONSTRAINTS
        ),
        "blocked_conditions": _bounded_codes(
            value.get("blocked_conditions"), BLOCKED_CONDITIONS,
            MAX_CONDITIONS,
        ),
        "source_strategy": _safe_text(value.get("source_strategy")),
        "source_orchestration": sanitize_source_orchestration_export(
            value.get("source_orchestration")
        ),
        "limitations": _bounded_codes(
            value.get("limitations"), BOUNDARY_LIMITATIONS, MAX_LIMITATIONS
        ),
        "execution_permitted": bool(value.get("execution_permitted")),
        "execution_performed": False,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ExecutionBoundaryPlan(BaseModel):
    """Deterministic execution boundary definition (R36.6)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EXECUTION_BOUNDARY_RULE_VERSION
    boundary_state: str
    authorization_result: str
    allowed_capabilities: list[str] = Field(default_factory=list)
    scope: str
    human_approval_required: bool = False
    risk_level: str
    constraints: list[str] = Field(default_factory=list)
    blocked_conditions: list[str] = Field(default_factory=list)
    source_strategy: str = ""
    source_orchestration: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    execution_permitted: bool = False
    execution_performed: bool = False
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EXECUTION_BOUNDARY_RULE_VERSION

    @field_validator("boundary_state")
    @classmethod
    def _valid_boundary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in BOUNDARY_STATES:
            raise ValueError(f"invalid boundary_state: {value!r}")
        return text

    @field_validator("authorization_result")
    @classmethod
    def _valid_decision(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_DECISIONS:
            raise ValueError(f"invalid authorization_result: {value!r}")
        return text

    @field_validator("allowed_capabilities")
    @classmethod
    def _valid_capabilities(cls, value: list) -> list[str]:
        return _require_codes(
            value, RESEARCH_CAPABILITIES, MAX_CAPABILITIES
        )

    @field_validator("scope")
    @classmethod
    def _valid_scope(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SCOPE_VALUES:
            raise ValueError(f"invalid scope: {value!r}")
        return text

    @field_validator("risk_level")
    @classmethod
    def _valid_risk(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RISK_LEVELS:
            raise ValueError(f"invalid risk_level: {value!r}")
        return text

    @field_validator("constraints")
    @classmethod
    def _valid_constraints(cls, value: list) -> list[str]:
        return _require_codes(value, BOUNDARY_CONSTRAINTS, MAX_CONSTRAINTS)

    @field_validator("blocked_conditions")
    @classmethod
    def _valid_conditions(cls, value: list) -> list[str]:
        return _require_codes(value, BLOCKED_CONDITIONS, MAX_CONDITIONS)

    @field_validator("source_strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("source_orchestration")
    @classmethod
    def _bounded_orchestration(cls, value: object) -> dict:
        return sanitize_source_orchestration_export(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, BOUNDARY_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("execution_performed")
    @classmethod
    def _never_performed(cls, value: object) -> bool:
        if value:
            raise ValueError("R36 never performs execution")
        return False

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("execution boundary plans are research-only")
        return True


def execution_boundary_plan_projection(
    value: ExecutionBoundaryPlan,
) -> dict:
    """Serialize an execution boundary plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EXECUTION_BOUNDARY_RULE_VERSION",
    "RULE_VERSION",
    "BOUNDARY_STATES",
    "BLOCKED_CONDITIONS",
    "BOUNDARY_CONSTRAINTS",
    "BOUNDARY_LIMITATIONS",
    "BOUNDARY_RESEARCH_ONLY",
    "BOUNDARY_AUTHORIZED",
    "BOUNDARY_HUMAN_REVIEW_REQUIRED",
    "BOUNDARY_BLOCKED",
    "BOUNDARY_UNKNOWN",
    "BLOCKED_POLICY",
    "BLOCKED_MISSING_SCOPE",
    "BLOCKED_APPROVAL_PENDING",
    "BLOCKED_APPROVAL_REJECTED",
    "BLOCKED_APPROVAL_EXPIRED",
    "BLOCKED_INVALID_WORKFLOW",
    "BLOCKED_UNKNOWN_CONTEXT",
    "BOUNDARY_LIMITATION_PLAN_ONLY",
    "BOUNDARY_LIMITATION_AUTHORIZATION_ONLY",
    "BOUNDARY_LIMITATION_RESEARCH_ONLY",
    "BOUNDARY_LIMITATION_HUMAN_APPROVAL",
    "BOUNDARY_LIMITATION_BLOCKED",
    "BOUNDARY_LIMITATION_UNKNOWN",
    "MAX_CAPABILITIES",
    "MAX_CONSTRAINTS",
    "MAX_CONDITIONS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ExecutionBoundaryPlan",
    "sanitize_execution_boundary_plan",
    "execution_boundary_plan_projection",
]
