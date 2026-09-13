"""Research execution authorization export schema (Stage R36.7).

A :class:`ResearchExecutionAuthorizationExportPlan` is the final deterministic,
read-only export of the R36 execution-safety boundary:

    "What authorization intelligence is ready for downstream consumers?"

Hard boundaries encoded here:

- Planning/authorization only: the export is advisory and never performs or
  schedules execution. No execution runtime, worker queue, scheduler,
  dispatch, subprocess, shell command, browser, network, Mongo persistence or
  LLM call is represented or created.
- ``ready`` is true only when every critical authorization component is
  present and non-UNKNOWN.
- Bounded, privacy-safe, JSON serializable: embedded plans are projected onto
  fixed closed key sets and sanitized.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.execution_authorization_plan import (
    sanitize_execution_authorization_plan,
    sanitize_source_orchestration_export,
    sanitize_source_strategy_export,
)
from ai.schemas.execution_boundary_plan import (
    BOUNDARY_CONSTRAINTS,
    sanitize_execution_boundary_plan,
)
from ai.schemas.execution_policy import (
    sanitize_execution_policy_plan,
)
from ai.schemas.execution_risk import sanitize_execution_risk_plan
from ai.schemas.human_approval_gate import sanitize_human_approval_gate_plan
from ai.schemas.scope_capability_gate import (
    RESEARCH_CAPABILITIES,
    sanitize_scope_capability_gate_plan,
)

RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION = "r36-7"
RULE_VERSION = RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIMITATION_UNKNOWN_AUTHORIZATION = "UNKNOWN_AUTHORIZATION"
LIMITATION_UNKNOWN_RISK = "UNKNOWN_RISK"
LIMITATION_UNKNOWN_SCOPE = "UNKNOWN_SCOPE"
LIMITATION_UNKNOWN_APPROVAL = "UNKNOWN_APPROVAL"
LIMITATION_UNKNOWN_BOUNDARY = "UNKNOWN_BOUNDARY"
LIMITATION_BLOCKED = "BLOCKED"
LIMITATION_HUMAN_APPROVAL_PENDING = "HUMAN_APPROVAL_PENDING"
LIMITATION_MISSING_SCOPE = "MISSING_SCOPE"
LIMITATION_INVALID_WORKFLOW = "INVALID_WORKFLOW"

EXPORT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_UNKNOWN_AUTHORIZATION,
    LIMITATION_UNKNOWN_RISK,
    LIMITATION_UNKNOWN_SCOPE,
    LIMITATION_UNKNOWN_APPROVAL,
    LIMITATION_UNKNOWN_BOUNDARY,
    LIMITATION_BLOCKED,
    LIMITATION_HUMAN_APPROVAL_PENDING,
    LIMITATION_MISSING_SCOPE,
    LIMITATION_INVALID_WORKFLOW,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_CAPABILITIES = 4
MAX_CONSTRAINTS = 8
MAX_LIMITATIONS = 9
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


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchExecutionAuthorizationExportPlan(BaseModel):
    """Final deterministic R36 authorization export object (R36.7)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION
    ready: bool
    authorization: dict = Field(default_factory=dict)
    policy: dict = Field(default_factory=dict)
    risk: dict = Field(default_factory=dict)
    scope: dict = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)
    human_approval: dict = Field(default_factory=dict)
    constraints: list[str] = Field(default_factory=list)
    source_strategy: dict = Field(default_factory=dict)
    source_orchestration: dict = Field(default_factory=dict)
    execution_boundary: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION

    @field_validator("authorization")
    @classmethod
    def _bounded_authorization(cls, value: object) -> dict:
        return sanitize_execution_authorization_plan(value)

    @field_validator("policy")
    @classmethod
    def _bounded_policy(cls, value: object) -> dict:
        return sanitize_execution_policy_plan(value)

    @field_validator("risk")
    @classmethod
    def _bounded_risk(cls, value: object) -> dict:
        return sanitize_execution_risk_plan(value)

    @field_validator("scope")
    @classmethod
    def _bounded_scope(cls, value: object) -> dict:
        return sanitize_scope_capability_gate_plan(value)

    @field_validator("capabilities")
    @classmethod
    def _valid_capabilities(cls, value: list) -> list[str]:
        return _require_codes(
            value, RESEARCH_CAPABILITIES, MAX_CAPABILITIES
        )

    @field_validator("human_approval")
    @classmethod
    def _bounded_approval(cls, value: object) -> dict:
        return sanitize_human_approval_gate_plan(value)

    @field_validator("constraints")
    @classmethod
    def _valid_constraints(cls, value: list) -> list[str]:
        return _require_codes(
            value, BOUNDARY_CONSTRAINTS, MAX_CONSTRAINTS
        )

    @field_validator("source_strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> dict:
        return sanitize_source_strategy_export(value)

    @field_validator("source_orchestration")
    @classmethod
    def _bounded_orchestration(cls, value: object) -> dict:
        return sanitize_source_orchestration_export(value)

    @field_validator("execution_boundary")
    @classmethod
    def _bounded_boundary(cls, value: object) -> dict:
        return sanitize_execution_boundary_plan(value)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(value, EXPORT_LIMITATIONS, MAX_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research execution authorization exports are research-only"
            )
        return True


def research_execution_authorization_export_plan_projection(
    value: ResearchExecutionAuthorizationExportPlan,
) -> dict:
    """Serialize an R36 authorization export to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_EXECUTION_AUTHORIZATION_EXPORT_RULE_VERSION",
    "RULE_VERSION",
    "EXPORT_LIMITATIONS",
    "LIMITATION_UNKNOWN_AUTHORIZATION",
    "LIMITATION_UNKNOWN_RISK",
    "LIMITATION_UNKNOWN_SCOPE",
    "LIMITATION_UNKNOWN_APPROVAL",
    "LIMITATION_UNKNOWN_BOUNDARY",
    "LIMITATION_BLOCKED",
    "LIMITATION_HUMAN_APPROVAL_PENDING",
    "LIMITATION_MISSING_SCOPE",
    "LIMITATION_INVALID_WORKFLOW",
    "MAX_CAPABILITIES",
    "MAX_CONSTRAINTS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ResearchExecutionAuthorizationExportPlan",
    "research_execution_authorization_export_plan_projection",
]
