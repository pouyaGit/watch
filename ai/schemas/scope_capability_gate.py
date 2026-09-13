"""Scope and capability gate schema (Stage R36.3).

A :class:`ScopeCapabilityGatePlan` is the deterministic capability/scope
authorization snapshot for one research candidate:

    "WHAT (capability) is authorized for WHOM (role), WHERE (scope), WHY
     (strategy context) and under what CONSTRAINTS?"

Hard boundaries encoded here:

- Planning/authorization only: capabilities are conceptual research labels.
  No operational execution capability exists and nothing is executed.
- Conservative scope: a missing or malformed scope resolves to ``UNKNOWN``;
  it can never become unrestricted scope.
- Bounded, privacy-safe, JSON serializable: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_role_plan import AGENT_ROLES

SCOPE_CAPABILITY_GATE_RULE_VERSION = "r36-3"
RULE_VERSION = SCOPE_CAPABILITY_GATE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

CAPABILITY_UNKNOWN = "UNKNOWN"

RESEARCH_CAPABILITIES: tuple[str, ...] = AGENT_ROLES + (CAPABILITY_UNKNOWN,)

SCOPE_AUTHORIZED_RESEARCH = "AUTHORIZED_RESEARCH_SCOPE"
SCOPE_COMPONENT = "COMPONENT_SCOPED"
SCOPE_PROGRAM = "PROGRAM_SCOPED"
SCOPE_UNKNOWN = "UNKNOWN"

SCOPE_VALUES: tuple[str, ...] = (
    SCOPE_AUTHORIZED_RESEARCH,
    SCOPE_COMPONENT,
    SCOPE_PROGRAM,
    SCOPE_UNKNOWN,
)

CERTAINTY_HIGH = "HIGH"
CERTAINTY_MEDIUM = "MEDIUM"
CERTAINTY_LOW = "LOW"
CERTAINTY_UNKNOWN = "UNKNOWN"

SCOPE_CERTAINTIES: tuple[str, ...] = (
    CERTAINTY_HIGH,
    CERTAINTY_MEDIUM,
    CERTAINTY_LOW,
    CERTAINTY_UNKNOWN,
)

GATE_CONSTRAINT_RESEARCH_ONLY = "RESEARCH_ONLY_BOUNDARY"
GATE_CONSTRAINT_COMPONENT_SCOPED = "COMPONENT_SCOPED_ONLY"
GATE_CONSTRAINT_HUMAN_APPROVAL = "HUMAN_APPROVAL_REQUIRED"
GATE_CONSTRAINT_BLOCKED = "BLOCKED"
GATE_CONSTRAINT_UNKNOWN = "UNKNOWN_CONTEXT"

GATE_CONSTRAINTS: tuple[str, ...] = (
    GATE_CONSTRAINT_RESEARCH_ONLY,
    GATE_CONSTRAINT_COMPONENT_SCOPED,
    GATE_CONSTRAINT_HUMAN_APPROVAL,
    GATE_CONSTRAINT_BLOCKED,
    GATE_CONSTRAINT_UNKNOWN,
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


def sanitize_scope_capability_gate_plan(value: object) -> dict:
    """Project an R36.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "capability": "",
            "agent_role": "",
            "scope": "",
            "scope_certainty": "",
            "authorized": False,
            "source_strategy": "",
            "constraints": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "capability": _safe_text(value.get("capability")),
        "agent_role": _safe_text(value.get("agent_role")),
        "scope": _safe_text(value.get("scope")),
        "scope_certainty": _safe_text(value.get("scope_certainty")),
        "authorized": bool(value.get("authorized")),
        "source_strategy": _safe_text(value.get("source_strategy")),
        "constraints": _bounded_codes(
            value.get("constraints"), GATE_CONSTRAINTS, MAX_CONSTRAINTS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ScopeCapabilityGatePlan(BaseModel):
    """Deterministic capability/scope authorization snapshot (R36.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SCOPE_CAPABILITY_GATE_RULE_VERSION
    capability: str
    agent_role: str
    scope: str
    scope_certainty: str
    authorized: bool
    source_strategy: str
    constraints: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SCOPE_CAPABILITY_GATE_RULE_VERSION

    @field_validator("capability")
    @classmethod
    def _valid_capability(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESEARCH_CAPABILITIES:
            raise ValueError(f"invalid capability: {value!r}")
        return text

    @field_validator("agent_role")
    @classmethod
    def _valid_role(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESEARCH_CAPABILITIES:
            raise ValueError(f"invalid agent_role: {value!r}")
        return text

    @field_validator("scope")
    @classmethod
    def _valid_scope(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SCOPE_VALUES:
            raise ValueError(f"invalid scope: {value!r}")
        return text

    @field_validator("scope_certainty")
    @classmethod
    def _valid_certainty(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SCOPE_CERTAINTIES:
            raise ValueError(f"invalid scope_certainty: {value!r}")
        return text

    @field_validator("source_strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("constraints")
    @classmethod
    def _valid_constraints(cls, value: list) -> list[str]:
        return _require_codes(value, GATE_CONSTRAINTS, MAX_CONSTRAINTS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("scope/capability gates are research-only")
        return True


def scope_capability_gate_plan_projection(
    value: ScopeCapabilityGatePlan,
) -> dict:
    """Serialize a scope/capability gate plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SCOPE_CAPABILITY_GATE_RULE_VERSION",
    "RULE_VERSION",
    "RESEARCH_CAPABILITIES",
    "SCOPE_VALUES",
    "SCOPE_CERTAINTIES",
    "GATE_CONSTRAINTS",
    "CAPABILITY_UNKNOWN",
    "SCOPE_AUTHORIZED_RESEARCH",
    "SCOPE_COMPONENT",
    "SCOPE_PROGRAM",
    "SCOPE_UNKNOWN",
    "CERTAINTY_HIGH",
    "CERTAINTY_MEDIUM",
    "CERTAINTY_LOW",
    "CERTAINTY_UNKNOWN",
    "GATE_CONSTRAINT_RESEARCH_ONLY",
    "GATE_CONSTRAINT_COMPONENT_SCOPED",
    "GATE_CONSTRAINT_HUMAN_APPROVAL",
    "GATE_CONSTRAINT_BLOCKED",
    "GATE_CONSTRAINT_UNKNOWN",
    "MAX_CONSTRAINTS",
    "MAX_VALUE_LEN",
    "ScopeCapabilityGatePlan",
    "sanitize_scope_capability_gate_plan",
    "scope_capability_gate_plan_projection",
]
