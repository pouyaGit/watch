"""Agent role schema (Stage R35.1).

An :class:`AgentRolePlan` determines which research roles are conceptually
needed for a given strategy. It answers the owner's personal-research
question:

    "Which conceptual research roles does this strategy require?"

Hard boundaries encoded here:

- Orchestration planning only: roles are planning labels. No agent runtime,
  worker queue, scheduler, task dispatch or execution is represented.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: role and role-reason codes are closed sets; confidence
  reuses the R31.15 set.
- Bounded, privacy-safe: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

AGENT_ROLE_PLAN_RULE_VERSION = "r35-1"
RULE_VERSION = AGENT_ROLE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

ROLE_ASSET_ANALYSIS = "ASSET_ANALYSIS"
ROLE_IDENTITY_ANALYSIS = "IDENTITY_ANALYSIS"
ROLE_TECHNOLOGY_ANALYSIS = "TECHNOLOGY_ANALYSIS"
ROLE_VERSION_ANALYSIS = "VERSION_ANALYSIS"
ROLE_EVIDENCE_ANALYSIS = "EVIDENCE_ANALYSIS"
ROLE_HISTORY_ANALYSIS = "HISTORY_ANALYSIS"
ROLE_HUMAN_REVIEW = "HUMAN_REVIEW"

AGENT_ROLES: tuple[str, ...] = (
    ROLE_ASSET_ANALYSIS,
    ROLE_IDENTITY_ANALYSIS,
    ROLE_TECHNOLOGY_ANALYSIS,
    ROLE_VERSION_ANALYSIS,
    ROLE_EVIDENCE_ANALYSIS,
    ROLE_HISTORY_ANALYSIS,
    ROLE_HUMAN_REVIEW,
)

REASON_IDENTITY = "IDENTITY_STRATEGY"
REASON_VERSION = "VERSION_STRATEGY"
REASON_TECHNOLOGY = "TECHNOLOGY_STRATEGY"
REASON_EVIDENCE = "EVIDENCE_STRATEGY"
REASON_SCOPE = "SCOPE_STRATEGY"
REASON_HUMAN = "HUMAN_REVIEW_STRATEGY"
REASON_DEFERRED = "DEFERRED_STRATEGY"
REASON_UNKNOWN = "UNKNOWN_STRATEGY"

ROLE_REASONS: tuple[str, ...] = (
    REASON_IDENTITY,
    REASON_VERSION,
    REASON_TECHNOLOGY,
    REASON_EVIDENCE,
    REASON_SCOPE,
    REASON_HUMAN,
    REASON_DEFERRED,
    REASON_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_ROLES = 4
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_roles(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in AGENT_ROLES:
            raise ValueError(f"invalid role: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_roles(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in AGENT_ROLES and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_agent_role_plan(value: object) -> dict:
    """Project an R35.1 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "required_roles": [],
            "primary_role": "",
            "role_reason": "",
            "confidence_level": "",
            "research_only": True,
        }
    primary = _safe_text(value.get("primary_role"))
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "required_roles": _bounded_roles(
            value.get("required_roles"), MAX_ROLES
        ),
        "primary_role": primary if primary in AGENT_ROLES else "",
        "role_reason": _safe_text(value.get("role_reason")),
        "confidence_level": _safe_text(value.get("confidence_level")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentRolePlan(BaseModel):
    """Deterministic conceptual research role plan (R35.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_ROLE_PLAN_RULE_VERSION
    required_roles: list[str] = Field(default_factory=list)
    primary_role: str
    role_reason: str
    confidence_level: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_ROLE_PLAN_RULE_VERSION

    @field_validator("required_roles")
    @classmethod
    def _valid_roles(cls, value: list) -> list[str]:
        return _require_roles(value, MAX_ROLES)

    @field_validator("primary_role")
    @classmethod
    def _valid_primary(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_ROLES:
            raise ValueError(f"invalid primary_role: {value!r}")
        return text

    @field_validator("role_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ROLE_REASONS:
            raise ValueError(f"invalid role_reason: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("agent role plans are research-only")
        return True


def agent_role_plan_projection(value: AgentRolePlan) -> dict:
    """Serialize an agent role plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_ROLE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "AGENT_ROLES",
    "ROLE_REASONS",
    "ROLE_ASSET_ANALYSIS",
    "ROLE_IDENTITY_ANALYSIS",
    "ROLE_TECHNOLOGY_ANALYSIS",
    "ROLE_VERSION_ANALYSIS",
    "ROLE_EVIDENCE_ANALYSIS",
    "ROLE_HISTORY_ANALYSIS",
    "ROLE_HUMAN_REVIEW",
    "REASON_IDENTITY",
    "REASON_VERSION",
    "REASON_TECHNOLOGY",
    "REASON_EVIDENCE",
    "REASON_SCOPE",
    "REASON_HUMAN",
    "REASON_DEFERRED",
    "REASON_UNKNOWN",
    "MAX_ROLES",
    "MAX_VALUE_LEN",
    "AgentRolePlan",
    "sanitize_agent_role_plan",
    "agent_role_plan_projection",
]
