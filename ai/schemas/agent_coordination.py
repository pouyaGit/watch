"""Agent coordination schema (Stage R35.3).

An :class:`AgentCoordinationPlan` describes conceptual coordination between
research roles. It answers the owner's personal-research question:

    "How would the conceptual research roles coordinate?"

Hard boundaries encoded here:

- Planning labels only: coordination modes and handoff points are conceptual.
  No agent runtime, real agent communication, worker queue, scheduler or
  dispatch is represented.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: coordination mode, roles and entry keys are closed
  sets.
- Bounded, privacy-safe: only closed codes are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_role_plan import AGENT_ROLES

AGENT_COORDINATION_RULE_VERSION = "r35-3"
RULE_VERSION = AGENT_COORDINATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

MODE_SEQUENTIAL = "SEQUENTIAL"
MODE_REVIEW_GATE = "REVIEW_GATE"
MODE_STOPPED = "STOPPED"
MODE_UNKNOWN = "UNKNOWN"

COORDINATION_MODES: tuple[str, ...] = (
    MODE_SEQUENTIAL,
    MODE_REVIEW_GATE,
    MODE_STOPPED,
    MODE_UNKNOWN,
)

DEPENDENCY_KEYS: tuple[str, ...] = ("role", "depends_on")
HANDOFF_KEYS: tuple[str, ...] = ("from", "to")

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_ROLES = 4
MAX_DEPENDENCIES = 4
MAX_HANDOFFS = 4
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_roles(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in AGENT_ROLES and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


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


def _bounded_pairs(
    value: object, keys: tuple, limit: int
) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        first = _safe_text(item.get(keys[0]))
        second = _safe_text(item.get(keys[1]))
        if first not in AGENT_ROLES or second not in AGENT_ROLES:
            continue
        if first == second:
            continue
        entry = {keys[0]: first, keys[1]: second}
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def _require_pairs(
    value: object, keys: tuple, limit: int
) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            raise ValueError(f"malformed entry: {item!r}")
        first = _safe_text(item.get(keys[0]))
        second = _safe_text(item.get(keys[1]))
        if first not in AGENT_ROLES or second not in AGENT_ROLES:
            raise ValueError(f"invalid role pair: {item!r}")
        if first == second:
            raise ValueError(f"self-pair: {item!r}")
        entry = {keys[0]: first, keys[1]: second}
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def sanitize_agent_coordination_plan(value: object) -> dict:
    """Project an R35.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "coordination_mode": "",
            "role_sequence": [],
            "dependencies": [],
            "handoff_points": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "coordination_mode": _safe_text(value.get("coordination_mode")),
        "role_sequence": _bounded_roles(
            value.get("role_sequence"), MAX_ROLES
        ),
        "dependencies": _bounded_pairs(
            value.get("dependencies"), DEPENDENCY_KEYS, MAX_DEPENDENCIES
        ),
        "handoff_points": _bounded_pairs(
            value.get("handoff_points"), HANDOFF_KEYS, MAX_HANDOFFS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentCoordinationPlan(BaseModel):
    """Deterministic conceptual role coordination (R35.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_COORDINATION_RULE_VERSION
    coordination_mode: str
    role_sequence: list[str] = Field(default_factory=list)
    dependencies: list[dict] = Field(default_factory=list)
    handoff_points: list[dict] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_COORDINATION_RULE_VERSION

    @field_validator("coordination_mode")
    @classmethod
    def _valid_mode(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in COORDINATION_MODES:
            raise ValueError(f"invalid coordination_mode: {value!r}")
        return text

    @field_validator("role_sequence")
    @classmethod
    def _valid_roles(cls, value: list) -> list[str]:
        return _require_roles(value, MAX_ROLES)

    @field_validator("dependencies")
    @classmethod
    def _valid_dependencies(cls, value: list) -> list[dict]:
        return _require_pairs(value, DEPENDENCY_KEYS, MAX_DEPENDENCIES)

    @field_validator("handoff_points")
    @classmethod
    def _valid_handoffs(cls, value: list) -> list[dict]:
        return _require_pairs(value, HANDOFF_KEYS, MAX_HANDOFFS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("agent coordination plans are research-only")
        return True


def agent_coordination_plan_projection(
    value: AgentCoordinationPlan,
) -> dict:
    """Serialize an agent coordination plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_COORDINATION_RULE_VERSION",
    "RULE_VERSION",
    "COORDINATION_MODES",
    "DEPENDENCY_KEYS",
    "HANDOFF_KEYS",
    "MODE_SEQUENTIAL",
    "MODE_REVIEW_GATE",
    "MODE_STOPPED",
    "MODE_UNKNOWN",
    "MAX_ROLES",
    "MAX_DEPENDENCIES",
    "MAX_HANDOFFS",
    "MAX_VALUE_LEN",
    "AgentCoordinationPlan",
    "sanitize_agent_coordination_plan",
    "agent_coordination_plan_projection",
]
