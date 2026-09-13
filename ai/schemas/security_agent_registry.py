"""Security agent registry schema (Stage R38.6).

A :class:`SecurityAgentRegistryPlan` is a static conceptual registry of the
security specialist categories available in the framework. It answers the
framework question:

    "Which conceptual security specialists exist in the framework?"

Hard boundaries encoded here:

- Framework/model only: the registry is a static data model. No plugin
  system, no dynamic discovery, no dynamic imports, no runtime, no execution.
- Closed categories only: every entry uses the R38.1 category/maturity
  vocabularies and the R38.2 capability vocabularies.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    AGENT_ID_RE,
    AGENT_MATURITIES,
)

SECURITY_AGENT_REGISTRY_RULE_VERSION = "r38-6"
RULE_VERSION = SECURITY_AGENT_REGISTRY_RULE_VERSION

REGISTRY_VALID = "VALID"
REGISTRY_PARTIAL = "PARTIAL"
REGISTRY_UNKNOWN = "UNKNOWN"

REGISTRY_STATES: tuple[str, ...] = (
    REGISTRY_VALID,
    REGISTRY_PARTIAL,
    REGISTRY_UNKNOWN,
)

REGISTRY_ENTRY_KEYS: tuple[str, ...] = (
    "agent_id",
    "category",
    "maturity",
    "capabilities",
)

MAX_ENTRIES = 16
MAX_CAPABILITIES = 6
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def sanitize_registry_entry(value: object) -> dict:
    """Project one registry entry onto fixed bounded closed fields."""

    if not isinstance(value, dict):
        return {
            "agent_id": "",
            "category": "",
            "maturity": "",
            "capabilities": [],
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    maturity = _safe_text(value.get("maturity")).strip().upper()
    if maturity not in AGENT_MATURITIES:
        maturity = "UNKNOWN"
    agent_id = _safe_text(value.get("agent_id"))
    if not AGENT_ID_RE.match(agent_id):
        agent_id = ""
    capabilities: list[str] = []
    for item in value.get("capabilities") or ():
        text = _safe_text(item)
        if (
            text in ALLOWED_CAPABILITIES
            and text not in capabilities
            and text not in PROHIBITED_CAPABILITIES
        ):
            capabilities.append(text)
        if len(capabilities) >= MAX_CAPABILITIES:
            break
    return {
        "agent_id": agent_id,
        "category": category,
        "maturity": maturity,
        "capabilities": capabilities,
    }


def _bounded_entries(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        entry = sanitize_registry_entry(item)
        if not entry["agent_id"] or not entry["category"]:
            continue
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def _require_entries(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            raise ValueError(f"malformed registry entry: {item!r}")
        entry = sanitize_registry_entry(item)
        if not entry["agent_id"]:
            raise ValueError(f"invalid agent_id: {item!r}")
        if not entry["category"]:
            raise ValueError(f"invalid category: {item!r}")
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def sanitize_security_agent_registry_plan(value: object) -> dict:
    """Project an R38.6 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "registered_agents": [],
            "registry_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "registered_agents": _bounded_entries(
            value.get("registered_agents"), MAX_ENTRIES
        ),
        "registry_state": _safe_text(value.get("registry_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentRegistryPlan(BaseModel):
    """Static conceptual security agent registry (R38.6)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_REGISTRY_RULE_VERSION
    registered_agents: list[dict] = Field(default_factory=list)
    registry_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_REGISTRY_RULE_VERSION

    @field_validator("registered_agents")
    @classmethod
    def _valid_entries(cls, value: list) -> list[dict]:
        return _require_entries(value, MAX_ENTRIES)

    @field_validator("registry_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REGISTRY_STATES:
            raise ValueError(f"invalid registry_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("security agent registries are research-only")
        return True


def security_agent_registry_plan_projection(
    value: SecurityAgentRegistryPlan,
) -> dict:
    """Serialize a registry plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_REGISTRY_RULE_VERSION",
    "RULE_VERSION",
    "REGISTRY_STATES",
    "REGISTRY_ENTRY_KEYS",
    "REGISTRY_VALID",
    "REGISTRY_PARTIAL",
    "REGISTRY_UNKNOWN",
    "MAX_ENTRIES",
    "MAX_CAPABILITIES",
    "MAX_VALUE_LEN",
    "sanitize_registry_entry",
    "sanitize_security_agent_registry_plan",
    "SecurityAgentRegistryPlan",
    "security_agent_registry_plan_projection",
]
