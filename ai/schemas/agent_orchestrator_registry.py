"""Agent orchestrator registry schema (Stage R52.1).

An :class:`AgentOrchestratorRegistryPlan` is the closed, static registry of
orchestration-supported security specialist categories. It answers the
orchestration question:

    "Which existing specialist categories may the orchestrator coordinate?"

Hard boundaries encoded here:

- Orchestration/model only: the registry is static data. No plugin system, no
  dynamic discovery, no dynamic imports, no runtime, no execution, no network,
  no LLM and no target interaction.
- Canonical categories only: every entry reuses the R38.1 canonical category
  vocabulary and the R38.2 allowed-capability vocabulary. R38 is not modified
  and no new canonical category is invented.
- The registry declares no executable capability. Only the analysis/planning
  capabilities the specialist already possesses are recorded.
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
    AGENT_ID_RE,
    CATEGORY_CVE_RESEARCH,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_RECON,
    CATEGORY_SQLI,
    CATEGORY_SSRF,
    CATEGORY_XSS,
)

AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION = "r52-1"
RULE_VERSION = AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

#: Canonical deterministic orchestration order. Every entry is an existing
#: R38.1 canonical category; R52 adds no category.
CANONICAL_SPECIALIST_ORDER: tuple[str, ...] = (
    CATEGORY_XSS,
    CATEGORY_SSRF,
    CATEGORY_SQLI,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_RECON,
    CATEGORY_CVE_RESEARCH,
)

SPECIALIST_CATEGORIES: tuple[str, ...] = CANONICAL_SPECIALIST_ORDER

REGISTRY_VALID = "VALID"
REGISTRY_PARTIAL = "PARTIAL"
REGISTRY_UNKNOWN = "UNKNOWN"

REGISTRY_STATES: tuple[str, ...] = (
    REGISTRY_VALID,
    REGISTRY_PARTIAL,
    REGISTRY_UNKNOWN,
)

REGISTRY_ENTRY_KEYS: tuple[str, ...] = (
    "category",
    "specialist_name",
    "agent_id",
    "capabilities",
    "supported_contexts",
    "priority",
    "enabled",
)

ORCHESTRATION_STAGES: tuple[str, ...] = (
    "SELECTION",
    "INVOCATION",
    "EVALUATION",
    "COLLABORATION",
    "FEEDBACK",
    "ADVISORY",
)

PRIORITY_MIN = 1
PRIORITY_MAX = 100

MAX_ENTRIES = len(CANONICAL_SPECIALIST_ORDER)
MAX_CAPABILITIES = 6
MAX_SUPPORTED_CONTEXTS = 64
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_CONTEXT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,60}$")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_capabilities(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if (
            text in ALLOWED_CAPABILITIES
            and text not in out
            and text not in PROHIBITED_CAPABILITIES
        ):
            out.append(text)
        if len(out) >= MAX_CAPABILITIES:
            break
    return out


def _bounded_contexts(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if _CONTEXT_KEY_RE.match(text) and text not in out:
            out.append(text)
        if len(out) >= MAX_SUPPORTED_CONTEXTS:
            break
    return out


def _bounded_priority(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return PRIORITY_MAX
    return max(PRIORITY_MIN, min(PRIORITY_MAX, value))


def sanitize_registry_entry(value: object) -> dict:
    """Project one registry entry onto fixed bounded closed fields."""

    if not isinstance(value, dict):
        return {
            "category": "",
            "specialist_name": "",
            "agent_id": "",
            "capabilities": [],
            "supported_contexts": [],
            "priority": PRIORITY_MAX,
            "enabled": False,
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in SPECIALIST_CATEGORIES:
        category = ""
    agent_id = _safe_text(value.get("agent_id"))
    if not AGENT_ID_RE.match(agent_id):
        agent_id = ""
    return {
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": agent_id,
        "capabilities": _bounded_capabilities(value.get("capabilities")),
        "supported_contexts": _bounded_contexts(
            value.get("supported_contexts")
        ),
        "priority": _bounded_priority(value.get("priority")),
        "enabled": bool(value.get("enabled")) is True,
    }


def sanitize_agent_orchestrator_registry_plan(value: object) -> dict:
    """Project an R52.1 registry plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "entries": [],
            "registry_state": "",
            "research_only": True,
        }
    entries: list[dict] = []
    for item in value.get("entries") or ():
        entry = sanitize_registry_entry(item)
        if entry["category"] and entry["specialist_name"]:
            if entry not in entries:
                entries.append(entry)
        if len(entries) >= MAX_ENTRIES:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "entries": entries,
        "registry_state": _safe_text(value.get("registry_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentOrchestratorRegistryPlan(BaseModel):
    """Closed static orchestrator specialist registry (R52.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION
    entries: list[dict] = Field(default_factory=list)
    registry_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION

    @field_validator("entries")
    @classmethod
    def _valid_entries(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError(f"malformed registry entry: {item!r}")
            entry = sanitize_registry_entry(item)
            if not entry["category"]:
                raise ValueError(f"invalid registry category: {item!r}")
            if not entry["specialist_name"]:
                raise ValueError(f"invalid specialist name: {item!r}")
            if entry not in out:
                out.append(entry)
            if len(out) >= MAX_ENTRIES:
                break
        return out

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
            raise ValueError("orchestrator registries are research-only")
        return True


def agent_orchestrator_registry_plan_projection(
    value: AgentOrchestratorRegistryPlan,
) -> dict:
    """Serialize an orchestrator registry to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION",
    "RULE_VERSION",
    "CANONICAL_SPECIALIST_ORDER",
    "SPECIALIST_CATEGORIES",
    "REGISTRY_STATES",
    "REGISTRY_ENTRY_KEYS",
    "REGISTRY_VALID",
    "REGISTRY_PARTIAL",
    "REGISTRY_UNKNOWN",
    "ORCHESTRATION_STAGES",
    "PRIORITY_MIN",
    "PRIORITY_MAX",
    "MAX_ENTRIES",
    "MAX_CAPABILITIES",
    "MAX_SUPPORTED_CONTEXTS",
    "MAX_VALUE_LEN",
    "sanitize_registry_entry",
    "sanitize_agent_orchestrator_registry_plan",
    "AgentOrchestratorRegistryPlan",
    "agent_orchestrator_registry_plan_projection",
]
