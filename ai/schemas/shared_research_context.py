"""Shared research context schema (Stage R43.2).

A :class:`SharedResearchContextPlan` is a bounded, read-only representation
of research context shared by collaborating specialist agents. It answers:

    "Which structured research context do the collaborating agents share?"

Hard boundaries encoded here:

- Collaboration only: the schema references normalized context; it never
  performs reasoning, memory, learning, strategy, orchestration,
  authorization or governance work, and never mutates another layer.
- Closed provenance source-layer vocabulary; layers are references only.
- No execution, no network, no database, no browser, no LLM, no payloads.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

SHARED_RESEARCH_CONTEXT_RULE_VERSION = "r43-2"
RULE_VERSION = SHARED_RESEARCH_CONTEXT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LAYER_REASONING = "REASONING"
LAYER_MEMORY = "MEMORY"
LAYER_LEARNING = "LEARNING"
LAYER_STRATEGY = "STRATEGY"
LAYER_ORCHESTRATION = "ORCHESTRATION"
LAYER_AUTHORIZATION = "AUTHORIZATION"
LAYER_GOVERNANCE = "GOVERNANCE"

SOURCE_LAYERS: tuple[str, ...] = (
    LAYER_REASONING,
    LAYER_MEMORY,
    LAYER_LEARNING,
    LAYER_STRATEGY,
    LAYER_ORCHESTRATION,
    LAYER_AUTHORIZATION,
    LAYER_GOVERNANCE,
)

MAX_BLOCK_KEYS = 12
MAX_LIST = 12
MAX_VALUE_LEN = 160
MAX_ASSET_REFERENCE_LEN = 120

_CONTEXT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:limit]


def _bounded_scalars(value: object, limit: int) -> list:
    out: list = []
    for item in value or ():
        if isinstance(item, bool):
            out.append(item)
        elif isinstance(item, (int, float)):
            out.append(item)
        elif isinstance(item, str):
            text = _safe_text(item)
            if text:
                out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_context_block(value: object) -> dict:
    """Project a context block onto bounded flat scalar/list keys."""

    if not isinstance(value, dict):
        return {}
    out: dict = {}
    for key in sorted(value.keys(), key=lambda item: str(item)):
        if len(out) >= MAX_BLOCK_KEYS:
            break
        name = str(key if key is not None else "")
        if not _CONTEXT_KEY_RE.match(name):
            continue
        raw = value.get(key)
        if isinstance(raw, bool):
            out[name] = raw
        elif isinstance(raw, (int, float)):
            out[name] = raw
        elif isinstance(raw, str):
            text = _safe_text(raw)
            if text:
                out[name] = text
        elif isinstance(raw, (list, tuple)):
            items = _bounded_scalars(raw, MAX_LIST)
            if items:
                out[name] = items
    return out


def _bounded_layers(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in SOURCE_LAYERS and text not in out:
            out.append(text)
    return out


def sanitize_shared_research_context(value: object) -> dict:
    """Project an R43.2 shared context onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "asset_reference": "",
            "application_context": {},
            "technology_context": {},
            "input_surface_context": {},
            "observed_behavior_context": {},
            "existing_research_context": {},
            "source_layers": [],
            "authorization_context": {},
            "governance_context": {},
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "asset_reference": _safe_text(
            value.get("asset_reference"), MAX_ASSET_REFERENCE_LEN
        ),
        "application_context": sanitize_context_block(
            value.get("application_context")
        ),
        "technology_context": sanitize_context_block(
            value.get("technology_context")
        ),
        "input_surface_context": sanitize_context_block(
            value.get("input_surface_context")
        ),
        "observed_behavior_context": sanitize_context_block(
            value.get("observed_behavior_context")
        ),
        "existing_research_context": sanitize_context_block(
            value.get("existing_research_context")
        ),
        "source_layers": _bounded_layers(value.get("source_layers")),
        "authorization_context": sanitize_context_block(
            value.get("authorization_context")
        ),
        "governance_context": sanitize_context_block(
            value.get("governance_context")
        ),
        "research_only": True,
    }


CONTEXT_BLOCK_KEYS: tuple[str, ...] = (
    "application_context",
    "technology_context",
    "input_surface_context",
    "observed_behavior_context",
    "existing_research_context",
    "authorization_context",
    "governance_context",
)

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SharedResearchContextPlan(BaseModel):
    """Bounded shared research context for collaboration (R43.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SHARED_RESEARCH_CONTEXT_RULE_VERSION
    asset_reference: str = ""
    application_context: dict = Field(default_factory=dict)
    technology_context: dict = Field(default_factory=dict)
    input_surface_context: dict = Field(default_factory=dict)
    observed_behavior_context: dict = Field(default_factory=dict)
    existing_research_context: dict = Field(default_factory=dict)
    source_layers: list[str] = Field(default_factory=list)
    authorization_context: dict = Field(default_factory=dict)
    governance_context: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SHARED_RESEARCH_CONTEXT_RULE_VERSION

    @field_validator("asset_reference")
    @classmethod
    def _bounded_asset(cls, value: object) -> str:
        return _safe_text(value, MAX_ASSET_REFERENCE_LEN)

    @field_validator(*CONTEXT_BLOCK_KEYS)
    @classmethod
    def _bounded_block(cls, value: object) -> dict:
        return sanitize_context_block(value)

    @field_validator("source_layers")
    @classmethod
    def _valid_layers(cls, value: list) -> list[str]:
        return _bounded_layers(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "shared research contexts are research-only"
            )
        return True


def shared_research_context_plan_projection(
    value: SharedResearchContextPlan,
) -> dict:
    """Serialize a shared research context to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SHARED_RESEARCH_CONTEXT_RULE_VERSION",
    "RULE_VERSION",
    "SOURCE_LAYERS",
    "LAYER_REASONING",
    "LAYER_MEMORY",
    "LAYER_LEARNING",
    "LAYER_STRATEGY",
    "LAYER_ORCHESTRATION",
    "LAYER_AUTHORIZATION",
    "LAYER_GOVERNANCE",
    "CONTEXT_BLOCK_KEYS",
    "MAX_BLOCK_KEYS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "MAX_ASSET_REFERENCE_LEN",
    "sanitize_context_block",
    "sanitize_shared_research_context",
    "SharedResearchContextPlan",
    "shared_research_context_plan_projection",
]
