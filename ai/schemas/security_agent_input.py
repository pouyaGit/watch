"""Security agent input contract schema (Stage R38.3).

A :class:`SecurityAgentInputPlan` defines the common, read-only input contract
for future security specialist agents. It answers the framework question:

    "Which bounded context may an agent consume, and what is absent?"

Hard boundaries encoded here:

- Framework/model only: no execution context, no agent runtime, no tool
  execution, no network, no LLM calls, no persistence.
- Read-only inputs: blocks are projected onto fixed bounded key sets and
  never mutated.
- No unrestricted assumption: a missing critical authorization context stays
  an empty (unknown) block; nothing is inferred or defaulted to permissive.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.security_agent_identity import (
    sanitize_security_agent_identity_plan,
)

SECURITY_AGENT_INPUT_RULE_VERSION = "r38-3"
RULE_VERSION = SECURITY_AGENT_INPUT_RULE_VERSION

MAX_CONTEXT_KEYS = 24
MAX_CONTEXT_LIST = 16
MAX_VALUE_LEN = 160

_CONTEXT_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:MAX_VALUE_LEN]


def sanitize_context_block(value: object) -> dict:
    """Project a context block onto a bounded, redacted, flat key set.

    Only lowercase token keys and scalar/list-of-string values survive;
    everything else (nested objects, mixed lists, secret-like values) is
    dropped or redacted. A missing or malformed block stays empty.
    """

    if not isinstance(value, dict):
        return {}
    out: dict = {}
    for key in sorted(value.keys(), key=lambda item: str(item)):
        if len(out) >= MAX_CONTEXT_KEYS:
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
            items: list[str] = []
            for item in list(raw)[:MAX_CONTEXT_LIST]:
                if not isinstance(item, (str, int, float, bool)):
                    continue
                text = _safe_text(item)
                if text and text not in items:
                    items.append(text)
            out[name] = items
    return out


def sanitize_security_agent_input_plan(value: object) -> dict:
    """Project an R38.3 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_identity": {},
            "research_context": {},
            "memory_context": {},
            "strategy_context": {},
            "orchestration_context": {},
            "authorization_context": {},
            "governance_context": {},
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_identity": sanitize_security_agent_identity_plan(
            value.get("agent_identity")
        ),
        "research_context": sanitize_context_block(
            value.get("research_context")
        ),
        "memory_context": sanitize_context_block(
            value.get("memory_context")
        ),
        "strategy_context": sanitize_context_block(
            value.get("strategy_context")
        ),
        "orchestration_context": sanitize_context_block(
            value.get("orchestration_context")
        ),
        "authorization_context": sanitize_context_block(
            value.get("authorization_context")
        ),
        "governance_context": sanitize_context_block(
            value.get("governance_context")
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentInputPlan(BaseModel):
    """Read-only bounded agent input contract (R38.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_INPUT_RULE_VERSION
    agent_identity: dict = Field(default_factory=dict)
    research_context: dict = Field(default_factory=dict)
    memory_context: dict = Field(default_factory=dict)
    strategy_context: dict = Field(default_factory=dict)
    orchestration_context: dict = Field(default_factory=dict)
    authorization_context: dict = Field(default_factory=dict)
    governance_context: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_INPUT_RULE_VERSION

    @field_validator("agent_identity")
    @classmethod
    def _bounded_identity(cls, value: object) -> dict:
        return sanitize_security_agent_identity_plan(value)

    @field_validator(
        "research_context", "memory_context", "strategy_context",
        "orchestration_context", "authorization_context",
        "governance_context",
    )
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_context_block(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("security agent inputs are research-only")
        return True


def security_agent_input_plan_projection(
    value: SecurityAgentInputPlan,
) -> dict:
    """Serialize an agent input contract to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_INPUT_RULE_VERSION",
    "RULE_VERSION",
    "MAX_CONTEXT_KEYS",
    "MAX_CONTEXT_LIST",
    "MAX_VALUE_LEN",
    "sanitize_context_block",
    "sanitize_security_agent_input_plan",
    "SecurityAgentInputPlan",
    "security_agent_input_plan_projection",
]
