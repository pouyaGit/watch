"""SSRF agent identity schema (Stage R40.1).

An :class:`SSRFAgentIdentityPlan` defines WHO the SSRF specialist research
agent is. It conforms to the R38 Security Agent Framework identity contract:

- category is fixed to ``SSRF`` (an R38 closed category),
- maturity uses the R38 maturity vocabulary,
- ``agent_id`` uses the R38 content-token format,
- ``supported_capabilities`` are restricted to the R38 analysis-only
  capability vocabulary (prohibited execution capabilities can never be
  declared),
- ``lifecycle_state`` is restricted to the identity lifecycle
  (``CREATED``/``PLANNED``); no runtime state is ever represented.

Hard boundaries encoded here:

- Research intelligence only: no network request, DNS resolution, payload
  execution, metadata access, subprocess, socket, browser, external API,
  LLM call, persistence, worker or scheduler is represented or created.
- The SSRF-specific scope is the bounded set of URL-handling contexts.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no DNS, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import AGENT_ID_RE
from ai.schemas.security_agent_lifecycle import (
    STATE_CREATED,
    STATE_PLANNED,
)
from ai.schemas.ssrf_context_analysis import URL_HANDLING_VALUES

SSRF_AGENT_IDENTITY_RULE_VERSION = "r40-1"
RULE_VERSION = SSRF_AGENT_IDENTITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

SSRF_CATEGORY = "SSRF"

MATURITY_EXPERIMENTAL = "EXPERIMENTAL"
MATURITY_RESEARCH = "RESEARCH"
MATURITY_STABLE = "STABLE"
MATURITY_UNKNOWN = "UNKNOWN"

SSRF_AGENT_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
    MATURITY_UNKNOWN,
)

SSRF_KNOWN_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
)

# SSRF-specific scope: which URL-handling contexts the agent covers.
SSRF_SUPPORTED_CONTEXTS: tuple[str, ...] = URL_HANDLING_VALUES

SSRF_SUPPORTED_CAPABILITIES: tuple[str, ...] = ALLOWED_CAPABILITIES

# Identity lifecycle only; runtime states are never entered.
SSRF_IDENTITY_LIFECYCLE_STATES: tuple[str, ...] = (
    STATE_CREATED,
    STATE_PLANNED,
)

LIFECYCLE_CREATED = STATE_CREATED
LIFECYCLE_PLANNED = STATE_PLANNED

LIMITATION_NO_EXECUTION_CAPABILITY = "NO_EXECUTION_CAPABILITY"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_DNS_RESOLUTION = "NO_DNS_RESOLUTION"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_SCOPE_UNKNOWN = "SCOPE_UNKNOWN"

SSRF_IDENTITY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_CAPABILITY,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_DNS_RESOLUTION,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_SCOPE_UNKNOWN,
)

MAX_CONTEXTS = 7
MAX_CAPABILITIES = 6
MAX_LIMITATIONS = 6
MAX_VALUE_LEN = 160

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


def sanitize_ssrf_agent_identity_plan(value: object) -> dict:
    """Project an R40.1 identity onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_name": "",
            "category": SSRF_CATEGORY,
            "version": "",
            "maturity": MATURITY_UNKNOWN,
            "supported_contexts": [],
            "supported_capabilities": [],
            "lifecycle_state": LIFECYCLE_CREATED,
            "limitations": [],
            "research_only": True,
        }
    agent_id = _safe_text(value.get("agent_id"))
    if not AGENT_ID_RE.match(agent_id):
        agent_id = ""
    maturity = _safe_text(value.get("maturity")).strip().upper()
    if maturity not in SSRF_AGENT_MATURITIES:
        maturity = MATURITY_UNKNOWN
    lifecycle_state = _safe_text(
        value.get("lifecycle_state")
    ).strip().upper()
    if lifecycle_state not in SSRF_IDENTITY_LIFECYCLE_STATES:
        lifecycle_state = LIFECYCLE_CREATED
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": agent_id,
        "agent_name": _safe_text(value.get("agent_name")),
        "category": SSRF_CATEGORY,
        "version": _safe_text(value.get("version")),
        "maturity": maturity,
        "supported_contexts": _bounded_codes(
            value.get("supported_contexts"),
            SSRF_SUPPORTED_CONTEXTS,
            MAX_CONTEXTS,
        ),
        "supported_capabilities": _bounded_codes(
            value.get("supported_capabilities"),
            SSRF_SUPPORTED_CAPABILITIES,
            MAX_CAPABILITIES,
        ),
        "lifecycle_state": lifecycle_state,
        "limitations": _bounded_codes(
            value.get("limitations"),
            SSRF_IDENTITY_LIMITATIONS,
            MAX_LIMITATIONS,
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SSRFAgentIdentityPlan(BaseModel):
    """Deterministic SSRF specialist agent identity (R40.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SSRF_AGENT_IDENTITY_RULE_VERSION
    agent_id: str
    agent_name: str
    category: str = SSRF_CATEGORY
    version: str = "UNKNOWN"
    maturity: str = MATURITY_UNKNOWN
    supported_contexts: list[str] = Field(default_factory=list)
    supported_capabilities: list[str] = Field(default_factory=list)
    lifecycle_state: str = LIFECYCLE_PLANNED
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SSRF_AGENT_IDENTITY_RULE_VERSION

    @field_validator("agent_id")
    @classmethod
    def _valid_agent_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not AGENT_ID_RE.match(text):
            raise ValueError(f"malformed agent_id: {value!r}")
        return text

    @field_validator("agent_name", "version")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("category")
    @classmethod
    def _fixed_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text != SSRF_CATEGORY:
            raise ValueError(
                f"ssrf agent category is fixed to {SSRF_CATEGORY}: "
                f"{value!r}"
            )
        return SSRF_CATEGORY

    @field_validator("maturity")
    @classmethod
    def _valid_maturity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SSRF_AGENT_MATURITIES:
            raise ValueError(f"invalid maturity: {value!r}")
        return text

    @field_validator("supported_contexts")
    @classmethod
    def _valid_contexts(cls, value: list) -> list[str]:
        return _require_codes(
            value, SSRF_SUPPORTED_CONTEXTS, MAX_CONTEXTS
        )

    @field_validator("supported_capabilities")
    @classmethod
    def _valid_capabilities(cls, value: list) -> list[str]:
        codes = _require_codes(
            value, SSRF_SUPPORTED_CAPABILITIES, MAX_CAPABILITIES
        )
        overlap = set(codes) & set(PROHIBITED_CAPABILITIES)
        if overlap:
            raise ValueError(
                f"prohibited capabilities cannot be declared: {overlap!r}"
            )
        return codes

    @field_validator("lifecycle_state")
    @classmethod
    def _valid_lifecycle(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SSRF_IDENTITY_LIFECYCLE_STATES:
            raise ValueError(
                f"invalid identity lifecycle_state: {value!r}"
            )
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, SSRF_IDENTITY_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("ssrf agent identities are research-only")
        return True


def ssrf_agent_identity_plan_projection(
    value: SSRFAgentIdentityPlan,
) -> dict:
    """Serialize an SSRF agent identity to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SSRF_AGENT_IDENTITY_RULE_VERSION",
    "RULE_VERSION",
    "SSRF_CATEGORY",
    "MATURITY_EXPERIMENTAL",
    "MATURITY_RESEARCH",
    "MATURITY_STABLE",
    "MATURITY_UNKNOWN",
    "SSRF_AGENT_MATURITIES",
    "SSRF_KNOWN_MATURITIES",
    "SSRF_SUPPORTED_CONTEXTS",
    "SSRF_SUPPORTED_CAPABILITIES",
    "SSRF_IDENTITY_LIFECYCLE_STATES",
    "LIFECYCLE_CREATED",
    "LIFECYCLE_PLANNED",
    "LIMITATION_NO_EXECUTION_CAPABILITY",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_DNS_RESOLUTION",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_SCOPE_UNKNOWN",
    "SSRF_IDENTITY_LIMITATIONS",
    "MAX_CONTEXTS",
    "MAX_CAPABILITIES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_ssrf_agent_identity_plan",
    "SSRFAgentIdentityPlan",
    "ssrf_agent_identity_plan_projection",
]
