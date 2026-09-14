"""JWT/authentication agent identity schema (Stage R47.1).

A :class:`JWTAuthenticationAgentIdentityPlan` defines WHO the JWT /
authentication specialist research agent is. It conforms to the R38 Security
Agent Framework identity contract:

- category is the canonical R38 closed category ``JWT``,
- maturity uses the R38 maturity vocabulary,
- ``agent_id`` uses the R38 content-token format,
- ``supported_capabilities`` are restricted to the R38 analysis-only
  capability vocabulary (prohibited execution capabilities can never be
  declared),
- ``lifecycle_state`` is restricted to the identity lifecycle
  (``CREATED``/``PLANNED``); no runtime state is ever represented.

Hard boundaries encoded here:

- Research intelligence only: no HTTP/HTTPS request, no DNS resolution, no
  socket, no browser, no database, no scanner, no token decoding or
  manipulation, no token forgery, no signature bypass, no authentication
  bypass, no brute force, no credential testing, no payload, no subprocess,
  no external API, no LLM call, no persistence, worker or scheduler is
  represented or created.
- The JWT/authentication-specific specialization is the bounded set of
  authentication mechanisms the agent covers.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.jwt_authentication_context_analysis import (
    AUTH_MECH_UNKNOWN,
    KNOWN_AUTHENTICATION_MECHANISMS,
)
from ai.schemas.security_agent_capability import ALLOWED_CAPABILITIES
from ai.schemas.security_agent_identity import (
    AGENT_ID_RE,
    CATEGORY_JWT,
)
from ai.schemas.security_agent_lifecycle import (
    STATE_CREATED,
    STATE_PLANNED,
)

JWT_AUTHENTICATION_AGENT_IDENTITY_RULE_VERSION = "r47-1"
RULE_VERSION = JWT_AUTHENTICATION_AGENT_IDENTITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Canonical category and research label
# ---------------------------------------------------------------------------

# Canonical R38 closed category for this specialist.
JWT_AUTHENTICATION_CATEGORY = CATEGORY_JWT

# Descriptive research label for the authentication scope. It is a label,
# not an R38 category; the canonical category above is used in contracts.
JWT_AUTHENTICATION_RESEARCH_LABEL = "JWT_AUTHENTICATION"

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

MATURITY_EXPERIMENTAL = "EXPERIMENTAL"
MATURITY_RESEARCH = "RESEARCH"
MATURITY_STABLE = "STABLE"
MATURITY_UNKNOWN = "UNKNOWN"

JWT_AUTHENTICATION_AGENT_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
    MATURITY_UNKNOWN,
)

JWT_AUTHENTICATION_KNOWN_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
)

# JWT/authentication-specific specialization: which authentication
# mechanisms the agent covers. ``UNKNOWN`` is the declarable degrade value.
JWT_AUTHENTICATION_SUPPORTED_CONTEXTS: tuple[str, ...] = (
    KNOWN_AUTHENTICATION_MECHANISMS + (AUTH_MECH_UNKNOWN,)
)

JWT_AUTHENTICATION_SUPPORTED_CAPABILITIES: tuple[str, ...] = (
    ALLOWED_CAPABILITIES
)

# Identity lifecycle only; runtime states are never entered.
JWT_AUTHENTICATION_IDENTITY_LIFECYCLE_STATES: tuple[str, ...] = (
    STATE_CREATED,
    STATE_PLANNED,
)

LIFECYCLE_CREATED = STATE_CREATED
LIFECYCLE_PLANNED = STATE_PLANNED

LIMITATION_NO_EXECUTION_CAPABILITY = "NO_EXECUTION_CAPABILITY"
LIMITATION_NO_TOKEN_MANIPULATION = "NO_TOKEN_MANIPULATION"
LIMITATION_NO_SIGNATURE_BYPASS = "NO_SIGNATURE_BYPASS"
LIMITATION_NO_AUTHENTICATION_BYPASS = "NO_AUTHENTICATION_BYPASS"
LIMITATION_NO_CREDENTIAL_TESTING = "NO_CREDENTIAL_TESTING"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_SCOPE_UNKNOWN = "SCOPE_UNKNOWN"

JWT_AUTHENTICATION_IDENTITY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_CAPABILITY,
    LIMITATION_NO_TOKEN_MANIPULATION,
    LIMITATION_NO_SIGNATURE_BYPASS,
    LIMITATION_NO_AUTHENTICATION_BYPASS,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_SCOPE_UNKNOWN,
)

MAX_CONTEXTS = 7
MAX_CAPABILITIES = 6
MAX_LIMITATIONS = 9
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


def sanitize_jwt_authentication_agent_identity_plan(value: object) -> dict:
    """Project an R47.1 identity onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_name": "",
            "category": JWT_AUTHENTICATION_CATEGORY,
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
    if maturity not in JWT_AUTHENTICATION_AGENT_MATURITIES:
        maturity = MATURITY_UNKNOWN
    lifecycle_state = _safe_text(
        value.get("lifecycle_state")
    ).strip().upper()
    if lifecycle_state not in JWT_AUTHENTICATION_IDENTITY_LIFECYCLE_STATES:
        lifecycle_state = LIFECYCLE_CREATED
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": agent_id,
        "agent_name": _safe_text(value.get("agent_name")),
        "category": JWT_AUTHENTICATION_CATEGORY,
        "version": _safe_text(value.get("version")),
        "maturity": maturity,
        "supported_contexts": _bounded_codes(
            value.get("supported_contexts"),
            JWT_AUTHENTICATION_SUPPORTED_CONTEXTS,
            MAX_CONTEXTS,
        ),
        "supported_capabilities": _bounded_codes(
            value.get("supported_capabilities"),
            JWT_AUTHENTICATION_SUPPORTED_CAPABILITIES,
            MAX_CAPABILITIES,
        ),
        "lifecycle_state": lifecycle_state,
        "limitations": _bounded_codes(
            value.get("limitations"),
            JWT_AUTHENTICATION_IDENTITY_LIMITATIONS,
            MAX_LIMITATIONS,
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class JWTAuthenticationAgentIdentityPlan(BaseModel):
    """Deterministic JWT/authentication specialist agent identity (R47.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = JWT_AUTHENTICATION_AGENT_IDENTITY_RULE_VERSION
    agent_id: str
    agent_name: str
    category: str = JWT_AUTHENTICATION_CATEGORY
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
        return JWT_AUTHENTICATION_AGENT_IDENTITY_RULE_VERSION

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
        if text != JWT_AUTHENTICATION_CATEGORY:
            raise ValueError(
                "jwt/authentication agent category is fixed to "
                f"{JWT_AUTHENTICATION_CATEGORY}: {value!r}"
            )
        return JWT_AUTHENTICATION_CATEGORY

    @field_validator("maturity")
    @classmethod
    def _valid_maturity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in JWT_AUTHENTICATION_AGENT_MATURITIES:
            raise ValueError(f"invalid maturity: {value!r}")
        return text

    @field_validator("supported_contexts")
    @classmethod
    def _valid_contexts(cls, value: list) -> list[str]:
        return _require_codes(
            value, JWT_AUTHENTICATION_SUPPORTED_CONTEXTS, MAX_CONTEXTS
        )

    @field_validator("supported_capabilities")
    @classmethod
    def _valid_capabilities(cls, value: list) -> list[str]:
        return _require_codes(
            value, JWT_AUTHENTICATION_SUPPORTED_CAPABILITIES,
            MAX_CAPABILITIES,
        )

    @field_validator("lifecycle_state")
    @classmethod
    def _valid_lifecycle(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in JWT_AUTHENTICATION_IDENTITY_LIFECYCLE_STATES:
            raise ValueError(f"invalid lifecycle_state: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, JWT_AUTHENTICATION_IDENTITY_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "jwt/authentication agent identities are research-only"
            )
        return True


def jwt_authentication_agent_identity_plan_projection(
    value: JWTAuthenticationAgentIdentityPlan,
) -> dict:
    """Serialize an R47.1 identity to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "JWT_AUTHENTICATION_AGENT_IDENTITY_RULE_VERSION",
    "RULE_VERSION",
    "JWT_AUTHENTICATION_CATEGORY",
    "JWT_AUTHENTICATION_RESEARCH_LABEL",
    "MATURITY_EXPERIMENTAL",
    "MATURITY_RESEARCH",
    "MATURITY_STABLE",
    "MATURITY_UNKNOWN",
    "JWT_AUTHENTICATION_AGENT_MATURITIES",
    "JWT_AUTHENTICATION_KNOWN_MATURITIES",
    "JWT_AUTHENTICATION_SUPPORTED_CONTEXTS",
    "JWT_AUTHENTICATION_SUPPORTED_CAPABILITIES",
    "JWT_AUTHENTICATION_IDENTITY_LIFECYCLE_STATES",
    "LIFECYCLE_CREATED",
    "LIFECYCLE_PLANNED",
    "LIMITATION_NO_EXECUTION_CAPABILITY",
    "LIMITATION_NO_TOKEN_MANIPULATION",
    "LIMITATION_NO_SIGNATURE_BYPASS",
    "LIMITATION_NO_AUTHENTICATION_BYPASS",
    "LIMITATION_NO_CREDENTIAL_TESTING",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_SCOPE_UNKNOWN",
    "JWT_AUTHENTICATION_IDENTITY_LIMITATIONS",
    "MAX_CONTEXTS",
    "MAX_CAPABILITIES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_jwt_authentication_agent_identity_plan",
    "JWTAuthenticationAgentIdentityPlan",
    "jwt_authentication_agent_identity_plan_projection",
]
