"""XSS agent identity schema (Stage R39.1).

An :class:`XSSAgentIdentityPlan` defines WHO the XSS specialist research agent
is. It conforms to the R38 Security Agent Framework identity contract:

- category is fixed to ``XSS`` (an R38 closed category),
- maturity uses the R38 maturity vocabulary,
- ``agent_id`` uses the R38 content-token format.

Hard boundaries encoded here:

- Research intelligence only: no HTTP, payload execution, browser or
  JavaScript execution, DOM crawling, fuzzing, exploitation, auth bypass,
  subprocess, shell, external API, LLM call, persistence, worker or scheduler
  is represented or created.
- Supported contexts are a closed set; unknown values stay ``UNKNOWN``.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.security_agent_identity import AGENT_ID_RE

XSS_AGENT_IDENTITY_RULE_VERSION = "r39-1"
RULE_VERSION = XSS_AGENT_IDENTITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

XSS_CATEGORY = "XSS"

MATURITY_EXPERIMENTAL = "EXPERIMENTAL"
MATURITY_RESEARCH = "RESEARCH"
MATURITY_STABLE = "STABLE"
MATURITY_UNKNOWN = "UNKNOWN"

XSS_AGENT_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
    MATURITY_UNKNOWN,
)

# Known (declarable) maturities exclude the UNKNOWN degrade value.
XSS_KNOWN_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
)

CONTEXT_REFLECTED = "REFLECTED"
CONTEXT_STORED = "STORED"
CONTEXT_DOM = "DOM"
CONTEXT_UNKNOWN = "UNKNOWN"

XSS_SUPPORTED_CONTEXTS: tuple[str, ...] = (
    CONTEXT_REFLECTED,
    CONTEXT_STORED,
    CONTEXT_DOM,
    CONTEXT_UNKNOWN,
)

LIMITATION_NO_EXECUTION_CAPABILITY = "NO_EXECUTION_CAPABILITY"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"

XSS_IDENTITY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_CAPABILITY,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_CONTEXT_UNKNOWN,
)

MAX_CONTEXTS = 4
MAX_LIMITATIONS = 4
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


def sanitize_xss_agent_identity_plan(value: object) -> dict:
    """Project an R39.1 identity onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_name": "",
            "category": XSS_CATEGORY,
            "version": "",
            "maturity": MATURITY_UNKNOWN,
            "supported_contexts": [],
            "limitations": [],
            "research_only": True,
        }
    agent_id = _safe_text(value.get("agent_id"))
    if not AGENT_ID_RE.match(agent_id):
        agent_id = ""
    maturity = _safe_text(value.get("maturity")).strip().upper()
    if maturity not in XSS_AGENT_MATURITIES:
        maturity = MATURITY_UNKNOWN
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": agent_id,
        "agent_name": _safe_text(value.get("agent_name")),
        "category": XSS_CATEGORY,
        "version": _safe_text(value.get("version")),
        "maturity": maturity,
        "supported_contexts": _bounded_codes(
            value.get("supported_contexts"),
            XSS_SUPPORTED_CONTEXTS,
            MAX_CONTEXTS,
        ),
        "limitations": _bounded_codes(
            value.get("limitations"),
            XSS_IDENTITY_LIMITATIONS,
            MAX_LIMITATIONS,
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class XSSAgentIdentityPlan(BaseModel):
    """Deterministic XSS specialist agent identity (R39.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = XSS_AGENT_IDENTITY_RULE_VERSION
    agent_id: str
    agent_name: str
    category: str = XSS_CATEGORY
    version: str = "UNKNOWN"
    maturity: str = MATURITY_UNKNOWN
    supported_contexts: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return XSS_AGENT_IDENTITY_RULE_VERSION

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
        if text != XSS_CATEGORY:
            raise ValueError(
                f"xss agent category is fixed to {XSS_CATEGORY}: {value!r}"
            )
        return XSS_CATEGORY

    @field_validator("maturity")
    @classmethod
    def _valid_maturity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in XSS_AGENT_MATURITIES:
            raise ValueError(f"invalid maturity: {value!r}")
        return text

    @field_validator("supported_contexts")
    @classmethod
    def _valid_contexts(cls, value: list) -> list[str]:
        return _require_codes(value, XSS_SUPPORTED_CONTEXTS, MAX_CONTEXTS)

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, XSS_IDENTITY_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("xss agent identities are research-only")
        return True


def xss_agent_identity_plan_projection(
    value: XSSAgentIdentityPlan,
) -> dict:
    """Serialize an XSS agent identity to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "XSS_AGENT_IDENTITY_RULE_VERSION",
    "RULE_VERSION",
    "XSS_CATEGORY",
    "MATURITY_EXPERIMENTAL",
    "MATURITY_RESEARCH",
    "MATURITY_STABLE",
    "MATURITY_UNKNOWN",
    "XSS_AGENT_MATURITIES",
    "XSS_KNOWN_MATURITIES",
    "CONTEXT_REFLECTED",
    "CONTEXT_STORED",
    "CONTEXT_DOM",
    "CONTEXT_UNKNOWN",
    "XSS_SUPPORTED_CONTEXTS",
    "LIMITATION_NO_EXECUTION_CAPABILITY",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_CONTEXT_UNKNOWN",
    "XSS_IDENTITY_LIMITATIONS",
    "MAX_CONTEXTS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_xss_agent_identity_plan",
    "XSSAgentIdentityPlan",
    "xss_agent_identity_plan_projection",
]
