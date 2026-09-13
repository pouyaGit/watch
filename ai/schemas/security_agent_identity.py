"""Security agent identity schema (Stage R38.1).

A :class:`SecurityAgentIdentityPlan` defines WHO a future security specialist
agent is. It answers the framework question:

    "Which category of security specialist is this agent?"

Hard boundaries encoded here:

- Framework/model only: no agent runtime, execution, scanning, tooling, LLM
  call, plugin loading, dynamic import or persistence is represented or
  created.
- Closed vocabularies: categories and maturity levels are closed sets;
  unknown categories always remain ``UNKNOWN``.
- No runtime metadata and no arbitrary execution capability: only bounded
  identity fields and a deterministic content id exist.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

SECURITY_AGENT_IDENTITY_RULE_VERSION = "r38-1"
RULE_VERSION = SECURITY_AGENT_IDENTITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

CATEGORY_XSS = "XSS"
CATEGORY_SSRF = "SSRF"
CATEGORY_SQLI = "SQLI"
CATEGORY_IDOR = "IDOR"
CATEGORY_JWT = "JWT"
CATEGORY_OAUTH = "OAUTH"
CATEGORY_CVE_RESEARCH = "CVE_RESEARCH"
CATEGORY_RECON = "RECON"
CATEGORY_UNKNOWN = "UNKNOWN"

AGENT_CATEGORIES: tuple[str, ...] = (
    CATEGORY_XSS,
    CATEGORY_SSRF,
    CATEGORY_SQLI,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_CVE_RESEARCH,
    CATEGORY_RECON,
    CATEGORY_UNKNOWN,
)

MATURITY_EXPERIMENTAL = "EXPERIMENTAL"
MATURITY_RESEARCH = "RESEARCH"
MATURITY_STABLE = "STABLE"
MATURITY_UNKNOWN = "UNKNOWN"

AGENT_MATURITIES: tuple[str, ...] = (
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
    MATURITY_STABLE,
    MATURITY_UNKNOWN,
)

AGENT_ID_PREFIX = "sa-"
AGENT_ID_RE = re.compile(r"^sa-[0-9a-f]{16}$")

MAX_VALUE_LEN = 160
DESCRIPTION_MAX_LEN = 320

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


def sanitize_security_agent_identity_plan(value: object) -> dict:
    """Project an R38.1 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_name": "",
            "category": "",
            "version": "",
            "maturity": "",
            "description": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": _safe_text(value.get("agent_id")),
        "agent_name": _safe_text(value.get("agent_name")),
        "category": _safe_text(value.get("category")),
        "version": _safe_text(value.get("version")),
        "maturity": _safe_text(value.get("maturity")),
        "description": _safe_text(
            value.get("description"), DESCRIPTION_MAX_LEN
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityAgentIdentityPlan(BaseModel):
    """Deterministic security agent identity (R38.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SECURITY_AGENT_IDENTITY_RULE_VERSION
    agent_id: str
    agent_name: str
    category: str
    version: str = "UNKNOWN"
    maturity: str = "UNKNOWN"
    description: str = ""
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SECURITY_AGENT_IDENTITY_RULE_VERSION

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
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid category: {value!r}")
        return text

    @field_validator("maturity")
    @classmethod
    def _valid_maturity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_MATURITIES:
            raise ValueError(f"invalid maturity: {value!r}")
        return text

    @field_validator("description")
    @classmethod
    def _bounded_description(cls, value: object) -> str:
        return _safe_text(value, DESCRIPTION_MAX_LEN)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("security agent identities are research-only")
        return True


def security_agent_identity_plan_projection(
    value: SecurityAgentIdentityPlan,
) -> dict:
    """Serialize a security agent identity to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SECURITY_AGENT_IDENTITY_RULE_VERSION",
    "RULE_VERSION",
    "AGENT_CATEGORIES",
    "AGENT_MATURITIES",
    "AGENT_ID_PREFIX",
    "AGENT_ID_RE",
    "CATEGORY_XSS",
    "CATEGORY_SSRF",
    "CATEGORY_SQLI",
    "CATEGORY_IDOR",
    "CATEGORY_JWT",
    "CATEGORY_OAUTH",
    "CATEGORY_CVE_RESEARCH",
    "CATEGORY_RECON",
    "CATEGORY_UNKNOWN",
    "MATURITY_EXPERIMENTAL",
    "MATURITY_RESEARCH",
    "MATURITY_STABLE",
    "MATURITY_UNKNOWN",
    "MAX_VALUE_LEN",
    "DESCRIPTION_MAX_LEN",
    "SecurityAgentIdentityPlan",
    "sanitize_security_agent_identity_plan",
    "security_agent_identity_plan_projection",
]
