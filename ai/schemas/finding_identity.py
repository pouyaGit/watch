"""Finding identity schema (Stage R53.1).

A :class:`FindingIdentityPlan` defines the stable, deterministic identity of a
research finding candidate produced by R53. It answers the finding question:

    "Which research finding candidate is this, and where did it originate?"

Hard boundaries encoded here:

- Research finding candidate only: identity is descriptive metadata. No
  execution, no network, no target interaction, no vulnerability
  confirmation is represented.
- Canonical categories only: the category reuses the existing R38.1
  specialist vocabulary. No new canonical category is invented and UNKNOWN
  is never a finding category.
- Deterministic: ``finding_id`` is a content token derived from the
  originating structured result; no timestamps, UUIDs, pids or randomness.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    AGENT_ID_RE,
    CATEGORY_UNKNOWN,
)

FINDING_IDENTITY_RULE_VERSION = "r53-1"
RULE_VERSION = FINDING_IDENTITY_RULE_VERSION

FINDING_ID_PREFIX = "fnd-"
FINDING_ID_RE = re.compile(r"^fnd-[0-9a-f]{16}$")

MAX_VALUE_LEN = 160
MAX_LABEL_LEN = 120

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def sanitize_finding_identity(value: object) -> dict:
    """Project a finding identity onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "finding_id": "",
            "category": "",
            "specialist_name": "",
            "agent_id": "",
            "category_label": "",
            "descriptive_label": "",
            "research_only": True,
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES or category == CATEGORY_UNKNOWN:
        category = ""
    agent_id = _safe_text(value.get("agent_id"))
    if agent_id and not AGENT_ID_RE.match(agent_id):
        agent_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "finding_id": _safe_text(value.get("finding_id")),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": agent_id,
        "category_label": _safe_text(
            value.get("category_label"), MAX_LABEL_LEN
        ),
        "descriptive_label": _safe_text(
            value.get("descriptive_label"), MAX_LABEL_LEN
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class FindingIdentityPlan(BaseModel):
    """Deterministic research finding identity (R53.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_IDENTITY_RULE_VERSION
    finding_id: str
    category: str
    specialist_name: str = ""
    agent_id: str = ""
    category_label: str = ""
    descriptive_label: str = ""
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_IDENTITY_RULE_VERSION

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES or text == CATEGORY_UNKNOWN:
            raise ValueError(f"invalid finding category: {value!r}")
        return text

    @field_validator("specialist_name")
    @classmethod
    def _bounded_name(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("agent_id")
    @classmethod
    def _bounded_agent_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not AGENT_ID_RE.match(text):
            raise ValueError(f"malformed agent_id: {value!r}")
        return text

    @field_validator("category_label", "descriptive_label")
    @classmethod
    def _bounded_label(cls, value: object) -> str:
        return _safe_text(value, MAX_LABEL_LEN)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding identities are research-only")
        return True


def finding_identity_plan_projection(value: FindingIdentityPlan) -> dict:
    """Serialize a finding identity to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_IDENTITY_RULE_VERSION",
    "RULE_VERSION",
    "FINDING_ID_PREFIX",
    "FINDING_ID_RE",
    "MAX_VALUE_LEN",
    "MAX_LABEL_LEN",
    "sanitize_finding_identity",
    "FindingIdentityPlan",
    "finding_identity_plan_projection",
]
