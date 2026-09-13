"""Collaboration evidence schema (Stage R43.4).

Bounded merged evidence view across collaborating specialists. It answers:

    "Which evidence categories do the collaborating agents require?"

Hard boundaries encoded here:

- Evidence coordination only: requirements are merged and attributed; no
  evidence is collected. No network, no database, no browser, no payloads.
- Deduplication happens only when the normalized evidence category is
  equivalent; source agents and hypothesis attribution are always preserved.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

COLLABORATION_EVIDENCE_RULE_VERSION = "r43-4"
RULE_VERSION = COLLABORATION_EVIDENCE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

REQUIREMENT_REQUIRED = "REQUIRED"
REQUIREMENT_CONSIDERED = "CONSIDERED"
REQUIREMENT_UNKNOWN = "UNKNOWN"

REQUIREMENT_STATES: tuple[str, ...] = (
    REQUIREMENT_REQUIRED,
    REQUIREMENT_CONSIDERED,
    REQUIREMENT_UNKNOWN,
)

STATE_COMPLETE = "COMPLETE"
STATE_PARTIAL = "PARTIAL"
STATE_UNKNOWN = "UNKNOWN"

EVIDENCE_STATES: tuple[str, ...] = (
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
)

LIMITATION_NO_COLLECTION_PERFORMED = "NO_COLLECTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_DATABASE_ACCESS = "NO_DATABASE_ACCESS"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

COLLABORATION_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_DATABASE_ACCESS,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

COLLABORATION_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_DATABASE_ACCESS,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_ITEMS = 24
MAX_AGENTS = 12
MAX_REFERENCES = 24
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_tokens(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if not text or not _TOKEN_RE.match(text) or text in out:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_hypothesis_reference_brief(value: object) -> dict:
    """Project a brief hypothesis reference onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "agent_id": "",
            "hypothesis_index": 0,
            "hypothesis_type": "UNKNOWN",
        }
    index = value.get("hypothesis_index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        index = 0
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if not hypothesis_type or not _TOKEN_RE.match(hypothesis_type):
        hypothesis_type = "UNKNOWN"
    return {
        "agent_id": _safe_text(value.get("agent_id")),
        "hypothesis_index": min(63, index),
        "hypothesis_type": hypothesis_type,
    }


def sanitize_collaboration_evidence_item(value: object) -> dict:
    """Project a merged evidence item onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_category": "",
            "requirement_state": REQUIREMENT_UNKNOWN,
            "source_agents": [],
            "hypothesis_references": [],
            "source_count": 0,
        }
    source_agents: list[str] = []
    for item in value.get("source_agents") or ():
        text = _safe_text(item)
        if text and text not in source_agents:
            source_agents.append(text)
        if len(source_agents) >= MAX_AGENTS:
            break
    references: list[dict] = []
    for item in value.get("hypothesis_references") or ():
        if isinstance(item, dict):
            projected = sanitize_hypothesis_reference_brief(item)
            if projected not in references:
                references.append(projected)
        if len(references) >= MAX_REFERENCES:
            break
    source_count = value.get("source_count")
    if isinstance(source_count, bool) or not isinstance(source_count, int):
        source_count = len(source_agents)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_category": _safe_text(
            value.get("evidence_category")
        ).strip().upper(),
        "requirement_state": _closed(
            value.get("requirement_state"),
            REQUIREMENT_STATES,
            REQUIREMENT_UNKNOWN,
        ),
        "source_agents": source_agents,
        "hypothesis_references": references,
        "source_count": max(0, min(MAX_AGENTS, source_count)),
    }


def sanitize_collaboration_evidence_plan(value: object) -> dict:
    """Project a collaboration evidence plan onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_items": [],
            "evidence_state": STATE_UNKNOWN,
            "confidence": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    items: list[dict] = []
    for item in value.get("evidence_items") or ():
        if isinstance(item, dict):
            projected = sanitize_collaboration_evidence_item(item)
            if projected["evidence_category"]:
                items.append(projected)
        if len(items) >= MAX_ITEMS:
            break
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_items": items,
        "evidence_state": _closed(
            value.get("evidence_state"), EVIDENCE_STATES, STATE_UNKNOWN
        ),
        "confidence": confidence,
        "limitations": [
            code
            for code in _bounded_tokens(value.get("limitations"), 8)
            if code in COLLABORATION_EVIDENCE_LIMITATIONS
        ],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CollaborationEvidenceItemPlan(BaseModel):
    """Merged, attributed evidence requirement (R43.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = COLLABORATION_EVIDENCE_RULE_VERSION
    evidence_category: str
    requirement_state: str = REQUIREMENT_REQUIRED
    source_agents: list[str] = Field(default_factory=list)
    hypothesis_references: list[dict] = Field(default_factory=list)
    source_count: int = 0

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return COLLABORATION_EVIDENCE_RULE_VERSION

    @field_validator("evidence_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if not text or not _TOKEN_RE.match(text):
            raise ValueError(f"invalid evidence_category: {value!r}")
        return text

    @field_validator("requirement_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in REQUIREMENT_STATES:
            raise ValueError(f"invalid requirement_state: {value!r}")
        return text

    @field_validator("source_agents")
    @classmethod
    def _valid_agents(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item)
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_AGENTS:
                break
        return out

    @field_validator("hypothesis_references")
    @classmethod
    def _valid_references(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                projected = sanitize_hypothesis_reference_brief(item)
                if projected not in out:
                    out.append(projected)
            if len(out) >= MAX_REFERENCES:
                break
        return out

    @field_validator("source_count")
    @classmethod
    def _valid_count(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid source_count: {value!r}")
        if value < 0 or value > MAX_AGENTS:
            raise ValueError(f"source_count out of range: {value!r}")
        return value


class CollaborationEvidencePlan(BaseModel):
    """Bounded merged evidence plan for collaboration (R43.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = COLLABORATION_EVIDENCE_RULE_VERSION
    evidence_items: list[dict] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return COLLABORATION_EVIDENCE_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                projected = sanitize_collaboration_evidence_item(item)
                if projected["evidence_category"]:
                    out.append(projected)
            if len(out) >= MAX_ITEMS:
                break
        return out

    @field_validator("evidence_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STATES:
            raise ValueError(f"invalid evidence_state: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return [
            code
            for code in _bounded_tokens(value, MAX_LIMITATIONS)
            if code in COLLABORATION_EVIDENCE_LIMITATIONS
        ]

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "collaboration evidence plans are research-only"
            )
        return True


def collaboration_evidence_item_plan_projection(
    value: CollaborationEvidenceItemPlan,
) -> dict:
    """Serialize a merged evidence item to a deterministic dict."""

    return value.model_dump(mode="json")


def collaboration_evidence_plan_projection(
    value: CollaborationEvidencePlan,
) -> dict:
    """Serialize a collaboration evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "COLLABORATION_EVIDENCE_RULE_VERSION",
    "RULE_VERSION",
    "REQUIREMENT_STATES",
    "REQUIREMENT_REQUIRED",
    "REQUIREMENT_CONSIDERED",
    "REQUIREMENT_UNKNOWN",
    "EVIDENCE_STATES",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "COLLABORATION_EVIDENCE_LIMITATIONS",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_DATABASE_ACCESS",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "MAX_ITEMS",
    "MAX_AGENTS",
    "MAX_REFERENCES",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_hypothesis_reference_brief",
    "sanitize_collaboration_evidence_item",
    "sanitize_collaboration_evidence_plan",
    "CollaborationEvidenceItemPlan",
    "CollaborationEvidencePlan",
    "collaboration_evidence_item_plan_projection",
    "collaboration_evidence_plan_projection",
]
