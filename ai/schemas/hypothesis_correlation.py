"""Hypothesis correlation schema (Stage R43.3).

Deterministic correlation model for hypotheses contributed by collaborating
specialist agents. It answers:

    "How do these hypotheses relate: duplicate, related, independent or
     conflicting?"

Hard boundaries encoded here:

- Collaboration only: correlation uses structured attributes (hypothesis
  type, supporting signals, evidence categories, agent category, normalized
  subject reference). No semantic/LLM similarity, no invented relations.
- Originals are never deleted: every hypothesis stays referenced with full
  attribution; duplicate groups preserve all members.
- Different vulnerability classes may be related without being duplicates.
- Specialists remain generic; no ``if category == XSS`` style logic.
- No execution, no network, no database, no LLM, no payloads.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

HYPOTHESIS_CORRELATION_RULE_VERSION = "r43-3"
RULE_VERSION = HYPOTHESIS_CORRELATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

CORRELATION_DUPLICATE = "DUPLICATE"
CORRELATION_RELATED = "RELATED"
CORRELATION_INDEPENDENT = "INDEPENDENT"
CORRELATION_CONFLICTING = "CONFLICTING"
CORRELATION_UNKNOWN = "UNKNOWN"

CORRELATION_TYPES: tuple[str, ...] = (
    CORRELATION_DUPLICATE,
    CORRELATION_RELATED,
    CORRELATION_INDEPENDENT,
    CORRELATION_CONFLICTING,
    CORRELATION_UNKNOWN,
)

CONFIDENCE_AGREE = "AGREE"
CONFIDENCE_DIVERGENT = "DIVERGENT"
CONFIDENCE_CONFLICT = "CONFLICT"
CONFIDENCE_UNKNOWN = "UNKNOWN"

CONFIDENCE_SUMMARY_STATES: tuple[str, ...] = (
    CONFIDENCE_AGREE,
    CONFIDENCE_DIVERGENT,
    CONFIDENCE_CONFLICT,
    CONFIDENCE_UNKNOWN,
)

CONFIDENCE_BANDS: dict[str, int] = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

CORRELATION_ID_PREFIX = "hg-"
CORRELATION_ID_RE = re.compile(r"^hg-[0-9a-f]{16}$")

MAX_SIGNALS = 12
MAX_LIMITATIONS = 8
MAX_REFERENCES = 32
MAX_AGENTS = 12
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


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


def sanitize_hypothesis_reference(value: object) -> dict:
    """Project a hypothesis reference onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_category": "UNKNOWN",
            "agent_rule_version": "",
            "result_rule_version": "",
            "hypothesis_index": 0,
            "hypothesis_type": "UNKNOWN",
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "limitations": [],
            "subject_reference": "",
            "fingerprint": "",
        }
    category = _safe_text(value.get("agent_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if not hypothesis_type or not _TOKEN_RE.match(hypothesis_type):
        hypothesis_type = "UNKNOWN"
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(value.get("priority")).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    index = value.get("hypothesis_index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        index = 0
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": _safe_text(value.get("agent_id")),
        "agent_category": category,
        "agent_rule_version": _safe_text(
            value.get("agent_rule_version")
        ),
        "result_rule_version": _safe_text(
            value.get("result_rule_version")
        ),
        "hypothesis_index": index,
        "hypothesis_type": hypothesis_type,
        "supporting_signals": _bounded_tokens(
            value.get("supporting_signals"), MAX_SIGNALS
        ),
        "confidence": confidence,
        "priority": priority,
        "limitations": _bounded_tokens(
            value.get("limitations"), MAX_LIMITATIONS
        ),
        "subject_reference": _safe_text(value.get("subject_reference")),
        "fingerprint": _safe_text(value.get("fingerprint")),
    }


def sanitize_confidence_summary(value: object) -> dict:
    """Project a confidence summary onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "highest_confidence": "UNKNOWN",
            "lowest_confidence": "UNKNOWN",
            "confidence_state": CONFIDENCE_UNKNOWN,
        }
    highest = _closed(
        value.get("highest_confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
    )
    lowest = _closed(
        value.get("lowest_confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
    )
    state = _closed(
        value.get("confidence_state"),
        CONFIDENCE_SUMMARY_STATES,
        CONFIDENCE_UNKNOWN,
    )
    return {
        "highest_confidence": highest,
        "lowest_confidence": lowest,
        "confidence_state": state,
    }


def sanitize_hypothesis_group(value: object) -> dict:
    """Project a hypothesis group onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "correlation_id": "",
            "correlation_type": CORRELATION_UNKNOWN,
            "hypothesis_references": [],
            "participating_agents": [],
            "shared_signals": [],
            "confidence_summary": sanitize_confidence_summary(None),
            "member_count": 0,
        }
    references: list[dict] = []
    for item in value.get("hypothesis_references") or ():
        if isinstance(item, dict):
            references.append(sanitize_hypothesis_reference(item))
        if len(references) >= MAX_REFERENCES:
            break
    agents: list[str] = []
    for item in value.get("participating_agents") or ():
        text = _safe_text(item)
        if text and text not in agents:
            agents.append(text)
        if len(agents) >= MAX_AGENTS:
            break
    member_count = value.get("member_count")
    if isinstance(member_count, bool) or not isinstance(member_count, int):
        member_count = len(references)
    member_count = max(0, min(MAX_REFERENCES, member_count))
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "correlation_type": _closed(
            value.get("correlation_type"),
            CORRELATION_TYPES,
            CORRELATION_UNKNOWN,
        ),
        "hypothesis_references": references,
        "participating_agents": agents,
        "shared_signals": _bounded_tokens(
            value.get("shared_signals"), MAX_SIGNALS
        ),
        "confidence_summary": sanitize_confidence_summary(
            value.get("confidence_summary")
        ),
        "member_count": member_count,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class HypothesisReferencePlan(BaseModel):
    """Attributed reference to one contributed hypothesis (R43.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HYPOTHESIS_CORRELATION_RULE_VERSION
    agent_id: str = ""
    agent_category: str = "UNKNOWN"
    agent_rule_version: str = ""
    result_rule_version: str = ""
    hypothesis_index: int = 0
    hypothesis_type: str = "UNKNOWN"
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    subject_reference: str = ""
    fingerprint: str = ""

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HYPOTHESIS_CORRELATION_RULE_VERSION

    @field_validator("agent_id")
    @classmethod
    def _bounded_agent(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("agent_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid agent_category: {value!r}")
        return text

    @field_validator("agent_rule_version", "result_rule_version")
    @classmethod
    def _bounded_rule_version(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("hypothesis_index")
    @classmethod
    def _valid_index(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid hypothesis_index: {value!r}")
        if value < 0 or value > 63:
            raise ValueError(f"hypothesis_index out of range: {value!r}")
        return value

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if not text or not _TOKEN_RE.match(text):
            raise ValueError(f"invalid hypothesis_type: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _bounded_tokens(value, MAX_SIGNALS)

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence/priority: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _bounded_tokens(value, MAX_LIMITATIONS)

    @field_validator("subject_reference", "fingerprint")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)


class HypothesisGroupPlan(BaseModel):
    """Deterministic correlation group (R43.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = HYPOTHESIS_CORRELATION_RULE_VERSION
    correlation_id: str = ""
    correlation_type: str = CORRELATION_UNKNOWN
    hypothesis_references: list[dict] = Field(default_factory=list)
    participating_agents: list[str] = Field(default_factory=list)
    shared_signals: list[str] = Field(default_factory=list)
    confidence_summary: dict = Field(default_factory=dict)
    member_count: int = 0

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return HYPOTHESIS_CORRELATION_RULE_VERSION

    @field_validator("correlation_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("correlation_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CORRELATION_TYPES:
            raise ValueError(f"invalid correlation_type: {value!r}")
        return text

    @field_validator("hypothesis_references")
    @classmethod
    def _valid_references(cls, value: list) -> list[dict]:
        out: list[dict] = []
        raw = value if isinstance(value, (list, tuple)) else []
        for item in raw:
            if isinstance(item, dict):
                out.append(sanitize_hypothesis_reference(item))
            if len(out) >= MAX_REFERENCES:
                break
        return out

    @field_validator("participating_agents")
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

    @field_validator("shared_signals")
    @classmethod
    def _valid_shared(cls, value: list) -> list[str]:
        return _bounded_tokens(value, MAX_SIGNALS)

    @field_validator("confidence_summary")
    @classmethod
    def _valid_summary(cls, value: object) -> dict:
        return sanitize_confidence_summary(value)

    @field_validator("member_count")
    @classmethod
    def _valid_count(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid member_count: {value!r}")
        if value < 0 or value > MAX_REFERENCES:
            raise ValueError(f"member_count out of range: {value!r}")
        return value


def hypothesis_reference_plan_projection(
    value: HypothesisReferencePlan,
) -> dict:
    """Serialize a hypothesis reference to a deterministic dict."""

    return value.model_dump(mode="json")


def hypothesis_group_plan_projection(value: HypothesisGroupPlan) -> dict:
    """Serialize a hypothesis group to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "HYPOTHESIS_CORRELATION_RULE_VERSION",
    "RULE_VERSION",
    "CORRELATION_TYPES",
    "CORRELATION_DUPLICATE",
    "CORRELATION_RELATED",
    "CORRELATION_INDEPENDENT",
    "CORRELATION_CONFLICTING",
    "CORRELATION_UNKNOWN",
    "CONFIDENCE_SUMMARY_STATES",
    "CONFIDENCE_AGREE",
    "CONFIDENCE_DIVERGENT",
    "CONFIDENCE_CONFLICT",
    "CONFIDENCE_UNKNOWN",
    "CONFIDENCE_BANDS",
    "CORRELATION_ID_PREFIX",
    "CORRELATION_ID_RE",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_REFERENCES",
    "MAX_AGENTS",
    "MAX_VALUE_LEN",
    "sanitize_hypothesis_reference",
    "sanitize_confidence_summary",
    "sanitize_hypothesis_group",
    "HypothesisReferencePlan",
    "HypothesisGroupPlan",
    "hypothesis_reference_plan_projection",
    "hypothesis_group_plan_projection",
]
