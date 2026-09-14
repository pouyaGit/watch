"""Finding correlation schema (Stage R54.1).

Defines the bounded, deterministic relationship between two R53 research
finding candidates. It answers the finding-correlation question:

    "How are these two structured findings related?"

Hard boundaries encoded here:

- Research correlation only: relationships describe structured research
  artifacts. They never confirm a vulnerability, never execute anything and
  never merge or delete the original findings.
- Reused vocabulary: relationship types reuse the existing R43 correlation
  vocabulary (``DUPLICATE``/``RELATED``/``INDEPENDENT``/``CONFLICTING``/
  ``UNKNOWN``); no incompatible free-form relationship value exists.
- Stable identity: every relationship references the stable R53 finding ids
  (``fnd-<16 hex>``); list position is never used as identity.
- Interpretable signals only: every relationship carries a closed set of
  structured signal codes and a bounded, explainable score derived from those
  signals. No LLM, no randomness, no timestamps.
- Preservation: the relationship references original finding metadata; it
  never rewrites evidence, hypotheses, provenance, governance or
  limitations.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_assessment import CONFIRMATION_NOT_CONFIRMED
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_evidence import EVIDENCE_COMPLETENESS_LEVELS
from ai.schemas.hypothesis_correlation import (
    CORRELATION_CONFLICTING,
    CORRELATION_DUPLICATE,
    CORRELATION_INDEPENDENT,
    CORRELATION_RELATED,
    CORRELATION_TYPES,
    CORRELATION_UNKNOWN,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

FINDING_CORRELATION_RULE_VERSION = "r54-1"
RULE_VERSION = FINDING_CORRELATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Relationship vocabulary (reused from R43; identical strings)
# ---------------------------------------------------------------------------

RELATIONSHIP_DUPLICATE = CORRELATION_DUPLICATE
RELATIONSHIP_RELATED = CORRELATION_RELATED
RELATIONSHIP_INDEPENDENT = CORRELATION_INDEPENDENT
RELATIONSHIP_CONFLICTING = CORRELATION_CONFLICTING
RELATIONSHIP_UNKNOWN = CORRELATION_UNKNOWN

RELATIONSHIP_TYPES: tuple[str, ...] = CORRELATION_TYPES

RELATIONSHIP_PRECEDENCE: dict[str, int] = {
    RELATIONSHIP_CONFLICTING: 4,
    RELATIONSHIP_DUPLICATE: 3,
    RELATIONSHIP_RELATED: 2,
    RELATIONSHIP_UNKNOWN: 1,
    RELATIONSHIP_INDEPENDENT: 0,
}

RELATIONSHIP_ID_PREFIX = "fcr-"
RELATIONSHIP_ID_RE = re.compile(r"^fcr-[0-9a-f]{16}$")

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NOT_CONFIRMED = "NOT_CONFIRMED"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_CONFIDENCE_NOT_UPGRADED = "CONFIDENCE_NOT_UPGRADED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
LIMITATION_CORRELATION_UNAVAILABLE = "CORRELATION_UNAVAILABLE"
LIMITATION_CONFLICT_PRESENT = "CONFLICT_PRESENT"
LIMITATION_DUPLICATE_RELATIONSHIP = "DUPLICATE_RELATIONSHIP"
LIMITATION_SHARED_CONTEXT = "SHARED_CONTEXT"
LIMITATION_EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
LIMITATION_PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"

CORRELATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_CONFIDENCE_NOT_UPGRADED,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_DUPLICATE_RELATIONSHIP,
    LIMITATION_SHARED_CONTEXT,
    LIMITATION_EVIDENCE_INCOMPLETE,
    LIMITATION_PROVENANCE_UNAVAILABLE,
    LIMITATION_GOVERNANCE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Signal vocabulary (closed)
# ---------------------------------------------------------------------------

SIGNAL_IDENTICAL_FINDING_ID = "IDENTICAL_FINDING_ID"
SIGNAL_SAME_CATEGORY = "SAME_CATEGORY"
SIGNAL_SAME_AGENT = "SAME_AGENT"
SIGNAL_SAME_ORCHESTRATION = "SAME_ORCHESTRATION"
SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT = "SHARED_HYPOTHESIS_FINGERPRINT"
SIGNAL_SHARED_HYPOTHESIS_TYPE = "SHARED_HYPOTHESIS_TYPE"
SIGNAL_SHARED_HYPOTHESIS_SIGNAL = "SHARED_HYPOTHESIS_SIGNAL"
SIGNAL_SHARED_EVIDENCE_REQUIREMENT = "SHARED_EVIDENCE_REQUIREMENT"
SIGNAL_SHARED_CONTEXT_VALUE = "SHARED_CONTEXT_VALUE"
SIGNAL_SHARED_COMPONENT = "SHARED_COMPONENT"
SIGNAL_SHARED_ENDPOINT = "SHARED_ENDPOINT"
SIGNAL_CATEGORY_FAMILY = "CATEGORY_FAMILY"
SIGNAL_R43_RELATED_GROUP = "R43_RELATED_GROUP"
SIGNAL_R43_MATERIAL_CONFLICT = "R43_MATERIAL_CONFLICT"
SIGNAL_CONTEXT_CONFLICT = "CONTEXT_CONFLICT"
SIGNAL_EVIDENCE_STATE_CONFLICT = "EVIDENCE_STATE_CONFLICT"
SIGNAL_EVIDENCE_STATE_DIVERGENCE = "EVIDENCE_STATE_DIVERGENCE"
SIGNAL_CONFIDENCE_CONFLICT = "CONFIDENCE_CONFLICT"
SIGNAL_CONFIDENCE_DIVERGENCE = "CONFIDENCE_DIVERGENCE"
SIGNAL_INSUFFICIENT_STRUCTURE = "INSUFFICIENT_STRUCTURE"
SIGNAL_NO_SHARED_SIGNAL = "NO_SHARED_SIGNAL"

CORRELATION_SIGNALS: tuple[str, ...] = (
    SIGNAL_IDENTICAL_FINDING_ID,
    SIGNAL_SAME_CATEGORY,
    SIGNAL_SAME_AGENT,
    SIGNAL_SAME_ORCHESTRATION,
    SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT,
    SIGNAL_SHARED_HYPOTHESIS_TYPE,
    SIGNAL_SHARED_HYPOTHESIS_SIGNAL,
    SIGNAL_SHARED_EVIDENCE_REQUIREMENT,
    SIGNAL_SHARED_CONTEXT_VALUE,
    SIGNAL_SHARED_COMPONENT,
    SIGNAL_SHARED_ENDPOINT,
    SIGNAL_CATEGORY_FAMILY,
    SIGNAL_R43_RELATED_GROUP,
    SIGNAL_R43_MATERIAL_CONFLICT,
    SIGNAL_CONTEXT_CONFLICT,
    SIGNAL_EVIDENCE_STATE_CONFLICT,
    SIGNAL_EVIDENCE_STATE_DIVERGENCE,
    SIGNAL_CONFIDENCE_CONFLICT,
    SIGNAL_CONFIDENCE_DIVERGENCE,
    SIGNAL_INSUFFICIENT_STRUCTURE,
    SIGNAL_NO_SHARED_SIGNAL,
)

#: Fixed, documented weights for the bounded interpretable relationship score.
#: The score is an explainability aid only; classification uses the closed
#: rule set, never a threshold.
SIGNAL_WEIGHTS: dict[str, int] = {
    SIGNAL_IDENTICAL_FINDING_ID: 100,
    SIGNAL_R43_MATERIAL_CONFLICT: 60,
    SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT: 55,
    SIGNAL_CONTEXT_CONFLICT: 50,
    SIGNAL_SHARED_COMPONENT: 40,
    SIGNAL_SHARED_ENDPOINT: 35,
    SIGNAL_SAME_CATEGORY: 25,
    SIGNAL_SAME_AGENT: 25,
    SIGNAL_R43_RELATED_GROUP: 25,
    SIGNAL_SHARED_CONTEXT_VALUE: 15,
    SIGNAL_SHARED_HYPOTHESIS_TYPE: 12,
    SIGNAL_SHARED_EVIDENCE_REQUIREMENT: 10,
    SIGNAL_SHARED_HYPOTHESIS_SIGNAL: 10,
    SIGNAL_EVIDENCE_STATE_CONFLICT: 20,
    SIGNAL_CONFIDENCE_CONFLICT: 10,
    SIGNAL_CATEGORY_FAMILY: 8,
    SIGNAL_EVIDENCE_STATE_DIVERGENCE: 4,
    SIGNAL_CONFIDENCE_DIVERGENCE: 4,
    SIGNAL_SAME_ORCHESTRATION: 0,
    SIGNAL_INSUFFICIENT_STRUCTURE: 0,
    SIGNAL_NO_SHARED_SIGNAL: 0,
}

MAX_RELATIONSHIP_SCORE = 100

MAX_SIGNALS = 16
MAX_SHARED_ITEMS = 12
MAX_CONFLICT_DETAILS = 8
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_tokens(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def sanitize_shared_context_value(value: object) -> dict:
    """Project one shared context observation onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {"key": "", "value": ""}
    key = _safe_text(value.get("key"), 80)
    if not re.match(r"^[a-z][a-z0-9_]{0,60}$", key):
        key = ""
    return {"key": key, "value": _safe_text(value.get("value"))}


def sanitize_conflict_detail(value: object) -> dict:
    """Project one preserved conflict detail onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    conflict_type = _safe_text(value.get("conflict_type")).strip().upper()
    if not conflict_type or not _TOKEN_RE.match(conflict_type):
        return {}
    return {
        "conflict_type": conflict_type,
        "resolution_state": _safe_text(
            value.get("resolution_state")
        ).strip().upper(),
        "conflicting_fields": _bounded_strings(
            value.get("conflicting_fields"), MAX_SHARED_ITEMS
        ),
    }


def sanitize_finding_reference(value: object) -> dict:
    """Project one correlated finding onto its fixed bounded key set.

    The projection references the stable finding identity and preserves the
    bounded metadata needed for correlation reasoning (state, confidence,
    evidence summary, component, governance state). It is a reference, not a
    copy of the finding.
    """

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "finding_id": "",
            "finding_rule_version": "",
            "category": "",
            "specialist_name": "",
            "agent_id": "",
            "state": "",
            "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
            "confidence": "UNKNOWN",
            "evidence_state": "UNKNOWN",
            "evidence_completeness": "UNKNOWN",
            "evidence_origin": "UNKNOWN",
            "context_fact_count": 0,
            "hypothesis_count": 0,
            "evidence_requirement_count": 0,
            "component_name": "",
            "component_version": "",
            "endpoint_reference": "",
            "orchestration_id": "",
            "governance_state": "UNKNOWN",
            "research_only": True,
        }
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    evidence_completeness = _safe_text(
        value.get("evidence_completeness")
    ).strip().upper()
    if evidence_completeness not in EVIDENCE_COMPLETENESS_LEVELS:
        evidence_completeness = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "finding_id": _safe_text(value.get("finding_id")),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": _safe_text(value.get("agent_id")),
        "state": _safe_text(value.get("state")).strip().upper(),
        "confirmation_state": _closed(
            value.get("confirmation_state"),
            (CONFIRMATION_NOT_CONFIRMED,),
            CONFIRMATION_NOT_CONFIRMED,
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "evidence_state": _safe_text(
            value.get("evidence_state")
        ).strip().upper(),
        "evidence_completeness": evidence_completeness,
        "evidence_origin": _safe_text(
            value.get("evidence_origin")
        ).strip().upper(),
        "context_fact_count": _bounded_int(
            value.get("context_fact_count"), 0, 64
        ),
        "hypothesis_count": _bounded_int(
            value.get("hypothesis_count"), 0, 64
        ),
        "evidence_requirement_count": _bounded_int(
            value.get("evidence_requirement_count"), 0, 64
        ),
        "component_name": _safe_text(value.get("component_name")),
        "component_version": _safe_text(value.get("component_version")),
        "endpoint_reference": _safe_text(
            value.get("endpoint_reference")
        ),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "governance_state": _safe_text(
            value.get("governance_state")
        ).strip().upper(),
        "research_only": True,
    }


def sanitize_finding_relationship(value: object) -> dict:
    """Project one finding relationship onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "relationship_id": "",
            "relationship_type": RELATIONSHIP_UNKNOWN,
            "source_finding_id": "",
            "target_finding_id": "",
            "source_agent_id": "",
            "target_agent_id": "",
            "signals": [],
            "score": 0,
            "shared_context_values": [],
            "shared_hypothesis_types": [],
            "shared_hypothesis_signals": [],
            "shared_evidence_requirements": [],
            "shared_component_name": "",
            "shared_endpoint_reference": "",
            "conflict_details": [],
            "confidence_effect": "NONE",
            "limitations": [],
            "research_only": True,
        }
    relationship_type = _closed(
        value.get("relationship_type"),
        RELATIONSHIP_TYPES,
        RELATIONSHIP_UNKNOWN,
    )
    shared_context_values: list[dict] = []
    for item in value.get("shared_context_values") or ():
        projected = sanitize_shared_context_value(item)
        if projected["key"] and projected not in shared_context_values:
            shared_context_values.append(projected)
        if len(shared_context_values) >= MAX_SHARED_ITEMS:
            break
    conflict_details: list[dict] = []
    for item in value.get("conflict_details") or ():
        projected = sanitize_conflict_detail(item)
        if projected and projected not in conflict_details:
            conflict_details.append(projected)
        if len(conflict_details) >= MAX_CONFLICT_DETAILS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "relationship_id": _safe_text(value.get("relationship_id")),
        "relationship_type": relationship_type,
        "source_finding_id": _safe_text(value.get("source_finding_id")),
        "target_finding_id": _safe_text(value.get("target_finding_id")),
        "source_agent_id": _safe_text(value.get("source_agent_id")),
        "target_agent_id": _safe_text(value.get("target_agent_id")),
        "signals": _bounded_tokens(
            value.get("signals"), CORRELATION_SIGNALS, MAX_SIGNALS
        ),
        "score": _bounded_int(
            value.get("score"), 0, MAX_RELATIONSHIP_SCORE
        ),
        "shared_context_values": shared_context_values,
        "shared_hypothesis_types": _bounded_strings(
            value.get("shared_hypothesis_types"), MAX_SHARED_ITEMS
        ),
        "shared_hypothesis_signals": _bounded_strings(
            value.get("shared_hypothesis_signals"), MAX_SHARED_ITEMS
        ),
        "shared_evidence_requirements": _bounded_strings(
            value.get("shared_evidence_requirements"), MAX_SHARED_ITEMS
        ),
        "shared_component_name": _safe_text(
            value.get("shared_component_name")
        ),
        "shared_endpoint_reference": _safe_text(
            value.get("shared_endpoint_reference")
        ),
        "conflict_details": conflict_details,
        "confidence_effect": "NONE",
        "limitations": _bounded_codes(
            value.get("limitations"), CORRELATION_LIMITATIONS, 16
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FindingReferencePlan(BaseModel):
    """Stable reference to one correlated R53 finding (R54.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_CORRELATION_RULE_VERSION
    finding_id: str
    finding_rule_version: str = ""
    category: str = ""
    specialist_name: str = ""
    agent_id: str = ""
    state: str = ""
    confirmation_state: str = CONFIRMATION_NOT_CONFIRMED
    confidence: str = "UNKNOWN"
    evidence_state: str = "UNKNOWN"
    evidence_completeness: str = "UNKNOWN"
    evidence_origin: str = "UNKNOWN"
    context_fact_count: int = 0
    hypothesis_count: int = 0
    evidence_requirement_count: int = 0
    component_name: str = ""
    component_version: str = ""
    endpoint_reference: str = ""
    orchestration_id: str = ""
    governance_state: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_CORRELATION_RULE_VERSION

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
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid finding category: {value!r}")
        return text

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != CONFIRMATION_NOT_CONFIRMED:
            raise ValueError("correlated findings are never confirmed")
        return CONFIRMATION_NOT_CONFIRMED

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator(
        "context_fact_count",
        "hypothesis_count",
        "evidence_requirement_count",
    )
    @classmethod
    def _bounded_count(cls, value: object) -> int:
        return _bounded_int(value, 0, 64)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding references are research-only")
        return True


class FindingRelationshipPlan(BaseModel):
    """Deterministic relationship between two R53 findings (R54.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_CORRELATION_RULE_VERSION
    relationship_id: str
    relationship_type: str
    source_finding_id: str
    target_finding_id: str
    source_agent_id: str = ""
    target_agent_id: str = ""
    signals: list[str] = Field(default_factory=list)
    score: int = 0
    shared_context_values: list[dict] = Field(default_factory=list)
    shared_hypothesis_types: list[str] = Field(default_factory=list)
    shared_hypothesis_signals: list[str] = Field(default_factory=list)
    shared_evidence_requirements: list[str] = Field(default_factory=list)
    shared_component_name: str = ""
    shared_endpoint_reference: str = ""
    conflict_details: list[dict] = Field(default_factory=list)
    confidence_effect: str = "NONE"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_CORRELATION_RULE_VERSION

    @field_validator("relationship_id")
    @classmethod
    def _valid_relationship_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not RELATIONSHIP_ID_RE.match(text):
            raise ValueError(f"malformed relationship_id: {value!r}")
        return text

    @field_validator("relationship_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RELATIONSHIP_TYPES:
            raise ValueError(f"invalid relationship_type: {value!r}")
        return text

    @field_validator("source_finding_id", "target_finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding id: {value!r}")
        return text

    @field_validator("signals")
    @classmethod
    def _valid_signals(cls, value: object) -> list[str]:
        return _bounded_tokens(value, CORRELATION_SIGNALS, MAX_SIGNALS)

    @field_validator("score")
    @classmethod
    def _valid_score(cls, value: object) -> int:
        return _bounded_int(value, 0, MAX_RELATIONSHIP_SCORE)

    @field_validator("shared_context_values")
    @classmethod
    def _bounded_context(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_shared_context_value(item)
            if projected["key"] and projected not in out:
                out.append(projected)
            if len(out) >= MAX_SHARED_ITEMS:
                break
        return out

    @field_validator(
        "shared_hypothesis_types",
        "shared_hypothesis_signals",
        "shared_evidence_requirements",
    )
    @classmethod
    def _bounded_shared(cls, value: object) -> list[str]:
        return _bounded_strings(value, MAX_SHARED_ITEMS)

    @field_validator("conflict_details")
    @classmethod
    def _bounded_conflicts(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_conflict_detail(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_CONFLICT_DETAILS:
                break
        return out

    @field_validator("confidence_effect")
    @classmethod
    def _no_confidence_effect(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NONE":
            raise ValueError("correlation never changes finding confidence")
        return "NONE"

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _bounded_strings(value, 16)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("finding relationships are research-only")
        return True


def finding_relationship_plan_projection(
    value: FindingRelationshipPlan,
) -> dict:
    """Serialize a finding relationship to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_CORRELATION_RULE_VERSION",
    "RULE_VERSION",
    "CORRELATION_LIMITATIONS",
    "RELATIONSHIP_TYPES",
    "RELATIONSHIP_PRECEDENCE",
    "RELATIONSHIP_DUPLICATE",
    "RELATIONSHIP_RELATED",
    "RELATIONSHIP_INDEPENDENT",
    "RELATIONSHIP_CONFLICTING",
    "RELATIONSHIP_UNKNOWN",
    "RELATIONSHIP_ID_PREFIX",
    "RELATIONSHIP_ID_RE",
    "CORRELATION_SIGNALS",
    "SIGNAL_WEIGHTS",
    "MAX_RELATIONSHIP_SCORE",
    "MAX_SIGNALS",
    "MAX_SHARED_ITEMS",
    "MAX_CONFLICT_DETAILS",
    "MAX_VALUE_LEN",
    "SIGNAL_IDENTICAL_FINDING_ID",
    "SIGNAL_SAME_CATEGORY",
    "SIGNAL_SAME_AGENT",
    "SIGNAL_SAME_ORCHESTRATION",
    "SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT",
    "SIGNAL_SHARED_HYPOTHESIS_TYPE",
    "SIGNAL_SHARED_HYPOTHESIS_SIGNAL",
    "SIGNAL_SHARED_EVIDENCE_REQUIREMENT",
    "SIGNAL_SHARED_CONTEXT_VALUE",
    "SIGNAL_SHARED_COMPONENT",
    "SIGNAL_SHARED_ENDPOINT",
    "SIGNAL_CATEGORY_FAMILY",
    "SIGNAL_R43_RELATED_GROUP",
    "SIGNAL_R43_MATERIAL_CONFLICT",
    "SIGNAL_CONTEXT_CONFLICT",
    "SIGNAL_EVIDENCE_STATE_CONFLICT",
    "SIGNAL_EVIDENCE_STATE_DIVERGENCE",
    "SIGNAL_CONFIDENCE_CONFLICT",
    "SIGNAL_CONFIDENCE_DIVERGENCE",
    "SIGNAL_INSUFFICIENT_STRUCTURE",
    "SIGNAL_NO_SHARED_SIGNAL",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NOT_CONFIRMED",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_CONFIDENCE_NOT_UPGRADED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "LIMITATION_CORRELATION_UNAVAILABLE",
    "LIMITATION_CONFLICT_PRESENT",
    "LIMITATION_DUPLICATE_RELATIONSHIP",
    "LIMITATION_SHARED_CONTEXT",
    "LIMITATION_EVIDENCE_INCOMPLETE",
    "LIMITATION_PROVENANCE_UNAVAILABLE",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "sanitize_shared_context_value",
    "sanitize_conflict_detail",
    "sanitize_finding_reference",
    "sanitize_finding_relationship",
    "FindingReferencePlan",
    "FindingRelationshipPlan",
    "finding_relationship_plan_projection",
]
