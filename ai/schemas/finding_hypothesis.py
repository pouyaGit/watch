"""Finding hypothesis linkage schema (Stage R53.3).

A :class:`FindingHypothesisLinkagePlan` preserves the specialist hypotheses
that a finding candidate rests on. It answers:

    "Which structured specialist hypotheses does this finding reference?"

Hard boundaries encoded here:

- Reference only: hypotheses come exclusively from the supplied structured
  specialist results. R53 never invents, merges or reclassifies a
  hypothesis, and never promotes a hypothesis into a vulnerability.
- Preservation: hypothesis type, source specialist, confidence, priority,
  supporting signals, safety limitations, subject reference and rationale
  are carried through unchanged (bounded).
- Closed vocabularies: confidence and priority reuse the shared
  evidence-confidence vocabulary; the hypothesis type is a bounded token
  owned by the source specialist.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.hypothesis_correlation import sanitize_confidence_summary
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

FINDING_HYPOTHESIS_RULE_VERSION = "r53-3"
RULE_VERSION = FINDING_HYPOTHESIS_RULE_VERSION

MAX_HYPOTHESES = 24
MAX_SIGNALS = 12
MAX_LIMITATIONS = 8
MAX_VALUE_LEN = 160
MAX_RATIONALE_LEN = 240

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


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


def sanitize_finding_hypothesis_reference(value: object) -> dict:
    """Project one specialist hypothesis reference onto bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_category": "UNKNOWN",
            "hypothesis_index": 0,
            "hypothesis_type": "UNKNOWN",
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "limitations": [],
            "subject_reference": "",
            "rationale": "",
            "fingerprint": "",
            "research_only": True,
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
        "hypothesis_index": min(63, index),
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
        "rationale": _safe_text(value.get("rationale"), MAX_RATIONALE_LEN),
        "fingerprint": _safe_text(value.get("fingerprint")),
        "research_only": True,
    }


def sanitize_finding_hypothesis_linkage(value: object) -> dict:
    """Project a hypothesis linkage onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "references": [],
            "hypothesis_count": 0,
            "hypothesis_types": [],
            "confidence_summary": sanitize_confidence_summary(None),
            "research_only": True,
        }
    references: list[dict] = []
    for item in value.get("references") or ():
        if isinstance(item, dict):
            references.append(sanitize_finding_hypothesis_reference(item))
        if len(references) >= MAX_HYPOTHESES:
            break
    types: list[str] = []
    for item in value.get("hypothesis_types") or ():
        text = _safe_text(item).strip().upper()
        if text and _TOKEN_RE.match(text) and text not in types:
            types.append(text)
        if len(types) >= MAX_HYPOTHESES:
            break
    if not types:
        for reference in references:
            text = reference["hypothesis_type"]
            if text != "UNKNOWN" and text not in types:
                types.append(text)
    count = value.get("hypothesis_count")
    if isinstance(count, bool) or not isinstance(count, int):
        count = len(references)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "references": references,
        "hypothesis_count": max(0, min(MAX_HYPOTHESES, count)),
        "hypothesis_types": types,
        "confidence_summary": sanitize_confidence_summary(
            value.get("confidence_summary")
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class FindingHypothesisReferencePlan(BaseModel):
    """One preserved specialist hypothesis reference (R53.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = ""
    agent_id: str = ""
    agent_category: str = "UNKNOWN"
    hypothesis_index: int = 0
    hypothesis_type: str = "UNKNOWN"
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    subject_reference: str = ""
    rationale: str = ""
    fingerprint: str = ""
    research_only: bool = True

    @field_validator("agent_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid hypothesis category: {value!r}")
        return text

    @field_validator("hypothesis_index")
    @classmethod
    def _valid_index(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid hypothesis_index: {value!r}")
        return min(63, value)

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if not text or not _TOKEN_RE.match(text):
            raise ValueError(f"invalid hypothesis type: {value!r}")
        return text

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("rule_version", "agent_id", "subject_reference",
                     "fingerprint")
    @classmethod
    def _bounded_text(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("rationale")
    @classmethod
    def _bounded_rationale(cls, value: object) -> str:
        return _safe_text(value, MAX_RATIONALE_LEN)

    @field_validator("supporting_signals")
    @classmethod
    def _bounded_signals(cls, value: object) -> list[str]:
        return _bounded_tokens(value, MAX_SIGNALS)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _bounded_tokens(value, MAX_LIMITATIONS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("hypothesis references are research-only")
        return True


class FindingHypothesisLinkagePlan(BaseModel):
    """Preserved specialist hypothesis linkage (R53.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_HYPOTHESIS_RULE_VERSION
    references: list[dict] = Field(default_factory=list)
    hypothesis_count: int = 0
    hypothesis_types: list[str] = Field(default_factory=list)
    confidence_summary: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_HYPOTHESIS_RULE_VERSION

    @field_validator("references")
    @classmethod
    def _bounded_references(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_finding_hypothesis_reference(item)
            if projected not in out:
                out.append(projected)
            if len(out) >= MAX_HYPOTHESES:
                break
        return out

    @field_validator("hypothesis_types")
    @classmethod
    def _bounded_types(cls, value: object) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text and _TOKEN_RE.match(text) and text not in out:
                out.append(text)
            if len(out) >= MAX_HYPOTHESES:
                break
        return out

    @field_validator("hypothesis_count")
    @classmethod
    def _bounded_count(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return max(0, min(MAX_HYPOTHESES, value))

    @field_validator("confidence_summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_confidence_summary(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("hypothesis linkages are research-only")
        return True


def finding_hypothesis_linkage_plan_projection(
    value: FindingHypothesisLinkagePlan,
) -> dict:
    """Serialize a hypothesis linkage to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_HYPOTHESIS_RULE_VERSION",
    "RULE_VERSION",
    "MAX_HYPOTHESES",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "MAX_RATIONALE_LEN",
    "sanitize_finding_hypothesis_reference",
    "sanitize_finding_hypothesis_linkage",
    "FindingHypothesisReferencePlan",
    "FindingHypothesisLinkagePlan",
    "finding_hypothesis_linkage_plan_projection",
]
