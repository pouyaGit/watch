"""Research pattern intelligence schema (Stage R33.1).

A :class:`ResearchPatternIntelligencePlan` converts historical structural
patterns into deterministic research signals. It answers the owner's
personal-research question:

    "Which historical pattern is the strongest signal for future attention?"

Hard boundaries encoded here:

- Deterministic frequency classification only: no statistical model, no ML,
  no embeddings, no LLM, no probability semantics.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: pattern codes and confidence levels are closed sets
  owned by R32.3/R31.15.
- Bounded, privacy-safe: only closed codes and bounded counts are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.research_pattern_plan import PATTERN_CODES

RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION = "r33-1"
RULE_VERSION = RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_PATTERNS = 8
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_patterns(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in PATTERN_CODES:
            raise ValueError(f"invalid pattern code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_scores(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            raise ValueError(f"malformed pattern score: {item!r}")
        pattern = _safe_text(item.get("pattern"))
        if pattern not in PATTERN_CODES:
            raise ValueError(f"invalid pattern code: {pattern!r}")
        try:
            frequency = int(item.get("frequency"))
        except (TypeError, ValueError):
            raise ValueError(f"malformed frequency: {item!r}")
        if frequency < 0:
            raise ValueError(f"negative frequency: {item!r}")
        confidence = _safe_text(item.get("confidence"))
        if confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {confidence!r}")
        entry = {
            "pattern": pattern,
            "frequency": frequency,
            "confidence": confidence,
        }
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def _bounded_patterns(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in PATTERN_CODES and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_scores(value: object, limit: int) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        if not isinstance(item, dict):
            continue
        pattern = _safe_text(item.get("pattern"))
        confidence = _safe_text(item.get("confidence"))
        if pattern not in PATTERN_CODES or confidence not in CONFIDENCE_LEVELS:
            continue
        try:
            frequency = max(0, int(item.get("frequency")))
        except (TypeError, ValueError):
            continue
        entry = {
            "pattern": pattern,
            "frequency": frequency,
            "confidence": confidence,
        }
        if entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def sanitize_research_pattern_intelligence_plan(value: object) -> dict:
    """Project an R33.1 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "dominant_patterns": [],
            "pattern_scores": [],
            "strongest_signal": "",
            "confidence": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "dominant_patterns": _bounded_patterns(
            value.get("dominant_patterns"), MAX_PATTERNS
        ),
        "pattern_scores": _bounded_scores(
            value.get("pattern_scores"), MAX_PATTERNS
        ),
        "strongest_signal": _safe_text(value.get("strongest_signal")),
        "confidence": _safe_text(value.get("confidence")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchPatternIntelligencePlan(BaseModel):
    """Deterministic historical pattern intelligence (R33.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION
    dominant_patterns: list[str] = Field(default_factory=list)
    pattern_scores: list[dict] = Field(default_factory=list)
    strongest_signal: str
    confidence: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION

    @field_validator("dominant_patterns")
    @classmethod
    def _valid_dominant(cls, value: list) -> list[str]:
        return _require_patterns(value, MAX_PATTERNS)

    @field_validator("pattern_scores")
    @classmethod
    def _valid_scores(cls, value: list) -> list[dict]:
        return _require_scores(value, MAX_PATTERNS)

    @field_validator("strongest_signal")
    @classmethod
    def _valid_signal(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PATTERN_CODES:
            raise ValueError(f"invalid strongest_signal: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research pattern intelligence plans are research-only"
            )
        return True


def research_pattern_intelligence_plan_projection(
    value: ResearchPatternIntelligencePlan,
) -> dict:
    """Serialize a pattern intelligence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_PATTERN_INTELLIGENCE_RULE_VERSION",
    "RULE_VERSION",
    "MAX_PATTERNS",
    "MAX_VALUE_LEN",
    "ResearchPatternIntelligencePlan",
    "sanitize_research_pattern_intelligence_plan",
    "research_pattern_intelligence_plan_projection",
]
