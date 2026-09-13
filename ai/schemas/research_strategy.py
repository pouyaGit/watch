"""Research strategy schema (Stage R34.1).

A :class:`ResearchStrategyPlan` is a deterministic, read-only high-level
research strategy derived from the R33.4 learning export and the R32.4 memory
export. It answers the owner's personal-research question:

    "What research strategy should be preferred next?"

Hard boundaries encoded here:

- Historical mapping only: no prediction, probability, ML, embeddings or LLM.
- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: strategy type, strategy reason and historical basis are
  closed sets; confidence and blockers reuse the R31.15 sets.
- Bounded, privacy-safe: only closed codes and bounded lists are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import (
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
)

RESEARCH_STRATEGY_RULE_VERSION = "r34-1"
RULE_VERSION = RESEARCH_STRATEGY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STRATEGY_EVIDENCE_FIRST = "EVIDENCE_FIRST"
STRATEGY_IDENTITY_FIRST = "IDENTITY_FIRST"
STRATEGY_TECHNOLOGY_FIRST = "TECHNOLOGY_FIRST"
STRATEGY_SCOPE_FIRST = "SCOPE_FIRST"
STRATEGY_VERSION_FIRST = "VERSION_FIRST"
STRATEGY_HUMAN_REVIEW_FIRST = "HUMAN_REVIEW_FIRST"
STRATEGY_DEFERRED = "DEFERRED"
STRATEGY_UNKNOWN = "UNKNOWN"

STRATEGY_TYPES: tuple[str, ...] = (
    STRATEGY_EVIDENCE_FIRST,
    STRATEGY_IDENTITY_FIRST,
    STRATEGY_TECHNOLOGY_FIRST,
    STRATEGY_SCOPE_FIRST,
    STRATEGY_VERSION_FIRST,
    STRATEGY_HUMAN_REVIEW_FIRST,
    STRATEGY_DEFERRED,
    STRATEGY_UNKNOWN,
)

REASON_SUCCESS_EVIDENCE = "SUCCESSFUL_EVIDENCE_HISTORY"
REASON_IDENTITY = "IDENTITY_LIMITATION_DOMINANT"
REASON_TECHNOLOGY = "TECHNOLOGY_PATTERN_DOMINANT"
REASON_SCOPE = "SCOPE_LIMITATION_DOMINANT"
REASON_VERSION = "VERSION_LIMITATION_DOMINANT"
REASON_HUMAN = "HUMAN_RESEARCH_DOMINANT"
REASON_DEFERRED = "DEFERRED_OUTCOME_DOMINANT"
REASON_NO_HISTORY = "INSUFFICIENT_HISTORY"
REASON_UNMAPPED = "UNMAPPED_PATTERN"
REASON_MALFORMED = "MALFORMED_INPUT"

STRATEGY_REASONS: tuple[str, ...] = (
    REASON_SUCCESS_EVIDENCE,
    REASON_IDENTITY,
    REASON_TECHNOLOGY,
    REASON_SCOPE,
    REASON_VERSION,
    REASON_HUMAN,
    REASON_DEFERRED,
    REASON_NO_HISTORY,
    REASON_UNMAPPED,
    REASON_MALFORMED,
)

BASIS_EVIDENCE_SUCCESS = "EVIDENCE_SUCCESS_PATTERN"
BASIS_IDENTITY = "IDENTITY_LIMITATION"
BASIS_TECHNOLOGY = "TECHNOLOGY_PATTERN"
BASIS_SCOPE = "SCOPE_LIMITATION"
BASIS_VERSION = "VERSION_LIMITATION"
BASIS_HUMAN = "HUMAN_RESEARCH_PATTERN"
BASIS_DEFERRED = "DEFERRED_OUTCOME"
BASIS_NO_HISTORY = "NO_HISTORY"
BASIS_UNKNOWN_PATTERN = "UNKNOWN_PATTERN"
BASIS_MALFORMED = "MALFORMED_INPUT"

HISTORICAL_BASES: tuple[str, ...] = (
    BASIS_EVIDENCE_SUCCESS,
    BASIS_IDENTITY,
    BASIS_TECHNOLOGY,
    BASIS_SCOPE,
    BASIS_VERSION,
    BASIS_HUMAN,
    BASIS_DEFERRED,
    BASIS_NO_HISTORY,
    BASIS_UNKNOWN_PATTERN,
    BASIS_MALFORMED,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


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


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_research_strategy_plan(value: object) -> dict:
    """Project an R34.1 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "strategy_type": "",
            "strategy_reason": "",
            "historical_basis": "",
            "confidence_level": "",
            "blockers": [],
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "strategy_type": _safe_text(value.get("strategy_type")),
        "strategy_reason": _safe_text(value.get("strategy_reason")),
        "historical_basis": _safe_text(value.get("historical_basis")),
        "confidence_level": _safe_text(value.get("confidence_level")),
        "blockers": _bounded_codes(
            value.get("blockers"), CONFIDENCE_BLOCKERS, MAX_BLOCKERS
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchStrategyPlan(BaseModel):
    """Deterministic high-level research strategy (R34.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_STRATEGY_RULE_VERSION
    strategy_type: str
    strategy_reason: str
    historical_basis: str
    confidence_level: str
    blockers: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_STRATEGY_RULE_VERSION

    @field_validator("strategy_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in STRATEGY_TYPES:
            raise ValueError(f"invalid strategy_type: {value!r}")
        return text

    @field_validator("strategy_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in STRATEGY_REASONS:
            raise ValueError(f"invalid strategy_reason: {value!r}")
        return text

    @field_validator("historical_basis")
    @classmethod
    def _valid_basis(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HISTORICAL_BASES:
            raise ValueError(f"invalid historical_basis: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        return _require_codes(value, CONFIDENCE_BLOCKERS, MAX_BLOCKERS)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research strategy plans are research-only")
        return True


def research_strategy_plan_projection(value: ResearchStrategyPlan) -> dict:
    """Serialize a research strategy plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_STRATEGY_RULE_VERSION",
    "RULE_VERSION",
    "STRATEGY_TYPES",
    "STRATEGY_REASONS",
    "HISTORICAL_BASES",
    "STRATEGY_EVIDENCE_FIRST",
    "STRATEGY_IDENTITY_FIRST",
    "STRATEGY_TECHNOLOGY_FIRST",
    "STRATEGY_SCOPE_FIRST",
    "STRATEGY_VERSION_FIRST",
    "STRATEGY_HUMAN_REVIEW_FIRST",
    "STRATEGY_DEFERRED",
    "STRATEGY_UNKNOWN",
    "REASON_SUCCESS_EVIDENCE",
    "REASON_IDENTITY",
    "REASON_TECHNOLOGY",
    "REASON_SCOPE",
    "REASON_VERSION",
    "REASON_HUMAN",
    "REASON_DEFERRED",
    "REASON_NO_HISTORY",
    "REASON_UNMAPPED",
    "REASON_MALFORMED",
    "BASIS_EVIDENCE_SUCCESS",
    "BASIS_IDENTITY",
    "BASIS_TECHNOLOGY",
    "BASIS_SCOPE",
    "BASIS_VERSION",
    "BASIS_HUMAN",
    "BASIS_DEFERRED",
    "BASIS_NO_HISTORY",
    "BASIS_UNKNOWN_PATTERN",
    "BASIS_MALFORMED",
    "MAX_BLOCKERS",
    "MAX_VALUE_LEN",
    "ResearchStrategyPlan",
    "sanitize_research_strategy_plan",
    "research_strategy_plan_projection",
]
