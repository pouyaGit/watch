"""Evidence decision schema (Stage R31.16).

An :class:`EvidenceDecisionPlan` is a deterministic, read-only final research
decision over one R31.13 Evidence Acquisition Plan, one R31.14 Evidence
Prioritization Plan and one R31.15 Evidence Confidence Plan. It answers the
owner's personal-research question:

    "Is the current evidence sufficient, should research continue, is more
     evidence planning required, or should this candidate be deferred?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: decision, decision reason, next state,
  confidence level, required evidence and blocker codes are closed
  deterministic sets. The R31.13/R31.14/R31.15 vocabularies remain owned by
  those stages and are imported, never redefined.
- Bounded, privacy-safe: strings and lists are bounded; all three embedded
  source plans are projected onto fixed, closed key sets and sanitized.
- No probability / exploitability / severity / CVSS / payout fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import (
    BLOCKER_MALFORMED_ACQUISITION_PLAN,
    BLOCKER_MISSING_PRIORITIZATION_ITEM,
    BLOCKER_NO_ACQUISITION_PLANNED,
    BLOCKER_PRIORITY_MISALIGNMENT,
    BLOCKER_UNKNOWN_ACQUISITION_METHOD,
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    LIMITING_FACTORS,
    LIMITING_UPSTREAM_PLAN,
    sanitize_source_prioritization_plan,
)
from ai.schemas.evidence_prioritization import sanitize_source_plan

EVIDENCE_DECISION_RULE_VERSION = "r31-16"
RULE_VERSION = EVIDENCE_DECISION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

DECISION_ACCEPT_EVIDENCE = "ACCEPT_EVIDENCE"
DECISION_CONTINUE_RESEARCH = "CONTINUE_RESEARCH"
DECISION_REQUIRE_MORE_EVIDENCE = "REQUIRE_MORE_EVIDENCE"
DECISION_DEFER_RESEARCH = "DEFER_RESEARCH"
DECISION_UNKNOWN = "UNKNOWN"

DECISIONS: tuple[str, ...] = (
    DECISION_ACCEPT_EVIDENCE,
    DECISION_CONTINUE_RESEARCH,
    DECISION_REQUIRE_MORE_EVIDENCE,
    DECISION_DEFER_RESEARCH,
    DECISION_UNKNOWN,
)

NEXT_STATE_COMPLETE = "COMPLETE"
NEXT_STATE_ACTIVE_RESEARCH = "ACTIVE_RESEARCH"
NEXT_STATE_WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
NEXT_STATE_DEFERRED = "DEFERRED"
NEXT_STATE_UNKNOWN = "UNKNOWN"

NEXT_STATES: tuple[str, ...] = (
    NEXT_STATE_COMPLETE,
    NEXT_STATE_ACTIVE_RESEARCH,
    NEXT_STATE_WAITING_FOR_EVIDENCE,
    NEXT_STATE_DEFERRED,
    NEXT_STATE_UNKNOWN,
)

REASON_EVIDENCE_SUFFICIENT = "EVIDENCE_SUFFICIENT"
REASON_HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
REASON_MISSING_IDENTITY = "MISSING_IDENTITY"
REASON_MISSING_VERSION = "MISSING_VERSION"
REASON_MISSING_SCOPE = "MISSING_SCOPE"
REASON_MISSING_PATH = "MISSING_PATH"
REASON_MISSING_PARAMETER = "MISSING_PARAMETER"
REASON_MISSING_HTTP_BEHAVIOR = "MISSING_HTTP_BEHAVIOR"
REASON_MISSING_TECHNOLOGY = "MISSING_TECHNOLOGY"
REASON_HUMAN_RESEARCH_REQUIRED = "HUMAN_RESEARCH_REQUIRED"
REASON_NO_PLAN_AVAILABLE = "NO_PLAN_AVAILABLE"

DECISION_REASONS: tuple[str, ...] = (
    REASON_EVIDENCE_SUFFICIENT,
    REASON_HIGH_CONFIDENCE,
    REASON_MISSING_IDENTITY,
    REASON_MISSING_VERSION,
    REASON_MISSING_SCOPE,
    REASON_MISSING_PATH,
    REASON_MISSING_PARAMETER,
    REASON_MISSING_HTTP_BEHAVIOR,
    REASON_MISSING_TECHNOLOGY,
    REASON_HUMAN_RESEARCH_REQUIRED,
    REASON_NO_PLAN_AVAILABLE,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_ITEMS = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.15 plan snapshot.
SOURCE_CONFIDENCE_KEYS: tuple[str, ...] = (
    "rule_version",
    "confidence_level",
    "confidence_category",
    "limiting_factor",
    "evidence_completeness",
    "priority_alignment",
    "blockers",
    "research_only",
)

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    """Bound and redact credential-like text before it enters evidence."""

    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:MAX_VALUE_LEN]


def _closed_token(value: object) -> str:
    text = _safe_text(value).strip().upper()
    if not text:
        return ""
    if not _TOKEN_RE.match(text):
        raise ValueError(f"malformed closed token: {value!r}")
    return text


def _bounded_blockers(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= MAX_BLOCKERS:
            break
    return out


def sanitize_source_confidence_plan(value: object) -> dict:
    """Project an R31.15 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "confidence_level": "",
            "confidence_category": "",
            "limiting_factor": "",
            "evidence_completeness": "",
            "priority_alignment": "",
            "blockers": [],
            "research_only": True,
        }
    out: dict = {}
    for key in SOURCE_CONFIDENCE_KEYS:
        if key not in value:
            continue
        raw = value.get(key)
        if key == "blockers":
            out[key] = [
                code
                for code in _bounded_blockers(raw)
                if code in CONFIDENCE_BLOCKERS
            ]
        elif key == "research_only":
            out[key] = True
        else:
            out[key] = _safe_text(raw)
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class EvidenceDecisionPlan(BaseModel):
    """Deterministic final research decision over R31.13/R31.14/R31.15."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EVIDENCE_DECISION_RULE_VERSION
    decision: str
    decision_reason: str
    confidence_level: str
    next_state: str
    required_evidence: str
    blockers: list[str] = Field(default_factory=list)
    source_confidence_plan: dict = Field(default_factory=dict)
    source_priority_plan: dict = Field(default_factory=dict)
    source_acquisition_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EVIDENCE_DECISION_RULE_VERSION

    @field_validator("decision")
    @classmethod
    def _valid_decision(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in DECISIONS:
            raise ValueError(f"invalid decision: {value!r}")
        return text

    @field_validator("decision_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in DECISION_REASONS:
            raise ValueError(f"invalid decision_reason: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("next_state")
    @classmethod
    def _valid_next_state(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in NEXT_STATES:
            raise ValueError(f"invalid next_state: {value!r}")
        return text

    @field_validator("required_evidence")
    @classmethod
    def _valid_required_evidence(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in LIMITING_FACTORS:
            raise ValueError(f"invalid required_evidence: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        codes = _bounded_blockers(value)
        for code in codes:
            if code not in CONFIDENCE_BLOCKERS:
                raise ValueError(f"invalid blocker code: {code!r}")
        return codes

    @field_validator("source_confidence_plan")
    @classmethod
    def _bounded_confidence(cls, value: object) -> dict:
        return sanitize_source_confidence_plan(value)

    @field_validator("source_priority_plan")
    @classmethod
    def _bounded_priority(cls, value: object) -> dict:
        return sanitize_source_prioritization_plan(value)

    @field_validator("source_acquisition_plan")
    @classmethod
    def _bounded_acquisition(cls, value: object) -> dict:
        return sanitize_source_plan(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "evidence decision plans are research-only"
            )
        return True


def decision_plan_projection(value: EvidenceDecisionPlan) -> dict:
    """Serialize a decision plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EVIDENCE_DECISION_RULE_VERSION",
    "RULE_VERSION",
    "DECISIONS",
    "NEXT_STATES",
    "DECISION_REASONS",
    "SOURCE_CONFIDENCE_KEYS",
    "DECISION_ACCEPT_EVIDENCE",
    "DECISION_CONTINUE_RESEARCH",
    "DECISION_REQUIRE_MORE_EVIDENCE",
    "DECISION_DEFER_RESEARCH",
    "DECISION_UNKNOWN",
    "NEXT_STATE_COMPLETE",
    "NEXT_STATE_ACTIVE_RESEARCH",
    "NEXT_STATE_WAITING_FOR_EVIDENCE",
    "NEXT_STATE_DEFERRED",
    "NEXT_STATE_UNKNOWN",
    "REASON_EVIDENCE_SUFFICIENT",
    "REASON_HIGH_CONFIDENCE",
    "REASON_MISSING_IDENTITY",
    "REASON_MISSING_VERSION",
    "REASON_MISSING_SCOPE",
    "REASON_MISSING_PATH",
    "REASON_MISSING_PARAMETER",
    "REASON_MISSING_HTTP_BEHAVIOR",
    "REASON_MISSING_TECHNOLOGY",
    "REASON_HUMAN_RESEARCH_REQUIRED",
    "REASON_NO_PLAN_AVAILABLE",
    "BLOCKER_MALFORMED_ACQUISITION_PLAN",
    "BLOCKER_MISSING_PRIORITIZATION_ITEM",
    "BLOCKER_NO_ACQUISITION_PLANNED",
    "BLOCKER_PRIORITY_MISALIGNMENT",
    "BLOCKER_UNKNOWN_ACQUISITION_METHOD",
    "LIMITING_UPSTREAM_PLAN",
    "MAX_BLOCKERS",
    "MAX_ITEMS",
    "MAX_VALUE_LEN",
    "EvidenceDecisionPlan",
    "sanitize_source_confidence_plan",
    "decision_plan_projection",
]
