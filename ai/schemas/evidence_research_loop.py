"""Evidence research loop schema (Stage R31.17).

An :class:`EvidenceResearchLoopPlan` is a deterministic, read-only research
lifecycle projection over one R31.16 Evidence Decision Plan (backed by the
R31.13/R31.14/R31.15 plans). It answers the owner's personal-research
question:

    "What is the current research lifecycle state, should the loop continue,
     what is the next allowed planning phase, and why is this transition
     valid?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: lifecycle state, next phase and transition reason are
  closed deterministic sets. Decision, confidence and blocker vocabularies
  remain owned by R31.15/R31.16 and are imported, never redefined.
- Bounded, privacy-safe: strings and lists are bounded; all four embedded
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
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    sanitize_source_prioritization_plan,
)
from ai.schemas.evidence_decision import (
    DECISIONS,
    sanitize_source_confidence_plan,
)
from ai.schemas.evidence_prioritization import sanitize_source_plan

EVIDENCE_RESEARCH_LOOP_RULE_VERSION = "r31-17"
RULE_VERSION = EVIDENCE_RESEARCH_LOOP_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LIFECYCLE_INITIAL = "INITIAL"
LIFECYCLE_RESEARCH_ACTIVE = "RESEARCH_ACTIVE"
LIFECYCLE_EVIDENCE_READY = "EVIDENCE_READY"
LIFECYCLE_WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
LIFECYCLE_COMPLETED = "COMPLETED"
LIFECYCLE_DEFERRED = "DEFERRED"
LIFECYCLE_UNKNOWN = "UNKNOWN"

LIFECYCLE_STATES: tuple[str, ...] = (
    LIFECYCLE_INITIAL,
    LIFECYCLE_RESEARCH_ACTIVE,
    LIFECYCLE_EVIDENCE_READY,
    LIFECYCLE_WAITING_FOR_EVIDENCE,
    LIFECYCLE_COMPLETED,
    LIFECYCLE_DEFERRED,
    LIFECYCLE_UNKNOWN,
)

PHASE_NONE = "NONE"
PHASE_EVIDENCE_REVIEW = "EVIDENCE_REVIEW"
PHASE_EVIDENCE_COLLECTION_PLANNING = "EVIDENCE_COLLECTION_PLANNING"
PHASE_DECISION_REVIEW = "DECISION_REVIEW"
PHASE_HUMAN_REVIEW = "HUMAN_REVIEW"
PHASE_UNKNOWN = "UNKNOWN"

NEXT_PHASES: tuple[str, ...] = (
    PHASE_NONE,
    PHASE_EVIDENCE_REVIEW,
    PHASE_EVIDENCE_COLLECTION_PLANNING,
    PHASE_DECISION_REVIEW,
    PHASE_HUMAN_REVIEW,
    PHASE_UNKNOWN,
)

REASON_START_RESEARCH = "START_RESEARCH"
REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE = (
    "CONTINUE_AFTER_MEDIUM_CONFIDENCE"
)
REASON_NEED_MORE_EVIDENCE = "NEED_MORE_EVIDENCE"
REASON_EVIDENCE_ACCEPTED = "EVIDENCE_ACCEPTED"
REASON_RESEARCH_DEFERRED = "RESEARCH_DEFERRED"
REASON_INVALID_INPUT = "INVALID_INPUT"

TRANSITION_REASONS: tuple[str, ...] = (
    REASON_START_RESEARCH,
    REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE,
    REASON_NEED_MORE_EVIDENCE,
    REASON_EVIDENCE_ACCEPTED,
    REASON_RESEARCH_DEFERRED,
    REASON_INVALID_INPUT,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_ITEMS = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.16 plan snapshot.
SOURCE_DECISION_KEYS: tuple[str, ...] = (
    "rule_version",
    "decision",
    "decision_reason",
    "confidence_level",
    "next_state",
    "required_evidence",
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


def sanitize_source_decision_plan(value: object) -> dict:
    """Project an R31.16 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "decision": "",
            "decision_reason": "",
            "confidence_level": "",
            "next_state": "",
            "required_evidence": "",
            "blockers": [],
            "research_only": True,
        }
    out: dict = {}
    for key in SOURCE_DECISION_KEYS:
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


class EvidenceResearchLoopPlan(BaseModel):
    """Deterministic research lifecycle projection over R31.16."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EVIDENCE_RESEARCH_LOOP_RULE_VERSION
    lifecycle_state: str
    next_phase: str
    transition_reason: str
    decision: str
    confidence_level: str
    blockers: list[str] = Field(default_factory=list)
    source_decision_plan: dict = Field(default_factory=dict)
    source_confidence_plan: dict = Field(default_factory=dict)
    source_priority_plan: dict = Field(default_factory=dict)
    source_acquisition_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EVIDENCE_RESEARCH_LOOP_RULE_VERSION

    @field_validator("lifecycle_state")
    @classmethod
    def _valid_lifecycle(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in LIFECYCLE_STATES:
            raise ValueError(f"invalid lifecycle_state: {value!r}")
        return text

    @field_validator("next_phase")
    @classmethod
    def _valid_phase(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in NEXT_PHASES:
            raise ValueError(f"invalid next_phase: {value!r}")
        return text

    @field_validator("transition_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in TRANSITION_REASONS:
            raise ValueError(f"invalid transition_reason: {value!r}")
        return text

    @field_validator("decision")
    @classmethod
    def _valid_decision(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in DECISIONS:
            raise ValueError(f"invalid decision: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        codes = _bounded_blockers(value)
        for code in codes:
            if code not in CONFIDENCE_BLOCKERS:
                raise ValueError(f"invalid blocker code: {code!r}")
        return codes

    @field_validator("source_decision_plan")
    @classmethod
    def _bounded_decision(cls, value: object) -> dict:
        return sanitize_source_decision_plan(value)

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
                "evidence research loop plans are research-only"
            )
        return True


def research_loop_plan_projection(value: EvidenceResearchLoopPlan) -> dict:
    """Serialize a research loop plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EVIDENCE_RESEARCH_LOOP_RULE_VERSION",
    "RULE_VERSION",
    "LIFECYCLE_STATES",
    "NEXT_PHASES",
    "TRANSITION_REASONS",
    "SOURCE_DECISION_KEYS",
    "LIFECYCLE_INITIAL",
    "LIFECYCLE_RESEARCH_ACTIVE",
    "LIFECYCLE_EVIDENCE_READY",
    "LIFECYCLE_WAITING_FOR_EVIDENCE",
    "LIFECYCLE_COMPLETED",
    "LIFECYCLE_DEFERRED",
    "LIFECYCLE_UNKNOWN",
    "PHASE_NONE",
    "PHASE_EVIDENCE_REVIEW",
    "PHASE_EVIDENCE_COLLECTION_PLANNING",
    "PHASE_DECISION_REVIEW",
    "PHASE_HUMAN_REVIEW",
    "PHASE_UNKNOWN",
    "REASON_START_RESEARCH",
    "REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE",
    "REASON_NEED_MORE_EVIDENCE",
    "REASON_EVIDENCE_ACCEPTED",
    "REASON_RESEARCH_DEFERRED",
    "REASON_INVALID_INPUT",
    "MAX_BLOCKERS",
    "MAX_ITEMS",
    "MAX_VALUE_LEN",
    "EvidenceResearchLoopPlan",
    "sanitize_source_decision_plan",
    "research_loop_plan_projection",
]
