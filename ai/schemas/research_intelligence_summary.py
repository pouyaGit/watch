"""Research intelligence summary schema (Stage R31.20).

A :class:`ResearchIntelligenceSummaryPlan` is the deterministic, read-only
final aggregation over the R31.13-R31.19 evidence pipeline plans. It answers
the owner's personal-research question:

    "What is the final research intelligence status for this candidate?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: research status and summary category are closed
  deterministic sets; evidence status, final state, confidence level,
  feedback signal, improvement area and blocker vocabularies remain owned by
  R31.15/R31.17/R31.18/R31.19 and are imported, never redefined.
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
    CONFIDENCE_BLOCKERS,
    CONFIDENCE_LEVELS,
    EVIDENCE_COMPLETENESS_LEVELS,
)
from ai.schemas.evidence_feedback_calibration import (
    FEEDBACK_TYPES,
    IMPROVEMENT_AREAS,
    sanitize_source_outcome_plan,
)
from ai.schemas.evidence_research_loop import LIFECYCLE_STATES
from ai.schemas.evidence_research_outcome import sanitize_source_loop_plan

RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION = "r31-20"
RULE_VERSION = RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_COMPLETE = "COMPLETE"
STATUS_ACTIVE = "ACTIVE"
STATUS_WAITING = "WAITING"
STATUS_DEFERRED = "DEFERRED"
STATUS_UNKNOWN = "UNKNOWN"

RESEARCH_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETE,
    STATUS_ACTIVE,
    STATUS_WAITING,
    STATUS_DEFERRED,
    STATUS_UNKNOWN,
)

CATEGORY_SUCCESSFUL = "SUCCESSFUL_RESEARCH"
CATEGORY_ONGOING = "ONGOING_RESEARCH"
CATEGORY_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
CATEGORY_PAUSED = "RESEARCH_PAUSED"
CATEGORY_INVALID = "INVALID"

SUMMARY_CATEGORIES: tuple[str, ...] = (
    CATEGORY_SUCCESSFUL,
    CATEGORY_ONGOING,
    CATEGORY_EVIDENCE_REQUIRED,
    CATEGORY_PAUSED,
    CATEGORY_INVALID,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_ITEMS = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.19 plan snapshot.
SOURCE_FEEDBACK_KEYS: tuple[str, ...] = (
    "rule_version",
    "feedback_type",
    "signal_strength",
    "improvement_area",
    "outcome",
    "confidence_level",
    "blockers",
    "research_only",
)

# Fixed, closed key set for the R31.20 plan snapshot used by R31.22.
SUMMARY_PLAN_KEYS: tuple[str, ...] = (
    "rule_version",
    "research_status",
    "evidence_status",
    "confidence_level",
    "final_state",
    "feedback_signal",
    "improvement_area",
    "blockers",
    "summary_category",
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


def sanitize_source_feedback_plan(value: object) -> dict:
    """Project an R31.19 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "feedback_type": "",
            "signal_strength": "",
            "improvement_area": "",
            "outcome": "",
            "confidence_level": "",
            "blockers": [],
            "research_only": True,
        }
    out: dict = {}
    for key in SOURCE_FEEDBACK_KEYS:
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


def sanitize_research_summary_plan(value: object) -> dict:
    """Project an R31.20 plan onto its fixed bounded summary key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "research_status": "",
            "evidence_status": "",
            "confidence_level": "",
            "final_state": "",
            "feedback_signal": "",
            "improvement_area": "",
            "blockers": [],
            "summary_category": "",
            "research_only": True,
        }
    out: dict = {}
    for key in SUMMARY_PLAN_KEYS:
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


class ResearchIntelligenceSummaryPlan(BaseModel):
    """Deterministic final research intelligence aggregation (R31.20)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION
    research_status: str
    evidence_status: str
    confidence_level: str
    final_state: str
    feedback_signal: str
    improvement_area: str
    blockers: list[str] = Field(default_factory=list)
    summary_category: str
    source_feedback_plan: dict = Field(default_factory=dict)
    source_outcome_plan: dict = Field(default_factory=dict)
    source_loop_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION

    @field_validator("research_status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in RESEARCH_STATUSES:
            raise ValueError(f"invalid research_status: {value!r}")
        return text

    @field_validator("evidence_status")
    @classmethod
    def _valid_evidence_status(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in EVIDENCE_COMPLETENESS_LEVELS:
            raise ValueError(f"invalid evidence_status: {value!r}")
        return text

    @field_validator("confidence_level")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence_level: {value!r}")
        return text

    @field_validator("final_state")
    @classmethod
    def _valid_final_state(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in LIFECYCLE_STATES:
            raise ValueError(f"invalid final_state: {value!r}")
        return text

    @field_validator("feedback_signal")
    @classmethod
    def _valid_feedback(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in FEEDBACK_TYPES:
            raise ValueError(f"invalid feedback_signal: {value!r}")
        return text

    @field_validator("improvement_area")
    @classmethod
    def _valid_area(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in IMPROVEMENT_AREAS:
            raise ValueError(f"invalid improvement_area: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        codes = _bounded_blockers(value)
        for code in codes:
            if code not in CONFIDENCE_BLOCKERS:
                raise ValueError(f"invalid blocker code: {code!r}")
        return codes

    @field_validator("summary_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in SUMMARY_CATEGORIES:
            raise ValueError(f"invalid summary_category: {value!r}")
        return text

    @field_validator("source_feedback_plan")
    @classmethod
    def _bounded_feedback(cls, value: object) -> dict:
        return sanitize_source_feedback_plan(value)

    @field_validator("source_outcome_plan")
    @classmethod
    def _bounded_outcome(cls, value: object) -> dict:
        return sanitize_source_outcome_plan(value)

    @field_validator("source_loop_plan")
    @classmethod
    def _bounded_loop(cls, value: object) -> dict:
        return sanitize_source_loop_plan(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "research intelligence summaries are research-only"
            )
        return True


def research_summary_plan_projection(
    value: ResearchIntelligenceSummaryPlan,
) -> dict:
    """Serialize a research intelligence summary to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_INTELLIGENCE_SUMMARY_RULE_VERSION",
    "RULE_VERSION",
    "RESEARCH_STATUSES",
    "SUMMARY_CATEGORIES",
    "SOURCE_FEEDBACK_KEYS",
    "SUMMARY_PLAN_KEYS",
    "STATUS_COMPLETE",
    "STATUS_ACTIVE",
    "STATUS_WAITING",
    "STATUS_DEFERRED",
    "STATUS_UNKNOWN",
    "CATEGORY_SUCCESSFUL",
    "CATEGORY_ONGOING",
    "CATEGORY_EVIDENCE_REQUIRED",
    "CATEGORY_PAUSED",
    "CATEGORY_INVALID",
    "MAX_BLOCKERS",
    "MAX_ITEMS",
    "MAX_VALUE_LEN",
    "ResearchIntelligenceSummaryPlan",
    "sanitize_source_feedback_plan",
    "sanitize_research_summary_plan",
    "research_summary_plan_projection",
]
