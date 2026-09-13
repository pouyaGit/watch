"""Evidence research outcome schema (Stage R31.18).

An :class:`EvidenceResearchOutcomePlan` is a deterministic, read-only outcome
projection over one R31.17 Evidence Research Loop Plan (backed by the
R31.13/R31.14/R31.15/R31.16 plans). It answers the owner's personal-research
question:

    "What is the current research outcome, is the research cycle complete,
     is evidence still required, and is the candidate deferred?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Closed vocabularies: outcome, outcome category, completion state and
  remaining need are closed deterministic sets. Blocker and phase vocabularies
  remain owned by R31.15/R31.17 and are imported, never redefined.
- Bounded, privacy-safe: strings and lists are bounded; all five embedded
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
    sanitize_source_prioritization_plan,
)
from ai.schemas.evidence_decision import sanitize_source_confidence_plan
from ai.schemas.evidence_prioritization import sanitize_source_plan
from ai.schemas.evidence_research_loop import sanitize_source_decision_plan

EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION = "r31-18"
RULE_VERSION = EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

OUTCOME_COMPLETED = "COMPLETED"
OUTCOME_IN_PROGRESS = "IN_PROGRESS"
OUTCOME_WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
OUTCOME_DEFERRED = "DEFERRED"
OUTCOME_UNKNOWN = "UNKNOWN"

OUTCOMES: tuple[str, ...] = (
    OUTCOME_COMPLETED,
    OUTCOME_IN_PROGRESS,
    OUTCOME_WAITING_FOR_EVIDENCE,
    OUTCOME_DEFERRED,
    OUTCOME_UNKNOWN,
)

CATEGORY_EVIDENCE_ACCEPTED = "EVIDENCE_ACCEPTED"
CATEGORY_RESEARCH_CONTINUING = "RESEARCH_CONTINUING"
CATEGORY_MORE_EVIDENCE_REQUIRED = "MORE_EVIDENCE_REQUIRED"
CATEGORY_RESEARCH_PAUSED = "RESEARCH_PAUSED"
CATEGORY_INVALID_STATE = "INVALID_STATE"

OUTCOME_CATEGORIES: tuple[str, ...] = (
    CATEGORY_EVIDENCE_ACCEPTED,
    CATEGORY_RESEARCH_CONTINUING,
    CATEGORY_MORE_EVIDENCE_REQUIRED,
    CATEGORY_RESEARCH_PAUSED,
    CATEGORY_INVALID_STATE,
)

COMPLETION_COMPLETE = "COMPLETE"
COMPLETION_PARTIAL = "PARTIAL"
COMPLETION_INCOMPLETE = "INCOMPLETE"
COMPLETION_NONE = "NONE"
COMPLETION_UNKNOWN = "UNKNOWN"

COMPLETION_STATES: tuple[str, ...] = (
    COMPLETION_COMPLETE,
    COMPLETION_PARTIAL,
    COMPLETION_INCOMPLETE,
    COMPLETION_NONE,
    COMPLETION_UNKNOWN,
)

NEED_NONE = "NONE"
NEED_IDENTITY = "IDENTITY"
NEED_VERSION = "VERSION"
NEED_SCOPE = "SCOPE"
NEED_PATH = "PATH"
NEED_PARAMETER = "PARAMETER"
NEED_HTTP_BEHAVIOR = "HTTP_BEHAVIOR"
NEED_TECHNOLOGY = "TECHNOLOGY"
NEED_HUMAN_RESEARCH = "HUMAN_RESEARCH"
NEED_UNKNOWN = "UNKNOWN"

REMAINING_NEEDS: tuple[str, ...] = (
    NEED_NONE,
    NEED_IDENTITY,
    NEED_VERSION,
    NEED_SCOPE,
    NEED_PATH,
    NEED_PARAMETER,
    NEED_HTTP_BEHAVIOR,
    NEED_TECHNOLOGY,
    NEED_HUMAN_RESEARCH,
    NEED_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_ITEMS = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.17 plan snapshot.
SOURCE_LOOP_KEYS: tuple[str, ...] = (
    "rule_version",
    "lifecycle_state",
    "next_phase",
    "transition_reason",
    "decision",
    "confidence_level",
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


def sanitize_source_loop_plan(value: object) -> dict:
    """Project an R31.17 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "lifecycle_state": "",
            "next_phase": "",
            "transition_reason": "",
            "decision": "",
            "confidence_level": "",
            "blockers": [],
            "research_only": True,
        }
    out: dict = {}
    for key in SOURCE_LOOP_KEYS:
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


class EvidenceResearchOutcomePlan(BaseModel):
    """Deterministic research outcome projection over R31.17."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION
    outcome: str
    outcome_category: str
    completion_state: str
    remaining_need: str
    blockers: list[str] = Field(default_factory=list)
    source_loop_plan: dict = Field(default_factory=dict)
    source_decision_plan: dict = Field(default_factory=dict)
    source_confidence_plan: dict = Field(default_factory=dict)
    source_priority_plan: dict = Field(default_factory=dict)
    source_acquisition_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION

    @field_validator("outcome")
    @classmethod
    def _valid_outcome(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in OUTCOMES:
            raise ValueError(f"invalid outcome: {value!r}")
        return text

    @field_validator("outcome_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in OUTCOME_CATEGORIES:
            raise ValueError(f"invalid outcome_category: {value!r}")
        return text

    @field_validator("completion_state")
    @classmethod
    def _valid_completion(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in COMPLETION_STATES:
            raise ValueError(f"invalid completion_state: {value!r}")
        return text

    @field_validator("remaining_need")
    @classmethod
    def _valid_need(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in REMAINING_NEEDS:
            raise ValueError(f"invalid remaining_need: {value!r}")
        return text

    @field_validator("blockers")
    @classmethod
    def _valid_blockers(cls, value: list) -> list[str]:
        codes = _bounded_blockers(value)
        for code in codes:
            if code not in CONFIDENCE_BLOCKERS:
                raise ValueError(f"invalid blocker code: {code!r}")
        return codes

    @field_validator("source_loop_plan")
    @classmethod
    def _bounded_loop(cls, value: object) -> dict:
        return sanitize_source_loop_plan(value)

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
                "evidence research outcome plans are research-only"
            )
        return True


def research_outcome_plan_projection(
    value: EvidenceResearchOutcomePlan,
) -> dict:
    """Serialize a research outcome plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EVIDENCE_RESEARCH_OUTCOME_RULE_VERSION",
    "RULE_VERSION",
    "OUTCOMES",
    "OUTCOME_CATEGORIES",
    "COMPLETION_STATES",
    "REMAINING_NEEDS",
    "SOURCE_LOOP_KEYS",
    "OUTCOME_COMPLETED",
    "OUTCOME_IN_PROGRESS",
    "OUTCOME_WAITING_FOR_EVIDENCE",
    "OUTCOME_DEFERRED",
    "OUTCOME_UNKNOWN",
    "CATEGORY_EVIDENCE_ACCEPTED",
    "CATEGORY_RESEARCH_CONTINUING",
    "CATEGORY_MORE_EVIDENCE_REQUIRED",
    "CATEGORY_RESEARCH_PAUSED",
    "CATEGORY_INVALID_STATE",
    "COMPLETION_COMPLETE",
    "COMPLETION_PARTIAL",
    "COMPLETION_INCOMPLETE",
    "COMPLETION_NONE",
    "COMPLETION_UNKNOWN",
    "NEED_NONE",
    "NEED_IDENTITY",
    "NEED_VERSION",
    "NEED_SCOPE",
    "NEED_PATH",
    "NEED_PARAMETER",
    "NEED_HTTP_BEHAVIOR",
    "NEED_TECHNOLOGY",
    "NEED_HUMAN_RESEARCH",
    "NEED_UNKNOWN",
    "MAX_BLOCKERS",
    "MAX_ITEMS",
    "MAX_VALUE_LEN",
    "EvidenceResearchOutcomePlan",
    "sanitize_source_loop_plan",
    "research_outcome_plan_projection",
]
