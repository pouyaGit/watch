"""Evidence feedback calibration schema (Stage R31.19).

An :class:`EvidenceFeedbackCalibrationPlan` is a deterministic, read-only
feedback projection over one R31.18 Evidence Research Outcome Plan (backed by
the R31.13-R31.17 plans). It answers the owner's personal-research question:

    "What feedback signal does this outcome produce, which research dimension
     needs improvement, and what should future planning stages be aware of?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``. This stage analyzes
  outcome signals only and never changes previous planner behavior.
- Closed vocabularies: feedback type, signal strength and improvement area
  are closed deterministic sets. Outcome, confidence and blocker
  vocabularies remain owned by R31.15/R31.18 and are imported, never
  redefined.
- Bounded, privacy-safe: strings and lists are bounded; all six embedded
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
from ai.schemas.evidence_decision import sanitize_source_confidence_plan
from ai.schemas.evidence_prioritization import sanitize_source_plan
from ai.schemas.evidence_research_loop import sanitize_source_decision_plan
from ai.schemas.evidence_research_outcome import (
    OUTCOMES,
    sanitize_source_loop_plan,
)

EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION = "r31-19"
RULE_VERSION = EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

FEEDBACK_SUCCESS = "SUCCESS_SIGNAL"
FEEDBACK_CONTINUE = "CONTINUE_SIGNAL"
FEEDBACK_EVIDENCE_GAP = "EVIDENCE_GAP_SIGNAL"
FEEDBACK_DEFER = "DEFER_SIGNAL"
FEEDBACK_UNKNOWN = "UNKNOWN"

FEEDBACK_TYPES: tuple[str, ...] = (
    FEEDBACK_SUCCESS,
    FEEDBACK_CONTINUE,
    FEEDBACK_EVIDENCE_GAP,
    FEEDBACK_DEFER,
    FEEDBACK_UNKNOWN,
)

STRENGTH_HIGH = "HIGH"
STRENGTH_MEDIUM = "MEDIUM"
STRENGTH_LOW = "LOW"
STRENGTH_UNKNOWN = "UNKNOWN"

SIGNAL_STRENGTHS: tuple[str, ...] = (
    STRENGTH_HIGH,
    STRENGTH_MEDIUM,
    STRENGTH_LOW,
    STRENGTH_UNKNOWN,
)

AREA_NONE = "NONE"
AREA_IDENTITY = "IDENTITY"
AREA_VERSION = "VERSION"
AREA_SCOPE = "SCOPE"
AREA_PATH = "PATH"
AREA_PARAMETER = "PARAMETER"
AREA_HTTP_BEHAVIOR = "HTTP_BEHAVIOR"
AREA_TECHNOLOGY = "TECHNOLOGY"
AREA_HUMAN_RESEARCH = "HUMAN_RESEARCH"
AREA_PROCESS = "PROCESS"
AREA_UNKNOWN = "UNKNOWN"

IMPROVEMENT_AREAS: tuple[str, ...] = (
    AREA_NONE,
    AREA_IDENTITY,
    AREA_VERSION,
    AREA_SCOPE,
    AREA_PATH,
    AREA_PARAMETER,
    AREA_HTTP_BEHAVIOR,
    AREA_TECHNOLOGY,
    AREA_HUMAN_RESEARCH,
    AREA_PROCESS,
    AREA_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_BLOCKERS = 8
MAX_ITEMS = 8
MAX_VALUE_LEN = 160

# Fixed, closed key set for the embedded R31.18 plan snapshot.
SOURCE_OUTCOME_KEYS: tuple[str, ...] = (
    "rule_version",
    "outcome",
    "outcome_category",
    "completion_state",
    "remaining_need",
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


def sanitize_source_outcome_plan(value: object) -> dict:
    """Project an R31.18 plan onto the fixed bounded snapshot key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "outcome": "",
            "outcome_category": "",
            "completion_state": "",
            "remaining_need": "",
            "blockers": [],
            "research_only": True,
        }
    out: dict = {}
    for key in SOURCE_OUTCOME_KEYS:
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


class EvidenceFeedbackCalibrationPlan(BaseModel):
    """Deterministic feedback calibration over the R31.18 outcome."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION
    feedback_type: str
    signal_strength: str
    improvement_area: str
    outcome: str
    confidence_level: str
    blockers: list[str] = Field(default_factory=list)
    source_outcome_plan: dict = Field(default_factory=dict)
    source_loop_plan: dict = Field(default_factory=dict)
    source_decision_plan: dict = Field(default_factory=dict)
    source_confidence_plan: dict = Field(default_factory=dict)
    source_priority_plan: dict = Field(default_factory=dict)
    source_acquisition_plan: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION

    @field_validator("feedback_type")
    @classmethod
    def _valid_feedback_type(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in FEEDBACK_TYPES:
            raise ValueError(f"invalid feedback_type: {value!r}")
        return text

    @field_validator("signal_strength")
    @classmethod
    def _valid_strength(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in SIGNAL_STRENGTHS:
            raise ValueError(f"invalid signal_strength: {value!r}")
        return text

    @field_validator("improvement_area")
    @classmethod
    def _valid_area(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in IMPROVEMENT_AREAS:
            raise ValueError(f"invalid improvement_area: {value!r}")
        return text

    @field_validator("outcome")
    @classmethod
    def _valid_outcome(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in OUTCOMES:
            raise ValueError(f"invalid outcome: {value!r}")
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

    @field_validator("source_outcome_plan")
    @classmethod
    def _bounded_outcome(cls, value: object) -> dict:
        return sanitize_source_outcome_plan(value)

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
                "evidence feedback calibration plans are research-only"
            )
        return True


def feedback_calibration_plan_projection(
    value: EvidenceFeedbackCalibrationPlan,
) -> dict:
    """Serialize a feedback calibration plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EVIDENCE_FEEDBACK_CALIBRATION_RULE_VERSION",
    "RULE_VERSION",
    "FEEDBACK_TYPES",
    "SIGNAL_STRENGTHS",
    "IMPROVEMENT_AREAS",
    "SOURCE_OUTCOME_KEYS",
    "FEEDBACK_SUCCESS",
    "FEEDBACK_CONTINUE",
    "FEEDBACK_EVIDENCE_GAP",
    "FEEDBACK_DEFER",
    "FEEDBACK_UNKNOWN",
    "STRENGTH_HIGH",
    "STRENGTH_MEDIUM",
    "STRENGTH_LOW",
    "STRENGTH_UNKNOWN",
    "AREA_NONE",
    "AREA_IDENTITY",
    "AREA_VERSION",
    "AREA_SCOPE",
    "AREA_PATH",
    "AREA_PARAMETER",
    "AREA_HTTP_BEHAVIOR",
    "AREA_TECHNOLOGY",
    "AREA_HUMAN_RESEARCH",
    "AREA_PROCESS",
    "AREA_UNKNOWN",
    "MAX_BLOCKERS",
    "MAX_ITEMS",
    "MAX_VALUE_LEN",
    "EvidenceFeedbackCalibrationPlan",
    "sanitize_source_outcome_plan",
    "feedback_calibration_plan_projection",
]
