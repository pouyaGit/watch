"""Research consistency validation schema (Stage R31.21).

A :class:`ResearchConsistencyValidationPlan` is a deterministic, read-only
consistency report over the complete R31.13-R31.20 evidence pipeline chain.
It answers the owner's personal-research question:

    "Is the complete R31 research chain internally consistent?"

Hard boundaries encoded here:

- Plan-only: nothing is acquired, executed, scanned, crawled, fuzzed or
  contacted; ``research_only`` is forced ``True``.
- Report-only: the validator records detected issues and never repairs,
  rewrites or recomputes any upstream plan.
- Closed vocabularies: validation status, issue codes and checked-stage codes
  are closed deterministic sets. Chain vocabularies remain owned by their
  stages and are imported by the validator, never redefined here.
- Bounded, privacy-safe: strings and lists are bounded; the plan contains
  only closed codes.
- No probability / exploitability / severity / CVSS / payout fields exist;
  unknown fields are rejected (``extra="forbid"``).

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION = "r31-21"
RULE_VERSION = RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

VALIDATION_VALID = "VALID"
VALIDATION_INVALID = "INVALID"
VALIDATION_UNKNOWN = "UNKNOWN"

VALIDATION_STATUSES: tuple[str, ...] = (
    VALIDATION_VALID,
    VALIDATION_INVALID,
    VALIDATION_UNKNOWN,
)

# Missing mandatory stage.
MISSING_ACQUISITION_PLAN = "MISSING_ACQUISITION_PLAN"
MISSING_PRIORITIZATION_PLAN = "MISSING_PRIORITIZATION_PLAN"
MISSING_CONFIDENCE_PLAN = "MISSING_CONFIDENCE_PLAN"
MISSING_DECISION_PLAN = "MISSING_DECISION_PLAN"
MISSING_LOOP_PLAN = "MISSING_LOOP_PLAN"
MISSING_OUTCOME_PLAN = "MISSING_OUTCOME_PLAN"
MISSING_FEEDBACK_PLAN = "MISSING_FEEDBACK_PLAN"
MISSING_SUMMARY_PLAN = "MISSING_SUMMARY_PLAN"

# Invalid vocabulary values.
INVALID_ACQUISITION_METHOD = "INVALID_ACQUISITION_METHOD"
INVALID_PRIORITIZATION_ITEMS = "INVALID_PRIORITIZATION_ITEMS"
INVALID_CONFIDENCE_LEVEL = "INVALID_CONFIDENCE_LEVEL"
INVALID_CONFIDENCE_CATEGORY = "INVALID_CONFIDENCE_CATEGORY"
INVALID_DECISION = "INVALID_DECISION"
INVALID_LIFECYCLE_STATE = "INVALID_LIFECYCLE_STATE"
INVALID_OUTCOME = "INVALID_OUTCOME"
INVALID_FEEDBACK_TYPE = "INVALID_FEEDBACK_TYPE"
INVALID_RESEARCH_STATUS = "INVALID_RESEARCH_STATUS"

# Cross-stage consistency mismatches.
DECISION_LIFECYCLE_MISMATCH = "DECISION_LIFECYCLE_MISMATCH"
LIFECYCLE_OUTCOME_MISMATCH = "LIFECYCLE_OUTCOME_MISMATCH"
OUTCOME_FEEDBACK_MISMATCH = "OUTCOME_FEEDBACK_MISMATCH"
OUTCOME_SUMMARY_MISMATCH = "OUTCOME_SUMMARY_MISMATCH"

DETECTED_ISSUES: tuple[str, ...] = (
    MISSING_ACQUISITION_PLAN,
    MISSING_PRIORITIZATION_PLAN,
    MISSING_CONFIDENCE_PLAN,
    MISSING_DECISION_PLAN,
    MISSING_LOOP_PLAN,
    MISSING_OUTCOME_PLAN,
    MISSING_FEEDBACK_PLAN,
    MISSING_SUMMARY_PLAN,
    INVALID_ACQUISITION_METHOD,
    INVALID_PRIORITIZATION_ITEMS,
    INVALID_CONFIDENCE_LEVEL,
    INVALID_CONFIDENCE_CATEGORY,
    INVALID_DECISION,
    INVALID_LIFECYCLE_STATE,
    INVALID_OUTCOME,
    INVALID_FEEDBACK_TYPE,
    INVALID_RESEARCH_STATUS,
    DECISION_LIFECYCLE_MISMATCH,
    LIFECYCLE_OUTCOME_MISMATCH,
    OUTCOME_FEEDBACK_MISMATCH,
    OUTCOME_SUMMARY_MISMATCH,
)

# Checked stage identifiers (closed, fixed order).
STAGE_ACQUISITION = "R31_13_ACQUISITION"
STAGE_PRIORITIZATION = "R31_14_PRIORITIZATION"
STAGE_CONFIDENCE = "R31_15_CONFIDENCE"
STAGE_DECISION = "R31_16_DECISION"
STAGE_LOOP = "R31_17_LOOP"
STAGE_OUTCOME = "R31_18_OUTCOME"
STAGE_FEEDBACK = "R31_19_FEEDBACK"
STAGE_SUMMARY = "R31_20_SUMMARY"

CHECKED_STAGES: tuple[str, ...] = (
    STAGE_ACQUISITION,
    STAGE_PRIORITIZATION,
    STAGE_CONFIDENCE,
    STAGE_DECISION,
    STAGE_LOOP,
    STAGE_OUTCOME,
    STAGE_FEEDBACK,
    STAGE_SUMMARY,
)

# Fixed, closed key set for the R31.21 plan snapshot used by R31.22.
VALIDATION_PLAN_KEYS: tuple[str, ...] = (
    "rule_version",
    "valid",
    "validation_status",
    "detected_issues",
    "checked_stages",
    "research_only",
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_ISSUES = 16
MAX_STAGES = 8
MAX_VALUE_LEN = 160

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


def _bounded_codes(
    value: object, allowed: tuple, limit: int
) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_consistency_validation_plan(value: object) -> dict:
    """Project an R31.21 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "valid": False,
            "validation_status": "",
            "detected_issues": [],
            "checked_stages": [],
            "research_only": True,
        }
    out: dict = {}
    for key in VALIDATION_PLAN_KEYS:
        if key not in value:
            continue
        raw = value.get(key)
        if key == "valid":
            out[key] = bool(raw)
        elif key == "detected_issues":
            out[key] = _bounded_codes(raw, DETECTED_ISSUES, MAX_ISSUES)
        elif key == "checked_stages":
            out[key] = _bounded_codes(raw, CHECKED_STAGES, MAX_STAGES)
        elif key == "research_only":
            out[key] = True
        else:
            out[key] = _safe_text(raw)
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ResearchConsistencyValidationPlan(BaseModel):
    """Deterministic consistency report over the complete R31 chain."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION
    valid: bool
    validation_status: str
    detected_issues: list[str] = Field(default_factory=list)
    checked_stages: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION

    @field_validator("validation_status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _closed_token(value)
        if text not in VALIDATION_STATUSES:
            raise ValueError(f"invalid validation_status: {value!r}")
        return text

    @field_validator("detected_issues")
    @classmethod
    def _valid_issues(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item)
            if not text:
                continue
            if text not in DETECTED_ISSUES:
                raise ValueError(f"invalid issue code: {text!r}")
            if text not in out:
                out.append(text)
            if len(out) >= MAX_ISSUES:
                break
        return out

    @field_validator("checked_stages")
    @classmethod
    def _valid_stages(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item)
            if not text:
                continue
            if text not in CHECKED_STAGES:
                raise ValueError(f"invalid checked stage: {text!r}")
            if text not in out:
                out.append(text)
            if len(out) >= MAX_STAGES:
                break
        return out

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "consistency validation plans are research-only"
            )
        return True


def consistency_validation_plan_projection(
    value: ResearchConsistencyValidationPlan,
) -> dict:
    """Serialize a consistency validation plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION",
    "RULE_VERSION",
    "VALIDATION_STATUSES",
    "DETECTED_ISSUES",
    "CHECKED_STAGES",
    "VALIDATION_PLAN_KEYS",
    "VALIDATION_VALID",
    "VALIDATION_INVALID",
    "VALIDATION_UNKNOWN",
    "MISSING_ACQUISITION_PLAN",
    "MISSING_PRIORITIZATION_PLAN",
    "MISSING_CONFIDENCE_PLAN",
    "MISSING_DECISION_PLAN",
    "MISSING_LOOP_PLAN",
    "MISSING_OUTCOME_PLAN",
    "MISSING_FEEDBACK_PLAN",
    "MISSING_SUMMARY_PLAN",
    "INVALID_ACQUISITION_METHOD",
    "INVALID_PRIORITIZATION_ITEMS",
    "INVALID_CONFIDENCE_LEVEL",
    "INVALID_CONFIDENCE_CATEGORY",
    "INVALID_DECISION",
    "INVALID_LIFECYCLE_STATE",
    "INVALID_OUTCOME",
    "INVALID_FEEDBACK_TYPE",
    "INVALID_RESEARCH_STATUS",
    "DECISION_LIFECYCLE_MISMATCH",
    "LIFECYCLE_OUTCOME_MISMATCH",
    "OUTCOME_FEEDBACK_MISMATCH",
    "OUTCOME_SUMMARY_MISMATCH",
    "STAGE_ACQUISITION",
    "STAGE_PRIORITIZATION",
    "STAGE_CONFIDENCE",
    "STAGE_DECISION",
    "STAGE_LOOP",
    "STAGE_OUTCOME",
    "STAGE_FEEDBACK",
    "STAGE_SUMMARY",
    "MAX_ISSUES",
    "MAX_STAGES",
    "MAX_VALUE_LEN",
    "ResearchConsistencyValidationPlan",
    "sanitize_consistency_validation_plan",
    "consistency_validation_plan_projection",
]
