"""Agent evaluation score schema (Stage R42.3).

Deterministic, bounded quality scoring model for structured agent results.

The score represents the quality of research output only. It MUST NOT be
interpreted as probability of vulnerability, exploitability, severity,
CVSS or likelihood of compromise.

Hard boundaries encoded here:

- Evaluation only: pure deterministic arithmetic over structured data. No
  execution, no network, no database, no browser, no LLM judgment.
- Rating bands, dimension weights and hard-gate states are closed sets and
  are never configurable at runtime.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_rule import (
    DIMENSION_CONFIDENCE_CALIBRATION,
    DIMENSION_CONTEXT_COMPLETENESS,
    DIMENSION_DETERMINISM,
    DIMENSION_EVIDENCE_COMPLETENESS,
    DIMENSION_GOVERNANCE_COMPLETENESS,
    DIMENSION_HYPOTHESIS_SUPPORT,
    DIMENSION_LIMITATION_DISCLOSURE,
    DIMENSION_PROVENANCE_COMPLETENESS,
    DIMENSION_SAFETY_COMPLIANCE,
    DIMENSION_STRUCTURAL_VALIDITY,
    EVALUATION_DIMENSIONS,
)

AGENT_EVALUATION_SCORE_RULE_VERSION = "r42-3"
RULE_VERSION = AGENT_EVALUATION_SCORE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed rating bands
# ---------------------------------------------------------------------------

RATING_EXCELLENT = "EXCELLENT"
RATING_GOOD = "GOOD"
RATING_ACCEPTABLE = "ACCEPTABLE"
RATING_WEAK = "WEAK"
RATING_CRITICAL = "CRITICAL"

EVALUATION_RATINGS: tuple[str, ...] = (
    RATING_EXCELLENT,
    RATING_GOOD,
    RATING_ACCEPTABLE,
    RATING_WEAK,
    RATING_CRITICAL,
)

# ---------------------------------------------------------------------------
# Fixed dimension weights (percent, total 100) — not runtime configurable
# ---------------------------------------------------------------------------

DIMENSION_WEIGHTS: dict[str, int] = {
    DIMENSION_STRUCTURAL_VALIDITY: 15,
    DIMENSION_CONTEXT_COMPLETENESS: 10,
    DIMENSION_HYPOTHESIS_SUPPORT: 15,
    DIMENSION_EVIDENCE_COMPLETENESS: 10,
    DIMENSION_CONFIDENCE_CALIBRATION: 15,
    DIMENSION_SAFETY_COMPLIANCE: 15,
    DIMENSION_PROVENANCE_COMPLETENESS: 5,
    DIMENSION_GOVERNANCE_COMPLETENESS: 5,
    DIMENSION_DETERMINISM: 5,
    DIMENSION_LIMITATION_DISCLOSURE: 5,
}

TOTAL_WEIGHT = sum(DIMENSION_WEIGHTS.values())

# ---------------------------------------------------------------------------
# Closed hard-gate vocabulary
# ---------------------------------------------------------------------------

HARD_GATE_PASS = "PASS"
HARD_GATE_CEILING_STRUCTURAL = "CEILING_STRUCTURAL"
HARD_GATE_CEILING_SAFETY = "CEILING_SAFETY"
HARD_GATE_FAIL_SAFETY = "FAIL_SAFETY"

HARD_GATE_STATES: tuple[str, ...] = (
    HARD_GATE_PASS,
    HARD_GATE_CEILING_STRUCTURAL,
    HARD_GATE_CEILING_SAFETY,
    HARD_GATE_FAIL_SAFETY,
)

# ---------------------------------------------------------------------------
# Closed safety-state vocabulary
# ---------------------------------------------------------------------------

SAFETY_PASS = "PASS"
SAFETY_DEGRADED = "DEGRADED"
SAFETY_FAILED = "FAILED"

SAFETY_STATES: tuple[str, ...] = (
    SAFETY_PASS,
    SAFETY_DEGRADED,
    SAFETY_FAILED,
)

# ---------------------------------------------------------------------------
# Deterministic thresholds
# ---------------------------------------------------------------------------

CRITICAL_CEILING_SCORE = 39
WEAK_CEILING_SCORE = 59
ACCEPTABLE_CEILING_SCORE = 74
GOOD_CEILING_SCORE = 89

STRUCTURAL_GATE_THRESHOLD = 40
SAFETY_GATE_THRESHOLD = 40
SAFETY_PASS_THRESHOLD = 75

MAX_REASONS = 8
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def rating_for_score(score: object) -> str:
    """Deterministic rating band for a bounded 0-100 score."""

    if isinstance(score, bool) or not isinstance(score, int):
        return RATING_CRITICAL
    bounded = max(0, min(100, score))
    if bounded >= 90:
        return RATING_EXCELLENT
    if bounded >= 75:
        return RATING_GOOD
    if bounded >= 60:
        return RATING_ACCEPTABLE
    if bounded >= 40:
        return RATING_WEAK
    return RATING_CRITICAL


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentEvaluationDimensionScorePlan(BaseModel):
    """Deterministic per-dimension evaluation score (R42.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_EVALUATION_SCORE_RULE_VERSION
    dimension: str
    score: int
    status: str
    weight: int
    reasons: list[str] = Field(default_factory=list)
    passed_rules: list[str] = Field(default_factory=list)
    failed_rules: list[str] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_EVALUATION_SCORE_RULE_VERSION

    @field_validator("dimension")
    @classmethod
    def _valid_dimension(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVALUATION_DIMENSIONS:
            raise ValueError(f"invalid evaluation dimension: {value!r}")
        return text

    @field_validator("score", "weight")
    @classmethod
    def _valid_score(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid integer score: {value!r}")
        if value < 0 or value > 100:
            raise ValueError(f"score out of range: {value!r}")
        return value

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVALUATION_RATINGS:
            raise ValueError(f"invalid rating: {value!r}")
        return text

    @field_validator("reasons")
    @classmethod
    def _valid_reasons(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item)
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_REASONS:
                break
        return out


def agent_evaluation_dimension_score_plan_projection(
    value: AgentEvaluationDimensionScorePlan,
) -> dict:
    """Serialize a dimension score to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_EVALUATION_SCORE_RULE_VERSION",
    "RULE_VERSION",
    "RATING_EXCELLENT",
    "RATING_GOOD",
    "RATING_ACCEPTABLE",
    "RATING_WEAK",
    "RATING_CRITICAL",
    "EVALUATION_RATINGS",
    "DIMENSION_WEIGHTS",
    "TOTAL_WEIGHT",
    "HARD_GATE_PASS",
    "HARD_GATE_CEILING_STRUCTURAL",
    "HARD_GATE_CEILING_SAFETY",
    "HARD_GATE_FAIL_SAFETY",
    "HARD_GATE_STATES",
    "SAFETY_PASS",
    "SAFETY_DEGRADED",
    "SAFETY_FAILED",
    "SAFETY_STATES",
    "CRITICAL_CEILING_SCORE",
    "WEAK_CEILING_SCORE",
    "ACCEPTABLE_CEILING_SCORE",
    "GOOD_CEILING_SCORE",
    "STRUCTURAL_GATE_THRESHOLD",
    "SAFETY_GATE_THRESHOLD",
    "SAFETY_PASS_THRESHOLD",
    "MAX_REASONS",
    "MAX_VALUE_LEN",
    "rating_for_score",
    "AgentEvaluationDimensionScorePlan",
    "agent_evaluation_dimension_score_plan_projection",
]
