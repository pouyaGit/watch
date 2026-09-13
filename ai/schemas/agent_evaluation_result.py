"""Agent evaluation result schema (Stage R42.5).

An :class:`AgentEvaluationResultPlan` is the final deterministic,
research-only evaluation artifact for a structured agent result. It answers:

    "How good is this structured research result?"

It does NOT answer whether a vulnerability is real, exploitable or should be
attacked. The score is a research-output quality score only.

Hard boundaries encoded here:

- Evaluation only: no execution, no network, no SQL, no database, no
  browser, no LLM judgment, no payloads, no exploit verification.
- Overall rating, dimension scores, hard-gate states and safety states are
  closed sets with fixed deterministic weights and thresholds.
- ``deterministic`` and ``research_only`` are always true.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_diagnostic import (
    AgentEvaluationDiagnosticPlan,
    DIAGNOSTIC_CODES,
)
from ai.schemas.agent_evaluation_score import (
    AgentEvaluationDimensionScorePlan,
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
    SAFETY_STATES,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

AGENT_EVALUATION_RESULT_RULE_VERSION = "r42-5"
RULE_VERSION = AGENT_EVALUATION_RESULT_RULE_VERSION

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_EVIDENCE_COLLECTED = "NO_EVIDENCE_COLLECTED"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_QUALITY_EVALUATION_ONLY = "QUALITY_EVALUATION_ONLY"

EVALUATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_EVIDENCE_COLLECTED,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_QUALITY_EVALUATION_ONLY,
)

MAX_DIMENSION_SCORES = 10
MAX_DIAGNOSTICS = 32
MAX_CAPS = 4
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_dimension_scores(value: object) -> list[dict]:
    out: list[dict] = []
    raw = value if isinstance(value, (list, tuple)) else []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            plan = AgentEvaluationDimensionScorePlan(**item)
        except Exception:
            continue
        out.append(plan.model_dump(mode="json"))
        if len(out) >= MAX_DIMENSION_SCORES:
            break
    return out


def _bounded_diagnostics(value: object) -> list[dict]:
    out: list[dict] = []
    raw = value if isinstance(value, (list, tuple)) else []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            plan = AgentEvaluationDiagnosticPlan(**item)
        except Exception:
            continue
        out.append(plan.model_dump(mode="json"))
        if len(out) >= MAX_DIAGNOSTICS:
            break
    return out


def _bounded_limitations(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in EVALUATION_LIMITATIONS and text not in out:
            out.append(text)
        if len(out) >= MAX_LIMITATIONS:
            break
    return out


def sanitize_agent_evaluation_result_plan(value: object) -> dict:
    """Project an R42.5 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evaluation_rule_version": "",
            "evaluated_agent_id": "",
            "evaluated_agent_category": "UNKNOWN",
            "evaluated_agent_rule_version": "",
            "evaluated_result_rule_version": "",
            "overall_score": 0,
            "overall_rating": "CRITICAL",
            "dimension_scores": [],
            "diagnostics": [],
            "hard_gate_state": "PASS",
            "safety_state": "PASS",
            "applied_caps": [],
            "deterministic": True,
            "research_only": True,
            "limitations": [],
        }
    category = _safe_text(
        value.get("evaluated_agent_category")
    ).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    rating = _safe_text(value.get("overall_rating")).strip().upper()
    if rating not in EVALUATION_RATINGS:
        rating = "CRITICAL"
    gate = _safe_text(value.get("hard_gate_state")).strip().upper()
    if gate not in HARD_GATE_STATES:
        gate = "PASS"
    safety = _safe_text(value.get("safety_state")).strip().upper()
    if safety not in SAFETY_STATES:
        safety = "FAILED"
    score = value.get("overall_score")
    if isinstance(score, bool) or not isinstance(score, int):
        score = 0
    score = max(0, min(100, score))
    caps: list[str] = []
    for item in value.get("applied_caps") or ():
        text = _safe_text(item).strip().upper()
        if text in HARD_GATE_STATES and text not in caps:
            caps.append(text)
        if len(caps) >= MAX_CAPS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evaluation_rule_version": _safe_text(
            value.get("evaluation_rule_version")
        ),
        "evaluated_agent_id": _safe_text(value.get("evaluated_agent_id")),
        "evaluated_agent_category": category,
        "evaluated_agent_rule_version": _safe_text(
            value.get("evaluated_agent_rule_version")
        ),
        "evaluated_result_rule_version": _safe_text(
            value.get("evaluated_result_rule_version")
        ),
        "overall_score": score,
        "overall_rating": rating,
        "dimension_scores": _bounded_dimension_scores(
            value.get("dimension_scores")
        ),
        "diagnostics": _bounded_diagnostics(value.get("diagnostics")),
        "hard_gate_state": gate,
        "safety_state": safety,
        "applied_caps": caps,
        "deterministic": bool(value.get("deterministic", True)) is True,
        "research_only": bool(value.get("research_only", True)) is True,
        "limitations": _bounded_limitations(value.get("limitations")),
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentEvaluationResultPlan(BaseModel):
    """Final deterministic agent evaluation result (R42.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_EVALUATION_RESULT_RULE_VERSION
    evaluation_rule_version: str = AGENT_EVALUATION_RESULT_RULE_VERSION
    evaluated_agent_id: str = ""
    evaluated_agent_category: str = "UNKNOWN"
    evaluated_agent_rule_version: str = ""
    evaluated_result_rule_version: str = ""
    overall_score: int = 0
    overall_rating: str = "CRITICAL"
    dimension_scores: list[dict] = Field(default_factory=list)
    diagnostics: list[dict] = Field(default_factory=list)
    hard_gate_state: str = "PASS"
    safety_state: str = "PASS"
    applied_caps: list[str] = Field(default_factory=list)
    deterministic: bool = True
    research_only: bool = True
    limitations: list[str] = Field(default_factory=list)

    @field_validator("rule_version", "evaluation_rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_EVALUATION_RESULT_RULE_VERSION

    @field_validator("evaluated_agent_id")
    @classmethod
    def _bounded_agent_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("evaluated_agent_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid evaluated_agent_category: {value!r}")
        return text

    @field_validator(
        "evaluated_agent_rule_version", "evaluated_result_rule_version"
    )
    @classmethod
    def _bounded_rule_version(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("overall_score")
    @classmethod
    def _valid_overall_score(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid overall_score: {value!r}")
        if value < 0 or value > 100:
            raise ValueError(f"overall_score out of range: {value!r}")
        return value

    @field_validator("overall_rating")
    @classmethod
    def _valid_rating(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVALUATION_RATINGS:
            raise ValueError(f"invalid overall_rating: {value!r}")
        return text

    @field_validator("dimension_scores")
    @classmethod
    def _valid_dimension_scores(cls, value: list) -> list[dict]:
        return _bounded_dimension_scores(value)

    @field_validator("diagnostics")
    @classmethod
    def _valid_diagnostics(cls, value: list) -> list[dict]:
        return _bounded_diagnostics(value)

    @field_validator("hard_gate_state")
    @classmethod
    def _valid_gate(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HARD_GATE_STATES:
            raise ValueError(f"invalid hard_gate_state: {value!r}")
        return text

    @field_validator("safety_state")
    @classmethod
    def _valid_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SAFETY_STATES:
            raise ValueError(f"invalid safety_state: {value!r}")
        return text

    @field_validator("applied_caps")
    @classmethod
    def _valid_caps(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item).strip().upper()
            if text in HARD_GATE_STATES and text not in out:
                out.append(text)
            if len(out) >= MAX_CAPS:
                break
        return out

    @field_validator("deterministic", "research_only")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError("evaluation results are deterministic and "
                             "research-only")
        return True

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _bounded_limitations(value)


def agent_evaluation_result_plan_projection(
    value: AgentEvaluationResultPlan,
) -> dict:
    """Serialize an evaluation result to a deterministic dict."""

    return value.model_dump(mode="json")


# Re-export diagnostic codes for convenience to callers of this schema.
DIAGNOSTIC_CODES_REFERENCE = DIAGNOSTIC_CODES

__all__ = [
    "AGENT_EVALUATION_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_EVIDENCE_COLLECTED",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_QUALITY_EVALUATION_ONLY",
    "EVALUATION_LIMITATIONS",
    "MAX_DIMENSION_SCORES",
    "MAX_DIAGNOSTICS",
    "MAX_CAPS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_agent_evaluation_result_plan",
    "AgentEvaluationResultPlan",
    "agent_evaluation_result_plan_projection",
]
