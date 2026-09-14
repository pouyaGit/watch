"""Continuous learning result schema (Stage R57.4).

Defines the deterministic R57 continuous-learning result that groups the
bounded signals, patterns and calibration recommendations derived from the
structured R42-R56 research workflow history. It answers:

    "What stable learning patterns and calibration recommendations can be
     extracted for future research?"

Hard boundaries encoded here:

- Learning intelligence only: the result never executes anything, never
  sends requests, never confirms a vulnerability, never authorizes
  execution and never modifies agents, rules, thresholds or strategies.
- Advisory: every recommendation remains advisory; ``auto_applies`` and
  ``execution_authorized`` are forced ``False`` and human authority is
  preserved.
- Human decisions are workflow feedback, never truth labels.
- Conservative: no causality is claimed; absence of structured support
  yields no signal or pattern.
- Closed vocabularies; bounded, privacy-safe, JSON serializable; no
  timestamps, UUIDs, pids or randomness.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.calibration_recommendation import (
    CALIBRATION_LIMITATIONS,
    CALIBRATION_RECOMMENDATION_CODES,
    CalibrationRecommendationPlan,
    sanitize_calibration_recommendation,
)
from ai.schemas.continuous_learning import (
    CONTINUOUS_LEARNING_SIGNAL_TYPES,
    MAX_SIGNALS,
    SOURCE_LAYERS,
)
from ai.schemas.learning_pattern import (
    LEARNING_PATTERN_TYPES,
    MAX_PATTERNS,
    LearningPatternPlan,
    sanitize_learning_pattern,
)
from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

CONTINUOUS_LEARNING_RESULT_RULE_VERSION = "r57-4"
RULE_VERSION = CONTINUOUS_LEARNING_RESULT_RULE_VERSION

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NO_SIGNALS = "NO_SIGNALS"
STATUS_FAILED = "FAILED"

CONTINUOUS_LEARNING_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_NO_SIGNALS,
    STATUS_FAILED,
)

SKIP_MALFORMED_INPUT = "MALFORMED_INPUT"
SKIP_UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
SKIP_RULE_VERSION_MISMATCH = "RULE_VERSION_MISMATCH"
SKIP_SAFETY_BLOCKED = "SAFETY_BLOCKED"
SKIP_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"

CONTINUOUS_LEARNING_SKIP_REASONS: tuple[str, ...] = (
    SKIP_MALFORMED_INPUT,
    SKIP_UNSUPPORTED_INPUT,
    SKIP_RULE_VERSION_MISMATCH,
    SKIP_SAFETY_BLOCKED,
    SKIP_LIMIT_EXCEEDED,
)

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_INPUT = "MALFORMED_INPUT"
ERROR_UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
ERROR_RULE_VERSION_MISMATCH = "RULE_VERSION_MISMATCH"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_CORRELATION_MISMATCH = "CORRELATION_MISMATCH"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

CONTINUOUS_LEARNING_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_INPUT,
    ERROR_UNSUPPORTED_INPUT,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    ERROR_LIMIT_EXCEEDED,
    ERROR_CORRELATION_MISMATCH,
    ERROR_UNKNOWN,
)

LEARNING_ID_PREFIX = "clr-"
LEARNING_ID_RE = re.compile(r"^clr-[0-9a-f]{16}$")

GOVERNANCE_SUMMARY_STATES: tuple[str, ...] = (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

MAX_SKIPPED = 16
MAX_ERRORS = 16
MAX_LIST = 32
MAX_MESSAGE_LEN = 240
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_ids(value: object, limit: int, pattern: str) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if re.match(pattern, text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _count_map(value: object, allowed: tuple, maximum: int) -> dict:
    counts = value if isinstance(value, dict) else {}
    return {
        code: _bounded_int(counts.get(code), 0, maximum) for code in allowed
    }


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in CALIBRATION_LIMITATIONS:
            found.add(text)
    return [code for code in CALIBRATION_LIMITATIONS if code in found]


def sanitize_learning_skip(value: object) -> dict:
    """Project one skipped input onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    return {
        "input_kind": _safe_text(value.get("input_kind")).strip().upper(),
        "reason": _closed(
            value.get("reason"),
            CONTINUOUS_LEARNING_SKIP_REASONS,
            SKIP_MALFORMED_INPUT,
        ),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_learning_error(value: object) -> dict:
    """Project one learning error onto fixed keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in CONTINUOUS_LEARNING_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "input_kind": _safe_text(value.get("input_kind")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_continuous_learning_summary(value: object) -> dict:
    """Project the aggregated learning summary onto fixed keys."""

    if not isinstance(value, dict):
        return _default_summary()
    return {
        "signal_count": _bounded_int(
            value.get("signal_count"), 0, MAX_SIGNALS
        ),
        "pattern_count": _bounded_int(
            value.get("pattern_count"), 0, MAX_PATTERNS
        ),
        "recommendation_count": _bounded_int(
            value.get("recommendation_count"), 0, MAX_PATTERNS
        ),
        "source_layer_counts": _count_map(
            value.get("source_layer_counts"), SOURCE_LAYERS, MAX_SIGNALS
        ),
        "signal_type_counts": _count_map(
            value.get("signal_type_counts"),
            CONTINUOUS_LEARNING_SIGNAL_TYPES,
            MAX_SIGNALS,
        ),
        "pattern_type_counts": _count_map(
            value.get("pattern_type_counts"),
            LEARNING_PATTERN_TYPES,
            MAX_PATTERNS,
        ),
        "recommendation_code_counts": _count_map(
            value.get("recommendation_code_counts"),
            CALIBRATION_RECOMMENDATION_CODES,
            MAX_PATTERNS,
        ),
        "workflow_feedback_signal_count": _bounded_int(
            value.get("workflow_feedback_signal_count"), 0, MAX_SIGNALS
        ),
        "cross_layer_pattern_count": _bounded_int(
            value.get("cross_layer_pattern_count"), 0, MAX_PATTERNS
        ),
        "safety_pattern_count": _bounded_int(
            value.get("safety_pattern_count"), 0, MAX_PATTERNS
        ),
        "human_decision_count": _bounded_int(
            value.get("human_decision_count"), 0, MAX_SIGNALS
        ),
        "research_only": True,
    }


def _default_summary() -> dict:
    return {
        "signal_count": 0,
        "pattern_count": 0,
        "recommendation_count": 0,
        "source_layer_counts": {
            layer: 0 for layer in SOURCE_LAYERS
        },
        "signal_type_counts": {
            signal_type: 0
            for signal_type in CONTINUOUS_LEARNING_SIGNAL_TYPES
        },
        "pattern_type_counts": {
            pattern_type: 0 for pattern_type in LEARNING_PATTERN_TYPES
        },
        "recommendation_code_counts": {
            code: 0 for code in CALIBRATION_RECOMMENDATION_CODES
        },
        "workflow_feedback_signal_count": 0,
        "cross_layer_pattern_count": 0,
        "safety_pattern_count": 0,
        "human_decision_count": 0,
        "research_only": True,
    }


def sanitize_learning_result_provenance(value: object) -> dict:
    """Project container-level learning provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "signal_rule_version": "",
            "pattern_rule_version": "",
            "recommendation_rule_version": "",
            "source_layers": [],
            "orchestration_ids": [],
            "prioritization_ids": [],
            "correlation_ids": [],
            "decision_ids": [],
            "finding_rule_versions": [],
            "deterministic": True,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "signal_rule_version": _safe_text(
            value.get("signal_rule_version")
        ),
        "pattern_rule_version": _safe_text(
            value.get("pattern_rule_version")
        ),
        "recommendation_rule_version": _safe_text(
            value.get("recommendation_rule_version")
        ),
        "source_layers": _bounded_strings(
            value.get("source_layers"), len(SOURCE_LAYERS), 40
        ),
        "orchestration_ids": _bounded_strings(
            value.get("orchestration_ids"), MAX_LIST, 80
        ),
        "prioritization_ids": _bounded_strings(
            value.get("prioritization_ids"), MAX_LIST, 80
        ),
        "correlation_ids": _bounded_strings(
            value.get("correlation_ids"), MAX_LIST, 80
        ),
        "decision_ids": _bounded_ids(
            value.get("decision_ids"), MAX_LIST, r"^hdc-[0-9a-f]{16}$"
        ),
        "finding_rule_versions": _bounded_strings(
            value.get("finding_rule_versions"), MAX_LIST, 40
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_learning_governance(value: object) -> dict:
    """Project the aggregated governance summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "governance_state": GOVERNANCE_UNKNOWN,
            "referenced_finding_ids": [],
            "unknown_finding_ids": [],
            "ready_finding_ids": [],
            "not_ready_finding_ids": [],
            "research_only": True,
        }
    return {
        "governance_state": _closed(
            value.get("governance_state"),
            GOVERNANCE_SUMMARY_STATES,
            GOVERNANCE_UNKNOWN,
        ),
        "referenced_finding_ids": _bounded_ids(
            value.get("referenced_finding_ids"), MAX_SIGNALS,
            r"^fnd-[0-9a-f]{16}$",
        ),
        "unknown_finding_ids": _bounded_ids(
            value.get("unknown_finding_ids"), MAX_SIGNALS,
            r"^fnd-[0-9a-f]{16}$",
        ),
        "ready_finding_ids": _bounded_ids(
            value.get("ready_finding_ids"), MAX_SIGNALS,
            r"^fnd-[0-9a-f]{16}$",
        ),
        "not_ready_finding_ids": _bounded_ids(
            value.get("not_ready_finding_ids"), MAX_SIGNALS,
            r"^fnd-[0-9a-f]{16}$",
        ),
        "research_only": True,
    }


def _bounded_signals(value: object) -> list[dict]:
    from ai.schemas.continuous_learning import (
        ContinuousLearningSignalPlan,
        sanitize_continuous_learning_signal,
    )

    out: list[dict] = []
    for item in value or ():
        try:
            projected = ContinuousLearningSignalPlan(
                **sanitize_continuous_learning_signal(item)
            ).model_dump(mode="json")
        except (TypeError, ValueError):
            continue
        out.append(projected)
        if len(out) >= MAX_SIGNALS:
            break
    return out


def _bounded_patterns(value: object) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        try:
            projected = LearningPatternPlan(
                **sanitize_learning_pattern(item)
            ).model_dump(mode="json")
        except (TypeError, ValueError):
            continue
        out.append(projected)
        if len(out) >= MAX_PATTERNS:
            break
    return out


def _bounded_recommendations(value: object) -> list[dict]:
    out: list[dict] = []
    for item in value or ():
        try:
            projected = CalibrationRecommendationPlan(
                **sanitize_calibration_recommendation(item)
            ).model_dump(mode="json")
        except (TypeError, ValueError):
            continue
        out.append(projected)
        if len(out) >= MAX_PATTERNS:
            break
    return out


def sanitize_continuous_learning_result(value: object) -> dict:
    """Project an R57 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_result()
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "signal_rule_version": _safe_text(
            value.get("signal_rule_version")
        ),
        "pattern_rule_version": _safe_text(
            value.get("pattern_rule_version")
        ),
        "recommendation_rule_version": _safe_text(
            value.get("recommendation_rule_version")
        ),
        "learning_id": _safe_text(value.get("learning_id")),
        "status": _closed(
            value.get("status"),
            CONTINUOUS_LEARNING_STATUSES,
            STATUS_NO_SIGNALS,
        ),
        "signals": _bounded_signals(value.get("signals")),
        "patterns": _bounded_patterns(value.get("patterns")),
        "calibration_recommendations": _bounded_recommendations(
            value.get("calibration_recommendations")
        ),
        "skipped_inputs": [
            projected
            for projected in (
                sanitize_learning_skip(item)
                for item in value.get("skipped_inputs") or ()
            )
            if projected
        ][:MAX_SKIPPED],
        "errors": [
            projected
            for projected in (
                sanitize_learning_error(item)
                for item in value.get("errors") or ()
            )
            if projected
        ][:MAX_ERRORS],
        "summary": sanitize_continuous_learning_summary(
            value.get("summary")
        ),
        "provenance": sanitize_learning_result_provenance(
            value.get("provenance")
        ),
        "governance": sanitize_learning_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "advisory": True,
        "human_authority": True,
        "auto_applies": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


def _default_result() -> dict:
    return {
        "rule_version": "",
        "signal_rule_version": "",
        "pattern_rule_version": "",
        "recommendation_rule_version": "",
        "learning_id": "",
        "status": STATUS_NO_SIGNALS,
        "signals": [],
        "patterns": [],
        "calibration_recommendations": [],
        "skipped_inputs": [],
        "errors": [],
        "summary": _default_summary(),
        "provenance": sanitize_learning_result_provenance(None),
        "governance": sanitize_learning_governance(None),
        "limitations": [],
        "advisory": True,
        "human_authority": True,
        "auto_applies": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ContinuousLearningResultPlan(BaseModel):
    """Deterministic R57 continuous-learning result (R57.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CONTINUOUS_LEARNING_RESULT_RULE_VERSION
    signal_rule_version: str = "r57-1"
    pattern_rule_version: str = "r57-2"
    recommendation_rule_version: str = "r57-3"
    learning_id: str = ""
    status: str = STATUS_NO_SIGNALS
    signals: list[dict] = Field(default_factory=list)
    patterns: list[dict] = Field(default_factory=list)
    calibration_recommendations: list[dict] = Field(default_factory=list)
    skipped_inputs: list[dict] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    advisory: bool = True
    human_authority: bool = True
    auto_applies: bool = False
    execution_authorized: bool = False
    vulnerability_confirmed: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CONTINUOUS_LEARNING_RESULT_RULE_VERSION

    @field_validator(
        "signal_rule_version",
        "pattern_rule_version",
        "recommendation_rule_version",
    )
    @classmethod
    def _bounded_rule(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("learning_id")
    @classmethod
    def _valid_learning_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not LEARNING_ID_RE.match(text):
            raise ValueError(f"malformed learning_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTINUOUS_LEARNING_STATUSES:
            raise ValueError(f"invalid learning status: {value!r}")
        return text

    @field_validator("signals")
    @classmethod
    def _bounded_signals_field(cls, value: object) -> list[dict]:
        return _bounded_signals(value)

    @field_validator("patterns")
    @classmethod
    def _bounded_patterns_field(cls, value: object) -> list[dict]:
        return _bounded_patterns(value)

    @field_validator("calibration_recommendations")
    @classmethod
    def _bounded_recommendations_field(cls, value: object) -> list[dict]:
        return _bounded_recommendations(value)

    @field_validator("skipped_inputs")
    @classmethod
    def _bounded_skipped(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_learning_skip(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_SKIPPED:
                break
        return out

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_learning_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("summary")
    @classmethod
    def _bounded_summary(cls, value: object) -> dict:
        return sanitize_continuous_learning_summary(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_learning_result_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_learning_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("advisory", "human_authority", "research_only",
                     "deterministic")
    @classmethod
    def _true_flags(cls, value: object) -> bool:
        if value is not True:
            raise ValueError(
                "continuous learning results are advisory research-only"
            )
        return True

    @field_validator(
        "auto_applies",
        "execution_authorized",
        "vulnerability_confirmed",
    )
    @classmethod
    def _false_flags(cls, value: object) -> bool:
        if value is not False:
            raise ValueError(
                "continuous learning never changes behavior or authorizes "
                "execution"
            )
        return False

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError(
                "continuous learning never confirms a vulnerability"
            )
        return "NOT_CONFIRMED"


def continuous_learning_result_plan_projection(
    value: ContinuousLearningResultPlan,
) -> dict:
    """Serialize an R57 result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CONTINUOUS_LEARNING_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "CONTINUOUS_LEARNING_STATUSES",
    "CONTINUOUS_LEARNING_SKIP_REASONS",
    "CONTINUOUS_LEARNING_ERROR_CATEGORIES",
    "GOVERNANCE_SUMMARY_STATES",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_NO_SIGNALS",
    "STATUS_FAILED",
    "SKIP_MALFORMED_INPUT",
    "SKIP_UNSUPPORTED_INPUT",
    "SKIP_RULE_VERSION_MISMATCH",
    "SKIP_SAFETY_BLOCKED",
    "SKIP_LIMIT_EXCEEDED",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_INPUT",
    "ERROR_UNSUPPORTED_INPUT",
    "ERROR_RULE_VERSION_MISMATCH",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_CORRELATION_MISMATCH",
    "ERROR_UNKNOWN",
    "LEARNING_ID_PREFIX",
    "LEARNING_ID_RE",
    "MAX_SKIPPED",
    "MAX_ERRORS",
    "MAX_LIST",
    "MAX_MESSAGE_LEN",
    "MAX_VALUE_LEN",
    "sanitize_learning_skip",
    "sanitize_learning_error",
    "sanitize_continuous_learning_summary",
    "sanitize_learning_result_provenance",
    "sanitize_learning_governance",
    "sanitize_continuous_learning_result",
    "ContinuousLearningResultPlan",
    "continuous_learning_result_plan_projection",
]
