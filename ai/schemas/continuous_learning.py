"""Continuous learning signal schema (Stage R57.1).

Defines the bounded, deterministic continuous-learning signal extracted from
one structured research-workflow observation (R42-R56). It answers:

    "What normalized observation does this research outcome contribute to
     future learning?"

Hard boundaries encoded here:

- Learning intelligence only: a signal is a normalized advisory observation.
  It never executes anything, never confirms a vulnerability, never
  authorizes execution or exploitation, and never modifies agents, rules,
  thresholds, prompts, models or strategies.
- Human decisions are workflow feedback, not truth labels: a signal derived
  from an R56 human decision forces ``feedback_kind = WORKFLOW_FEEDBACK``,
  ``truth_label = False`` and preserves the R56 authority context
  (source, authority, confirmation and authorization flags).
- Conservative: a signal only records what the structured input supports;
  no causal claim is made and no value is invented.
- Provenance and governance are preserved references, never fabricated.
- Closed vocabularies; bounded, privacy-safe, JSON serializable; no
  timestamps, UUIDs, pids or randomness.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.finding_result import sanitize_finding_governance
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

CONTINUOUS_LEARNING_RULE_VERSION = "r57-1"
RULE_VERSION = CONTINUOUS_LEARNING_RULE_VERSION

# ---------------------------------------------------------------------------
# Signal vocabulary (closed)
# ---------------------------------------------------------------------------

SIGNAL_REPEATED_EVIDENCE_GAP = "REPEATED_EVIDENCE_GAP"
SIGNAL_REPEATED_CONTEXT_GAP = "REPEATED_CONTEXT_GAP"
SIGNAL_REPEATED_WEAK_HYPOTHESIS = "REPEATED_WEAK_HYPOTHESIS"
SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION = (
    "RECURRING_CONFIDENCE_OVERESTIMATION"
)
SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION = (
    "RECURRING_CONFIDENCE_UNDERESTIMATION"
)
SIGNAL_REPEATED_DUPLICATION = "REPEATED_DUPLICATION"
SIGNAL_RECURRING_CONFLICT = "RECURRING_CONFLICT"
SIGNAL_REPEATED_GOVERNANCE_ISSUE = "REPEATED_GOVERNANCE_ISSUE"
SIGNAL_REPEATED_PROVENANCE_ISSUE = "REPEATED_PROVENANCE_ISSUE"
SIGNAL_REPEATED_SAFETY_ISSUE = "REPEATED_SAFETY_ISSUE"
SIGNAL_REPEATED_QUALITY_ISSUE = "REPEATED_QUALITY_ISSUE"
SIGNAL_SUCCESSFUL_RESEARCH_PATTERN = "SUCCESSFUL_RESEARCH_PATTERN"
SIGNAL_SPECIALIST_RELIABILITY = "SPECIALIST_RELIABILITY"
SIGNAL_PRIORITIZATION_MISMATCH = "PRIORITIZATION_MISMATCH"
SIGNAL_HUMAN_APPROVED_RESEARCH = "HUMAN_APPROVED_RESEARCH"
SIGNAL_HUMAN_REQUESTED_EVIDENCE = "HUMAN_REQUESTED_EVIDENCE"
SIGNAL_HUMAN_DEFERRED_RESEARCH = "HUMAN_DEFERRED_RESEARCH"
SIGNAL_HUMAN_REJECTED_WORKFLOW = "HUMAN_REJECTED_WORKFLOW"
SIGNAL_HUMAN_ESCALATED_RESEARCH = "HUMAN_ESCALATED_RESEARCH"
SIGNAL_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"

CONTINUOUS_LEARNING_SIGNAL_TYPES: tuple[str, ...] = (
    SIGNAL_REPEATED_EVIDENCE_GAP,
    SIGNAL_REPEATED_CONTEXT_GAP,
    SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION,
    SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION,
    SIGNAL_REPEATED_DUPLICATION,
    SIGNAL_RECURRING_CONFLICT,
    SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    SIGNAL_REPEATED_PROVENANCE_ISSUE,
    SIGNAL_REPEATED_SAFETY_ISSUE,
    SIGNAL_REPEATED_QUALITY_ISSUE,
    SIGNAL_SUCCESSFUL_RESEARCH_PATTERN,
    SIGNAL_SPECIALIST_RELIABILITY,
    SIGNAL_PRIORITIZATION_MISMATCH,
    SIGNAL_HUMAN_APPROVED_RESEARCH,
    SIGNAL_HUMAN_REQUESTED_EVIDENCE,
    SIGNAL_HUMAN_DEFERRED_RESEARCH,
    SIGNAL_HUMAN_REJECTED_WORKFLOW,
    SIGNAL_HUMAN_ESCALATED_RESEARCH,
    SIGNAL_HUMAN_REVIEW_REQUIRED,
)

# ---------------------------------------------------------------------------
# Source-layer vocabulary (closed)
# ---------------------------------------------------------------------------

SOURCE_LAYER_R42 = "R42_EVALUATION"
SOURCE_LAYER_R43 = "R43_COLLABORATION"
SOURCE_LAYER_R44 = "R44_FEEDBACK"
SOURCE_LAYER_R53 = "R53_FINDING"
SOURCE_LAYER_R54 = "R54_CORRELATION"
SOURCE_LAYER_R55 = "R55_PRIORITIZATION"
SOURCE_LAYER_R56 = "R56_HUMAN_DECISION"

SOURCE_LAYERS: tuple[str, ...] = (
    SOURCE_LAYER_R42,
    SOURCE_LAYER_R43,
    SOURCE_LAYER_R44,
    SOURCE_LAYER_R53,
    SOURCE_LAYER_R54,
    SOURCE_LAYER_R55,
    SOURCE_LAYER_R56,
)

# ---------------------------------------------------------------------------
# Observation / feedback vocabulary (closed)
# ---------------------------------------------------------------------------

OBSERVATION_ISSUE = "ISSUE"
OBSERVATION_SUCCESS = "SUCCESS"
OBSERVATION_WORKFLOW_FEEDBACK = "WORKFLOW_FEEDBACK"
OBSERVATION_NEUTRAL = "OBSERVATION"

OBSERVATIONS: tuple[str, ...] = (
    OBSERVATION_ISSUE,
    OBSERVATION_SUCCESS,
    OBSERVATION_WORKFLOW_FEEDBACK,
    OBSERVATION_NEUTRAL,
)

FEEDBACK_KIND_WORKFLOW = "WORKFLOW_FEEDBACK"
FEEDBACK_KIND_QUALITY = "QUALITY_OBSERVATION"

FEEDBACK_KINDS: tuple[str, ...] = (
    FEEDBACK_KIND_WORKFLOW,
    FEEDBACK_KIND_QUALITY,
)

STRENGTH_WEAK = "WEAK"
STRENGTH_MODERATE = "MODERATE"
STRENGTH_STRONG = "STRONG"

EVIDENCE_STRENGTHS: tuple[str, ...] = (
    STRENGTH_WEAK,
    STRENGTH_MODERATE,
    STRENGTH_STRONG,
)

STRENGTH_ORDER: dict[str, int] = {
    STRENGTH_WEAK: 0,
    STRENGTH_MODERATE: 1,
    STRENGTH_STRONG: 2,
}

# ---------------------------------------------------------------------------
# Signal limitation vocabulary (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"
LIMITATION_NO_AGENT_MODIFICATION = "NO_AGENT_MODIFICATION"
LIMITATION_NO_RULE_MODIFICATION = "NO_RULE_MODIFICATION"
LIMITATION_NO_THRESHOLD_MODIFICATION = "NO_THRESHOLD_MODIFICATION"
LIMITATION_NO_STRATEGY_MODIFICATION = "NO_STRATEGY_MODIFICATION"
LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL = (
    "HUMAN_DECISION_NOT_TRUTH_LABEL"
)
LIMITATION_NO_CAUSALITY_CLAIM = "NO_CAUSALITY_CLAIM"
LIMITATION_CORRELATION_NOT_CAUSALITY = "CORRELATION_NOT_CAUSALITY"
LIMITATION_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
LIMITATION_UNSUPPORTED_INPUT = "UNSUPPORTED_INPUT"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
LIMITATION_SINGLE_OBSERVATION = "SINGLE_OBSERVATION"

CONTINUOUS_LEARNING_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_NO_AGENT_MODIFICATION,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_NO_THRESHOLD_MODIFICATION,
    LIMITATION_NO_STRATEGY_MODIFICATION,
    LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL,
    LIMITATION_NO_CAUSALITY_CLAIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_SINGLE_OBSERVATION,
    LIMITATION_INSUFFICIENT_DATA,
    LIMITATION_UNSUPPORTED_INPUT,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_PROVENANCE_INCOMPLETE,
)

# ---------------------------------------------------------------------------
# Bounds and ids
# ---------------------------------------------------------------------------

SIGNAL_ID_PREFIX = "cls-"
SIGNAL_ID_RE = re.compile(r"^cls-[0-9a-f]{16}$")

MAX_SIGNALS = 64
MAX_REFERENCES = 12
MAX_LIMITATIONS = 24
MAX_LIST = 24
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


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def _ordered_limitations(codes: object) -> list[str]:
    return _ordered_codes(
        codes, CONTINUOUS_LEARNING_LIMITATIONS, MAX_LIMITATIONS
    )


def sanitize_learning_reference(value: object) -> dict:
    """Project a bounded provenance reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "prioritization_id": "",
            "correlation_id": "",
            "orchestration_id": "",
            "decision_id": "",
            "source_rule_version": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "priority_rule_version": "",
            "decision_rule_version": "",
            "research_only": True,
        }
    return {
        "prioritization_id": _safe_text(value.get("prioritization_id")),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "decision_id": _safe_text(value.get("decision_id")),
        "source_rule_version": _safe_text(
            value.get("source_rule_version")
        ),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "priority_rule_version": _safe_text(
            value.get("priority_rule_version")
        ),
        "decision_rule_version": _safe_text(
            value.get("decision_rule_version")
        ),
        "research_only": True,
    }


def sanitize_decision_context(value: object) -> dict:
    """Project the R56 human authority context onto fixed keys.

    The context is preserved read-only: human decisions are workflow
    feedback, never truth labels, and never authorize execution.
    """

    if not isinstance(value, dict):
        return {
            "present": False,
            "decision_source": "",
            "decision_authority": "",
            "human_authority": False,
            "execution_authorized": False,
            "vulnerability_confirmed": False,
            "exploit_authorized": False,
            "confirmation_state": "NOT_CONFIRMED",
            "truth_label": False,
            "research_only": True,
        }
    return {
        "present": bool(value.get("present")) is True,
        "decision_source": _safe_text(
            value.get("decision_source")
        ).strip().upper(),
        "decision_authority": _safe_text(
            value.get("decision_authority")
        ).strip().upper(),
        "human_authority": bool(value.get("human_authority")) is True,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "truth_label": False,
        "research_only": True,
    }


def sanitize_continuous_learning_signal(value: object) -> dict:
    """Project a continuous learning signal onto its fixed bounded keys."""

    if not isinstance(value, dict):
        return _default_signal()
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    decision_id = _safe_text(value.get("decision_id"))
    if decision_id and not re.match(r"^hdc-[0-9a-f]{16}$", decision_id):
        decision_id = ""
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    feedback_kind = _closed(
        value.get("feedback_kind"),
        FEEDBACK_KINDS,
        FEEDBACK_KIND_QUALITY,
    )
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "signal_id": _safe_text(value.get("signal_id")),
        "signal_type": _closed(
            value.get("signal_type"),
            CONTINUOUS_LEARNING_SIGNAL_TYPES,
            "",
        ),
        "source_layer": _closed(value.get("source_layer"), SOURCE_LAYERS, ""),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": _safe_text(value.get("agent_id")),
        "finding_id": finding_id,
        "decision_id": decision_id,
        "subject_reference": _safe_text(
            value.get("subject_reference"), 120
        ),
        "observation": _closed(
            value.get("observation"), OBSERVATIONS, OBSERVATION_NEUTRAL
        ),
        "feedback_kind": feedback_kind,
        "evidence_strength": _closed(
            value.get("evidence_strength"),
            EVIDENCE_STRENGTHS,
            STRENGTH_WEAK,
        ),
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "supporting_references": _bounded_strings(
            value.get("supporting_references"), MAX_REFERENCES, 120
        ),
        "workflow_feedback": feedback_kind == FEEDBACK_KIND_WORKFLOW,
        "truth_label": False,
        "confirmation_state": "NOT_CONFIRMED",
        "execution_authorized": False,
        "decision_context": sanitize_decision_context(
            value.get("decision_context")
        ),
        "provenance": sanitize_learning_reference(value.get("provenance")),
        "governance": sanitize_finding_governance(value.get("governance")),
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
        "deterministic": True,
    }


def _default_signal() -> dict:
    return {
        "rule_version": "",
        "signal_id": "",
        "signal_type": "",
        "source_layer": "",
        "category": "UNKNOWN",
        "specialist_name": "",
        "agent_id": "",
        "finding_id": "",
        "decision_id": "",
        "subject_reference": "",
        "observation": OBSERVATION_NEUTRAL,
        "feedback_kind": FEEDBACK_KIND_QUALITY,
        "evidence_strength": STRENGTH_WEAK,
        "confidence": "UNKNOWN",
        "supporting_references": [],
        "workflow_feedback": False,
        "truth_label": False,
        "confirmation_state": "NOT_CONFIRMED",
        "execution_authorized": False,
        "decision_context": sanitize_decision_context(None),
        "provenance": sanitize_learning_reference(None),
        "governance": sanitize_finding_governance(None),
        "limitations": [],
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ContinuousLearningSignalPlan(BaseModel):
    """Deterministic continuous-learning signal (R57.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = CONTINUOUS_LEARNING_RULE_VERSION
    signal_id: str
    signal_type: str
    source_layer: str
    category: str = "UNKNOWN"
    specialist_name: str = ""
    agent_id: str = ""
    finding_id: str = ""
    decision_id: str = ""
    subject_reference: str = ""
    observation: str = OBSERVATION_NEUTRAL
    feedback_kind: str = FEEDBACK_KIND_QUALITY
    evidence_strength: str = STRENGTH_WEAK
    confidence: str = "UNKNOWN"
    supporting_references: list[str] = Field(default_factory=list)
    workflow_feedback: bool = False
    truth_label: bool = False
    confirmation_state: str = "NOT_CONFIRMED"
    execution_authorized: bool = False
    decision_context: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return CONTINUOUS_LEARNING_RULE_VERSION

    @field_validator("signal_id")
    @classmethod
    def _valid_signal_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not SIGNAL_ID_RE.match(text):
            raise ValueError(f"malformed signal_id: {value!r}")
        return text

    @field_validator("signal_type")
    @classmethod
    def _valid_signal_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONTINUOUS_LEARNING_SIGNAL_TYPES:
            raise ValueError(f"invalid signal_type: {value!r}")
        return text

    @field_validator("source_layer")
    @classmethod
    def _valid_source_layer(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SOURCE_LAYERS:
            raise ValueError(f"invalid source_layer: {value!r}")
        return text

    @field_validator("category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid category: {value!r}")
        return text

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("decision_id")
    @classmethod
    def _valid_decision_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not re.match(r"^hdc-[0-9a-f]{16}$", text):
            raise ValueError(f"malformed decision_id: {value!r}")
        return text

    @field_validator("observation")
    @classmethod
    def _valid_observation(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OBSERVATIONS:
            raise ValueError(f"invalid observation: {value!r}")
        return text

    @field_validator("feedback_kind")
    @classmethod
    def _valid_feedback_kind(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FEEDBACK_KINDS:
            raise ValueError(f"invalid feedback_kind: {value!r}")
        return text

    @field_validator("evidence_strength")
    @classmethod
    def _valid_strength(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STRENGTHS:
            raise ValueError(f"invalid evidence_strength: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("truth_label")
    @classmethod
    def _never_truth_label(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("learning signals are never truth labels")
        return False

    @field_validator("workflow_feedback")
    @classmethod
    def _workflow_feedback_is_bool(cls, value: object) -> bool:
        if not isinstance(value, bool):
            raise ValueError("workflow_feedback must be a boolean")
        return value

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NOT_CONFIRMED":
            raise ValueError("learning signals never confirm a vulnerability")
        return "NOT_CONFIRMED"

    @field_validator("execution_authorized")
    @classmethod
    def _never_authorized(cls, value: object) -> bool:
        if value is not False:
            raise ValueError("learning signals never authorize execution")
        return False

    @field_validator("decision_context")
    @classmethod
    def _bounded_decision_context(cls, value: object) -> dict:
        return sanitize_decision_context(value)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_learning_reference(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_finding_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("learning signals are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("learning signals are deterministic")
        return True


def continuous_learning_signal_plan_projection(
    value: ContinuousLearningSignalPlan,
) -> dict:
    """Serialize a learning signal to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "CONTINUOUS_LEARNING_RULE_VERSION",
    "RULE_VERSION",
    "CONTINUOUS_LEARNING_SIGNAL_TYPES",
    "SOURCE_LAYERS",
    "OBSERVATIONS",
    "FEEDBACK_KINDS",
    "EVIDENCE_STRENGTHS",
    "STRENGTH_ORDER",
    "CONTINUOUS_LEARNING_LIMITATIONS",
    "SIGNAL_ID_PREFIX",
    "SIGNAL_ID_RE",
    "MAX_SIGNALS",
    "MAX_REFERENCES",
    "MAX_LIMITATIONS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "SIGNAL_REPEATED_EVIDENCE_GAP",
    "SIGNAL_REPEATED_CONTEXT_GAP",
    "SIGNAL_REPEATED_WEAK_HYPOTHESIS",
    "SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION",
    "SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION",
    "SIGNAL_REPEATED_DUPLICATION",
    "SIGNAL_RECURRING_CONFLICT",
    "SIGNAL_REPEATED_GOVERNANCE_ISSUE",
    "SIGNAL_REPEATED_PROVENANCE_ISSUE",
    "SIGNAL_REPEATED_SAFETY_ISSUE",
    "SIGNAL_REPEATED_QUALITY_ISSUE",
    "SIGNAL_SUCCESSFUL_RESEARCH_PATTERN",
    "SIGNAL_SPECIALIST_RELIABILITY",
    "SIGNAL_PRIORITIZATION_MISMATCH",
    "SIGNAL_HUMAN_APPROVED_RESEARCH",
    "SIGNAL_HUMAN_REQUESTED_EVIDENCE",
    "SIGNAL_HUMAN_DEFERRED_RESEARCH",
    "SIGNAL_HUMAN_REJECTED_WORKFLOW",
    "SIGNAL_HUMAN_ESCALATED_RESEARCH",
    "SIGNAL_HUMAN_REVIEW_REQUIRED",
    "SOURCE_LAYER_R42",
    "SOURCE_LAYER_R43",
    "SOURCE_LAYER_R44",
    "SOURCE_LAYER_R53",
    "SOURCE_LAYER_R54",
    "SOURCE_LAYER_R55",
    "SOURCE_LAYER_R56",
    "OBSERVATION_ISSUE",
    "OBSERVATION_SUCCESS",
    "OBSERVATION_WORKFLOW_FEEDBACK",
    "OBSERVATION_NEUTRAL",
    "FEEDBACK_KIND_WORKFLOW",
    "FEEDBACK_KIND_QUALITY",
    "STRENGTH_WEAK",
    "STRENGTH_MODERATE",
    "STRENGTH_STRONG",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_ADVISORY_ONLY",
    "LIMITATION_NO_AGENT_MODIFICATION",
    "LIMITATION_NO_RULE_MODIFICATION",
    "LIMITATION_NO_THRESHOLD_MODIFICATION",
    "LIMITATION_NO_STRATEGY_MODIFICATION",
    "LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL",
    "LIMITATION_NO_CAUSALITY_CLAIM",
    "LIMITATION_CORRELATION_NOT_CAUSALITY",
    "LIMITATION_INSUFFICIENT_DATA",
    "LIMITATION_UNSUPPORTED_INPUT",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_PROVENANCE_INCOMPLETE",
    "LIMITATION_SINGLE_OBSERVATION",
    "sanitize_learning_reference",
    "sanitize_decision_context",
    "sanitize_continuous_learning_signal",
    "ContinuousLearningSignalPlan",
    "continuous_learning_signal_plan_projection",
]
