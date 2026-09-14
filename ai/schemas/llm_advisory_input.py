"""LLM advisory input schema (Stage R45.1).

An :class:`LLMAdvisoryInputPlan` is the bounded, read-only projection of
structured deterministic research artifacts (R42 evaluation, R43
collaboration, R44 learning signals) used by the advisory layer. It answers:

    "What structured research intelligence should be explained?"

Hard boundaries encoded here:

- Advisory only: the input is a bounded projection of already-produced
  structured artifacts. No execution, no network, no database, no browser,
  no LLM provider call, no payloads, no target access.
- The deterministic layers stay authoritative: R42 owns evaluation, R43 owns
  collaboration, R44 owns learning signals. R45 only projects their outputs
  and never recomputes them.
- No runtime identity: ``advisory_id`` is a deterministic content token or a
  caller-supplied validated token; no timestamps, UUIDs, randomness or
  runtime ids.
- ``research_only`` is required and always true.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_diagnostic import DIAGNOSTIC_CODES
from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
    SAFETY_STATES,
)
from ai.schemas.collaboration_conflict import CONFLICT_TYPES
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.learning_signal import (
    LEARNING_SIGNAL_TYPES,
    sanitize_learning_signal,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

LLM_ADVISORY_INPUT_RULE_VERSION = "r45-1"
RULE_VERSION = LLM_ADVISORY_INPUT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

SOURCE_LAYER_R42 = "R42"
SOURCE_LAYER_R43 = "R43"
SOURCE_LAYER_R44 = "R44"
SOURCE_LAYER_MULTI = "MULTI"
SOURCE_LAYER_UNKNOWN = "UNKNOWN"

LLM_ADVISORY_SOURCE_LAYERS: tuple[str, ...] = (
    SOURCE_LAYER_R42,
    SOURCE_LAYER_R43,
    SOURCE_LAYER_R44,
    SOURCE_LAYER_MULTI,
    SOURCE_LAYER_UNKNOWN,
)

GOVERNANCE_CONSISTENT_REFERENCED = "CONSISTENT_REFERENCED"
GOVERNANCE_MIXED = "MIXED"
GOVERNANCE_UNKNOWN = "UNKNOWN"

ADVISORY_GOVERNANCE_STATES: tuple[str, ...] = (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

SAFETY_PASS = "PASS"
SAFETY_DEGRADED = "DEGRADED"
SAFETY_FAILED = "FAILED"
SAFETY_UNKNOWN = "UNKNOWN"

ADVISORY_SAFETY_STATES: tuple[str, ...] = (
    SAFETY_PASS,
    SAFETY_DEGRADED,
    SAFETY_FAILED,
    SAFETY_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_NO_CREDENTIALS_EXPOSED = "NO_CREDENTIALS_EXPOSED"
LIMITATION_ADVISORY_ONLY = "ADVISORY_ONLY"

ADVISORY_INPUT_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_CREDENTIALS_EXPOSED,
    LIMITATION_ADVISORY_ONLY,
)

FLAG_MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
FLAG_INVALID_RULE_VERSION = "INVALID_RULE_VERSION"
FLAG_INVALID_ENUM_VALUE = "INVALID_ENUM_VALUE"
FLAG_UNKNOWN_SOURCE_LAYER = "UNKNOWN_SOURCE_LAYER"
FLAG_MALFORMED_EVALUATION_SUMMARY = "MALFORMED_EVALUATION_SUMMARY"
FLAG_MALFORMED_COLLABORATION_SUMMARY = "MALFORMED_COLLABORATION_SUMMARY"
FLAG_MALFORMED_LEARNING_SIGNALS = "MALFORMED_LEARNING_SIGNALS"
FLAG_INVALID_ADVISORY_ID = "INVALID_ADVISORY_ID"
FLAG_NON_DETERMINISTIC_INPUT = "NON_DETERMINISTIC_INPUT"

ADVISORY_INPUT_STRUCTURAL_FLAGS: tuple[str, ...] = (
    FLAG_MISSING_REQUIRED_FIELD,
    FLAG_INVALID_RULE_VERSION,
    FLAG_INVALID_ENUM_VALUE,
    FLAG_UNKNOWN_SOURCE_LAYER,
    FLAG_MALFORMED_EVALUATION_SUMMARY,
    FLAG_MALFORMED_COLLABORATION_SUMMARY,
    FLAG_MALFORMED_LEARNING_SIGNALS,
    FLAG_INVALID_ADVISORY_ID,
    FLAG_NON_DETERMINISTIC_INPUT,
)

ADVISORY_ID_PREFIX = "adv-"
ADVISORY_ID_RE = re.compile(r"^adv-[0-9a-f]{16}$")

RESEARCH_CONTEXT_KEYS: tuple[str, ...] = (
    "research_question",
    "research_focus",
    "context_fact_count",
    "source_layers",
    "research_only",
)

ADVISORY_CONTEXT_LAYERS: tuple[str, ...] = (
    "REASONING",
    "MEMORY",
    "LEARNING",
    "STRATEGY",
    "ORCHESTRATION",
    "AUTHORIZATION",
    "GOVERNANCE",
)

MERGED_EVIDENCE_STATES: tuple[str, ...] = (
    "COMPLETE",
    "PARTIAL",
    "UNKNOWN",
)

MAX_SIGNALS = 8
MAX_LIST = 16
MAX_DIAGNOSTIC_CODES = 16
MAX_FLAGS = 12
MAX_RESEARCH_QUESTION_LEN = 240
MAX_VALUE_LEN = 160
MAX_RECOMMENDATION_LEN = 240

_TOKEN_RE = re.compile(r"^[A-Z0-9_]{1,80}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_texts(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def sanitize_advisory_research_context(value: object) -> dict:
    """Project a research context onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "research_question": "",
            "research_focus": "",
            "context_fact_count": 0,
            "source_layers": [],
            "research_only": True,
        }
    layers: list[str] = []
    for item in value.get("source_layers") or ():
        text = _safe_text(item).strip().upper()
        if text in ADVISORY_CONTEXT_LAYERS and text not in layers:
            layers.append(text)
    return {
        "research_question": _safe_text(
            value.get("research_question"), MAX_RESEARCH_QUESTION_LEN
        ),
        "research_focus": _safe_text(value.get("research_focus")),
        "context_fact_count": _bounded_int(
            value.get("context_fact_count"), 0, 256
        ),
        "source_layers": layers,
        "research_only": True,
    }


def sanitize_advisory_evaluation_summary(value: object) -> dict:
    """Project an R42 evaluation result onto a bounded advisory view.

    Nothing is recomputed: the score, rating, hard-gate state, safety state
    and diagnostic codes are read from the supplied deterministic artifact.
    """

    if not isinstance(value, dict):
        return {
            "present": False,
            "reference_rule_version": "",
            "evaluated_agent_category": "UNKNOWN",
            "overall_score": 0,
            "overall_rating": "CRITICAL",
            "hard_gate_state": "PASS",
            "safety_state": SAFETY_UNKNOWN,
            "diagnostic_count": 0,
            "diagnostic_codes": [],
        }
    known = (
        "overall_score",
        "overall_rating",
        "hard_gate_state",
        "safety_state",
        "evaluated_agent_category",
    )
    if "present" in value:
        present = bool(value.get("present")) is True
    else:
        present = any(key in value for key in known)
    category = _closed(
        value.get("evaluated_agent_category"), AGENT_CATEGORIES, "UNKNOWN"
    )
    score = value.get("overall_score")
    if isinstance(score, bool) or not isinstance(score, int):
        score = 0
    score = max(0, min(100, score))
    rating = _closed(value.get("overall_rating"), EVALUATION_RATINGS, "CRITICAL")
    gate = _closed(value.get("hard_gate_state"), HARD_GATE_STATES, "PASS")
    safety = _closed(value.get("safety_state"), SAFETY_STATES, SAFETY_UNKNOWN)
    codes = _bounded_codes(
        value.get("diagnostic_codes"), DIAGNOSTIC_CODES, MAX_DIAGNOSTIC_CODES
    )
    diagnostic_count = value.get("diagnostic_count")
    if isinstance(diagnostic_count, bool) or not isinstance(
        diagnostic_count, int
    ):
        diagnostic_count = len(codes)
    return {
        "present": present,
        "reference_rule_version": _safe_text(
            value.get("reference_rule_version") or value.get("rule_version")
        ),
        "evaluated_agent_category": category,
        "overall_score": score,
        "overall_rating": rating,
        "hard_gate_state": gate,
        "safety_state": safety if present else SAFETY_UNKNOWN,
        "diagnostic_count": _bounded_int(
            diagnostic_count, 0, MAX_DIAGNOSTIC_CODES
        ),
        "diagnostic_codes": codes,
    }


def sanitize_advisory_collaboration_summary(value: object) -> dict:
    """Project an R43 collaboration result onto a bounded advisory view.

    Counts are read from the already-computed collaboration artifact; R43
    correlation logic is never duplicated or recomputed.
    """

    if not isinstance(value, dict):
        return {
            "present": False,
            "reference_rule_version": "",
            "participant_count": 0,
            "hypothesis_group_count": 0,
            "conflict_count": 0,
            "conflict_types": [],
            "merged_evidence_state": "UNKNOWN",
            "governance_state": GOVERNANCE_UNKNOWN,
            "provenance_state": "UNKNOWN",
        }
    known = (
        "participating_agents",
        "hypothesis_groups",
        "conflicts",
        "merged_evidence",
        "collaboration_rankings",
    )
    if "present" in value:
        present = bool(value.get("present")) is True
    else:
        present = any(key in value for key in known)
    participants = value.get("participating_agents")
    groups = value.get("hypothesis_groups")
    conflicts = value.get("conflicts")
    if isinstance(participants, (list, tuple)):
        participant_count = len(list(participants))
    else:
        participant_count = _bounded_int(
            value.get("participant_count"), 0, 256
        )
    if isinstance(groups, (list, tuple)):
        hypothesis_group_count = len(list(groups))
    else:
        hypothesis_group_count = _bounded_int(
            value.get("hypothesis_group_count"), 0, 256
        )
    if isinstance(conflicts, (list, tuple)):
        conflict_count = len(list(conflicts))
    else:
        conflict_count = _bounded_int(
            value.get("conflict_count"), 0, 256
        )
    merged = value.get("merged_evidence")
    merged = merged if isinstance(merged, dict) else {}
    governance = value.get("governance_summary")
    governance = governance if isinstance(governance, dict) else {}
    provenance = value.get("provenance_summary")
    provenance = provenance if isinstance(provenance, dict) else {}
    conflict_types: list[str] = []
    raw_conflict_types = value.get("conflict_types")
    if not isinstance(conflicts, (list, tuple)) and isinstance(
        raw_conflict_types, (list, tuple)
    ):
        conflict_types = _bounded_codes(
            raw_conflict_types, CONFLICT_TYPES, MAX_LIST
        )
    for item in conflicts or ():
        if not isinstance(item, dict):
            continue
        text = _safe_text(item.get("conflict_type")).strip().upper()
        if text in CONFLICT_TYPES and text not in conflict_types:
            conflict_types.append(text)
        if len(conflict_types) >= MAX_LIST:
            break
    return {
        "present": present,
        "reference_rule_version": _safe_text(
            value.get("reference_rule_version") or value.get("rule_version")
        ),
        "participant_count": participant_count,
        "hypothesis_group_count": hypothesis_group_count,
        "conflict_count": conflict_count,
        "conflict_types": conflict_types,
        "merged_evidence_state": _closed(
            merged.get("evidence_state")
            if "evidence_state" in merged
            else value.get("merged_evidence_state"),
            MERGED_EVIDENCE_STATES,
            "UNKNOWN",
        ),
        "governance_state": _closed(
            governance.get("governance_state")
            if "governance_state" in governance
            else value.get("governance_state"),
            ADVISORY_GOVERNANCE_STATES,
            GOVERNANCE_UNKNOWN,
        ),
        "provenance_state": _closed(
            provenance.get("provenance_state")
            if "provenance_state" in provenance
            else value.get("provenance_state"),
            MERGED_EVIDENCE_STATES,
            "UNKNOWN",
        ),
    }


def sanitize_advisory_learning_signals(value: object) -> list[dict]:
    """Project R44 learning signals onto a bounded advisory view."""

    if isinstance(value, dict):
        raw_items = [value]
    elif isinstance(value, (list, tuple)):
        raw_items = list(value)
    else:
        return []
    out: list[dict] = []
    seen: set[tuple] = set()
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        bounded = sanitize_learning_signal(item)
        signal_type = bounded["signal_type"]
        if signal_type not in LEARNING_SIGNAL_TYPES:
            continue
        subject = bounded["subject"]
        if subject not in AGENT_CATEGORIES:
            subject = "UNKNOWN"
        confidence = bounded["confidence"]
        if confidence not in CONFIDENCE_LEVELS:
            confidence = "UNKNOWN"
        key = (
            signal_type,
            subject,
            bounded["source_agent"],
            bounded["source_classification"],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "signal_type": signal_type,
                "subject": subject,
                "source_agent": bounded["source_agent"],
                "source_classification": bounded["source_classification"],
                "recommendation": _safe_text(
                    bounded["recommendation"], MAX_RECOMMENDATION_LEN
                ),
                "confidence": confidence,
                "research_only": True,
            }
        )
        if len(out) >= MAX_SIGNALS:
            break
    return out


def sanitize_llm_advisory_input(value: object) -> dict:
    """Project an advisory input onto its fixed bounded key set."""

    if not isinstance(value, dict):
        value = {}
    source_layer = _closed(
        value.get("source_layer"),
        LLM_ADVISORY_SOURCE_LAYERS,
        SOURCE_LAYER_UNKNOWN,
    )
    governance_state = _closed(
        value.get("governance_state"),
        ADVISORY_GOVERNANCE_STATES,
        GOVERNANCE_UNKNOWN,
    )
    safety_state = _closed(
        value.get("safety_state"), ADVISORY_SAFETY_STATES, SAFETY_UNKNOWN
    )
    advisory_id = _safe_text(value.get("advisory_id"))
    if advisory_id and not ADVISORY_ID_RE.match(advisory_id):
        advisory_id = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "advisory_id": advisory_id,
        "source_layer": source_layer,
        "research_context": sanitize_advisory_research_context(
            value.get("research_context")
        ),
        "evaluation_summary": sanitize_advisory_evaluation_summary(
            value.get("evaluation_summary")
        ),
        "collaboration_summary": sanitize_advisory_collaboration_summary(
            value.get("collaboration_summary")
        ),
        "learning_signals": sanitize_advisory_learning_signals(
            value.get("learning_signals")
        ),
        "governance_state": governance_state,
        "safety_state": safety_state,
        "limitations": _bounded_codes(
            value.get("limitations"), ADVISORY_INPUT_LIMITATIONS, MAX_LIST
        ),
        "research_only": bool(value.get("research_only", True)) is True,
        "structural_flags": _bounded_codes(
            value.get("structural_flags"), ADVISORY_INPUT_STRUCTURAL_FLAGS,
            MAX_FLAGS,
        ),
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class LLMAdvisoryInputPlan(BaseModel):
    """Bounded, read-only advisory input (R45.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = LLM_ADVISORY_INPUT_RULE_VERSION
    advisory_id: str = ""
    source_layer: str = SOURCE_LAYER_UNKNOWN
    research_context: dict = Field(default_factory=dict)
    evaluation_summary: dict = Field(default_factory=dict)
    collaboration_summary: dict = Field(default_factory=dict)
    learning_signals: list[dict] = Field(default_factory=list)
    governance_state: str = GOVERNANCE_UNKNOWN
    safety_state: str = SAFETY_UNKNOWN
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    structural_flags: list[str] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return LLM_ADVISORY_INPUT_RULE_VERSION

    @field_validator("advisory_id")
    @classmethod
    def _valid_advisory_id(cls, value: object) -> str:
        text = _safe_text(value)
        if text and not ADVISORY_ID_RE.match(text):
            raise ValueError(f"invalid advisory_id: {value!r}")
        return text

    @field_validator("source_layer")
    @classmethod
    def _valid_source_layer(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in LLM_ADVISORY_SOURCE_LAYERS:
            raise ValueError(f"invalid source_layer: {value!r}")
        return text

    @field_validator("research_context")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_advisory_research_context(value)

    @field_validator("evaluation_summary")
    @classmethod
    def _bounded_evaluation(cls, value: object) -> dict:
        return sanitize_advisory_evaluation_summary(value)

    @field_validator("collaboration_summary")
    @classmethod
    def _bounded_collaboration(cls, value: object) -> dict:
        return sanitize_advisory_collaboration_summary(value)

    @field_validator("learning_signals")
    @classmethod
    def _bounded_signals(cls, value: list) -> list[dict]:
        return sanitize_advisory_learning_signals(value)

    @field_validator("governance_state")
    @classmethod
    def _valid_governance(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_GOVERNANCE_STATES:
            raise ValueError(f"invalid governance_state: {value!r}")
        return text

    @field_validator("safety_state")
    @classmethod
    def _valid_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ADVISORY_SAFETY_STATES:
            raise ValueError(f"invalid safety_state: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _bounded_codes(value, ADVISORY_INPUT_LIMITATIONS, MAX_LIST)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("LLM advisory input is research-only")
        return True

    @field_validator("structural_flags")
    @classmethod
    def _valid_flags(cls, value: list) -> list[str]:
        return _bounded_codes(
            value, ADVISORY_INPUT_STRUCTURAL_FLAGS, MAX_FLAGS
        )


def llm_advisory_input_plan_projection(value: LLMAdvisoryInputPlan) -> dict:
    """Serialize an advisory input to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "LLM_ADVISORY_INPUT_RULE_VERSION",
    "RULE_VERSION",
    "LLM_ADVISORY_SOURCE_LAYERS",
    "SOURCE_LAYER_R42",
    "SOURCE_LAYER_R43",
    "SOURCE_LAYER_R44",
    "SOURCE_LAYER_MULTI",
    "SOURCE_LAYER_UNKNOWN",
    "ADVISORY_GOVERNANCE_STATES",
    "GOVERNANCE_CONSISTENT_REFERENCED",
    "GOVERNANCE_MIXED",
    "GOVERNANCE_UNKNOWN",
    "ADVISORY_SAFETY_STATES",
    "SAFETY_PASS",
    "SAFETY_DEGRADED",
    "SAFETY_FAILED",
    "SAFETY_UNKNOWN",
    "ADVISORY_INPUT_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_NO_CREDENTIALS_EXPOSED",
    "LIMITATION_ADVISORY_ONLY",
    "ADVISORY_INPUT_STRUCTURAL_FLAGS",
    "FLAG_MISSING_REQUIRED_FIELD",
    "FLAG_INVALID_RULE_VERSION",
    "FLAG_INVALID_ENUM_VALUE",
    "FLAG_UNKNOWN_SOURCE_LAYER",
    "FLAG_MALFORMED_EVALUATION_SUMMARY",
    "FLAG_MALFORMED_COLLABORATION_SUMMARY",
    "FLAG_MALFORMED_LEARNING_SIGNALS",
    "FLAG_INVALID_ADVISORY_ID",
    "FLAG_NON_DETERMINISTIC_INPUT",
    "ADVISORY_ID_PREFIX",
    "ADVISORY_ID_RE",
    "RESEARCH_CONTEXT_KEYS",
    "ADVISORY_CONTEXT_LAYERS",
    "MERGED_EVIDENCE_STATES",
    "MAX_SIGNALS",
    "MAX_LIST",
    "MAX_DIAGNOSTIC_CODES",
    "MAX_FLAGS",
    "MAX_VALUE_LEN",
    "MAX_RESEARCH_QUESTION_LEN",
    "MAX_RECOMMENDATION_LEN",
    "sanitize_advisory_research_context",
    "sanitize_advisory_evaluation_summary",
    "sanitize_advisory_collaboration_summary",
    "sanitize_advisory_learning_signals",
    "sanitize_llm_advisory_input",
    "LLMAdvisoryInputPlan",
    "llm_advisory_input_plan_projection",
]
