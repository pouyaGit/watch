"""Stage R57.5 deterministic continuous-learning rules (pure engine).

Extracts, aggregates and calibrates continuous-learning intelligence from
structured R42-R56 research-workflow history:

    R42 evaluations / R43 collaboration / R44 feedback / R53 findings /
    R54 correlation / R55 prioritization / R56 human decisions
      -> normalized learning signals (closed vocabularies)
      -> conservative learning patterns (recurrence / cross-layer support)
      -> advisory calibration recommendations
      -> provenance, governance and limitations

Hard boundaries encoded here:

- Advisory only: R57 never executes anything, never sends requests, never
  confirms a vulnerability, never authorizes execution or exploitation and
  never modifies agents, rules, thresholds or strategies.
- Human decisions are workflow feedback, never truth labels: decision-derived
  signals force ``feedback_kind = WORKFLOW_FEEDBACK`` and preserve the R56
  authority context; approval is never interpreted as "finding is true".
- Conservative: a pattern is emitted only with recurrence or cross-layer
  corroboration; no causal relationship is inferred or invented.
- Deterministic: content-derived ids only; canonical ordering; stable
  tie-breaking; no timestamps, UUIDs, pids or randomness.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no database, no wall-clock time.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.agent_evaluation_rules import (
    CONFIRMATION_CLAIM_TOKENS,
    EXECUTION_CLAIM_TOKENS,
)
from ai.schemas.agent_evaluation_diagnostic import (
    CONFIDENCE_OVERSTATED,
    CONFIDENCE_UNDERSPECIFIED,
    CONTEXT_TOO_SPARSE,
    EVIDENCE_INCONSISTENT,
    EVIDENCE_REQUIRED_LIMITATION_MISSING,
    EXECUTION_CLAIM_DETECTED,
    GOVERNANCE_INCONSISTENT,
    GOVERNANCE_UNKNOWN,
    HYPOTHESIS_SAFETY_FLAGS_MISSING,
    INVALID_ENUM_VALUE,
    INVALID_RULE_VERSION,
    LIMITATION_DISCLOSURE_INCOMPLETE,
    MALFORMED_EVIDENCE_PLAN,
    MALFORMED_GOVERNANCE,
    MALFORMED_HYPOTHESIS,
    MALFORMED_LIMITATIONS,
    MALFORMED_PROVENANCE,
    MISSING_EVIDENCE_REQUIREMENT,
    MISSING_REQUIRED_FIELD,
    NON_DETERMINISTIC_OUTPUT,
    NO_HYPOTHESES_REPORTED,
    PROVENANCE_INCOMPLETE,
    PROVENANCE_INVENTED_LAYER,
    RESEARCH_ONLY_FALSE,
    SAFETY_LIMITATION_MISSING,
    UNKNOWN_AGENT_CATEGORY,
    UNSUPPORTED_HYPOTHESIS,
    VULNERABILITY_CONFIRMATION_CLAIM,
)
from ai.schemas.calibration_recommendation import (
    CALIB_INCREASE_CONTEXT_COLLECTION,
    CALIB_PRESERVE_SUCCESS_PATTERN,
    CALIB_REDUCE_CONFIDENCE,
    CALIB_REQUEST_MORE_EVIDENCE,
    CALIB_REVIEW_CONFIDENCE_CALIBRATION,
    CALIB_REVIEW_CONFLICT,
    CALIB_REVIEW_DUPLICATION,
    CALIB_REVIEW_GOVERNANCE,
    CALIB_REVIEW_HYPOTHESIS,
    CALIB_REVIEW_HUMAN_FEEDBACK,
    CALIB_REVIEW_PRIORITY_ALIGNMENT,
    CALIB_REVIEW_PROVENANCE,
    CALIB_REVIEW_RESEARCH_QUALITY,
    CALIB_REVIEW_SAFETY_BOUNDARY,
    CALIB_REVIEW_SPECIALIST_RELIABILITY,
    CALIBRATION_LIMITATIONS,
    RATIONALE_CROSS_LAYER_CORROBORATION,
    RATIONALE_EVIDENCE_GAP,
    RATIONALE_GOVERNANCE_PRESERVED,
    RATIONALE_HUMAN_DECISION_NOT_TRUTH_LABEL,
    RATIONALE_HUMAN_WORKFLOW_FEEDBACK,
    RATIONALE_LIMITED_SUPPORT,
    RATIONALE_PRIORITY_ALIGNMENT,
    RATIONALE_RECURRENCE_COUNT,
    RATIONALE_RECURRING_OBSERVATION,
    RATIONALE_SAFETY_BOUNDARY,
    RATIONALE_SPECIALIST_RELIABILITY,
    RATIONALE_SUCCESS_PATTERN,
    RECOMMENDATION_ORDER,
    SCOPE_CATEGORY,
    SCOPE_GOVERNANCE,
    SCOPE_PRIORITY,
    SCOPE_PROVENANCE,
    SCOPE_QUALITY,
    SCOPE_SAFETY,
    SCOPE_SPECIALIST,
    SCOPE_WORKFLOW,
    sanitize_calibration_recommendation,
)
from ai.schemas.continuous_learning import (
    CONTINUOUS_LEARNING_SIGNAL_TYPES,
    FEEDBACK_KIND_QUALITY,
    FEEDBACK_KIND_WORKFLOW,
    LIMITATION_ADVISORY_ONLY,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL,
    LIMITATION_INSUFFICIENT_DATA,
    LIMITATION_NO_AGENT_MODIFICATION,
    LIMITATION_NO_CAUSALITY_CLAIM,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_RULE_MODIFICATION,
    LIMITATION_NO_STRATEGY_MODIFICATION,
    LIMITATION_NO_THRESHOLD_MODIFICATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_SINGLE_OBSERVATION,
    LIMITATION_UNSUPPORTED_INPUT,
    OBSERVATION_ISSUE,
    OBSERVATION_SUCCESS,
    OBSERVATION_WORKFLOW_FEEDBACK,
    SIGNAL_HUMAN_APPROVED_RESEARCH,
    SIGNAL_HUMAN_DEFERRED_RESEARCH,
    SIGNAL_HUMAN_ESCALATED_RESEARCH,
    SIGNAL_HUMAN_REJECTED_WORKFLOW,
    SIGNAL_HUMAN_REQUESTED_EVIDENCE,
    SIGNAL_HUMAN_REVIEW_REQUIRED,
    SIGNAL_ID_PREFIX,
    SIGNAL_PRIORITIZATION_MISMATCH,
    SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION,
    SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION,
    SIGNAL_RECURRING_CONFLICT,
    SIGNAL_REPEATED_CONTEXT_GAP,
    SIGNAL_REPEATED_DUPLICATION,
    SIGNAL_REPEATED_EVIDENCE_GAP,
    SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    SIGNAL_REPEATED_PROVENANCE_ISSUE,
    SIGNAL_REPEATED_QUALITY_ISSUE,
    SIGNAL_REPEATED_SAFETY_ISSUE,
    SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    SIGNAL_SPECIALIST_RELIABILITY,
    SIGNAL_SUCCESSFUL_RESEARCH_PATTERN,
    SOURCE_LAYER_R42,
    SOURCE_LAYER_R43,
    SOURCE_LAYER_R44,
    SOURCE_LAYER_R53,
    SOURCE_LAYER_R54,
    SOURCE_LAYER_R55,
    SOURCE_LAYER_R56,
    SOURCE_LAYERS,
    STRENGTH_MODERATE,
    STRENGTH_ORDER,
    STRENGTH_STRONG,
    STRENGTH_WEAK,
    sanitize_continuous_learning_signal,
)
from ai.schemas.learning_pattern import (
    LEARNING_PATTERN_TYPES,
    INDICATOR_CONFIDENCE_MIXED,
    INDICATOR_CONFIDENCE_OVERESTIMATION,
    INDICATOR_CONFIDENCE_UNDERESTIMATION,
    INDICATOR_CONFLICT_RECURRENCE,
    INDICATOR_CONTEXT_GAP_RECURRING,
    INDICATOR_DUPLICATION_OVERLAP,
    INDICATOR_EVIDENCE_GAP_RECURRING,
    INDICATOR_GOVERNANCE_RECURRENCE,
    INDICATOR_HYPOTHESIS_WEAKNESS_RECURRING,
    INDICATOR_PRIORITY_MISALIGNMENT,
    INDICATOR_PROVENANCE_RECURRENCE,
    INDICATOR_QUALITY_RECURRENCE,
    INDICATOR_SAFETY_RECURRENCE,
    INDICATOR_SPECIALIST_RELIABILITY,
    INDICATOR_SUCCESS_PATTERN,
    INDICATOR_UNKNOWN,
    INDICATOR_WORKFLOW_FEEDBACK_PATTERN,
    PATTERN_CONFIDENCE_CALIBRATION,
    PATTERN_CONFLICT,
    PATTERN_CONTEXT_GAP,
    PATTERN_DUPLICATION,
    PATTERN_EVIDENCE_GAP,
    PATTERN_GOVERNANCE,
    PATTERN_HYPOTHESIS_WEAKNESS,
    PATTERN_ID_PREFIX,
    PATTERN_PRIORITY_ALIGNMENT,
    PATTERN_PROVENANCE,
    PATTERN_QUALITY,
    PATTERN_SAFETY,
    PATTERN_SPECIALIST_RELIABILITY,
    PATTERN_SUCCESS,
    PATTERN_TYPE_ORDER,
    PATTERN_WORKFLOW_FEEDBACK,
    sanitize_learning_pattern,
)
from ai.schemas.research_feedback_classification import (
    CLASSIFICATION_CONFIDENCE_CALIBRATION,
    CLASSIFICATION_CONFLICT_PATTERN,
    CLASSIFICATION_DUPLICATION_PATTERN,
    CLASSIFICATION_EVIDENCE_GAP,
    CLASSIFICATION_GOVERNANCE_ISSUE,
    CLASSIFICATION_HYPOTHESIS_WEAKNESS,
    CLASSIFICATION_PROVENANCE_ISSUE,
    CLASSIFICATION_QUALITY_IMPROVEMENT,
    CLASSIFICATION_SAFETY_ISSUE,
    CLASSIFICATION_SUCCESS_PATTERN,
)
from ai.schemas.learning_signal import (
    SIGNAL_AVOID_DUPLICATION,
    SIGNAL_IMPROVE_CONTEXT_COLLECTION,
    SIGNAL_IMPROVE_HYPOTHESIS_QUALITY,
    SIGNAL_IMPROVE_SAFETY_BOUNDARY,
    SIGNAL_PRESERVE_SUCCESS_PATTERN,
    SIGNAL_REDUCE_CONFIDENCE,
    SIGNAL_REQUIRE_MORE_EVIDENCE,
    SIGNAL_REVIEW_GOVERNANCE,
    SIGNAL_REVIEW_PROVENANCE,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

CONTINUOUS_LEARNING_RULES_RULE_VERSION = "r57-5"
RULE_VERSION = CONTINUOUS_LEARNING_RULES_RULE_VERSION

MAX_SIGNALS = 64
MAX_PATTERNS = 24
MAX_REFERENCES = 12
MAX_LIST = 24

#: Signal family mapping: generic repeated-workflow observations.
SIGNAL_TO_PATTERN: dict[str, str] = {
    SIGNAL_REPEATED_EVIDENCE_GAP: PATTERN_EVIDENCE_GAP,
    SIGNAL_HUMAN_REQUESTED_EVIDENCE: PATTERN_EVIDENCE_GAP,
    SIGNAL_REPEATED_CONTEXT_GAP: PATTERN_CONTEXT_GAP,
    SIGNAL_REPEATED_WEAK_HYPOTHESIS: PATTERN_HYPOTHESIS_WEAKNESS,
    SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION: PATTERN_CONFIDENCE_CALIBRATION,
    SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION: (
        PATTERN_CONFIDENCE_CALIBRATION
    ),
    SIGNAL_REPEATED_DUPLICATION: PATTERN_DUPLICATION,
    SIGNAL_RECURRING_CONFLICT: PATTERN_CONFLICT,
    SIGNAL_REPEATED_GOVERNANCE_ISSUE: PATTERN_GOVERNANCE,
    SIGNAL_REPEATED_PROVENANCE_ISSUE: PATTERN_PROVENANCE,
    SIGNAL_REPEATED_SAFETY_ISSUE: PATTERN_SAFETY,
    SIGNAL_REPEATED_QUALITY_ISSUE: PATTERN_QUALITY,
    SIGNAL_SUCCESSFUL_RESEARCH_PATTERN: PATTERN_SUCCESS,
    SIGNAL_HUMAN_APPROVED_RESEARCH: PATTERN_SUCCESS,
    SIGNAL_SPECIALIST_RELIABILITY: PATTERN_SPECIALIST_RELIABILITY,
    SIGNAL_PRIORITIZATION_MISMATCH: PATTERN_PRIORITY_ALIGNMENT,
    SIGNAL_HUMAN_DEFERRED_RESEARCH: PATTERN_WORKFLOW_FEEDBACK,
    SIGNAL_HUMAN_REJECTED_WORKFLOW: PATTERN_WORKFLOW_FEEDBACK,
    SIGNAL_HUMAN_ESCALATED_RESEARCH: PATTERN_WORKFLOW_FEEDBACK,
    SIGNAL_HUMAN_REVIEW_REQUIRED: PATTERN_WORKFLOW_FEEDBACK,
}

#: R42 diagnostic -> learning signal.
R42_DIAGNOSTIC_SIGNAL: dict[str, str] = {
    EVIDENCE_INCONSISTENT: SIGNAL_REPEATED_EVIDENCE_GAP,
    MISSING_EVIDENCE_REQUIREMENT: SIGNAL_REPEATED_EVIDENCE_GAP,
    EVIDENCE_REQUIRED_LIMITATION_MISSING: SIGNAL_REPEATED_EVIDENCE_GAP,
    MALFORMED_EVIDENCE_PLAN: SIGNAL_REPEATED_EVIDENCE_GAP,
    CONTEXT_TOO_SPARSE: SIGNAL_REPEATED_CONTEXT_GAP,
    NO_HYPOTHESES_REPORTED: SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    UNSUPPORTED_HYPOTHESIS: SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    HYPOTHESIS_SAFETY_FLAGS_MISSING: SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    MALFORMED_HYPOTHESIS: SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    CONFIDENCE_OVERSTATED: SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION,
    CONFIDENCE_UNDERSPECIFIED: (
        SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION
    ),
    PROVENANCE_INCOMPLETE: SIGNAL_REPEATED_PROVENANCE_ISSUE,
    PROVENANCE_INVENTED_LAYER: SIGNAL_REPEATED_PROVENANCE_ISSUE,
    MALFORMED_PROVENANCE: SIGNAL_REPEATED_PROVENANCE_ISSUE,
    GOVERNANCE_UNKNOWN: SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    GOVERNANCE_INCONSISTENT: SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    MALFORMED_GOVERNANCE: SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    EXECUTION_CLAIM_DETECTED: SIGNAL_REPEATED_SAFETY_ISSUE,
    VULNERABILITY_CONFIRMATION_CLAIM: SIGNAL_REPEATED_SAFETY_ISSUE,
    RESEARCH_ONLY_FALSE: SIGNAL_REPEATED_SAFETY_ISSUE,
    SAFETY_LIMITATION_MISSING: SIGNAL_REPEATED_SAFETY_ISSUE,
    LIMITATION_DISCLOSURE_INCOMPLETE: SIGNAL_REPEATED_QUALITY_ISSUE,
    MALFORMED_LIMITATIONS: SIGNAL_REPEATED_QUALITY_ISSUE,
    MISSING_REQUIRED_FIELD: SIGNAL_REPEATED_QUALITY_ISSUE,
    INVALID_RULE_VERSION: SIGNAL_REPEATED_QUALITY_ISSUE,
    INVALID_ENUM_VALUE: SIGNAL_REPEATED_QUALITY_ISSUE,
    UNKNOWN_AGENT_CATEGORY: SIGNAL_REPEATED_QUALITY_ISSUE,
    NON_DETERMINISTIC_OUTPUT: SIGNAL_REPEATED_QUALITY_ISSUE,
}

#: R42 diagnostic severity -> signal strength.
R42_SEVERITY_STRENGTH: dict[str, str] = {
    "CRITICAL": STRENGTH_STRONG,
    "HIGH": STRENGTH_STRONG,
    "MEDIUM": STRENGTH_MODERATE,
    "LOW": STRENGTH_WEAK,
    "INFO": STRENGTH_WEAK,
}

#: R44 classification -> learning signal.
R44_CLASSIFICATION_SIGNAL: dict[str, str] = {
    CLASSIFICATION_QUALITY_IMPROVEMENT: SIGNAL_REPEATED_QUALITY_ISSUE,
    CLASSIFICATION_CONFIDENCE_CALIBRATION: (
        SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION
    ),
    CLASSIFICATION_EVIDENCE_GAP: SIGNAL_REPEATED_EVIDENCE_GAP,
    CLASSIFICATION_HYPOTHESIS_WEAKNESS: SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    CLASSIFICATION_DUPLICATION_PATTERN: SIGNAL_REPEATED_DUPLICATION,
    CLASSIFICATION_CONFLICT_PATTERN: SIGNAL_RECURRING_CONFLICT,
    CLASSIFICATION_GOVERNANCE_ISSUE: SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    CLASSIFICATION_PROVENANCE_ISSUE: SIGNAL_REPEATED_PROVENANCE_ISSUE,
    CLASSIFICATION_SAFETY_ISSUE: SIGNAL_REPEATED_SAFETY_ISSUE,
    CLASSIFICATION_SUCCESS_PATTERN: SIGNAL_SUCCESSFUL_RESEARCH_PATTERN,
}

#: R44 learning signal -> learning signal (fallback when no classifications).
R44_SIGNAL_MAP: dict[str, str] = {
    SIGNAL_REQUIRE_MORE_EVIDENCE: SIGNAL_REPEATED_EVIDENCE_GAP,
    SIGNAL_REDUCE_CONFIDENCE: SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION,
    SIGNAL_IMPROVE_CONTEXT_COLLECTION: SIGNAL_REPEATED_CONTEXT_GAP,
    SIGNAL_PRESERVE_SUCCESS_PATTERN: SIGNAL_SUCCESSFUL_RESEARCH_PATTERN,
    SIGNAL_AVOID_DUPLICATION: SIGNAL_REPEATED_DUPLICATION,
    SIGNAL_REVIEW_GOVERNANCE: SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    SIGNAL_REVIEW_PROVENANCE: SIGNAL_REPEATED_PROVENANCE_ISSUE,
    SIGNAL_IMPROVE_HYPOTHESIS_QUALITY: SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    SIGNAL_IMPROVE_SAFETY_BOUNDARY: SIGNAL_REPEATED_SAFETY_ISSUE,
}

#: R56 decision -> workflow feedback signal.
DECISION_SIGNAL: dict[str, str] = {
    "APPROVE_RESEARCH": SIGNAL_HUMAN_APPROVED_RESEARCH,
    "REQUEST_MORE_EVIDENCE": SIGNAL_HUMAN_REQUESTED_EVIDENCE,
    "DEFER": SIGNAL_HUMAN_DEFERRED_RESEARCH,
    "REJECT": SIGNAL_HUMAN_REJECTED_WORKFLOW,
    "ESCALATE": SIGNAL_HUMAN_ESCALATED_RESEARCH,
    "NEEDS_REVIEW": SIGNAL_HUMAN_REVIEW_REQUIRED,
}

#: R56 rationale -> corroborating learning signal (workflow feedback).
RATIONALE_SIGNAL: dict[str, str] = {
    "EVIDENCE_INCOMPLETE": SIGNAL_REPEATED_EVIDENCE_GAP,
    "HYPOTHESIS_NEEDS_STRENGTHENING": SIGNAL_REPEATED_WEAK_HYPOTHESIS,
    "CONFLICT_REQUIRES_RESOLUTION": SIGNAL_RECURRING_CONFLICT,
    "DUPLICATE_RESEARCH_OVERLAP": SIGNAL_REPEATED_DUPLICATION,
    "GOVERNANCE_REVIEW_REQUIRED": SIGNAL_REPEATED_GOVERNANCE_ISSUE,
    "PROVENANCE_INCOMPLETE": SIGNAL_REPEATED_PROVENANCE_ISSUE,
}

INDICATOR_RECOMMENDATION: dict[str, tuple[str, ...]] = {
    INDICATOR_EVIDENCE_GAP_RECURRING: (CALIB_REQUEST_MORE_EVIDENCE,),
    INDICATOR_CONTEXT_GAP_RECURRING: (CALIB_INCREASE_CONTEXT_COLLECTION,),
    INDICATOR_HYPOTHESIS_WEAKNESS_RECURRING: (CALIB_REVIEW_HYPOTHESIS,),
    INDICATOR_CONFIDENCE_OVERESTIMATION: (CALIB_REDUCE_CONFIDENCE,),
    INDICATOR_CONFIDENCE_UNDERESTIMATION: (
        CALIB_REVIEW_CONFIDENCE_CALIBRATION,
    ),
    INDICATOR_CONFIDENCE_MIXED: (CALIB_REVIEW_CONFIDENCE_CALIBRATION,),
    INDICATOR_DUPLICATION_OVERLAP: (CALIB_REVIEW_DUPLICATION,),
    INDICATOR_CONFLICT_RECURRENCE: (CALIB_REVIEW_CONFLICT,),
    INDICATOR_GOVERNANCE_RECURRENCE: (CALIB_REVIEW_GOVERNANCE,),
    INDICATOR_PROVENANCE_RECURRENCE: (CALIB_REVIEW_PROVENANCE,),
    INDICATOR_SAFETY_RECURRENCE: (CALIB_REVIEW_SAFETY_BOUNDARY,),
    INDICATOR_QUALITY_RECURRENCE: (CALIB_REVIEW_RESEARCH_QUALITY,),
    INDICATOR_SUCCESS_PATTERN: (CALIB_PRESERVE_SUCCESS_PATTERN,),
    INDICATOR_WORKFLOW_FEEDBACK_PATTERN: (CALIB_REVIEW_HUMAN_FEEDBACK,),
    INDICATOR_PRIORITY_MISALIGNMENT: (CALIB_REVIEW_PRIORITY_ALIGNMENT,),
    INDICATOR_SPECIALIST_RELIABILITY: (
        CALIB_REVIEW_SPECIALIST_RELIABILITY,
    ),
    INDICATOR_UNKNOWN: (),
}

PATTERN_SCOPE: dict[str, str] = {
    PATTERN_EVIDENCE_GAP: SCOPE_CATEGORY,
    PATTERN_CONTEXT_GAP: SCOPE_CATEGORY,
    PATTERN_HYPOTHESIS_WEAKNESS: SCOPE_CATEGORY,
    PATTERN_CONFIDENCE_CALIBRATION: SCOPE_CATEGORY,
    PATTERN_DUPLICATION: SCOPE_CATEGORY,
    PATTERN_CONFLICT: SCOPE_CATEGORY,
    PATTERN_GOVERNANCE: SCOPE_GOVERNANCE,
    PATTERN_PROVENANCE: SCOPE_PROVENANCE,
    PATTERN_SAFETY: SCOPE_SAFETY,
    PATTERN_QUALITY: SCOPE_QUALITY,
    PATTERN_SUCCESS: SCOPE_SPECIALIST,
    PATTERN_WORKFLOW_FEEDBACK: SCOPE_WORKFLOW,
    PATTERN_PRIORITY_ALIGNMENT: SCOPE_PRIORITY,
    PATTERN_SPECIALIST_RELIABILITY: SCOPE_SPECIALIST,
}

#: Forbidden autonomous/execution markers (defense in depth; these never
#: appear in legitimate R42-R56 negatives such as *_NOT_AUTHORIZED).
FORBIDDEN_LEARNING_MARKERS: tuple[str, ...] = (
    EXECUTION_CLAIM_TOKENS
    + CONFIRMATION_CLAIM_TOKENS
    + (
        "AUTO_APPLY",
        "AUTO_MODIFY",
        "AUTONOMOUS_EXECUTION",
        "DISABLE_SAFETY",
        "DISABLE_GOVERNANCE",
        "BYPASS_HUMAN",
        "BYPASS_APPROVAL",
        "SKIP_HUMAN_APPROVAL",
        "GENERATE_PAYLOAD",
        "PAYLOAD_GENERATION",
        "ATTACK_PLANNING_AUTHORIZED",
        "EXPLOIT_GUIDANCE",
        "CONFIRM_VULNERABILITY",
    )
)

_FORBIDDEN_TRUE_KEYS: tuple[str, ...] = (
    "auto_applies",
    "auto_apply",
    "auto_modify",
    "modifies_agents",
    "modifies_rules",
    "modifies_thresholds",
    "modifies_strategies",
    "execution_authorized",
    "vulnerability_confirmed",
    "exploit_authorized",
    "auto_execute",
    "execute",
)

_BASE_SIGNAL_LIMITATIONS: tuple[str, ...] = (
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
    LIMITATION_NO_CAUSALITY_CLAIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
)

_BASE_PATTERN_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_CAUSALITY_CLAIM,
    LIMITATION_CORRELATION_NOT_CAUSALITY,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _sorted_unique(values: object) -> list[str]:
    out: list[str] = []
    for item in values or ():
        text = _text(item)
        if text and text not in out:
            out.append(text)
    return sorted(out)


def _category(value: object) -> str:
    text = _upper(value)
    return text if text in AGENT_CATEGORIES else "UNKNOWN"


# ---------------------------------------------------------------------------
# Deterministic ids
# ---------------------------------------------------------------------------


def signal_id(
    signal_type: str,
    source_layer: str,
    category: str,
    agent_id: str,
    finding_id: str,
    decision_id: str,
    subject_reference: str,
    observation: str,
    feedback_kind: str,
) -> str:
    """Content-derived signal id (canonicalized; no runtime ordering)."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r57-1",
                "signal_type": signal_type,
                "source_layer": source_layer,
                "category": category,
                "agent_id": agent_id,
                "finding_id": finding_id,
                "decision_id": decision_id,
                "subject_reference": subject_reference,
                "observation": observation,
                "feedback_kind": feedback_kind,
            }
        ).encode("utf-8")
    ).hexdigest()
    return SIGNAL_ID_PREFIX + digest[:16]


def pattern_id(
    pattern_type: str,
    category: str,
    signal_ids: list[str],
) -> str:
    """Content-derived pattern id from its canonical signal membership."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r57-2",
                "pattern_type": pattern_type,
                "category": category,
                "signal_ids": sorted(signal_ids),
            }
        ).encode("utf-8")
    ).hexdigest()
    return PATTERN_ID_PREFIX + digest[:16]


def recommendation_id(
    recommendation_code: str,
    pattern_id_value: str,
    target_scope: str,
) -> str:
    """Content-derived calibration recommendation id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r57-3",
                "recommendation_code": recommendation_code,
                "pattern_id": pattern_id_value,
                "target_scope": target_scope,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "clc-" + digest[:16]


def learning_id(
    signal_ids: list[str],
    pattern_ids: list[str],
    recommendation_ids: list[str],
) -> str:
    """Content-derived learning result id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r57-4",
                "signal_ids": sorted(signal_ids),
                "pattern_ids": sorted(pattern_ids),
                "recommendation_ids": sorted(recommendation_ids),
            }
        ).encode("utf-8")
    ).hexdigest()
    return "clr-" + digest[:16]


# ---------------------------------------------------------------------------
# Safety gate (defense in depth)
# ---------------------------------------------------------------------------


def _collect_text(value: object, depth: int = 0) -> str:
    """Collect string content only (structural keys and flags are excluded).

    Flag-based attacks are handled separately by
    :func:`_collect_forbidden_flags`; scanning only string content avoids
    false positives from legitimate negative keys such as
    ``vulnerability_confirmed: false``.
    """

    if depth > 6:
        return ""
    parts: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            parts.append(_collect_text(item, depth + 1))
    elif isinstance(value, (list, tuple)):
        for item in value:
            parts.append(_collect_text(item, depth + 1))
    elif isinstance(value, str):
        parts.append(value)
    return " ".join(parts)


def _collect_forbidden_flags(value: object, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key).strip().lower()
            if key_text in _FORBIDDEN_TRUE_KEYS and item is True:
                return True
            if _collect_forbidden_flags(item, depth + 1):
                return True
    elif isinstance(value, (list, tuple)):
        for item in value:
            if _collect_forbidden_flags(item, depth + 1):
                return True
    return False


_SAFE_MARKER_PREFIXES: tuple[str, ...] = (
    "NO_",
    "NOT_",
    "NON_",
    "WITHOUT_",
    "AVOID_",
    "PREVENT_",
    "DISABLE_",
)


def _marker_present(text: str, marker: str) -> bool:
    """True when a forbidden marker occurs without a safe negation prefix."""

    start = 0
    while True:
        index = text.find(marker, start)
        if index == -1:
            return False
        window = text[max(0, index - 8):index]
        if not any(
            window.endswith(prefix) for prefix in _SAFE_MARKER_PREFIXES
        ):
            return True
        start = index + len(marker)


def unsafe_input_reason(value: object) -> str:
    """Closed safety reason when an input requests forbidden behavior."""

    if _collect_forbidden_flags(value):
        return "AUTONOMOUS_OR_EXECUTION_FLAG_REJECTED"
    text = _collect_text(value).upper()
    for marker in FORBIDDEN_LEARNING_MARKERS:
        if _marker_present(text, marker):
            return "FORBIDDEN_LEARNING_CLAIM"
    return ""


# ---------------------------------------------------------------------------
# Signal construction
# ---------------------------------------------------------------------------


def _provenance(
    *,
    source_rule_version: str = "",
    orchestration_id: str = "",
    finding_rule_version: str = "",
    correlation_rule_version: str = "",
    priority_rule_version: str = "",
    decision_rule_version: str = "",
    prioritization_id: str = "",
    correlation_id: str = "",
    decision_id_value: str = "",
) -> dict:
    return {
        "prioritization_id": prioritization_id,
        "correlation_id": correlation_id,
        "orchestration_id": orchestration_id,
        "decision_id": decision_id_value,
        "source_rule_version": source_rule_version,
        "finding_rule_version": finding_rule_version,
        "correlation_rule_version": correlation_rule_version,
        "priority_rule_version": priority_rule_version,
        "decision_rule_version": decision_rule_version,
        "research_only": True,
    }


def make_signal(
    *,
    signal_type: str,
    source_layer: str,
    observation: str,
    feedback_kind: str = FEEDBACK_KIND_QUALITY,
    category: str = "UNKNOWN",
    specialist_name: str = "",
    agent_id: str = "",
    finding_id: str = "",
    decision_id_value: str = "",
    subject_reference: str = "",
    evidence_strength: str = STRENGTH_WEAK,
    confidence: str = "UNKNOWN",
    supporting_references: list[str] | None = None,
    provenance: dict | None = None,
    governance: dict | None = None,
    decision_context: dict | None = None,
) -> dict:
    """Build one sanitized continuous-learning signal (read-only)."""

    category = _category(category)
    sid = signal_id(
        signal_type,
        source_layer,
        category,
        agent_id,
        finding_id,
        decision_id_value,
        subject_reference,
        observation,
        feedback_kind,
    )
    limitations = list(_BASE_SIGNAL_LIMITATIONS)
    if feedback_kind == FEEDBACK_KIND_WORKFLOW:
        limitations.append(LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL)
    if evidence_strength == STRENGTH_WEAK:
        limitations.append(LIMITATION_SINGLE_OBSERVATION)
    governance_value = governance or {}
    if _upper(governance_value.get("reference_state")) != "REFERENCED":
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    provenance_value = provenance or {}
    if not _text(provenance_value.get("orchestration_id")):
        limitations.append(LIMITATION_PROVENANCE_INCOMPLETE)
    return sanitize_continuous_learning_signal(
        {
            "rule_version": "r57-1",
            "signal_id": sid,
            "signal_type": signal_type,
            "source_layer": source_layer,
            "category": category,
            "specialist_name": specialist_name,
            "agent_id": agent_id,
            "finding_id": finding_id,
            "decision_id": decision_id_value,
            "subject_reference": subject_reference,
            "observation": observation,
            "feedback_kind": feedback_kind,
            "evidence_strength": evidence_strength,
            "confidence": confidence,
            "supporting_references": supporting_references or [],
            "decision_context": decision_context or {},
            "provenance": provenance_value,
            "governance": governance_value,
            "limitations": limitations,
        }
    )


# ---------------------------------------------------------------------------
# Source extraction (R42-R56)
# ---------------------------------------------------------------------------


def signals_from_evaluations(
    evaluations: object, orchestration_id: str = ""
) -> list[dict]:
    """Extract signals from R42 evaluation results (read-only)."""

    signals: list[dict] = []
    if not isinstance(evaluations, (list, tuple)):
        return signals
    for evaluation in evaluations:
        if not isinstance(evaluation, dict):
            continue
        agent_id = _text(evaluation.get("evaluated_agent_id"))
        category = _category(evaluation.get("evaluated_agent_category"))
        rating = _upper(evaluation.get("overall_rating"))
        safety = _upper(evaluation.get("safety_state"))
        gate = _upper(evaluation.get("hard_gate_state"))
        provenance = _provenance(
            source_rule_version=_text(evaluation.get("rule_version")),
            orchestration_id=orchestration_id,
        )
        if safety == "FAILED" or gate == "FAIL_SAFETY":
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_SAFETY_ISSUE,
                    source_layer=SOURCE_LAYER_R42,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    agent_id=agent_id,
                    subject_reference=f"SAFETY:{safety or 'UNKNOWN'}",
                    evidence_strength=STRENGTH_STRONG,
                    supporting_references=[gate] if gate else [],
                    provenance=provenance,
                )
            )
        if rating in ("WEAK", "CRITICAL", "UNKNOWN", ""):
            if rating:
                signals.append(
                    make_signal(
                        signal_type=SIGNAL_REPEATED_QUALITY_ISSUE,
                        source_layer=SOURCE_LAYER_R42,
                        observation=OBSERVATION_ISSUE,
                        category=category,
                        agent_id=agent_id,
                        subject_reference=f"RATING:{rating}",
                        evidence_strength=STRENGTH_MODERATE,
                        provenance=provenance,
                    )
                )
        elif rating in ("GOOD", "EXCELLENT") and safety == "PASS" and (
            gate != "FAIL_SAFETY"
        ):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_SPECIALIST_RELIABILITY,
                    source_layer=SOURCE_LAYER_R42,
                    observation=OBSERVATION_SUCCESS,
                    category=category,
                    agent_id=agent_id,
                    subject_reference=f"RATING:{rating}",
                    evidence_strength=STRENGTH_MODERATE,
                    confidence="MEDIUM",
                    provenance=provenance,
                )
            )
        diagnostics = evaluation.get("diagnostics")
        if isinstance(diagnostics, (list, tuple)):
            for diagnostic in diagnostics:
                if not isinstance(diagnostic, dict):
                    continue
                code = _upper(diagnostic.get("diagnostic_code"))
                signal_type = R42_DIAGNOSTIC_SIGNAL.get(code)
                if not signal_type:
                    continue
                severity = _upper(diagnostic.get("severity"))
                strength = R42_SEVERITY_STRENGTH.get(
                    severity, STRENGTH_WEAK
                )
                signals.append(
                    make_signal(
                        signal_type=signal_type,
                        source_layer=SOURCE_LAYER_R42,
                        observation=OBSERVATION_ISSUE,
                        category=category,
                        agent_id=agent_id,
                        subject_reference=code,
                        evidence_strength=strength,
                        supporting_references=[severity]
                        if severity
                        else [],
                        provenance=provenance,
                    )
                )
    return signals


def signals_from_collaboration(
    collaboration: object, orchestration_id: str = ""
) -> list[dict]:
    """Extract signals from an R43 collaboration result (read-only)."""

    signals: list[dict] = []
    if not isinstance(collaboration, dict):
        return signals
    provenance = _provenance(
        source_rule_version=_text(collaboration.get("rule_version")),
        orchestration_id=orchestration_id,
    )
    for conflict in collaboration.get("conflicts") or ():
        if not isinstance(conflict, dict):
            continue
        subjects = [
            _text(item) for item in conflict.get("subjects") or ()
        ]
        signals.append(
            make_signal(
                signal_type=SIGNAL_RECURRING_CONFLICT,
                source_layer=SOURCE_LAYER_R43,
                observation=OBSERVATION_ISSUE,
                agent_id=subjects[0] if subjects else "",
                subject_reference=(
                    _upper(conflict.get("conflict_type")) or "CONFLICT"
                ),
                evidence_strength=STRENGTH_MODERATE,
                supporting_references=[
                    _upper(conflict.get("resolution_state"))
                ]
                if conflict.get("resolution_state")
                else [],
                provenance=provenance,
            )
        )
    for group in collaboration.get("hypothesis_groups") or ():
        if not isinstance(group, dict):
            continue
        if _upper(group.get("correlation_type")) != "DUPLICATE":
            continue
        agents = [
            _text(item) for item in group.get("participating_agents") or ()
        ]
        signals.append(
            make_signal(
                signal_type=SIGNAL_REPEATED_DUPLICATION,
                source_layer=SOURCE_LAYER_R43,
                observation=OBSERVATION_ISSUE,
                agent_id=agents[0] if agents else "",
                subject_reference="DUPLICATE_GROUP",
                evidence_strength=STRENGTH_MODERATE,
                supporting_references=agents[:4],
                provenance=provenance,
            )
        )
    return signals


def signals_from_feedback(
    feedback: object, orchestration_id: str = ""
) -> list[dict]:
    """Extract signals from an R44 feedback result (read-only)."""

    signals: list[dict] = []
    if not isinstance(feedback, dict):
        return signals
    provenance = _provenance(
        source_rule_version=_text(feedback.get("rule_version")),
        orchestration_id=orchestration_id,
    )
    classifications = [
        item
        for item in feedback.get("classifications") or ()
        if isinstance(item, dict)
    ]
    if classifications:
        for classification in classifications:
            signal_type = R44_CLASSIFICATION_SIGNAL.get(
                _upper(classification.get("classification"))
            )
            if not signal_type:
                continue
            is_success = signal_type in (
                SIGNAL_SUCCESSFUL_RESEARCH_PATTERN,
            )
            signals.append(
                make_signal(
                    signal_type=signal_type,
                    source_layer=SOURCE_LAYER_R44,
                    observation=(
                        OBSERVATION_SUCCESS
                        if is_success
                        else OBSERVATION_ISSUE
                    ),
                    category=classification.get("subject"),
                    specialist_name=_text(
                        classification.get("source_agent")
                    ),
                    agent_id=_text(classification.get("source_agent")),
                    subject_reference=_upper(
                        classification.get("classification")
                    ),
                    evidence_strength=STRENGTH_MODERATE,
                    confidence=_upper(classification.get("confidence")),
                    provenance=provenance,
                )
            )
        return signals
    for learning_signal in feedback.get("learning_signals") or ():
        if not isinstance(learning_signal, dict):
            continue
        signal_type = R44_SIGNAL_MAP.get(
            _upper(learning_signal.get("signal_type"))
        )
        if not signal_type:
            continue
        is_success = signal_type == SIGNAL_SUCCESSFUL_RESEARCH_PATTERN
        signals.append(
            make_signal(
                signal_type=signal_type,
                source_layer=SOURCE_LAYER_R44,
                observation=(
                    OBSERVATION_SUCCESS if is_success else OBSERVATION_ISSUE
                ),
                category=learning_signal.get("subject"),
                agent_id=_text(learning_signal.get("source_agent")),
                subject_reference=_upper(
                    learning_signal.get("signal_type")
                ),
                evidence_strength=STRENGTH_MODERATE,
                confidence=_upper(learning_signal.get("confidence")),
                provenance=provenance,
            )
        )
    return signals


def _finding_governance(finding: dict) -> dict:
    return finding.get("governance") or {}


def signals_from_findings(
    finding_intelligence: object,
) -> list[dict]:
    """Extract signals from R53 finding intelligence (read-only)."""

    signals: list[dict] = []
    if not isinstance(finding_intelligence, dict):
        return signals
    findings = finding_intelligence.get("findings")
    if not isinstance(findings, (list, tuple)):
        return signals
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        identity = finding.get("identity") or {}
        assessment = finding.get("assessment") or {}
        evidence = finding.get("evidence") or {}
        context = finding.get("context") or {}
        hypotheses = finding.get("hypotheses") or {}
        correlation = finding.get("correlation") or {}
        provenance_block = finding.get("provenance") or {}
        finding_id_value = _text(identity.get("finding_id"))
        category = _category(identity.get("category"))
        agent_id = _text(identity.get("agent_id"))
        specialist_name = _text(identity.get("specialist_name"))
        state = _upper(finding.get("state"))
        confidence = _upper(assessment.get("confidence")) or "UNKNOWN"
        completeness = _upper(evidence.get("evidence_completeness"))
        context_count = _bounded_int(
            context.get("context_fact_count"), 0, 64
        )
        hypothesis_count = _bounded_int(
            hypotheses.get("hypothesis_count"), 0, 64
        )
        governance = _finding_governance(finding)
        provenance = _provenance(
            source_rule_version=_text(finding.get("rule_version")),
            orchestration_id=_text(provenance_block.get("orchestration_id")),
            finding_rule_version=_text(finding.get("rule_version")),
        )
        if completeness in ("MISSING", "PARTIAL") or state == (
            "NEEDS_MORE_EVIDENCE"
        ):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_EVIDENCE_GAP,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference=completeness or state,
                    evidence_strength=STRENGTH_MODERATE,
                    confidence=confidence,
                    provenance=provenance,
                    governance=governance,
                )
            )
        if state == "INSUFFICIENT_EVIDENCE" or hypothesis_count == 0:
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_WEAK_HYPOTHESIS,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference=state or "NO_HYPOTHESES",
                    evidence_strength=STRENGTH_MODERATE,
                    confidence=confidence,
                    provenance=provenance,
                    governance=governance,
                )
            )
        if context_count == 0:
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_CONTEXT_GAP,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="CONTEXT_MISSING",
                    evidence_strength=STRENGTH_WEAK,
                    provenance=provenance,
                    governance=governance,
                )
            )
        if confidence == "HIGH" and completeness != "COMPLETE":
            signals.append(
                make_signal(
                    signal_type=SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference=f"CONFIDENCE:{confidence}",
                    evidence_strength=STRENGTH_MODERATE,
                    confidence=confidence,
                    provenance=provenance,
                    governance=governance,
                )
            )
        if (
            confidence in ("LOW", "UNKNOWN")
            and state in ("EVIDENCE_SUPPORTED", "CONFIRMED_OBSERVED")
            and completeness == "COMPLETE"
        ):
            signals.append(
                make_signal(
                    signal_type=(
                        SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION
                    ),
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference=f"CONFIDENCE:{confidence}",
                    evidence_strength=STRENGTH_MODERATE,
                    confidence=confidence,
                    provenance=provenance,
                    governance=governance,
                )
            )
        duplicate_groups = _bounded_int(
            correlation.get("duplicate_group_count"), 0, 64
        )
        if duplicate_groups:
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_DUPLICATION,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="DUPLICATE_GROUPS",
                    evidence_strength=STRENGTH_MODERATE,
                    provenance=provenance,
                    governance=governance,
                )
            )
        conflicts = correlation.get("conflicts")
        if state == "CONFLICTED" or (
            isinstance(conflicts, (list, tuple)) and conflicts
        ):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_RECURRING_CONFLICT,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="FINDING_CONFLICT",
                    evidence_strength=STRENGTH_MODERATE,
                    provenance=provenance,
                    governance=governance,
                )
            )
        reference_state = _upper(governance.get("reference_state"))
        if reference_state != "REFERENCED":
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_GOVERNANCE_ISSUE,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="GOVERNANCE_UNKNOWN",
                    evidence_strength=STRENGTH_WEAK,
                    provenance=provenance,
                    governance=governance,
                )
            )
        if not _text(provenance_block.get("orchestration_id")):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_PROVENANCE_ISSUE,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="ORCHESTRATION_ID_MISSING",
                    evidence_strength=STRENGTH_WEAK,
                    provenance=provenance,
                    governance=governance,
                )
            )
        safety = _upper(assessment.get("safety_state"))
        gate = _upper(assessment.get("hard_gate_state"))
        if safety == "FAILED" or gate == "FAIL_SAFETY":
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_SAFETY_ISSUE,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="FINDING_SAFETY_STATE",
                    evidence_strength=STRENGTH_STRONG,
                    provenance=provenance,
                    governance=governance,
                )
            )
        rating = _upper(assessment.get("evaluation_rating"))
        if rating in ("WEAK", "CRITICAL"):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_QUALITY_ISSUE,
                    source_layer=SOURCE_LAYER_R53,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference=f"EVALUATION_RATING:{rating}",
                    evidence_strength=STRENGTH_WEAK,
                    provenance=provenance,
                    governance=governance,
                )
            )
    return signals


def _reference_categories(correlation: dict) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for reference in correlation.get("finding_references") or ():
        if not isinstance(reference, dict):
            continue
        finding_id_value = _text(reference.get("finding_id"))
        if finding_id_value:
            mapping[finding_id_value] = _category(
                reference.get("category")
            )
    return mapping


def signals_from_correlation(
    correlation: object,
) -> list[dict]:
    """Extract signals from an R54 correlation result (read-only)."""

    signals: list[dict] = []
    if not isinstance(correlation, dict):
        return signals
    correlation_id_value = _text(correlation.get("correlation_id"))
    categories = _reference_categories(correlation)
    for relationship in correlation.get("relationships") or ():
        if not isinstance(relationship, dict):
            continue
        relationship_type = _upper(relationship.get("relationship_type"))
        if relationship_type not in ("CONFLICTING", "DUPLICATE"):
            continue
        source = _text(relationship.get("source_finding_id"))
        target = _text(relationship.get("target_finding_id"))
        signal_type = (
            SIGNAL_RECURRING_CONFLICT
            if relationship_type == "CONFLICTING"
            else SIGNAL_REPEATED_DUPLICATION
        )
        signals.append(
            make_signal(
                signal_type=signal_type,
                source_layer=SOURCE_LAYER_R54,
                observation=OBSERVATION_ISSUE,
                category=categories.get(source, "UNKNOWN"),
                agent_id=_text(relationship.get("source_agent_id")),
                finding_id=source,
                subject_reference=relationship_type,
                evidence_strength=STRENGTH_MODERATE,
                supporting_references=[
                    item
                    for item in (source, target)
                    if item
                ],
                provenance=_provenance(
                    source_rule_version=_text(
                        correlation.get("rule_version")
                    ),
                    correlation_rule_version=(
                        _text(correlation.get("relationship_rule_version"))
                        or _text(correlation.get("rule_version"))
                    ),
                    correlation_id=correlation_id_value,
                ),
            )
        )
    return signals


def signals_from_prioritization(
    prioritization: object,
) -> list[dict]:
    """Extract signals from an R55 prioritization result (read-only)."""

    signals: list[dict] = []
    if not isinstance(prioritization, dict):
        return signals
    prioritization_id_value = _text(
        prioritization.get("prioritization_id")
    )
    priority_rule_version = _text(
        prioritization.get("priority_rule_version")
    )
    plans = list(prioritization.get("ranked_findings") or ()) + list(
        prioritization.get("deferred_findings") or ()
    )
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        finding_id_value = _text(plan.get("finding_id"))
        category = _category(plan.get("category"))
        agent_id = _text(plan.get("agent_id"))
        specialist_name = _text(plan.get("specialist_name"))
        provenance_block = plan.get("provenance") or {}
        governance = plan.get("governance") or {}
        summary = plan.get("correlation_summary") or {}
        relationship_types = summary.get("relationship_types") or ()
        common_provenance = _provenance(
            source_rule_version=_text(plan.get("rule_version")),
            orchestration_id=_text(provenance_block.get("orchestration_id")),
            finding_rule_version=_text(
                provenance_block.get("finding_rule_version")
            ),
            priority_rule_version=priority_rule_version,
            prioritization_id=prioritization_id_value,
        )
        if _upper(plan.get("conflict_state")) == "CONFLICT_PRESENT":
            signals.append(
                make_signal(
                    signal_type=SIGNAL_RECURRING_CONFLICT,
                    source_layer=SOURCE_LAYER_R55,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="PRIORITY_CONFLICT_CONTEXT",
                    evidence_strength=STRENGTH_MODERATE,
                    provenance=common_provenance,
                    governance=governance,
                )
            )
        if "DUPLICATE" in relationship_types:
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_DUPLICATION,
                    source_layer=SOURCE_LAYER_R55,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="PRIORITY_DUPLICATE_CONTEXT",
                    evidence_strength=STRENGTH_MODERATE,
                    provenance=common_provenance,
                    governance=governance,
                )
            )
        governance_constrained = any(
            isinstance(factor, dict)
            and _upper(factor.get("factor")) == "GOVERNANCE_CONSTRAINT"
            for factor in plan.get("priority_factors") or ()
        )
        if (
            _upper(governance.get("reference_state")) != "REFERENCED"
            or governance_constrained
        ):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_GOVERNANCE_ISSUE,
                    source_layer=SOURCE_LAYER_R55,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="PRIORITY_GOVERNANCE_CONTEXT",
                    evidence_strength=STRENGTH_MODERATE,
                    provenance=common_provenance,
                    governance=governance,
                )
            )
        if not _text(provenance_block.get("orchestration_id")):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_REPEATED_PROVENANCE_ISSUE,
                    source_layer=SOURCE_LAYER_R55,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="PRIORITY_PROVENANCE_MISSING",
                    evidence_strength=STRENGTH_WEAK,
                    provenance=common_provenance,
                    governance=governance,
                )
            )
        if (
            _upper(plan.get("priority_band")) == "LOW"
            and _upper(plan.get("evidence_completeness")) == "COMPLETE"
            and _upper(plan.get("state"))
            in ("EVIDENCE_SUPPORTED", "CONFIRMED_OBSERVED")
            and _upper(plan.get("conflict_state")) != "CONFLICT_PRESENT"
        ):
            signals.append(
                make_signal(
                    signal_type=SIGNAL_PRIORITIZATION_MISMATCH,
                    source_layer=SOURCE_LAYER_R55,
                    observation=OBSERVATION_ISSUE,
                    category=category,
                    specialist_name=specialist_name,
                    agent_id=agent_id,
                    finding_id=finding_id_value,
                    subject_reference="LOW_BAND_STRONG_EVIDENCE",
                    evidence_strength=STRENGTH_MODERATE,
                    confidence=_upper(plan.get("confidence")),
                    provenance=common_provenance,
                    governance=governance,
                )
            )
    return signals


def signals_from_human_review(
    human_review: object,
) -> list[dict]:
    """Extract workflow-feedback signals from an R56 result (read-only)."""

    signals: list[dict] = []
    if not isinstance(human_review, dict):
        return signals
    decision_rule_version = _text(
        human_review.get("decision_rule_version")
    ) or _text((human_review.get("provenance") or {}).get(
        "decision_rule_version"
    ))
    for review in human_review.get("reviews") or ():
        if not isinstance(review, dict):
            continue
        decision = review.get("decision")
        if not isinstance(decision, dict) or not decision:
            continue
        decision_type = _upper(decision.get("decision_type"))
        signal_type = DECISION_SIGNAL.get(decision_type)
        if not signal_type:
            continue
        reference = review.get("finding_reference") or {}
        priority_reference = review.get("priority_reference") or {}
        provenance_block = review.get("provenance") or {}
        governance = review.get("governance") or {}
        finding_id_value = _text(review.get("finding_id"))
        category = _category(reference.get("category"))
        agent_id = _text(reference.get("agent_id"))
        decision_context = {
            "present": True,
            "decision_source": decision.get("decision_source"),
            "decision_authority": decision.get("decision_authority"),
            "human_authority": decision.get("human_authority"),
        }
        is_positive = signal_type == SIGNAL_HUMAN_APPROVED_RESEARCH
        common = dict(
            source_layer=SOURCE_LAYER_R56,
            feedback_kind=FEEDBACK_KIND_WORKFLOW,
            category=category,
            agent_id=agent_id,
            finding_id=finding_id_value,
            decision_id_value=_text(decision.get("decision_id")),
            evidence_strength=STRENGTH_MODERATE,
            decision_context=decision_context,
            provenance=_provenance(
                source_rule_version=_text(decision.get("rule_version")),
                orchestration_id=_text(
                    provenance_block.get("orchestration_id")
                ),
                finding_rule_version=_text(
                    provenance_block.get("finding_rule_version")
                ),
                priority_rule_version=_text(
                    provenance_block.get("priority_rule_version")
                ),
                decision_rule_version=decision_rule_version,
                prioritization_id=_text(
                    provenance_block.get("prioritization_id")
                ),
                correlation_id=_text(
                    provenance_block.get("correlation_id")
                ),
                decision_id_value=_text(decision.get("decision_id")),
            ),
            governance=governance,
        )
        signals.append(
            make_signal(
                signal_type=signal_type,
                observation=(
                    OBSERVATION_SUCCESS
                    if is_positive
                    else OBSERVATION_WORKFLOW_FEEDBACK
                ),
                subject_reference=decision_type,
                supporting_references=[
                    _text(priority_reference.get("priority_band"))
                ]
                if priority_reference.get("priority_band")
                else [],
                **common,
            )
        )
        rationale = decision.get("rationale") or {}
        for code in rationale.get("rationale_codes") or ():
            corroborating = RATIONALE_SIGNAL.get(_upper(code))
            if not corroborating:
                continue
            signals.append(
                make_signal(
                    signal_type=corroborating,
                    observation=OBSERVATION_WORKFLOW_FEEDBACK,
                    subject_reference=_upper(code),
                    supporting_references=[decision_type],
                    **common,
                )
            )
    return signals


# ---------------------------------------------------------------------------
# Dedupe and aggregation
# ---------------------------------------------------------------------------


def dedupe_signals(signals: object) -> list[dict]:
    """Deterministic content-addressed dedupe, sorted by signal id.

    Deduplication and truncation happen after canonical sorting so the result
    is independent of input ordering.
    """

    unique: dict[str, dict] = {}
    for signal in signals or ():
        if not isinstance(signal, dict):
            continue
        sid = _text(signal.get("signal_id"))
        if not sid or sid in unique:
            continue
        unique[sid] = signal
    return [unique[sid] for sid in sorted(unique)][:MAX_SIGNALS]


def _derive_indicator(family: str, members: list[dict]) -> str:
    if family == PATTERN_EVIDENCE_GAP:
        return INDICATOR_EVIDENCE_GAP_RECURRING
    if family == PATTERN_CONTEXT_GAP:
        return INDICATOR_CONTEXT_GAP_RECURRING
    if family == PATTERN_HYPOTHESIS_WEAKNESS:
        return INDICATOR_HYPOTHESIS_WEAKNESS_RECURRING
    if family == PATTERN_CONFIDENCE_CALIBRATION:
        over = sum(
            1
            for member in members
            if member.get("signal_type")
            == SIGNAL_RECURRING_CONFIDENCE_OVERESTIMATION
        )
        under = sum(
            1
            for member in members
            if member.get("signal_type")
            == SIGNAL_RECURRING_CONFIDENCE_UNDERESTIMATION
        )
        if over > under:
            return INDICATOR_CONFIDENCE_OVERESTIMATION
        if under > over:
            return INDICATOR_CONFIDENCE_UNDERESTIMATION
        return INDICATOR_CONFIDENCE_MIXED
    if family == PATTERN_DUPLICATION:
        return INDICATOR_DUPLICATION_OVERLAP
    if family == PATTERN_CONFLICT:
        return INDICATOR_CONFLICT_RECURRENCE
    if family == PATTERN_GOVERNANCE:
        return INDICATOR_GOVERNANCE_RECURRENCE
    if family == PATTERN_PROVENANCE:
        return INDICATOR_PROVENANCE_RECURRENCE
    if family == PATTERN_SAFETY:
        return INDICATOR_SAFETY_RECURRENCE
    if family == PATTERN_QUALITY:
        return INDICATOR_QUALITY_RECURRENCE
    if family == PATTERN_SUCCESS:
        return INDICATOR_SUCCESS_PATTERN
    if family == PATTERN_WORKFLOW_FEEDBACK:
        return INDICATOR_WORKFLOW_FEEDBACK_PATTERN
    if family == PATTERN_PRIORITY_ALIGNMENT:
        return INDICATOR_PRIORITY_MISALIGNMENT
    if family == PATTERN_SPECIALIST_RELIABILITY:
        return INDICATOR_SPECIALIST_RELIABILITY
    return INDICATOR_UNKNOWN


def _derive_strength(
    family: str, frequency: int, cross_layer_support: int
) -> str:
    if family == PATTERN_SAFETY:
        return STRENGTH_STRONG
    if cross_layer_support >= 3:
        return STRENGTH_STRONG
    if cross_layer_support == 2 and frequency >= 3:
        return STRENGTH_STRONG
    if cross_layer_support == 2 or frequency >= 3:
        return STRENGTH_MODERATE
    return STRENGTH_WEAK


def _strength_confidence(strength: str) -> str:
    if strength == STRENGTH_STRONG:
        return "HIGH"
    if strength == STRENGTH_MODERATE:
        return "MEDIUM"
    return "LOW"


def _unique_or_blank(values: list[str]) -> str:
    if len(values) == 1:
        return values[0]
    return ""


def _aggregate_pattern_provenance(members: list[dict]) -> dict:
    return {
        "prioritization_ids": _sorted_unique(
            (member.get("provenance") or {}).get("prioritization_id")
            for member in members
        ),
        "correlation_ids": _sorted_unique(
            (member.get("provenance") or {}).get("correlation_id")
            for member in members
        ),
        "orchestration_ids": _sorted_unique(
            (member.get("provenance") or {}).get("orchestration_id")
            for member in members
        ),
        "finding_rule_versions": _sorted_unique(
            (member.get("provenance") or {}).get("finding_rule_version")
            for member in members
        ),
        "priority_rule_versions": _sorted_unique(
            (member.get("provenance") or {}).get("priority_rule_version")
            for member in members
        ),
        "decision_rule_versions": _sorted_unique(
            (member.get("provenance") or {}).get("decision_rule_version")
            for member in members
        ),
        "research_only": True,
    }


def _aggregate_governance(members: list[dict]) -> dict:
    canonical = sorted(
        {
            _canonical(member.get("governance") or {})
            for member in members
        }
    )
    if len(canonical) == 1:
        return members[0].get("governance") or {}
    return {}


def _pattern_limitations(
    members: list[dict], frequency: int, cross_layer_support: int
) -> list[str]:
    limitations = list(_BASE_PATTERN_LIMITATIONS)
    if any(
        member.get("feedback_kind") == FEEDBACK_KIND_WORKFLOW
        for member in members
    ):
        limitations.append(LIMITATION_HUMAN_DECISION_NOT_TRUTH_LABEL)
    if any(
        _upper((member.get("governance") or {}).get("reference_state"))
        != "REFERENCED"
        for member in members
    ):
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if any(
        not _text((member.get("provenance") or {}).get("orchestration_id"))
        for member in members
    ):
        limitations.append(LIMITATION_PROVENANCE_INCOMPLETE)
    if frequency == 1 and cross_layer_support >= 2:
        limitations.append(LIMITATION_SINGLE_OBSERVATION)
    return limitations


def aggregate_patterns(signals: object) -> list[dict]:
    """Conservative deterministic pattern aggregation (read-only)."""

    groups: dict[tuple[str, str], list[dict]] = {}
    for signal in signals or ():
        if not isinstance(signal, dict):
            continue
        family = SIGNAL_TO_PATTERN.get(_upper(signal.get("signal_type")))
        if not family:
            continue
        key = (family, _text(signal.get("category")) or "UNKNOWN")
        groups.setdefault(key, []).append(signal)

    patterns: list[dict] = []
    for key in sorted(
        groups,
        key=lambda item: (
            PATTERN_TYPE_ORDER.get(item[0], 99),
            item[1],
        ),
    ):
        family, category = key
        members = sorted(
            groups[key], key=lambda item: _text(item.get("signal_id"))
        )
        frequency = len(members)
        layers = sorted(
            {_text(member.get("source_layer")) for member in members},
            key=lambda layer: (
                SOURCE_LAYERS.index(layer)
                if layer in SOURCE_LAYERS
                else 99
            ),
        )
        cross_layer_support = len(layers)
        if frequency < 2 and cross_layer_support < 2:
            continue
        indicator = _derive_indicator(family, members)
        strength = _derive_strength(
            family, frequency, cross_layer_support
        )
        recommendation_codes = list(
            INDICATOR_RECOMMENDATION.get(indicator, ())
        )
        signal_ids = [
            _text(member.get("signal_id")) for member in members
        ]
        decision_ids = _sorted_unique(
            member.get("decision_id") for member in members
        )
        decision_types = _sorted_unique(
            _text(member.get("subject_reference"))
            for member in members
            if _upper(member.get("signal_type")) in DECISION_SIGNAL.values()
        )
        decision_context = {
            "present": bool(decision_ids),
            "decision_source": "HUMAN" if decision_ids else "",
            "decision_authority": "HUMAN" if decision_ids else "",
            "human_authority": bool(decision_ids),
        }
        payload = {
            "rule_version": "r57-2",
            "pattern_id": pattern_id(family, category, signal_ids),
            "pattern_type": family,
            "source_layers": layers,
            "category": category,
            "specialist_name": _unique_or_blank(
                _sorted_unique(
                    member.get("specialist_name") for member in members
                )
            ),
            "agent_id": _unique_or_blank(
                _sorted_unique(
                    member.get("agent_id") for member in members
                )
            ),
            "frequency": frequency,
            "cross_layer_support": cross_layer_support,
            "supporting_signal_ids": sorted(signal_ids),
            "supporting_finding_ids": _sorted_unique(
                member.get("finding_id") for member in members
            ),
            "supporting_decision_ids": decision_ids,
            "supporting_decision_types": decision_types,
            "calibration_indicator": indicator,
            "calibration_recommendation_codes": recommendation_codes,
            "evidence_strength": strength,
            "confidence": _strength_confidence(strength),
            "decision_context": decision_context,
            "provenance": _aggregate_pattern_provenance(members),
            "governance": _aggregate_governance(members),
            "limitations": _pattern_limitations(
                members, frequency, cross_layer_support
            ),
        }
        patterns.append(sanitize_learning_pattern(payload))
        if len(patterns) >= MAX_PATTERNS:
            break
    return patterns


def _recommendation_limitations(
    pattern: dict, recommendation_code: str
) -> list[str]:
    limitations = [
        code
        for code in CALIBRATION_LIMITATIONS
        if code
        not in (
            LIMITATION_GOVERNANCE_UNKNOWN,
            LIMITATION_PROVENANCE_INCOMPLETE,
            LIMITATION_INSUFFICIENT_DATA,
        )
    ]
    governance = pattern.get("governance") or {}
    if _upper(governance.get("reference_state")) != "REFERENCED":
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    provenance = pattern.get("provenance") or {}
    if not (provenance.get("orchestration_ids") or []):
        limitations.append(LIMITATION_PROVENANCE_INCOMPLETE)
    return [code for code in CALIBRATION_LIMITATIONS if code in limitations]


def _recommendation_rationales(
    pattern: dict, recommendation_code: str
) -> list[str]:
    rationales = [
        RATIONALE_RECURRING_OBSERVATION,
        RATIONALE_GOVERNANCE_PRESERVED,
    ]
    if pattern.get("cross_layer_support", 0) >= 2:
        rationales.append(RATIONALE_CROSS_LAYER_CORROBORATION)
    if pattern.get("frequency", 0) >= 2:
        rationales.append(RATIONALE_RECURRENCE_COUNT)
    decision_context = pattern.get("decision_context") or {}
    if decision_context.get("present"):
        rationales.append(RATIONALE_HUMAN_WORKFLOW_FEEDBACK)
        rationales.append(RATIONALE_HUMAN_DECISION_NOT_TRUTH_LABEL)
    if recommendation_code == CALIB_REQUEST_MORE_EVIDENCE:
        rationales.append(RATIONALE_EVIDENCE_GAP)
    if recommendation_code == CALIB_REVIEW_SAFETY_BOUNDARY:
        rationales.append(RATIONALE_SAFETY_BOUNDARY)
    if recommendation_code == CALIB_PRESERVE_SUCCESS_PATTERN:
        rationales.append(RATIONALE_SUCCESS_PATTERN)
    if recommendation_code == CALIB_REVIEW_PRIORITY_ALIGNMENT:
        rationales.append(RATIONALE_PRIORITY_ALIGNMENT)
    if recommendation_code == CALIB_REVIEW_SPECIALIST_RELIABILITY:
        rationales.append(RATIONALE_SPECIALIST_RELIABILITY)
    if pattern.get("evidence_strength") == STRENGTH_WEAK:
        rationales.append(RATIONALE_LIMITED_SUPPORT)
    return rationales


def build_calibration_recommendations(patterns: object) -> list[dict]:
    """Build ranked advisory calibration recommendations (read-only)."""

    candidates: list[tuple] = []
    for pattern in patterns or ():
        if not isinstance(pattern, dict):
            continue
        pattern_id_value = _text(pattern.get("pattern_id"))
        scope = PATTERN_SCOPE.get(
            _upper(pattern.get("pattern_type")), SCOPE_CATEGORY
        )
        for code in pattern.get("calibration_recommendation_codes") or ():
            recommendation = sanitize_calibration_recommendation(
                {
                    "rule_version": "r57-3",
                    "recommendation_id": recommendation_id(
                        code, pattern_id_value, scope
                    ),
                    "recommendation_code": code,
                    "target_scope": scope,
                    "category": pattern.get("category"),
                    "specialist_name": pattern.get("specialist_name"),
                    "pattern_id": pattern_id_value,
                    "supporting_pattern_ids": [pattern_id_value],
                    "supporting_signal_ids": pattern.get(
                        "supporting_signal_ids"
                    ),
                    "rationale_codes": _recommendation_rationales(
                        pattern, code
                    ),
                    "evidence_strength": pattern.get("evidence_strength"),
                    "confidence": pattern.get("confidence"),
                    "human_feedback_basis": (
                        pattern.get("decision_context") or {}
                    ).get("present", False),
                    "provenance": {
                        "orchestration_id": (
                            (pattern.get("provenance") or {}).get(
                                "orchestration_ids"
                            )
                            or [""]
                        )[0],
                        "prioritization_id": (
                            (pattern.get("provenance") or {}).get(
                                "prioritization_ids"
                            )
                            or [""]
                        )[0],
                        "correlation_id": (
                            (pattern.get("provenance") or {}).get(
                                "correlation_ids"
                            )
                            or [""]
                        )[0],
                        "finding_rule_version": (
                            (pattern.get("provenance") or {}).get(
                                "finding_rule_versions"
                            )
                            or [""]
                        )[0],
                        "priority_rule_version": (
                            (pattern.get("provenance") or {}).get(
                                "priority_rule_versions"
                            )
                            or [""]
                        )[0],
                        "decision_rule_version": (
                            (pattern.get("provenance") or {}).get(
                                "decision_rule_versions"
                            )
                            or [""]
                        )[0],
                    },
                    "governance": pattern.get("governance"),
                    "limitations": _recommendation_limitations(
                        pattern, code
                    ),
                }
            )
            safety_first = (
                0 if code == CALIB_REVIEW_SAFETY_BOUNDARY else 1
            )
            candidates.append(
                (
                    safety_first,
                    -STRENGTH_ORDER.get(
                        pattern.get("evidence_strength"), 0
                    ),
                    _bounded_int(pattern.get("frequency"), 0, MAX_SIGNALS),
                    RECOMMENDATION_ORDER.get(code, 99),
                    pattern_id_value,
                    recommendation,
                )
            )
    candidates.sort(key=lambda item: item[:5])
    recommendations: list[dict] = []
    seen: set[str] = set()
    for _, _, _, _, _, recommendation in candidates:
        rid = recommendation.get("recommendation_id", "")
        if not rid or rid in seen:
            continue
        seen.add(rid)
        recommendation["recommendation_rank"] = len(recommendations) + 1
        recommendations.append(recommendation)
        if len(recommendations) >= MAX_PATTERNS:
            break
    return recommendations


# ---------------------------------------------------------------------------
# Summary, provenance and governance
# ---------------------------------------------------------------------------


def build_summary(
    signals: list[dict],
    patterns: list[dict],
    recommendations: list[dict],
) -> dict:
    """Deterministic aggregate learning summary."""

    source_layer_counts = {layer: 0 for layer in SOURCE_LAYERS}
    signal_type_counts = {
        signal_type: 0
        for signal_type in CONTINUOUS_LEARNING_SIGNAL_TYPES
    }
    pattern_type_counts = {
        pattern_type: 0 for pattern_type in LEARNING_PATTERN_TYPES
    }
    recommendation_code_counts = {
        code: 0 for code in RECOMMENDATION_ORDER
    }
    decision_ids: list[str] = []
    for signal in signals:
        layer = _upper(signal.get("source_layer"))
        if layer in source_layer_counts:
            source_layer_counts[layer] += 1
        signal_type = _upper(signal.get("signal_type"))
        if signal_type in signal_type_counts:
            signal_type_counts[signal_type] += 1
        decision_id_value = _text(signal.get("decision_id"))
        if decision_id_value and decision_id_value not in decision_ids:
            decision_ids.append(decision_id_value)
    for pattern in patterns:
        pattern_type = _upper(pattern.get("pattern_type"))
        if pattern_type in pattern_type_counts:
            pattern_type_counts[pattern_type] += 1
    for recommendation in recommendations:
        code = _upper(recommendation.get("recommendation_code"))
        if code in recommendation_code_counts:
            recommendation_code_counts[code] += 1
    return {
        "signal_count": len(signals),
        "pattern_count": len(patterns),
        "recommendation_count": len(recommendations),
        "source_layer_counts": source_layer_counts,
        "signal_type_counts": signal_type_counts,
        "pattern_type_counts": pattern_type_counts,
        "recommendation_code_counts": recommendation_code_counts,
        "workflow_feedback_signal_count": sum(
            1
            for signal in signals
            if signal.get("feedback_kind") == FEEDBACK_KIND_WORKFLOW
        ),
        "cross_layer_pattern_count": sum(
            1
            for pattern in patterns
            if _bounded_int(pattern.get("cross_layer_support"), 0, 7) >= 2
        ),
        "safety_pattern_count": sum(
            1
            for pattern in patterns
            if _upper(pattern.get("pattern_type")) == PATTERN_SAFETY
        ),
        "human_decision_count": len(decision_ids),
        "research_only": True,
    }


def aggregate_governance(signals: list[dict]) -> dict:
    """Aggregate governance over signals (referenced/unknown)."""

    referenced: list[str] = []
    unknown: list[str] = []
    ready: list[str] = []
    not_ready: list[str] = []
    for signal in signals:
        finding_id_value = _text(signal.get("finding_id"))
        governance = signal.get("governance") or {}
        if _upper(governance.get("reference_state")) == "REFERENCED":
            if finding_id_value and finding_id_value not in referenced:
                referenced.append(finding_id_value)
            if governance.get("ready") is True:
                if finding_id_value and finding_id_value not in ready:
                    ready.append(finding_id_value)
            else:
                if finding_id_value and finding_id_value not in not_ready:
                    not_ready.append(finding_id_value)
        elif finding_id_value:
            if finding_id_value not in unknown:
                unknown.append(finding_id_value)
    if referenced and unknown:
        state = "MIXED"
    elif referenced:
        state = "CONSISTENT_REFERENCED"
    else:
        state = "UNKNOWN"
    return {
        "governance_state": state,
        "referenced_finding_ids": sorted(referenced),
        "unknown_finding_ids": sorted(unknown),
        "ready_finding_ids": sorted(ready),
        "not_ready_finding_ids": sorted(not_ready),
        "research_only": True,
    }


def build_result_provenance(signals: list[dict]) -> dict:
    """Aggregate container-level learning provenance."""

    layers = {
        _upper(signal.get("source_layer")) for signal in signals
    }
    return {
        "rule_version": "r57-4",
        "signal_rule_version": "r57-1",
        "pattern_rule_version": "r57-2",
        "recommendation_rule_version": "r57-3",
        "source_layers": [
            layer for layer in SOURCE_LAYERS if layer in layers
        ],
        "orchestration_ids": _sorted_unique(
            (signal.get("provenance") or {}).get("orchestration_id")
            for signal in signals
        ),
        "prioritization_ids": _sorted_unique(
            (signal.get("provenance") or {}).get("prioritization_id")
            for signal in signals
        ),
        "correlation_ids": _sorted_unique(
            (signal.get("provenance") or {}).get("correlation_id")
            for signal in signals
        ),
        "decision_ids": _sorted_unique(
            signal.get("decision_id") for signal in signals
        ),
        "finding_rule_versions": _sorted_unique(
            (signal.get("provenance") or {}).get("finding_rule_version")
            for signal in signals
        ),
        "deterministic": True,
        "research_only": True,
    }


def result_limitations(
    signals: list[dict],
    patterns: list[dict],
    recommendations: list[dict],
    skipped: list[dict],
) -> list[str]:
    """Deterministic container limitations."""

    limitations = [
        code
        for code in CALIBRATION_LIMITATIONS
        if code
        not in (
            LIMITATION_GOVERNANCE_UNKNOWN,
            LIMITATION_PROVENANCE_INCOMPLETE,
            LIMITATION_INSUFFICIENT_DATA,
        )
    ]
    if not signals:
        limitations.append(LIMITATION_INSUFFICIENT_DATA)
    if skipped:
        limitations.append(LIMITATION_UNSUPPORTED_INPUT)
    if any(
        _upper((signal.get("governance") or {}).get("reference_state"))
        != "REFERENCED"
        for signal in signals
        if signal.get("finding_id")
    ):
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if any(
        not _text((signal.get("provenance") or {}).get("orchestration_id"))
        for signal in signals
    ):
        limitations.append(LIMITATION_PROVENANCE_INCOMPLETE)
    if not patterns:
        limitations.append(LIMITATION_SINGLE_OBSERVATION)
    return [code for code in CALIBRATION_LIMITATIONS if code in limitations]


__all__ = [
    "CONTINUOUS_LEARNING_RULES_RULE_VERSION",
    "RULE_VERSION",
    "SIGNAL_TO_PATTERN",
    "R42_DIAGNOSTIC_SIGNAL",
    "R42_SEVERITY_STRENGTH",
    "R44_CLASSIFICATION_SIGNAL",
    "R44_SIGNAL_MAP",
    "DECISION_SIGNAL",
    "RATIONALE_SIGNAL",
    "INDICATOR_RECOMMENDATION",
    "PATTERN_SCOPE",
    "FORBIDDEN_LEARNING_MARKERS",
    "signal_id",
    "pattern_id",
    "recommendation_id",
    "learning_id",
    "unsafe_input_reason",
    "make_signal",
    "signals_from_evaluations",
    "signals_from_collaboration",
    "signals_from_feedback",
    "signals_from_findings",
    "signals_from_correlation",
    "signals_from_prioritization",
    "signals_from_human_review",
    "dedupe_signals",
    "aggregate_patterns",
    "build_calibration_recommendations",
    "build_summary",
    "aggregate_governance",
    "build_result_provenance",
    "result_limitations",
]
