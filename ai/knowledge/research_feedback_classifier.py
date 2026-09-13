"""Stage R44.2 deterministic feedback classifier (pure engine).

Classifies feedback events into deterministic learning categories:

    "What kind of learning does this structured research outcome suggest?"

Hard boundaries encoded here:

- Learning only: classification uses structured signals only. No LLM, no
  semantic inference beyond structured indicators, no execution, no network,
  no database, no browser, no payloads.
- R42/R43 outputs are consumed, never recomputed.
- Classification is advisory; it never modifies agents, rules or runtime
  behavior.
- Deterministic: classification, reasons, signals and confidence are pure
  functions of the bounded event.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.

Priority: SAFETY, CONFLICT, DUPLICATION, CONFIDENCE, EVIDENCE, HYPOTHESIS,
SUCCESS, GOVERNANCE, PROVENANCE, QUALITY, UNKNOWN. Specific structured
signals are evaluated before generic unknown governance/provenance so a
concrete calibration or evidence gap is not masked by default unknowns. The
SUCCESS pattern requires an entirely clean structured result (no evaluation
diagnostics, no conflicts, no duplicates).
"""

from __future__ import annotations

from ai.schemas.research_feedback_classification import (
    CLASSIFICATION_CONFIDENCE_CALIBRATION,
    CLASSIFICATION_CONFLICT_PATTERN,
    CLASSIFICATION_DUPLICATION_PATTERN,
    CLASSIFICATION_EVIDENCE_GAP,
    CLASSIFICATION_GOVERNANCE_ISSUE,
    CLASSIFICATION_HYPOTHESIS_WEAKNESS,
    CLASSIFICATION_LIMITATIONS,
    CLASSIFICATION_PROVENANCE_ISSUE,
    CLASSIFICATION_QUALITY_IMPROVEMENT,
    CLASSIFICATION_SAFETY_ISSUE,
    CLASSIFICATION_SUCCESS_PATTERN,
    CLASSIFICATION_UNKNOWN,
    LIMITATION_INSUFFICIENT_DATA,
    REASON_CONFIDENCE_MISCALIBRATION,
    REASON_CONFLICTS_PRESENT,
    REASON_DUPLICATE_GROUPS,
    REASON_EVIDENCE_GAP,
    REASON_FORBIDDEN_CLAIM,
    REASON_GOVERNANCE_INCONSISTENT,
    REASON_GOVERNANCE_UNKNOWN,
    REASON_HARD_GATE_FAIL_SAFETY,
    REASON_HYPOTHESIS_WEAKNESS,
    REASON_INSUFFICIENT_DATA,
    REASON_LOW_QUALITY,
    REASON_OBSERVED_ISSUE,
    REASON_OBSERVED_SUCCESS,
    REASON_PROVENANCE_MISSING,
    REASON_RESEARCH_ONLY_FALSE,
    REASON_SAFETY_LIMITATION_MISSING,
    REASON_SAFETY_STATE_FAILED,
    REASON_STRONG_EVALUATION,
    RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION,
    SIGNAL_COLLABORATION_CONFLICTS,
    SIGNAL_COLLABORATION_DUPLICATE_GROUPS,
    SIGNAL_COLLABORATION_EVIDENCE_STATE,
    SIGNAL_EVALUATION_DIAGNOSTIC,
    SIGNAL_EVALUATION_DIMENSION_SCORE,
    SIGNAL_EVALUATION_HARD_GATE,
    SIGNAL_EVALUATION_OVERALL_RATING,
    SIGNAL_EVALUATION_PRESENT,
    SIGNAL_EVALUATION_SAFETY_STATE,
    SIGNAL_GOVERNANCE_STATE,
    SIGNAL_OBSERVED_ISSUE,
    SIGNAL_OBSERVED_SUCCESS,
    SIGNAL_PROVENANCE_STATE,
    ResearchFeedbackClassificationPlan,
    research_feedback_classification_plan_projection,
)
from ai.schemas.research_feedback_event import (
    ISSUE_CONFLICTING_HYPOTHESES,
    ISSUE_DUPLICATE_HYPOTHESES,
    ISSUE_EVIDENCE_INCONSISTENT,
    ISSUE_FORBIDDEN_CLAIM,
    ISSUE_GOVERNANCE_INCONSISTENT,
    ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE,
    ISSUE_MISSING_EVIDENCE_REQUIREMENT,
    ISSUE_MISSING_PROVENANCE,
    ISSUE_NO_HYPOTHESES,
    ISSUE_NONE_OBSERVED,
    ISSUE_RESEARCH_ONLY_FALSE,
    ISSUE_SAFETY_LIMITATION_MISSING,
    ISSUE_UNKNOWN,
    ISSUE_UNKNOWN_GOVERNANCE,
    ISSUE_WEAK_HYPOTHESIS_SIGNALS,
    SUCCESS_COMPLETE_EVIDENCE,
    SUCCESS_SAFE_RESEARCH,
    SUCCESS_STRONG_EVALUATION,
    SUCCESS_UNKNOWN,
    sanitize_research_feedback_event,
)

RESEARCH_FEEDBACK_CLASSIFIER_RULE_VERSION = "r44-2"
RULE_VERSION = RESEARCH_FEEDBACK_CLASSIFIER_RULE_VERSION

SAFETY_ISSUE_CODES: tuple[str, ...] = (
    ISSUE_FORBIDDEN_CLAIM,
    ISSUE_SAFETY_LIMITATION_MISSING,
    ISSUE_RESEARCH_ONLY_FALSE,
)

GOVERNANCE_ISSUE_CODES: tuple[str, ...] = (
    ISSUE_UNKNOWN_GOVERNANCE,
    ISSUE_GOVERNANCE_INCONSISTENT,
)

PROVENANCE_ISSUE_CODES: tuple[str, ...] = (ISSUE_MISSING_PROVENANCE,)

CONFLICT_ISSUE_CODES: tuple[str, ...] = (ISSUE_CONFLICTING_HYPOTHESES,)

DUPLICATION_ISSUE_CODES: tuple[str, ...] = (ISSUE_DUPLICATE_HYPOTHESES,)

CONFIDENCE_ISSUE_CODES: tuple[str, ...] = (
    ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE,
)

EVIDENCE_ISSUE_CODES: tuple[str, ...] = (
    ISSUE_MISSING_EVIDENCE_REQUIREMENT,
    ISSUE_EVIDENCE_INCONSISTENT,
)

HYPOTHESIS_ISSUE_CODES: tuple[str, ...] = (
    ISSUE_WEAK_HYPOTHESIS_SIGNALS,
    ISSUE_NO_HYPOTHESES,
)

SUCCESS_CODES: tuple[str, ...] = (
    SUCCESS_STRONG_EVALUATION,
    SUCCESS_COMPLETE_EVIDENCE,
    SUCCESS_SAFE_RESEARCH,
)

SAFETY_DIAGNOSTICS: tuple[str, ...] = (
    "RESEARCH_ONLY_FALSE",
    "VULNERABILITY_CONFIRMATION_CLAIM",
    "EXECUTION_CLAIM_DETECTED",
    "SAFETY_LIMITATION_MISSING",
)

GOVERNANCE_DIAGNOSTICS: tuple[str, ...] = (
    "GOVERNANCE_UNKNOWN",
    "GOVERNANCE_INCONSISTENT",
)

PROVENANCE_DIAGNOSTICS: tuple[str, ...] = (
    "PROVENANCE_INCOMPLETE",
    "PROVENANCE_INVENTED_LAYER",
)

CONFIDENCE_DIAGNOSTICS: tuple[str, ...] = (
    "CONFIDENCE_OVERSTATED",
    "CONFIDENCE_UNDERSPECIFIED",
)

EVIDENCE_DIAGNOSTICS: tuple[str, ...] = (
    "MISSING_EVIDENCE_REQUIREMENT",
    "EVIDENCE_INCONSISTENT",
    "EVIDENCE_REQUIRED_LIMITATION_MISSING",
)

HYPOTHESIS_DIAGNOSTICS: tuple[str, ...] = (
    "UNSUPPORTED_HYPOTHESIS",
    "NO_HYPOTHESES_REPORTED",
    "HYPOTHESIS_SAFETY_FLAGS_MISSING",
)

QUALITY_DIAGNOSTICS: tuple[str, ...] = (
    "MISSING_REQUIRED_FIELD",
    "INVALID_RULE_VERSION",
    "INVALID_ENUM_VALUE",
    "UNKNOWN_AGENT_CATEGORY",
    "MALFORMED_HYPOTHESIS",
    "MALFORMED_EVIDENCE_PLAN",
    "MALFORMED_PROVENANCE",
    "MALFORMED_GOVERNANCE",
    "MALFORMED_LIMITATIONS",
    "CONTEXT_TOO_SPARSE",
    "NON_DETERMINISTIC_OUTPUT",
    "LIMITATION_DISCLOSURE_INCOMPLETE",
)

_STRONG_RATINGS: tuple[str, ...] = ("EXCELLENT", "GOOD")
_WEAK_RATINGS: tuple[str, ...] = ("WEAK", "CRITICAL")


def _result(
    context: dict,
    classification: str,
    reasons: list[str],
    signals: list[str],
    confidence: str,
) -> dict:
    event = context["event"]
    limitations = [
        code
        for code in CLASSIFICATION_LIMITATIONS
        if code != LIMITATION_INSUFFICIENT_DATA
    ]
    if classification == CLASSIFICATION_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_DATA)
    plan = ResearchFeedbackClassificationPlan(
        rule_version=RESEARCH_FEEDBACK_CLASSIFICATION_RULE_VERSION,
        classification=classification,
        subject=event.get("source_category") or "UNKNOWN",
        source_agent=event.get("source_agent") or "",
        feedback_id=event.get("feedback_id") or "",
        reasons=reasons,
        supporting_signals=signals,
        confidence=confidence,
        limitations=limitations,
    )
    return research_feedback_classification_plan_projection(plan)


def _confidence_for(context: dict, structured: bool) -> str:
    observed = (
        context["issue"] not in (ISSUE_NONE_OBSERVED, ISSUE_UNKNOWN)
        or context["success"] not in (SUCCESS_UNKNOWN, "NONE_OBSERVED")
    )
    if observed and structured:
        return "HIGH"
    if structured or observed:
        return "MEDIUM"
    return "LOW"


def _safety_branch(context: dict) -> dict | None:
    evaluation = context["evaluation"]
    conflict_types = context["conflict_types"]
    issue = context["issue"]
    diagnostics = context["diagnostics"]
    structured = (
        (
            context["evaluation_present"]
            and evaluation.get("safety_state") == "FAILED"
        )
        or (
            context["evaluation_present"]
            and evaluation.get("hard_gate_state") == "FAIL_SAFETY"
        )
        or ("SAFETY_CONFLICT" in conflict_types)
        or bool(diagnostics & set(SAFETY_DIAGNOSTICS))
    )
    if issue not in SAFETY_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if issue in SAFETY_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        if issue == ISSUE_FORBIDDEN_CLAIM:
            reasons.append(REASON_FORBIDDEN_CLAIM)
        elif issue == ISSUE_RESEARCH_ONLY_FALSE:
            reasons.append(REASON_RESEARCH_ONLY_FALSE)
        elif issue == ISSUE_SAFETY_LIMITATION_MISSING:
            reasons.append(REASON_SAFETY_LIMITATION_MISSING)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if context["evaluation_present"]:
        signals.append(SIGNAL_EVALUATION_PRESENT)
        if evaluation.get("safety_state") == "FAILED":
            reasons.append(REASON_SAFETY_STATE_FAILED)
            signals.append(SIGNAL_EVALUATION_SAFETY_STATE)
        if evaluation.get("hard_gate_state") == "FAIL_SAFETY":
            reasons.append(REASON_HARD_GATE_FAIL_SAFETY)
            signals.append(SIGNAL_EVALUATION_HARD_GATE)
    if "SAFETY_CONFLICT" in conflict_types:
        reasons.append(REASON_CONFLICTS_PRESENT)
        signals.append(SIGNAL_COLLABORATION_CONFLICTS)
    if diagnostics & set(SAFETY_DIAGNOSTICS):
        signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_SAFETY_ISSUE, reasons, signals,
        _confidence_for(context, structured),
    )


def _conflict_branch(context: dict) -> dict | None:
    collaboration = context["collaboration"]
    structured = context["collaboration_present"] and (
        collaboration.get("conflict_count") or 0
    ) > 0
    if context["issue"] not in CONFLICT_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in CONFLICT_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if structured:
        reasons.append(REASON_CONFLICTS_PRESENT)
        signals.append(SIGNAL_EVALUATION_PRESENT)
        signals.append(SIGNAL_COLLABORATION_CONFLICTS)
    return _result(
        context, CLASSIFICATION_CONFLICT_PATTERN, reasons, signals,
        _confidence_for(context, structured),
    )


def _duplication_branch(context: dict) -> dict | None:
    collaboration = context["collaboration"]
    structured = context["collaboration_present"] and (
        collaboration.get("duplicate_group_count") or 0
    ) > 0
    if context["issue"] not in DUPLICATION_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in DUPLICATION_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if structured:
        reasons.append(REASON_DUPLICATE_GROUPS)
        signals.append(SIGNAL_COLLABORATION_DUPLICATE_GROUPS)
    return _result(
        context, CLASSIFICATION_DUPLICATION_PATTERN, reasons, signals,
        _confidence_for(context, structured),
    )


def _confidence_branch(context: dict) -> dict | None:
    evaluation = context["evaluation"]
    diagnostics = context["diagnostics"]
    structured = bool(diagnostics & set(CONFIDENCE_DIAGNOSTICS)) or (
        context["evaluation_present"]
        and (evaluation.get("confidence_score") or 0) < 60
    )
    if context["issue"] not in CONFIDENCE_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in CONFIDENCE_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if structured:
        reasons.append(REASON_CONFIDENCE_MISCALIBRATION)
        if context["evaluation_present"]:
            signals.append(SIGNAL_EVALUATION_PRESENT)
            signals.append(SIGNAL_EVALUATION_DIMENSION_SCORE)
        if diagnostics & set(CONFIDENCE_DIAGNOSTICS):
            signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_CONFIDENCE_CALIBRATION, reasons, signals,
        _confidence_for(context, structured),
    )


def _evidence_branch(context: dict) -> dict | None:
    evaluation = context["evaluation"]
    collaboration = context["collaboration"]
    diagnostics = context["diagnostics"]
    structured = (
        bool(diagnostics & set(EVIDENCE_DIAGNOSTICS))
        or (
            context["collaboration_present"]
            and (collaboration.get("participant_count") or 0) > 0
            and collaboration.get("merged_evidence_state") == "UNKNOWN"
        )
        or (
            context["evaluation_present"]
            and (evaluation.get("evidence_score") or 0) < 60
        )
    )
    if context["issue"] not in EVIDENCE_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in EVIDENCE_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if structured:
        reasons.append(REASON_EVIDENCE_GAP)
        if context["evaluation_present"]:
            signals.append(SIGNAL_EVALUATION_PRESENT)
            signals.append(SIGNAL_EVALUATION_DIMENSION_SCORE)
        if context["collaboration_present"]:
            signals.append(SIGNAL_COLLABORATION_EVIDENCE_STATE)
        if diagnostics & set(EVIDENCE_DIAGNOSTICS):
            signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_EVIDENCE_GAP, reasons, signals,
        _confidence_for(context, structured),
    )


def _hypothesis_branch(context: dict) -> dict | None:
    diagnostics = context["diagnostics"]
    structured = bool(diagnostics & set(HYPOTHESIS_DIAGNOSTICS))
    if context["issue"] not in HYPOTHESIS_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in HYPOTHESIS_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if structured:
        reasons.append(REASON_HYPOTHESIS_WEAKNESS)
        signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_HYPOTHESIS_WEAKNESS, reasons, signals,
        _confidence_for(context, structured),
    )


def _success_branch(context: dict) -> dict | None:
    evaluation = context["evaluation"]
    collaboration = context["collaboration"]
    diagnostics = context["diagnostics"]
    success = context["success"]
    structured = (
        context["evaluation_present"]
        and evaluation.get("overall_rating") in _STRONG_RATINGS
        and evaluation.get("safety_state") == "PASS"
        and (evaluation.get("evidence_score") or 0) >= 75
        and not diagnostics
        and (
            not context["collaboration_present"]
            or (
                (collaboration.get("conflict_count") or 0) == 0
                and (collaboration.get("duplicate_group_count") or 0) == 0
            )
        )
    )
    if success not in SUCCESS_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if success in SUCCESS_CODES:
        reasons.append(REASON_OBSERVED_SUCCESS)
        signals.append(SIGNAL_OBSERVED_SUCCESS)
    if structured:
        reasons.append(REASON_STRONG_EVALUATION)
        signals.append(SIGNAL_EVALUATION_PRESENT)
        signals.append(SIGNAL_EVALUATION_OVERALL_RATING)
    if success == SUCCESS_COMPLETE_EVIDENCE and context[
        "collaboration_present"
    ]:
        signals.append(SIGNAL_COLLABORATION_EVIDENCE_STATE)
    if success == SUCCESS_SAFE_RESEARCH and context["evaluation_present"]:
        signals.append(SIGNAL_EVALUATION_SAFETY_STATE)
    return _result(
        context, CLASSIFICATION_SUCCESS_PATTERN, reasons, signals,
        _confidence_for(context, structured),
    )


def _governance_branch(context: dict) -> dict | None:
    governance = context["governance"]
    conflict_types = context["conflict_types"]
    diagnostics = context["diagnostics"]
    structured = (
        ("GOVERNANCE_CONFLICT" in conflict_types)
        or bool(diagnostics & set(GOVERNANCE_DIAGNOSTICS))
        or (
            bool(governance)
            and governance.get("reference_state") == "UNKNOWN"
        )
    )
    if context["issue"] not in GOVERNANCE_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in GOVERNANCE_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        if context["issue"] == ISSUE_GOVERNANCE_INCONSISTENT:
            reasons.append(REASON_GOVERNANCE_INCONSISTENT)
        else:
            reasons.append(REASON_GOVERNANCE_UNKNOWN)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if governance:
        signals.append(SIGNAL_GOVERNANCE_STATE)
        if governance.get("reference_state") == "UNKNOWN":
            reasons.append(REASON_GOVERNANCE_UNKNOWN)
    if "GOVERNANCE_CONFLICT" in conflict_types:
        reasons.append(REASON_CONFLICTS_PRESENT)
        signals.append(SIGNAL_COLLABORATION_CONFLICTS)
    if diagnostics & set(GOVERNANCE_DIAGNOSTICS):
        signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_GOVERNANCE_ISSUE, reasons, signals,
        _confidence_for(context, structured),
    )


def _provenance_branch(context: dict) -> dict | None:
    provenance = context["provenance"]
    conflict_types = context["conflict_types"]
    diagnostics = context["diagnostics"]
    structured = (
        ("PROVENANCE_CONFLICT" in conflict_types)
        or bool(diagnostics & set(PROVENANCE_DIAGNOSTICS))
        or (
            bool(provenance)
            and provenance.get("provenance_state") == "UNKNOWN"
        )
    )
    if context["issue"] not in PROVENANCE_ISSUE_CODES and not structured:
        return None
    reasons: list[str] = []
    signals: list[str] = []
    if context["issue"] in PROVENANCE_ISSUE_CODES:
        reasons.append(REASON_OBSERVED_ISSUE)
        reasons.append(REASON_PROVENANCE_MISSING)
        signals.append(SIGNAL_OBSERVED_ISSUE)
    if provenance:
        signals.append(SIGNAL_PROVENANCE_STATE)
        if provenance.get("provenance_state") == "UNKNOWN":
            reasons.append(REASON_PROVENANCE_MISSING)
    if "PROVENANCE_CONFLICT" in conflict_types:
        reasons.append(REASON_CONFLICTS_PRESENT)
        signals.append(SIGNAL_COLLABORATION_CONFLICTS)
    if diagnostics & set(PROVENANCE_DIAGNOSTICS):
        signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_PROVENANCE_ISSUE, reasons, signals,
        _confidence_for(context, structured),
    )


def _quality_branch(context: dict) -> dict | None:
    evaluation = context["evaluation"]
    diagnostics = context["diagnostics"]
    structured = (
        context["evaluation_present"]
        and (
            evaluation.get("overall_rating") in _WEAK_RATINGS
            or (evaluation.get("overall_score") or 0) < 75
        )
    ) or bool(diagnostics & set(QUALITY_DIAGNOSTICS))
    if not structured:
        return None
    reasons: list[str] = [REASON_LOW_QUALITY]
    signals: list[str] = []
    if context["evaluation_present"]:
        signals.append(SIGNAL_EVALUATION_PRESENT)
        signals.append(SIGNAL_EVALUATION_OVERALL_RATING)
    if diagnostics & set(QUALITY_DIAGNOSTICS):
        signals.append(SIGNAL_EVALUATION_DIAGNOSTIC)
    return _result(
        context, CLASSIFICATION_QUALITY_IMPROVEMENT, reasons, signals,
        _confidence_for(context, structured),
    )


_BRANCHES = (
    _safety_branch,
    _conflict_branch,
    _duplication_branch,
    _confidence_branch,
    _evidence_branch,
    _hypothesis_branch,
    _success_branch,
    _governance_branch,
    _provenance_branch,
    _quality_branch,
)


def classify_research_feedback(event: object = None) -> dict:
    """Classify one feedback event deterministically (read-only)."""

    bounded = sanitize_research_feedback_event(event)
    context = {
        "event": bounded,
        "evaluation": bounded.get("evaluation_reference") or {},
        "collaboration": bounded.get("collaboration_reference") or {},
        "governance": bounded.get("governance_reference") or {},
        "provenance": bounded.get("provenance") or {},
        "issue": bounded.get("observed_issue") or ISSUE_UNKNOWN,
        "success": bounded.get("observed_success") or SUCCESS_UNKNOWN,
    }
    context["evaluation_present"] = bool(
        context["evaluation"].get("present")
    )
    context["collaboration_present"] = bool(
        context["collaboration"].get("present")
    )
    context["diagnostics"] = set(
        context["evaluation"].get("diagnostic_codes") or ()
    )
    context["conflict_types"] = set(
        context["collaboration"].get("conflict_types") or ()
    )

    for branch in _BRANCHES:
        result = branch(context)
        if result is not None:
            return result
    return _result(
        context, CLASSIFICATION_UNKNOWN,
        [REASON_INSUFFICIENT_DATA], [], "UNKNOWN",
    )


def classify_research_feedback_events(events: object = None) -> list[dict]:
    """Classify a sequence of feedback events in input order (read-only)."""

    if not isinstance(events, (list, tuple)):
        return []
    return [classify_research_feedback(event) for event in events]


__all__ = [
    "RESEARCH_FEEDBACK_CLASSIFIER_RULE_VERSION",
    "RULE_VERSION",
    "SAFETY_ISSUE_CODES",
    "GOVERNANCE_ISSUE_CODES",
    "PROVENANCE_ISSUE_CODES",
    "CONFLICT_ISSUE_CODES",
    "DUPLICATION_ISSUE_CODES",
    "CONFIDENCE_ISSUE_CODES",
    "EVIDENCE_ISSUE_CODES",
    "HYPOTHESIS_ISSUE_CODES",
    "SUCCESS_CODES",
    "SAFETY_DIAGNOSTICS",
    "GOVERNANCE_DIAGNOSTICS",
    "PROVENANCE_DIAGNOSTICS",
    "CONFIDENCE_DIAGNOSTICS",
    "EVIDENCE_DIAGNOSTICS",
    "HYPOTHESIS_DIAGNOSTICS",
    "QUALITY_DIAGNOSTICS",
    "classify_research_feedback",
    "classify_research_feedback_events",
]
