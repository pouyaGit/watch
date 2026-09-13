"""Stage R31.21 deterministic research consistency validator (pure engine).

Validates the complete read-only R31.13-R31.20 evidence pipeline chain for one
Asset<->CVE research candidate:

    "Is the complete R31 research chain internally consistent?"

The validator only reports consistency. It never repairs, rewrites or
recomputes any upstream plan, never executes research, never acquires
evidence, never contacts a target, never scans, never runs Nuclei, never
crawls, never fuzzes, never exploits, never calls an LLM and never touches
Mongo.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Report-only and read-only: inputs are never mutated; the result is a new
  dict with rule version ``r31-21`` and closed issue codes.
- Authority reuse: the cross-stage expectations are read from the real
  upstream planner tables (R31.17 ``DECISION_TRANSITIONS``, R31.18
  ``LIFECYCLE_OUTCOMES``, R31.19 ``OUTCOME_FEEDBACK``, R31.20
  ``OUTCOME_SUMMARY``), so the validator cannot drift from the pipeline it
  checks.
- Deterministic: fixed check order, closed vocabularies and byte-identical
  repeated output. No randomness, no timestamps, no hashes, no external
  state.
- Never repairs: a detected issue is recorded only.
"""

from __future__ import annotations

from ai.knowledge.evidence_acquisition_planner import ACQUISITION_METHODS
from ai.knowledge.evidence_feedback_calibration_planner import (
    OUTCOME_FEEDBACK,
)
from ai.knowledge.evidence_research_loop_planner import DECISION_TRANSITIONS
from ai.knowledge.evidence_research_outcome_tracker import LIFECYCLE_OUTCOMES
from ai.knowledge.research_intelligence_summary_planner import OUTCOME_SUMMARY
from ai.schemas.evidence_confidence import (
    CONFIDENCE_CATEGORIES,
    CONFIDENCE_LEVELS,
)
from ai.schemas.evidence_decision import DECISIONS
from ai.schemas.evidence_feedback_calibration import (
    FEEDBACK_TYPES,
    FEEDBACK_UNKNOWN,
)
from ai.schemas.evidence_research_loop import (
    LIFECYCLE_STATES,
    LIFECYCLE_UNKNOWN,
)
from ai.schemas.evidence_research_outcome import (
    OUTCOMES,
    OUTCOME_UNKNOWN,
)
from ai.schemas.research_consistency_validation import (
    CHECKED_STAGES,
    DECISION_LIFECYCLE_MISMATCH,
    INVALID_ACQUISITION_METHOD,
    INVALID_CONFIDENCE_CATEGORY,
    INVALID_CONFIDENCE_LEVEL,
    INVALID_DECISION,
    INVALID_FEEDBACK_TYPE,
    INVALID_LIFECYCLE_STATE,
    INVALID_OUTCOME,
    INVALID_PRIORITIZATION_ITEMS,
    INVALID_RESEARCH_STATUS,
    LIFECYCLE_OUTCOME_MISMATCH,
    MAX_ISSUES,
    MISSING_ACQUISITION_PLAN,
    MISSING_CONFIDENCE_PLAN,
    MISSING_DECISION_PLAN,
    MISSING_FEEDBACK_PLAN,
    MISSING_LOOP_PLAN,
    MISSING_OUTCOME_PLAN,
    MISSING_PRIORITIZATION_PLAN,
    MISSING_SUMMARY_PLAN,
    OUTCOME_FEEDBACK_MISMATCH,
    OUTCOME_SUMMARY_MISMATCH,
    RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION,
    VALIDATION_INVALID,
    VALIDATION_UNKNOWN,
    VALIDATION_VALID,
    ResearchConsistencyValidationPlan,
    consistency_validation_plan_projection,
)
from ai.schemas.research_intelligence_summary import (
    RESEARCH_STATUSES,
    STATUS_UNKNOWN,
)

RESEARCH_CONSISTENCY_VALIDATOR_RULE_VERSION = "r31-21"
RULE_VERSION = RESEARCH_CONSISTENCY_VALIDATOR_RULE_VERSION

# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _present(value: object) -> bool:
    return isinstance(value, dict) and bool(value)


def _expected(table: dict, key: str, fallback: str) -> str:
    row = table.get(key)
    return row[0] if row is not None else fallback


def _result(
    *,
    status: str,
    valid: bool,
    issues: list[str],
) -> dict:
    plan = ResearchConsistencyValidationPlan(
        rule_version=RESEARCH_CONSISTENCY_VALIDATION_RULE_VERSION,
        valid=valid,
        validation_status=status,
        detected_issues=issues[:MAX_ISSUES],
        checked_stages=list(CHECKED_STAGES),
        research_only=True,
    )
    return consistency_validation_plan_projection(plan)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def validate_research_consistency(
    acquisition_plan: object = None,
    prioritization_plan: object = None,
    confidence_plan: object = None,
    decision_plan: object = None,
    loop_plan: object = None,
    outcome_plan: object = None,
    feedback_plan: object = None,
    summary_plan: object = None,
) -> dict:
    """Validate the R31.13-R31.20 chain and report closed issue codes.

    All eight inputs are consumed read-only. The validator checks mandatory
    stage presence, closed vocabulary values, and the decision -> lifecycle ->
    outcome -> feedback -> summary transitions against the authoritative
    upstream tables. It never repairs data.
    """

    acquisition = _block(acquisition_plan)
    prioritization = _block(prioritization_plan)
    confidence = _block(confidence_plan)
    decision = _block(decision_plan)
    loop = _block(loop_plan)
    outcome = _block(outcome_plan)
    feedback = _block(feedback_plan)
    summary = _block(summary_plan)

    issues: list[str] = []

    def add(issue: str) -> None:
        if issue not in issues:
            issues.append(issue)

    # -- stage presence and closed vocabulary values ------------------------
    acquisition_method = _upper(acquisition.get("acquisition_method"))
    acquisition_valid = acquisition_method in ACQUISITION_METHODS
    if not _present(acquisition_plan):
        add(MISSING_ACQUISITION_PLAN)
    elif not acquisition_valid:
        add(INVALID_ACQUISITION_METHOD)

    prioritization_valid = isinstance(
        prioritization.get("items"), (list, tuple)
    )
    if not _present(prioritization_plan):
        add(MISSING_PRIORITIZATION_PLAN)
    elif not prioritization_valid:
        add(INVALID_PRIORITIZATION_ITEMS)

    confidence_level = _upper(confidence.get("confidence_level"))
    confidence_category = _upper(confidence.get("confidence_category"))
    confidence_valid = (
        confidence_level in CONFIDENCE_LEVELS
        and confidence_category in CONFIDENCE_CATEGORIES
    )
    if not _present(confidence_plan):
        add(MISSING_CONFIDENCE_PLAN)
    else:
        if confidence_level not in CONFIDENCE_LEVELS:
            add(INVALID_CONFIDENCE_LEVEL)
        if confidence_category not in CONFIDENCE_CATEGORIES:
            add(INVALID_CONFIDENCE_CATEGORY)

    decision_value = _upper(decision.get("decision"))
    decision_valid = decision_value in DECISIONS
    if not _present(decision_plan):
        add(MISSING_DECISION_PLAN)
    elif not decision_valid:
        add(INVALID_DECISION)

    lifecycle = _upper(loop.get("lifecycle_state"))
    lifecycle_valid = lifecycle in LIFECYCLE_STATES
    if not _present(loop_plan):
        add(MISSING_LOOP_PLAN)
    elif not lifecycle_valid:
        add(INVALID_LIFECYCLE_STATE)

    outcome_value = _upper(outcome.get("outcome"))
    outcome_valid = outcome_value in OUTCOMES
    if not _present(outcome_plan):
        add(MISSING_OUTCOME_PLAN)
    elif not outcome_valid:
        add(INVALID_OUTCOME)

    feedback_value = _upper(feedback.get("feedback_type"))
    feedback_valid = feedback_value in FEEDBACK_TYPES
    if not _present(feedback_plan):
        add(MISSING_FEEDBACK_PLAN)
    elif not feedback_valid:
        add(INVALID_FEEDBACK_TYPE)

    status_value = _upper(summary.get("research_status"))
    summary_valid = status_value in RESEARCH_STATUSES
    if not _present(summary_plan):
        add(MISSING_SUMMARY_PLAN)
    elif not summary_valid:
        add(INVALID_RESEARCH_STATUS)

    # -- cross-stage consistency -------------------------------------------
    if decision_valid and lifecycle_valid:
        expected = _expected(
            DECISION_TRANSITIONS, decision_value, LIFECYCLE_UNKNOWN
        )
        if lifecycle != expected:
            add(DECISION_LIFECYCLE_MISMATCH)

    if lifecycle_valid and outcome_valid:
        expected = _expected(
            LIFECYCLE_OUTCOMES, lifecycle, OUTCOME_UNKNOWN
        )
        if outcome_value != expected:
            add(LIFECYCLE_OUTCOME_MISMATCH)

    if outcome_valid and feedback_valid:
        expected = _expected(
            OUTCOME_FEEDBACK, outcome_value, FEEDBACK_UNKNOWN
        )
        if feedback_value != expected:
            add(OUTCOME_FEEDBACK_MISMATCH)

    if outcome_valid and summary_valid:
        expected = _expected(
            OUTCOME_SUMMARY, outcome_value, STATUS_UNKNOWN
        )
        if status_value != expected:
            add(OUTCOME_SUMMARY_MISMATCH)

    # -- status -------------------------------------------------------------
    any_present = any(
        _present(value)
        for value in (
            acquisition_plan,
            prioritization_plan,
            confidence_plan,
            decision_plan,
            loop_plan,
            outcome_plan,
            feedback_plan,
            summary_plan,
        )
    )
    if not any_present:
        return _result(
            status=VALIDATION_UNKNOWN,
            valid=False,
            issues=issues,
        )
    if issues:
        return _result(
            status=VALIDATION_INVALID,
            valid=False,
            issues=issues,
        )
    return _result(
        status=VALIDATION_VALID,
        valid=True,
        issues=[],
    )


__all__ = [
    "RESEARCH_CONSISTENCY_VALIDATOR_RULE_VERSION",
    "RULE_VERSION",
    "validate_research_consistency",
]
