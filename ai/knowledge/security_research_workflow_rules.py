"""Stage R59.5 deterministic workflow rules (pure engine).

Provides the deterministic primitives behind the R59 end-to-end security
research workflow:

    normalized upstream artifacts
      -> stage facts and bounded references
      -> fixed-order workflow stages
      -> deterministic workflow state and safety status
      -> advisory next-action recommendation
      -> deterministic summary, ids, provenance and limitations

Hard boundaries encoded here:

- Workflow state only: no primitive executes, sends, scans, browses or
  modifies anything; the only side effect is returning data.
- No duplicated intelligence: upstream artifacts are consumed and validated
  through their existing rule versions; the R58 safety scanner and R57
  blocking-recommendation vocabulary are imported, never re-implemented.
- Fail closed: malformed, mis-versioned, contradictory or missing-required
  inputs produce closed structured errors; nothing is silently skipped.
- Deterministic: content-derived ids only; fixed stage ordering; stable
  sorting; no timestamps, UUIDs, pids, randomness or wall-clock time.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no database.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.execution_control_rules import (
    BLOCKING_LEARNING_RECOMMENDATIONS,
    safety_reasons_for,
    structured_safety_reasons,
)
from ai.schemas.calibration_recommendation import (
    CALIBRATION_RECOMMENDATION_CODES,
)
from ai.schemas.execution_control_result import (
    CONTROL_OUTCOME_ALLOW,
    CONTROL_OUTCOME_DENY,
    CONTROL_OUTCOME_INVALID,
    CONTROL_OUTCOME_NOT_REQUESTED,
    SAFETY_BLOCKED,
    SAFETY_INVALID,
    SAFETY_PASS,
)
from ai.schemas.finding_correlation_result import (
    FINDING_CORRELATION_RESULT_RULE_VERSION,
)
from ai.schemas.finding_result import FINDING_RESULT_RULE_VERSION
from ai.schemas.human_decision import (
    DECISION_APPROVE_RESEARCH,
    DECISION_DEFER,
    DECISION_ESCALATE,
    DECISION_NEEDS_REVIEW,
    DECISION_REJECT,
    DECISION_REQUEST_MORE_EVIDENCE,
    DECISION_STATE_DECIDED,
    DECISION_STATE_PENDING,
    HUMAN_DECISION_TYPES,
)
from ai.schemas.human_decision_result import (
    HUMAN_REVIEW_RESULT_RULE_VERSION,
)
from ai.schemas.research_priority_result import (
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
)
from ai.schemas.security_research_workflow import (
    OPTION_ENABLE_EXECUTION_REVIEW,
    OPTION_ENABLE_LEARNING,
    SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
    WORKFLOW_ID_PREFIX,
)
from ai.schemas.security_research_workflow_result import (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_INPUT,
    ERROR_MISSING_REQUIRED_STAGE,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_STAGE_ORDER_INVALID,
    ERROR_UNSUPPORTED_TRANSITION,
    ERROR_UPSTREAM_RESULT_INVALID,
    ERROR_WORKFLOW_CONFLICT,
    HUMAN_STATUS_BLOCKED,
    HUMAN_STATUS_CONFLICT,
    HUMAN_STATUS_DECIDED,
    HUMAN_STATUS_NOT_REQUESTED,
    HUMAN_STATUS_PENDING,
    HUMAN_STATUS_REVIEW_REQUIRED,
    REFERENCE_KINDS,
    RESULT_BASE_LIMITATIONS,
    SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
    SAFETY_STATUS_EXECUTION_BLOCKED,
    SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
    SAFETY_STATUS_INVALID,
    SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    SAFETY_STATUS_RESEARCH_ONLY,
    SAFETY_STATUS_SAFETY_BLOCKED,
    STATE_AWAITING_HUMAN_DECISION,
    STATE_BLOCKED,
    STATE_COLLABORATED,
    STATE_COMPLETED,
    STATE_EXECUTION_REVIEWED,
    STATE_FEEDBACK_ANALYZED,
    STATE_FINDINGS_BUILT,
    STATE_FINDINGS_CORRELATED,
    STATE_HUMAN_DECIDED,
    STATE_INITIALIZED,
    STATE_INVALID,
    STATE_LEARNING_UPDATED,
    STATE_PRIORITIZED,
    STATE_RESEARCH_READY,
    STATE_SPECIALISTS_EVALUATED,
    sanitize_workflow_reference,
)
from ai.schemas.workflow_next_action import (
    ACTION_BLOCK_WORKFLOW,
    ACTION_BUILD_FINDINGS,
    ACTION_COMPLETE_WORKFLOW,
    ACTION_CORRELATE_FINDINGS,
    ACTION_PRIORITIZE_RESEARCH,
    ACTION_REQUEST_HUMAN_REVIEW,
    ACTION_REVIEW_EXECUTION_CONTROL,
    ACTION_RUN_COLLABORATION,
    ACTION_RUN_EVALUATION,
    ACTION_RUN_FEEDBACK_ANALYSIS,
    ACTION_RUN_RESEARCH_ANALYSIS,
    ACTION_STAGE,
    ACTION_UPDATE_LEARNING,
    ACTION_WAIT_FOR_HUMAN_DECISION,
    REASON_COLLABORATION_MISSING,
    REASON_CORRELATION_MISSING,
    REASON_EXECUTION_AUTHORIZED,
    REASON_EXECUTION_BLOCKED,
    REASON_EXECUTION_READY,
    REASON_EXECUTION_REVIEW_MISSING,
    REASON_FEEDBACK_MISSING,
    REASON_FINDINGS_MISSING,
    REASON_HUMAN_DECISION_MISSING,
    REASON_HUMAN_DECISION_PENDING,
    REASON_HUMAN_DEFERRED,
    REASON_HUMAN_ESCALATED,
    REASON_HUMAN_NEEDS_REVIEW,
    REASON_HUMAN_REJECTED,
    REASON_HUMAN_REQUESTED_MORE_EVIDENCE,
    REASON_LEARNING_BLOCKING_RECOMMENDATION,
    REASON_LEARNING_MISSING,
    REASON_NO_FINDINGS_PRODUCED,
    REASON_PRIORITIZATION_MISSING,
    REASON_RESEARCH_INPUT_READY,
    REASON_SAFETY_BLOCKED,
    REASON_SPECIALIST_RESULTS_PRESENT,
    REASON_WORKFLOW_COMPLETE,
    REASON_WORKFLOW_CONFLICT,
    REASON_WORKFLOW_INVALID,
)
from ai.schemas.workflow_stage import (
    REASON_EXECUTION_BLOCKED,
    REASON_EXECUTION_READY,
    REASON_NO_FINDINGS_PRODUCED,
    REASON_RECOMMENDED_NEXT_STAGE,
    REASON_SPECIALIST_RESULTS_PRESENT,
    STAGE_BASE_LIMITATIONS,
    STAGE_COLLABORATION,
    STAGE_CORRELATION,
    STAGE_EVALUATION,
    STAGE_EXECUTION_CONTROL,
    STAGE_FEEDBACK,
    STAGE_FINDING,
    STAGE_HUMAN_REVIEW,
    STAGE_LEARNING,
    STAGE_PRIORITIZATION,
    STAGE_SPECIALIST_RESEARCH,
    STAGE_STATUS_BLOCKED,
    STAGE_STATUS_COMPLETED,
    STAGE_STATUS_INVALID,
    STAGE_STATUS_NOT_STARTED,
    STAGE_STATUS_READY,
    STAGE_STATUS_SKIPPED,
    WORKFLOW_STAGE_ORDER,
)
from ai.schemas.workflow_stage import (
    sanitize_workflow_stage as _sanitize_stage,
)

SECURITY_RESEARCH_WORKFLOW_RULES_RULE_VERSION = "r59-5"
RULE_VERSION = SECURITY_RESEARCH_WORKFLOW_RULES_RULE_VERSION

#: Upstream rule versions this workflow understands (fail closed).
EXPECTED_ORCHESTRATION_RULE_VERSION = "r52-6"
EXPECTED_EVALUATION_RULE_VERSION = "r42-5"
EXPECTED_COLLABORATION_RULE_VERSION = "r43-6"
EXPECTED_FEEDBACK_RULE_VERSION = "r52-5"
EXPECTED_FINDING_RULE_VERSION = FINDING_RESULT_RULE_VERSION
EXPECTED_CORRELATION_RULE_VERSION = FINDING_CORRELATION_RESULT_RULE_VERSION
EXPECTED_PRIORITIZATION_RULE_VERSION = (
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION
)
EXPECTED_HUMAN_REVIEW_RULE_VERSION = HUMAN_REVIEW_RESULT_RULE_VERSION
EXPECTED_LEARNING_RULE_VERSION = "r57-4"
EXPECTED_EXECUTION_CONTROL_RULE_VERSION = "r58-4"
EXPECTED_EXECUTION_REQUEST_RULE_VERSION = "r58-1"

#: R58 plan status that represents controlled readiness (never execution).
EXECUTION_READY_STATUS = "READY_FOR_EXTERNAL_EXECUTOR"

#: Fatal error categories that force the workflow into INVALID.
FATAL_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MISSING_REQUIRED_STAGE,
    ERROR_STAGE_ORDER_INVALID,
    ERROR_UPSTREAM_RESULT_INVALID,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_MALFORMED_INPUT,
)

#: Human decision types that block the workflow outright.
BLOCKING_DECISION_TYPES: tuple[str, ...] = (
    DECISION_REQUEST_MORE_EVIDENCE,
    DECISION_DEFER,
    DECISION_REJECT,
)

#: Human decision types that require further review (human boundary).
REVIEW_REQUIRED_DECISION_TYPES: tuple[str, ...] = (
    DECISION_ESCALATE,
    DECISION_NEEDS_REVIEW,
)

#: Deterministic precedence when multiple blocking decisions exist.
BLOCKING_PRECEDENCE: tuple[str, ...] = (
    DECISION_REJECT,
    DECISION_DEFER,
    DECISION_REQUEST_MORE_EVIDENCE,
)

_REVIEW_PRECEDENCE: tuple[str, ...] = (
    DECISION_ESCALATE,
    DECISION_NEEDS_REVIEW,
)

MAX_STAGE_METADATA = 24
MAX_LIST = 24
MAX_TEXT = 240


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def workflow_error(
    error_category: str, stage_type: str = "", message: str = ""
) -> dict:
    """Closed structured workflow error (never silently skipped)."""

    return {
        "stage": "SECURITY_RESEARCH_WORKFLOW",
        "error_category": error_category,
        "stage_type": stage_type,
        "message": message[:MAX_TEXT],
    }


def is_fatal(errors: object) -> bool:
    """True when any structured error is a fatal (INVALID) category."""

    if not isinstance(errors, (list, tuple)):
        return False
    for entry in errors:
        if isinstance(entry, dict) and entry.get(
            "error_category"
        ) in FATAL_ERROR_CATEGORIES:
            return True
    return False


# ---------------------------------------------------------------------------
# Deterministic ids
# ---------------------------------------------------------------------------


def workflow_id(descriptor: object) -> str:
    """Content-derived workflow id (no runtime ordering)."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
                "descriptor": descriptor,
            }
        ).encode("utf-8")
    ).hexdigest()
    return WORKFLOW_ID_PREFIX + digest[:16]


def stage_id(workflow_id_value: str, stage_type: str) -> str:
    """Content-derived stage id (stable per workflow/stage)."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r59-2",
                "workflow_id": workflow_id_value,
                "stage_type": stage_type,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "wfs-" + digest[:16]


def next_action_id(workflow_id_value: str, action_code: str, reason: str) -> str:
    """Content-derived next-action id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r59-3",
                "workflow_id": workflow_id_value,
                "action_code": action_code,
                "reason": reason,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "wna-" + digest[:16]


def workflow_result_id(
    workflow_id_value: str,
    workflow_state: str,
    stage_ids: object,
    action_code: str,
    action_reason: str,
) -> str:
    """Content-derived workflow result id."""

    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": "r59-4",
                "workflow_id": workflow_id_value,
                "workflow_state": workflow_state,
                "stage_ids": sorted(
                    _text(item) for item in (stage_ids or ()) if _text(item)
                ),
                "action_code": action_code,
                "action_reason": action_reason,
            }
        ).encode("utf-8")
    ).hexdigest()
    return "wrr-" + digest[:16]


# ---------------------------------------------------------------------------
# Safety gate (reuses the R58 scanner; never duplicated)
# ---------------------------------------------------------------------------


def workflow_safety_reasons(value: object) -> list[str]:
    """Closed safety reasons detected in one input (R58 scanner reused).

    A top-level list is scanned element by element: the R58 scanner treats a
    bare list as an unsupported container, and a list of valid structured
    results must not create a false safety block.
    """

    reasons: list[str] = []
    candidates = (
        list(value) if isinstance(value, (list, tuple)) else [value]
    )
    for candidate in candidates:
        for reason in safety_reasons_for(candidate):
            if reason not in reasons:
                reasons.append(reason)
        for reason in structured_safety_reasons(candidate):
            if reason not in reasons:
                reasons.append(reason)
    return reasons


def collect_safety_reasons(*values: object) -> list[str]:
    """Ordered union of safety reasons across workflow inputs."""

    reasons: list[str] = []
    for value in values:
        if value is None:
            continue
        for reason in workflow_safety_reasons(value):
            if reason not in reasons:
                reasons.append(reason)
    return reasons


# ---------------------------------------------------------------------------
# Reference projection
# ---------------------------------------------------------------------------


def make_reference(
    reference_kind: str,
    *,
    present: bool,
    reference_id: str = "",
    rule_version: str = "",
    status: str = "",
    item_count: int = 0,
) -> dict:
    """Build one bounded upstream reference."""

    kind = reference_kind if reference_kind in REFERENCE_KINDS else ""
    return sanitize_workflow_reference(
        {
            "present": present,
            "reference_kind": kind,
            "reference_id": reference_id,
            "rule_version": rule_version,
            "status": status,
            "item_count": item_count,
        }
    )


def evaluation_safety_state(evaluations: object) -> str:
    """Deterministic aggregate safety state of R42 evaluation results."""

    states = []
    for entry in evaluations or ():
        if isinstance(entry, dict):
            state = _upper(entry.get("safety_state"))
            if state in ("PASS", "DEGRADED", "FAILED"):
                states.append(state)
    if not states:
        return "UNKNOWN"
    if "FAILED" in states:
        return "FAILED"
    if "DEGRADED" in states:
        return "DEGRADED"
    return "PASS"


# ---------------------------------------------------------------------------
# Human decision facts (R56 remains authoritative)
# ---------------------------------------------------------------------------


def human_decision_summary(review_result: object) -> dict:
    """Deterministic summary of the R56 review result (read-only)."""

    if not isinstance(review_result, dict) or not review_result:
        return _empty_human_summary()
    if (
        _text(review_result.get("rule_version"))
        != EXPECTED_HUMAN_REVIEW_RULE_VERSION
    ):
        summary = _empty_human_summary()
        summary["error"] = ERROR_RULE_VERSION_MISMATCH
        return summary
    decided: list[dict] = []
    pending = 0
    for review in review_result.get("reviews") or ():
        if not isinstance(review, dict):
            continue
        decision = review.get("decision")
        if review.get("review_state") == DECISION_STATE_DECIDED and isinstance(
            decision, dict
        ) and decision:
            decided.append(decision)
        elif review.get("review_state") == DECISION_STATE_PENDING:
            pending += 1
    types: list[str] = []
    for decision in decided:
        dtype = _upper(decision.get("decision_type"))
        if dtype in HUMAN_DECISION_TYPES and dtype not in types:
            types.append(dtype)
    blocks = [t for t in BLOCKING_PRECEDENCE if t in types]
    reviews = [t for t in _REVIEW_PRECEDENCE if t in types]
    approved = DECISION_APPROVE_RESEARCH in types
    categories = set()
    if approved:
        categories.add("APPROVE")
    if blocks:
        categories.add("BLOCK")
    if reviews:
        categories.add("REVIEW")
    conflict = len(categories) > 1
    if conflict:
        human_status = HUMAN_STATUS_CONFLICT
    elif blocks:
        human_status = HUMAN_STATUS_BLOCKED
    elif reviews:
        human_status = HUMAN_STATUS_REVIEW_REQUIRED
    elif approved:
        human_status = HUMAN_STATUS_DECIDED
    elif pending:
        human_status = HUMAN_STATUS_PENDING
    else:
        human_status = HUMAN_STATUS_NOT_REQUESTED
    execution_authorized = any(
        decision.get("execution_authorized") is True for decision in decided
    )
    vulnerability_confirmed = any(
        decision.get("vulnerability_confirmed") is True
        for decision in decided
    )
    return {
        "present": True,
        "decided_count": len(decided),
        "pending_count": pending,
        "decision_ids": [
            _text(decision.get("decision_id"))
            for decision in decided
            if _text(decision.get("decision_id"))
        ][:MAX_LIST],
        "decision_types": types,
        "human_status": human_status,
        "blocking_type": blocks[0] if blocks else "",
        "review_type": reviews[0] if reviews else "",
        "approved": approved and not conflict,
        "conflict": conflict,
        "execution_authorized": execution_authorized,
        "vulnerability_confirmed": vulnerability_confirmed,
        "error": "",
    }


def _empty_human_summary() -> dict:
    return {
        "present": False,
        "decided_count": 0,
        "pending_count": 0,
        "decision_ids": [],
        "decision_types": [],
        "human_status": HUMAN_STATUS_NOT_REQUESTED,
        "blocking_type": "",
        "review_type": "",
        "approved": False,
        "conflict": False,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "error": "",
    }


# ---------------------------------------------------------------------------
# Learning facts (R57 is advisory only)
# ---------------------------------------------------------------------------


def learning_summary(learning_result: object) -> dict:
    """Deterministic summary of the R57 learning result (read-only)."""

    if not isinstance(learning_result, dict) or not learning_result:
        return {
            "present": False,
            "pattern_count": 0,
            "recommendation_count": 0,
            "blocking_codes": [],
            "blocking_count": 0,
            "error": "",
        }
    if (
        _text(learning_result.get("rule_version"))
        != EXPECTED_LEARNING_RULE_VERSION
    ):
        return {
            "present": False,
            "pattern_count": 0,
            "recommendation_count": 0,
            "blocking_codes": [],
            "blocking_count": 0,
            "error": ERROR_RULE_VERSION_MISMATCH,
        }
    codes: list[str] = []
    for recommendation in learning_result.get(
        "calibration_recommendations"
    ) or ():
        if isinstance(recommendation, dict):
            code = _upper(recommendation.get("recommendation_code"))
            if code in CALIBRATION_RECOMMENDATION_CODES and code not in codes:
                codes.append(code)
    blocking = [
        code for code in codes if code in BLOCKING_LEARNING_RECOMMENDATIONS
    ]
    return {
        "present": True,
        "pattern_count": len(learning_result.get("patterns") or ()),
        "recommendation_count": len(
            learning_result.get("calibration_recommendations") or ()
        ),
        "blocking_codes": blocking,
        "blocking_count": len(blocking),
        "error": "",
    }


# ---------------------------------------------------------------------------
# Execution control facts (R58 remains the final gate)
# ---------------------------------------------------------------------------


def execution_control_summary(control_result: object) -> dict:
    """Deterministic summary of the R58 control result (read-only)."""

    if not isinstance(control_result, dict) or not control_result:
        return _empty_execution_summary()
    if (
        _text(control_result.get("rule_version"))
        != EXPECTED_EXECUTION_CONTROL_RULE_VERSION
    ):
        summary = _empty_execution_summary()
        summary["error"] = ERROR_RULE_VERSION_MISMATCH
        return summary
    outcome = _upper(control_result.get("control_outcome"))
    execution_status = _upper(control_result.get("execution_status"))
    authorization_status = _upper(control_result.get("authorization_status"))
    safety_result = _upper(control_result.get("safety_result"))
    unsafe_claim = (
        control_result.get("execution_performed") is True
        or control_result.get("external_executor_present") is True
        or control_result.get("vulnerability_confirmed") is True
        or control_result.get("exploit_authorized") is True
    )
    allow_without_authorization = (
        outcome == CONTROL_OUTCOME_ALLOW
        and control_result.get("execution_authorized") is not True
    )
    return {
        "present": True,
        "control_outcome": outcome
        if outcome
        in (
            CONTROL_OUTCOME_ALLOW,
            CONTROL_OUTCOME_DENY,
            CONTROL_OUTCOME_INVALID,
            CONTROL_OUTCOME_NOT_REQUESTED,
        )
        else "",
        "authorization_status": authorization_status,
        "execution_status": execution_status,
        "safety_result": safety_result
        if safety_result in (SAFETY_PASS, SAFETY_BLOCKED, SAFETY_INVALID)
        else "",
        "authorized": outcome == CONTROL_OUTCOME_ALLOW,
        "blocked": outcome in (CONTROL_OUTCOME_DENY, CONTROL_OUTCOME_INVALID)
        or authorization_status in ("BLOCKED", "INVALID", "EXPIRED")
        or safety_result in (SAFETY_BLOCKED, SAFETY_INVALID),
        "ready": execution_status == EXECUTION_READY_STATUS,
        "unsafe_claim": unsafe_claim,
        "contradiction": allow_without_authorization,
        "error": "",
    }


def _empty_execution_summary() -> dict:
    return {
        "present": False,
        "control_outcome": "",
        "authorization_status": "",
        "execution_status": "",
        "safety_result": "",
        "authorized": False,
        "blocked": False,
        "ready": False,
        "unsafe_claim": False,
        "contradiction": False,
        "error": "",
    }


# ---------------------------------------------------------------------------
# Stage construction
# ---------------------------------------------------------------------------


def make_stage(
    workflow_id_value: str,
    stage_type: str,
    stage_status: str,
    reason: str,
    *,
    input_reference: object = None,
    output_reference: object = None,
    metadata: object = None,
    upstream_rule_version: str = "",
    upstream_reference_id: str = "",
) -> dict:
    """Build one sanitized R59 workflow stage (read-only)."""

    limitations = list(STAGE_BASE_LIMITATIONS)
    if stage_status == STAGE_STATUS_BLOCKED:
        limitations.append("BLOCKED_PENDING_HUMAN_REVIEW")
    if stage_status == STAGE_STATUS_SKIPPED:
        limitations.append("STAGE_SKIPPED_BY_OPTION")
    return _sanitize_stage(
        {
            "rule_version": "r59-2",
            "stage_id": stage_id(workflow_id_value, stage_type),
            "stage_type": stage_type,
            "stage_status": stage_status,
            "input_reference": input_reference or {},
            "output_reference": output_reference or {},
            "reason": reason,
            "deterministic_metadata": metadata or {},
            "provenance": {
                "workflow_id": workflow_id_value,
                "upstream_rule_version": upstream_rule_version,
                "upstream_reference_id": upstream_reference_id,
            },
            "governance": {},
            "limitations": limitations,
        }
    )


def stage_by_type(stages: object, stage_type: str) -> dict:
    """Return the (unique) stage of one type, or an empty dict."""

    for stage in stages or ():
        if isinstance(stage, dict) and stage.get("stage_type") == stage_type:
            return stage
    return {}


# ---------------------------------------------------------------------------
# State and next-action resolution
# ---------------------------------------------------------------------------


def _stage_status(stages: object, stage_type: str) -> str:
    return _text(stage_by_type(stages, stage_type).get("stage_status"))


def _ordered_types(stages: object, status: str) -> list[str]:
    found = set()
    for stage in stages or ():
        if isinstance(stage, dict) and stage.get("stage_status") == status:
            text = _text(stage.get("stage_type"))
            if text in WORKFLOW_STAGE_ORDER:
                found.add(text)
    return [stage for stage in WORKFLOW_STAGE_ORDER if stage in found]


def resolve_workflow_state(
    stages: object,
    errors: object,
    safety_reasons: object,
) -> dict:
    """Resolve the deterministic workflow state and safety status.

    Returns ``{state, safety_status, action_code, action_reason,
    execution_blocked}``.
    """

    options = _resolve_options_from_stages(stages)
    human = _resolve_human_status(stages)
    execution = _resolve_execution_status(stages)

    # ------------------------------------------------------------------
    # Fatal input conditions
    # ------------------------------------------------------------------
    if is_fatal(errors):
        return _resolution(
            STATE_INVALID,
            SAFETY_STATUS_INVALID,
            ACTION_BLOCK_WORKFLOW,
            REASON_WORKFLOW_INVALID,
            True,
        )

    # ------------------------------------------------------------------
    # Conflicting inputs (fail closed; never silently resolved)
    # ------------------------------------------------------------------
    if any(
        isinstance(entry, dict)
        and entry.get("error_category") == ERROR_WORKFLOW_CONFLICT
        for entry in (errors or ())
    ):
        return _resolution(
            STATE_BLOCKED,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
            ACTION_BLOCK_WORKFLOW,
            REASON_WORKFLOW_CONFLICT,
            True,
        )

    # ------------------------------------------------------------------
    # Safety gate
    # ------------------------------------------------------------------
    if list(safety_reasons or ()):
        return _resolution(
            STATE_BLOCKED,
            SAFETY_STATUS_SAFETY_BLOCKED,
            ACTION_BLOCK_WORKFLOW,
            REASON_SAFETY_BLOCKED,
            True,
        )

    # ------------------------------------------------------------------
    # Human decision boundary (R56 authoritative)
    # ------------------------------------------------------------------
    if human == HUMAN_STATUS_CONFLICT:
        return _resolution(
            STATE_BLOCKED,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
            ACTION_BLOCK_WORKFLOW,
            REASON_WORKFLOW_CONFLICT,
            True,
        )
    if human == HUMAN_STATUS_REVIEW_REQUIRED:
        review_type = _stage_metadata(
            stages, STAGE_HUMAN_REVIEW, "decision_type"
        )
        reason = (
            REASON_HUMAN_ESCALATED
            if review_type == DECISION_ESCALATE
            else REASON_HUMAN_NEEDS_REVIEW
        )
        return _resolution(
            STATE_AWAITING_HUMAN_DECISION,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
            ACTION_REQUEST_HUMAN_REVIEW,
            reason,
            True,
        )
    if human == HUMAN_STATUS_BLOCKED:
        block_type = _stage_metadata(
            stages, STAGE_HUMAN_REVIEW, "decision_type"
        )
        if block_type == DECISION_REJECT:
            return _resolution(
                STATE_BLOCKED,
                SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
                ACTION_BLOCK_WORKFLOW,
                REASON_HUMAN_REJECTED,
                True,
            )
        if block_type == DECISION_DEFER:
            return _resolution(
                STATE_BLOCKED,
                SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
                ACTION_WAIT_FOR_HUMAN_DECISION,
                REASON_HUMAN_DEFERRED,
                True,
            )
        return _resolution(
            STATE_BLOCKED,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
            ACTION_RUN_RESEARCH_ANALYSIS,
            REASON_HUMAN_REQUESTED_MORE_EVIDENCE,
            True,
        )
    if human == HUMAN_STATUS_PENDING:
        return _resolution(
            STATE_AWAITING_HUMAN_DECISION,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
            ACTION_WAIT_FOR_HUMAN_DECISION,
            REASON_HUMAN_DECISION_PENDING,
            True,
        )

    # ------------------------------------------------------------------
    # R57 learning boundary (advisory only; can block, never authorize)
    # ------------------------------------------------------------------
    learning_blocking = _bounded_int(
        _stage_metadata(stages, STAGE_LEARNING, "blocking_recommendation_count"),
        0,
        MAX_LIST,
    )
    if learning_blocking > 0:
        return _resolution(
            STATE_BLOCKED,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
            ACTION_REQUEST_HUMAN_REVIEW,
            REASON_LEARNING_BLOCKING_RECOMMENDATION,
            True,
        )

    # ------------------------------------------------------------------
    # R58 execution control boundary (final gate)
    # ------------------------------------------------------------------
    if execution["unsafe_claim"] or execution["contradiction"]:
        return _resolution(
            STATE_INVALID,
            SAFETY_STATUS_SAFETY_BLOCKED,
            ACTION_BLOCK_WORKFLOW,
            REASON_WORKFLOW_INVALID,
            True,
        )
    if execution["present"] and execution["blocked"]:
        if human in (HUMAN_STATUS_NOT_REQUESTED, HUMAN_STATUS_PENDING):
            return _resolution(
                STATE_BLOCKED,
                SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
                ACTION_WAIT_FOR_HUMAN_DECISION,
                REASON_HUMAN_DECISION_MISSING,
                True,
            )
        safety = (
            SAFETY_STATUS_SAFETY_BLOCKED
            if execution["safety_result"] == SAFETY_BLOCKED
            else SAFETY_STATUS_EXECUTION_BLOCKED
        )
        return _resolution(
            STATE_BLOCKED,
            safety,
            ACTION_BLOCK_WORKFLOW,
            REASON_EXECUTION_BLOCKED,
            True,
        )
    if execution["present"] and execution["authorized"]:
        if execution["ready"]:
            return _resolution(
                STATE_COMPLETED,
                SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
                ACTION_COMPLETE_WORKFLOW,
                REASON_EXECUTION_READY,
                True,
            )
        return _resolution(
            STATE_EXECUTION_REVIEWED,
            SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
            ACTION_COMPLETE_WORKFLOW,
            REASON_EXECUTION_AUTHORIZED,
            True,
        )

    # ------------------------------------------------------------------
    # Furthest completed stage
    # ------------------------------------------------------------------
    furthest = ""
    for stage_type in WORKFLOW_STAGE_ORDER:
        status = _stage_status(stages, stage_type)
        if status == STAGE_STATUS_COMPLETED:
            furthest = stage_type
        elif status == STAGE_STATUS_INVALID:
            return _resolution(
                STATE_INVALID,
                SAFETY_STATUS_INVALID,
                ACTION_BLOCK_WORKFLOW,
                REASON_WORKFLOW_INVALID,
                True,
            )

    if furthest == STAGE_EXECUTION_CONTROL:
        return _resolution(
            STATE_EXECUTION_REVIEWED,
            SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
            ACTION_COMPLETE_WORKFLOW,
            REASON_EXECUTION_AUTHORIZED,
            True,
        )
    if furthest == STAGE_LEARNING:
        if (
            options[OPTION_ENABLE_EXECUTION_REVIEW]
            and _stage_status(stages, STAGE_EXECUTION_CONTROL)
            in (STAGE_STATUS_NOT_STARTED, STAGE_STATUS_READY)
        ):
            return _resolution(
                STATE_LEARNING_UPDATED,
                SAFETY_STATUS_RESEARCH_ONLY,
                ACTION_REVIEW_EXECUTION_CONTROL,
                REASON_EXECUTION_REVIEW_MISSING,
                False,
            )
        return _resolution(
            STATE_LEARNING_UPDATED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_COMPLETE_WORKFLOW,
            REASON_WORKFLOW_COMPLETE,
            False,
        )
    if furthest == STAGE_HUMAN_REVIEW:
        if human == HUMAN_STATUS_PENDING:
            return _resolution(
                STATE_AWAITING_HUMAN_DECISION,
                SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
                ACTION_WAIT_FOR_HUMAN_DECISION,
                REASON_HUMAN_DECISION_PENDING,
                True,
            )
        if options[OPTION_ENABLE_LEARNING] and _stage_status(
            stages, STAGE_LEARNING
        ) in (STAGE_STATUS_NOT_STARTED, STAGE_STATUS_READY):
            return _resolution(
                STATE_HUMAN_DECIDED,
                SAFETY_STATUS_RESEARCH_ONLY,
                ACTION_UPDATE_LEARNING,
                REASON_LEARNING_MISSING,
                False,
            )
        if (
            options[OPTION_ENABLE_EXECUTION_REVIEW]
            and _stage_status(stages, STAGE_EXECUTION_CONTROL)
            in (STAGE_STATUS_NOT_STARTED, STAGE_STATUS_READY)
        ):
            return _resolution(
                STATE_HUMAN_DECIDED,
                SAFETY_STATUS_RESEARCH_ONLY,
                ACTION_REVIEW_EXECUTION_CONTROL,
                REASON_EXECUTION_REVIEW_MISSING,
                False,
            )
        return _resolution(
            STATE_HUMAN_DECIDED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_COMPLETE_WORKFLOW,
            REASON_WORKFLOW_COMPLETE,
            False,
        )
    if furthest == STAGE_PRIORITIZATION:
        return _resolution(
            STATE_PRIORITIZED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_REQUEST_HUMAN_REVIEW,
            REASON_HUMAN_DECISION_MISSING,
            True,
        )
    if furthest == STAGE_CORRELATION:
        return _resolution(
            STATE_FINDINGS_CORRELATED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_PRIORITIZE_RESEARCH,
            REASON_PRIORITIZATION_MISSING,
            False,
        )
    if furthest == STAGE_FINDING:
        finding_count = _bounded_int(
            _stage_metadata(stages, STAGE_FINDING, "finding_count"),
            0,
            4096,
        )
        if finding_count == 0:
            return _resolution(
                STATE_COMPLETED,
                SAFETY_STATUS_RESEARCH_ONLY,
                ACTION_COMPLETE_WORKFLOW,
                REASON_NO_FINDINGS_PRODUCED,
                False,
            )
        return _resolution(
            STATE_FINDINGS_BUILT,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_CORRELATE_FINDINGS,
            REASON_CORRELATION_MISSING,
            False,
        )
    if furthest == STAGE_FEEDBACK:
        return _resolution(
            STATE_FEEDBACK_ANALYZED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_BUILD_FINDINGS,
            REASON_FINDINGS_MISSING,
            False,
        )
    if furthest == STAGE_COLLABORATION:
        return _resolution(
            STATE_COLLABORATED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_RUN_FEEDBACK_ANALYSIS,
            REASON_FEEDBACK_MISSING,
            False,
        )
    if furthest == STAGE_EVALUATION:
        return _resolution(
            STATE_SPECIALISTS_EVALUATED,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_RUN_COLLABORATION,
            REASON_COLLABORATION_MISSING,
            False,
        )
    if furthest == STAGE_SPECIALIST_RESEARCH:
        return _resolution(
            STATE_RESEARCH_READY,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_RUN_EVALUATION,
            REASON_SPECIALIST_RESULTS_PRESENT,
            False,
        )
    if _stage_status(stages, STAGE_SPECIALIST_RESEARCH) == (
        STAGE_STATUS_READY
    ):
        return _resolution(
            STATE_RESEARCH_READY,
            SAFETY_STATUS_RESEARCH_ONLY,
            ACTION_RUN_RESEARCH_ANALYSIS,
            REASON_RESEARCH_INPUT_READY,
            False,
        )
    return _resolution(
        STATE_INITIALIZED,
        SAFETY_STATUS_RESEARCH_ONLY,
        ACTION_RUN_RESEARCH_ANALYSIS,
        REASON_RESEARCH_INPUT_READY,
        False,
    )


def _resolution(
    state: str,
    safety_status: str,
    action_code: str,
    action_reason: str,
    execution_blocked: bool,
) -> dict:
    return {
        "state": state,
        "safety_status": safety_status,
        "action_code": action_code,
        "action_reason": action_reason,
        "execution_blocked": execution_blocked,
    }


def _resolve_options_from_stages(stages: object) -> dict:
    return {
        OPTION_ENABLE_LEARNING: _stage_status(
            stages, STAGE_LEARNING
        )
        != STAGE_STATUS_SKIPPED,
        OPTION_ENABLE_EXECUTION_REVIEW: _stage_status(
            stages, STAGE_EXECUTION_CONTROL
        )
        != STAGE_STATUS_SKIPPED,
    }


def _resolve_human_status(stages: object) -> str:
    status = _stage_status(stages, STAGE_HUMAN_REVIEW)
    metadata = stage_by_type(stages, STAGE_HUMAN_REVIEW).get(
        "deterministic_metadata"
    ) or {}
    if status == STAGE_STATUS_BLOCKED:
        if metadata.get("decision_conflict") is True:
            return HUMAN_STATUS_CONFLICT
        return HUMAN_STATUS_BLOCKED
    if status == STAGE_STATUS_READY:
        return HUMAN_STATUS_PENDING
    if status == STAGE_STATUS_COMPLETED:
        if metadata.get("review_required") is True:
            return HUMAN_STATUS_REVIEW_REQUIRED
        return HUMAN_STATUS_DECIDED
    return HUMAN_STATUS_NOT_REQUESTED


def _resolve_execution_status(stages: object) -> dict:
    status = _stage_status(stages, STAGE_EXECUTION_CONTROL)
    metadata = stage_by_type(stages, STAGE_EXECUTION_CONTROL).get(
        "deterministic_metadata"
    ) or {}
    if status == STAGE_STATUS_BLOCKED:
        return {
            "present": True,
            "blocked": True,
            "authorized": False,
            "ready": False,
            "safety_result": metadata.get("safety_result", ""),
            "unsafe_claim": metadata.get("unsafe_claim") is True,
            "contradiction": metadata.get("contradiction") is True,
        }
    if status == STAGE_STATUS_COMPLETED:
        return {
            "present": True,
            "blocked": False,
            "authorized": True,
            "ready": metadata.get("execution_ready") is True,
            "safety_result": metadata.get("safety_result", ""),
            "unsafe_claim": metadata.get("unsafe_claim") is True,
            "contradiction": metadata.get("contradiction") is True,
        }
    return {
        "present": False,
        "blocked": False,
        "authorized": False,
        "ready": False,
        "safety_result": "",
        "unsafe_claim": metadata.get("unsafe_claim") is True,
        "contradiction": metadata.get("contradiction") is True,
    }


def _stage_metadata(stages: object, stage_type: str, key: str) -> object:
    stage = stage_by_type(stages, stage_type)
    metadata = stage.get("deterministic_metadata")
    if not isinstance(metadata, dict):
        return ""
    return metadata.get(key, "")


def mark_recommended_stage_ready(
    stages: list[dict], workflow_id_value: str, action_code: str
) -> list[dict]:
    """Mark the recommended stage READY when it has not started."""

    target = ACTION_STAGE.get(action_code, "")
    if not target:
        return stages
    updated: list[dict] = []
    for stage in stages:
        if (
            stage.get("stage_type") == target
            and stage.get("stage_status") == STAGE_STATUS_NOT_STARTED
        ):
            updated.append(
                make_stage(
                    workflow_id_value,
                    target,
                    STAGE_STATUS_READY,
                    REASON_RECOMMENDED_NEXT_STAGE,
                    input_reference=stage.get("input_reference") or {},
                    output_reference=stage.get("output_reference") or {},
                    metadata=stage.get("deterministic_metadata") or {},
                    upstream_rule_version=(
                        stage.get("provenance") or {}
                    ).get("upstream_rule_version", ""),
                    upstream_reference_id=(
                        stage.get("provenance") or {}
                    ).get("upstream_reference_id", ""),
                )
            )
        else:
            updated.append(stage)
    return updated


# ---------------------------------------------------------------------------
# Transitions (used by advance_security_research_workflow)
# ---------------------------------------------------------------------------


def next_stage_index(stages: object) -> int:
    """Index of the stage the workflow can advance next.

    The frontier is the recommended (READY) stage, a BLOCKED/INVALID stage, or
    the first stage after the furthest completed/skipped stage. Earlier
    NOT_STARTED stages never move the frontier backwards.
    """

    last_settled = -1
    for index, stage_type in enumerate(WORKFLOW_STAGE_ORDER):
        status = _stage_status(stages, stage_type)
        if status in (STAGE_STATUS_COMPLETED, STAGE_STATUS_SKIPPED):
            last_settled = index
        elif status in (
            STAGE_STATUS_BLOCKED,
            STAGE_STATUS_INVALID,
            STAGE_STATUS_READY,
        ):
            return index
    return min(last_settled + 1, len(WORKFLOW_STAGE_ORDER))


def transition_error(
    stages: object, stage_type: str
) -> tuple[str, str]:
    """Validate one requested stage transition (fail closed).

    Returns ``(error_category, message)`` or ``("", "")`` when allowed.
    """

    if stage_type not in WORKFLOW_STAGE_ORDER:
        return ERROR_MALFORMED_INPUT, "unknown stage type"
    target_index = WORKFLOW_STAGE_ORDER.index(stage_type)
    expected_index = next_stage_index(stages)
    if target_index == expected_index:
        if expected_index > 0:
            predecessor = WORKFLOW_STAGE_ORDER[expected_index - 1]
            predecessor_status = _stage_status(stages, predecessor)
            if predecessor_status not in (
                STAGE_STATUS_COMPLETED,
                STAGE_STATUS_SKIPPED,
            ):
                return (
                    ERROR_MISSING_REQUIRED_STAGE,
                    f"{predecessor} is not complete",
                )
        return "", ""
    if target_index < expected_index:
        return (
            ERROR_UNSUPPORTED_TRANSITION,
            f"{stage_type} is already complete or skipped",
        )
    return (
        ERROR_STAGE_ORDER_INVALID,
        f"{stage_type} cannot advance before the pending stage",
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def build_summary(
    stages: object,
    errors: object,
    state: str,
    safety_status: str,
    action_code: str,
) -> dict:
    """Deterministic workflow summary from stages and references."""

    completed = _ordered_types(stages, STAGE_STATUS_COMPLETED)
    blocked = _ordered_types(stages, STAGE_STATUS_BLOCKED)
    pending = []
    started = False
    for stage_type in WORKFLOW_STAGE_ORDER:
        status = _stage_status(stages, stage_type)
        if not started and status in (
            STAGE_STATUS_COMPLETED,
            STAGE_STATUS_SKIPPED,
        ):
            continue
        started = True
        if status in (STAGE_STATUS_NOT_STARTED, STAGE_STATUS_READY):
            pending.append(stage_type)

    specialist_meta = stage_by_type(
        stages, STAGE_SPECIALIST_RESEARCH
    ).get("deterministic_metadata") or {}
    specialist_ref = stage_by_type(
        stages, STAGE_SPECIALIST_RESEARCH
    ).get("output_reference") or {}
    evaluation_meta = stage_by_type(stages, STAGE_EVALUATION).get(
        "deterministic_metadata"
    ) or {}
    finding_meta = stage_by_type(stages, STAGE_FINDING).get(
        "deterministic_metadata"
    ) or {}
    correlation_ref = stage_by_type(stages, STAGE_CORRELATION).get(
        "output_reference"
    ) or {}
    prioritization_meta = stage_by_type(
        stages, STAGE_PRIORITIZATION
    ).get("deterministic_metadata") or {}
    human_meta = stage_by_type(stages, STAGE_HUMAN_REVIEW).get(
        "deterministic_metadata"
    ) or {}
    learning_meta = stage_by_type(stages, STAGE_LEARNING).get(
        "deterministic_metadata"
    ) or {}
    execution_meta = stage_by_type(
        stages, STAGE_EXECUTION_CONTROL
    ).get("deterministic_metadata") or {}

    specialists_completed = _bounded_int(
        specialist_meta.get("specialist_count"), 0, 4096
    )
    specialists_considered = _bounded_int(
        specialist_ref.get("item_count"), 0, 4096
    )
    if specialists_considered < specialists_completed:
        specialists_considered = specialists_completed

    return {
        "stage_count": len(WORKFLOW_STAGE_ORDER),
        "completed_stage_count": len(completed),
        "pending_stage_count": len(pending),
        "blocked_stage_count": len(blocked),
        "specialists_considered": specialists_considered,
        "specialists_completed": specialists_completed,
        "evaluation_count": _bounded_int(
            evaluation_meta.get("evaluation_count"), 0, 4096
        ),
        "finding_count": _bounded_int(
            finding_meta.get("finding_count"), 0, 4096
        ),
        "correlated_finding_count": _bounded_int(
            correlation_ref.get("item_count"), 0, 4096
        ),
        "priority_band": _upper(
            prioritization_meta.get("priority_band")
        ),
        "human_decision_status": _human_summary_status(human_meta),
        "human_decision_type": _upper(human_meta.get("decision_type")),
        "learning_pattern_count": _bounded_int(
            learning_meta.get("pattern_count"), 0, 4096
        ),
        "recommendation_count": _bounded_int(
            learning_meta.get("recommendation_count"), 0, 4096
        ),
        "execution_control_status": _upper(
            execution_meta.get("execution_status")
        )
        or _upper(execution_meta.get("control_outcome")),
        "safety_status": safety_status,
        "workflow_state": state,
        "next_action": action_code,
        "research_only": True,
    }


def _human_summary_status(metadata: dict) -> str:
    if metadata.get("decision_conflict") is True:
        return HUMAN_STATUS_CONFLICT
    if metadata.get("decision_blocks") is True:
        return HUMAN_STATUS_BLOCKED
    if metadata.get("review_required") is True:
        return HUMAN_STATUS_REVIEW_REQUIRED
    if metadata.get("decision_present") is True:
        return HUMAN_STATUS_DECIDED
    if metadata.get("review_present") is True:
        return HUMAN_STATUS_PENDING
    return HUMAN_STATUS_NOT_REQUESTED


def workflow_limitations(
    *, blocked: bool, learning_present: bool, execution_present: bool
) -> list[str]:
    """Deterministic ordered result limitations."""

    from ai.schemas.security_research_workflow_result import (
        WORKFLOW_RESULT_LIMITATIONS,
    )

    found = set(RESULT_BASE_LIMITATIONS)
    if blocked:
        found.add("SAFETY_BLOCKED")
    if learning_present:
        found.add("LEARNING_NOT_AUTHORIZATION")
    if execution_present:
        found.add("EXECUTION_GATE_ONLY")
    return [code for code in WORKFLOW_RESULT_LIMITATIONS if code in found]


__all__ = [
    "SECURITY_RESEARCH_WORKFLOW_RULES_RULE_VERSION",
    "RULE_VERSION",
    "EXPECTED_ORCHESTRATION_RULE_VERSION",
    "EXPECTED_EVALUATION_RULE_VERSION",
    "EXPECTED_COLLABORATION_RULE_VERSION",
    "EXPECTED_FEEDBACK_RULE_VERSION",
    "EXPECTED_FINDING_RULE_VERSION",
    "EXPECTED_CORRELATION_RULE_VERSION",
    "EXPECTED_PRIORITIZATION_RULE_VERSION",
    "EXPECTED_HUMAN_REVIEW_RULE_VERSION",
    "EXPECTED_LEARNING_RULE_VERSION",
    "EXPECTED_EXECUTION_CONTROL_RULE_VERSION",
    "EXPECTED_EXECUTION_REQUEST_RULE_VERSION",
    "FATAL_ERROR_CATEGORIES",
    "BLOCKING_DECISION_TYPES",
    "REVIEW_REQUIRED_DECISION_TYPES",
    "BLOCKING_PRECEDENCE",
    "MAX_STAGE_METADATA",
    "MAX_LIST",
    "MAX_TEXT",
    "workflow_error",
    "is_fatal",
    "workflow_id",
    "stage_id",
    "next_action_id",
    "workflow_result_id",
    "workflow_safety_reasons",
    "collect_safety_reasons",
    "make_reference",
    "evaluation_safety_state",
    "human_decision_summary",
    "learning_summary",
    "execution_control_summary",
    "make_stage",
    "stage_by_type",
    "resolve_workflow_state",
    "mark_recommended_stage_ready",
    "next_stage_index",
    "transition_error",
    "build_summary",
    "workflow_limitations",
]
