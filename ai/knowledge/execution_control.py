"""Stage R58.6 deterministic execution-control builder (public API).

Implements the R58 controlled-execution boundary:

    R53 finding intelligence / R54 correlation / R55 prioritization /
    R56 human decisions / R57 continuous learning
      -> build_execution_request
      -> validate_execution_authorization
      -> build_controlled_execution_plan
      -> evaluate_execution_control
      -> export_execution_control

The gate answers exactly one question:

    "Is a proposed action structurally eligible to enter a controlled
     execution workflow, under explicit human authorization and safety
     constraints?"

Hard boundaries encoded here:

- R58 is not an executor: nothing is sent, resolved, spawned, scanned,
  browsed, executed or modified. ``execution_performed`` and
  ``external_executor_present`` are always ``False``.
- AI can recommend; only a human can authorize: AI-originated, autonomous,
  missing, ambiguous, mismatched or expired authorization fails closed with
  structured reasons.
- No silent downgrade: unsafe requests are rejected, never sanitized into a
  different safe action.
- Exact scope: action, target, scope, finding and decision must match
  exactly; wildcards and expansion are rejected.
- Priority, findings, correlation and learning are context only; they can
  never authorize execution and never confirm a vulnerability.
- Deterministic: content-derived ids; canonical ordering; stable
  tie-breaking; no timestamps, UUIDs, pids, randomness or wall-clock time.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.execution_control_rules import (
    EXPECTED_CORRELATION_RULE_VERSION,
    EXPECTED_DECISION_RULE_VERSION,
    EXPECTED_FINDING_RULE_VERSION,
    EXPECTED_LEARNING_RULE_VERSION,
    EXPECTED_PRIORITY_RULE_VERSION,
    action_matches,
    action_steps,
    blocking_learning_recommendations,
    control_outcome_for,
    control_status_for,
    control_summary,
    controlled_execution_plan_id,
    decision_authorizes,
    decision_blocks,
    decision_is_human,
    decision_matches,
    decision_requires_review,
    decision_type_is_known,
    execution_audit_id,
    execution_authorization_id,
    execution_control_id,
    execution_request_id,
    finding_matches,
    has_wildcard,
    limitations_for,
    plan_preconditions,
    plan_safety_checks,
    plan_status_for,
    plan_stop_conditions,
    request_rejection_codes,
    request_state_for,
    review_decisions,
    safety_reasons_for,
    scope_matches,
    structured_safety_reasons,
    target_matches,
)
from ai.schemas.controlled_execution_authorization import (
    APPROVAL_CONSTRAINTS,
    AUTHORIZATION_STATUS_AUTHORIZED,
    AUTHORIZATION_STATUS_BLOCKED,
    AUTHORIZATION_STATUS_EXPIRED,
    AUTHORIZATION_STATUS_INVALID,
    AUTHORIZATION_STATUS_NOT_REQUESTED,
    AUTHORIZATION_SOURCE_AI,
    AUTHORIZATION_SOURCE_HUMAN,
    AUTHORIZATION_SOURCE_SYSTEM,
    AUTHORIZATION_SOURCE_UNSPECIFIED,
    AUTHORIZATION_AUTHORITY_HUMAN,
    CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION,
    VALIDITY_EXPIRED,
    VALIDITY_INVALID,
    VALIDITY_VALID,
    ControlledExecutionAuthorizationPlan,
    controlled_execution_authorization_plan_projection,
    normalize_authorization_text,
    sanitize_execution_authorization,
)
from ai.schemas.controlled_execution_plan import (
    CONTROLLED_EXECUTION_PLAN_RULE_VERSION,
    PLAN_STATUS_AUTHORIZED,
    PLAN_STATUS_BLOCKED,
    PLAN_STATUS_EXPIRED,
    PLAN_STATUS_INVALID,
    PLAN_STATUS_NOT_REQUESTED,
    PLAN_STATUS_REQUESTED,
    ROLLBACK_REASON_NO_EXECUTION,
    STEP_DESCRIPTIONS,
    ControlledExecutionPlan,
    controlled_execution_plan_projection,
    sanitize_controlled_execution_plan,
)
from ai.schemas.execution_control_result import (
    ALLOW_REASON_ACTION_MATCH,
    ALLOW_REASON_DECISION_APPROVES_RESEARCH,
    ALLOW_REASON_DECISION_MATCH,
    ALLOW_REASON_FINDING_MATCH,
    ALLOW_REASON_HUMAN_AUTHORITY,
    ALLOW_REASON_SAFETY_GATE_PASS,
    ALLOW_REASON_SCOPE_MATCH,
    ALLOW_REASON_TARGET_MATCH,
    ALLOW_REASON_VALIDITY_VALID,
    CONTROL_OUTCOME_ALLOW,
    CONTROL_OUTCOME_DENY,
    CONTROL_OUTCOME_INVALID,
    CONTROL_OUTCOME_NOT_REQUESTED,
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_INPUT,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    EXECUTION_CONTROL_RESULT_RULE_VERSION,
    EXECUTION_OUTCOME_REASONS,
    ExecutionControlResultPlan,
    REASON_ACTION_MISMATCH,
    REASON_AI_AUTHORIZATION_REJECTED,
    REASON_AUTHORIZATION_AMBIGUOUS,
    REASON_AUTHORIZATION_EXPIRED,
    REASON_AUTHORIZATION_INVALID,
    REASON_AUTHORIZATION_MISSING,
    REASON_DECISION_DOES_NOT_AUTHORIZE,
    REASON_DECISION_MISMATCH,
    REASON_ESCALATION_REVIEW_REQUIRED,
    REASON_EXECUTION_NOT_REQUESTED,
    REASON_FINDING_MISMATCH,
    REASON_HUMAN_DECISION_PENDING,
    REASON_HUMAN_DECISION_REQUIRED,
    REASON_INVALID_INPUT,
    REASON_MALFORMED_INPUT,
    REASON_R57_RECOMMENDATION_REVIEW,
    REASON_REQUEST_INVALID,
    REASON_RULE_VERSION_MISMATCH,
    REASON_SCOPE_MISMATCH,
    REASON_TARGET_MISMATCH,
    REASON_UNSUPPORTED_ACTION,
    REASON_WILDCARD_SCOPE,
    SAFETY_BLOCKED,
    SAFETY_INVALID,
    SAFETY_PASS,
    SAFETY_REASON_MALFORMED_INPUT,
    SAFETY_REJECTION_REASONS,
    SAFETY_UNKNOWN,
    execution_control_result_plan_projection,
    sanitize_execution_control_provenance,
    sanitize_execution_control_result,
    sanitize_execution_error,
)
from ai.schemas.execution_request import (
    ACTION_UNSPECIFIED,
    EXECUTION_REQUEST_RULE_VERSION,
    ExecutionRequestPlan,
    REJECTION_ACTION_NOT_SUPPORTED,
    REJECTION_MALFORMED_REQUEST,
    REJECTION_UNSAFE_REQUEST,
    REJECTION_WILDCARD_SCOPE,
    REJECTION_WILDCARD_TARGET,
    REQUEST_STATE_BLOCKED,
    REQUEST_STATE_INVALID,
    REQUEST_STATE_NOT_REQUESTED,
    REQUEST_STATE_REQUESTED,
    REQUESTER_UNSPECIFIED,
    SCOPE_KIND_UNSPECIFIED,
    execution_request_plan_projection,
    normalize_execution_scope,
    normalize_target_reference,
    sanitize_decision_reference,
    sanitize_execution_request,
)
from ai.schemas.finding_result import sanitize_finding_governance
from ai.schemas.human_decision import (
    HUMAN_DECISION_RULE_VERSION,
    sanitize_human_decision,
)

EXECUTION_CONTROL_BUILDER_RULE_VERSION = "r58-6"
RULE_VERSION = EXECUTION_CONTROL_BUILDER_RULE_VERSION

MAX_TEXT = 240

#: Request rejection -> authorization rejection mapping (closed).
_REQUEST_REJECTION_TO_AUTHORIZATION: dict[str, str] = {
    REJECTION_ACTION_NOT_SUPPORTED: REASON_UNSUPPORTED_ACTION,
    REJECTION_WILDCARD_SCOPE: REASON_WILDCARD_SCOPE,
    REJECTION_WILDCARD_TARGET: REASON_WILDCARD_SCOPE,
    REJECTION_UNSAFE_REQUEST: REASON_INVALID_INPUT,
    REJECTION_MALFORMED_REQUEST: REASON_MALFORMED_INPUT,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _bounded(value: object, limit: int = MAX_TEXT) -> str:
    return " ".join(_text(value).split())[:limit]


def _error(
    error_category: str, input_kind: str = "", message: str = ""
) -> dict:
    return sanitize_execution_error(
        {
            "stage": "EXECUTION_CONTROL",
            "error_category": error_category,
            "input_kind": input_kind,
            "message": message,
        }
    )


def _request_rejections_for_authorization(request: dict) -> list[str]:
    reasons = []
    for code in request.get("request_rejection_codes") or ():
        mapped = _REQUEST_REJECTION_TO_AUTHORIZATION.get(code)
        if mapped and mapped not in reasons:
            reasons.append(mapped)
    if not reasons:
        reasons.append(REASON_REQUEST_INVALID)
    return reasons


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------


def _merge_request_inputs(request: object, overrides: dict) -> dict:
    base: dict = dict(request) if isinstance(request, dict) else {}
    for key, value in overrides.items():
        if value is None:
            continue
        base[key] = value
    return base


def build_execution_request(
    request: object = None,
    *,
    finding_id: object = None,
    action_type: object = None,
    action_scope: object = None,
    scope_kind: object = None,
    target_reference: object = None,
    purpose: object = None,
    requested_by: object = None,
    human_decision_reference: object = None,
    authorization_context: object = None,
    priority_reference: object = None,
    correlation_reference: object = None,
    finding_reference: object = None,
    safety_context: object = None,
    provenance: object = None,
    governance: object = None,
    execution_requested: object = None,
) -> dict:
    """Build one deterministic R58 execution request (read-only).

    The request is a proposal only: it never authorizes or performs anything.
    Unsupported actions, missing fields, wildcard scopes and unsafe inputs are
    preserved as structured rejection codes and are never repaired.
    """

    raw = _merge_request_inputs(
        request,
        {
            "finding_id": finding_id,
            "action_type": action_type,
            "action_scope": action_scope,
            "scope_kind": scope_kind,
            "target_reference": target_reference,
            "purpose": purpose,
            "requested_by": requested_by,
            "human_decision_reference": human_decision_reference,
            "authorization_context": authorization_context,
            "priority_reference": priority_reference,
            "correlation_reference": correlation_reference,
            "finding_reference": finding_reference,
            "safety_context": safety_context,
            "provenance": provenance,
            "governance": governance,
            "execution_requested": execution_requested,
        },
    )

    malformed = request is not None and not isinstance(request, dict)
    execution_requested_value = raw.get("execution_requested")
    if execution_requested_value is None:
        execution_requested_value = True
    execution_requested_bool = execution_requested_value is True

    raw_decision_reference = raw.get("human_decision_reference")
    if not isinstance(raw_decision_reference, dict):
        raw_decision_reference = {}
    resolved_priority = raw.get("priority_reference")
    if not isinstance(resolved_priority, dict) or not resolved_priority:
        resolved_priority = (
            raw_decision_reference.get("priority_reference") or {}
        )
    resolved_correlation = raw.get("correlation_reference")
    if not isinstance(resolved_correlation, dict) or not resolved_correlation:
        resolved_correlation = (
            raw_decision_reference.get("correlation_reference") or {}
        )
    resolved_finding = raw.get("finding_reference")
    if not isinstance(resolved_finding, dict) or not resolved_finding:
        resolved_finding = (
            raw_decision_reference.get("finding_reference") or {}
        )
    resolved_governance = raw.get("governance")
    if not isinstance(resolved_governance, dict) or not resolved_governance:
        resolved_governance = raw_decision_reference.get("governance")

    finding_value = _bounded(raw.get("finding_id"))
    action_value = _upper(raw.get("action_type"))
    scope_value = normalize_execution_scope(raw.get("action_scope"))
    target_value = normalize_target_reference(raw.get("target_reference"))
    purpose_value = _bounded(raw.get("purpose"))
    requester_value = _upper(raw.get("requested_by")) or (
        REQUESTER_UNSPECIFIED
    )

    safety_reasons = _collect_safety(raw) if not malformed else []
    wildcard_scope = has_wildcard(scope_value)
    wildcard_target = has_wildcard(target_value)
    rejection_codes = request_rejection_codes(
        finding_id=finding_value,
        action_type=action_value,
        action_scope=scope_value,
        target_reference=target_value,
        purpose=purpose_value,
        requested_by=requester_value,
        wildcard_scope=wildcard_scope,
        wildcard_target=wildcard_target,
        safety_reasons=safety_reasons,
    )
    if malformed and REJECTION_MALFORMED_REQUEST not in rejection_codes:
        rejection_codes = [REJECTION_MALFORMED_REQUEST] + rejection_codes

    state = request_state_for(
        execution_requested=execution_requested_bool,
        rejection_codes=rejection_codes,
        safety_reasons=safety_reasons,
        wildcard_present=wildcard_scope or wildcard_target,
    )

    decision_reference = sanitize_decision_reference(
        raw.get("human_decision_reference")
    )
    request_id = execution_request_id(
        finding_id=finding_value,
        action_type=(
            action_value
            if action_value in _supported_actions()
            else ACTION_UNSPECIFIED
        ),
        requested_action_type=_upper(raw.get("requested_action_type"))
        or action_value,
        action_scope=scope_value,
        target_reference=target_value,
        purpose=purpose_value,
        requested_by=requester_value,
        decision_reference=_text(decision_reference.get("decision_id")),
        execution_requested=execution_requested_bool,
    )

    if safety_reasons:
        safety_state = SAFETY_BLOCKED
    elif state == REQUEST_STATE_REQUESTED:
        safety_state = SAFETY_PASS
    else:
        safety_state = SAFETY_UNKNOWN

    extra_limitations = []
    if state == REQUEST_STATE_BLOCKED:
        extra_limitations.append("SAFETY_BLOCKED")
    governance_value = sanitize_finding_governance(resolved_governance)
    if _upper(governance_value.get("reference_state")) != "REFERENCED":
        extra_limitations.append("GOVERNANCE_UNKNOWN")
    provenance_value = sanitize_request_provenance_for(raw)
    if not _text(provenance_value.get("orchestration_id")):
        extra_limitations.append("PROVENANCE_INCOMPLETE")

    payload = {
        "rule_version": EXECUTION_REQUEST_RULE_VERSION,
        "request_id": request_id,
        "finding_id": finding_value,
        "action_type": (
            action_value
            if action_value in _supported_actions()
            else ACTION_UNSPECIFIED
        ),
        "requested_action_type": _bounded(
            raw.get("requested_action_type")
        ).upper()
        or action_value,
        "action_scope": scope_value,
        "scope_kind": _upper(raw.get("scope_kind")) or SCOPE_KIND_UNSPECIFIED,
        "target_reference": target_value,
        "purpose": purpose_value,
        "requested_by": requester_value,
        "request_state": state,
        "request_rejection_codes": rejection_codes,
        "human_decision_reference": decision_reference,
        "authorization_context": raw.get("authorization_context") or {},
        "priority_reference": resolved_priority,
        "correlation_reference": resolved_correlation,
        "finding_reference": resolved_finding,
        "safety_context": {
            "safety_state": safety_state,
            "safety_reasons": safety_reasons,
        },
        "provenance": provenance_value,
        "governance": governance_value,
        "limitations": limitations_for(*extra_limitations),
        "execution_requested": execution_requested_bool,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }
    return _request_model(payload)


def _supported_actions() -> tuple[str, ...]:
    from ai.schemas.execution_request import EXECUTION_ACTIONS

    return EXECUTION_ACTIONS


def sanitize_request_provenance_for(raw: dict) -> dict:
    """Derive bounded request provenance from the supplied references."""

    decision_raw = raw.get("human_decision_reference")
    decision_raw = decision_raw if isinstance(decision_raw, dict) else {}
    finding = raw.get("finding_reference")
    if not isinstance(finding, dict) or not finding:
        finding = decision_raw.get("finding_reference")
    finding = finding if isinstance(finding, dict) else {}
    priority = raw.get("priority_reference")
    if not isinstance(priority, dict) or not priority:
        priority = decision_raw.get("priority_reference")
    priority = priority if isinstance(priority, dict) else {}
    correlation = raw.get("correlation_reference")
    if not isinstance(correlation, dict) or not correlation:
        correlation = decision_raw.get("correlation_reference")
    correlation = correlation if isinstance(correlation, dict) else {}
    decision = sanitize_decision_reference(raw.get("human_decision_reference"))
    provenance = raw.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    stages = []
    for stage in (
        "FINDING_INTELLIGENCE",
        "CORRELATION",
        "PRIORITIZATION",
        "HUMAN_DECISION",
        "CONTINUOUS_LEARNING",
    ):
        if stage in (provenance.get("source_stages") or ()):
            stages.append(stage)
    return {
        "finding_rule_version": _bounded(
            provenance.get("finding_rule_version")
        )
        or _bounded(finding.get("finding_rule_version")),
        "correlation_rule_version": _bounded(
            provenance.get("correlation_rule_version")
        )
        or _bounded(correlation.get("correlation_rule_version")),
        "priority_rule_version": _bounded(
            provenance.get("priority_rule_version")
        )
        or _bounded(priority.get("priority_rule_version")),
        "decision_rule_version": _bounded(
            provenance.get("decision_rule_version")
        )
        or HUMAN_DECISION_RULE_VERSION,
        "learning_rule_version": _bounded(
            provenance.get("learning_rule_version")
        ),
        "prioritization_id": _bounded(
            provenance.get("prioritization_id")
        )
        or _bounded(priority.get("prioritization_id")),
        "correlation_id": _bounded(provenance.get("correlation_id"))
        or _bounded(correlation.get("correlation_id")),
        "orchestration_id": _bounded(provenance.get("orchestration_id"))
        or _bounded(finding.get("orchestration_id")),
        "decision_id": _bounded(provenance.get("decision_id"))
        or _bounded(decision.get("decision_id")),
        "agent_id": _bounded(provenance.get("agent_id"))
        or _bounded(finding.get("agent_id")),
        "category": _bounded(provenance.get("category"))
        or _bounded(finding.get("category")),
        "source_stages": stages,
        "deterministic": True,
        "research_only": True,
    }


def _request_model(payload: dict) -> dict:
    try:
        return execution_request_plan_projection(
            ExecutionRequestPlan(**payload)
        )
    except (TypeError, ValueError):
        projected = sanitize_execution_request(payload)
        projected["request_state"] = REQUEST_STATE_INVALID
        return projected


# ---------------------------------------------------------------------------
# Authorization validation
# ---------------------------------------------------------------------------


def _coerce_request(value: object) -> tuple[dict | None, str]:
    """Return ``(request, "")`` or ``(None, failure_kind)``."""

    if value is None:
        return None, "MISSING"
    if not isinstance(value, dict):
        return None, "MALFORMED"
    if _text(value.get("rule_version")) == EXECUTION_REQUEST_RULE_VERSION:
        return sanitize_execution_request(value), ""
    if _text(value.get("rule_version")):
        return None, "RULE_VERSION_MISMATCH"
    return build_execution_request(request=value), ""


def _authorization_claims(
    authorization_context: object, overrides: dict
) -> tuple[dict, bool]:
    if authorization_context is None:
        claims: dict = {}
        ambiguous = False
    elif isinstance(authorization_context, dict):
        claims = dict(authorization_context)
        ambiguous = False
    else:
        return {}, True
    for key, value in overrides.items():
        if value is None:
            continue
        existing = claims.get(key)
        if existing not in (None, "", [], {}) and value != existing:
            ambiguous = True
        claims[key] = value
    return claims, ambiguous


def _layer_error(
    value: object,
    input_kind: str,
    expected_rule_version: str,
) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return _error(
            ERROR_INVALID_INPUT, input_kind, "input must be a mapping"
        )
    if _text(value.get("rule_version")) != expected_rule_version:
        return _error(
            ERROR_RULE_VERSION_MISMATCH,
            input_kind,
            "input rule version does not match the expected layer",
        )
    if safety_reasons_for(value):
        return _error(
            ERROR_SAFETY_BLOCKED,
            input_kind,
            "input carries a forbidden execution claim",
        )
    return None


def validate_execution_authorization(
    execution_request: object = None,
    *,
    human_review_result: object = None,
    human_decision: object = None,
    authorization_context: object = None,
    authorization_source: object = None,
    authorization_authority: object = None,
    decision_reference: object = None,
    approved_action: object = None,
    approved_scope: object = None,
    approved_target: object = None,
    approval_constraints: object = None,
    validity: object = None,
    learning_result: object = None,
    prioritization_result: object = None,
    correlation_result: object = None,
    finding_intelligence: object = None,
    provenance: object = None,
    governance: object = None,
) -> dict:
    """Validate whether an explicit human authorization matches exactly.

    Fails closed: AI-originated, missing, ambiguous, mismatched or expired
    authorization is represented as a bounded record with closed rejection
    codes. R53/R54/R55/R57 inputs are context only and can never authorize.
    """

    request, failure = _coerce_request(execution_request)
    errors: list[dict] = []
    reasons: list[str] = []
    allow_reasons: list[str] = []
    safety_reasons: list[str] = []
    status = AUTHORIZATION_STATUS_BLOCKED
    decision: dict = {}
    validity_state = VALIDITY_VALID
    claims, context_ambiguous = _authorization_claims(
        authorization_context,
        {
            "authorization_source": authorization_source,
            "authorization_authority": authorization_authority,
            "decision_reference": decision_reference,
            "approved_action": approved_action,
            "approved_scope": approved_scope,
            "approved_target": approved_target,
            "approval_constraints": approval_constraints,
            "validity": validity,
        },
    )

    if failure == "MISSING":
        status = AUTHORIZATION_STATUS_NOT_REQUESTED
        reasons.append(REASON_EXECUTION_NOT_REQUESTED)
    elif failure == "MALFORMED":
        status = AUTHORIZATION_STATUS_INVALID
        reasons.append(REASON_MALFORMED_INPUT)
        errors.append(_error(ERROR_MALFORMED_INPUT, "EXECUTION_REQUEST"))
    elif failure == "RULE_VERSION_MISMATCH":
        status = AUTHORIZATION_STATUS_INVALID
        reasons.append(REASON_RULE_VERSION_MISMATCH)
        errors.append(
            _error(ERROR_RULE_VERSION_MISMATCH, "EXECUTION_REQUEST")
        )
    else:
        if context_ambiguous:
            reasons.append(REASON_AUTHORIZATION_AMBIGUOUS)

        # --------------------------------------------------------------
        # Safety gate over every supplied input (never repaired)
        # --------------------------------------------------------------
        safety_reasons = _collect_safety(
            request,
            authorization_context,
            human_review_result,
            human_decision,
            learning_result,
            prioritization_result,
            correlation_result,
            finding_intelligence,
        )
        if safety_reasons:
            reasons.append(REASON_INVALID_INPUT)

        # --------------------------------------------------------------
        # Context-layer validation (fail closed; context only, no authority)
        # --------------------------------------------------------------
        for value, input_kind, expected in (
            (
                finding_intelligence,
                "FINDING_INTELLIGENCE",
                EXPECTED_FINDING_RULE_VERSION,
            ),
            (
                correlation_result,
                "CORRELATION_RESULT",
                EXPECTED_CORRELATION_RULE_VERSION,
            ),
            (
                prioritization_result,
                "PRIORITIZATION_RESULT",
                EXPECTED_PRIORITY_RULE_VERSION,
            ),
            (
                learning_result,
                "LEARNING_RESULT",
                EXPECTED_LEARNING_RULE_VERSION,
            ),
        ):
            layer_error = _layer_error(value, input_kind, expected)
            if layer_error:
                errors.append(layer_error)
                if layer_error["error_category"] == ERROR_RULE_VERSION_MISMATCH:
                    if REASON_RULE_VERSION_MISMATCH not in reasons:
                        reasons.append(REASON_RULE_VERSION_MISMATCH)
                else:
                    if REASON_INVALID_INPUT not in reasons:
                        reasons.append(REASON_INVALID_INPUT)

        # --------------------------------------------------------------
        # Request state
        # --------------------------------------------------------------
        request_state = request.get("request_state")
        finding_id = request.get("finding_id", "")
        if request_state == REQUEST_STATE_NOT_REQUESTED:
            status = AUTHORIZATION_STATUS_NOT_REQUESTED
            if REASON_EXECUTION_NOT_REQUESTED not in reasons:
                reasons.append(REASON_EXECUTION_NOT_REQUESTED)
        elif request_state == REQUEST_STATE_INVALID:
            status = AUTHORIZATION_STATUS_INVALID
            for code in _request_rejections_for_authorization(request):
                if code not in reasons:
                    reasons.append(code)
        elif request_state == REQUEST_STATE_BLOCKED:
            status = AUTHORIZATION_STATUS_BLOCKED
            for code in _request_rejections_for_authorization(request):
                if code not in reasons:
                    reasons.append(code)
        else:
            # ----------------------------------------------------------
            # Human decision resolution (R56 is the only authority source)
            # ----------------------------------------------------------
            resolution = review_decisions(human_review_result, finding_id)
            if resolution["error"]:
                status = AUTHORIZATION_STATUS_INVALID
                if resolution["error"] not in reasons:
                    reasons.append(resolution["error"])
            decisions = list(resolution["decisions"])
            if human_decision is not None:
                if not isinstance(human_decision, dict):
                    status = AUTHORIZATION_STATUS_INVALID
                    if REASON_MALFORMED_INPUT not in reasons:
                        reasons.append(REASON_MALFORMED_INPUT)
                elif (
                    _text(human_decision.get("rule_version"))
                    != HUMAN_DECISION_RULE_VERSION
                ):
                    status = AUTHORIZATION_STATUS_INVALID
                    if REASON_RULE_VERSION_MISMATCH not in reasons:
                        reasons.append(REASON_RULE_VERSION_MISMATCH)
                else:
                    direct = sanitize_human_decision(human_decision)
                    if direct.get("decision_id"):
                        decisions.append(direct)

            distinct: dict[str, dict] = {}
            for candidate in decisions:
                decision_key = _text(candidate.get("decision_id"))
                if decision_key and decision_key not in distinct:
                    distinct[decision_key] = candidate
            if len(distinct) > 1:
                reasons.append(REASON_AUTHORIZATION_AMBIGUOUS)
                status = AUTHORIZATION_STATUS_BLOCKED
            elif not distinct:
                if resolution["pending"]:
                    reasons.append(REASON_HUMAN_DECISION_PENDING)
                elif resolution["invalid"]:
                    reasons.append(REASON_HUMAN_DECISION_REQUIRED)
                else:
                    reasons.append(REASON_AUTHORIZATION_MISSING)
                status = AUTHORIZATION_STATUS_BLOCKED
            else:
                decision = next(iter(distinct.values()))
                if not decision_is_human(decision):
                    reasons.append(REASON_AI_AUTHORIZATION_REJECTED)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif _text(decision.get("decision_state")) != "DECIDED":
                    reasons.append(REASON_HUMAN_DECISION_PENDING)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif not finding_matches(
                    finding_id, decision.get("finding_id")
                ):
                    reasons.append(REASON_FINDING_MISMATCH)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif not decision_matches(
                    (request.get("human_decision_reference") or {}).get(
                        "decision_id"
                    ),
                    decision.get("decision_id"),
                ):
                    reasons.append(REASON_DECISION_MISMATCH)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif not decision_type_is_known(decision.get("decision_type")):
                    reasons.append(REASON_HUMAN_DECISION_REQUIRED)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif decision_blocks(decision.get("decision_type")):
                    reasons.append(REASON_DECISION_DOES_NOT_AUTHORIZE)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif decision_requires_review(decision.get("decision_type")):
                    reasons.append(REASON_ESCALATION_REVIEW_REQUIRED)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif not decision_authorizes(decision.get("decision_type")):
                    reasons.append(REASON_DECISION_DOES_NOT_AUTHORIZE)
                    status = AUTHORIZATION_STATUS_BLOCKED

            # ----------------------------------------------------------
            # Explicit human authorization context (required, exact)
            # ----------------------------------------------------------
            source = _upper(claims.get("authorization_source"))
            authority = _upper(claims.get("authorization_authority"))
            if not _text(claims.get("approved_action")) and not _text(
                claims.get("approved_scope")
            ) and not _text(claims.get("approved_target")):
                reasons.append(REASON_AUTHORIZATION_MISSING)
                status = AUTHORIZATION_STATUS_BLOCKED
            else:
                if source in (
                    AUTHORIZATION_SOURCE_AI,
                    AUTHORIZATION_SOURCE_SYSTEM,
                ) or authority not in (
                    "",
                    AUTHORIZATION_AUTHORITY_HUMAN,
                ):
                    reasons.append(REASON_AI_AUTHORIZATION_REJECTED)
                    status = AUTHORIZATION_STATUS_BLOCKED
                elif source != AUTHORIZATION_SOURCE_HUMAN:
                    reasons.append(REASON_AUTHORIZATION_MISSING)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if (
                    not _text(claims.get("approved_action"))
                    or not _text(claims.get("approved_scope"))
                    or not _text(claims.get("approved_target"))
                ):
                    reasons.append(REASON_AUTHORIZATION_MISSING)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if context_ambiguous:
                    reasons.append(REASON_AUTHORIZATION_AMBIGUOUS)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if has_wildcard(claims.get("approved_scope")) or (
                    has_wildcard(claims.get("approved_target"))
                ):
                    reasons.append(REASON_WILDCARD_SCOPE)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if not action_matches(
                    request.get("action_type"),
                    claims.get("approved_action"),
                ):
                    reasons.append(REASON_ACTION_MISMATCH)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if not target_matches(
                    request.get("target_reference"),
                    claims.get("approved_target"),
                ):
                    reasons.append(REASON_TARGET_MISMATCH)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if not scope_matches(
                    request.get("action_scope"),
                    claims.get("approved_scope"),
                ):
                    reasons.append(REASON_SCOPE_MISMATCH)
                    status = AUTHORIZATION_STATUS_BLOCKED
                if not decision_matches(
                    claims.get("decision_reference"),
                    decision.get("decision_id"),
                ):
                    reasons.append(REASON_DECISION_MISMATCH)
                    status = AUTHORIZATION_STATUS_BLOCKED

        # ------------------------------------------------------------------
        # Validity (explicit structured metadata only; no wall clock)
        # ------------------------------------------------------------------
        validity_value = claims.get("validity")
        validity_state = VALIDITY_VALID
        if isinstance(validity_value, dict) and validity_value:
            validity_state = _upper(
                validity_value.get("validity_state")
            ) or VALIDITY_VALID
        if validity_state == VALIDITY_EXPIRED:
            status = AUTHORIZATION_STATUS_EXPIRED
            if REASON_AUTHORIZATION_EXPIRED not in reasons:
                reasons.append(REASON_AUTHORIZATION_EXPIRED)
        elif validity_state == VALIDITY_INVALID:
            status = AUTHORIZATION_STATUS_INVALID
            if REASON_AUTHORIZATION_INVALID not in reasons:
                reasons.append(REASON_AUTHORIZATION_INVALID)

        # ------------------------------------------------------------------
        # R57 learning: blocking recommendations keep execution blocked
        # ------------------------------------------------------------------
        blocking = blocking_learning_recommendations(learning_result)
        if blocking:
            status = AUTHORIZATION_STATUS_BLOCKED
            if REASON_R57_RECOMMENDATION_REVIEW not in reasons:
                reasons.append(REASON_R57_RECOMMENDATION_REVIEW)

        if not reasons:
            status = AUTHORIZATION_STATUS_AUTHORIZED
            allow_reasons = [
                ALLOW_REASON_HUMAN_AUTHORITY,
                ALLOW_REASON_DECISION_APPROVES_RESEARCH,
                ALLOW_REASON_ACTION_MATCH,
                ALLOW_REASON_TARGET_MATCH,
                ALLOW_REASON_SCOPE_MATCH,
                ALLOW_REASON_FINDING_MATCH,
                ALLOW_REASON_DECISION_MATCH,
                ALLOW_REASON_VALIDITY_VALID,
                ALLOW_REASON_SAFETY_GATE_PASS,
            ]

    approved_action_value = _upper(claims.get("approved_action"))
    approved_scope_value = normalize_authorization_text(
        claims.get("approved_scope")
    )
    approved_target_value = normalize_authorization_text(
        claims.get("approved_target")
    )
    decision_id = _text(decision.get("decision_id")) if decision else ""
    provenance_value = sanitize_authorization_provenance_from(
        request, decision, provenance
    )
    governance_value = sanitize_finding_governance(
        governance
        or (request.get("governance") if request else None)
    )
    extra: list[str] = []
    if safety_reasons:
        extra.append("SAFETY_BLOCKED")
    if status in (AUTHORIZATION_STATUS_BLOCKED, AUTHORIZATION_STATUS_EXPIRED):
        extra.append("AUTHORIZATION_MISSING")
    if status == AUTHORIZATION_STATUS_EXPIRED:
        extra.append("AUTHORIZATION_EXPIRED")
    if _upper(governance_value.get("reference_state")) != "REFERENCED":
        extra.append("GOVERNANCE_UNKNOWN")
    if not _text(provenance_value.get("orchestration_id")):
        extra.append("PROVENANCE_INCOMPLETE")

    authorization_status_value = status
    authorization_id = execution_authorization_id(
        request_id=_text((request or {}).get("request_id")),
        finding_id=_text((request or {}).get("finding_id")),
        decision_reference=decision_id,
        approved_action=approved_action_value,
        approved_scope=approved_scope_value,
        approved_target=approved_target_value,
        validity_state=validity_state,
        authorization_status=authorization_status_value,
    )

    authority_value = _upper(claims.get("authorization_authority"))
    if not authority_value:
        authority_value = (
            AUTHORIZATION_AUTHORITY_HUMAN
            if status == AUTHORIZATION_STATUS_AUTHORIZED
            else "UNSPECIFIED"
        )
    source_value = (
        _upper(claims.get("authorization_source"))
        or AUTHORIZATION_SOURCE_UNSPECIFIED
    )

    payload = {
        "rule_version": CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION,
        "authorization_id": authorization_id,
        "request_id": _text((request or {}).get("request_id")),
        "finding_id": _text((request or {}).get("finding_id")),
        "authorization_status": authorization_status_value,
        "authorization_source": source_value,
        "authorization_authority": authority_value,
        "human_authority": (
            source_value == AUTHORIZATION_SOURCE_HUMAN
            and authority_value == AUTHORIZATION_AUTHORITY_HUMAN
        ),
        "decision_reference": decision_id,
        "decision_type": _text(decision.get("decision_type")),
        "decision_state": _text(decision.get("decision_state")),
        "approved_action": approved_action_value,
        "approved_scope": approved_scope_value,
        "approved_target": approved_target_value,
        "approval_constraints": list(APPROVAL_CONSTRAINTS),
        "allow_reasons": allow_reasons,
        "rejection_codes": reasons,
        "validity": (
            {"validity_state": validity_state}
            if isinstance(claims.get("validity"), dict)
            and claims.get("validity")
            else {}
        ),
        "authorization_context": claims,
        "execution_authorized": status
        == AUTHORIZATION_STATUS_AUTHORIZED,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "provenance": provenance_value,
        "governance": governance_value,
        "limitations": limitations_for(*extra),
        "research_only": True,
        "deterministic": True,
    }
    return _authorization_model(payload, safety_reasons, errors)


def sanitize_authorization_provenance_from(
    request: dict | None, decision: dict, provenance: object
) -> dict:
    """Derive bounded authorization provenance from request and decision."""

    supplied = provenance if isinstance(provenance, dict) else {}
    request_provenance = (request or {}).get("provenance") or {}
    decision_provenance = (decision or {}).get("provenance") or {}
    return {
        "finding_rule_version": _bounded(
            supplied.get("finding_rule_version")
        )
        or _bounded(request_provenance.get("finding_rule_version"))
        or _bounded(decision_provenance.get("finding_rule_version")),
        "correlation_rule_version": _bounded(
            supplied.get("correlation_rule_version")
        )
        or _bounded(request_provenance.get("correlation_rule_version"))
        or _bounded(decision_provenance.get("correlation_rule_version")),
        "priority_rule_version": _bounded(
            supplied.get("priority_rule_version")
        )
        or _bounded(request_provenance.get("priority_rule_version"))
        or _bounded(decision_provenance.get("priority_rule_version")),
        "decision_rule_version": _bounded(
            supplied.get("decision_rule_version")
        )
        or HUMAN_DECISION_RULE_VERSION,
        "learning_rule_version": _bounded(
            supplied.get("learning_rule_version")
        )
        or _bounded(request_provenance.get("learning_rule_version")),
        "prioritization_id": _bounded(supplied.get("prioritization_id"))
        or _bounded(request_provenance.get("prioritization_id"))
        or _bounded(decision_provenance.get("prioritization_id")),
        "correlation_id": _bounded(supplied.get("correlation_id"))
        or _bounded(request_provenance.get("correlation_id"))
        or _bounded(decision_provenance.get("correlation_id")),
        "orchestration_id": _bounded(supplied.get("orchestration_id"))
        or _bounded(request_provenance.get("orchestration_id"))
        or _bounded(decision_provenance.get("orchestration_id")),
        "decision_id": _bounded(supplied.get("decision_id"))
        or _bounded((decision or {}).get("decision_id")),
        "deterministic": True,
        "research_only": True,
    }


def _authorization_model(
    payload: dict, safety_reasons: list[str], errors: list[dict]
) -> dict:
    try:
        projected = controlled_execution_authorization_plan_projection(
            ControlledExecutionAuthorizationPlan(**payload)
        )
    except (TypeError, ValueError):
        projected = sanitize_execution_authorization(payload)
        projected["authorization_status"] = AUTHORIZATION_STATUS_INVALID
    projected["safety_reasons"] = [
        reason
        for reason in SAFETY_REJECTION_REASONS
        if reason in set(safety_reasons)
    ]
    projected["errors"] = [entry for entry in errors if entry]
    return projected


# ---------------------------------------------------------------------------
# Controlled execution plan
# ---------------------------------------------------------------------------


def _authorization_status(value: object) -> tuple[str, str]:
    """Return ``(status, validity_state)`` for a supplied authorization."""

    if not isinstance(value, dict):
        return "", ""
    if (
        _text(value.get("rule_version"))
        != CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION
    ):
        return AUTHORIZATION_STATUS_INVALID, ""
    status = _upper(value.get("authorization_status"))
    validity = value.get("validity")
    validity_state = ""
    if isinstance(validity, dict):
        validity_state = _upper(validity.get("validity_state"))
    return status, validity_state


def build_controlled_execution_plan(
    execution_request: object = None,
    *,
    execution_authorization: object = None,
    preconditions_met: object = None,
    safety_result: object = None,
    safety_reasons: object = None,
    provenance: object = None,
    governance: object = None,
) -> dict:
    """Build one declarative controlled execution plan (no execution).

    The plan describes the ordered steps that a *future* external executor
    could consider. R58 never executes the steps and never claims an executor
    exists.
    """

    request, failure = _coerce_request(execution_request)
    if failure == "MISSING":
        plan_status = PLAN_STATUS_NOT_REQUESTED
    elif failure in ("MALFORMED", "RULE_VERSION_MISMATCH"):
        plan_status = PLAN_STATUS_INVALID
    else:
        request_state = request.get("request_state")
        authorization_status, validity_state = _authorization_status(
            execution_authorization
        )
        derived_safety = SAFETY_PASS
        if request_state == REQUEST_STATE_BLOCKED:
            derived_safety = SAFETY_BLOCKED
        elif request_state in (
            REQUEST_STATE_NOT_REQUESTED,
            REQUEST_STATE_INVALID,
        ):
            derived_safety = SAFETY_UNKNOWN
        safety_value = (
            _upper(safety_result) if safety_result is not None
            else derived_safety
        )
        if safety_value not in (
            SAFETY_PASS,
            SAFETY_BLOCKED,
            SAFETY_INVALID,
            SAFETY_UNKNOWN,
        ):
            safety_value = SAFETY_UNKNOWN
        plan_status = plan_status_for(
            request_state=request_state,
            authorization_status=authorization_status,
            validity_state=validity_state,
            safety_result=safety_value,
            preconditions_met=preconditions_met is True,
        )

    if failure == "MISSING":
        steps: list[dict] = []
        plan_id = controlled_execution_plan_id(
            request_id="",
            finding_id="",
            action_type=ACTION_UNSPECIFIED,
            target_reference="",
            action_scope="",
            step_codes=[],
        )
        request_view: dict = {}
    else:
        step_codes = action_steps(request.get("action_type")) if request else []
        steps = [
            {
                "step_index": index,
                "step_code": code,
                "description": STEP_DESCRIPTIONS.get(code, ""),
            }
            for index, code in enumerate(step_codes)
        ]
        plan_id = controlled_execution_plan_id(
            request_id=_text((request or {}).get("request_id")),
            finding_id=_text((request or {}).get("finding_id")),
            action_type=_text((request or {}).get("action_type")),
            target_reference=_text(
                (request or {}).get("target_reference")
            ),
            action_scope=_text((request or {}).get("action_scope")),
            step_codes=step_codes,
        )
        request_view = request or {}

    safety_reason_list = [
        reason
        for reason in SAFETY_REJECTION_REASONS
        if reason in set(safety_reasons or ())
    ]
    governance_value = sanitize_finding_governance(
        governance or request_view.get("governance")
    )
    authorization_reference = {
        "present": isinstance(execution_authorization, dict)
        and _text(execution_authorization.get("authorization_id")) != "",
        "authorization_id": _text(
            (execution_authorization or {}).get("authorization_id")
        )
        if isinstance(execution_authorization, dict)
        else "",
        "authorization_status": _authorization_status(
            execution_authorization
        )[0],
        "decision_reference": _text(
            (execution_authorization or {}).get("decision_reference")
        )
        if isinstance(execution_authorization, dict)
        else "",
        "validity_state": _authorization_status(execution_authorization)[1],
    }
    extra: list[str] = []
    if plan_status == PLAN_STATUS_BLOCKED:
        if safety_reason_list:
            extra.append("SAFETY_BLOCKED")
        else:
            extra.append("AUTHORIZATION_MISSING")
    if plan_status == PLAN_STATUS_EXPIRED:
        extra.append("AUTHORIZATION_EXPIRED")
    if plan_status in (
        PLAN_STATUS_REQUESTED,
        PLAN_STATUS_AUTHORIZED,
    ):
        extra.append("PLAN_NOT_READY_FOR_EXTERNAL_EXECUTOR")
    if _upper(governance_value.get("reference_state")) != "REFERENCED":
        extra.append("GOVERNANCE_UNKNOWN")
    if plan_status == PLAN_STATUS_INVALID:
        extra.append("AUTHORIZATION_MISSING")

    provenance_value = request_view.get("provenance") or {}
    supplied_provenance = provenance if isinstance(provenance, dict) else {}
    plan_provenance = {
        "request_rule_version": EXECUTION_REQUEST_RULE_VERSION
        if request_view
        else "",
        "authorization_rule_version": (
            CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION
            if isinstance(execution_authorization, dict)
            else ""
        ),
        "finding_rule_version": _bounded(
            supplied_provenance.get("finding_rule_version")
        )
        or _bounded(provenance_value.get("finding_rule_version")),
        "decision_rule_version": _bounded(
            supplied_provenance.get("decision_rule_version")
        )
        or HUMAN_DECISION_RULE_VERSION,
        "learning_rule_version": _bounded(
            supplied_provenance.get("learning_rule_version")
        )
        or _bounded(provenance_value.get("learning_rule_version")),
        "request_id": _text(request_view.get("request_id")),
        "authorization_id": authorization_reference["authorization_id"],
        "finding_id": _text(request_view.get("finding_id")),
        "decision_id": _text(provenance_value.get("decision_id")),
        "deterministic": True,
        "research_only": True,
    }

    payload = {
        "rule_version": CONTROLLED_EXECUTION_PLAN_RULE_VERSION,
        "plan_id": plan_id,
        "request_id": _text(request_view.get("request_id")),
        "finding_id": _text(request_view.get("finding_id")),
        "action_type": _text(request_view.get("action_type"))
        or ACTION_UNSPECIFIED,
        "action_scope": _text(request_view.get("action_scope")),
        "target_reference": _text(request_view.get("target_reference")),
        "ordered_steps": steps,
        "target_scope": {
            "target_reference": _text(
                request_view.get("target_reference")
            ),
            "action_scope": _text(request_view.get("action_scope")),
            "scope_kind": _text(
                request_view.get("scope_kind")
            )
            or SCOPE_KIND_UNSPECIFIED,
            "wildcard": has_wildcard(request_view.get("action_scope"))
            or has_wildcard(request_view.get("target_reference")),
        },
        "preconditions": plan_preconditions()
        if request_view
        else [],
        "authorization_reference": authorization_reference,
        "safety_checks": plan_safety_checks() if request_view else [],
        "stop_conditions": plan_stop_conditions()
        if request_view
        else [],
        "rollback": {
            "abort_supported": True,
            "rollback_supported": False,
            "rollback_reason": ROLLBACK_REASON_NO_EXECUTION,
            "reversible": False,
        },
        "provenance": plan_provenance,
        "governance": governance_value,
        "limitations": limitations_for(*extra),
        "execution_status": plan_status,
        "execution_performed": False,
        "external_executor_present": False,
        "external_executor_state": "ABSENT",
        "plan_declarative": True,
        "research_only": True,
        "deterministic": True,
    }
    try:
        return controlled_execution_plan_projection(
            ControlledExecutionPlan(**payload)
        )
    except (TypeError, ValueError):
        projected = sanitize_controlled_execution_plan(payload)
        projected["execution_status"] = PLAN_STATUS_INVALID
        return projected


# ---------------------------------------------------------------------------
# Execution control evaluation
# ---------------------------------------------------------------------------


def _coerce_authorization(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    if (
        _text(value.get("rule_version"))
        != CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION
    ):
        return {}
    return dict(value)


def _collect_safety(*values: object) -> list[str]:
    found: set[str] = set()
    for value in values:
        for reason in safety_reasons_for(value):
            found.add(reason)
        for reason in structured_safety_reasons(value):
            found.add(reason)
    return [reason for reason in SAFETY_REJECTION_REASONS if reason in found]


def evaluate_execution_control(
    execution_request: object = None,
    *,
    human_review_result: object = None,
    human_decision: object = None,
    authorization_context: object = None,
    authorization_source: object = None,
    authorization_authority: object = None,
    decision_reference: object = None,
    approved_action: object = None,
    approved_scope: object = None,
    approved_target: object = None,
    approval_constraints: object = None,
    validity: object = None,
    learning_result: object = None,
    prioritization_result: object = None,
    correlation_result: object = None,
    finding_intelligence: object = None,
    execution_authorization: object = None,
    controlled_execution_plan: object = None,
    preconditions_met: object = None,
    provenance: object = None,
    governance: object = None,
) -> dict:
    """Evaluate whether a request is eligible for controlled execution.

    R58 never executes anything: ``ALLOW`` means the request is structurally
    eligible to enter a future controlled execution workflow under an exact
    human authorization and a passing safety gate.
    """

    errors: list[dict] = []
    block_reasons: list[str] = []
    allow_reasons: list[str] = []

    if execution_request is None:
        return _not_requested_result(provenance, governance)

    if not isinstance(execution_request, dict):
        errors.append(
            _error(ERROR_MALFORMED_INPUT, "EXECUTION_REQUEST")
        )
        return _invalid_result(
            errors=errors,
            provenance=provenance,
            governance=governance,
        )

    request, failure = _coerce_request(execution_request)
    if failure == "RULE_VERSION_MISMATCH":
        errors.append(
            _error(ERROR_RULE_VERSION_MISMATCH, "EXECUTION_REQUEST")
        )
        request = None
    if request is None:
        return _invalid_result(
            errors=errors
            or [_error(ERROR_MALFORMED_INPUT, "EXECUTION_REQUEST")],
            provenance=provenance,
            governance=governance,
        )

    # ------------------------------------------------------------------
    # Safety gate over every supplied input; malformed layers fail closed
    # ------------------------------------------------------------------
    safety_reason_list = _collect_safety(
        request,
        authorization_context,
        human_review_result,
        human_decision,
        learning_result,
        prioritization_result,
        correlation_result,
        finding_intelligence,
        execution_authorization,
        controlled_execution_plan,
    )
    layer_error_found = False
    for value, input_kind, expected in (
        (
            finding_intelligence,
            "FINDING_INTELLIGENCE",
            EXPECTED_FINDING_RULE_VERSION,
        ),
        (
            correlation_result,
            "CORRELATION_RESULT",
            EXPECTED_CORRELATION_RULE_VERSION,
        ),
        (
            prioritization_result,
            "PRIORITIZATION_RESULT",
            EXPECTED_PRIORITY_RULE_VERSION,
        ),
        (
            learning_result,
            "LEARNING_RESULT",
            EXPECTED_LEARNING_RULE_VERSION,
        ),
        (
            human_review_result,
            "HUMAN_REVIEW_RESULT",
            EXPECTED_DECISION_RULE_VERSION,
        ),
    ):
        layer_error = _layer_error(value, input_kind, expected)
        if layer_error:
            errors.append(layer_error)
            layer_error_found = True

    safety_result = SAFETY_UNKNOWN
    if safety_reason_list:
        safety_result = SAFETY_BLOCKED
    elif layer_error_found or errors:
        safety_result = SAFETY_INVALID
    elif request.get("request_state") == REQUEST_STATE_BLOCKED:
        safety_result = SAFETY_BLOCKED
    elif request.get("request_state") == REQUEST_STATE_REQUESTED:
        safety_result = SAFETY_PASS

    # ------------------------------------------------------------------
    # Authorization (validate from human sources unless pre-built)
    # ------------------------------------------------------------------
    authorization = _coerce_authorization(execution_authorization)
    if not authorization:
        authorization = validate_execution_authorization(
            request,
            human_review_result=human_review_result,
            human_decision=human_decision,
            authorization_context=authorization_context,
            authorization_source=authorization_source,
            authorization_authority=authorization_authority,
            decision_reference=decision_reference,
            approved_action=approved_action,
            approved_scope=approved_scope,
            approved_target=approved_target,
            approval_constraints=approval_constraints,
            validity=validity,
            learning_result=learning_result,
            prioritization_result=prioritization_result,
            correlation_result=correlation_result,
            finding_intelligence=finding_intelligence,
            provenance=provenance,
            governance=governance,
        )
    if safety_reason_list and (
        authorization.get("authorization_status")
        == AUTHORIZATION_STATUS_AUTHORIZED
    ):
        authorization = dict(authorization)
        authorization["authorization_status"] = AUTHORIZATION_STATUS_BLOCKED
        authorization["execution_authorized"] = False

    # ------------------------------------------------------------------
    # Declarative plan
    # ------------------------------------------------------------------
    plan = (
        dict(controlled_execution_plan)
        if isinstance(controlled_execution_plan, dict)
        and _text(controlled_execution_plan.get("rule_version"))
        == CONTROLLED_EXECUTION_PLAN_RULE_VERSION
        else build_controlled_execution_plan(
            request,
            execution_authorization=authorization,
            preconditions_met=preconditions_met,
            safety_result=safety_result,
            safety_reasons=safety_reason_list,
            provenance=provenance,
            governance=governance,
        )
    )

    # ------------------------------------------------------------------
    # Deterministic outcome
    # ------------------------------------------------------------------
    authorization_status = _upper(authorization.get("authorization_status"))
    outcome = control_outcome_for(
        request_state=request.get("request_state"),
        safety_result=safety_result,
        authorization_status=authorization_status,
    )
    status = control_status_for(control_outcome=outcome)
    if safety_result == SAFETY_INVALID and not errors:
        errors.append(_error(ERROR_INVALID_INPUT, "EXECUTION_CONTROL"))

    authorization_reasons = [
        code
        for code in authorization.get("rejection_codes") or ()
        if code in EXECUTION_OUTCOME_REASONS
    ]
    if outcome == CONTROL_OUTCOME_ALLOW:
        allow_reasons = list(authorization.get("allow_reasons") or ())
    else:
        seen: list[str] = []
        for code in (
            list(authorization_reasons) + list(safety_reason_list)
        ):
            if code not in seen:
                seen.append(code)
        if not seen and outcome == CONTROL_OUTCOME_INVALID:
            seen.append(REASON_MALFORMED_INPUT)
        if not seen and outcome == CONTROL_OUTCOME_NOT_REQUESTED:
            seen.append(REASON_EXECUTION_NOT_REQUESTED)
        block_reasons = [code for code in seen][:32]

    if authorization_status == AUTHORIZATION_STATUS_EXPIRED:
        if REASON_AUTHORIZATION_EXPIRED not in block_reasons:
            block_reasons.append(REASON_AUTHORIZATION_EXPIRED)

    # ------------------------------------------------------------------
    # Audit, provenance, limitations
    # ------------------------------------------------------------------
    request_id = _text(request.get("request_id"))
    authorization_id = _text(authorization.get("authorization_id"))
    plan_id = _text(plan.get("plan_id"))
    finding_id = _text(request.get("finding_id"))
    decision_id = _text(
        authorization.get("decision_reference")
        or (request.get("human_decision_reference") or {}).get(
            "decision_id"
        )
    )
    action_type = _text(request.get("action_type"))
    action_scope = _text(request.get("action_scope"))
    target_reference = _text(request.get("target_reference"))
    execution_status = _text(plan.get("execution_status"))

    outcome_reasons = (
        allow_reasons if outcome == CONTROL_OUTCOME_ALLOW else block_reasons
    )
    audit_id = execution_audit_id(
        request_id=request_id,
        decision_id=decision_id,
        authorization_id=authorization_id,
        action_type=action_type,
        target_reference=target_reference,
        action_scope=action_scope,
        safety_result=safety_result,
        control_outcome=outcome,
        reasons=outcome_reasons,
    )
    control_id = execution_control_id(
        request_id=request_id,
        authorization_id=authorization_id,
        plan_id=plan_id,
        finding_id=finding_id,
        action_type=action_type,
        target_reference=target_reference,
        action_scope=action_scope,
        safety_result=safety_result,
        control_outcome=outcome,
        reasons=outcome_reasons,
    )
    provenance_value = _control_provenance(
        request, authorization, plan, learning_result,
        prioritization_result, correlation_result, finding_intelligence,
        provenance, request_id, authorization_id, plan_id, finding_id,
        decision_id,
    )
    governance_value = sanitize_finding_governance(
        governance
        or authorization.get("governance")
        or request.get("governance")
    )
    extra: list[str] = []
    if safety_reason_list:
        extra.append("SAFETY_BLOCKED")
    if block_reasons and not safety_reason_list:
        if REASON_AUTHORIZATION_EXPIRED in block_reasons:
            extra.append("AUTHORIZATION_EXPIRED")
        else:
            extra.append("AUTHORIZATION_MISSING")
    if execution_status in (PLAN_STATUS_REQUESTED, PLAN_STATUS_AUTHORIZED):
        extra.append("PLAN_NOT_READY_FOR_EXTERNAL_EXECUTOR")
    if _upper(governance_value.get("reference_state")) != "REFERENCED":
        extra.append("GOVERNANCE_UNKNOWN")
    if not _text(provenance_value.get("orchestration_id")):
        extra.append("PROVENANCE_INCOMPLETE")

    steps = plan.get("ordered_steps") or []
    payload = {
        "rule_version": EXECUTION_CONTROL_RESULT_RULE_VERSION,
        "control_id": control_id,
        "request_id": request_id,
        "authorization_id": authorization_id,
        "plan_id": plan_id,
        "finding_id": finding_id,
        "decision_id": decision_id,
        "action_type": action_type,
        "action_scope": action_scope,
        "target_reference": target_reference,
        "status": status,
        "control_outcome": outcome,
        "safety_result": safety_result,
        "safety_reasons": safety_reason_list,
        "authorization_status": authorization_status,
        "execution_status": execution_status,
        "block_reasons": block_reasons,
        "allow_reasons": allow_reasons,
        "request": request,
        "authorization": authorization,
        "plan": plan,
        "audit": {
            "rule_version": EXECUTION_CONTROL_RESULT_RULE_VERSION,
            "audit_id": audit_id,
            "request_id": request_id,
            "decision_id": decision_id,
            "authorization_id": authorization_id,
            "plan_id": plan_id,
            "finding_id": finding_id,
            "action_type": action_type,
            "action_scope": action_scope,
            "target_reference": target_reference,
            "safety_result": safety_result,
            "control_outcome": outcome,
            "outcome_reasons": outcome_reasons,
            "authorization_status": authorization_status,
            "execution_status": execution_status,
            "audit_state": (
                "VALID" if status in ("COMPLETED", "BLOCKED") else "UNKNOWN"
            ),
            "provenance": provenance_value,
            "governance": governance_value,
        },
        "summary": control_summary(
            request_present=True,
            block_reasons=block_reasons,
            safety_reasons=safety_reason_list,
            authorization_reasons=authorization_reasons,
            step_count=len(steps),
        ),
        "errors": errors,
        "provenance": provenance_value,
        "governance": governance_value,
        "limitations": limitations_for(*extra),
        "execution_authorized": outcome == CONTROL_OUTCOME_ALLOW,
        "execution_performed": False,
        "external_executor_present": False,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }
    try:
        return execution_control_result_plan_projection(
            ExecutionControlResultPlan(**payload)
        )
    except (TypeError, ValueError):
        projected = sanitize_execution_control_result(payload)
        projected["status"] = "FAILED"
        projected["control_outcome"] = CONTROL_OUTCOME_DENY
        projected["execution_authorized"] = False
        return projected


def _not_requested_result(
    provenance: object, governance: object
) -> dict:
    control_id = execution_control_id(
        request_id="",
        authorization_id="",
        plan_id="",
        finding_id="",
        action_type="",
        target_reference="",
        action_scope="",
        safety_result=SAFETY_UNKNOWN,
        control_outcome=CONTROL_OUTCOME_NOT_REQUESTED,
        reasons=[],
    )
    provenance_value = sanitize_execution_control_provenance(
        provenance if isinstance(provenance, dict) else None
    )
    governance_value = sanitize_finding_governance(governance)
    payload = {
        "rule_version": EXECUTION_CONTROL_RESULT_RULE_VERSION,
        "control_id": control_id,
        "status": "NOT_REQUESTED",
        "control_outcome": CONTROL_OUTCOME_NOT_REQUESTED,
        "safety_result": SAFETY_UNKNOWN,
        "authorization_status": "",
        "execution_status": "",
        "audit": {
            "rule_version": EXECUTION_CONTROL_RESULT_RULE_VERSION,
            "audit_id": execution_audit_id(
                request_id="",
                decision_id="",
                authorization_id="",
                action_type="",
                target_reference="",
                action_scope="",
                safety_result=SAFETY_UNKNOWN,
                control_outcome=CONTROL_OUTCOME_NOT_REQUESTED,
                reasons=[],
            ),
            "safety_result": SAFETY_UNKNOWN,
            "control_outcome": CONTROL_OUTCOME_NOT_REQUESTED,
            "outcome_reasons": [],
            "audit_state": "UNKNOWN",
            "provenance": provenance_value,
            "governance": governance_value,
        },
        "summary": control_summary(
            request_present=False,
            block_reasons=[],
            safety_reasons=[],
            authorization_reasons=[],
            step_count=0,
        ),
        "provenance": provenance_value,
        "governance": governance_value,
        "limitations": limitations_for(),
        "execution_authorized": False,
        "execution_performed": False,
        "external_executor_present": False,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }
    try:
        return execution_control_result_plan_projection(
            ExecutionControlResultPlan(**payload)
        )
    except (TypeError, ValueError):
        return sanitize_execution_control_result(payload)


def _invalid_result(
    *,
    errors: list[dict],
    provenance: object,
    governance: object,
) -> dict:
    control_id = execution_control_id(
        request_id="",
        authorization_id="",
        plan_id="",
        finding_id="",
        action_type="",
        target_reference="",
        action_scope="",
        safety_result=SAFETY_INVALID,
        control_outcome=CONTROL_OUTCOME_INVALID,
        reasons=[REASON_MALFORMED_INPUT],
    )
    provenance_value = sanitize_execution_control_provenance(
        provenance if isinstance(provenance, dict) else None
    )
    governance_value = sanitize_finding_governance(governance)
    payload = {
        "rule_version": EXECUTION_CONTROL_RESULT_RULE_VERSION,
        "control_id": control_id,
        "status": "INVALID",
        "control_outcome": CONTROL_OUTCOME_INVALID,
        "safety_result": SAFETY_INVALID,
        "safety_reasons": [SAFETY_REASON_MALFORMED_INPUT],
        "authorization_status": AUTHORIZATION_STATUS_INVALID,
        "execution_status": PLAN_STATUS_INVALID,
        "block_reasons": [REASON_MALFORMED_INPUT],
        "errors": errors,
        "audit": {
            "rule_version": EXECUTION_CONTROL_RESULT_RULE_VERSION,
            "audit_id": execution_audit_id(
                request_id="",
                decision_id="",
                authorization_id="",
                action_type="",
                target_reference="",
                action_scope="",
                safety_result=SAFETY_INVALID,
                control_outcome=CONTROL_OUTCOME_INVALID,
                reasons=[REASON_MALFORMED_INPUT],
            ),
            "safety_result": SAFETY_INVALID,
            "control_outcome": CONTROL_OUTCOME_INVALID,
            "outcome_reasons": [REASON_MALFORMED_INPUT],
            "audit_state": "INVALID",
            "provenance": provenance_value,
            "governance": governance_value,
        },
        "summary": control_summary(
            request_present=False,
            block_reasons=[REASON_MALFORMED_INPUT],
            safety_reasons=[SAFETY_REASON_MALFORMED_INPUT],
            authorization_reasons=[],
            step_count=0,
        ),
        "provenance": provenance_value,
        "governance": governance_value,
        "limitations": limitations_for(),
        "execution_authorized": False,
        "execution_performed": False,
        "external_executor_present": False,
        "exploit_authorized": False,
        "vulnerability_confirmed": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }
    try:
        return execution_control_result_plan_projection(
            ExecutionControlResultPlan(**payload)
        )
    except (TypeError, ValueError):
        return sanitize_execution_control_result(payload)


def _control_provenance(
    request: dict,
    authorization: dict,
    plan: dict,
    learning_result: object,
    prioritization_result: object,
    correlation_result: object,
    finding_intelligence: object,
    supplied: object,
    request_id: str,
    authorization_id: str,
    plan_id: str,
    finding_id: str,
    decision_id: str,
) -> dict:
    supplied_value = supplied if isinstance(supplied, dict) else {}
    request_provenance = request.get("provenance") or {}
    authorization_provenance = authorization.get("provenance") or {}
    learning_version = ""
    if isinstance(learning_result, dict):
        learning_version = _bounded(learning_result.get("rule_version"))
    priority_version = ""
    prioritization_id = ""
    if isinstance(prioritization_result, dict):
        priority_version = _bounded(
            prioritization_result.get("rule_version")
        )
        prioritization_id = _bounded(
            prioritization_result.get("prioritization_id")
        )
    correlation_version = ""
    correlation_id = ""
    if isinstance(correlation_result, dict):
        correlation_version = _bounded(
            correlation_result.get("rule_version")
        )
        correlation_id = _bounded(correlation_result.get("correlation_id"))
    finding_version = ""
    if isinstance(finding_intelligence, dict):
        finding_version = _bounded(
            finding_intelligence.get("rule_version")
        )
    stages: list[str] = []
    if finding_intelligence is not None:
        stages.append("FINDING_INTELLIGENCE")
    if correlation_result is not None:
        stages.append("CORRELATION")
    if prioritization_result is not None:
        stages.append("PRIORITIZATION")
    if learning_result is not None:
        stages.append("CONTINUOUS_LEARNING")
    return sanitize_execution_control_provenance(
        {
            "rule_version": EXECUTION_CONTROL_BUILDER_RULE_VERSION,
            "request_rule_version": EXECUTION_REQUEST_RULE_VERSION,
            "authorization_rule_version": (
                CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION
            ),
            "plan_rule_version": CONTROLLED_EXECUTION_PLAN_RULE_VERSION,
            "finding_rule_version": _bounded(
                supplied_value.get("finding_rule_version")
            )
            or finding_version
            or _bounded(request_provenance.get("finding_rule_version"))
            or _bounded(
                authorization_provenance.get("finding_rule_version")
            ),
            "correlation_rule_version": _bounded(
                supplied_value.get("correlation_rule_version")
            )
            or correlation_version
            or _bounded(
                request_provenance.get("correlation_rule_version")
            ),
            "priority_rule_version": _bounded(
                supplied_value.get("priority_rule_version")
            )
            or priority_version
            or _bounded(request_provenance.get("priority_rule_version")),
            "decision_rule_version": _bounded(
                supplied_value.get("decision_rule_version")
            )
            or HUMAN_DECISION_RULE_VERSION,
            "learning_rule_version": _bounded(
                supplied_value.get("learning_rule_version")
            )
            or learning_version,
            "request_id": request_id,
            "authorization_id": authorization_id,
            "plan_id": plan_id,
            "finding_id": finding_id,
            "decision_id": decision_id
            or _bounded(authorization_provenance.get("decision_id")),
            "prioritization_id": _bounded(
                supplied_value.get("prioritization_id")
            )
            or prioritization_id
            or _bounded(request_provenance.get("prioritization_id")),
            "correlation_id": _bounded(
                supplied_value.get("correlation_id")
            )
            or correlation_id
            or _bounded(request_provenance.get("correlation_id")),
            "orchestration_id": _bounded(
                supplied_value.get("orchestration_id")
            )
            or _bounded(request_provenance.get("orchestration_id")),
            "source_stages": stages,
        }
    )


def export_execution_control(
    execution_request: object = None, **kwargs
) -> dict:
    """Alias for :func:`evaluate_execution_control`."""

    return evaluate_execution_control(execution_request, **kwargs)


__all__ = [
    "EXECUTION_CONTROL_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "build_execution_request",
    "validate_execution_authorization",
    "build_controlled_execution_plan",
    "evaluate_execution_control",
    "export_execution_control",
]
