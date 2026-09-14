"""Stage R52.6 deterministic agent orchestrator (pure engine).

Coordinates the existing specialist research agents and the existing
intelligence layers without duplicating their logic:

    input
      -> context normalization (R52.2)
      -> specialist eligibility analysis (R52.2)
      -> deterministic specialist selection (R52.2)
      -> deterministic invocation of the existing R39-R50 exports (R52.4)
      -> R42 evaluation (existing generic evaluator)
      -> R43 collaboration (existing multi-agent layer)
      -> R44 feedback (existing event/classifier/signal/recommendation chain)
      -> optional R45/R51 advisory (existing structured bridge)
      -> structured orchestration result (R52.6)

Hard boundaries encoded here:

- Orchestration only: R52 dispatches existing pure research components. It
  performs no HTTP, no DNS, no scanning, no nuclei/ffuf/sqlmap, no browser
  automation, no subprocess, no shell, no database access, no payload
  generation, no exploitation, no authentication bypass, no target state
  modification, no credential testing and no vulnerability confirmation.
- No duplicated logic: specialist pipelines, the R42 evaluator, the R43
  collaboration layer and the R44 feedback chain are invoked through their
  existing structured APIs. R52 recomputes nothing.
- Advisory only through the existing bridge: the R51 advisory bridge is
  invoked through its structured Python API when advisory mode is explicitly
  enabled. R52 never imports or instantiates a provider adapter and never
  calls OpenRouter/OpenAI directly.
- Deterministic: selection, ordering, stage plan, error classification and
  the result structure are pure functions of the bounded context, registry
  and policy. No timestamps, UUIDs, pids or randomness.
- Fail closed and bounded: invalid input/policy, unknown explicit
  categories, execution failures and resource limits are structured; nothing
  is fabricated and no execution error ever becomes a finding.
- Pure and offline by default: no I/O, no network, no LLM, no Mongo, no
  wall-clock time, no randomness. Advisory is disabled unless requested.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.learning_recommendation_generator import (
    generate_learning_recommendations,
)
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.orchestration_policy import (
    OrchestrationPolicyError,
    resolve_orchestration_policy,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import (
    build_research_feedback_event,
)
from ai.knowledge.specialist_eligibility import (
    SpecialistSelectionError,
    analyze_specialist_eligibility,
    select_specialists,
)
from ai.knowledge.specialist_invoker import (
    invoke_specialist,
    specialist_identity_metadata,
)
from ai.providers.advisory_bridge import export_real_llm_advisory
from ai.schemas.agent_orchestrator_context import (
    context_value_is_known,
    sanitize_orchestration_context,
)
from ai.schemas.agent_orchestrator_policy import (
    MODE_AUTOMATIC,
    sanitize_orchestration_policy,
)
from ai.schemas.agent_orchestrator_registry import ORCHESTRATION_STAGES
from ai.schemas.agent_orchestrator_result import (
    AGENT_ORCHESTRATOR_RESULT_RULE_VERSION,
    ERROR_ADVISORY,
    ERROR_COLLABORATION,
    ERROR_EVALUATION,
    ERROR_FEEDBACK,
    ERROR_INVALID_INPUT,
    ERROR_INVALID_POLICY,
    ERROR_LIMIT_EXCEEDED,
    ERROR_NO_ELIGIBLE_SPECIALISTS,
    ERROR_SAFETY,
    ERROR_SPECIALIST_EXECUTION,
    ERROR_UNKNOWN,
    LIMITATION_ADVISORY_DISABLED,
    LIMITATION_ADVISORY_ERRORS,
    LIMITATION_COLLABORATION_SKIPPED,
    LIMITATION_EVALUATION_ERRORS,
    LIMITATION_FEEDBACK_ERRORS,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_NO_ELIGIBLE_SPECIALISTS,
    LIMITATION_RESOURCE_LIMIT,
    LIMITATION_SELECTION_LIMITED,
    LIMITATION_SPECIALIST_ERRORS,
    LIMITATION_STAGE_LIMIT,
    ORCHESTRATION_ID_PREFIX,
    ORCHESTRATION_LIMITATIONS,
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
    REFERENCE_REFERENCED,
    REFERENCE_UNKNOWN,
    SKIP_STOPPED_AFTER_ERROR,
    STAGE_ADVISORY,
    STAGE_COLLABORATION,
    STAGE_CONTEXT,
    STAGE_EVALUATION,
    STAGE_FEEDBACK,
    STAGE_INVOCATION,
    STAGE_POLICY,
    STAGE_SELECTION,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_ELIGIBLE_SPECIALISTS,
    STATUS_PARTIAL,
    AgentOrchestrationResultPlan,
    agent_orchestration_result_plan_projection,
    build_orchestration_governance_reference,
    sanitize_orchestration_error,
)
from ai.schemas.llm_advisory_input import (
    SAFETY_DEGRADED,
    SAFETY_FAILED,
    SAFETY_PASS,
    SAFETY_UNKNOWN,
)
from ai.schemas.research_feedback_event import (
    OUTCOME_CONFLICT,
    OUTCOME_DUPLICATION,
    OUTCOME_QUALITY,
    OUTCOME_SAFETY,
    OUTCOME_SUCCESS,
)

AGENT_ORCHESTRATOR_RULE_VERSION = "r52-6"
RULE_VERSION = AGENT_ORCHESTRATOR_RULE_VERSION

FEEDBACK_AGGREGATION_RULE_VERSION = "r52-5"

_STRONG_RATINGS: tuple[str, ...] = ("EXCELLENT", "GOOD")
_SAFETY_FAILURE_GATES: tuple[str, ...] = ("FAIL_SAFETY",)

_STAGE_INDEX: dict[str, int] = {
    stage: index + 1 for index, stage in enumerate(ORCHESTRATION_STAGES)
}

_DOWNSTREAM_STAGES: tuple[str, ...] = (
    STAGE_EVALUATION,
    STAGE_COLLABORATION,
    STAGE_FEEDBACK,
    STAGE_ADVISORY,
)


def _stage_allowed(stage: str, policy: dict) -> bool:
    budget = policy.get("max_orchestration_stages")
    if isinstance(budget, bool) or not isinstance(budget, int):
        return False
    return _STAGE_INDEX.get(stage, 99) <= budget


def _error(
    stage: str,
    error_category: str,
    specialist_category: str = "",
    message: str = "",
) -> dict:
    return sanitize_orchestration_error(
        {
            "stage": stage,
            "error_category": error_category,
            "specialist_category": specialist_category,
            "message": message,
        }
    )


def _ordered_limitations(codes: list[str]) -> list[str]:
    return [code for code in ORCHESTRATION_LIMITATIONS if code in codes]


def _ordered_stages(stages: list[str]) -> list[str]:
    return [stage for stage in ORCHESTRATION_STAGES if stage in stages]


def _orchestration_id(
    mode: str,
    selected: list[str],
    skipped: list[dict],
    context: dict,
    policy: dict,
    stages: list[str],
    origins: list[dict],
) -> str:
    """Derive the deterministic content id (no clock, no randomness)."""

    basis = json.dumps(
        {
            "rule_version": AGENT_ORCHESTRATOR_RESULT_RULE_VERSION,
            "mode": mode,
            "selected_specialists": list(selected),
            "skipped_specialists": [
                {
                    "category": item.get("category"),
                    "reason": item.get("reason"),
                }
                for item in skipped
            ],
            "context": context,
            "policy": policy,
            "stages": _ordered_stages(stages),
            "specialist_origins": [
                {
                    "category": origin.get("category"),
                    "agent_id": origin.get("agent_id"),
                }
                for origin in origins
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return ORCHESTRATION_ID_PREFIX + digest[:16]


def _aggregate_safety_state(evaluations: list[dict]) -> str:
    """Aggregate R42 safety states (no new security semantics)."""

    states = [
        str(evaluation.get("safety_state") or "").strip().upper()
        for evaluation in evaluations
    ]
    if SAFETY_FAILED in states:
        return SAFETY_FAILED
    if SAFETY_DEGRADED in states:
        return SAFETY_DEGRADED
    if states and all(state == SAFETY_PASS for state in states):
        return SAFETY_PASS
    return SAFETY_UNKNOWN


def _evaluation_for(
    evaluations: list[dict], agent_id: str, category: str
) -> dict | None:
    for evaluation in evaluations:
        if (
            evaluation.get("evaluated_agent_id") == agent_id
            and evaluation.get("evaluated_agent_category") == category
        ):
            return evaluation
    return None


def _collaboration_summary(collaboration: object) -> dict:
    if not isinstance(collaboration, dict):
        return {"conflict_count": 0, "duplicate_group_count": 0}
    conflicts = [
        item
        for item in collaboration.get("conflicts") or ()
        if isinstance(item, dict)
    ]
    duplicates = 0
    for group in collaboration.get("hypothesis_groups") or ():
        if isinstance(group, dict) and (
            str(group.get("correlation_type") or "").upper() == "DUPLICATE"
        ):
            duplicates += 1
    return {
        "conflict_count": len(conflicts),
        "duplicate_group_count": duplicates,
    }


def _derive_outcome_type(
    evaluation: object,
    collaboration_summary: dict,
) -> str:
    """Select the descriptive R44 outcome type (no classification logic)."""

    if isinstance(evaluation, dict):
        safety_state = str(
            evaluation.get("safety_state") or ""
        ).strip().upper()
        hard_gate = str(
            evaluation.get("hard_gate_state") or ""
        ).strip().upper()
        if safety_state == SAFETY_FAILED or hard_gate in _SAFETY_FAILURE_GATES:
            return OUTCOME_SAFETY
    if collaboration_summary.get("conflict_count"):
        return OUTCOME_CONFLICT
    if collaboration_summary.get("duplicate_group_count"):
        return OUTCOME_DUPLICATION
    if isinstance(evaluation, dict):
        diagnostics = evaluation.get("diagnostics") or []
        rating = str(evaluation.get("overall_rating") or "").upper()
        if not diagnostics and rating in _STRONG_RATINGS:
            return OUTCOME_SUCCESS
    return OUTCOME_QUALITY


def _finalize(
    *,
    status: str,
    mode: str,
    selected: list[str],
    skipped: list[dict],
    entries: list[dict],
    evaluations: list[dict],
    collaboration: dict | None,
    feedback_result: dict | None,
    advisory_result: dict | None,
    errors: list[dict],
    stages: list[str],
    skipped_stages: list[str],
    context: dict,
    policy: dict,
    governance: dict,
    limitations: list[str],
) -> dict:
    origins = [
        {
            "category": entry["category"],
            "specialist_name": entry["specialist_name"],
            "agent_id": entry["agent_id"],
            "stage": STAGE_INVOCATION,
        }
        for entry in entries
    ]
    provenance_state = PROVENANCE_UNKNOWN
    if origins:
        provenance_state = (
            PROVENANCE_PARTIAL if errors else PROVENANCE_COMPLETE
        )
    result = AgentOrchestrationResultPlan(
        rule_version=AGENT_ORCHESTRATOR_RESULT_RULE_VERSION,
        orchestration_id=_orchestration_id(
            mode, selected, skipped, context, policy, stages, origins
        ),
        status=status,
        mode=mode,
        selected_specialists=list(selected),
        skipped_specialists=list(skipped),
        specialist_results=list(entries),
        evaluation_results=list(evaluations),
        collaboration_result=collaboration,
        feedback_result=feedback_result,
        advisory_result=advisory_result,
        errors=list(errors),
        provenance={
            "rule_version": AGENT_ORCHESTRATOR_RESULT_RULE_VERSION,
            "stages": _ordered_stages(stages),
            "skipped_stages": _ordered_stages(skipped_stages),
            "specialist_origins": origins,
            "provenance_state": provenance_state,
            "research_only": True,
        },
        governance=governance,
        limitations=_ordered_limitations(limitations),
        research_only=True,
        deterministic=True,
    )
    return agent_orchestration_result_plan_projection(result)


def _specialist_input(
    base_input: dict,
    context: dict,
    mode: str,
    category: str,
) -> dict:
    block = {
        "rule_version": AGENT_ORCHESTRATOR_RESULT_RULE_VERSION,
        "mode": mode,
        "stage": STAGE_INVOCATION,
        "specialist_category": category,
        "research_only": True,
    }
    return {
        **base_input,
        "research_context": context,
        "orchestration_context": block,
    }


def _early_result(
    *,
    status: str,
    mode: str,
    context: dict,
    policy: dict,
    governance: dict,
    errors: list[dict],
    limitations: list[str],
    skipped: list[dict] | None = None,
    stages: list[str] | None = None,
) -> dict:
    return _finalize(
        status=status,
        mode=mode,
        selected=[],
        skipped=list(skipped or []),
        entries=[],
        evaluations=[],
        collaboration=None,
        feedback_result=None,
        advisory_result=None,
        errors=errors,
        stages=list(stages or []),
        skipped_stages=[],
        context=context,
        policy=policy,
        governance=governance,
        limitations=limitations,
    )


def _orchestrate(research_context, policy, security_agent_input,
                 governance_plan, shared_context, advisory_provider) -> dict:
    errors: list[dict] = []
    limitations: list[str] = []
    stages: list[str] = []
    skipped_stages: list[str] = []

    # ------------------------------------------------------------------
    # Context normalization
    # ------------------------------------------------------------------
    if research_context is not None and not isinstance(
        research_context, dict
    ):
        errors.append(
            _error(
                STAGE_CONTEXT,
                ERROR_INVALID_INPUT,
                message="research_context must be a mapping",
            )
        )
    context = sanitize_orchestration_context(research_context)

    # ------------------------------------------------------------------
    # Policy resolution (fail closed)
    # ------------------------------------------------------------------
    try:
        resolved_policy = resolve_orchestration_policy(policy)
    except OrchestrationPolicyError as exc:
        projected = sanitize_orchestration_policy(policy)
        governance = build_orchestration_governance_reference(
            governance_plan
        )
        errors.append(
            _error(STAGE_POLICY, ERROR_INVALID_POLICY, message=str(exc))
        )
        if governance.get("reference_state") != "REFERENCED":
            limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
        return _early_result(
            status=STATUS_FAILED,
            mode=projected.get("mode") or MODE_AUTOMATIC,
            context=context,
            policy=projected,
            governance=governance,
            errors=errors,
            limitations=limitations,
        )

    mode = resolved_policy["mode"]

    for name, value in (
        ("security_agent_input", security_agent_input),
        ("governance_plan", governance_plan),
        ("shared_context", shared_context),
    ):
        if value is not None and not isinstance(value, dict):
            errors.append(
                _error(
                    STAGE_CONTEXT,
                    ERROR_INVALID_INPUT,
                    message=f"{name} must be a mapping",
                )
            )

    governance = build_orchestration_governance_reference(governance_plan)
    if governance.get("reference_state") != "REFERENCED":
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)

    if errors:
        return _early_result(
            status=STATUS_FAILED,
            mode=mode,
            context=context,
            policy=resolved_policy,
            governance=governance,
            errors=errors,
            limitations=limitations,
        )

    base_input = (
        dict(security_agent_input)
        if isinstance(security_agent_input, dict)
        else {}
    )

    # ------------------------------------------------------------------
    # Eligibility analysis and deterministic selection
    # ------------------------------------------------------------------
    eligibility = analyze_specialist_eligibility(context)

    try:
        selection = select_specialists(eligibility, resolved_policy)
    except SpecialistSelectionError as exc:
        errors.append(
            _error(
                STAGE_SELECTION,
                exc.error_category,
                specialist_category=exc.category,
                message=str(exc),
            )
        )
        return _early_result(
            status=STATUS_FAILED,
            mode=mode,
            context=context,
            policy=resolved_policy,
            governance=governance,
            errors=errors,
            limitations=limitations,
        )

    stages.append(STAGE_SELECTION)
    selected = list(selection["selected_specialists"])
    skipped = list(selection["skipped_specialists"])

    if selection.get("limit_exceeded_specialists"):
        errors.append(
            _error(
                STAGE_SELECTION,
                ERROR_LIMIT_EXCEEDED,
                message="eligible specialists exceed max_specialists",
            )
        )
        limitations.append(LIMITATION_SELECTION_LIMITED)

    if not selected:
        errors.append(
            _error(
                STAGE_SELECTION,
                ERROR_NO_ELIGIBLE_SPECIALISTS,
                message="no eligible specialist for the supplied context",
            )
        )
        return _early_result(
            status=STATUS_NO_ELIGIBLE_SPECIALISTS,
            mode=mode,
            context=context,
            policy=resolved_policy,
            governance=governance,
            errors=errors,
            limitations=[
                *limitations,
                LIMITATION_NO_ELIGIBLE_SPECIALISTS,
            ],
            skipped=skipped,
            stages=stages,
        )

    # ------------------------------------------------------------------
    # Specialist invocation
    # ------------------------------------------------------------------
    entries: list[dict] = []
    invocation_ran = False
    if _stage_allowed(STAGE_INVOCATION, resolved_policy):
        invocation_ran = True
        stages.append(STAGE_INVOCATION)
        for index, category in enumerate(selected):
            try:
                result = invoke_specialist(
                    category,
                    context,
                    _specialist_input(base_input, context, mode, category),
                    governance_plan,
                )
            except Exception:
                errors.append(
                    _error(
                        STAGE_INVOCATION,
                        ERROR_SPECIALIST_EXECUTION,
                        specialist_category=category,
                        message="specialist execution failed",
                    )
                )
                limitations.append(LIMITATION_SPECIALIST_ERRORS)
                if not resolved_policy["continue_on_specialist_error"]:
                    skipped.extend(
                        {
                            "category": remaining,
                            "reason": SKIP_STOPPED_AFTER_ERROR,
                        }
                        for remaining in selected[index + 1:]
                    )
                    break
            else:
                metadata = specialist_identity_metadata(category)
                entries.append(
                    {
                        "category": category,
                        "specialist_name": metadata["specialist_name"],
                        "agent_id": metadata["agent_id"],
                        "stage": STAGE_INVOCATION,
                        "result": result,
                        "evaluation_reference": {
                            "reference_state": REFERENCE_UNKNOWN
                        },
                        "collaboration_reference": {
                            "reference_state": REFERENCE_UNKNOWN
                        },
                        "feedback_reference": {
                            "reference_state": REFERENCE_UNKNOWN
                        },
                        "advisory_reference": {
                            "reference_state": REFERENCE_UNKNOWN
                        },
                    }
                )
    else:
        skipped_stages.append(STAGE_INVOCATION)
        limitations.append(LIMITATION_STAGE_LIMIT)

    # ------------------------------------------------------------------
    # Resource limits before downstream processing
    # ------------------------------------------------------------------
    limits_exceeded = False
    if entries and _stage_allowed(STAGE_EVALUATION, resolved_policy):
        hypothesis_total = sum(
            len(entry["result"].get("hypotheses") or ())
            for entry in entries
        )
        evidence_total = sum(
            len(
                (entry["result"].get("evidence_plan") or {}).get(
                    "evidence_items"
                )
                or ()
            )
            for entry in entries
        )
        if (
            hypothesis_total
            > resolved_policy["max_hypotheses_processed"]
            or evidence_total
            > resolved_policy["max_evidence_items_processed"]
        ):
            errors.append(
                _error(
                    STAGE_EVALUATION,
                    ERROR_LIMIT_EXCEEDED,
                    message="specialist output exceeds processing limits",
                )
            )
            limitations.append(LIMITATION_RESOURCE_LIMIT)
            limits_exceeded = True

    # ------------------------------------------------------------------
    # R42 evaluation (existing generic evaluator)
    # ------------------------------------------------------------------
    evaluations: list[dict] = []
    if limits_exceeded:
        skipped_stages.append(STAGE_EVALUATION)
    elif resolved_policy["evaluate_results"]:
        if not entries:
            skipped_stages.append(STAGE_EVALUATION)
        elif not _stage_allowed(STAGE_EVALUATION, resolved_policy):
            skipped_stages.append(STAGE_EVALUATION)
            limitations.append(LIMITATION_STAGE_LIMIT)
        else:
            stages.append(STAGE_EVALUATION)
            for entry in entries:
                try:
                    evaluation = evaluate_agent_result(
                        entry["result"],
                        agent_id=entry["agent_id"],
                        agent_category=entry["category"],
                    )
                except Exception:
                    errors.append(
                        _error(
                            STAGE_EVALUATION,
                            ERROR_EVALUATION,
                            specialist_category=entry["category"],
                            message="evaluation failed",
                        )
                    )
                    limitations.append(LIMITATION_EVALUATION_ERRORS)
                else:
                    evaluations.append(evaluation)
    else:
        skipped_stages.append(STAGE_EVALUATION)

    # ------------------------------------------------------------------
    # R43 collaboration (existing multi-agent layer)
    # ------------------------------------------------------------------
    collaboration: dict | None = None
    if limits_exceeded or not resolved_policy["collaborate_results"]:
        skipped_stages.append(STAGE_COLLABORATION)
    elif len(entries) < 2:
        skipped_stages.append(STAGE_COLLABORATION)
        if len(entries) == 1:
            limitations.append(LIMITATION_COLLABORATION_SKIPPED)
    elif not _stage_allowed(STAGE_COLLABORATION, resolved_policy):
        skipped_stages.append(STAGE_COLLABORATION)
        limitations.append(LIMITATION_STAGE_LIMIT)
    else:
        stages.append(STAGE_COLLABORATION)
        wrapped = [
            {
                "specialist_result": entry["result"],
                "agent_id": entry["agent_id"],
                "agent_category": entry["category"],
            }
            for entry in entries
        ]
        try:
            collaboration = export_multi_agent_collaboration(
                wrapped,
                evaluation_results=evaluations,
                shared_context=shared_context,
            )
        except Exception:
            errors.append(
                _error(
                    STAGE_COLLABORATION,
                    ERROR_COLLABORATION,
                    message="collaboration failed",
                )
            )
            limitations.append(LIMITATION_COLLABORATION_SKIPPED)

    collaboration_summary = _collaboration_summary(collaboration)

    # ------------------------------------------------------------------
    # R44 feedback (existing event/classifier/signal/recommendation chain)
    # ------------------------------------------------------------------
    feedback_result: dict | None = None
    if limits_exceeded or not resolved_policy["generate_feedback"]:
        skipped_stages.append(STAGE_FEEDBACK)
    elif not entries:
        skipped_stages.append(STAGE_FEEDBACK)
    elif not _stage_allowed(STAGE_FEEDBACK, resolved_policy):
        skipped_stages.append(STAGE_FEEDBACK)
        limitations.append(LIMITATION_STAGE_LIMIT)
    else:
        stages.append(STAGE_FEEDBACK)
        try:
            events: list[dict] = []
            for entry in entries:
                evaluation = _evaluation_for(
                    evaluations, entry["agent_id"], entry["category"]
                )
                events.append(
                    build_research_feedback_event(
                        source_agent=entry["agent_id"],
                        source_category=entry["category"],
                        evaluation_result=evaluation,
                        collaboration_result=collaboration,
                        outcome_type=_derive_outcome_type(
                            evaluation, collaboration_summary
                        ),
                    )
                )
            classifications = classify_research_feedback_events(events)
            signals = extract_learning_signals(classifications)
            recommendations = generate_learning_recommendations(
                signals=signals
            )
            feedback_result = {
                "rule_version": FEEDBACK_AGGREGATION_RULE_VERSION,
                "events": events,
                "classifications": classifications,
                "learning_signals": signals,
                "recommendations": recommendations,
                "research_only": True,
            }
        except Exception:
            errors.append(
                _error(
                    STAGE_FEEDBACK,
                    ERROR_FEEDBACK,
                    message="feedback aggregation failed",
                )
            )
            limitations.append(LIMITATION_FEEDBACK_ERRORS)

    # ------------------------------------------------------------------
    # Optional R45/R51 advisory (existing structured bridge only)
    # ------------------------------------------------------------------
    advisory: dict | None = None
    if limits_exceeded or not resolved_policy["advisory_enabled"]:
        skipped_stages.append(STAGE_ADVISORY)
        if not resolved_policy["advisory_enabled"]:
            limitations.append(LIMITATION_ADVISORY_DISABLED)
    elif not _stage_allowed(STAGE_ADVISORY, resolved_policy):
        skipped_stages.append(STAGE_ADVISORY)
        limitations.append(LIMITATION_STAGE_LIMIT)
    else:
        stages.append(STAGE_ADVISORY)
        try:
            advisory = export_real_llm_advisory(
                evaluation_result=evaluations[0] if evaluations else None,
                collaboration_result=collaboration,
                learning_signals=(
                    (feedback_result or {}).get("learning_signals") or None
                ),
                research_context={
                    "context_fact_count": sum(
                        1
                        for value in context.values()
                        if context_value_is_known(value)
                    )
                },
                governance_state=(
                    governance.get("reference_state") or "UNKNOWN"
                ),
                safety_state=_aggregate_safety_state(evaluations),
                requested_mode=resolved_policy["advisory_mode"],
                provider=advisory_provider,
                provider_kind=resolved_policy["advisory_provider_kind"],
            )
        except Exception:
            errors.append(
                _error(
                    STAGE_ADVISORY,
                    ERROR_ADVISORY,
                    message="advisory bridge failed",
                )
            )
            limitations.append(LIMITATION_ADVISORY_ERRORS)
        else:
            provider_state = (
                str(advisory.get("provider_state") or "").upper()
                if isinstance(advisory, dict)
                else ""
            )
            if provider_state == "REJECTED":
                errors.append(
                    _error(
                        STAGE_ADVISORY,
                        ERROR_SAFETY,
                        message="unsafe advisory output was rejected",
                    )
                )
                limitations.append(LIMITATION_ADVISORY_ERRORS)
            elif provider_state != "OK":
                errors.append(
                    _error(
                        STAGE_ADVISORY,
                        ERROR_ADVISORY,
                        message="advisory provider did not succeed",
                    )
                )
                limitations.append(LIMITATION_ADVISORY_ERRORS)

    # ------------------------------------------------------------------
    # Provenance references (per specialist result origin)
    # ------------------------------------------------------------------
    for entry in entries:
        evaluation = _evaluation_for(
            evaluations, entry["agent_id"], entry["category"]
        )
        if evaluation is not None:
            entry["evaluation_reference"] = {
                "reference_state": REFERENCE_REFERENCED,
                "overall_rating": evaluation.get("overall_rating") or "",
                "safety_state": evaluation.get("safety_state") or "",
                "hard_gate_state": evaluation.get("hard_gate_state") or "",
                "confidence": entry["result"].get("confidence") or "",
            }
        if isinstance(collaboration, dict) and (
            collaboration.get("collaboration_id")
        ):
            entry["collaboration_reference"] = {
                "reference_state": REFERENCE_REFERENCED,
                "collaboration_id": collaboration.get("collaboration_id"),
            }
        if isinstance(feedback_result, dict):
            for event in feedback_result.get("events") or ():
                if not isinstance(event, dict):
                    continue
                if (
                    event.get("source_agent") == entry["agent_id"]
                    and event.get("source_category") == entry["category"]
                ):
                    entry["feedback_reference"] = {
                        "reference_state": REFERENCE_REFERENCED,
                        "feedback_id": event.get("feedback_id") or "",
                    }
                    break
        if isinstance(advisory, dict) and (
            str(advisory.get("provider_state") or "").upper() == "OK"
        ):
            advisory_result = advisory.get("advisory_result")
            advisory_id = (
                advisory_result.get("advisory_id")
                if isinstance(advisory_result, dict)
                else ""
            )
            entry["advisory_reference"] = {
                "reference_state": REFERENCE_REFERENCED,
                "advisory_id": advisory_id or "",
            }

    # ------------------------------------------------------------------
    # Final status
    # ------------------------------------------------------------------
    if not entries:
        if invocation_ran and selected:
            status = STATUS_FAILED
        elif selected and not invocation_ran:
            status = STATUS_PARTIAL
        else:
            status = STATUS_FAILED
    elif errors:
        status = STATUS_PARTIAL
    else:
        status = STATUS_COMPLETED

    return _finalize(
        status=status,
        mode=mode,
        selected=selected,
        skipped=skipped,
        entries=entries,
        evaluations=evaluations,
        collaboration=collaboration,
        feedback_result=feedback_result,
        advisory_result=advisory,
        errors=errors,
        stages=stages,
        skipped_stages=skipped_stages,
        context=context,
        policy=resolved_policy,
        governance=governance,
        limitations=limitations,
    )


def _unknown_error_result(
    policy: object,
    research_context: object,
    governance_plan: object,
) -> dict:
    context = sanitize_orchestration_context(research_context)
    projected = sanitize_orchestration_policy(policy)
    governance = build_orchestration_governance_reference(governance_plan)
    return _early_result(
        status=STATUS_FAILED,
        mode=projected.get("mode") or MODE_AUTOMATIC,
        context=context,
        policy=projected,
        governance=governance,
        errors=[
            _error(
                STAGE_CONTEXT,
                ERROR_UNKNOWN,
                message="orchestration failed unexpectedly",
            )
        ],
        limitations=(
            [LIMITATION_GOVERNANCE_UNKNOWN]
            if governance.get("reference_state") != "REFERENCED"
            else []
        ),
    )


def orchestrate_research(
    research_context: object = None,
    policy: object = None,
    security_agent_input: object = None,
    governance_plan: object = None,
    shared_context: object = None,
    advisory_provider: object = None,
) -> dict:
    """Run one deterministic orchestration over the structured context.

    ``research_context`` is the bounded structured context the specialists
    reason over. ``policy`` is the explicit R52.3 policy (``None`` selects the
    safe default: automatic selection, advisory disabled).
    ``advisory_provider`` may inject a provider object for tests; real
    providers are only ever reached through the R51 advisory bridge, and only
    when advisory is explicitly enabled. Nothing is executed and no
    vulnerability is claimed.
    """

    try:
        return _orchestrate(
            research_context,
            policy,
            security_agent_input,
            governance_plan,
            shared_context,
            advisory_provider,
        )
    except Exception:
        return _unknown_error_result(
            policy, research_context, governance_plan
        )


def export_agent_orchestration(**kwargs) -> dict:
    """Alias for :func:`orchestrate_research` (project naming pattern)."""

    return orchestrate_research(**kwargs)


def run_agent_orchestration(**kwargs) -> dict:
    """Alias for :func:`orchestrate_research` (project naming pattern)."""

    return orchestrate_research(**kwargs)


__all__ = [
    "AGENT_ORCHESTRATOR_RULE_VERSION",
    "RULE_VERSION",
    "FEEDBACK_AGGREGATION_RULE_VERSION",
    "CANONICAL_SPECIALIST_ORDER",
    "orchestrate_research",
    "export_agent_orchestration",
    "run_agent_orchestration",
]
