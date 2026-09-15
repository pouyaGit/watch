"""Stage R59.6 deterministic end-to-end workflow builder (public API).

Implements the R59 end-to-end security research workflow over the existing
intelligence layers:

    Specialist Research (R39-R50/R52)
      -> R42 Evaluation
      -> R43 Collaboration
      -> R44 Feedback
      -> R53 Finding Intelligence
      -> R54 Finding Correlation
      -> R55 Research Prioritization
      -> R56 Human Decision Boundary
      -> R57 Continuous Learning
      -> R58 Controlled Execution Gate
      -> R59 Workflow State + Next Action

The workflow answers exactly one question:

    "What is the current structured state of a security research workflow,
     what should happen next, and what is the safest valid boundary the
     workflow can reach?"

Hard boundaries encoded here:

- Workflow layer, not executor: R59 consumes existing artifacts, validates
  them and recommends advisory next steps. It never sends requests, scans,
  browses, exploits, confirms vulnerabilities or executes anything.
- No duplicated intelligence: every stage reads its existing structured
  contract; R58 is reached only through its public API
  (:func:`ai.knowledge.execution_control.evaluate_execution_control`).
- Human authority preserved: R56 decision fields are never reinterpreted;
  ``APPROVE_RESEARCH`` is not confirmation, not exploit authorization and
  not arbitrary execution authorization.
- Fail closed: malformed, mis-versioned, contradictory or missing-required
  inputs produce closed structured errors; nothing is silently skipped.
- Deterministic: content-derived ids; fixed stage order; stable sorting; no
  timestamps, UUIDs, pids, randomness or wall-clock time.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.execution_control import evaluate_execution_control
from ai.knowledge.security_research_workflow_rules import (
    EXPECTED_COLLABORATION_RULE_VERSION,
    EXPECTED_CORRELATION_RULE_VERSION,
    EXPECTED_EVALUATION_RULE_VERSION,
    EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
    EXPECTED_EXECUTION_REQUEST_RULE_VERSION,
    EXPECTED_FEEDBACK_RULE_VERSION,
    EXPECTED_FINDING_RULE_VERSION,
    EXPECTED_HUMAN_REVIEW_RULE_VERSION,
    EXPECTED_LEARNING_RULE_VERSION,
    EXPECTED_ORCHESTRATION_RULE_VERSION,
    EXPECTED_PRIORITIZATION_RULE_VERSION,
    build_summary,
    collect_safety_reasons,
    evaluation_safety_state,
    execution_control_summary,
    human_decision_summary,
    learning_summary,
    make_reference,
    make_stage,
    mark_recommended_stage_ready,
    next_action_id,
    resolve_workflow_state,
    stage_by_type,
    transition_error,
    workflow_error,
    workflow_id,
    workflow_limitations,
    workflow_result_id,
)
from ai.schemas.finding_result import (
    build_finding_governance_reference,
    sanitize_finding_governance,
)
from ai.schemas.human_decision import DECISION_APPROVE_RESEARCH
from ai.schemas.security_research_workflow import (
    SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
    sanitize_workflow_options,
)
from ai.schemas.security_research_workflow_result import (
    ERROR_EXECUTION_CONTROL_BLOCKED,
    ERROR_HUMAN_DECISION_REQUIRED,
    ERROR_INVALID_INPUT,
    ERROR_LEARNING_REVIEW_REQUIRED,
    ERROR_MALFORMED_INPUT,
    ERROR_MISSING_REQUIRED_STAGE,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    ERROR_UNSUPPORTED_TRANSITION,
    ERROR_UPSTREAM_RESULT_INVALID,
    ERROR_WORKFLOW_CONFLICT,
    HUMAN_STATUS_BLOCKED,
    HUMAN_STATUS_REVIEW_REQUIRED,
    SAFETY_STATUS_EXECUTION_BLOCKED,
    SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
    SAFETY_STATUS_SAFETY_BLOCKED,
    STATE_AWAITING_HUMAN_DECISION,
    STATE_BLOCKED,
    STATE_COMPLETED,
    STATE_INVALID,
    SecurityResearchWorkflowResultPlan,
    sanitize_security_research_workflow_result,
    sanitize_workflow_reference,
    sanitize_workflow_result_provenance,
    sanitize_workflow_result_summary,
    security_research_workflow_result_plan_projection,
)
from ai.schemas.workflow_next_action import (
    ACTION_STAGE,
    WORKFLOW_NEXT_ACTION_LIMITATIONS,
    WorkflowNextActionPlan,
    sanitize_workflow_next_action,
    workflow_next_action_plan_projection,
)
from ai.schemas.workflow_stage import (
    REASON_COLLABORATION_PRESENT,
    REASON_CORRELATION_PRESENT,
    REASON_EVALUATIONS_PRESENT,
    REASON_EXECUTION_ALLOWED,
    REASON_EXECUTION_BLOCKED,
    REASON_EXECUTION_READY,
    REASON_FEEDBACK_PRESENT,
    REASON_FINDINGS_PRESENT,
    REASON_HUMAN_DECIDED,
    REASON_HUMAN_DECISION_BLOCKS,
    REASON_HUMAN_ESCALATION_REQUIRED,
    REASON_HUMAN_REVIEW_PENDING,
    REASON_LEARNING_PRESENT,
    REASON_LEARNING_REVIEW_REQUIRED,
    REASON_NO_FINDINGS_PRODUCED,
    REASON_NOT_PROVIDED,
    REASON_PRIORITIZATION_PRESENT,
    REASON_RESEARCH_INPUT_PRESENT,
    REASON_SKIPPED_BY_OPTION,
    REASON_SPECIALIST_RESULTS_PRESENT,
    REASON_STAGE_COMPLETED_EXTERNALLY,
    REASON_UPSTREAM_RESULT_INVALID,
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
    sanitize_workflow_stage,
)

SECURITY_RESEARCH_WORKFLOW_BUILDER_RULE_VERSION = "r59-6"
RULE_VERSION = SECURITY_RESEARCH_WORKFLOW_BUILDER_RULE_VERSION

MAX_TEXT = 240

#: Artifact parameters accepted by the workflow builder.
ARTIFACT_PARAMETERS: tuple[str, ...] = (
    "workflow_input",
    "research_context",
    "specialist_results",
    "orchestration_result",
    "evaluation_results",
    "collaboration_result",
    "feedback_result",
    "finding_intelligence",
    "correlation_result",
    "prioritization_result",
    "human_review_result",
    "learning_result",
    "execution_control_result",
    "execution_request",
)

_MISSING = object()


def _field(base: dict, key: str, override: object) -> object:
    if override is not _MISSING and override is not None:
        return override
    return base.get(key, _MISSING)


def _merge_inputs(workflow_request: object, overrides: dict) -> tuple[dict, bool]:
    """Merge a request dict with explicit keyword overrides (fail closed)."""

    if workflow_request is None:
        base: dict = {}
        malformed = False
    elif isinstance(workflow_request, dict):
        base = dict(workflow_request)
        malformed = False
    else:
        base = {}
        malformed = True
    for key, value in overrides.items():
        if value is not _MISSING and value is not None:
            base[key] = value
    return base, malformed


def _validate_container(
    value: object,
    label: str,
    expected_rule_version: str,
    errors: list[dict],
) -> dict | None:
    """Validate one structured upstream container (fail closed)."""

    if value is None or value is _MISSING:
        return None
    if not isinstance(value, dict) or not value:
        errors.append(
            workflow_error(
                ERROR_MALFORMED_INPUT,
                label,
                "input must be a non-empty mapping",
            )
        )
        return None
    if (
        expected_rule_version
        and str(value.get("rule_version") or "").strip()
        != expected_rule_version
    ):
        errors.append(
            workflow_error(
                ERROR_RULE_VERSION_MISMATCH,
                label,
                "input rule version does not match the expected layer",
            )
        )
        return None
    return value


def _validate_list(
    value: object, label: str, expected_rule_version: str, errors: list[dict]
) -> list | None:
    if value is None or value is _MISSING:
        return None
    if not isinstance(value, (list, tuple)):
        errors.append(
            workflow_error(ERROR_MALFORMED_INPUT, label, "input must be a list")
        )
        return None
    out: list = []
    for entry in list(value):
        if not isinstance(entry, dict) or not entry:
            errors.append(
                workflow_error(
                    ERROR_MALFORMED_INPUT,
                    label,
                    "entry must be a mapping",
                )
            )
            return None
        if (
            expected_rule_version
            and str(entry.get("rule_version") or "").strip()
            != expected_rule_version
        ):
            errors.append(
                workflow_error(
                    ERROR_RULE_VERSION_MISMATCH,
                    label,
                    "entry rule version does not match the layer",
                )
            )
            return None
        out.append(entry)
    return out


def _validate_specialist_results(
    value: object, errors: list[dict]
) -> list | None:
    if value is None or value is _MISSING:
        return None
    if not isinstance(value, (list, tuple)):
        errors.append(
            workflow_error(
                ERROR_MALFORMED_INPUT,
                STAGE_SPECIALIST_RESEARCH,
                "specialist_results must be a list",
            )
        )
        return None
    out = [entry for entry in list(value) if isinstance(entry, dict)]
    if len(out) != len(list(value)):
        errors.append(
            workflow_error(
                ERROR_MALFORMED_INPUT,
                STAGE_SPECIALIST_RESEARCH,
                "specialist entries must be mappings",
            )
        )
        return None
    return out


# ---------------------------------------------------------------------------
# Stage construction
# ---------------------------------------------------------------------------


def _build_stages(
    workflow_id_value: str,
    *,
    research_input: bool,
    specialist_results: object,
    evaluations: object,
    collaboration: object,
    feedback: object,
    findings: object,
    correlation: object,
    prioritization: object,
    human_review: object,
    learning: object,
    execution_control: object,
    options: dict,
    specialist_count: int,
) -> list[dict]:
    """Build the fixed-order workflow stages from validated artifacts."""

    stages: list[dict] = []

    # SPECIALIST_RESEARCH ------------------------------------------------
    specialist_list = specialist_results or []
    if specialist_list:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_SPECIALIST_RESEARCH,
                STAGE_STATUS_COMPLETED,
                REASON_SPECIALIST_RESULTS_PRESENT,
                output_reference=make_reference(
                    "SPECIALIST_RESULTS",
                    present=True,
                    reference_id=_text(
                        (specialist_list[0] or {}).get("agent_id")
                    )
                    if specialist_list
                    else "",
                    rule_version=_text(
                        (specialist_list[0] or {}).get("rule_version")
                    )
                    if specialist_list
                    else "",
                    status="COMPLETED",
                    item_count=max(specialist_count, len(specialist_list)),
                ),
                metadata={
                    "specialist_count": max(
                        specialist_count, len(specialist_list)
                    ),
                    "research_input_present": research_input,
                },
                upstream_rule_version=_text(
                    (specialist_list[0] or {}).get("rule_version")
                )
                if specialist_list
                else "",
            )
        )
    elif research_input:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_SPECIALIST_RESEARCH,
                STAGE_STATUS_READY,
                REASON_RESEARCH_INPUT_PRESENT,
                metadata={
                    "specialist_count": 0,
                    "research_input_present": True,
                },
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_SPECIALIST_RESEARCH,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
                metadata={"specialist_count": 0},
            )
        )

    # EVALUATION ---------------------------------------------------------
    evaluation_list = evaluations or []
    if evaluation_list:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EVALUATION,
                STAGE_STATUS_COMPLETED,
                REASON_EVALUATIONS_PRESENT,
                output_reference=make_reference(
                    "EVALUATION",
                    present=True,
                    reference_id=_text(
                        evaluation_list[0].get("evaluation_id")
                    ),
                    rule_version=EXPECTED_EVALUATION_RULE_VERSION,
                    status="COMPLETED",
                    item_count=len(evaluation_list),
                ),
                metadata={
                    "evaluation_count": len(evaluation_list),
                    "evaluation_safety_state": evaluation_safety_state(
                        evaluation_list
                    ),
                },
                upstream_rule_version=EXPECTED_EVALUATION_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EVALUATION,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # COLLABORATION ------------------------------------------------------
    if collaboration:
        participants = collaboration.get("participating_agents") or ()
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_COLLABORATION,
                STAGE_STATUS_COMPLETED,
                REASON_COLLABORATION_PRESENT,
                output_reference=make_reference(
                    "COLLABORATION",
                    present=True,
                    reference_id=_text(collaboration.get("collaboration_id")),
                    rule_version=EXPECTED_COLLABORATION_RULE_VERSION,
                    status="COMPLETED",
                    item_count=len(participants) if participants else 0,
                ),
                metadata={
                    "participant_count": len(participants)
                    if participants
                    else 0,
                    "conflict_count": len(
                        collaboration.get("conflicts") or ()
                    ),
                },
                upstream_rule_version=EXPECTED_COLLABORATION_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_COLLABORATION,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # FEEDBACK -----------------------------------------------------------
    if feedback:
        classification_count = len(feedback.get("classifications") or ())
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_FEEDBACK,
                STAGE_STATUS_COMPLETED,
                REASON_FEEDBACK_PRESENT,
                output_reference=make_reference(
                    "FEEDBACK",
                    present=True,
                    rule_version=EXPECTED_FEEDBACK_RULE_VERSION,
                    status="COMPLETED",
                    item_count=classification_count,
                ),
                metadata={
                    "classification_count": classification_count,
                    "recommendation_count": len(
                        feedback.get("recommendations") or ()
                    ),
                },
                upstream_rule_version=EXPECTED_FEEDBACK_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_FEEDBACK,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # FINDING ------------------------------------------------------------
    if findings:
        finding_list = findings.get("findings") or ()
        finding_count = len(finding_list)
        reason = (
            REASON_FINDINGS_PRESENT
            if finding_count
            else REASON_NO_FINDINGS_PRODUCED
        )
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_FINDING,
                STAGE_STATUS_COMPLETED,
                reason,
                output_reference=make_reference(
                    "FINDING",
                    present=True,
                    reference_id=_text(findings.get("intelligence_id")),
                    rule_version=EXPECTED_FINDING_RULE_VERSION,
                    status=_upper(findings.get("status")),
                    item_count=finding_count,
                ),
                metadata={
                    "finding_count": finding_count,
                    "finding_status": _upper(findings.get("status")),
                },
                upstream_rule_version=EXPECTED_FINDING_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_FINDING,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # CORRELATION --------------------------------------------------------
    if correlation:
        references = correlation.get("finding_references") or ()
        items = len(references) if references else len(
            correlation.get("relationships") or ()
        )
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_CORRELATION,
                STAGE_STATUS_COMPLETED,
                REASON_CORRELATION_PRESENT,
                output_reference=make_reference(
                    "CORRELATION",
                    present=True,
                    reference_id=_text(correlation.get("correlation_id")),
                    rule_version=EXPECTED_CORRELATION_RULE_VERSION,
                    status=_upper(correlation.get("status")),
                    item_count=items,
                ),
                metadata={
                    "relationship_count": len(
                        correlation.get("relationships") or ()
                    ),
                    "cluster_count": len(
                        correlation.get("clusters") or ()
                    ),
                    "correlation_status": _upper(
                        correlation.get("status")
                    ),
                },
                upstream_rule_version=EXPECTED_CORRELATION_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_CORRELATION,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # PRIORITIZATION -----------------------------------------------------
    if prioritization:
        ranked = prioritization.get("ranked_findings") or ()
        deferred = prioritization.get("deferred_findings") or ()
        band = ""
        for plan in list(ranked) + list(deferred):
            candidate = _upper((plan or {}).get("priority_band"))
            if candidate:
                band = candidate
                break
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_PRIORITIZATION,
                STAGE_STATUS_COMPLETED,
                REASON_PRIORITIZATION_PRESENT,
                output_reference=make_reference(
                    "PRIORITIZATION",
                    present=True,
                    reference_id=_text(
                        prioritization.get("prioritization_id")
                    ),
                    rule_version=EXPECTED_PRIORITIZATION_RULE_VERSION,
                    status=_upper(prioritization.get("status")),
                    item_count=len(ranked) + len(deferred),
                ),
                metadata={
                    "ranked_count": len(ranked),
                    "deferred_count": len(deferred),
                    "priority_band": band,
                    "prioritization_status": _upper(
                        prioritization.get("status")
                    ),
                },
                upstream_rule_version=EXPECTED_PRIORITIZATION_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_PRIORITIZATION,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # HUMAN_REVIEW -------------------------------------------------------
    human = human_decision_summary(human_review)
    if human.get("error"):
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_HUMAN_REVIEW,
                STAGE_STATUS_INVALID,
                REASON_UPSTREAM_RESULT_INVALID,
                metadata={"review_present": True},
            )
        )
    elif human["conflict"]:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_HUMAN_REVIEW,
                STAGE_STATUS_BLOCKED,
                REASON_HUMAN_DECISION_BLOCKS,
                output_reference=make_reference(
                    "HUMAN_DECISION",
                    present=True,
                    rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
                    status="DECIDED",
                    item_count=human["decided_count"],
                ),
                metadata={
                    "decided_count": human["decided_count"],
                    "pending_count": human["pending_count"],
                    "decision_present": True,
                    "decision_conflict": True,
                    "review_present": True,
                },
                upstream_rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
            )
        )
    elif human["human_status"] == HUMAN_STATUS_BLOCKED:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_HUMAN_REVIEW,
                STAGE_STATUS_BLOCKED,
                REASON_HUMAN_DECISION_BLOCKS,
                output_reference=make_reference(
                    "HUMAN_DECISION",
                    present=True,
                    rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
                    status="DECIDED",
                    item_count=human["decided_count"],
                ),
                metadata={
                    "decided_count": human["decided_count"],
                    "pending_count": human["pending_count"],
                    "decision_present": True,
                    "decision_blocks": True,
                    "decision_type": human["blocking_type"],
                    "review_present": True,
                },
                upstream_rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
            )
        )
    elif human["decided_count"]:
        review_required = (
            human["human_status"] == HUMAN_STATUS_REVIEW_REQUIRED
        )
        decision_type = (
            human["review_type"]
            if review_required
            else DECISION_APPROVE_RESEARCH
        )
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_HUMAN_REVIEW,
                STAGE_STATUS_COMPLETED,
                REASON_HUMAN_ESCALATION_REQUIRED
                if review_required
                else REASON_HUMAN_DECIDED,
                output_reference=make_reference(
                    "HUMAN_DECISION",
                    present=True,
                    rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
                    status="DECIDED",
                    item_count=human["decided_count"],
                ),
                metadata={
                    "decided_count": human["decided_count"],
                    "pending_count": human["pending_count"],
                    "decision_present": True,
                    "review_required": review_required,
                    "decision_type": decision_type,
                    "review_present": True,
                },
                upstream_rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
            )
        )
    elif human["pending_count"]:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_HUMAN_REVIEW,
                STAGE_STATUS_READY,
                REASON_HUMAN_REVIEW_PENDING,
                output_reference=make_reference(
                    "HUMAN_DECISION",
                    present=True,
                    rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
                    status="PENDING_HUMAN_REVIEW",
                    item_count=human["pending_count"],
                ),
                metadata={
                    "pending_count": human["pending_count"],
                    "review_present": True,
                },
                upstream_rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_HUMAN_REVIEW,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # LEARNING -----------------------------------------------------------
    learning_facts = learning_summary(learning)
    if not options.get("enable_learning", True):
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_LEARNING,
                STAGE_STATUS_SKIPPED,
                REASON_SKIPPED_BY_OPTION,
            )
        )
    elif learning_facts.get("error"):
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_LEARNING,
                STAGE_STATUS_INVALID,
                REASON_UPSTREAM_RESULT_INVALID,
            )
        )
    elif learning_facts["blocking_count"]:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_LEARNING,
                STAGE_STATUS_BLOCKED,
                REASON_LEARNING_REVIEW_REQUIRED,
                output_reference=make_reference(
                    "LEARNING",
                    present=True,
                    rule_version=EXPECTED_LEARNING_RULE_VERSION,
                    status="COMPLETED",
                    item_count=learning_facts["recommendation_count"],
                ),
                metadata={
                    "pattern_count": learning_facts["pattern_count"],
                    "recommendation_count": learning_facts[
                        "recommendation_count"
                    ],
                    "blocking_recommendation_count": learning_facts[
                        "blocking_count"
                    ],
                },
                upstream_rule_version=EXPECTED_LEARNING_RULE_VERSION,
            )
        )
    elif learning_facts["present"]:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_LEARNING,
                STAGE_STATUS_COMPLETED,
                REASON_LEARNING_PRESENT,
                output_reference=make_reference(
                    "LEARNING",
                    present=True,
                    rule_version=EXPECTED_LEARNING_RULE_VERSION,
                    status="COMPLETED",
                    item_count=learning_facts["recommendation_count"],
                ),
                metadata={
                    "pattern_count": learning_facts["pattern_count"],
                    "recommendation_count": learning_facts[
                        "recommendation_count"
                    ],
                    "blocking_recommendation_count": 0,
                },
                upstream_rule_version=EXPECTED_LEARNING_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_LEARNING,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    # EXECUTION_CONTROL --------------------------------------------------
    execution_facts = execution_control_summary(execution_control)
    if not options.get("enable_execution_review", True):
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EXECUTION_CONTROL,
                STAGE_STATUS_SKIPPED,
                REASON_SKIPPED_BY_OPTION,
            )
        )
    elif execution_facts.get("error"):
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EXECUTION_CONTROL,
                STAGE_STATUS_INVALID,
                REASON_UPSTREAM_RESULT_INVALID,
            )
        )
    elif execution_facts["present"] and (
        execution_facts["unsafe_claim"] or execution_facts["contradiction"]
    ):
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EXECUTION_CONTROL,
                STAGE_STATUS_INVALID,
                REASON_UPSTREAM_RESULT_INVALID,
                metadata={
                    "unsafe_claim": execution_facts["unsafe_claim"],
                    "contradiction": execution_facts["contradiction"],
                },
                upstream_rule_version=EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
            )
        )
    elif execution_facts["blocked"]:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EXECUTION_CONTROL,
                STAGE_STATUS_BLOCKED,
                REASON_EXECUTION_BLOCKED,
                output_reference=make_reference(
                    "EXECUTION_CONTROL",
                    present=True,
                    reference_id="",
                    rule_version=EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
                    status=execution_facts["control_outcome"],
                    item_count=0,
                ),
                metadata={
                    "control_outcome": execution_facts["control_outcome"],
                    "authorization_status": execution_facts[
                        "authorization_status"
                    ],
                    "execution_status": execution_facts["execution_status"],
                    "safety_result": execution_facts["safety_result"],
                },
                upstream_rule_version=EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
            )
        )
    elif execution_facts["authorized"]:
        reason = (
            REASON_EXECUTION_READY
            if execution_facts["ready"]
            else REASON_EXECUTION_ALLOWED
        )
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EXECUTION_CONTROL,
                STAGE_STATUS_COMPLETED,
                reason,
                output_reference=make_reference(
                    "EXECUTION_CONTROL",
                    present=True,
                    rule_version=EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
                    status=execution_facts["execution_status"],
                    item_count=0,
                ),
                metadata={
                    "control_outcome": execution_facts["control_outcome"],
                    "authorization_status": execution_facts[
                        "authorization_status"
                    ],
                    "execution_status": execution_facts["execution_status"],
                    "safety_result": execution_facts["safety_result"],
                    "execution_ready": execution_facts["ready"],
                },
                upstream_rule_version=EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
            )
        )
    else:
        stages.append(
            make_stage(
                workflow_id_value,
                STAGE_EXECUTION_CONTROL,
                STAGE_STATUS_NOT_STARTED,
                REASON_NOT_PROVIDED,
            )
        )

    return stages


# ---------------------------------------------------------------------------
# Result assembly
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _governance_reference(value: object) -> dict:
    """Project either an R37 governance export or a bounded reference."""

    if isinstance(value, dict) and "reference_state" in value:
        return sanitize_finding_governance(value)
    return build_finding_governance_reference(value)


def _current_stage(stages: object, state: str) -> str:
    if state == STATE_INVALID:
        for stage in stages or ():
            if stage.get("stage_status") == STAGE_STATUS_INVALID:
                return _text(stage.get("stage_type"))
        return ""
    if state == STATE_BLOCKED:
        for stage in stages or ():
            if stage.get("stage_status") == STAGE_STATUS_BLOCKED:
                return _text(stage.get("stage_type"))
    if state == STATE_AWAITING_HUMAN_DECISION:
        return STAGE_HUMAN_REVIEW
    for stage in stages or ():
        if stage.get("stage_status") == STAGE_STATUS_READY:
            return _text(stage.get("stage_type"))
    last = ""
    for stage in stages or ():
        if stage.get("stage_status") == STAGE_STATUS_COMPLETED:
            last = _text(stage.get("stage_type"))
    return last


def _pending_stages(stages: object, state: str) -> list[str]:
    if state in (STATE_INVALID, STATE_BLOCKED):
        return []
    current = _current_stage(stages, state)
    started = False
    pending: list[str] = []
    for stage in stages or ():
        stage_type = _text(stage.get("stage_type"))
        if not started:
            if stage_type == current:
                started = True
            continue
        if stage.get("stage_status") in (
            STAGE_STATUS_NOT_STARTED,
            STAGE_STATUS_READY,
        ):
            pending.append(stage_type)
    return pending


def _build_next_action(
    workflow_id_value: str,
    resolution: dict,
    state: str,
) -> dict:
    action_code = resolution["action_code"]
    reason = resolution["action_reason"]
    return workflow_next_action_plan_projection(
        WorkflowNextActionPlan(
            rule_version="r59-3",
            action_id=next_action_id(
                workflow_id_value, action_code, reason
            ),
            action_code=action_code,
            stage_type=ACTION_STAGE.get(action_code, ""),
            reason=reason,
            execution_blocked=bool(resolution["execution_blocked"]),
            human_authority_required=True,
            advisory=True,
            auto_execute=False,
            provenance={
                "workflow_id": workflow_id_value,
                "workflow_state": state,
            },
            limitations=list(WORKFLOW_NEXT_ACTION_LIMITATIONS),
        )
    )


def _result_payload(
    workflow_id_value: str,
    stages: list[dict],
    errors: list[dict],
    safety_reasons: list[str],
    references: dict,
    *,
    provenance: object,
    governance: object,
) -> dict:
    resolution = resolve_workflow_state(stages, errors, safety_reasons)
    state = resolution["state"]
    stages = mark_recommended_stage_ready(
        stages, workflow_id_value, resolution["action_code"]
    )
    next_action = _build_next_action(
        workflow_id_value, resolution, state
    )
    current_stage = _current_stage(stages, state)
    blocked_stages = [
        _text(stage.get("stage_type"))
        for stage in stages
        if stage.get("stage_status") == STAGE_STATUS_BLOCKED
    ]
    completed_stages = [
        _text(stage.get("stage_type"))
        for stage in stages
        if stage.get("stage_status") == STAGE_STATUS_COMPLETED
    ]
    pending_stages = _pending_stages(stages, state)
    summary = build_summary(
        stages,
        errors,
        state,
        resolution["safety_status"],
        resolution["action_code"],
    )
    result_id = workflow_result_id(
        workflow_id_value,
        state,
        [stage.get("stage_id") for stage in stages],
        resolution["action_code"],
        resolution["action_reason"],
    )
    provenance_value = sanitize_workflow_result_provenance(
        {
            "workflow_id": workflow_id_value,
            "request_rule_version": SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
            "stage_ids": [stage.get("stage_id") for stage in stages],
            "orchestration_id": (provenance or {}).get("orchestration_id", ""),
            "finding_rule_version": (provenance or {}).get(
                "finding_rule_version", ""
            ),
            "correlation_rule_version": (provenance or {}).get(
                "correlation_rule_version", ""
            ),
            "priority_rule_version": (provenance or {}).get(
                "priority_rule_version", ""
            ),
            "decision_rule_version": (provenance or {}).get(
                "decision_rule_version", ""
            ),
            "learning_rule_version": (provenance or {}).get(
                "learning_rule_version", ""
            ),
            "execution_control_rule_version": (provenance or {}).get(
                "execution_control_rule_version", ""
            ),
            "source_stages": [
                stage.get("stage_type")
                for stage in stages
                if stage.get("stage_status") == STAGE_STATUS_COMPLETED
            ],
        }
    )
    governance_value = sanitize_finding_governance(governance)
    learning_present = bool(
        references.get("learning_reference", {}).get("present")
    )
    execution_present = bool(
        references.get("execution_control_reference", {}).get("present")
    )
    limitations = workflow_limitations(
        blocked=state in (STATE_BLOCKED, STATE_INVALID)
        or resolution["safety_status"]
        in (
            SAFETY_STATUS_SAFETY_BLOCKED,
            SAFETY_STATUS_EXECUTION_BLOCKED,
            SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
        ),
        learning_present=learning_present,
        execution_present=execution_present,
    )
    return {
        "rule_version": "r59-4",
        "result_id": result_id,
        "workflow_id": workflow_id_value,
        "workflow_state": state,
        "current_stage": current_stage,
        "completed_stages": completed_stages,
        "pending_stages": pending_stages,
        "blocked_stages": blocked_stages,
        "stages": stages,
        "next_action": next_action,
        "next_action_reason": resolution["action_reason"],
        "specialist_results_reference": references.get(
            "specialist_results_reference", {}
        ),
        "evaluation_reference": references.get("evaluation_reference", {}),
        "collaboration_reference": references.get(
            "collaboration_reference", {}
        ),
        "feedback_reference": references.get("feedback_reference", {}),
        "finding_reference": references.get("finding_reference", {}),
        "correlation_reference": references.get("correlation_reference", {}),
        "priority_reference": references.get("priority_reference", {}),
        "human_decision_reference": references.get(
            "human_decision_reference", {}
        ),
        "learning_reference": references.get("learning_reference", {}),
        "execution_control_reference": references.get(
            "execution_control_reference", {}
        ),
        "safety_status": resolution["safety_status"],
        "summary": summary,
        "errors": errors,
        "governance": governance_value,
        "provenance": provenance_value,
        "limitations": limitations,
        "advisory": True,
        "human_authority_preserved": True,
        "execution_performed": False,
        "external_executor_present": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "research_only": True,
        "deterministic": True,
    }


def _finalize(payload: dict) -> dict:
    try:
        return security_research_workflow_result_plan_projection(
            SecurityResearchWorkflowResultPlan(**payload)
        )
    except (TypeError, ValueError):
        projected = sanitize_security_research_workflow_result(payload)
        projected["workflow_state"] = "INVALID"
        return projected


def _invalid_result(
    errors: list[dict],
    workflow_id_value: str = "",
    *,
    provenance: object = None,
    governance: object = None,
) -> dict:
    if not workflow_id_value:
        workflow_id_value = workflow_id({"empty": True})
    stages = [
        make_stage(
            workflow_id_value,
            stage_type,
            STAGE_STATUS_NOT_STARTED,
            REASON_NOT_PROVIDED,
        )
        for stage_type in WORKFLOW_STAGE_ORDER
    ]
    references = {
        key: sanitize_workflow_reference(None)
        for key in (
            "specialist_results_reference",
            "evaluation_reference",
            "collaboration_reference",
            "feedback_reference",
            "finding_reference",
            "correlation_reference",
            "priority_reference",
            "human_decision_reference",
            "learning_reference",
            "execution_control_reference",
        )
    }
    payload = _result_payload(
        workflow_id_value,
        stages,
        errors,
        [],
        references,
        provenance=provenance,
        governance=governance,
    )
    payload["workflow_state"] = "INVALID"
    return _finalize(payload)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_security_research_workflow(
    workflow_request: object = None,
    *,
    workflow_input: object = _MISSING,
    research_context: object = _MISSING,
    specialist_results: object = _MISSING,
    orchestration_result: object = _MISSING,
    evaluation_results: object = _MISSING,
    collaboration_result: object = _MISSING,
    feedback_result: object = _MISSING,
    finding_intelligence: object = _MISSING,
    correlation_result: object = _MISSING,
    prioritization_result: object = _MISSING,
    human_review_result: object = _MISSING,
    learning_result: object = _MISSING,
    execution_control_result: object = _MISSING,
    execution_request: object = _MISSING,
    authorization_context: object = _MISSING,
    execution_authorization: object = _MISSING,
    workflow_options: object = _MISSING,
    provenance: object = _MISSING,
    governance: object = _MISSING,
) -> dict:
    """Build the deterministic end-to-end workflow state (read-only).

    Every artifact is optional: the workflow honestly represents partial
    state and recommends the next advisory step. R58 is reached only through
    its public API when an execution request is supplied without a
    pre-computed control result.
    """

    errors: list[dict] = []
    base, malformed = _merge_inputs(
        workflow_request,
        {
            "workflow_input": workflow_input,
            "research_context": research_context,
            "specialist_results": specialist_results,
            "orchestration_result": orchestration_result,
            "evaluation_results": evaluation_results,
            "collaboration_result": collaboration_result,
            "feedback_result": feedback_result,
            "finding_intelligence": finding_intelligence,
            "correlation_result": correlation_result,
            "prioritization_result": prioritization_result,
            "human_review_result": human_review_result,
            "learning_result": learning_result,
            "execution_control_result": execution_control_result,
            "execution_request": execution_request,
            "authorization_context": authorization_context,
            "execution_authorization": execution_authorization,
            "workflow_options": workflow_options,
            "provenance": provenance,
            "governance": governance,
        },
    )
    if malformed:
        errors.append(
            workflow_error(
                ERROR_MALFORMED_INPUT,
                "",
                "workflow_request must be a mapping",
            )
        )
        return _invalid_result(errors)

    raw_input = _field(base, "workflow_input", _MISSING)
    raw_research = _field(base, "research_context", _MISSING)
    if raw_input is not _MISSING and not isinstance(raw_input, dict):
        errors.append(
            workflow_error(
                ERROR_INVALID_INPUT,
                "",
                "workflow_input must be a mapping",
            )
        )
    if raw_research is not _MISSING and not isinstance(raw_research, dict):
        errors.append(
            workflow_error(
                ERROR_INVALID_INPUT,
                "",
                "research_context must be a mapping",
            )
        )
    research_input = bool(
        (raw_input if isinstance(raw_input, dict) else None)
        or (raw_research if isinstance(raw_research, dict) else None)
    )

    specialists = _validate_specialist_results(
        _field(base, "specialist_results", _MISSING), errors
    )
    orchestration = _validate_container(
        _field(base, "orchestration_result", _MISSING),
        "ORCHESTRATION_RESULT",
        EXPECTED_ORCHESTRATION_RULE_VERSION,
        errors,
    )
    evaluations = _validate_list(
        _field(base, "evaluation_results", _MISSING),
        "EVALUATION_RESULTS",
        EXPECTED_EVALUATION_RULE_VERSION,
        errors,
    )
    collaboration = _validate_container(
        _field(base, "collaboration_result", _MISSING),
        "COLLABORATION_RESULT",
        EXPECTED_COLLABORATION_RULE_VERSION,
        errors,
    )
    feedback = _validate_container(
        _field(base, "feedback_result", _MISSING),
        "FEEDBACK_RESULT",
        EXPECTED_FEEDBACK_RULE_VERSION,
        errors,
    )
    findings = _validate_container(
        _field(base, "finding_intelligence", _MISSING),
        "FINDING_INTELLIGENCE",
        EXPECTED_FINDING_RULE_VERSION,
        errors,
    )
    correlation = _validate_container(
        _field(base, "correlation_result", _MISSING),
        "CORRELATION_RESULT",
        EXPECTED_CORRELATION_RULE_VERSION,
        errors,
    )
    prioritization = _validate_container(
        _field(base, "prioritization_result", _MISSING),
        "PRIORITIZATION_RESULT",
        EXPECTED_PRIORITIZATION_RULE_VERSION,
        errors,
    )
    human_review = _validate_container(
        _field(base, "human_review_result", _MISSING),
        "HUMAN_REVIEW_RESULT",
        EXPECTED_HUMAN_REVIEW_RULE_VERSION,
        errors,
    )
    learning = _validate_container(
        _field(base, "learning_result", _MISSING),
        "LEARNING_RESULT",
        EXPECTED_LEARNING_RULE_VERSION,
        errors,
    )
    supplied_control = _validate_container(
        _field(base, "execution_control_result", _MISSING),
        "EXECUTION_CONTROL_RESULT",
        EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
        errors,
    )
    execution_request_value = _validate_container(
        _field(base, "execution_request", _MISSING),
        "EXECUTION_REQUEST",
        EXPECTED_EXECUTION_REQUEST_RULE_VERSION,
        errors,
    )

    options_value = _field(base, "workflow_options", _MISSING)
    options = sanitize_workflow_options(
        options_value if isinstance(options_value, dict) else {}
    )

    # ------------------------------------------------------------------
    # Ambiguity: orchestration bundle versus standalone layers
    # ------------------------------------------------------------------
    if orchestration is not None:
        for label, value in (
            ("specialist_results", specialists),
            ("evaluation_results", evaluations),
            ("collaboration_result", collaboration),
            ("feedback_result", feedback),
        ):
            if value:
                errors.append(
                    workflow_error(
                        ERROR_WORKFLOW_CONFLICT,
                        "",
                        (
                            "supply either orchestration_result or the "
                            f"standalone {label}, not both"
                        ),
                    )
                )
        specialists = orchestration.get("specialist_results") or []
        evaluations = orchestration.get("evaluation_results") or []
        collaboration = orchestration.get("collaboration_result")
        feedback = orchestration.get("feedback_result")

    # ------------------------------------------------------------------
    # Required upstream stages (fail closed; partial entry points allowed)
    # ------------------------------------------------------------------
    if evaluations and not specialists:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_EVALUATION,
                "evaluation results require specialist results",
            )
        )
    if collaboration and not evaluations:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_COLLABORATION,
                "collaboration requires evaluation results",
            )
        )
    if feedback and not evaluations:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_FEEDBACK,
                "feedback requires evaluation results",
            )
        )
    if correlation and not findings:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_CORRELATION,
                "correlation requires finding intelligence",
            )
        )
    if prioritization and not findings:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_PRIORITIZATION,
                "prioritization requires finding intelligence",
            )
        )
    if human_review and not prioritization:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_HUMAN_REVIEW,
                "human review requires prioritization",
            )
        )
    if learning and not human_review:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_LEARNING,
                "learning requires the human decision boundary",
            )
        )
    if supplied_control and not human_review:
        errors.append(
            workflow_error(
                ERROR_MISSING_REQUIRED_STAGE,
                STAGE_EXECUTION_CONTROL,
                "execution control requires the human decision boundary",
            )
        )

    # ------------------------------------------------------------------
    # Safety gate (R58 scanner reused; never repaired)
    # ------------------------------------------------------------------
    safety_reasons = collect_safety_reasons(
        base.get("workflow_input"),
        base.get("research_context"),
        specialists,
        orchestration,
        evaluations,
        collaboration,
        feedback,
        findings,
        correlation,
        prioritization,
        human_review,
        learning,
        supplied_control,
        execution_request_value,
        base.get("authorization_context"),
    )
    if safety_reasons:
        errors.append(
            workflow_error(
                ERROR_SAFETY_BLOCKED,
                "",
                "a supplied input carries a forbidden execution claim",
            )
        )

    # ------------------------------------------------------------------
    # R58 public API (only when requested; never autonomous execution)
    # ------------------------------------------------------------------
    execution_control = supplied_control
    control_derived = False
    if execution_control is None and execution_request_value is not None:
        try:
            execution_control = evaluate_execution_control(
                execution_request_value,
                human_review_result=human_review,
                authorization_context=base.get("authorization_context"),
                execution_authorization=base.get("execution_authorization"),
                learning_result=learning,
                prioritization_result=prioritization,
                correlation_result=correlation,
                finding_intelligence=findings,
                provenance=base.get("provenance"),
                governance=base.get("governance"),
            )
            control_derived = True
        except Exception:
            execution_control = None
            errors.append(
                workflow_error(
                    ERROR_UPSTREAM_RESULT_INVALID,
                    STAGE_EXECUTION_CONTROL,
                    "execution control evaluation failed",
                )
            )
    if control_derived and execution_control and not human_review:
        errors.append(
            workflow_error(
                ERROR_HUMAN_DECISION_REQUIRED,
                STAGE_HUMAN_REVIEW,
                "execution review requires an explicit human decision",
            )
        )

    # ------------------------------------------------------------------
    # Deterministic workflow identity
    # ------------------------------------------------------------------
    specialist_count = len(specialists or [])
    descriptors = {
        "research_input": research_input,
        "options": options,
        "specialist_count": specialist_count,
        "orchestration_id": _text((orchestration or {}).get("orchestration_id")),
        "evaluation_count": len(evaluations or []),
        "collaboration_id": _text(
            (collaboration or {}).get("collaboration_id")
        ),
        "feedback_recommendation_count": len(
            (feedback or {}).get("recommendations") or ()
        ),
        "intelligence_id": _text((findings or {}).get("intelligence_id")),
        "correlation_id": _text((correlation or {}).get("correlation_id")),
        "prioritization_id": _text(
            (prioritization or {}).get("prioritization_id")
        ),
        "review_result_id": _text(
            (human_review or {}).get("review_result_id")
        ),
        "learning_id": _text((learning or {}).get("learning_id")),
        "control_id": _text((execution_control or {}).get("control_id")),
    }
    workflow_id_value = workflow_id(descriptors)

    # ------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------
    references = {
        "specialist_results_reference": make_reference(
            "SPECIALIST_RESULTS",
            present=bool(specialists),
            reference_id=_text(
                (specialists[0] or {}).get("agent_id") if specialists else ""
            ),
            rule_version=_text(
                (specialists[0] or {}).get("rule_version")
                if specialists
                else ""
            ),
            status="COMPLETED" if specialists else "",
            item_count=specialist_count,
        ),
        "evaluation_reference": make_reference(
            "EVALUATION",
            present=bool(evaluations),
            reference_id=_text(
                (evaluations[0] or {}).get("evaluation_id")
                if evaluations
                else ""
            ),
            rule_version=EXPECTED_EVALUATION_RULE_VERSION
            if evaluations
            else "",
            status="COMPLETED" if evaluations else "",
            item_count=len(evaluations or []),
        ),
        "collaboration_reference": make_reference(
            "COLLABORATION",
            present=bool(collaboration),
            reference_id=_text(
                (collaboration or {}).get("collaboration_id")
            ),
            rule_version=EXPECTED_COLLABORATION_RULE_VERSION
            if collaboration
            else "",
            status="COMPLETED" if collaboration else "",
            item_count=len(
                (collaboration or {}).get("participating_agents") or ()
            ),
        ),
        "feedback_reference": make_reference(
            "FEEDBACK",
            present=bool(feedback),
            rule_version=EXPECTED_FEEDBACK_RULE_VERSION if feedback else "",
            status="COMPLETED" if feedback else "",
            item_count=len((feedback or {}).get("classifications") or ()),
        ),
        "finding_reference": make_reference(
            "FINDING",
            present=bool(findings),
            reference_id=_text((findings or {}).get("intelligence_id")),
            rule_version=EXPECTED_FINDING_RULE_VERSION if findings else "",
            status=_upper((findings or {}).get("status")),
            item_count=len((findings or {}).get("findings") or ()),
        ),
        "correlation_reference": make_reference(
            "CORRELATION",
            present=bool(correlation),
            reference_id=_text((correlation or {}).get("correlation_id")),
            rule_version=EXPECTED_CORRELATION_RULE_VERSION
            if correlation
            else "",
            status=_upper((correlation or {}).get("status")),
            item_count=len(
                (correlation or {}).get("finding_references") or ()
            ),
        ),
        "priority_reference": make_reference(
            "PRIORITIZATION",
            present=bool(prioritization),
            reference_id=_text(
                (prioritization or {}).get("prioritization_id")
            ),
            rule_version=EXPECTED_PRIORITIZATION_RULE_VERSION
            if prioritization
            else "",
            status=_upper((prioritization or {}).get("status")),
            item_count=len(
                (prioritization or {}).get("ranked_findings") or ()
            )
            + len((prioritization or {}).get("deferred_findings") or ()),
        ),
        "human_decision_reference": make_reference(
            "HUMAN_DECISION",
            present=bool(human_review),
            reference_id=_text((human_review or {}).get("review_result_id")),
            rule_version=EXPECTED_HUMAN_REVIEW_RULE_VERSION
            if human_review
            else "",
            status=_upper((human_review or {}).get("status")),
            item_count=len((human_review or {}).get("reviews") or ()),
        ),
        "learning_reference": make_reference(
            "LEARNING",
            present=bool(learning),
            rule_version=EXPECTED_LEARNING_RULE_VERSION if learning else "",
            status=_upper((learning or {}).get("status")),
            item_count=len(
                (learning or {}).get("calibration_recommendations") or ()
            ),
        ),
        "execution_control_reference": make_reference(
            "EXECUTION_CONTROL",
            present=bool(execution_control),
            rule_version=EXPECTED_EXECUTION_CONTROL_RULE_VERSION
            if execution_control
            else "",
            status=_upper((execution_control or {}).get("control_outcome")),
            item_count=0,
        ),
    }

    orchestration_id_value = _text(
        (orchestration or {}).get("orchestration_id")
    )
    if not orchestration_id_value:
        orchestration_id_value = _text(
            ((findings or {}).get("provenance") or {}).get(
                "orchestration_id"
            )
        ) or _text(
            ((human_review or {}).get("provenance") or {}).get(
                "orchestration_id"
            )
        )
    provenance_value = {
        "orchestration_id": orchestration_id_value,
        "finding_rule_version": EXPECTED_FINDING_RULE_VERSION
        if findings
        else "",
        "correlation_rule_version": EXPECTED_CORRELATION_RULE_VERSION
        if correlation
        else "",
        "priority_rule_version": EXPECTED_PRIORITIZATION_RULE_VERSION
        if prioritization
        else "",
        "decision_rule_version": EXPECTED_HUMAN_REVIEW_RULE_VERSION
        if human_review
        else "",
        "learning_rule_version": EXPECTED_LEARNING_RULE_VERSION
        if learning
        else "",
        "execution_control_rule_version": (
            EXPECTED_EXECUTION_CONTROL_RULE_VERSION
            if execution_control
            else ""
        ),
    }
    governance_value = base.get("governance")
    if not isinstance(governance_value, dict) or not governance_value:
        governance_value = (
            (execution_control or {}).get("governance")
            or (human_review or {}).get("governance")
            or (prioritization or {}).get("governance")
            or (findings or {}).get("governance")
        )
    governance_value = _governance_reference(governance_value)

    stages = _build_stages(
        workflow_id_value,
        research_input=research_input,
        specialist_results=specialists,
        evaluations=evaluations,
        collaboration=collaboration,
        feedback=feedback,
        findings=findings,
        correlation=correlation,
        prioritization=prioritization,
        human_review=human_review,
        learning=learning,
        execution_control=execution_control,
        options=options,
        specialist_count=specialist_count,
    )

    # ------------------------------------------------------------------
    # Fatal stage conditions and structured blocking errors
    # ------------------------------------------------------------------
    for stage in stages:
        if stage.get("stage_status") == STAGE_STATUS_INVALID:
            errors.append(
                workflow_error(
                    ERROR_UPSTREAM_RESULT_INVALID,
                    _text(stage.get("stage_type")),
                    "an upstream artifact could not be trusted",
                )
            )
    human_stage = stage_by_type(stages, STAGE_HUMAN_REVIEW)
    if (
        human_stage.get("deterministic_metadata") or {}
    ).get("decision_conflict") is True:
        errors.append(
            workflow_error(
                ERROR_WORKFLOW_CONFLICT,
                STAGE_HUMAN_REVIEW,
                "human decisions conflict and cannot be silently resolved",
            )
        )
    if learning_summary(learning)["blocking_count"]:
        errors.append(
            workflow_error(
                ERROR_LEARNING_REVIEW_REQUIRED,
                STAGE_LEARNING,
                "learning requires review before the workflow can proceed",
            )
        )
    if execution_control_summary(execution_control)["blocked"]:
        errors.append(
            workflow_error(
                ERROR_EXECUTION_CONTROL_BLOCKED,
                STAGE_EXECUTION_CONTROL,
                "the controlled execution gate did not allow the request",
            )
        )

    payload = _result_payload(
        workflow_id_value,
        stages,
        errors,
        safety_reasons,
        references,
        provenance=provenance_value,
        governance=governance_value,
    )
    return _finalize(payload)


def advance_security_research_workflow(
    workflow_result: object = None,
    *,
    stage_type: object = None,
    stage_status: object = "COMPLETED",
    stage_facts: object = None,
    stage_reference: object = None,
    reason: object = None,
    provenance: object = None,
    governance: object = None,
) -> dict:
    """Advance one workflow stage deterministically (no execution).

    Validates the transition against the fixed stage order and recomputes
    the workflow state, summary and next action. Invalid or unsupported
    transitions fail closed with structured errors and leave the state
    unchanged.
    """

    if not isinstance(workflow_result, dict) or (
        _text(workflow_result.get("rule_version")) != "r59-4"
    ):
        return _invalid_result(
            [
                workflow_error(
                    ERROR_MALFORMED_INPUT,
                    "",
                    "workflow_result must be a valid R59 result",
                )
            ]
        )

    sanitized = sanitize_security_research_workflow_result(workflow_result)
    workflow_id_value = _text(sanitized.get("workflow_id")) or workflow_id(
        {"advance": True}
    )
    stage_type_value = _upper(stage_type)
    status_value = _upper(stage_status) if stage_status else "COMPLETED"
    errors = list(sanitized.get("errors") or ())
    stages = list(sanitized.get("stages") or ())

    if (
        sanitized.get("workflow_state")
        in (STATE_INVALID, STATE_COMPLETED, STATE_BLOCKED)
        or status_value not in ("COMPLETED", "BLOCKED", "INVALID")
    ):
        errors.append(
            workflow_error(
                ERROR_UNSUPPORTED_TRANSITION,
                stage_type_value,
                "the workflow cannot advance from its current state",
            )
        )
        return _finalize({**sanitized, "errors": errors})

    transition_category, transition_message = transition_error(
        stages, stage_type_value
    )
    if transition_category:
        errors.append(
            workflow_error(
                transition_category, stage_type_value, transition_message
            )
        )
        return _finalize({**sanitized, "errors": errors})

    updated_stages: list[dict] = []
    found_target = False
    for stage in stages:
        if _text(stage.get("stage_type")) != stage_type_value:
            updated_stages.append(stage)
            continue
        found_target = True
        metadata = dict(
            sanitize_workflow_stage(stage).get("deterministic_metadata") or {}
        )
        if isinstance(stage_facts, dict):
            projected_facts = sanitize_workflow_stage(
                {
                    "stage_id": stage.get("stage_id"),
                    "stage_type": stage_type_value,
                    "stage_status": status_value,
                    "deterministic_metadata": stage_facts,
                    "reason": reason
                    or REASON_STAGE_COMPLETED_EXTERNALLY,
                }
            ).get("deterministic_metadata") or {}
            metadata.update(projected_facts)
        output_reference = stage.get("output_reference") or {}
        if stage_reference is not None:
            reference = sanitize_workflow_reference(stage_reference)
            if reference.get("reference_kind") == "":
                reference["reference_kind"] = _stage_reference_kind(
                    stage_type_value
                )
            reference["present"] = True
            output_reference = reference
        updated_stages.append(
            make_stage(
                workflow_id_value,
                stage_type_value,
                status_value,
                _upper(reason) or REASON_STAGE_COMPLETED_EXTERNALLY,
                input_reference=stage.get("input_reference") or {},
                output_reference=output_reference,
                metadata=metadata,
                upstream_rule_version=(
                    stage.get("provenance") or {}
                ).get("upstream_rule_version", ""),
                upstream_reference_id=(
                    stage.get("provenance") or {}
                ).get("upstream_reference_id", ""),
            )
        )
    if not found_target:
        errors.append(
            workflow_error(
                ERROR_MALFORMED_INPUT,
                stage_type_value,
                "stage is not present in the workflow",
            )
        )
        return _finalize({**sanitized, "errors": errors})

    references = {
        key: sanitized.get(key) or {}
        for key in (
            "specialist_results_reference",
            "evaluation_reference",
            "collaboration_reference",
            "feedback_reference",
            "finding_reference",
            "correlation_reference",
            "priority_reference",
            "human_decision_reference",
            "learning_reference",
            "execution_control_reference",
        )
    }
    reference_key = _stage_reference_key(stage_type_value)
    if stage_reference is not None and reference_key:
        references[reference_key] = sanitize_workflow_reference(
            stage_reference
        )

    payload = _result_payload(
        workflow_id_value,
        updated_stages,
        errors,
        [],
        references,
        provenance=sanitized.get("provenance"),
        governance=governance or sanitized.get("governance"),
    )
    return _finalize(payload)


def _stage_reference_key(stage_type: str) -> str:
    return {
        STAGE_SPECIALIST_RESEARCH: "specialist_results_reference",
        STAGE_EVALUATION: "evaluation_reference",
        STAGE_COLLABORATION: "collaboration_reference",
        STAGE_FEEDBACK: "feedback_reference",
        STAGE_FINDING: "finding_reference",
        STAGE_CORRELATION: "correlation_reference",
        STAGE_PRIORITIZATION: "priority_reference",
        STAGE_HUMAN_REVIEW: "human_decision_reference",
        STAGE_LEARNING: "learning_reference",
        STAGE_EXECUTION_CONTROL: "execution_control_reference",
    }.get(stage_type, "")


def _stage_reference_kind(stage_type: str) -> str:
    return {
        STAGE_SPECIALIST_RESEARCH: "SPECIALIST_RESULTS",
        STAGE_EVALUATION: "EVALUATION",
        STAGE_COLLABORATION: "COLLABORATION",
        STAGE_FEEDBACK: "FEEDBACK",
        STAGE_FINDING: "FINDING",
        STAGE_CORRELATION: "CORRELATION",
        STAGE_PRIORITIZATION: "PRIORITIZATION",
        STAGE_HUMAN_REVIEW: "HUMAN_DECISION",
        STAGE_LEARNING: "LEARNING",
        STAGE_EXECUTION_CONTROL: "EXECUTION_CONTROL",
    }.get(stage_type, "")


def determine_next_workflow_action(
    workflow_result: object = None, **kwargs
) -> dict:
    """Return the advisory next action for a workflow result (or inputs)."""

    if isinstance(workflow_result, dict) and (
        _text(workflow_result.get("rule_version")) == "r59-4"
    ):
        action = sanitize_workflow_next_action(
            workflow_result.get("next_action")
        )
        if action.get("action_id"):
            return action
        return sanitize_workflow_next_action(None)
    if workflow_result is not None and not isinstance(workflow_result, dict):
        return sanitize_workflow_next_action(None)
    if workflow_result is not None and isinstance(workflow_result, dict):
        kwargs = {**workflow_result, **kwargs}
    result = build_security_research_workflow(**kwargs)
    return result.get("next_action") or sanitize_workflow_next_action(None)


def build_security_research_workflow_summary(
    workflow_result: object = None, **kwargs
) -> dict:
    """Return the deterministic workflow summary (result or inputs)."""

    if isinstance(workflow_result, dict) and (
        _text(workflow_result.get("rule_version")) == "r59-4"
    ):
        return sanitize_workflow_result_summary(
            workflow_result.get("summary")
        )
    if workflow_result is not None and not isinstance(workflow_result, dict):
        return sanitize_workflow_result_summary(None)
    result = build_security_research_workflow(
        workflow_result if isinstance(workflow_result, dict) else None,
        **kwargs,
    )
    return result.get("summary") or sanitize_workflow_result_summary(None)


def export_security_research_workflow(
    workflow_request: object = None, **kwargs
) -> dict:
    """Alias for :func:`build_security_research_workflow`."""

    return build_security_research_workflow(workflow_request, **kwargs)


__all__ = [
    "SECURITY_RESEARCH_WORKFLOW_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "ARTIFACT_PARAMETERS",
    "build_security_research_workflow",
    "advance_security_research_workflow",
    "determine_next_workflow_action",
    "build_security_research_workflow_summary",
    "export_security_research_workflow",
]
