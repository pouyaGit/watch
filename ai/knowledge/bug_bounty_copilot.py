"""Stage R60.6 deterministic bug bounty copilot builder (public API).

Implements the Watch Bug Bounty Copilot: a deterministic, advisory product
layer over the existing research intelligence stack:

    R31-R37 (research intelligence / memory / strategy / governance)
    R42-R44 (evaluation / collaboration / feedback)
    R53-R58 (finding / correlation / prioritization / human review /
             learning / controlled execution)
    R59 (end-to-end workflow state)
      -> R60 copilot briefing
      -> human researcher

The copilot answers:

    1. What should I investigate?
    2. Why is it interesting?
    3. What evidence already exists?
    4. What findings are related?
    5. How strong is the evidence?
    6. What should I do next?
    7. What requires human review?
    8. What should NOT be executed automatically?

Hard boundaries encoded here:

- Product layer, not a new orchestrator: R60 consumes the existing structured
  outputs and reaches R59 only through its public API to resolve the current
  workflow state. It never replaces R52/R56/R58/R59.
- Advisory only: the copilot recommends research attention. It never sends
  requests, scans, browses, exploits, confirms vulnerabilities, authorizes
  execution or modifies authorization state. ``execution_performed`` and
  ``external_executor_present`` are forced ``False`` and no ``EXECUTED``
  state exists.
- Human authority: every recommendation carries explicit human-review
  requirements; R56 remains authoritative and R58 remains the final
  execution-control gate.
- Deterministic: no LLM, no randomness, no wall-clock time; content-derived
  ids and byte-identical repeated output.
- Fail closed: malformed, mis-versioned or contradictory context produces
  structured errors and a safe advisory state; nothing is optimistically
  authorized.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.bug_bounty_copilot_rules import (
    EXPECTED_CORRELATION_RULE_VERSION,
    EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
    EXPECTED_FINDING_RULE_VERSION,
    EXPECTED_HUMAN_REVIEW_RULE_VERSION,
    EXPECTED_LEARNING_RULE_VERSION,
    EXPECTED_PRIORITIZATION_RULE_VERSION,
    EXPECTED_WORKFLOW_RULE_VERSION,
    brief_id,
    brief_confidence,
    brief_limitations,
    brief_rationale_codes,
    brief_review_reasons,
    brief_safety_status,
    collect_safety_reasons,
    copilot_error,
    copilot_id,
    copilot_status,
    copilot_summary,
    correlation_index,
    evidence_summary,
    execution_context_facts,
    has_fatal_error,
    human_context_facts,
    learning_context_facts,
    opportunity_plans,
    recommended_actions,
    result_id,
    workflow_facts,
)
from ai.knowledge.security_research_workflow import (
    build_security_research_workflow,
)
from ai.schemas.finding_result import (
    build_finding_governance_reference,
    sanitize_finding_governance,
)
from ai.schemas.bug_bounty_copilot import (
    BUG_BOUNTY_COPILOT_RULE_VERSION,
    BugBountyCopilotInputPlan,
    bug_bounty_copilot_input_plan_projection,
    sanitize_bug_bounty_copilot_input,
    sanitize_copilot_reference,
)
from ai.schemas.copilot_brief import (
    CopilotBriefPlan,
    copilot_brief_plan_projection,
    sanitize_copilot_brief,
)
from ai.schemas.copilot_opportunity import COPILOT_SAFETY_RESTRICTIONS
from ai.schemas.security_research_workflow_result import (
    SAFETY_STATUS_SAFETY_BLOCKED,
)
from ai.schemas.copilot_result import (
    STATUS_FAILED,
    STATUS_NO_CONTEXT,
    STATUS_PARTIAL,
    CopilotResultPlan,
    copilot_result_plan_projection,
    sanitize_copilot_result,
    sanitize_copilot_summary,
)

BUG_BOUNTY_COPILOT_BUILDER_RULE_VERSION = "r60-6"
RULE_VERSION = BUG_BOUNTY_COPILOT_BUILDER_RULE_VERSION

MAX_TEXT = 240
MAX_LIST = 24

_MISSING = object()

#: Artifact parameters accepted by the copilot builder.
ARTIFACT_PARAMETERS: tuple[str, ...] = (
    "workflow_result",
    "finding_intelligence",
    "correlation_result",
    "prioritization_result",
    "human_review_result",
    "learning_result",
    "execution_control_result",
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _field(base: dict, key: str, override: object) -> object:
    if override is not _MISSING and override is not None:
        return override
    return base.get(key, _MISSING)


def _merge_inputs(copilot_input: object, overrides: dict) -> tuple[dict, bool]:
    """Merge an input dict with explicit keyword overrides (fail closed)."""

    if copilot_input is None:
        base: dict = {}
        malformed = False
    elif isinstance(copilot_input, dict):
        base = dict(copilot_input)
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
    """Validate one structured container (fail closed)."""

    if value is None or value is _MISSING:
        return None
    if not isinstance(value, dict) or not value:
        errors.append(
            copilot_error(
                "MALFORMED_INPUT", label, "input must be a non-empty mapping"
            )
        )
        return None
    if (
        expected_rule_version
        and _text(value.get("rule_version")) != expected_rule_version
    ):
        errors.append(
            copilot_error(
                "RULE_VERSION_MISMATCH",
                label,
                "input rule version does not match the expected layer",
            )
        )
        return None
    return value


def _governance_reference(value: object) -> dict:
    """Project either an R37 governance export or a bounded reference."""

    if isinstance(value, dict) and "reference_state" in value:
        return sanitize_finding_governance(value)
    return build_finding_governance_reference(value)


def _reference_from_artifact(
    kind: str, value: object, rule_version: str, status: str = ""
) -> dict:
    return sanitize_copilot_reference(
        {
            "present": isinstance(value, dict) and bool(value),
            "reference_kind": kind,
            "reference_id": _text((value or {}).get("workflow_id"))
            or _text((value or {}).get("intelligence_id"))
            or _text((value or {}).get("correlation_id"))
            or _text((value or {}).get("prioritization_id"))
            or _text((value or {}).get("review_result_id"))
            or _text((value or {}).get("learning_id"))
            or _text((value or {}).get("control_id"))
            if isinstance(value, dict)
            else "",
            "rule_version": rule_version,
            "status": status,
            "item_count": 0,
        }
    )


def _finding_ids(finding_intelligence: object) -> set[str]:
    ids: set[str] = set()
    if isinstance(finding_intelligence, dict):
        for finding in finding_intelligence.get("findings") or ():
            if isinstance(finding, dict):
                finding_id = _text(finding.get("finding_id"))
                if finding_id:
                    ids.add(finding_id)
    return ids


def _prioritized_finding_ids(prioritization_result: object) -> list[str]:
    ids: list[str] = []
    if isinstance(prioritization_result, dict):
        for plan in list(
            prioritization_result.get("ranked_findings") or ()
        ) + list(prioritization_result.get("deferred_findings") or ()):
            if isinstance(plan, dict):
                finding_id = _text(plan.get("finding_id"))
                if finding_id:
                    ids.append(finding_id)
    return ids


def _build_brief_payload(
    *,
    copilot_id_value: str,
    target_reference: str,
    research_context: dict,
    workflow_facts_value: dict,
    prioritization_result: object,
    human_facts: dict,
    learning_facts: dict,
    execution_facts: dict,
    correlation_index_value: dict,
    safety_reasons: list[str],
    options: dict,
    provenance: dict,
    governance: object,
    upstream_error: bool,
) -> dict:
    safety_blocked = bool(safety_reasons) or (
        _upper(workflow_facts_value.get("safety_status"))
        == SAFETY_STATUS_SAFETY_BLOCKED
    )
    opportunities = opportunity_plans(
        prioritization_result,
        workflow_facts_value=workflow_facts_value,
        human_facts=human_facts,
        learning_facts=learning_facts,
        execution_facts=execution_facts,
        correlation_index_value=correlation_index_value,
        safety_blocked=safety_blocked,
        upstream_error=upstream_error,
        max_opportunities=int(
            options.get("max_opportunities") or 8
        ),
    )
    review_reasons = brief_review_reasons(
        opportunities,
        human_facts=human_facts,
        learning_facts=learning_facts,
        execution_facts=execution_facts,
        workflow_facts_value=workflow_facts_value,
        safety_blocked=safety_blocked,
        upstream_error=upstream_error,
    )
    human_review_required = bool(review_reasons)
    confidence, basis = brief_confidence(
        opportunities,
        conflict_present=bool(
            (correlation_index_value.get("_meta") or {}).get(
                "conflict_count"
            )
        ),
        duplicate_present=bool(
            (correlation_index_value.get("_meta") or {}).get(
                "duplicate_count"
            )
        ),
        human_pending=bool(human_facts.get("pending")),
        workflow_blocked=bool(workflow_facts_value.get("blocked")),
        safety_blocked=safety_blocked,
    )
    rationale_codes = brief_rationale_codes(
        opportunities,
        workflow_facts_value=workflow_facts_value,
        human_facts=human_facts,
        learning_facts=learning_facts,
        execution_facts=execution_facts,
        safety_blocked=safety_blocked,
    )
    actions = recommended_actions(opportunities)
    safety_status = brief_safety_status(
        safety_blocked=safety_blocked,
        workflow_facts_value=workflow_facts_value,
        human_review_required=human_review_required,
    )
    opportunity_ids = [
        _text(entry.get("opportunity_id")) for entry in opportunities
    ]
    action_keys = [
        f"{entry.get('workflow_next_action')}/{entry.get('research_action')}"
        for entry in actions
    ]
    brief_id_value = brief_id(
        copilot_id_value,
        _text(workflow_facts_value.get("workflow_id")),
        opportunity_ids,
        action_keys,
    )
    meta = correlation_index_value.get("_meta") or {}
    payload = {
        "rule_version": "r60-3",
        "brief_id": brief_id_value,
        "target_reference": target_reference,
        "research_context": research_context,
        "workflow_id": _text(workflow_facts_value.get("workflow_id")),
        "workflow_state": _text(workflow_facts_value.get("state")),
        "workflow_safety_status": _text(
            workflow_facts_value.get("safety_status")
        ),
        "workflow_next_action": _text(
            workflow_facts_value.get("next_action")
        ),
        "workflow_next_action_reason": _text(
            workflow_facts_value.get("next_action_reason")
        ),
        "opportunities": opportunities,
        "opportunity_count": len(opportunities),
        "high_priority_count": sum(
            1
            for entry in opportunities
            if entry.get("opportunity_class") == "HIGH_PRIORITY_RESEARCH"
        ),
        "evidence_summary": evidence_summary(
            prioritization_result, opportunities, correlation_index_value
        ),
        "related_finding_ids": list(
            meta.get("related_finding_ids") or ()
        )[:MAX_LIST],
        "relationship_types": list(
            meta.get("relationship_types") or ()
        )[:MAX_LIST],
        "confidence": confidence,
        "confidence_basis": basis,
        "copilot_rationale_codes": rationale_codes,
        "recommended_actions": actions,
        "human_review_required": human_review_required,
        "human_review_reasons": review_reasons,
        "safety_status": safety_status,
        "safety_restrictions": list(COPILOT_SAFETY_RESTRICTIONS),
        "provenance": provenance,
        "governance": governance if isinstance(governance, dict) else {},
        "limitations": brief_limitations(
            safety_blocked=safety_blocked,
            workflow_present=bool(workflow_facts_value.get("present")),
        ),
    }
    try:
        return copilot_brief_plan_projection(CopilotBriefPlan(**payload))
    except (TypeError, ValueError):
        return sanitize_copilot_brief(payload)


def _finalize_result(payload: dict) -> dict:
    try:
        return copilot_result_plan_projection(CopilotResultPlan(**payload))
    except (TypeError, ValueError):
        return sanitize_copilot_result(payload)


def _failure_result(
    *,
    errors: list[dict],
    target_reference: str = "",
    provenance: object = None,
    governance: object = None,
) -> dict:
    copilot_id_value = copilot_id({"empty": True})
    brief = _build_brief_payload(
        copilot_id_value=copilot_id_value,
        target_reference=target_reference,
        research_context={},
        workflow_facts_value=workflow_facts(None),
        prioritization_result=None,
        human_facts=human_context_facts(None),
        learning_facts=learning_context_facts(None),
        execution_facts=execution_context_facts(None),
        correlation_index_value=correlation_index(None),
        safety_reasons=[],
        options={"max_opportunities": 8},
        provenance=provenance if isinstance(provenance, dict) else {},
        governance=governance,
        upstream_error=True,
    )
    status = STATUS_FAILED if has_fatal_error(errors) else STATUS_PARTIAL
    payload = {
        "rule_version": "r60-4",
        "result_id": result_id(
            _text(brief.get("brief_id")), status,
            _text(brief.get("safety_status")), errors,
        ),
        "status": status,
        "brief": brief,
        "summary": copilot_summary(brief, errors),
        "errors": errors,
        "provenance": provenance if isinstance(provenance, dict) else {},
        "governance": governance if isinstance(governance, dict) else {},
        "limitations": brief.get("limitations") or [],
    }
    return _finalize_result(payload)


def _no_context_result(
    *,
    target_reference: str,
    research_context: dict,
    provenance: object,
    governance: object,
) -> dict:
    copilot_id_value = copilot_id(
        {"target_reference": target_reference, "context": research_context}
    )
    brief = _build_brief_payload(
        copilot_id_value=copilot_id_value,
        target_reference=target_reference,
        research_context=research_context,
        workflow_facts_value=workflow_facts(None),
        prioritization_result=None,
        human_facts=human_context_facts(None),
        learning_facts=learning_context_facts(None),
        execution_facts=execution_context_facts(None),
        correlation_index_value=correlation_index(None),
        safety_reasons=[],
        options={"max_opportunities": 8},
        provenance=provenance if isinstance(provenance, dict) else {},
        governance=governance,
        upstream_error=False,
    )
    payload = {
        "rule_version": "r60-4",
        "result_id": result_id(
            _text(brief.get("brief_id")),
            STATUS_NO_CONTEXT,
            _text(brief.get("safety_status")),
            [],
        ),
        "status": STATUS_NO_CONTEXT,
        "brief": brief,
        "summary": copilot_summary(brief, []),
        "errors": [],
        "provenance": provenance if isinstance(provenance, dict) else {},
        "governance": governance if isinstance(governance, dict) else {},
        "limitations": brief.get("limitations") or [],
    }
    return _finalize_result(payload)


def build_bug_bounty_copilot(
    copilot_input: object = None,
    *,
    target_reference: object = _MISSING,
    research_context: object = _MISSING,
    intelligence_context: object = _MISSING,
    workflow_result: object = _MISSING,
    finding_intelligence: object = _MISSING,
    correlation_result: object = _MISSING,
    prioritization_result: object = _MISSING,
    human_review_result: object = _MISSING,
    learning_result: object = _MISSING,
    execution_control_result: object = _MISSING,
    copilot_options: object = _MISSING,
    provenance: object = _MISSING,
    governance: object = _MISSING,
) -> dict:
    """Build the deterministic advisory bug-bounty copilot briefing.

    R59 is reached only through its public API when artifacts are supplied
    without a pre-computed workflow result. Nothing is executed, confirmed or
    authorized.
    """

    errors: list[dict] = []
    base, malformed = _merge_inputs(
        copilot_input,
        {
            "target_reference": target_reference,
            "research_context": research_context,
            "intelligence_context": intelligence_context,
            "workflow_result": workflow_result,
            "finding_intelligence": finding_intelligence,
            "correlation_result": correlation_result,
            "prioritization_result": prioritization_result,
            "human_review_result": human_review_result,
            "learning_result": learning_result,
            "execution_control_result": execution_control_result,
            "copilot_options": copilot_options,
            "provenance": provenance,
            "governance": governance,
        },
    )
    if malformed:
        return _failure_result(
            errors=[
                copilot_error(
                    "MALFORMED_INPUT",
                    "",
                    "copilot_input must be a mapping",
                )
            ],
        )

    raw_target = _field(base, "target_reference", _MISSING)
    target_value = "" if raw_target is _MISSING else _text(raw_target)
    raw_research = _field(base, "research_context", _MISSING)
    if raw_research is not _MISSING and not isinstance(raw_research, dict):
        errors.append(
            copilot_error(
                "INVALID_INPUT", "", "research_context must be a mapping"
            )
        )
        raw_research = _MISSING
    research_value = (
        sanitize_bug_bounty_copilot_input(
            {"research_context": raw_research}
        )["research_context"]
        if isinstance(raw_research, dict)
        else {}
    )
    provenance_value = _field(base, "provenance", _MISSING)
    provenance_value = (
        provenance_value if isinstance(provenance_value, dict) else {}
    )
    governance_value = _field(base, "governance", _MISSING)
    governance_value = _governance_reference(
        governance_value if isinstance(governance_value, dict) else None
    )
    options_value = _field(base, "copilot_options", _MISSING)
    options = sanitize_bug_bounty_copilot_input(
        {"copilot_options": options_value}
        if isinstance(options_value, dict)
        else {}
    )["copilot_options"]

    workflow = _validate_container(
        _field(base, "workflow_result", _MISSING),
        "WORKFLOW_RESULT",
        EXPECTED_WORKFLOW_RULE_VERSION,
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
    control = _validate_container(
        _field(base, "execution_control_result", _MISSING),
        "EXECUTION_CONTROL_RESULT",
        EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
        errors,
    )
    if not options.get("include_learning_context", True):
        learning = None
    if not options.get("include_execution_context", True):
        control = None

    # ------------------------------------------------------------------
    # Safety gate (R58 scanner reused; never repaired)
    # ------------------------------------------------------------------
    safety_reasons = collect_safety_reasons(
        base.get("intelligence_context"),
        workflow,
        findings,
        correlation,
        prioritization,
        human_review,
        learning,
        control,
    )
    if safety_reasons:
        errors.append(
            copilot_error(
                "SAFETY_BLOCKED",
                "",
                "a supplied input carries a forbidden execution claim",
            )
        )

    # ------------------------------------------------------------------
    # Contradictory context (fail closed)
    # ------------------------------------------------------------------
    if prioritization and findings:
        known = _finding_ids(findings)
        missing = [
            finding_id
            for finding_id in _prioritized_finding_ids(prioritization)
            if finding_id not in known
        ]
        if missing:
            errors.append(
                copilot_error(
                    "CONFLICTING_CONTEXT",
                    "PRIORITIZATION_RESULT",
                    "prioritized findings are absent from the finding "
                    "intelligence context",
                )
            )

    supplied_keys = (
        "workflow_result",
        "finding_intelligence",
        "correlation_result",
        "prioritization_result",
        "human_review_result",
        "learning_result",
        "execution_control_result",
    )
    any_supplied = False
    for key in supplied_keys:
        raw = _field(base, key, _MISSING)
        if raw is not _MISSING and raw is not None:
            any_supplied = True
            break
    any_context = bool(
        workflow
        or findings
        or correlation
        or prioritization
        or human_review
        or learning
        or control
        or _text(target_value)
        or research_value
        or any_supplied
    )
    if not any_context:
        return _no_context_result(
            target_reference=target_value,
            research_context=research_value,
            provenance=provenance_value,
            governance=governance_value,
        )

    # ------------------------------------------------------------------
    # R59 public API (workflow state is composed, never re-implemented)
    # ------------------------------------------------------------------
    if workflow is None:
        try:
            workflow = build_security_research_workflow(
                finding_intelligence=findings,
                correlation_result=correlation,
                prioritization_result=prioritization,
                human_review_result=human_review,
                learning_result=learning,
                execution_control_result=control,
                provenance=provenance_value,
                governance=governance_value,
            )
        except Exception:
            workflow = None
            errors.append(
                copilot_error(
                    "WORKFLOW_CONTEXT_UNAVAILABLE",
                    "WORKFLOW_RESULT",
                    "workflow state could not be composed",
                )
            )
    workflow_facts_value = workflow_facts(workflow)
    if workflow_facts_value.get("error"):
        errors.append(
            copilot_error(
                workflow_facts_value["error"],
                "WORKFLOW_RESULT",
                "workflow result could not be trusted",
            )
        )
        workflow_facts_value = workflow_facts(None)
        workflow = None
    if workflow_facts_value.get("blocked"):
        errors.append(
            copilot_error(
                "UPSTREAM_WORKFLOW_BLOCKED",
                "WORKFLOW_RESULT",
                "the upstream workflow is blocked or invalid",
            )
        )

    human_facts = human_context_facts(human_review)
    if human_facts.get("error"):
        errors.append(
            copilot_error(
                human_facts["error"],
                "HUMAN_REVIEW_RESULT",
                "human review context could not be trusted",
            )
        )
        human_facts = human_context_facts(None)
        human_review = None
    learning_facts = learning_context_facts(learning)
    if learning_facts.get("error"):
        errors.append(
            copilot_error(
                learning_facts["error"],
                "LEARNING_RESULT",
                "learning context could not be trusted",
            )
        )
        learning_facts = learning_context_facts(None)
        learning = None
    execution_facts = execution_context_facts(control)
    if execution_facts.get("error"):
        errors.append(
            copilot_error(
                execution_facts["error"],
                "EXECUTION_CONTROL_RESULT",
                "execution control context could not be trusted",
            )
        )
        execution_facts = execution_context_facts(None)
        control = None

    correlation_data = correlation_index(correlation)
    if correlation_data["_meta"].get("error"):
        errors.append(
            copilot_error(
                correlation_data["_meta"]["error"],
                "CORRELATION_RESULT",
                "correlation context could not be trusted",
            )
        )
        correlation_data = correlation_index(None)
        correlation = None

    # ------------------------------------------------------------------
    # Copilot input identity
    # ------------------------------------------------------------------
    descriptor = {
        "target_reference": target_value,
        "research_context": research_value,
        "options": options,
        "workflow_id": _text(workflow_facts_value.get("workflow_id")),
        "intelligence_id": _text((findings or {}).get("intelligence_id")),
        "correlation_id": _text((correlation or {}).get("correlation_id")),
        "prioritization_id": _text(
            (prioritization or {}).get("prioritization_id")
        ),
        "review_result_id": _text(
            (human_review or {}).get("review_result_id")
        ),
        "control_id": _text((control or {}).get("control_id")),
    }
    copilot_id_value = copilot_id(descriptor)
    input_payload = sanitize_bug_bounty_copilot_input(
        {
            "rule_version": BUG_BOUNTY_COPILOT_RULE_VERSION,
            "copilot_id": copilot_id_value,
            "target_reference": target_value,
            "research_context": research_value,
            "workflow_reference": _reference_from_artifact(
                "WORKFLOW",
                workflow,
                EXPECTED_WORKFLOW_RULE_VERSION,
                _text(workflow_facts_value.get("state")),
            ),
            "finding_reference": _reference_from_artifact(
                "FINDING",
                findings,
                EXPECTED_FINDING_RULE_VERSION,
            ),
            "correlation_reference": _reference_from_artifact(
                "CORRELATION",
                correlation,
                EXPECTED_CORRELATION_RULE_VERSION,
            ),
            "priority_reference": _reference_from_artifact(
                "PRIORITIZATION",
                prioritization,
                EXPECTED_PRIORITIZATION_RULE_VERSION,
            ),
            "human_reference": _reference_from_artifact(
                "HUMAN_DECISION",
                human_review,
                EXPECTED_HUMAN_REVIEW_RULE_VERSION,
            ),
            "learning_reference": _reference_from_artifact(
                "LEARNING",
                learning,
                EXPECTED_LEARNING_RULE_VERSION,
            ),
            "execution_reference": _reference_from_artifact(
                "EXECUTION_CONTROL",
                control,
                EXPECTED_EXECUTION_CONTROL_RULE_VERSION,
            ),
            "copilot_options": options,
            "provenance": {
                "workflow_id": _text(
                    workflow_facts_value.get("workflow_id")
                ),
                "source_stages": [
                    stage
                    for stage, present in (
                        ("FINDING", bool(findings)),
                        ("CORRELATION", bool(correlation)),
                        ("PRIORITIZATION", bool(prioritization)),
                        ("HUMAN_REVIEW", bool(human_review)),
                        ("LEARNING", bool(learning)),
                        ("EXECUTION_CONTROL", bool(control)),
                    )
                    if present
                ],
            },
            "governance": governance_value,
        }
    )
    try:
        copilot_input_value = bug_bounty_copilot_input_plan_projection(
            BugBountyCopilotInputPlan(**input_payload)
        )
    except (TypeError, ValueError):
        copilot_input_value = input_payload

    # ------------------------------------------------------------------
    # Brief and result
    # ------------------------------------------------------------------
    brief_provenance = {
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
            EXPECTED_EXECUTION_CONTROL_RULE_VERSION if control else ""
        ),
        "workflow_rule_version": EXPECTED_WORKFLOW_RULE_VERSION
        if workflow
        else "",
        "prioritization_id": _text(
            (prioritization or {}).get("prioritization_id")
        ),
        "correlation_id": _text((correlation or {}).get("correlation_id")),
        "intelligence_id": _text((findings or {}).get("intelligence_id")),
        "review_result_id": _text(
            (human_review or {}).get("review_result_id")
        ),
        "workflow_id": _text(workflow_facts_value.get("workflow_id")),
    }
    brief = _build_brief_payload(
        copilot_id_value=copilot_id_value,
        target_reference=target_value,
        research_context=research_value,
        workflow_facts_value=workflow_facts_value,
        prioritization_result=prioritization,
        human_facts=human_facts,
        learning_facts=learning_facts,
        execution_facts=execution_facts,
        correlation_index_value=correlation_data,
        safety_reasons=safety_reasons,
        options=options,
        provenance=brief_provenance,
        governance=governance_value,
        upstream_error=has_fatal_error(errors)
        or any(
            entry.get("error_category")
            in ("UPSTREAM_WORKFLOW_BLOCKED", "CONFLICTING_CONTEXT")
            for entry in errors
        ),
    )
    status = copilot_status(
        errors=errors,
        workflow_present=bool(workflow_facts_value.get("present")),
        any_context=True,
    )
    result_payload = {
        "rule_version": "r60-4",
        "result_id": result_id(
            _text(brief.get("brief_id")),
            status,
            _text(brief.get("safety_status")),
            errors,
        ),
        "status": status,
        "brief": brief,
        "summary": copilot_summary(brief, errors),
        "errors": errors,
        "provenance": brief.get("provenance") or {},
        "governance": governance_value,
        "limitations": brief.get("limitations") or [],
    }
    return _finalize_result(result_payload)


def build_copilot_brief(
    copilot_input: object = None, **kwargs
) -> dict:
    """Return only the deterministic advisory brief for the context."""

    result = build_bug_bounty_copilot(copilot_input, **kwargs)
    return result.get("brief") or sanitize_copilot_brief(None)


def build_copilot_opportunities(
    copilot_input: object = None, **kwargs
) -> list[dict]:
    """Return the ranked research opportunities for the context."""

    brief = build_copilot_brief(copilot_input, **kwargs)
    return list(brief.get("opportunities") or ())


def determine_copilot_priorities(
    copilot_input: object = None, **kwargs
) -> list[dict]:
    """Alias for :func:`build_copilot_opportunities` (ranked priorities)."""

    return build_copilot_opportunities(copilot_input, **kwargs)


def summarize_copilot_brief(value: object = None, **kwargs) -> dict:
    """Return the deterministic copilot summary for a brief, result or input."""

    if isinstance(value, dict) and _text(value.get("rule_version")) == (
        "r60-4"
    ):
        return sanitize_copilot_summary(value.get("summary"))
    if isinstance(value, dict) and _text(value.get("rule_version")) == (
        "r60-3"
    ):
        return copilot_summary(value, [])
    if value is not None and not isinstance(value, dict):
        return sanitize_copilot_summary(None)
    kwargs = {**value, **kwargs} if isinstance(value, dict) else kwargs
    result = build_bug_bounty_copilot(**kwargs)
    return sanitize_copilot_summary(result.get("summary"))


def export_bug_bounty_copilot(
    copilot_input: object = None, **kwargs
) -> dict:
    """Alias for :func:`build_bug_bounty_copilot`."""

    return build_bug_bounty_copilot(copilot_input, **kwargs)


__all__ = [
    "BUG_BOUNTY_COPILOT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "ARTIFACT_PARAMETERS",
    "build_bug_bounty_copilot",
    "build_copilot_brief",
    "build_copilot_opportunities",
    "determine_copilot_priorities",
    "summarize_copilot_brief",
    "export_bug_bounty_copilot",
]
