"""Stage R56.5 deterministic human review builder (pure engine).

Consumes structured R55 prioritization output (optionally enriched with the
R54 correlation result) and records explicit human review decisions:

    R55 prioritization result (immutable recommendations)
      -> bounded review plans (stable finding ids)
      -> explicit human decisions (authority-validated, fail closed)
      -> deterministic audit representation, history and batches
      -> human review result (research-only records)

Hard boundaries encoded here:

- AI recommends, the human decides: R55 priority is carried read-only and is
  never rewritten; a human decision changes research-workflow direction only.
- No execution: R56 never executes commands, never sends HTTP/DNS requests,
  never invokes scanners, subprocesses, browsers, databases or LLMs, never
  generates payloads and never confirms a vulnerability. A decision is
  recorded only.
- Authority is explicit and enforced: automated/AI authority, execution
  authorization, vulnerability confirmation and exploit authorization are
  rejected fail-closed and preserved as invalid-decision records.
- Fail closed: ambiguous or malformed inputs are rejected or skipped with
  structured reasons; nothing is silently repaired.
- Deterministic: content-derived ids only; canonical ordering; stable
  tie-breaking; no timestamps, UUIDs, pids or randomness.
- Pure and offline: no I/O, no network, no subprocess, no shell, no
  database, no wall-clock time.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.human_decision_rules import (
    batch_id,
    build_review,
    correlation_reference,
    result_id,
)
from ai.schemas.finding_correlation import sanitize_finding_relationship
from ai.schemas.finding_correlation_result import (
    FINDING_CORRELATION_RESULT_RULE_VERSION,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.human_decision import (
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_PENDING,
    HUMAN_DECISION_TYPES,
    LIMITATION_AI_ADVISORY_ONLY,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_DECISION_HISTORY_PRESENT,
    LIMITATION_DECISION_RECORDED_ONLY,
    LIMITATION_DUPLICATE_PRESENT,
    LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY,
    LIMITATION_ESCALATION_RECORDED_ONLY,
    LIMITATION_EXECUTION_NOT_AUTHORIZED,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_HUMAN_DECISION_DOES_NOT_CONFIRM,
    LIMITATION_NOT_AUTHORIZED_LISTED,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_PENDING_HUMAN_DECISION,
    LIMITATION_PRIORITY_PRESERVED,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_RATIONALE_NOT_PROVIDED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_REVIEW_EXPIRED,
    LIMITATION_SAFETY_DEFERRED,
    RATIONALE_STATE_PROVIDED,
    sanitize_human_governance,
)
from ai.schemas.human_decision_result import (
    ERROR_CORRELATION_MISMATCH,
    ERROR_DECISION_REJECTED,
    ERROR_DUPLICATE_DECISION,
    ERROR_INVALID_INPUT,
    ERROR_INVALID_REVIEW_ORDER,
    ERROR_MALFORMED_PRIORITY,
    ERROR_NOT_FOUND,
    HUMAN_REVIEW_RESULT_RULE_VERSION,
    MAX_REVIEWS,
    REJECTION_DUPLICATE_DECISION,
    REJECTION_FINDING_NOT_FOUND,
    REJECTION_MALFORMED_DECISION,
    REJECTION_MISSING_FINDING_ID,
    SKIP_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED,
    SKIP_MALFORMED_PRIORITY,
    SKIP_UNSUPPORTED_CATEGORY,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_PARTIAL,
    STATUS_PENDING,
    HumanReviewResultPlan,
    human_review_result_plan_projection,
    sanitize_human_review_error,
    sanitize_human_review_skip,
    sanitize_invalid_decision,
)
from ai.schemas.human_review import (
    HUMAN_REVIEW_RULE_VERSION,
    HumanReviewBatchPlan,
    sanitize_human_review_batch,
)
from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)
from ai.schemas.research_priority import (
    BAND_DEFERRED,
    CONFLICT_PRESENT,
    sanitize_research_priority,
)
from ai.schemas.research_priority_result import (
    RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION,
)
from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    CATEGORY_UNKNOWN,
)

HUMAN_REVIEW_BUILDER_RULE_VERSION = "r56-5"
RULE_VERSION = HUMAN_REVIEW_BUILDER_RULE_VERSION

SUPPORTED_CATEGORIES: tuple[str, ...] = tuple(
    category for category in AGENT_CATEGORIES if category != CATEGORY_UNKNOWN
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_AI_ADVISORY_ONLY,
    LIMITATION_HUMAN_DECISION_DOES_NOT_CONFIRM,
    LIMITATION_EXECUTION_NOT_AUTHORIZED,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_NOT_AUTHORIZED_LISTED,
    LIMITATION_DECISION_RECORDED_ONLY,
    LIMITATION_PRIORITY_PRESERVED,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _error(
    error_category: str,
    finding_id: str = "",
    category: str = "",
    message: str = "",
) -> dict:
    return sanitize_human_review_error(
        {
            "stage": "HUMAN_REVIEW",
            "error_category": error_category,
            "finding_id": finding_id,
            "category": category,
            "message": message,
        }
    )


def _skip(
    finding_id: str, category: str, agent_id: str, reason: str
) -> dict:
    return sanitize_human_review_skip(
        {
            "finding_id": finding_id,
            "category": category,
            "agent_id": agent_id,
            "reason": reason,
        }
    )


def _invalid(
    finding_id: str,
    decision_type: str,
    rejection_reason: str,
    message: str,
) -> dict:
    return sanitize_invalid_decision(
        {
            "rule_version": HUMAN_REVIEW_RESULT_RULE_VERSION,
            "finding_id": finding_id,
            "decision_type": decision_type,
            "rejection_reason": rejection_reason,
            "message": message,
        }
    )


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------


def _normalize_plan(raw: object) -> tuple[dict, str]:
    """Normalize one R55 priority plan (read-only)."""

    if not isinstance(raw, dict):
        return {}, SKIP_MALFORMED_PRIORITY
    plan = sanitize_research_priority(raw)
    finding_id = _text(plan.get("finding_id"))
    if not FINDING_ID_RE.match(finding_id):
        return {}, SKIP_MALFORMED_PRIORITY
    category = _upper(plan.get("category"))
    if category not in SUPPORTED_CATEGORIES:
        return {}, SKIP_UNSUPPORTED_CATEGORY
    if not plan.get("priority_band"):
        return {}, SKIP_MALFORMED_PRIORITY
    return plan, ""


def _extract_plans(
    prioritization_result: object,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Extract ranked + deferred plans in canonical review order."""

    plans: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    ranked = prioritization_result.get("ranked_findings") or []
    deferred = prioritization_result.get("deferred_findings") or []
    seen: list[str] = []
    for raw in list(ranked) + list(deferred):
        plan, skip_reason = _normalize_plan(raw)
        raw_dict = raw if isinstance(raw, dict) else {}
        finding_id = _text(plan.get("finding_id")) or _text(
            raw_dict.get("finding_id")
        )
        category = _upper(plan.get("category")) or _upper(
            raw_dict.get("category")
        )
        agent_id = _text(plan.get("agent_id")) or _text(
            raw_dict.get("agent_id")
        )
        if skip_reason:
            skipped.append(_skip(finding_id, category, agent_id, skip_reason))
            errors.append(
                _error(
                    ERROR_MALFORMED_PRIORITY,
                    finding_id,
                    category,
                    "priority plan is not a supported review source",
                )
            )
            continue
        if finding_id in seen:
            skipped.append(
                _skip(
                    finding_id,
                    category,
                    agent_id,
                    SKIP_DUPLICATE_IDENTITY,
                )
            )
            errors.append(
                _error(
                    ERROR_DUPLICATE_DECISION,
                    finding_id,
                    category,
                    "the same finding identity was supplied twice",
                )
            )
            continue
        if len(plans) >= MAX_REVIEWS:
            skipped.append(
                _skip(
                    finding_id,
                    category,
                    agent_id,
                    SKIP_LIMIT_EXCEEDED,
                )
            )
            errors.append(
                _error(
                    ERROR_LIMIT_EXCEEDED,
                    finding_id,
                    category,
                    "review limit reached",
                )
            )
            continue
        seen.append(finding_id)
        plans.append(plan)
    return plans, skipped, errors


def _decision_requests(
    decisions: object,
) -> tuple[dict[str, dict], list[dict], list[dict]]:
    """Normalize the supplied decision requests (fail closed)."""

    mapping: dict[str, dict] = {}
    invalid: list[dict] = []
    errors: list[dict] = []
    if decisions is None:
        return mapping, invalid, errors
    items: list[dict] = []
    if isinstance(decisions, dict):
        for key, value in decisions.items():
            key_text = _text(key)
            if not isinstance(value, dict):
                invalid.append(
                    _invalid(
                        key_text,
                        "",
                        REJECTION_MALFORMED_DECISION,
                        "decision request must be a mapping",
                    )
                )
                errors.append(
                    _error(
                        ERROR_DECISION_REJECTED,
                        key_text,
                        "",
                        "decision request must be a mapping",
                    )
                )
                continue
            request = dict(value)
            declared = _text(request.get("finding_id"))
            if declared and key_text and declared != key_text:
                invalid.append(
                    _invalid(
                        declared,
                        _text(request.get("decision_type")),
                        REJECTION_MALFORMED_DECISION,
                        "decision finding_id conflicts with the mapping key",
                    )
                )
                errors.append(
                    _error(
                        ERROR_DECISION_REJECTED,
                        declared,
                        "",
                        "decision finding_id conflicts with the mapping key",
                    )
                )
                continue
            request["finding_id"] = declared or key_text
            items.append(request)
    elif isinstance(decisions, (list, tuple)):
        for value in decisions:
            if not isinstance(value, dict):
                invalid.append(
                    _invalid(
                        "",
                        "",
                        REJECTION_MALFORMED_DECISION,
                        "decision request must be a mapping",
                    )
                )
                errors.append(
                    _error(
                        ERROR_DECISION_REJECTED,
                        "",
                        "",
                        "decision request must be a mapping",
                    )
                )
                continue
            items.append(dict(value))
    else:
        invalid.append(
            _invalid(
                "",
                "",
                REJECTION_MALFORMED_DECISION,
                "decisions must be a mapping or a list",
            )
        )
        errors.append(
            _error(
                ERROR_DECISION_REJECTED,
                "",
                "",
                "decisions must be a mapping or a list",
            )
        )
        return mapping, invalid, errors

    for request in items:
        finding_id = _text(request.get("finding_id"))
        decision_type = _text(request.get("decision_type"))
        if not FINDING_ID_RE.match(finding_id):
            invalid.append(
                _invalid(
                    finding_id,
                    decision_type,
                    REJECTION_MISSING_FINDING_ID,
                    "decision request has no valid finding_id",
                )
            )
            errors.append(
                _error(
                    ERROR_DECISION_REJECTED,
                    finding_id,
                    "",
                    "decision request has no valid finding_id",
                )
            )
            continue
        if finding_id in mapping:
            invalid.append(
                _invalid(
                    finding_id,
                    decision_type,
                    REJECTION_DUPLICATE_DECISION,
                    "the same finding received more than one decision",
                )
            )
            errors.append(
                _error(
                    ERROR_DUPLICATE_DECISION,
                    finding_id,
                    "",
                    "the same finding received more than one decision",
                )
            )
            continue
        mapping[finding_id] = request
    return mapping, invalid, errors


def _correlation_context(
    correlation_result: object,
) -> tuple[str, str, set[str], list[dict]]:
    """Validate the optional R54 result and collect its identity/endpoints."""

    correlation_id = ""
    correlation_rule_version = ""
    endpoints: set[str] = set()
    errors: list[dict] = []
    if correlation_result is None:
        return correlation_id, correlation_rule_version, endpoints, errors
    correlation_id = _text(correlation_result.get("correlation_id"))
    correlation_rule_version = _text(
        correlation_result.get("rule_version")
    )
    for raw in correlation_result.get("relationships") or ():
        relationship = sanitize_finding_relationship(raw)
        source = _text(relationship.get("source_finding_id"))
        target = _text(relationship.get("target_finding_id"))
        if not FINDING_ID_RE.match(source) or not FINDING_ID_RE.match(
            target
        ):
            errors.append(
                _error(
                    ERROR_CORRELATION_MISMATCH,
                    message="malformed correlation relationship ignored",
                )
            )
            continue
        endpoints.add(source)
        endpoints.add(target)
    return correlation_id, correlation_rule_version, endpoints, errors


def _plan_provenance(
    plan: dict,
    *,
    prioritization_id: str,
    priority_rule_version: str,
    correlation_id: str,
    correlation_rule_version: str,
) -> dict:
    provenance = plan.get("provenance") or {}
    return {
        "finding_rule_version": _text(
            provenance.get("finding_rule_version")
        ),
        "correlation_rule_version": _text(
            provenance.get("correlation_rule_version")
        )
        or correlation_rule_version,
        "priority_rule_version": priority_rule_version,
        "prioritization_id": prioritization_id,
        "correlation_id": correlation_id,
        "orchestration_id": _text(provenance.get("orchestration_id")),
        "agent_id": _text(plan.get("agent_id")),
        "category": _upper(plan.get("category")),
        "decision_source": "HUMAN",
        "source_stages": list(provenance.get("source_stages") or ()),
        "deterministic": True,
        "research_only": True,
    }


def _governance_summary(plans: list[dict]) -> dict:
    referenced: list[str] = []
    unknown: list[str] = []
    ready: list[str] = []
    not_ready: list[str] = []
    for plan in plans:
        finding_id = _text(plan.get("finding_id"))
        governance = sanitize_human_governance(plan.get("governance"))
        if _upper(governance.get("reference_state")) == "REFERENCED":
            referenced.append(finding_id)
            if governance.get("ready") is True:
                ready.append(finding_id)
            else:
                not_ready.append(finding_id)
        else:
            unknown.append(finding_id)
    if referenced and unknown:
        state = GOVERNANCE_MIXED
    elif referenced:
        state = GOVERNANCE_CONSISTENT_REFERENCED
    else:
        state = GOVERNANCE_UNKNOWN
    return {
        "governance_state": state,
        "referenced_finding_ids": referenced,
        "unknown_finding_ids": unknown,
        "ready_finding_ids": ready,
        "not_ready_finding_ids": not_ready,
        "research_only": True,
    }


def _review_order(
    plans: list[dict], explicit_order: object
) -> tuple[list[str], list[dict]]:
    """Deterministic review order (R55 order or a validated explicit one)."""

    canonical = [_text(plan.get("finding_id")) for plan in plans]
    errors: list[dict] = []
    if explicit_order is None:
        return canonical, errors
    if not isinstance(explicit_order, (list, tuple)):
        errors.append(
            _error(
                ERROR_INVALID_REVIEW_ORDER,
                message="review_order must be a list of finding ids",
            )
        )
        return canonical, errors
    requested = [_text(item) for item in explicit_order]
    if (
        len(requested) != len(canonical)
        or set(requested) != set(canonical)
    ):
        errors.append(
            _error(
                ERROR_INVALID_REVIEW_ORDER,
                message=(
                    "review_order must contain exactly the reviewed "
                    "finding ids"
                ),
            )
        )
        return canonical, errors
    return requested, errors


def _batch(
    plans: list[dict],
    reviews: list[dict],
    *,
    prioritization_id: str,
    review_order: list[str],
) -> dict:
    decisions_by_finding: list[dict] = []
    for review in reviews:
        decision = review.get("decision") or {}
        decisions_by_finding.append(
            {
                "finding_id": review.get("finding_id"),
                "decision_id": decision.get("decision_id", ""),
                "decision_type": decision.get("decision_type", ""),
                "decision_state": review.get("review_state"),
            }
        )
    conflict_ids = [
        _text(plan.get("finding_id"))
        for plan in plans
        if _upper(plan.get("conflict_state")) == CONFLICT_PRESENT
    ]
    duplicate_ids = [
        _text(plan.get("finding_id"))
        for plan in plans
        if "DUPLICATE"
        in (
            (plan.get("correlation_summary") or {}).get(
                "relationship_types"
            )
            or ()
        )
    ]
    payload = {
        "rule_version": HUMAN_REVIEW_RULE_VERSION,
        "prioritization_id": prioritization_id,
        "review_order": review_order,
        "finding_ids": [_text(plan.get("finding_id")) for plan in plans],
        "ranked_snapshot": [
            {
                "finding_id": plan.get("finding_id"),
                "priority_band": plan.get("priority_band"),
                "priority_score": plan.get("priority_score"),
                "ranking_position": plan.get("ranking_position"),
            }
            for plan in plans
        ],
        "decisions_by_finding": decisions_by_finding,
        "conflict_finding_ids": conflict_ids,
        "duplicate_finding_ids": duplicate_ids,
        "priority_immutable": True,
        "research_only": True,
        "deterministic": True,
    }
    payload["batch_id"] = batch_id(
        prioritization_id,
        review_order,
        [review.get("review_id", "") for review in reviews],
    )
    batch = HumanReviewBatchPlan(
        **sanitize_human_review_batch(payload)
    ).model_dump(mode="json")
    return batch


def _summary(
    plans: list[dict],
    reviews: list[dict],
    invalid: list[dict],
    skipped: list[dict],
) -> dict:
    decision_type_counts = {
        decision_type: 0 for decision_type in HUMAN_DECISION_TYPES
    }
    for review in reviews:
        decision = review.get("decision") or {}
        decision_type = _text(decision.get("decision_type"))
        if decision_type in decision_type_counts:
            decision_type_counts[decision_type] += 1
    conflict_count = sum(
        1
        for plan in plans
        if _upper(plan.get("conflict_state")) == CONFLICT_PRESENT
    )
    duplicate_count = sum(
        1
        for plan in plans
        if "DUPLICATE"
        in (
            (plan.get("correlation_summary") or {}).get(
                "relationship_types"
            )
            or ()
        )
    )
    return {
        "finding_count": len(plans),
        "review_count": len(reviews),
        "decided_count": sum(
            1
            for review in reviews
            if review.get("review_state") == DECISION_STATE_DECIDED
        ),
        "pending_count": sum(
            1
            for review in reviews
            if review.get("review_state") == DECISION_STATE_PENDING
        ),
        "expired_count": sum(
            1
            for review in reviews
            if review.get("review_state") == DECISION_STATE_EXPIRED
        ),
        "invalid_count": len(invalid),
        "skipped_count": len(skipped),
        "decision_type_counts": decision_type_counts,
        "conflict_review_count": conflict_count,
        "duplicate_review_count": duplicate_count,
        "evidence_request_count": decision_type_counts[
            "REQUEST_MORE_EVIDENCE"
        ],
        "escalation_count": decision_type_counts["ESCALATE"],
        "research_only": True,
    }


def _container(
    *,
    prioritization_result: object,
    plans: list[dict],
    reviews: list[dict],
    invalid: list[dict],
    skipped: list[dict],
    errors: list[dict],
    review_order: list[str],
    prioritization_id: str,
    priority_rule_version: str,
    finding_rule_version: str,
    correlation_rule_version: str,
    correlation_id: str,
    fatal: bool = False,
) -> dict:
    decided = sum(
        1
        for review in reviews
        if review.get("review_state") == DECISION_STATE_DECIDED
    )
    if fatal:
        status = STATUS_FAILED
    elif not reviews and not skipped and not errors:
        status = STATUS_NO_FINDINGS
    elif (
        reviews
        and decided == len(reviews)
        and not (errors or skipped or invalid)
    ):
        status = STATUS_COMPLETED
    elif not decided and not (errors or skipped or invalid) and reviews:
        status = STATUS_PENDING
    else:
        status = STATUS_PARTIAL

    limitations = list(_BASE_LIMITATIONS)
    if not any(
        review.get("review_state") == DECISION_STATE_DECIDED
        for review in reviews
    ):
        limitations.append(LIMITATION_PENDING_HUMAN_DECISION)
    if not correlation_id and not correlation_rule_version:
        limitations.append(LIMITATION_CORRELATION_UNAVAILABLE)
    if any(
        _upper(plan.get("conflict_state")) == CONFLICT_PRESENT
        for plan in plans
    ):
        limitations.append(LIMITATION_CONFLICT_PRESENT)
    if any(
        "DUPLICATE"
        in (
            (plan.get("correlation_summary") or {}).get(
                "relationship_types"
            )
            or ()
        )
        for plan in plans
    ):
        limitations.append(LIMITATION_DUPLICATE_PRESENT)
    if any(
        review.get("audit", {}).get("decision_rationale_state")
        != RATIONALE_STATE_PROVIDED
        for review in reviews
        if review.get("review_state") == DECISION_STATE_DECIDED
    ):
        limitations.append(LIMITATION_RATIONALE_NOT_PROVIDED)
    if any(
        (review.get("decision") or {}).get("decision_type")
        == "REQUEST_MORE_EVIDENCE"
        for review in reviews
    ):
        limitations.append(LIMITATION_EVIDENCE_REQUEST_RECORDED_ONLY)
    if any(
        (review.get("decision") or {}).get("decision_type") == "ESCALATE"
        for review in reviews
    ):
        limitations.append(LIMITATION_ESCALATION_RECORDED_ONLY)
    if any(review.get("decision_history") for review in reviews):
        limitations.append(LIMITATION_DECISION_HISTORY_PRESENT)
    if any(
        review.get("review_state") == DECISION_STATE_EXPIRED
        for review in reviews
    ):
        limitations.append(LIMITATION_REVIEW_EXPIRED)
    if any(
        _upper(plan.get("priority_band")) == BAND_DEFERRED for plan in plans
    ):
        limitations.append(LIMITATION_SAFETY_DEFERRED)
    governance = _governance_summary(plans)
    if governance["governance_state"] == GOVERNANCE_UNKNOWN:
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    if any(
        not ((plan.get("provenance") or {}).get("orchestration_id"))
        for plan in plans
    ):
        limitations.append(LIMITATION_PROVENANCE_INCOMPLETE)

    result = HumanReviewResultPlan(
        rule_version=HUMAN_REVIEW_RESULT_RULE_VERSION,
        review_rule_version=HUMAN_REVIEW_RULE_VERSION,
        decision_rule_version="r56-1",
        priority_rule_version=priority_rule_version,
        finding_rule_version=finding_rule_version,
        correlation_rule_version=correlation_rule_version,
        review_result_id=result_id(
            prioritization_id,
            [review.get("review_id", "") for review in reviews],
            [
                f"{item.get('finding_id', '')}:{item.get('rejection_reason', '')}"
                for item in invalid
            ],
        ),
        prioritization_id=prioritization_id,
        status=status,
        reviews=reviews,
        invalid_decisions=invalid,
        skipped_findings=skipped,
        errors=errors,
        batch=_batch(
            plans,
            reviews,
            prioritization_id=prioritization_id,
            review_order=review_order,
        ),
        summary=_summary(plans, reviews, invalid, skipped),
        provenance={
            "rule_version": HUMAN_REVIEW_RESULT_RULE_VERSION,
            "review_rule_version": HUMAN_REVIEW_RULE_VERSION,
            "decision_rule_version": "r56-1",
            "priority_rule_version": priority_rule_version,
            "finding_rule_version": finding_rule_version,
            "correlation_rule_version": correlation_rule_version,
            "prioritization_id": prioritization_id,
            "correlation_id": correlation_id,
            "source_kinds": sorted(
                {
                    _text(
                        (plan.get("provenance") or {}).get("source_kind")
                    )
                    for plan in plans
                    if _text(
                        (plan.get("provenance") or {}).get("source_kind")
                    )
                }
            ),
            "orchestration_ids": sorted(
                {
                    _text(
                        (plan.get("provenance") or {}).get(
                            "orchestration_id"
                        )
                    )
                    for plan in plans
                    if _text(
                        (plan.get("provenance") or {}).get(
                            "orchestration_id"
                        )
                    )
                }
            ),
            "source_categories": sorted(
                {
                    _upper(plan.get("category"))
                    for plan in plans
                    if _upper(plan.get("category"))
                }
            ),
            "source_agent_ids": sorted(
                {
                    _text(plan.get("agent_id"))
                    for plan in plans
                    if _text(plan.get("agent_id"))
                }
            ),
            "decision_source": "HUMAN",
            "deterministic": True,
            "research_only": True,
        },
        governance=governance,
        limitations=limitations,
        decision_authority="HUMAN",
        ai_role="ADVISORY",
        execution_authorized=False,
        vulnerability_confirmed=False,
        confirmation_state="NOT_CONFIRMED",
        confidence_effect="NONE",
        research_only=True,
        deterministic=True,
    )
    return human_review_result_plan_projection(result)


def _fatal_result(errors: list[dict]) -> dict:
    return _container(
        prioritization_result=None,
        plans=[],
        reviews=[],
        invalid=[],
        skipped=[],
        errors=errors,
        review_order=[],
        prioritization_id="",
        priority_rule_version="",
        finding_rule_version="",
        correlation_rule_version="",
        correlation_id="",
        fatal=True,
    )


# ---------------------------------------------------------------------------
# Core run
# ---------------------------------------------------------------------------


def _run(
    *,
    prioritization_result: object,
    correlation_result: object,
    decisions: object,
    review_order: object,
    target_finding_id: str = "",
    previous_review: object = None,
) -> dict:
    # ------------------------------------------------------------------
    # Input validation (fail closed)
    # ------------------------------------------------------------------
    if prioritization_result is not None and not isinstance(
        prioritization_result, dict
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="prioritization_result must be a mapping",
                )
            ]
        )
    if correlation_result is not None and not isinstance(
        correlation_result, dict
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="correlation_result must be a mapping",
                )
            ]
        )
    if previous_review is not None and not isinstance(
        previous_review, dict
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="previous_review must be a mapping",
                )
            ]
        )

    prioritization_id = ""
    priority_rule_version = ""
    finding_rule_version = ""
    correlation_rule_version = ""
    plans: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []

    if prioritization_result is not None:
        if (
            _text(prioritization_result.get("rule_version"))
            != RESEARCH_PRIORITIZATION_RESULT_RULE_VERSION
        ):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=(
                            "prioritization_result is not an R55 result"
                        ),
                    )
                ]
            )
        for key in ("ranked_findings", "deferred_findings"):
            if key in prioritization_result and not isinstance(
                prioritization_result.get(key), (list, tuple)
            ):
                return _fatal_result(
                    [
                        _error(
                            ERROR_INVALID_INPUT,
                            message=(
                                f"prioritization_result.{key} must be a list"
                            ),
                        )
                    ]
                )
        prioritization_id = _text(
            prioritization_result.get("prioritization_id")
        )
        priority_rule_version = _text(
            prioritization_result.get("priority_rule_version")
        )
        finding_rule_version = _text(
            prioritization_result.get("finding_rule_version")
        )
        correlation_rule_version = _text(
            prioritization_result.get("correlation_rule_version")
        )
        plans, skipped, errors = _extract_plans(prioritization_result)

    if correlation_result is not None:
        if (
            _text(correlation_result.get("rule_version"))
            != FINDING_CORRELATION_RESULT_RULE_VERSION
        ):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message="correlation_result is not an R54 result",
                    )
                ]
            )
        for key in ("relationships", "clusters", "finding_references"):
            if key in correlation_result and not isinstance(
                correlation_result.get(key), (list, tuple)
            ):
                return _fatal_result(
                    [
                        _error(
                            ERROR_INVALID_INPUT,
                            message=f"correlation_result.{key} must be a list",
                        )
                    ]
                )

    target = _text(target_finding_id)
    if not target and isinstance(previous_review, dict):
        target = _text(previous_review.get("finding_id"))
    if target:
        plans = [
            plan
            for plan in plans
            if _text(plan.get("finding_id")) == target
        ]
        if not plans:
            return _fatal_result(
                [
                    _error(
                        ERROR_NOT_FOUND,
                        finding_id=target,
                        message="finding is not part of the R55 result",
                    )
                ]
            )

    (
        correlation_id,
        correlation_rule_version_value,
        endpoints,
        correlation_errors,
    ) = _correlation_context(correlation_result)
    errors.extend(correlation_errors)
    if correlation_result is not None and endpoints:
        plan_ids = {_text(plan.get("finding_id")) for plan in plans}
        if not endpoints.issubset(plan_ids):
            for missing in sorted(endpoints - plan_ids):
                errors.append(
                    _error(
                        ERROR_CORRELATION_MISMATCH,
                        finding_id=missing,
                        message=(
                            "correlation references a finding outside the "
                            "review set"
                        ),
                    )
                )
    if not correlation_rule_version:
        correlation_rule_version = correlation_rule_version_value

    mapping, invalid, decision_errors = _decision_requests(decisions)
    errors.extend(decision_errors)
    plan_ids = {_text(plan.get("finding_id")) for plan in plans}
    for finding_id in sorted(set(mapping) - plan_ids):
        invalid.append(
            _invalid(
                finding_id,
                _text(mapping[finding_id].get("decision_type")),
                REJECTION_FINDING_NOT_FOUND,
                "decision references a finding outside the review set",
            )
        )
        errors.append(
            _error(
                ERROR_NOT_FOUND,
                finding_id=finding_id,
                message="decision references a finding outside the review set",
            )
        )
        mapping.pop(finding_id, None)

    if previous_review is not None:
        review_finding_id = _text(previous_review.get("finding_id"))
        if target and review_finding_id and review_finding_id != target:
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        finding_id=review_finding_id,
                        message=(
                            "previous_review does not match the target "
                            "finding"
                        ),
                    )
                ]
            )
        if len(plans) != 1:
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=(
                            "previous_review requires a single target "
                            "finding"
                        ),
                    )
                ]
            )

    order, order_errors = _review_order(plans, review_order)
    errors.extend(order_errors)

    reviews: list[dict] = []
    for plan in plans:
        finding_id = _text(plan.get("finding_id"))
        request = mapping.get(finding_id)
        if (
            request is None
            and target
            and isinstance(previous_review, dict)
            and _text(previous_review.get("finding_id")) == finding_id
        ):
            request = None
        provenance_value = _plan_provenance(
            plan,
            prioritization_id=prioritization_id,
            priority_rule_version=priority_rule_version,
            correlation_id=correlation_id,
            correlation_rule_version=correlation_rule_version,
        )
        governance = sanitize_human_governance(plan.get("governance"))
        correlation_value = correlation_reference(
            plan, correlation_result
        )
        if correlation_result is not None:
            correlation_value["correlation_id"] = (
                correlation_id or correlation_value.get("correlation_id", "")
            )
        review, rejection = build_review(
            finding_id=finding_id,
            plan=plan,
            prioritization_id=prioritization_id,
            correlation_reference_value=correlation_value,
            provenance_value=provenance_value,
            governance=governance,
            request=request,
            previous_review=previous_review,
        )
        if rejection:
            invalid.append(
                _invalid(
                    finding_id,
                    _text(
                        (request or {}).get("decision_type")
                        if isinstance(request, dict)
                        else ""
                    ),
                    rejection,
                    "human decision request was rejected",
                )
            )
            errors.append(
                _error(
                    ERROR_DECISION_REJECTED,
                    finding_id=finding_id,
                    message=rejection,
                )
            )
        reviews.append(review)

    return _container(
        prioritization_result=prioritization_result,
        plans=plans,
        reviews=reviews,
        invalid=invalid,
        skipped=skipped,
        errors=errors,
        review_order=order,
        prioritization_id=prioritization_id,
        priority_rule_version=priority_rule_version,
        finding_rule_version=finding_rule_version,
        correlation_rule_version=correlation_rule_version,
        correlation_id=correlation_id,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_human_review(
    prioritization_result: object = None,
    correlation_result: object = None,
    decisions: object = None,
) -> dict:
    """Create deterministic human reviews for an R55 prioritization result.

    Every ranked and deferred finding becomes a review plan. Supplied human
    decisions are validated and recorded; missing decisions leave the review
    explicitly ``PENDING_HUMAN_REVIEW``. Nothing is executed and no upstream
    artifact is modified.
    """

    return _run(
        prioritization_result=prioritization_result,
        correlation_result=correlation_result,
        decisions=decisions,
        review_order=None,
    )


def review_finding(
    finding_id: str = "",
    prioritization_result: object = None,
    correlation_result: object = None,
    decision: object = None,
) -> dict:
    """Review one specific finding from an R55 prioritization result."""

    return _run(
        prioritization_result=prioritization_result,
        correlation_result=correlation_result,
        decisions=None if decision is None else [decision],
        review_order=None,
        target_finding_id=finding_id,
    )


def record_human_decision(
    finding_id: str = "",
    prioritization_result: object = None,
    correlation_result: object = None,
    decision: object = None,
    previous_review: object = None,
) -> dict:
    """Record (or supersede) one human decision with closed transitions.

    Supplying ``previous_review`` performs a deterministic
    ``DECIDED -> DECIDED`` supersession with preserved history; transitions
    that are not allowed fail closed and are never applied.
    """

    return _run(
        prioritization_result=prioritization_result,
        correlation_result=correlation_result,
        decisions=None if decision is None else [decision],
        review_order=None,
        target_finding_id=finding_id,
        previous_review=previous_review,
    )


def create_review_batch(
    prioritization_result: object = None,
    correlation_result: object = None,
    decisions: object = None,
    review_order: object = None,
) -> dict:
    """Create a deterministic review batch (explicit order supported).

    The review order defaults to the R55 ranking and may only be an explicit
    permutation of the reviewed finding ids; R55 itself is never mutated.
    """

    return _run(
        prioritization_result=prioritization_result,
        correlation_result=correlation_result,
        decisions=decisions,
        review_order=review_order,
    )


def export_human_review(**kwargs) -> dict:
    """Alias for :func:`create_human_review` (project naming pattern)."""

    return create_human_review(**kwargs)


__all__ = [
    "HUMAN_REVIEW_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "SUPPORTED_CATEGORIES",
    "create_human_review",
    "review_finding",
    "record_human_decision",
    "create_review_batch",
    "export_human_review",
]
