"""Research pipeline (EPIC 5 Parts 1/2/3/5/6/10): the offline workflow.

``run_research`` takes candidate mappings plus optional case memories
and walks each candidate through adapt → recall → prioritize → assign →
staff → case → draft → plan → gate → evidence → review, recording a
``ResearchRun``. One candidate's failure never stops the run: every
refusal and every unexpected error is recorded with a closed kind and
the walk continues. Same input snapshot always yields equal output.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from aec.assignment import rules as assignment_rules
from aec.authorization_gate import check_authorization_eligibility
from aec.case_compiler import compile_authorization_request
from aec.coordinator import specialists
from aec.coordinator.models import ResearchRun
from aec.evidence.state_machine import initial_state as initial_gap_state
from aec.intelligence import scoring as intelligence_scoring
from aec.memory import connect as memory_connect
from aec.models import CaseRef, EvidenceGap
from aec.observation_plan import compile_observation_plan
from aec.orchestrator import lifecycle
from aec.queue import priority as queue_priority
from aec.review import queue as review_queue
from aec.surface import adapter as surface_adapter

#: Adapter refusals that mean the input itself is malformed.
_MALFORMED_ADAPTER_CODES = frozenset({
    "INVALID_INPUT", "MISSING_ENDPOINT", "MISSING_ASSET",
})

#: Adapter refusals that mean the category is the problem.
_CATEGORY_ADAPTER_CODES = frozenset({
    "MISSING_CATEGORY", "UNKNOWN_CATEGORY",
})


def _canonical(candidates: Sequence[Any]) -> str:
    plain = [dict(item) if isinstance(item, Mapping) else item
             for item in candidates]
    return json.dumps(plain, sort_keys=True, separators=(",", ":"))


def _failure(ref: str, kind: str, detail: str) -> dict[str, str]:
    return {"ref": ref, "kind": kind, "detail": detail[:500]}


def _skip(ref: str, reason: str) -> dict[str, str]:
    return {"ref": ref, "reason": reason}


def _state_reason(case_id: str, state: str, reason: str) -> dict[str, str]:
    return {"case_id": case_id, "state": state, "reason": reason}


def _review_history(context: Any) -> dict[str, Any]:
    if hasattr(context, "to_dict"):
        document = context.to_dict()
    elif isinstance(context, Mapping):
        document = dict(context)
    else:
        document = {}
    return {
        "duplicates": list(document.get("duplicates", [])),
        "related_patterns": len(document.get("related_patterns", [])),
    }


def run_research(candidates: Sequence[Any],
                 memories: Mapping[str, Any] | None = None) -> ResearchRun:
    """Drive candidates through the offline lifecycle. Never raises."""
    supplied = list(candidates)
    held_memories: Mapping[str, Any] = memories if isinstance(
        memories, Mapping) else {}
    canonical = _canonical(supplied)
    snapshot = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    run_id = "run-" + snapshot[:12]

    seen_ids: set[str] = set()
    cases_created: list[str] = []
    cases_skipped: list[dict[str, str]] = []
    case_entries: list[dict[str, Any]] = []
    assignments: list[dict[str, Any]] = []
    plans_generated: list[str] = []
    authorization_states: dict[str, str] = {}
    evidence_states: dict[str, str] = {}
    review_items: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    state_reasons: list[dict[str, str]] = []
    queue_items: list[dict[str, Any]] = []
    order = 0

    for position, raw in enumerate(supplied):
        ref = f"input[{position}]"
        try:
            outcome = surface_adapter.adapt_record(raw)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            failures.append(_failure(ref, "MALFORMED_CANDIDATE", str(exc)))
            continue
        if not outcome.ok:
            code = outcome.refusal_code or "INVALID_INPUT"
            if code in _MALFORMED_ADAPTER_CODES:
                failures.append(_failure(
                    ref, "MALFORMED_CANDIDATE",
                    f"adapter refused: {code}"))
            else:
                failures.append(_failure(
                    ref, "UNSUPPORTED_CATEGORY",
                    f"adapter refused: {code}"))
            continue
        draft = outcome.draft
        assert draft is not None
        ref = draft.candidate_id
        if ref in seen_ids:
            cases_skipped.append(_skip(ref, "DUPLICATE_CANDIDATE"))
            continue
        seen_ids.add(ref)
        try:
            context = memory_connect.find_related(held_memories, draft.to_dict())
            summary = memory_connect.history_summary(context)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            failures.append(_failure(ref, "MEMORY_FAILURE", str(exc)))
            continue
        if summary.get("researched"):
            cases_skipped.append(_skip(ref, "PRIOR_RESEARCH"))
            continue
        priority = intelligence_scoring.prioritize(draft.to_dict(), summary)
        assignment = assignment_rules.assign(draft.to_dict())
        staffed = specialists.specialize(
            assignment.to_dict(), draft.to_dict(), prior=summary)
        assignments.append(staffed.to_dict())
        try:
            gap = EvidenceGap.build(
                tuple(draft.evidence_gap.get("required", ())),
                tuple(draft.evidence_gap.get("missing", ())),
            )
            kwargs = surface_adapter.to_case_kwargs(draft)
            kwargs["evidence_gap"] = gap
            case = CaseRef(**kwargs)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            failures.append(_failure(ref, "INVALID_DRAFT", str(exc)))
            continue
        record = lifecycle.intake(case)
        order += 1
        selected = lifecycle.mark_selected(record, order)
        if not selected.ok:
            failures.append(_failure(
                ref, "INVALID_DRAFT",
                selected.refusal_code or "selection refused"))
            continue
        record = selected.record
        state_reasons.append(_state_reason(
            record.case_id, "SELECTED", f"intake accepted case; selection order {order}"))
        cases_created.append(record.case_id)
        steps_count = 0
        missing = list(gap.missing)
        draft_outcome = compile_authorization_request(case)
        if not draft_outcome.ok:
            gap_code = draft_outcome.refusal_code or "draft refused"
            kind = ("MISSING_GAP" if draft_outcome.refusal_code in
                    {"MISSING_EVIDENCE_GAP", "GAP_COMPLETE"} else "INVALID_DRAFT")
            failures.append(_failure(ref, kind, gap_code))
            review_items.append(review_queue.build_review_item({
                "case_id": record.case_id,
                "reason": "DRAFT_INVALID",
                "current_state": record.state,
                "evidence_state": record.evidence_state or "WAITING_EVIDENCE",
                "missing_evidence": missing,
                "research_history": _review_history(context),
            }).to_dict())
            queue_items.append({
                "case_id": record.case_id,
                "risk_category": f"RESEARCH_{draft.research_category.upper()}",
                "evidence_state": "WAITING_EVIDENCE",
                "planned_cost": 0,
                "selection_order": order,
            })
            case_entries.append(_case_entry(
                draft, priority, staffed, record, steps_count, [],
                missing, summary))
            continue
        request = draft_outcome.request
        assert request is not None
        plan_outcome = compile_observation_plan(request)
        if not plan_outcome.ok:
            failures.append(_failure(
                ref, "INVALID_PLAN",
                plan_outcome.refusal_code or "plan refused"))
            review_items.append(review_queue.build_review_item({
                "case_id": record.case_id,
                "reason": "PLAN_INVALID",
                "current_state": record.state,
                "evidence_state": record.evidence_state or "WAITING_EVIDENCE",
                "missing_evidence": missing,
                "research_history": _review_history(context),
            }).to_dict())
            queue_items.append({
                "case_id": record.case_id,
                "risk_category": f"RESEARCH_{draft.research_category.upper()}",
                "evidence_state": "WAITING_EVIDENCE",
                "planned_cost": 0,
                "selection_order": order,
            })
            case_entries.append(_case_entry(
                draft, priority, staffed, record, steps_count, [],
                missing, summary))
            continue
        plan = plan_outcome.plan
        assert plan is not None
        attached = lifecycle.attach_plan(record, plan)
        if not attached.ok:
            failures.append(_failure(
                ref, "INVALID_PLAN",
                attached.refusal_code or "attach refused"))
            continue
        record = attached.record
        plans_generated.append(plan.plan_id)
        steps_count = len(plan.steps)
        step_summaries = [
            {"step_id": step.step_id, "purpose": step.purpose,
             "endpoint": step.endpoint}
            for step in plan.steps
        ]
        state_reasons.append(_state_reason(
            record.case_id, "PLANNED",
            f"plan {plan.plan_id} with {steps_count} steps attached"))
        decision = check_authorization_eligibility(plan)
        if decision.decision != "ALLOW":
            failures.append(_failure(
                ref, "GATE_REFUSAL", decision.reason_code))
            authorization_states[record.case_id] = "REFUSE"
            review_items.append(review_queue.build_review_item({
                "case_id": record.case_id,
                "reason": "AUTHORIZATION_REFUSED",
                "current_state": record.state,
                "evidence_state": record.evidence_state or "WAITING_EVIDENCE",
                "missing_evidence": missing,
                "research_history": _review_history(context),
            }).to_dict())
            state_reasons.append(_state_reason(
                record.case_id, record.state,
                f"gate refused: {decision.reason_code}"))
            queue_items.append({
                "case_id": record.case_id,
                "risk_category": f"RESEARCH_{draft.research_category.upper()}",
                "evidence_state": "WAITING_EVIDENCE",
                "planned_cost": steps_count,
                "selection_order": order,
            })
            case_entries.append(_case_entry(
                draft, priority, staffed, record, steps_count, step_summaries,
                missing, summary))
            continue
        authorized = lifecycle.record_authorized(record, decision)
        if not authorized.ok:
            failures.append(_failure(
                ref, "GATE_REFUSAL",
                authorized.refusal_code or "authorize refused"))
            continue
        record = authorized.record
        authorization_states[record.case_id] = "ALLOW"
        state_reasons.append(_state_reason(
            record.case_id, "AUTHORIZED_PLAN",
            f"gate allowed plan {plan.plan_id}"))
        gap_state = initial_gap_state(record.case_id)
        routed = lifecycle.route_evidence(record, gap_state)
        if not routed.ok:
            failures.append(_failure(
                ref, "QUEUE_FAILURE",
                routed.refusal_code or "route refused"))
            continue
        record = routed.record
        evidence_states[record.case_id] = record.evidence_state
        state_reasons.append(_state_reason(
            record.case_id, record.evidence_state,
            "no artifacts collected offline; evidence still outstanding"))
        review_items.append(review_queue.build_review_item({
            "case_id": record.case_id,
            "reason": "EVIDENCE_INCOMPLETE",
            "current_state": record.state,
            "evidence_state": record.evidence_state,
            "missing_evidence": missing,
            "research_history": _review_history(context),
        }).to_dict())
        queue_items.append({
            "case_id": record.case_id,
            "risk_category": f"RESEARCH_{draft.research_category.upper()}",
            "evidence_state": record.evidence_state,
            "planned_cost": steps_count,
            "selection_order": order,
        })
        case_entries.append(_case_entry(
            draft, priority, staffed, record, steps_count, step_summaries,
            missing, summary))

    queue_snapshot: dict[str, Any] | None = None
    try:
        if queue_items:
            built = queue_priority.build_queue(queue_items)
            queue_snapshot = built.to_dict()
    except Exception as exc:  # noqa: BLE001 - recorded, never raised
        failures.append(_failure(run_id, "QUEUE_FAILURE", str(exc)))

    allow_count = sum(1 for state in authorization_states.values()
                      if state == "ALLOW")
    refuse_count = sum(1 for state in authorization_states.values()
                       if state == "REFUSE")
    completion_summary = {
        "candidates_processed": len(supplied),
        "cases_created": len(cases_created),
        "cases_skipped": len(cases_skipped),
        "plans_generated": len(plans_generated),
        "authorizations": {"ALLOW": allow_count, "REFUSE": refuse_count},
        "evidence": {
            state: sum(1 for value in evidence_states.values() if value == state)
            for state in sorted(set(evidence_states.values()))
        },
        "review_items": len(review_items),
        "failures": len(failures),
    }
    return ResearchRun(
        run_id=run_id,
        input_snapshot=snapshot,
        candidates_processed=len(supplied),
        cases_created=tuple(cases_created),
        cases_skipped=tuple(cases_skipped),
        cases=tuple(case_entries),
        assignments=tuple(assignments),
        plans_generated=tuple(plans_generated),
        authorization_states=authorization_states,
        evidence_states=evidence_states,
        review_items=tuple(review_items),
        failures=tuple(failures),
        state_reasons=tuple(state_reasons),
        queue_snapshot=queue_snapshot,
        completion_summary=completion_summary,
    )


def _case_entry(draft: Any, priority: Any, staffed: Any, record: Any,
                steps_count: int, step_summaries: list[dict[str, str]],
                missing: list[str],
                summary: Mapping[str, Any]) -> dict[str, Any]:
    parameters = draft.parameters if isinstance(
        draft.parameters, tuple) else tuple(draft.parameters or ())
    return {
        "case_id": record.case_id,
        "candidate_id": draft.candidate_id,
        "category": draft.research_category,
        "asset": draft.asset,
        "endpoint": draft.endpoint,
        "parameter": parameters[0] if parameters else "",
        "technology": list(draft.technology),
        "specialist": staffed.specialist,
        "band": priority.band,
        "score": int(priority.score),
        "state": record.state,
        "evidence_state": record.evidence_state,
        "plan_id": record.plan_id,
        "steps": [dict(step) for step in step_summaries],
        "step_count": steps_count,
        "missing": list(missing),
        "prior": dict(summary),
    }


def serialize_run(run: ResearchRun) -> str:
    """Stable JSON bytes for a run (sorted keys, compact separators)."""
    try:
        return json.dumps(run.to_dict(), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"run is not serializable: {exc}") from exc
