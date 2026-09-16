"""Stage R77 deterministic human research workbench (presentation only).

R70-R76 form the research state pipeline; R77 turns one R76 research case into
a concise, human-readable workbench that answers:

    "What do I need to know right now, what evidence do I have, what is
     missing, and what can I do next?"

R77 is presentation/workflow composition only. It is not a planner, not an
intelligence engine and not an execution engine. Authorities stay unchanged:

- R70 = research action
- R71 = evidence acquisition
- R72 = readiness
- R73 = feedback
- R74 = evidence intake
- R75 = provenance/conflict
- R76 = case state

R77 reads those outputs, copies bounded fields and never re-derives, re-ranks,
re-validates, resolves or executes anything. It produces no shell/scanner/exploit
instructions, no security verdict and no UI/backend changes.

Hard boundaries encoded here:

- Five primary sections only: ``current_state`` (what is happening),
  ``what_we_know``, ``what_is_missing``, ``what_to_do_next`` and
  ``human_review``; hypotheses, conflicts, history and safety are secondary.
- Deterministic: same case state -> byte-identical output; stable ordering,
  bounded strings, no timestamps, no randomness; inputs are never mutated.
- No invention: every value comes from an existing stage output; absent stage
  inputs produce explicit bounded absence states, never guesses.
- Safe data: only bounded codes, counts, canonical ``kind:value`` references
  and closed texts; raw URLs, IPs, Mongo ids, credentials, tokens, request
  bodies and payloads are never exposed.
- Conflicting evidence is displayed, never resolved; no winner is chosen.
- ``RESEARCH_WORKBENCH`` case actions (REVIEW_EVIDENCE, PROVIDE_EVIDENCE,
  REVIEW_CONFLICT, CONTINUE_RESEARCH, HUMAN_REVIEW, STOP) are workflow
  labels only and execute nothing. The external evidence path remains
  R74 -> R75 -> R73 -> R72 -> R76.
- Pure and offline: no I/O, no network, no HTTP, no socket, no subprocess, no
  shell, no LLM, no Mongo, no target interaction, no authorization semantics.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from ai.knowledge.research_outcome_planner import SAFETY_BLOCK

RULE_VERSION = "r77-1"

MAX_HISTORY = 8
MAX_STEPS = 3
MAX_HYPOTHESES = 8
MAX_KINDS = 8
MAX_REFS = 8
MAX_REASONS = 3
MAX_TEXT_CHARS = 320
MAX_ACQUISITION_STEPS = 3

# ---------------------------------------------------------------------------
# Closed workflow-action vocabulary (labels only; nothing executes)
# ---------------------------------------------------------------------------

ACTION_REVIEW_EVIDENCE = "REVIEW_EVIDENCE"
ACTION_PROVIDE_EVIDENCE = "PROVIDE_EVIDENCE"
ACTION_REVIEW_CONFLICT = "REVIEW_CONFLICT"
ACTION_CONTINUE_RESEARCH = "CONTINUE_RESEARCH"
ACTION_HUMAN_REVIEW = "HUMAN_REVIEW"
ACTION_STOP = "STOP"

WORKFLOW_ACTIONS: tuple[str, ...] = (
    ACTION_REVIEW_EVIDENCE,
    ACTION_PROVIDE_EVIDENCE,
    ACTION_REVIEW_CONFLICT,
    ACTION_CONTINUE_RESEARCH,
    ACTION_HUMAN_REVIEW,
    ACTION_STOP,
)

# ---------------------------------------------------------------------------
# Closed human-review reason vocabulary
# ---------------------------------------------------------------------------

REVIEW_READINESS = "READINESS_READY_FOR_HUMAN_REVIEW"
REVIEW_CONFLICT = "CONFLICT_REQUIRES_HUMAN_REVIEW"
REVIEW_FEEDBACK_STOP = "FEEDBACK_STOP"
REVIEW_ACQUISITION_UNAVAILABLE = "ACQUISITION_UNAVAILABLE"

HUMAN_REVIEW_REASONS: tuple[str, ...] = (
    REVIEW_READINESS,
    REVIEW_CONFLICT,
    REVIEW_FEEDBACK_STOP,
    REVIEW_ACQUISITION_UNAVAILABLE,
)

# ---------------------------------------------------------------------------
# Closed absence / provenance states for presentation
# ---------------------------------------------------------------------------

DETAIL_AVAILABLE = "AVAILABLE"
DETAIL_UNAVAILABLE = "UNAVAILABLE"

# ---------------------------------------------------------------------------
# Closed error codes
# ---------------------------------------------------------------------------

ERROR_MALFORMED_CASE = "MALFORMED_CASE"
ERROR_LIMIT_INVALID = "LIMIT_INVALID"

WORKBENCH_ERROR_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_CASE,
    ERROR_LIMIT_INVALID,
)

EXTERNAL_EVIDENCE_MESSAGE = (
    "External evidence must be supplied through the R74 intake contract."
)


class ResearchWorkbenchError(ValueError):
    """Deterministic, secret-free R77 workbench failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_strings(value: object, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item)[:item_limit]
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_reasons(value: object, limit: int = MAX_REASONS) -> list[str]:
    return [
        text
        for text in _bounded_strings(value, limit, MAX_TEXT_CHARS)
        if text
    ]


def _limit_value(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResearchWorkbenchError(
            ERROR_LIMIT_INVALID, "limit must be an integer"
        )
    if value < 1:
        raise ResearchWorkbenchError(ERROR_LIMIT_INVALID, "limit must be >= 1")
    return min(value, 32)


# ---------------------------------------------------------------------------
# Stage lookups (read-only)
# ---------------------------------------------------------------------------


def _outcome_by_ref(action_plan: object) -> dict[str, Mapping]:
    out: dict[str, Mapping] = {}
    for outcome in _mapping_items(_block(action_plan).get("outcomes")):
        ref = _text(outcome.get("hypothesis_ref"))
        if ref:
            out[ref] = outcome
    return out


def _action_by_ref(action_plan: object, action_ref: str) -> Mapping | None:
    for action in _mapping_items(_block(action_plan).get("actions")):
        if _text(action.get("action_id")) == action_ref:
            return action
    return None


def _plan_by_ref(acquisition_plan: object, plan_ref: str) -> Mapping | None:
    for plan in _mapping_items(_block(acquisition_plan).get("plans")):
        if _text(plan.get("plan_id")) == plan_ref:
            return plan
    return None


def _provenance_records(evidence_provenance: object) -> list[Mapping]:
    return _mapping_items(_block(evidence_provenance).get("records"))


def _provenance_conflicts(evidence_provenance: object) -> list[Mapping]:
    block = _block(evidence_provenance)
    conflicts = _mapping_items(block.get("conflicts"))
    if conflicts:
        return conflicts
    return [
        record
        for record in _provenance_records(block)
        if _upper(record.get("conflict_state")) == "CONFLICTING"
    ]


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _validate_case(case: object) -> dict:
    block = _block(case)
    if not _text(block.get("case_id")):
        raise ResearchWorkbenchError(
            ERROR_MALFORMED_CASE, "case_id is required"
        )
    if not _text(block.get("status")):
        raise ResearchWorkbenchError(
            ERROR_MALFORMED_CASE, "status is required"
        )
    for key in ("readiness", "feedback"):
        if not isinstance(block.get(key), Mapping):
            raise ResearchWorkbenchError(
                ERROR_MALFORMED_CASE, f"{key} is required"
            )
    return block


def _current_state(case: Mapping) -> dict:
    readiness = _block(case.get("readiness"))
    feedback = _block(case.get("feedback"))
    return {
        "status": _upper(case.get("status")),
        "stopping_reason": _upper(case.get("stopping_reason")),
        "readiness": _upper(readiness.get("sufficiency_state")),
        "decision": _upper(readiness.get("decision_state")),
        "feedback": _upper(feedback.get("feedback_state")),
        "hypothesis_state": _upper(feedback.get("hypothesis_state")),
        "next_iteration": _upper(feedback.get("next_iteration")),
        "human_review_required": bool(case.get("human_review_required")),
        "iteration_count": int(case.get("iteration_count") or 0),
        "history_truncated": bool(case.get("history_truncated")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _hypotheses(
    case: Mapping, action_plan: object
) -> list[dict]:
    outcomes = _outcome_by_ref(action_plan)
    hypothesis_state = _upper(
        _block(case.get("feedback")).get("hypothesis_state")
    )
    items: list[dict] = []
    for ref in _bounded_strings(case.get("hypothesis_refs"), MAX_HYPOTHESES, 16):
        outcome = outcomes.get(ref)
        if outcome is None:
            items.append(
                {
                    "hypothesis_ref": ref,
                    "title": "",
                    "category": "",
                    "priority": "",
                    "confidence": "",
                    "evidence_state": "",
                    "hypothesis_state": hypothesis_state,
                    "detail_state": DETAIL_UNAVAILABLE,
                }
            )
            continue
        items.append(
            {
                "hypothesis_ref": ref,
                "title": _text(outcome.get("title"))[:MAX_TEXT_CHARS],
                "category": _upper(outcome.get("category")),
                "priority": _upper(outcome.get("priority")),
                "confidence": _upper(outcome.get("confidence")),
                "evidence_state": _upper(outcome.get("evidence_state")),
                "hypothesis_state": hypothesis_state,
                "detail_state": DETAIL_AVAILABLE,
            }
        )
    return items


def _why_interesting(
    case: Mapping, action_plan: object
) -> dict:
    reasons: list[str] = []
    action = _action_by_ref(action_plan, _text(case.get("action_ref")))
    if isinstance(action, Mapping):
        reasons.extend(_bounded_reasons([action.get("reason")]))
    for ref in _bounded_strings(case.get("hypothesis_refs"), MAX_HYPOTHESES, 16):
        outcome = _outcome_by_ref(action_plan).get(ref)
        if isinstance(outcome, Mapping):
            reasons.extend(
                _bounded_reasons([outcome.get("reason_for_action")])
            )
    reasons = _bounded_reasons(reasons)
    return {
        "state": DETAIL_AVAILABLE if reasons else DETAIL_UNAVAILABLE,
        "reasons": reasons,
    }


def _what_we_know(
    case: Mapping,
    action_plan: object,
    evidence_provenance: object,
) -> dict:
    evidence = _block(case.get("evidence"))
    provenance = _block(case.get("provenance"))
    action = _action_by_ref(action_plan, _text(case.get("action_ref")))
    evidence_states = (
        _bounded_strings(action.get("evidence_states"), MAX_HYPOTHESES, 32)
        if isinstance(action, Mapping)
        else []
    )
    supporting_refs: list[str] = []
    for record in _provenance_records(evidence_provenance):
        if _upper(record.get("effect")) != "PROVIDES":
            continue
        supporting_refs.extend(
            _bounded_strings(record.get("evidence_refs"), MAX_REFS, 512)
        )
    return {
        "available_requirement_kinds": _bounded_strings(
            evidence.get("available_requirement_kinds"), MAX_KINDS, 64
        ),
        "available_count": int(evidence.get("available_count") or 0),
        "evidence_states": evidence_states,
        "accepted_evidence_count": int(
            evidence.get("accepted_evidence_count") or 0
        ),
        "provenance_state": _upper(provenance.get("state")),
        "supporting_evidence_refs": _bounded_strings(
            supporting_refs, MAX_REFS, 512
        ),
        "advisory": True,
        "research_only": True,
    }


def _missing_descriptions(
    case: Mapping, acquisition_plan: object
) -> list[dict]:
    plan = _plan_by_ref(
        acquisition_plan,
        _text(_block(case.get("acquisition")).get("plan_ref")),
    )
    if not isinstance(plan, Mapping):
        return []
    missing_kinds = set(
        _bounded_strings(
            _block(case.get("evidence")).get("missing_requirement_kinds"),
            MAX_KINDS,
            64,
        )
    )
    out: list[dict] = []
    for entry in _mapping_items(plan.get("required_evidence")):
        kind = _upper(entry.get("requirement_kind"))
        if kind not in missing_kinds:
            continue
        out.append(
            {
                "requirement_kind": kind,
                "description": _text(entry.get("description"))[:MAX_TEXT_CHARS],
            }
        )
        if len(out) >= MAX_KINDS:
            break
    return out


def _what_is_missing(
    case: Mapping, acquisition_plan: object
) -> dict:
    evidence = _block(case.get("evidence"))
    readiness = _block(case.get("readiness"))
    acquisition = _block(case.get("acquisition"))
    plan = _plan_by_ref(acquisition_plan, _text(acquisition.get("plan_ref")))
    expected_result = (
        _text(plan.get("expected_result"))[:MAX_TEXT_CHARS]
        if isinstance(plan, Mapping)
        else ""
    )
    stopping_condition = (
        _text(plan.get("stopping_condition"))[:MAX_TEXT_CHARS]
        if isinstance(plan, Mapping)
        else ""
    )
    return {
        "missing_requirement_kinds": _bounded_strings(
            evidence.get("missing_requirement_kinds"), MAX_KINDS, 64
        ),
        "missing_count": int(evidence.get("missing_count") or 0),
        "decision_missing_count": int(
            evidence.get("decision_missing_count") or 0
        ),
        "decision_critical_missing": _bounded_strings(
            readiness.get("blocking_codes"), MAX_KINDS, 64
        ),
        "acquisition_plan_ref": _upper(acquisition.get("plan_ref")),
        "requirement_details": _missing_descriptions(case, acquisition_plan),
        "expected_result": expected_result,
        "stopping_condition": stopping_condition,
        "detail_state": (
            DETAIL_AVAILABLE if expected_result else DETAIL_UNAVAILABLE
        ),
    }


def _acquisition_steps(plan: Mapping | None) -> list[dict]:
    if not isinstance(plan, Mapping):
        return []
    steps: list[dict] = []
    for entry in _mapping_items(plan.get("acquisition_steps")):
        steps.append(
            {
                "step": int(entry.get("step") or len(steps) + 1),
                "source": _upper(entry.get("source")),
                "expected": _text(entry.get("expected"))[:MAX_TEXT_CHARS],
            }
        )
        if len(steps) >= MAX_ACQUISITION_STEPS:
            break
    return steps


def _what_to_do_next(
    case: Mapping, action_plan: object, acquisition_plan: object
) -> dict:
    action = _action_by_ref(action_plan, _text(case.get("action_ref")))
    plan = _plan_by_ref(
        acquisition_plan,
        _text(_block(case.get("acquisition")).get("plan_ref")),
    )
    acquisition = _block(case.get("acquisition"))
    feedback = _block(case.get("feedback"))
    objective = _text(_block(case.get("action")).get("objective"))[
        :MAX_TEXT_CHARS
    ]
    return {
        "objective": objective,
        "recommended_action": (
            _text(action.get("recommended_action"))[:MAX_TEXT_CHARS]
            if isinstance(action, Mapping)
            else ""
        ),
        "acquisition_method": _upper(acquisition.get("method")),
        "sources": _bounded_strings(acquisition.get("sources"), MAX_KINDS, 64),
        "steps": _acquisition_steps(plan),
        "expected_result": (
            _text(plan.get("expected_result"))[:MAX_TEXT_CHARS]
            if isinstance(plan, Mapping)
            else ""
        ),
        "stopping_condition": (
            _text(plan.get("stopping_condition"))[:MAX_TEXT_CHARS]
            if isinstance(plan, Mapping)
            else ""
        ),
        "next_iteration": _upper(feedback.get("next_iteration")),
        "detail_state": (
            DETAIL_AVAILABLE if isinstance(action, Mapping) else DETAIL_UNAVAILABLE
        ),
    }


def _human_review(case: Mapping) -> dict:
    readiness = _block(case.get("readiness"))
    feedback = _block(case.get("feedback"))
    provenance = _block(case.get("provenance"))
    reasons: list[str] = []
    if (
        _upper(readiness.get("decision_state")) == "READY_FOR_HUMAN_REVIEW"
        or _upper(feedback.get("next_iteration")) == "HUMAN_REVIEW"
    ):
        reasons.append(REVIEW_READINESS)
    if bool(provenance.get("human_review_required")) or (
        int(provenance.get("conflict_count") or 0) > 0
    ):
        reasons.append(REVIEW_CONFLICT)
    if (
        _upper(case.get("status")) == "STOPPED"
        or _upper(feedback.get("next_iteration")) == "STOP"
    ):
        reasons.append(REVIEW_FEEDBACK_STOP)
    if _upper(case.get("stopping_reason")) == "ACQUISITION_UNAVAILABLE":
        reasons.append(REVIEW_ACQUISITION_UNAVAILABLE)
    reasons = [
        reason for reason in HUMAN_REVIEW_REASONS if reason in set(reasons)
    ]
    return {
        "required": bool(case.get("human_review_required")) or bool(reasons),
        "reasons": reasons[:MAX_REASONS],
        "case_stopping_reason": _upper(case.get("stopping_reason")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _next_steps(
    case: Mapping, human_review: Mapping
) -> list[dict]:
    evidence = _block(case.get("evidence"))
    readiness = _block(case.get("readiness"))
    feedback = _block(case.get("feedback"))
    acquisition = _block(case.get("acquisition"))
    decision_missing = int(evidence.get("decision_missing_count") or 0)
    available_count = int(evidence.get("available_count") or 0)
    conflicts = _block(case.get("provenance"))
    conflict_count = int(conflicts.get("conflict_count") or 0)
    conflict_kinds = _bounded_strings(
        conflicts.get("conflicting_requirement_kinds"), MAX_KINDS, 64
    )
    blocking = _bounded_strings(readiness.get("blocking_codes"), MAX_KINDS, 64)
    steps: list[dict] = []

    if decision_missing > 0:
        steps.append(
            {
                "action": ACTION_PROVIDE_EVIDENCE,
                "reason": "DECISION_CRITICAL_EVIDENCE_MISSING",
                "requirement_kinds": blocking or _bounded_strings(
                    evidence.get("missing_requirement_kinds"), MAX_KINDS, 64
                ),
            }
        )
    if conflict_count > 0:
        steps.append(
            {
                "action": ACTION_REVIEW_CONFLICT,
                "reason": REVIEW_CONFLICT,
                "requirement_kinds": conflict_kinds,
            }
        )
    if human_review.get("required"):
        steps.append(
            {
                "action": ACTION_HUMAN_REVIEW,
                "reason": (
                    human_review.get("reasons") or ["HUMAN_AUTHORITY_REQUIRED"]
                )[0],
                "requirement_kinds": [],
            }
        )
    if (
        _upper(feedback.get("next_iteration")) == "CONTINUE"
        and decision_missing > 0
    ):
        steps.append(
            {
                "action": ACTION_CONTINUE_RESEARCH,
                "reason": "ACQUISITION_CONTINUES",
                "requirement_kinds": [],
                "acquisition_plan_ref": _upper(acquisition.get("plan_ref")),
                "acquisition_method": _upper(acquisition.get("method")),
            }
        )
    elif available_count > 0 and decision_missing == 0:
        steps.append(
            {
                "action": ACTION_REVIEW_EVIDENCE,
                "reason": "AVAILABLE_EVIDENCE_TO_REVIEW",
                "requirement_kinds": _bounded_strings(
                    evidence.get("available_requirement_kinds"),
                    MAX_KINDS,
                    64,
                ),
            }
        )
    if _upper(case.get("status")) == "STOPPED":
        steps.append(
            {
                "action": ACTION_STOP,
                "reason": _upper(case.get("stopping_reason")) or "STOPPED",
                "requirement_kinds": [],
            }
        )
    seen: set[str] = set()
    unique: list[dict] = []
    for step in steps:
        action = step["action"]
        if action in seen:
            continue
        seen.add(action)
        unique.append(step)
    return unique[:MAX_STEPS]


def _conflicts(
    case: Mapping, evidence_provenance: object
) -> dict:
    provenance = _block(case.get("provenance"))
    preserved: list[dict] = []
    for conflict in _provenance_conflicts(evidence_provenance):
        preserved.append(
            {
                "requirement_kind": _upper(conflict.get("requirement_kind")),
                "relation_to_previous": _upper(
                    conflict.get("relation_to_previous")
                ),
                "existing_evidence_refs": _bounded_strings(
                    conflict.get("existing_evidence_refs"), MAX_REFS, 512
                ),
                "new_evidence_refs": _bounded_strings(
                    conflict.get("new_evidence_refs"), MAX_REFS, 512
                ),
            }
        )
        if len(preserved) >= MAX_KINDS:
            break
    return {
        "count": int(provenance.get("conflict_count") or 0),
        "requirement_kinds": _bounded_strings(
            provenance.get("conflicting_requirement_kinds"), MAX_KINDS, 64
        ),
        "human_review_required": bool(
            provenance.get("human_review_required")
        )
        or int(provenance.get("conflict_count") or 0) > 0,
        "preserved": preserved,
        "resolved": False,
    }


def _history(case: Mapping, limit: int) -> tuple[list[dict], bool]:
    entries = [
        dict(entry)
        for entry in _mapping_items(case.get("history"))
    ]
    truncated = bool(case.get("history_truncated")) or len(entries) > limit
    trimmed = entries[-limit:] if entries else []
    return trimmed, truncated


def build_research_workbench(
    case: object = None,
    *,
    action_plan: object = None,
    acquisition_plan: object = None,
    evidence_provenance: object = None,
    limit: int = MAX_HISTORY,
) -> dict:
    """Compose one bounded, human-readable workbench from an R76 case."""

    history_limit = _limit_value(limit, MAX_HISTORY)
    block = _validate_case(case)
    human_review = _human_review(block)
    history, history_truncated = _history(block, history_limit)
    hypotheses = _hypotheses(block, action_plan)
    category = _upper(block.get("category"))
    gap_id = _upper(block.get("gap_id"))
    return {
        "workbench_version": RULE_VERSION,
        "case_ref": _text(block.get("case_id")),
        "case_version": _upper(block.get("case_version")),
        "title": (
            f"{gap_id} research case" if gap_id else "research case"
        )[:MAX_TEXT_CHARS],
        "program": _text(block.get("program")),
        "category": category,
        "gap_id": gap_id,
        "current_state": _current_state(block),
        "hypotheses": hypotheses,
        "why_interesting": _why_interesting(block, action_plan),
        "what_we_know": _what_we_know(
            block, action_plan, evidence_provenance
        ),
        "what_is_missing": _what_is_missing(block, acquisition_plan),
        "what_to_do_next": _what_to_do_next(
            block, action_plan, acquisition_plan
        ),
        "next_steps": _next_steps(block, human_review),
        "human_review": human_review,
        "conflicts": _conflicts(block, evidence_provenance),
        "history": history,
        "history_truncated": history_truncated,
        "evidence_input": {
            "action": ACTION_PROVIDE_EVIDENCE,
            "accepted": False,
            "message": EXTERNAL_EVIDENCE_MESSAGE,
        },
        "workflow_actions": WORKFLOW_ACTIONS,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def build_workbench_set(
    cases: object = None,
    *,
    action_plan: object = None,
    acquisition_plan: object = None,
    evidence_provenance: object = None,
    limit: int = MAX_HISTORY,
) -> dict:
    """One workbench per R76 case, with a bounded summary."""

    items = _mapping_items(cases)
    history_limit = _limit_value(limit, MAX_HISTORY)
    workbenches: list[dict] = []
    for case in items:
        workbenches.append(
            build_research_workbench(
                case,
                action_plan=action_plan,
                acquisition_plan=acquisition_plan,
                evidence_provenance=evidence_provenance,
                limit=history_limit,
            )
        )
    return {
        "rule_version": RULE_VERSION,
        "status": "BUILT" if workbenches else "NO_CASES",
        "workbench_count": len(workbenches),
        "workbenches": workbenches,
        "summary": summarize_workbenches(workbenches),
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


def summarize_workbenches(workbenches: object = None) -> dict:
    """Bounded summary over a list of workbenches."""

    items = _mapping_items(workbenches)
    status_bands: dict[str, int] = {}
    for workbench in items:
        status = _upper(_block(workbench.get("current_state")).get("status"))
        if status:
            status_bands[status] = status_bands.get(status, 0) + 1
    return {
        "rule_version": RULE_VERSION,
        "workbench_count": len(items),
        "status_bands": status_bands,
        "human_review_required": any(
            bool(_block(workbench.get("human_review")).get("required"))
            for workbench in items
        ),
        "conflicts": sum(
            int(_block(workbench.get("conflicts")).get("count") or 0)
            for workbench in items
        ),
        "top_case_ref": _text(items[0].get("case_ref")) if items else "",
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "MAX_HISTORY",
    "MAX_STEPS",
    "MAX_HYPOTHESES",
    "MAX_KINDS",
    "MAX_REFS",
    "MAX_TEXT_CHARS",
    "MAX_ACQUISITION_STEPS",
    "ACTION_REVIEW_EVIDENCE",
    "ACTION_PROVIDE_EVIDENCE",
    "ACTION_REVIEW_CONFLICT",
    "ACTION_CONTINUE_RESEARCH",
    "ACTION_HUMAN_REVIEW",
    "ACTION_STOP",
    "WORKFLOW_ACTIONS",
    "REVIEW_READINESS",
    "REVIEW_CONFLICT",
    "REVIEW_FEEDBACK_STOP",
    "REVIEW_ACQUISITION_UNAVAILABLE",
    "HUMAN_REVIEW_REASONS",
    "DETAIL_AVAILABLE",
    "DETAIL_UNAVAILABLE",
    "WORKBENCH_ERROR_CODES",
    "ERROR_MALFORMED_CASE",
    "ERROR_LIMIT_INVALID",
    "EXTERNAL_EVIDENCE_MESSAGE",
    "ResearchWorkbenchError",
    "build_research_workbench",
    "build_workbench_set",
    "summarize_workbenches",
]
