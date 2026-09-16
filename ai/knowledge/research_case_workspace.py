"""Stage R76 deterministic research case workspace (aggregation state).

R70-R75 each answer one question about an investigation. R76 gives Watch one
coherent, bounded representation of that investigation:

    "Where exactly are we in this research case?"

It is an **aggregation/state layer only**. It is not a planner, not an
intelligence layer and not a new authority: it never re-runs or re-derives a
stage, and it never changes a stage's output.

Authorities (each stays authoritative for its own output and is consumed
read-only):

- R70 action -> ``action``
- R71 acquisition plan -> ``acquisition``
- R72 readiness record -> ``readiness``
- R73 feedback iteration -> ``feedback``
- R74 evidence intake -> ``evidence``
- R75 provenance/conflict -> ``provenance``

One correlated R70 action maps to exactly one case; hypotheses that R70
correlated are never split. Case identity is deterministic (program + action
ref + gap id, slugged) and never uses Mongo ids or timestamps.

Hard boundaries encoded here:

- Research workflow state only: case status (`ACTIVE`,
  `WAITING_FOR_EVIDENCE`, `READY_FOR_HUMAN_REVIEW`, `STOPPED`) is never a
  security verdict. `READY_FOR_HUMAN_REVIEW` does not mean a vulnerability
  exists; no `CONFIRMED`/`VULNERABLE`/`EXPLOITABLE` state exists.
- Fail closed: unknown action refs, mismatched program/gap/hypotheses and
  orphan readiness/feedback/provenance/intake inputs raise a bounded
  ``ResearchCaseError``; missing stages are never manufactured.
- No conflict resolution: R75 conflict output is exposed as counts and
  requirement kinds; the case never chooses a winner and never alters
  readiness because of a conflict.
- Bounded snapshot: references plus bounded summaries and counts only; raw
  evidence, URLs, IPs, Mongo ids, credentials, tokens, request bodies and
  payloads never enter a case. Inputs are never mutated.
- Deterministic: stable case ids, stable iteration ordering, no timestamps,
  no randomness; repeated runs are byte-identical.
- Pure and offline: no I/O, no network, no HTTP client, no socket, no
  subprocess, no shell, no LLM, no Mongo, no target interaction, no
  execution, no authorization semantics.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ai.knowledge.research_evidence_intake import (
    STATUS_NOT_PROVIDED,
)
from ai.knowledge.research_outcome_planner import SAFETY_BLOCK

RULE_VERSION = "r76-1"

MAX_HISTORY_DEFAULT = 8
MAX_HISTORY_HARD = 32
MAX_CASES = 8
MAX_KINDS = 8
MAX_REFS = 8
MAX_TEXT_CHARS = 320
MAX_PROGRAM_CHARS = 64
MAX_CASE_ID_CHARS = 96

# ---------------------------------------------------------------------------
# Closed case-status vocabulary (research workflow state only)
# ---------------------------------------------------------------------------

CASE_ACTIVE = "ACTIVE"
CASE_WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
CASE_READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
CASE_STOPPED = "STOPPED"

CASE_STATUSES: tuple[str, ...] = (
    CASE_ACTIVE,
    CASE_WAITING_FOR_EVIDENCE,
    CASE_READY_FOR_HUMAN_REVIEW,
    CASE_STOPPED,
)

# ---------------------------------------------------------------------------
# Closed stopping-reason vocabulary
# ---------------------------------------------------------------------------

STOPPING_NONE = ""
STOPPING_BASIS_REMOVED = "RESEARCH_BASIS_REMOVED"
STOPPING_DECISION_COMPLETE = "DECISION_EVIDENCE_COMPLETE"
STOPPING_CONFLICT = "CONFLICT_REQUIRES_HUMAN_REVIEW"
STOPPING_ACQUISITION_UNAVAILABLE = "ACQUISITION_UNAVAILABLE"

STOPPING_REASONS: tuple[str, ...] = (
    STOPPING_NONE,
    STOPPING_BASIS_REMOVED,
    STOPPING_DECISION_COMPLETE,
    STOPPING_CONFLICT,
    STOPPING_ACQUISITION_UNAVAILABLE,
)

# ---------------------------------------------------------------------------
# Closed failure codes
# ---------------------------------------------------------------------------

ERROR_MALFORMED_STAGE_INPUT = "MALFORMED_STAGE_INPUT"
ERROR_UNKNOWN_ACTION_REF = "UNKNOWN_ACTION_REF"
ERROR_MISSING_ACQUISITION_PLAN = "MISSING_ACQUISITION_PLAN"
ERROR_MISSING_READINESS_RECORD = "MISSING_READINESS_RECORD"
ERROR_MISSING_FEEDBACK_ITERATION = "MISSING_FEEDBACK_ITERATION"
ERROR_GAP_MISMATCH = "GAP_MISMATCH"
ERROR_PROGRAM_MISMATCH = "PROGRAM_MISMATCH"
ERROR_HYPOTHESIS_MISMATCH = "HYPOTHESIS_MISMATCH"
ERROR_ORPHAN_READINESS = "ORPHAN_READINESS"
ERROR_ORPHAN_FEEDBACK = "ORPHAN_FEEDBACK"
ERROR_ORPHAN_PROVENANCE = "ORPHAN_PROVENANCE"
ERROR_ORPHAN_INTAKE = "ORPHAN_INTAKE"
ERROR_SENSITIVE_CASE_INPUT = "SENSITIVE_CASE_INPUT"
ERROR_LIMIT_INVALID = "LIMIT_INVALID"

CASE_ERROR_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_STAGE_INPUT,
    ERROR_UNKNOWN_ACTION_REF,
    ERROR_MISSING_ACQUISITION_PLAN,
    ERROR_MISSING_READINESS_RECORD,
    ERROR_MISSING_FEEDBACK_ITERATION,
    ERROR_GAP_MISMATCH,
    ERROR_PROGRAM_MISMATCH,
    ERROR_HYPOTHESIS_MISMATCH,
    ERROR_ORPHAN_READINESS,
    ERROR_ORPHAN_FEEDBACK,
    ERROR_ORPHAN_PROVENANCE,
    ERROR_ORPHAN_INTAKE,
    ERROR_SENSITIVE_CASE_INPUT,
    ERROR_LIMIT_INVALID,
)

_URL_RE = re.compile(r"://")
_MONGO_ID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*\S+"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


class ResearchCaseError(ValueError):
    """Deterministic, secret-free R76 case failure."""

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


def _program_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())[:MAX_PROGRAM_CHARS]
    if not text:
        raise ResearchCaseError(
            ERROR_MALFORMED_STAGE_INPUT, "program is required"
        )
    if (
        _URL_RE.search(text)
        or _MONGO_ID_RE.search(text)
        or _IPV4_RE.search(text)
        or _SECRET_RE.search(text)
    ):
        raise ResearchCaseError(
            ERROR_SENSITIVE_CASE_INPUT, "program contains sensitive data"
        )
    return text


def _slug(value: object, limit: int) -> str:
    text = _SLUG_RE.sub("-", _text(value).lower()).strip("-")
    return text[:limit]


def case_id_for(program: object, action_ref: object, gap_id: object) -> str:
    """Deterministic, bounded, dateless case identity."""

    program_part = _slug(program, 24) or "unknown"
    action_part = _slug(action_ref, 16) or "unknown"
    gap_part = _slug(gap_id, 40) or "unknown"
    return f"case-{program_part}-{action_part}-{gap_part}"[:MAX_CASE_ID_CHARS]


def _limit_value(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResearchCaseError(ERROR_LIMIT_INVALID, "limit must be an integer")
    if value < 1:
        raise ResearchCaseError(ERROR_LIMIT_INVALID, "limit must be >= 1")
    return min(value, MAX_HISTORY_HARD)


# ---------------------------------------------------------------------------
# Stage selection (read-only)
# ---------------------------------------------------------------------------


def _action_items(action_plan: object) -> list[Mapping]:
    return _mapping_items(_block(action_plan).get("actions"))


def _plan_items(acquisition_plan: object) -> list[Mapping]:
    return _mapping_items(_block(acquisition_plan).get("plans"))


def _readiness_items(readiness_plan: object) -> list[Mapping]:
    return _mapping_items(_block(readiness_plan).get("records"))


def _iteration_items(iteration_plan: object) -> list[Mapping]:
    return _mapping_items(_block(iteration_plan).get("iterations"))


def _find(
    items: Sequence[Mapping], *, action_ref: str = "", plan_ref: str = ""
) -> Mapping | None:
    for item in items:
        if action_ref and _text(item.get("action_ref")) == action_ref:
            return item
        if plan_ref and _text(item.get("plan_ref")) == plan_ref:
            return item
    return None


def _case_hypotheses(
    action: Mapping, plan: Mapping, record: Mapping, iteration: Mapping
) -> list[str]:
    groups = [
        _bounded_strings(action.get("hypothesis_refs"), MAX_REFS, 16),
        _bounded_strings(plan.get("hypothesis_refs"), MAX_REFS, 16),
        _bounded_strings(record.get("hypothesis_refs"), MAX_REFS, 16),
        _bounded_strings(iteration.get("hypothesis_refs"), MAX_REFS, 16),
    ]
    first = groups[0]
    for group in groups[1:]:
        if sorted(group) != sorted(first):
            raise ResearchCaseError(
                ERROR_HYPOTHESIS_MISMATCH,
                "stage outputs reference different hypotheses",
            )
    if not first:
        raise ResearchCaseError(
            ERROR_MALFORMED_STAGE_INPUT, "case has no hypotheses"
        )
    return first


def _effective_stages(
    readiness_plan: object,
    iteration_plan: object,
    evidence_intake: object,
    plan_ref: str,
) -> tuple[Mapping, Mapping]:
    """Prefer the post-intake R72/R73 projections when they exist."""

    readiness = _block(readiness_plan)
    iteration = _block(iteration_plan)
    intake = _block(evidence_intake)
    reevaluation = _block(intake.get("reevaluation"))
    if reevaluation:
        after = reevaluation.get("readiness_after")
        if isinstance(after, Mapping) and _readiness_items(after):
            readiness = after
        feedback = reevaluation.get("feedback")
        if isinstance(feedback, Mapping) and _iteration_items(feedback):
            iteration = feedback
    record = _find(_readiness_items(readiness), plan_ref=plan_ref)
    feedback = _find(_iteration_items(iteration), plan_ref=plan_ref)
    if record is None:
        raise ResearchCaseError(
            ERROR_ORPHAN_READINESS, "no readiness record for the plan"
        )
    if feedback is None:
        raise ResearchCaseError(
            ERROR_ORPHAN_FEEDBACK, "no feedback iteration for the plan"
        )
    return record, feedback


def _evidence_summary(record: Mapping) -> dict:
    entries = _mapping_items(record.get("required_evidence"))
    available = [
        entry
        for entry in entries
        if _upper(entry.get("status")) == "AVAILABLE"
    ]
    missing = [
        entry for entry in entries if _upper(entry.get("status")) == "MISSING"
    ]
    decision_missing = [
        entry for entry in missing if _upper(entry.get("requirement_class")) == "DECISION"
    ]
    return {
        "required_count": len(entries),
        "available_count": len(available),
        "missing_count": len(missing),
        "decision_missing_count": len(decision_missing),
        "available_requirement_kinds": _bounded_strings(
            [entry.get("requirement_kind") for entry in available],
            MAX_KINDS,
            64,
        ),
        "missing_requirement_kinds": _bounded_strings(
            [entry.get("requirement_kind") for entry in missing],
            MAX_KINDS,
            64,
        ),
    }


def _case_status(
    record: Mapping,
    feedback: Mapping,
    provenance_review: bool,
) -> tuple[str, str]:
    next_iteration = _upper(feedback.get("next_iteration"))
    decision = _upper(record.get("decision_state"))
    sufficiency = _upper(record.get("sufficiency_state"))
    hypothesis_state = _upper(feedback.get("current_state"))
    feedback_state = _upper(feedback.get("feedback_state"))
    reason = _upper(feedback.get("reason"))

    if next_iteration == "STOP":
        if reason in ("CONTRADICTING_EVIDENCE", "EVIDENCE_INVALIDATED"):
            return CASE_STOPPED, STOPPING_BASIS_REMOVED
        return CASE_STOPPED, STOPPING_DECISION_COMPLETE
    if decision == "READY_FOR_HUMAN_REVIEW" or next_iteration == "HUMAN_REVIEW":
        if reason == "ACQUISITION_UNAVAILABLE":
            return CASE_READY_FOR_HUMAN_REVIEW, STOPPING_ACQUISITION_UNAVAILABLE
        return CASE_READY_FOR_HUMAN_REVIEW, STOPPING_DECISION_COMPLETE
    if provenance_review:
        return CASE_READY_FOR_HUMAN_REVIEW, STOPPING_CONFLICT
    if sufficiency == "PARTIALLY_SUFFICIENT" or feedback_state in (
        "EVIDENCE_GAP_REDUCED",
        "NEW_SUPPORTING_EVIDENCE",
    ) or hypothesis_state in ("REFINE", "WEAKEN"):
        return CASE_ACTIVE, STOPPING_NONE
    return CASE_WAITING_FOR_EVIDENCE, STOPPING_NONE


# ---------------------------------------------------------------------------
# Case construction
# ---------------------------------------------------------------------------


def _build_current(
    action: Mapping,
    plan: Mapping,
    record: Mapping,
    feedback: Mapping,
    program: str,
    accepted_items: Sequence[Mapping],
    rejected_count: int,
    provenance_records: Sequence[Mapping],
    intake_meta: Mapping,
) -> dict:
    action_ref = _text(action.get("action_id"))
    plan_ref = _text(plan.get("plan_id"))
    readiness_ref = _text(record.get("readiness_id"))
    iteration_ref = _text(feedback.get("iteration_id"))
    gap_id = _upper(action.get("gap_id"))
    if _upper(plan.get("gap_id")) != gap_id or _upper(record.get("gap_id")) != gap_id:
        raise ResearchCaseError(ERROR_GAP_MISMATCH, "gap ids do not match")
    if _upper(feedback.get("gap_id")) != gap_id:
        raise ResearchCaseError(ERROR_GAP_MISMATCH, "gap ids do not match")

    case_refs = set(
        _bounded_strings(feedback.get("hypothesis_refs"), MAX_REFS, 16)
    )
    for entry in accepted_items:
        if _text(entry.get("hypothesis_ref")) not in case_refs:
            raise ResearchCaseError(
                ERROR_ORPHAN_INTAKE,
                "accepted evidence does not belong to the case",
            )
    provenance_conflicts = [
        entry
        for entry in provenance_records
        if _upper(entry.get("conflict_state")) == "CONFLICTING"
    ]
    provenance_review = any(
        bool(entry.get("human_review_required"))
        for entry in provenance_records
    )
    status, stopping_reason = _case_status(
        record, feedback, provenance_review
    )
    evidence = _evidence_summary(record)
    return {
        "case_id": case_id_for(program, action_ref, gap_id),
        "case_version": RULE_VERSION,
        "program": program,
        "action_ref": action_ref,
        "hypothesis_refs": list(feedback.get("hypothesis_refs") or ()),
        "hypothesis_count": int(feedback.get("hypothesis_count") or 0)
        or len(feedback.get("hypothesis_refs") or ()),
        "category": _upper(record.get("category")) or _upper(action.get("category")),
        "gap_id": gap_id,
        "status": status,
        "stopping_reason": stopping_reason,
        "action": {
            "action_ref": action_ref,
            "priority": _upper(action.get("priority")),
            "objective": _text(action.get("objective"))[:MAX_TEXT_CHARS],
        },
        "acquisition": {
            "plan_ref": plan_ref,
            "acquisition_status": _upper(record.get("acquisition_status")),
            "method": _upper(plan.get("acquisition_method")),
            "sources": _bounded_strings(
                plan.get("acquisition_sources"), MAX_KINDS, 64
            ),
            "step_count": len(_mapping_items(plan.get("acquisition_steps"))),
        },
        "readiness": {
            "readiness_ref": readiness_ref,
            "sufficiency_state": _upper(record.get("sufficiency_state")),
            "decision_state": _upper(record.get("decision_state")),
            "blocking_codes": _bounded_strings(
                record.get("blocking_codes"), MAX_KINDS, 64
            ),
            "decision_basis": _upper(
                _block(record.get("decision_basis")).get("code")
            ),
        },
        "feedback": {
            "iteration_ref": iteration_ref,
            "feedback_state": _upper(feedback.get("feedback_state")),
            "hypothesis_state": _upper(feedback.get("current_state")),
            "next_iteration": _upper(feedback.get("next_iteration")),
            "reason": _upper(feedback.get("reason")),
            "delta_count": len(_mapping_items(feedback.get("evidence_delta"))),
        },
        "evidence": {
            **evidence,
            "intake_state": _upper(intake_meta.get("package_status")),
            "accepted_evidence_count": len(accepted_items),
            "rejected_evidence_count": rejected_count,
        },
        "provenance": {
            "state": _upper(intake_meta.get("provenance_state")),
            "record_count": len(provenance_records),
            "conflict_count": len(provenance_conflicts),
            "conflicting_requirement_kinds": _bounded_strings(
                [
                    entry.get("requirement_kind")
                    for entry in provenance_conflicts
                ],
                MAX_KINDS,
                64,
            ),
            "human_review_required": provenance_review,
        },
        "human_review_required": bool(
            provenance_review
            or status == CASE_READY_FOR_HUMAN_REVIEW
        ),
        "iteration_count": 1,
        "current_iteration": {
            "iteration_number": 1,
            "plan_ref": plan_ref,
            "readiness_ref": readiness_ref,
            "iteration_ref": iteration_ref,
            "sufficiency_state": _upper(record.get("sufficiency_state")),
            "decision_state": _upper(record.get("decision_state")),
            "feedback_state": _upper(feedback.get("feedback_state")),
            "hypothesis_state": _upper(feedback.get("current_state")),
            "next_iteration": _upper(feedback.get("next_iteration")),
            "reason": _upper(feedback.get("reason")),
            "accepted_evidence_count": len(accepted_items),
            "conflict_count": len(provenance_conflicts),
            "status": status,
            "stopping_reason": stopping_reason,
        },
        "history": [],
        "history_truncated": False,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _intake_meta(
    evidence_intake: object, evidence_provenance: object
) -> dict:
    intake = _block(evidence_intake)
    provenance = _block(evidence_provenance)
    return {
        "package_status": _upper(intake.get("package_status"))
        or STATUS_NOT_PROVIDED,
        "provenance_state": _upper(
            provenance.get("package_status")
            or intake.get("package_status")
        )
        or STATUS_NOT_PROVIDED,
    }


def _select_case_inputs(
    action: Mapping,
    evidence_intake: object,
    evidence_provenance: object,
    *,
    attribute_rejections: bool,
) -> tuple[list[Mapping], int, list[Mapping]]:
    refs = set(
        _bounded_strings(action.get("hypothesis_refs"), MAX_REFS, 16)
    )
    intake = _block(evidence_intake)
    accepted = [
        entry
        for entry in _mapping_items(intake.get("accepted_items"))
        if _text(entry.get("hypothesis_ref")) in refs
    ]
    rejections = _mapping_items(intake.get("rejections"))
    package_rejections = _mapping_items(intake.get("package_rejections"))
    rejected_count = (
        len(rejections) + len(package_rejections)
        if attribute_rejections
        else 0
    )
    provenance = _block(evidence_provenance)
    records = [
        entry
        for entry in _mapping_items(provenance.get("records"))
        if _text(entry.get("hypothesis_ref")) in refs
        or not _text(entry.get("hypothesis_ref"))
    ] if attribute_rejections else [
        entry
        for entry in _mapping_items(provenance.get("records"))
        if _text(entry.get("hypothesis_ref")) in refs
    ]
    return accepted, rejected_count, records


def build_research_cases(
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    iteration_plan: object = None,
    *,
    program: object = None,
    evidence_intake: object = None,
    evidence_provenance: object = None,
    limit: int = MAX_HISTORY_DEFAULT,
) -> list[dict]:
    """One bounded case per R70 action (input order); fail closed."""

    history_limit = _limit_value(limit, MAX_HISTORY_DEFAULT)
    program_text = _program_text(program)
    actions = _action_items(action_plan)[:MAX_CASES]
    if not actions:
        raise ResearchCaseError(
            ERROR_MALFORMED_STAGE_INPUT, "no R70 actions supplied"
        )
    if evidence_provenance is not None and evidence_intake is None:
        provenance = _block(evidence_provenance)
        if _mapping_items(provenance.get("records")) or _mapping_items(
            provenance.get("conflicts")
        ):
            raise ResearchCaseError(
                ERROR_ORPHAN_PROVENANCE,
                "provenance supplied without a matching intake result",
            )
    single_case = len(actions) == 1
    intake_meta = _intake_meta(evidence_intake, evidence_provenance)
    cases: list[dict] = []
    for action in actions:
        action_ref = _text(action.get("action_id"))
        if not action_ref:
            raise ResearchCaseError(
                ERROR_MALFORMED_STAGE_INPUT, "action without action_id"
            )
        plan = _find(_plan_items(acquisition_plan), action_ref=action_ref)
        if plan is None:
            raise ResearchCaseError(
                ERROR_MISSING_ACQUISITION_PLAN,
                "no acquisition plan for the action",
            )
        plan_ref = _text(plan.get("plan_id"))
        record, feedback = _effective_stages(
            readiness_plan, iteration_plan, evidence_intake, plan_ref
        )
        if _text(record.get("action_ref")) != action_ref:
            raise ResearchCaseError(
                ERROR_ORPHAN_READINESS,
                "readiness record does not belong to the action",
            )
        if _text(feedback.get("action_ref")) != action_ref:
            raise ResearchCaseError(
                ERROR_ORPHAN_FEEDBACK,
                "feedback iteration does not belong to the action",
            )
        _case_hypotheses(action, plan, record, feedback)
        accepted, rejected_count, provenance_records = _select_case_inputs(
            action,
            evidence_intake,
            evidence_provenance,
            attribute_rejections=single_case,
        )
        case = _build_current(
            action,
            plan,
            record,
            feedback,
            program_text,
            accepted,
            rejected_count,
            provenance_records,
            intake_meta,
        )
        entry = dict(case["current_iteration"])
        entry["status"] = case["status"]
        entry["stopping_reason"] = case["stopping_reason"]
        case["current_iteration"] = dict(entry)
        case["history"] = [dict(entry)]
        case["iteration_count"] = 1
        case["history_truncated"] = False
        case["history_limit"] = history_limit
        cases.append(case)
    return cases[:MAX_CASES]


def build_research_case(
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    iteration_plan: object = None,
    *,
    program: object = None,
    action_ref: object = None,
    evidence_intake: object = None,
    evidence_provenance: object = None,
    limit: int = MAX_HISTORY_DEFAULT,
) -> dict:
    """Single-case convenience wrapper around :func:`build_research_cases`."""

    cases = build_research_cases(
        action_plan,
        acquisition_plan,
        readiness_plan,
        iteration_plan,
        program=program,
        evidence_intake=evidence_intake,
        evidence_provenance=evidence_provenance,
        limit=limit,
    )
    if action_ref is None:
        if len(cases) != 1:
            raise ResearchCaseError(
                ERROR_MALFORMED_STAGE_INPUT,
                "action_ref is required when multiple cases exist",
            )
        return cases[0]
    wanted = _text(action_ref)
    for case in cases:
        if case["action_ref"] == wanted:
            return case
    raise ResearchCaseError(
        ERROR_UNKNOWN_ACTION_REF, "action_ref not found in R70 actions"
    )


def update_research_case(
    case: object = None,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    iteration_plan: object = None,
    *,
    program: object = None,
    evidence_intake: object = None,
    evidence_provenance: object = None,
) -> dict:
    """Append one bounded iteration to an existing case (identity preserved)."""

    block = _block(case)
    case_id = _text(block.get("case_id"))
    if not case_id:
        raise ResearchCaseError(
            ERROR_MALFORMED_STAGE_INPUT, "existing case is required"
        )
    identity_program = _text(block.get("program"))
    if program is None:
        program = identity_program
    program_text = _program_text(program)
    if identity_program and program_text != identity_program:
        raise ResearchCaseError(
            ERROR_PROGRAM_MISMATCH, "update program differs from the case"
        )
    old_action_ref = _text(block.get("action_ref"))
    old_gap_id = _upper(block.get("gap_id"))
    old_refs = sorted(
        _bounded_strings(block.get("hypothesis_refs"), MAX_REFS, 16)
    )

    action = None
    for item in _action_items(action_plan):
        if _text(item.get("action_id")) == old_action_ref:
            action = item
            break
    if action is None:
        raise ResearchCaseError(
            ERROR_UNKNOWN_ACTION_REF, "case action is not in the update"
        )
    if _upper(action.get("gap_id")) != old_gap_id:
        raise ResearchCaseError(ERROR_GAP_MISMATCH, "update gap differs")

    cases = build_research_cases(
        {"actions": [dict(action)]},
        acquisition_plan,
        readiness_plan,
        iteration_plan,
        program=program_text,
        evidence_intake=evidence_intake,
        evidence_provenance=evidence_provenance,
        limit=_limit_value(block.get("history_limit"), MAX_HISTORY_DEFAULT),
    )
    current = cases[0]
    if sorted(current["hypothesis_refs"]) != old_refs:
        raise ResearchCaseError(
            ERROR_HYPOTHESIS_MISMATCH, "update hypotheses differ"
        )
    if case_id_for(program_text, old_action_ref, old_gap_id) != case_id:
        raise ResearchCaseError(
            ERROR_MALFORMED_STAGE_INPUT, "case identity is inconsistent"
        )

    history = [
        dict(entry)
        for entry in _mapping_items(block.get("history"))
    ]
    iteration_count = int(block.get("iteration_count") or len(history)) + 1
    new_entry = dict(current["current_iteration"])
    new_entry["iteration_number"] = iteration_count
    history.append(new_entry)
    history_limit = _limit_value(
        block.get("history_limit"), MAX_HISTORY_DEFAULT
    )
    truncated = iteration_count > history_limit
    if len(history) > history_limit:
        history = history[-history_limit:]

    updated = dict(current)
    updated["case_id"] = case_id
    updated["iteration_count"] = iteration_count
    updated["history"] = history
    updated["history_truncated"] = truncated
    updated["history_limit"] = history_limit
    updated["current_iteration"] = dict(history[-1])
    return updated


def summarize_research_case(case: object = None) -> dict:
    """Bounded, JSON-compatible case summary."""

    block = _block(case)
    evidence = _block(block.get("evidence"))
    provenance = _block(block.get("provenance"))
    readiness = _block(block.get("readiness"))
    feedback = _block(block.get("feedback"))
    return {
        "case_id": _text(block.get("case_id")),
        "case_version": _upper(block.get("case_version")),
        "program": _text(block.get("program")),
        "status": _upper(block.get("status")),
        "stopping_reason": _upper(block.get("stopping_reason")),
        "category": _upper(block.get("category")),
        "gap_id": _upper(block.get("gap_id")),
        "hypothesis_refs": _bounded_strings(
            block.get("hypothesis_refs"), MAX_REFS, 16
        ),
        "hypothesis_count": int(block.get("hypothesis_count") or 0),
        "sufficiency_state": _upper(readiness.get("sufficiency_state")),
        "decision_state": _upper(readiness.get("decision_state")),
        "feedback_state": _upper(feedback.get("feedback_state")),
        "hypothesis_state": _upper(feedback.get("hypothesis_state")),
        "next_iteration": _upper(feedback.get("next_iteration")),
        "available_count": int(evidence.get("available_count") or 0),
        "missing_count": int(evidence.get("missing_count") or 0),
        "decision_missing_count": int(
            evidence.get("decision_missing_count") or 0
        ),
        "accepted_evidence_count": int(
            evidence.get("accepted_evidence_count") or 0
        ),
        "rejected_evidence_count": int(
            evidence.get("rejected_evidence_count") or 0
        ),
        "conflict_count": int(provenance.get("conflict_count") or 0),
        "human_review_required": bool(block.get("human_review_required")),
        "iteration_count": int(block.get("iteration_count") or 0),
        "history_truncated": bool(block.get("history_truncated")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def summarize_research_cases(cases: object = None) -> dict:
    """Bounded workspace summary over a list of cases."""

    items = _mapping_items(cases)
    status_bands = {status: 0 for status in CASE_STATUSES}
    for case in items:
        status = _upper(case.get("status"))
        if status in status_bands:
            status_bands[status] += 1
    return {
        "rule_version": RULE_VERSION,
        "case_count": len(items),
        "covered_hypotheses": sum(
            int(case.get("hypothesis_count") or 0) for case in items
        ),
        "status_bands": status_bands,
        "conflicts": sum(
            int(_block(case.get("provenance")).get("conflict_count") or 0)
            for case in items
        ),
        "human_review_required": any(
            bool(case.get("human_review_required")) for case in items
        ),
        "top_case_id": _text(items[0].get("case_id")) if items else "",
        "top_status": _upper(items[0].get("status")) if items else "",
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "MAX_HISTORY_DEFAULT",
    "MAX_HISTORY_HARD",
    "MAX_CASES",
    "MAX_KINDS",
    "MAX_REFS",
    "MAX_TEXT_CHARS",
    "CASE_ACTIVE",
    "CASE_WAITING_FOR_EVIDENCE",
    "CASE_READY_FOR_HUMAN_REVIEW",
    "CASE_STOPPED",
    "CASE_STATUSES",
    "STOPPING_NONE",
    "STOPPING_BASIS_REMOVED",
    "STOPPING_DECISION_COMPLETE",
    "STOPPING_CONFLICT",
    "STOPPING_ACQUISITION_UNAVAILABLE",
    "STOPPING_REASONS",
    "CASE_ERROR_CODES",
    "ERROR_MALFORMED_STAGE_INPUT",
    "ERROR_UNKNOWN_ACTION_REF",
    "ERROR_MISSING_ACQUISITION_PLAN",
    "ERROR_MISSING_READINESS_RECORD",
    "ERROR_MISSING_FEEDBACK_ITERATION",
    "ERROR_GAP_MISMATCH",
    "ERROR_PROGRAM_MISMATCH",
    "ERROR_HYPOTHESIS_MISMATCH",
    "ERROR_ORPHAN_READINESS",
    "ERROR_ORPHAN_FEEDBACK",
    "ERROR_ORPHAN_PROVENANCE",
    "ERROR_ORPHAN_INTAKE",
    "ERROR_SENSITIVE_CASE_INPUT",
    "ERROR_LIMIT_INVALID",
    "ResearchCaseError",
    "case_id_for",
    "build_research_case",
    "build_research_cases",
    "update_research_case",
    "summarize_research_case",
    "summarize_research_cases",
]
