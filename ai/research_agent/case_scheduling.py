"""Stage R92 deterministic case-aware research scheduling (pure engine).

R23 selects R22 research plans without any knowledge of the active research
case portfolio; after R91 the case acquisition ledger can state truthfully
what was already attempted, which requirements remain unresolved and which
controlled next action applies. R92 is the smallest deterministic bridge:

    R76 case + R91 acquisition ledger
        -> bounded case scheduling context
        -> per (case, plan) compatibility decision (SELECT / SKIP + reason)
        -> case-aware eligible plans for the existing R23 selection order

Authorities stay unchanged (R92 re-derives none of them):

- R76 case workspace -> case status / readiness / requirements universe
- R91 acquisition ledger -> per-requirement status, remaining sources,
  offline exhaustion, next action
- R22 plan projection -> plan identity, program/CVE binding, evidence targets
- R23 scheduler -> ordering, bounds, execution flow (R92 only filters)
- R77 workbench action vocabulary -> the only next-action vocabulary used

Hard boundaries encoded here:

- Deterministic and pure: no I/O, no network, no DNS, no LLM, no subprocess,
  no browser, no scanner, no database, no persistence, no clock, no
  randomness. The same inputs always produce byte-identical output.
- Fail closed: a malformed/contradictory case context raises a bounded
  :class:`CaseSchedulingError`; an invalid context supplied to selection can
  never authorize a plan (``MISSING_CASE_CONTEXT``).
- No inference: missing facts stay missing; a requirement that was attempted
  and exhausted is never treated as open; the next action comes from the R91
  ledger, never from this module.
- No scoring: eligibility is a closed set of reason codes over existing case
  state; no priority/confidence/value number is introduced or reinterpreted.
- No execution: a decision is research-planning only and never authorizes
  target interaction, scanning, payloads or confirmation. Every decision
  carries ``execution_authorized=False`` and
  ``authorization_state="NOT_AUTHORIZED"``.
- No evidence invention: only requirement identifiers, classes, statuses and
  bounded counts enter the context; evidence refs, observations, attempts and
  raw artifact contents are never copied.
"""

from __future__ import annotations

import re
from typing import Mapping

from ai.knowledge.research_acquisition_ledger import (
    ACTION_RANK,
    REQUIREMENT_STATUSES,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_ATTEMPTED_UNRESOLVED,
    STATUS_CONFLICT_REVIEW,
    STATUS_HUMAN_REQUIRED,
    STATUS_NOT_ATTEMPTED,
    STATUS_SATISFIED,
)
from ai.knowledge.research_case_workspace import (
    CASE_ACTIVE,
    CASE_READY_FOR_HUMAN_REVIEW,
    CASE_STATUSES,
    CASE_STOPPED,
    CASE_WAITING_FOR_EVIDENCE,
)
from ai.knowledge.research_workbench import (
    ACTION_CONTINUE_RESEARCH,
    ACTION_HUMAN_REVIEW,
    ACTION_PROVIDE_EVIDENCE,
    ACTION_REVIEW_CONFLICT,
    ACTION_REVIEW_EVIDENCE,
    ACTION_STOP,
    WORKFLOW_ACTIONS,
)

RULE_VERSION = "r92-1"

MAX_CONTEXTS = 32
MAX_REQUIREMENTS = 24
MAX_DECISIONS = 256
MAX_TEXT_CHARS = 240
MAX_COUNTS = 64

# ---------------------------------------------------------------------------
# Closed decision vocabulary
# ---------------------------------------------------------------------------

DECISION_SELECT = "SELECT"
DECISION_SKIP = "SKIP"

DECISIONS: tuple[str, ...] = (DECISION_SELECT, DECISION_SKIP)

#: Positive selection reason (mirrors the R86 ``REASON_ELIGIBLE`` convention:
#: an empty reason code means "no reason to skip").
REASON_ELIGIBLE = ""

# ---------------------------------------------------------------------------
# Closed skip/eligibility reason vocabulary
# ---------------------------------------------------------------------------

REASON_MALFORMED_PLAN = "MALFORMED_PLAN"
REASON_UNSAFE_ACTION = "UNSAFE_ACTION"
REASON_MISSING_CASE_CONTEXT = "MISSING_CASE_CONTEXT"
REASON_CASE_STOPPED = "CASE_STOPPED"
REASON_CASE_NOT_ACTIVE = "CASE_NOT_ACTIVE"
REASON_CASE_ALREADY_SATISFIED = "CASE_ALREADY_SATISFIED"
REASON_REQUIREMENT_ALREADY_SATISFIED = "REQUIREMENT_ALREADY_SATISFIED"
REASON_ACQUISITION_EXHAUSTED = "ACQUISITION_EXHAUSTED"
REASON_HUMAN_EVIDENCE_REQUIRED = "HUMAN_EVIDENCE_REQUIRED"
REASON_CONFLICT_REVIEW_REQUIRED = "CONFLICT_REVIEW_REQUIRED"
REASON_PLAN_NOT_RELEVANT = "PLAN_NOT_RELEVANT"
REASON_PLAN_ALREADY_ATTEMPTED = "PLAN_ALREADY_ATTEMPTED"

SCHEDULING_REASONS: tuple[str, ...] = (
    REASON_ELIGIBLE,
    REASON_MALFORMED_PLAN,
    REASON_UNSAFE_ACTION,
    REASON_MISSING_CASE_CONTEXT,
    REASON_CASE_STOPPED,
    REASON_CASE_NOT_ACTIVE,
    REASON_CASE_ALREADY_SATISFIED,
    REASON_REQUIREMENT_ALREADY_SATISFIED,
    REASON_ACQUISITION_EXHAUSTED,
    REASON_HUMAN_EVIDENCE_REQUIRED,
    REASON_CONFLICT_REVIEW_REQUIRED,
    REASON_PLAN_NOT_RELEVANT,
    REASON_PLAN_ALREADY_ATTEMPTED,
)

# ---------------------------------------------------------------------------
# Closed scheduling constraint vocabulary (derived R91 facts only)
# ---------------------------------------------------------------------------

CONSTRAINT_CASE_STOPPED = "CASE_STOPPED"
CONSTRAINT_CASE_READY_FOR_HUMAN_REVIEW = "CASE_READY_FOR_HUMAN_REVIEW"
CONSTRAINT_HUMAN_ACTION_REQUIRED = "HUMAN_ACTION_REQUIRED"
CONSTRAINT_HUMAN_EVIDENCE_REQUIRED = "HUMAN_EVIDENCE_REQUIRED"
CONSTRAINT_CONFLICT_REVIEW_REQUIRED = "CONFLICT_REVIEW_REQUIRED"
CONSTRAINT_OFFLINE_SOURCES_EXHAUSTED = "OFFLINE_SOURCES_EXHAUSTED"
CONSTRAINT_CASE_SATISFIED = "CASE_SATISFIED"
CONSTRAINT_DETERMINISTIC_RESEARCH_OPEN = "DETERMINISTIC_RESEARCH_OPEN"

SCHEDULING_CONSTRAINTS: tuple[str, ...] = (
    CONSTRAINT_CASE_STOPPED,
    CONSTRAINT_CASE_READY_FOR_HUMAN_REVIEW,
    CONSTRAINT_HUMAN_ACTION_REQUIRED,
    CONSTRAINT_HUMAN_EVIDENCE_REQUIRED,
    CONSTRAINT_CONFLICT_REVIEW_REQUIRED,
    CONSTRAINT_OFFLINE_SOURCES_EXHAUSTED,
    CONSTRAINT_CASE_SATISFIED,
    CONSTRAINT_DETERMINISTIC_RESEARCH_OPEN,
)

# ---------------------------------------------------------------------------
# Closed plan persistence-binding vocabulary
# ---------------------------------------------------------------------------

BOUND_BY_SAME_PLAN = "SAME_PLAN"
BOUND_BY_SAME_CVE = "SAME_CVE"

BINDING_MODES: tuple[str, ...] = (BOUND_BY_SAME_PLAN, BOUND_BY_SAME_CVE)

#: The R92 bridge table between the existing R22 evidence-target codes and the
#: existing R71/R72 requirement kinds. It mirrors the R87 deterministic
#: completion mapping (asset technology -> TECHNOLOGY_IDENTITY, asset
#: version -> VERSION_IDENTITY, component/plugin -> COMPONENT_BINDING) and is
#: deliberately minimal: codes with no existing requirement-kind counterpart
#: are not mapped, so they never authorize a requirement-specific skip.
TARGET_REQUIREMENT_KINDS: dict[str, str] = {
    "ASSET_TECHNOLOGY": "TECHNOLOGY_IDENTITY",
    "AFFECTED_TECHNOLOGY": "TECHNOLOGY_IDENTITY",
    "ASSET_COMPONENT": "COMPONENT_BINDING",
    "AFFECTED_COMPONENT": "COMPONENT_BINDING",
    "ASSET_VERSION": "VERSION_IDENTITY",
    "AFFECTED_VERSION": "VERSION_IDENTITY",
}

#: The same bridge for the R22 step vocabulary (real plans always carry
#: ``steps[]``; ``evidence_targets[]`` may be empty).
STEP_REQUIREMENT_KINDS: dict[str, str] = {
    "REVIEW_TECHNOLOGY_MATCH": "TECHNOLOGY_IDENTITY",
    "REVIEW_COMPONENT_MATCH": "COMPONENT_BINDING",
    "REVIEW_VERSION": "VERSION_IDENTITY",
}

#: Explicit non-research execution markers. A plan carrying any truthy marker
#: is never selected: scheduling must not become an execution authorization.
UNSAFE_PLAN_FLAGS: tuple[str, ...] = (
    "execution_authorized",
    "authorized_execution",
    "execute",
    "execution",
    "active_validation",
    "target_interaction",
)

#: Requirement-status precedence used to summarize a decision's acquisition
#: state (most blocking first). This is a projection order, not a score.
STATUS_PRECEDENCE: tuple[str, ...] = (
    STATUS_CONFLICT_REVIEW,
    STATUS_HUMAN_REQUIRED,
    STATUS_ATTEMPTED_NO_OBSERVATION,
    STATUS_ATTEMPTED_UNRESOLVED,
    STATUS_NOT_ATTEMPTED,
    STATUS_SATISFIED,
)

# ---------------------------------------------------------------------------
# Closed error codes
# ---------------------------------------------------------------------------

ERROR_MALFORMED_CASE_CONTEXT = "MALFORMED_CASE_CONTEXT"
ERROR_UNKNOWN_CASE_STATUS = "UNKNOWN_CASE_STATUS"
ERROR_CONTRADICTORY_CASE_CONTEXT = "CONTRADICTORY_CASE_CONTEXT"
ERROR_MALFORMED_LEDGER = "MALFORMED_LEDGER"
ERROR_UNKNOWN_NEXT_ACTION = "UNKNOWN_NEXT_ACTION"

CASE_SCHEDULING_ERROR_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_CASE_CONTEXT,
    ERROR_UNKNOWN_CASE_STATUS,
    ERROR_CONTRADICTORY_CASE_CONTEXT,
    ERROR_MALFORMED_LEDGER,
    ERROR_UNKNOWN_NEXT_ACTION,
)

_PLAN_ID_RE = re.compile(r"^r22-[0-9a-f]{16}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


class CaseSchedulingError(ValueError):
    """Deterministic, secret-free R92 scheduling failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Bounded helpers (same conventions as the previous stages)
# ---------------------------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _upper(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return _text(value, limit).upper()


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_list(value: object, limit: int, width: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item, width)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _plan_ref(value: object) -> str:
    text = _text(value, 64)
    return text if _PLAN_ID_RE.match(text) else ""


# ---------------------------------------------------------------------------
# Context normalization (selection-safe, fail closed)
# ---------------------------------------------------------------------------


def _normalize_requirements(value: object) -> list[dict] | None:
    """Bounded requirement projection, or None when malformed."""

    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        return None
    out: list[dict] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            return None
        kind = _upper(entry.get("requirement_kind"), 64)
        status = _upper(entry.get("status"), 32)
        if not kind or len(kind) > 64:
            return None
        if status not in REQUIREMENT_STATUSES:
            return None
        out.append(
            {
                "requirement_kind": kind,
                "requirement_class": _upper(
                    entry.get("requirement_class"), 16
                ),
                "status": status,
                "offline_exhausted": bool(entry.get("offline_exhausted")),
                "remaining_sources": _bounded_list(
                    entry.get("remaining_sources"), 4, 32
                ),
            }
        )
        if len(out) >= MAX_REQUIREMENTS:
            break
    return out


def _normalize_counts(value: object) -> dict:
    block = _block(value)
    keys = (
        "required",
        "satisfied",
        "missing",
        "decision_missing",
        "human_required",
        "attempted_no_observation",
        "attempted_unresolved",
        "not_attempted",
        "conflict_review",
    )
    return {
        key: min(max(_int(block.get(key), 0), 0), MAX_COUNTS) for key in keys
    }


def normalize_scheduling_context(context: object) -> dict | None:
    """Validate and bound an existing scheduling context, or None."""

    block = _block(context)
    case_ref = _text(block.get("case_ref"), 96)
    if not case_ref:
        return None
    case_status = _upper(block.get("case_status"), 40)
    if case_status not in CASE_STATUSES:
        return None
    next_action = _upper(block.get("next_action"), 40)
    if next_action not in WORKFLOW_ACTIONS:
        return None
    requirements = _normalize_requirements(block.get("requirements"))
    if requirements is None:
        return None
    return {
        "context_version": RULE_VERSION,
        "case_ref": case_ref,
        "case_version": _upper(block.get("case_version"), 16),
        "program": _text(block.get("program"), 64),
        "case_status": case_status,
        "readiness_state": _upper(block.get("readiness_state"), 40),
        "sufficiency_state": _upper(block.get("sufficiency_state"), 40),
        "next_action": next_action,
        "offline_sources_exhausted": bool(
            block.get("offline_sources_exhausted")
        ),
        "human_action_required": bool(block.get("human_action_required")),
        "iteration_count": max(_int(block.get("iteration_count"), 0), 0),
        "source_plan_ref": _plan_ref(block.get("source_plan_ref")),
        "source_cve": _upper(block.get("source_cve"), 32),
        "requirements": requirements,
        "counts": _normalize_counts(block.get("counts")),
        "scheduling_constraints": _bounded_list(
            block.get("scheduling_constraints"), 8, 48
        ),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _scheduling_constraints(
    status: str, next_action: str, counts: Mapping, ledger: Mapping
) -> list[str]:
    constraints: list[str] = []
    if status == CASE_STOPPED:
        constraints.append(CONSTRAINT_CASE_STOPPED)
    if status == CASE_READY_FOR_HUMAN_REVIEW:
        constraints.append(CONSTRAINT_CASE_READY_FOR_HUMAN_REVIEW)
    if bool(ledger.get("human_action_required")):
        constraints.append(CONSTRAINT_HUMAN_ACTION_REQUIRED)
    if next_action == ACTION_HUMAN_REVIEW or counts.get("human_required", 0) > 0:
        constraints.append(CONSTRAINT_HUMAN_EVIDENCE_REQUIRED)
    if (
        next_action == ACTION_REVIEW_CONFLICT
        or counts.get("conflict_review", 0) > 0
    ):
        constraints.append(CONSTRAINT_CONFLICT_REVIEW_REQUIRED)
    if bool(ledger.get("offline_sources_exhausted")):
        constraints.append(CONSTRAINT_OFFLINE_SOURCES_EXHAUSTED)
    if counts.get("missing", 0) == 0:
        constraints.append(CONSTRAINT_CASE_SATISFIED)
    if next_action == ACTION_CONTINUE_RESEARCH:
        constraints.append(CONSTRAINT_DETERMINISTIC_RESEARCH_OPEN)
    return constraints


def build_case_scheduling_context(
    case: object,
    *,
    acquisition_ledger: object,
    source_plan_ref: object = "",
    source_cve: object = "",
) -> dict:
    """Bounded, deterministic scheduling context for one persisted case.

    Consumes the R76 case and the R91 ledger only. Raises
    :class:`CaseSchedulingError` (fail closed) when the case identity, case
    status, ledger identity, ledger next action or ledger requirements are
    missing, malformed or contradictory. Never mutates its inputs and never
    copies evidence contents (refs/attempts/observations are excluded).
    """

    block = _block(case)
    case_id = _text(block.get("case_id"), 96)
    if not case_id:
        raise CaseSchedulingError(
            ERROR_MALFORMED_CASE_CONTEXT, "case_id is required"
        )
    status = _upper(block.get("status"), 40)
    if status not in CASE_STATUSES:
        raise CaseSchedulingError(
            ERROR_UNKNOWN_CASE_STATUS,
            "case status is not in the R76 vocabulary",
        )

    ledger = _block(acquisition_ledger)
    if not ledger:
        raise CaseSchedulingError(
            ERROR_MALFORMED_LEDGER, "acquisition ledger is required"
        )
    ledger_case_id = _text(ledger.get("case_id"), 96)
    if not ledger_case_id or ledger_case_id != case_id:
        raise CaseSchedulingError(
            ERROR_CONTRADICTORY_CASE_CONTEXT,
            "ledger case_id does not match the case",
        )
    next_action = _upper(ledger.get("next_action"), 40)
    if next_action not in WORKFLOW_ACTIONS:
        raise CaseSchedulingError(
            ERROR_UNKNOWN_NEXT_ACTION,
            "next action is not in the R77 vocabulary",
        )
    requirements = _normalize_requirements(ledger.get("requirements"))
    if requirements is None:
        raise CaseSchedulingError(
            ERROR_MALFORMED_LEDGER, "ledger requirements are malformed"
        )
    counts = _normalize_counts(ledger.get("counts"))
    readiness = _block(block.get("readiness"))

    context = {
        "context_version": RULE_VERSION,
        "case_ref": case_id,
        "case_version": _upper(block.get("case_version"), 16),
        "program": _text(block.get("program"), 64),
        "case_status": status,
        "readiness_state": _upper(readiness.get("decision_state"), 40),
        "sufficiency_state": _upper(readiness.get("sufficiency_state"), 40),
        "next_action": next_action,
        "offline_sources_exhausted": bool(
            ledger.get("offline_sources_exhausted")
        ),
        "human_action_required": bool(ledger.get("human_action_required")),
        "iteration_count": max(_int(ledger.get("iteration_count"), 0), 0),
        "source_plan_ref": _plan_ref(source_plan_ref),
        "source_cve": _upper(source_cve, 32),
        "requirements": requirements,
        "counts": counts,
        "scheduling_constraints": _scheduling_constraints(
            status, next_action, counts, ledger
        ),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }
    normalized = normalize_scheduling_context(context)
    if normalized is None:  # pragma: no cover - defensive self-check
        raise CaseSchedulingError(
            ERROR_MALFORMED_CASE_CONTEXT, "context failed normalization"
        )
    return normalized


# ---------------------------------------------------------------------------
# Plan -> requirement relevance (existing vocabularies only)
# ---------------------------------------------------------------------------


def plan_requirement_kinds(plan: object) -> list[str]:
    """Requirement kinds this plan can review (deterministic, bounded)."""

    block = _block(plan)
    kinds: list[str] = []
    for target in _mapping_items(block.get("evidence_targets")):
        kind = TARGET_REQUIREMENT_KINDS.get(_upper(target.get("code"), 48))
        if kind and kind not in kinds:
            kinds.append(kind)
    for step in _mapping_items(block.get("steps")):
        kind = STEP_REQUIREMENT_KINDS.get(_upper(step.get("code"), 48))
        if kind and kind not in kinds:
            kinds.append(kind)
    return kinds[:8]


def _most_restrictive(relevant: list[dict]) -> str:
    statuses = {entry["status"] for entry in relevant}
    for status in STATUS_PRECEDENCE:
        if status in statuses:
            return status
    return ""


def _decision(
    plan_id: str,
    case_id: str,
    *,
    decision: str,
    reason_code: str,
    reason: str,
    next_action: str = "",
    relevant: list[dict] | None = None,
    acquisition_state: str = "",
    deterministic_context: Mapping | None = None,
) -> dict:
    return {
        "rule_version": RULE_VERSION,
        "plan_id": plan_id,
        "case_id": case_id,
        "decision": decision,
        "reason_code": reason_code,
        "reason": _text(reason),
        "relevant_requirements": [dict(entry) for entry in (relevant or [])],
        "acquisition_state": acquisition_state,
        "next_action": next_action,
        "deterministic_context": dict(deterministic_context or {}),
        "execution_authorized": False,
        "authorization_state": "NOT_AUTHORIZED",
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _skip(
    plan_id: str,
    case_id: str,
    code: str,
    reason: str,
    **kwargs,
) -> dict:
    return _decision(
        plan_id,
        case_id,
        decision=DECISION_SKIP,
        reason_code=code,
        reason=reason,
        **kwargs,
    )


def _context_brief(context: Mapping) -> dict:
    counts = _block(context.get("counts"))
    return {
        "case_status": context.get("case_status", ""),
        "readiness_state": context.get("readiness_state", ""),
        "sufficiency_state": context.get("sufficiency_state", ""),
        "next_action": context.get("next_action", ""),
        "offline_sources_exhausted": bool(
            context.get("offline_sources_exhausted")
        ),
        "human_action_required": bool(context.get("human_action_required")),
        "missing": counts.get("missing", 0),
        "decision_missing": counts.get("decision_missing", 0),
    }


def evaluate_plan_compatibility(plan: object, context: object) -> dict:
    """One deterministic SELECT/SKIP decision for (plan, case context).

    Never raises: malformed plans/contexts fail closed with a bounded reason.
    First failure wins in this fixed order: plan identity, execution safety,
    case context validity, case status, ledger next action, requirement
    relevance/attempt state.
    """

    block = _block(plan)
    plan_id = _text(block.get("plan_id"), 64)
    if not plan_id or not _PLAN_ID_RE.match(plan_id):
        return _skip(
            plan_id,
            "",
            REASON_MALFORMED_PLAN,
            "plan is missing a valid plan_id",
        )

    if any(block.get(flag) for flag in UNSAFE_PLAN_FLAGS):
        return _skip(
            plan_id,
            "",
            REASON_UNSAFE_ACTION,
            "plan carries a non-research execution marker",
        )

    normalized = normalize_scheduling_context(context)
    if normalized is None:
        return _skip(
            plan_id,
            "",
            REASON_MISSING_CASE_CONTEXT,
            "case scheduling context is missing or malformed",
        )

    case_id = normalized["case_ref"]
    next_action = normalized["next_action"]
    brief = _context_brief(normalized)
    status = normalized["case_status"]

    if status == CASE_STOPPED:
        return _skip(
            plan_id,
            case_id,
            REASON_CASE_STOPPED,
            "case is stopped; no research is scheduled",
            next_action=next_action,
            deterministic_context=brief,
        )
    if status == CASE_READY_FOR_HUMAN_REVIEW:
        return _skip(
            plan_id,
            case_id,
            REASON_HUMAN_EVIDENCE_REQUIRED,
            "case is ready for human review; no research is scheduled",
            next_action=next_action,
            deterministic_context=brief,
        )
    if status not in (CASE_ACTIVE, CASE_WAITING_FOR_EVIDENCE):
        return _skip(
            plan_id,
            case_id,
            REASON_CASE_NOT_ACTIVE,
            "case status is not eligible for research scheduling",
            next_action=next_action,
            deterministic_context=brief,
        )

    action_reason = {
        ACTION_STOP: REASON_CASE_STOPPED,
        ACTION_REVIEW_CONFLICT: REASON_CONFLICT_REVIEW_REQUIRED,
        ACTION_HUMAN_REVIEW: REASON_HUMAN_EVIDENCE_REQUIRED,
        ACTION_REVIEW_EVIDENCE: REASON_CASE_ALREADY_SATISFIED,
        ACTION_PROVIDE_EVIDENCE: REASON_ACQUISITION_EXHAUSTED,
    }
    if next_action in action_reason:
        return _skip(
            plan_id,
            case_id,
            action_reason[next_action],
            f"ledger next action is {next_action}; deterministic research "
            "is not the remaining controlled action",
            next_action=next_action,
            deterministic_context=brief,
        )
    if next_action != ACTION_CONTINUE_RESEARCH:
        return _skip(
            plan_id,
            case_id,
            REASON_MISSING_CASE_CONTEXT,
            "ledger next action is not in the R77 vocabulary",
            next_action=next_action,
            deterministic_context=brief,
        )

    by_kind = {
        entry["requirement_kind"]: entry
        for entry in normalized["requirements"]
    }
    relevant = [
        by_kind[kind]
        for kind in plan_requirement_kinds(block)
        if kind in by_kind
    ]
    counts = normalized["counts"]

    if not relevant:
        if counts.get("missing", 0) == 0:
            return _skip(
                plan_id,
                case_id,
                REASON_CASE_ALREADY_SATISFIED,
                "case has no missing requirement; nothing to acquire",
                next_action=next_action,
                deterministic_context=brief,
            )
        return _skip(
            plan_id,
            case_id,
            REASON_PLAN_NOT_RELEVANT,
            "plan does not review any requirement of this case",
            next_action=next_action,
            deterministic_context=brief,
        )

    acquisition_state = _most_restrictive(relevant)
    open_kinds = [
        entry["requirement_kind"]
        for entry in relevant
        if entry["status"] == STATUS_NOT_ATTEMPTED
    ]
    if open_kinds:
        return _decision(
            plan_id,
            case_id,
            decision=DECISION_SELECT,
            reason_code=REASON_ELIGIBLE,
            reason=(
                "case has un-attempted requirement(s) this plan can review: "
                + ", ".join(open_kinds)
            ),
            next_action=next_action,
            relevant=relevant,
            acquisition_state=acquisition_state,
            deterministic_context=brief,
        )

    statuses = {entry["status"] for entry in relevant}
    if STATUS_CONFLICT_REVIEW in statuses:
        code = REASON_CONFLICT_REVIEW_REQUIRED
        reason = "conflicting evidence for this requirement needs human review"
    elif STATUS_HUMAN_REQUIRED in statuses:
        code = REASON_HUMAN_EVIDENCE_REQUIRED
        reason = "requirement is human-review-only and cannot be acquired"
    elif STATUS_ATTEMPTED_NO_OBSERVATION in statuses:
        code = REASON_ACQUISITION_EXHAUSTED
        reason = (
            "deterministic acquisition for this requirement was attempted "
            "with no observation"
        )
    elif STATUS_ATTEMPTED_UNRESOLVED in statuses:
        code = REASON_PLAN_ALREADY_ATTEMPTED
        reason = "this acquisition path was already attempted and remains unresolved"
    elif statuses == {STATUS_SATISFIED}:
        code = REASON_REQUIREMENT_ALREADY_SATISFIED
        reason = "the reviewed requirement is already satisfied"
    else:  # pragma: no cover - defensive fallback, fail closed
        code = REASON_PLAN_NOT_RELEVANT
        reason = "no un-attempted requirement this plan can review"

    return _skip(
        plan_id,
        case_id,
        code,
        reason,
        next_action=next_action,
        relevant=relevant,
        acquisition_state=acquisition_state,
        deterministic_context=brief,
    )


# ---------------------------------------------------------------------------
# Case-aware selection (bounded, deterministic)
# ---------------------------------------------------------------------------


def _bindings(
    plan: Mapping, contexts: list[dict]
) -> list[tuple[dict, str]]:
    plan_id = _text(plan.get("plan_id"), 64)
    cve = _upper(plan.get("cve_id"), 32)
    program = _text(plan.get("program"), 64)
    matches: list[tuple[dict, str]] = []
    for context in contexts:
        if context["source_plan_ref"] and context["source_plan_ref"] == plan_id:
            matches.append((context, BOUND_BY_SAME_PLAN))
            continue
        if (
            context["source_cve"]
            and context["source_cve"] == cve
            and context["program"]
            and context["program"] == program
        ):
            matches.append((context, BOUND_BY_SAME_CVE))
    return matches


def _case_attention(
    contexts: list[dict], decisions: list[dict]
) -> list[dict]:
    by_case: dict[str, dict] = {}
    for decision in decisions:
        case_id = decision.get("case_id") or ""
        if not case_id:
            continue
        row = by_case.get(case_id)
        if row is None:
            row = {"eligible_plan_ids": [], "reason_code": ""}
            by_case[case_id] = row
        if decision["decision"] == DECISION_SELECT:
            row["eligible_plan_ids"].append(decision["plan_id"])
        elif not row["reason_code"]:
            row["reason_code"] = decision["reason_code"]

    rows: list[dict] = []
    for context in contexts:
        counts = _block(context.get("counts"))
        row = by_case.get(context["case_ref"], {})
        eligible = sorted(set(row.get("eligible_plan_ids") or []))
        rows.append(
            {
                "case_id": context["case_ref"],
                "program": context["program"],
                "case_status": context["case_status"],
                "readiness_state": context["readiness_state"],
                "next_action": context["next_action"],
                "actionable": bool(eligible),
                "eligible_plan_ids": eligible,
                "reason_code": (
                    "" if eligible else (row.get("reason_code") or "")
                ),
                "missing": counts.get("missing", 0),
                "decision_missing": counts.get("decision_missing", 0),
                "offline_sources_exhausted": bool(
                    context["offline_sources_exhausted"]
                ),
                "human_action_required": bool(
                    context["human_action_required"]
                ),
            }
        )
    rows.sort(
        key=lambda row: (
            ACTION_RANK.get(row["next_action"], len(ACTION_RANK)),
            -row["decision_missing"],
            -row["missing"],
            row["case_id"],
        )
    )
    return rows[:MAX_CONTEXTS]


def select_case_aware_plans(
    plans: object,
    contexts: object = None,
) -> dict:
    """Deterministic case-aware eligibility over candidate R22 plans.

    Returns a bounded result with one decision per (plan, bound case) pair,
    a per-case attention projection ordered by the existing R91 action order,
    and the eligible plan ids (plans with at least one SELECT decision).
    Ordering/bounds of the final scheduled plans stay with the R23 scheduler.
    """

    raw_contexts = _mapping_items(contexts)
    valid: list[dict] = []
    malformed: list[dict] = []
    seen_cases: set[str] = set()
    for raw in raw_contexts[: MAX_CONTEXTS + 8]:
        normalized = normalize_scheduling_context(raw)
        if normalized is None:
            malformed.append(
                {
                    "case_ref": _text(
                        _block(raw).get("case_ref")
                        or _block(raw).get("case_id"),
                        96,
                    ),
                    "artifact": _text(_block(raw).get("artifact"), 128),
                    "reason_code": ERROR_MALFORMED_CASE_CONTEXT,
                }
            )
            continue
        if normalized["case_ref"] in seen_cases:
            continue
        seen_cases.add(normalized["case_ref"])
        valid.append(normalized)
        if len(valid) >= MAX_CONTEXTS:
            break

    plan_items = _mapping_items(plans)
    decisions: list[dict] = []
    eligible: list[str] = []
    unbound_plans = 0
    for plan in plan_items:
        plan_id = _text(plan.get("plan_id"), 64)
        if not plan_id or not _PLAN_ID_RE.match(plan_id):
            decisions.append(
                _skip(
                    plan_id,
                    "",
                    REASON_MALFORMED_PLAN,
                    "plan is missing a valid plan_id",
                )
            )
            continue
        matches = _bindings(plan, valid)
        if not matches:
            unbound_plans += 1
            decisions.append(
                _skip(
                    plan_id,
                    "",
                    REASON_MISSING_CASE_CONTEXT,
                    "plan is not bound to any persisted case context",
                )
            )
            continue
        selected_for_plan = False
        for context, bound_by in matches:
            decision = evaluate_plan_compatibility(plan, context)
            decision["bound_by"] = bound_by
            if decision["decision"] == DECISION_SELECT:
                selected_for_plan = True
            decisions.append(decision)
        if selected_for_plan and plan_id not in eligible:
            eligible.append(plan_id)

    decisions.sort(key=lambda item: (item["plan_id"], item["case_id"]))
    total_decisions = len(decisions)
    bounded = decisions[:MAX_DECISIONS]

    attention = _case_attention(valid, decisions)
    ordered_contexts = sorted(valid, key=lambda item: item["case_ref"])
    selected = sum(
        1 for item in bounded if item["decision"] == DECISION_SELECT
    )
    return {
        "rule_version": RULE_VERSION,
        "case_aware": True,
        "contexts": [
            {
                "case_ref": context["case_ref"],
                "program": context["program"],
                "case_status": context["case_status"],
                "readiness_state": context["readiness_state"],
                "next_action": context["next_action"],
                "offline_sources_exhausted": context[
                    "offline_sources_exhausted"
                ],
                "human_action_required": context["human_action_required"],
                "requirements": [
                    {
                        "requirement_kind": entry["requirement_kind"],
                        "requirement_class": entry["requirement_class"],
                        "status": entry["status"],
                        "offline_exhausted": entry["offline_exhausted"],
                    }
                    for entry in context["requirements"]
                ],
                "counts": dict(context["counts"]),
                "scheduling_constraints": list(
                    context["scheduling_constraints"]
                ),
            }
            for context in ordered_contexts
        ],
        "case_attention": attention,
        "decisions": bounded,
        "eligible_plan_ids": sorted(eligible),
        "malformed_contexts": malformed[:8],
        "summary": {
            "contexts": len(valid),
            "malformed_contexts": len(malformed),
            "plans": len(plan_items),
            "plans_eligible": len(eligible),
            "plans_unbound": unbound_plans,
            "decisions_total": total_decisions,
            "decisions": len(bounded),
            "decisions_truncated": total_decisions > len(bounded),
            "select_decisions": selected,
            "skip_decisions": len(bounded) - selected,
            "advisory": True,
            "research_only": True,
            "confirmation_state": "NOT_CONFIRMED",
        },
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "MAX_CONTEXTS",
    "MAX_REQUIREMENTS",
    "MAX_DECISIONS",
    "DECISION_SELECT",
    "DECISION_SKIP",
    "DECISIONS",
    "REASON_ELIGIBLE",
    "REASON_MALFORMED_PLAN",
    "REASON_UNSAFE_ACTION",
    "REASON_MISSING_CASE_CONTEXT",
    "REASON_CASE_STOPPED",
    "REASON_CASE_NOT_ACTIVE",
    "REASON_CASE_ALREADY_SATISFIED",
    "REASON_REQUIREMENT_ALREADY_SATISFIED",
    "REASON_ACQUISITION_EXHAUSTED",
    "REASON_HUMAN_EVIDENCE_REQUIRED",
    "REASON_CONFLICT_REVIEW_REQUIRED",
    "REASON_PLAN_NOT_RELEVANT",
    "REASON_PLAN_ALREADY_ATTEMPTED",
    "SCHEDULING_REASONS",
    "CONSTRAINT_CASE_STOPPED",
    "CONSTRAINT_CASE_READY_FOR_HUMAN_REVIEW",
    "CONSTRAINT_HUMAN_ACTION_REQUIRED",
    "CONSTRAINT_HUMAN_EVIDENCE_REQUIRED",
    "CONSTRAINT_CONFLICT_REVIEW_REQUIRED",
    "CONSTRAINT_OFFLINE_SOURCES_EXHAUSTED",
    "CONSTRAINT_CASE_SATISFIED",
    "CONSTRAINT_DETERMINISTIC_RESEARCH_OPEN",
    "SCHEDULING_CONSTRAINTS",
    "BOUND_BY_SAME_PLAN",
    "BOUND_BY_SAME_CVE",
    "BINDING_MODES",
    "TARGET_REQUIREMENT_KINDS",
    "STEP_REQUIREMENT_KINDS",
    "UNSAFE_PLAN_FLAGS",
    "CASE_SCHEDULING_ERROR_CODES",
    "CaseSchedulingError",
    "normalize_scheduling_context",
    "build_case_scheduling_context",
    "plan_requirement_kinds",
    "evaluate_plan_compatibility",
    "select_case_aware_plans",
]
