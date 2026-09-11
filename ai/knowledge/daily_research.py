"""Stage R26.3 deterministic daily research workflow (pure engine).

Derives a compact daily researcher workflow from the already-computed R26.2
Action Queue items: what to work on today, what is blocked, what is already
in progress, and what changed since a caller-supplied previous workflow.

Presentation/decision layer only: no new numeric score, no Money Score
modification, no persistence, no snapshots, no I/O, no network, no LLM, no
Mongo, no subprocess, no execution, no clock, no randomness.

Snapshots are external inputs: the caller supplies previous/current
structures; this module never reads or writes files.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ai.knowledge.opportunity_action import translate_blockers
from ai.schemas.daily_research import (
    CHANGE_TYPE_ORDER,
    CHANGE_TYPES,
    WORKFLOW_VERSION,
    DailyWorkflow,
    WorkflowChange,
)

DEFAULT_TOP_N = 5
MAX_TOP_N = 50

# Fixed field checks for compare_workflows (order = change-type order).
_FIELD_CHECKS: tuple[tuple[str, str, str], ...] = (
    ("CLASS_CHANGED", "opportunity_class", "opportunity class"),
    ("ACTION_CHANGED", "recommended_action", "recommended action"),
    ("MONEY_CHANGED", "money_score", "Money Score"),
    ("CONFIDENCE_CHANGED", "confidence", "confidence"),
    ("EVIDENCE_CHANGED", "evidence_quality", "evidence quality"),
)

RECOMMEND_CONTINUE = "Continue the active research session."
RECOMMEND_START_HIGH = "Start the highest-value research opportunity."
RECOMMEND_RESOLVE_BLOCKERS = (
    "Resolve asset-match blockers before spending research time."
)
RECOMMEND_REVIEW_OUTCOMES = (
    "Review completed research outcomes before starting additional work."
)
RECOMMEND_WORK_READY = "Work the ready research opportunities."
RECOMMEND_NONE = "No research opportunity currently requires action."


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean_items(items: Iterable[Any]) -> list[dict]:
    """Keep well-formed item mappings with a lead_id (fail-soft)."""

    out: list[dict] = []
    for item in items or ():
        if not isinstance(item, Mapping):
            continue
        if not str(item.get("lead_id") or "").strip():
            continue
        out.append(dict(item))
    return out


def build_top_opportunities(
    items: Iterable[Any], top_n: int = DEFAULT_TOP_N
) -> list[dict]:
    """Top-N deterministic opportunities (input order = R26.2 ranking)."""

    try:
        count = max(0, min(int(top_n), MAX_TOP_N))
    except (TypeError, ValueError):
        count = DEFAULT_TOP_N
    out: list[dict] = []
    for item in _clean_items(items)[:count]:
        out.append({
            "lead_id": str(_get(item, "lead_id") or ""),
            "cve_id": str(_get(item, "cve_id") or ""),
            "program": str(_get(item, "program") or ""),
            "opportunity_class": str(
                _get(item, "opportunity_class") or "DEFER"),
            "money_score": _coerce_int(_get(item, "money_score")),
            "priority": str(_get(item, "priority") or ""),
            "confidence": str(_get(item, "confidence") or "LOW"),
            "evidence_quality": str(
                _get(item, "evidence_quality") or "NONE"),
            "estimated_minutes": _coerce_int(
                _get(item, "estimated_minutes")),
            "current_status": str(
                _get(item, "current_status") or "DEFERRED"),
            "recommended_action": str(
                _get(item, "recommended_action") or "DEFER"),
            "why_now": [str(x) for x in _get(item, "why_now") or []],
            "blockers": [str(x) for x in _get(item, "blockers") or []],
            "next_step": str(_get(item, "next_step") or ""),
        })
    return out


def build_daily_plan(items: Iterable[Any]) -> list[dict]:
    """Today's research plan: READY items in existing R26.2 rank order."""

    plan: list[dict] = []
    for item in _clean_items(items):
        if str(_get(item, "current_status") or "").upper() != "READY":
            continue
        plan.append({
            "lead_id": str(_get(item, "lead_id") or ""),
            "cve_id": str(_get(item, "cve_id") or ""),
            "program": str(_get(item, "program") or ""),
            "recommended_action": str(
                _get(item, "recommended_action") or "DEFER"),
            "estimated_minutes": _coerce_int(
                _get(item, "estimated_minutes")),
            "reason": str(_get(item, "action_reason") or ""),
            "next_step": str(_get(item, "next_step") or ""),
        })
    return plan


def build_blocked_work(items: Iterable[Any]) -> list[dict]:
    """Blocked items with machine codes AND human explanations."""

    blocked: list[dict] = []
    for item in _clean_items(items):
        if str(_get(item, "current_status") or "").upper() != "BLOCKED":
            continue
        codes = [str(x) for x in _get(item, "blockers") or []]
        blocked.append({
            "lead_id": str(_get(item, "lead_id") or ""),
            "cve_id": str(_get(item, "cve_id") or ""),
            "program": str(_get(item, "program") or ""),
            "money_score": _coerce_int(_get(item, "money_score")),
            "blockers": codes,
            "blocker_explanations": translate_blockers(codes),
            "recommended_action": str(
                _get(item, "recommended_action") or "VERIFY_ASSET_MATCH"),
            "next_step": str(_get(item, "next_step") or ""),
        })
    return blocked


def build_in_progress_work(
    items: Iterable[Any],
    sessions_by_lead: Mapping[str, Any] | None = None,
) -> list[dict]:
    """Active R25.7 session detail for IN_PROGRESS leads (never starts one)."""

    sessions_by_lead = sessions_by_lead or {}
    out: list[dict] = []
    for item in _clean_items(items):
        if str(_get(item, "current_status") or "").upper() != "IN_PROGRESS":
            continue
        lead_id = str(_get(item, "lead_id") or "")
        sessions = sessions_by_lead.get(lead_id) or []
        if isinstance(sessions, Mapping):
            sessions = []  # summaries carry no per-session detail
        for session in sessions:
            if not isinstance(session, Mapping):
                continue
            status = str(session.get("status") or "").upper()
            if status != "IN_PROGRESS":
                continue
            out.append({
                "lead_id": lead_id,
                "cve_id": str(_get(item, "cve_id") or ""),
                "program": str(_get(item, "program") or ""),
                "session_id": str(session.get("session_id") or ""),
                "planned_minutes": _coerce_int(
                    session.get("planned_minutes")),
                "actual_minutes": _coerce_int(
                    session.get("actual_minutes")),
                "status": status,
                "recommended_action": str(
                    _get(item, "recommended_action") or "CONTINUE_RESEARCH"),
            })
    return out


def build_workflow_recommendations(summary: Mapping[str, Any]) -> list[str]:
    """Deterministic recommendations from existing structured counts only."""

    total = _coerce_int(_get(summary, "total_opportunities"))
    ready = _coerce_int(_get(summary, "ready"))
    blocked = _coerce_int(_get(summary, "blocked"))
    in_progress = _coerce_int(_get(summary, "in_progress"))
    completed = _coerce_int(_get(summary, "completed"))
    ready_high_value = bool(_get(summary, "ready_high_value"))
    has_terminal = bool(_get(summary, "has_terminal_outcomes"))

    if total <= 0:
        return [RECOMMEND_NONE]

    out: list[str] = []
    if in_progress > 0:
        out.append(RECOMMEND_CONTINUE)
    if ready > 0 and ready_high_value:
        out.append(RECOMMEND_START_HIGH)
    if blocked > 0 and blocked == total:
        out.append(RECOMMEND_RESOLVE_BLOCKERS)
    if completed > 0 or has_terminal:
        out.append(RECOMMEND_REVIEW_OUTCOMES)
    if ready > 0 and not ready_high_value:
        out.append(RECOMMEND_WORK_READY)
    if not out:
        out.append(RECOMMEND_NONE)
    return out


def build_daily_workflow(
    items: Iterable[Any],
    sessions_by_lead: Mapping[str, Any] | None = None,
    outcomes_by_lead: Mapping[str, Any] | None = None,
    changed_items: Iterable[Any] | None = None,
    top_n: int = DEFAULT_TOP_N,
) -> DailyWorkflow:
    """Compose the deterministic read-only daily workflow (never executes)."""

    cleaned = _clean_items(items)
    statuses = [
        str(_get(item, "current_status") or "DEFERRED").upper()
        for item in cleaned
    ]
    counts = {
        "ready": statuses.count("READY"),
        "blocked": statuses.count("BLOCKED"),
        "in_progress": statuses.count("IN_PROGRESS"),
        "deferred": statuses.count("DEFERRED"),
        "completed": statuses.count("COMPLETED"),
    }
    ready_high_value = any(
        str(_get(item, "current_status") or "").upper() == "READY"
        and str(_get(item, "opportunity_class") or "").upper() == "HIGH_VALUE"
        for item in cleaned
    )
    outcomes_by_lead = outcomes_by_lead or {}
    has_terminal = counts["completed"] > 0
    for item in cleaned:
        lead_id = str(_get(item, "lead_id") or "")
        outcome_status = str(
            _get(outcomes_by_lead.get(lead_id), "outcome_status")
            or _get(item, "outcome_status") or "NONE"
        ).upper()
        if outcome_status not in ("NONE", "", "IN_PROGRESS"):
            has_terminal = True
            break

    # changed_items are supplied pre-built (e.g. by compare_workflows) as
    # WorkflowChange-compatible dicts; validate the closed vocabulary.
    changes: list[dict] = []
    for entry in changed_items or ():
        if not isinstance(entry, Mapping):
            continue
        try:
            changes.append(
                WorkflowChange(**dict(entry)).model_dump(mode="json")
            )
        except ValueError:
            continue

    workflow = DailyWorkflow(
        workflow_version=WORKFLOW_VERSION,
        total_opportunities=len(cleaned),
        ready=counts["ready"],
        blocked=counts["blocked"],
        in_progress=counts["in_progress"],
        deferred=counts["deferred"],
        completed=counts["completed"],
        top_actions=build_daily_plan(cleaned),
        top_opportunities=build_top_opportunities(cleaned, top_n=top_n),
        blocked_items=build_blocked_work(cleaned),
        in_progress_items=build_in_progress_work(cleaned, sessions_by_lead),
        changed_items=changes,
        recommendations=build_workflow_recommendations({
            "total_opportunities": len(cleaned),
            **counts,
            "ready_high_value": ready_high_value,
            "has_terminal_outcomes": has_terminal,
        }),
        items=cleaned,
        research_only=True,
    )
    return workflow


# ---------------------------------------------------------------------------
# Comparison (pure; caller supplies previous/current structures)
# ---------------------------------------------------------------------------


def _extract_items(doc: Any, label: str) -> list[dict]:
    """Extract an item list from a workflow document (raises when malformed).

    Accepted shapes: a list of items, or a mapping containing one of
    ``items`` / ``top_opportunities`` / ``top_actions`` / ``blocked_items``
    as a list. No I/O is performed here.
    """

    if isinstance(doc, list):
        return _clean_items(doc)
    if isinstance(doc, Mapping):
        for key in ("items", "top_opportunities", "top_actions",
                    "blocked_items"):
            value = doc.get(key)
            if isinstance(value, list):
                return _clean_items(value)
        raise ValueError(
            f"malformed {label} workflow: no item list "
            "(items/top_opportunities/top_actions/blocked_items)"
        )
    raise ValueError(
        f"malformed {label} workflow: expected a mapping or list"
    )


def _item_map(items: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items:
        lead_id = str(_get(item, "lead_id") or "").strip()
        if lead_id:
            out.setdefault(lead_id, item)
    return out


def _summary_of(item: Mapping[str, Any]) -> dict:
    return {
        "cve_id": str(_get(item, "cve_id") or ""),
        "program": str(_get(item, "program") or ""),
        "opportunity_class": str(_get(item, "opportunity_class") or ""),
        "money_score": _coerce_int(_get(item, "money_score")),
        "recommended_action": str(
            _get(item, "recommended_action") or ""),
    }


def _session_state(item: Mapping[str, Any]) -> str:
    value = str(_get(item, "session_status") or "").strip().upper()
    if value:
        return value
    return ("IN_PROGRESS"
            if str(_get(item, "current_status") or "").upper()
            == "IN_PROGRESS" else "NONE")


def _outcome_state(item: Mapping[str, Any]) -> str:
    value = str(_get(item, "outcome_status") or "").strip().upper()
    if value:
        return value
    return ("COMPLETED"
            if str(_get(item, "current_status") or "").upper() == "COMPLETED"
            else "NONE")


def compare_workflows(previous: Any, current: Any) -> list[dict]:
    """Deterministic change detection between two caller-supplied workflows.

    Detects only the closed vocabulary: NEW, REMOVED, CLASS_CHANGED,
    ACTION_CHANGED, MONEY_CHANGED, CONFIDENCE_CHANGED, EVIDENCE_CHANGED,
    SESSION_CHANGED, OUTCOME_CHANGED. No clock, no I/O, no persistence.
    """

    prev_map = _item_map(_extract_items(previous, "previous"))
    curr_map = _item_map(_extract_items(current, "current"))
    changes: list[dict] = []

    for lead_id in sorted(set(prev_map) | set(curr_map)):
        before = prev_map.get(lead_id)
        after = curr_map.get(lead_id)
        base = {
            "lead_id": lead_id,
            "cve_id": str(
                _get(after or before, "cve_id") or ""),
            "program": str(
                _get(after or before, "program") or ""),
        }
        if before is None:
            changes.append(WorkflowChange(
                **base,
                change_type="NEW",
                before=None,
                after=_summary_of(after),
                reason="new opportunity in the current workflow",
            ).model_dump(mode="json"))
            continue
        if after is None:
            changes.append(WorkflowChange(
                **base,
                change_type="REMOVED",
                before=_summary_of(before),
                after=None,
                reason="opportunity no longer present in the current workflow",
            ).model_dump(mode="json"))
            continue

        for change_type, field, label in _FIELD_CHECKS:
            old = _get(before, field)
            new = _get(after, field)
            if old != new:
                changes.append(WorkflowChange(
                    **base,
                    change_type=change_type,
                    before=old,
                    after=new,
                    reason=f"{label} changed from {old!r} to {new!r}",
                ).model_dump(mode="json"))

        old_session, new_session = _session_state(before), _session_state(after)
        if old_session != new_session:
            changes.append(WorkflowChange(
                **base,
                change_type="SESSION_CHANGED",
                before=old_session,
                after=new_session,
                reason=(
                    f"session state changed from {old_session} "
                    f"to {new_session}"
                ),
            ).model_dump(mode="json"))

        old_outcome, new_outcome = _outcome_state(before), _outcome_state(after)
        if old_outcome != new_outcome:
            changes.append(WorkflowChange(
                **base,
                change_type="OUTCOME_CHANGED",
                before=old_outcome,
                after=new_outcome,
                reason=(
                    f"outcome state changed from {old_outcome} "
                    f"to {new_outcome}"
                ),
            ).model_dump(mode="json"))

    changes.sort(key=lambda entry: (
        str(entry.get("lead_id") or ""),
        CHANGE_TYPE_ORDER.get(str(entry.get("change_type") or ""), 99),
    ))
    return changes


def build_workflow_summary(workflow: Any) -> dict:
    """Compact deterministic workflow summary (counts + top action)."""

    top_actions = list(_get(workflow, "top_actions") or [])
    recommendations = list(_get(workflow, "recommendations") or [])
    return {
        "workflow_version": WORKFLOW_VERSION,
        "total_opportunities": _coerce_int(
            _get(workflow, "total_opportunities")),
        "ready": _coerce_int(_get(workflow, "ready")),
        "blocked": _coerce_int(_get(workflow, "blocked")),
        "in_progress": _coerce_int(_get(workflow, "in_progress")),
        "deferred": _coerce_int(_get(workflow, "deferred")),
        "completed": _coerce_int(_get(workflow, "completed")),
        "top_action": top_actions[0] if top_actions else {},
        "recommendation": recommendations[0] if recommendations else "",
        "change_types": list(CHANGE_TYPES),
        "research_only": True,
    }
