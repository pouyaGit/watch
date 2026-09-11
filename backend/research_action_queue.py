"""backend/research_action_queue.py — Stage R26.2 Action Queue composition.

Read-only composition around the existing R26.1 opportunity view: it folds
in the R25.5 outcomes and R25.7 sessions already produced by prior stages
into a deterministic, researcher-oriented Action Queue that answers
*"What should I work on first, and what exactly is blocking the other
items?"*.

No new scoring formula: the Money Score is copied verbatim from the R26.1
opportunity. No new persistence layer, no writes, no network, no DNS, no
LLM, no subprocess, no target interaction, no Nuclei, no browser, no PoC
execution, no 5B-5J, no findings, no alerts, no Mongo writes. This module
never executes anything.
"""

from __future__ import annotations

from typing import Any, Optional

from ai.knowledge.opportunity_action import (
    build_action,
    build_action_summary,
    rank_actions,
)
from ai.schemas.opportunity_action import (
    ACTION_RULE_VERSION,
    OpportunityAction,
    action_projection,
)

MAX_ACTIONS = 100


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _outcomes_for(lead_id: str) -> dict:
    """R25.5 performance summary + latest outcome status (fail-soft)."""

    from backend import research_opportunities

    base = {
        "accepted": 0,
        "duplicate": 0,
        "rejected": 0,
        "wasted_time": 0,
        "terminal_attempts": 0,
        "acceptance_rate": 0.0,
        "wasted_rate": 0.0,
        "outcome_status": "NONE",
    }
    try:
        perf = research_opportunities._outcomes_for(lead_id)
    except Exception:
        return base
    base.update(
        {
            "accepted": int(perf.get("accepted") or 0),
            "duplicate": int(perf.get("duplicate") or 0),
            "rejected": int(perf.get("rejected") or 0),
            "wasted_time": int(perf.get("wasted_time") or 0),
            "terminal_attempts": int(perf.get("terminal_attempts") or 0),
            "acceptance_rate": float(perf.get("acceptance_rate") or 0.0),
            "wasted_rate": float(perf.get("wasted_rate") or 0.0),
            "outcome_status": str(perf.get("outcome_status") or "NONE"),
        }
    )
    return base


def _sessions_for(lead_id: str) -> dict:
    """R25.7 session summary (fail-soft, read-only)."""

    from backend import research_opportunities

    base = {
        "total_sessions": 0,
        "planned_sessions": 0,
        "in_progress_sessions": 0,
        "completed_sessions": 0,
        "abandoned_sessions": 0,
        "session_status": "NONE",
        "planned_time": 0,
        "actual_time": 0,
    }
    try:
        summary = research_opportunities._sessions_for(lead_id)
    except Exception:
        return base
    base.update(
        {
            "total_sessions": int(summary.get("total_sessions") or 0),
            "planned_sessions": int(summary.get("planned_sessions") or 0),
            "in_progress_sessions": int(
                summary.get("in_progress_sessions") or 0
            ),
            "completed_sessions": int(
                summary.get("completed_sessions") or 0
            ),
            "abandoned_sessions": int(
                summary.get("abandoned_sessions") or 0
            ),
            "session_status": str(summary.get("session_status") or "NONE"),
            "planned_time": int(summary.get("planned_time") or 0),
            "actual_time": int(summary.get("actual_time") or 0),
        }
    )
    return base


def _action_for_opportunity(opportunity: dict) -> OpportunityAction | None:
    lead_id = _safe_str(opportunity.get("lead_id"))
    if not lead_id:
        return None
    try:
        action = build_action(
            opportunity,
            _sessions_for(lead_id),
            _outcomes_for(lead_id),
        )
    except Exception:
        return None
    # Stage R30.1: additive asset <-> CVE match context (read-only; never
    # changes the Money Score, opportunity class or action precedence).
    try:
        from backend import asset_cve_matching

        projection = asset_cve_matching.get_projection(
            _safe_str(opportunity.get("cve_id")),
            _safe_str(opportunity.get("program")),
        )
    except Exception:
        projection = {}
    if projection:
        try:
            action = action.model_copy(update=projection)
        except Exception:
            pass
    return action


def build_action_queue() -> list[dict]:
    """Deterministic, ranked action projections for every opportunity.

    Fail-soft: malformed opportunities are skipped; missing sessions or
    outcomes become explicit NONE values; nothing is fabricated.
    """

    from backend import research_opportunities

    try:
        opportunities = research_opportunities.build_opportunities()
    except Exception:
        return []
    actions: list[OpportunityAction] = []
    for opportunity in opportunities or []:
        if not isinstance(opportunity, dict):
            continue
        action = _action_for_opportunity(opportunity)
        if action is None:
            continue
        actions.append(action)
    ranked = rank_actions(actions)
    return [action_projection(model) for model in ranked]


def list_actions(
    limit: int = 50,
    offset: int = 0,
    opportunity_class: Optional[str] = None,
    status: Optional[str] = None,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Capped deterministic action queue slice (ranking preserved)."""

    from backend.research_data import clamp_limit, normalize_cve

    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    items = build_action_queue()
    if opportunity_class:
        opportunity_class = str(opportunity_class).strip().upper()
        items = [
            item for item in items
            if item["opportunity_class"] == opportunity_class
        ]
    if status:
        status = str(status).strip().upper()
        items = [item for item in items if item["current_status"] == status]
    if cve:
        cve = normalize_cve(cve)
        items = [item for item in items if item["cve_id"] == cve]
    if program:
        program = str(program).strip()
        items = [item for item in items if item["program"] == program]
    total = len(items)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset: offset + limit],
        "rule_version": ACTION_RULE_VERSION,
        "research_only": True,
    }


def get_action(lead_id: str) -> dict:
    """One action by deterministic lead id (404 when absent)."""

    from backend.research_data import NotFoundError
    from backend.research_leads import LEAD_ID_RE

    if not LEAD_ID_RE.match(str(lead_id).strip()):
        raise NotFoundError("expected a lead id like rl-0123456789abcdef")
    for item in build_action_queue():
        if item["lead_id"] == lead_id:
            return item
    raise NotFoundError(
        "no opportunity action for that lead (no R18 candidate / "
        "R26 opportunity projection)"
    )


def action_summary() -> dict:
    """Compact counts + top action (read-only)."""

    actions = [
        OpportunityAction.model_validate(item)
        for item in build_action_queue()
    ]
    return build_action_summary(actions)