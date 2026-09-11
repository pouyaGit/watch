"""backend/daily_research.py — Stage R26.3 daily workflow composition.

Composition only: builds the R26.2 Action Queue (which itself composes R26.1
opportunities with R25.5 outcomes and R25.7 sessions) and folds it into the
pure ``ai.knowledge.daily_research`` workflow engine.

No new scoring formula. No persistence, no snapshots, no writes, no network,
no DNS, no LLM, no subprocess, no target interaction, no Nuclei, no browser,
no PoC execution, no findings, no alerts, no Mongo writes.
"""

from __future__ import annotations

from typing import Any, Optional

from ai.knowledge.daily_research import (
    build_daily_workflow as _build_daily_workflow,
)
from ai.knowledge.daily_research import (
    build_workflow_summary,
    compare_workflows,
)
from ai.schemas.daily_research import (
    WORKFLOW_VERSION,
    daily_workflow_projection,
)

DEFAULT_TOP_N = 5
MAX_TOP_N = 50


def _sessions_detail(lead_id: str) -> list[dict]:
    """Per-session detail for one lead (read-only, fail-soft)."""

    from backend import research_sessions

    try:
        data = research_sessions.list_sessions(limit=50, offset=0,
                                               lead_id=lead_id)
    except Exception:
        return []
    return [s for s in (data.get("items") or []) if isinstance(s, dict)]


def _enrich_actions(actions: list[dict]) -> tuple[list[dict], dict, dict]:
    """Attach session/outcome state for comparison (read-only, fail-soft)."""

    from backend import research_action_queue

    enriched: list[dict] = []
    sessions_by_lead: dict = {}
    outcomes_by_lead: dict = {}
    for action in actions or []:
        if not isinstance(action, dict):
            continue
        lead_id = str(action.get("lead_id") or "")
        if not lead_id:
            continue
        sessions_summary: dict = {}
        outcomes_summary: dict = {}
        try:
            sessions_summary = research_action_queue._sessions_for(lead_id)
        except Exception:
            sessions_summary = {}
        try:
            outcomes_summary = research_action_queue._outcomes_for(lead_id)
        except Exception:
            outcomes_summary = {}
        sessions_by_lead[lead_id] = _sessions_detail(lead_id)
        outcomes_by_lead[lead_id] = outcomes_summary
        item = dict(action)
        item["session_status"] = str(
            sessions_summary.get("session_status") or "NONE")
        item["outcome_status"] = str(
            outcomes_summary.get("outcome_status") or "NONE")
        enriched.append(item)
    return enriched, sessions_by_lead, outcomes_by_lead


def build_daily_workflow(
    top_n: int = DEFAULT_TOP_N,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    opportunity_class: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    """Deterministic daily workflow projection (read-only; no writes).

    Fail-soft: a failing action queue or enrichment degrades to an empty or
    partially enriched workflow; nothing is fabricated.
    """

    from backend import research_action_queue

    try:
        count = max(0, min(int(top_n), MAX_TOP_N))
    except (TypeError, ValueError):
        count = DEFAULT_TOP_N
    try:
        actions = research_action_queue.list_actions(
            limit=research_action_queue.MAX_ACTIONS,
            offset=0,
            opportunity_class=opportunity_class,
            status=status,
            cve=cve,
            program=program,
        )["items"]
    except Exception:
        actions = []
    enriched, sessions_by_lead, outcomes_by_lead = _enrich_actions(actions)
    workflow = _build_daily_workflow(
        enriched,
        sessions_by_lead=sessions_by_lead,
        outcomes_by_lead=outcomes_by_lead,
        top_n=count,
    )
    return daily_workflow_projection(workflow)


def compare_daily_workflows(previous: Any, current: Any) -> list[dict]:
    """Deterministic diff between two caller-supplied workflow structures.

    Pure comparison; never reads or writes files and never persists a
    snapshot. Malformed input raises ``ValueError``.
    """

    return compare_workflows(previous, current)


def daily_summary(
    top_n: int = DEFAULT_TOP_N,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Compact workflow summary (read-only)."""

    workflow = build_daily_workflow(top_n=top_n, cve=cve, program=program)
    return build_workflow_summary(workflow)


def workflow_meta() -> dict:
    """Version metadata only (no data)."""

    return {"workflow_version": WORKFLOW_VERSION, "research_only": True}
