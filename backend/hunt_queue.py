"""backend/hunt_queue.py — Stage R29.1 personal hunt queue composition.

Composition only: joins the existing R26.2 Action Queue with the R25.5
outcome history and R25.7 session history, then projects through the pure
``ai.knowledge.hunt_queue`` engine.

No new persistence, no writes, no network, no DNS, no LLM, no subprocess, no
target interaction, no Nuclei, no browser, no PoC execution, no findings, no
alerts, no payouts, no Mongo. The Money Score is copied verbatim.
"""

from __future__ import annotations

from typing import Any, Optional

from ai.knowledge.hunt_queue import (
    build_hunt_item,
    build_hunt_summary,
    rank_hunt_queue,
)
from ai.schemas.hunt_queue import HUNT_RULE_VERSION, hunt_item_projection

MAX_HUNT_ITEMS = 100

# Stage R30.1 additive asset <-> CVE match context copied from the action
# projection (read-only; never changes the Money Score or hunt priority).
_ASSET_CONTEXT_FIELDS: tuple[str, ...] = (
    "asset_match_confidence",
    "asset_match_state",
    "strongest_match_type",
    "matched_component",
    "matched_version",
    "matched_parameter",
    "resolved_blockers",
    "remaining_blockers",
    "asset_match_reason",
)


def _outcomes_for(lead_id: str) -> dict:
    """R25.5 per-lead history summary (fail-soft)."""

    from backend import research_outcomes

    try:
        return research_outcomes.summarize_lead_outcomes(lead_id)
    except Exception:
        return {}


def _sessions_for(lead_id: str) -> dict:
    """R25.7 per-lead session summary + latest session status (fail-soft)."""

    from backend import research_sessions

    base: dict = {}
    try:
        base = dict(research_sessions.summarize_session(lead_id))
    except Exception:
        base = {}
    latest_status = ""
    try:
        items = research_sessions.list_sessions(
            limit=1, offset=0, lead_id=lead_id)["items"]
        if items:
            latest_status = str(items[0].get("status") or "")
    except Exception:
        latest_status = ""
    if not latest_status:
        if int(base.get("in_progress_sessions") or 0) > 0:
            latest_status = "IN_PROGRESS"
        elif int(base.get("completed_sessions") or 0) > 0:
            latest_status = "COMPLETED"
        elif int(base.get("planned_sessions") or 0) > 0:
            latest_status = "PLANNED"
        elif int(base.get("abandoned_sessions") or 0) > 0:
            latest_status = "ABANDONED"
        else:
            latest_status = "NONE"
    base["latest_session_status"] = latest_status
    return base


def build_hunt_queue() -> list[dict]:
    """Deterministic, ranked personal hunt items for all action candidates.

    Fail-soft: a malformed action is skipped; missing history becomes explicit
    zeros/NONE; nothing is fabricated.
    """

    from backend import research_action_queue

    try:
        actions = research_action_queue.build_action_queue()
    except Exception:
        return []
    items = []
    for action in actions or []:
        if not isinstance(action, dict):
            continue
        lead_id = str(action.get("lead_id") or "")
        if not lead_id:
            continue
        try:
            item = build_hunt_item(
                action, _outcomes_for(lead_id), _sessions_for(lead_id))
        except Exception:
            continue
        updates = {
            key: action[key]
            for key in _ASSET_CONTEXT_FIELDS
            if key in action
        }
        if updates:
            try:
                item = item.model_copy(update=updates)
            except Exception:
                pass
        items.append(item)
    ranked = rank_hunt_queue(items)
    return [hunt_item_projection(item) for item in ranked]


def list_hunt_items(
    limit: int = 50,
    offset: int = 0,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    priority: Optional[str] = None,
    opportunity_class: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    """Capped deterministic hunt slice (ranking preserved)."""

    from backend.research_data import clamp_limit, normalize_cve

    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    items = build_hunt_queue()
    if cve:
        cve = normalize_cve(cve)
        items = [i for i in items if i["cve_id"] == cve]
    if program:
        program = str(program).strip()
        items = [i for i in items if i["program"] == program]
    if priority:
        wanted = str(priority).strip().upper()
        items = [i for i in items if i["hunt_priority"] == wanted]
    if opportunity_class:
        wanted = str(opportunity_class).strip().upper()
        items = [i for i in items if i["opportunity_class"] == wanted]
    if status:
        wanted = str(status).strip().upper()
        items = [i for i in items if i["current_status"] == wanted]
    total = len(items)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset: offset + limit],
        "rule_version": HUNT_RULE_VERSION,
        "research_only": True,
    }


def get_hunt_item(lead_id: str) -> dict:
    """One hunt item by deterministic lead id (404-style when absent)."""

    from backend.research_data import NotFoundError
    from backend.research_leads import LEAD_ID_RE

    if not LEAD_ID_RE.match(str(lead_id).strip()):
        raise NotFoundError("expected a lead id like rl-0123456789abcdef")
    for item in build_hunt_queue():
        if item["lead_id"] == lead_id:
            return item
    raise NotFoundError("no hunt item for that lead")


def hunt_summary() -> dict:
    """Compact tier counts + top items (read-only)."""

    from ai.schemas.hunt_queue import HuntItem

    items = [HuntItem.model_validate(item) for item in build_hunt_queue()]
    return build_hunt_summary(items)
