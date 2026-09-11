"""backend/product_api.py — Stage R28.1 product API composition.

Read-only composition: maps the internal R26.1 opportunity view and the
R26.2 action view into the public v1 ``ResearchOpportunityResponse``
contract. No new scoring, no writes, no network, no DNS, no LLM, no
subprocess, no target interaction, no Nuclei, no browser, no PoC execution,
no findings, no alerts, no Mongo writes, no payouts.
"""

from __future__ import annotations

from typing import Any, Optional

from ai.schemas.product_api import (
    PRODUCT_API_VERSION,
    opportunity_response,
)

MAX_ITEMS = 100


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _clamp_limit(limit: Any) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return 50
    return min(max(value, 1), MAX_ITEMS)


def _clamp_score(value: Any) -> int:
    try:
        score = int(value)
    except (TypeError, ValueError):
        return 0
    return min(max(score, 0), 100)


def build_product_opportunities() -> list[dict]:
    """Deterministic v1 responses for every valid opportunity.

    Composes R26.1 opportunities with their R26.2 action rows by lead_id
    (R26.2 ranking preserved). Malformed rows and rows without a lead are
    skipped; nothing is fabricated.
    """

    from backend import research_action_queue
    from backend import research_opportunities

    try:
        opportunities = research_opportunities.build_opportunities()
    except Exception:
        return []
    try:
        actions = research_action_queue.build_action_queue()
    except Exception:
        actions = []
    by_lead: dict[str, dict] = {}
    for action in actions or []:
        if isinstance(action, dict) and action.get("lead_id"):
            by_lead.setdefault(str(action["lead_id"]), action)
    items: list[dict] = []
    for opportunity in opportunities or []:
        if not isinstance(opportunity, dict):
            continue
        lead_id = _safe_str(opportunity.get("lead_id"))
        if not lead_id:
            continue
        try:
            items.append(opportunity_response(
                opportunity, by_lead.get(lead_id, {})))
        except Exception:
            continue
    return items


def list_product_opportunities(
    limit: int = 50,
    offset: int = 0,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    opportunity_class: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    min_money_score: int = 0,
) -> dict:
    """Capped deterministic v1 list (R26.2 ranking preserved)."""

    from backend.research_data import normalize_cve

    limit = _clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    floor = _clamp_score(min_money_score)
    items = build_product_opportunities()
    if cve:
        cve = normalize_cve(cve)
        items = [i for i in items if i["cve_id"] == cve]
    if program:
        program = str(program).strip()
        items = [i for i in items if i["program"] == program]
    if opportunity_class:
        wanted = str(opportunity_class).strip().upper()
        items = [i for i in items
                 if str(i["opportunity_class"]).upper() == wanted]
    if action:
        wanted = str(action).strip().upper()
        items = [i for i in items
                 if str(i["recommended_action"]).upper() == wanted]
    if status:
        wanted = str(status).strip().upper()
        items = [i for i in items
                 if str(i["current_status"]).upper() == wanted]
    items = [i for i in items if int(i["money_score"]) >= floor]
    total = len(items)
    return {
        "api_version": PRODUCT_API_VERSION,
        "research_only": True,
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset: offset + limit],
    }


def get_product_opportunity(lead_id: str) -> dict:
    """One v1 response by deterministic lead id (404-style when absent)."""

    from backend.research_data import NotFoundError
    from backend.research_leads import LEAD_ID_RE

    if not LEAD_ID_RE.match(str(lead_id).strip()):
        raise NotFoundError("expected a lead id like rl-0123456789abcdef")
    for item in build_product_opportunities():
        if item["lead_id"] == lead_id:
            return item
    raise NotFoundError("no product opportunity for that lead")


def product_opportunity_summary() -> dict:
    """Compact v1 counts + top items (read-only)."""

    items = build_product_opportunities()
    by_class: dict[str, int] = {}
    by_action: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for item in items:
        by_class[item["opportunity_class"]] = \
            by_class.get(item["opportunity_class"], 0) + 1
        by_action[item["recommended_action"]] = \
            by_action.get(item["recommended_action"], 0) + 1
        by_status[item["current_status"]] = \
            by_status.get(item["current_status"], 0) + 1
    return {
        "api_version": PRODUCT_API_VERSION,
        "research_only": True,
        "total": len(items),
        "by_class": dict(sorted(by_class.items())),
        "by_action": dict(sorted(by_action.items())),
        "by_status": dict(sorted(by_status.items())),
        "top_opportunities": items[:3],
    }


def product_research_status() -> dict:
    """High-level v1 system state (no secrets, no target data)."""

    from backend import research_outcomes
    from backend import research_sessions

    items = build_product_opportunities()
    statuses = [i["current_status"] for i in items]
    try:
        outcomes = research_outcomes.list_outcomes(limit=1)["total"]
    except Exception:
        outcomes = 0
    try:
        sessions = research_sessions.list_sessions(limit=1)["total"]
    except Exception:
        sessions = 0
    evidence_available = any(
        str(i.get("evidence_quality") or "NONE").upper() != "NONE"
        for i in items
    )
    return {
        "api_version": PRODUCT_API_VERSION,
        "research_only": True,
        "product_api_version": PRODUCT_API_VERSION,
        "opportunity_count": len(items),
        "ready_count": statuses.count("READY"),
        "blocked_count": statuses.count("BLOCKED"),
        "in_progress_count": statuses.count("IN_PROGRESS"),
        "completed_count": statuses.count("COMPLETED"),
        "evidence_available": evidence_available,
        "outcomes_available": outcomes > 0,
        "sessions_available": sessions > 0,
    }
