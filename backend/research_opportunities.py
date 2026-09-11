"""backend/research_opportunities.py — Stage R26.1 opportunity composition.

Read-only composition around existing R21 research leads:
R18 queue -> R21 lead -> R22 plan -> R23/R24 evidence -> R25.2 Money Score ->
R25.5 outcomes -> R25.7 sessions, projected through the pure
``ai.knowledge.opportunity`` engine.

No new scoring formula: the Money Score is copied verbatim. No writes, no
network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei, no
browser, no PoC execution, no 5B-5J, no findings, no alerts, no Mongo writes.
"""

from __future__ import annotations

from typing import Any, Optional

from ai.knowledge.opportunity import (
    build_opportunity,
    build_opportunity_summary,
    rank_opportunities,
)
from ai.schemas.research_opportunity import (
    OPPORTUNITY_RULE_VERSION,
    opportunity_projection,
)

MAX_OPPORTUNITIES = 100

_TIER_ORDER = {
    "TRUSTED": 3,
    "SEMI_TRUSTED": 2,
    "DISCOVERY_ONLY": 1,
    "GENERIC": 0,
}
_CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _economics_by_lead() -> dict:
    """{lead_id: R25.2 projection} (read-only, fail-soft)."""

    from backend import research_economics

    try:
        items = research_economics.build_economics()
    except Exception:
        return {}
    mapping: dict = {}
    for item in items or []:
        if isinstance(item, dict) and item.get("lead_id"):
            mapping.setdefault(str(item["lead_id"]), item)
    return mapping


def _evidence_for(cve: str, program: str) -> dict:
    """Compose R23/R24 evidence metadata only (never fetches anything)."""

    from ai.research_agent import storage
    from backend import research_execution

    summary = {
        "source_count": 0,
        "evidence_count": 0,
        "strongest_source_tier": "NONE",
        "evidence_confidence": "NONE",
        "latest_research_status": "NONE",
    }
    try:
        plan_id = research_execution.plan_id_for(cve, program)
    except Exception:
        return summary
    r23 = {}
    r24 = {}
    try:
        r23 = storage.load_result(plan_id, "r23-1") or {}
    except Exception:
        r23 = {}
    try:
        r24 = storage.load_research_loop(plan_id) or {}
    except Exception:
        r24 = {}

    r23_sources = list(r23.get("sources") or []) if isinstance(r23, dict) else []
    r23_evidence = list(r23.get("evidence") or []) if isinstance(r23, dict) else []
    r24_sources: list = []
    r24_evidence: list = []
    for rnd in (r24.get("rounds") or []) if isinstance(r24, dict) else []:
        discovery = rnd.get("discovery") or {}
        r24_sources.extend(discovery.get("sources") or [])
        r24_evidence.extend(discovery.get("evidence") or [])

    summary["source_count"] = len(r23_sources) + len(r24_sources)
    summary["evidence_count"] = len(r23_evidence) + len(r24_evidence)

    best_tier = None
    for src in r24_sources:
        tier = str((src or {}).get("tier") or "").upper()
        if best_tier is None or _TIER_ORDER.get(tier, 0) > _TIER_ORDER.get(
            best_tier, 0
        ):
            best_tier = tier
    if best_tier:
        summary["strongest_source_tier"] = best_tier

    best_conf = None
    for item in r23_evidence + r24_evidence:
        conf = str((item or {}).get("confidence") or "").upper()
        if best_conf is None or _CONFIDENCE_ORDER.get(conf, 0) > \
                _CONFIDENCE_ORDER.get(best_conf, 0):
            best_conf = conf
    if best_conf:
        summary["evidence_confidence"] = best_conf

    status = ""
    if isinstance(r24, dict) and r24.get("status"):
        status = str(r24["status"]).upper()
    elif isinstance(r23, dict) and r23.get("status"):
        status = str(r23["status"]).upper()
    if status:
        summary["latest_research_status"] = status
    summary["evidence_summary"] = dict(summary)
    return summary


def _outcomes_for(lead_id: str) -> dict:
    """R25.5 performance summary + latest outcome status (fail-soft)."""

    from backend import research_outcomes

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
        perf = research_outcomes.lead_performance(lead_id)
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
        }
    )
    latest = perf.get("latest_outcome")
    if isinstance(latest, dict) and latest.get("status"):
        base["outcome_status"] = str(latest["status"]).upper()
    return base


def _sessions_for(lead_id: str) -> dict:
    """R25.7 session summary + derived status/efficiency (fail-soft)."""

    from backend import research_sessions

    base = {
        "total_sessions": 0,
        "planned_sessions": 0,
        "in_progress_sessions": 0,
        "completed_sessions": 0,
        "abandoned_sessions": 0,
        "planned_time": 0,
        "actual_time": 0,
        "session_status": "NONE",
        "historical_time_status": "NONE",
        "efficiency_ratio": None,
    }
    try:
        summary = research_sessions.summarize_session(lead_id)
    except Exception:
        return base
    base.update(
        {
            "total_sessions": int(summary.get("total_sessions") or 0),
            "planned_sessions": int(summary.get("planned_sessions") or 0),
            "in_progress_sessions": int(
                summary.get("in_progress_sessions") or 0),
            "completed_sessions": int(summary.get("completed_sessions") or 0),
            "abandoned_sessions": int(summary.get("abandoned_sessions") or 0),
            "planned_time": int(summary.get("planned_time") or 0),
            "actual_time": int(summary.get("actual_time") or 0),
        }
    )
    if base["in_progress_sessions"] > 0:
        base["session_status"] = "ACTIVE"
        base["historical_time_status"] = "IN_PROGRESS"
    elif base["planned_sessions"] > 0:
        base["session_status"] = "PLANNED"
    elif base["completed_sessions"] > 0:
        base["session_status"] = "COMPLETED"
        base["historical_time_status"] = "COMPLETED"
    elif base["abandoned_sessions"] > 0:
        base["session_status"] = "ABANDONED"
        base["historical_time_status"] = "ABANDONED"
    if base["actual_time"] > 0 and base["planned_time"] > 0:
        base["efficiency_ratio"] = round(
            base["planned_time"] / base["actual_time"], 4)
    return base


def build_opportunities() -> list[dict]:
    """Deterministic, ranked opportunity projections for all valid leads.

    Fail-soft: malformed leads and leads without an economic projection are
    skipped; missing evidence/sessions/outcomes become explicit NONE values.
    """

    from backend import research_leads

    try:
        leads = research_leads.build_leads()
    except Exception:
        return []
    economics = _economics_by_lead()
    models = []
    for lead in leads or []:
        if not isinstance(lead, dict):
            continue
        lead_id = _safe_str(lead.get("lead_id"))
        cve = _safe_str(lead.get("cve_id"))
        program = _safe_str(lead.get("program"))
        if not lead_id or not cve or not program:
            continue
        economic = economics.get(lead_id)
        if not economic:
            continue
        try:
            model = build_opportunity(
                lead,
                economic,
                _outcomes_for(lead_id),
                _sessions_for(lead_id),
                _evidence_for(cve, program),
            )
        except Exception:
            continue
        models.append(model)
    ranked = rank_opportunities(models)
    return [opportunity_projection(model) for model in ranked]


def list_opportunities(
    limit: int = 50,
    offset: int = 0,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Capped deterministic opportunity queue slice (ranking preserved)."""

    from backend.research_data import clamp_limit, normalize_cve

    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    items = build_opportunities()
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
        "rule_version": OPPORTUNITY_RULE_VERSION,
        "research_only": True,
    }


def get_opportunity(lead_id: str) -> dict:
    """One opportunity by deterministic lead id (404-style when absent)."""

    from backend.research_data import NotFoundError
    from backend.research_leads import LEAD_ID_RE

    if not LEAD_ID_RE.match(str(lead_id).strip()):
        raise NotFoundError("expected a lead id like rl-0123456789abcdef")
    for item in build_opportunities():
        if item["lead_id"] == lead_id:
            return item
    raise NotFoundError(
        "no opportunity for that lead (no R18 candidate / R25 projection)"
    )


def opportunity_summary() -> dict:
    """Compact class counts + top opportunities (read-only)."""

    from ai.schemas.research_opportunity import ResearchOpportunity

    models = [
        ResearchOpportunity.model_validate(item)
        for item in build_opportunities()
    ]
    return build_opportunity_summary(models)
