"""backend/prod_intel/agents_intel.py — per-specialist intelligence.

One projection per registered specialist (the 8 declared capabilities
plus any runtime-registered agent found in persisted records). Identity
comes from the capability registry; every activity number comes from
persisted records attributed strictly by ``specialist``/``agent``/``category``
fields — never inferred from the domain of the work.

Knowledge lineage (agent -> job -> document) is exposed ONLY where
``knowledge_use`` rows exist: no causal claims beyond the persisted row.
"""

from __future__ import annotations

from typing import Any

from backend.prod_intel import activity as activity_mod
from backend.prod_intel import sources
from backend.prod_intel.semantics import (
    DEFAULT_WINDOW_HOURS,
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    in_window,
    metric,
    window_bounds,
)

_SOURCE_KEYS = ("specialist", "agent", "agent_name")


def _belongs(row: Any, agent: str) -> bool:
    if isinstance(row, dict):
        return any(str(row.get(k) or "").lower() == agent
                   for k in _SOURCE_KEYS)
    return any(str(getattr(row, k, "") or "").lower() == agent
               for k in ("assigned_agent",))


def registered_agents() -> dict[str, Any]:
    """Declared specialists from the capability registry (authoritative)."""
    try:
        from backend.research_agents.capabilities import CAPABILITIES
        return {"state": OK,
                "agents": [{"category": cat,
                            "slug": str(getattr(cap, "agent_name", "")
                                        or cat).lower().replace(" ", "-"),
                            "agent": str(getattr(cap, "agent_name", "")
                                         or ""),
                            "mission": str(getattr(cap, "mission_types", "")
                                           or ""),
                            "observation_types": list(
                                getattr(cap, "allowed_observation_types",
                                        ()) or ())}
                           for cat, cap in CAPABILITIES.items()],
                "reason": ""}
    except Exception as exc:
        return {"state": UNAVAILABLE, "agents": [],
                "reason": f"{type(exc).__name__}: {str(exc)[:120]}"}


def agent_intelligence(*, hours: float | int | None = DEFAULT_WINDOW_HOURS
                       ) -> dict[str, Any]:
    """List projection over every registered specialist."""
    iso_lower, window = window_bounds(hours)
    reg = registered_agents()
    if reg["state"] != "ok":
        return {"rule_version": "production-intelligence-v1",
                "window": window, "state": UNAVAILABLE,
                "reason": reg["reason"], "count": 0, "agents": []}
    rows = [agent_detail(a["category"], iso_lower=iso_lower, window=window)
            for a in reg["agents"]]
    return {"rule_version": "production-intelligence-v1",
            "window": window, "state": OK, "count": len(rows),
            "agents": rows}


def agent_detail(category: str, *, iso_lower: str = "",
                 window: dict[str, Any] | None = None) -> dict[str, Any]:
    """Full intelligence bundle for one specialist.

    ``category`` accepts the capability category (XSS), the agent slug
    (xss-agent) or the agent name — SOC pages pass slugs.
    """
    if window is None:
        iso_lower, window = window_bounds(DEFAULT_WINDOW_HOURS)
    reg = registered_agents()
    needle = str(category).lower().replace("-", "_")
    meta = next((a for a in reg.get("agents", [])
                 if a["category"].lower() == needle
                 or a["slug"].lower() == str(category).lower()
                 or a["agent"].lower() == str(category).lower()), None)
    category = (meta or {}).get("category") or category
    agent_label = (meta or {}).get("agent") or str(category)
    agent_lower = agent_label.lower()

    # -- identity ----------------------------------------------------------
    identity = metric(
        meta or {"category": str(category)},
        source="capabilities.CAPABILITIES",
        population="declared specialist capability definitions",
        aggregation="identity record", time_range=window,
        state=OK if meta else UNAVAILABLE,
        reason="" if meta else "category not in the capability registry")

    # -- jobs / research ---------------------------------------------------
    jobs_env = sources.jobs()
    my_jobs = [j for j in (jobs_env["data"] or [])
               if str(getattr(j, "assigned_agent", "") or "").lower()
               == agent_lower
               or str(getattr(j, "agent_category", "") or "").upper()
               == str(category).upper()] \
        if jobs_env["state"] == "ok" else []
    by_status: dict[str, int] = {}
    for j in my_jobs:
        by_status[str(j.status)] = by_status.get(str(j.status), 0) + 1
    recent_jobs = sum(1 for j in my_jobs
                      if in_window(str(j.updated_at or j.created_at or ""),
                                   iso_lower))
    research = metric(
        {"total": len(my_jobs), "recent": recent_jobs,
         "by_status": by_status},
        source="runtime.store", population="jobs assigned to this specialist",
        aggregation="count by job status; recent = updated in window",
        time_range=window,
        state=(OK if my_jobs else NOT_OBSERVED)
        if jobs_env["state"] == "ok" else UNAVAILABLE,
        reason=jobs_env["reason"] or "")

    # -- knowledge: available vs USED (persisted rows only) ---------------
    kb_env = sources.kb_total()
    ku_env = sources.knowledge_use()
    my_use = [k for k in (ku_env["data"] or [])
              if str(k.get("agent") or "").lower() == agent_lower] \
        if ku_env["state"] == "ok" else []
    used_docs = sorted({str(k.get("document_id") or "") for k in my_use
                        if k.get("document_id")})
    knowledge = metric(
        {"documents_available": (kb_env["data"]
                                 if kb_env["state"] == "ok" else None),
         "documents_used": len(used_docs),
         "use_rows": len(my_use),
         "used_document_ids": used_docs[:40],
         "lineage": [{"job_id": str(k.get("job_id") or ""),
                      "document_id": str(k.get("document_id") or ""),
                      "title": str(k.get("title") or "")[:160],
                      "at": str(k.get("created_at") or "")}
                     for k in my_use[-20:]]},
        source="runtime.knowledge_use + research_data.list_kb",
        population="knowledge-use rows with agent == this specialist "
                   "(lineage is the persisted row, not inferred causality)",
        aggregation="distinct document ids + use-row count",
        time_range=window,
        # an unreadable knowledge-use source must read unavailable —
        # reporting "ok / 0 uses" would zero-fill misleadingly
        state=(UNAVAILABLE if ku_env["state"] != "ok"
               else OK if (my_use or kb_env["state"] == "ok")
               else NOT_OBSERVED),
        reason=ku_env["reason"] or kb_env["reason"] or "")

    # -- hunt objectives ---------------------------------------------------
    hunt_env = sources.hunt_objectives()
    my_objs = [o for o in (hunt_env["data"] or [])
               if str(o.specialist or "").lower() == agent_lower] \
        if hunt_env["state"] == "ok" else []
    obj_states: dict[str, int] = {}
    blocked_reasons: dict[str, int] = {}
    for o in my_objs:
        obj_states[str(o.state)] = obj_states.get(str(o.state), 0) + 1
        if str(o.state) == "BLOCKED":
            rsn = str(o.termination_reason or "blocked")[:80]
            blocked_reasons[rsn] = blocked_reasons.get(rsn, 0) + 1
    hunts = metric(
        {"total": len(my_objs), "by_state": obj_states,
         "blocked_reasons": blocked_reasons},
        source="hunt.store",
        population="hunt objectives whose specialist is this agent",
        aggregation="count by state + blocked termination reasons",
        time_range=window,
        state=(OK if my_objs else NOT_OBSERVED)
        if hunt_env["state"] == "ok" else UNAVAILABLE,
        reason=hunt_env["reason"] or "")

    # -- candidates / verifications / cases --------------------------------
    cand_env = sources.candidates()
    my_cands = [c for c in (cand_env["data"] or [])
                if str(c.specialist or "").lower() == agent_lower] \
        if cand_env["state"] == "ok" else []
    cand_states: dict[str, int] = {}
    for c in my_cands:
        cand_states[str(c.lifecycle_state)] = (
            cand_states.get(str(c.lifecycle_state), 0) + 1)
    ver_env = sources.verifications()
    cand_ids = {c.candidate_id for c in my_cands}
    my_vers = [v for v in (ver_env["data"] or [])
               if v.candidate_id in cand_ids] \
        if ver_env["state"] == "ok" else []
    ver_states: dict[str, int] = {}
    for v in my_vers:
        ver_states[str(v.state)] = ver_states.get(str(v.state), 0) + 1
    fc_env = sources.finding_cases()
    my_cases = [c for c in (fc_env["data"] or [])
                if str(c.candidate_id) in cand_ids] \
        if fc_env["state"] == "ok" else []
    case_states: dict[str, int] = {}
    for c in my_cases:
        case_states[str(c.state)] = case_states.get(str(c.state), 0) + 1

    findings = metric(
        {"candidates": len(my_cands), "candidate_states": cand_states,
         "verifications": len(my_vers), "verification_states": ver_states,
         "cases": len(my_cases), "case_states": case_states},
        source="finding.store",
        population="candidates whose specialist is this agent (+ their "
                   "verifications/cases via candidate id)",
        aggregation="counts by persisted state", time_range=window,
        state=(OK if my_cands else NOT_OBSERVED)
        if cand_env["state"] == "ok" else UNAVAILABLE,
        reason=cand_env["reason"] or "")

    # -- rejected hypotheses (persisted learning memory) -------------------
    mem_env = sources.memory_heads()
    my_rejected = [i for i in (mem_env["data"] or [])
                   if str(i.agent or "").lower() == agent_lower
                   and str(i.state) in ("REJECTED", "INFERRED")] \
        if mem_env["state"] == "ok" else []
    learning = metric(
        [{"id": i.id, "kind": i.kind, "state": i.state,
          "text": str(i.text)[:160], "updated_at": i.updated_at}
         for i in my_rejected[:20]],
        source="intelligence.memory",
        population="memory heads for this agent with state REJECTED or "
                   "INFERRED (never promoted to VERIFIED here)",
        aggregation="list, newest state-rank first", time_range=window,
        state=(OK if my_rejected else NOT_OBSERVED)
        if mem_env["state"] == "ok" else UNAVAILABLE,
        reason=mem_env["reason"] or "")

    # -- recent meaningful activity (agent-attributed) ---------------------
    feed_hours = (window or {}).get("hours", DEFAULT_WINDOW_HOURS)
    feed = activity_mod.build_feed(hours=feed_hours, limit=500)
    mine = []
    if isinstance(feed.get("value"), list):
        for item in feed["value"]:
            ctx = item.get("context") or {}
            sp = str(ctx.get("specialist") or "")
            if sp and sp.lower() == agent_lower:
                mine.append(item)
            elif (not sp and str(ctx.get("category") or "").upper()
                  == str(category).upper()
                  and str(ctx.get("agent") or "").lower() == agent_lower):
                mine.append(item)
    recent = metric(
        mine[:15], source=feed.get("source", "runtime.audit"),
        population="meaningful audit events whose specialist/agent field "
                   "equals this agent",
        aggregation="agent-attributed events, newest first",
        time_range=window,
        state=feed.get("state", UNAVAILABLE) if mine else NOT_OBSERVED)

    return {
        "category": str(category),
        "agent": agent_label,
        "slug": (meta or {}).get("slug", ""),
        "registered": bool(meta),
        "identity": identity,
        "research": research,
        "knowledge": knowledge,
        "hunts": hunts,
        "findings": findings,
        "learning": learning,
        "activity": recent,
        "window": window,
        "rule_version": "production-intelligence-v1",
    }
