"""backend/prod_intel/overview.py — production intelligence overview.

One authoritative projection feeding the JSON API and the AI SOC home
page (Epic8 sections 1 + 7A). Counts are grouped by SOURCE FAMILY so
runtime gate-cases and finding case packages are never summed into one
misleading "cases" number.
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
    UNKNOWN,
    in_window,
    metric,
    window_bounds,
)

# campaign states that mean "actively executing work right now"
_ACTIVE_CAMPAIGN = frozenset({"READY", "RUNNING", "WAITING", "PAUSED"})
# hunt objective states that are still open (non-terminal)
_OPEN_HUNT = frozenset({"OPEN", "NEEDS_EVIDENCE", "READY_FOR_PLANNING",
                        "PLANNED", "OBSERVATION_PENDING",
                        "OBSERVATION_COMPLETE"})
# job states that count as work in flight
_INFLIGHT_JOB = frozenset({"NEW", "QUEUED", "CLAIMED", "RUNNING", "RETRY"})


def _state_metric(env: dict[str, Any], *, population: str,
                  aggregation: str, window: dict[str, Any]
                  ) -> dict[str, Any]:
    if env["state"] != "ok":
        return metric(None, source=env["reason"].split(":")[0],
                      population=population, aggregation=aggregation,
                      time_range=window, state=UNAVAILABLE,
                      reason=env["reason"])
    return metric(len(env["data"]), source=population.split(" via ")[0],
                  population=population, aggregation=aggregation,
                  time_range=window, state=OK)


def overview(*, hours: float | int | None = DEFAULT_WINDOW_HOURS
             ) -> dict[str, Any]:
    """High-level operational state, fully provenanced."""
    iso_lower, window = window_bounds(hours)

    # -- agents (reuse the SAME projection the Agents page renders) ------
    agents_state: dict[str, Any]
    try:
        from backend.soc import agents as soc_agents
        idx = soc_agents.agents_index()
        listed = idx.get("agents") or []
        split = {"registered": int(idx.get("count") or len(listed))}
        for st in ("READY", "IDLE", "ACTIVE", "FAILED", "PLANNED"):
            split[st.lower()] = sum(
                1 for a in listed if str(a.get("status") or "") == st)
        agents_state = metric(split, source="backend.soc.agents",
                              population="declared specialist registry "
                                         "+ runtime liveness",
                              aggregation="count by runtime status",
                              time_range=window, state=OK)
    except Exception as exc:
        agents_state = metric(None, source="backend.soc.agents",
                              population="specialist registry",
                              aggregation="count by runtime status",
                              time_range=window, state=UNAVAILABLE,
                              reason=f"{type(exc).__name__}")

    # -- campaigns ---------------------------------------------------------
    camp_env = sources.campaigns()
    if camp_env["state"] == "ok":
        camps = camp_env["data"]
        active = [c for c in camps if str(c.state) in _ACTIVE_CAMPAIGN]
        by_state: dict[str, int] = {}
        for c in camps:
            by_state[str(c.state)] = by_state.get(str(c.state), 0) + 1
        campaigns_m = metric(
            {"active": len(active), "total": len(camps),
             "by_state": by_state},
            source="campaign.store", population="persisted campaigns",
            aggregation="state counts; active = READY/RUNNING/WAITING/"
                        "PAUSED", time_range=window, state=OK)
    else:
        campaigns_m = metric(None, source="campaign.store",
                             population="persisted campaigns",
                             aggregation="state counts", time_range=window,
                             state=UNAVAILABLE, reason=camp_env["reason"])

    # -- hunts -------------------------------------------------------------
    hunt_env = sources.hunt_objectives()
    if hunt_env["state"] == "ok":
        objs = hunt_env["data"]
        open_n = sum(1 for o in objs if str(o.state) in _OPEN_HUNT)
        blocked_n = sum(1 for o in objs if str(o.state) == "BLOCKED")
        hunts_m = metric(
            {"open": open_n, "total": len(objs), "blocked": blocked_n},
            source="hunt.store",
            population="latest-revision hunt objectives",
            aggregation="state counts; open = non-terminal uncertainty "
                        "states", time_range=window, state=OK)
    else:
        hunts_m = metric(None, source="hunt.store",
                         population="hunt objectives", aggregation="counts",
                         time_range=window, state=UNAVAILABLE,
                         reason=hunt_env["reason"])

    # -- recent candidates (finding family) --------------------------------
    cand_env = sources.candidates()
    if cand_env["state"] == "ok":
        cands = cand_env["data"]
        recent = [c for c in cands
                  if in_window(str(c.updated_at or c.created_at), iso_lower)]
        by_state: dict[str, int] = {}
        for c in recent:
            by_state[str(c.lifecycle_state)] = (
                by_state.get(str(c.lifecycle_state), 0) + 1)
        findings_m = metric(
            {"count": len(recent), "by_state": by_state},
            source="finding.store", population="candidate findings",
            aggregation="candidates updated within the window, by state",
            time_range=window,
            state=OK if recent else NOT_OBSERVED)
    else:
        findings_m = metric(None, source="finding.store",
                            population="candidate findings",
                            aggregation="windowed counts", time_range=window,
                            state=UNAVAILABLE, reason=cand_env["reason"])

    # -- cases: kept per source family (never summed across families) -----
    fc_env = sources.finding_cases()
    rc_env = sources.runtime_cases()
    cases_m: dict[str, Any] = {
        "finding_cases": (
            metric(len(fc_env["data"]), source="finding.store",
                   population="finding case packages",
                   aggregation="count", time_range=window, state=OK)
            if fc_env["state"] == "ok"
            else metric(None, source="finding.store",
                        population="finding case packages",
                        aggregation="count", time_range=window,
                        state=UNAVAILABLE, reason=fc_env["reason"])),
        "runtime_gate_cases": (
            metric(len(rc_env["data"]), source="runtime.store",
                   population="evidence-gate runtime cases",
                   aggregation="count", time_range=window, state=OK)
            if rc_env["state"] == "ok"
            else metric(None, source="runtime.store",
                        population="evidence-gate runtime cases",
                        aggregation="count", time_range=window,
                        state=UNAVAILABLE, reason=rc_env["reason"])),
        "semantics": "source families reported separately — never summed",
    }

    # -- handoff -----------------------------------------------------------
    handoff_m: dict[str, Any]
    try:
        from backend.soc import handoff as soc_handoff
        h = soc_handoff.handoff_index()
        rows = h.get("reports") or []
        ready = sum(1 for r in rows
                    if str(r.get("status") or "") == "READY_FOR_REVIEW")
        handoff_m = metric({"count": len(rows), "ready_for_review": ready},
                           source="backend.soc.handoff",
                           population="handoff rows across families",
                           aggregation="count; ready_for_review = rows in "
                                       "READY_FOR_REVIEW", time_range=window,
                           state=OK)
    except Exception as exc:
        handoff_m = metric(None, source="backend.soc.handoff",
                           population="handoff rows", aggregation="count",
                           time_range=window, state=UNAVAILABLE,
                           reason=f"{type(exc).__name__}")

    # -- meaningful activity + blockers ------------------------------------
    feed = activity_mod.build_feed(hours=hours, limit=20)
    activity_summary = metric(
        feed["value"], source=feed["source"],
        population=feed["population"],
        aggregation="top 20 meaningful events in window",
        time_range=window, state=feed["state"],
        total_categories=feed.get("categories", [])) \
        if isinstance(feed, dict) else feed

    blockers = _blockers(window, iso_lower)

    return {
        "rule_version": "production-intelligence-v1",
        "window": window,
        "agents": agents_state,
        "campaigns": campaigns_m,
        "hunts": hunts_m,
        "recent_findings": findings_m,
        "cases": cases_m,
        "handoff": handoff_m,
        "meaningful_activity": activity_summary,
        "blockers": blockers,
        "current_activity": activity_mod.current_activity(),
    }


def _blockers(window: dict[str, Any], iso_lower: str) -> dict[str, Any]:
    """Everything currently blocking autonomous work — real records only.

    If ANY blocker source is unreadable the metric is ``unavailable``
    (never ``not_observed``): an unreadable source must not silently
    shrink the blocker list.
    """
    items: list[dict[str, Any]] = []
    unavailable: list[str] = []

    hunt_env = sources.hunt_objectives()
    if hunt_env["state"] == "ok":
        for o in hunt_env["data"]:
            if str(o.state) == "BLOCKED":
                items.append({
                    "kind": "hunt_objective",
                    "id": o.objective_id,
                    "reason": o.termination_reason or "blocked",
                    "target": str(o.target_context.get("subdomain")
                                  if isinstance(o.target_context, dict)
                                  else "") or "",
                    "at": o.updated_at,
                    "link": None,
                    "source": "hunt.store",
                })
    else:
        unavailable.append("hunt.store")
    camp_env = sources.campaigns()
    if camp_env["state"] == "ok":
        for c in camp_env["data"]:
            if str(c.state) in ("BLOCKED", "FAILED", "BUDGET_EXHAUSTED"):
                items.append({
                    "kind": "campaign",
                    "id": c.campaign_id,
                    "reason": c.termination_reason or str(c.state),
                    "target": c.program,
                    "at": c.updated_at,
                    "link": f"/ui/soc/campaigns/{c.campaign_id}",
                    "source": "campaign.store",
                })
    else:
        unavailable.append("campaign.store")
    ver_env = sources.verifications()
    if ver_env["state"] == "ok":
        for v in ver_env["data"]:
            if str(v.state) in ("BLOCKED", "FAILED"):
                items.append({
                    "kind": "verification",
                    "id": v.verification_id,
                    "reason": v.gate_reason or v.termination_reason
                              or str(v.state),
                    "target": "",
                    "at": v.updated_at,
                    "link": f"/ui/soc/findings/{v.candidate_id}",
                    "source": "finding.store",
                })
    else:
        unavailable.append("finding.store.verifications")
    jobs_env = sources.jobs()
    if jobs_env["state"] == "ok":
        for job in jobs_env["data"]:
            if str(job.status) == "TERMINAL_FAILED" and in_window(
                    str(job.updated_at or job.completed_at or ""),
                    iso_lower):
                items.append({
                    "kind": "job",
                    "id": job.id,
                    "reason": job.error or "terminal failure",
                    "target": job.subdomain,
                    "at": str(job.updated_at or job.completed_at or ""),
                    "link": None,
                    "source": "runtime.store",
                })
    else:
        unavailable.append("runtime.store.jobs")
    items.sort(key=lambda b: str(b.get("at") or ""), reverse=True)
    state = UNAVAILABLE if unavailable else (OK if items else NOT_OBSERVED)
    return metric(items[:50], source="hunt/campaign/finding/runtime stores",
                  population="blocked objectives, blocked/failed campaigns, "
                             "blocked/failed verifications, terminal-failed "
                             "jobs in window",
                  aggregation="state predicates over persisted records, "
                              "newest first", time_range=window,
                  state=state,
                  unavailable_sources=unavailable)
