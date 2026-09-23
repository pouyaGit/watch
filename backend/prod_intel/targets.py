"""backend/prod_intel/targets.py — target-level intelligence.

Targets are discovered ONLY from persisted records (jobs, candidates,
campaigns, hunt objectives, memory heads) — never guessed. For every
discovered target we expose scope, bounded attack-surface counts,
research/campaign/findings/cases/learning lineage, and time-aware
MEANINGFUL ACTIVITY attributed strictly by id membership (a target is
credited with an audit event only when the event's job/candidate/case/
campaign id belongs to that target — never by keyword guessing).
"""

from __future__ import annotations

import re
from typing import Any

from backend.prod_intel import activity as activity_mod
from backend.prod_intel import learning_signals as learning_mod
from backend.prod_intel import sources
from backend.prod_intel.overview import _ACTIVE_CAMPAIGN  # shared definition
from backend.prod_intel.semantics import (
    DEFAULT_WINDOW_HOURS,
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    in_window,
    metric,
    unavailable_metric,
    window_bounds,
)

_SCOPE_RE = re.compile(r"^watch:scope:(?P<program>[^/]+)/(?P<target>.+)$")
_TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", re.I)


def _norm_target(label: str) -> str:
    label = str(label or "").strip().lower()
    return label if _TARGET_RE.match(label) else ""


def _scope_parts(scope_ref: str) -> tuple[str, str]:
    m = _SCOPE_RE.match(str(scope_ref or ""))
    if not m:
        return "", ""
    return m.group("program"), _norm_target(m.group("target"))


def discover_targets() -> dict[str, Any]:
    """Every target mentioned by a persisted record, with its scopes."""
    targets: dict[str, dict[str, Any]] = {}

    def slot(t: str) -> dict[str, Any]:
        if t not in targets:
            targets[t] = {"target": t, "programs": set(), "scopes": set(),
                          "sources": set()}
        return targets[t]

    jobs_env = sources.jobs()
    if jobs_env["state"] == "ok":
        for job in jobs_env["data"]:
            t = _norm_target(getattr(job, "subdomain", ""))
            if t:
                s = slot(t)
                p = str(getattr(job, "program", "") or "")
                if p:
                    s["programs"].add(p)
                sc = str(getattr(job, "scope_ref", "") or "")
                if sc:
                    s["scopes"].add(sc)
                s["sources"].add("runtime.jobs")

    cand_env = sources.candidates()
    if cand_env["state"] == "ok":
        for c in cand_env["data"]:
            t = _norm_target(c.target)
            if t:
                s = slot(t)
                prog, _ = _scope_parts(c.scope_ref)
                if prog:
                    s["programs"].add(prog)
                s["scopes"].add(c.scope_ref)
                s["sources"].add("finding.candidates")

    camp_env = sources.campaigns()
    if camp_env["state"] == "ok":
        for c in camp_env["data"]:
            t = _norm_target(
                (c.target_context or {}).get("subdomain", "")
                if isinstance(c.target_context, dict) else "")
            if t:
                s = slot(t)
                s["programs"].add(str(c.program))
                s["scopes"].add(c.scope_ref)
                s["sources"].add("campaign.campaigns")

    hunt_env = sources.hunt_objectives()
    if hunt_env["state"] == "ok":
        for o in hunt_env["data"]:
            ctx = o.target_context if isinstance(o.target_context, dict) else {}
            t = _norm_target(str(ctx.get("subdomain", ""))
                             or str(ctx.get("target", "")))
            if not t:
                _, t = _scope_parts(o.scope_ref)
            if t:
                s = slot(t)
                prog, _ = _scope_parts(o.scope_ref)
                if prog:
                    s["programs"].add(prog)
                s["scopes"].add(o.scope_ref)
                s["sources"].add("hunt.objectives")

    mem_env = sources.memory_heads()
    if mem_env["state"] == "ok":
        for item in mem_env["data"]:
            t = _norm_target(item.target)
            if t:
                s = slot(t)
                if item.program:
                    s["programs"].add(str(item.program))
                s["sources"].add("intelligence.memory")

    unavailable = [name for name, env in (
        ("runtime.jobs", jobs_env), ("finding.candidates", cand_env),
        ("campaign.campaigns", camp_env), ("hunt.objectives", hunt_env),
        ("intelligence.memory", mem_env)) if env["state"] != "ok"]

    return {
        "targets": sorted(targets.values(),
                          key=lambda s: s["target"]),
        "unavailable_sources": unavailable,
    }


def _id_index(target: str, disc: dict[str, Any]
              ) -> dict[str, set[str]]:
    """job/candidate/case/campaign ids attributable to this target."""
    entry = next((s for s in disc.get("targets", [])
                  if s["target"] == target), None)
    if entry is None:
        return {k: set() for k in ("job_id", "candidate_id", "case_id",
                                   "campaign_id", "objective_id")}
    ids: dict[str, set[str]] = {"job_id": set(), "candidate_id": set(),
                                "case_id": set(), "campaign_id": set(),
                                "objective_id": set()}
    scope_set = entry["scopes"]
    jobs_env = sources.jobs()
    if jobs_env["state"] == "ok":
        for job in jobs_env["data"]:
            if (_norm_target(getattr(job, "subdomain", "")) == target
                    or str(getattr(job, "scope_ref", "") or "") in scope_set):
                ids["job_id"].add(str(job.id))
    cand_env = sources.candidates()
    if cand_env["state"] == "ok":
        for c in cand_env["data"]:
            if _norm_target(c.target) == target:
                ids["candidate_id"].add(c.candidate_id)
                if c.case_id:
                    ids["case_id"].add(str(c.case_id))
                if c.source_job:
                    ids["job_id"].add(str(c.source_job))
    fc_env = sources.finding_cases()
    if fc_env["state"] == "ok":
        for case in fc_env["data"]:
            if _norm_target(case.target) == target:
                ids["case_id"].add(case.case_id)
                if case.candidate_id:
                    ids["candidate_id"].add(case.candidate_id)
    camp_env = sources.campaigns()
    if camp_env["state"] == "ok":
        for c in camp_env["data"]:
            t = _norm_target((c.target_context or {}).get("subdomain", "")
                             if isinstance(c.target_context, dict) else "")
            if t == target or str(c.scope_ref) in scope_set:
                ids["campaign_id"].add(c.campaign_id)
    hunt_env = sources.hunt_objectives()
    if hunt_env["state"] == "ok":
        for o in hunt_env["data"]:
            ctx = o.target_context if isinstance(o.target_context, dict) else {}
            if _norm_target(str(ctx.get("subdomain", ""))) == target \
                    or str(o.scope_ref) in scope_set:
                ids["objective_id"].add(o.objective_id)
                if o.job_id:
                    ids["job_id"].add(str(o.job_id))
    return ids


def target_intelligence(*, hours: float | int | None = DEFAULT_WINDOW_HOURS
                        ) -> dict[str, Any]:
    """List projection: every discovered target with provenance."""
    iso_lower, window = window_bounds(hours)
    disc = discover_targets()
    rows = [target_detail(s["target"], disc=disc, iso_lower=iso_lower,
                          window=window)
            for s in disc["targets"]]
    return {
        "state": "ok" if rows else "unknown",
        "rule_version": "production-intelligence-v1",
        "window": window,
        "meaningful_activity_definition":
            activity_mod.build_feed(hours=None, limit=1).get(
                "categories", []),
        "count": len(rows),
        "unavailable_sources": disc["unavailable_sources"],
        "targets": rows,
    }


def target_detail(target: str, *, disc: dict[str, Any] | None = None,
                  iso_lower: str = "", window: dict[str, Any] | None = None
                  ) -> dict[str, Any]:
    """Full intelligence bundle for one target (all honest states)."""
    if window is None:
        iso_lower, window = window_bounds(DEFAULT_WINDOW_HOURS)
    disc = disc or discover_targets()
    entry = next((s for s in disc["targets"] if s["target"] == target), None)
    if entry is None:
        return {"target": target, "found": False,
                "reason": "target not present in any persisted record",
                "state": NOT_OBSERVED}

    programs = sorted(entry["programs"])
    scopes = sorted(entry["scopes"])

    # -- attack surface (bounded Mongo counts; unavailable on failure) ----
    surface_env = sources.attack_surface(target)
    attack_surface = (
        metric(surface_env["data"], source="recon database (Urls, "
               "Endpoints)", population=f"rows with subdomain={target}",
               aggregation="exact count_documents per collection",
               time_range={"kind": "current_snapshot"}, state=OK)
        if surface_env["state"] == "ok"
        else metric(None, source="recon database",
                    population=f"rows with subdomain={target}",
                    aggregation="count", time_range={"kind": "snapshot"},
                    state=UNAVAILABLE, reason=surface_env["reason"]))

    # -- research activity -------------------------------------------------
    jobs_env = sources.jobs()
    job_rows = []
    if jobs_env["state"] == "ok":
        job_rows = [j for j in jobs_env["data"]
                    if _norm_target(j.subdomain) == target]
    by_status: dict[str, int] = {}
    for j in job_rows:
        by_status[str(j.status)] = by_status.get(str(j.status), 0) + 1
    recent_jobs = [j for j in job_rows
                   if in_window(str(j.updated_at or j.created_at or ""),
                                iso_lower)]
    research = metric(
        {"by_status": by_status, "total": len(job_rows),
         "recent": len(recent_jobs)},
        source="runtime.store", population=f"jobs with subdomain={target}",
        aggregation="count by status; recent = updated in window",
        time_range=window,
        state=(OK if job_rows else NOT_OBSERVED)
        if jobs_env["state"] == "ok" else UNAVAILABLE,
        reason=jobs_env["reason"] or "")

    # -- campaigns ---------------------------------------------------------
    camp_env = sources.campaigns()
    camp_rows: list[dict[str, Any]] = []
    if camp_env["state"] == "ok":
        for c in camp_env["data"]:
            ctx = c.target_context if isinstance(c.target_context, dict) else {}
            if _norm_target(str(ctx.get("subdomain", ""))) == target \
                    or str(c.scope_ref) in scopes:
                camp_rows.append({"campaign_id": c.campaign_id,
                                  "state": str(c.state),
                                  "link": f"/ui/soc/campaigns/{c.campaign_id}"})
    campaigns_m = metric(
        camp_rows, source="campaign.store",
        population="campaigns whose scope matches this target",
        aggregation="list with state; active/completed use the SAME "
                    "_ACTIVE_CAMPAIGN + COMPLETED definitions as the "
                    "overview projection",
        time_range=window,
        # spec §2: expose active and completed campaign counts per target
        active=sum(1 for r in camp_rows
                   if r["state"] in _ACTIVE_CAMPAIGN),
        completed=sum(1 for r in camp_rows
                      if r["state"] == "COMPLETED"),
        state=(OK if camp_rows else NOT_OBSERVED)
        if camp_env["state"] == "ok" else UNAVAILABLE,
        reason=camp_env["reason"] or "")

    # -- findings / verifications / cases ----------------------------------
    cand_env = sources.candidates()
    mine = [c for c in (cand_env["data"] or [])
            if _norm_target(c.target) == target] \
        if cand_env["state"] == "ok" else []
    cand_states: dict[str, int] = {}
    for c in mine:
        cand_states[str(c.lifecycle_state)] = (
            cand_states.get(str(c.lifecycle_state), 0) + 1)
    findings_m = metric(
        cand_states, source="finding.store",
        population="candidate findings for this target",
        aggregation="count by lifecycle state", time_range=window,
        state=(OK if mine else NOT_OBSERVED)
        if cand_env["state"] == "ok" else UNAVAILABLE,
        reason=cand_env["reason"] or "")

    ver_env = sources.verifications()
    ver_rows = [v for v in (ver_env["data"] or [])
                if v.candidate_id in {c.candidate_id for c in mine}] \
        if ver_env["state"] == "ok" else []
    ver_states: dict[str, int] = {}
    for v in ver_rows:
        ver_states[str(v.state)] = ver_states.get(str(v.state), 0) + 1
    verifications_m = metric(
        ver_states, source="finding.store",
        population="verifications of this target's candidates",
        aggregation="count by verification state", time_range=window,
        state=(OK if ver_rows else NOT_OBSERVED)
        if ver_env["state"] == "ok" else UNAVAILABLE,
        reason=ver_env["reason"] or "")

    fc_env = sources.finding_cases()
    case_rows = [c for c in (fc_env["data"] or [])
                 if _norm_target(c.target) == target] \
        if fc_env["state"] == "ok" else []
    case_states: dict[str, int] = {}
    for c in case_rows:
        case_states[str(c.state)] = case_states.get(str(c.state), 0) + 1
    cases_m = metric(
        case_states, source="finding.store",
        population="finding case packages for this target",
        aggregation="count by case state", time_range=window,
        state=(OK if case_rows else NOT_OBSERVED)
        if fc_env["state"] == "ok" else UNAVAILABLE,
        reason=fc_env["reason"] or "")

    # -- evidence (attributed via jobs) ------------------------------------
    job_ids = {str(j.id) for j in job_rows}
    ev_env = sources.evidence()
    ev_rows = [e for e in (ev_env["data"] or [])
               if str(e.get("job_id") or "") in job_ids] \
        if ev_env["state"] == "ok" else []
    evidence_m = metric(
        len(ev_rows), source="runtime.store",
        population="evidence rows from this target's jobs",
        aggregation="count", time_range=window,
        state=(OK if ev_rows else NOT_OBSERVED)
        if ev_env["state"] == "ok" else UNAVAILABLE,
        reason=ev_env["reason"] or "")

    # -- knowledge usage + memory ------------------------------------------
    ku_env = sources.knowledge_use()
    ku_rows = [k for k in (ku_env["data"] or [])
               if str(k.get("job_id") or "") in job_ids] \
        if ku_env["state"] == "ok" else []
    docs = sorted({str(k.get("document_id") or "") for k in ku_rows
                   if k.get("document_id")})
    knowledge_m = metric(
        {"uses": len(ku_rows), "distinct_documents": len(docs),
         "documents": docs[:20]},
        source="runtime.knowledge_use",
        population="knowledge-use rows for this target's jobs",
        aggregation="count + distinct document ids", time_range=window,
        state=(OK if ku_rows else NOT_OBSERVED)
        if ku_env["state"] == "ok" else UNAVAILABLE,
        reason=ku_env["reason"] or "")

    mem_env = sources.memory_heads()
    mem_rows = [i for i in (mem_env["data"] or [])
                if _norm_target(i.target) == target] \
        if mem_env["state"] == "ok" else []
    mem_states: dict[str, int] = {}
    for i in mem_rows:
        mem_states[str(i.state)] = mem_states.get(str(i.state), 0) + 1
    memory_m = metric(
        {"count": len(mem_rows), "by_state": mem_states,
         "items": [{"id": i.id, "kind": i.kind, "state": i.state}
                   for i in mem_rows[:20]]},
        source="intelligence.memory",
        population="memory item heads for this target",
        aggregation="count by memory state", time_range=window,
        state=(OK if mem_rows else NOT_OBSERVED)
        if mem_env["state"] == "ok" else UNAVAILABLE,
        reason=mem_env["reason"] or "")

    # -- time-aware meaningful activity (id-attributed only) ---------------
    ids = _id_index(target, disc)
    # the window dict carries its own hours (None = all history)
    feed_hours = (window or {}).get("hours", DEFAULT_WINDOW_HOURS)
    feed = activity_mod.build_feed(hours=feed_hours, limit=500)

    # -- learning signals recorded for this target (spec §2) --------------
    learn_metric: dict[str, Any]
    try:
        ls = learning_mod.learning_signals(hours=feed_hours)
        ls_state = ls.get("state", UNAVAILABLE) \
            if isinstance(ls, dict) else UNAVAILABLE
        sig_rows = [s for s in (ls.get("value") or [])
                    if str(s.get("target") or "") == target] \
            if ls_state == OK else []
        learn_metric = metric(
            {"count": len(sig_rows), "signals": sig_rows[:20]},
            source="prod_intel.learning_signals",
            population="derived learning signals whose recorded target "
                       "matches this target",
            aggregation="derived pattern count (state capped at INFERRED; "
                        "REJECTED preserved)",
            time_range=window,
            state=(OK if sig_rows else NOT_OBSERVED)
            if ls_state == OK else ls_state,
            reason=str(ls.get("reason") or ""))
    except Exception as exc:                      # fail-closed projection
        learn_metric = unavailable_metric(
            "prod_intel.learning_signals", "target learning signals",
            "derived signal list", f"{type(exc).__name__}: {exc}")
    mine_events = []
    if isinstance(feed.get("value"), list):
        for item in feed["value"]:
            ctx = item.get("context") or {}
            if any(str(ctx.get(k) or "") in ids[k]
                   for k in ("job_id", "candidate_id", "case_id",
                             "campaign_id", "objective_id")):
                mine_events.append(item)
    last_activity = mine_events[0]["at"] if mine_events else ""
    activity_m = metric(
        mine_events[:20], source=feed.get("source", "runtime.audit"),
        population="meaningful audit events whose job/candidate/case/"
                   "campaign/objective id belongs to this target",
        aggregation="id-attributed meaningful events, newest first",
        time_range=window, state=feed.get("state", UNAVAILABLE)
        if mine_events else NOT_OBSERVED)

    return {
        "target": target,
        "found": True,
        "programs": programs,
        "scopes": scopes,
        "discovery_sources": sorted(entry["sources"]),
        "attack_surface": attack_surface,
        "research": research,
        "campaigns": campaigns_m,
        "findings": findings_m,
        "verifications": verifications_m,
        "cases": cases_m,
        "evidence": evidence_m,
        "knowledge": knowledge_m,
        "memory": memory_m,
        "learning": learn_metric,
        "activity": activity_m,
        "last_meaningful_activity": last_activity,
        "window": window,
        "rule_version": "production-intelligence-v1",
    }
