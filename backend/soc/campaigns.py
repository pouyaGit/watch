"""backend/soc/campaigns.py — SOC campaign visibility (read-only).

Projects the Campaign Orchestrator's persisted stores into the existing
AI SOC: campaign list, campaign detail (state, objectives, budget,
activity, termination) and objective detail (dependencies, hunt plans,
observations, cases, memory, evidence state).

Views only: no state changes, no invented counters.  Every number comes
from the same append-only files the orchestrator wrote; missing stores
render as honest empty states.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.soc._util import _bounded, _text

_STATE_ORDER = ("RUNNING", "WAITING", "PAUSED", "READY", "DRAFT",
                "COMPLETED", "BLOCKED", "BUDGET_EXHAUSTED", "FAILED",
                "EXPIRED", "CANCELLED")


def _campaign_store():
    from backend.research_agents.campaign.store import CampaignStore
    from backend.research_agents.runtime_store import default_store

    return CampaignStore(default_store().base)


def _runtime_store():
    from backend.research_agents.runtime_store import default_store

    return default_store()


def _budget_view(cs, campaign) -> dict[str, Any]:
    from backend.research_agents.campaign.budget import CampaignBudget

    objectives = cs.objectives_for_campaign(campaign.campaign_id)
    budget = CampaignBudget(cs, campaign)
    budget.sync_from_objectives(objectives)
    return budget.report().to_dict()


def _objective_counts(objectives: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for obj in objectives:
        counts[obj.state] = counts.get(obj.state, 0) + 1
    return counts


def _next_objective(objectives: list) -> dict[str, Any] | None:
    """Deterministic next-in-line preview (priority, then age)."""

    ready = [o for o in objectives
             if o.state in ("QUEUED", "READY", "WAITING")]
    if not ready:
        return None
    ready.sort(key=lambda o: (-int(o.priority), o.created_at,
                              o.objective_id))
    head = ready[0]
    return {"objective_id": head.objective_id,
            "category": head.category,
            "priority": head.priority,
            "state": head.state,
            "research_question": _text(head.research_question, 160)}


def _objective_evidence_view(store, obj) -> dict[str, Any]:
    """Real evidence/gate state for one objective (from its job)."""

    view: dict[str, Any] = {
        "job_id": obj.job_id,
        "job_status": "",
        "gate_reason": "",
        "case_id": "",
        "confidence": "",
        "evidence_rows": 0,
        "hunt": {},
    }
    if not obj.job_id:
        return view
    job = store.get(obj.job_id)
    if job is not None:
        view["job_status"] = _text(job.status, 40)
    result = store.get_result(obj.job_id)
    if result is not None:
        structured = result.structured or {}
        lineage = structured.get("research_lineage") or {}
        view["gate_reason"] = _text(lineage.get("gate_reason"), 120)
        view["case_id"] = _text(lineage.get("case_id"), 60)
        view["confidence"] = _text(result.confidence, 40)
        view["hunt"] = structured.get("hunt") or {}
    try:
        view["evidence_rows"] = len(store.list_evidence(job_id=obj.job_id))
    except Exception:  # noqa: BLE001 - honest zero on read failure
        view["evidence_rows"] = 0
    return view


# ---------------------------------------------------------------------------
# campaign list
# ---------------------------------------------------------------------------

def campaigns_index() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    store = _runtime_store()
    if not Path(store.base).exists():
        return {"count": 0, "campaigns": [],
                "empty_reason": "runtime store absent — no campaigns "
                                "have been created yet"}
    try:
        cs = _campaign_store()
        campaigns = cs.list_campaigns()
    except Exception as exc:  # noqa: BLE001 - honest error, no fabrication
        return {"count": 0, "campaigns": [],
                "empty_reason": f"campaign store unavailable: "
                                f"{_text(exc, 120)}"}
    for camp in campaigns:
        objectives = cs.objectives_for_campaign(camp.campaign_id)
        counts = _objective_counts(objectives)
        budget = _budget_view(cs, camp)
        rows.append({
            "campaign_id": camp.campaign_id,
            "program": _text(camp.program, 60),
            "scope_ref": _text(camp.scope_ref, 80),
            "objective": _text(camp.campaign_objective, 160),
            "state": camp.state,
            "priority": camp.priority,
            "objective_total": len(objectives),
            "objective_counts": counts,
            "active": counts.get("RUNNING", 0),
            "resolved": counts.get("RESOLVED", 0),
            "rejected": counts.get("REJECTED", 0),
            "blocked": counts.get("BLOCKED", 0),
            "terminal": counts.get("RESOLVED", 0)
            + counts.get("REJECTED", 0)
            + counts.get("FAILED", 0)
            + counts.get("CANCELLED", 0)
            + counts.get("EXPIRED", 0),
            "remaining_objectives": len([
                o for o in objectives if not o.is_terminal]),
            "budget_remaining": budget.get("remaining", {}),
            "termination_reason": _text(camp.termination_reason, 160),
            "created_at": _text(camp.created_at, 40),
            "updated_at": _text(camp.updated_at, 40),
            "detail_url": f"/ui/soc/campaigns/{camp.campaign_id}",
        })
    rows.sort(key=lambda r: (_STATE_ORDER.index(r["state"])
                             if r["state"] in _STATE_ORDER else 99,
                             r["created_at"]))
    return {"count": len(rows), "campaigns": _bounded(rows, 100),
            "empty_reason": ""}


# ---------------------------------------------------------------------------
# campaign detail
# ---------------------------------------------------------------------------

def campaign_detail(campaign_id: str) -> dict[str, Any] | None:
    store = _runtime_store()
    try:
        cs = _campaign_store()
        camp = cs.get_campaign(campaign_id)
    except Exception:  # noqa: BLE001
        return None
    if camp is None:
        return None

    objectives = cs.objectives_for_campaign(campaign_id)
    counts = _objective_counts(objectives)
    budget = _budget_view(cs, camp)

    objective_rows: list[dict[str, Any]] = []
    current_specialist = ""
    current_hunt_plan = ""
    latest_evidence: dict[str, Any] = {}
    latest_evidence_at = ""
    for obj in sorted(objectives,
                      key=lambda o: (o.created_at, o.objective_id)):
        ev = _objective_evidence_view(store, obj)
        if obj.state == "RUNNING" and obj.job_id:
            current_specialist = obj.specialist or _text(
                (store.get(obj.job_id).assigned_agent
                 if store.get(obj.job_id) else ""), 60)
            plan_ids = (ev.get("hunt") or {}).get("plan_ids") or []
            current_hunt_plan = _text(plan_ids[-1], 60) if plan_ids else ""
        if ev["evidence_rows"] and obj.updated_at >= latest_evidence_at:
            latest_evidence_at = obj.updated_at
            latest_evidence = {
                "objective_id": obj.objective_id,
                "job_id": obj.job_id,
                "rows": ev["evidence_rows"],
                "gate_reason": ev["gate_reason"],
                "case_id": ev["case_id"],
                "confidence": ev["confidence"],
            }
        objective_rows.append({
            "objective_id": obj.objective_id,
            "category": obj.category,
            "specialist": obj.specialist or "(selector)",
            "state": obj.state,
            "priority": obj.priority,
            "attempts": obj.attempts,
            "job_id": obj.job_id,
            "research_question": _text(obj.research_question, 160),
            "dependencies": [
                {"depends_on": d.depends_on, "kind": d.kind,
                 "dep_state": next(
                     (o.state for o in objectives
                      if o.objective_id == d.depends_on), "missing")}
                for d in obj.dependencies],
            "termination_reason": _text(obj.termination_reason, 160),
            "gate_reason": ev["gate_reason"],
            "case_id": ev["case_id"],
            "evidence_rows": ev["evidence_rows"],
            "detail_url":
                f"/ui/soc/campaigns/{campaign_id}/objectives/"
                f"{obj.objective_id}",
        })

    # campaign activity: campaign_* rows + rows tied to campaign jobs
    campaign_job_ids = {o.job_id for o in objectives if o.job_id}
    activity_rows: list[dict[str, Any]] = []
    try:
        for row in store.list_activity(limit=300):
            if row.get("campaign_id") == campaign_id or \
                    row.get("job_id") in campaign_job_ids:
                activity_rows.append({
                    "at": _text(row.get("at"), 40),
                    "action": _text(row.get("action"), 60),
                    "detail": _text(row.get("detail"), 240),
                    "objective_id": _text(row.get("objective_id"), 40),
                    "job_id": _text(row.get("job_id"), 40),
                })
    except Exception:  # noqa: BLE001
        activity_rows = []
    activity_rows.reverse()   # newest first (store appends oldest first)

    context_rows = []
    try:
        for row in cs.context_for(campaign_id, limit=20):
            context_rows.append({
                "at": _text(row.get("at"), 40),
                "source_objective_id": _text(
                    row.get("source_objective_id"), 40),
                "text": _text(row.get("text"), 240),
                "confidence": _text(row.get("confidence"), 40),
                "research_context_only": True,
            })
    except Exception:  # noqa: BLE001
        context_rows = []
    context_rows.reverse()

    budget_rows = []
    for k, v in sorted(budget.get("limits", {}).items()):
        res = k[4:] if k.startswith("max_") else k
        budget_rows.append({
            "resource": res,
            "used": int(budget.get("used", {}).get(res, 0) or 0),
            "limit": v,
            "remaining": budget.get("remaining", {}).get(res, "")})

    return {
        "campaign": {
            "campaign_id": camp.campaign_id,
            "program": _text(camp.program, 60),
            "scope_ref": _text(camp.scope_ref, 80),
            "objective": _text(camp.campaign_objective, 400),
            "state": camp.state,
            "priority": camp.priority,
            "created_at": _text(camp.created_at, 40),
            "updated_at": _text(camp.updated_at, 40),
            "lease": (f"held by {camp.lease_owner} until "
                      f"{camp.lease_expires_at}"
                      if camp.lease_owner else "no active coordinator"),
            "termination_reason": _text(camp.termination_reason, 200),
            "termination_detail": _text(camp.termination_detail, 300),
            "termination_record": dict(camp.termination_record or {}),
            "is_terminal": camp.is_terminal,
        },
        "counts": counts,
        "objective_total": len(objectives),
        "active_objective": next(
            (r for r in objective_rows if r["state"] == "RUNNING"), None),
        "completed_objectives": counts.get("RESOLVED", 0),
        "blocked_objectives": counts.get("BLOCKED", 0),
        "rejected_objectives": counts.get("REJECTED", 0),
        "remaining_objectives": len(
            [o for o in objectives if not o.is_terminal]),
        "next_objective": _next_objective(objectives),
        "current_specialist": current_specialist,
        "current_hunt_plan": current_hunt_plan,
        "latest_evidence": latest_evidence,
        "objectives": objective_rows,
        "budget": budget,
        "budget_rows": budget_rows,
        "activity": _bounded(activity_rows, 60),
        "context": _bounded(context_rows, 20),
        "empty_objectives": not objective_rows,
    }


# ---------------------------------------------------------------------------
# objective detail
# ---------------------------------------------------------------------------

def objective_detail(campaign_id: str, objective_id: str) -> dict[str, Any] | None:
    store = _runtime_store()
    try:
        cs = _campaign_store()
        camp = cs.get_campaign(campaign_id)
        if camp is None:
            return None
        obj = cs.get_objective(objective_id)
    except Exception:  # noqa: BLE001
        return None
    if obj is None or obj.campaign_id != campaign_id:
        return None

    objectives = cs.objectives_for_campaign(campaign_id)
    ev = _objective_evidence_view(store, obj)

    # hunt plans / authorizations / observations — real store rows only
    plans: list[dict[str, Any]] = []
    authorizations: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    hunt_obj_id = str((ev.get("hunt") or {}).get("objective_id") or "")
    try:
        from backend.research_agents.hunt.store import HuntStore
        hstore = HuntStore(store.base)
        if hunt_obj_id:
            for plan in hstore.plans_for_objective(hunt_obj_id):
                plans.append({
                    "plan_id": plan.plan_id,
                    "version": plan.version,
                    "state": _text(hstore.plan_state(plan.plan_id), 30),
                    "types": [
                        str(o.get("observation_type", ""))
                        for o in plan.observations_requested
                        if isinstance(o, dict)
                        and o.get("observation_type")],
                    "reason": _text(plan.reason, 200),
                })
        if obj.job_id:
            for rec in hstore.observations_for_job(obj.job_id):
                observations.append({
                    "observation_id": _text(rec.observation_id, 60),
                    "types": [str(t)
                              for t in rec.observation_types],
                    "outcome": _text(rec.outcome, 40),
                    "new_rows": int(rec.new_rows),
                    "authorization_id": _text(rec.auth_id, 60),
                })
        for aid in (ev.get("hunt") or {}).get("authorization_ids") or []:
            rec = hstore.get_authorization(_text(aid, 60))
            if rec is not None:
                authorizations.append({
                    "auth_id": _text(rec.auth_id, 60),
                    "status": _text(rec.status, 30),
                    "scope_ref": _text(rec.scope_ref, 80),
                })
    except Exception:  # noqa: BLE001 - honest empty lists on read failure
        plans, authorizations, observations = [], [], []

    # cases from this objective's job
    cases: list[dict[str, Any]] = []
    if obj.job_id:
        try:
            for case in store.list_cases():
                if case.get("job_id") == obj.job_id:
                    cases.append({
                        "case_id": _text(case.get("id"), 60),
                        "confidence": _text(case.get("confidence"), 40),
                        "hypothesis": _text(case.get("hypothesis"), 200),
                    })
        except Exception:  # noqa: BLE001
            cases = []

    # memory learned — real memory rows with this job's provenance
    memory: list[dict[str, Any]] = []
    try:
        mem_path = Path(store.base) / "memory.jsonl"
        if mem_path.exists():
            with mem_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    prov = (row.get("provenance") or {})
                    if prov.get("job_id") == obj.job_id or \
                            str(prov.get("source", "")).startswith(
                                f"campaign:{campaign_id}"):
                        memory.append({
                            "id": _text(row.get("id"), 60),
                            "kind": _text(row.get("kind"), 40),
                            "state": _text(row.get("state"), 20),
                            "text": _text(row.get("text"), 240),
                        })
    except Exception:  # noqa: BLE001
        memory = []
    memory.reverse()

    hunt = ev.get("hunt") or {}
    return {
        "campaign_id": campaign_id,
        "objective": {
            "objective_id": obj.objective_id,
            "category": obj.category,
            "specialist": obj.specialist or "(selected at run time)",
            "state": obj.state,
            "priority": obj.priority,
            "attempts": obj.attempts,
            "research_question": _text(obj.research_question, 400),
            "hypothesis": _text(obj.hypothesis, 400),
            "scope_ref": _text(obj.scope_ref, 80),
            "created_at": _text(obj.created_at, 40),
            "updated_at": _text(obj.updated_at, 40),
            "job_id": obj.job_id,
            "termination_reason": _text(obj.termination_reason, 200),
            "termination_detail": _text(obj.termination_detail, 300),
            "evidence_requirements": dict(obj.evidence_requirements or {}),
        },
        "dependencies": [
            {"depends_on": d.depends_on, "kind": d.kind,
             "dep_state": next(
                 (o.state for o in objectives
                  if o.objective_id == d.depends_on), "missing"),
             "dep_question": _text(
                 next((o.research_question for o in objectives
                       if o.objective_id == d.depends_on), ""), 160)}
            for d in obj.dependencies],
        "evidence": {
            "job_status": ev["job_status"],
            "gate_reason": ev["gate_reason"],
            "case_id": ev["case_id"],
            "confidence": ev["confidence"],
            "evidence_rows": ev["evidence_rows"],
        },
        "hunt": {
            "objective_id": hunt_obj_id,
            "state": _text(hunt.get("state"), 30),
            "termination_reason": _text(
                hunt.get("termination_reason"), 160),
            "plan_ids": list(hunt.get("plan_ids") or []),
            "authorization_ids": list(
                hunt.get("authorization_ids") or []),
            "observation_ids": list(hunt.get("observation_ids") or []),
            "rows_added": int(hunt.get("rows_added") or 0),
            "llm_advisory": dict(hunt.get("llm_advisory") or {}),
        },
        "plans": plans,
        "authorizations": authorizations,
        "observations": observations,
        "cases": cases,
        "memory": memory,
        "campaign_state": camp.state,
    }


__all__ = ["campaigns_index", "campaign_detail", "objective_detail"]
