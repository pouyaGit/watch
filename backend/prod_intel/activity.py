"""backend/prod_intel/activity.py — meaningful autonomous activity.

The MEANINGINGFUL-ACTIVITY DEFINITION (Epic8 section 2), applied to the
append-only runtime audit trail (``audit.jsonl`` — the same file the
runtime, campaign, hunt and finding layers all append to):

An audit event is *meaningful* iff its ``event`` name maps to one of the
documented categories below. Events outside the taxonomy are NOT shown
as activity (lineage/bookkeeping rows are provenance, not operations).
Failure events are meaningful but are typed ``failure``/``denied``/
``blocked`` so a failed attempt can NEVER be read as successful work.

Categories (examples mandated by the Epic, plus the documented extras):
  research_started          job enqueued/claimed/started, campaign obj start
  research_completed        job completed / result persisted
  research_failed           job failed / terminal failed / timeout
  research_retry            job retry
  hunt_objective_created    hunt lineage opened for a job
  authorization_granted     hunt authorization GRANTED
  authorization_denied      hunt authorization DENIED (fail-closed record)
  typed_observation_produced  evidence row recorded
  candidate_created         candidate detected
  candidate_correlated      candidate deduplicated / correlated
  candidate_triaged         candidate triaged
  verification_started      verification created/started
  verification_authorized   verification authorization recorded
  verification_completed    gate decided
  case_created              runtime or finding case created
  case_transitioned         case state change (reason carried)
  handoff_produced          case handoff-ready package produced
  campaign_started/paused/resumed/terminated  campaign lifecycle
  campaign_objective_started/terminal         objective lifecycle
  knowledge_used            KB document used for a job
  knowledge_retrieval       intelligence memory retrieved
  knowledge_memory_update   learning loop wrote memory items
  integrity_repair          audited one-way data correction

Every item carries: category, event, at, kind, context (source ids),
``link`` (deep link when a stable object route exists, else None — the
context always carries the ids), and ``source`` provenance.
"""

from __future__ import annotations

from typing import Any

from backend.prod_intel import sources
from backend.prod_intel.semantics import (
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    in_window,
    metric,
    window_bounds,
)

# event -> (category, kind)   kind: progression | failure | denied | blocked
EVENT_CATEGORY: dict[str, tuple[str, str]] = {
    # research lifecycle
    "job_enqueued": ("research_started", "progression"),
    "job_claimed": ("research_started", "progression"),
    "job_started": ("research_started", "progression"),
    "job_completed": ("research_completed", "progression"),
    "result_persisted": ("research_completed", "progression"),
    "job_failed": ("research_failed", "failure"),
    "job_terminal_failed": ("research_failed", "failure"),
    "job_timeout": ("research_failed", "failure"),
    "job_retry": ("research_retry", "progression"),
    # hunt
    "hunt_lineage": ("hunt_objective_created", "progression"),
    "hunt_authorization": ("authorization_granted", "progression"),
    # observations/evidence
    "evidence_recorded": ("typed_observation_produced", "progression"),
    # candidates
    "finding_candidate_detected": ("candidate_created", "progression"),
    "finding_candidate_deduplicated": ("candidate_correlated", "progression"),
    "finding_candidate_triaged": ("candidate_triaged", "progression"),
    # verification
    "finding_verification_created": ("verification_started", "progression"),
    "finding_verification_started": ("verification_started", "progression"),
    "finding_verification_authorized": ("verification_authorized",
                                        "progression"),
    "finding_verification_gate_decided": ("verification_completed",
                                          "progression"),
    # cases / handoff
    "case_created": ("case_created", "progression"),
    "finding_case_created": ("case_created", "progression"),
    "finding_case_state": ("case_transitioned", "progression"),
    "finding_case_handoff_ready": ("handoff_produced", "progression"),
    "finding_integrity_repair": ("integrity_repair", "progression"),
    # campaigns
    "campaign_started": ("campaign_started", "progression"),
    "campaign_paused": ("campaign_paused", "progression"),
    "campaign_resumed": ("campaign_resumed", "progression"),
    "campaign_terminated": ("campaign_terminated", "progression"),
    "campaign_objective_started": ("campaign_objective_started",
                                   "progression"),
    "campaign_objective_terminal": ("campaign_objective_terminal",
                                    "progression"),
    # knowledge / memory
    "knowledge_used": ("knowledge_used", "progression"),
    "intelligence_memory_retrieved": ("knowledge_retrieval", "progression"),
    "intelligence_memory_learned": ("knowledge_memory_update", "progression"),
    "intelligence_lineage_recorded": ("knowledge_memory_update",
                                      "progression"),
}

_MEANINGFUL_CATEGORIES = sorted({c for c, _ in EVENT_CATEGORY.values()})

FAILURE_CATEGORIES = frozenset({
    "research_failed", "authorization_denied",
})


def _authorization_kind(row: dict[str, Any]) -> str:
    return ("progression" if str(row.get("status") or "").upper() == "GRANTED"
            else "denied")


def _link(row: dict[str, Any], category: str) -> str | None:
    """Deep link only where a stable object route exists."""
    cand = str(row.get("candidate_id") or "")
    if cand:
        return f"/ui/soc/findings/{cand}"
    case_id = str(row.get("case_id") or "")
    if case_id:
        return (f"/ui/soc/findings/{cand}" if cand
                else f"/ui/soc/cases/{case_id}")
    camp = str(row.get("campaign_id") or "")
    obj = str(row.get("objective_id") or "")
    if camp and category.startswith("campaign_objective") and obj:
        return f"/ui/soc/campaigns/{camp}/objectives/{obj}"
    if camp and category.startswith("campaign"):
        return f"/ui/soc/campaigns/{camp}"
    doc = str(row.get("document") or "")
    if doc and category == "knowledge_used":
        return f"/ui/kb/{doc}"
    return None     # job/hunt-scoped rows: context ids carry navigation


def _context(row: dict[str, Any]) -> dict[str, Any]:
    """Source ids an analyst needs to navigate to the origin object."""
    keep = ("job_id", "candidate_id", "case_id", "verification_id",
            "objective_id", "campaign_id", "plan_id", "auth_id",
            "evidence_id", "document", "specialist", "category", "status",
            "state", "reason", "gate_reason", "decision", "relation",
            "duplicate_id", "canonical_id", "mode")
    return {k: row[k] for k in keep if row.get(k) not in (None, "", [], {})}


def build_feed(*, hours: float | int | None = None,
               limit: int = 60) -> dict[str, Any]:
    """Chronological meaningful-activity feed (newest first, bounded)."""
    iso_lower, window = window_bounds(hours)
    env = sources.audit()
    if env["state"] != "ok":
        return metric(None, source="runtime.audit",
                      population="append-only runtime audit events",
                      aggregation="meaningful events, newest first",
                      time_range=window, state=UNAVAILABLE,
                      reason=env["reason"], items=[],
                      categories=_MEANINGFUL_CATEGORIES)
    items: list[dict[str, Any]] = []
    for row in env["data"]:
        event = str(row.get("event") or "")
        mapped = EVENT_CATEGORY.get(event)
        if mapped is None:
            continue                                   # not meaningful
        category, kind = mapped
        if event == "hunt_authorization":
            kind = _authorization_kind(row)
            category = ("authorization_granted" if kind == "progression"
                        else "authorization_denied")
        ts = str(row.get("ts") or row.get("at") or "")
        if not in_window(ts, iso_lower):
            continue
        items.append({
            "category": category,
            "event": event,
            "kind": kind,
            "at": ts,
            "context": _context(row),
            "link": _link(row, category),
            "source": "runtime_audit",
        })
    items.sort(key=lambda r: r["at"], reverse=True)
    items = items[:max(1, int(limit))]
    state = OK if items else NOT_OBSERVED
    return metric(items, source="runtime.audit",
                  population="append-only runtime audit events mapped to "
                             "the documented meaningful-activity taxonomy",
                  aggregation=f"meaningful events in window, newest first, "
                              f"capped at {len(items)}",
                  time_range=window, state=state,
                  categories=_MEANINGFUL_CATEGORIES)


def current_activity() -> dict[str, Any]:
    """What the system is doing RIGHT NOW — UNKNOWN preferred to fake.

    ACTIVE only when a job is genuinely CLAIMED/RUNNING under a fresh
    worker heartbeat; otherwise the honest worker/job/campaign states.
    """
    w = sources.worker()
    jobs_env = sources.jobs()
    running: list[dict[str, Any]] = []
    if jobs_env["state"] == "ok":
        for job in jobs_env["data"]:
            st = str(getattr(job, "status", "") or "")
            if st in ("CLAIMED", "RUNNING"):
                running.append({
                    "job_id": getattr(job, "id", ""),
                    "agent": getattr(job, "assigned_agent", ""),
                    "category": getattr(job, "agent_category", ""),
                    "target": getattr(job, "subdomain", ""),
                    "status": st,
                    "link": "/ui/soc/activity",
                })
    alive = bool(w["data"].get("alive")) if w["state"] == "ok" else None
    if w["state"] != "ok":
        overall, basis = "UNKNOWN", f"worker source {w['state']}"
    elif jobs_env["state"] != "ok":
        # we cannot claim any activity state without the job records
        overall, basis = "UNKNOWN", f"job source {jobs_env['state']}"
    elif running and alive:
        overall, basis = "ACTIVE", "job executing under a live worker"
    elif running and not alive:
        # a claimed job WITHOUT a live heartbeat is a stale lease — never
        # report ACTIVE on a dead worker; UNKNOWN is the honest state
        overall, basis = ("UNKNOWN",
                          "job claimed but no live worker heartbeat "
                          "(stale lease or crashed worker)")
    elif alive:
        overall, basis = "IDLE", "fresh worker heartbeat, no running job"
    else:
        overall, basis = "PLANNED", str(w["data"].get("reason") or "")
    return {
        "state": overall,
        "basis": basis,
        "worker": ({"alive": bool(w["data"].get("alive")),
                    "last_heartbeat": w["data"].get("last_heartbeat", ""),
                    "reason": w["data"].get("reason", "")}
                   if w["state"] == "ok"
                   else {"state": UNAVAILABLE, "reason": w["reason"]}),
        "running_jobs": running,
        "rule_version": "production-intelligence-v1",
    }
