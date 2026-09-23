"""EPIC9 §4/§5: fail-closed work discovery over EXISTING authoritative
stores. No new queue: every item below already lives in a Watch store.

Each discovered item carries an explicit executable/not classification
with a closed reason vocabulary (§5) so nothing is silently skipped.
Classification functions are pure (dataclasses in, WorkItem out) and the
IO wrapper ``discover()`` is fail-soft per source: an unreadable source
produces an honest ``errors`` entry, never a crash and never a
zero-filled illusion of "no work".

Reasons (closed vocabulary; extra detail strings never replace a reason):

    EXECUTABLE              all existing safety conditions permit a run
    NOT_AUTHORIZED          scope/authorization missing or invalid
    WAITING_FOR_EVIDENCE    NEEDS_EVIDENCE semantics — never bypassed
    DEPENDENCY_BLOCKED      prerequisites/lifecycle not satisfied
    ALREADY_RUNNING         a live lease/claim exists
    TERMINAL                terminal lifecycle state
    RETRY_NOT_DUE           retry backoff still active
    OUT_OF_WINDOW           outside 12:00-00:00 Asia/Tehran
    INVALID_STATE           lifecycle state not executable (detail says why)
    BUDGET_DEFERRED         executable but deferred by fairness budgets
                            (assigned during selection, see priority.py)

Hunt objectives are DISCOVERED FOR REPORTING ONLY: they execute inside
their job's existing hunt loop (campaign/finding executors), never as a
dispatcher-owned unit — no duplicate queue (EPIC9 §4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

RULE_VERSION = "ai-ops-discovery-v1"

CLASS_JOB = "RUNTIME_JOB"
CLASS_FINDING = "FINDING_PIPELINE"
CLASS_CAMPAIGN = "CAMPAIGN_OBJECTIVE"
CLASS_HUNT = "HUNT_OBJECTIVE"
CLASS_VERIFICATION = "VERIFICATION_OBJECTIVE"
CLASSES = (CLASS_JOB, CLASS_FINDING, CLASS_CAMPAIGN, CLASS_HUNT,
           CLASS_VERIFICATION)

EXECUTABLE = "EXECUTABLE"
NOT_AUTHORIZED = "NOT_AUTHORIZED"
WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
DEPENDENCY_BLOCKED = "DEPENDENCY_BLOCKED"
ALREADY_RUNNING = "ALREADY_RUNNING"
TERMINAL = "TERMINAL"
RETRY_NOT_DUE = "RETRY_NOT_DUE"
OUT_OF_WINDOW = "OUT_OF_WINDOW"
INVALID_STATE = "INVALID_STATE"
BUDGET_DEFERRED = "BUDGET_DEFERRED"

REASONS = (EXECUTABLE, NOT_AUTHORIZED, WAITING_FOR_EVIDENCE,
           DEPENDENCY_BLOCKED, ALREADY_RUNNING, TERMINAL, RETRY_NOT_DUE,
           OUT_OF_WINDOW, INVALID_STATE, BUDGET_DEFERRED)

#: classes the dispatcher may execute (hunt/verification report only)
EXECUTABLE_CLASSES = (CLASS_JOB, CLASS_FINDING, CLASS_CAMPAIGN)


@dataclass
class WorkItem:
    work_id: str
    work_class: str
    source: str                     # authoritative store that owns it
    source_id: str                  # id within that store
    scope_ref: str = ""
    target: str = ""
    priority: int = 50
    created_at: str = ""
    state: str = ""
    executable: bool = False
    reason: str = ""
    detail: str = ""
    campaign_id: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "work_id": self.work_id, "work_class": self.work_class,
            "source": self.source, "source_id": self.source_id,
            "scope_ref": self.scope_ref, "target": self.target,
            "priority": self.priority, "created_at": self.created_at,
            "state": self.state, "executable": self.executable,
            "reason": self.reason, "detail": self.detail,
            "campaign_id": self.campaign_id, "meta": dict(self.meta),
        }


@dataclass
class DiscoveryReport:
    items: list[WorkItem] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def executable(self) -> list[WorkItem]:
        return [i for i in self.items if i.executable]

    @property
    def waiting(self) -> list[WorkItem]:
        return [i for i in self.items
                if i.reason == WAITING_FOR_EVIDENCE]

    @property
    def blocked(self) -> list[WorkItem]:
        return [i for i in self.items
                if not i.executable and i.reason != WAITING_FOR_EVIDENCE]

    def counts(self) -> dict[str, Any]:
        by_reason: dict[str, int] = {}
        by_class: dict[str, int] = {}
        for item in self.items:
            by_reason[item.reason] = by_reason.get(item.reason, 0) + 1
            by_class[item.work_class] = by_class.get(item.work_class, 0) + 1
        counts = {
            "discovered": len(self.items),
            "executable": len(self.executable),
            "waiting": len(self.waiting),
            "blocked": len(self.blocked),
            "terminal": len([i for i in self.items
                             if i.reason == TERMINAL]),
            "by_reason": dict(sorted(by_reason.items())),
            "by_class": dict(sorted(by_class.items())),
            "source_errors": len(self.errors),
        }
        counts["non_terminal_blocked"] = (
            counts["blocked"] - counts["terminal"]
        )
        return counts


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ pure
# classifiers (dataclasses in -> WorkItem out; fully unit-testable)


def classify_job(job: Any) -> WorkItem:
    """Runtime queue job eligibility (existing JobStatus vocabulary)."""
    from backend.research_agents.models import JobStatus

    status = str(getattr(job, "status", "") or "")
    terminal = {
        JobStatus.COMPLETED.value, JobStatus.CANCELLED.value,
        JobStatus.EXPIRED.value, JobStatus.TIMEOUT.value,
        JobStatus.FAILED.value, JobStatus.TERMINAL_FAILED.value,
    }
    running = {JobStatus.CLAIMED.value, JobStatus.RUNNING.value,
               JobStatus.ASSIGNED.value}
    item = WorkItem(
        work_id=f"job:{getattr(job, 'id', '')}",
        work_class=CLASS_JOB, source="runtime.jobs",
        source_id=str(getattr(job, "id", "") or ""),
        scope_ref=f"watch:scope:{getattr(job, 'program', '')}/"
                  f"{getattr(job, 'subdomain', '')}"
                  if getattr(job, "program", "") else "",
        target="/".join(x for x in
                        (str(getattr(job, "program", "") or ""),
                         str(getattr(job, "subdomain", "") or "")) if x),
        priority=int(getattr(job, "priority_score", 50) or 50),
        created_at=str(getattr(job, "created_at", "") or ""),
        state=status,
    )
    if status in (JobStatus.QUEUED.value, JobStatus.NEW.value):
        item.executable = True
        item.reason = EXECUTABLE
        item.detail = "queued runtime job; existing worker claim path"
    elif status == JobStatus.WAITING_EVIDENCE.value:
        item.reason = WAITING_FOR_EVIDENCE
        item.detail = "job waiting for evidence"
    elif status in running:
        expiry = str(getattr(job, "lease_expires_at", "") or "")
        live = False
        if expiry:
            try:
                live = datetime.fromisoformat(expiry).timestamp() \
                    > datetime.now(timezone.utc).timestamp()
            except ValueError:
                live = False
        if live:
            item.reason = ALREADY_RUNNING
            item.detail = f"lease held until {expiry}"
        else:
            item.reason = INVALID_STATE
            item.detail = "claim without live lease; store sweep recovers"
    elif status in terminal:
        item.reason = TERMINAL
        item.detail = f"terminal state {status}"
    else:
        item.reason = INVALID_STATE
        item.detail = f"unhandled job state {status or 'unknown'}"
    return item


def classify_campaign_objective(
    campaign: Any, objective: Any, by_id: dict[str, Any], *,
    now: datetime | None = None, max_attempts: int = 3,
    backoff_seconds: int = 900,
) -> WorkItem:
    """Campaign objective eligibility (fail-closed, executor remains the
    final authority for authorization/evidence/lease at run time)."""
    from backend.research_agents.campaign import dependencies as deps
    from backend.research_agents.campaign.models import (
        CAMPAIGN_TERMINAL,
        OBJECTIVE_EXECUTABLE,
        OBJECTIVE_STATES,
        OBJECTIVE_TERMINAL,
    )

    now = now or datetime.now(timezone.utc)
    camp_state = str(getattr(campaign, "state", "") or "")
    obj_state = str(getattr(objective, "state", "") or "")
    item = WorkItem(
        work_id=f"objective:{getattr(objective, 'objective_id', '')}",
        work_class=CLASS_CAMPAIGN, source="campaign.objectives",
        source_id=str(getattr(objective, "objective_id", "") or ""),
        scope_ref=str(getattr(objective, "scope_ref", "") or ""),
        target=str(getattr(objective, "scope_ref", "") or ""),
        priority=int(getattr(objective, "priority", 50) or 50),
        created_at=str(getattr(objective, "created_at", "") or ""),
        state=obj_state,
        campaign_id=str(getattr(campaign, "campaign_id", "") or ""),
        meta={"campaign_state": camp_state,
              "attempts": int(getattr(objective, "attempts", 0) or 0)},
    )

    # scope must be an explicit authorized scope (models validate on
    # write; re-check HERE for both campaign and objective so a
    # corrupted row on either side never classifies executable)
    scope = item.scope_ref
    camp_scope = str(getattr(campaign, "scope_ref", "") or "")
    for label, value in (("objective scope_ref", scope),
                         ("campaign scope_ref", camp_scope)):
        if not (value.startswith("watch:scope:")
                or value.startswith("fixture:")):
            item.reason = NOT_AUTHORIZED
            item.detail = (f"{label} missing or not an authorized "
                           f"prefix")
            return item

    if camp_state in CAMPAIGN_TERMINAL:
        item.reason = TERMINAL
        item.detail = f"campaign state {camp_state}"
        return item

    lease_until = str(getattr(campaign, "lease_expires_at", "") or "")
    lease_owner = str(getattr(campaign, "lease_owner", "") or "")
    if lease_owner and lease_until:
        try:
            if datetime.fromisoformat(lease_until) > now:
                item.reason = ALREADY_RUNNING
                item.detail = f"campaign leased by {lease_owner}"
                return item
        except ValueError:
            pass

    if camp_state not in ("READY", "RUNNING"):
        item.reason = INVALID_STATE
        item.detail = f"campaign state {camp_state} does not dispatch"
        return item

    if obj_state not in OBJECTIVE_STATES:
        item.reason = INVALID_STATE
        item.detail = f"unknown objective state {obj_state}"
        return item

    if obj_state == "RUNNING":
        item.reason = ALREADY_RUNNING
        item.detail = "objective already running"
        return item
    if obj_state == "WAITING":
        item.reason = DEPENDENCY_BLOCKED
        item.detail = "objective waiting"
        return item
    if obj_state == "BLOCKED":
        item.reason = INVALID_STATE
        item.detail = "objective blocked"
        return item
    if obj_state in OBJECTIVE_TERMINAL:
        item.reason = TERMINAL
        item.detail = f"objective state {obj_state} is terminal"
        return item
    if obj_state not in OBJECTIVE_EXECUTABLE:
        item.reason = INVALID_STATE
        item.detail = (f"objective state {obj_state} not executable "
                       f"(executable set: {sorted(OBJECTIVE_EXECUTABLE)})")
        return item

    # dependencies (existing resolver, fail closed)
    try:
        resolution = deps.resolve_dependencies(objective, by_id)
    except Exception as exc:  # noqa: BLE001 - fail closed, bounded
        item.reason = DEPENDENCY_BLOCKED
        item.detail = f"dependency resolution error: " \
                      f"{type(exc).__name__}"
        return item
    if not resolution.get("ready", False):
        item.reason = DEPENDENCY_BLOCKED
        item.detail = "; ".join(resolution.get("reasons", [])[:3]) \
            or "dependencies not satisfied"
        return item

    # retry backoff (bounded fairness; attempts>0 => exponential-ish wait)
    attempts = int(getattr(objective, "attempts", 0) or 0)
    if attempts > 0 and backoff_seconds > 0:
        updated = str(getattr(objective, "updated_at", "") or "")
        try:
            age = (now - datetime.fromisoformat(updated)).total_seconds()
            if age < backoff_seconds * attempts:
                item.reason = RETRY_NOT_DUE
                item.detail = (f"attempt {attempts}; backoff "
                               f"{backoff_seconds * attempts}s")
                return item
        except ValueError:
            pass
    if attempts >= max_attempts:
        item.reason = RETRY_NOT_DUE
        item.detail = f"attempts {attempts} >= max {max_attempts}"
        return item

    item.executable = True
    item.reason = EXECUTABLE
    item.detail = "scope authorized; lifecycle READY; dependencies ready"
    return item


def classify_hunt_objective(objective: Any, *, job_state: str = "",
                            ) -> WorkItem:
    """Report-only classification (hunt executes inside job loops)."""
    from backend.research_agents.hunt.uncertainty import TERMINAL_STATES

    state = str(getattr(objective, "state", "") or "")
    item = WorkItem(
        work_id=f"hunt:{getattr(objective, 'objective_id', '')}",
        work_class=CLASS_HUNT, source="hunt.objectives",
        source_id=str(getattr(objective, "objective_id", "") or ""),
        scope_ref=str(getattr(objective, "scope_ref", "") or ""),
        target=str(getattr(objective, "scope_ref", "") or ""),
        priority=int(getattr(objective, "priority", 50) or 50),
        created_at=str(getattr(objective, "created_at", "") or ""),
        state=state,
        meta={"job_id": str(getattr(objective, "job_id", "") or ""),
              "job_state": job_state},
    )
    if state in TERMINAL_STATES:
        item.reason = TERMINAL
        item.detail = f"hunt state {state} is terminal"
    elif state == "NEEDS_EVIDENCE":
        item.reason = WAITING_FOR_EVIDENCE
        item.detail = "evidence workflow required (never bypassed)"
    else:
        item.reason = DEPENDENCY_BLOCKED
        item.detail = ("executes within its job's bounded hunt loop"
                       + (f"; job state {job_state}" if job_state else ""))
    return item


def classify_finding_candidate(candidate: Any, *, now: datetime | None = None,
                               ) -> WorkItem:
    """Candidate-driven finding pipeline eligibility (class D)."""
    state = str(getattr(candidate, "lifecycle_state", "") or "")
    source_job = str(getattr(candidate, "source_job", "") or "")
    item = WorkItem(
        work_id=f"finding:{source_job}",
        work_class=CLASS_FINDING, source="finding.candidates",
        source_id=source_job,
        scope_ref=str(getattr(candidate, "scope_ref", "") or ""),
        target=str(getattr(candidate, "target", "") or "")
               or str(getattr(candidate, "scope_ref", "") or ""),
        priority=50,
        created_at=str(getattr(candidate, "created_at", "") or ""),
        state=state,
        meta={"candidate_ids": [str(getattr(candidate, "candidate_id", ""))],
              "source_job": source_job},
    )
    if state in ("VERIFICATION_PLANNED", "VERIFICATION_PENDING",
                 "TRIAGED", "DETECTED"):
        if not source_job:
            item.reason = INVALID_STATE
            item.detail = "candidate has no source job"
        else:
            item.executable = True
            item.reason = EXECUTABLE
            item.detail = ("bounded finding pipeline for completed "
                           f"source job {source_job}")
    elif state == "NEEDS_EVIDENCE":
        item.reason = WAITING_FOR_EVIDENCE
        item.detail = "candidate evidence requirement outstanding"
    elif state in ("VERIFIED", "DUPLICATE", "REJECTED"):
        item.reason = TERMINAL
        item.detail = f"candidate state {state}"
    elif state == "VERIFYING":
        item.reason = ALREADY_RUNNING
        item.detail = "verification in progress"
    else:
        item.reason = INVALID_STATE
        item.detail = f"candidate state {state} not dispatchable"
    return item


def classify_verification_objective(ver: Any) -> WorkItem:
    """Report-only: verification objects are advanced by the finding
    pipeline itself (class D execution keys off candidates, deduplicated
    per source job, so a run can never be issued twice)."""
    from backend.research_agents.finding.models import VERIFICATION_TERMINAL

    state = str(getattr(ver, "state", "") or "")
    item = WorkItem(
        work_id=f"verification:{getattr(ver, 'verification_id', '')}",
        work_class=CLASS_VERIFICATION, source="finding.verifications",
        source_id=str(getattr(ver, "verification_id", "") or ""),
        scope_ref=str(getattr(ver, "scope_ref", "") or ""),
        target=str(getattr(ver, "scope_ref", "") or ""),
        priority=50,
        created_at=str(getattr(ver, "created_at", "") or ""),
        state=state,
        meta={"candidate_id": str(getattr(ver, "candidate_id", ""))},
    )
    if state in VERIFICATION_TERMINAL:
        item.reason = TERMINAL
        item.detail = f"verification state {state}"
    elif state == "AUTHORIZATION_REQUIRED":
        item.reason = NOT_AUTHORIZED
        item.detail = "verification awaits authorization decision"
    elif state == "WAITING":
        item.reason = WAITING_FOR_EVIDENCE
        item.detail = "verification waiting on evidence/decision"
    elif state == "EXECUTING":
        item.reason = ALREADY_RUNNING
        item.detail = "verification executing"
    elif state in ("READY", "AUTHORIZED", "CREATED"):
        item.reason = INVALID_STATE
        item.detail = (f"verification state {state}; progressed by the "
                       "candidate-driven finding pipeline (no duplicate "
                       "dispatch)")
    else:
        item.reason = INVALID_STATE
        item.detail = f"verification state {state or 'unknown'}"
    return item


# --------------------------------------------------------------- IO glue

def _safe(label: str, fn: Callable[[], list[WorkItem]],
          report: DiscoveryReport) -> None:
    try:
        report.items.extend(fn())
    except Exception as exc:  # noqa: BLE001 - honest per-source failure
        report.errors.append({"source": label,
                              "error": type(exc).__name__,
                              "detail": str(exc)[:160]})


def discover(*, runtime_store: Any = None, campaign_store: Any = None,
             hunt_store: Any = None, finding_store: Any = None,
             now: datetime | None = None,
             max_attempts: int = 3, backoff_seconds: int = 900,
             ) -> DiscoveryReport:
    """Discover work across the four existing stores (fail-soft per
    source, bounded reads, no writes anywhere)."""
    from backend.research_agents.campaign.store import CampaignStore
    from backend.research_agents.finding.store import FindingStore
    from backend.research_agents.hunt.store import HuntStore
    from backend.research_agents.runtime_store import default_store

    now = now or datetime.now(timezone.utc)
    report = DiscoveryReport()
    rt = runtime_store or default_store()

    # Sibling stores share the runtime store's base when it exposes
    # one; a custom/partial runtime_store must not break the other
    # sources (fail-soft per source, not all-or-nothing).
    base = getattr(rt, "base", None)

    def _mk(cls: Any) -> Any:
        return cls(base) if base is not None else cls()

    cs = campaign_store or _mk(CampaignStore)
    hs = hunt_store or _mk(HuntStore)
    fs = finding_store or _mk(FindingStore)

    def jobs() -> list[WorkItem]:
        return [classify_job(j) for j in rt.list_jobs()]

    def campaigns() -> list[WorkItem]:
        items: list[WorkItem] = []
        for camp in cs.list_campaigns():
            objectives = cs.objectives_for_campaign(camp.campaign_id)
            by_id = {o.objective_id: o for o in objectives}
            for obj in objectives:
                items.append(
                    classify_campaign_objective(
                        camp, obj, by_id, now=now,
                        max_attempts=max_attempts,
                        backoff_seconds=backoff_seconds))
        return items

    def hunts() -> list[WorkItem]:
        job_states: dict[str, str] = {}
        items: list[WorkItem] = []
        for obj in hs.list_objectives():
            job_id = str(getattr(obj, "job_id", "") or "")
            if job_id and job_id not in job_states:
                job = rt.get(job_id)
                job_states[job_id] = (str(job.status) if job else "missing")
            items.append(classify_hunt_objective(
                obj, job_state=job_states.get(job_id, "")))
        return items

    def findings() -> list[WorkItem]:
        items: list[WorkItem] = []
        # candidates first; group multiple candidates of one source job
        # into a single executable work item (no duplicate dispatch)
        grouped: dict[str, WorkItem] = {}
        for cand in fs.list_candidates():
            item = classify_finding_candidate(cand, now=now)
            key = item.work_id
            if key in grouped and item.executable \
                    and grouped[key].executable:
                ids = grouped[key].meta.setdefault("candidate_ids", [])
                cid = str(getattr(cand, "candidate_id", ""))
                if cid and cid not in ids:
                    ids.append(cid)
                continue
            # keep report-only rows (terminal/blocked) per candidate id
            if not item.executable:
                item.work_id = (f"finding:{item.meta.get('source_job')}:"
                                f"{getattr(cand, 'candidate_id', '')}")
            grouped.setdefault(key, item)
            if not item.executable:
                grouped[item.work_id] = item
        items.extend(grouped.values())
        for ver in fs.list_verifications():
            items.append(classify_verification_objective(ver))
        return items

    _safe("runtime.jobs", jobs, report)
    _safe("campaign.objectives", campaigns, report)
    _safe("hunt.objectives", hunts, report)
    _safe("finding", findings, report)
    return report
