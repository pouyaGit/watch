"""
backend/routers/research.py — Stage D2 read-only research API.

Exposes already-persisted research/KB/XSS/report artifacts as compact,
key-gated JSON. READ-ONLY by construction:

- no writes (no KB mutation, no Mongo writes)
- no subprocess, no network, no LLM, no Nuclei execution
- no production verifier / live validation
- Markdown is returned raw (never rendered to HTML, never |safe)

All routes are behind ``verify_api_key`` (same dependency as the
existing routers) and the global APIKeyMiddleware in api.py.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from ai.knowledge.research_outcomes import (
    OutcomeNotFound,
    OutcomeValidationError,
)
from ai.knowledge.research_sessions import (
    SessionNotFound,
    SessionValidationError,
)
from ai.knowledge.task_store import (
    StaleTaskError,
    TaskNotFound,
    TaskStoreError,
    TaskValidationError,
)
from backend import research_tasks
from backend.deps import verify_api_key
from backend.research_data import (
    NotFoundError,
    ResearchDataError,
    cve_relevance,
    get_kb,
    get_overview,
    get_report,
    get_research,
    get_xss,
    get_xss_llm_research,
    list_kb,
    list_reports,
    list_research,
    list_research_queue,
    list_xss,
)

router = APIRouter()

_AUTH = [Depends(verify_api_key)]


def _bad(exc: ResearchDataError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _task_error(exc: TaskStoreError) -> HTTPException:
    """Map research-workflow store errors onto HTTP status codes."""

    if isinstance(exc, StaleTaskError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, TaskNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, TaskValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class ResearchTaskCreate(BaseModel):
    """Validated task-create payload (bounded; no arbitrary paths)."""

    cve: str
    program: str
    queue_id: str
    title: str | None = None
    notes: str | None = None
    references: list[str] | None = None


class ResearchTaskPatch(BaseModel):
    """Validated task-update payload with optimistic-concurrency token."""

    expected_version: int
    status: str | None = None
    notes: str | None = None
    blocker: str | None = None
    result_summary: str | None = None
    references: list[str] | None = None


class ResearchSessionCreate(BaseModel):
    """Validated R25.7 session-create payload (no target/execution fields)."""

    model_config = ConfigDict(extra="forbid")

    lead_id: str
    planned_minutes: int = 0
    note: str = ""


class ResearchSessionComplete(BaseModel):
    """Validated R25.7 completion payload (time accounting only)."""

    model_config = ConfigDict(extra="forbid")

    actual_minutes: int | None = None
    outcome_id: str = ""
    note: str = ""


class ResearchSessionAbandon(BaseModel):
    """Validated R25.7 abandon payload (time accounting only)."""

    model_config = ConfigDict(extra="forbid")

    actual_minutes: int | None = None
    note: str = ""


class ResearchOutcomeCreate(BaseModel):
    """Validated R25.5 outcome-create payload.

    No payout/reward fields exist and unknown fields are rejected
    (``extra="forbid"``), so a payout field can never be persisted.
    """

    model_config = ConfigDict(extra="forbid")

    lead_id: str
    status: str
    time_spent_minutes: int = 0
    researcher_note: str = ""
    source: str = "MANUAL"


# ---------------------------------------------------------------------------
# Research
# ---------------------------------------------------------------------------


@router.get("/api/research", dependencies=_AUTH)
def api_research_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    q: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    try:
        return list_research(limit=limit, offset=offset, q=q, cve=cve, severity=severity, status=status)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/overview", dependencies=_AUTH)
def api_research_overview():
    try:
        return get_overview()
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Research workflow tasks (Stage R20) — read/write, key-gated, local JSON only.
# Declared before /api/research/{cve} so "tasks" is not captured as a CVE.
# ---------------------------------------------------------------------------


@router.get("/api/research/tasks", dependencies=_AUTH)
def api_research_tasks(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    status: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
):
    try:
        return research_tasks.list_tasks(
            limit=limit, offset=offset, status=status, cve=cve
        )
    except TaskStoreError as exc:
        raise _task_error(exc)


@router.post("/api/research/tasks", dependencies=_AUTH, status_code=201)
def api_research_task_create(body: ResearchTaskCreate):
    try:
        task, created = research_tasks.create_task(
            cve=body.cve,
            program=body.program,
            queue_id=body.queue_id,
            title=body.title,
            notes=body.notes,
            references=body.references,
        )
    except TaskStoreError as exc:
        raise _task_error(exc)
    return {"created": created, "task": task.model_dump(mode="json")}


@router.get("/api/research/tasks/{task_id}", dependencies=_AUTH)
def api_research_task_detail(task_id: str):
    try:
        task = research_tasks.get_task(task_id)
    except TaskStoreError as exc:
        raise _task_error(exc)
    return task.model_dump(mode="json")


@router.patch("/api/research/tasks/{task_id}", dependencies=_AUTH)
def api_research_task_update(task_id: str, body: ResearchTaskPatch):
    try:
        task = research_tasks.update_task(
            task_id,
            expected_version=body.expected_version,
            status=body.status,
            notes=body.notes,
            blocker=body.blocker,
            result_summary=body.result_summary,
            references=body.references,
        )
    except TaskStoreError as exc:
        raise _task_error(exc)
    return task.model_dump(mode="json")


@router.get("/api/research/queue", dependencies=_AUTH)
def api_research_queue(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
):
    """Ranked R18 research queue (research planning only). Read-only."""

    try:
        return list_research_queue(limit=limit, offset=offset, cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/queue/{cve}", dependencies=_AUTH)
def api_research_queue_cve(cve: str):
    """Ranked queue items for one CVE. Read-only."""

    try:
        return list_research_queue(limit=100, offset=0, cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/leads", dependencies=_AUTH)
def api_research_leads(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
):
    """Stage R21 research leads (read-only, deterministic, key-gated)."""
    from backend import research_leads

    try:
        return research_leads.list_leads(limit=limit, offset=offset, cve=cve, program=program)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/leads/{lead_id}", dependencies=_AUTH)
def api_research_lead_detail(lead_id: str):
    """One Stage R21 research lead by deterministic id (read-only)."""
    from backend import research_leads

    try:
        return research_leads.get_lead(lead_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="research lead not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Stage R22: deterministic Research Execution Plans (read-only, key-gated).
# Must be declared before generic /api/research/{cve} so "plans" is not
# captured as a CVE id.
# ---------------------------------------------------------------------------


@router.get("/api/research/plans", dependencies=_AUTH)
def api_research_plans(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    lead: Optional[str] = Query(default=None),
):
    """Stage R22 research execution plans (read-only, deterministic, key-gated)."""
    from backend import research_execution

    try:
        return research_execution.list_plans(
            limit=limit, offset=offset, cve=cve, program=program, lead=lead
        )
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/plans/{plan_id}", dependencies=_AUTH)
def api_research_plan_detail(plan_id: str):
    """One Stage R22 research execution plan by deterministic id (read-only)."""
    from backend import research_execution
    from backend.research_data import NotFoundError as PlanNotFound

    try:
        return research_execution.get_plan(plan_id)
    except PlanNotFound:
        raise HTTPException(status_code=404, detail="research plan not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Stage R25: deterministic Money Score queue (read-only, key-gated).
# Must be declared before generic /api/research/{cve} so "economics" is not
# captured as a CVE id.
# ---------------------------------------------------------------------------


@router.get("/api/research/economics", dependencies=_AUTH)
def api_research_economics(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
):
    """Stage R25 Money Score queue (read-only, deterministic, key-gated)."""
    from backend import research_economics

    try:
        return research_economics.list_research_economics(
            limit=limit, offset=offset, cve=cve, program=program
        )
    except ResearchDataError as exc:
        raise _bad(exc)


# Stage R25.6: read-only calibration audit. Declared before
# /api/research/economics/{lead_id} so "calibration" is not captured as a
# lead id. There is deliberately no write endpoint.


@router.get("/api/research/economics/calibration", dependencies=_AUTH)
def api_research_economics_calibration(
    min_samples: int = Query(default=10, ge=1, le=100000),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
):
    """R25.6 offline Money Score calibration (read-only, no weight changes)."""
    from backend import research_calibration

    try:
        return research_calibration.build_report(
            min_samples=min_samples, cve=cve, program=program
        )
    except ResearchDataError as exc:
        raise _bad(exc)


# Stage R25.7: research session time accounting (append-only, no execution).
# Declared before /api/research/economics/{lead_id} so "sessions" is not
# captured as a lead id.


@router.post("/api/research/economics/sessions", dependencies=_AUTH,
             status_code=201)
def api_research_session_create(body: ResearchSessionCreate):
    """Create a PLANNED session (idempotent; never auto-started)."""
    from backend import research_sessions

    try:
        return research_sessions.create_session(
            lead_id=body.lead_id,
            planned_minutes=body.planned_minutes,
            note=body.note,
        )
    except SessionValidationError as exc:
        raise _bad(exc)
    except OSError as exc:
        raise HTTPException(status_code=500,
                            detail="session store unavailable") from exc


@router.get("/api/research/economics/sessions", dependencies=_AUTH)
def api_research_sessions(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    lead_id: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List research sessions (read-only, bounded, key-gated)."""
    from backend import research_sessions

    try:
        return research_sessions.list_sessions(
            limit=limit, offset=offset, lead_id=lead_id, cve=cve,
            program=program, status=status,
        )
    except SessionValidationError as exc:
        raise _bad(exc)


@router.get("/api/research/economics/sessions/summary", dependencies=_AUTH)
def api_research_session_summary(lead_id: str = Query(...)):
    """Read-only R25.2+R25.5+R25.7 performance view for one lead."""
    from backend import research_sessions

    try:
        return research_sessions.lead_execution_performance(lead_id)
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="session not found")
    except NotFoundError:
        raise HTTPException(status_code=404,
                            detail="economic projection not found")
    except SessionValidationError as exc:
        raise _bad(exc)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/economics/sessions/{session_id}", dependencies=_AUTH)
def api_research_session_detail(session_id: str):
    """One research session by deterministic id (read-only)."""
    from backend import research_sessions

    try:
        return research_sessions.get_session(session_id)
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="research session not found")
    except SessionValidationError as exc:
        raise _bad(exc)


@router.post("/api/research/economics/sessions/{session_id}/start",
             dependencies=_AUTH)
def api_research_session_start(session_id: str):
    """Explicitly start a PLANNED session (metadata only)."""
    from backend import research_sessions

    try:
        return research_sessions.start_session(session_id)
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="research session not found")
    except SessionValidationError as exc:
        raise _bad(exc)


@router.post("/api/research/economics/sessions/{session_id}/complete",
             dependencies=_AUTH)
def api_research_session_complete(session_id: str,
                                  body: ResearchSessionComplete):
    """Complete an IN_PROGRESS session; optional existing R25.5 outcome link."""
    from backend import research_sessions

    try:
        return research_sessions.complete_session(
            session_id=session_id,
            actual_minutes=body.actual_minutes,
            outcome_id=body.outcome_id,
            note=body.note,
        )
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="research session not found")
    except SessionValidationError as exc:
        raise _bad(exc)


@router.post("/api/research/economics/sessions/{session_id}/abandon",
             dependencies=_AUTH)
def api_research_session_abandon(session_id: str,
                                 body: ResearchSessionAbandon):
    """Abandon a PLANNED/IN_PROGRESS session (time accounting only)."""
    from backend import research_sessions

    try:
        return research_sessions.abandon_session(
            session_id=session_id,
            actual_minutes=body.actual_minutes,
            note=body.note,
        )
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="research session not found")
    except SessionValidationError as exc:
        raise _bad(exc)


# Stage R25.5: append-only economic research outcomes. Declared before
# /api/research/economics/{lead_id} so "outcomes" is not captured as a lead id.


@router.get("/api/research/economics/outcomes", dependencies=_AUTH)
def api_research_outcomes(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    lead_id: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """Recorded R25.5 research outcomes (read-only, bounded, key-gated)."""
    from backend import research_outcomes

    try:
        return research_outcomes.list_outcomes(
            limit=limit, offset=offset, lead_id=lead_id, cve=cve,
            program=program, status=status,
        )
    except OutcomeValidationError as exc:
        raise _bad(exc)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/economics/outcomes/{outcome_id}", dependencies=_AUTH)
def api_research_outcome_detail(outcome_id: str):
    """One recorded R25.5 outcome by deterministic id (read-only)."""
    from backend import research_outcomes

    try:
        return research_outcomes.get_outcome(outcome_id)
    except OutcomeNotFound:
        raise HTTPException(status_code=404, detail="research outcome not found")
    except OutcomeValidationError as exc:
        raise _bad(exc)


@router.post("/api/research/economics/outcomes", dependencies=_AUTH,
             status_code=201)
def api_research_outcome_create(body: ResearchOutcomeCreate):
    """Record one research outcome (append-only, idempotent, no payouts).

    Never executes research, never triggers a worker, never contacts
    external sources, never touches the Money Score.
    """
    from backend import research_outcomes

    try:
        result = research_outcomes.record_outcome(
            lead_id=body.lead_id,
            status=body.status,
            time_spent_minutes=body.time_spent_minutes,
            note=body.researcher_note,
            source=body.source,
        )
    except OutcomeValidationError as exc:
        raise _bad(exc)
    except OSError as exc:
        raise HTTPException(status_code=500, detail="outcome store unavailable") from exc
    return result


@router.get("/api/research/economics/{lead_id}", dependencies=_AUTH)
def api_research_economic_detail(lead_id: str):
    """One Stage R25 economic projection by deterministic lead id (read-only)."""
    from backend import research_economics

    try:
        return research_economics.get_research_economic_value(lead_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="economic projection not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Stage R26.1: read-only opportunity intelligence (Money Score copied).
# Declared before /api/research/{cve} so literal paths are not captured.
# ---------------------------------------------------------------------------


@router.get("/api/research/opportunities", dependencies=_AUTH)
def api_research_opportunities(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
):
    """Ranked economic opportunity queue (read-only, deterministic)."""
    from backend import research_opportunities

    try:
        return research_opportunities.list_opportunities(
            limit=limit, offset=offset, cve=cve, program=program
        )
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/opportunities/summary", dependencies=_AUTH)
def api_research_opportunity_summary():
    """Compact opportunity class counts + top items (read-only)."""
    from backend import research_opportunities

    return research_opportunities.opportunity_summary()


# ---------------------------------------------------------------------------
# Stage R26.2: read-only researcher Action Queue (no new scoring, no writes).
# Declared BEFORE /api/research/opportunities/{lead_id} so "actions" is not
# captured as a lead id, and BEFORE /api/research/{cve}.
# ---------------------------------------------------------------------------


@router.get("/api/research/opportunities/actions", dependencies=_AUTH)
def api_research_opportunity_actions(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    status: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    cls: Optional[str] = Query(default=None, alias="class"),
):
    """Ranked researcher Action Queue (read-only, deterministic, key-gated)."""
    from backend import research_action_queue

    try:
        return research_action_queue.list_actions(
            limit=limit,
            offset=offset,
            status=status,
            opportunity_class=cls,
            cve=cve,
            program=program,
        )
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/opportunities/actions/summary", dependencies=_AUTH)
def api_research_opportunity_actions_summary():
    """Compact action counts + top action (read-only)."""
    from backend import research_action_queue

    return research_action_queue.action_summary()


@router.get("/api/research/opportunities/actions/{lead_id}",
            dependencies=_AUTH)
def api_research_opportunity_action_detail(lead_id: str):
    """One researcher action by deterministic lead id (read-only)."""
    from backend import research_action_queue

    try:
        return research_action_queue.get_action(lead_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="opportunity action not found")
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/opportunities/{lead_id}", dependencies=_AUTH)
def api_research_opportunity_detail(lead_id: str):
    """One opportunity by deterministic lead id (read-only)."""
    from backend import research_opportunities

    try:
        return research_opportunities.get_opportunity(lead_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="opportunity not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Stage R26.3: daily research workflow (read-only, derived; no persistence).
# ---------------------------------------------------------------------------


@router.get("/api/research/workflow/daily", dependencies=_AUTH)
def api_research_workflow_daily(
    limit: int = Query(default=5, ge=1, le=50),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    opportunity_class: Optional[str] = Query(default=None, alias="class"),
    status: Optional[str] = Query(default=None),
):
    """Derived daily research workflow (read-only, no snapshots)."""
    from backend import daily_research

    try:
        return daily_research.build_daily_workflow(
            top_n=limit,
            cve=cve,
            program=program,
            opportunity_class=opportunity_class,
            status=status,
        )
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/workflow/summary", dependencies=_AUTH)
def api_research_workflow_summary(
    limit: int = Query(default=5, ge=1, le=50),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
):
    """Compact daily workflow counts + top action (read-only)."""
    from backend import daily_research

    try:
        return daily_research.daily_summary(
            top_n=limit, cve=cve, program=program
        )
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Stage R29.1: personal hunt queue (internal read-only; no public API).
# Declared before /api/research/{cve} so "hunt" is not captured as a CVE.
# ---------------------------------------------------------------------------


@router.get("/api/research/hunt", dependencies=_AUTH)
def api_research_hunt(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
    priority: Optional[str] = Query(default=None),
    opportunity_class: Optional[str] = Query(default=None, alias="class"),
    status: Optional[str] = Query(default=None),
):
    """Personal bug-bounty hunt queue (read-only, research-only)."""
    from backend import hunt_queue

    try:
        return hunt_queue.list_hunt_items(
            limit=limit, offset=offset, cve=cve, program=program,
            priority=priority, opportunity_class=opportunity_class,
            status=status,
        )
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/hunt/summary", dependencies=_AUTH)
def api_research_hunt_summary():
    """Compact personal hunt tier counts + top items (read-only)."""
    from backend import hunt_queue

    return hunt_queue.hunt_summary()


# ---------------------------------------------------------------------------
# Stage R27.1: product validation audit (read-only, no new score).
# ---------------------------------------------------------------------------


@router.get("/api/research/product-validation", dependencies=_AUTH)
def api_research_product_validation(
    min_sessions: int = Query(default=20, ge=0, le=100000),
    min_outcomes: int = Query(default=20, ge=0, le=100000),
    min_leads: int = Query(default=10, ge=0, le=100000),
    cve: Optional[str] = Query(default=None),
    program: Optional[str] = Query(default=None),
):
    """Deterministic product validation report (read-only, no persistence)."""
    from backend import product_validation

    try:
        return product_validation.build_product_validation_report(
            min_sessions=min_sessions,
            min_outcomes=min_outcomes,
            min_leads=min_leads,
            cve=cve,
            program=program,
        )
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/agent/status", dependencies=_AUTH)
def api_research_agent_status():
    """Stage R23: read-only autonomous research agent status."""
    from backend import research_agent as ra

    return ra.agent_status()


@router.get("/api/research/agent/runs", dependencies=_AUTH)
def api_research_agent_runs(limit: int = Query(default=50)):
    """Stage R23: read-only autonomous research agent runs."""
    from backend import research_agent as ra

    return {"items": ra.list_runs(limit=limit), "total": len(ra.list_runs(limit=1000))}


@router.get("/api/research/matches/{cve}/summary", dependencies=_AUTH)
def api_research_match_summary(cve: str):
    """Stage R30.1 aggregate asset <-> CVE match summary (read-only)."""
    from backend import asset_cve_matching

    try:
        return asset_cve_matching.get_match_summary(cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/matches/{cve}", dependencies=_AUTH)
def api_research_matches(cve: str):
    """Stage R30.1 asset <-> CVE matches for one CVE (read-only)."""
    from backend import asset_cve_matching

    try:
        return asset_cve_matching.build_matches(cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/matches/{cve}/{program}", dependencies=_AUTH)
def api_research_match_program(cve: str, program: str):
    """Stage R30.1 asset <-> CVE match for one CVE/program (read-only)."""
    from backend import asset_cve_matching

    try:
        data = asset_cve_matching.get_match_summary(cve, program=program)
    except ResearchDataError as exc:
        raise _bad(exc)
    if not data.get("items"):
        raise HTTPException(status_code=404, detail="asset/CVE match not found")
    return data


@router.get("/api/research/inventory/summary", dependencies=_AUTH)
def api_research_inventory_summary():
    """Stage R30.2 observed inventory summary (read-only, research-only)."""
    from backend import observed_inventory

    return observed_inventory.get_inventory_summary()


@router.get("/api/research/inventory/{program}", dependencies=_AUTH)
def api_research_inventory_program(program: str):
    """Stage R30.2 observed inventory for one program (read-only)."""
    from backend import observed_inventory

    inventory = observed_inventory.get_inventory(program)
    if inventory is None:
        raise HTTPException(status_code=404, detail="program inventory not found")
    return inventory


@router.get("/api/research/{cve}", dependencies=_AUTH)
def api_research_detail(cve: str):
    try:
        return get_research(cve)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="research artifact not found")
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/research/{cve}/relevance", dependencies=_AUTH)
def api_research_relevance(cve: str):
    """R17 asset/program relevance for one CVE (research relevance only)."""

    try:
        return cve_relevance(cve)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="research artifact not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Knowledge base (read-only KnowledgeStore)
# ---------------------------------------------------------------------------


@router.get("/api/kb", dependencies=_AUTH)
def api_kb_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    q: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
):
    try:
        return list_kb(limit=limit, offset=offset, q=q, cve=cve, tag=tag)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/kb/{kid}", dependencies=_AUTH)
def api_kb_detail(kid: str):
    try:
        return get_kb(kid)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="knowledge document not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# XSS candidates (research candidates, NOT findings)
# ---------------------------------------------------------------------------


@router.get("/api/xss/candidates", dependencies=_AUTH)
def api_xss_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    status: Optional[str] = Query(default=None),
    type: Optional[str] = Query(default=None, alias="type"),
    context: Optional[str] = Query(default=None),
):
    try:
        return list_xss(limit=limit, offset=offset, status=status, xss_type=type, context=context)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/xss/candidates/{candidate_id}", dependencies=_AUTH)
def api_xss_detail(candidate_id: str):
    try:
        return get_xss(candidate_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="xss candidate not found")
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/xss/candidates/{candidate_id}/llm-research", dependencies=_AUTH)
def api_xss_llm_research(candidate_id: str):
    """Read-only R7 LLM research record (research commentary, not verified).

    Never invokes a provider; serves only the persisted JSON under
    ``ai_data/research/xss/llm/``. 404 when no research was generated.
    """
    try:
        return get_xss_llm_research(candidate_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="llm research not found")
    except ResearchDataError as exc:
        raise _bad(exc)


# ---------------------------------------------------------------------------
# Reports (raw Markdown)
# ---------------------------------------------------------------------------


@router.get("/api/reports", dependencies=_AUTH)
def api_reports_list(
    limit: int = Query(default=50),
    offset: int = Query(default=0),
    q: Optional[str] = Query(default=None),
    cve: Optional[str] = Query(default=None),
):
    try:
        return list_reports(limit=limit, offset=offset, q=q, cve=cve)
    except ResearchDataError as exc:
        raise _bad(exc)


@router.get("/api/reports/{cve}", dependencies=_AUTH)
def api_report_detail(cve: str):
    try:
        return get_report(cve)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="report not found")
    except ResearchDataError as exc:
        raise _bad(exc)
