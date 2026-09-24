"""Shared builders for the Hunt Planner test suites (not a test module)."""

from __future__ import annotations

import tempfile
from typing import Any

from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AuthorizationChecker,
    FixtureObservations,
    deterministic_analysis,
    evaluate_case_creation,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow
from backend.research_agents.capabilities import capability_for
from backend.research_agents.hunt import HuntLimits, HuntStore, run_hunt


def make_store_dir() -> str:
    return tempfile.mkdtemp(prefix="hunt-test-", dir="/tmp")


def make_store(base: str | None = None) -> RuntimeStore:
    return RuntimeStore(base or make_store_dir())


def make_job(*, job_id: str = "job-xss-hunt-test", category: str = "XSS",
             auth_ref: str = "fixture:shop/shop.test",
             mode: str = "fixture") -> ResearchJob:
    return ResearchJob(
        id=job_id, candidate_id="cand", category=category,
        endpoint="https://shop.test/search?q=abc", parameter="q",
        priority_score=50, status=JobStatus.QUEUED.value,
        assigned_agent=(capability_for(category).agent_name
                        if capability_for(category) else "xss-agent"),
        created_at=utcnow(), updated_at=utcnow(),
        agent_category=category, program="fixture:shop",
        subdomain="shop.test", url="https://shop.test/search?q=abc",
        mission="reflected-input-review", authorization_ref=auth_ref,
        execution_mode=mode, timeout_seconds=60,
    )


def rich_rows() -> list[dict[str, Any]]:
    """Fixture rows covering all three sources (param-rich XSS scope)."""
    return [
        {"source": "urls", "ref": "u1", "url": "https://shop.test/search",
         "status": 200, "params": ["q", "redirect"]},
        {"source": "urls", "ref": "u2", "url": "https://shop.test/lookup",
         "status": 200, "params": ["id"]},
        {"source": "endpoints", "ref": "e1",
         "url": "https://shop.test/api/find", "params": ["q"]},
        {"source": "http", "ref": "h1", "url": "https://shop.test/search",
         "status": 200, "title": "search", "tech": "nginx",
         "headers_snippet": "server: nginx"},
        {"source": "http", "ref": "h2", "url": "https://shop.test/lookup",
         "status": 200, "title": "lookup", "tech": "php",
         "headers_snippet": "x-powered-by: php"},
    ]


def cve_rows() -> list[dict[str, Any]]:
    """CVE scope: initial rows carry NO technology signal (http unread)."""
    return [
        {"source": "urls", "ref": "u1", "url": "https://shop.test/a",
         "status": 200, "params": []},
        {"source": "urls", "ref": "u2", "url": "https://shop.test/b",
         "status": 200, "params": []},
    ]


def http_rows_for_cve() -> list[dict[str, Any]]:
    """What the typed http-rows read yields (technology signals)."""
    return [
        {"source": "http", "ref": "h1", "url": "https://shop.test/a",
         "status": 200, "title": "shop", "tech": "Apache httpd",
         "headers_snippet": "server: Apache"},
        {"source": "http", "ref": "h2", "url": "https://shop.test/b",
         "status": 200, "title": "shop", "tech": "Apache httpd",
         "headers_snippet": "server: Apache"},
    ]


class SplitFixture(FixtureObservations):
    """Fixture that serves DIFFERENT rows for typed (hunt) reads than the
    legacy full read — models production, where typed reads reach
    collections the legacy budget never touched."""

    def __init__(self, rows_by_job: dict[str, list[dict[str, Any]]],
                 typed_rows_by_job: dict[str, dict[str, list[dict]]] | None = None):
        super().__init__(rows_by_job)
        self.typed_rows_by_job = typed_rows_by_job or {}

    def observe(self, job: ResearchJob, *, types: tuple[str, ...] | None = None,
                limit: int | None = None):
        if types:
            out: list[dict[str, Any]] = []
            mapping = self.typed_rows_by_job.get(job.id, {})
            for t in types:
                out.extend(mapping.get(t, []))
            if limit is not None:
                out = out[: max(0, int(limit))]
            return out
        return super().observe(job)


def claim_grade_determin(determin_fn: Any, *, category: str = "XSS") -> Any:
    """Wrap a deterministic analyser so the fixture scope already carries
    the claim-grade evidence an authorized verification run would have
    persisted (stage 3 + stage 4 + the authorization confirmation).

    EPIC11: the runtime's observation providers can only ever produce
    observation-stage signals, so a fixture that wants to exercise the
    *resolution* path must state that the stored observations include a
    controlled-verification record.  It never bypasses the gate — the
    gate still evaluates the real claim contract over these rows.
    """
    from tests.finding_fixtures import contract_evidence

    def wrapped(capability: Any, job: Any, observations: Any,
                knowledge: Any) -> dict[str, Any]:
        analysis = determin_fn(capability, job, observations, knowledge)
        analysis = dict(analysis or {})
        cands = list(analysis.get("evidence_candidates") or [])
        for row in contract_evidence(cls=category, count=6):
            cands.append({
                "type": "observation",
                "observation_ref": row["observation_ref"],
                "signal": row["signal"],
                "detail": row["detail"],
                "category": category,
            })
        analysis["evidence_candidates"] = cands
        return analysis

    return wrapped


def run_hunt_fixture(
    *,
    rows: list[dict[str, Any]] | None = None,
    typed: dict[str, list[dict]] | None = None,
    category: str = "XSS",
    limits: HuntLimits | None = None,
    determin_fn: Any = None,
    advisor_fn=None,
    knowledge_fn=None,
    auth_ref: str = "fixture:shop/shop.test",
    store: RuntimeStore | None = None,
    memory: Any = None,
    gate_fn=None,
    deadline_fn=None,
    emit_activity=None,
    emit_audit=None,
) -> tuple[Any, Any, Any, HuntStore, RuntimeStore]:
    """Run one bounded hunt loop against fixture data.

    Returns (outcome, job, capability, hunt_store, runtime_store).
    """
    store = store or make_store()
    job = make_job(category=category, auth_ref=auth_ref)
    provider = SplitFixture(
        {job.id: list(rows if rows is not None else rich_rows())},
        {job.id: dict(typed or {})})
    cap = capability_for(category)
    limits = limits or HuntLimits(max_plans_per_objective=3,
                                  max_planning_iterations=4,
                                  max_llm_planning_calls=0,
                                  max_seconds=30)
    outcome = run_hunt(
        job=job, capability=cap, store=store, hunt_store=HuntStore(store.base),
        observations=provider, auth_checker=AuthorizationChecker(),
        determin_fn=determin_fn or deterministic_analysis,
        gate_fn=gate_fn or evaluate_case_creation,
        limits=limits,
        initial_rows=list(rows if rows is not None else rich_rows()),
        initial_knowledge=[],
        advisor_fn=advisor_fn,
        knowledge_fn=knowledge_fn,
        memory_store=memory,
        deadline_fn=deadline_fn,
        emit_activity=emit_activity or _recorder(store),
        emit_audit=emit_audit or _audit_recorder(store),
    )
    return outcome, job, cap, HuntStore(store.base), store


def _recorder(store: RuntimeStore, job_id: str = "job-xss-hunt-test"):
    def emit(action: str, detail: str) -> None:
        store.record_activity({
            "job_id": job_id, "agent": "xss-agent", "category": "XSS",
            "action": action, "detail": detail, "mode": "fixture"})
    return emit


def _audit_recorder(store: RuntimeStore, job_id: str = "job-xss-hunt-test"):
    from backend.research_agents.hunt.audit import hunt_audit_event

    def emit(stage: str, payload: dict) -> None:
        store.record_audit_event(
            hunt_audit_event(stage, job_id=job_id, **payload))
    return emit
