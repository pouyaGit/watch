"""Shared builders for the Campaign Orchestrator test suites (not a test module).

Deterministic: real stores in tmp dirs, a scripted fake worker (the
executor's ``worker_factory`` injection point), and advisor stubs.  The
REAL AgentWorker path is exercised by the fixture smoke script and by the
mandatory Phase-18 production campaign, not here.
"""

from __future__ import annotations

import tempfile
from typing import Any, Callable

from backend.research_agents.campaign.models import (
    Campaign,
    CampaignObjective,
    Dependency,
    new_id,
    utcnow,
)
from backend.research_agents.campaign.store import CampaignStore
from backend.research_agents.models import (
    JobStatus,
    ResearchJob,
    ResearchResult,
)
from backend.research_agents.runtime_store import RuntimeStore

SCOPE = "fixture:test/campaign.test"


def make_base() -> str:
    return tempfile.mkdtemp(prefix="campaign-test-", dir="/tmp")


def make_stores(base: str | None = None
                ) -> tuple[RuntimeStore, CampaignStore]:
    base = base or make_base()
    return RuntimeStore(base), CampaignStore(base)


def make_campaign(cs: CampaignStore, *,
                  scope: str = SCOPE,
                  program: str = "fixture:test",
                  objective: str = "Research authorized XSS and CVE "
                                   "questions for the campaign target.",
                  limits: dict[str, int] | None = None,
                  priority: int = 60) -> Campaign:
    camp = Campaign(
        campaign_id=new_id("cmp"),
        program=program,
        scope_ref=scope,
        campaign_objective=objective,
        target_context={"program": program, "subdomain": "test",
                        "url": "https://test/"},
        priority=priority,
        provenance={"created_by": "campaign-test"},
        limits=dict(limits or {}),
    )
    return cs.create_campaign(camp)


def add_obj(cs: CampaignStore, camp: Campaign, *,
            category: str = "XSS",
            question: str = "Is reflected input on the search path "
                            "executable as XSS?",
            hypothesis: str = "The parameter reflects unencoded input.",
            priority: int = 50,
            deps: list[Dependency] | None = None,
            specialist: str = "") -> CampaignObjective:
    obj = CampaignObjective(
        objective_id=new_id("obj"),
        campaign_id=camp.campaign_id,
        category=category,
        scope_ref=camp.scope_ref,
        research_question=question,
        hypothesis=hypothesis,
        specialist=specialist,
        priority=priority,
        dependencies=list(deps or []),
        provenance={"created_by": "campaign-test"},
    )
    return cs.add_objective(obj, camp)


def make_dependency(dependent_id: str, prereq_id: str,
                    kind: str = "REQUIRED") -> Dependency:
    return Dependency(objective_id=dependent_id, depends_on=prereq_id,
                      kind=kind)


# ---------------------------------------------------------------------------
# scripted outcomes (structured result payloads the fake worker writes)
# ---------------------------------------------------------------------------

def _structured(gate_reason: str, case_id: str,
                hunt: dict[str, Any] | None) -> dict[str, Any]:
    structured: dict[str, Any] = {
        "research_lineage": {"gate_reason": gate_reason,
                             "case_id": case_id},
        # production runtime shape: the authoritative Evidence Gate
        # record at structured["evidence_gate"] (primary extraction path)
        "evidence_gate": {
            "authoritative": True,
            "confidence": "high"
            if gate_reason == "evidence_rules_met" else "medium",
            "created_case": bool(case_id),
            "reason": gate_reason,
        },
    }
    if hunt is not None:
        structured["hunt"] = hunt
    return structured


OUTCOMES: dict[str, dict[str, Any]] = {
    # Evidence Gate claimed a case -> objective RESOLVED (memory VERIFIED)
    "completed_case": {
        "confidence": "high",
        "structured": _structured(
            "evidence_rules_met", "case-fake-0001", {
                "objective_id": "hunt-obj-fake", "state": "RESOLVED",
                "termination_reason": "evidence gate: evidence_rules_met",
                "plan_ids": ["plan-fake-1"],
                "authorization_ids": ["auth-fake-1"],
                "observation_ids": ["obs-fake-1", "obs-fake-2"],
                "rows_added": 9, "llm_advisory": {"calls": 0},
            })},
    # gate met but no case row (e.g. dedupe) -> RESOLVED, memory RESEARCHED
    "completed_gate_met_no_case": {
        "confidence": "medium",
        "structured": _structured(
            "evidence_rules_met", "", {
                "objective_id": "hunt-obj-fake", "state": "RESOLVED",
                "plan_ids": ["plan-fake-1"],
                "authorization_ids": ["auth-fake-1"],
                "observation_ids": ["obs-fake-1"],
                "rows_added": 4, "llm_advisory": {"calls": 0},
            })},
    # hunt could not reduce uncertainty -> objective BLOCKED
    "completed_blocked": {
        "confidence": "low",
        "structured": _structured(
            "no_case/unsatisfiable", "", {
                "objective_id": "hunt-obj-fake", "state": "BLOCKED",
                "termination_reason":
                    "no_authorized_observation_can_reduce_uncertainty",
                "plan_ids": ["plan-fake-1"],
                "authorization_ids": ["auth-fake-1"],
                "observation_ids": ["obs-fake-1"],
                "rows_added": 0, "llm_advisory": {"calls": 0},
            })},
    # completed, hunt resolved, gate did NOT claim -> objective REJECTED
    "completed_no_case": {
        "confidence": "insufficient",
        "structured": _structured(
            "insufficient_evidence", "", {
                "objective_id": "hunt-obj-fake", "state": "RESOLVED",
                "plan_ids": ["plan-fake-1"],
                "authorization_ids": [],
                "observation_ids": [],
                "rows_added": 0, "llm_advisory": {"calls": 0},
            })},
    # hunt planner produced nothing and gate lineage missing -> honest REJECTED
    "completed_no_hunt": {
        "confidence": "not_evaluated",
        "structured": _structured("gate_not_claimed", "", None)},
}


def put_job_result(store: RuntimeStore, job: ResearchJob,
                   outcome: str) -> None:
    """Persist a result + terminal job status for ``outcome`` (or FAILED)."""
    st = JobStatus

    def _status() -> str:
        current = store.get(job.id)
        return str(getattr(current, "status", "") or "")

    if _status() == st.QUEUED.value:
        store.transition(job.id, st.CLAIMED.value, worker="fake-test")
    if _status() == st.CLAIMED.value:
        store.transition(job.id, st.RUNNING.value, worker="fake-test")
    if outcome == "failed":
        store.transition(job.id, st.FAILED.value, worker="fake-test",
                         reason="injected observation failure")
        store.transition(job.id, st.TERMINAL_FAILED.value,
                         worker="fake-test",
                         reason="attempts exhausted (injected)")
        return
    if outcome == "leave_queued":
        # undo the claims: the job simply does not finish this run
        store.transition(job.id, st.QUEUED.value, worker="fake-test",
                         reason="released (injected pending job)")
        return
    spec = OUTCOMES[outcome]
    result = ResearchResult(
        job_id=job.id,
        agent_name=job.assigned_agent,
        confidence=str(spec["confidence"]),
        findings=("injected deterministic finding",),
        status=st.COMPLETED.value,
        execution_mode="fixture",
        structured=dict(spec["structured"]),
    )
    store.put_result(result)
    store.transition(job.id, st.COMPLETED.value, worker="fake-test")


class _FakeWorker:
    def __init__(self, store: RuntimeStore, outcome: str,
                 journal: dict[str, Any]) -> None:
        self.store = store
        self.outcome = outcome
        self.journal = journal

    def run(self, max_jobs: int = 1, **_kw: Any) -> dict[str, Any]:
        queued = self.store.list_jobs(status=JobStatus.QUEUED.value,
                                      limit=10)
        if not queued:
            return {"ran": 0}
        job = queued[0]
        self.journal["run_jobs"].append(job.id)
        self.journal["ran"] += 1
        if self.outcome == "leave_queued":
            return {"ran": 0}   # job stays QUEUED within this run
        put_job_result(self.store, job, self.outcome)
        return {"ran": 1}


def fake_worker_factory(outcome: str = "completed_case"
                        ) -> tuple[Callable[..., Any], dict[str, Any]]:
    journal: dict[str, Any] = {"ran": 0, "run_jobs": []}

    def factory(config: Any = None, store: Any = None) -> _FakeWorker:
        # NOTE: the executor calls worker factories POSITIONALLY
        # (matching _default_worker_factory(config, store)).
        return _FakeWorker(store, outcome, journal)

    return factory, journal


# ---------------------------------------------------------------------------
# advisor stubs
# ---------------------------------------------------------------------------

def advisor_valid(rec_id: str):
    def fn(request: dict) -> tuple[dict, dict]:
        return ({
            "summary": f"prioritize {rec_id}",
            "insights": [{"insight_code": "INFO_VALUE_1",
                          "text": "bounded information value note"}],
            "recommendations": [{
                "recommendation_code": "OBJECTIVE_PRIORITY_1",
                "text": rec_id}],
        }, {"model_requested": "openrouter/free",
            "model_resolved": "openrouter/free",
            "latency_ms": 3})
    return fn


def advisor_raises(exc: Exception):
    def fn(request: dict) -> tuple[dict, dict]:
        raise exc
    return fn


def advisor_malformed(payload: Any):
    def fn(request: dict) -> tuple[Any, dict]:
        return payload, {"model_requested": "openrouter/free",
                         "model_resolved": "", "latency_ms": 1}
    return fn


def run_campaign(cid: str, cs: CampaignStore, store: RuntimeStore, *,
                 advisor_fn: Any = None, max_objectives: int = 1,
                 outcome: str = "completed_case",
                 worker_factory: Callable[..., Any] | None = None,
                 now_fn: Any = None, memory_store: Any = None
                 ) -> tuple[Any, dict[str, Any]]:
    """One executor run with a scripted worker; returns (summary, journal)."""
    from backend.research_agents.campaign.executor import (
        execute_campaign,
    )
    from backend.research_agents.runtime import RuntimeConfig

    wf, journal = (worker_factory, {"ran": 0, "run_jobs": []}) \
        if worker_factory else fake_worker_factory(outcome)
    kwargs: dict[str, Any] = dict(
        advisor_fn=advisor_fn, store=store, campaign_store=cs,
        max_objectives=max_objectives, worker_factory=wf,
        config=RuntimeConfig(execution_mode="fixture"),
    )
    if now_fn is not None:
        kwargs["now_fn"] = now_fn
    if memory_store is not None:
        kwargs["memory_store"] = memory_store
    summary = execute_campaign(cid, **kwargs)
    return summary, journal


def read_memory_rows(base: str) -> list[dict[str, Any]]:
    import json as _json
    from pathlib import Path
    path = Path(base) / "memory.jsonl"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rows.append(_json.loads(line))
            except (TypeError, ValueError):
                continue
    return rows


def append_raw_objective(base: str, row: dict[str, Any]) -> None:
    """Tamper helper: append a raw objective snapshot (latest-row-wins)."""
    import json as _json
    from pathlib import Path
    path = Path(base) / "campaign_objectives.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(_json.dumps(row, sort_keys=True) + "\n")


__all__ = [
    "SCOPE", "make_base", "make_stores", "make_campaign", "add_obj",
    "make_dependency", "OUTCOMES", "put_job_result", "fake_worker_factory",
    "advisor_valid", "advisor_raises", "advisor_malformed", "run_campaign",
    "read_memory_rows", "append_raw_objective",
]
