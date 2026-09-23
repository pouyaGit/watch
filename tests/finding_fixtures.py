"""Shared builders for the Finding Verification & Triage test suites.

Deterministic: real stores in tmp dirs, scripted job/result/evidence
outcomes mirroring PRODUCTION shapes (authoritative structured
``evidence_gate``), a scripted fake worker via the executor's
``worker_factory`` injection point, and advisor stubs.  The REAL
AgentWorker path is exercised by the fixture smoke script and the
mandatory Phase-19 production validation, not here.
"""

from __future__ import annotations

import tempfile
from typing import Any, Callable

from backend.research_agents.finding.models import (
    CandidateFinding,
    CasePackage,
    new_id,
    utcnow,
)
from backend.research_agents.finding.store import FindingStore
from backend.research_agents.models import (
    JobStatus,
    ResearchJob,
    ResearchResult,
)
from backend.research_agents.runtime_store import RuntimeStore

SCOPE = "fixture:test/cap.test"
SCOPE_PROD = "watch:scope:test/target.test"


def make_base() -> str:
    return tempfile.mkdtemp(prefix="finding-test-", dir="/tmp")


def make_stores(base: str | None = None
                ) -> tuple[RuntimeStore, FindingStore]:
    base = base or make_base()
    return RuntimeStore(base), FindingStore(base)


def make_candidate(fs: FindingStore, *,
                   cls: str = "XSS",
                   hypothesis: str = "parameter reflects unencoded input",
                   endpoint: dict[str, Any] | str | None = None,
                   scope: str = SCOPE,
                   target: str = "test",
                   job: str = "",
                   confidence: str = "medium",
                   specialist: str = "xss-agent",
                   evidence_refs: list[str] | None = None,
                   missing: list[str] | None = None,
                   campaign: str = "",
                   objective: str = "",
                   created_at: str = "") -> CandidateFinding:
    cand = CandidateFinding(
        candidate_id=new_id("cand"),
        source_job=job or f"job-src-{new_id('j')[2:10]}",
        scope_ref=scope,
        vulnerability_class=cls,
        hypothesis=hypothesis,
        specialist=specialist,
        target=target,
        endpoint=endpoint if endpoint is not None else {
            "url": "https://test/support/search",
            "method": "GET",
            "parameter": "q",
        },
        confidence=confidence,
        supporting_signals=[],
        evidence_refs=list(evidence_refs or []),
        missing_evidence=list(missing or []),
        source_campaign=campaign,
        source_objective=objective,
        provenance={"created_by": "finding-test"},
        created_at=created_at or utcnow(),
        updated_at=utcnow(),
    )
    return fs.add_candidate(cand)


def make_case(fs: FindingStore, candidate: CandidateFinding,
              *, state: str = "TRIAGED") -> CasePackage:
    case = CasePackage(
        case_id=new_id("case"),
        candidate_id=candidate.candidate_id,
        scope_ref=candidate.scope_ref,
        title=f"{candidate.vulnerability_class} candidate review",
        vulnerability_class=candidate.vulnerability_class,
        target=candidate.target,
        created_at=utcnow(),
        updated_at=utcnow(),
        state=state,
    )
    return fs.add_case(case)


def gate_structured(gate_reason: str, created_case: bool,
                    hunt: dict[str, Any] | None = None,
                    *, confidence: str = "medium",
                    extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """PRODUCTION result shape: authoritative structured evidence_gate."""
    structured: dict[str, Any] = {
        "evidence_gate": {
            "authoritative": True,
            "reason": gate_reason,
            "created_case": bool(created_case),
            "confidence": confidence,
        },
        "research_lineage": {
            "gate_reason": gate_reason,
            "case_id": "case-runtime-1" if created_case else "",
        },
    }
    if hunt is not None:
        structured["hunt"] = hunt
    if extra:
        structured.update(extra)
    return structured


HUNT_OK = {
    "objective_id": "hunt-obj-fix-1", "state": "RESOLVED",
    "termination_reason": "evidence gate: evidence_rules_met",
    "plan_ids": ["plan-fix-1"], "authorization_ids": ["auth-fix-1"],
    "observation_ids": ["obs-fix-1", "obs-fix-2"], "rows_added": 7,
}
HUNT_BLOCKED = {
    "objective_id": "hunt-obj-fix-2", "state": "BLOCKED",
    "termination_reason": "no_authorized_observation_can_reduce_uncertainty",
    "plan_ids": ["plan-fix-2"], "authorization_ids": ["auth-fix-2"],
    "observation_ids": [], "rows_added": 0,
}

# verification-job outcomes (what the scripted worker writes)
OUTCOMES: dict[str, dict[str, Any]] = {
    "verified": {
        "confidence": "high",
        "structured": gate_structured("evidence_rules_met", True,
                                      dict(HUNT_OK), confidence="high"),
    },
    "inconclusive": {
        "confidence": "insufficient",
        "structured": gate_structured("insufficient_evidence", False,
                                      dict(HUNT_OK)),
    },
    "no_hypothesis": {
        "confidence": "insufficient",
        "structured": gate_structured("no_hypothesis", False,
                                      dict(HUNT_OK)),
    },
    "hunt_blocked": {
        "confidence": "low",
        "structured": gate_structured("confidence_below_threshold", False,
                                      dict(HUNT_BLOCKED)),
    },
    "no_gate": {
        "confidence": "not_evaluated",
        "structured": {"hunt": dict(HUNT_OK)},
    },
}


def enqueue_job(store: RuntimeStore, *, category: str = "XSS",
                scope: str = SCOPE, url: str = "https://test/support",
                program: str = "fixture:test", subdomain: str = "test",
                execution_mode: str = "fixture",
                mission: str = "finding verification",
                status: str = "queued") -> ResearchJob:
    job = ResearchJob(
        id=f"job-{new_id('x')[2:]}",
        candidate_id="", category=category, endpoint=url, parameter="q",
        priority_score=50,
        status=JobStatus.QUEUED.value if status == "queued"
        else JobStatus.NEW.value,
        agent_category=category, program=program, subdomain=subdomain,
        url=url, mission=mission, authorization_ref=scope,
        execution_mode=execution_mode, assigned_agent=f"{category.lower()}-agent",
    )
    return store.enqueue(job)


def complete_job(store: RuntimeStore, job: ResearchJob, *,
                 outcome: str = "verified",
                 structured: dict[str, Any] | None = None,
                 confidence: str = "medium") -> None:
    """Drive QUEUED -> COMPLETED with a scripted result (or FAILED)."""
    st = JobStatus

    def status() -> str:
        cur = store.get(job.id)
        return str(getattr(cur, "status", "") or "")

    if status() == st.QUEUED.value:
        store.transition(job.id, st.CLAIMED.value, worker="fake-test")
    if status() == st.CLAIMED.value:
        store.transition(job.id, st.RUNNING.value, worker="fake-test")
    if outcome == "failed":
        store.transition(job.id, st.FAILED.value, worker="fake-test",
                         reason="injected verification failure")
        store.transition(job.id, st.TERMINAL_FAILED.value, worker="fake-test",
                         reason="attempts exhausted (injected)")
        return
    spec = OUTCOMES[outcome]
    result = ResearchResult(
        job_id=job.id,
        agent_name=job.assigned_agent,
        confidence=str(spec.get("confidence") or confidence),
        findings=("injected deterministic verification finding",),
        status=st.COMPLETED.value,
        execution_mode="fixture",
        structured=dict(structured if structured is not None
                        else spec["structured"]),
    )
    store.put_result(result)
    store.transition(job.id, st.COMPLETED.value, worker="fake-test")


def add_evidence(store: RuntimeStore, job_id: str, *,
                 kind: str = "supporting",
                 category: str = "XSS",
                 count: int = 2) -> list[str]:
    """Record real evidence rows on a job (production row shape)."""
    ids: list[str] = []
    for i in range(count):
        row = {
            "job_id": job_id,
            "type": "observation",
            "label": ("reflected marker observed" if kind == "supporting"
                      else "input did not reflect"),
            "signal": ("" if kind == "supporting" else "contradiction"),
            "category": category,
            "confidence": "high",
            "observation_ref": f"obs-fix-{i + 1}",
            "execution_mode": "fixture",
            "detail": f"deterministic {kind} evidence {i + 1}",
        }
        ids.append(store.record_evidence(row))
    return ids


# ---------------------------------------------------------------------
# scripted worker (the executor's worker_factory injection point)
# ---------------------------------------------------------------------
class _FindingWorker:
    def __init__(self, store: RuntimeStore, outcome: str,
                 evidence_kind: str, journal: dict[str, Any]) -> None:
        self.store = store
        self.outcome = outcome
        self.evidence_kind = evidence_kind
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
            return {"ran": 0}
        if self.evidence_kind:
            add_evidence(self.store, job.id, kind=self.evidence_kind,
                         category=job.agent_category)
        if self.outcome == "failed":
            complete_job(self.store, job, outcome="failed")
        else:
            complete_job(self.store, job, outcome=self.outcome)
        return {"ran": 1}


def finding_worker_factory(outcome: str = "verified",
                           evidence_kind: str = "supporting"
                           ) -> tuple[Callable[..., Any], dict[str, Any]]:
    journal: dict[str, Any] = {"ran": 0, "run_jobs": []}

    def factory(config: Any = None, store: Any = None) -> _FindingWorker:
        return _FindingWorker(store, outcome, evidence_kind, journal)

    return factory, journal


# ---------------------------------------------------------------------
# advisor stubs
# ---------------------------------------------------------------------
def advisor_valid(observation_token: str = "http-rows"):
    def fn(request: dict) -> tuple[dict, dict]:
        return ({
            "summary": "bounded interpretation of the candidate signals",
            "insights": [
                {"insight_code": "MISSING_EVIDENCE_1",
                 "text": "direct marker observation is missing"},
                {"insight_code": "RELATED_CASE_1",
                 "text": "no related verified case"},
            ],
            "recommendations": [
                {"recommendation_code": "VERIFY_MARKER",
                 "text": observation_token},
            ],
        }, {"model_requested": "openrouter/free",
            "model_resolved": "openrouter/free", "latency_ms": 5})
    return fn


def advisor_severity_claim():
    def fn(request: dict) -> tuple[dict, dict]:
        return ({
            "summary": "candidate looks serious",
            "insights": [],
            "recommendations": [
                {"recommendation_code": "SEVERITY_CRITICAL",
                 "text": "critical"},
            ],
        }, {"model_requested": "openrouter/free",
            "model_resolved": "openrouter/free", "latency_ms": 4})
    return fn


def advisor_cve_claim():
    def fn(request: dict) -> tuple[dict, dict]:
        return ({
            "summary": "cve applies",
            "insights": [],
            "recommendations": [
                {"recommendation_code": "CVE_APPLICABILITY_1",
                 "text": "applicable"},
            ],
        }, {"model_requested": "openrouter/free",
            "model_resolved": "openrouter/free", "latency_ms": 3})
    return fn


def advisor_unknown_type():
    def fn(request: dict) -> tuple[dict, dict]:
        return ({
            "summary": "try this",
            "insights": [],
            "recommendations": [
                {"recommendation_code": "VERIFY_ARBITRARY",
                 "text": "shell_exec"},
            ],
        }, {"model_requested": "openrouter/free",
            "model_resolved": "openrouter/free", "latency_ms": 3})
    return fn


def advisor_forbidden_content():
    def fn(request: dict) -> tuple[dict, dict]:
        return ({
            "summary": "fetch https://evil.test/payload to confirm",
            "insights": [],
            "recommendations": [],
        }, {"model_requested": "openrouter/free",
            "model_resolved": "openrouter/free", "latency_ms": 3})
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


# ---------------------------------------------------------------------
# end-to-end executor wrapper
# ---------------------------------------------------------------------
def run_findings(source_jobs: list[str], *, store: RuntimeStore,
                 finding_store: FindingStore,
                 advisor_fn: Any = None,
                 outcome: str = "verified",
                 evidence_kind: str = "supporting",
                 worker_factory: Callable[..., Any] | None = None,
                 extract_only: bool = False,
                 campaign_id: str = "",
                 objective_id: str = "",
                 limits: dict[str, int] | None = None,
                 max_verifications: int | None = None,
                 wall_seconds: float | None = None,
                 ) -> tuple[Any, dict[str, Any]]:
    from backend.research_agents.finding.executor import run_findings as rf
    from backend.research_agents.runtime import RuntimeConfig

    wf, journal = (worker_factory,
                   {"ran": 0, "run_jobs": []}) if worker_factory \
        else finding_worker_factory(outcome, evidence_kind)
    summary = rf(
        source_jobs=source_jobs, config=RuntimeConfig(
            execution_mode="fixture"),
        store=store, finding_store=finding_store,
        campaign_id=campaign_id, objective_id=objective_id,
        limits=limits, advisor_fn=advisor_fn, worker_factory=wf,
        extract_only=extract_only,
        max_verifications=max_verifications,
        wall_seconds=wall_seconds,
    )
    return summary, journal
