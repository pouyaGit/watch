"""Shared builders for the Epic8 Production Intelligence test suites.

Every suite runs HERMETICALLY: ``WATCH_AGENT_RUNTIME_DIR`` is pointed at
a fresh tmp dir in setUp (sources construct stores per call, so the env
swap is complete) and restored in tearDown — no suite can ever touch the
production runtime directory, whatever the caller's cwd.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

from backend.research_agents.campaign.models import Campaign, new_id, utcnow
from backend.research_agents.finding.models import (
    CandidateFinding,
    VerificationObjective,
    new_id as fnew_id,
)
from backend.research_agents.hunt.models import HuntObjective
from backend.research_agents.intelligence.memory import make_item

SCOPE = "fixture:test/target.example"
PROD_SCOPE = "watch:scope:prog/target.example"


class IntelEnvMixin:
    """Points every store at a fresh tmp dir for one test."""

    def setUp(self) -> None:                      # noqa: N802 (unittest)
        super().setUp()
        self._saved_env = os.environ.get("WATCH_AGENT_RUNTIME_DIR")
        self.base = tempfile.mkdtemp(prefix="prod-intel-", dir="/tmp")
        os.environ["WATCH_AGENT_RUNTIME_DIR"] = self.base
        # known pitfall: default_store() caches the first RuntimeStore,
        # so SOC handlers would keep reading the PREVIOUS test's dir
        # until rebind_store resets the cache (skill: rebind_store when
        # changing WATCH_AGENT_RUNTIME_DIR inside a suite).
        from backend.research_agents.runtime_store import rebind_store
        rebind_store(None)

    def tearDown(self) -> None:                   # noqa: N802
        if self._saved_env is None:
            os.environ.pop("WATCH_AGENT_RUNTIME_DIR", None)
        else:
            os.environ["WATCH_AGENT_RUNTIME_DIR"] = self._saved_env
        from backend.research_agents.runtime_store import rebind_store
        rebind_store(None)
        super().tearDown()


def runtime():
    from backend.research_agents.runtime_store import RuntimeStore
    return RuntimeStore()


def finding():
    from backend.research_agents.finding.store import FindingStore
    from backend.research_agents.runtime_store import runtime_base_dir
    return FindingStore(runtime_base_dir())


def campaigns():
    from backend.research_agents.campaign.store import CampaignStore
    return CampaignStore()


def hunts():
    from backend.research_agents.hunt.store import HuntStore
    return HuntStore()


def memory():
    from backend.research_agents.intelligence.memory import MemoryStore
    return MemoryStore()


# ------------------------------------------------------------------ runtime
def add_job(store=None, *, status: str = "COMPLETED", agent: str = "xss-agent",
            category: str = "XSS", subdomain: str = "target.example",
            program: str = "prog", job_id: str = "") -> Any:
    from backend.research_agents.models import JobStatus, ResearchJob
    from backend.research_agents.finding.models import new_id as nid

    store = store or runtime()
    st = JobStatus
    job = ResearchJob(
        id=job_id or f"job-{nid('x')[2:]}",
        candidate_id="", category=category, endpoint="https://t.example/",
        parameter="q", priority_score=50,
        status=st.QUEUED.value, agent_category=category,
        program=program, subdomain=subdomain,
        url=f"https://{subdomain}/", mission="finding verification",
        authorization_ref=SCOPE, execution_mode="fixture",
        assigned_agent=agent,
    )
    store.enqueue(job)
    if status == "QUEUED":
        return store.get(job.id)
    store.transition(job.id, st.CLAIMED.value, worker="t")
    store.transition(job.id, st.RUNNING.value, worker="t")
    if status == "RUNNING":
        return store.get(job.id)
    if status == "TERMINAL_FAILED":
        store.transition(job.id, st.FAILED.value, worker="t",
                         reason="injected failure")
        store.transition(job.id, st.TERMINAL_FAILED.value, worker="t",
                         reason="attempts exhausted (injected)")
        return store.get(job.id)
    from backend.research_agents.models import ResearchResult
    store.put_result(ResearchResult(
        job_id=job.id, agent_name=agent, confidence="medium",
        findings=("fixture finding",), status=st.COMPLETED.value,
        execution_mode="fixture", structured={}))
    store.transition(job.id, st.COMPLETED.value, worker="t")
    return store.get(job.id)


def add_evidence(store=None, job_id: str = "job-x", *, count: int = 2
                 ) -> list[str]:
    store = store or runtime()
    ids = []
    for i in range(count):
        ids.append(store.record_evidence({
            "job_id": job_id, "type": "observation",
            "label": f"fixture observation {i}",
            "category": "XSS", "confidence": "high",
            "observation_ref": f"obs-fx-{i}", "execution_mode": "fixture",
            "detail": "deterministic fixture detail"}))
    return ids


def add_knowledge_use(store=None, *, job_id: str = "job-x",
                      agent: str = "xss-agent", doc: str = "kb-fixture0001",
                      at: str = "") -> None:
    store = store or runtime()
    store.record_knowledge_use({
        "agent": agent, "category": "XSS",
        "document_id": doc, "job_id": job_id, "mode": "fixture",
        "title": "fixture knowledge doc", "topic": "XSS",
        **({"created_at": at} if at else {})})


def add_runtime_case(store=None, *, case_id: str = "case-fx1",
                     job_id: str = "job-x", status: str = "OPEN",
                     target: str = "target.example") -> str:
    store = store or runtime()
    return store.record_case({"id": case_id, "job_id": job_id,
                              "status": status, "target": target,
                              "specialist": "xss-agent",
                              "category": "XSS", "title": "fixture case"})


def audit(store=None, event: str = "job_claimed", *, ts: str = "",
          **payload: Any) -> None:
    store = store or runtime()
    store.record_audit_event({"event": event,
                              **({"ts": ts} if ts else {}),
                              **payload})


# ---------------------------------------------------------------- campaign
def add_campaign(*, state: str = "BLOCKED", program: str = "prog",
                 subdomain: str = "target.example",
                 termination: str = "") -> Campaign:
    camp = Campaign(
        campaign_id=f"camp-{new_id('c')[5:]}",
        program=program, scope_ref=PROD_SCOPE,
        campaign_objective="fixture objective",
        target_context={"program": program, "subdomain": subdomain,
                        "url": f"https://{subdomain}/"},
        state=state, provenance={"created_by": "prod-intel-test"},
        termination_reason=termination,
        updated_at=utcnow(), created_at=utcnow())
    return campaigns().create_campaign(camp)


# ------------------------------------------------------------------- hunt
def add_hunt_objective(*, state: str = "BLOCKED",
                       reason: str = "no_authorized_observation_available",
                       specialist: str = "xss-agent",
                       category: str = "XSS",
                       subdomain: str = "target.example",
                       scope: str = PROD_SCOPE,
                       plans: int = 1, observations: int = 2
                       ) -> HuntObjective:
    store = hunts()
    obj = HuntObjective(
        objective_id=f"obj-{fnew_id('o')[4:]}",
        job_id=f"job-h-{fnew_id('j')[2:]}",
        specialist=specialist, category=category, scope_ref=scope,
        target_context={"program": "prog", "subdomain": subdomain,
                        "url": f"https://{subdomain}/"},
        hypothesis="fixture hypothesis", research_objective="fixture ro",
        evidence_requirements={}, state="OPEN",
        provenance={"source": "prod-intel-test"},
        plans_created=plans, observations_run=observations,
        created_at=utcnow(), updated_at=utcnow())
    store.create_objective(obj)
    if state != "OPEN":
        store.revise_objective(obj.objective_id, state=state,
                               reason="fixture transition",
                               termination_reason=reason,
                               termination_detail="fixture detail")
    return store.get_objective(obj.objective_id)


# ---------------------------------------------------------------- findings
def add_candidate(*, target: str = "target.example",
                  scope: str = SCOPE, cls: str = "XSS",
                  specialist: str = "xss-agent", job: str = "job-fx"
                  ) -> CandidateFinding:
    cand = CandidateFinding(
        candidate_id=f"cand-{fnew_id('c')[5:]}",
        source_job=job, scope_ref=scope, vulnerability_class=cls,
        hypothesis="fixture hypothesis", specialist=specialist,
        target=target, evidence_refs=["ev-fx-1"],
        created_at=utcnow(), updated_at=utcnow())
    return finding().add_candidate(cand)


def add_verification(candidate: CandidateFinding, *,
                     state: str = "VERIFIED",
                     gate_reason: str = "evidence_rules_met"
                     ) -> VerificationObjective:
    ver = VerificationObjective(
        verification_id=f"ver-{fnew_id('v')[4:]}",
        candidate_id=candidate.candidate_id,
        scope_ref=candidate.scope_ref,
        job_id=candidate.source_job,
        hypothesis=candidate.hypothesis,
        vulnerability_class=candidate.vulnerability_class,
        state="CREATED",
        gate_reason=gate_reason,
        decision=("VERIFIED" if state == "VERIFIED" else ""),
        created_at=utcnow(), updated_at=utcnow())
    fs = finding()
    fs.add_verification(ver)
    # move to the requested state through the store's own transitions;
    # the path's LAST element is always the terminal state itself
    path = {
        "CREATED": [],
        "VERIFIED": ["READY", "AUTHORIZATION_REQUIRED", "AUTHORIZED",
                     "EXECUTING", "VERIFIED"],
        "BLOCKED": ["BLOCKED"],          # CREATED -> BLOCKED is legal
        "FAILED": ["FAILED"],
        "REJECTED": ["READY", "REJECTED"],
        "INCONCLUSIVE": ["READY", "AUTHORIZATION_REQUIRED", "AUTHORIZED",
                         "EXECUTING", "INCONCLUSIVE"],
    }
    cur = ver
    for step in path.get(state, []):
        cur = fs.transition_verification(cur.verification_id, step,
                                         reason="fixture step")
    return fs.get_verification(ver.verification_id)


def add_finding_case(candidate: CandidateFinding, *, state: str = "TRIAGED"
                     ):
    from backend.research_agents.finding.models import CasePackage
    fs = finding()
    cand = fs.get_candidate(candidate.candidate_id)
    if cand is not None and cand.lifecycle_state == "DETECTED":
        # real lifecycle: a case may only be created for a triaged,
        # verification-bound candidate (store enforces this)
        fs.transition_candidate(candidate.candidate_id, "TRIAGED",
                                reason="fixture triage")
    case = CasePackage(
        case_id=f"fcase-{fnew_id('c')[5:]}",
        candidate_id=candidate.candidate_id,
        scope_ref=candidate.scope_ref,
        title="fixture case package",
        vulnerability_class=candidate.vulnerability_class,
        target=candidate.target, state=state,
        created_at=utcnow(), updated_at=utcnow())
    return finding().add_case(case)


# ----------------------------------------------------------------- memory
def add_memory(*, kind: str = "observed_behavior", state: str = "OBSERVED",
               subject: str = "status:200", text: str = "fixture memory",
               target: str = "target.example", agent: str = "xss-agent",
               job: str = "job-mem1", now: str = ""):
    item = make_item(kind=kind, state=state, subject_key=subject,
                     text=text, category="XSS", agent=agent, target=target,
                     provenance_job=job, provenance_source="fixture-test",
                     **({"now": now} if now else {}))
    memory().append([item])
    return item


def envelope(data: Any, state: str = "ok", reason: str = "") -> dict:
    """A source envelope for patching sources.* in unit tests."""
    return {"state": state, "data": data, "reason": reason}
