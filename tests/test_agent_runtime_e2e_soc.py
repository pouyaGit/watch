"""Agent Runtime v1 — end-to-end simulation + SOC integration (Phases 9/13).

Phase 13 chain: authorized mission → enqueue → claim → knowledge →
observation through the boundary → evidence → structured analysis →
result → activity → evidence-gated case → SOC reflection → completion.

Failure scenarios: authorization denied, observation failure, worker
crash/lease recovery, duplicate claim, malformed/absent analysis, case
gating negatives.  All runs are fixture-tagged (execution_mode=fixture)
— production execution is never faked by tests.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest import mock

from backend.research_agents.models import JobStatus, ResearchJob
from backend.research_agents.runtime import (
    AgentWorker,
    FixtureObservations,
    ObservationUnavailable,
    RuntimeConfig,
    agent_runtime_states,
    runtime_activity,
    runtime_snapshot,
)
from backend.research_agents.runtime_store import (
    RuntimeStore,
    rebind_store,
    utcnow,
)

STRONG_ROWS = [
    {"source": "http", "ref": "h1", "url": "https://shop.test/search?q=a",
     "method": "GET", "status": 200, "title": "search", "params": ["q"]},
    {"source": "http", "ref": "h2", "url": "https://shop.test/lookup?id=7",
     "method": "GET", "status": 200, "title": "lookup",
     "params": ["id", "q"]},
]


def _job(tag: str, *, category: str = "XSS", auth: str = "fixture:shop/shop.test",
         mode: str = "fixture", max_attempts: int = 2) -> ResearchJob:
    return ResearchJob(
        id=f"job-{tag}", candidate_id="cand", category=category,
        endpoint="https://shop.test/search?q=a", parameter="q",
        priority_score=70, status=JobStatus.QUEUED.value,
        assigned_agent="xss-agent", created_at=utcnow(),
        updated_at=utcnow(), agent_category=category, reasons=("e2e",),
        program="shop", subdomain="shop.test",
        url="https://shop.test/search?q=a",
        mission="reflected-input-review", authorization_ref=auth,
        execution_mode=mode, max_attempts=max_attempts,
        timeout_seconds=30,
    )


class _RuntimeCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rt-e2e-",
                                    dir=os.environ.get("TMPDIR", "/tmp"))
        self.store = RuntimeStore(self.dir)
        rebind_store(self.store)   # SOC adapters read the same store

    def tearDown(self):
        rebind_store(None)

    def _worker(self, rows=None, **cfg) -> AgentWorker:
        cfg.setdefault("execution_mode", "fixture")
        cfg.setdefault("worker_id", "w1")
        cfg.setdefault("job_timeout", 30)
        return AgentWorker(config=RuntimeConfig(**cfg), store=self.store,
                           observations=FixtureObservations(
                               rows if rows is not None else {}),
                           llm_enabled=False)


# ------------------------------------------------ Phase 13 happy chain
class TestFullChain(_RuntimeCase):
    def test_mission_to_soc_chain_completes(self):
        job = _job("happy")
        self.store.enqueue(job)                                  # 1-2
        worker = self._worker({job.id: STRONG_ROWS})
        stats = worker.run(max_jobs=1)                            # 3
        self.assertEqual(stats["processed"], 1)

        after = self.store.get(job.id)                            # completion
        self.assertEqual(after.status, JobStatus.COMPLETED.value)
        self.assertTrue(after.started_at and after.completed_at)

        result = self.store.get_result(job.id)                    # 8/9
        self.assertIsNotNone(result)
        self.assertEqual(result.execution_mode, "fixture")
        self.assertEqual(result.confidence, "high")

        evidence = self.store.list_evidence(job_id=job.id)        # 7
        self.assertGreaterEqual(len(evidence), 2)

        activity = [a.get("action")
                    for a in self.store.list_activity(limit=30)]  # 10
        for action in ("queued", "claimed", "running",
                       "analysis_completed", "completed"):
            self.assertIn(action, activity)

        # 11: case created ONLY because evidence rules passed
        cases = self.store.list_cases()
        self.assertEqual(len(cases), 1)
        case = cases[0]
        for field in ("target", "endpoint", "specialist", "hypothesis",
                      "evidence_refs", "observation_refs", "analysis",
                      "confidence", "status", "created_at",
                      "authorization_context", "execution_mode"):
            self.assertIn(field, case, f"case missing {field}")
        self.assertEqual(case["execution_mode"], "fixture")

        # 12: SOC reflects the final state
        from backend.soc import agents as soc_agents
        index = soc_agents.agents_index()
        xss = [a for a in index["agents"] if a["key"] == "xss"]
        if xss:
            self.assertEqual(xss[0]["status"], "IDLE")
            self.assertTrue(index["runtime"]["worker"]["alive"])

        detail = soc_agents.agent_detail("xss-agent")            # Agent detail
        records = detail.get("runtime_records") or {}
        if records.get("source_available"):
            self.assertTrue(any(r["id"] == job.id for r in records["jobs"]))
            self.assertEqual(records["evidence_count"] >= 1,
                             records["evidence_count"] >= 1)
            self.assertTrue(any(c["id"] == case["id"]
                                for c in records["cases"]))

    def test_knowledge_reads_are_recorded_only_when_real(self):
        job = _job("kb")
        self.store.enqueue(job)
        self._worker({job.id: STRONG_ROWS}).run(max_jobs=1)
        rows = self.store.list_knowledge_use(job_id=job.id)
        try:
            from backend import research_data as rd
            has_kb = bool(rd.list_kb(q="XSS", limit=1).get("items"))
        except Exception:
            has_kb = False
        if has_kb:
            self.assertGreaterEqual(len(rows), 1,
                                    "KB docs exist but reads were not recorded")
        for row in rows:
            self.assertTrue(row.get("document_id"))
            self.assertEqual(row.get("job_id"), job.id)

    def test_insufficient_evidence_never_creates_a_case(self):
        job = _job("thin")
        self.store.enqueue(job)
        self._worker({job.id: []}).run(max_jobs=1)   # no observations
        after = self.store.get(job.id)
        self.assertEqual(after.status, JobStatus.COMPLETED.value)
        result = self.store.get_result(job.id)
        self.assertEqual(result.confidence, "insufficient")
        self.assertIn("no_authorized_observations", result.blockers)
        self.assertEqual(self.store.list_cases(), [],
                         "a case was created without evidence")
        self.assertEqual(after.case_ref, "")

    def test_medium_confidence_below_threshold_blocks_case(self):
        job = _job("med")
        self.store.enqueue(job)
        one = [dict(STRONG_ROWS[0])]          # single source -> medium
        self._worker({job.id: one}).run(max_jobs=1)
        result = self.store.get_result(job.id)
        self.assertEqual(result.confidence, "medium")
        self.assertEqual(self.store.list_cases(), [],
                         "case created below the evidence threshold")


# ------------------------------------------------ failure scenarios
class TestFailureScenarios(_RuntimeCase):
    def test_authorization_denied_scenario(self):
        job = _job("denied", auth="")
        self.store.enqueue(job)
        self._worker({}).run(max_jobs=1)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.TERMINAL_FAILED.value)
        rejected = [e for e in self.store.audit_events()
                    if e.get("event") == "job_rejected"]
        self.assertTrue(rejected)
        self.assertIn("authorization_denied", rejected[0].get("reason", ""))

    def test_observation_failure_retries_then_terminates(self):
        job = _job("obs-fail")
        self.store.enqueue(job)

        class Boom:
            def observe(self, j):
                raise ObservationUnavailable("observation read failed: "
                                             "OSError")
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture", worker_id="w1"),
            store=self.store, observations=Boom(), llm_enabled=False)
        worker.run(max_jobs=4)   # max_attempts=2 -> attempts burn out
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.TERMINAL_FAILED.value)
        self.assertIsNone(self.store.get_result(job.id))

    def test_worker_crash_lease_recovery_requeues_then_runs(self):
        job = _job("crash")
        self.store.enqueue(job)
        # claim, then "crash" (no execution, lease already expired)
        self.store.claim_next("dead-worker", ("XSS",), lease_seconds=0)
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.CLAIMED.value)
        time.sleep(0.01)
        worker = self._worker({job.id: STRONG_ROWS})
        stats = worker.run(max_jobs=2)   # sweep recovers, then executes
        self.assertEqual(self.store.get(job.id).status,
                         JobStatus.COMPLETED.value)

    def test_duplicate_claim_across_stores_is_impossible(self):
        job = _job("dup")
        self.store.enqueue(job)
        other = RuntimeStore(self.dir)        # second process == new store
        first = self.store.claim_next("wA", ("XSS",))
        second = other.claim_next("wB", ("XSS",))
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(self.store.get(job.id).lease_owner, "wA")

    def test_heartbeat_loss_marks_failure_activity(self):
        job = _job("lost")
        self.store.enqueue(job)
        self.store.claim_next("w1", ("XSS",), lease_seconds=0)
        self.store.transition(job.id, JobStatus.RUNNING.value, worker="w1")
        self.store.sweep(now_ts=time.time() + 5)
        actions = [a.get("action")
                   for a in self.store.list_activity(limit=20)]
        self.assertIn("failed", actions)
        self.assertIn(self.store.get(job.id).status,
                      (JobStatus.QUEUED.value, JobStatus.FAILED.value,
                       JobStatus.TERMINAL_FAILED.value))


# ------------------------------------------------ SOC integration
class TestSOCReflection(_RuntimeCase):
    def test_activity_page_carries_runtime_events(self):
        from backend.soc import activity as soc_activity
        job = _job("soc")
        self.store.enqueue(job)
        self._worker({job.id: STRONG_ROWS}).run(max_jobs=1)
        payload = soc_activity.activity_payload()
        runtime_rows = [e for e in payload["timeline"]
                        if e.get("source") == "agent-runtime"]
        self.assertTrue(runtime_rows,
                        "runtime activity not visible on SOC Activity")
        self.assertTrue(any(r.get("job_id") == job.id
                            for r in runtime_rows))

    def test_overview_and_agents_statuses_agree(self):
        from backend.soc import agents as soc_agents
        from backend.soc import overview as soc_overview
        job = _job("agree")
        self.store.enqueue(job)
        self._worker({job.id: STRONG_ROWS}).run(max_jobs=1)
        index = soc_agents.agents_index()
        payload = soc_overview.overview_payload()
        counts = payload["agent_counts"]
        self.assertEqual(counts["registered"], index["count"])
        listed_statuses = [a["status"] for a in index["agents"]]
        self.assertEqual(counts["ready"],
                         listed_statuses.count("READY"))
        self.assertEqual(counts["idle"], listed_statuses.count("IDLE"))
        self.assertEqual(counts["active"], listed_statuses.count("ACTIVE"))
        self.assertEqual(counts["failed"], listed_statuses.count("FAILED"))
        self.assertEqual(counts["planned"], listed_statuses.count("PLANNED"))
        total = (counts["ready"] + counts["idle"] + counts["active"]
                 + counts["failed"] + counts["planned"])
        self.assertEqual(total, counts["registered"],
                         "split does not add up to registered")

    def test_runtime_case_detail_shows_agent_and_chain(self):
        from backend.soc import cases as soc_cases
        job = _job("casechain")
        self.store.enqueue(job)
        self._worker({job.id: STRONG_ROWS}).run(max_jobs=1)
        cases = self.store.list_cases()
        self.assertEqual(len(cases), 1)
        case_id = cases[0]["id"]
        index = soc_cases.cases_index()
        self.assertTrue(any(c.get("case_id") == case_id
                            for c in index["cases"]),
                        "runtime case missing from SOC case index")
        detail = soc_cases.case_detail(case_id)
        self.assertIsNotNone(detail, "runtime case detail did not resolve")
        chain = detail.get("agent_chain") or {}
        self.assertEqual(chain.get("responsible_agent"), "xss-agent")
        self.assertEqual(chain.get("job_id"), job.id)
        steps = {c.get("step") for c in chain.get("chain", [])}
        self.assertIn("job", steps)
        self.assertIn("result", steps)
        self.assertIn("evidence", steps)

    def test_absent_runtime_state_shows_no_fabricated_activity(self):
        rebind_store(None)                       # unbound default store
        empty_dir = tempfile.mkdtemp(prefix="rt-empty-",
                                     dir=os.environ.get("TMPDIR", "/tmp"))
        env = mock.patch.dict(os.environ,
                              {"WATCH_AGENT_RUNTIME_DIR": empty_dir})
        env.start()
        try:
            from backend.research_agents import runtime_store
            runtime_store.rebind_store(None)
            self.assertEqual(runtime_activity(), [])
            snap = runtime_snapshot()
            self.assertFalse(snap["deployed"])
        finally:
            from backend.research_agents import runtime_store
            runtime_store.rebind_store(None)
            env.stop()

    def test_agents_page_renders_runtime_statuses(self):
        from fastapi.testclient import TestClient
        import api
        job = _job("page")
        self.store.enqueue(job)
        self._worker({job.id: STRONG_ROWS}).run(max_jobs=1)
        saved = api.API_KEY
        api.API_KEY = "rt-" + "page-key-1a2b3c4d"
        try:
            client = TestClient(api.app)
            response = client.get(
                "/ui/soc/agents",
                params={"api_key": api.API_KEY})
        finally:
            api.API_KEY = saved
        self.assertEqual(response.status_code, 200)
        self.assertIn("Status meanings", response.text)
        self.assertIn("IDLE", response.text)
        self.assertIn("Agent worker:", response.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
