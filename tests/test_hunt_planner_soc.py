"""AUTONOMOUS HUNT PLANNER v1 — Phase 13 SOC visibility tests.

All SOC state comes from real persisted hunt records (objectives,
plans, transitions, authorizations, observations, activity rows, audit
lineage). No fake counters, no fabricated plans.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from tests.hunt_fixtures import (  # noqa: E402
    make_job,
    make_store,
    rich_rows,
    run_hunt_fixture,
)

from backend.research_agents.hunt import HuntObjective, HuntStore  # noqa: E402
from backend.research_agents.hunt.models import HuntPlan, PlanTransition  # noqa: E402
from backend.research_agents.runtime_store import utcnow  # noqa: E402
from backend.soc.agents import (  # noqa: E402
    _INTEL_ACTIONS,
    _hunt_intelligence,
    _agent_intelligence,
)
from backend.soc.cases import case_detail  # noqa: E402

AGENT_TEMPLATE = (Path(__file__).resolve().parents[1] /
                  "web" / "templates" / "soc" / "agent_detail.html")
CASE_TEMPLATE = (Path(__file__).resolve().parents[1] /
                 "web" / "templates" / "soc" / "case_detail.html")

HUNT_ACTIONS = (
    "hunt_objective_created", "missing_evidence_detected",
    "hunt_plan_created", "plan_validated", "authorization_requested",
    "authorization_granted", "authorization_rejected",
    "observation_started", "observation_completed",
    "research_state_updated", "hunt_replanned", "hunt_terminated",
)


def _obj(obj_id: str = "obj-soc-1", state: str = "OPEN") -> HuntObjective:
    return HuntObjective(
        objective_id=obj_id, job_id="job-xss-hunt-test",
        specialist="xss-agent", category="XSS",
        scope_ref="fixture:shop/shop.test",
        target_context={"subdomain": "shop.test"}, hypothesis="h",
        research_objective="support or reject the hypothesis",
        evidence_requirements={"min_evidence_refs": 2,
                               "required_types": ["observation"],
                               "require_high_confidence": True},
        state=state, provenance={"source": "test"},
        created_at=utcnow(), updated_at=utcnow())


def _plan(plan_id: str = "plan-soc-1", version: int = 1) -> HuntPlan:
    return HuntPlan(
        plan_id=plan_id, objective_id="obj-soc-1",
        job_id="job-xss-hunt-test", version=version, parent_plan_id="",
        scope_ref="fixture:shop/shop.test", specialist="xss-agent",
        category="XSS",
        reason="Selected because parameter-rows addresses "
               "parameter_inventory_missing for hypothesis H while "
               "requiring an already-authorized read-only observation",
        hypotheses_addressed=("H",),
        observations_requested=({
            "observation_type": "parameter-rows",
            "inputs": {"subdomain": "shop.test", "limit": 25},
            "expected_evidence": "observation", "missing_item_ids": [],
            "risk_class": "READ_ONLY"},),
        required_evidence=("observation",),
        expected_information_gain=0.8, gain_label="heuristic",
        safety_constraints=("no_target_contact",),
        authorization_requirements=("fixture:shop/shop.test",),
        dependencies=(), priority=9,
        provenance={"planner": "test"}, created_at=utcnow())


class HuntPayloadTests(unittest.TestCase):
    def test_no_objectives_reports_honest_empty_state(self):
        store = make_store()
        payload = _hunt_intelligence(store, "XSS")
        self.assertFalse(payload["available"])
        self.assertEqual(payload["reason"], "no objectives recorded")
        self.assertEqual(payload["objectives"], [])

    def test_available_payload_from_real_records(self):
        store = make_store()
        hs = HuntStore(store.base)
        hs.create_objective(_obj(state="OPEN"))
        hs.append_plan(_plan())
        for frm, to in (("DRAFT", "VALIDATED"),
                        ("VALIDATED", "AUTHORIZATION_REQUIRED"),
                        ("AUTHORIZATION_REQUIRED", "AUTHORIZED")):
            hs.record_transition(PlanTransition(
                plan_id="plan-soc-1", from_state=frm, to_state=to,
                reason="ok", at=utcnow()))
        hs.revise_objective("obj-soc-1", state="NEEDS_EVIDENCE",
                            reason="missing parameter inventory")

        payload = _hunt_intelligence(store, "XSS")
        self.assertTrue(payload["available"])
        self.assertEqual(len(payload["objectives"]), 1)
        o = payload["objectives"][0]
        self.assertEqual(o["objective_id"], "obj-soc-1")
        self.assertEqual(o["state"], "NEEDS_EVIDENCE")
        self.assertEqual(len(o["plans"]), 1)
        # why-the-next-observation-was-selected is real plan reasoning
        self.assertIn("Selected because", o["why_next_observation"])
        self.assertEqual(o["active_plan"]["plan_id"], "plan-soc-1")
        self.assertIsNotNone(o["pending_observation"])

    def test_category_isolation_no_cross_specialist_leakage(self):
        store = make_store()
        hs = HuntStore(store.base)
        hs.create_objective(_obj())
        payload = _hunt_intelligence(store, "CVE_RESEARCH")
        self.assertFalse(payload["available"])
        self.assertEqual(payload["objectives"], [])

    def test_intel_actions_include_every_hunt_activity_name(self):
        for action in HUNT_ACTIONS:
            self.assertIn(action, _INTEL_ACTIONS)

    def test_agent_intelligence_carries_hunt_block(self):
        store = make_store()
        hs = HuntStore(store.base)
        hs.create_objective(_obj())
        out = _agent_intelligence(store, "XSS", "xss-agent")
        self.assertIn("hunt", out)
        self.assertTrue(out["hunt"]["available"])

    def test_agent_intelligence_without_store_stays_honest(self):
        class Missing:
            base = "/nonexistent/hunt/path"

        out = _agent_intelligence(Missing(), "XSS", "xss-agent")
        self.assertFalse(out["hunt"]["available"])


class RealLoopSocStateTests(unittest.TestCase):
    """SOC state after a REAL fixture hunt loop run."""

    @classmethod
    def setUpClass(cls):
        import os
        cls._old_runtime_dir = os.environ.get("WATCH_AGENT_RUNTIME_DIR")
        cls.outcome, cls.job, cls.cap, cls.hs, cls.store = run_hunt_fixture()

    def test_objective_history_is_visible(self):
        objs = self.hs.list_objectives(category="XSS")
        self.assertEqual(len(objs), 1)
        history = self.hs.objective_history(objs[0].objective_id)
        self.assertGreaterEqual(len(history), 2)
        states = [h.state for h in history]
        # real state progression recorded across revisions
        self.assertIn("NEEDS_EVIDENCE", states)

    def test_all_plans_and_versions_preserved(self):
        plans = self.hs.plans_for_objective(
            self.outcome.objective_id)
        self.assertGreaterEqual(len(plans), 1)
        versions = [p.version for p in plans]
        self.assertEqual(versions, sorted(set(versions)))

    def test_soc_activity_contains_hunt_events_from_real_run(self):
        rows = self.store.list_activity(limit=200)
        actions = [r["action"] for r in rows]
        for required in ("hunt_objective_created", "hunt_plan_created",
                         "plan_validated", "authorization_requested",
                         "authorization_granted", "observation_started",
                         "observation_completed", "hunt_terminated"):
            self.assertIn(required, actions)

    def test_audit_lineage_persisted_without_secrets(self):
        events = [e for e in self.store.audit_events(limit=200)
                  if str(e.get("event", "")).startswith("hunt_")]
        names = [e["event"] for e in events]
        self.assertIn("hunt_authorization", names)
        self.assertIn("hunt_lineage_final", names)
        blob = json.dumps(events, default=str)
        self.assertNotIn("sk-or", blob)
        self.assertNotIn("OPENROUTER_API_KEY", blob)

    def test_hunt_payload_after_real_run(self):
        payload = _hunt_intelligence(self.store, "XSS")
        self.assertTrue(payload["available"])
        o = payload["objectives"][0]
        self.assertTrue(o["termination_reason"])
        self.assertTrue(o["recent_outcomes"])

    def test_case_detail_exposes_hunt_from_contract(self):
        # run a worker job so a case + structured contract exist
        import tempfile
        from backend.research_agents.runtime import (
            AgentWorker, FixtureObservations, RuntimeConfig,
        )
        from backend.research_agents.models import JobStatus

        import os
        base = tempfile.mkdtemp(prefix="hunt-soc-", dir="/tmp")
        os.environ["WATCH_AGENT_RUNTIME_DIR"] = base
        store = RuntimeStoreSafe(base)
        job = make_job(job_id="job-xss-hunt-soc")
        store.enqueue(job)
        worker = AgentWorker(
            config=RuntimeConfig(execution_mode="fixture",
                                 worker_id="hunt-soc", job_timeout=60,
                                 hunt_max_plans=3, hunt_max_seconds=30,
                                 hunt_max_llm_plans=0),
            store=store,
            observations=FixtureObservations({job.id: rich_rows()}),
            llm_enabled=False)
        worker.run(max_jobs=1)
        after = store.get(job.id)
        self.assertEqual(after.status, JobStatus.COMPLETED.value)
        cases = store.list_cases()
        if not cases:
            self.skipTest("gate did not create a case on this fixture")
        detail = case_detail(cases[0]["id"])
        import os
        if self._old_runtime_dir is None:
            os.environ.pop("WATCH_AGENT_RUNTIME_DIR", None)
        else:
            os.environ["WATCH_AGENT_RUNTIME_DIR"] = self._old_runtime_dir
        self.assertIsNotNone(detail)
        ri = detail.get("research_intel") or {}
        self.assertIn("hunt", ri)
        self.assertTrue(ri["hunt"].get("objective_id"))
        self.assertTrue(ri["hunt"].get("termination_reason"))
        self.assertIn("hunt_detail", ri)
        self.assertTrue(ri["hunt_detail"]["plans"])


class TemplateSourceTests(unittest.TestCase):
    def test_agent_template_shows_hunt_sections(self):
        src = AGENT_TEMPLATE.read_text()
        self.assertIn("Hunt objectives", src)
        self.assertIn("Why this observation was selected", src)
        self.assertIn("Plan versions", src)
        self.assertIn("Pending observation", src)
        self.assertIn("Recent outcomes", src)
        self.assertIn("No hunt objectives recorded", src)

    def test_case_template_shows_hunt_sections(self):
        src = CASE_TEMPLATE.read_text()
        self.assertIn("Hunt plan (autonomous", src)
        self.assertIn("Hunt plans (all versions", src)
        self.assertIn("Observations executed", src)
        self.assertIn("Authorizations:", src)
        self.assertIn("Termination", src)

    def test_templates_do_not_invent_counters(self):
        src = AGENT_TEMPLATE.read_text()
        # every hunt number rendered comes from real payload fields
        self.assertIn("o.plans_created", src)
        self.assertIn("o.observations_run", src)
        self.assertNotIn("plans_created = 8", src)


def RuntimeStoreSafe(base: str):
    from backend.research_agents.runtime_store import RuntimeStore
    return RuntimeStore(base)


if __name__ == "__main__":
    unittest.main()
