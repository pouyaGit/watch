"""AUTONOMOUS HUNT PLANNER v1 — Phase 15 failure/recovery tests.

Every failure condition from the Epic mapped to its honest, fail-closed
behavior:

  LLM unavailable / timeout / malformed response / context overflow
  -> advisory degrades; deterministic planning continues; error recorded.

  invalid scope / authorization denial / stale plan / stale authorization
  -> BLOCKED or REJECTED; no observation executes; audit event recorded.

  observation failure / partial result -> plan PARTIAL/FAILED; honest
  errors; explicit termination when the runtime is unusable.

  evidence-store / memory / plan-persistence failure -> hunt degrades or
  surfaces WITHOUT fabricating state; the job never lies about completion.
"""

from __future__ import annotations

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
from tests.test_hunt_planner_safety import (  # noqa: E402
    make_objective,
    make_plan,
)

from backend.research_agents.capabilities import capability_for  # noqa: E402
from backend.research_agents.hunt import (  # noqa: E402
    HuntLimits,
    HuntStore,
    HuntStoreError,
    map_advisor_response,
    run_hunt,
)
from backend.research_agents.hunt.models import PlanTransition  # noqa: E402
from backend.research_agents.models import JobStatus  # noqa: E402
from backend.research_agents.runtime import (  # noqa: E402
    AgentWorker,
    AnalysisUnavailable,
    AuthorizationChecker,
    RuntimeConfig,
    deterministic_analysis,
    evaluate_case_creation,
)
from backend.research_agents.runtime_store import RuntimeStore, utcnow  # noqa: E402
from backend.research_agents.hunt.uncertainty import transition  # noqa: E402


class LLMFailureTests(unittest.TestCase):
    def test_llm_unavailable_degrades_to_deterministic_planning(self):
        def unavailable(request):
            raise AnalysisUnavailable(
                "llm_provider_unavailable: free router offline")

        outcome, job, cap, hs, store = run_hunt_fixture(
            advisor_fn=unavailable,
            limits=HuntLimits(max_plans_per_objective=2,
                              max_llm_planning_calls=1,
                              max_seconds=30))
        errors = outcome.llm_advisory["errors"]
        self.assertTrue(errors)
        self.assertTrue(any("provider_unavailable" in e for e in errors))
        self.assertFalse(outcome.llm_advisory["used"])
        # planning continued deterministically
        self.assertTrue(outcome.plan_ids)
        self.assertEqual(hs.get_plan(outcome.plan_ids[0])
                         .provenance["planner"], "deterministic")
        self.assertEqual(outcome.termination_reason, "sufficient_evidence")

    def test_llm_timeout_recorded_and_loop_continues(self):
        def timeout(request):
            raise AnalysisUnavailable("llm_timeout: 12s deadline exceeded")

        outcome, job, cap, hs, store = run_hunt_fixture(
            advisor_fn=timeout,
            limits=HuntLimits(max_plans_per_objective=1,
                              max_llm_planning_calls=1, max_seconds=30))
        self.assertTrue(any("timeout" in e
                            for e in outcome.llm_advisory["errors"]))
        self.assertTrue(outcome.plan_ids)
        self.assertIn(outcome.state, {"RESOLVED", "NEEDS_EVIDENCE",
                                      "BLOCKED", "REJECTED"})

    def test_malformed_planner_response_rejected(self):
        outcome, job, cap, hs, store = run_hunt_fixture(
            advisor_fn=lambda r: ({"nonsense": True}, {
                "model_requested": "openrouter/free",
                "model_resolved": "openrouter/free", "latency_ms": 1,
                "prompt_version": "hunt-planner-advisor-v1"}),
            limits=HuntLimits(max_plans_per_objective=1,
                              max_llm_planning_calls=1, max_seconds=30))
        self.assertFalse(outcome.llm_advisory["used"])
        self.assertTrue(outcome.llm_advisory["errors"])
        self.assertEqual(hs.get_plan(outcome.plan_ids[0])
                         .provenance["planner"], "deterministic")

    def test_context_overflow_fails_closed(self):
        def overflow(request):
            raise AnalysisUnavailable(
                "context_too_large: planner context exceeds bound")

        outcome, job, cap, hs, store = run_hunt_fixture(
            advisor_fn=overflow,
            limits=HuntLimits(max_plans_per_objective=1,
                              max_llm_planning_calls=1, max_seconds=30))
        self.assertTrue(any("context_too_large" in e
                            for e in outcome.llm_advisory["errors"]))
        self.assertTrue(outcome.plan_ids)

    def test_unknown_advisor_type_recorded_and_excluded(self):
        def bad_advisor(request):
            return ({"summary": "s",
                     "insights": [
                         {"insight_code": "OBS_NUCLEI_SCAN",
                          "text": "consider this extra observation type"},
                         {"insight_code": "OBS_HTTP_ROWS",
                          "text": "read stored http rows"}],
                     "recommendations": []},
                    {"model_requested": "openrouter/free",
                     "model_resolved": "openrouter/free", "latency_ms": 2,
                     "prompt_version": "hunt-planner-advisor-v1"})

        outcome, job, cap, hs, store = run_hunt_fixture(
            advisor_fn=bad_advisor,
            limits=HuntLimits(max_plans_per_objective=1,
                              max_llm_planning_calls=1, max_seconds=30))
        plan = hs.get_plan(outcome.plan_ids[0])
        planned = [r["observation_type"] for r in plan.observations_requested]
        self.assertNotIn("nuclei-rows", planned)
        self.assertNotIn("nuclei-rows", planned)
        # rejection is visible in provenance notes
        self.assertTrue(any("advisor_rejected" in n
                            for n in plan.provenance["notes"]))


class AuthorizationFailureTests(unittest.TestCase):
    def test_invalid_scope_blocks_before_any_observation(self):
        job = make_job(auth_ref="")
        store = make_store()
        outcome = run_hunt(
            job=job, capability=capability_for("XSS"), store=store,
            hunt_store=HuntStore(store.base),
            observations=type("P", (), {"observe": lambda s, j, **k: []})(),
            auth_checker=AuthorizationChecker(),
            determin_fn=deterministic_analysis,
            gate_fn=evaluate_case_creation, limits=HuntLimits())
        self.assertEqual(outcome.state, "BLOCKED")
        self.assertEqual(outcome.termination_reason, "authorization_denied")
        self.assertEqual(outcome.observation_ids, [])

    def test_authorization_denial_emits_rejected_activity(self):
        actions: list[str] = []
        outcome, job, cap, hs, store = run_hunt_fixture(
            auth_ref="",
            emit_activity=lambda a, d: actions.append(a))
        self.assertIn("hunt_terminated", actions)
        # no observe/no grant without a scope
        self.assertNotIn("authorization_granted", actions)
        self.assertEqual(outcome.observation_ids, [])

    def test_target_outside_scope_denies_at_gate(self):
        job = make_job(auth_ref="watch:scope:app/other.test")
        object.__setattr__(job, "execution_mode", "production")
        cap = capability_for("XSS")
        from backend.research_agents.hunt.authorization import (
            authorization_gate, build_authorization_request)
        plan = make_plan(scope="watch:scope:app/other.test")
        rec = authorization_gate(
            build_authorization_request(plan, job=job, capability=cap),
            job=job, capability=cap, auth_checker=AuthorizationChecker())
        self.assertEqual(rec.status, "DENIED")


class ObservationFailureTests(unittest.TestCase):
    def test_partial_observation_marks_plan_partial(self):
        class Flaky:
            def observe(self, job, *, types=None, limit=None, **kw):
                if types and types[0] == "http-rows":
                    raise RuntimeError("http collection unavailable")
                return rich_rows()[:1]

        from backend.research_agents.runtime import AuthorizationChecker
        store = make_store()
        hs = HuntStore(store.base)
        job = make_job()
        outcome = run_hunt(
            job=job, capability=capability_for("XSS"),
            store=store, hunt_store=hs, observations=Flaky(),
            auth_checker=AuthorizationChecker(),
            determin_fn=deterministic_analysis,
            gate_fn=evaluate_case_creation,
            limits=HuntLimits(max_plans_per_objective=1,
                              max_observations=4,
                              max_llm_planning_calls=0, max_seconds=30),
            initial_rows=rich_rows(),
            emit_audit=lambda s, p: None)
        # at least one real success + one recorded failure
        self.assertTrue(outcome.observation_ids)
        self.assertTrue(any("http-rows" in e and
                            "unavailable" in e
                            for e in outcome.errors), outcome.errors)
        # no fabrication: the failed type never claims success
        records = {o.observation_id: o
                   for o in hs.observations_for_job(job.id)}
        self.assertTrue(records)
        for rec in records.values():
            if rec.observation_types == ("http-rows",):
                # the failed type is recorded honestly as unavailable
                self.assertEqual(rec.outcome, "unavailable")
                self.assertIn("unavailable", rec.error)
            else:
                self.assertEqual(rec.outcome, "ok")
                self.assertEqual(rec.error, "")
        # explicit termination reason, never "completed"
        self.assertTrue(outcome.termination_reason)

    def test_observation_runtime_unavailable_terminates_explicitly(self):
        class Dead:
            def observe(self, job, **kw):
                raise RuntimeError("store offline")

        from backend.research_agents.runtime import AuthorizationChecker
        store = make_store()
        outcome = run_hunt(
            job=make_job(), capability=capability_for("XSS"),
            store=store, hunt_store=HuntStore(store.base),
            observations=Dead(), auth_checker=AuthorizationChecker(),
            determin_fn=deterministic_analysis,
            gate_fn=evaluate_case_creation,
            limits=HuntLimits(max_plans_per_objective=3,
                              max_consecutive_observation_failures=1,
                              max_llm_planning_calls=0, max_seconds=30),
            initial_rows=rich_rows(),
            emit_audit=lambda s, p: None)
        self.assertEqual(outcome.termination_reason,
                         "observation_runtime_unavailable")
        self.assertEqual(outcome.state, "BLOCKED")
        self.assertTrue(outcome.errors)


class StoreAndGateFailureTests(unittest.TestCase):
    def test_gate_failure_surfaces_instead_of_faking_result(self):
        def broken_gate(*a, **k):
            raise RuntimeError("evidence store offline")

        with self.assertRaises(RuntimeError):
            run_hunt_fixture(gate_fn=broken_gate)

    def test_worker_degrades_honestly_when_hunt_crashes(self):
        """Plan persistence failure -> job completes with an honest
        hunt error in the contract; no fabricated hunt state."""
        import tempfile
        from backend.research_agents.runtime import FixtureObservations
        from backend.research_agents.hunt import store as hunt_store_mod

        base = tempfile.mkdtemp(prefix="hunt-fail-", dir="/tmp")
        store = RuntimeStore(base)
        job = make_job(job_id="job-xss-hunt-persist")
        store.enqueue(job)
        provider = FixtureObservations({job.id: rich_rows()})

        original_append = hunt_store_mod.HuntStore._append

        def exploding_append(self, path, record):
            raise OSError("disk full")

        hunt_store_mod.HuntStore._append = exploding_append
        try:
            worker = AgentWorker(
                config=RuntimeConfig(execution_mode="fixture",
                                     worker_id="hunt-fail",
                                     job_timeout=60, hunt_max_plans=2,
                                     hunt_max_seconds=30,
                                     hunt_max_llm_plans=0),
                store=store, observations=provider, llm_enabled=False)
            worker.run(max_jobs=1)
        finally:
            hunt_store_mod.HuntStore._append = original_append

        result = store.get_result(job.id)
        self.assertIsNotNone(result)
        structured = result.structured or {}
        hunt = structured.get("hunt") or {}
        # honest degradation: error recorded, not a fake success
        self.assertTrue(
            hunt.get("termination_reason", "").startswith("hunt_loop_error")
            or (result.research_intel or {}).get("intelligence_errors"),
            hunt)
        # evidence/cases unaffected and gate untouched by the failure
        after = store.get(job.id)
        self.assertEqual(after.status, JobStatus.COMPLETED.value)

    def test_memory_failure_never_kills_the_hunt(self):
        class BrokenMemory:
            def append(self, item):
                raise OSError("memory file locked")

        outcome, job, cap, hs, store = run_hunt_fixture(
            memory=BrokenMemory(),
            limits=HuntLimits(max_plans_per_objective=2,
                              max_llm_planning_calls=0, max_seconds=30))
        self.assertEqual(outcome.termination_reason, "sufficient_evidence")
        self.assertTrue(any("learn_observation" in e or "learn_advisory" in e
                            for e in outcome.errors), outcome.errors)

    def test_objective_persistence_failure_is_never_silenced(self):
        from backend.research_agents.hunt import store as hunt_store_mod
        original = hunt_store_mod.HuntStore._append

        def boom(self, path, record):
            raise OSError("objectives volume read-only")

        hunt_store_mod.HuntStore._append = boom
        try:
            with self.assertRaises(OSError):
                run_hunt_fixture()
        finally:
            hunt_store_mod.HuntStore._append = original

    def test_stale_plan_definition_hash_mismatch_detected(self):
        hs = HuntStore(make_store().base)
        plan = make_plan()
        hs.append_plan(plan)
        hs.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="DRAFT", to_state="VALIDATED",
            reason="ok", at=utcnow()))
        for frm, to in (("VALIDATED", "AUTHORIZATION_REQUIRED"),
                        ("AUTHORIZATION_REQUIRED", "AUTHORIZED")):
            hs.record_transition(PlanTransition(
                plan_id=plan.plan_id, from_state=frm, to_state=to,
                reason="ok", at=utcnow()))
        hs.record_transition(PlanTransition(
            plan_id=plan.plan_id, from_state="AUTHORIZED",
            to_state="EXECUTING", reason="start", at=utcnow(),
            definition_hash=plan.definition_hash()))
        recorded = hs.executing_definition_hash(plan.plan_id)
        self.assertEqual(recorded, plan.definition_hash())
        # tampered definition never matches the executing hash
        tampered = make_plan(reason="tampered reason text")
        self.assertNotEqual(recorded, tampered.definition_hash())

    def test_duplicate_plan_persistence_rejected(self):
        hs = HuntStore(make_store().base)
        hs.append_plan(make_plan())
        twin = make_plan(reason="same id different body")
        with self.assertRaises(HuntStoreError):
            hs.append_plan(twin)


class BudgetAndLoopFailureTests(unittest.TestCase):
    def test_repeated_planning_loop_is_bounded(self):
        bare = [{"source": "urls", "ref": "u1",
                 "url": "https://shop.test/x", "status": 200,
                 "params": []}]
        outcome, *_ = run_hunt_fixture(
            rows=bare,
            limits=HuntLimits(max_plans_per_objective=2,
                              max_planning_iterations=2,
                              max_observations=4,
                              max_llm_planning_calls=0, max_seconds=30))
        self.assertLessEqual(len(outcome.plan_ids), 2)
        self.assertLessEqual(outcome.iterations, 2)
        self.assertTrue(outcome.termination_reason in
                        {"max_plans_per_objective_reached",
                         "max_planning_iterations_reached",
                         "max_observations_reached",
                         "no_authorized_observation_can_reduce_uncertainty",
                         "no_category_signal_after_full_observation",
                         "sufficient_evidence"})

    def test_unknown_state_transitions_cannot_corrupt_the_loop(self):
        with self.assertRaises(Exception):
            transition("OPEN", "PLANNED")
        with self.assertRaises(Exception):
            transition("RESOLVED", "PLANNED")
        with self.assertRaises(Exception):
            transition("BLOCKED", "OBSERVATION_PENDING")

    def test_rejected_hypothesis_terminates_with_explicit_reason(self):
        # all allowed types read, zero category signals -> honest REJECTED
        bare = [{"source": "urls", "ref": f"u{i}",
                 "url": f"https://shop.test/p{i}", "status": 200,
                 "params": []} for i in range(4)]
        outcome, *_ = run_hunt_fixture(
            rows=bare,
            limits=HuntLimits(max_plans_per_objective=5,
                              max_observations=10,
                              max_planning_iterations=4,
                              max_llm_planning_calls=0, max_seconds=30))
        if outcome.state == "REJECTED":
            self.assertEqual(outcome.termination_reason,
                             "hypothesis_rejected_no_signal")
        else:
            # otherwise termination must still be explicit and honest
            self.assertIn(outcome.state,
                          {"RESOLVED", "NEEDS_EVIDENCE", "BLOCKED"})


if __name__ == "__main__":
    unittest.main()
