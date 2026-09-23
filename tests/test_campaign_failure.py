"""AUTONOMOUS SECURITY CAMPAIGN ORCHESTRATOR v1 — failure/recovery tests.

Phase 16: LLM failures, invalid recommendations, dependency failures,
budget exhaustion, stale/duplicate coordinators, observation and hunt
failures, memory and persistence failures, resume after interruption,
and partial objective completion — every path must land in an honest
state with no fake completion, no lost budget, no duplicate execution,
and no unauthorized observation.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from tests.campaign_fixtures import (  # noqa: E402
    add_obj,
    advisor_malformed,
    advisor_raises,
    advisor_valid,
    make_campaign,
    make_dependency,
    make_stores,
    put_job_result,
    run_campaign,
)
from backend.research_agents.campaign import (  # noqa: E402
    CampaignStateError,
    CampaignStoreError,
    execute_campaign,
)


class _BrokenMemory:
    """Memory backend that fails every append (Phase 16 memory failure)."""

    def append(self, _items):
        raise IOError("memory store unavailable")

    def query(self, **_kw):
        return []

    def heads(self):
        raise IOError("memory store unavailable")


class TestAdvisorFailures(unittest.TestCase):
    """LLM unavailable / timeout / malformed / invalid recommendations."""

    def _one_objective(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        return store, cs, camp, obj

    def test_llm_unavailable_continues_deterministically(self):
        store, cs, camp, obj = self._one_objective()
        summ, _ = run_campaign(
            camp.campaign_id, cs, store,
            advisor_fn=advisor_raises(
                ConnectionError("provider unavailable")))
        self.assertEqual(len(summ.advisor_outcomes), 1)
        out = summ.advisor_outcomes[0]
        self.assertFalse(out["used"])
        self.assertIn("advisor_unavailable", out["error"])
        # deterministic path still executed exactly one objective
        self.assertEqual(summ.selected[0]["objective_id"],
                         obj.objective_id)
        self.assertEqual(len(store.list_jobs()), 1)
        self.assertTrue(summ.ok, summ.reason)

    def test_llm_timeout_continues_deterministically(self):
        store, cs, camp, _ = self._one_objective()
        summ, _ = run_campaign(
            camp.campaign_id, cs, store,
            advisor_fn=advisor_raises(TimeoutError("llm_timeout")))
        out = summ.advisor_outcomes[0]
        self.assertFalse(out["used"])
        self.assertIn("advisor_unavailable", out["error"])
        self.assertEqual(len(summ.selected), 1)

    def test_malformed_advisor_response_rejected(self):
        store, cs, camp, obj = self._one_objective()
        summ, _ = run_campaign(
            camp.campaign_id, cs, store,
            advisor_fn=advisor_malformed({"summary": "only-a-summary"}))
        out = summ.advisor_outcomes[0]
        self.assertFalse(out["used"])
        self.assertTrue(out["error"].startswith("malformed"), out)
        self.assertEqual(summ.selected[0]["objective_id"],
                         obj.objective_id)

    def test_invalid_recommendation_rejected_deterministic_kept(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        ready = add_obj(cs, camp, priority=70)
        dep_obj = add_obj(cs, camp, priority=99,
                          question="prereq question",
                          hypothesis="prereq hypothesis")
        from backend.research_agents.campaign.models import (
            CampaignObjective,
            new_id,
        )
        w_id = new_id("obj")
        waiting = CampaignObjective(
            objective_id=w_id, campaign_id=camp.campaign_id,
            category="CVE_RESEARCH", scope_ref=camp.scope_ref,
            research_question="depends on prereq",
            hypothesis="h", priority=99, state="QUEUED",
            dependencies=[make_dependency(w_id, dep_obj.objective_id)])
        cs.add_objective(waiting, camp)
        # advisor recommends the WAITING (non-executable) objective
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               advisor_fn=advisor_valid(
                                   waiting.objective_id))
        out = summ.advisor_outcomes[0]
        self.assertFalse(out["used"], out)
        self.assertIn("invalid_recommendation", out["error"])
        self.assertTrue(out["rejected"], out)
        # deterministic head (dep_obj, priority 99) executed instead
        self.assertEqual(summ.selected[0]["objective_id"],
                         dep_obj.objective_id)

    def test_specialist_unavailable_blocks_honestly(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90, category="NO_SUCH_SKILL")
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=2)
        self.assertEqual(summ.state, "BLOCKED")
        self.assertEqual(len(store.list_jobs()), 0)
        self.assertEqual(cs.get_objective(obj.objective_id).state,
                         "BLOCKED")

    def test_llm_budget_exhaustion_disables_advisor_not_the_campaign(
            self):
        store, cs = make_stores()
        camp = make_campaign(cs, limits={"max_llm_calls": 1})
        add_obj(cs, camp, priority=90)
        add_obj(cs, camp, priority=80, question="second question",
                hypothesis="second hypothesis")
        s1, _ = run_campaign(camp.campaign_id, cs, store,
                             max_objectives=1,
                             advisor_fn=advisor_valid("obj-unused"))
        # run 1 parks WAITING (objective 2 remains) and consumes the
        # one allowed LLM call (the rejected advisory still called out).
        self.assertEqual(s1.state, "WAITING", s1.state)
        s2, _ = run_campaign(camp.campaign_id, cs, store,
                             max_objectives=1,
                             advisor_fn=advisor_valid("obj-unused2"))
        # the advisory layer is skipped honestly (budget) ...
        self.assertTrue(s2.advisor_outcomes, s2.advisor_outcomes)
        out = s2.advisor_outcomes[0]
        self.assertFalse(out["used"], out)
        self.assertTrue("budget" in out["error"]
                        or "advisor" in out["error"], out)
        # ... but the deterministic objective STILL executed (llm budget
        # bounds LLM calls only; it must not fake a stop either)
        self.assertEqual(len(s2.selected), 1, s2)
        self.assertNotEqual(s2.state, "BUDGET_EXHAUSTED")


class TestDependencyFailures(unittest.TestCase):
    def test_failed_prereq_permanently_blocks_dependent(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        prereq = add_obj(cs, camp, priority=99)
        from backend.research_agents.campaign.models import (
            CampaignObjective,
            new_id,
        )
        d_id = new_id("obj")
        dep = CampaignObjective(
            objective_id=d_id, campaign_id=camp.campaign_id,
            category="CVE_RESEARCH", scope_ref=camp.scope_ref,
            research_question="needs prereq", hypothesis="h",
            priority=50, state="QUEUED",
            dependencies=[make_dependency(d_id, prereq.objective_id)])
        cs.add_objective(dep, camp)
        # prereq job fails outright
        run_campaign(camp.campaign_id, cs, store, max_objectives=1,
                     outcome="failed")
        self.assertEqual(
            cs.get_objective(prereq.objective_id).state, "FAILED")
        # dependent can never execute after a FAILED required prereq
        s2, _ = run_campaign(camp.campaign_id, cs, store,
                             max_objectives=2, outcome="failed")
        self.assertEqual(
            cs.get_objective(dep.objective_id).state, "BLOCKED")
        self.assertEqual(s2.selected, [])
        self.assertEqual(len(store.list_jobs()), 1)
        final = cs.get_campaign(camp.campaign_id)
        # never COMPLETED; the surviving objective is BLOCKED behind a
        # FAILED prereq -> campaign reports BLOCKED, honestly.
        self.assertNotEqual(final.state, "COMPLETED")
        self.assertEqual(final.state, "BLOCKED")
        self.assertTrue(final.termination_reason, final.termination_reason)

    def test_budget_exhaustion_after_first_objective(self):
        store, cs = make_stores()
        camp = make_campaign(cs, limits={"max_hunt_plans": 2,
                                         "max_observations": 2})
        first = add_obj(cs, camp, priority=90)
        second = add_obj(cs, camp, priority=80)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=2,
                               outcome="completed_case")
        self.assertEqual(summ.state, "BUDGET_EXHAUSTED")
        self.assertTrue(summ.termination_reason, summ.termination_reason)
        jobs = store.list_jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(summ.selected[0]["objective_id"],
                         first.objective_id)
        self.assertIn(cs.get_objective(second.objective_id).state,
                      ("QUEUED", "READY"))
        # no lost accounting: ledger holds before/after rows
        ledger = cs.budget_ledger(camp.campaign_id)
        self.assertTrue([r for r in ledger
                         if r["resource"] == "hunt_plans"], ledger)
        final = cs.get_campaign(camp.campaign_id)
        record = final.termination_record or {}
        self.assertTrue(record)
        self.assertTrue(record.get("remaining_objectives")
                        or record.get("budget_state"), record)


class TestCoordinatorFailures(unittest.TestCase):
    def test_duplicate_coordinator_second_run_refused(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        # first coordinator already holds a fresh lease
        self.assertTrue(cs.claim_lease(camp.campaign_id, "coord-1",
                                       ttl_seconds=3600))
        summ, _ = run_campaign(camp.campaign_id, cs, store)
        self.assertFalse(summ.ok)
        self.assertTrue(summ.reason.startswith("lease_refused"),
                        summ.reason)
        # an audit row exists proving the refusal was recorded
        events = store.audit_events(limit=50)
        names = [e.get("event") for e in events]
        self.assertIn("campaign_lease_refused", names)
        self.assertEqual(len(store.list_jobs()), 0)

    def test_stale_lease_from_crashed_coordinator_reclaimed(self):
        from datetime import datetime, timedelta, timezone
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        past = (datetime.now(timezone.utc) -
                timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cs.claim_lease(camp.campaign_id, "dead-coord",
                       ttl_seconds=1, now=past)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_case")
        self.assertTrue(summ.ok, summ.reason)
        self.assertEqual(len(store.list_jobs()), 1)


class TestExecutionFailures(unittest.TestCase):
    def test_observation_failure_maps_to_failed_honestly(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1, outcome="failed")
        stored = cs.get_objective(obj.objective_id)
        self.assertEqual(stored.state, "FAILED")
        self.assertTrue(stored.termination_reason, stored)
        jobs = store.list_jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].status, "TERMINAL_FAILED")
        # single-objective campaign with a FAILED objective must not
        # claim COMPLETED
        final = cs.get_campaign(camp.campaign_id)
        self.assertNotEqual(final.state, "COMPLETED")

    def test_hunt_planner_missing_falls_back_to_gate_truth(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_no_hunt")
        self.assertEqual(summ.selected[0]["state"], "REJECTED")
        stored = cs.get_objective(obj.objective_id)
        self.assertEqual(stored.state, "REJECTED")
        self.assertTrue(stored.termination_detail, stored)
        final = cs.get_campaign(camp.campaign_id)
        # all objectives terminal (rejected) -> honest COMPLETED reason
        self.assertEqual(final.state, "COMPLETED")
        self.assertIn("rejected=1", final.termination_reason)

    def test_gate_failure_is_rejected_not_resolved(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store,
                     outcome="completed_no_case")
        stored = cs.get_objective(obj.objective_id)
        self.assertEqual(stored.state, "REJECTED")
        self.assertIn("insufficient_evidence",
                      stored.termination_reason)

    def test_memory_failure_is_recorded_nonfatal(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_case",
                               memory_store=_BrokenMemory())
        # objective still reaches its honest terminal state
        self.assertEqual(cs.get_objective(obj.objective_id).state,
                         "RESOLVED")
        # the memory failure is VISIBLE, not swallowed
        mem_errors = [e for e in summ.errors if e.startswith("memory:")]
        self.assertTrue(mem_errors, summ.errors)
        events = [e.get("event")
                  for e in store.audit_events(limit=50)]
        self.assertIn("campaign_memory_failed", events)
        # and no fake VERIFIED memory was written by the campaign
        # (the broken backend wrote nothing at all)
        from tests.campaign_fixtures import read_memory_rows
        camp_rows = [
            r for r in read_memory_rows(store.base)
            if str((r.get("provenance") or {}).get("source", ""))
            .startswith(f"campaign:{camp.campaign_id}")]
        self.assertEqual(camp_rows, [])

    def test_persistence_failure_fails_loudly(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        add_obj(cs, camp, priority=90)
        # corrupt the campaign file entirely (external writer damage)
        path = Path(store.base) / "campaigns.jsonl"
        path.write_text("{this is not valid json\n", encoding="utf-8")
        try:
            summ = execute_campaign(camp.campaign_id, store=store,
                                    campaign_store=cs,
                                    max_objectives=1)
        except CampaignStoreError:
            pass            # fail-closed exception IS an honest state
        else:
            self.assertFalse(summ.ok, summ)
            self.assertTrue(summ.reason, summ.reason)
            self.assertEqual(len(store.list_jobs()), 0)
        # either way: zero jobs ran, nothing was fabricated
        self.assertEqual(len(store.list_jobs()), 0)

    def test_resume_after_interruption_completes_without_duplicates(
            self):
        from tests.campaign_fixtures import append_raw_objective
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        # run 1: coordinator interrupted while the job was running
        s1, _ = run_campaign(camp.campaign_id, cs, store,
                             outcome="leave_queued")
        self.assertEqual(len(store.list_jobs()), 1)
        job_id = s1.selected[0]["job_id"]
        # simulate crash AFTER the job completed but BEFORE mapping:
        # manually complete the job, then leave the objective RUNNING
        job = store.get(job_id)
        put_job_result(store, job, "completed_case")
        # objective stays WAITING as parked: the recovered coordinator's
        # own refresh/selection path must advance it (no manual states).
        # run 2 (recovered coordinator): maps the existing completed job
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               outcome="completed_no_case")
        self.assertEqual(len(store.list_jobs()), 1,
                         "recovery must not duplicate the job")
        self.assertEqual(
            cs.get_objective(obj.objective_id).state, "RESOLVED")
        self.assertTrue(summ.ok, summ.reason)

    def test_partial_objective_completion_not_counted_as_done(self):
        store, cs = make_stores()
        camp = make_campaign(cs)
        obj = add_obj(cs, camp, priority=90)
        summ, _ = run_campaign(camp.campaign_id, cs, store,
                               max_objectives=1,
                               outcome="leave_queued")
        # the job did not finish: objective must be parked, not claimed
        # done, and the campaign is WAITING (resumable), not COMPLETED
        stored = cs.get_objective(obj.objective_id)
        self.assertNotIn(stored.state, ("RESOLVED", "REJECTED"))
        self.assertEqual(summ.state, "WAITING")
        final = cs.get_campaign(camp.campaign_id)
        self.assertFalse(final.is_terminal or
                         final.state == "COMPLETED")


if __name__ == "__main__":
    unittest.main()
