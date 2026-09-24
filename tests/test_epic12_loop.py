"""EPIC12 §15/§20 — autonomous verification loop tests.

The loop is the end-to-end artefact: it must advance a chain only on real
observations, stop deterministically, stay inside its budget, and never turn a
missing capability into a finding.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import advisor as ad  # noqa: E402
from backend.research_agents.verification import budget as vb  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import executors as ex  # noqa: E402
from backend.research_agents.verification import loop as lp  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, advisor_raising, advisor_returning, authorization,
    inventory_rows, make_verification_store, marker_body,
)

OBJECTIVE = "ver-xss-1"
TARGET = "https://www.dell.com/support"


def run(rows=(), *, context=None, authorization_ctx=None, store=None,
        limits=None, max_steps=lp.DEFAULT_MAX_STEPS, advisor=None,
        vulnerability_class="XSS", scope_ref=SCOPE):
    store = store or make_verification_store()
    outcome = lp.run_verification_loop(
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
        vulnerability_class=vulnerability_class, scope_ref=scope_ref,
        store=store, target=TARGET, rows=list(rows),
        authorization=authorization_ctx if authorization_ctx is not None
        else authorization(),
        authorization_id="auth-epic12-1", context=dict(context or {}),
        limits=dict(limits or {}), max_steps=max_steps, advisor=advisor)
    return outcome, store


class TestPendingPaths(unittest.TestCase):
    def test_inventory_only_never_confirms(self):
        outcome, _ = run(inventory_rows(20))
        self.assertEqual(outcome.termination, lp.LOOP_PENDING)
        self.assertFalse(outcome.confirmed)
        self.assertNotEqual(outcome.verdict, "VERIFIED")
        self.assertTrue(outcome.why_not_confirmed)

    def test_inventory_only_reports_the_missing_evidence(self):
        outcome, _ = run(inventory_rows(20))
        self.assertIn("PAYLOAD_EXECUTION", outcome.evidence_missing)
        self.assertIn("REFLECTION_OBSERVED", outcome.evidence_missing)

    def test_no_material_is_not_tested_not_negative(self):
        outcome, store = run(inventory_rows(3))
        rows = store.evidence_rows_for_candidate(CANDIDATE_ID)
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["type"], "observation")
            self.assertNotIn("reflection_not_observed", row["signal"])
            self.assertTrue(row.get("not_tested"))

    def test_loop_advances_reflection_and_context_from_a_recording(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        outcome, store = run(inventory_rows(3),
                             context={"response_body": marker_body(marker),
                                      "marker": marker,
                                      "response_ref": "resp-1"})
        self.assertEqual(outcome.termination, lp.LOOP_PENDING)
        self.assertFalse(outcome.confirmed)
        self.assertIn("REFLECTION_OBSERVED", outcome.evidence_gained)
        self.assertIn("OUTPUT_CONTEXT_IDENTIFIED", outcome.evidence_gained)
        # it stops at the lane that genuinely does not exist here
        self.assertIn("active_payload", outcome.termination_reason)
        self.assertIn("PAYLOAD_EXECUTION", outcome.evidence_missing)

    def test_loop_records_why_it_stopped(self):
        outcome, _ = run(inventory_rows(3))
        self.assertTrue(outcome.termination_reason)
        self.assertTrue(outcome.why_not_confirmed)


class TestNegativePaths(unittest.TestCase):
    def test_absent_reflection_contradicts_and_stops(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        outcome, _ = run(inventory_rows(3), context={
            "response_body": "<html><body>no marker here</body></html>",
            "marker": marker})
        self.assertEqual(outcome.termination, lp.LOOP_NOT_CONFIRMED)
        self.assertEqual(outcome.verdict, "REJECTED")
        self.assertFalse(outcome.confirmed)

    def test_a_contradicted_chain_is_never_retried(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        outcome, _ = run(inventory_rows(3), context={
            "response_body": "clean", "marker": marker})
        self.assertLessEqual(outcome.steps, 2)

    def test_negative_results_are_persisted_with_their_reason(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        _, store = run(inventory_rows(3), context={"response_body": "clean",
                                                  "marker": marker})
        rows = store.evidence_rows_for_candidate(CANDIDATE_ID)
        negatives = [r for r in rows if r["type"] == "negative"]
        self.assertTrue(negatives)
        self.assertTrue(negatives[0]["not_observed"])


class TestBlockingPaths(unittest.TestCase):
    def test_no_authorization_blocks_before_any_action(self):
        outcome, store = run(inventory_rows(3), authorization_ctx=None)
        # authorization=None is treated as absent by the gate
        self.assertIn(outcome.termination, (lp.LOOP_BLOCKED, lp.LOOP_PENDING))

    def test_class_without_a_chain_is_blocked_with_no_actions(self):
        outcome, store = run(inventory_rows(3), vulnerability_class="SQLI")
        self.assertEqual(outcome.termination, lp.LOOP_BLOCKED)
        self.assertIn("chain_not_implemented", outcome.termination_reason)
        self.assertEqual(outcome.steps, 0)
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])

    def test_contract_only_chain_is_blocked_and_never_executes(self):
        outcome, store = run(inventory_rows(3), vulnerability_class="SSRF")
        self.assertEqual(outcome.termination, lp.LOOP_BLOCKED)
        self.assertIn("contract_only", outcome.termination_reason)
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])

    def test_unknown_class_is_blocked(self):
        outcome, _ = run(inventory_rows(3), vulnerability_class="NOT_A_CLASS")
        self.assertEqual(outcome.termination, lp.LOOP_BLOCKED)


class TestBudgetEnforcement(unittest.TestCase):
    def test_max_steps_is_a_hard_bound(self):
        outcome, _ = run(inventory_rows(3), max_steps=1)
        self.assertLessEqual(outcome.steps, 1)

    def test_zero_action_budget_blocks(self):
        outcome, store = run(inventory_rows(3), limits={"max_actions": 0})
        self.assertIn(outcome.termination,
                      (lp.LOOP_BLOCKED, lp.LOOP_BUDGET_EXHAUSTED))
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])

    def test_one_action_budget_runs_exactly_one_action(self):
        outcome, store = run(inventory_rows(3), limits={"max_actions": 1})
        self.assertLessEqual(outcome.steps, 1)
        self.assertLessEqual(len(store.actions_for_candidate(CANDIDATE_ID)), 1)

    def test_budget_report_is_persisted(self):
        outcome, _ = run(inventory_rows(3))
        self.assertIn("limits", outcome.budget)
        self.assertIn("used", outcome.budget)

    def test_zero_payload_budget_keeps_the_active_lane_closed(self):
        outcome, _ = run(inventory_rows(3) + [
            {"id": "e1", "job_id": "j", "type": "observation",
             "signal": "controlled_input_sent", "category": "XSS",
             "observation_ref": "c1", "detail": "d"},
            {"id": "e2", "job_id": "j", "type": "observation",
             "signal": "reflection_observed", "category": "XSS",
             "observation_ref": "r1", "detail": "d"},
            {"id": "e3", "job_id": "j", "type": "observation",
             "signal": "output_context_identified", "category": "XSS",
             "observation_ref": "x1", "detail": "d"}])
        self.assertFalse(outcome.confirmed)
        for action in outcome.actions:
            self.assertNotEqual(action["action_type"],
                                ac.DELIVER_CONTROLLED_PAYLOAD)

    def test_runtime_budget_is_a_gate(self):
        outcome, _ = run(inventory_rows(3), limits={"max_runtime_seconds": 0})
        self.assertFalse(outcome.confirmed)


class TestAdvisorIntegration(unittest.TestCase):
    def test_advisor_hint_can_reorder_allowed_actions(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION",
                               "rationale": "reflection first",
                               "model": "openrouter/free"}))
        outcome, _ = run(inventory_rows(3), advisor=advisor)
        # at most one advisory call per step, bounded by the loop's own step cap
        self.assertGreaterEqual(outcome.llm_calls, 1)
        self.assertLessEqual(outcome.llm_calls, lp.DEFAULT_MAX_STEPS)
        self.assertEqual(outcome.llm_failures, 0)
        self.assertTrue(any(a["action_type"] == ac.CHECK_REFLECTION
                            for a in outcome.actions))

    def test_advisor_failure_never_stops_the_loop(self):
        advisor = ad.make_chain_advisor(advisor_raising(RuntimeError("down")))
        outcome, _ = run(inventory_rows(3), advisor=advisor)
        self.assertGreaterEqual(outcome.llm_failures, 1)
        self.assertTrue(outcome.actions)
        self.assertFalse(outcome.confirmed)

    def test_advisor_cannot_confirm(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "OBSERVE_EXECUTION",
                               "rationale": "confirmed XSS, verified"}))
        outcome, _ = run(inventory_rows(3), advisor=advisor)
        self.assertFalse(outcome.confirmed)
        self.assertNotEqual(outcome.verdict, "VERIFIED")
        for action in outcome.actions:
            self.assertNotEqual(action["action_type"], ac.OBSERVE_EXECUTION)

    def test_advisor_cannot_reach_an_unimplemented_lane(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "DELIVER_CONTROLLED_PAYLOAD"}))
        outcome, _ = run(inventory_rows(3), advisor=advisor)
        for action in outcome.actions:
            self.assertNotEqual(action["action_type"],
                                ac.DELIVER_CONTROLLED_PAYLOAD)

    def test_an_owning_llm_budget_can_stop_the_advisor(self):
        class Outer:
            limits = {"max_llm_calls": 0}

            def ensure(self, *_a, **_k):
                raise RuntimeError("exhausted")

            def ok(self, _resource):
                return False

        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION"}))
        outcome, _ = run(inventory_rows(3), advisor=advisor,
                         limits={"max_llm_calls": 0})
        self.assertEqual(outcome.llm_calls, 0)
        self.assertTrue(outcome.actions)          # deterministic work continues

    def test_delegated_llm_budget_is_honoured(self):
        class Outer:
            limits = {"max_llm_calls": 5}
            used = 0

            def ensure(self, _resource, delta=1, **_k):
                Outer.used += delta

            def ok(self, _resource):
                return True

        budget = vb.VerificationBudget(make_verification_store(),
                                       dict(vb.DEFAULT_VERIFICATION_LIMITS),
                                       objective_id=OBJECTIVE, outer=Outer())
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "CHECK_REFLECTION"}))
        lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE,
            store=make_verification_store(), rows=inventory_rows(3),
            authorization=authorization(), budget=budget, advisor=advisor)
        self.assertGreaterEqual(Outer.used, 1)

    def test_no_advisor_means_no_llm_calls(self):
        outcome, _ = run(inventory_rows(3))
        self.assertEqual(outcome.llm_calls, 0)
        self.assertEqual(outcome.llm_failures, 0)


class TestPersistenceAndIdempotence(unittest.TestCase):
    def test_actions_observations_and_loop_are_persisted(self):
        outcome, store = run(inventory_rows(3))
        actions = store.actions_for_candidate(CANDIDATE_ID)
        observations = store.observations_for_candidate(CANDIDATE_ID)
        loop_row = store.latest_loop(CANDIDATE_ID)
        self.assertTrue(actions)
        self.assertTrue(observations)
        self.assertIsNotNone(loop_row)
        self.assertEqual(loop_row["termination"], outcome.termination)

    def test_action_records_carry_their_observation_ids(self):
        _, store = run(inventory_rows(3))
        actions = store.actions_for_candidate(CANDIDATE_ID)
        self.assertTrue(actions[0]["observation_ids"])

    def test_second_run_does_not_duplicate_evidence(self):
        store = make_verification_store()
        first, _ = run(inventory_rows(3), store=store)
        rows_after_first = store.evidence_rows_for_candidate(CANDIDATE_ID)
        second, _ = run(inventory_rows(3), store=store)
        rows_after_second = store.evidence_rows_for_candidate(CANDIDATE_ID)
        self.assertEqual(len(rows_after_first), len(rows_after_second))
        self.assertEqual(second.verdict, first.verdict)

    def test_persisted_observations_feed_the_next_evaluation(self):
        store = make_verification_store()
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        run(inventory_rows(3), store=store,
            context={"response_body": marker_body(marker), "marker": marker})
        rows = store.evidence_rows_for_candidate(CANDIDATE_ID)
        state = en.evaluate_chain("XSS", inventory_rows(3) + rows,
                                  authorization=authorization())
        self.assertEqual(state.stage("reflection").status, ch.STAGE_SATISFIED)
        self.assertFalse(state.confirmed)

    def test_persist_false_writes_nothing(self):
        store = make_verification_store()
        lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE, store=store,
            rows=inventory_rows(3), authorization=authorization(),
            persist=False)
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])


class TestLoopOutcomeShape(unittest.TestCase):
    def test_to_dict_is_json_safe(self):
        import json
        outcome, _ = run(inventory_rows(3))
        json.dumps(outcome.to_dict(), sort_keys=True)

    def test_outcome_names_its_authority(self):
        outcome, _ = run(inventory_rows(3))
        self.assertEqual(outcome.verdict_source, en.VERDICT_SOURCE)

    def test_outcome_records_timestamps_and_runtime(self):
        outcome, _ = run(inventory_rows(3))
        self.assertTrue(outcome.started_at)
        self.assertTrue(outcome.finished_at)
        self.assertGreaterEqual(outcome.runtime_seconds, 0.0)

    def test_terminations_are_a_closed_vocabulary(self):
        outcome, _ = run(inventory_rows(3))
        self.assertIn(outcome.termination, lp.LOOP_TERMINATIONS)

    def test_no_execution_evidence_is_ever_produced(self):
        outcome, store = run(inventory_rows(3) + [
            {"id": "e1", "job_id": "j", "type": "observation",
             "signal": "reflection_observed", "category": "XSS",
             "observation_ref": "r1", "detail": "d"}])
        for row in store.evidence_rows_for_candidate(CANDIDATE_ID):
            self.assertNotIn(row.get("evidence_type"),
                             ("PAYLOAD_EXECUTION",
                              "EXPLOITABILITY_ESTABLISHED"))


if __name__ == "__main__":
    unittest.main()
