"""EPIC12 §16/§21 — the mandatory regression on the REAL candidate.

``cand-7c229c48c455`` (scope ``watch:scope:dell/www.dell.com``, endpoint
``https://www.dell.com/support``) carries parameter-inventory evidence only.
Under EPIC12 it must stay NOT CONFIRMED / VERIFICATION_PENDING, with the exact
missing evidence recorded — and it must be impossible to promote it by
duplicating, relabelling or re-running anything.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import loop as lp  # noqa: E402
from backend.research_agents.verification import planner as pl  # noqa: E402
from backend.research_agents.verification import projection as pj  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, SOURCE_JOB, TARGET, VERIFY_JOB, authorization,
    inventory_rows, make_verification_store, negative_row, row,
)

OBJECTIVE = "ver-cand-7c229c48c455"


def real_rows():
    """The real evidence shape: 20 parameter-inventory observations."""
    return inventory_rows(20)


class TestRealCandidateStaysUnconfirmed(unittest.TestCase):
    def test_verdict_is_pending(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        self.assertEqual(state.verdict, "VERIFICATION_PENDING")
        self.assertFalse(state.confirmed)

    def test_only_the_parameter_stage_is_satisfied(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        self.assertEqual(state.stage("parameter").status, ch.STAGE_SATISFIED)
        for key in ("reflection", "context", "execution", "exploitability"):
            self.assertEqual(state.stage(key).status, ch.STAGE_MISSING, key)

    def test_missing_evidence_names_the_confirmation_types(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        joined = " ".join(state.why_not_confirmed)
        self.assertIn("REFLECTION_OBSERVED", joined)
        self.assertIn("PAYLOAD_EXECUTION", joined)

    def test_no_divergence_and_no_inadmissible_rows(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        self.assertEqual(state.divergence, ())
        self.assertEqual(state.inadmissible_row_count, 0)

    def test_badge_is_never_green(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        badge = pj.badge_for(state)
        self.assertEqual(badge["state"], pj.BADGE_PENDING)
        self.assertFalse(badge["optimistic"])
        self.assertIn("not confirmed", badge["label"].lower())

    def test_planner_wants_the_reflection_stage_next(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        decision = pl.plan_next_action(
            state, candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            scope_ref=SCOPE, target=TARGET, authorization_id="auth-1")
        self.assertTrue(decision.has_plan)
        self.assertEqual(decision.plan.stage_key, "reflection")
        self.assertEqual(decision.plan.action_type, ac.CHECK_REFLECTION)

    def test_the_real_evidence_maps_to_parameter_observed(self):
        from backend.research_agents.finding.integrity import taxonomy as tx
        items = tx.classify_rows(real_rows())
        types = {i.evidence_type for i in tx.unique_items(items)}
        self.assertEqual(types, {tx.PARAMETER_OBSERVED})


class TestRealCandidateUnderTheLoop(unittest.TestCase):
    def test_loop_never_confirms_it(self):
        store = make_verification_store()
        outcome = lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE, store=store,
            target=TARGET, rows=real_rows(), authorization=authorization(),
            authorization_id="auth-1", context={"job_id": VERIFY_JOB})
        self.assertFalse(outcome.confirmed)
        self.assertNotEqual(outcome.verdict, "VERIFIED")
        self.assertIn(outcome.termination, (lp.LOOP_PENDING, lp.LOOP_BLOCKED,
                                           lp.LOOP_BUDGET_EXHAUSTED))

    def test_loop_produces_no_confirmation_evidence(self):
        store = make_verification_store()
        lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE, store=store,
            target=TARGET, rows=real_rows(), authorization=authorization(),
            authorization_id="auth-1", context={"job_id": VERIFY_JOB})
        for evidence_row in store.evidence_rows_for_candidate(CANDIDATE_ID):
            self.assertNotIn(evidence_row.get("evidence_type"),
                             ("PAYLOAD_EXECUTION",
                              "EXPLOITABILITY_ESTABLISHED"))
            self.assertNotIn(evidence_row.get("evidence_type"),
                             ("REFLECTION_OBSERVED",
                              "OUTPUT_CONTEXT_IDENTIFIED",
                              "DOM_SINK_IDENTIFIED"))

    def test_loop_never_runs_a_payload_action(self):
        store = make_verification_store()
        outcome = lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE, store=store,
            target=TARGET, rows=real_rows(), authorization=authorization(),
            authorization_id="auth-1", context={"job_id": VERIFY_JOB})
        for action in outcome.actions:
            self.assertNotIn(action["action_type"],
                             (ac.DELIVER_CONTROLLED_PAYLOAD,
                              ac.OBSERVE_EXECUTION))

    def test_repeated_runs_never_drift_towards_confirmation(self):
        store = make_verification_store()
        verdicts = set()
        for _ in range(3):
            outcome = lp.run_verification_loop(
                candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
                vulnerability_class="XSS", scope_ref=SCOPE, store=store,
                target=TARGET, rows=real_rows(), authorization=authorization(),
                authorization_id="auth-1", context={"job_id": VERIFY_JOB})
            verdicts.add(outcome.verdict)
        self.assertEqual(verdicts, {"VERIFICATION_PENDING"})

    def test_projection_after_the_loop_is_still_not_confirmed(self):
        store = make_verification_store()
        lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE, store=store,
            target=TARGET, rows=real_rows(), authorization=authorization(),
            authorization_id="auth-1", context={"job_id": VERIFY_JOB})
        blob = pj.chain_projection_for_candidate(
            candidate_id=CANDIDATE_ID, vulnerability_class="XSS", store=store,
            rows=real_rows(), authorization=authorization())
        self.assertNotEqual(blob["badge"]["state"], pj.BADGE_VERIFIED)
        self.assertEqual(blob["verdict"], "VERIFICATION_PENDING")


class TestCannotBePromotedByRelabelling(unittest.TestCase):
    """§20: duplicates, history and labels must not manufacture evidence."""

    def test_two_hundred_inventory_rows_still_satisfy_one_stage(self):
        state = en.evaluate_chain("XSS", inventory_rows(200),
                                  authorization=authorization())
        self.assertEqual(state.satisfied_count, 1)
        self.assertFalse(state.confirmed)

    def test_duplicate_reflection_rows_do_not_reach_confirmation(self):
        rows = real_rows() + [
            row("reflection_observed", ref="dup", job=VERIFY_JOB)
            for _ in range(50)]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.stage("reflection").status, ch.STAGE_SATISFIED)
        self.assertEqual(state.stage("context").status, ch.STAGE_MISSING)
        self.assertFalse(state.confirmed)

    def test_the_other_real_job_id_does_not_add_evidence(self):
        state = en.evaluate_chain("XSS", real_rows(),
                                  authorization=authorization())
        self.assertFalse(state.confirmed)
        self.assertEqual(state.satisfied_count, 1)

    def test_a_negative_from_the_verification_job_contradicts(self):
        rows = real_rows() + [negative_row("reflection_not_observed",
                                           ref="real-neg", job=VERIFY_JOB)]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.verdict, "REJECTED")
        self.assertFalse(state.confirmed)

    def test_a_historical_verified_row_is_not_a_contract(self):
        rows = real_rows() + [
            {"id": "old-1", "job_id": SOURCE_JOB, "type": "verification",
             "signal": "verified", "category": "XSS",
             "observation_ref": "old-1", "detail": "VERIFIED (2026-08)"}]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertFalse(state.confirmed)
        self.assertEqual(state.verdict, "VERIFICATION_PENDING")

    def test_source_and_verification_jobs_are_both_represented(self):
        rows = real_rows() + [row("xss_parameter_inventory", ref="inv-v",
                                  job=VERIFY_JOB)]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.stage("parameter").status, ch.STAGE_SATISFIED)
        self.assertFalse(state.confirmed)


if __name__ == "__main__":
    unittest.main()
