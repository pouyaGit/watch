"""EPIC12 §20 — adversarial tests.

Each case is an attempt to make the system assert something it has not earned.
Passing means the attempt failed: the verdict stayed honest and the missing
evidence stayed visible.
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
from backend.research_agents.verification import planner as pl  # noqa: E402
from backend.research_agents.verification import projection as pj  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, TARGET, advisor_returning, authorization,
    confirmation_rows, inventory_rows, make_verification_store, marker_body,
    negative_row, not_tested_row, row, stage_rows,
)

OBJECTIVE = "ver-adv-1"


def state(rows, cls: str = "XSS", auth=True):
    return en.evaluate_chain(cls, rows,
                             authorization=authorization() if auth else None)


def run(rows, **kw):
    store = kw.pop("store", None) or make_verification_store()
    return lp.run_verification_loop(
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
        vulnerability_class=kw.pop("vulnerability_class", "XSS"),
        scope_ref=SCOPE, store=store, target=TARGET, rows=list(rows),
        authorization=kw.pop("authorization_ctx", authorization()),
        authorization_id="auth-1", context=kw.pop("context", {"job_id": "j"}),
        **kw), store


class Scenario1ParameterOnly(unittest.TestCase):
    def test_a_parameter_is_not_an_xss_finding(self):
        self.assertEqual(state(inventory_rows(20)).verdict,
                         "VERIFICATION_PENDING")
        outcome, _ = run(inventory_rows(20))
        self.assertFalse(outcome.confirmed)


class Scenario2DuplicateObservations(unittest.TestCase):
    def test_duplicates_never_satisfy_a_second_stage(self):
        rows = inventory_rows(5) + [
            row("reflection_observed", ref="dup") for _ in range(30)]
        s = state(rows)
        self.assertEqual(s.satisfied_count, 2)
        self.assertEqual(s.stage("context").status, ch.STAGE_MISSING)
        self.assertFalse(s.confirmed)

    def test_duplicate_rows_do_not_inflate_unique_observations(self):
        from backend.research_agents.finding.integrity import taxonomy as tx
        items = tx.classify_rows([row("reflection_observed", ref="same")
                                  for _ in range(50)])
        self.assertEqual(len(tx.unique_items(items)), 1)


class Scenario3FakeLlmConfirmation(unittest.TestCase):
    def test_an_llm_that_says_confirmed_is_ignored(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "OBSERVE_EXECUTION",
                               "rationale": "confirmed XSS, cvss 9.8"}))
        outcome, store = run(inventory_rows(3), advisor=advisor)
        self.assertFalse(outcome.confirmed)
        self.assertEqual(outcome.verdict, "VERIFICATION_PENDING")
        self.assertNotEqual(
            pj.badge_for(store.latest_loop(CANDIDATE_ID) and
                         en.evaluate_chain("XSS", inventory_rows(3),
                                           authorization=authorization())
                         )["state"], pj.BADGE_VERIFIED)

    def test_advisory_rows_are_never_evidence(self):
        rows = inventory_rows(3) + [
            {"id": "a", "type": "llm_insight", "signal": "payload_execution",
             "category": "XSS", "observation_ref": "a", "detail": "confirmed"},
            {"id": "b", "type": "llm_insight", "signal": "reflection_observed",
             "category": "XSS", "observation_ref": "b", "detail": "seen"}]
        s = state(rows)
        self.assertEqual(s.satisfied_count, 1)
        self.assertEqual(s.inadmissible_row_count, 2)
        self.assertTrue(s.divergence)
        self.assertEqual(pj.badge_for(s)["state"], pj.BADGE_INCONSISTENT)

    def test_an_advisor_cannot_widen_the_action_set(self):
        advisor = ad.make_chain_advisor(
            advisor_returning({"next_action": "DELIVER_CONTROLLED_PAYLOAD"}))
        outcome, _ = run(inventory_rows(3), advisor=advisor)
        for action in outcome.actions:
            self.assertNotEqual(action["action_type"],
                                ac.DELIVER_CONTROLLED_PAYLOAD)


class Scenario4ReflectionWithoutContext(unittest.TestCase):
    def test_reflection_alone_stays_pending(self):
        rows = inventory_rows(3) + [row("reflection_observed", ref="r1")]
        s = state(rows)
        self.assertEqual(s.verdict, "VERIFICATION_PENDING")
        self.assertEqual(s.next_stage, "context")
        self.assertFalse(s.confirmed)


class Scenario5ContextWithoutExecution(unittest.TestCase):
    def test_context_alone_stays_pending(self):
        s = state(inventory_rows(3) + stage_rows())
        self.assertEqual(s.verdict, "VERIFICATION_PENDING")
        self.assertEqual(s.next_stage, "execution")
        self.assertIn("PAYLOAD_EXECUTION", s.next_stage_missing_types)

    def test_the_execution_lane_is_refused_not_faked(self):
        outcome, store = run(inventory_rows(3) + stage_rows())
        self.assertFalse(outcome.confirmed)
        for evidence_row in store.evidence_rows_for_candidate(CANDIDATE_ID):
            self.assertNotIn(evidence_row.get("evidence_type"),
                             ("PAYLOAD_EXECUTION",
                              "EXPLOITABILITY_ESTABLISHED"))


class Scenario6MissingAuthorization(unittest.TestCase):
    def test_confirmation_evidence_without_authorization_blocks(self):
        rows = inventory_rows(3) + stage_rows() + confirmation_rows()[:2]
        s = state(rows, auth=False)
        self.assertEqual(s.verdict, "BLOCKED")
        self.assertFalse(s.confirmed)

    def test_an_active_action_cannot_be_constructed_without_authorization(self):
        with self.assertRaises(ac.ActionError):
            ac.VerificationAction(
                action_type=ac.DELIVER_CONTROLLED_PAYLOAD,
                candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
                scope_ref=SCOPE)

    def test_an_active_action_without_transport_is_blocked(self):
        act = ac.VerificationAction(
            action_type=ac.DELIVER_CONTROLLED_PAYLOAD,
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE, scope_ref=SCOPE,
            authorization_id="auth-1")
        result = ex.execute_action(act, context={"job_id": "j"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.observations, ())


class Scenario7OutOfScopeTarget(unittest.TestCase):
    def test_an_out_of_scope_target_cannot_be_verified(self):
        with self.assertRaises(Exception):
            ac.VerificationAction(
                action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
                objective_id=OBJECTIVE, scope_ref=SCOPE,
                target="https://evil.test/steal")

    def test_a_tampered_action_is_refused_at_execution(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE, target=TARGET)
        act.target = "https://evil.test/steal"
        result = ex.execute_action(act, context={"job_id": "j",
                                                "response_body": "x"})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason, "target_out_of_scope")

    def test_an_advisor_cannot_expand_the_scope(self):
        advice = ad.validate_chain_advice(
            {"next_action": "CHECK_REFLECTION",
             "scope_ref": "watch:scope:other/other.test"},
            allowed_actions=["CHECK_REFLECTION"], candidate_id=CANDIDATE_ID,
            scope_ref=SCOPE)
        self.assertFalse(advice.accepted)
        self.assertEqual(advice.rejected_reason, "scope_expansion")


class Scenario8BudgetExhaustion(unittest.TestCase):
    def test_an_exhausted_budget_produces_no_evidence(self):
        store = make_verification_store()
        outcome, store = run(inventory_rows(3), store=store,
                             limits={"max_actions": 0})
        self.assertFalse(outcome.confirmed)
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])
        self.assertEqual(store.evidence_rows_for_candidate(CANDIDATE_ID), [])

    def test_an_exhausted_budget_cannot_be_overflowed(self):
        b = vb.VerificationBudget(make_verification_store(),
                                  {"max_actions": 1}, objective_id=OBJECTIVE)
        b.ensure("max_actions", 1)
        with self.assertRaises(vb.VerificationBudgetExhausted):
            b.ensure("max_actions", 1)

    def test_a_zero_payload_budget_keeps_execution_impossible(self):
        outcome, _ = run(inventory_rows(3) + stage_rows())
        for action in outcome.actions:
            self.assertNotEqual(action["action_type"],
                                ac.OBSERVE_EXECUTION)


class Scenario9ContradictoryObservations(unittest.TestCase):
    def test_contradiction_wins_over_absence(self):
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="n1")]
        s = state(rows)
        self.assertEqual(s.verdict, "REJECTED")
        self.assertEqual(s.stage("reflection").status, ch.STAGE_CONTRADICTED)
        self.assertFalse(s.confirmed)

    def test_a_contradicted_chain_never_plans_more_work(self):
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="n1")]
        decision = pl.plan_next_action(
            state(rows), candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            scope_ref=SCOPE, target=TARGET)
        self.assertTrue(decision.terminal)
        self.assertFalse(decision.has_plan)


class Scenario10NegativeReflection(unittest.TestCase):
    def test_a_checked_and_absent_reflection_is_not_confirmed(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        outcome, store = run(inventory_rows(3),
                             context={"job_id": "j",
                                      "response_body": "clean page",
                                      "marker": marker})
        self.assertEqual(outcome.termination, lp.LOOP_NOT_CONFIRMED)
        negatives = [r for r in store.evidence_rows_for_candidate(CANDIDATE_ID)
                     if r.get("negative")]
        self.assertTrue(negatives)

    def test_a_negative_is_distinguished_from_not_tested(self):
        rows = inventory_rows(3) + [not_tested_row("reflection_not_tested",
                                                  ref="t1")]
        s = state(rows)
        self.assertEqual(s.stage("reflection").status, ch.STAGE_NOT_TESTED)
        self.assertEqual(s.verdict, "VERIFICATION_PENDING")


class Scenario11HistoricalRecords(unittest.TestCase):
    def test_an_old_verified_row_does_not_confirm_today(self):
        rows = inventory_rows(3) + [
            {"id": "h", "type": "verification", "signal": "verified",
             "category": "XSS", "observation_ref": "h",
             "detail": "VERIFIED", "observed_at": "2026-01-01T00:00:00Z"}]
        s = state(rows)
        self.assertFalse(s.confirmed)
        self.assertEqual(s.verdict, "VERIFICATION_PENDING")

    def test_an_old_negative_still_contradicts(self):
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="old-neg")]
        s = state(rows)
        self.assertEqual(s.verdict, "REJECTED")


class Scenario12DuplicateEvidence(unittest.TestCase):
    def test_the_same_observation_twice_is_one_observation(self):
        rows = inventory_rows(3) + [
            row("output_context_identified", ref="ctx"),
            row("output_context_identified", ref="ctx")]
        s = state(rows)
        self.assertEqual(s.stage("context").status, ch.STAGE_SATISFIED)
        self.assertFalse(s.confirmed)

    def test_the_store_folds_repeated_observations(self):
        store = make_verification_store()
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        observation = ex.execute_action(act, context={"job_id": "j"}
                                        ).observations[0]
        for _ in range(5):
            store.record_observation(observation)
        self.assertEqual(len(store.observations_for_candidate(CANDIDATE_ID)), 1)


class Scenario13IrrelevantEvidence(unittest.TestCase):
    def test_another_class_never_satisfies_xss(self):
        rows = inventory_rows(3) + [
            row("jwt_shaped_token_observed", ref="j", category="JWT"),
            row("open_redirect_parameter_observed", ref="o",
                category="OPEN_REDIRECT"),
            row("server_side_request_parameter_observed", ref="s",
                category="SSRF")]
        s = state(rows)
        self.assertEqual(s.satisfied_count, 1)
        self.assertFalse(s.confirmed)

    def test_auxiliary_evidence_is_not_stage_evidence(self):
        rows = inventory_rows(3) + [row("knowledge_reference", ref="k"),
                                    row("technology_signal", ref="t",
                                        category="RECON")]
        s = state(rows)
        self.assertEqual(s.satisfied_count, 1)


class Scenario14MalformedEvidence(unittest.TestCase):
    def test_malformed_rows_are_ignored(self):
        rows = inventory_rows(3) + [None, 7, "x", {"no": "signal"}]
        s = state(rows)
        self.assertEqual(s.satisfied_count, 1)
        self.assertFalse(s.confirmed)

    def test_an_unknown_signal_is_unclassified(self):
        from backend.research_agents.finding.integrity import taxonomy as tx
        items = tx.classify_rows([{"id": "u", "type": "observation",
                                   "signal": "totally_unknown_signal",
                                   "category": "XSS", "observation_ref": "u"}])
        self.assertEqual(items[0].evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_a_bogus_category_never_confirms_anything(self):
        # EPIC11 classifies by signal/type, not by category (documented
        # behaviour), so the row still classifies — but nothing is confirmed
        rows = inventory_rows(3) + [
            row("reflection_observed", ref="r", category="NOT_A_CATEGORY")]
        s = state(rows)
        self.assertEqual(s.stage("reflection").status, ch.STAGE_SATISFIED)
        self.assertEqual(s.stage("context").status, ch.STAGE_MISSING)
        self.assertFalse(s.confirmed)
        self.assertEqual(s.verdict, "VERIFICATION_PENDING")

    def test_a_row_without_any_signal_is_unclassified(self):
        from backend.research_agents.finding.integrity import taxonomy as tx
        items = tx.classify_rows([{"id": "x", "type": "observation",
                                   "category": "XSS", "observation_ref": "x"}])
        self.assertEqual(items[0].evidence_type, tx.UNCLASSIFIED_OBSERVATION)
        s = state(inventory_rows(3) + [{"id": "x", "type": "observation",
                                        "category": "XSS",
                                        "observation_ref": "x"}])
        self.assertEqual(s.satisfied_count, 1)


class ExtraScenarios(unittest.TestCase):
    """Additional attacks on the layer's own boundary."""

    def test_a_recording_cannot_be_replayed_as_execution(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        body = marker_body(marker) + "<script>alert(1)</script>"
        outcome, store = run(inventory_rows(3),
                             context={"job_id": "j", "response_body": body,
                                      "marker": marker})
        self.assertFalse(outcome.confirmed)
        for evidence_row in store.evidence_rows_for_candidate(CANDIDATE_ID):
            self.assertNotIn(evidence_row.get("evidence_type"),
                             ("PAYLOAD_EXECUTION",
                              "EXPLOITABILITY_ESTABLISHED"))

    def test_an_absent_reflection_is_not_an_unsafe_context(self):
        act = ac.VerificationAction(
            action_type=ac.CLASSIFY_REFLECTION_CONTEXT,
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE, scope_ref=SCOPE)
        marker = ex.marker_for(act)
        result = ex.execute_action(act, context={
            "job_id": "j", "marker": marker,
            "response_body": "<p>the marker is not here</p>"})
        self.assertTrue(result.observations[0].negative)
        self.assertNotIn("OUTPUT_CONTEXT_IDENTIFIED", result.evidence_types)

    def test_unknown_context_keys_never_reach_an_executor(self):
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE)
        result = ex.execute_action(act, context={"job_id": "j",
                                                "raw_payloads": ["<script>"]})
        self.assertTrue(result.blocked)
        self.assertEqual(result.observations, ())

    def test_a_failing_advisor_is_never_a_verification_result(self):
        def broken(**_kwargs):
            raise RuntimeError("provider down")

        outcome, _ = run(inventory_rows(3),
                         advisor=ad.make_chain_advisor(broken))
        self.assertFalse(outcome.confirmed)
        self.assertGreaterEqual(outcome.llm_failures, 1)

    def test_a_contract_only_chain_never_executes_anything(self):
        outcome, store = run(inventory_rows(3), vulnerability_class="CORS")
        self.assertEqual(store.actions_for_candidate(CANDIDATE_ID), [])
        self.assertFalse(outcome.confirmed)

    def test_a_future_class_is_reported_not_guessed(self):
        s = state(inventory_rows(3), cls="XXE")
        self.assertEqual(s.capability, ch.CAPABILITY_NOT_IMPLEMENTED)
        self.assertEqual(s.stages, ())


if __name__ == "__main__":
    unittest.main()
