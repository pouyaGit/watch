"""EPIC12 §19 — verification-chain SOC projection tests.

The projection is the analyst's view, so its hardest requirement is negative:
it must never show a green badge for an incomplete chain, and it must show the
missing evidence, the negative results and the actions that actually ran.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import executors as ex  # noqa: E402
from backend.research_agents.verification import loop as lp  # noqa: E402
from backend.research_agents.verification import projection as pj  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    CANDIDATE_ID, SCOPE, authorization, confirmation_rows, full_chain_rows,
    inventory_rows, marker_body, make_verification_store, negative_row,
    stage_rows,
)

OBJECTIVE = "ver-xss-1"
TARGET = "https://www.dell.com/support"


def state(rows, cls: str = "XSS"):
    return en.evaluate_chain(cls, rows, authorization=authorization())


class TestBadges(unittest.TestCase):
    def test_parameter_only_is_a_pending_badge(self):
        badge = pj.badge_for(state(inventory_rows(3)))
        self.assertEqual(badge["state"], pj.BADGE_PENDING)
        self.assertFalse(badge["optimistic"])

    def test_contradicted_is_a_not_confirmed_badge(self):
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="n1")]
        badge = pj.badge_for(state(rows))
        self.assertEqual(badge["state"], pj.BADGE_REJECTED)
        self.assertFalse(badge["optimistic"])

    def test_complete_chain_is_the_only_verified_badge(self):
        badge = pj.badge_for(state(full_chain_rows()))
        self.assertEqual(badge["state"], pj.BADGE_VERIFIED)
        self.assertFalse(badge["optimistic"])

    def test_missing_authorization_is_a_blocked_badge(self):
        rows = inventory_rows(3) + stage_rows() + confirmation_rows()[:2]
        badge = pj.badge_for(en.evaluate_chain("XSS", rows, authorization=None))
        self.assertEqual(badge["state"], pj.BADGE_BLOCKED)

    def test_authorization_context_alone_is_not_a_confirmation(self):
        # the context satisfies the authorization requirement; the chain still
        # needs the confirmation evidence itself
        rows = inventory_rows(3) + stage_rows()
        blob = pj.project_chain(state(rows))
        self.assertEqual(blob["badge"]["state"], pj.BADGE_PENDING)
        self.assertTrue(blob["authorization"]["satisfied"])

    def test_no_state_is_an_unknown_badge(self):
        self.assertEqual(pj.badge_for(None)["state"], pj.BADGE_UNKNOWN)

    def test_verified_without_a_complete_chain_is_inconsistent(self):
        fake = {"verdict": "VERIFIED", "confirmed": True,
                "stages": [{"key": "reflection", "status": "MISSING",
                            "required_for_confirmation": True}]}
        badge = pj.badge_for(fake)
        self.assertEqual(badge["state"], pj.BADGE_INCONSISTENT)
        self.assertFalse(badge["optimistic"])
        self.assertTrue(badge["reason"])

    def test_badge_labels_are_present_for_every_state(self):
        for badge_state in (pj.BADGE_VERIFIED, pj.BADGE_PENDING,
                            pj.BADGE_BLOCKED, pj.BADGE_REJECTED,
                            pj.BADGE_UNKNOWN, pj.BADGE_INCONSISTENT):
            self.assertTrue(pj.BADGE_LABELS[badge_state])

    def test_pending_label_says_not_confirmed(self):
        self.assertIn("not confirmed",
                      pj.BADGE_LABELS[pj.BADGE_PENDING].lower())


class TestProjectionShape(unittest.TestCase):
    def test_unavailable_projection_is_explicit(self):
        blob = pj.project_chain(None)
        self.assertFalse(blob["available"])
        self.assertEqual(blob["badge"]["state"], pj.BADGE_UNKNOWN)
        self.assertTrue(blob["limitations"])

    def test_stages_carry_status_glyph_and_next_actions(self):
        blob = pj.project_chain(state(inventory_rows(3)))
        self.assertEqual(len(blob["stages"]), 6)
        self.assertEqual(blob["stages"][0]["status"], "SATISFIED")
        self.assertTrue(blob["stages"][1]["next_actions"])

    def test_projection_reports_the_verdict_and_its_source(self):
        blob = pj.project_chain(state(inventory_rows(3)))
        self.assertEqual(blob["verdict"], "VERIFICATION_PENDING")
        self.assertEqual(blob["verdict_source"], en.VERDICT_SOURCE)

    def test_projection_reports_what_is_missing(self):
        blob = pj.project_chain(state(inventory_rows(3)))
        self.assertIn("REFLECTION_OBSERVED", blob["evidence_missing_types"])

    def test_projection_reports_the_next_stage(self):
        blob = pj.project_chain(state(inventory_rows(3)))
        self.assertEqual(blob["next_stage"], "reflection")
        self.assertEqual(blob["next_stage_missing_types"],
                         ["REFLECTION_OBSERVED"])

    def test_projection_of_a_class_without_a_chain(self):
        blob = pj.project_chain(state(inventory_rows(3), cls="SQLI"))
        self.assertEqual(blob["capability"], "NOT_IMPLEMENTED")
        self.assertEqual(blob["stages"], [])

    def test_projection_is_json_safe(self):
        blob = pj.project_chain(state(full_chain_rows()))
        json.dumps(blob, sort_keys=True)


class TestProjectedEvidence(unittest.TestCase):
    def _observations(self):
        store = make_verification_store()
        act = ac.VerificationAction(
            action_type=ac.CHECK_REFLECTION, candidate_id=CANDIDATE_ID,
            objective_id=OBJECTIVE, scope_ref=SCOPE, target=TARGET)
        marker = ex.marker_for(act)
        result = ex.execute_action(act, context={
            "job_id": "j", "response_body": marker_body(marker),
            "marker": marker, "request_ref": "req-1",
            "response_ref": "resp-1"})
        for observation in result.observations:
            store.record_observation(observation)
        return store, act, result

    def test_evidence_used_answers_the_structured_questions(self):
        store, _act, _result = self._observations()
        blob = pj.project_chain(state(inventory_rows(3)),
                                observations=store.observations_for_candidate(
                                    CANDIDATE_ID))
        self.assertTrue(blob["evidence_used"])
        entry = blob["evidence_used"][0]
        for key in ("observation_id", "signal", "evidence_class", "where",
                    "under_input", "observed", "confidence", "observed_at"):
            self.assertIn(key, entry)
        self.assertEqual(entry["evidence_class"], "REFLECTION_OBSERVED")

    def test_requests_are_surfaced(self):
        store, _act, _result = self._observations()
        blob = pj.project_chain(state(inventory_rows(3)),
                                observations=store.observations_for_candidate(
                                    CANDIDATE_ID))
        self.assertTrue(blob["requests"])
        self.assertEqual(blob["requests"][0]["request_ref"], "req-1")

    def test_negative_results_are_separated_from_evidence(self):
        observations = [
            {"observation_id": "o1", "signal": "reflection_observed",
             "evidence_class": "REFLECTION_OBSERVED", "observed": "marker"},
            {"observation_id": "o2", "signal": "reflection_not_observed",
             "negative": True, "not_observed": "no marker"},
            {"observation_id": "o3", "signal": "not_tested",
             "not_tested": True, "not_observed": "never attempted"},
        ]
        blob = pj.project_chain(state(inventory_rows(3)),
                                observations=observations)
        self.assertEqual(len(blob["evidence_used"]), 1)
        self.assertEqual(len(blob["negative_results"]), 2)
        self.assertNotIn("o2", [e["observation_id"] for e in blob["evidence_used"]])

    def test_actions_are_projected_with_their_state_and_executor(self):
        actions = [{"action_id": "a1", "action_type": "CHECK_REFLECTION",
                    "label": "Check reflection", "state": "SUCCEEDED",
                    "safety": "READ_ONLY", "target": TARGET,
                    "observation_ids": ["o1"], "executor": "read_only_evidence"}]
        blob = pj.project_chain(state(inventory_rows(3)), actions=actions)
        self.assertEqual(len(blob["actions"]), 1)
        self.assertEqual(blob["actions"][0]["state"], "SUCCEEDED")
        self.assertEqual(blob["actions"][0]["observation_count"], 1)

    def test_blocked_actions_show_their_reason(self):
        actions = [{"action_id": "a1", "action_type": "OBSERVE_EXECUTION",
                    "state": "BLOCKED", "blocked_reason": "capability_unavailable"}]
        blob = pj.project_chain(state(inventory_rows(3)), actions=actions)
        self.assertEqual(blob["actions"][0]["blocked_reason"],
                         "capability_unavailable")


class TestCandidateProjection(unittest.TestCase):
    def test_projection_reads_the_persisted_loop_and_actions(self):
        store = make_verification_store()
        lp.run_verification_loop(
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE,
            vulnerability_class="XSS", scope_ref=SCOPE, store=store,
            target=TARGET, rows=inventory_rows(3),
            authorization=authorization(), authorization_id="auth-1",
            context={"job_id": "j"})
        blob = pj.chain_projection_for_candidate(
            candidate_id=CANDIDATE_ID, vulnerability_class="XSS", store=store,
            rows=inventory_rows(3), authorization=authorization())
        self.assertTrue(blob["available"])
        self.assertTrue(blob["actions"])
        self.assertTrue(blob["loop"])
        self.assertFalse(blob["badge"]["optimistic"])
        self.assertNotEqual(blob["badge"]["state"], pj.BADGE_VERIFIED)

    def test_a_broken_store_shows_no_chain_data_instead_of_raising(self):
        class Broken:
            def actions_for_candidate(self, *_a, **_k):
                raise RuntimeError("boom")

            def observations_for_candidate(self, *_a, **_k):
                raise RuntimeError("boom")

            def latest_loop(self, *_a, **_k):
                raise RuntimeError("boom")

        blob = pj.chain_projection_for_candidate(
            candidate_id=CANDIDATE_ID, vulnerability_class="XSS", store=Broken(),
            rows=inventory_rows(3))
        self.assertTrue(blob["available"])
        self.assertEqual(blob["actions"], [])

    def test_projection_never_claims_confirmation_without_evidence(self):
        store = make_verification_store()
        blob = pj.chain_projection_for_candidate(
            candidate_id=CANDIDATE_ID, vulnerability_class="XSS", store=store,
            rows=inventory_rows(20), authorization=authorization())
        self.assertNotEqual(blob["badge"]["state"], pj.BADGE_VERIFIED)
        self.assertEqual(blob["verdict"], "VERIFICATION_PENDING")


if __name__ == "__main__":
    unittest.main()
