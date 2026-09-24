"""EPIC12 §8/§18 — deterministic chain-engine tests.

Every case asserts the AUTHORITATIVE outcome: the chain explains, the EPIC11
gate decides.  Nothing here may pass by making a claim look better.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from tests.epic12_fixtures import (  # noqa: E402
    SCOPE, authorization, confirmation_rows, full_chain_rows, inventory_rows,
    negative_row, not_tested_row, row, stage_rows,
)


class TestVerdicts(unittest.TestCase):
    """§8 CASE A-D plus the two blocking cases."""

    def test_case_a_parameter_only_is_never_confirmed(self):
        state = en.evaluate_chain("XSS", inventory_rows(20),
                                  authorization=authorization())
        self.assertEqual(state.verdict, ig.VERIFICATION_PENDING)
        self.assertFalse(state.confirmed)
        self.assertEqual(state.satisfied_count, 1)
        self.assertEqual(state.stage("parameter").status, ch.STAGE_SATISFIED)
        self.assertEqual(state.stage("reflection").status, ch.STAGE_MISSING)

    def test_case_b_reflection_without_context_is_pending(self):
        rows = inventory_rows(3) + [
            row("controlled_input_sent", ref="c1"),
            row("reflection_observed", ref="r1"),
        ]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.verdict, ig.VERIFICATION_PENDING)
        self.assertEqual(state.next_stage, "context")
        self.assertFalse(state.confirmed)

    def test_case_c_context_without_execution_is_pending(self):
        rows = inventory_rows(3) + stage_rows()
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.verdict, ig.VERIFICATION_PENDING)
        self.assertEqual(state.next_stage, "execution")
        self.assertEqual(state.next_stage_missing_types, ("PAYLOAD_EXECUTION",))
        self.assertFalse(state.confirmed)

    def test_case_d_execution_and_exploitability_confirms(self):
        state = en.evaluate_chain("XSS", full_chain_rows(),
                                  authorization=authorization())
        self.assertEqual(state.verdict, ig.VERIFIED)
        self.assertTrue(state.confirmed)
        self.assertEqual(state.verdict_source, en.VERDICT_SOURCE)

    def test_missing_authorization_blocks(self):
        rows = inventory_rows(3) + stage_rows() + confirmation_rows()[:2]
        state = en.evaluate_chain("XSS", rows, authorization=None)
        self.assertEqual(state.verdict, ig.BLOCKED)
        self.assertIn(ig.BLOCKER_MISSING_AUTHORIZATION, state.blockers)
        self.assertFalse(state.authorization_satisfied)
        self.assertFalse(state.confirmed)

    def test_evidence_confirmed_authorization_is_reported_satisfied(self):
        # EPIC11 accepts authorization CONFIRMED as evidence; the chain must
        # report that faithfully rather than understate it
        state = en.evaluate_chain("XSS", full_chain_rows(), authorization=None)
        self.assertTrue(state.authorization_satisfied)
        self.assertEqual(state.verdict, ig.VERIFIED)

    def test_authorization_context_satisfies_the_requirement(self):
        rows = inventory_rows(3) + stage_rows() + confirmation_rows()[:2]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertTrue(state.authorization_satisfied)
        self.assertEqual(state.verdict, ig.VERIFIED)

    def test_class_without_a_chain_reports_the_contract_verdict(self):
        state = en.evaluate_chain("SQLI", inventory_rows(3))
        self.assertEqual(state.capability, ch.CAPABILITY_NOT_IMPLEMENTED)
        self.assertEqual(state.stages, ())
        self.assertIn(state.verdict, ig.INTEGRITY_STATES)


class TestStageStates(unittest.TestCase):
    def test_negative_evidence_contradicts_the_stage(self):
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="n1")]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.stage("reflection").status, ch.STAGE_CONTRADICTED)
        self.assertEqual(state.verdict, ig.REJECTED)
        self.assertTrue(state.chain_terminated)
        self.assertEqual(state.termination_reason, "required_stage_contradicted")

    def test_not_tested_is_not_missing_and_not_observed(self):
        rows = inventory_rows(3) + [not_tested_row("reflection_not_tested",
                                                  ref="t1")]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.stage("reflection").status, ch.STAGE_NOT_TESTED)
        self.assertEqual(state.verdict, ig.VERIFICATION_PENDING)
        self.assertFalse(state.confirmed)

    def test_irrelevant_evidence_satisfies_nothing(self):
        rows = inventory_rows(3) + [
            row("technology_signal", ref="tech-1", category="RECON"),
            row("jwt_shaped_token_observed", ref="jwt-1", category="JWT"),
        ]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.satisfied_count, 1)
        self.assertEqual(state.stage("reflection").status, ch.STAGE_MISSING)

    def test_unclassified_rows_satisfy_nothing(self):
        rows = inventory_rows(3) + [
            {"id": "ev-x", "job_id": "j", "type": "observation",
             "signal": "something_unknown", "category": "XSS",
             "observation_ref": "u1", "detail": "u"}]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.satisfied_count, 1)

    def test_malformed_rows_never_satisfy_a_stage(self):
        rows = inventory_rows(3) + [None, 42, "not-a-row", object()]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.satisfied_count, 1)
        self.assertEqual(state.verdict, ig.VERIFICATION_PENDING)

    def test_duplicate_observations_do_not_satisfy_two_stages(self):
        dup = [row("reflection_observed", ref="same-ref") for _ in range(40)]
        rows = inventory_rows(3) + dup
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.stage("reflection").status, ch.STAGE_SATISFIED)
        self.assertEqual(state.stage("context").status, ch.STAGE_MISSING)
        self.assertFalse(state.confirmed)

    def test_duplicate_inventory_rows_are_one_unique_observation(self):
        state = en.evaluate_chain("XSS", inventory_rows(40),
                                  authorization=authorization())
        self.assertEqual(state.stage("parameter").status, ch.STAGE_SATISFIED)
        self.assertEqual(state.satisfied_count, 1)


class TestConditionalSinkStage(unittest.TestCase):
    def test_sink_is_not_applicable_for_a_reflected_only_hypothesis(self):
        rows = inventory_rows(3) + stage_rows()
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        sink = state.stage("sink")
        self.assertEqual(sink.status, ch.STAGE_NOT_APPLICABLE)
        self.assertEqual(sink.not_applicable_reason,
                         ch.NOT_APPLICABLE_REFLECTED_ONLY)
        self.assertFalse(sink.satisfied)          # never a silent pass

    def test_sink_stays_missing_before_the_context_is_known(self):
        state = en.evaluate_chain("XSS", inventory_rows(3),
                                  authorization=authorization())
        self.assertEqual(state.stage("sink").status, ch.STAGE_MISSING)

    def test_dom_evidence_satisfies_the_sink_stage(self):
        rows = inventory_rows(3) + stage_rows() + [
            row("dom_sink_identified", ref="dom-1")]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.stage("sink").status, ch.STAGE_SATISFIED)
        self.assertTrue(state.stage("sink").satisfied)

    def test_not_applicable_never_contributes_to_confirmation(self):
        rows = inventory_rows(3) + stage_rows()
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertFalse(state.confirmed)
        self.assertEqual(state.next_stage, "execution")


class TestAuthoritativeGate(unittest.TestCase):
    """§1/§18: model output, historical state and prose are never evidence."""

    def test_llm_insight_rows_never_satisfy_a_stage(self):
        rows = inventory_rows(3) + [
            {"id": "ev-llm-1", "job_id": "j", "type": "llm_insight",
             "signal": "reflection_observed", "category": "XSS",
             "observation_ref": "llm-1",
             "detail": "the model says this is confirmed XSS"},
            {"id": "ev-llm-2", "job_id": "j", "type": "prior_recommendation",
             "signal": "payload_execution", "category": "XSS",
             "observation_ref": "llm-2", "detail": "confirmed"}]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.satisfied_count, 1)
        # the chain view refuses advisory rows, so no stage advances
        self.assertEqual(state.stage("reflection").status, ch.STAGE_MISSING)
        self.assertEqual(state.stage("execution").status, ch.STAGE_MISSING)
        self.assertEqual(state.inadmissible_row_count, 2)
        # EPIC14 closed this: the authoritative classifier derives the type
        # from the signal AND requires trusted provenance for confirmation-
        # capable evidence, so a mislabelled advisory row can no longer reach
        # the gate as confirmation evidence.  The chain and the verdict now
        # agree, and the exclusion is explicit.
        self.assertFalse(state.confirmed)
        self.assertTrue(state.pending)
        self.assertTrue(state.excluded_evidence)
        self.assertEqual(state.excluded_evidence[0]["reason"],
                         "confirmation_evidence_without_trusted_provenance")
        # no divergence remains: the authoritative verdict and the chain view
        # now agree, because the gate no longer counts the advisory rows
        self.assertEqual(state.divergence, ())
        from backend.research_agents.verification import projection as pj
        self.assertEqual(pj.badge_for(state)["state"], pj.BADGE_PENDING)
        self.assertFalse(pj.badge_for(state)["optimistic"])

    def test_advisory_rows_are_inadmissible(self):
        advisory = [
            {"id": "a1", "type": "llm_insight", "signal": "reflection_observed",
             "category": "XSS", "observation_ref": "a1"},
            {"id": "a2", "type": "prior_recommendation",
             "signal": "payload_execution", "category": "XSS",
             "observation_ref": "a2"},
            {"id": "a3", "type": "advisor_recommendation",
             "signal": "exploitability_established", "category": "XSS",
             "observation_ref": "a3"},
        ]
        self.assertEqual(len(en.inadmissible_rows(advisory)), 3)
        self.assertEqual(en.admissible_rows(advisory), [])

    def test_real_observation_rows_stay_admissible(self):
        rows = inventory_rows(3) + stage_rows()
        self.assertEqual(en.inadmissible_rows(rows), [])
        self.assertEqual(len(en.admissible_rows(rows)), len(rows))

    def test_non_rows_are_dropped_from_the_chain_view(self):
        rows = inventory_rows(3) + [None, 7, "x"]
        self.assertEqual(len(en.admissible_rows(rows)), 3)

    def test_a_claimed_verified_state_is_not_a_contract(self):
        rows = inventory_rows(3) + [
            {"id": "ev-v", "job_id": "j", "type": "verification",
             "signal": "verified", "category": "XSS",
             "observation_ref": "v-1", "detail": "VERIFIED"}]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertFalse(state.confirmed)

    def test_no_divergence_when_the_chain_explains_the_verdict(self):
        state = en.evaluate_chain("XSS", full_chain_rows(),
                                  authorization=authorization())
        self.assertEqual(state.divergence, ())
        self.assertEqual(state.inadmissible_row_count, 0)

    def test_pending_verdict_never_reports_divergence(self):
        state = en.evaluate_chain("XSS", inventory_rows(3),
                                  authorization=authorization())
        self.assertEqual(state.divergence, ())

    def test_verdict_is_never_computed_by_the_engine(self):
        state = en.evaluate_chain("XSS", full_chain_rows(),
                                  authorization=authorization())
        self.assertEqual(state.verdict_source, en.VERDICT_SOURCE)
        self.assertEqual(state.verdict, ig.VERIFIED)

    def test_knowledge_rows_are_auxiliary_only(self):
        rows = inventory_rows(3) + [
            row("knowledge_reference", ref="k-1")]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertEqual(state.satisfied_count, 1)
        self.assertFalse(state.confirmed)


class TestWhyNotConfirmed(unittest.TestCase):
    def test_reasons_name_the_missing_stage_and_types(self):
        state = en.evaluate_chain("XSS", inventory_rows(3),
                                  authorization=authorization())
        joined = " ".join(state.why_not_confirmed)
        self.assertIn("reflection:missing_REFLECTION_OBSERVED", joined)
        self.assertIn("execution:missing_PAYLOAD_EXECUTION", joined)

    def test_contradicted_stage_is_reported(self):
        rows = inventory_rows(3) + [negative_row("reflection_not_observed",
                                                 ref="n1")]
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        self.assertIn("reflection:contradicting_evidence",
                      " ".join(state.why_not_confirmed))

    def test_confirmed_state_has_no_missing_required_stage(self):
        state = en.evaluate_chain("XSS", full_chain_rows(),
                                  authorization=authorization())
        self.assertNotIn("missing_", " ".join(state.why_not_confirmed))


class TestChainMatrix(unittest.TestCase):
    def test_matrix_rows_carry_stage_status_and_next_actions(self):
        state = en.evaluate_chain("XSS", inventory_rows(3),
                                  authorization=authorization())
        matrix = en.chain_matrix(state)
        self.assertEqual(len(matrix), 6)
        first = matrix[0]
        self.assertEqual(first["key"], "parameter")
        self.assertEqual(first["glyph"], "\u2713")
        reflection = matrix[1]
        self.assertEqual(reflection["status"], ch.STAGE_MISSING)
        self.assertTrue(reflection["next_actions"])

    def test_not_applicable_glyph_is_explicit(self):
        rows = inventory_rows(3) + stage_rows()
        state = en.evaluate_chain("XSS", rows, authorization=authorization())
        sink = [r for r in en.chain_matrix(state) if r["key"] == "sink"][0]
        self.assertEqual(sink["glyph"], "n/a")
        self.assertEqual(sink["not_applicable_reason"],
                         ch.NOT_APPLICABLE_REFLECTED_ONLY)

    def test_to_dict_serialises(self):
        import json
        state = en.evaluate_chain("XSS", inventory_rows(3),
                                  authorization=authorization())
        blob = json.dumps(state.to_dict(), sort_keys=True)
        self.assertIn("chain-xss", blob)
        self.assertIn("VERIFICATION_PENDING", blob)


class TestNegativeTargeting(unittest.TestCase):
    def test_targeting_is_deterministic_per_evidence_type(self):
        self.assertTrue(en.negative_targets_stage(
            "reflection_not_observed", tx.REFLECTION_OBSERVED))
        self.assertTrue(en.negative_targets_stage(
            "output_context_not_observed", tx.OUTPUT_CONTEXT_IDENTIFIED))
        self.assertTrue(en.negative_targets_stage(
            "dom_sink_not_observed", tx.DOM_SINK_IDENTIFIED))
        self.assertTrue(en.negative_targets_stage(
            "payload_execution_not_observed", tx.PAYLOAD_EXECUTION))

    def test_unrelated_negatives_do_not_contradict_a_stage(self):
        self.assertFalse(en.negative_targets_stage(
            "unrelated_thing_not_observed", tx.REFLECTION_OBSERVED))

    def test_tokens_are_closed_and_documented(self):
        self.assertEqual(en.stage_tokens(tx.REFLECTION_OBSERVED),
                         ("reflection", "reflected", "marker"))


if __name__ == "__main__":
    unittest.main()
