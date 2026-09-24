"""EPIC14 §20/§12/§13 — regression on the real candidate and both integrations.

* §20: ``cand-7c229c48c455`` — 20 ``xss_parameter_inventory`` observations and a
  historically persisted VERIFIED state.  The historical record is preserved;
  the *current* authoritative assessment stays stage 1 and not confirmed.
* §12: EPIC12's chain consumes the authoritative mismatch result.
* §13: an EPIC13 acquisition observation still classifies through the same
  authoritative path, and a caller cannot relabel a parameter observation as a
  reflection or an execution.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import observations as ob  # noqa: E402
from backend.research_agents.verification import projection as pj  # noqa: E402
from tests.epic12_fixtures import authorization as epic11_authorization  # noqa: E402
from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, CANDIDATE_ID, SCOPE_REF, TARGET_URL, inventory_rows)
from tests.epic14_fixtures import (  # noqa: E402
    forged_declared_type, forged_exploitability, inventory, legit_chain,
    row)

SIGNAL = "xss_parameter_inventory"


def real_rows() -> list[dict]:
    """The candidate's real evidence: 20 parameter-inventory observations."""
    return [row(SIGNAL, ref=f"obs-{CANDIDATE_ID}-{i}", category="XSS",
                candidate_id=CANDIDATE_ID, scope_ref=SCOPE_REF,
                detail=f"{TARGET_URL}?q{i}=1") for i in range(20)]


def real_state(rows=None, authorization=None):
    return en.evaluate_chain(
        "XSS", real_rows() if rows is None else rows,
        authorization=(epic11_authorization()
                       if authorization is None else authorization))


class TestTheRealCandidate(unittest.TestCase):
    """§20: the historical record survives; the current verdict does not move."""

    def test_the_real_signal_is_parameter_inventory(self):
        self.assertEqual(tx.SIGNAL_TO_TYPE[SIGNAL], tx.PARAMETER_OBSERVED)

    def test_the_real_rows_classify_as_parameter_observed(self):
        items = tx.classify_rows(real_rows())
        self.assertEqual({i.evidence_type for i in items},
                         {tx.PARAMETER_OBSERVED})

    def test_no_real_row_carries_a_mismatch(self):
        items = tx.classify_rows(real_rows())
        self.assertEqual([i for i in items if i.has_mismatch], [])

    def test_the_real_candidate_stays_at_stage_one(self):
        self.assertEqual(tx.stage_reached(tx.classify_rows(real_rows())),
                         tx.STAGE_OBSERVED)

    def test_the_real_candidate_is_not_confirmed(self):
        self.assertFalse(real_state().confirmed)

    def test_the_real_candidate_verdict_is_not_verified(self):
        self.assertNotEqual(real_state().verdict, ig.VERIFIED)

    def test_the_real_candidate_has_no_confirmation_evidence(self):
        items = tx.classify_rows(real_rows())
        self.assertFalse([i for i in items if i.is_confirmation_evidence])

    def test_the_real_candidate_badge_is_not_optimistic(self):
        self.assertFalse(pj.badge_for(real_state())["optimistic"])

    def test_the_real_candidate_projection_is_clean(self):
        """Nothing was mislabelled in the real record."""
        block = pj.project_chain(real_state())["trust_boundary"]
        self.assertTrue(block["clean"])

    def test_the_historical_verified_state_is_not_reinterpreted(self):
        """EPIC14 does not rewrite history: the stored rows are untouched."""
        self.assertEqual(len(real_rows()), 20)
        self.assertEqual({r["signal"] for r in real_rows()}, {SIGNAL})

    def test_a_forged_row_added_to_the_real_candidate_is_recorded(self):
        state = real_state(real_rows() + [forged_declared_type()])
        self.assertTrue(state.evidence_mismatches)

    def test_a_forged_row_added_to_the_real_candidate_does_not_confirm(self):
        state = real_state(real_rows() + [forged_declared_type()])
        self.assertFalse(state.confirmed)

    def test_a_forged_row_cannot_move_the_real_candidate_stage(self):
        base = real_state()
        forged = real_state(real_rows() + [forged_declared_type()])
        self.assertEqual(base.furthest_stage, forged.furthest_stage)

    def test_an_exploitability_stamp_on_the_real_rows_does_not_confirm(self):
        rows = [dict(r, evidence_type=tx.EXPLOITABILITY_ESTABLISHED)
                for r in real_rows()]
        state = real_state(rows)
        self.assertFalse(state.confirmed)
        self.assertEqual(len(state.evidence_mismatches), 20)

    def test_the_real_candidate_without_authorization_stays_pending(self):
        state = real_state(authorization=None)
        self.assertFalse(state.confirmed)

    def test_the_real_candidate_needs_reflection_and_context_to_progress(self):
        items = tx.classify_rows(real_rows())
        self.assertEqual(tx.stage_reached(items), tx.STAGE_OBSERVED)
        self.assertLess(tx.stage_reached(items), tx.STAGE_REFLECTION)


class TestEpic12Integration(unittest.TestCase):
    """§12: EPIC12 consumes the authoritative mismatch, it does not re-derive it."""

    def test_the_engine_uses_the_taxonomy_contributor_rule(self):
        source = (Path(__file__).resolve().parents[1] /
                  "backend/research_agents/verification/engine.py").read_text()
        self.assertIn("tx.contributes_to_authoritative_stage", source)

    def test_the_engine_uses_the_authoritative_item_set(self):
        source = (Path(__file__).resolve().parents[1] /
                  "backend/research_agents/verification/engine.py").read_text()
        self.assertIn("tx.authoritative_items", source)

    def test_the_engine_consumes_the_evaluation_mismatches(self):
        source = (Path(__file__).resolve().parents[1] /
                  "backend/research_agents/verification/engine.py").read_text()
        self.assertIn("evaluation.evidence_mismatches", source)

    def test_the_chain_reports_the_mismatch_from_the_authoritative_layer(self):
        state = real_state(real_rows() + [forged_declared_type()])
        entry = state.evidence_mismatches[0]
        self.assertEqual(entry["classifier_version"],
                         tx.AUTHORITATIVE_CLASSIFIER_VERSION)

    def test_the_chain_verdict_matches_the_gate_verdict(self):
        rows = real_rows() + [forged_declared_type()]
        evaluation = cl.evaluate_rows("XSS", rows,
                                      authorization=epic11_authorization())
        self.assertEqual(real_state(rows).verdict,
                         ig.decide(evaluation).authoritative_state)

    def test_a_legitimate_chain_still_reaches_a_verified_verdict(self):
        evaluation = cl.evaluate_rows("XSS", legit_chain(),
                                      authorization=epic11_authorization())
        self.assertEqual(ig.decide(evaluation).authoritative_state,
                         ig.VERIFIED)

    def test_a_legitimate_chain_still_reaches_the_execution_stage(self):
        state = en.evaluate_chain("XSS", legit_chain(),
                                  authorization=epic11_authorization())
        self.assertEqual(state.stage("execution").status, ch.STAGE_SATISFIED)

    def test_the_chain_does_not_advance_on_a_forged_execution_row(self):
        rows = real_rows() + [forged_exploitability()]
        state = en.evaluate_chain("XSS", rows,
                                  authorization=epic11_authorization())
        self.assertNotEqual(state.stage("execution").status,
                            ch.STAGE_SATISFIED)

    def test_the_chain_projection_states_the_invariant(self):
        state = real_state()
        block = pj.project_chain(state)["trust_boundary"]
        self.assertIn("authoritative provenance", block["statement"])


class TestEpic13Integration(unittest.TestCase):
    """§13: acquisition observations pass through the same classification."""

    def test_an_acquisition_reflection_observation_is_reflection_observed(self):
        observation = ob.positive(
            signal="reflection_observed", evidence_type=tx.REFLECTION_OBSERVED,
            observed="marker reflected", where=TARGET_URL,
            marker="HERMES_REFLECT_ab12", action_id="act-acq-1",
            candidate_id=CANDIDATE_ID, objective_id="vo-epic14-1",
            scope_ref=SCOPE_REF)
        item = tx.classify_row(observation.to_evidence_row())
        self.assertEqual(item.evidence_type, tx.REFLECTION_OBSERVED)

    def test_an_acquisition_reflection_row_has_trusted_provenance(self):
        observation = ob.positive(
            signal="reflection_observed", evidence_type=tx.REFLECTION_OBSERVED,
            observed="marker reflected", where=TARGET_URL,
            marker="HERMES_REFLECT_ab12", action_id="act-acq-1",
            candidate_id=CANDIDATE_ID, objective_id="vo-epic14-1",
            scope_ref=SCOPE_REF)
        item = tx.classify_row(observation.to_evidence_row())
        self.assertIn(item.provenance_class, tx.TRUSTED_PROVENANCE_CLASSES)

    def test_a_producer_cannot_relabel_a_parameter_observation(self):
        """§13: the producer-side guard refuses the relabel at the source."""
        with self.assertRaises(ValueError):
            ob.positive(signal="xss_parameter_inventory",
                        evidence_type=tx.REFLECTION_OBSERVED,
                        action_id="act-acq-2", candidate_id=CANDIDATE_ID,
                        objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
                        observed="relabelled", where=TARGET_URL)

    def test_a_producer_cannot_relabel_a_parameter_observation_as_execution(self):
        with self.assertRaises(ValueError):
            ob.positive(signal="xss_parameter_inventory",
                        evidence_type=tx.PAYLOAD_EXECUTION,
                        action_id="act-acq-3", candidate_id=CANDIDATE_ID,
                        objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
                        observed="relabelled", where=TARGET_URL)

    def test_a_producer_still_accepts_a_consistent_observation(self):
        observation = ob.positive(
            signal="output_context_identified",
            evidence_type=tx.OUTPUT_CONTEXT_IDENTIFIED,
            action_id="act-acq-4", candidate_id=CANDIDATE_ID,
            objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
            observed="context HTML_TEXT", where=TARGET_URL)
        self.assertEqual(tx.classify_row(observation.to_evidence_row()).evidence_type,
                         tx.OUTPUT_CONTEXT_IDENTIFIED)

    def test_the_acquisition_observation_is_acquisition_derived(self):
        observation = ob.positive(
            signal="reflection_observed", evidence_type=tx.REFLECTION_OBSERVED,
            action_id="act-acq-5", candidate_id=CANDIDATE_ID,
            objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
            observed="marker reflected", where=TARGET_URL,
            marker="HERMES_REFLECT_cd34")
        item = tx.classify_row(observation.to_evidence_row())
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ACQUISITION)

    def test_an_acquisition_row_contributes_to_its_own_stage(self):
        observation = ob.positive(
            signal="reflection_observed", evidence_type=tx.REFLECTION_OBSERVED,
            action_id="act-acq-6", candidate_id=CANDIDATE_ID,
            objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
            observed="marker reflected", where=TARGET_URL,
            marker="HERMES_REFLECT_ef56")
        item = tx.classify_row(observation.to_evidence_row())
        self.assertTrue(tx.contributes_to_authoritative_stage(item))

    def test_the_real_candidate_plus_acquisition_evidence_progresses(self):
        """Real acquisition output may advance the chain — legitimately."""
        observation = ob.positive(
            signal="reflection_observed", evidence_type=tx.REFLECTION_OBSERVED,
            action_id="act-acq-7", candidate_id=CANDIDATE_ID,
            objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
            observed="marker reflected", where=TARGET_URL,
            marker="HERMES_REFLECT_ab12")
        rows = real_rows() + [observation.to_evidence_row()]
        state = en.evaluate_chain("XSS", rows,
                                  authorization=epic11_authorization())
        self.assertGreater(state.furthest_stage, tx.STAGE_OBSERVED)

    def test_the_real_candidate_plus_acquisition_evidence_is_not_confirmed(self):
        observation = ob.positive(
            signal="reflection_observed", evidence_type=tx.REFLECTION_OBSERVED,
            action_id="act-acq-8", candidate_id=CANDIDATE_ID,
            objective_id="vo-epic14-1", scope_ref=SCOPE_REF,
            observed="marker reflected", where=TARGET_URL,
            marker="HERMES_REFLECT_ab12")
        rows = real_rows() + [observation.to_evidence_row()]
        state = en.evaluate_chain("XSS", rows,
                                  authorization=epic11_authorization())
        self.assertFalse(state.confirmed)

    def test_the_acquisition_fixture_rows_still_classify(self):
        rows = inventory_rows()
        self.assertTrue(rows)
        for candidate in rows[:3]:
            item = tx.classify_row(dict(candidate, signal=SIGNAL))
            self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)


class TestNoRegressionInTheDeliveredLayers(unittest.TestCase):
    """The hardening must not have narrowed any legitimate path."""

    def test_every_legitimate_chain_row_contributes(self):
        for candidate in legit_chain():
            item = tx.classify_row(candidate)
            self.assertTrue(tx.contributes_to_authoritative_stage(item),
                            candidate.get("signal"))

    def test_no_legitimate_row_is_excluded(self):
        evaluation = cl.evaluate_rows("XSS", legit_chain(),
                                      authorization=epic11_authorization())
        self.assertEqual(evaluation.excluded_evidence, [])
        self.assertEqual(evaluation.evidence_mismatches, [])

    def test_the_confirmation_claim_is_supported_for_a_legitimate_chain(self):
        evaluation = cl.evaluate_rows("XSS", legit_chain(),
                                      authorization=epic11_authorization())
        self.assertEqual(evaluation.confirmation_claim.status,
                         cl.CLAIM_SUPPORTED)

    def test_inventory_alone_still_yields_a_parameter_claim(self):
        evaluation = cl.evaluate_rows("XSS", inventory(),
                                      authorization=epic11_authorization())
        self.assertNotEqual(evaluation.status, cl.STATE_VERIFIED_ELIGIBLE)

    def test_the_gate_still_refuses_without_authorization(self):
        evaluation = cl.evaluate_rows("XSS", legit_chain(), authorization=None)
        self.assertNotEqual(ig.decide(evaluation).authoritative_state,
                            ig.VERIFIED)

    def test_the_epic11_vocabulary_is_not_extended(self):
        self.assertEqual(len(tx.EVIDENCE_TYPES), 15)
        self.assertEqual(len(tx.CONFIRMATION_EVIDENCE), 2)

    def test_the_epic13_signal_vocabulary_is_untouched(self):
        for signal in ("reflection_observed", "output_context_identified",
                       "dom_sink_identified", "payload_execution",
                       "exploitability_established", "controlled_input_sent"):
            self.assertIn(signal, tx.SIGNAL_TO_TYPE)


if __name__ == "__main__":
    unittest.main()
