"""EPIC14 §6/§7/§16 — provenance classes, trust and confirmation eligibility."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from tests.epic14_fixtures import (  # noqa: E402
    ACTION_ID, MARKER, VERIFY_JOB, advisory_confirmation, forged_provenance,
    inventory, legit_context, legit_execution, legit_reflection,
    legacy_confirmation, row)


class TestProvenanceDerivation(unittest.TestCase):
    """§6: provenance comes from structure, never from a row's own claim."""

    def test_an_observation_row_is_observation_derived(self):
        item = tx.classify_row(row("reflection_observed", ref="r1"))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_OBSERVATION)

    def test_a_row_with_an_acquisition_marker_is_acquisition_derived(self):
        item = tx.classify_row(row("reflection_observed", ref="r2",
                                   marker=MARKER))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ACQUISITION)

    def test_a_row_with_an_action_id_is_verification_derived(self):
        item = tx.classify_row(row("reflection_observed", ref="r3",
                                   action_id=ACTION_ID))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ACQUISITION
                         if "acq" in ACTION_ID else
                         tx.PROVENANCE_VERIFICATION)

    def test_a_verification_job_row_is_verification_derived(self):
        item = tx.classify_row(row("output_context_identified", ref="r4",
                                   job=VERIFY_JOB, action_id="act-9"))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_VERIFICATION)

    def test_a_cve_knowledge_row_is_research_derived(self):
        item = tx.classify_row({"id": "e", "type": "knowledge",
                                "signal": "knowledge_reference",
                                "source": "cve_research"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_RESEARCH)

    def test_an_llm_insight_row_is_advisory(self):
        item = tx.classify_row({"id": "e", "type": "llm_insight",
                                "signal": "reflection_observed"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_an_advisor_id_makes_a_row_advisory(self):
        item = tx.classify_row(row("reflection_observed", ref="r5",
                                   advisory_id="adv-1"))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_an_advisor_mode_makes_a_row_advisory(self):
        item = tx.classify_row(row("reflection_observed", ref="r6",
                                   advisory_mode="EXPLANATION"))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_an_openrouter_agent_makes_a_row_advisory(self):
        item = tx.classify_row(row("reflection_observed", ref="r7",
                                   agent="openrouter-free"))
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_a_row_with_no_signal_and_no_type_is_legacy(self):
        item = tx.classify_row(legacy_confirmation())
        self.assertEqual(item.provenance_class, tx.PROVENANCE_LEGACY)

    def test_an_imported_row_with_only_a_type_is_legacy(self):
        item = tx.classify_row({"id": "e", "type": "observation"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_LEGACY)

    def test_a_row_with_a_signal_is_never_legacy(self):
        item = tx.classify_row({"id": "e", "signal": "mystery_signal"})
        self.assertNotEqual(item.provenance_class, tx.PROVENANCE_LEGACY)

    def test_the_class_is_one_of_the_closed_vocabulary(self):
        for candidate in (legit_reflection(), advisory_confirmation(),
                          legacy_confirmation(), forged_provenance()):
            item = tx.classify_row(candidate)
            self.assertIn(item.provenance_class, tx.PROVENANCE_CLASSES)

    def test_the_class_is_deterministic(self):
        first = tx.classify_row(legit_reflection()).provenance_class
        for _ in range(5):
            self.assertEqual(
                tx.classify_row(legit_reflection()).provenance_class, first)
        self.assertIn(first, tx.PROVENANCE_CLASSES)

    def test_an_acquisition_marker_makes_the_row_acquisition_derived(self):
        self.assertEqual(
            tx.classify_row(legit_reflection()).provenance_class,
            tx.PROVENANCE_ACQUISITION)

    def test_a_malformed_row_is_unknown_provenance(self):
        self.assertEqual(tx.classify_row("nope").provenance_class,
                         tx.PROVENANCE_UNKNOWN)

    def test_advisory_wins_over_observation_structure(self):
        """An LLM row cannot buy trust by looking like an observation."""
        item = tx.classify_row({
            "id": "e", "type": "observation", "signal": "reflection_observed",
            "job_id": "j", "observation_ref": "o", "agent": "llm"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)


class TestForgedProvenance(unittest.TestCase):
    """§6: a row cannot declare its own provenance class."""

    def test_a_declared_provenance_class_is_ignored(self):
        item = tx.classify_row(forged_provenance())
        self.assertNotEqual(item.provenance_class, tx.PROVENANCE_ACQUISITION)

    def test_a_declared_class_does_not_buy_confirmation(self):
        item = tx.classify_row(forged_provenance())
        self.assertEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)
        self.assertTrue(item.is_confirmation_eligible)  # shaped like a real row

    def test_a_declared_class_never_appears_in_the_derived_class(self):
        """The derivation reads structure only; the declaration is inert."""
        item = tx.classify_row({
            "id": "e", "type": "llm_insight", "signal": "payload_execution",
            "provenance_class": "OBSERVATION_DERIVED"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_a_declared_provenance_mapping_is_ignored(self):
        item = tx.classify_row({
            "id": "e", "type": "llm_insight", "signal": "payload_execution",
            "provenance": {"class": "VERIFICATION_DERIVED",
                           "source": "evidence_taxonomy"}})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_the_recorded_provenance_names_the_derived_class(self):
        item = tx.classify_row(legit_execution())
        self.assertEqual(item.provenance.get("provenance_class"),
                         item.provenance_class)

    def test_the_recorded_provenance_names_the_classifier_version(self):
        item = tx.classify_row(legit_execution())
        self.assertEqual(item.provenance.get("classifier_version"),
                         tx.AUTHORITATIVE_CLASSIFIER_VERSION)


class TestConfirmationEligibility(unittest.TestCase):
    """§16/§17: who may support a confirmation claim."""

    def test_a_legitimate_execution_row_is_eligible(self):
        item = tx.classify_row(legit_execution())
        self.assertTrue(item.is_confirmation_eligible)

    def test_an_execution_row_without_provenance_is_not_eligible(self):
        item = tx.classify_row(legacy_confirmation())
        self.assertFalse(item.is_confirmation_eligible)

    def test_an_advisory_execution_row_is_not_eligible(self):
        item = tx.classify_row(advisory_confirmation())
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_mismatched_execution_row_is_not_eligible(self):
        item = tx.classify_row(row("payload_execution", ref="r",
                                   etype=tx.PARAMETER_OBSERVED))
        self.assertTrue(item.mismatch_reason)
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_non_confirmation_type_is_never_confirmation_evidence(self):
        for candidate in (legit_reflection(), legit_context()):
            item = tx.classify_row(candidate)
            self.assertFalse(item.is_confirmation_evidence)
            self.assertFalse(item.is_confirmation_eligible)

    def test_a_negative_is_never_eligible(self):
        item = tx.classify_row({"id": "e",
                                "signal": "payload_execution_not_observed"})
        self.assertFalse(item.is_confirmation_eligible)

    def test_eligibility_requires_all_three_conditions(self):
        eligible = tx.classify_row(legit_execution())
        self.assertIn(eligible.evidence_type, tx.CONFIRMATION_EVIDENCE)
        self.assertFalse(eligible.has_mismatch)
        self.assertIn(eligible.provenance_class,
                      tx.TRUSTED_PROVENANCE_CLASSES)

    def test_exploitability_eligibility_mirrors_execution(self):
        legit = row("exploitability_established", ref="obs-act-4",
                    job=VERIFY_JOB, action_id=ACTION_ID)
        advisory = dict(advisory_confirmation(),
                        signal="exploitability_established")
        self.assertTrue(tx.classify_row(legit).is_confirmation_eligible)
        self.assertFalse(tx.classify_row(advisory).is_confirmation_eligible)

    def test_an_observation_derived_execution_row_is_eligible(self):
        """The runtime's own deterministic observation path is trusted."""
        item = tx.classify_row(row("payload_execution", ref="obs-prod-1"))
        self.assertTrue(item.is_confirmation_eligible)

    def test_eligibility_is_reproducible(self):
        for _ in range(5):
            self.assertTrue(
                tx.classify_row(legit_execution()).is_confirmation_eligible)


class TestEvidenceEscalationRule(unittest.TestCase):
    """§7: strength may only increase through a trusted transition."""

    def test_a_parameter_row_cannot_become_reflection_by_metadata(self):
        item = tx.classify_row(row("xss_parameter_inventory", ref="r",
                                   etype=tx.REFLECTION_OBSERVED))
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_a_parameter_row_cannot_become_execution_by_metadata(self):
        item = tx.classify_row(row("xss_parameter_inventory", ref="r",
                                   etype=tx.PAYLOAD_EXECUTION))
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_the_stage_never_advances_by_metadata(self):
        base = tx.classify_row(row("xss_parameter_inventory", ref="r"))
        stamped = tx.classify_row(row("xss_parameter_inventory", ref="r",
                                      etype=tx.PAYLOAD_EXECUTION))
        self.assertEqual(base.stage, stamped.stage)

    def test_a_chain_of_stamps_never_escalates(self):
        for declared in (tx.REFLECTION_OBSERVED,
                         tx.OUTPUT_CONTEXT_IDENTIFIED,
                         tx.DOM_SINK_IDENTIFIED, tx.PAYLOAD_EXECUTION,
                         tx.EXPLOITABILITY_ESTABLISHED,
                         tx.IMPACT_ESTABLISHED):
            item = tx.classify_row(row("xss_parameter_inventory", ref="r",
                                       etype=declared))
            self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED,
                             declared)

    def test_only_a_real_signal_carries_the_stronger_type(self):
        item = tx.classify_row(row("payload_execution", ref="r"))
        self.assertEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_the_stage_order_is_the_epic11_one(self):
        self.assertLess(tx.STAGE_OBSERVED, tx.STAGE_CONTROLLED)
        self.assertLess(tx.STAGE_CONTROLLED, tx.STAGE_REFLECTION)
        self.assertLess(tx.STAGE_REFLECTION, tx.STAGE_EXPLOITABILITY)
        self.assertLess(tx.STAGE_EXPLOITABILITY, tx.STAGE_IMPACT)

    def test_a_legitimate_chain_reaches_the_exploitability_stage(self):
        items = tx.classify_rows(inventory() + [legit_reflection(),
                                                legit_context(),
                                                legit_execution()])
        self.assertEqual(tx.stage_reached(items),
                         tx.STAGE_EXPLOITABILITY)


class TestLineageAndReproducibility(unittest.TestCase):
    """§16: 'why was this classified as PAYLOAD_EXECUTION?' must be answerable."""

    def test_a_legitimate_execution_row_records_its_signal(self):
        item = tx.classify_row(legit_execution())
        self.assertEqual(item.raw_signal, "payload_execution")

    def test_a_legitimate_execution_row_records_its_observation(self):
        item = tx.classify_row(legit_execution())
        self.assertEqual(item.observation_ref, "obs-act-3")

    def test_a_legitimate_execution_row_records_its_job(self):
        item = tx.classify_row(legit_execution())
        self.assertEqual(item.job_id, VERIFY_JOB)

    def test_a_legitimate_execution_row_records_its_rule_version(self):
        item = tx.classify_row(legit_execution())
        self.assertEqual(item.rule_version, tx.TAXONOMY_RULE_VERSION)

    def test_a_legitimate_execution_row_records_its_provenance_class(self):
        item = tx.classify_row(legit_execution())
        self.assertIn(item.provenance_class, tx.TRUSTED_PROVENANCE_CLASSES)

    def test_the_classification_is_reproducible_from_the_row_alone(self):
        first = tx.classify_row(legit_execution()).to_dict()
        second = tx.classify_row(legit_execution()).to_dict()
        self.assertEqual(first, second)

    def test_a_mismatch_classification_is_reproducible(self):
        row_a = row("xss_parameter_inventory", ref="r",
                    etype=tx.PAYLOAD_EXECUTION)
        self.assertEqual(tx.classify_row(row_a).mismatch,
                         tx.classify_row(row_a).mismatch)

    def test_the_observation_key_is_stable(self):
        self.assertEqual(tx.classify_row(legit_execution()).observation_key(),
                         tx.classify_row(legit_execution()).observation_key())


if __name__ == "__main__":
    unittest.main()
