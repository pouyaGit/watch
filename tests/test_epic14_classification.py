"""EPIC14 §3/§4/§8 — authoritative classification vs a declared stamp."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from tests.epic14_fixtures import (  # noqa: E402
    advisory_confirmation, forged_declared_type, forged_provenance,
    inventory, legit_chain, legit_execution, legit_reflection,
    legacy_confirmation, row, unknown_signal_strong_type)


class TestTheSignalRegistryIsAuthoritative(unittest.TestCase):
    """§3: the registry decides; a row's stamp is metadata."""

    def test_every_registry_signal_classifies_to_its_registry_type(self):
        for signal, expected in tx.SIGNAL_TO_TYPE.items():
            item = tx.classify_row({"id": "e", "signal": signal})
            self.assertEqual(item.evidence_type, expected, signal)

    def test_a_stronger_declared_stamp_is_never_honoured(self):
        item = tx.classify_row(forged_declared_type())
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_the_declared_stamp_is_preserved_as_metadata(self):
        item = tx.classify_row(forged_declared_type())
        self.assertEqual(item.declared_evidence_type, tx.PAYLOAD_EXECUTION)

    def test_the_authoritative_type_property_matches_the_classification(self):
        item = tx.classify_row(forged_declared_type())
        self.assertEqual(item.authoritative_evidence_type,
                         tx.PARAMETER_OBSERVED)

    def test_a_forged_execution_stamp_is_not_confirmation_evidence(self):
        item = tx.classify_row(forged_declared_type())
        self.assertFalse(item.is_confirmation_evidence)

    def test_a_forged_execution_stamp_cannot_confirm(self):
        item = tx.classify_row(forged_declared_type())
        self.assertFalse(item.is_confirmation_eligible)

    def test_an_agreeing_stamp_is_accepted_without_a_mismatch(self):
        item = tx.classify_row(row("reflection_observed", ref="r1",
                                   etype=tx.REFLECTION_OBSERVED))
        self.assertEqual(item.evidence_type, tx.REFLECTION_OBSERVED)
        self.assertFalse(item.has_mismatch)

    def test_a_weaker_declared_stamp_does_not_weaken_the_registry_type(self):
        item = tx.classify_row(row("payload_execution", ref="r2",
                                   etype=tx.PARAMETER_OBSERVED))
        self.assertEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_a_weaker_declared_stamp_is_still_recorded_as_a_mismatch(self):
        item = tx.classify_row(row("payload_execution", ref="r2",
                                   etype=tx.PARAMETER_OBSERVED))
        self.assertEqual(item.mismatch_reason, tx.MISMATCH_WEAKER)

    def test_an_unrelated_declared_stamp_is_recorded_as_unrelated(self):
        item = tx.classify_row(row("reflection_observed", ref="r3",
                                   etype=tx.OUTPUT_CONTEXT_IDENTIFIED))
        self.assertEqual(item.evidence_type, tx.REFLECTION_OBSERVED)
        self.assertEqual(item.mismatch_reason, tx.MISMATCH_UNRELATED)

    def test_the_registry_type_decides_the_stage(self):
        item = tx.classify_row(forged_declared_type())
        self.assertEqual(item.stage, tx.STAGE_OBSERVED)

    def test_the_declared_stamp_cannot_move_the_stage(self):
        item = tx.classify_row(forged_declared_type())
        self.assertNotEqual(item.stage, tx.EVIDENCE_STAGE[tx.PAYLOAD_EXECUTION])

    def test_a_missing_declared_type_is_not_a_mismatch(self):
        item = tx.classify_row(row("reflection_observed", ref="r4"))
        self.assertFalse(item.has_mismatch)
        self.assertEqual(item.declared_evidence_type, "")

    def test_an_out_of_vocabulary_declared_type_is_not_a_mismatch(self):
        """It is not a stamp at all: it is not inside the closed set."""
        item = tx.classify_row(row("reflection_observed", ref="r5",
                                   etype="TOTALLY_MADE_UP"))
        self.assertEqual(item.evidence_type, tx.REFLECTION_OBSERVED)
        self.assertEqual(item.declared_evidence_type, "")


class TestUnknownSignalsFailClosed(unittest.TestCase):
    """§8: an unknown signal never infers a type from anything else."""

    def test_an_unknown_signal_is_unclassified(self):
        item = tx.classify_row(unknown_signal_strong_type())
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_an_unknown_signal_records_the_reason(self):
        item = tx.classify_row(unknown_signal_strong_type())
        self.assertTrue(item.unclassified_reason.startswith(
            "unrecognised_signal:"))

    def test_an_unknown_signal_cannot_use_its_stamp(self):
        item = tx.classify_row(unknown_signal_strong_type())
        self.assertNotEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_an_unknown_signal_with_a_stamp_is_a_mismatch(self):
        item = tx.classify_row(unknown_signal_strong_type())
        self.assertEqual(item.mismatch_reason, tx.MISMATCH_UNKNOWN_SIGNAL)

    def test_an_unknown_signal_never_reaches_a_stage(self):
        item = tx.classify_row(unknown_signal_strong_type())
        self.assertEqual(item.stage, tx.STAGE_AUXILIARY)

    def test_row_text_cannot_infer_a_type(self):
        item = tx.classify_row({"id": "e", "signal": "mystery",
                                "detail": "PAYLOAD_EXECUTION confirmed!"})
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_an_llm_description_cannot_infer_a_type(self):
        item = tx.classify_row({
            "id": "e", "type": "observation", "signal": "mystery",
            "detail": "the model believes this is payload_execution"})
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_no_signal_and_no_type_is_unclassified(self):
        item = tx.classify_row({"id": "e"})
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_a_negative_family_signal_is_negative_not_unknown(self):
        item = tx.classify_row({"id": "e", "signal": "dom_sink_not_observed"})
        self.assertEqual(item.evidence_type, tx.NEGATIVE_EVIDENCE)

    def test_a_not_tested_family_signal_is_not_tested(self):
        item = tx.classify_row({"id": "e", "signal": "parameter_not_tested"})
        self.assertEqual(item.evidence_type, tx.NEGATIVE_EVIDENCE)
        self.assertEqual(item.negative_kind, tx.NOT_TESTED)

    def test_a_not_observed_family_signal_is_not_observed(self):
        item = tx.classify_row({"id": "e", "signal": "output_context_not_observed"})
        self.assertEqual(item.negative_kind, tx.NOT_OBSERVED)

    def test_an_absent_family_signal_is_negative(self):
        item = tx.classify_row({"id": "e", "signal": "marker_absent"})
        self.assertEqual(item.evidence_type, tx.NEGATIVE_EVIDENCE)

    def test_a_negative_family_never_becomes_confirmation_evidence(self):
        for signal in ("payload_execution_not_observed",
                       "exploitability_not_established",
                       "dom_sink_not_identified"):
            item = tx.classify_row({"id": "e", "signal": signal})
            self.assertEqual(item.evidence_type, tx.NEGATIVE_EVIDENCE, signal)
            self.assertFalse(item.is_confirmation_eligible, signal)


class TestDeclaredOnlyRows(unittest.TestCase):
    """A stamp with no signal is honoured for typing but never for confirming."""

    def test_a_stamp_without_a_signal_is_typed(self):
        item = tx.classify_row({"id": "e", "evidence_type":
                                tx.PARAMETER_OBSERVED})
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_a_stamp_without_a_signal_has_no_mismatch(self):
        item = tx.classify_row({"id": "e", "evidence_type":
                                tx.PARAMETER_OBSERVED})
        self.assertFalse(item.has_mismatch)

    def test_a_confirmation_stamp_without_a_signal_is_not_eligible(self):
        item = tx.classify_row(legacy_confirmation())
        self.assertEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_legacy_row_is_classified_as_legacy(self):
        item = tx.classify_row(legacy_confirmation())
        self.assertEqual(item.provenance_class, tx.PROVENANCE_LEGACY)

    def test_a_knowledge_row_is_a_knowledge_reference(self):
        item = tx.classify_row({"id": "e", "type": "knowledge"})
        self.assertEqual(item.evidence_type, tx.KNOWLEDGE_REFERENCE)

    def test_a_llm_insight_row_is_a_knowledge_reference(self):
        item = tx.classify_row({"id": "e", "type": "llm_insight"})
        self.assertEqual(item.evidence_type, tx.KNOWLEDGE_REFERENCE)

    def test_an_llm_insight_row_is_advisory_provenance(self):
        item = tx.classify_row({"id": "e", "type": "llm_insight"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_ADVISORY)

    def test_a_malformed_row_is_still_malformed(self):
        item = tx.classify_row("not a row")
        self.assertEqual(item.evidence_type, tx.MALFORMED_EVIDENCE)

    def test_a_malformed_row_has_no_mismatch(self):
        item = tx.classify_row(object())
        self.assertEqual(item.mismatch, {})


class TestMismatchRecords(unittest.TestCase):
    """§5: the mismatch must be explicit, complete and auditable."""

    def test_the_record_names_the_kind(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["kind"], tx.MISMATCH_KIND)

    def test_the_record_names_the_class(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["class"], tx.MISMATCH_STRONGER)

    def test_the_record_names_the_signal(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["signal"], "xss_parameter_inventory")

    def test_the_record_names_both_types(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["declared_evidence_type"],
                         tx.PAYLOAD_EXECUTION)
        self.assertEqual(record["authoritative_evidence_type"],
                         tx.PARAMETER_OBSERVED)

    def test_the_record_names_the_classifier_version(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["classifier_version"],
                         tx.AUTHORITATIVE_CLASSIFIER_VERSION)

    def test_the_record_carries_the_evidence_id(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertTrue(record["evidence_id"])

    def test_the_record_carries_the_observation_id(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["observation_id"], "obs-forged-1")

    def test_the_record_carries_the_job_id(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(record["job_id"], "job-xss-source")

    def test_the_record_carries_the_candidate_id_when_present(self):
        record = tx.classify_row(forged_declared_type(
            )).mismatch
        self.assertEqual(record["candidate_id"], "")
        record2 = tx.classify_row(row("xss_parameter_inventory", ref="r",
                                      etype=tx.PAYLOAD_EXECUTION,
                                      candidate_id="cand-1")).mismatch
        self.assertEqual(record2["candidate_id"], "cand-1")

    def test_the_record_carries_the_provenance_class(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertIn(record["provenance_class"], tx.PROVENANCE_CLASSES)

    def test_the_record_is_empty_when_there_is_no_mismatch(self):
        self.assertEqual(tx.classify_row(legit_reflection()).mismatch, {})

    def test_the_record_is_serialisable(self):
        import json
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertTrue(json.dumps(record))

    def test_the_mismatch_appears_in_the_item_dict(self):
        payload = tx.classify_row(forged_declared_type()).to_dict()
        self.assertEqual(payload["mismatch"]["class"],
                         tx.MISMATCH_STRONGER)
        self.assertEqual(payload["declared_evidence_type"],
                         tx.PAYLOAD_EXECUTION)
        self.assertEqual(payload["authoritative_evidence_type"],
                         tx.PARAMETER_OBSERVED)

    def test_the_item_dict_states_confirmation_eligibility(self):
        payload = tx.classify_row(forged_declared_type()).to_dict()
        self.assertFalse(payload["confirmation_eligible"])


class TestTheMismatchClassesAreDeterministic(unittest.TestCase):
    def test_a_stage_up_stamp_is_declared_stronger(self):
        item = tx.classify_row(row("xss_parameter_inventory", ref="r",
                                   etype=tx.REFLECTION_OBSERVED))
        self.assertEqual(item.mismatch_reason, tx.MISMATCH_STRONGER)

    def test_a_stage_down_stamp_is_declared_weaker(self):
        item = tx.classify_row(row("reflection_observed", ref="r",
                                   etype=tx.PARAMETER_OBSERVED))
        self.assertEqual(item.mismatch_reason, tx.MISMATCH_WEAKER)

    def test_a_same_stage_stamp_is_declared_unrelated(self):
        item = tx.classify_row(row("reflection_observed", ref="r",
                                   etype=tx.DOM_SINK_IDENTIFIED))
        self.assertEqual(item.mismatch_reason, tx.MISMATCH_UNRELATED)

    def test_the_class_is_stable_across_repeats(self):
        first = tx.classify_row(forged_declared_type()).mismatch_reason
        for _ in range(5):
            self.assertEqual(
                tx.classify_row(forged_declared_type()).mismatch_reason, first)


class TestBulkClassification(unittest.TestCase):
    def test_classify_rows_keeps_every_row(self):
        items = tx.classify_rows(legit_chain() + [forged_declared_type()])
        self.assertEqual(len(items), len(legit_chain()) + 1)

    def test_classify_rows_reports_the_forgery(self):
        items = tx.classify_rows(legit_chain() + [forged_declared_type()])
        mismatched = [i for i in items if i.mismatch]
        self.assertEqual(len(mismatched), 1)

    def test_unique_items_drops_duplicate_events(self):
        rows = inventory(2) + inventory(2)
        items = tx.classify_rows(rows)
        self.assertEqual(len(tx.unique_items(items)), 2)

    def test_duplicate_forgeries_are_one_unique_event(self):
        from tests.epic14_fixtures import duplicate_forgeries
        items = tx.classify_rows(duplicate_forgeries(5))
        self.assertEqual(len(tx.unique_items(items)), 1)

    def test_a_forged_duplicate_cannot_multiply_evidence(self):
        from tests.epic14_fixtures import duplicate_forgeries
        items = tx.classify_rows(duplicate_forgeries(5))
        unique = tx.unique_items(items)
        self.assertEqual(sum(1 for i in unique if i.mismatch), 0)
        self.assertEqual(unique[0].evidence_type, tx.PAYLOAD_EXECUTION)

    def test_stage_reached_ignores_a_forged_stronger_stamp(self):
        items = tx.classify_rows(inventory() + [forged_declared_type()])
        self.assertEqual(tx.stage_reached(items), tx.STAGE_OBSERVED)

    def test_stage_reached_counts_a_legitimate_chain(self):
        items = tx.classify_rows(legit_chain())
        self.assertEqual(tx.stage_reached(items),
                         tx.STAGE_EXPLOITABILITY)

    def test_negative_evidence_is_reported(self):
        items = tx.classify_rows([{"id": "e", "signal":
                                   "reflection_not_observed"}])
        self.assertEqual(len(tx.negative_evidence(items)), 1)


class TestVocabularyIsClosed(unittest.TestCase):
    def test_the_evidence_vocabulary_is_unchanged(self):
        self.assertEqual(len(tx.EVIDENCE_TYPES), 15)

    def test_the_confirmation_set_is_unchanged(self):
        self.assertEqual(tx.CONFIRMATION_EVIDENCE,
                         frozenset({tx.PAYLOAD_EXECUTION,
                                    tx.EXPLOITABILITY_ESTABLISHED}))

    def test_the_taxonomy_rule_version_is_unchanged(self):
        """EPIC14 hardens precedence; it does not rewrite the taxonomy."""
        self.assertEqual(tx.TAXONOMY_RULE_VERSION,
                         "epic11-evidence-taxonomy-1")

    def test_the_classifier_version_is_the_epic14_one(self):
        self.assertEqual(tx.AUTHORITATIVE_CLASSIFIER_VERSION,
                         "epic14-authoritative-classification-1")

    def test_provenance_classes_are_closed(self):
        self.assertEqual(len(tx.PROVENANCE_CLASSES), 7)

    def test_the_trusted_provenance_set_is_closed(self):
        self.assertEqual(
            tx.TRUSTED_PROVENANCE_CLASSES,
            frozenset({tx.PROVENANCE_OBSERVATION, tx.PROVENANCE_ACQUISITION,
                       tx.PROVENANCE_VERIFICATION}))

    def test_advisory_is_not_a_trusted_provenance(self):
        self.assertNotIn(tx.PROVENANCE_ADVISORY, tx.TRUSTED_PROVENANCE_CLASSES)

    def test_legacy_is_not_a_trusted_provenance(self):
        self.assertNotIn(tx.PROVENANCE_LEGACY, tx.TRUSTED_PROVENANCE_CLASSES)

    def test_unknown_is_not_a_trusted_provenance(self):
        self.assertNotIn(tx.PROVENANCE_UNKNOWN, tx.TRUSTED_PROVENANCE_CLASSES)


if __name__ == "__main__":
    unittest.main()
