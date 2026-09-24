"""EPIC14 §15/§14/§19 — the API/persistence trust boundary and the attack model."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.runtime_store import (  # noqa: E402
    EvidenceTrustError, RuntimeStore)
from tests.epic14_fixtures import (  # noqa: E402
    advisory_confirmation, authorization, forged_declared_type,
    forged_exploitability, inventory, legit_chain, legit_execution,
    legacy_confirmation, row, unknown_signal_strong_type)


class TestPersistenceBoundary(unittest.TestCase):
    """§15: the write boundary enforces the invariant, not the caller."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = RuntimeStore(Path(self.tmp.name))

    def test_a_mislabelled_row_is_refused(self):
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence(forged_declared_type())

    def test_the_refusal_names_both_types(self):
        with self.assertRaises(EvidenceTrustError) as ctx:
            self.store.record_evidence(forged_declared_type())
        message = str(ctx.exception)
        self.assertIn(tx.PAYLOAD_EXECUTION, message)
        self.assertIn(tx.PARAMETER_OBSERVED, message)

    def test_the_refusal_names_the_signal(self):
        with self.assertRaises(EvidenceTrustError) as ctx:
            self.store.record_evidence(forged_declared_type())
        self.assertIn("xss_parameter_inventory", str(ctx.exception))

    def test_an_exploitability_stamp_is_refused(self):
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence(forged_exploitability())

    def test_an_unknown_signal_with_a_strong_stamp_is_refused(self):
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence(unknown_signal_strong_type())

    def test_an_agreeing_stamp_is_persisted(self):
        evidence_id = self.store.record_evidence(
            row("reflection_observed", ref="obs-act-1",
                job="job-xss-verify", action_id="act-1",
                etype=tx.REFLECTION_OBSERVED))
        self.assertTrue(evidence_id)

    def test_an_ordinary_observation_row_is_persisted(self):
        self.assertTrue(self.store.record_evidence(
            row("xss_parameter_inventory", ref="obs-inv-1")))

    def test_a_confirmation_row_without_attestation_is_refused(self):
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence({"id": "e1",
                                        "signal": "payload_execution",
                                        "type": "observation"})

    def test_a_confirmation_row_with_attestation_is_persisted(self):
        self.assertTrue(self.store.record_evidence(legit_execution()))

    def test_the_attestation_requires_a_job_id(self):
        bad = dict(legit_execution(), job_id="")
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence(bad)

    def test_the_attestation_requires_an_observation_ref(self):
        bad = dict(legit_execution(), observation_ref="")
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence(bad)

    def test_a_declared_confirmation_type_without_a_signal_is_refused(self):
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence({"id": "e3", "signal": "",
                                        "evidence_type":
                                        tx.PAYLOAD_EXECUTION})

    def test_a_row_with_no_signal_is_persisted_but_unclassifiable(self):
        evidence_id = self.store.record_evidence({"id": "e4",
                                                  "detail": "no signal"})
        self.assertTrue(evidence_id)
        self.assertEqual(tx.classify_row({"id": "e4"}).evidence_type,
                         tx.UNCLASSIFIED_OBSERVATION)

    def test_the_error_is_a_value_error_for_callers(self):
        self.assertTrue(issubclass(EvidenceTrustError, ValueError))

    def test_a_non_confirmation_row_needs_no_attestation(self):
        self.assertTrue(self.store.record_evidence(
            {"id": "e2", "signal": "response_observed"}))

    def test_the_store_never_writes_a_refused_row(self):
        before = self.store.evidence_rows() if hasattr(
            self.store, "evidence_rows") else None
        with self.assertRaises(EvidenceTrustError):
            self.store.record_evidence(forged_declared_type())
        after = self.store.evidence_rows() if hasattr(
            self.store, "evidence_rows") else None
        self.assertEqual(before, after)


class TestSerialisationAndDeserialisation(unittest.TestCase):
    """§15: a round trip through storage cannot upgrade a type."""

    def test_a_mismatched_row_survives_as_json_without_upgrading(self):
        payload = json.loads(json.dumps(forged_declared_type()))
        item = tx.classify_row(payload)
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)
        self.assertTrue(item.has_mismatch)

    def test_a_deserialised_row_keeps_its_declared_metadata(self):
        payload = json.loads(json.dumps(forged_declared_type()))
        item = tx.classify_row(payload)
        self.assertEqual(item.declared_evidence_type, tx.PAYLOAD_EXECUTION)

    def test_a_direct_evidence_item_construction_cannot_confirm(self):
        """A caller who constructs the item by hand gets no confirmation."""
        item = tx.EvidenceItem(
            evidence_id="forged", evidence_type=tx.PAYLOAD_EXECUTION,
            stage=tx.STAGE_EXPLOITABILITY, raw_type="observation",
            raw_signal="payload_execution")
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_direct_construction_without_provenance_is_not_eligible(self):
        item = tx.EvidenceItem(
            evidence_id="forged", evidence_type=tx.EXPLOITABILITY_ESTABLISHED,
            stage=tx.STAGE_EXPLOITABILITY, raw_type="observation",
            raw_signal="exploitability_established")
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_direct_construction_has_unknown_provenance(self):
        """A hand-built item carries no provenance: it is UNKNOWN, and so it
        can never be confirmation evidence (fail closed)."""
        item = tx.EvidenceItem(
            evidence_id="forged", evidence_type=tx.PAYLOAD_EXECUTION,
            stage=tx.STAGE_EXPLOITABILITY, raw_type="observation",
            raw_signal="payload_execution")
        self.assertEqual(item.provenance_class, tx.PROVENANCE_UNKNOWN)
        self.assertNotIn(item.provenance_class,
                         tx.TRUSTED_PROVENANCE_CLASSES)
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_hand_built_row_is_still_classified_from_its_signal(self):
        item = tx.classify_row({"id": "forged",
                                "signal": "xss_parameter_inventory",
                                "evidence_type": tx.PAYLOAD_EXECUTION})
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_a_bare_row_with_a_confirmation_signal_has_no_trusted_provenance(self):
        """A row that is only a signal is not an observation: UNKNOWN."""
        item = tx.classify_row({"id": "forged",
                                "signal": "payload_execution"})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_UNKNOWN)
        self.assertFalse(item.is_confirmation_eligible)

    def test_a_bare_row_with_a_confirmation_stamp_is_legacy(self):
        item = tx.classify_row({"id": "forged",
                                "evidence_type": tx.PAYLOAD_EXECUTION})
        self.assertEqual(item.provenance_class, tx.PROVENANCE_LEGACY)
        self.assertFalse(item.is_confirmation_eligible)

    def test_an_imported_row_is_legacy_and_cannot_confirm(self):
        imported = {"id": "imported-1", "evidence_type": tx.PAYLOAD_EXECUTION,
                    "detail": "imported from an old export"}
        self.assertFalse(tx.classify_row(imported).is_confirmation_eligible)

    def test_a_replayed_row_is_classified_the_same_way(self):
        first = tx.classify_row(legit_execution())
        second = tx.classify_row(json.loads(json.dumps(legit_execution())))
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_a_replayed_mismatch_stays_a_mismatch(self):
        row_payload = json.loads(json.dumps(forged_declared_type()))
        self.assertEqual(tx.classify_row(row_payload).mismatch_reason,
                         tx.MISMATCH_STRONGER)


class TestLlmBoundary(unittest.TestCase):
    """§14: LLM output is advisory; it can never escalate evidence."""

    def test_an_llm_execution_claim_is_not_confirmation_evidence(self):
        item = tx.classify_row(advisory_confirmation())
        self.assertFalse(item.is_confirmation_eligible)

    def test_an_llm_evidence_type_field_is_not_authoritative(self):
        item = tx.classify_row({
            "id": "llm-1", "type": "llm_insight",
            "evidence_type": tx.PAYLOAD_EXECUTION,
            "detail": "the model says payload_execution"})
        self.assertNotEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_an_llm_signal_stamp_pair_is_a_mismatch(self):
        item = tx.classify_row({
            "id": "llm-2", "type": "llm_insight",
            "signal": "xss_parameter_inventory",
            "evidence_type": tx.PAYLOAD_EXECUTION})
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)
        self.assertTrue(item.has_mismatch)

    def test_an_llm_claim_of_confirmation_does_not_confirm(self):
        rows = inventory() + [advisory_confirmation()]
        evaluation = cl.evaluate_rows("XSS", rows,
                                      authorization=authorization())
        self.assertNotEqual(evaluation.confirmation_claim.status,
                            cl.CLAIM_SUPPORTED)

    def test_an_llm_summary_cannot_influence_classification(self):
        item = tx.classify_row({
            "id": "llm-3", "type": "observation",
            "signal": "xss_parameter_inventory",
            "detail": "PAYLOAD_EXECUTION CONFIRMED — exploitability high"})
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_an_llm_confidence_field_cannot_influence_classification(self):
        item = tx.classify_row({
            "id": "llm-4", "signal": "xss_parameter_inventory",
            "confidence": "certain", "detail": "confirmed"})
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_an_llm_confidence_field_cannot_influence_the_claim(self):
        rows = inventory() + [dict(row("xss_parameter_inventory", ref="o-c",
                                       confidence="certain",
                                       detail="confirmed"))]
        evaluation = cl.evaluate_rows("XSS", rows,
                                      authorization=authorization())
        self.assertNotEqual(evaluation.confirmation_claim.status,
                            cl.CLAIM_SUPPORTED)

    def test_the_runtime_keeps_evidence_candidates_deterministic(self):
        """Phase 12 boundary, re-pinned by EPIC14: the LLM proposes reasoning
        only; the merged analysis never takes LLM evidence candidates."""
        source = (Path(__file__).resolve().parents[1]
                  / "backend/research_agents/runtime.py").read_text()
        self.assertIn("evidence candidates remain deterministic", source)

    def test_the_llm_schema_is_not_an_authority_path(self):
        """The merge assigns reasoning/hypotheses, never evidence_candidates."""
        source = (Path(__file__).resolve().parents[1]
                  / "backend/research_agents/runtime.py").read_text()
        merge = source.split("evidence candidates remain deterministic")[1]
        merge = merge.split("return merged, meta")[0]
        self.assertNotIn('merged["evidence_candidates"]', merge)


class TestAdversarialCases(unittest.TestCase):
    """§19: the fifteen adversarial cases, each with its expected outcome."""

    def gate(self, rows, cls="XSS"):
        return ig.decide(cl.evaluate_rows(cls, rows,
                                          authorization=authorization()))

    def test_1_parameter_signal_plus_execution_stamp(self):
        result = self.gate(inventory() + [forged_declared_type()])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)
        self.assertTrue(result.evidence_mismatches)

    def test_2_reflection_signal_plus_exploitability_stamp(self):
        result = self.gate(inventory() + [forged_exploitability()])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)
        self.assertTrue(result.evidence_mismatches)

    def test_3_cors_signal_plus_confirmation_evidence(self):
        rows = [row("response_observed", ref="c1", category="CORS",
                    etype=tx.PAYLOAD_EXECUTION)]
        result = self.gate(rows, cls="CORS")
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)
        self.assertTrue(result.evidence_mismatches)

    def test_4_unknown_signal_plus_strong_type(self):
        result = self.gate(inventory() + [unknown_signal_strong_type()])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)

    def test_5_advisory_row_plus_confirmation_evidence(self):
        result = self.gate(inventory() + [advisory_confirmation()])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)
        self.assertTrue(result.excluded_evidence)

    def test_6_llm_created_evidence_object(self):
        rows = inventory() + [{"id": "llm-e", "type": "llm_insight",
                               "signal": "payload_execution",
                               "evidence_type": tx.PAYLOAD_EXECUTION,
                               "detail": "confirmed"}]
        result = self.gate(rows)
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)

    def test_7_api_created_evidence_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RuntimeStore(Path(tmp))
            with self.assertRaises(EvidenceTrustError):
                store.record_evidence(forged_declared_type())
            with self.assertRaises(EvidenceTrustError):
                store.record_evidence({"id": "api-1",
                                       "signal": "payload_execution"})

    def test_8_imported_legacy_row(self):
        result = self.gate(inventory() + [legacy_confirmation()])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)
        self.assertTrue(result.excluded_evidence)

    def test_9_deserialised_forged_object(self):
        forged = json.loads(json.dumps(forged_declared_type()))
        result = self.gate(inventory() + [forged])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)

    def test_10_duplicate_forged_rows(self):
        from tests.epic14_fixtures import duplicate_forgeries
        result = self.gate(inventory() + duplicate_forgeries(5))
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)

    def test_11_mixed_legitimate_and_forged_rows(self):
        result = self.gate(legit_chain() + [forged_declared_type()])
        self.assertTrue(result.evidence_mismatches)
        self.assertTrue(result.excluded_evidence)

    def test_12_forged_provenance(self):
        rows = inventory() + [row("payload_execution", ref="obs-prov-1",
                                  provenance_class="ACQUISITION_DERIVED")]
        result = self.gate(rows)
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)

    def test_13_missing_provenance(self):
        result = self.gate(inventory() + [{"id": "e",
                                           "signal": "payload_execution",
                                           "evidence_type":
                                           tx.PAYLOAD_EXECUTION}])
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)

    def test_14_contradictory_signal_and_type(self):
        item = tx.classify_row(forged_declared_type())
        self.assertTrue(item.has_mismatch)
        self.assertEqual(item.evidence_type, tx.PARAMETER_OBSERVED)

    def test_15_lifecycle_transition_from_forged_evidence(self):
        rows = inventory() + [forged_declared_type(),
                              forged_exploitability()]
        result = self.gate(rows)
        self.assertNotEqual(result.authoritative_state, ig.VERIFIED)
        self.assertEqual(len(result.evidence_mismatches), 2)

    def test_no_adversarial_case_produces_a_confirmed_finding(self):
        from tests.epic14_fixtures import ATTACKS
        for label, forged in ATTACKS.items():
            result = self.gate(inventory() + forged)
            self.assertNotEqual(result.authoritative_state, ig.VERIFIED,
                                label)
            self.assertFalse(result.confirmed, label)


class TestCredentialAndSecretHygiene(unittest.TestCase):
    """§26: no credential leakage into the new records."""

    def test_the_mismatch_record_carries_no_detail_text(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertNotIn("detail", record)

    def test_the_mismatch_record_is_field_bounded(self):
        record = tx.classify_row(forged_declared_type()).mismatch
        self.assertEqual(set(record), {
            "kind", "class", "signal", "declared_evidence_type",
            "authoritative_evidence_type", "source", "evidence_id",
            "observation_id", "job_id", "candidate_id", "observed_at",
            "classifier_version", "provenance_class"})

    def test_the_provenance_record_is_field_bounded(self):
        provenance = tx.classify_row(legit_execution()).provenance
        self.assertEqual(set(provenance), {
            "provenance_class", "classifier_version", "rule_version",
            "source", "observation_key", "evidence_job", "candidate_id",
            "authorization_ref", "scope_ref", "agent"})

    def test_the_provenance_record_states_the_class(self):
        provenance = tx.classify_row(legit_execution()).provenance
        self.assertIn(provenance["provenance_class"],
                      tx.PROVENANCE_CLASSES)

    def test_a_secret_shaped_detail_is_not_copied_into_the_record(self):
        secret = "Bearer eyJhbGciOiJIUzI1NiJ9.SECRET.SIGNATURE"
        row_payload = forged_declared_type()
        row_payload["detail"] = secret
        record = tx.classify_row(row_payload).mismatch
        self.assertNotIn("SECRET", json.dumps(record))


if __name__ == "__main__":
    unittest.main()
