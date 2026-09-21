"""EPIC6 Part 5: evidence bridge — ingestion, provenance, gap application."""

from __future__ import annotations

import unittest

from aec.evidence.state_machine import EvidenceGapState, initial_state
from aec.evidence_bridge.bridge import (
    SOURCE_MODES, IngestionFailure, apply_to_gap, ingest)
from aec.evidence_bridge.models import EvidenceRecord

RESULT = {
    "observation_id": "obs-1",
    "request_id": "obsreq-abc",
    "observed_fields": ["status_code", "content_type"],
    "missing_fields": ["response_headers"],
    "tick": 5,
    "source": "fixture-observer",
}


class TestIngestValidation(unittest.TestCase):
    def test_source_modes_exact(self):
        self.assertEqual(
            SOURCE_MODES, frozenset({"REAL_WATCH_DATA", "OFFLINE_FIXTURE"}))

    def test_empty_case_refused(self):
        with self.assertRaises(IngestionFailure):
            ingest("", "job-1", RESULT, "OFFLINE_FIXTURE", 1)

    def test_empty_job_refused(self):
        with self.assertRaises(IngestionFailure):
            ingest("case-1", "", RESULT, "OFFLINE_FIXTURE", 1)

    def test_unknown_source_mode_refused(self):
        with self.assertRaises(IngestionFailure):
            ingest("case-1", "job-1", RESULT, "LIVE", 1)

    def test_non_mapping_result_refused(self):
        with self.assertRaises(IngestionFailure):
            ingest("case-1", "job-1", "result", "OFFLINE_FIXTURE", 1)

    def test_missing_observation_id_refused(self):
        bad = dict(RESULT)
        del bad["observation_id"]
        with self.assertRaises(IngestionFailure):
            ingest("case-1", "job-1", bad, "OFFLINE_FIXTURE", 1)

    def test_no_observed_fields_refused(self):
        bad = dict(RESULT, observed_fields=[])
        with self.assertRaises(IngestionFailure):
            ingest("case-1", "job-1", bad, "OFFLINE_FIXTURE", 1)

    def test_malformed_missing_refused(self):
        bad = dict(RESULT, missing_fields="nope")
        with self.assertRaises(IngestionFailure):
            ingest("case-1", "job-1", bad, "OFFLINE_FIXTURE", 1)


class TestRecordShape(unittest.TestCase):
    def test_evidence_id_minted(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertTrue(record.evidence_id.startswith("ev-"))
        self.assertEqual(len(record.evidence_id), 15)

    def test_level_partial_when_missing(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.evidence_level, "PARTIAL")

    def test_level_complete_when_no_missing(self):
        clean = dict(RESULT, missing_fields=[])
        record = ingest("case-1", "job-1", clean, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.evidence_level, "COMPLETE")

    def test_source_propagated(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.source, "fixture-observer")

    def test_source_defaults_unknown(self):
        clean = dict(RESULT)
        del clean["source"]
        record = ingest("case-1", "job-1", clean, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.source, "unknown")

    def test_source_mode_carried(self):
        record = ingest("case-1", "job-1", RESULT, "REAL_WATCH_DATA", 1)
        self.assertEqual(record.source_mode, "REAL_WATCH_DATA")

    def test_artifact_reference_shape(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertTrue(record.artifact_reference.startswith("obs-1:"))

    def test_observation_fields_tuple(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.observation,
                         ("status_code", "content_type"))

    def test_missing_fields_carried(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.missing_fields, ("response_headers",))

    def test_integrity_digest_present(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(len(record.integrity), 64)

    def test_confidence_unstated(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.confidence, "unstated")

    def test_deterministic_ingest(self):
        first = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        second = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first, second)


class TestRedaction(unittest.TestCase):
    def test_sensitive_field_scrubbed(self):
        result = dict(RESULT, observed_fields=["set-cookie", "session_id"])
        record = ingest("case-1", "job-1", result, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.redaction_status, "scrubbed")

    def test_clean_fields_clean(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.redaction_status, "clean")

    def test_token_shaped_scrubbed(self):
        result = dict(RESULT,
                      observed_fields=["authorization-bearer-token-value"])
        record = ingest("case-1", "job-1", result, "OFFLINE_FIXTURE", 1)
        self.assertEqual(record.redaction_status, "scrubbed")


class TestRecordModel(unittest.TestCase):
    def test_to_dict_exact_keys(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        self.assertEqual(sorted(record.to_dict()), [
            "artifact_reference", "case_id", "confidence", "evidence_id",
            "evidence_level", "integrity", "job_id", "missing_fields",
            "observation", "redaction_status", "source", "source_mode",
            "tick"])

    def test_frozen(self):
        record = ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1)
        with self.assertRaises(Exception):
            record.source = "changed"  # type: ignore[misc]


class TestGapApplication(unittest.TestCase):
    def test_partial_records_advance_gap(self):
        records = [
            ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1),
        ]
        state = initial_state("case-1")
        advanced, drafts = apply_to_gap(state, records, "case-1", "plan-1")
        self.assertEqual(advanced.state, "EVIDENCE_PARTIAL")
        self.assertEqual(len(drafts), 1)

    def test_complete_records_reach_ready(self):
        clean = dict(RESULT, missing_fields=[])
        records = [
            ingest("case-1", "job-1", clean, "OFFLINE_FIXTURE", 1),
            ingest("case-1", "job-1", dict(
                clean, observation_id="obs-2",
                observed_fields=["response_headers"]), "OFFLINE_FIXTURE", 1),
        ]
        state = initial_state("case-1")
        advanced, _ = apply_to_gap(state, records, "case-1", "plan-1")
        self.assertEqual(advanced.state, "EVIDENCE_READY")

    def test_wrong_case_id_refused(self):
        records = [
            ingest("case-2", "job-1", RESULT, "OFFLINE_FIXTURE", 1),
        ]
        state = initial_state("case-1")
        with self.assertRaises(IngestionFailure):
            apply_to_gap(state, records, "case-1", "plan-1")

    def test_draft_shape(self):
        records = [
            ingest("case-1", "job-1", RESULT, "OFFLINE_FIXTURE", 1),
        ]
        state = initial_state("case-1")
        _, drafts = apply_to_gap(state, records, "case-1", "plan-1")
        draft = drafts[0]
        self.assertEqual(draft.case_id, "case-1")
        self.assertEqual(draft.plan_id, "plan-1")
        self.assertEqual(draft.artifact_kind, "observation")
        self.assertIn(("mode", "OFFLINE_FIXTURE"), draft.provenance)
        self.assertEqual(draft.missing_fields, ("response_headers",))

    def test_no_finding_ever_created(self):
        records = [
            ingest("case-1", "job-1", dict(
                RESULT, missing_fields=[],
                observed_fields=["status_code"]), "OFFLINE_FIXTURE", 1),
        ]
        state = initial_state("case-1")
        advanced, drafts = apply_to_gap(state, records, "case-1", "plan-1")
        for draft in drafts:
            self.assertNotEqual(draft.artifact_kind, "finding")
        self.assertNotEqual(advanced.state, "FINDING")


if __name__ == "__main__":
    unittest.main()