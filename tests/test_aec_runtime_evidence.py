"""EPIC7 Part 8+19: evidence artifact output and bridge compatibility."""

from __future__ import annotations

import unittest


def valid_request(**overrides):
    request = {
        "request_id": "obsreq-abc123",
        "research_job_id": "job-123",
        "case_id": "case-123",
        "target_id": "tgt-000000000001",
        "observation_type": "HTTP_METADATA",
        "method": "GET",
        "required_evidence_level": "PARTIAL",
        "authorization_reference": "authz-123",
        "policy_version": "v1",
    }
    request.update(overrides)
    return request


def build(**overrides):
    from aec.runtime.results.evidence import build_evidence

    kwargs = dict(
        request=valid_request(),
        tick=7,
        status=200,
        selected_headers={"content-type": "text/html"},
        content_metadata={"content_type": "text/html"},
        response_size=1024,
        timing_ms=15,
        target_id="tgt-000000000001",
        authorization_reference="authz-123",
        policy_version="v1",
        mode="LIVE_OBSERVATION",
        scope_validation="PASS",
    )
    kwargs.update(overrides)
    return build_evidence(**kwargs)


class TestEvidenceFields(unittest.TestCase):
    def test_all_documented_fields_present(self):
        artifact = build()
        data = artifact.to_dict()
        for key in (
            "evidence_id", "request_id", "research_job_id", "case_id",
            "target_id", "observation_type", "timestamp", "status",
            "selected_headers", "content_metadata", "response_size",
            "timing_metadata", "scope_validation", "authorization_reference",
            "policy_version", "redaction_status", "integrity"):
            self.assertIn(key, data, f"missing {key}")

    def test_evidence_id_minted(self):
        artifact = build()
        self.assertTrue(artifact.evidence_id.startswith("ev-"))

    def test_evidence_id_deterministic(self):
        first = build()
        second = build()
        self.assertEqual(first.evidence_id, second.evidence_id)

    def test_integrity_hex(self):
        artifact = build()
        int(artifact.integrity, 16)
        self.assertEqual(len(artifact.integrity), 64)

    def test_observation_type_recorded(self):
        artifact = build()
        self.assertEqual(artifact.observation_type, "HTTP_METADATA")

    def test_status_recorded(self):
        artifact = build()
        self.assertEqual(artifact.status, 200)

    def test_authorization_reference_recorded(self):
        artifact = build()
        self.assertEqual(artifact.authorization_reference, "authz-123")

    def test_policy_version_recorded(self):
        artifact = build()
        self.assertEqual(artifact.policy_version, "v1")

    def test_mode_recorded(self):
        artifact = build()
        self.assertEqual(artifact.mode, "LIVE_OBSERVATION")

    def test_timestamp_recorded(self):
        artifact = build()
        self.assertEqual(artifact.timestamp, 7)


class TestEvidenceIntegrity(unittest.TestCase):
    def test_changes_with_content(self):
        from aec.runtime.results.evidence import build_evidence

        first = build()
        second = build_evidence(
            request=valid_request(case_id="case-other"),
            tick=7, status=200,
            selected_headers={"content-type": "text/html"},
            content_metadata={"content_type": "text/html"},
            response_size=1024, timing_ms=15,
            target_id="tgt-000000000001",
            authorization_reference="authz-123",
            policy_version="v1", mode="LIVE_OBSERVATION")
        self.assertNotEqual(first.integrity, second.integrity)

    def test_redaction_status_scrubbed(self):
        artifact = build()
        self.assertEqual(artifact.redaction_status, "scrubbed")


class TestBridgeCompatibility(unittest.TestCase):
    def test_bridge_result_shape(self):
        artifact = build()
        result = artifact.bridge_result()
        self.assertIn("observation_id", result)
        self.assertIn("request_id", result)
        self.assertIn("observed_fields", result)
        self.assertIn("missing_fields", result)
        self.assertIn("tick", result)

    def test_bridge_result_ingests(self):
        from aec.evidence_bridge.bridge import ingest

        artifact = build()
        record = ingest(
            artifact.case_id, artifact.research_job_id,
            artifact.bridge_result(), "REAL_WATCH_DATA",
            artifact.timestamp)
        self.assertEqual(record.case_id, "case-123")
        self.assertTrue(record.evidence_id.startswith("ev-"))

    def test_bridge_result_has_observation_type(self):
        artifact = build()
        observed = artifact.bridge_result()["observed_fields"]
        self.assertIn("HTTP_METADATA", observed)

    def test_bridge_never_creates_finding(self):
        from aec.runtime.results.evidence import EvidenceArtifact

        data = build().to_dict()
        joined = " ".join(str(v) for v in data.values()).lower()
        for word in ("finding", "confirmed", "verdict", "vulnerable",
                     "exploit"):
            self.assertNotIn(word, joined)


class TestEvidenceNeverClaims(unittest.TestCase):
    def test_no_confidence_field(self):
        artifact = build()
        data = artifact.to_dict()
        self.assertNotIn("confidence", data)

    def test_no_severity_field(self):
        artifact = build()
        data = artifact.to_dict()
        self.assertNotIn("severity", data)

    def test_mode_dry_run_distinguishable(self):
        dry = build(mode="DRY_RUN")
        live = build(mode="LIVE_OBSERVATION")
        self.assertNotEqual(dry.mode, live.mode)


class TestEvidenceSecrets(unittest.TestCase):
    def test_sensitive_headers_absent(self):
        artifact = build(
            selected_headers={"content-type": "text/html",
                              "set-cookie": "sid=secret123"})
        joined = str(artifact.to_dict())
        self.assertNotIn("secret123", joined)
        self.assertNotIn("set-cookie", joined)

    def test_header_order_deterministic(self):
        first = build(selected_headers={"b": "2", "a": "1"})
        second = build(selected_headers={"a": "1", "b": "2"})
        self.assertEqual(
            list(first.selected_headers), list(second.selected_headers))


if __name__ == "__main__":
    unittest.main()