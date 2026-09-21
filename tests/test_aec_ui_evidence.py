"""EPIC8 Part 6: evidence viewer — artifacts, integrity, redaction."""

from __future__ import annotations

import unittest


def view():
    from backend.routers import aec
    return aec.build_evidence_viewer_view()


class TestArtifactFields(unittest.TestCase):
    def test_all_documented_fields(self):
        for artifact in view()["artifacts"]:
            for field in ("evidence_id", "case_id", "observation_type",
                          "authorization_reference", "scope_validation",
                          "provenance", "integrity", "redaction_status",
                          "quality_score"):
                self.assertIn(field, artifact, field)

    def test_evidence_id_prefix(self):
        for artifact in view()["artifacts"]:
            self.assertTrue(artifact["evidence_id"].startswith("ev-"))

    def test_case_id_present(self):
        for artifact in view()["artifacts"]:
            self.assertTrue(artifact["case_id"])

    def test_observation_type_allowlisted(self):
        allowed = {"HTTP_METADATA", "HTTP_HEADERS", "HTTP_STATUS",
                   "HTTP_BODY_METADATA"}
        for artifact in view()["artifacts"]:
            self.assertIn(artifact["observation_type"], allowed)

    def test_authorization_reference_present(self):
        for artifact in view()["artifacts"]:
            self.assertTrue(artifact["authorization_reference"])

    def test_scope_validation_closed(self):
        for artifact in view()["artifacts"]:
            self.assertIn(artifact["scope_validation"],
                          {"PASS", "n/a"})


class TestIntegrity(unittest.TestCase):
    def test_integrity_prefixed(self):
        for artifact in view()["artifacts"]:
            self.assertTrue(artifact["integrity"].startswith("sha256:"))

    def test_integrity_hex(self):
        for artifact in view()["artifacts"]:
            int(artifact["integrity"].split(":", 1)[1], 16)

    def test_integrity_deterministic(self):
        first = view()
        second = view()
        self.assertEqual(
            [a["integrity"] for a in first["artifacts"]],
            [a["integrity"] for a in second["artifacts"]])


class TestRedactionStatus(unittest.TestCase):
    def test_status_closed(self):
        for artifact in view()["artifacts"]:
            self.assertIn(artifact["redaction_status"],
                          {"clean", "scrubbed", "n/a"})

    def test_no_sensitive_values(self):
        blob = str(view()).lower()
        for secret in ("cookie", "set-cookie", "authorization:",
                       "password", "bearer", "secret"):
            self.assertNotIn(secret, blob)


class TestProvenance(unittest.TestCase):
    def test_provenance_fields(self):
        for artifact in view()["artifacts"]:
            provenance = artifact["provenance"]
            self.assertIn("source", provenance)
            self.assertIn("source_mode", provenance)
            self.assertIn("tick", provenance)

    def test_source_mode_offline(self):
        for artifact in view()["artifacts"]:
            self.assertEqual(artifact["provenance"]["source_mode"],
                             "OFFLINE_FIXTURE")


class TestQualityScore(unittest.TestCase):
    def test_score_never_verdict(self):
        for artifact in view()["artifacts"]:
            self.assertIsInstance(artifact["quality_score"], str)

    def test_score_allowed_values(self):
        allowed = {"partial", "adequate", "insufficient", "n/a"}
        for artifact in view()["artifacts"]:
            self.assertIn(artifact["quality_score"], allowed)


class TestNeverFindings(unittest.TestCase):
    def test_no_confidence(self):
        for artifact in view()["artifacts"]:
            self.assertNotIn("confidence", artifact)

    def test_no_severity(self):
        for artifact in view()["artifacts"]:
            self.assertNotIn("severity", artifact)

    def test_no_verdict_vocabulary(self):
        blob = str(view()).lower()
        for word in ("confirmed", "finding", "verdict", "exploit",
                     "vulnerable"):
            self.assertNotIn(word, blob)

    def test_no_body_content(self):
        blob = str(view()).lower()
        self.assertNotIn("<html", blob)


class TestEmptyAndDeterminism(unittest.TestCase):
    def test_empty(self):
        from backend.routers import aec
        view = aec.build_evidence_viewer_view([])
        self.assertEqual(view["artifacts"], [])

    def test_deterministic(self):
        from backend.routers import aec
        first = aec.build_evidence_viewer_view()
        second = aec.build_evidence_viewer_view()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()