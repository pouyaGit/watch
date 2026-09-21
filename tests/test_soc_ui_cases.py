"""SOC-3 — Case investigation interface (RED phase).

/ui/soc/cases/{case_id} must show target, program, endpoint, HTTP method,
parameters, technology, research hypothesis, suggested analysis, evidence,
and provenance — read from existing AEC case views plus the investigation
evidence store.  Never claim a vulnerability is confirmed unless the
underlying verification state says so.
"""

from __future__ import annotations

import unittest


class TestCaseIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.soc import cases as soc_cases

        cls.payload = soc_cases.cases_index()

    def test_case_rows_present(self):
        self.assertIn("cases", self.payload)
        self.assertIsInstance(self.payload["cases"], list)

    def test_case_row_shape(self):
        for case in self.payload["cases"][:5]:
            for key in ("case_id", "target", "category", "research_state",
                        "evidence_state", "specialist", "next_action",
                        "detail_url"):
                self.assertIn(key, case, case)

    def test_rows_link_to_detail(self):
        for case in self.payload["cases"][:5]:
            self.assertIn("/ui/soc/cases/", case["detail_url"])


class TestCaseDetail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.soc import cases as soc_cases

        cls.known = "rc-1430e0f21394"  # a real AEC fixture case id
        cls.detail = soc_cases.case_detail(cls.known)

    def test_known_case_resolves(self):
        self.assertIsNotNone(self.detail)

    def test_unknown_case_returns_none(self):
        from backend.soc import cases as soc_cases

        self.assertIsNone(soc_cases.case_detail("rc-does-not-exist"))
        self.assertIsNone(soc_cases.case_detail(""))

    def test_target_block_shape(self):
        target = self.detail["target"]
        for key in ("domain", "program", "endpoint", "method",
                    "parameters", "technology", "category"):
            self.assertIn(key, target)

    def test_hypothesis_present(self):
        self.assertIn("hypothesis", self.detail)
        self.assertIn("why", self.detail["hypothesis"])
        self.assertIn("research_history", self.detail["hypothesis"])

    def test_suggested_analysis_shape(self):
        analysis = self.detail["suggested_analysis"]
        for key in ("attack_paths", "required_validation",
                    "payload_ideas", "related_knowledge"):
            self.assertIn(key, analysis)
            self.assertIsInstance(analysis[key], list)

    def test_evidence_shape(self):
        evidence = self.detail["evidence"]
        self.assertIsInstance(evidence, list)
        for artifact in evidence:
            for key in ("evidence_id", "evidence_level", "integrity",
                        "redaction_status", "source", "tick"):
                self.assertIn(key, artifact, artifact)

    def test_never_claims_confirmation_unsupported(self):
        # The view may only assert a confirmed finding when the source
        # verification state literally says REVIEW/COMPLETED+verified;
        # for the fixture this must be absent or honest.
        verdict = self.detail.get("verdict")
        if verdict is not None:
            self.assertIn(str(verdict).upper(),
                          ("CONFIRMED", "UNCONFIRMED", "NOT_CLAIMED"))
        # the actual rule: hypothesis language must not say confirmed
        import re
        text = str(self.detail.get("hypothesis", ""))
        self.assertNotIn("confirmed vulnerability", text.lower())
        self.assertNotIn("verified vulnerability", text.lower())


if __name__ == "__main__":
    unittest.main()