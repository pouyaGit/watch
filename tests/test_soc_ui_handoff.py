"""SOC-5 — External Analyst Handoff (RED phase).

/ui/soc/handoff and /ui/soc/handoff/{job_id} give an external researcher
a shareable read-only view: target, endpoint, context, evidence summary,
agent reasoning, suggested tests, questions for analyst.  Read-only,
auth-gated (same api_key middleware), no raw secrets.  Future-ready:
the route is structured so a tokenized variant can be added later WITHOUT
an authentication bypass.
"""

from __future__ import annotations

import unittest


class TestHandoffIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.soc import handoff as soc_handoff

        cls.payload = soc_handoff.handoff_index()

    def test_index_has_reports(self):
        self.assertIn("reports", self.payload)
        self.assertIsInstance(self.payload["reports"], list)

    def test_report_row_shape(self):
        for report in self.payload["reports"][:5]:
            for key in ("job_id", "report_id", "target", "category",
                        "status", "generated_at", "view_url"):
                self.assertIn(key, report, report)
            self.assertIn("/ui/soc/handoff/", report["view_url"])


class TestHandoffDetail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from backend.soc import handoff as soc_handoff

        idx = soc_handoff.handoff_index()
        cls.job = idx["reports"][0]["job_id"] if idx["reports"] else None
        cls.detail = soc_handoff.handoff_detail(cls.job) if cls.job else None

    def test_report_available(self):
        self.assertIsNotNone(self.job, "no investigation reports present")
        self.assertIsNotNone(self.detail)

    def test_detail_blocks(self):
        for key in ("target", "endpoint", "context", "evidence_summary",
                    "agent_reasoning", "suggested_tests", "questions"):
            self.assertIn(key, self.detail, f"missing {key}")

    def test_no_secrets_in_detail(self):
        text = str(self.detail).lower()
        for secret in ("password=", "set-cookie", "authorization:",
                       "x-api-key", "apikey:", "client_secret"):
            self.assertNotIn(secret, text, f"leaked {secret}")

    def test_evidence_summary_is_aggregate_only(self):
        summary = self.detail["evidence_summary"]
        self.assertIsInstance(summary, list)
        for item in summary:
            # hashes may appear (integrity), but never bodies or cookies
            if isinstance(item, dict):
                self.assertNotIn("body", item)
                self.assertNotIn("response_headers", item)

    def test_unknown_job_returns_none(self):
        from backend.soc import handoff as soc_handoff

        self.assertIsNone(soc_handoff.handoff_detail("rj-nope"))
        self.assertIsNone(soc_handoff.handoff_detail(""))


class TestHandoffAuthContract(unittest.TestCase):
    def test_routes_are_get_only(self):
        from backend.routers import soc

        for r in soc.router.routes:
            if getattr(r, "path", "").startswith("/ui/soc/handoff"):
                self.assertTrue(r.methods == {"GET"} or r.methods == ["GET"],
                                r.path)


if __name__ == "__main__":
    unittest.main()