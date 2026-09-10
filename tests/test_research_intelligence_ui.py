"""
tests/test_research_intelligence_ui.py — Stage R19 research intelligence UI/API.

Exercises the R15-R18 dashboard integration through the real FastAPI app with
TestClient. Read-only: no network, no Mongo writes, no LLM, no validation.
Hostile-payload tests patch the read-only data layer, never the real ai_data/.
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)


class TestResearchOverview(_Base):
    def test_overview_shows_intelligence_counts(self):
        r = self._get("/ui/research")
        self.assertEqual(r.status_code, 200)
        # R16 priority-class overview cards
        for frag in ("Critical Research", "High Research", "Medium Research",
                     "Low Research", "Research Queue"):
            self.assertIn(frag, r.text)
        # link to the queue survives
        self.assertIn("/ui/research/queue", r.text)

    def test_sidebar_has_queue_nav(self):
        r = self._get("/ui/research")
        self.assertIn("/ui/research/queue", r.text)


class TestResearchQueuePage(_Base):
    def test_queue_page_renders_rows(self):
        r = self._get("/ui/research/queue")
        self.assertEqual(r.status_code, 200)
        self.assertIn("RESEARCH PLANNING — NOT VERIFIED", r.text)
        self.assertIn("Queue score", r.text)
        self.assertIn(CVE, r.text)
        self.assertIn("dell", r.text)
        self.assertIn("/ui/research/queue", r.text)

    def test_queue_page_shows_blockers(self):
        r = self._get("/ui/research/queue")
        self.assertEqual(r.status_code, 200)
        self.assertIn("affected plugin not observed", r.text)

    def test_queue_page_cve_filter(self):
        r = self._get("/ui/research/queue", cve=CVE)
        self.assertEqual(r.status_code, 200)
        self.assertIn(CVE, r.text)
        r = self._get("/ui/research/queue", cve="CVE-2024-42327")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No deterministic CVE/program research candidates", r.text)

    def test_queue_empty_state(self):
        with tempfile.TemporaryDirectory() as td:
            empty = Path(td)
            (empty / "programs").mkdir()
            (empty / "research").mkdir()
            from backend import research_data as rd
            with mock.patch.object(rd, "PROGRAMS_DIR", empty / "programs"), \
                    mock.patch.object(rd, "RESEARCH_DIR", empty / "research"):
                r = self._get("/ui/research/queue")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No deterministic CVE/program research candidates", r.text)

    def test_hostile_queue_values_are_escaped(self):
        payload = "<script>alert('xss')</script>"
        hostile = {
            "total": 1, "offset": 0, "limit": 50,
            "items": [{
                "rank": 1, "queue_id": "rq-x", "cve": payload,
                "program": payload, "priority_class": payload,
                "priority_score": 50, "relevance": payload,
                "relevance_score": 20, "queue_score": 38,
                "reasons": [payload], "blockers": [payload],
                "unknown_factors": [payload], "rule_version": "r18-1",
            }],
        }
        from backend.routers import research_pages as pages
        with mock.patch.object(pages.rdata, "list_research_queue", return_value=hostile):
            r = self._get("/ui/research/queue")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("<script>alert('xss')</script>", r.text)
        self.assertIn("&lt;script&gt;", r.text)

    def test_long_reasons_are_bounded_by_the_data_layer(self):
        from backend import research_data as rd
        clipped = rd._compact_list(["R" * 1000])
        self.assertEqual(len(clipped), 1)
        self.assertLessEqual(len(clipped[0]), 240)
        self.assertTrue(clipped[0].endswith("…"))
        # the queue projection never exposes unbounded evidence bodies
        compacted = rd._compact_queue_item(
            {"reasons": ["R" * 1000], "evidence": [{"x": 1}]}
        )
        self.assertNotIn("evidence", compacted)
        self.assertLessEqual(len(compacted["reasons"][0]), 240)


class TestCveDetailIntelligence(_Base):
    def test_detail_shows_r15_r18_panels(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        for frag in ("Exploitability", "CVSS Structural", "Research Priority",
                     "Asset Relevance", "Research Queue Candidates"):
            self.assertIn(frag, r.text)

    def test_exploitability_display(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertIn("Authentication required", r.text)
        self.assertIn("Active exploitation", r.text)
        # 1557 is unauthenticated + no public-active-exploitation
        self.assertIn("false", r.text)

    def test_priority_display(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertIn("CRITICAL_RESEARCH", r.text)

    def test_relevance_display(self):
        r = self._get(f"/ui/research/{CVE}")
        self.assertIn("technology match: wordpress", r.text)

    def test_detail_missing_cve_404(self):
        r = self._get("/ui/research/CVE-2026-99999")
        self.assertEqual(r.status_code, 404)


class TestQueueApi(_Base):
    def test_api_auth_required(self):
        if not API_KEY:
            self.skipTest("API key not configured")
        for path in ("/api/research/queue",
                     f"/api/research/queue/{CVE}",
                     f"/api/research/{CVE}/relevance"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)

    def test_queue_api_shape_and_determinism(self):
        r = self._get("/api/research/queue")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("items", data)
        ranks = [i["rank"] for i in data["items"]]
        self.assertEqual(ranks, sorted(ranks))
        # deterministic ordering: queue_score desc, priority desc, relevance desc,
        # cve asc, program asc
        key = lambda i: (-i["queue_score"], -i["priority_score"],
                         -i["relevance_score"], i["cve"], i["program"])
        self.assertEqual(data["items"], sorted(data["items"], key=key))
        # repeat is byte-identical
        self.assertEqual(r.text, self._get("/api/research/queue").text)

    def test_queue_api_pagination_and_limit(self):
        full = self._get("/api/research/queue").json()
        if full["total"] < 2:
            self.skipTest("need >=2 queue items")
        one = self._get("/api/research/queue", limit=1).json()
        self.assertEqual(len(one["items"]), 1)
        self.assertEqual(one["total"], full["total"])
        second = self._get("/api/research/queue", limit=1, offset=1).json()
        self.assertNotEqual(one["items"][0]["queue_id"],
                            second["items"][0]["queue_id"])
        # limit is clamped, never unbounded
        clamped = self._get("/api/research/queue", limit=100000).json()
        self.assertLessEqual(len(clamped["items"]), 100)

    def test_queue_api_cve_scope(self):
        r = self._get(f"/api/research/queue/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(all(i["cve"] == CVE for i in r.json()["items"]))
        self.assertEqual(
            self._get("/api/research/queue/not-a-cve").status_code, 400
        )

    def test_relevance_api(self):
        r = self._get(f"/api/research/{CVE}/relevance")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["cve"], CVE)
        self.assertTrue(body["research_only"])
        self.assertIn("relevance", body)
        self.assertEqual(
            self._get("/api/research/not-a-cve/relevance").status_code, 400
        )

    def test_api_no_mutation(self):
        r1 = self._get("/api/research/queue").text
        r2 = self._get("/api/research/queue").text
        self.assertEqual(r1, r2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
