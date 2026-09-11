"""tests/test_research_economics_projection.py — Stage R25.3 projection tests.

Deterministic, offline, read-only tests for the Money Score presentation
layer (backend/research_economics.py + `research_cli economics`).

No network, no DNS, no LLM, no subprocess, no target interaction, no
Nuclei, no browser, no PoC execution, no 5B-5J, no findings, no alerts,
no Mongo writes, no persistence. No R25.2 engine logic is re-tested here
(see tests/test_research_economics.py); this suite covers composition,
ordering, filtering, detail lookup, fail-soft behaviour and CLI output.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from backend.research_data import NotFoundError

CVE = "CVE-2026-1557"
EXPECTED_MONEY = 53
EXPECTED_PRIORITY = "P3_MEDIUM"
ALLOWED_PRIORITIES = {
    "P1_START_NOW", "P2_HIGH", "P3_MEDIUM", "P4_LOW", "P5_DEFER",
}
ALLOWED_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
FORBIDDEN = ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING")
REQUIRED_KEYS = {
    "cve_id", "program", "lead_id", "plan_id", "queue_id", "task_id",
    "money_score", "priority", "confidence", "confidence_basis",
    "effort", "effort_estimate", "asset_match", "why_valuable",
    "main_blockers", "recommended_action", "subscores",
    "evidence_summary", "caps_applied", "rule_version", "research_only",
}


def _real_leads():
    from backend import research_leads
    return research_leads.build_leads()


class TestQueueComposition(unittest.TestCase):
    def test_real_corpus_scores(self):
        from backend import research_economics
        items = research_economics.build_economics()
        self.assertEqual(len(items), 2)
        by_program = {e["program"]: e for e in items}
        self.assertEqual(by_program["dell"]["money_score"], EXPECTED_MONEY)
        self.assertEqual(by_program["indeed"]["money_score"], EXPECTED_MONEY)
        self.assertEqual(by_program["dell"]["priority"], EXPECTED_PRIORITY)
        self.assertEqual(by_program["indeed"]["priority"], EXPECTED_PRIORITY)

    def test_projection_shape(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            self.assertTrue(REQUIRED_KEYS.issubset(set(item.keys())),
                            f"missing keys: {REQUIRED_KEYS - set(item.keys())}")
            self.assertIsInstance(item["money_score"], int)
            self.assertTrue(0 <= item["money_score"] <= 100)
            self.assertIn(item["priority"], ALLOWED_PRIORITIES)
            self.assertIn(item["confidence"], ALLOWED_CONFIDENCE)
            self.assertTrue(item["research_only"])
            self.assertEqual(item["rule_version"], "r25-1")
            for sub in ("value", "confidence", "effort", "risk"):
                self.assertIn(sub, item["subscores"])
            for key in ("r23_confidence", "r24_tier", "sources", "evidence"):
                self.assertIn(key, item["evidence_summary"])

    def test_lead_plan_mapping(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            self.assertTrue(item["lead_id"].startswith("rl-"))
            self.assertTrue(item["plan_id"].startswith("r22-"))
            self.assertTrue(item["queue_id"].startswith("rq-"))

    def test_r18_blockers_propagated(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            self.assertIn("only generic technology match", item["main_blockers"])
            self.assertIn("asset version unknown", item["main_blockers"])

    def test_r15_inputs_visible(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            self.assertIn("public proof-of-concept available",
                          item["why_valuable"])

    def test_no_forbidden_vocabulary(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            blob = " ".join([
                str(item["priority"]), str(item["confidence"]),
                str(item["recommended_action"]),
                *[str(r) for r in item["why_valuable"]],
                *[str(b) for b in item["main_blockers"]],
            ]).upper()
            for word in FORBIDDEN:
                self.assertNotIn(word, blob)


class TestInputs(unittest.TestCase):
    def test_r23_result_loading(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            self.assertEqual(item["evidence_summary"]["r23_confidence"], "HIGH")
            self.assertGreaterEqual(item["evidence_summary"]["sources"], 1)
            self.assertGreaterEqual(item["evidence_summary"]["evidence"], 1)

    def test_r24_result_loading(self):
        from backend import research_economics
        for item in research_economics.build_economics():
            self.assertEqual(item["evidence_summary"]["r24_tier"], "TRUSTED")

    def test_missing_optional_r23_r24(self):
        from backend import research_economics
        with mock.patch("ai.research_agent.storage.load_result",
                        return_value=None), \
             mock.patch("ai.research_agent.storage.load_research_loop",
                        return_value=None):
            items = research_economics.build_economics()
        self.assertEqual(len(items), 2)
        for item in items:
            self.assertTrue(item["research_only"])
            self.assertIsInstance(item["money_score"], int)

    def test_r20_task_states(self):
        from backend import research_economics
        leads = _real_leads()
        self.assertTrue(leads)
        queue_id = leads[0]["queue_id"]
        task = {"queue_id": queue_id, "task_id": "rt-0123456789abcdef",
                "status": "DONE", "cve": CVE, "program": leads[0]["program"]}
        with mock.patch("backend.research_tasks.list_tasks",
                        return_value={"items": [task], "total": 1,
                                      "offset": 0, "limit": 100}):
            items = research_economics.build_economics()
        target = [e for e in items if e["cve_id"] == leads[0]["cve_id"]
                  and e["program"] == leads[0]["program"]]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["recommended_action"], "COMPLETED")

    def test_r20_task_in_progress(self):
        from backend import research_economics
        leads = _real_leads()
        queue_id = leads[0]["queue_id"]
        task = {"queue_id": queue_id, "task_id": "rt-0123456789abcdef",
                "status": "IN_PROGRESS", "cve": CVE,
                "program": leads[0]["program"]}
        with mock.patch("backend.research_tasks.list_tasks",
                        return_value={"items": [task], "total": 1,
                                      "offset": 0, "limit": 100}):
            items = research_economics.build_economics()
        target = [e for e in items if e["cve_id"] == leads[0]["cve_id"]
                  and e["program"] == leads[0]["program"]]
        self.assertEqual(target[0]["recommended_action"], "CONTINUE")


class TestOrderingFiltering(unittest.TestCase):
    def test_deterministic_ordering(self):
        from backend import research_economics
        items = research_economics.build_economics()
        keys = [(-e["money_score"], e["cve_id"], e["program"]) for e in items]
        self.assertEqual(keys, sorted(keys))
        # real corpus tie (53/53) breaks on program ascending
        self.assertEqual([e["program"] for e in items], ["dell", "indeed"])

    def test_repeated_execution_deterministic(self):
        from backend import research_economics
        first = research_economics.build_economics()
        second = research_economics.build_economics()
        self.assertEqual(first, second)
        self.assertEqual(research_economics.list_research_economics(),
                         research_economics.list_research_economics())

    def test_cve_filter(self):
        from backend import research_economics
        data = research_economics.list_research_economics(cve=CVE)
        self.assertEqual(data["total"], 2)
        self.assertTrue(all(e["cve_id"] == CVE for e in data["items"]))
        empty = research_economics.list_research_economics(cve="CVE-2024-0001")
        self.assertEqual(empty["total"], 0)
        self.assertEqual(empty["items"], [])

    def test_program_filter(self):
        from backend import research_economics
        data = research_economics.list_research_economics(program="dell")
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["program"], "dell")
        self.assertEqual(data["items"][0]["money_score"], EXPECTED_MONEY)

    def test_limit(self):
        from backend import research_economics
        data = research_economics.list_research_economics(limit=1)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["program"], "dell")
        self.assertEqual(data["limit"], 1)

    def test_offset(self):
        from backend import research_economics
        data = research_economics.list_research_economics(limit=10, offset=1)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["program"], "indeed")

    def test_json_serializable(self):
        from backend import research_economics
        data = research_economics.list_research_economics(limit=10)
        text = json.dumps(data["items"], ensure_ascii=False, indent=2,
                          sort_keys=True)
        back = json.loads(text)
        self.assertEqual(back, data["items"])


class TestDetailLookup(unittest.TestCase):
    def test_detail_by_lead_id(self):
        from backend import research_economics
        lead_id = _real_leads()[0]["lead_id"]
        item = research_economics.get_research_economic_value(lead_id)
        self.assertEqual(item["lead_id"], lead_id)
        self.assertTrue(REQUIRED_KEYS.issubset(set(item.keys())))
        self.assertTrue(item["research_only"])

    def test_detail_malformed_id(self):
        from backend import research_economics
        with self.assertRaises(NotFoundError):
            research_economics.get_research_economic_value("not-a-lead")

    def test_detail_unknown_id(self):
        from backend import research_economics
        with self.assertRaises(NotFoundError):
            research_economics.get_research_economic_value(
                "rl-ffffffffffffffff")

    def test_summary(self):
        from backend import research_economics
        summary = research_economics.economic_summary()
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_priority"], {"P3_MEDIUM": 2})
        self.assertEqual(len(summary["top"]), 2)
        self.assertTrue(summary["research_only"])
        self.assertEqual(summary["rule_version"], "r25-1")


class TestFailSoft(unittest.TestCase):
    def test_malformed_item_does_not_blank_queue(self):
        from backend import research_economics
        leads = _real_leads()
        bad = [{"bogus": 1}, "not-a-dict",
               {"lead_id": "rl-aaaaaaaaaaaaaaaa"}]
        with mock.patch("backend.research_leads.build_leads",
                        return_value=leads + bad):
            data = research_economics.list_research_economics(limit=100)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["skipped"]), 3)
        for skip in data["skipped"]:
            self.assertIn("reason", skip)
            self.assertTrue(skip["reason"])

    def test_empty_queue(self):
        from backend import research_economics
        with mock.patch("backend.research_leads.build_leads",
                        return_value=[]):
            data = research_economics.list_research_economics()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["items"], [])
        self.assertEqual(data["skipped"], [])

    def test_lead_snapshot_failure(self):
        from backend import research_economics
        with mock.patch("backend.research_leads.build_leads",
                        side_effect=OSError("store unavailable")):
            data = research_economics.list_research_economics()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["items"], [])
        self.assertEqual(len(data["skipped"]), 1)

    def test_missing_payload_and_intel(self):
        from backend import research_economics
        leads = _real_leads()
        with mock.patch("backend.research_data.cve_intelligence",
                        side_effect=OSError("kb unavailable")), \
             mock.patch("backend.research_data._research_payload",
                        side_effect=OSError("payload unavailable")), \
             mock.patch("ai.research_agent.storage.load_result",
                        return_value=None), \
             mock.patch("ai.research_agent.storage.load_research_loop",
                        return_value=None):
            data = research_economics.list_research_economics()
        # engine degrades to zero-signal projections, never fabricated values
        self.assertEqual(data["total"], len(leads))
        for item in data["items"]:
            self.assertTrue(item["research_only"])
            self.assertLessEqual(item["money_score"], 45)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_human_output(self):
        code, out = self._run(["economics", "--limit", "10"])
        self.assertEqual(code, 0)
        self.assertIn("MONEY QUEUE", out)
        self.assertIn("#1  53  P3_MEDIUM", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertIn("Confidence: HIGH", out)
        self.assertIn("Effort: 1–2 h", out)
        self.assertIn("Action: VERIFY_ASSET_MATCH_FIRST", out)
        self.assertIn("#2  53  P3_MEDIUM", out)
        self.assertIn("CVE-2026-1557 → indeed", out)
        self.assertIn("MONEY QUEUE: 2", out)

    def test_json_output(self):
        code, out = self._run(["economics", "--json"])
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertEqual(len(items), 2)
        self.assertTrue(REQUIRED_KEYS.issubset(set(items[0].keys())))
        self.assertEqual(
            [i["money_score"] for i in items], [EXPECTED_MONEY] * 2)

    def test_cve_and_program_filters(self):
        code, out = self._run(["economics", "--cve", CVE, "--program", "dell"])
        self.assertEqual(code, 0)
        self.assertIn("MONEY QUEUE: 1", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertNotIn("indeed", out)

    def test_empty_filter(self):
        code, out = self._run(["economics", "--cve", "CVE-2024-0001"])
        self.assertEqual(code, 0)
        self.assertIn("MONEY QUEUE: none", out)

    def test_malformed_cve(self):
        from ai.research_cli import main
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["economics", "--cve", "not-a-cve"])
        self.assertEqual(code, 1)


class TestSafety(unittest.TestCase):
    def test_no_network_subprocess_llm_sources(self):
        source = (Path(__file__).resolve().parent / ".." / "backend"
                  / "research_economics.py").read_text(encoding="utf-8")
        for token in ("import socket", "import subprocess", "import urllib",
                      "import requests", "import httpx", "import llm",
                      "import openai", "import anthropic", "nuclei",
                      "requests.", "urlopen", "browser", "Popen"):
            self.assertNotIn(token, source)

    def test_no_persistence(self):
        from backend import research_economics
        watched = [
            Path("/opt/watch/ai_data/research/agent"),
            Path("/opt/watch/ai_data/research/tasks"),
            Path("/opt/watch/ai_data/knowledge"),
            Path("/opt/watch/ai_data/research"),
        ]
        before = {}
        for root in watched:
            before[str(root)] = (
                sorted(str(p) for p in root.rglob("*")) if root.exists()
                else None)
        research_economics.build_economics()
        research_economics.list_research_economics(limit=100)
        research_economics.economic_summary()
        for root in watched:
            after = (sorted(str(p) for p in root.rglob("*"))
                     if root.exists() else None)
            self.assertEqual(after, before[str(root)],
                             f"projection wrote under {root}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
