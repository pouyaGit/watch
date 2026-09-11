"""tests/test_hunt_queue.py — Stage R29.1 personal hunt queue tests.

Deterministic, offline tests for the personal bug-bounty hunt queue: schema,
hunt ids, every priority tier + precedence, history handling, time-box bands,
ranking, backend composition, CLI, API, UI and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no findings, no alerts, no Mongo writes, no
persistence. Money Score is never modified.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import hunt_queue as hq
from ai.schemas.hunt_queue import (
    HUNT_PRIORITIES,
    HUNT_RULE_VERSION,
    HuntItem,
    hunt_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"


def make_action(**over):
    action = {
        "action_id": "oa-8796970d0b5db714",
        "opportunity_id": "op-27deff4809384156",
        "lead_id": DELL,
        "cve_id": CVE,
        "program": "dell",
        "opportunity_class": "BLOCKED",
        "money_score": 53,
        "priority": "P3_MEDIUM",
        "confidence": "HIGH",
        "evidence_quality": "HIGH",
        "effort_score": 47,
        "estimated_minutes": 90,
        "current_status": "BLOCKED",
        "recommended_action": "VERIFY_ASSET_MATCH",
        "action_reason": "Asset relationship unproven.",
        "blockers": ["only generic technology match"],
        "why_now": ["PUBLIC_POC"],
        "next_step": "Confirm affected component/plugin presence.",
        "research_only": True,
        "rule_version": "r26-2",
    }
    action.update(over)
    return action


def make_outcomes(**over):
    outcomes = {
        "lead_id": DELL,
        "attempts": 0,
        "terminal_attempts": 0,
        "accepted": 0,
        "duplicate": 0,
        "rejected": 0,
        "not_applicable": 0,
        "wasted_time": 0,
        "in_progress": 0,
        "total_time_spent_minutes": 0,
        "average_time_spent_minutes": 0,
        "latest_outcome": None,
        "data_quality": "NONE",
    }
    outcomes.update(over)
    return outcomes


def make_sessions(**over):
    sessions = {
        "lead_id": DELL,
        "total_sessions": 0,
        "planned_sessions": 0,
        "in_progress_sessions": 0,
        "completed_sessions": 0,
        "abandoned_sessions": 0,
        "planned_time": 0,
        "actual_time": 0,
        "average_actual_minutes": 0,
        "session_status": "NONE",
        "latest_session_status": "NONE",
    }
    sessions.update(over)
    return sessions


class TestSchema(unittest.TestCase):
    def test_deterministic_hunt_id(self):
        first = hunt_id_for(DELL)
        self.assertEqual(first, hunt_id_for(DELL))
        self.assertTrue(first.startswith("hq-"))
        self.assertNotEqual(first, hunt_id_for(INDEED))

    def test_item_fields(self):
        item = hq.build_hunt_item(make_action(), make_outcomes(),
                                  make_sessions())
        data = item.model_dump(mode="json")
        for field in ("hunt_id", "lead_id", "cve_id", "program",
                      "money_score", "money_priority", "opportunity_class",
                      "current_status", "recommended_action", "confidence",
                      "evidence_quality", "estimated_minutes", "why_now",
                      "blockers", "next_step", "historical_outcome",
                      "historical_time", "hunt_priority",
                      "recommended_time_box", "hunt_reason",
                      "hunt_reason_code", "research_only", "rule_version"):
            self.assertIn(field, data)

    def test_forbidden_fields_rejected(self):
        base = hq.build_hunt_item(make_action(), make_outcomes(),
                                  make_sessions()).model_dump(mode="json")
        for field in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "credentials", "execution_command",
                      "production_finding"):
            with self.subTest(field=field):
                payload = dict(base)
                payload[field] = "x"
                with self.assertRaises(ValueError):
                    HuntItem(**payload)

    def test_closed_tiers_and_time_boxes(self):
        base = hq.build_hunt_item(make_action(), make_outcomes(),
                                  make_sessions()).model_dump(mode="json")
        for bad in ("HUNT_SOON", "PROVEN"):
            payload = dict(base)
            payload["hunt_priority"] = bad
            with self.assertRaises(ValueError):
                HuntItem(**payload)
        payload = dict(base)
        payload["recommended_time_box"] = "5 MIN"
        with self.assertRaises(ValueError):
            HuntItem(**payload)

    def test_rule_and_research_only_forced(self):
        base = hq.build_hunt_item(make_action(), make_outcomes(),
                                  make_sessions()).model_dump(mode="json")
        base["rule_version"] = "r99-9"
        self.assertEqual(HuntItem(**base).rule_version, HUNT_RULE_VERSION)
        base["research_only"] = False
        with self.assertRaises(ValueError):
            HuntItem(**base)

    def test_no_new_numeric_score(self):
        base = hq.build_hunt_item(make_action(), make_outcomes(),
                                  make_sessions())
        data = base.model_dump(mode="json")
        for key in data:
            if "score" in key.lower():
                self.assertIn(key, {"money_score", "effort_score"})
        self.assertNotIn("hunt_score", data)


class TestPriorityPrecedence(unittest.TestCase):
    def _prio(self, action, outcomes=None, sessions=None):
        return hq.classify_hunt_priority(
            action, outcomes or make_outcomes(),
            sessions or make_sessions())

    def test_active_session_hunt_now(self):
        self.assertEqual(self._prio(make_action(current_status="IN_PROGRESS")),
                         "HUNT_NOW")
        self.assertEqual(self._prio(
            make_action(),
            sessions=make_sessions(in_progress_sessions=1)),
            "HUNT_NOW")
        self.assertEqual(self._prio(
            make_action(),
            sessions=make_sessions(session_status="ACTIVE")),
            "HUNT_NOW")

    def test_active_beats_blocked(self):
        self.assertEqual(self._prio(
            make_action(current_status="IN_PROGRESS",
                        opportunity_class="BLOCKED")),
            "HUNT_NOW")

    def test_blocked_verify_first(self):
        self.assertEqual(self._prio(make_action()), "VERIFY_FIRST")
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="BLOCKED")),
            "VERIFY_FIRST")

    def test_blocked_beats_accepted(self):
        self.assertEqual(self._prio(
            make_action(),
            outcomes=make_outcomes(accepted=1, terminal_attempts=1)),
            "VERIFY_FIRST")

    def test_previously_accepted_hunt_now(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM"),
            outcomes=make_outcomes(accepted=1, terminal_attempts=1)),
            "HUNT_NOW")

    def test_high_value_high_confidence_hunt_now(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="HIGH_VALUE", confidence="HIGH")),
            "HUNT_NOW")

    def test_good_opportunity_hunt_next(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="GOOD_OPPORTUNITY",
                        confidence="MEDIUM")),
            "HUNT_NEXT")

    def test_research_first_hunt_next(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="RESEARCH_FIRST",
                        confidence="MEDIUM")),
            "HUNT_NEXT")

    def test_low_confidence_verify_first(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="HIGH_VALUE", confidence="LOW")),
            "VERIFY_FIRST")
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="LOW_CONFIDENCE",
                        confidence="MEDIUM")),
            "VERIFY_FIRST")

    def test_high_waste_history_research_later(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM"),
            outcomes=make_outcomes(terminal_attempts=4, duplicate=1,
                                   wasted_time=1)),
            "RESEARCH_LATER")

    def test_research_first_beats_waste_history(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="RESEARCH_FIRST",
                        confidence="MEDIUM"),
            outcomes=make_outcomes(terminal_attempts=4, wasted_time=2)),
            "HUNT_NEXT")

    def test_default_skip(self):
        self.assertEqual(self._prio(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM")),
            "SKIP_FOR_NOW")

    def test_all_tiers_reachable(self):
        seen = set()
        seen.add(self._prio(make_action(current_status="IN_PROGRESS")))
        seen.add(self._prio(make_action()))
        seen.add(self._prio(
            make_action(current_status="READY",
                        opportunity_class="HIGH_VALUE", confidence="HIGH")))
        seen.add(self._prio(
            make_action(current_status="READY",
                        opportunity_class="GOOD_OPPORTUNITY",
                        confidence="HIGH")))
        seen.add(self._prio(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM"),
            outcomes=make_outcomes(terminal_attempts=2, wasted_time=2)))
        seen.add(self._prio(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM")))
        self.assertEqual(seen, set(HUNT_PRIORITIES))


class TestReasons(unittest.TestCase):
    def _reason(self, action, outcomes=None, sessions=None):
        priority = hq.classify_hunt_priority(
            action, outcomes or make_outcomes(),
            sessions or make_sessions())
        return priority, hq.build_hunt_reason(
            priority, action, outcomes or make_outcomes(),
            sessions or make_sessions())

    def test_active_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="IN_PROGRESS"))
        self.assertEqual(code, "ACTIVE_SESSION")
        self.assertIn("Active research session", text)

    def test_blocked_reason(self):
        _, (code, text) = self._reason(make_action())
        self.assertEqual(code, "BLOCKED")
        self.assertIn("Asset relationship", text)

    def test_accepted_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM"),
            outcomes=make_outcomes(accepted=1, terminal_attempts=1))
        self.assertEqual(code, "PREVIOUSLY_ACCEPTED")
        self.assertIn("Previously accepted", text)

    def test_high_value_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="READY",
                        opportunity_class="HIGH_VALUE", confidence="HIGH"))
        self.assertEqual(code, "HIGH_VALUE_HIGH_CONFIDENCE")

    def test_next_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="READY",
                        opportunity_class="GOOD_OPPORTUNITY",
                        confidence="HIGH"))
        self.assertEqual(code, "GOOD_OPPORTUNITY")

    def test_verify_low_confidence_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="LOW"))
        self.assertEqual(code, "LOW_CONFIDENCE")

    def test_later_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM"),
            outcomes=make_outcomes(terminal_attempts=2, wasted_time=2))
        self.assertEqual(code, "HIGH_DUPLICATE_WASTE")

    def test_skip_reason(self):
        _, (code, text) = self._reason(
            make_action(current_status="READY",
                        opportunity_class="DEFER", confidence="MEDIUM"))
        self.assertEqual(code, "NO_STRONG_SIGNAL")


class TestTimeBox(unittest.TestCase):
    def test_bands(self):
        cases = {0: "30 MIN", 30: "30 MIN", 31: "60 MIN", 60: "60 MIN",
                 61: "120 MIN", 90: "120 MIN", 120: "120 MIN",
                 121: "120 MIN + REVIEW", 480: "120 MIN + REVIEW"}
        for minutes, expected in cases.items():
            with self.subTest(minutes=minutes):
                self.assertEqual(hq.build_time_box(minutes), expected)


class TestHistory(unittest.TestCase):
    def test_history_aggregation(self):
        outcomes = make_outcomes(
            attempts=3, accepted=1, duplicate=1, rejected=0, wasted_time=0,
            total_time_spent_minutes=90, average_time_spent_minutes=30,
            latest_outcome={"status": "ACCEPTED"}, data_quality="MEDIUM")
        sessions = make_sessions(
            total_sessions=2, completed_sessions=1, actual_time=90,
            average_actual_minutes=45, latest_session_status="COMPLETED")
        item = hq.build_hunt_item(make_action(), outcomes, sessions)
        self.assertEqual(item.historical_outcome["attempts"], 3)
        self.assertEqual(item.historical_outcome["accepted"], 1)
        self.assertEqual(item.historical_outcome["duplicate"], 1)
        self.assertEqual(item.historical_outcome["latest_outcome"], "ACCEPTED")
        self.assertEqual(item.historical_time["total_time"], 90)
        self.assertEqual(item.historical_time["average_time"], 45)
        self.assertEqual(item.historical_time["latest_session_status"],
                         "COMPLETED")

    def test_no_history_defaults(self):
        item = hq.build_hunt_item(make_action(), {}, {})
        self.assertEqual(item.historical_outcome["attempts"], 0)
        self.assertEqual(item.historical_time["total_time"], 0)
        self.assertEqual(item.historical_time["latest_session_status"], "NONE")

    def test_no_history_not_penalized(self):
        # a high-value/high-confidence lead with no history is HUNT_NOW
        item = hq.build_hunt_item(
            make_action(current_status="READY",
                        opportunity_class="HIGH_VALUE", confidence="HIGH"),
            {}, {})
        self.assertEqual(item.hunt_priority, "HUNT_NOW")

    def test_history_does_not_change_money(self):
        item = hq.build_hunt_item(
            make_action(money_score=53),
            make_outcomes(accepted=5, terminal_attempts=5), {})
        self.assertEqual(item.money_score, 53)


class TestRanking(unittest.TestCase):
    def _item(self, lead_id, tier, money, confidence="HIGH",
              evidence="HIGH", minutes=30, cve=CVE, program="dell"):
        return HuntItem(
            hunt_id=hunt_id_for(lead_id), lead_id=lead_id, cve_id=cve,
            program=program, money_score=money, money_priority="P2_HIGH",
            opportunity_class="DEFER", current_status="READY",
            recommended_action="DEFER", confidence=confidence,
            evidence_quality=evidence, estimated_minutes=minutes,
            hunt_priority=tier, hunt_reason="x", hunt_reason_code="X")

    def test_tier_first(self):
        low = self._item(DELL, "SKIP_FOR_NOW", 99)
        high = self._item(INDEED, "HUNT_NOW", 1)
        ranked = hq.rank_hunt_queue([low, high])
        self.assertEqual(ranked[0].hunt_priority, "HUNT_NOW")

    def test_money_within_tier(self):
        a = self._item(DELL, "HUNT_NEXT", 53)
        b = self._item(INDEED, "HUNT_NEXT", 80)
        ranked = hq.rank_hunt_queue([a, b])
        self.assertEqual([r.money_score for r in ranked], [80, 53])

    def test_effort_tiebreak_ascending(self):
        slow = self._item(DELL, "HUNT_NEXT", 53, minutes=120)
        fast = self._item(INDEED, "HUNT_NEXT", 53, minutes=30)
        ranked = hq.rank_hunt_queue([slow, fast])
        self.assertEqual([r.estimated_minutes for r in ranked], [30, 120])

    def test_full_tiebreak(self):
        items = [
            self._item(DELL, "HUNT_NEXT", 53, cve="CVE-2024-0002",
                       program="b"),
            self._item(INDEED, "HUNT_NEXT", 53, cve="CVE-2024-0001",
                       program="a"),
            self._item("rl-0000000000000003", "HUNT_NEXT", 53,
                       cve="CVE-2024-0001", program="a"),
        ]
        ranked = hq.rank_hunt_queue(items)
        self.assertEqual([r.program for r in ranked], ["a", "a", "b"])
        self.assertEqual([r.lead_id for r in ranked][:2],
                         ["rl-0000000000000003", INDEED])

    def test_summary(self):
        items = [self._item(DELL, "HUNT_NOW", 80),
                 self._item(INDEED, "VERIFY_FIRST", 53)]
        summary = hq.build_hunt_summary(items)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_priority"]["HUNT_NOW"], 1)
        self.assertEqual(summary["by_priority"]["VERIFY_FIRST"], 1)
        self.assertTrue(summary["research_only"])
        self.assertEqual(summary["rule_version"], HUNT_RULE_VERSION)


class TestBackend(unittest.TestCase):
    def test_real_corpus(self):
        from backend import hunt_queue
        items = hunt_queue.build_hunt_queue()
        self.assertEqual(len(items), 2)
        for item in items:
            self.assertEqual(item["cve_id"], CVE)
            self.assertEqual(item["money_score"], 53)
            self.assertEqual(item["money_priority"], "P3_MEDIUM")
            self.assertEqual(item["hunt_priority"], "VERIFY_FIRST")
            self.assertEqual(item["hunt_reason"],
                             "Asset relationship is not sufficiently "
                             "established.")
            self.assertEqual(item["recommended_time_box"], "120 MIN")
            self.assertEqual(item["rule_version"], "r29-1")
            self.assertTrue(item["research_only"])

    def test_filters(self):
        from backend import hunt_queue
        self.assertEqual(hunt_queue.list_hunt_items(
            priority="VERIFY_FIRST")["total"], 2)
        self.assertEqual(hunt_queue.list_hunt_items(
            priority="HUNT_NOW")["total"], 0)
        self.assertEqual(hunt_queue.list_hunt_items(
            program="dell")["total"], 1)
        self.assertEqual(hunt_queue.list_hunt_items(cve=CVE)["total"], 2)
        self.assertEqual(hunt_queue.list_hunt_items(
            status="BLOCKED")["total"], 2)
        self.assertEqual(hunt_queue.list_hunt_items(
            opportunity_class="BLOCKED")["total"], 2)
        data = hunt_queue.list_hunt_items(limit=1)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 1)

    def test_detail_and_summary(self):
        from backend import hunt_queue
        item = hunt_queue.get_hunt_item(DELL)
        self.assertEqual(item["lead_id"], DELL)
        summary = hunt_queue.hunt_summary()
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_priority"]["VERIFY_FIRST"], 2)

    def test_detail_errors(self):
        from backend import hunt_queue
        with self.assertRaises(ValueError):
            hunt_queue.get_hunt_item("not-a-lead")
        with self.assertRaises(ValueError):
            hunt_queue.get_hunt_item("rl-ffffffffffffffff")

    def test_deterministic(self):
        from backend import hunt_queue
        self.assertEqual(hunt_queue.build_hunt_queue(),
                         hunt_queue.build_hunt_queue())

    def test_money_score_unchanged(self):
        from backend import hunt_queue
        from backend import research_economics
        before = research_economics.build_economics()
        hunt_queue.build_hunt_queue()
        hunt_queue.hunt_summary()
        after = research_economics.build_economics()
        self.assertEqual(before, after)
        self.assertEqual([e["money_score"] for e in after], [53, 53])

    def test_no_persistence(self):
        from backend import hunt_queue
        base = Path("/opt/watch/ai_data/research")
        before = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        hunt_queue.build_hunt_queue()
        after = sorted(str(p) for p in base.rglob("*")) if base.exists() else []
        self.assertEqual(before, after)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_human_output(self):
        code, out, _ = self._run(["hunt"])
        self.assertEqual(code, 0)
        self.assertIn("PERSONAL HUNT QUEUE", out)
        self.assertIn("#1 VERIFY_FIRST", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertIn("Money: 53 / P3", out)
        self.assertIn("Time box: 120 MIN", out)
        self.assertIn("Asset relationship is not sufficiently established.",
                      out)
        self.assertIn("Confirm affected component/plugin presence.", out)

    def test_json_and_filters(self):
        code, out, _ = self._run(["hunt", "--json"])
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["hunt_priority"], "VERIFY_FIRST")
        code, out, _ = self._run([
            "hunt", "--priority", "HUNT_NOW", "--json"])
        self.assertEqual(json.loads(out), [])
        code, out, _ = self._run(["hunt", "--program", "dell", "--json"])
        self.assertEqual(len(json.loads(out)), 1)
        code, out, _ = self._run(["hunt", "--cve", "CVE-2024-0001"])
        self.assertIn("none", out)

    def test_no_payout_flags(self):
        for flag in ("--payout", "--bounty", "--target", "--execute"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit) as ctx:
                    with redirect_stderr(io.StringIO()):
                        self._run(["hunt", flag, "x"])
                self.assertEqual(ctx.exception.code, 2)


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_auth_required(self):
        for path in ("/api/research/hunt", "/api/research/hunt/summary"):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_list_shape(self):
        r = self._get("/api/research/hunt")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["rule_version"], "r29-1")
        self.assertTrue(body["research_only"])
        self.assertEqual(body["items"][0]["hunt_priority"], "VERIFY_FIRST")

    def test_summary(self):
        body = self._get("/api/research/hunt/summary").json()
        self.assertEqual(body["by_priority"]["VERIFY_FIRST"], 2)
        self.assertTrue(body["research_only"])

    def test_filters(self):
        body = self._get("/api/research/hunt", program="dell").json()
        self.assertEqual(body["total"], 1)
        body = self._get("/api/research/hunt", priority="HUNT_NOW").json()
        self.assertEqual(body["total"], 0)

    def test_no_write_endpoint(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.post("/api/research/hunt", params=params)
        self.assertIn(r.status_code, (405, 401))

    def test_no_payout_vocabulary(self):
        blob = json.dumps(self._get("/api/research/hunt").json()).lower()
        for token in ("payout", "bounty", "reward", "amount", "usd"):
            self.assertNotIn(token, blob)


class TestUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_leads_page_hunt_section(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Personal hunt queue", r.text)
        title = r.text.split("Personal hunt queue", 1)[1].split(
            "ECONOMIC CALIBRATION", 1)[0]
        self.assertIn("VERIFY FIRST", title)
        self.assertIn("120 MIN", title)
        self.assertIn("Asset relationship", title)

    def test_lead_detail_hunt_panel(self):
        r = self._get(f"/ui/research/leads/{DELL}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Personal hunt decision", r.text)
        panel = r.text.split("Personal hunt decision", 1)[1].split(
            "Why investigate", 1)[0]
        self.assertIn("VERIFY FIRST", panel)
        self.assertIn("Time box", panel)
        self.assertIn("Historical", panel)
        self.assertIn("does not confirm vulnerability", panel)

    def test_no_charts_or_polling(self):
        r = self._get("/ui/research/leads")
        panel = r.text.split("Personal hunt queue", 1)[1].split(
            "ECONOMIC CALIBRATION", 1)[0]
        for token in ("setInterval", "websocket", "EventSource", "chart"):
            self.assertNotIn(token, panel)


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        for rel in ("ai/schemas/hunt_queue.py",
                    "ai/knowledge/hunt_queue.py",
                    "backend/hunt_queue.py"):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            for token in ("import subprocess", "subprocess.",
                          "import socket", "socket.",
                          "import requests", "requests.",
                          "import httpx", "httpx.",
                          "import openai", "import anthropic",
                          "from ai.llm", "nuclei.", "Popen(",
                          "selenium", "playwright", "os.system(",
                          "urlopen"):
                self.assertNotIn(token, source,
                                 f"{token} found in {rel}")

    def test_no_persistence_tokens(self):
        source = (Path("/opt/watch") / "backend"
                  / "hunt_queue.py").read_text(encoding="utf-8")
        for token in ("O_APPEND", "fsync", "open(", "os.replace",
                      "insert_one", "update_one", "pymongo", "mongoengine",
                      "write_text"):
            self.assertNotIn(token, source)

    def test_engine_purity(self):
        action = make_action()
        first = hq.build_hunt_item(action, make_outcomes(),
                                   make_sessions()).model_dump(mode="json")
        second = hq.build_hunt_item(action, make_outcomes(),
                                    make_sessions()).model_dump(mode="json")
        self.assertEqual(first, second)

    def test_upstream_rules_unchanged(self):
        from ai.knowledge import daily_research
        from ai.knowledge import economics
        from ai.knowledge import opportunity
        from ai.knowledge import opportunity_action
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(daily_research.WORKFLOW_VERSION, "r26-3")

    def test_no_forbidden_model_fields(self):
        fields = set(HuntItem.model_fields)
        for token in ("payout", "bounty", "reward", "target", "url", "ip",
                      "domain", "credential", "command", "finding"):
            self.assertFalse([f for f in fields if token in f.lower()],
                             f"{token} in {fields}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
