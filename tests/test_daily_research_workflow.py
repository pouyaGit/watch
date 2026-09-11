"""tests/test_daily_research_workflow.py — Stage R26.3 workflow tests.

Deterministic, offline tests for the daily research workflow: schema,
top-N, daily plan, blocked work, in-progress work, recommendations, the
closed-vocabulary workflow diff, backend composition, CLI (including the
read-only `workflow diff` file inputs), API, UI and safety invariants.

No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no findings, no alerts, no Mongo writes, no
snapshots, no persistence. Money Score is never modified.
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge import daily_research as daily
from ai.schemas.daily_research import (
    CHANGE_TYPES,
    WORKFLOW_VERSION,
    DailyWorkflow,
    WorkflowChange,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
DELL = "rl-af7ecfba1a86fc83"
INDEED = "rl-d1d66e2ee9d8467c"


def make_item(**over):
    item = {
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
        "action_reason": "Asset relationship to the vulnerability is unproven.",
        "blockers": ["only generic technology match",
                     "affected plugin not observed"],
        "why_now": ["PUBLIC_POC", "NO_SESSION_HISTORY"],
        "next_step": "Confirm affected component/plugin presence.",
        "session_status": "NONE",
        "outcome_status": "NONE",
        "rule_version": "r26-2",
        "research_only": True,
    }
    item.update(over)
    return item


def make_ready(**over):
    item = make_item(
        opportunity_class="HIGH_VALUE", current_status="READY",
        recommended_action="START_RESEARCH", money_score=78,
        blockers=[], action_reason="Opportunity class is HIGH_VALUE.",
        next_step="Begin a time-boxed research session.")
    item.update(over)
    return item


class TestSchema(unittest.TestCase):
    def test_workflow_version_and_research_only_forced(self):
        model = DailyWorkflow(workflow_version="other", research_only=True)
        self.assertEqual(model.workflow_version, WORKFLOW_VERSION)
        with self.assertRaises(ValueError):
            DailyWorkflow(research_only=False)

    def test_change_types_closed(self):
        self.assertEqual(WorkflowChange(
            lead_id=DELL, change_type="new").change_type, "NEW")
        with self.assertRaises(ValueError):
            WorkflowChange(lead_id=DELL, change_type="SOMETHING")

    def test_forbidden_fields_rejected(self):
        for field in ("payout", "bounty", "reward", "target_url", "ip",
                      "domain", "execution_command", "production_finding"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    DailyWorkflow(**{field: "x"})
                with self.assertRaises(ValueError):
                    WorkflowChange(lead_id=DELL, change_type="NEW",
                                   **{field: "x"})

    def test_no_forbidden_model_fields(self):
        for model in (DailyWorkflow, WorkflowChange):
            fields = set(model.model_fields)
            for token in ("payout", "bounty", "reward", "target", "url",
                          "ip", "domain", "command", "finding"):
                self.assertFalse([f for f in fields if token in f.lower()],
                                 f"{token} in {model.__name__}: {fields}")

    def test_bounded_lists(self):
        model = DailyWorkflow(recommendations=["a", "a", "b"])
        self.assertEqual(model.recommendations, ["a", "b"])


class TestTopOpportunities(unittest.TestCase):
    def test_default_and_custom_top_n(self):
        items = [make_item(lead_id=f"rl-{i:016x}") for i in range(8)]
        self.assertEqual(
            len(daily.build_top_opportunities(items)), 5)
        self.assertEqual(
            len(daily.build_top_opportunities(items, top_n=2)), 2)

    def test_item_shape_and_order(self):
        items = [make_item(), make_item(lead_id=INDEED, program="indeed")]
        top = daily.build_top_opportunities(items)
        self.assertEqual([t["lead_id"] for t in top], [DELL, INDEED])
        for field in ("lead_id", "cve_id", "program", "opportunity_class",
                      "money_score", "confidence", "evidence_quality",
                      "estimated_minutes", "current_status",
                      "recommended_action", "why_now", "blockers",
                      "next_step"):
            self.assertIn(field, top[0])

    def test_empty(self):
        self.assertEqual(daily.build_top_opportunities([]), [])

    def test_malformed_items_skipped(self):
        self.assertEqual(
            daily.build_top_opportunities(["bad", {"no_lead": 1}, None]), [])


class TestDailyPlan(unittest.TestCase):
    def test_ready_only(self):
        items = [make_ready(), make_item()]
        plan = daily.build_daily_plan(items)
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["lead_id"], DELL)
        self.assertEqual(plan[0]["recommended_action"], "START_RESEARCH")
        self.assertIn("next_step", plan[0])
        self.assertIn("reason", plan[0])
        self.assertIn("estimated_minutes", plan[0])

    def test_order_preserved(self):
        items = [make_ready(), make_ready(lead_id=INDEED, program="indeed")]
        plan = daily.build_daily_plan(items)
        self.assertEqual([p["lead_id"] for p in plan], [DELL, INDEED])


class TestBlockedWork(unittest.TestCase):
    def test_blocked_items(self):
        blocked = daily.build_blocked_work([make_item(), make_ready()])
        self.assertEqual(len(blocked), 1)
        item = blocked[0]
        self.assertEqual(item["money_score"], 53)
        self.assertIn("only generic technology match", item["blockers"])
        codes = [e["code"] for e in item["blocker_explanations"]]
        self.assertIn("affected plugin not observed", codes)
        self.assertTrue(all(e["text"] for e in item["blocker_explanations"]))
        self.assertEqual(item["recommended_action"], "VERIFY_ASSET_MATCH")
        self.assertTrue(item["next_step"])

    def test_unknown_blocker_code_fallback(self):
        item = make_item(blockers=["mystery blocker code"])
        blocked = daily.build_blocked_work([item])
        self.assertEqual(
            blocked[0]["blocker_explanations"][0]["text"],
            "Investigate the unknown blocker code.")


class TestInProgressWork(unittest.TestCase):
    def test_active_session_detail(self):
        items = [make_item(current_status="IN_PROGRESS",
                           recommended_action="CONTINUE_RESEARCH")]
        sessions = {DELL: [{"session_id": "rs-1", "planned_minutes": 60,
                            "actual_minutes": 0, "status": "IN_PROGRESS"}]}
        work = daily.build_in_progress_work(items, sessions)
        self.assertEqual(len(work), 1)
        entry = work[0]
        self.assertEqual(entry["session_id"], "rs-1")
        self.assertEqual(entry["planned_minutes"], 60)
        self.assertEqual(entry["status"], "IN_PROGRESS")
        self.assertEqual(entry["recommended_action"], "CONTINUE_RESEARCH")

    def test_skips_non_active(self):
        items = [make_item(current_status="IN_PROGRESS")]
        sessions = {DELL: [{"session_id": "rs-1", "status": "COMPLETED",
                            "planned_minutes": 60, "actual_minutes": 60}]}
        self.assertEqual(daily.build_in_progress_work(items, sessions), [])
        self.assertEqual(daily.build_in_progress_work([make_item()],
                                                      sessions), [])

    def test_no_sessions(self):
        items = [make_item(current_status="IN_PROGRESS")]
        self.assertEqual(daily.build_in_progress_work(items, {}), [])


class TestRecommendations(unittest.TestCase):
    def _rec(self, **over):
        base = {
            "total_opportunities": 1, "ready": 0, "blocked": 0,
            "in_progress": 0, "completed": 0, "ready_high_value": False,
            "has_terminal_outcomes": False,
        }
        base.update(over)
        return daily.build_workflow_recommendations(base)

    def test_empty(self):
        self.assertEqual(
            self._rec(total_opportunities=0),
            [daily.RECOMMEND_NONE])

    def test_all_blocked(self):
        recs = self._rec(blocked=2, total_opportunities=2)
        self.assertEqual(recs, [daily.RECOMMEND_RESOLVE_BLOCKERS])

    def test_high_value_ready(self):
        recs = self._rec(ready=1, ready_high_value=True)
        self.assertEqual(recs, [daily.RECOMMEND_START_HIGH])

    def test_ready_non_high(self):
        recs = self._rec(ready=1)
        self.assertEqual(recs, [daily.RECOMMEND_WORK_READY])

    def test_active_session(self):
        recs = self._rec(in_progress=1, total_opportunities=2)
        self.assertEqual(recs, [daily.RECOMMEND_CONTINUE])

    def test_completed_outcome(self):
        recs = self._rec(completed=1)
        self.assertEqual(recs, [daily.RECOMMEND_REVIEW_OUTCOMES])

    def test_multiple_recommendations_order(self):
        recs = self._rec(in_progress=1, ready=1, ready_high_value=True,
                         completed=1, total_opportunities=3)
        self.assertEqual(recs, [daily.RECOMMEND_CONTINUE,
                                daily.RECOMMEND_START_HIGH,
                                daily.RECOMMEND_REVIEW_OUTCOMES])


class TestDailyWorkflow(unittest.TestCase):
    def test_counts_and_shape(self):
        items = [make_ready(), make_item(), make_item(
            lead_id=INDEED, program="indeed", current_status="IN_PROGRESS"),
            make_item(lead_id="rl-0000000000000003", current_status="COMPLETED"),
            make_item(lead_id="rl-0000000000000004",
                      current_status="DEFERRED")]
        workflow = daily.build_daily_workflow(items)
        self.assertEqual(workflow.total_opportunities, 5)
        self.assertEqual(workflow.ready, 1)
        self.assertEqual(workflow.blocked, 1)
        self.assertEqual(workflow.in_progress, 1)
        self.assertEqual(workflow.completed, 1)
        self.assertEqual(workflow.deferred, 1)
        self.assertEqual(workflow.workflow_version, WORKFLOW_VERSION)
        self.assertTrue(workflow.research_only)
        self.assertEqual(len(workflow.items), 5)

    def test_empty_workflow(self):
        workflow = daily.build_daily_workflow([])
        self.assertEqual(workflow.total_opportunities, 0)
        self.assertEqual(workflow.recommendations, [daily.RECOMMEND_NONE])
        self.assertEqual(workflow.top_actions, [])
        self.assertEqual(workflow.changed_items, [])

    def test_deterministic(self):
        items = [make_ready(), make_item()]
        first = daily.build_daily_workflow(items).model_dump(mode="json")
        second = daily.build_daily_workflow(items).model_dump(mode="json")
        self.assertEqual(first, second)

    def test_summary(self):
        workflow = daily.build_daily_workflow([make_item()])
        summary = daily.build_workflow_summary(workflow)
        self.assertEqual(summary["blocked"], 1)
        self.assertEqual(summary["top_action"], {})
        self.assertEqual(summary["recommendation"],
                         daily.RECOMMEND_RESOLVE_BLOCKERS)
        self.assertTrue(summary["research_only"])
        self.assertEqual(summary["workflow_version"], WORKFLOW_VERSION)

    def test_no_duplicate_score(self):
        workflow = daily.build_daily_workflow([make_item()])
        blob = json.dumps(workflow.model_dump(mode="json"))
        self.assertNotIn("opportunity_score", blob)
        self.assertNotIn("workflow_score", blob)


class TestCompare(unittest.TestCase):
    def _doc(self, items):
        return {"items": items}

    def test_new(self):
        changes = daily.compare_workflows(self._doc([]),
                                          self._doc([make_item()]))
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["change_type"], "NEW")
        self.assertIsNone(changes[0]["before"])
        self.assertEqual(changes[0]["lead_id"], DELL)
        self.assertEqual(changes[0]["cve_id"], CVE)

    def test_removed(self):
        changes = daily.compare_workflows(self._doc([make_item()]),
                                          self._doc([]))
        self.assertEqual(changes[0]["change_type"], "REMOVED")
        self.assertIsNone(changes[0]["after"])

    def test_class_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item()]),
            self._doc([make_item(opportunity_class="HIGH_VALUE")]))
        self.assertEqual([c["change_type"] for c in changes],
                         ["CLASS_CHANGED"])
        self.assertEqual(changes[0]["before"], "BLOCKED")
        self.assertEqual(changes[0]["after"], "HIGH_VALUE")

    def test_action_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item()]),
            self._doc([make_item(recommended_action="START_RESEARCH")]))
        self.assertIn("ACTION_CHANGED",
                      [c["change_type"] for c in changes])

    def test_money_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item(money_score=53)]),
            self._doc([make_item(money_score=71)]))
        self.assertIn("MONEY_CHANGED",
                      [c["change_type"] for c in changes])
        entry = next(c for c in changes if c["change_type"] == "MONEY_CHANGED")
        self.assertEqual(entry["before"], 53)
        self.assertEqual(entry["after"], 71)

    def test_confidence_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item(confidence="HIGH")]),
            self._doc([make_item(confidence="MEDIUM")]))
        self.assertIn("CONFIDENCE_CHANGED",
                      [c["change_type"] for c in changes])

    def test_evidence_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item(evidence_quality="LOW")]),
            self._doc([make_item(evidence_quality="HIGH")]))
        self.assertIn("EVIDENCE_CHANGED",
                      [c["change_type"] for c in changes])

    def test_session_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item(session_status="NONE")]),
            self._doc([make_item(session_status="ACTIVE")]))
        self.assertIn("SESSION_CHANGED",
                      [c["change_type"] for c in changes])

    def test_session_changed_fallback_current_status(self):
        before = make_item(current_status="READY")
        after = make_item(current_status="IN_PROGRESS")
        before.pop("session_status")
        after.pop("session_status")
        changes = daily.compare_workflows(
            self._doc([before]), self._doc([after]))
        self.assertIn("SESSION_CHANGED",
                      [c["change_type"] for c in changes])

    def test_outcome_changed(self):
        changes = daily.compare_workflows(
            self._doc([make_item(outcome_status="NONE")]),
            self._doc([make_item(outcome_status="ACCEPTED")]))
        self.assertIn("OUTCOME_CHANGED",
                      [c["change_type"] for c in changes])

    def test_unchanged(self):
        self.assertEqual(
            daily.compare_workflows(self._doc([make_item()]),
                                    self._doc([make_item()])), [])

    def test_deterministic_and_type_order(self):
        before = {"items": [make_item(), make_item(
            lead_id=INDEED, program="indeed", money_score=10)]}
        after = {"items": [make_item(opportunity_class="HIGH_VALUE",
                                     money_score=71),
                           make_item(lead_id=INDEED, program="indeed",
                                     money_score=99, outcome_status="ACCEPTED")]}
        first = daily.compare_workflows(before, after)
        second = daily.compare_workflows(before, after)
        self.assertEqual(first, second)
        for entry in first:
            self.assertIn(entry["change_type"], CHANGE_TYPES)
        lead_ids = [c["lead_id"] for c in first]
        self.assertEqual(lead_ids, sorted(lead_ids))

    def test_accepts_list_and_all_document_keys(self):
        self.assertEqual(
            daily.compare_workflows([], [make_item()])[0]["change_type"],
            "NEW")
        for key in ("items", "top_opportunities", "top_actions",
                    "blocked_items"):
            changes = daily.compare_workflows({key: []},
                                              {key: [make_item()]})
            self.assertEqual(changes[0]["change_type"], "NEW")

    def test_malformed_inputs(self):
        for bad in (None, 42, "text", {"no_items": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    daily.compare_workflows(bad, {"items": []})
                with self.assertRaises(ValueError):
                    daily.compare_workflows({"items": []}, bad)

    def test_empty_workflows(self):
        self.assertEqual(
            daily.compare_workflows({"items": []}, {"items": []}), [])


class TestBackend(unittest.TestCase):
    def test_real_corpus(self):
        from backend import daily_research
        workflow = daily_research.build_daily_workflow()
        self.assertEqual(workflow["workflow_version"], "r26-3")
        self.assertEqual(workflow["total_opportunities"], 2)
        self.assertEqual(workflow["blocked"], 2)
        self.assertEqual(workflow["ready"], 0)
        self.assertEqual(workflow["in_progress"], 0)
        self.assertEqual(workflow["top_actions"], [])
        self.assertEqual(len(workflow["blocked_items"]), 2)
        self.assertEqual(len(workflow["top_opportunities"]), 2)
        self.assertEqual(workflow["top_opportunities"][0]
                         ["recommended_action"], "VERIFY_ASSET_MATCH")
        self.assertEqual(workflow["recommendations"],
                         [daily.RECOMMEND_RESOLVE_BLOCKERS])
        self.assertTrue(workflow["research_only"])

    def test_filters(self):
        from backend import daily_research
        self.assertEqual(daily_research.build_daily_workflow(
            program="dell")["total_opportunities"], 1)
        self.assertEqual(daily_research.build_daily_workflow(
            cve=CVE)["total_opportunities"], 2)
        blocked = daily_research.build_daily_workflow(
            opportunity_class="BLOCKED")
        self.assertEqual(blocked["blocked"], 2)
        ready = daily_research.build_daily_workflow(status="READY")
        self.assertEqual(ready["total_opportunities"], 0)
        self.assertEqual(ready["recommendations"], [daily.RECOMMEND_NONE])

    def test_summary(self):
        from backend import daily_research
        summary = daily_research.daily_summary()
        self.assertEqual(summary["blocked"], 2)
        self.assertEqual(summary["recommendation"],
                         daily.RECOMMEND_RESOLVE_BLOCKERS)
        self.assertTrue(summary["research_only"])

    def test_compare_between_builds(self):
        from backend import daily_research
        current = daily_research.build_daily_workflow()
        previous = json.loads(json.dumps(current))
        previous["items"] = previous["items"][:1]
        changes = daily_research.compare_daily_workflows(previous, current)
        self.assertEqual([c["change_type"] for c in changes], ["NEW"])

    def test_deterministic(self):
        from backend import daily_research
        self.assertEqual(daily_research.build_daily_workflow(),
                         daily_research.build_daily_workflow())

    def test_no_snapshot_dir_or_writes(self):
        from backend import daily_research
        before = sorted(str(p) for p in Path(
            "/opt/watch/ai_data/research").rglob("*"))
        daily_research.build_daily_workflow()
        daily_research.daily_summary()
        daily_research.compare_daily_workflows({"items": []},
                                               {"items": []})
        after = sorted(str(p) for p in Path(
            "/opt/watch/ai_data/research").rglob("*"))
        self.assertEqual(before, after)
        self.assertFalse(Path(
            "/opt/watch/ai_data/research/snapshots").exists())

    def test_money_score_unchanged(self):
        from backend import daily_research
        from backend import research_economics
        before = research_economics.build_economics()
        daily_research.build_daily_workflow()
        after = research_economics.build_economics()
        self.assertEqual(before, after)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        from ai.research_cli import main
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_daily_human(self):
        code, out, _ = self._run(["workflow", "daily"])
        self.assertEqual(code, 0)
        self.assertIn("DAILY RESEARCH WORKFLOW", out)
        self.assertIn("READY: 0", out)
        self.assertIn("BLOCKED: 2", out)
        self.assertIn("IN PROGRESS: 0", out)
        self.assertIn("TOP OPPORTUNITIES", out)
        self.assertIn("CVE-2026-1557 → dell", out)
        self.assertIn("Action: VERIFY_ASSET_MATCH", out)
        self.assertIn("BLOCKED WORK", out)
        self.assertIn("RECOMMENDATION", out)
        self.assertIn("Resolve asset-match blockers", out)

    def test_daily_json_and_filters(self):
        code, out, _ = self._run(["workflow", "daily", "--json"])
        self.assertEqual(code, 0)
        workflow = json.loads(out)
        self.assertEqual(workflow["workflow_version"], "r26-3")
        self.assertEqual(workflow["blocked"], 2)
        code, out, _ = self._run([
            "workflow", "daily", "--program", "dell", "--json"])
        self.assertEqual(len(json.loads(out)["top_opportunities"]), 1)
        code, out, _ = self._run([
            "workflow", "daily", "--limit", "1", "--json"])
        self.assertEqual(len(json.loads(out)["top_opportunities"]), 1)
        code, out, _ = self._run([
            "workflow", "daily", "--class", "BLOCKED", "--json"])
        self.assertEqual(json.loads(out)["blocked"], 2)

    def test_workflow_has_no_payout_flags(self):
        for flag in ("--payout", "--bounty", "--target", "--execute"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit) as ctx:
                    with redirect_stderr(io.StringIO()):
                        self._run(["workflow", "daily", flag, "x"])
                self.assertEqual(ctx.exception.code, 2)

    def test_diff_files_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = self._run(["workflow", "daily", "--json"])[1]
            previous_obj = json.loads(current)
            previous_obj["items"] = [dict(previous_obj["items"][0])]
            previous_obj["items"][0]["money_score"] = 40
            previous_obj["items"][0]["recommended_action"] = "START_RESEARCH"
            prev_path = Path(tmp) / "prev.json"
            curr_path = Path(tmp) / "curr.json"
            prev_path.write_text(json.dumps(previous_obj), encoding="utf-8")
            curr_path.write_text(current, encoding="utf-8")
            prev_bytes = prev_path.read_bytes()
            curr_bytes = curr_path.read_bytes()
            code, out, _ = self._run([
                "workflow", "diff", "--previous", str(prev_path),
                "--current", str(curr_path)])
            self.assertEqual(code, 0)
            self.assertIn("WORKFLOW CHANGES", out)
            self.assertIn("ACTION_CHANGED", out)
            self.assertIn("START_RESEARCH → VERIFY_ASSET_MATCH", out)
            self.assertIn("MONEY_CHANGED", out)
            self.assertIn("40 → 53", out)
            self.assertIn("NEW", out)
            # inputs are never modified
            self.assertEqual(prev_path.read_bytes(), prev_bytes)
            self.assertEqual(curr_path.read_bytes(), curr_bytes)

    def test_diff_json_and_no_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = self._run(["workflow", "daily", "--json"])[1]
            path = Path(tmp) / "wf.json"
            path.write_text(current, encoding="utf-8")
            code, out, _ = self._run([
                "workflow", "diff", "--previous", str(path),
                "--current", str(path), "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out), [])
            code, out, _ = self._run([
                "workflow", "diff", "--previous", str(path),
                "--current", str(path)])
            self.assertEqual(code, 0)
            self.assertIn("none", out)

    def test_diff_malformed_inputs(self):
        code, _, err = self._run([
            "workflow", "diff", "--previous", "/nonexistent.json",
            "--current", "/nonexistent.json"])
        self.assertEqual(code, 1)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            good = Path(tmp) / "good.json"
            bad.write_text("{not json", encoding="utf-8")
            good.write_text("{\"items\": []}", encoding="utf-8")
            code, _, err = self._run([
                "workflow", "diff", "--previous", str(bad),
                "--current", str(good)])
            self.assertEqual(code, 1)
            self.assertIn("invalid JSON", err)
            bad.write_text("{\"no_items\": 1}", encoding="utf-8")
            code, _, err = self._run([
                "workflow", "diff", "--previous", str(bad),
                "--current", str(good)])
            self.assertEqual(code, 1)
            self.assertIn("malformed", err)


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
        for path in ("/api/research/workflow/daily",
                     "/api/research/workflow/summary"):
            with self.subTest(path=path):
                r = self.client.get(path)
                if API_KEY:
                    self.assertEqual(r.status_code, 401)

    def test_daily_shape(self):
        r = self._get("/api/research/workflow/daily")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["workflow_version"], "r26-3")
        self.assertTrue(body["research_only"])
        self.assertEqual(body["blocked"], 2)
        self.assertEqual(body["recommendations"],
                         [daily.RECOMMEND_RESOLVE_BLOCKERS])
        for key in ("top_actions", "top_opportunities", "blocked_items",
                    "in_progress_items", "changed_items", "items"):
            self.assertIn(key, body)

    def test_summary(self):
        r = self._get("/api/research/workflow/summary")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["blocked"], 2)
        self.assertEqual(r.json()["workflow_version"], "r26-3")

    def test_filters_and_bounds(self):
        body = self._get("/api/research/workflow/daily",
                         program="dell").json()
        self.assertEqual(body["total_opportunities"], 1)
        body = self._get("/api/research/workflow/daily", limit=1).json()
        self.assertEqual(len(body["top_opportunities"]), 1)
        bad = self._get("/api/research/workflow/daily", limit=0)
        self.assertEqual(bad.status_code, 422)

    def test_no_write_endpoints(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        r = self.client.post("/api/research/workflow/daily", params=params)
        self.assertIn(r.status_code, (405, 401))

    def test_no_payout_vocabulary(self):
        blob = json.dumps(
            self._get("/api/research/workflow/daily").json()).lower()
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

    def test_leads_page_workflow_section(self):
        r = self._get("/ui/research/leads")
        self.assertEqual(r.status_code, 200)
        for text in ("Daily research workflow", "Ready", "Blocked",
                     "In progress", "Top opportunities",
                     "Resolve asset-match blockers"):
            self.assertIn(text, r.text)
        panel = r.text.split("Daily research workflow", 1)[1].split(
            'action="/ui/research/leads"', 1)[0]
        for token in ("payout", "bounty", "target url", "run nuclei"):
            self.assertNotIn(token, panel.lower())

    def test_no_new_page_or_polling(self):
        r = self._get("/ui/research/leads")
        panel = r.text.split("Daily research workflow", 1)[1]
        for token in ("setInterval", "websocket", "EventSource"):
            self.assertNotIn(token, panel)


class TestSafety(unittest.TestCase):
    def test_no_execution_tokens(self):
        for rel in ("ai/schemas/daily_research.py",
                    "ai/knowledge/daily_research.py",
                    "backend/daily_research.py"):
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
                  / "daily_research.py").read_text(encoding="utf-8")
        for token in ("O_APPEND", "fsync", "open(", "os.replace",
                      "insert_one", "update_one", "pymongo", "mongoengine",
                      "store_snapshot", "write_text"):
            self.assertNotIn(token, source)

    def test_engine_pure(self):
        items = [make_item()]
        first = daily.build_daily_workflow(items).model_dump(mode="json")
        second = daily.build_daily_workflow(items).model_dump(mode="json")
        self.assertEqual(first, second)

    def test_money_and_upstream_rules_unchanged(self):
        from ai.knowledge import economics
        from ai.knowledge import opportunity_action
        from ai.knowledge import opportunity
        self.assertEqual(economics.MONEY_W_VALUE, 0.55)
        self.assertEqual(economics.MONEY_W_CONFIDENCE, 0.15)
        self.assertEqual(economics.MONEY_W_EFFORT_EFF, 0.15)
        self.assertEqual(economics.MONEY_W_RISK_AVOID, 0.15)
        self.assertEqual(economics.RULE_VERSION, "r25-1")
        self.assertEqual(opportunity_action.ACTION_RULE_VERSION, "r26-2")
        self.assertEqual(opportunity.OPPORTUNITY_RULE_VERSION, "r26-1")

    def test_calibration_unchanged(self):
        from backend import research_calibration
        report = research_calibration.build_report()
        self.assertEqual(report["recommendation"], "INSUFFICIENT_DATA")
        self.assertTrue(report["weights_unchanged"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
