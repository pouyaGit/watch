"""
tests/test_research_workflow.py — Stage R20 research workflow tests.

Covers the deterministic task store (state machine, idempotent create,
optimistic concurrency, audit, atomic bounded persistence), the read/write API,
and the UI routes. No network, no subprocess, no LLM, no production Mongo.
"""
import ast
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge.task_store import (
    ALLOWED_TRANSITIONS,
    StaleTaskError,
    TaskNotFound,
    TaskStoreError,
    TaskValidationError,
    ResearchTaskStore,
    task_id_for,
)

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-1557"
QUEUE_ID = "rq-075e9ef25c8f94a7"


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


class _StoreBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = ResearchTaskStore(self._tmp.name)

    def _new(self, **kwargs):
        params = {"cve": CVE, "program": "dell", "queue_id": QUEUE_ID}
        params.update(kwargs)
        task, created = self.store.create(**params)
        return task, created


class TaskStoreTests(_StoreBase):
    def test_create_task(self):
        task, created = self._new(title="Investigate")
        self.assertTrue(created)
        self.assertEqual(task.status, "TODO")
        self.assertEqual(task.cve, CVE)
        self.assertEqual(task.program, "dell")
        self.assertEqual(task.queue_id, QUEUE_ID)
        self.assertEqual(task.version, 1)
        self.assertEqual(task.title, "Investigate")
        self.assertEqual(task.rule_version, "r20-1")
        self.assertTrue(task.created_at and task.updated_at)

    def test_deterministic_task_id(self):
        self.assertEqual(
            task_id_for(CVE, "dell", QUEUE_ID),
            task_id_for(CVE, "dell", QUEUE_ID),
        )
        task, _ = self._new()
        self.assertEqual(task.task_id, task_id_for(CVE, "dell", QUEUE_ID))
        self.assertRegex(task.task_id, r"^rt-[0-9a-f]{16}$")

    def test_duplicate_create_idempotency(self):
        first, created1 = self._new()
        second, created2 = self._new(title="Different title ignored")
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(first.task_id, second.task_id)
        self.assertEqual(second.title, first.title)
        json_files = [f for f in os.listdir(self._tmp.name) if f.endswith(".json")]
        self.assertEqual(len(json_files), 1)

    def test_todo_to_in_progress(self):
        task, _ = self._new()
        updated = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        self.assertEqual(updated.status, "IN_PROGRESS")
        self.assertEqual(updated.version, 2)

    def test_in_progress_to_blocked_requires_blocker(self):
        task, _ = self._new()
        task = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        with self.assertRaises(TaskValidationError):
            self.store.update(task.task_id, task.version, status="BLOCKED")
        blocked = self.store.update(
            task.task_id, task.version, status="BLOCKED", blocker="needs lab"
        )
        self.assertEqual(blocked.status, "BLOCKED")
        self.assertEqual(blocked.blocker, "needs lab")

    def test_blocked_to_in_progress(self):
        task, _ = self._new()
        task = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        task = self.store.update(
            task.task_id, task.version, status="BLOCKED", blocker="needs lab"
        )
        task = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        self.assertEqual(task.status, "IN_PROGRESS")

    def test_in_progress_to_done_requires_result(self):
        task, _ = self._new()
        task = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        with self.assertRaises(TaskValidationError):
            self.store.update(task.task_id, task.version, status="DONE")
        task = self.store.update(
            task.task_id, task.version, result_summary="Plugin not installed."
        )
        done = self.store.update(task.task_id, task.version, status="DONE")
        self.assertEqual(done.status, "DONE")
        self.assertTrue(done.completed_at)

    def test_invalid_transitions_rejected(self):
        task, _ = self._new()
        with self.assertRaises(TaskValidationError):
            self.store.update(task.task_id, task.version, status="DONE")
        with self.assertRaises(TaskValidationError):
            self.store.update(task.task_id, task.version, status="BLOCKED")
        task = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        task = self.store.update(
            task.task_id, task.version, result_summary="done"
        )
        task = self.store.update(task.task_id, task.version, status="DONE")
        with self.assertRaises(TaskValidationError):
            self.store.update(task.task_id, task.version, status="IN_PROGRESS")

    def test_notes_bounded(self):
        task, _ = self._new()
        with self.assertRaises(TaskValidationError):
            self.store.update(task.task_id, task.version, notes="n" * 5000)

    def test_references_bounded(self):
        task, _ = self._new()
        with self.assertRaises(TaskValidationError):
            self.store.update(
                task.task_id, task.version, references=["x"] * 25
            )
        with self.assertRaises(TaskValidationError):
            self.store.update(
                task.task_id, task.version, references=["x" * 600]
            )

    def test_audit_history(self):
        task, _ = self._new()
        task = self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        task = self.store.update(task.task_id, task.version, notes="more")
        self.assertGreaterEqual(len(task.history), 3)
        entry = task.history[-1]
        self.assertEqual(entry.previous_status, "IN_PROGRESS")
        self.assertEqual(entry.new_status, "IN_PROGRESS")
        self.assertEqual(entry.version, task.version)
        self.assertTrue(entry.at)
        # bounded
        for _ in range(80):
            task = self.store.update(task.task_id, task.version, notes="x")
        self.assertLessEqual(len(task.history), 50)

    def test_stale_update_rejected(self):
        task, _ = self._new()
        self.store.update(task.task_id, task.version, status="IN_PROGRESS")
        with self.assertRaises(StaleTaskError):
            self.store.update(task.task_id, 1, notes="stale")

    def test_atomic_persistence(self):
        task, _ = self._new()
        directory = Path(self._tmp.name)
        files = sorted(os.listdir(directory))
        self.assertIn(f"{task.task_id}.json", files)
        self.assertFalse([f for f in files if f.endswith(".tmp")])
        payload = json.loads(
            (directory / f"{task.task_id}.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["task_id"], task.task_id)

    def test_concurrent_create_and_update(self):
        results = []

        def create_many():
            for _ in range(5):
                results.append(self.store.create(CVE, "dell", QUEUE_ID))

        threads = [threading.Thread(target=create_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        created_true = [r for r in results if r[1]]
        self.assertEqual(len(created_true), 1)
        self.assertEqual(
            len([f for f in os.listdir(self._tmp.name) if f.endswith(".json")]), 1
        )

        task = self.store.get(task_id_for(CVE, "dell", QUEUE_ID))
        outcomes = []

        def update_once():
            try:
                self.store.update(task.task_id, task.version, notes="race")
                outcomes.append("ok")
            except StaleTaskError:
                outcomes.append("stale")

        threads = [threading.Thread(target=update_once) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("stale"), 3)

    def test_list_filter_and_missing(self):
        self._new()
        self.store.create(CVE, "indeed", "rq-1111111111111111")
        self.assertEqual(self.store.list()["total"], 2)
        self.assertEqual(self.store.list(cve=CVE)["total"], 2)
        self.assertEqual(self.store.list(status="DONE")["total"], 0)
        with self.assertRaises(TaskNotFound):
            self.store.get("rt-0000000000000000")
        with self.assertRaises(TaskValidationError):
            self.store.get("../etc/passwd")

    def test_corruption_resistant_list(self):
        self._new()
        bad = Path(self._tmp.name) / "rt-aaaaaaaaaaaaaaaa.json"
        bad.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.store.list()["total"], 1)


class SecurityBoundaryTests(unittest.TestCase):
    def _scan(self, rel):
        text = Path("/opt/watch", rel).read_text(encoding="utf-8")
        tree = ast.parse(text)
        banned = {
            "subprocess", "socket", "requests", "urllib", "httpx",
            "pymongo", "mongoengine", "openai", "database", "ftplib",
            "smtplib", "telnetlib", "http",
        }
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name.split(".")[0] for a in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module.split(".")[0])
                for name in names:
                    self.assertNotIn(name, banned, f"{rel} imports {name!r}")
        for needle in ("ai.llm", "mongo", "database.db",
                       "requests.", "socket."):
            self.assertNotIn(needle, text, f"{rel} references {needle!r}")

    def test_no_network_no_mongo_no_llm(self):
        for rel in ("ai/knowledge/task_store.py", "backend/research_tasks.py"):
            with self.subTest(rel=rel):
                self._scan(rel)

    def test_store_ops_without_network_or_subprocess(self):
        import socket
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            store = ResearchTaskStore(td)
            with mock.patch.object(
                socket, "socket", side_effect=AssertionError("network used")
            ):
                with mock.patch.object(
                    subprocess, "Popen", side_effect=AssertionError("subprocess used")
                ):
                    task, _ = store.create(CVE, "dell", QUEUE_ID)
                    task = store.update(task.task_id, task.version, status="IN_PROGRESS")
        self.assertEqual(task.status, "IN_PROGRESS")


class ApiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._patch = mock.patch(
            "backend.research_tasks.TASKS_DIR", Path(self._tmp.name)
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _req(self, method, path, **kwargs):
        if API_KEY:
            kwargs.setdefault("params", {})["api_key"] = API_KEY
        return self.client.request(method, path, **kwargs)

    def _create(self):
        return self._req(
            "POST",
            "/api/research/tasks",
            json={"cve": CVE, "program": "dell", "queue_id": QUEUE_ID},
        )

    def test_api_authentication(self):
        if not API_KEY:
            self.skipTest("API key not configured")
        r = self.client.get("/api/research/tasks")
        self.assertEqual(r.status_code, 401)
        r = self.client.post(
            "/api/research/tasks",
            json={"cve": CVE, "program": "dell", "queue_id": QUEUE_ID},
        )
        self.assertEqual(r.status_code, 401)

    def test_create_get_list(self):
        r = self._create()
        self.assertEqual(r.status_code, 201)
        body = r.json()
        self.assertTrue(body["created"])
        task = body["task"]
        self.assertEqual(task["status"], "TODO")
        tid = task["task_id"]
        r = self._req("GET", f"/api/research/tasks/{tid}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["task_id"], tid)
        r = self._req("GET", "/api/research/tasks")
        self.assertEqual(r.json()["total"], 1)

    def test_duplicate_create_idempotent(self):
        first = self._create().json()
        second = self._create().json()
        self.assertFalse(second["created"])
        self.assertEqual(first["task"]["task_id"], second["task"]["task_id"])

    def test_patch_transitions_and_gates(self):
        task = self._create().json()["task"]
        tid = task["task_id"]
        v = task["version"]
        r = self._req(
            "PATCH", f"/api/research/tasks/{tid}",
            json={"expected_version": v, "status": "IN_PROGRESS"},
        )
        self.assertEqual(r.status_code, 200)
        v = r.json()["version"]
        r = self._req(
            "PATCH", f"/api/research/tasks/{tid}",
            json={"expected_version": v, "status": "DONE"},
        )
        self.assertEqual(r.status_code, 400)
        r = self._req(
            "PATCH", f"/api/research/tasks/{tid}",
            json={"expected_version": v, "status": "BLOCKED", "blocker": "lab"},
        )
        self.assertEqual(r.status_code, 200)

    def test_stale_update_409(self):
        task = self._create().json()["task"]
        tid = task["task_id"]
        self._req(
            "PATCH", f"/api/research/tasks/{tid}",
            json={"expected_version": 1, "status": "IN_PROGRESS"},
        )
        r = self._req(
            "PATCH", f"/api/research/tasks/{tid}",
            json={"expected_version": 1, "notes": "stale"},
        )
        self.assertEqual(r.status_code, 409)

    def test_api_validation(self):
        r = self._req(
            "POST", "/api/research/tasks",
            json={"cve": "nope", "program": "dell", "queue_id": QUEUE_ID},
        )
        self.assertEqual(r.status_code, 400)
        r = self._req(
            "POST", "/api/research/tasks",
            json={"cve": CVE, "program": "dell", "queue_id": "bad"},
        )
        self.assertEqual(r.status_code, 400)
        # missing required fields -> 422 (pydantic)
        r = self._req("POST", "/api/research/tasks", json={"cve": CVE})
        self.assertEqual(r.status_code, 422)
        # malformed task id
        self.assertIn(
            self._req("GET", "/api/research/tasks/not-an-id").status_code,
            (400, 404),
        )

    def test_api_pagination(self):
        for program, qid in (("dell", QUEUE_ID),
                             ("indeed", "rq-1111111111111111")):
            self._req(
                "POST", "/api/research/tasks",
                json={"cve": CVE, "program": program, "queue_id": qid},
            )
        r = self._req("GET", "/api/research/tasks", params={"limit": 500})
        self.assertEqual(r.json()["limit"], 100)
        r = self._req("GET", "/api/research/tasks", params={"limit": 1, "offset": 0})
        self.assertEqual(len(r.json()["items"]), 1)

    def test_transitions_are_defined(self):
        self.assertEqual(ALLOWED_TRANSITIONS["TODO"], frozenset({"IN_PROGRESS"}))
        self.assertEqual(
            ALLOWED_TRANSITIONS["IN_PROGRESS"], frozenset({"BLOCKED", "DONE"})
        )
        self.assertEqual(ALLOWED_TRANSITIONS["DONE"], frozenset())


class UiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._patch = mock.patch(
            "backend.research_tasks.TASKS_DIR", Path(self._tmp.name)
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def _post(self, path, data, **params):
        p, q = _qs(path, **params)
        return self.client.post(p, data=data, params=q, follow_redirects=False)

    def test_tasks_page_empty_state(self):
        r = self._get("/ui/research/tasks")
        self.assertEqual(r.status_code, 200)
        self.assertIn("RESEARCH WORKFLOW — NOT VERIFIED", r.text)
        self.assertIn("No research tasks yet", r.text)

    def test_create_via_ui_and_detail(self):
        r = self._post("/ui/research/tasks", {
            "cve": CVE, "program": "dell", "queue_id": QUEUE_ID,
            "title": "Investigate WP plugin",
        })
        self.assertEqual(r.status_code, 303)
        r = self._get("/ui/research/tasks")
        self.assertIn("Investigate WP plugin", r.text)
        self.assertIn("TODO", r.text)
        import re
        tid = re.search(r"/ui/research/tasks/(rt-[0-9a-f]{16})", r.text).group(1)
        r = self._get(f"/ui/research/tasks/{tid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research Task", r.text)
        self.assertIn("Audit History", r.text)
        self.assertIn("RESEARCH WORKFLOW — NOT VERIFIED", r.text)

    def test_queue_page_has_start_research(self):
        r = self._get("/ui/research/queue")
        self.assertIn("Start Research", r.text)
        r = self._post("/ui/research/tasks", {
            "cve": CVE, "program": "dell", "queue_id": QUEUE_ID,
        })
        self.assertEqual(r.status_code, 303)
        r = self._get("/ui/research/queue")
        self.assertIn("Open task", r.text)

    def test_cve_detail_shows_tasks_panel(self):
        self._post("/ui/research/tasks", {
            "cve": CVE, "program": "dell", "queue_id": QUEUE_ID,
        })
        r = self._get(f"/ui/research/{CVE}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Research Tasks", r.text)

    def test_ui_stale_update_shows_error(self):
        self._post("/ui/research/tasks", {
            "cve": CVE, "program": "dell", "queue_id": QUEUE_ID,
        })
        import re
        r = self._get("/ui/research/tasks")
        tid = re.search(r"/ui/research/tasks/(rt-[0-9a-f]{16})", r.text).group(1)
        # first update succeeds
        self._post(f"/ui/research/tasks/{tid}", {
            "expected_version": "1", "status": "IN_PROGRESS", "notes": "",
            "blocker": "", "result_summary": "",
        })
        # replay with the old version -> 409 render
        r = self._post(f"/ui/research/tasks/{tid}", {
            "expected_version": "1", "status": "BLOCKED", "notes": "",
            "blocker": "x", "result_summary": "",
        })
        self.assertEqual(r.status_code, 409)
        self.assertIn("stale", r.text.lower())

    def test_hostile_values_escaped(self):
        payload = "<script>alert('xss')</script>"
        self._post("/ui/research/tasks", {
            "cve": CVE, "program": "dell", "queue_id": QUEUE_ID,
            "title": payload,
        })
        import re
        r = self._get("/ui/research/tasks")
        tid = re.search(r"/ui/research/tasks/(rt-[0-9a-f]{16})", r.text).group(1)
        self._post(f"/ui/research/tasks/{tid}", {
            "expected_version": "1", "status": "IN_PROGRESS",
            "notes": payload, "blocker": "", "result_summary": "",
        })
        r = self._get(f"/ui/research/tasks/{tid}")
        self.assertNotIn("<script>alert('xss')</script>", r.text)
        self.assertIn("&lt;script&gt;", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
