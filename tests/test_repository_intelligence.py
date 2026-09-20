"""tests/test_repository_intelligence.py — Repository State Intelligence v1.

Focused tests for ``backend.repository_intelligence``:

- path classification (source / generated knowledge / agent reports /
  runtime / ignored / unknown);
- generated knowledge detection (modified index + new documents);
- agent report detection (untracked + modified);
- source code modification detection;
- deleted-file detection;
- unknown file detection;
- runtime / ignored artifact markers;
- deterministic summary + risk;
- Git index v2/v3 parsing (and v4 rejection);
- Command Center integration (page panel + JSON projections).

Fully offline: Git index data is supplied directly or built synthetically, so
no git command is ever run. No network, no writes, no LLM.
"""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import repository_intelligence as ri
from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")


def _qs(path, **params):
    if API_KEY:
        params["api_key"] = API_KEY
    return path, params


def _write(root: Path, rel: str, content: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _tracked(path: Path, *, modified: bool = False) -> dict:
    stat = path.stat()
    size = stat.st_size + (1 if modified else 0)
    return {"size": size, "mtime_s": int(stat.st_mtime), "sha": ""}


def _build_index(entries) -> bytes:
    """Build a minimal Git index v2 (entries: (name, size, mtime_s, sha_hex))."""

    body = b""
    for name, size, mtime_s, sha_hex in entries:
        raw = name.encode("utf-8")
        record = struct.pack(
            ">10I", 0, 0, mtime_s, 0, 0, 0, 0o100644, 0, 0, size)
        record += bytes.fromhex(sha_hex)
        record += struct.pack(">H", len(raw) & 0x0FFF)
        record += raw + b"\x00"
        pad = (8 - (len(record) % 8)) % 8
        record += b"\x00" * pad
        body += record
    return (b"DIRC" + struct.pack(">II", 2, len(entries)) + body
            + b"\x00" * 20)


class _RepoFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class TestClassification(unittest.TestCase):
    def test_classify_path(self):
        cases = {
            "backend/app.py": "source_changes",
            "web/templates/x.html": "source_changes",
            "tests/test_x.py": "source_changes",
            "docs/readme.md": "source_changes",
            "wordlists/dell_params.txt": "source_changes",
            "ai_data/knowledge/index.json": "generated_knowledge",
            "ai_data/knowledge/documents/ab.json": "generated_knowledge",
            "agent-reports/foo.md": "agent_reports",
            "ai_data/research/watchlist/x.json": "runtime_artifacts",
            "logs/task.log": "runtime_artifacts",
            "something.lock": "runtime_artifacts",
            ".env": "ignored_artifacts",
            "Thumbs.db": "ignored_artifacts",
            "notes.unknownext": "unknown_changes",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(ri.classify_path(path), expected)


class TestDetection(_RepoFixture):
    def test_generated_knowledge_detection(self):
        index_json = _write(self.root, "ai_data/knowledge/index.json", "{}")
        _write(self.root, "ai_data/knowledge/documents/abc.json", "{}")
        tracked = {"ai_data/knowledge/index.json": _tracked(index_json,
                                                            modified=True)}
        result = ri.analyze(self.root, tracked=tracked)
        category = result["categories"]["generated_knowledge"]
        self.assertIn("ai_data/knowledge/index.json", category)
        self.assertIn("ai_data/knowledge/documents/abc.json", category)
        self.assertEqual(result["summary"]["counts"]["generated_knowledge"], 2)

    def test_agent_report_detection(self):
        old = _write(self.root, "agent-reports/old.md", "# old")
        _write(self.root, "agent-reports/new.md", "# new")
        tracked = {"agent-reports/old.md": _tracked(old, modified=True)}
        result = ri.analyze(self.root, tracked=tracked)
        category = result["categories"]["agent_reports"]
        self.assertIn("agent-reports/old.md", category)
        self.assertIn("agent-reports/new.md", category)
        self.assertEqual(result["summary"]["counts"]["agent_reports"], 2)

    def test_source_code_modification_detection(self):
        tracked = {}
        for rel in ("backend/app.py", "web/app.js", "tests/test_app.py"):
            tracked[rel] = _tracked(_write(self.root, rel), modified=True)
        result = ri.analyze(self.root, tracked=tracked)
        self.assertEqual(
            result["categories"]["source_changes"],
            ["backend/app.py", "tests/test_app.py", "web/app.js"],
        )
        self.assertEqual(result["summary"]["risk"], "high")

    def test_deleted_file_detection(self):
        tracked = {"backend/removed.py": {"size": 10, "mtime_s": 1, "sha": ""}}
        result = ri.analyze(self.root, tracked=tracked)
        self.assertEqual(result["categories"]["deleted_files"],
                         ["backend/removed.py"])
        self.assertEqual(result["summary"]["risk"], "high")

    def test_unknown_file_detection(self):
        _write(self.root, "mystery.bin", "??")
        result = ri.analyze(self.root, tracked={})
        self.assertEqual(result["categories"]["unknown_changes"],
                         ["mystery.bin"])
        self.assertEqual(result["summary"]["risk"], "medium")

    def test_runtime_and_ignored_markers(self):
        _write(self.root, "logs/watch.log", "log")
        _write(self.root, ".env", "SECRET=1")
        _write(self.root, "venv/lib/site.py", "x")
        _write(self.root, "session.lock", "lock")
        result = ri.analyze(self.root, tracked={})
        runtime = result["categories"]["runtime_artifacts"]
        ignored = result["categories"]["ignored_artifacts"]
        self.assertIn("logs/", runtime)
        self.assertIn("session.lock", runtime)
        self.assertIn(".env", ignored)
        self.assertIn("venv/", ignored)

    def test_clean_state_and_summary(self):
        app = _write(self.root, "backend/app.py", "print(1)")
        result = ri.analyze(self.root, tracked={"backend/app.py": _tracked(app)})
        self.assertEqual(result["summary"]["state"], "clean")
        self.assertEqual(result["summary"]["risk"], "none")
        self.assertEqual(result["summary"]["total_changes"], 0)

    def test_reports_only_are_low_risk(self):
        _write(self.root, "agent-reports/r.md", "# r")
        _write(self.root, "ai_data/knowledge/index.json", "{}")
        result = ri.analyze(self.root, tracked={})
        self.assertEqual(result["summary"]["state"], "dirty")
        self.assertEqual(result["summary"]["risk"], "low")

    def test_missing_index_is_untracked_only(self):
        _write(self.root, "backend/new.py", "x")
        result = ri.analyze(self.root, use_index=True)
        self.assertFalse(result["index_available"])
        self.assertIn("backend/new.py", result["categories"]["source_changes"])


class TestIndexParsing(_RepoFixture):
    def test_parse_synthetic_v2_index(self):
        sha = "ab" * 20
        data = _build_index([("backend/app.py", 123, 4567, sha)])
        path = self.root / "index"
        path.write_bytes(data)
        parsed = ri.parse_index(path)
        self.assertIsNotNone(parsed)
        self.assertIn("backend/app.py", parsed)
        entry = parsed["backend/app.py"]
        self.assertEqual(entry["size"], 123)
        self.assertEqual(entry["mtime_s"], 4567)
        self.assertEqual(entry["sha"], sha)

    def test_parse_unsupported_version_returns_none(self):
        path = self.root / "index"
        path.write_bytes(b"DIRC" + struct.pack(">II", 4, 0) + b"\x00" * 20)
        self.assertIsNone(ri.parse_index(path))

    def test_parse_missing_or_invalid_returns_none(self):
        self.assertIsNone(ri.parse_index(self.root / "nope"))
        bad = self.root / "bad"
        bad.write_bytes(b"NOPE" + b"\x00" * 20)
        self.assertIsNone(ri.parse_index(bad))


REPO_FIXTURE = {
    "available": True,
    "root": "/tmp/repo",
    "branch": "agent/daily-development",
    "detached": False,
    "index_available": True,
    "summary": {
        "state": "dirty",
        "risk": "low",
        "total_changes": 3,
        "counts": {
            "source_changes": 0,
            "generated_knowledge": 1,
            "agent_reports": 2,
            "runtime_artifacts": 0,
            "ignored_artifacts": 0,
            "deleted_files": 0,
            "unknown_changes": 0,
        },
        "truncated_categories": [],
    },
    "categories": {
        "source_changes": [],
        "generated_knowledge": ["ai_data/knowledge/index.json"],
        "agent_reports": ["agent-reports/a.md", "agent-reports/b.md"],
        "runtime_artifacts": [],
        "ignored_artifacts": [],
        "deleted_files": [],
        "unknown_changes": [],
    },
    "scan": {"files_visited": 10, "truncated": False, "display_limit": 60},
    "generated_from": "test fixture",
}


class _RouteFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        (root / "agent").mkdir()
        (root / "watch").mkdir()
        self._env = mock.patch.dict(os.environ, {
            "WATCH_AGENT_DIR": str(root / "agent"),
            "WATCH_RESEARCH_WATCHLIST_DIR": str(root / "watch"),
        })
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()


class TestRepositoryRoutes(_RouteFixture):
    @classmethod
    def setUpClass(cls):
        from api import app
        cls.client = TestClient(app)

    def _get(self, path, **params):
        p, q = _qs(path, **params)
        return self.client.get(p, params=q)

    def test_repository_endpoint(self):
        with mock.patch("backend.repository_intelligence.analyze",
                        return_value=REPO_FIXTURE):
            r = self._get("/api/command/repository")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["summary"]["risk"], "low")
        self.assertEqual(body["categories"]["generated_knowledge"],
                         ["ai_data/knowledge/index.json"])

    def test_overview_includes_repository(self):
        with mock.patch("backend.repository_intelligence.analyze",
                        return_value=REPO_FIXTURE), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=False):
            r = self._get("/api/command/overview")
        self.assertEqual(r.status_code, 200)
        self.assertIn("repository", r.json())

    def test_page_renders_repository_section(self):
        with mock.patch("backend.repository_intelligence.analyze",
                        return_value=REPO_FIXTURE), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]), \
             mock.patch("backend.research_data.has_report", return_value=False):
            r = self._get("/ui/command")
        self.assertEqual(r.status_code, 200)
        text = r.text
        self.assertIn("Repository Intelligence", text)
        self.assertIn("Repository state", text)
        self.assertIn("LOW", text)
        self.assertIn("ai_data/knowledge/index.json", text)
        self.assertIn("agent-reports/a.md", text)
        self.assertNotIn("Vulnerable", text)
        self.assertNotIn("Exploitable", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
