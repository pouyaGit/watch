"""tests/test_attack_surface_api.py — Command Center + API contract tests.

Fully offline: the read-only repository loader is patched with an injected
snapshot, so no Mongo, no network and no target interaction occur. Covers the
stable ``/api/command/attack-surface`` schema, auth, empty-data honesty, the
Command Center section rendering and the no-write guarantee.
"""
from __future__ import annotations

import json
import re
import unittest
from unittest import mock

from config import config
from fastapi.testclient import TestClient

from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
)
from backend.attack_surface import repository as repo
from backend.attack_surface.models import AttackSurfaceSnapshot

API_KEY = config().get("API_KEY", "")


def _fixture_snapshot() -> AttackSurfaceSnapshot:
    return repo.normalize_records(
        http_records=[
            HttpRecord(program_name="dell", subdomain="a.dell.com",
                       tech=("WordPress:6.4",)),
        ],
        endpoint_records=[
            EndpointRecord(
                program_name="dell",
                subdomain="a.dell.com",
                path="/api/user",
                params=("id",),
                param_records=(ParamRecord(name="id", method="GET",
                                           location="query",
                                           source="crawl"),),
            ),
            EndpointRecord(
                program_name="dell",
                subdomain="a.dell.com",
                path="/search",
                params=("q",),
                param_records=(ParamRecord(name="q", method="GET",
                                           location="query",
                                           source="crawl"),),
            ),
        ],
        url_records=[],
    )


def _patch_loader(snapshot):
    return mock.patch(
        "backend.attack_surface.repository.load_snapshot",
        side_effect=lambda program=None, **kwargs: snapshot,
    )


class TestAttackSurfaceApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_auth_required(self):
        if not API_KEY:
            self.skipTest("API key not configured")
        response = self.client.get("/api/command/attack-surface")
        self.assertEqual(response.status_code, 401)

    def test_schema_is_stable(self):
        with _patch_loader(_fixture_snapshot()):
            response = self._get("/api/command/attack-surface")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            set(body),
            {"available", "rule_version", "summary", "discovery",
             "candidates", "priority_queue"},
        )
        self.assertEqual(body["rule_version"], "attack-surface-1")
        self.assertIn("XSS", body["candidates"]["short"])
        self.assertIn("IDOR", body["candidates"]["short"])
        self.assertIn("SSRF", body["candidates"]["short"])
        self.assertIn("UPLOAD", body["candidates"]["short"])

    def test_response_values(self):
        with _patch_loader(_fixture_snapshot()):
            body = self._get("/api/command/attack-surface").json()
        self.assertTrue(body["available"])
        self.assertEqual(body["discovery"]["domains"], 1)
        self.assertEqual(body["discovery"]["endpoints"], 2)
        self.assertEqual(body["candidates"]["short"]["IDOR"], 1)
        self.assertEqual(body["candidates"]["short"]["XSS"], 1)
        top = body["priority_queue"][0]
        for key in ("rank", "id", "category", "confidence", "score",
                    "endpoint", "parameter", "reasons", "status",
                    "created_at"):
            self.assertIn(key, top)
        self.assertEqual(top["rank"], 1)

    def test_program_filter_is_forwarded(self):
        captured = {}

        def fake(program=None, **kwargs):
            captured["program"] = program
            return _fixture_snapshot()

        with mock.patch(
            "backend.attack_surface.repository.load_snapshot",
            side_effect=fake,
        ):
            self._get("/api/command/attack-surface", program="dell")
        self.assertEqual(captured["program"], "dell")

    def test_empty_data_is_honest(self):
        with _patch_loader(AttackSurfaceSnapshot()):
            body = self._get("/api/command/attack-surface").json()
        self.assertFalse(body["available"])
        self.assertEqual(body["summary"]["total"], 0)
        self.assertEqual(body["discovery"]["domains"], 0)
        self.assertEqual(body["discovery"]["urls"], 0)
        self.assertEqual(body["discovery"]["endpoints"], 0)
        self.assertEqual(body["discovery"]["parameters"], 0)
        self.assertEqual(body["priority_queue"], [])
        for value in body["candidates"]["short"].values():
            self.assertEqual(value, 0)

    def test_no_write_endpoint(self):
        params = {"api_key": API_KEY} if API_KEY else {}
        response = self.client.post("/api/command/attack-surface",
                                    params=params)
        self.assertIn(response.status_code, (405, 401))

    def test_overview_includes_attack_surface(self):
        with _patch_loader(_fixture_snapshot()), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]):
            body = self._get("/api/command/overview").json()
        self.assertIn("attack_surface", body)
        self.assertEqual(body["attack_surface"]["rule_version"],
                         "attack-surface-1")

    def test_no_scheme_or_forbidden_words(self):
        with _patch_loader(_fixture_snapshot()):
            blob = json.dumps(
                self._get("/api/command/attack-surface").json()
            ).lower()
        for token in ("http://", "https://", "vulnerable", "exploitable"):
            self.assertNotIn(token, blob)


class TestAttackSurfaceNavigation(unittest.TestCase):
    """The Attack Surface Intelligence section must be reachable from the UI."""

    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def _dashboard_mocks(self):
        counts = {"programs": 0, "subdomains": 0, "live": 0, "http": 0,
                  "urls": 0, "endpoints": 0, "params": 0,
                  "fresh_http_24h": 0}
        return (
            mock.patch("backend.dashboard.global_counts", return_value=counts),
            mock.patch("backend.dashboard.program_rows", return_value=[]),
            mock.patch("backend.dashboard.latest_runs", return_value=[]),
            mock.patch("backend.dashboard.recent_changes", return_value=[]),
            mock.patch("backend.dashboard.activity_summary",
                       return_value={"total": 0}),
        )

    def test_attack_surface_is_not_a_sidebar_item(self):
        with _patch_loader(_fixture_snapshot()), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]):
            response = self._get("/ui/command")
        self.assertEqual(response.status_code, 200)
        nav = re.search(r'<nav class="sidebar-nav">(.*?)</nav>',
                        response.text, re.S).group(1)
        self.assertNotIn("Attack Surface</a>", nav,
                         "attack surface must not sit in the product sidebar")
        # the page itself still exposes the section and the route resolves
        self.assertIn('id="attack-surface"', response.text)

    def test_quick_action_present(self):
        with _patch_loader(_fixture_snapshot()), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]):
            response = self._get("/ui/command")
        quick = re.search(
            r'<a class="quick-action" href="([^"]*)"[^>]*>\s*'
            r'<span class="qa-icon">[^<]*</span>\s*Attack Surface</a>',
            response.text,
        )
        self.assertIsNotNone(quick, "missing Attack Surface quick action")

    def test_attack_surface_absent_from_sidebar_on_other_pages(self):
        patches = self._dashboard_mocks()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            response = self._get("/")
        self.assertEqual(response.status_code, 200)
        nav = re.search(r'<nav class="sidebar-nav">(.*?)</nav>',
                        response.text, re.S).group(1)
        self.assertNotIn("Attack Surface</a>", nav)


class TestAttackSurfaceUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_command_center_renders_section(self):
        with _patch_loader(_fixture_snapshot()), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]):
            response = self._get("/ui/command")
        self.assertEqual(response.status_code, 200)
        text = response.text
        self.assertIn("Attack Surface Intelligence", text)
        self.assertIn("Discovery", text)
        self.assertIn("Priority queue", text)
        self.assertIn("/api/user", text)
        self.assertIn("object identifier parameter", text)
        self.assertNotIn("Vulnerable", text)
        self.assertNotIn("Exploitable", text)

    def test_command_center_empty_state(self):
        with _patch_loader(AttackSurfaceSnapshot()), \
             mock.patch("backend.dashboard.latest_runs", return_value=[]):
            response = self._get("/ui/command")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Attack surface intelligence unavailable", response.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
