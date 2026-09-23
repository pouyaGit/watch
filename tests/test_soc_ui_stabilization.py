"""SOC UI stabilization — production-surface regressions.

Two defects surfaced by the first real browser verification of the live SOC:

1. ``/ui/soc/agents`` answered **HTTP 500**.  The adapter imported
   ``backend.research_agents`` — a module that is *not* part of the deployed
   tree — from an unguarded helper, so the page raised
   ``ModuleNotFoundError``.  Identity sources must be optional and layered,
   and a page with no available source must render an explicit empty state
   instead of raising.

2. the shared sidebar still showed the legacy Research section as *primary*
   navigation.  The legacy pages must stay available (nothing deleted, no
   route removed, no data invented) but live behind the collapsed
   "Legacy / Engineering" area, with the AI SOC group as primary navigation.

The deployed module set is reproduced by blocking imports of the modules that
exist only in this worktree (``backend.research_agents``,
``backend.investigation_engine``) — that is exactly what production looked
like when the 500 was observed.
"""

from __future__ import annotations

import builtins
import re
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

KEY = "soc-" + "stabilization-" + "key-1a2b3c4d"
BAD_KEY = "soc-" + "stabilization-" + "key-9z8y7x6w"

#: Modules present only in the worktree, never promoted: the deployed
#: (production) tree does not contain them.
UNDEPLOYED = ("backend.research_agents", "backend.investigation_engine")

SOC_PAGES = ["/ui/soc/", "/ui/soc/agents", "/ui/soc/cases", "/ui/soc/activity",
             "/ui/soc/handoff"]

SOC_PRIMARY_LABELS = ["Overview", "Agents", "Targets",
                      "Missions / Activity", "Cases",
                      "Evidence", "Knowledge", "Handoff"]

#: Legacy pages that must NOT be primary navigation anymore (still reachable).
LEGACY_PRIMARY_LABELS = ["Research Cases", "Research / CVEs", "Research Queue",
                         "Research Tasks", "Research Leads", "Research Plans",
                         "Research Agent", "XSS", "Knowledge Base", "Reports"]

#: Their routes must keep working — hiding navigation is not deleting features.
LEGACY_ROUTES = ["/ui/research", "/ui/research/queue", "/ui/research/tasks",
                 "/ui/research/leads", "/ui/research/plans",
                 "/ui/research/agent", "/ui/xss", "/ui/kb", "/ui/reports",
                 "/ui/runs", "/ui/tasks", "/ui/command", "/ui/programs",
                 "/ui/domains", "/ui/endpoints", "/ui/parameters",
                 "/ui/changes", "/static/research/index.html"]

NAV_RE = re.compile(r'<nav class="sidebar-nav">(.*?)</nav>', re.S)
LINK_RE = re.compile(
    r'<a class="side-link[^"]*" href="([^"]*)"[^>]*>\s*'
    r'<span class="side-ico">[^<]*</span>([^<]+)</a>')
LEGACY_SECTION_MARKER = '<details class="nav-legacy"'


@contextmanager
def undeployed(*prefixes):
    """Make ``prefixes`` (and their submodules) unimportable.

    Blocks the import machinery *and* neutralises already-imported packages,
    so ``from parent import submodule`` cannot silently succeed by attribute
    access on a cached parent package.
    """

    real_import = builtins.__import__

    def _fake(name, *args, **kwargs):
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            raise ImportError(f"undeployed module: {name}")
        return real_import(name, *args, **kwargs)

    saved_modules = {}
    for name in list(sys.modules):
        if any(name == p or name.startswith(p + ".") for p in prefixes):
            saved_modules[name] = sys.modules.pop(name)

    saved_attrs = {}
    for prefix in prefixes:
        parent_name, _, attr = prefix.rpartition(".")
        parent = sys.modules.get(parent_name)
        if parent is not None and hasattr(parent, attr):
            saved_attrs[(parent, attr)] = getattr(parent, attr)
            setattr(parent, attr, None)

    try:
        with mock.patch("builtins.__import__", side_effect=_fake):
            yield
    finally:
        for (parent, attr), value in saved_attrs.items():
            setattr(parent, attr, value)
        sys.modules.update(saved_modules)


def sidebar(html: str) -> str:
    match = NAV_RE.search(html)
    assert match, "sidebar-nav block not found"
    return match.group(1)


def sidebar_parts(html: str) -> tuple[str, str]:
    """(primary navigation, legacy area) of the shared sidebar."""

    nav = sidebar(html)
    primary, marker, legacy = nav.partition(LEGACY_SECTION_MARKER)
    return primary, (marker + legacy) if marker else ""


def link_names(html: str) -> set[str]:
    return {name.strip() for _, name in LINK_RE.findall(html)}


def routes_of(app) -> dict[str, tuple[str, ...]]:
    found: dict[str, tuple[str, ...]] = {}

    def _walk(entries):
        for entry in entries:
            path = getattr(entry, "path", None)
            methods = getattr(entry, "methods", None)
            if path is not None and methods:
                found[path] = tuple(sorted(methods))
            for attr in ("routes", "original_router"):
                sub = getattr(entry, attr, None)
                if sub is not None and getattr(sub, "routes", None):
                    _walk(sub.routes)

    _walk(app.routes)
    return found


class _MountedApp(unittest.TestCase):
    client = None
    api = None
    saved_key = None

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        import api

        cls.api = api
        cls.saved_key = api.API_KEY
        api.API_KEY = KEY
        cls.client = TestClient(api.app)

    @classmethod
    def tearDownClass(cls):
        cls.api.API_KEY = cls.saved_key

    def get(self, path):
        return self.client.get(path, params={"api_key": KEY})


# --------------------------------------------------------------------------
# 1-2. Agents page must render in the deployed module set, never 500
# --------------------------------------------------------------------------
class TestAgentsPageDeployedModuleSet(_MountedApp):
    def test_agents_page_renders_with_valid_auth(self):
        response = self.get("/ui/soc/agents")
        self.assertEqual(response.status_code, 200)
        self.assertIn("AI Agents", response.text)

    def test_agents_page_does_not_500_without_the_undeployed_registry(self):
        with undeployed(*UNDEPLOYED):
            response = self.get("/ui/soc/agents")
        self.assertNotEqual(response.status_code, 500)
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.text), 200)

    def test_agents_page_lists_real_engine_specialists(self):
        from ai.knowledge import specialist_registry as sr

        with undeployed(*UNDEPLOYED):
            payload = self.api and None  # keep the import order explicit
            from backend.soc import agents as soc_agents

            index = soc_agents.agents_index()
        real_categories = {c.lower() for c in sr.CANONICAL_SPECIALIST_ORDER}
        self.assertGreaterEqual(index["count"], 1)
        for agent in index["agents"]:
            self.assertIn(agent["key"], real_categories,
                          f"{agent['key']} is not a declared specialist")
            self.assertTrue(agent["name"], "agent name must not be empty")
            self.assertTrue(agent["slug"].endswith("-agent"), agent["slug"])

    def test_agent_detail_renders_for_a_real_slug(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            index = soc_agents.agents_index()
            slug = index["agents"][0]["slug"]
            response = self.get(f"/ui/soc/agents/{slug}")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.text), 200)

    def test_unknown_agent_slug_is_a_safe_404(self):
        response = self.get("/ui/soc/agents/no-such-agent")
        self.assertEqual(response.status_code, 404)

    def test_every_declared_slug_resolves(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            index = soc_agents.agents_index()
            for agent in index["agents"]:
                self.assertIsNotNone(
                    soc_agents.agent_detail(agent["slug"]), agent["slug"])
            self.assertIsNone(soc_agents.agent_detail("no-such-agent"))


class TestMissingOptionalAgentData(unittest.TestCase):
    """Missing/empty optional sources must degrade, never raise."""

    def test_no_registry_at_all_yields_an_empty_index(self):
        from backend.soc import agents as soc_agents

        with undeployed("backend.research_agents",
                        "ai.knowledge.specialist_registry"):
            index = soc_agents.agents_index()
        self.assertEqual(index["count"], 0)
        self.assertEqual(index["agents"], [])
        self.assertFalse(index["runtime"]["deployed"],
                         "no runtime may be claimed when none is importable")

    def test_empty_index_renders_an_explicit_empty_state(self):
        from backend.soc import agents as soc_agents
        from fastapi.testclient import TestClient

        import api

        saved = api.API_KEY
        api.API_KEY = KEY
        try:
            client = TestClient(api.app)
            with undeployed("backend.research_agents",
                            "ai.knowledge.specialist_registry"):
                response = client.get("/ui/soc/agents",
                                      params={"api_key": KEY})
            self.assertEqual(response.status_code, 200)
            self.assertIn("No registered", response.text)
        finally:
            api.API_KEY = saved

    def test_optional_source_failures_are_soft(self):
        from backend.soc import agents as soc_agents

        with mock.patch("backend.research_data.list_kb",
                        side_effect=RuntimeError("kb unavailable")), \
             mock.patch("backend.routers.aec.build_case_explorer_view",
                        side_effect=RuntimeError("cases unavailable")):
            index = soc_agents.agents_index()
            self.assertGreaterEqual(index["count"], 1)
            detail = soc_agents.agent_detail(index["agents"][0]["slug"])
        self.assertEqual(detail["history"]["papers"], [])
        self.assertEqual(detail["target_cases"], [])

    def test_knowledge_lists_never_carry_empty_entries(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            detail = soc_agents.agent_detail("xss-agent")
        knowledge = detail["knowledge"]
        for field, values in knowledge.items():
            for value in values:
                self.assertTrue(str(value).strip(),
                                f"empty {field} entry in {detail['identity']}")


# --------------------------------------------------------------------------
# 3-4. SOC-first primary navigation, legacy pages behind Legacy / Engineering
# --------------------------------------------------------------------------
class TestSocPrimaryNavigation(_MountedApp):
    def test_soc_pages_show_the_soc_primary_navigation(self):
        for path in SOC_PAGES:
            with self.subTest(page=path):
                primary, _ = sidebar_parts(self.get(path).text)
                names = link_names(primary)
                for label in SOC_PRIMARY_LABELS:
                    self.assertIn(label, names, f"{path}: missing {label!r}")

    def test_legacy_pages_are_not_in_the_sidebar_at_all(self):
        # the collapsed disclosure was itself part of the primary sidebar, so
        # the legacy destinations must now be absent from it entirely while
        # their routes stay mounted (TestLegacyRoutesStillAvailable).
        for path in SOC_PAGES:
            with self.subTest(page=path):
                nav = sidebar(self.get(path).text)
                names = link_names(nav)
                overlap = set(names) & set(LEGACY_PRIMARY_LABELS)
                self.assertEqual(overlap, set(),
                                 f"{path}: legacy links still in sidebar: {overlap}")

    def test_no_legacy_disclosure_or_section_in_the_sidebar(self):
        nav = sidebar(self.get("/ui/soc/").text)
        self.assertNotIn("<details", nav)
        self.assertNotIn("nav-legacy", nav)
        self.assertNotIn("Legacy / Engineering", nav)
        for label in LEGACY_PRIMARY_LABELS:
            self.assertNotIn(f"</span>{label}</a>", nav, label)

    def test_legacy_group_label_is_gone_from_the_sidebar(self):
        html = self.get("/ui/soc/").text
        self.assertNotIn("Legacy / Engineering", sidebar(html))

    def test_all_soc_pages_share_one_navigation(self):
        # the active marker legitimately differs per page; the navigation
        # itself (groups, links, order) must be identical everywhere
        def shape(nav: str) -> str:
            return nav.replace('side-link active', 'side-link')

        navs = {path: shape(sidebar(self.get(path).text)) for path in SOC_PAGES}
        reference = navs[SOC_PAGES[0]]
        for path, nav in navs.items():
            self.assertEqual(nav, reference, f"{path} has a different sidebar")
        # exactly one shared navigation system — no per-page duplicate tree
        for path in SOC_PAGES:
            html = self.get(path).text
            self.assertEqual(html.count('<nav class="sidebar-nav">'), 1, path)

    def test_soc_labels_are_not_duplicated(self):
        primary, _ = sidebar_parts(self.get("/ui/soc/").text)
        names = [name for _, name in LINK_RE.findall(primary)]
        for label in SOC_PRIMARY_LABELS:
            self.assertEqual(names.count(label), 1, f"duplicate nav: {label}")


class TestLegacyRoutesStillAvailable(_MountedApp):
    def test_legacy_routes_stay_mounted(self):
        surface = routes_of(self.api.app)
        for path in LEGACY_ROUTES:
            if path.startswith("/static/"):
                continue
            self.assertIn(path, surface, f"legacy route lost: {path}")

    def test_legacy_pages_still_render(self):
        for path in ("/ui/research", "/ui/research/queue", "/ui/research/tasks",
                     "/ui/research/leads", "/ui/research/plans",
                     "/ui/research/agent", "/ui/xss", "/ui/kb", "/ui/reports",
                     "/ui/runs", "/ui/tasks", "/static/research/index.html"):
            self.assertEqual(self.get(path).status_code, 200, path)


# --------------------------------------------------------------------------
# 5. Handoff: intentional empty state, real projection when data exists
# --------------------------------------------------------------------------
class TestHandoffState(_MountedApp):
    def test_handoff_index_reports_source_availability(self):
        from backend.soc import handoff as soc_handoff

        with undeployed("backend.investigation_engine"):
            payload = soc_handoff.handoff_index()
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["reports"], [])
        self.assertIs(payload["source_available"], False)

    def test_handoff_page_empty_state_is_explicit(self):
        with undeployed("backend.investigation_engine"):
            response = self.get("/ui/soc/handoff")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No handoff packages available.", response.text)
        self.assertIn("not deployed", response.text)
        self.assertNotIn("job_id", response.text)

    def test_real_report_source_is_reported_when_present(self):
        from backend.soc import handoff as soc_handoff

        try:
            from backend.investigation_engine import service as inv
        except Exception:  # deployed module set: nothing to project
            self.skipTest("investigation engine not deployed")
        expected = len(list((inv.report_documents() or {}).get("reports", [])))
        payload = soc_handoff.handoff_index()
        self.assertIs(payload["source_available"], True)
        self.assertEqual(payload["count"], expected)

    def test_projection_keeps_real_report_fields(self):
        from backend.soc import handoff as soc_handoff

        rows = [{
            "job_id": "rj-abc", "report_id": "rr-1", "target": "t.example.com",
            "subdomain": "sub", "endpoint": "/x", "category": "xss",
            "status": "COMPLETED", "agent": "input-researcher",
            "generated_at": "2026-09-22T00:00:00Z",
        }]
        with mock.patch.object(soc_handoff, "_reports", return_value=rows), \
             mock.patch.object(soc_handoff, "_source_available",
                               return_value=True):
            payload = soc_handoff.handoff_index()
        self.assertEqual(payload["count"], 1)
        row = payload["reports"][0]
        self.assertEqual(row["job_id"], "rj-abc")
        self.assertEqual(row["view_url"], "/ui/soc/handoff/rj-abc")
        self.assertEqual(row["target"], "t.example.com")


# --------------------------------------------------------------------------
# 6. Authentication constraints unchanged
# --------------------------------------------------------------------------
class TestAuthConstraintsIntact(_MountedApp):
    def test_soc_pages_still_require_the_api_key(self):
        for path in SOC_PAGES + ["/ui/soc/agents/xss-agent"]:
            with self.subTest(page=path):
                self.assertEqual(self.client.get(path).status_code, 401)
                self.assertEqual(
                    self.client.get(path,
                                    headers={"X-API-Key": BAD_KEY}).status_code,
                    401)

    def test_legacy_pages_still_require_the_api_key(self):
        for path in ("/ui/research", "/ui/kb", "/ui/reports"):
            self.assertEqual(self.client.get(path).status_code, 401, path)

    def test_static_and_docs_stay_exempt(self):
        self.assertEqual(self.client.get("/static/css/custom.css").status_code, 200)
        self.assertEqual(self.client.get("/docs").status_code, 200)


if __name__ == "__main__":
    unittest.main()
