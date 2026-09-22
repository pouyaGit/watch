"""SOC UX correction — composition + truthful agent status.

Two defects from browser verification of the live AI SOC:

1. the legacy Research section was still *in* the primary sidebar (the
   previous fix only wrapped it in a collapsed ``<details>``).  The approved IA
   wants it out of the normal sidebar entirely: routes stay mounted for
   backward compatibility, links going.  Nothing may replace it with another
   dropdown, and no "Legacy / Engineering" section may remain visible.  The
   sidebar itself carries two product surfaces — Recon Ops (restored core
   recon navigation) + AI SOC — plus the System group; see
   ``tests.test_recon_soc_navigation`` for that composition contract.

2. the Agents page statuses did not describe the real runtime.  ``ready`` was
   a *default substituted when the registry declared no lifecycle, and queue /
   active-job columns rendered 0 although no agent runtime exists in the
   deployed tree.  Status must be derived from what the runtime actually
   reports, and nothing may imply activity that never happened.

The deployed module set is reproduced by blocking imports of the worktree-only
modules (``backend.research_agents``, ``backend.investigation_engine``).
"""

from __future__ import annotations

import re
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

KEY = "ux-" + "correction-" + "key-1a2b3c4d"
BAD_KEY = "ux-" + "correction-" + "key-9z8y7x6w"

UNDEPLOYED = ("backend.research_agents", "backend.investigation_engine")

SOC_PAGES = ["/ui/soc/", "/ui/soc/agents", "/ui/soc/cases", "/ui/soc/activity",
             "/ui/soc/handoff"]

#: the approved primary product navigation
SOC_PRIMARY_LABELS = ["Overview", "Agents", "Missions / Activity", "Cases",
                      "Evidence", "Knowledge", "Handoff"]
#: restored core Recon Operations navigation (second product surface)
RECON_PRIMARY_LABELS = ["Programs", "Subdomains", "Live", "HTTP",
                        "Fresh HTTP", "Wordlists", "URLs", "Endpoints",
                        "Parameter Discovery", "Recent Changes"]
#: the only non-SOC items allowed to stay (system links)
SYSTEM_LABELS = ["Runs", "Tasks", "API docs"]
ALLOWED_SIDEBAR_LABELS = (set(SOC_PRIMARY_LABELS) | set(RECON_PRIMARY_LABELS)
                          | set(SYSTEM_LABELS))

#: must be gone from the normal sidebar: the OLD research navigation plus
#: engineering entries that are intentionally not primary navigation.
#: (Core recon items are deliberately NOT in this list — they were
#: restored; see RECON_PRIMARY_LABELS.)
LEGACY_PRIMARY_LABELS = ["Research Cases", "Research / CVEs", "Research Queue",
                         "Research Tasks", "Research Leads", "Research Plans",
                         "Research Agent", "XSS", "Knowledge Base", "Reports",
                         "Command Center", "Dashboard", "Domains", "Crawl",
                         "DNS Bruteforce", "Attack Surface"]

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
GROUP_RE = re.compile(r'<p class="nav-group">([^<]+)</p>')


@contextmanager
def undeployed(*prefixes):
    """Make ``prefixes`` unimportable (deployed module set)."""

    real_import = __import__("builtins").__import__

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


def link_names(nav: str) -> list[str]:
    return [name.strip() for _, name in LINK_RE.findall(nav)]


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
# 1-3. Sidebar: SOC-only, legacy routes untouched
# --------------------------------------------------------------------------
class TestSidebarIsSocOnly(_MountedApp):
    def test_no_legacy_research_section_anywhere_in_the_sidebar(self):
        for path in SOC_PAGES:
            with self.subTest(page=path):
                nav = sidebar(self.get(path).text)
                names = set(link_names(nav))
                leaked = names & set(LEGACY_PRIMARY_LABELS)
                self.assertEqual(leaked, set(),
                                 f"{path}: legacy links still in sidebar: {leaked}")

    def test_no_legacy_or_dropdown_section_label(self):
        nav = sidebar(self.get("/ui/soc/").text)
        self.assertNotIn("Legacy / Engineering", nav)
        self.assertNotIn("nav-legacy", nav)
        self.assertNotIn("<details", nav)
        self.assertNotIn("Research</p>", nav)
        groups = GROUP_RE.findall(nav)
        self.assertEqual(groups, ["Recon Ops", "AI SOC", "System"],
                         f"unexpected sidebar groups: {groups}")

    def test_recon_and_soc_items_coexist(self):
        names = set(link_names(sidebar(self.get("/ui/soc/").text)))
        for label in RECON_PRIMARY_LABELS:
            self.assertIn(label, names, f"restored recon link missing: {label}")
        for label in SOC_PRIMARY_LABELS:
            self.assertIn(label, names, f"SOC link missing: {label}")

    def test_sidebar_contains_exactly_the_intended_items(self):
        names = set(link_names(sidebar(self.get("/ui/soc/").text)))
        self.assertEqual(names, ALLOWED_SIDEBAR_LABELS,
                         f"sidebar items drifted: {names ^ ALLOWED_SIDEBAR_LABELS}")

    def test_soc_destinations_present_on_every_soc_page(self):
        for path in SOC_PAGES:
            with self.subTest(page=path):
                names = set(link_names(sidebar(self.get(path).text)))
                for label in SOC_PRIMARY_LABELS:
                    self.assertIn(label, names, f"{path}: missing {label!r}")

    def test_sidebar_is_identical_across_soc_pages(self):
        def shape(nav: str) -> str:
            return nav.replace("side-link active", "side-link")

        navs = {p: shape(sidebar(self.get(p).text)) for p in SOC_PAGES}
        reference = navs[SOC_PAGES[0]]
        for path, nav in navs.items():
            self.assertEqual(nav, reference, f"{path}: different sidebar")

    def test_legacy_routes_remain_mounted(self):
        surface = routes_of(self.api.app)
        for path in LEGACY_ROUTES:
            if path.startswith("/static/"):
                continue
            self.assertIn(path, surface, f"legacy route lost: {path}")

    def test_legacy_pages_still_render_directly(self):
        for path in ("/ui/research", "/ui/research/queue", "/ui/research/tasks",
                     "/ui/research/leads", "/ui/research/plans",
                     "/ui/research/agent", "/ui/xss", "/ui/kb", "/ui/reports",
                     "/ui/runs", "/ui/tasks", "/ui/command", "/ui/programs",
                     "/static/research/index.html"):
            self.assertEqual(self.get(path).status_code, 200, path)

    def test_base_template_no_longer_renders_legacy_links(self):
        text = (ROOT / "web" / "templates" / "base.html").read_text()
        for var in ("research_url", "queue_url", "leads_url", "plans_url",
                    "agent_url", "xss_url", "reports_url", "command_url",
                    "programs_url", "domains_url"):
            self.assertNotIn(f"{{{{ {var} }}}}", text,
                             f"legacy sidebar link still rendered: {var}")
        for href in ("/ui/soc/agents", "/ui/soc/cases", "/ui/soc/handoff"):
            self.assertIn(href, text)


# --------------------------------------------------------------------------
# 4. Agent status must reflect the real lifecycle
# --------------------------------------------------------------------------
class TestAgentStatusTruthfulness(unittest.TestCase):
    def test_deployed_set_status_is_planned_not_ready(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            payload = soc_agents.agents_index()
        self.assertGreaterEqual(payload["count"], 1)
        for agent in payload["agents"]:
            self.assertEqual(agent["status"], "PLANNED",
                             f"{agent['name']}: status {agent['status']!r} "
                             "claims a runtime that is not deployed")
            self.assertTrue(agent["status_meaning"], "status meaning missing")
            self.assertFalse(agent["runtime_tracked"], agent["name"])

    def test_deployed_set_counters_are_untracked_not_zero(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            payload = soc_agents.agents_index()
        for agent in payload["agents"]:
            for field in ("queue", "active_jobs", "job_count"):
                self.assertIsNone(agent[field],
                                  f"{agent['name']}: {field} must be None "
                                  "when no runtime tracks it")

    def test_status_is_derived_from_the_runtime_report(self):
        from backend.soc import agents as soc_agents

        try:
            from backend.research_agents import service as ra
        except Exception:  # deployed module set: nothing to derive from
            self.skipTest("agent runtime not deployed")

        reported = {str(a.get("category")).lower(): a
                    for a in (ra.agents_payload().get("agents") or [])}
        payload = soc_agents.agents_index()
        self.assertGreaterEqual(payload["count"], 1)
        for agent in payload["agents"]:
            source = reported.get(agent["key"])
            if source is None:
                self.assertEqual(agent["status"], "PLANNED", agent["name"])
                self.assertFalse(agent["runtime_tracked"], agent["name"])
                continue
            self.assertTrue(agent["runtime_tracked"], agent["name"])
            if int(source.get("active_jobs") or 0) > 0:
                expected = "ACTIVE"
            elif bool(source.get("available")):
                expected = "READY"
            else:
                expected = "PLANNED"
            self.assertEqual(agent["status"], expected, agent["name"])

    def test_declared_lifecycle_is_reported_not_invented(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            detail = soc_agents.agent_detail("xss-agent")
        identity = detail["identity"]
        self.assertIn("declared_lifecycle", identity)
        # the XSS identity planner declares no lifecycle at all — the UI must
        # say so instead of substituting a flattering default
        self.assertNotEqual(identity["declared_lifecycle"].upper(), "READY",
                            "declared lifecycle was invented")

    def test_status_meaning_explains_the_state(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED):
            detail = soc_agents.agent_detail("xss-agent")
        meaning = detail["identity"]["status_meaning"]
        self.assertIn("no agent runtime", meaning.lower())


# --------------------------------------------------------------------------
# 5-6. No fabricated activity; explicit empty states
# --------------------------------------------------------------------------
class TestNoFabricatedActivity(_MountedApp):
    def test_agents_page_explains_missing_runtime(self):
        with undeployed(*UNDEPLOYED):
            response = self.get("/ui/soc/agents")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No agent runtime is deployed", response.text)
        self.assertIn("not tracked", response.text)
        self.assertIn("PLANNED = definition exists", response.text)

    def test_detail_pages_explain_missing_runtime(self):
        with undeployed(*UNDEPLOYED):
            from backend.soc import agents as soc_agents

            for agent in soc_agents.agents_index()["agents"]:
                with self.subTest(agent=agent["slug"]):
                    response = self.get(f"/ui/soc/agents/{agent['slug']}")
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("not tracked", response.text)
                    self.assertNotIn(">ACTIVE<", response.text)

    def test_kb_sources_are_labelled_platform_wide(self):
        response = self.get("/ui/soc/agents/xss-agent")
        self.assertEqual(response.status_code, 200)
        body = response.text.replace("\n", " ")
        self.assertIn("platform-wide", body,
                      "shared knowledge is not labelled as platform-wide")

    def test_agent_attributed_research_shows_empty_state(self):
        with undeployed("backend.investigation_engine"):
            response = self.get("/ui/soc/agents/xss-agent")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No research is recorded against this agent",
                      response.text)

    def test_target_cases_are_labelled_as_category_association(self):
        response = self.get("/ui/soc/agents/xss-agent")
        self.assertEqual(response.status_code, 200)
        self.assertIn("associated by vulnerability category", response.text)

    def test_all_optional_sources_missing_still_renders(self):
        from backend.soc import agents as soc_agents

        with undeployed(*UNDEPLOYED), \
             mock.patch("backend.research_data.list_kb",
                        side_effect=RuntimeError("kb unavailable")), \
             mock.patch("backend.routers.aec.build_case_explorer_view",
                        side_effect=RuntimeError("cases unavailable")):
            detail = soc_agents.agent_detail("xss-agent")
            response = self.get("/ui/soc/agents/xss-agent")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(detail["history"]["papers"], [])
        self.assertEqual(detail["history"]["notes"], [])
        self.assertEqual(detail["target_cases"], [])
        for field in ("vulnerability_areas", "techniques", "frameworks",
                      "topics"):
            for value in detail["knowledge"][field]:
                self.assertTrue(str(value).strip(), f"empty {field} entry")


# --------------------------------------------------------------------------
# 7-10. Routing and authentication unchanged
# --------------------------------------------------------------------------
class TestRoutingAndAuth(_MountedApp):
    def test_agents_page_renders_with_valid_auth(self):
        self.assertEqual(self.get("/ui/soc/agents").status_code, 200)

    def test_every_declared_agent_slug_renders(self):
        with undeployed(*UNDEPLOYED):
            from backend.soc import agents as soc_agents

            slugs = [a["slug"] for a in soc_agents.agents_index()["agents"]]
            self.assertGreaterEqual(len(slugs), 1)
            for slug in slugs:
                with self.subTest(slug=slug):
                    self.assertEqual(
                        self.get(f"/ui/soc/agents/{slug}").status_code, 200)
                    self.assertEqual(
                        self.client.get(
                            f"/ui/soc/agents/{slug}").status_code, 401)

    def test_unknown_agent_slug_is_404(self):
        self.assertEqual(
            self.get("/ui/soc/agents/no-such-agent").status_code, 404)

    def test_soc_and_legacy_pages_still_require_the_key(self):
        for path in SOC_PAGES + ["/ui/soc/agents/xss-agent",
                                 "/ui/research", "/ui/kb", "/ui/command"]:
            with self.subTest(page=path):
                self.assertEqual(self.client.get(path).status_code, 401)
                self.assertEqual(
                    self.client.get(path,
                                    headers={"X-API-Key": BAD_KEY}).status_code,
                    401)

    def test_static_and_docs_stay_exempt(self):
        self.assertEqual(
            self.client.get("/static/css/custom.css").status_code, 200)
        self.assertEqual(self.client.get("/docs").status_code, 200)

    def test_get_only_and_no_new_routes(self):
        surface = routes_of(self.api.app)
        for path in SOC_PAGES + ["/ui/soc/agents/{slug}"]:
            self.assertEqual(surface.get(path), ("GET",), path)
        for path in ("/api/research", "/api/tasks", "/api/system/stats"):
            self.assertIn(path, surface, f"existing route lost: {path}")


if __name__ == "__main__":
    unittest.main()
