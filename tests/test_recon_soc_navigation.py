"""Recon Ops + AI SOC composition, Overview metric truth, runtime semantics.

Three defects from browser verification of the live product:

1. the SOC navigation redesign removed the *entire* core Recon Operations
   surface from the primary sidebar.  AI SOC is an additional intelligence
   layer over Watch, not a replacement for the recon UI: Programs,
   Subdomains, Live, HTTP, Fresh HTTP, Wordlists, URLs, Endpoints,
   Parameter Discovery and Recent Changes must be primary navigation
   again — while the OLD research-oriented links (Research Cases, Research
   / CVEs, Research Queue, Research Tasks, Research Leads, Research Plans,
   Research Agent, XSS, old Knowledge Base, old Reports) stay removed, and
   no Legacy/Engineering dropdown may come back.

2. the SOC Overview reported ``Agents = 0`` while ``/ui/soc/agents``
   reports the declared specialist registry: the overview counted
   ``backend.research_agents.registry`` (a module that is not part of the
   deployed tree) instead of the authoritative agents projection.

3. the Overview/Activity runtime block showed ``Status: UNKNOWN`` with
   ``basis: runtime_state_not_observable`` because
   ``backend.soc.activity._runtime_status()`` called the pure R83 engine
   with *no facts* instead of the existing read-only collector
   (``backend.research_activity.collect_activity``) that the Command
   Center and ``/api/research-activity`` already use.  UNKNOWN must mean
   genuinely unobservable, not "nobody looked".

The deployed module set is reproduced with ``undeployed()`` (blocks
``backend.research_agents`` / ``backend.investigation_engine``).
"""

from __future__ import annotations

import re
import unittest
from unittest import mock

from tests.test_soc_ux_correction import (  # shared, proven helpers
    GROUP_RE,
    LINK_RE,
    UNDEPLOYED,
    _MountedApp,
    link_names,
    routes_of,
    sidebar,
    undeployed,
)

# --- the approved primary navigation, in product-architecture order ------
RECON_LINKS = [
    ("Programs", "/ui/programs"),
    ("Subdomains", "/ui/domains"),          # product's own Subdomains target
    ("Live", "/ui/domains"),                # page title: "Live Domains"
    ("HTTP", "/ui/http"),
    ("Fresh HTTP", "/ui/http/fresh"),
    ("Wordlists", "/ui/wordlists"),
    ("URLs", "/ui/urls"),
    ("Endpoints", "/ui/endpoints"),
    ("Parameter Discovery", "/ui/parameters"),
    ("Recent Changes", "/ui/changes"),
]
SOC_LINKS = [
    ("Overview", "/ui/soc/"),
    ("Agents", "/ui/soc/agents"),
    ("Campaigns", "/ui/soc/campaigns"),
    ("Missions / Activity", "/ui/soc/activity"),
    ("Cases", "/ui/soc/cases"),
    ("Evidence", "/ui/soc/cases"),
    ("Knowledge", "/ui/kb"),
    ("Handoff", "/ui/soc/handoff"),
]
SYSTEM_LINKS = [
    ("Runs", "/ui/runs"),
    ("Tasks", "/ui/tasks"),
    ("API docs", "/docs"),
]
EXPECTED_GROUPS = ["Recon Ops", "AI SOC", "System"]
ALL_LINKS = RECON_LINKS + SOC_LINKS + SYSTEM_LINKS
EXPECTED_LABELS = {label for label, _ in ALL_LINKS}

#: the OLD research navigation — must stay out of the primary sidebar
OLD_RESEARCH_LABELS = [
    "Research Cases", "Research / CVEs", "Research Queue",
    "Research Tasks", "Research Leads", "Research Plans",
    "Research Agent", "XSS", "Knowledge Base", "Reports",
]

SIDEBAR_PROBE_PAGES = ["/ui/soc/", "/ui/programs", "/ui/wordlists"]

#: legacy engineering entries that are intentionally *not* restored
STILL_OUT_LABELS = ["Command Center", "Dashboard", "Attack Surface",
                    "Legacy / Engineering"]


def _path(href: str) -> str:
    """Strip query/fragment so pinned paths compare cleanly."""
    return href.split("#", 1)[0].split("?", 1)[0]


def _href_map(nav: str) -> dict[str, str]:
    return {name.strip(): href for href, name in LINK_RE.findall(nav)}


# --------------------------------------------------------------------------
# 1. Primary navigation composition: RECON OPS + AI SOC + SYSTEM
# --------------------------------------------------------------------------
class TestPrimaryNavigationComposition(_MountedApp):
    def test_groups_follow_the_product_architecture(self):
        for page in SIDEBAR_PROBE_PAGES:
            with self.subTest(page=page):
                groups = GROUP_RE.findall(sidebar(self.get(page).text))
                self.assertEqual(groups, EXPECTED_GROUPS,
                                 f"{page}: sidebar groups {groups}")

    def test_every_recon_destination_is_present_with_its_real_route(self):
        for page in SIDEBAR_PROBE_PAGES:
            with self.subTest(page=page):
                hrefs = _href_map(sidebar(self.get(page).text))
                for label, path in RECON_LINKS:
                    self.assertIn(label, hrefs, f"{page}: missing {label!r}")
                    self.assertEqual(_path(hrefs[label]), path,
                                     f"{page}: {label!r} -> {hrefs[label]}")

    def test_every_ai_soc_destination_is_present(self):
        hrefs = _href_map(sidebar(self.get("/ui/soc/").text))
        for label, path in SOC_LINKS:
            self.assertIn(label, hrefs, f"missing {label!r}")
            self.assertEqual(_path(hrefs[label]), path, f"{label!r}")
        self.assertIn("#evidence", hrefs["Evidence"],
                      "Evidence must keep its section anchor")

    def test_system_group_still_present(self):
        hrefs = _href_map(sidebar(self.get("/ui/soc/").text))
        for label, path in SYSTEM_LINKS:
            self.assertIn(label, hrefs, f"missing {label!r}")
            self.assertEqual(_path(hrefs[label]), path, f"{label!r}")

    def test_sidebar_is_exactly_the_intended_items(self):
        names = set(link_names(sidebar(self.get("/ui/soc/").text)))
        self.assertEqual(names, EXPECTED_LABELS,
                         f"drift: {sorted(names ^ EXPECTED_LABELS)}")

    def test_old_research_navigation_stays_out(self):
        for page in SIDEBAR_PROBE_PAGES:
            with self.subTest(page=page):
                nav = sidebar(self.get(page).text)
                names = set(link_names(nav))
                leaked = names & set(OLD_RESEARCH_LABELS)
                self.assertEqual(leaked, set(),
                                 f"{page}: old research links back: {leaked}")
                for label in OLD_RESEARCH_LABELS:
                    self.assertNotIn(f"</span>{label}</a>", nav, label)

    def test_no_research_or_legacy_dropdown_may_return(self):
        nav = sidebar(self.get("/ui/soc/").text)
        self.assertNotIn("<details", nav)
        self.assertNotIn("nav-legacy", nav)
        for label in STILL_OUT_LABELS:
            self.assertNotIn(label, nav, label)
        self.assertNotIn("Research</p>", nav)

    def test_no_duplicate_links(self):
        listed = link_names(sidebar(self.get("/ui/soc/").text))
        self.assertEqual(len(listed), len(set(listed)),
                         f"duplicate sidebar labels: {listed}")

    def test_sidebar_identical_across_recon_soc_and_new_pages(self):
        def shape(page: str) -> str:
            html = sidebar(self.get(page).text)
            html = html.replace("side-link active", "side-link")
            # legacy page handlers bind the API key into their context at
            # import time while the SOC handlers read it dynamically; in
            # production both resolve to the same config value, but under
            # the test patch they differ.  The *links* must be identical —
            # normalise the secret they carry, not the structure.
            return re.sub(r'api_key=[^"&]*', "api_key=X", html)

        reference = shape(SIDEBAR_PROBE_PAGES[0])
        for page in SIDEBAR_PROBE_PAGES[1:]:
            self.assertEqual(shape(page), reference,
                             f"{page}: different sidebar")


# --------------------------------------------------------------------------
# 2. Functionality: every restored link resolves; auth unchanged
# --------------------------------------------------------------------------
class TestReconAndSocFunctional(_MountedApp):
    def test_every_recon_link_resolves(self):
        for _, path in RECON_LINKS:
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 200, path)

    def test_soc_pages_still_resolve(self):
        for path in ("/ui/soc/", "/ui/soc/agents", "/ui/soc/agents/xss-agent",
                     "/ui/soc/cases", "/ui/soc/activity", "/ui/soc/handoff"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 200, path)

    def test_old_routes_stay_directly_accessible(self):
        for path in ("/ui/research", "/ui/research/queue",
                     "/ui/research/tasks", "/ui/xss", "/ui/kb", "/ui/reports",
                     "/ui/command", "/"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 200, path)

    def test_wordlists_page_uses_the_existing_wordlist_api(self):
        body = self.get("/ui/wordlists").text
        self.assertIn("Wordlists", body)
        self.assertIn("/api/wordlist/", body,
                      "page must link the existing per-program wordlist API")
        self.assertIn("per program", body)

    def test_wordlists_route_is_get_only_and_mounted(self):
        surface = routes_of(self.api.app)
        self.assertEqual(surface.get("/ui/wordlists"), ("GET",))

    def test_authentication_is_unchanged(self):
        for path in ("/ui/programs", "/ui/domains", "/ui/wordlists",
                     "/ui/soc/", "/ui/soc/agents"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401, path)
                self.assertEqual(
                    self.client.get(path, headers={"X-API-Key": "bad-key"}).status_code,
                    401, path)

    def test_no_new_post_or_mutation_routes(self):
        surface = routes_of(self.api.app)
        for path in ("/ui/wordlists", "/ui/soc/", "/ui/soc/agents"):
            self.assertEqual(surface.get(path), ("GET",), path)


# --------------------------------------------------------------------------
# 3. Overview metric derives from the authoritative agents projection
# --------------------------------------------------------------------------
class TestOverviewAgentMetric(unittest.TestCase):
    def test_overview_uses_the_agents_page_projection(self):
        from backend.soc import agents as soc_agents
        from backend.soc import overview as soc_overview

        with undeployed(*UNDEPLOYED):
            index = soc_agents.agents_index()
            payload = soc_overview.overview_payload()
        self.assertEqual(payload["agents"], index["count"],
                         "Overview and /ui/soc/agents disagree on agents")
        self.assertEqual(payload["agents"], len(index["agents"]))
        self.assertGreaterEqual(payload["agents"], 1,
                                "declared specialists vanished")

    def test_overview_counts_match_the_projection_statuses(self):
        from backend.soc import agents as soc_agents
        from backend.soc import overview as soc_overview

        with undeployed(*UNDEPLOYED):
            index = soc_agents.agents_index()
            counts = soc_overview.overview_payload()["agent_counts"]
        statuses = [agent["status"] for agent in index["agents"]]
        self.assertEqual(counts["registered"], len(statuses))
        for status in ("READY", "ACTIVE", "PLANNED"):
            self.assertEqual(counts[status.lower()], statuses.count(status),
                             f"{status} count disagrees with the projection")

    def test_metric_is_derived_not_hardcoded(self):
        from backend.soc import overview as soc_overview

        fake_index = {
            "count": 3,
            "agents": [{"status": "ACTIVE"}, {"status": "READY"},
                       {"status": "PLANNED"}],
        }
        with mock.patch("backend.soc.agents.agents_index",
                        return_value=fake_index):
            payload = soc_overview.overview_payload()
        self.assertEqual(payload["agents"], 3)
        self.assertEqual(payload["agent_counts"],
                         {"registered": 3, "ready": 1, "idle": 0,
                          "active": 1, "failed": 0, "planned": 1})

    def test_overview_page_labels_the_metric_truthfully(self):
        from fastapi.testclient import TestClient

        import api
        saved = api.API_KEY
        api.API_KEY = "ov-" + "iew-key-1a2b3c4d"
        try:
            with mock.patch(
                    "backend.soc.agents.agents_index",
                    return_value={"count": 2,
                                  "agents": [{"status": "PLANNED"},
                                             {"status": "PLANNED"}]}):
                response = TestClient(api.app).get(
                    "/ui/soc/", params={"api_key": api.API_KEY})
        finally:
            api.API_KEY = saved
        self.assertEqual(response.status_code, 200)
        self.assertIn("Agents registered", response.text,
                      "Overview must label what the number counts")
        self.assertIn("2 planned", response.text,
                      "Overview must expose the planned/ready/active split")
        self.assertIn("0 active", response.text)

    def test_overview_still_reports_zero_only_when_the_source_is_empty(self):
        from backend.soc import overview as soc_overview

        with mock.patch("backend.soc.agents.agents_index",
                        return_value={"count": 0, "agents": []}):
            payload = soc_overview.overview_payload()
        self.assertEqual(payload["agents"], 0)
        self.assertEqual(payload["agent_counts"]["registered"], 0)


# --------------------------------------------------------------------------
# 4. Runtime status: same real collector everywhere, UNKNOWN only if
#    genuinely unobservable
# --------------------------------------------------------------------------
class TestRuntimeStatusSemantics(unittest.TestCase):
    def test_overview_and_activity_share_one_runtime_source(self):
        from backend.soc import activity as soc_activity
        from backend.soc import overview as soc_overview

        self.assertEqual(soc_overview.overview_payload()["runtime"],
                         soc_activity.activity_payload()["runtime"],
                         "Overview and Activity disagree on runtime state")

    def test_runtime_comes_from_the_existing_read_only_collector(self):
        from backend.soc import activity as soc_activity
        from backend.soc import overview as soc_overview

        observed = {
            "status": "RUNNING",
            "status_basis": "execution_lock_held",
            "current_stage": None,
            "current_run": "run-42",
            "rule_version": "r83-1",
        }
        with mock.patch("backend.research_activity.collect_activity",
                        return_value=dict(observed)):
            overview_runtime = soc_overview.overview_payload()["runtime"]
            activity_runtime = soc_activity.activity_payload()["runtime"]
        self.assertEqual(overview_runtime["status"], "RUNNING")
        self.assertEqual(overview_runtime["status_basis"],
                         "execution_lock_held")
        self.assertEqual(overview_runtime, activity_runtime,
                         "the two SOC pages must project the same facts")

    def test_probe_failure_keeps_unknown_and_never_fakes_activity(self):
        from backend.soc import overview as soc_overview

        with mock.patch("backend.research_activity.collect_activity",
                        side_effect=RuntimeError("probe boom")):
            runtime = soc_overview.overview_payload()["runtime"]
        self.assertEqual(runtime["status"], "UNKNOWN")
        self.assertTrue(runtime["status_basis"])

    def test_observed_status_uses_the_closed_vocabulary(self):
        from ai.knowledge.ai_activity_status import STATUSES
        from backend.soc import overview as soc_overview

        runtime = soc_overview.overview_payload()["runtime"]
        self.assertIn(runtime["status"], STATUSES, runtime["status"])
        self.assertTrue(runtime.get("status_basis"),
                        "status must name the fact it is based on")

    def test_unknown_is_explained_on_the_overview_page(self):
        from fastapi.testclient import TestClient

        import api
        saved = api.API_KEY
        api.API_KEY = "rt-" + "unknown-key-1a2b3c4d"
        try:
            with mock.patch("backend.research_activity.collect_activity",
                            side_effect=RuntimeError("probe boom")):
                response = TestClient(api.app).get(
                    "/ui/soc/", params={"api_key": api.API_KEY})
        finally:
            api.API_KEY = saved
        self.assertEqual(response.status_code, 200)
        self.assertIn("UNKNOWN", response.text)
        self.assertIn("UNKNOWN is not failure", response.text,
                      "UNKNOWN must be explained, not shown raw")


if __name__ == "__main__":
    unittest.main()
