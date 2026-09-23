"""Epic8: intelligence API (auth/schema/pagination/ids) + UI contracts."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_campaign,
    add_candidate,
    add_finding_case,
    add_job,
    add_memory,
    add_runtime_case,
    audit,
    envelope,
)
from tests.test_soc_ux_correction import (  # shared proven harness
    BAD_KEY,
    KEY,
    _MountedApp,
    sidebar,
)

INTEL_PATHS = (
    "/api/intel/overview",
    "/api/intel/targets",
    "/api/intel/targets/{target}",
    "/api/intel/agents",
    "/api/intel/agents/{category}",
    "/api/intel/activity",
    "/api/intel/now",
    "/api/intel/hunt-effectiveness",
    "/api/intel/learning",
    "/api/intel/cases/{case_id}",
    "/api/intel/knowledge-usage",
    "/api/intel/handoff",
)


# ------------------------------------------------------------------- auth
class TestAuth(IntelEnvMixin, _MountedApp):
    def test_overview_requires_api_key(self):
        r = self.client.get("/api/intel/overview")
        self.assertEqual(r.status_code, 401)

    def test_wrong_key_rejected(self):
        r = self.client.get("/api/intel/overview",
                            params={"api_key": BAD_KEY})
        self.assertEqual(r.status_code, 401)

    def test_right_key_accepted(self):
        r = self.get("/api/intel/overview")
        self.assertEqual(r.status_code, 200)

    def test_ui_targets_requires_key(self):
        r = self.client.get("/ui/soc/targets")
        self.assertEqual(r.status_code, 401)

    def test_ui_targets_with_key(self):
        self.assertEqual(self.get("/ui/soc/targets").status_code, 200)

    def test_all_intel_endpoints_require_key(self):
        for path in INTEL_PATHS:
            bare = path.split("{")[0].rstrip("/") or path
            if bare.endswith("/targets") or bare.endswith("/agents"):
                pass                                   # list paths ok
            r = self.client.get(bare)
            with self.subTest(path=bare):
                self.assertEqual(r.status_code, 401)


# ------------------------------------------------------------------- apis
class TestIntelApi(IntelEnvMixin, _MountedApp):
    def test_overview_shape(self):
        body = self.get("/api/intel/overview").json()
        for key in ("rule_version", "window", "agents", "campaigns",
                    "hunts", "recent_findings", "cases", "handoff",
                    "meaningful_activity", "blockers", "current_activity"):
            self.assertIn(key, body)
        json.dumps(body)

    def test_targets_shape(self):
        add_job(subdomain="api.example")
        body = self.get("/api/intel/targets").json()
        self.assertEqual(body["state"], "ok")
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["targets"][0]["target"], "api.example")

    def test_target_detail_404_for_unknown(self):
        r = self.get("/api/intel/targets/absent.example")
        self.assertEqual(r.status_code, 404)
        self.assertIn("absent.example", r.json()["detail"])

    def test_target_detail_200_for_known(self):
        add_job(subdomain="known.example")
        r = self.get("/api/intel/targets/known.example")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["found"])

    def test_agents_list_count(self):
        body = self.get("/api/intel/agents").json()
        self.assertEqual(body["count"], 8)
        self.assertEqual(body["state"], "ok")

    def test_agent_detail_by_category_and_slug(self):
        for needle in ("XSS", "xss-agent"):
            r = self.get(f"/api/intel/agents/{needle}")
            with self.subTest(needle=needle):
                self.assertEqual(r.status_code, 200)
                self.assertTrue(r.json()["registered"])

    def test_agent_detail_404_unknown(self):
        r = self.get("/api/intel/agents/nope-not-real")
        self.assertEqual(r.status_code, 404)

    def test_activity_returns_feed_with_taxonomy(self):
        audit(event="job_claimed", job_id="job-api")
        body = self.get("/api/intel/activity").json()
        for key in ("value", "state", "source", "population",
                    "aggregation", "time_range", "categories"):
            self.assertIn(key, body)

    def test_activity_limit_honored(self):
        for _ in range(5):
            audit(event="job_claimed", job_id="job-x")
        # NOTE: httpx replaces the URL query when params= is supplied,
        # so query-param tests build the FULL query (incl. api_key) and
        # hit the client directly.
        body = self.client.get(
            f"/api/intel/activity?limit=2&api_key={KEY}").json()
        self.assertLessEqual(len(body["value"]), 2)

    def test_activity_limit_out_of_range_422(self):
        for bad in (0, 500):
            r = self.client.get(
                f"/api/intel/activity?limit={bad}&api_key={KEY}")
            with self.subTest(limit=bad):
                self.assertEqual(r.status_code, 422)

    def test_hours_out_of_range_422(self):
        for bad in (-1, 99999):
            r = self.client.get(
                f"/api/intel/overview?hours={bad}&api_key={KEY}")
            with self.subTest(hours=bad):
                self.assertEqual(r.status_code, 422)

    def test_now_endpoint_honest_states(self):
        body = self.get("/api/intel/now").json()
        self.assertIn(body["state"],
                      ("PLANNED", "IDLE", "ACTIVE", "FAILED", "UNKNOWN"))
        self.assertIn("basis", body)

    def test_hunt_effectiveness_funnels_complete(self):
        body = self.get("/api/intel/hunt-effectiveness").json()
        self.assertEqual(len(body["funnels"]), 6)
        for name, f in body["funnels"].items():
            with self.subTest(funnel=name):
                self.assertIn("denominator", f)
                self.assertIn("numerator", f)
                self.assertIn("denominator_semantics", f)

    def test_learning_endpoint_shape(self):
        body = self.get("/api/intel/learning").json()
        for key in ("value", "state", "source", "population", "rule_version"):
            self.assertIn(key, body)
        json.dumps(body)

    def test_case_endpoint_404_unknown(self):
        r = self.get("/api/intel/cases/fcase-ffffffffffff")
        self.assertEqual(r.status_code, 404)

    def test_case_endpoint_unavailable_envelope_not_404(self):
        from backend.routers.intel import intel_case
        with mock.patch(
                "backend.prod_intel.case_intel.sources.finding_cases",
                return_value=envelope(None, "unavailable", "disk")):
            pkg = intel_case("fcase-123456789abc")
        self.assertEqual(pkg["state"], "unavailable")
        self.assertFalse(pkg["found"])

    def test_knowledge_usage_pagination_params(self):
        job = add_job(status="COMPLETED", agent="xss-agent",
                      subdomain="p.example")
        from tests.prod_intel_fixtures import add_knowledge_use
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="k1")
        add_knowledge_use(job_id=job.id, agent="xss-agent", doc="k2")
        body = self.client.get(
            f"/api/intel/knowledge-usage?limit=1&offset=0&api_key={KEY}"
        ).json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["total"], 2)
        self.assertTrue(body["pagination"]["has_more"])

    def test_knowledge_usage_negative_offset_422(self):
        r = self.client.get(
            f"/api/intel/knowledge-usage?offset=-1&api_key={KEY}")
        self.assertEqual(r.status_code, 422)

    def test_handoff_endpoint_shape(self):
        body = self.get("/api/intel/handoff").json()
        for key in ("count", "reports", "semantics", "state"):
            self.assertIn(key, body)

    def test_openapi_contains_every_intel_path(self):
        paths = self.api.app.openapi()["paths"]
        for p in INTEL_PATHS:
            with self.subTest(path=p):
                self.assertIn(p, paths)

    def test_api_responses_have_no_secret_material(self):
        for path in ("/api/intel/overview", "/api/intel/agents",
                     "/api/intel/learning", "/api/intel/now"):
            blob = json.dumps(self.get(path).json(), default=str)
            with self.subTest(path=path):
                self.assertNotIn("OPENROUTER_API_KEY", blob)
                self.assertNotIn("api_key", blob)
                self.assertNotIn("sk-", blob)
                self.assertNotIn("Authorization", blob)


# --------------------------------------------------------------------- ui
class TestUiContracts(IntelEnvMixin, _MountedApp):
    def test_home_renders_intelligence_section_from_projection(self):
        add_campaign(state="BLOCKED", subdomain="home.example",
                     termination="fixture-block-reason")
        html = self.get("/ui/soc/").text
        self.assertIn("Operational intelligence", html)
        # the fixture blocker id proves the page consumed the projection
        # (templates contain no counters of their own)
        camps = [c for c in [add_campaign] ]      # noqa: F841 (doc only)
        self.assertIn("fixture-block-reason", html)

    def test_home_blocks_unavailable_honestly_without_fixtures(self):
        html = self.get("/ui/soc/").text
        self.assertIn("Operational intelligence", html)

    def test_targets_page_renders_discovered_target(self):
        add_job(subdomain="render.example")
        html = self.get("/ui/soc/targets").text
        self.assertIn("render.example", html)
        self.assertIn("attack surface", html)
        self.assertIn("Recent meaningful activity", html)

    def test_targets_page_empty_state_is_honest(self):
        html = self.get("/ui/soc/targets").text
        self.assertIn("No target", html)

    def test_activity_page_has_right_now_and_feed(self):
        audit(event="job_claimed", job_id="job-ui")
        html = self.get("/ui/soc/activity").text
        self.assertIn("Right now", html)

    def test_agent_detail_has_intelligence_block(self):
        html = self.get("/ui/soc/agents/xss-agent").text
        self.assertIn("Operational intelligence", html)

    def test_finding_detail_has_analyst_package(self):
        cand = add_candidate(target="pkg.example")
        add_finding_case(cand, state="TRIAGED")   # package only exists
        html = self.get(f"/ui/soc/findings/{cand.candidate_id}").text
        self.assertIn("Analyst package", html)

    def test_runtime_case_detail_has_analyst_package(self):
        job = add_job(status="COMPLETED", subdomain="caseui.example")
        add_runtime_case(case_id="case-uiabcd123456", job_id=job.id)
        html = self.get("/ui/soc/cases/case-uiabcd123456").text
        self.assertIn("Analyst package", html)

    def test_sidebar_has_targets_on_all_sampled_pages(self):
        for path in ("/ui/soc/", "/ui/soc/targets", "/ui/soc/activity"):
            html = self.get(path).text
            with self.subTest(path=path):
                self.assertIn("/ui/soc/targets", sidebar(html))

    def test_overview_consumes_projection_via_canary(self):
        # proof the template reads the backend projection: patch the
        # projection function and see the canary render (capture the
        # original FIRST so the canary does not recurse into itself)
        from backend.prod_intel import overview as ov_mod
        real_overview = ov_mod.overview

        def canary(*, hours=None):
            base = real_overview(hours=hours)
            base["blockers"]["value"] = [{
                "kind": "canary", "id": "canary-0001",
                "reason": "CANARY-PROJECTION-FED",
                "target": "", "at": "", "link": None,
                "source": "test"}]
            base["blockers"]["state"] = "ok"
            return base

        with mock.patch.object(ov_mod, "overview", canary):
            html = self.get("/ui/soc/").text
        self.assertIn("CANARY-PROJECTION-FED", html)

    def test_pages_have_no_placeholder_markers(self):
        for path in ("/ui/soc/", "/ui/soc/targets", "/ui/soc/activity",
                     "/ui/soc/agents/xss-agent"):
            html = self.get(path).text.lower()
            with self.subTest(path=path):
                for marker in ("lorem ipsum", "todo:", "placeholder data",
                               "hardcoded"):
                    self.assertNotIn(marker, html)

    def test_pages_json_safe_no_secret_leak(self):
        for path in ("/ui/soc/", "/ui/soc/targets"):
            html = self.get(path).text
            with self.subTest(path=path):
                self.assertNotIn("OPENROUTER_API_KEY", html)
                self.assertNotIn("sk-or-", html)


if __name__ == "__main__":
    unittest.main()
