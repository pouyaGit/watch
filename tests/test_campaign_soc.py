"""AUTONOMOUS SECURITY CAMPAIGN ORCHESTRATOR v1 — SOC UI tests (Phase 14).

Campaign-level visibility inside the EXISTING AI SOC: campaign list,
campaign detail, objective detail — all fed from real persisted store
rows via the adapter's own store factories (patched here to tmp
fixtures so tests never read production state), with honest empty
states and no fake counters.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from jinja2 import Environment, FileSystemLoader  # noqa: E402

from tests.campaign_fixtures import (  # noqa: E402
    add_obj,
    make_campaign,
    make_dependency,
    make_stores,
    run_campaign,
)
import backend.soc.campaigns as soc_campaigns  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO_ROOT / "web" / "templates"
ENV = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))

_SOC_CTX = {
    "active": "soc-campaigns",
    "api_key_qs": "",
    "title": "WATCH",
    "page_title": "Campaigns",
}


def _render(template: str, payload: dict) -> str:
    return ENV.get_template(template).render(**{**_SOC_CTX, **payload})


def _patched(cs, store):
    """Point the adapter's store factories at tmp fixtures."""
    return (mock.patch.object(soc_campaigns, "_campaign_store",
                              return_value=cs),
            mock.patch.object(soc_campaigns, "_runtime_store",
                              return_value=store))


class TestCampaignIndex(unittest.TestCase):
    def test_empty_state_is_honest(self):
        store, cs = make_stores()
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            payload = soc_campaigns.campaigns_index()
        self.assertEqual(payload["count"], 0)
        html = _render("soc/campaigns.html", payload)
        self.assertIn("No campaigns", html)

    def test_index_counts_real_rows(self):
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        add_obj(cs, camp, priority=90)
        add_obj(cs, camp, priority=80, question="second question",
                hypothesis="second hypothesis")
        run_campaign(camp.campaign_id, cs, store, max_objectives=1)
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            payload = soc_campaigns.campaigns_index()
        self.assertEqual(payload["count"], 1)
        row = payload["campaigns"][0]
        self.assertEqual(row["campaign_id"], camp.campaign_id)
        self.assertEqual(row["objective_total"], 2)
        self.assertTrue(row["scope_ref"])
        self.assertEqual(row["resolved"], 1)   # real count, not a stub
        self.assertIn("/ui/soc/campaigns/", row["detail_url"])
        html = _render("soc/campaigns.html", payload)
        self.assertIn(camp.campaign_id, html)
        self.assertNotIn("No campaigns recorded", html)


class TestCampaignDetail(unittest.TestCase):
    def _build(self):
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        prereq = add_obj(cs, camp, priority=90)
        from backend.research_agents.campaign.models import (
            CampaignObjective,
            new_id,
        )
        dep_id = new_id("obj")
        dependent = CampaignObjective(
            objective_id=dep_id, campaign_id=camp.campaign_id,
            category="CVE_RESEARCH", scope_ref=camp.scope_ref,
            research_question="evaluate CVE applicability",
            hypothesis="applicable", priority=50, state="QUEUED",
            dependencies=[make_dependency(dep_id, prereq.objective_id)])
        cs.add_objective(dependent, camp)
        run_campaign(camp.campaign_id, cs, store, max_objectives=1)
        return store, cs, camp

    def test_detail_sections_all_present(self):
        store, cs, camp = self._build()
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            payload = soc_campaigns.campaign_detail(camp.campaign_id)
        self.assertIsNotNone(payload)
        campaign = payload["campaign"]
        self.assertEqual(campaign["campaign_id"], camp.campaign_id)
        self.assertTrue(campaign["scope_ref"])
        # run bound parked the campaign WAITING with one objective left
        self.assertEqual(campaign["state"], "WAITING")
        counts = payload["counts"]
        self.assertEqual(sum(counts.values()), 2, counts)
        self.assertEqual(len(payload["objectives"]), 2)
        # dependent shows its dependency with real prereq state
        dep_rows = [o for o in payload["objectives"]
                    if o["dependencies"]]
        self.assertTrue(dep_rows, payload["objectives"])
        self.assertEqual(dep_rows[0]["dependencies"][0]["dep_state"],
                         "RESOLVED")
        # budget table: every resource with numeric used/limit
        budget_rows = payload["budget_rows"]
        self.assertTrue(budget_rows)
        obs = [b for b in budget_rows if b["resource"] == "observations"]
        self.assertTrue(obs, budget_rows)
        self.assertIsInstance(obs[0]["used"], int)
        # activity comes from real store rows only
        self.assertTrue(payload["activity"], payload["activity"])
        for act in payload["activity"]:
            self.assertTrue(act["action"])
            self.assertTrue(act["at"])
        # campaign-level KPIs are real numbers
        self.assertEqual(payload["completed_objectives"], 1)
        self.assertEqual(payload["remaining_objectives"], 1)
        self.assertIsNotNone(payload["next_objective"])

    def test_detail_renders(self):
        store, cs, camp = self._build()
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            payload = soc_campaigns.campaign_detail(camp.campaign_id)
        html = _render("soc/campaign_detail.html", payload)
        self.assertIn(camp.campaign_id, html)
        self.assertIn(payload["campaign"]["scope_ref"], html)
        self.assertIn("Cumulative budget", html)
        self.assertIn("Objectives", html)
        self.assertIn("Campaign activity", html)
        self.assertNotIn("99.9", html)

    def test_unknown_campaign_returns_none(self):
        store, cs = make_stores()
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            self.assertIsNone(
                soc_campaigns.campaign_detail("cmp-missing"))
            self.assertIsNone(
                soc_campaigns.objective_detail("cmp-missing",
                                               "obj-missing"))


class TestObjectiveDetail(unittest.TestCase):
    def test_objective_detail_sections(self):
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        obj = add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store, max_objectives=1,
                     outcome="completed_case")
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            payload = soc_campaigns.objective_detail(
                camp.campaign_id, obj.objective_id)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["objective"]["objective_id"],
                         obj.objective_id)
        self.assertTrue(payload["objective"]["research_question"])
        self.assertTrue(payload["objective"]["hypothesis"])
        self.assertEqual(payload["evidence"]["gate_reason"],
                         "evidence_rules_met")
        self.assertEqual(payload["evidence"]["case_id"],
                         "case-fake-0001")
        self.assertEqual(payload["hunt"]["state"], "RESOLVED")
        self.assertEqual(len(payload["hunt"]["plan_ids"]), 1)
        self.assertEqual(len(payload["hunt"]["observation_ids"]), 2)
        self.assertEqual(payload["objective"]["state"], "RESOLVED")
        html = _render("soc/campaign_objective.html", payload)
        self.assertIn(obj.objective_id, html)
        self.assertIn("Dependencies", html)

    def test_pending_objective_shows_honest_pending_state(self):
        store, cs = make_stores()
        camp = make_campaign(cs, scope="fixture:a/a.test")
        obj = add_obj(cs, camp, priority=90)
        run_campaign(camp.campaign_id, cs, store, max_objectives=1,
                     outcome="leave_queued")
        p_cs, p_store = _patched(cs, store)
        with p_cs, p_store:
            payload = soc_campaigns.objective_detail(
                camp.campaign_id, obj.objective_id)
        self.assertIsNotNone(payload)
        self.assertNotIn(payload["objective"]["state"],
                         ("RESOLVED", "REJECTED"))
        ev = payload["evidence"]
        self.assertIn(ev["job_status"], ("QUEUED", "CLAIMED",
                                         "RUNNING"))
        self.assertEqual(ev["case_id"], "")
        self.assertEqual(payload["hunt"]["state"], "")
        html = _render("soc/campaign_objective.html", payload)
        self.assertIn(obj.objective_id, html)


class TestNavigationStillIntact(unittest.TestCase):
    def test_sidebar_campaigns_link_and_legacy_targets_kept(self):
        base = (REPO_ROOT / "web/templates/base.html").read_text(
            encoding="utf-8")
        self.assertIn('href="/ui/soc/campaigns', base)
        for kept in ("/ui/programs", "/ui/domains", "/ui/http",
                     "/ui/wordlists", "/ui/urls", "/ui/endpoints",
                     "/ui/parameters", "/ui/changes", "/ui/soc/",
                     "/ui/soc/agents", "/ui/soc/activity",
                     "/ui/soc/cases", "/ui/kb", "/ui/soc/handoff",
                     "/ui/runs", "/ui/tasks", "/docs"):
            self.assertIn(f'href="{kept}', base)


if __name__ == "__main__":
    unittest.main()
