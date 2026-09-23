"""Epic8: meaningful-activity + AI-activity (right-now) tests."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from backend.prod_intel import activity as A
from tests.prod_intel_fixtures import (
    IntelEnvMixin,
    add_job,
    audit,
    envelope,
)

MEANINGFUL = set(A._MEANINGFUL_CATEGORIES)


class TestTaxonomy(unittest.TestCase):
    def test_every_mapped_category_is_in_the_meaningful_set(self):
        for event, (cat, kind) in A.EVENT_CATEGORY.items():
            self.assertIn(cat, MEANINGFUL, event)

    def test_taxonomy_covers_the_epic_example_categories(self):
        needed = {
            "research_started", "hunt_objective_created",
            "authorization_granted", "typed_observation_produced",
            "candidate_created", "candidate_correlated",
            "verification_started", "verification_completed",
            "case_created", "case_transitioned", "handoff_produced",
            "knowledge_memory_update",
        }
        self.assertLessEqual(needed, MEANINGFUL)

    def test_every_kind_is_valid(self):
        for event, (_cat, kind) in A.EVENT_CATEGORY.items():
            self.assertIn(kind, ("progression", "failure", "denied",
                                 "blocked"), event)

    def test_no_duplicate_keys_in_taxonomy_source(self):
        import ast
        import pathlib
        src = pathlib.Path(A.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and getattr(
                    node.targets[0], "id", "") == "EVENT_CATEGORY":
                keys = [k.value for k in node.value.keys
                        if isinstance(k, ast.Constant)]
                self.assertEqual(len(keys), len(set(keys)),
                                 "duplicate taxonomy keys")


class TestFeed(IntelEnvMixin, unittest.TestCase):
    def test_empty_store_feed_is_not_observed(self):
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["state"], "not_observed")
        self.assertEqual(feed["value"], [])

    def test_failure_events_typed_failure_not_success(self):
        audit(event="job_failed", job_id="job-x", reason="boom")
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["value"][0]["kind"], "failure")
        self.assertEqual(feed["value"][0]["category"], "research_failed")

    def test_denied_authorization_is_denied_not_granted(self):
        audit(event="hunt_authorization", auth_id="authz-1",
              status="DENIED")
        feed = A.build_feed(hours=None, limit=50)
        item = feed["value"][0]
        self.assertEqual(item["category"], "authorization_denied")
        self.assertEqual(item["kind"], "denied")

    def test_granted_authorization_category(self):
        audit(event="hunt_authorization", auth_id="authz-1",
              status="GRANTED")
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["value"][0]["category"],
                         "authorization_granted")
        self.assertEqual(feed["value"][0]["kind"], "progression")

    def test_unmapped_events_are_excluded_from_meaningful_feed(self):
        audit(event="some_internal_debug_event", job_id="job-1")
        audit(event="job_claimed", job_id="job-2")
        feed = A.build_feed(hours=None, limit=50)
        events = [i["event"] for i in feed["value"]]
        self.assertNotIn("some_internal_debug_event", events)
        self.assertIn("job_claimed", events)

    def test_window_filters_old_events(self):
        audit(event="job_claimed", job_id="job-old",
              ts="2020-01-01T00:00:00+00:00")
        feed = A.build_feed(hours=24, limit=50)
        self.assertEqual(feed["state"], "not_observed")
        self.assertEqual(feed["value"], [])

    def test_recent_events_pass_window(self):
        audit(event="job_claimed", job_id="job-new")
        feed = A.build_feed(hours=24, limit=50)
        self.assertEqual(len(feed["value"]), 1)

    def test_feed_ordered_newest_first(self):
        for i in range(3):
            audit(event="job_claimed", job_id=f"job-{i}")
        feed = A.build_feed(hours=None, limit=50)
        stamps = [i["at"] for i in feed["value"]]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_feed_limit_bounds_records(self):
        for i in range(10):
            audit(event="job_claimed", job_id=f"job-{i}")
        feed = A.build_feed(hours=None, limit=3)
        self.assertEqual(len(feed["value"]), 3)
        self.assertIn("capped at 3", feed["aggregation"])

    def test_candidate_event_links_to_finding_detail(self):
        audit(event="finding_candidate_detected",
              candidate_id="cand-abc123456789")
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["value"][0]["link"],
                         "/ui/soc/findings/cand-abc123456789")

    def test_campaign_event_links_to_campaign_page(self):
        audit(event="campaign_started", campaign_id="camp-1")
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["value"][0]["link"],
                         "/ui/soc/campaigns/camp-1")

    def test_knowledge_event_links_to_kb(self):
        audit(event="knowledge_used", job_id="job-k",
              document="kb-0001-abc")
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["value"][0]["link"], "/ui/kb/kb-0001-abc")

    def test_runtime_case_event_links_to_case_page(self):
        audit(event="case_created", case_id="case-1234abcd5678")
        feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["value"][0]["link"],
                         "/ui/soc/cases/case-1234abcd5678")

    def test_job_event_carries_job_context_even_without_link(self):
        audit(event="job_started", job_id="job-ctx", specialist="xss-agent")
        feed = A.build_feed(hours=None, limit=50)
        item = feed["value"][0]
        self.assertEqual(item["context"]["job_id"], "job-ctx")
        self.assertEqual(item["context"]["specialist"], "xss-agent")
        self.assertIsNone(item["link"])       # no stable route -> honest

    def test_categories_list_names_all_meaningful_kinds_used(self):
        audit(event="job_claimed", job_id="j1")
        audit(event="job_failed", job_id="j2", reason="x")
        feed = A.build_feed(hours=None, limit=50)
        self.assertIn("research_started", feed["categories"])
        self.assertIn("research_failed", feed["categories"])

    def test_unavailable_source_propagates(self):
        with mock.patch("backend.prod_intel.activity.sources.audit",
                        return_value=envelope(None, "unavailable", "x")):
            feed = A.build_feed(hours=None, limit=50)
        self.assertEqual(feed["state"], "unavailable")
        self.assertIsNone(feed["value"])

    def test_every_item_has_provenance_fields(self):
        audit(event="job_claimed", job_id="job-p")
        feed = A.build_feed(hours=None, limit=50)
        item = feed["value"][0]
        for key in ("category", "event", "at", "kind", "context", "link",
                    "source"):
            self.assertIn(key, item)
        for key in ("source", "population", "aggregation", "time_range"):
            self.assertIn(key, feed)

    def test_feed_json_serializable(self):
        audit(event="job_claimed", job_id="job-j")
        json.dumps(A.build_feed(hours=None, limit=10), default=str)


class TestCurrentActivity(IntelEnvMixin, unittest.TestCase):
    def test_no_heartbeat_no_job_is_planned_not_active(self):
        act = A.current_activity()
        self.assertIn(act["state"], ("PLANNED", "UNKNOWN", "IDLE"))
        self.assertNotEqual(act["state"], "ACTIVE")

    def test_worker_source_failure_is_unknown_not_active(self):
        with mock.patch("backend.prod_intel.activity.sources.worker",
                        return_value=envelope(None, "unavailable", "x")):
            act = A.current_activity()
        self.assertEqual(act["state"], "UNKNOWN")
        self.assertIn("worker", act["basis"])

    def test_jobs_source_failure_is_unknown_not_planned(self):
        with mock.patch("backend.prod_intel.activity.sources.jobs",
                        return_value=envelope(None, "unavailable", "x")):
            act = A.current_activity()
        self.assertEqual(act["state"], "UNKNOWN")
        self.assertIn("job source", act["basis"])

    def test_active_requires_running_job_and_live_heartbeat(self):
        add_job(status="RUNNING")
        with mock.patch("backend.prod_intel.activity.sources.worker",
                        return_value=envelope(
                            {"alive": True, "reason": "fresh"}, "ok")):
            act = A.current_activity()
        self.assertEqual(act["state"], "ACTIVE")
        self.assertEqual(len(act["running_jobs"]), 1)
        self.assertEqual(act["running_jobs"][0]["status"], "RUNNING")
        self.assertEqual(act["running_jobs"][0]["link"],
                         "/ui/soc/activity")

    def test_running_job_without_heartbeat_is_unknown_stale_lease(self):
        add_job(status="RUNNING")
        with mock.patch("backend.prod_intel.activity.sources.worker",
                        return_value=envelope(
                            {"alive": False, "reason": "stale"}, "ok")):
            act = A.current_activity()
        self.assertEqual(act["state"], "UNKNOWN")
        self.assertIn("stale lease", act["basis"])

    def test_terminal_failed_job_is_not_shown_as_running(self):
        add_job(status="TERMINAL_FAILED")
        with mock.patch("backend.prod_intel.activity.sources.worker",
                        return_value=envelope(
                            {"alive": True, "reason": ""}, "ok")):
            act = A.current_activity()
        self.assertEqual(act["running_jobs"], [])
        self.assertNotEqual(act["state"], "ACTIVE")

    def test_running_jobs_carry_navigation_context(self):
        job = add_job(status="RUNNING")
        act = A.current_activity()
        row = act["running_jobs"][0]
        for key in ("job_id", "agent", "category", "target", "status",
                    "link"):
            self.assertIn(key, row)
        self.assertEqual(row["job_id"], job.id)

    def test_activity_json_serializable(self):
        add_job(status="QUEUED")
        json.dumps(A.current_activity(), default=str)

    def test_rule_version_present(self):
        act = A.current_activity()
        self.assertEqual(act["rule_version"], "production-intelligence-v1")


if __name__ == "__main__":
    unittest.main()
