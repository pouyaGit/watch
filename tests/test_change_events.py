"""
tests/test_change_events.py — Unit tests for the change-event tracking layer
(new_endpoint / new_parameter / batch recording / labels).
"""
import unittest
from unittest import mock

from database.change_events import (
    EVENT_LABELS,
    EVENT_TYPES,
    build_recon_events,
    event_class,
    event_label,
    record_change,
    record_changes,
)


class TestEventVocabulary(unittest.TestCase):
    def test_required_types_present(self):
        for t in ("new_endpoint", "new_parameter", "title_changed",
                  "status_changed", "cdn_changed", "ip_changed",
                  "technology_changed", "new_live", "new_http"):
            self.assertIn(t, EVENT_TYPES)

    def test_labels_are_human_readable(self):
        label, icon = EVENT_LABELS["new_parameter"]
        self.assertTrue(label)
        self.assertTrue(icon)
        self.assertIn("New", label)


class TestEventClass(unittest.TestCase):
    def test_known_type_kept(self):
        self.assertEqual(event_class("new_endpoint"), "new_endpoint")

    def test_unknown_type_maps_to_other(self):
        self.assertEqual(event_class('\"><script>alert(1)</script>'), "other")
        self.assertEqual(event_class(None), "other")

    def test_label_never_contains_raw_type(self):
        # Label comes from a fixed lookup; unknown types get a safe default.
        self.assertNotIn("<script>", event_label("<script>"))


class TestBuildReconEvents(unittest.TestCase):
    def test_new_endpoint_and_params(self):
        ep_agg = {
            ("dell", "api.dell.com", "/x"): {"params": {"a", "b"}},
        }
        events = build_recon_events(ep_agg, {})
        types = [e[2] for e in events]
        self.assertIn("new_endpoint", types)
        self.assertIn("new_parameter", types)
        new_params = {e[4] for e in events if e[2] == "new_parameter"}
        self.assertEqual(new_params, {"a", "b"})
        ep_event = next(e for e in events if e[2] == "new_endpoint")
        self.assertEqual(ep_event[4], "/x")

    def test_existing_endpoint_new_param_only(self):
        ep_agg = {("dell", "api.dell.com", "/x"): {"params": {"a", "b", "c"}}}
        snapshot = {("dell", "api.dell.com", "/x"): {"a", "b"}}
        events = build_recon_events(ep_agg, snapshot)
        self.assertNotIn("new_endpoint", [e[2] for e in events])
        new_params = {e[4] for e in events if e[2] == "new_parameter"}
        self.assertEqual(new_params, {"c"})

    def test_no_change_yields_no_events(self):
        ep_agg = {("dell", "api.dell.com", "/x"): {"params": {"a"}}}
        snapshot = {("dell", "api.dell.com", "/x"): {"a"}}
        self.assertEqual(build_recon_events(ep_agg, snapshot), [])

    def test_param_dedup_across_run(self):
        # Same param on two endpoints -> ONE new_parameter event.
        ep_agg = {
            ("dell", "a.dell.com", "/1"): {"params": {"token"}},
            ("dell", "b.dell.com", "/2"): {"params": {"token"}},
        }
        events = build_recon_events(ep_agg, {})
        new_params = [e for e in events if e[2] == "new_parameter"]
        self.assertEqual(len(new_params), 1)

    def test_param_events_capped(self):
        ep_agg = {("dell", "a.dell.com", "/1"): {"params": {f"p{i}" for i in range(50)}}}
        events = build_recon_events(ep_agg, {}, max_param_events=10)
        new_params = [e for e in events if e[2] == "new_parameter"]
        self.assertLessEqual(len(new_params), 10)


class TestRecordFunctions(unittest.TestCase):
    @mock.patch("database.change_events.ChangeEvent")
    def test_record_change_valid(self, CE):
        record_change("dell", "api.dell.com", "new_endpoint", "", "/x")
        self.assertEqual(CE.call_count, 1)

    @mock.patch("database.change_events.ChangeEvent")
    def test_record_change_ignores_unknown_type(self, CE):
        record_change("dell", "api.dell.com", "bogus_type", "", "")
        self.assertEqual(CE.call_count, 0)

    @mock.patch("database.change_events.ChangeEvent")
    def test_record_change_ignores_empty_program(self, CE):
        record_change("", "api.dell.com", "new_endpoint", "", "")
        self.assertEqual(CE.call_count, 0)

    @mock.patch("database.change_events.ChangeEvent.objects.insert")
    @mock.patch("database.change_events.ChangeEvent")
    def test_record_changes_batches(self, CE, insert):
        events = [
            ("dell", "api.dell.com", "new_endpoint", "", "/x"),
            ("dell", "api.dell.com", "new_parameter", "", "token"),
            ("dell", "x", "bogus", "", ""),  # skipped
        ]
        count = record_changes(events)
        self.assertEqual(count, 2)
        insert.assert_called_once()


if __name__ == "__main__":
    unittest.main()
