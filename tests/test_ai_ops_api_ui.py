"""EPIC9 §14/§15/§20: AI operations surfaced through API + SOC UI."""

from __future__ import annotations

import unittest

from backend.ai_ops.activity import AI_EVENTS
from backend.ai_ops.state import STATES, state_path
from backend.prod_intel.activity import EVENT_CATEGORY
from backend.soc.overview import overview_payload
from tests.prod_intel_fixtures import IntelEnvMixin
from tests.test_soc_ux_correction import (   # shared proven harness
    BAD_KEY, KEY, _MountedApp,
)

AI_OPS_PATH = "/api/intel/ai-ops"
ALLOWED_OPS_STATES = set(STATES) | {"UNAVAILABLE"}


class TestAiOpsAuth(IntelEnvMixin, _MountedApp):

    def test_requires_api_key(self):
        self.assertEqual(self.client.get(AI_OPS_PATH).status_code, 401)

    def test_wrong_key_rejected(self):
        r = self.client.get(AI_OPS_PATH, params={"api_key": BAD_KEY})
        self.assertEqual(r.status_code, 401)

    def test_right_key_accepted(self):
        r = self.get(AI_OPS_PATH)
        self.assertEqual(r.status_code, 200)

    def test_no_secrets_in_response(self):
        text = self.get(AI_OPS_PATH).text
        self.assertNotIn("sk" + "-or" + "-", text)
        self.assertNotIn("OPENROUTER", text)
        self.assertNotIn("Authorization", text)


class TestAiOpsSchema(IntelEnvMixin, _MountedApp):

    def test_schema_shape(self):
        data = self.get(AI_OPS_PATH).json()
        for key in ("window", "operations_state", "operations_display",
                    "current_tick", "last_tick", "next_tick_at",
                    "work", "process", "rule_version", "updated_at"):
            self.assertIn(key, data)
        self.assertIsInstance(data["window"]["open"], bool)
        self.assertIn(data["operations_state"], ALLOWED_OPS_STATES)
        self.assertIsInstance(data["process"]["alive"], bool)

    def test_window_label_is_authoritative(self):
        data = self.get(AI_OPS_PATH).json()
        self.assertEqual(data["window"]["label"],
                         "12:00-00:00 Asia/Tehran")

    def test_process_never_claimed_without_evidence(self):
        # No live worker in a fresh tmp environment: `alive` is False,
        # and a reason says why — not a fabricated heartbeat.
        data = self.get(AI_OPS_PATH).json()
        self.assertFalse(data["process"]["alive"])
        self.assertTrue(data["process"].get("reason"))

    def test_state_semantics_values(self):
        # operations state is one of the documented states — never a
        # free-text guess.
        data = self.get(AI_OPS_PATH).json()
        self.assertRegex(data["operations_state"],
                         r"^[A-Z_]+$")

    def test_projection_is_read_only(self):
        # GETting the panel must not create runtime state.
        self.get(AI_OPS_PATH)
        self.assertFalse(state_path(None).exists())

    def test_openapi_lists_the_endpoint(self):
        paths = self.client.app.openapi()["paths"]
        self.assertIn(AI_OPS_PATH, paths)


class TestOverviewIntegration(IntelEnvMixin, _MountedApp):

    def test_overview_payload_carries_ai_ops(self):
        payload = overview_payload()
        self.assertIn("ai_ops", payload)
        self.assertIn("operations_state", payload["ai_ops"])

    def test_intel_overview_still_works(self):
        # EPIC8 projection unaffected by the new route.
        r = self.get("/api/intel/overview")
        self.assertEqual(r.status_code, 200)


class TestHomeUi(IntelEnvMixin, _MountedApp):

    def test_home_renders_ai_window_panel(self):
        r = self.get("/ui/soc/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("AI operations", r.text)
        self.assertIn("AI window", r.text)

    def test_home_shows_window_label_and_open_state(self):
        text = self.get("/ui/soc/").text
        self.assertIn("12:00", text)
        self.assertTrue("OPEN" in text or "CLOSED" in text)

    def test_home_distinguishes_process_from_operations(self):
        text = self.get("/ui/soc/").text
        # The two facts are rendered as separate blocks, and the
        # healthy "no worker between ticks" explanation is visible.
        self.assertIn("Worker process", text)
        self.assertIn("AI operations (not process state)", text)
        self.assertIn("normally NO worker process", text)
        self.assertTrue("NOT RUNNING" in text or "RUNNING" in text)

    def test_home_shows_last_and_next_tick(self):
        text = self.get("/ui/soc/").text
        self.assertIn("Last tick:", text)
        self.assertIn("Next tick:", text)

    def test_home_does_not_pretend_persistent_worker_required(self):
        text = self.get("/ui/soc/").text
        self.assertNotIn("worker required", text.lower())


class TestActivityTaxonomyIntegration(unittest.TestCase):

    def test_every_ai_event_is_categorized_for_the_feed(self):
        # prod_intel's MEANINGFUL feed can place every emitted event —
        # no AI operations event falls off the intelligence feed.
        missing = set(AI_EVENTS) - set(EVENT_CATEGORY)
        self.assertEqual(missing, set())

    def test_waiting_event_maps_to_blocked_kind(self):
        kind = EVENT_CATEGORY.get("waiting_for_evidence", ("", ""))[1]
        self.assertEqual(kind, "blocked")


if __name__ == "__main__":
    unittest.main()
