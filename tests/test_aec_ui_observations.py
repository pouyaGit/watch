"""EPIC8 Part 5: observation center — read-only, state-closed, no controls."""

from __future__ import annotations

import unittest

ALL_STATES = frozenset({
    "RECEIVED", "VALIDATING", "AUTHORIZED", "DISPATCHED", "OBSERVING",
    "COLLECTING", "COMPLETED", "REFUSED", "BLOCKED", "FAILED",
    "TIMED_OUT",
})


def view():
    from backend.routers import aec
    return aec.build_observations_view()


class TestObservationRows(unittest.TestCase):
    def test_request_ids_unique(self):
        ids = [row["request_id"] for row in view()["observations"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_request_id_prefix(self):
        for row in view()["observations"]:
            self.assertTrue(row["request_id"].startswith("obs-"))

    def test_case_id_present(self):
        for row in view()["observations"]:
            self.assertTrue(row["case_id"])

    def test_target_present(self):
        for row in view()["observations"]:
            self.assertTrue(row["target"])

    def test_observation_type_allowlisted(self):
        allowed = {"HTTP_METADATA", "HTTP_HEADERS", "HTTP_STATUS",
                   "HTTP_BODY_METADATA"}
        for row in view()["observations"]:
            self.assertIn(row["observation_type"], allowed)

    def test_states_closed(self):
        for row in view()["observations"]:
            self.assertIn(row["state"], ALL_STATES)

    def test_created_time_leq_completed(self):
        for row in view()["observations"]:
            created = row["created_time"]
            completed = row["completed_time"]
            if created and completed:
                self.assertLessEqual(created, completed)

    def test_evidence_id_present_when_completed(self):
        for row in view()["observations"]:
            if row["state"] == "COMPLETED":
                self.assertTrue(
                    row["evidence_id"].startswith("ev-"))


class TestNoControls(unittest.TestCase):
    def test_no_action_buttons_field(self):
        blob = str(view())
        self.assertNotIn("buttons", blob)
        self.assertNotIn("controls", blob)

    def test_no_run_endpoint(self):
        from backend.routers import aec
        paths = [r.path for r in aec.router.routes
                 if hasattr(r, "methods")]
        self.assertNotIn("/api/aec/observations/run", paths)
        self.assertNotIn("/api/aec/observations/execute", paths)

    def test_handler_returns_read_only(self):
        from backend.routers import aec
        result = aec.get_observations()
        self.assertEqual(sorted(result),
                         sorted(["observations", "total"]))


class TestObservationFiltering(unittest.TestCase):
    def test_no_sensitive_headers(self):
        blob = str(view()).lower()
        for secret in ("authorization:", "set-cookie", "cookie=",
                       "password", "bearer"):
            self.assertNotIn(secret, blob)

    def test_no_raw_urls(self):
        blob = str(view())
        self.assertNotIn("https://", blob)

    def test_no_request_bodies(self):
        blob = str(view()).lower()
        self.assertNotIn("body", blob)

    def test_observation_count_consistent(self):
        result = view()
        self.assertEqual(result["total"],
                         len(result["observations"]))


class TestObservationStates(unittest.TestCase):
    def test_state_names_exact(self):
        for state in ALL_STATES:
            self.assertRegex(state, r"^[A-Z][A-Z_]*$")

    def test_all_states_are_runtime_lifecycle(self):
        from aec.runtime.execution.states import STATES
        self.assertLessEqual(ALL_STATES, set(STATES))

    def test_no_custom_states(self):
        for row in view()["observations"]:
            self.assertIn(row["state"], set(STATES)
                          if False else ALL_STATES)


if __name__ == "__main__":
    unittest.main()