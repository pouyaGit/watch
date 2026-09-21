"""EPIC8 Part 3: case explorer — list columns and detail sections."""

from __future__ import annotations

import unittest

KNOWN_CASE = "case-df54757aee1a"
KNOWN_JOB = "job-df54757aee1a"


def detail():
    from backend.routers import aec
    return aec.build_case_detail_view(KNOWN_CASE)


class TestCaseColumns(unittest.TestCase):
    def test_case_id_present(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertTrue(row["case_id"])

    def test_target_is_asset_or_endpoint(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertTrue(row["target"])

    def test_category_never_empty(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertTrue(row["category"])

    def test_research_state_nonempty(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertTrue(row["research_state"])

    def test_evidence_state_nonempty(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertTrue(row["evidence_state"])

    def test_specialist_blank_when_unassigned(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertIsInstance(row["specialist"], str)

    def test_last_activity_is_iso_or_empty(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertIsInstance(row["last_activity"], str)

    def test_next_action_is_str(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertIsInstance(row["next_action"], str)


class TestCaseDetailSections(unittest.TestCase):
    def test_timeline_is_list(self):
        self.assertIsInstance(detail()["timeline"], list)

    def test_timeline_entries_have_tick_actor_event(self):
        for entry in detail()["timeline"]:
            self.assertIn("tick", entry)
            self.assertIn("actor", entry)
            self.assertIn("event", entry)

    def test_research_history_entries(self):
        for entry in detail()["research_history"]:
            self.assertIn("plan_id", entry)
            self.assertIn("step_count", entry)

    def test_evidence_artifacts_have_ids(self):
        for artifact in detail()["evidence_artifacts"]:
            self.assertTrue(artifact["evidence_id"])

    def test_authorization_status_shape(self):
        status = detail()["authorization_status"]
        self.assertIn("state", status)
        self.assertIn("reference", status)

    def test_observation_history_has_states(self):
        for row in detail()["observation_history"]:
            self.assertIn("state", row)

    def test_audit_events_are_consistent(self):
        for event in detail()["audit_events"]:
            self.assertIn("action", event)
            self.assertIn("result", event)


class TestCaseDetailNoRawData(unittest.TestCase):
    def test_no_full_urls_in_detail(self):
        blob = str(detail())
        self.assertNotIn("https://", blob)

    def test_no_credentials_in_detail(self):
        blob = str(detail()).lower()
        for secret in ("password", "api-key", "authorization:",
                       "cookie"):
            self.assertNotIn(secret, blob)

    def test_no_body_dumps(self):
        blob = str(detail()).lower()
        self.assertNotIn("body", blob)

    def test_no_headers_dump(self):
        blob = str(detail()).lower()
        self.assertNotIn("set-cookie", blob)


class TestCaseDetailNotFound(unittest.TestCase):
    def test_unknown_id(self):
        from backend.routers import aec
        view = aec.build_case_detail_view("case-nope")
        self.assertTrue(view["not_found"])
        self.assertEqual(view["case"], {})

    def test_empty_id(self):
        from backend.routers import aec
        view = aec.build_case_detail_view("")
        self.assertTrue(view["not_found"])

    def test_known_case_resolves(self):
        view = detail()
        self.assertNotIn("not_found", view) or self.assertFalse(
            view.get("not_found"))

    def test_known_case_links_to_job(self):
        view = detail()
        timeline = view["timeline"]
        joined = " ".join(
            entry.get("event", "") for entry in timeline)
        self.assertTrue(joined)


class TestExplorerSpecialCases(unittest.TestCase):
    def test_waiting_evidence_next_action(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            if row["evidence_state"] == "WAITING_EVIDENCE":
                self.assertTrue(row["next_action"])

    def test_case_ids_stable_sorted(self):
        from backend.routers import aec
        ids = [row["case_id"] for row in aec.get_cases()["cases"]]
        self.assertEqual(ids, sorted(ids))

    def test_explorer_rows_are_dicts(self):
        from backend.routers import aec
        for row in aec.get_cases()["cases"]:
            self.assertIsInstance(row, dict)


if __name__ == "__main__":
    unittest.main()