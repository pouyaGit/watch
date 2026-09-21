"""EPIC8: case explorer page + evidence viewer page render contracts."""

from __future__ import annotations

import unittest


class TestCasesPage(unittest.TestCase):
    def test_page_title(self):
        from backend.routers import aec
        payload = aec.cases_page_payload()
        self.assertEqual(payload["page_title"], "AEC Cases")

    def test_active_nav(self):
        from backend.routers import aec
        self.assertEqual(aec.cases_page_payload()["active"], "aec-cases")

    def test_rows_have_badge_state(self):
        from backend.routers import aec
        for row in aec.cases_page_payload()["cases"]:
            self.assertIn("badge", row)

    def test_badge_closed_set(self):
        from backend.routers import aec
        allowed = {"ok", "warn", "err", "muted"}
        for row in aec.cases_page_payload()["cases"]:
            self.assertIn(row["badge"], allowed)

    def test_evidence_state_badge_consistent(self):
        from backend.routers import aec
        for row in aec.cases_page_payload()["cases"]:
            if row["evidence_state"] == "WAITING_EVIDENCE":
                self.assertEqual(row["badge"], "warn")

    def test_empty_view_payload(self):
        from backend.routers import aec
        payload = aec.cases_page_payload(empty=True)
        self.assertEqual(payload["cases"], [])
        self.assertEqual(payload["total"], 0)


class TestCaseDetailPage(unittest.TestCase):
    def test_header_badge(self):
        from backend.routers import aec
        payload = aec.case_detail_page_payload("case-df54757aee1a")
        self.assertIn("badge", payload["case"])

    def test_timeline_sorted_ascending(self):
        from backend.routers import aec
        timeline = aec.case_detail_page_payload(
            "case-df54757aee1a")["timeline"]
        ticks = [entry["tick"] for entry in timeline]
        self.assertEqual(ticks, sorted(ticks))

    def test_audit_events_match_kinds(self):
        from backend.routers import aec
        events = aec.case_detail_page_payload(
            "case-df54757aee1a")["audit_events"]
        for event in events:
            self.assertIn("action", event)


class TestEvidencePage(unittest.TestCase):
    def test_page_title(self):
        from backend.routers import aec
        self.assertEqual(aec.evidence_page_payload()["page_title"],
                         "AEC Evidence")

    def test_artifacts_ordered_by_id(self):
        from backend.routers import aec
        artifacts = aec.evidence_page_payload()["artifacts"]
        ids = [a["evidence_id"] for a in artifacts]
        self.assertEqual(ids, sorted(ids))

    def test_row_badge_fields(self):
        from backend.routers import aec
        for artifact in aec.evidence_page_payload()["artifacts"]:
            self.assertIn("integrity_badge", artifact)
            self.assertIn("redaction_badge", artifact)

    def test_empty_payload(self):
        from backend.routers import aec
        payload = aec.evidence_page_payload([])
        self.assertEqual(payload["artifacts"], [])


class TestAuditPage(unittest.TestCase):
    def test_page_title(self):
        from backend.routers import aec
        self.assertEqual(aec.audit_page_payload()["page_title"],
                         "AEC Audit")

    def test_events_have_badge(self):
        from backend.routers import aec
        for event in aec.audit_page_payload()["events"]:
            self.assertIn("badge", event)

    def test_event_badges_closed(self):
        from backend.routers import aec
        allowed = {"ok", "warn", "err", "muted"}
        for event in aec.audit_page_payload()["events"]:
            self.assertIn(event["badge"], allowed)


class TestPipelinePage(unittest.TestCase):
    def test_page_title(self):
        from backend.routers import aec
        self.assertEqual(aec.pipeline_page_payload()["page_title"],
                         "AEC Research Pipeline")

    def test_stages_have_badge(self):
        from backend.routers import aec
        for stage in aec.pipeline_page_payload()["stages"]:
            self.assertIn("badge", stage)

    def test_stage_badge_matches_state(self):
        from backend.routers import aec
        for stage in aec.pipeline_page_payload()["stages"]:
            if stage["state"] in ("WAITING_EVIDENCE", "BLOCKED",
                                  "REFUSED"):
                self.assertEqual(stage["badge"], "warn")
            elif stage["state"] == "":
                self.assertEqual(stage["badge"], "muted")


class TestObservationsPage(unittest.TestCase):
    def test_page_title(self):
        from backend.routers import aec
        self.assertEqual(aec.observations_page_payload()["page_title"],
                         "AEC Observations")

    def test_rows_have_badge(self):
        from backend.routers import aec
        for row in aec.observations_page_payload()["observations"]:
            self.assertIn("badge", row)

    def test_completed_rows_green(self):
        from backend.routers import aec
        for row in aec.observations_page_payload()["observations"]:
            if row["state"] == "COMPLETED":
                self.assertEqual(row["badge"], "ok")

    def test_blocked_rows_red(self):
        from backend.routers import aec
        for row in aec.observations_page_payload()["observations"]:
            if row["state"] in ("BLOCKED", "FAILED"):
                self.assertEqual(row["badge"], "err")


if __name__ == "__main__":
    unittest.main()