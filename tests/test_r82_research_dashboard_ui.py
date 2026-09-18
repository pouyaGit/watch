"""Focused tests for the Stage R82 Research Dashboard UI (frontend only).

Static assets + R81 API data-contract checks. No evidence is submitted, no
backend route is exercised beyond the existing read-only R81 GETs, and no
Mongo/artifact writes occur.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")
CASE_ID = "case-indeed-a1-endpoint-behavior"

INDEX_HTML = Path("web/static/research/index.html")
CASE_HTML = Path("web/static/research/case.html")
DASHBOARD_JS = Path("web/static/js/research_dashboard.js")
CUSTOM_CSS = Path("web/static/css/custom.css")
BASE_HTML = Path("web/templates/base.html")
ARTIFACT = Path("ai_data/research/r77/r64-indeed-b1ebaaf9f2211f82.json")

SECTION_ORDER = (
    "section-current-state",
    "section-what-we-know",
    "section-what-is-missing",
    "section-what-to-do-next",
    "section-human-review",
    "section-hypotheses",
    "section-why-interesting",
    "section-conflicts",
    "section-history",
    "section-safety",
)


def _params(**extra):
    params = {"api_key": API_KEY} if API_KEY else {}
    params.update(extra)
    return params


class _ClientTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)


class TestAssetsServed(_ClientTestCase):
    def test_case_list_page_served(self):
        response = self.client.get("/static/research/index.html")
        self.assertEqual(response.status_code, 200)
        text = response.text
        for marker in (
            'data-r82-page="case-list"',
            'id="case-list-body"',
            'id="case-list-state"',
            'id="case-search"',
            'id="case-status-filter"',
            'id="case-review-filter"',
            'id="case-sort"',
            "/static/js/research_dashboard.js",
            "WAITING_FOR_EVIDENCE",
            "READY_FOR_HUMAN_REVIEW",
            "STOPPED",
        ):
            self.assertIn(marker, text, marker)

    def test_case_detail_page_served(self):
        response = self.client.get("/static/research/case.html")
        self.assertEqual(response.status_code, 200)
        text = response.text
        for marker in (
            'data-r82-page="case-detail"',
            'id="workbench"',
            'id="case-detail-state"',
            'id="case-back"',
            'id="case-refresh"',
            'id="evidence-form"',
            'id="evidence-requirement"',
            'id="submission-result"',
            "/static/js/research_dashboard.js",
        ):
            self.assertIn(marker, text, marker)

    def test_dashboard_js_served(self):
        response = self.client.get("/static/js/research_dashboard.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("/api/research/cases", response.text)

    def test_custom_css_contains_dashboard_styles(self):
        response = self.client.get("/static/css/custom.css")
        self.assertEqual(response.status_code, 200)
        for marker in (".r82-topnav", ".r82-missing-box", ".r82-safety", ".r82-result-err"):
            self.assertIn(marker, response.text, marker)


class TestApiIntegrationContract(unittest.TestCase):
    def test_js_uses_only_bounded_endpoints(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertIn("'/api/research/cases'", source)
        self.assertIn("'/human-evidence'", source)
        self.assertNotIn("intake_and_reevaluate", source)
        self.assertNotIn("/api/research/tasks", source)
        # exactly one POST target, the R89 persisted human-evidence endpoint
        self.assertEqual(source.count("method: 'POST'"), 1)

    def test_js_reads_api_key_from_location_only(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertIn("window.location.search", source)
        self.assertIn("URLSearchParams", source)

    def test_js_renders_without_innerhtml(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", source)
        self.assertIn("textContent", source)

    def test_no_external_network_targets_in_js(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertNotIn("http://", source)
        self.assertNotIn("https://", source)
        self.assertNotIn("XMLHttpRequest", source)
        self.assertNotIn("WebSocket", source)

    def test_workbench_section_order(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        positions = [source.index(marker) for marker in SECTION_ORDER]
        self.assertEqual(positions, sorted(positions))

    def test_terminology_and_safety_panel(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        for label in (
            "PROVIDE_EVIDENCE",
            "CONTINUE_RESEARCH",
            "REVIEW_CONFLICT",
            "HUMAN_REVIEW",
            "STOP",
            "NOT RESOLVED",
            "NOT_CONFIRMED",
            "Execution performed",
            "Vulnerability confirmed",
            "Exploit authorized",
            "Human authority required",
        ):
            self.assertIn(label, source, label)

    def test_submission_uses_r80_envelope_and_human_boundary(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertIn("submission_version: 'r80-1'", source)
        self.assertIn("case_ref", source)
        self.assertIn("items", source)
        form = CASE_HTML.read_text(encoding="utf-8")
        self.assertIn("HUMAN_REVIEW", form)
        # R89: the human boundary accepts only the human source; model or
        # research output can never be submitted as human evidence here.
        for source_name in (
            "AUTHORIZED_TEST_CONTEXT",
            "STORED_RESPONSE",
            "EXISTING_CONTEXT",
            "WATCH_DERIVED",
        ):
            self.assertNotIn(source_name, form, source_name)

    def test_error_states_implemented(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        for kind in ("unauthorized", "unavailable", "not-found", "rejected"):
            self.assertIn(kind, source, kind)
        for code in (
            "CASE_MISMATCH",
            "UNKNOWN_REQUIREMENT_FOR_CASE",
            "SENSITIVE_SUBMISSION_REJECTED",
            "EXECUTION_CONTENT_REJECTED",
            "DUPLICATE_EVIDENCE",
        ):
            self.assertIn(code, source, code)

    def test_no_hardcoded_secrets(self):
        api_key = config().get("API_KEY", "")
        for path in (INDEX_HTML, CASE_HTML, DASHBOARD_JS, CUSTOM_CSS):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("openrouter", text.lower(), path.name)
            self.assertNotIn("Bearer ", text, path.name)
            if api_key:
                self.assertNotIn(api_key, text, path.name)
        base = BASE_HTML.read_text(encoding="utf-8")
        self.assertNotIn("Bearer ", base)
        if api_key:
            self.assertNotIn(api_key, base)


class TestEvidenceRequestUiContract(unittest.TestCase):
    """R96: dashboard exposes the R95 request and the R89 hand-off."""

    def test_request_section_and_handoff_present(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        for marker in (
            "renderEvidenceRequest",
            "requestRequirementKinds",
            "EVIDENCE_REQUESTED",
            "evidence_request",
            "request_ref",
            "acquisition_type",
            "Use in submission",
            "requested, not evidence",
        ):
            self.assertIn(marker, source, marker)
        html = CASE_HTML.read_text(encoding="utf-8")
        self.assertIn('id="evidence-request"', html)
        self.assertIn('id="evidence-hypotheses"', html)
        self.assertIn('list="evidence-hypotheses"', html)
        self.assertIn('id="evidence-request-note"', html)

    def test_request_form_keeps_r77_fallback_and_empty_evidence(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        # the unchanged R77 missing lists remain the fallback
        self.assertIn("snapshot.missingAll", source)
        # the client never ships sample facts or observations
        self.assertNotIn("NON-REAL", source)
        self.assertNotIn("response:observation-1", source)

    def test_request_refresh_after_submission(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertIn("refreshEvidenceRequest(caseId)", source)


class TestEvidencePackageUiContract(unittest.TestCase):
    """R99: dashboard renders the evidence package as non-confirmed."""

    def test_package_section_markers(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        for marker in (
            "renderEvidencePackage",
            "evidence_package",
            "not a confirmed finding",
            "non_claims",
            "supporting",
            "contradicting",
        ):
            self.assertIn(marker, source, marker)
        html = CASE_HTML.read_text(encoding="utf-8")
        self.assertIn('id="evidence-package"', html)

    def test_package_refresh_after_submission(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        self.assertIn("renderEvidencePackage(result.body.evidence_package", source)


class TestHumanDecisionUiContract(unittest.TestCase):
    """R100: dashboard shows the human decision as human authority only."""

    def test_decision_section_markers(self):
        source = DASHBOARD_JS.read_text(encoding="utf-8")
        for marker in (
            "renderTriageDecision",
            "triage_decision",
            "Human triage decision",
            "NOT_DECIDED",
            "STALE",
            "agent human-decision",
            "human authority",
        ):
            self.assertIn(marker, source, marker)
        html = CASE_HTML.read_text(encoding="utf-8")
        self.assertIn('id="triage-decision"', html)


class TestSidebarNavigation(unittest.TestCase):
    def test_sidebar_link_present(self):
        text = BASE_HTML.read_text(encoding="utf-8")
        self.assertIn("Research Cases", text)
        self.assertIn("/static/research/index.html", text)

    def test_sidebar_link_rendered(self):
        from api import app

        client = TestClient(app)
        response = client.get("/", params=_params())
        if response.status_code == 401:
            self.skipTest("API key required and not configured for the test")
        self.assertEqual(response.status_code, 200)
        self.assertIn("/static/research/index.html", response.text)


class TestRealCaseContract(_ClientTestCase):
    def test_real_case_list_payload(self):
        response = self.client.get("/api/research/cases", params=_params())
        self.assertEqual(response.status_code, 200)
        body = response.json()
        item = next(
            (
                entry
                for entry in body["items"]
                if entry["case_id"] == CASE_ID
            ),
            None,
        )
        self.assertIsNotNone(item)
        self.assertEqual(item["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(item["readiness"], "INSUFFICIENT")
        self.assertEqual(
            item["missing_evidence"]["decision_critical"],
            ["METHOD_AUTH", "RESPONSE_BEHAVIOR"],
        )
        text = json.dumps(body)
        for forbidden in ("://", "sk-", "Bearer", '"_id"'):
            self.assertNotIn(forbidden, text)

    def test_real_case_workbench_values_rendered_by_ui(self):
        response = self.client.get(
            f"/api/research/cases/{CASE_ID}", params=_params()
        )
        self.assertEqual(response.status_code, 200)
        workbench = response.json()["workbench"]
        self.assertEqual(
            workbench["current_state"]["status"], "WAITING_FOR_EVIDENCE"
        )
        self.assertEqual(
            workbench["what_we_know"]["available_requirement_kinds"],
            ["ENDPOINT_PURPOSE", "WATCH_SIGNAL"],
        )
        self.assertEqual(
            workbench["what_is_missing"]["decision_critical_missing"],
            ["METHOD_AUTH", "RESPONSE_BEHAVIOR"],
        )
        self.assertEqual(
            [step["action"] for step in workbench["next_steps"]],
            ["PROVIDE_EVIDENCE", "CONTINUE_RESEARCH"],
        )
        self.assertEqual(
            workbench["safety"]["confirmation_state"], "NOT_CONFIRMED"
        )
        self.assertFalse(workbench["safety"]["vulnerability_confirmed"])
        self.assertFalse(workbench["safety"]["exploit_authorized"])
        self.assertTrue(workbench["safety"]["human_authority_required"])

    def test_read_only_no_evidence_submitted(self):
        before = ARTIFACT.read_bytes()
        self.client.get("/api/research/cases", params=_params())
        self.client.get(f"/api/research/cases/{CASE_ID}", params=_params())
        self.assertEqual(before, ARTIFACT.read_bytes())


if __name__ == "__main__":
    unittest.main()
