"""EPIC8 Part 1: server-rendered page payloads — ctx builders."""

from __future__ import annotations

import unittest


class TestPagePayloads(unittest.TestCase):
    def test_dashboard_payload(self):
        from backend.routers import aec
        payload = aec.dashboard_page_payload()
        self.assertIn("view", payload)
        self.assertIn("active", payload)
        self.assertIn("page_title", payload)
        self.assertEqual(payload["active"], "aec-dashboard")

    def test_cases_payload(self):
        from backend.routers import aec
        payload = aec.cases_page_payload()
        self.assertIn("cases", payload)
        self.assertIn("total", payload)
        self.assertIn("page_title", payload)

    def test_case_detail_payload(self):
        from backend.routers import aec
        payload = aec.case_detail_page_payload("case-df54757aee1a")
        self.assertIn("case", payload)
        self.assertIn("timeline", payload)
        self.assertIn("page_title", payload)

    def test_case_detail_payload_missing(self):
        from backend.routers import aec
        payload = aec.case_detail_page_payload("case-nope")
        self.assertTrue(payload["not_found"])
        self.assertEqual(payload["page_title"], "Case not found")

    def test_pipeline_payload(self):
        from backend.routers import aec
        payload = aec.pipeline_page_payload()
        self.assertIn("stages", payload)
        self.assertEqual(len(payload["stages"]), 8)

    def test_observations_payload(self):
        from backend.routers import aec
        payload = aec.observations_page_payload()
        self.assertIn("observations", payload)
        self.assertIn("total", payload)

    def test_evidence_payload(self):
        from backend.routers import aec
        payload = aec.evidence_page_payload()
        self.assertIn("artifacts", payload)

    def test_audit_payload(self):
        from backend.routers import aec
        payload = aec.audit_page_payload()
        self.assertIn("events", payload)
        self.assertIn("page_title", payload)


class TestPagePayloadSecurity(unittest.TestCase):
    def test_no_secrets_in_any_payload(self):
        from backend.routers import aec
        payloads = (
            aec.dashboard_page_payload(),
            aec.cases_page_payload(),
            aec.case_detail_page_payload("case-df54757aee1a"),
            aec.pipeline_page_payload(),
            aec.observations_page_payload(),
            aec.evidence_page_payload(),
            aec.audit_page_payload(),
        )
        for payload in payloads:
            blob = str(payload).lower()
            for secret in ("cookie", "authorization:", "bearer",
                           "password", "set-cookie"):
                self.assertNotIn(secret, blob)

    def test_payloads_json_serializable(self):
        import json
        from backend.routers import aec
        for payload in (aec.dashboard_page_payload(),
                        aec.observations_page_payload(),
                        aec.audit_page_payload()):
            json.dumps(payload)

    def test_no_urls_in_payloads(self):
        from backend.routers import aec
        blob = str(aec.case_detail_page_payload(
            "case-df54757aee1a"))
        self.assertNotIn("https://", blob)


class TestPagePayloadDeterminism(unittest.TestCase):
    def test_payloads_deterministic(self):
        from backend.routers import aec
        first = aec.dashboard_page_payload()
        second = aec.dashboard_page_payload()
        self.assertEqual(first, second)

    def test_audit_payload_deterministic(self):
        from backend.routers import aec
        first = aec.audit_page_payload()
        second = aec.audit_page_payload()
        self.assertEqual(first["events"], second["events"])

    def test_observations_payload_deterministic(self):
        from backend.routers import aec
        first = aec.observations_page_payload()
        second = aec.observations_page_payload()
        self.assertEqual(first, second)


class TestPageRoutes(unittest.TestCase):
    def test_seven_page_routes(self):
        from backend.routers import aec
        page_paths = [
            r.path for r in aec.router.routes
            if hasattr(r, "methods") and r.path.startswith("/ui/aec")
        ]
        self.assertEqual(len(page_paths), 7)

    def test_page_routes_get_only(self):
        from backend.routers import aec
        for route in aec.router.routes:
            if hasattr(route, "methods") and route.path.startswith(
                    "/ui/aec"):
                self.assertEqual(route.methods, {"GET"})

    def test_templates_correspond_to_routes(self):
        from backend.routers import aec
        routes = {
            r.path for r in aec.router.routes
            if hasattr(r, "methods") and r.path.startswith("/ui/aec")
        }
        self.assertEqual(
            routes,
            {"/ui/aec/dashboard", "/ui/aec/cases",
             "/ui/aec/cases/{id}", "/ui/aec/pipeline",
             "/ui/aec/observations", "/ui/aec/evidence",
             "/ui/aec/audit"})


if __name__ == "__main__":
    unittest.main()