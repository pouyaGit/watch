"""Focused tests for the Stage R81 researcher API contract.

Covers list/detail/submission on the real persisted artifact plus hermetic
artifact-root tests. All evidence packages are labelled NON-REAL/OFFLINE.
Read-only: no Mongo writes, no artifact writes, no network.
"""

from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from config import config
from fastapi.testclient import TestClient

API_KEY = config().get("API_KEY", "")
CASE_ID = "case-indeed-a1-endpoint-behavior"
ARTIFACT = Path(
    "ai_data/research/r77/r64-indeed-b1ebaaf9f2211f82.json"
)

METHOD_REF = "response:nonreal-api-method-auth-1"
RESPONSE_REF = "response:nonreal-api-response-behavior-1"
CONFLICT_A = "response:nonreal-api-conflict-provides-1"
CONFLICT_B = "response:nonreal-api-conflict-contradicts-1"


def _params(**extra):
    params = {"api_key": API_KEY} if API_KEY else {}
    params.update(extra)
    return params


def api_item(
    ref: str,
    *,
    kind: str = "METHOD_AUTH",
    effect: str = "PROVIDES",
    hypothesis_ref: str = "H1",
    source: str = "HUMAN_REVIEW",
) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": kind,
        "effect": effect,
        "source": source,
        "evidence_ref": ref,
        "observations": [
            {
                "ref": ref,
                "fact": f"NON-REAL/OFFLINE api contract fixture for {kind}",
            }
        ],
    }


class _ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        return self.client.get(path, params=_params(**params))

    def _post(self, path, body, **params):
        return self.client.post(path, params=_params(**params), json=body)


class TestListCases(_ApiTestCase):
    def test_list_cases_shape_and_bounds(self):
        response = self._get("/api/research/cases")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["rule_version"], "r81-1")
        self.assertGreaterEqual(body["total"], 1)
        self.assertLessEqual(body["total"], 32)
        item = next(
            (
                entry
                for entry in body["items"]
                if entry["case_id"] == CASE_ID
            ),
            None,
        )
        self.assertIsNotNone(item)
        for field in (
            "case_id",
            "program",
            "category",
            "gap_id",
            "status",
            "readiness",
            "decision",
            "feedback",
            "next_iteration",
            "human_review_required",
            "evidence",
            "missing_evidence",
        ):
            self.assertIn(field, item)
        self.assertEqual(item["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(
            item["missing_evidence"]["decision_critical"],
            ["METHOD_AUTH", "RESPONSE_BEHAVIOR"],
        )
        text = json.dumps(body)
        for forbidden in ("://", "sk-", "Bearer", '"_id"', "Traceback"):
            self.assertNotIn(forbidden, text)

    def test_list_is_read_only(self):
        before = ARTIFACT.read_bytes()
        self._get("/api/research/cases")
        self.assertEqual(before, ARTIFACT.read_bytes())


class TestCaseDetail(_ApiTestCase):
    def test_case_detail_returns_r77_workbench(self):
        response = self._get(f"/api/research/cases/{CASE_ID}")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["case_id"], CASE_ID)
        workbench = body["workbench"]
        for field in (
            "current_state",
            "hypotheses",
            "why_interesting",
            "what_we_know",
            "what_is_missing",
            "what_to_do_next",
            "next_steps",
            "human_review",
            "conflicts",
            "history",
            "workflow_actions",
            "safety",
        ):
            self.assertIn(field, workbench)
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
        text = json.dumps(body)
        for forbidden in ("://", "sk-", "Bearer", '"_id"', "Traceback"):
            self.assertNotIn(forbidden, text)

    def test_case_detail_unknown_case(self):
        response = self._get("/api/research/cases/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertIn("UNKNOWN_CASE", response.json()["detail"])

    def test_case_detail_reuses_r77_authority(self):
        from ai.knowledge.research_workbench import build_research_workbench
        from backend import research_cases

        entry = research_cases.get_case_entry(CASE_ID)
        self.assertIsNotNone(entry)
        stages = entry["stages"]
        expected = build_research_workbench(
            entry["case"],
            action_plan=stages["action_plan"],
            acquisition_plan=stages["acquisition_plan"],
            evidence_provenance=stages["evidence_provenance"],
            limit=research_cases.MAX_HISTORY,
        )
        response = self._get(f"/api/research/cases/{CASE_ID}")
        self.assertEqual(
            json.dumps(response.json()["workbench"], sort_keys=True),
            json.dumps(expected, sort_keys=True),
        )

    def test_case_detail_is_read_only(self):
        before = ARTIFACT.read_bytes()
        self._get(f"/api/research/cases/{CASE_ID}")
        self.assertEqual(before, ARTIFACT.read_bytes())


class TestEvidenceSubmission(_ApiTestCase):
    def test_valid_submission(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "submitted_by": "authorized-researcher-1",
                "items": [api_item(METHOD_REF)],
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["submission_status"], "ACCEPTED")
        self.assertEqual(body["accepted_external_evidence"], 1)
        self.assertEqual(body["rejection_codes"], [])
        self.assertEqual(body["accepted_requirement_kinds"], ["METHOD_AUTH"])
        self.assertEqual(body["case_summary"]["status"], "ACTIVE")
        self.assertEqual(
            body["case_summary"]["sufficiency_state"], "PARTIALLY_SUFFICIENT"
        )
        self.assertIn(
            "METHOD_AUTH",
            body["workbench"]["what_we_know"]["available_requirement_kinds"],
        )
        self.assertEqual(
            body["workbench"]["what_is_missing"]["decision_critical_missing"],
            ["RESPONSE_BEHAVIOR"],
        )
        self.assertEqual(
            body["safety"]["confirmation_state"], "NOT_CONFIRMED"
        )

    def test_complete_submission_reaches_human_review(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [
                    api_item(METHOD_REF),
                    api_item(RESPONSE_REF, kind="RESPONSE_BEHAVIOR"),
                ],
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["submission_status"], "ACCEPTED")
        self.assertEqual(
            body["case_summary"]["status"], "READY_FOR_HUMAN_REVIEW"
        )
        self.assertEqual(
            body["case_summary"]["stopping_reason"],
            "DECISION_EVIDENCE_COMPLETE",
        )
        self.assertTrue(body["workbench"]["human_review"]["required"])

    def test_case_mismatch_rejected(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": "case-somewhere-else",
                "items": [api_item(METHOD_REF)],
            },
        )
        self.assertEqual(response.status_code, 409)
        self.assertIn("CASE_MISMATCH", response.json()["detail"])

    def test_unknown_case_submission(self):
        response = self._post(
            "/api/research/cases/no-such-case/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": "no-such-case",
                "items": [api_item(METHOD_REF)],
            },
        )
        self.assertEqual(response.status_code, 404)
        self.assertIn("UNKNOWN_CASE", response.json()["detail"])

    def test_unknown_requirement_rejected(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [api_item(METHOD_REF, kind="TOKEN_VALIDATION")],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "UNKNOWN_REQUIREMENT_FOR_CASE", response.json()["detail"]
        )

    def test_unknown_hypothesis_rejected(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [api_item(METHOD_REF, hypothesis_ref="H9")],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("HYPOTHESIS_NOT_IN_CASE", response.json()["detail"])

    def test_sensitive_evidence_rejected_without_leak(self):
        secret = "supersecretvalue12345"
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [
                    {
                        "hypothesis_ref": "H1",
                        "requirement_kind": "METHOD_AUTH",
                        "effect": "PROVIDES",
                        "source": "HUMAN_REVIEW",
                        "observations": [
                            {
                                "ref": "response:nonreal-api-sensitive-1",
                                "fact": f"authorization token={secret}",
                            }
                        ],
                    }
                ],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "SENSITIVE_SUBMISSION_REJECTED", response.json()["detail"]
        )
        self.assertNotIn(secret, response.text)
        self.assertNotIn("://", response.text)

    def test_execution_content_rejected(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [
                    {
                        "hypothesis_ref": "H1",
                        "requirement_kind": "METHOD_AUTH",
                        "effect": "PROVIDES",
                        "source": "HUMAN_REVIEW",
                        "observations": [
                            {
                                "ref": "response:nonreal-api-exec-1",
                                "fact": "sqlmap -u target",
                            }
                        ],
                    }
                ],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "EXECUTION_CONTENT_REJECTED", response.json()["detail"]
        )

    def test_unsupported_source_delegated(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [api_item(METHOD_REF, source="RANDOM_PROCESS")],
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["submission_status"], "REJECTED")
        self.assertIn("INVALID_EVIDENCE_SOURCE", body["rejection_codes"])

    def test_duplicate_evidence_delegated(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [
                    api_item("response:nonreal-api-dup-1"),
                    api_item("response:nonreal-api-dup-1"),
                ],
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["submission_status"], "PARTIAL")
        self.assertIn("DUPLICATE_EVIDENCE", body["rejection_codes"])

    def test_conflicting_evidence_preserved(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [
                    api_item(CONFLICT_A),
                    api_item(CONFLICT_B, effect="CONTRADICTS"),
                ],
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["provenance"]["conflict_count"], 1)
        self.assertEqual(
            body["provenance"]["conflicting_requirement_kinds"],
            ["METHOD_AUTH"],
        )
        self.assertTrue(body["provenance"]["human_review_required"])
        self.assertFalse(body["workbench"]["conflicts"]["resolved"])
        self.assertEqual(
            body["case_summary"]["stopping_reason"],
            "CONFLICT_REQUIRES_HUMAN_REVIEW",
        )
        self.assertNotIn("winner", response.text.lower())

    def test_malformed_body_rejected(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {"case_ref": CASE_ID},
        )
        self.assertEqual(response.status_code, 422)

    def test_submission_does_not_write_artifacts(self):
        before = ARTIFACT.read_bytes()
        self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": CASE_ID,
                "items": [api_item(METHOD_REF)],
            },
        )
        self.assertEqual(before, ARTIFACT.read_bytes())

    def test_post_delegates_to_r80_boundary(self):
        from backend import research_cases

        sentinel = {
            "status": "SUBMISSION_REJECTED",
            "rejections": [{"code": "SENSITIVE_SUBMISSION_REJECTED"}],
            "intake": None,
            "safety": {},
        }
        with mock.patch.object(
            research_cases,
            "submit_research_evidence",
            return_value=sentinel,
        ) as boundary:
            response = self._post(
                f"/api/research/cases/{CASE_ID}/evidence",
                {
                    "submission_version": "r80-1",
                    "case_ref": CASE_ID,
                    "items": [api_item(METHOD_REF)],
                },
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("SENSITIVE_SUBMISSION_REJECTED", response.json()["detail"])
        self.assertEqual(boundary.call_count, 1)
        payload = boundary.call_args.kwargs
        self.assertEqual(
            payload["case"]["case_id"], CASE_ID
        )

    def test_no_stack_traces_or_secrets_in_errors(self):
        response = self._post(
            f"/api/research/cases/{CASE_ID}/evidence",
            {
                "submission_version": "r80-1",
                "case_ref": "other",
                "items": [api_item(METHOD_REF)],
            },
        )
        self.assertNotIn("Traceback", response.text)
        self.assertNotIn("://", response.text)
        self.assertNotIn("sk-", response.text)


class TestRouteCompatibility(_ApiTestCase):
    def test_existing_generic_research_route_still_served(self):
        response = self._get("/api/research/CVE-2024-27956")
        self.assertIn(response.status_code, (200, 400, 404))

    def test_auth_gate_on_new_routes(self):
        if not API_KEY:
            self.skipTest("API key not configured")
        for method, path in (
            ("get", "/api/research/cases"),
            ("get", f"/api/research/cases/{CASE_ID}"),
        ):
            with self.subTest(path=path):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 401)


class TestHermeticArtifactRoot(unittest.TestCase):
    def test_empty_artifact_root(self):
        from backend import research_cases

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                research_cases, "ARTIFACT_ROOT", Path(tmp)
            ):
                body = research_cases.list_cases()
                self.assertEqual(body["total"], 0)
                self.assertEqual(body["items"], [])
                self.assertIsNone(
                    research_cases.get_case_workbench(CASE_ID)
                )

    def test_malformed_artifacts_are_skipped(self):
        from backend import research_cases

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "r81").mkdir()
            (root / "r81" / "broken.json").write_text(
                "{not json", encoding="utf-8"
            )
            (root / "r81" / "empty.json").write_text(
                "{}", encoding="utf-8"
            )
            with mock.patch.object(
                research_cases, "ARTIFACT_ROOT", root
            ):
                body = research_cases.list_cases()
                self.assertEqual(body["total"], 0)

    def test_service_has_no_write_or_network_primitives(self):
        from backend import research_cases

        source = inspect.getsource(research_cases)
        for forbidden in (
            "MongoClient",
            "insert_one(",
            "insert_many(",
            "update_one(",
            "update_many(",
            "delete_one(",
            "delete_many(",
            "write_text(",
            "persist_result(",
            "import subprocess",
            "import socket",
            "import requests",
            "from openai",
        ):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertIn("submit_research_evidence(", source)
        self.assertIn("build_research_workbench(", source)


if __name__ == "__main__":
    unittest.main()
