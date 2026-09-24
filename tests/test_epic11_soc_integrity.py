"""EPIC11 §21/§22 — SOC / analyst-workspace integrity rendering.

The analyst must be able to tell, from the page alone:

  * which state is authoritative (and that the LLM advisory is not);
  * for a confirmed finding, its evidence basis;
  * for a pending/blocked finding, exactly which evidence is missing;
  * that a legacy record without the claim contract implies no verdict.

Everything is asserted against the real read-model (``findings.py`` →
``candidate_workspace.build_workspace`` → ``finding_detail.html``), so a
template that quietly hides missing evidence fails these tests.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.soc import candidate_workspace as cw  # noqa: E402
from tests.finding_fixtures import (  # noqa: E402
    contract_evidence,
    inventory_evidence,
)
from tests.test_candidate_workspace import (  # noqa: E402
    base_detail,
    render,
)


def integrity_detail(*, state: str, matrix_status: str, missing: list[str],
                     gate_reason: str, evidence_ids: list[str],
                     advisory_state: str, validation_status: str,
                     blockers: list[dict] | None = None) -> dict:
    d = base_detail()
    d["candidate"]["lifecycle_state"] = state
    d["integrity"] = {
        "recorded": True,
        "authoritative_state": state,
        "confirmation_status": ("SUPPORTED" if state == "VERIFIED"
                               else "UNSUPPORTED"),
        "confirmed": state == "VERIFIED",
        "gate_reason": gate_reason,
        "stage_reached": 1 if state != "VERIFIED" else 4,
        "stage_label": ("parameter observed" if state != "VERIFIED"
                        else "exploitability established"),
        "missing_evidence_types": missing,
        "missing_evidence_reasons": [gate_reason],
        "malformed_evidence": [],
        "claim_evidence_matrix": [
            {"claim_type": "parameter_observed",
             "statement": "The parameter was observed on the target.",
             "status": "SUPPORTED", "evidence_ids": ["ev-0001"]},
            {"claim_type": "reflection_observed",
             "statement": "The controlled input reflected.",
             "status": matrix_status, "evidence_ids": evidence_ids},
            {"claim_type": "vulnerability_confirmed",
             "statement": "Reflected XSS confirmed.",
             "status": matrix_status, "evidence_ids": evidence_ids},
        ],
        "evidence_basis": {"evidence_ids": evidence_ids,
                           "unique_observations": 2,
                           "duplicate_events": 0},
        "report_validation": {"status": validation_status,
                              "blockers": blockers or [],
                              "unsupported_claims": []},
        "advisory": {"label": "Historical / Advisory Only",
                     "state": advisory_state, "authoritative": False,
                     "conflicts_with_current_state": True},
        "source": "persisted claim-integrity record",
    }
    return d


class TestPendingCandidateShowsMissingEvidence(unittest.TestCase):
    def setUp(self):
        self.detail = integrity_detail(
            state="VERIFICATION_PENDING", matrix_status="MISSING",
            missing=["REFLECTION_OBSERVED", "PAYLOAD_EXECUTION"],
            gate_reason="missing_reflection_evidence", evidence_ids=[],
            advisory_state="VERIFICATION_PENDING",
            validation_status="BLOCKED",
            blockers=[{"code": "report_ready_without_verified_state",
                       "detail": "gate state is VERIFICATION_PENDING"}])
        self.ws = cw.build_workspace(self.detail)

    def test_workspace_exposes_the_exact_missing_evidence(self):
        integrity = self.ws["integrity"]
        self.assertTrue(integrity["available"])
        self.assertFalse(integrity["confirmed"])
        self.assertEqual(integrity["authoritative_state"],
                         "VERIFICATION_PENDING")
        self.assertEqual(integrity["gate_reason"],
                         "missing_reflection_evidence")
        self.assertEqual(integrity["missing_evidence_types"],
                         ["REFLECTION_OBSERVED", "PAYLOAD_EXECUTION"])
        self.assertEqual(integrity["report_validation"]["status"], "BLOCKED")
        self.assertIn("report_ready_without_verified_state",
                      integrity["report_validation"]["blockers"])

    def test_page_shows_missing_evidence_and_never_a_verified_badge(self):
        html = render(self.detail)
        self.assertIn("Claim / Evidence Integrity", html)
        self.assertIn("REFLECTION_OBSERVED", html)
        self.assertIn("PAYLOAD_EXECUTION", html)
        self.assertIn("Why this is NOT confirmed", html)
        self.assertIn("missing_reflection_evidence", html)
        self.assertNotIn("Evidence basis of the confirmed claim", html)
        self.assertIn("Historical / Advisory Only", html)

    def test_matrix_renders_every_claim_with_its_status(self):
        html = render(self.detail)
        matrix = self.ws["integrity"]["matrix"]
        self.assertEqual([row["claim"] for row in matrix],
                         ["parameter_observed", "reflection_observed",
                          "vulnerability_confirmed"])
        self.assertIn("parameter_observed", html)
        self.assertIn("vulnerability_confirmed", html)
        self.assertEqual(self.ws["integrity"]["matrix_counts"]["supported"], 1)
        self.assertEqual(self.ws["integrity"]["matrix_counts"]["missing"], 2)


class TestVerifiedCandidateShowsEvidenceBasis(unittest.TestCase):
    def setUp(self):
        self.detail = integrity_detail(
            state="VERIFIED", matrix_status="SUPPORTED", missing=[],
            gate_reason="claim_supported",
            evidence_ids=["ev-0001", "ev-0002"],
            advisory_state="VERIFICATION_PENDING",
            validation_status="READY_FOR_REVIEW")
        self.ws = cw.build_workspace(self.detail)

    def test_verified_finding_publishes_its_evidence_basis(self):
        integrity = self.ws["integrity"]
        self.assertTrue(integrity["confirmed"])
        self.assertEqual(integrity["evidence_basis"]["evidence_ids"],
                         ["ev-0001", "ev-0002"])
        self.assertEqual(integrity["report_validation"]["status"],
                         "READY_FOR_REVIEW")
        self.assertEqual(integrity["missing_evidence_types"], [])

    def test_page_shows_the_basis_and_the_advisory_conflict(self):
        html = render(self.detail)
        self.assertIn("Evidence basis of the confirmed claim", html)
        self.assertIn("ev-0001", html)
        self.assertIn("conflicts with the current", html)
        self.assertIn("authoritative: <span class=\"mono\">false", html)


class TestContradictedClaimIsVisible(unittest.TestCase):
    def test_contradicted_claim_is_labelled_in_the_ui(self):
        detail = integrity_detail(
            state="REJECTED", matrix_status="CONTRADICTED",
            missing=["REFLECTION_OBSERVED"],
            gate_reason="contradicting_evidence:ev-neg-1", evidence_ids=[],
            advisory_state="VERIFIED", validation_status="BLOCKED")
        ws = cw.build_workspace(detail)
        html = render(detail)
        self.assertEqual(ws["integrity"]["matrix_counts"]["contradicted"], 2)
        self.assertIn("CONTRADICTED", html)
        self.assertIn("authoritative_state", ws["integrity"])


class TestLegacyRecordImpliesNoVerdict(unittest.TestCase):
    def test_missing_claim_contract_is_reported_not_inferred(self):
        detail = base_detail()
        detail["candidate"]["lifecycle_state"] = "VERIFIED"
        # no "integrity" key at all: a pre-EPIC11 persisted record
        ws = cw.build_workspace(detail)
        self.assertFalse(ws["integrity"]["available"])
        self.assertIn("No claim/evidence contract", ws["integrity"]["note"])
        html = render(detail)
        self.assertIn("No claim/evidence contract is recorded", html)

    def test_empty_integrity_payload_is_treated_as_absent(self):
        detail = base_detail()
        detail["integrity"] = {}
        ws = cw.build_workspace(detail)
        self.assertFalse(ws["integrity"]["available"])


class TestIntegritySectionSafety(unittest.TestCase):
    def test_malformed_integrity_payload_never_crashes(self):
        detail = base_detail()
        detail["integrity"] = {"claim_evidence_matrix": ["junk", 3, None],
                              "evidence_basis": "not-a-dict",
                              "report_validation": None,
                              "advisory": ["x"],
                              "missing_evidence_types": "oops"}
        ws = cw.build_workspace(detail)
        self.assertTrue(ws["integrity"]["available"])
        self.assertEqual(ws["integrity"]["matrix"], [])
        html = render(detail)
        self.assertIn("Claim / Evidence Integrity", html)

    def test_duplicate_evidence_not_presented_as_support(self):
        detail = integrity_detail(
            state="VERIFICATION_PENDING", matrix_status="MISSING",
            missing=["REFLECTION_OBSERVED"],
            gate_reason="missing_reflection_evidence", evidence_ids=[],
            advisory_state="VERIFICATION_PENDING",
            validation_status="BLOCKED")
        detail["evidence"] = [
            {"id": f"ev-{i:04d}", "job_id": "job-a", "type": "evidence",
             "observation_ref": f"urls:obs-{i % 2}",
             "signal": "xss_parameter_inventory",
             "detail": "https://host/x?p=1", "created_at":
             "2026-09-23T04:38:49Z"}
            for i in range(8)]
        ws = cw.build_workspace(detail)
        # presentation dedup keeps the row count honest and the claim
        # matrix still shows the reflection claim as missing
        self.assertEqual(ws["integrity"]["matrix_counts"]["supported"], 1)
        self.assertEqual(ws["integrity"]["matrix_counts"]["missing"], 2)
        self.assertFalse(ws["integrity"]["confirmed"])

    def test_fixture_evidence_shapes_are_consumed_without_upgrade(self):
        # the real regression evidence (inventory only) and the contract
        # evidence must classify differently through the SAME reader
        inventory = cw._integrity_section({
            "integrity": {"recorded": True,
                          "authoritative_state": "VERIFICATION_PENDING",
                          "claim_evidence_matrix": [
                              {"claim_type": "parameter_observed",
                               "status": "SUPPORTED",
                               "evidence_ids": ["ev-1"]}],
                          "missing_evidence_types": ["REFLECTION_OBSERVED"]}})
        self.assertEqual(inventory["authoritative_state"],
                         "VERIFICATION_PENDING")
        self.assertFalse(inventory["confirmed"])
        # default fixture shape: 2 runs x 10 shared observation refs = 20
        # events (the 40-event/20-unique production shape is owned by
        # test_epic11_regression_cand_7c229c48c455.py)
        self.assertEqual(len(inventory_evidence()), 20)
        self.assertTrue(contract_evidence())


if __name__ == "__main__":
    unittest.main()
