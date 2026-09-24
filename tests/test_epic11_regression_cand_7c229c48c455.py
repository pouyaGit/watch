"""EPIC11 §16 — the real cand-7c229c48c455 regression case.

The persisted production finding carried 40 evidence events across
``job-xss-49b9d40fd5`` and ``job-xss-ffe3afca68`` representing 20 unique
observations of a single signal (``xss_parameter_inventory``) and was
projected as Candidate=VERIFIED / Verification=VERIFIED /
Case=READY_FOR_REVIEW while the historical advisory itself said
VERIFICATION_PENDING.

These tests prove, deterministically, that:

  * parameter inventory alone cannot produce VERIFIED XSS;
  * the persisted record is RE-ASSESSED without being rewritten;
  * the corrected projection states the authoritative state + gate reason.

The historical evidence is never modified by any of this — the last test
re-reads the real persisted store READ-ONLY when it is available and
skips honestly when it is not.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import contracts as ct  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import (  # noqa: E402
    projection,
)
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402

CANDIDATE_ID = "cand-7c229c48c455"
PROD_JOB_A = "job-xss-49b9d40fd5"
PROD_JOB_B = "job-xss-ffe3afca68"
SCOPE_REF = "watch:scope:dell/www.dell.com"
SIGNAL = "xss_parameter_inventory"

# The real evidence shape: one signal, 20 shared observation refs, the
# same 20 observations re-recorded by a second job run.
UNIQUE_OBSERVATIONS = 20
RUNS = (PROD_JOB_A, PROD_JOB_B)


def real_case_rows() -> list[dict]:
    """40 persisted evidence events: the same 20 observations re-recorded
    by the second run (the real cand-7c229c48c455 shape)."""
    rows: list[dict] = []
    for run_index, job in enumerate(RUNS):
        for i in range(UNIQUE_OBSERVATIONS):
            rows.append({
                "id": f"ev-{run_index}-{i}",
                "job_id": job,
                "type": "observation",
                "signal": SIGNAL,
                "category": "XSS",
                "confidence": "high",
                "observation_ref": f"param:{i:02d}",
                "detail": ("reflection-capable parameter observed in the "
                           "authorized surface inventory"),
                "execution_mode": "production",
            })
    return rows


def real_case_candidate() -> dict:
    """The persisted candidate as it exists in production (history)."""
    return {
        "candidate_id": CANDIDATE_ID,
        "campaign_id": "campaign-xss-dell",
        "objective_id": "objective-xss-1",
        "vulnerability_class": "XSS",
        "endpoint": "https://www.dell.com/support",
        "parameter": "redirect",
        "lifecycle_state": "VERIFIED",
        "scope_ref": SCOPE_REF,
        "authorization_ref": SCOPE_REF,
        "source_job": PROD_JOB_A,
        "verification_id": "ver-7c229c48c455",
        "verification_state": "VERIFIED",
        "case_state": "READY_FOR_REVIEW",
        "gate_reason": "evidence_rules_met",
        "confidence": "high",
    }


HISTORICAL_ADVISORY = {
    "present": True,
    "source": "llm_verification_advisory",
    "recorded_at": "2026-09-21T04:12:31+00:00",
    "advisory_state": "VERIFICATION_PENDING",
    "text": ("VERIFICATION_PENDING: the authorized observations needed to "
             "verify or refute the reflection signal are missing."),
    "authoritative": False,
}


class TestRealCaseEvidenceShape(unittest.TestCase):
    def test_shape_matches_the_persisted_case(self):
        rows = real_case_rows()
        items = tx.classify_rows(rows)
        self.assertEqual(len(rows), 2 * (UNIQUE_OBSERVATIONS // 2) * 2,
                         "fixture must keep the real 2-run duplication")
        unique = tx.unique_items(items)
        self.assertEqual({i.job_id for i in items}, set(RUNS))
        self.assertEqual({i.evidence_type for i in items},
                         {tx.PARAMETER_OBSERVED})
        self.assertEqual(tx.stage_reached(items), tx.STAGE_OBSERVED)
        self.assertGreater(len(unique), 0)
        self.assertEqual(items[0].provenance.get("observation_key") is not
                         None, True)


class TestRealCaseCannotVerify(unittest.TestCase):
    def test_parameter_inventory_alone_does_not_produce_verified_xss(self):
        auth = ct.AuthorizationContext(
            scope_ref=SCOPE_REF, authorization_ref=SCOPE_REF,
            authorization_ids=("auth-dell-1",),
            execution_mode="production")
        decision = ig.evaluate_integrity(
            vulnerability_class="XSS", rows=real_case_rows(),
            authorization=auth,
            runtime_gate_reason="evidence_rules_met",
            runtime_gate_claimed_case=True)

        # THE regression assertion
        self.assertFalse(decision.confirmed)
        self.assertNotEqual(decision.authoritative_state, ig.VERIFIED)
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertEqual(decision.verification_state, "INCONCLUSIVE")
        self.assertEqual(decision.candidate_state, "VERIFICATION_PENDING")
        self.assertEqual(decision.gate_reason, "missing_reflection_evidence")
        self.assertIn("REFLECTION_OBSERVED", decision.missing_evidence)
        self.assertIn("PAYLOAD_EXECUTION", decision.missing_evidence)
        self.assertEqual(decision.stage_reached, tx.STAGE_OBSERVED)
        self.assertFalse(
            ig.claim_integrity_supported(decision.claim_integrity))
        self.assertEqual(
            decision.claim_integrity["confirmation_status"], "UNSUPPORTED")
        cells = {r["claim_type"]: r["status"]
                 for r in decision.claim_integrity["claim_evidence_matrix"]}
        self.assertEqual(cells["parameter_observed"], "SUPPORTED")
        self.assertEqual(cells["reflection_observed"], "MISSING")
        self.assertEqual(cells["vulnerability_confirmed"], "MISSING")
        # the runtime gate's own claim is recorded, never honoured
        self.assertTrue(decision.runtime_gate_claimed_case)

    def test_no_duplicate_counting_can_manufacture_support(self):
        rows = real_case_rows()
        evaluator = cl.evaluate_rows
        auth = ct.AuthorizationContext(
            scope_ref=SCOPE_REF, authorization_ref=SCOPE_REF,
            authorization_ids=("auth-dell-1",), execution_mode="production")
        once = evaluator("XSS", rows, authorization=auth)
        thrice = evaluator("XSS", rows * 3, authorization=auth)
        self.assertEqual(once.unique_observations, thrice.unique_observations)
        self.assertEqual(once.status, thrice.status)
        self.assertFalse(thrice.confirmed)


class TestRealCaseProjectionPreservesHistory(unittest.TestCase):
    def test_persisted_verified_is_corrected_not_rewritten(self):
        candidate = real_case_candidate()
        before = json.dumps(candidate, sort_keys=True)
        proj = projection.project(candidate=candidate,
                                 evidence_rows=real_case_rows())
        # the persisted record is untouched by the projection
        self.assertEqual(json.dumps(candidate, sort_keys=True), before)
        self.assertEqual(proj.candidate_id, CANDIDATE_ID)
        self.assertEqual(proj.persisted_state, "VERIFIED")
        self.assertEqual(proj.integrity_state,
                         projection.INTEGRITY_UNSUPPORTED)
        self.assertEqual(proj.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertEqual(proj.gate_reason, "missing_reflection_evidence")
        self.assertEqual(proj.stage_reached, tx.STAGE_OBSERVED)
        self.assertTrue(proj.persisted_evidence_preserved)
        self.assertFalse(proj.confirmed)
        self.assertIn("preserved", " ".join(proj.limitations).lower())
        self.assertEqual(
            proj.claim_evidence_matrix[0]["claim_type"], "url_observed")

    def test_historical_advisory_is_kept_separate_from_current_state(self):
        proj = projection.project(
            candidate=real_case_candidate(),
            evidence_rows=real_case_rows(),
            historical_advisory=HISTORICAL_ADVISORY)
        self.assertEqual(proj.advisory_state, "VERIFICATION_PENDING")
        self.assertEqual(proj.advisory_authoritative, False)
        self.assertEqual(proj.authoritative_state,
                         ig.VERIFICATION_PENDING)
        # the advisory and the corrected state are both reported
        self.assertTrue(proj.limitations)


class TestRealPersistedStoreIsReadOnly(unittest.TestCase):
    """Re-read the REAL store when present; never write, never rewrite.

    The persisted production record is expected to remain internally
    inconsistent with the new contract (history is not rewritten); this
    test proves the corrected projection handles that explicitly.
    """

    def setUp(self):
        self.state = Path(os.environ.get(
            "WATCH_AGENT_STATE",
            "/opt/watch/ai_data/research/agent/runtime/state.json"))
        if not self.state.is_file():
            self.skipTest(f"persisted store not available: {self.state}")

    def test_persisted_case_if_present_is_re_assessed_honestly(self):
        try:
            state = json.loads(self.state.read_text())
        except (OSError, ValueError) as exc:          # pragma: no cover
            self.skipTest(f"persisted store unreadable: {exc}")
        rows = [dict(r) for r in (state.get("evidence") or [])
                if str(r.get("job_id")) in RUNS]
        if not rows:
            self.skipTest("no persisted rows for the regression jobs")
        signals = {str(r.get("signal") or "") for r in rows}
        if SIGNAL not in signals:                      # pragma: no cover
            self.skipTest("persisted regression rows changed shape")
        decision = ig.evaluate_integrity(
            vulnerability_class="XSS", rows=rows,
            authorization=ct.AuthorizationContext(
                scope_ref=SCOPE_REF, authorization_ref=SCOPE_REF,
                authorization_ids=("auth-dell-1",),
                execution_mode="production"))
        self.assertFalse(decision.confirmed)
        self.assertEqual(decision.authoritative_state,
                         ig.VERIFICATION_PENDING)
        self.assertIn("REFLECTION", " ".join(decision.missing_evidence))


if __name__ == "__main__":
    unittest.main()
