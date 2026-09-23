"""Gate extraction + sanctioned objective correction (defect class tests).

Production validation of the first real campaign exposed a mapping defect:
the executor read gate fields from ``research_lineage`` while the runtime
persists the authoritative gate at ``structured["evidence_gate"]``, so two
objectives whose gates DID claim cases were mis-labelled REJECTED.  These
tests pin the extraction order, the mapping semantics, and the narrow
corrective API used to repair mis-labelled objectives honestly.
"""

from __future__ import annotations

import unittest

from backend.research_agents.campaign.executor import (
    _extract_gate,
    _map_objective_outcome,
)
from backend.research_agents.campaign.models import (
    OBJECTIVE_TERMINAL,
    CampaignObjective,
    CampaignStateError,
)
from backend.research_agents.campaign.store import (
    CampaignStore,
    CampaignStoreError,
)

REASON = "authoritative_gate_correction: evidence_gate authoritative " \
         "created_case=true reason=evidence_rules_met"


def _objective(state: str = "REJECTED") -> CampaignObjective:
    return CampaignObjective(
        objective_id="obj-fix-test",
        campaign_id="camp-fix-test",
        category="XSS",
        scope_ref="watch:scope:dell/www.dell.com",
        research_question="q?",
        hypothesis="h?",
        state=state,
    )


def _job(status: str = "COMPLETED", job_id: str = "job-fix-1"):
    class _J:
        pass
    j = _J()
    j.id = job_id
    j.status = status
    j.error = ""
    return j


class TestExtractGate(unittest.TestCase):
    """Extraction prefers the authoritative Evidence Gate record."""

    def test_production_shape_extracts_evidence_gate(self):
        reason, claimed, case_id = _extract_gate({
            "evidence_gate": {"authoritative": True,
                              "reason": "evidence_rules_met",
                              "created_case": True,
                              "confidence": "high"},
            "research_lineage": {"digest": "d"},
        })
        self.assertEqual(reason, "evidence_rules_met")
        self.assertTrue(claimed)
        self.assertEqual(case_id, "")

    def test_authoritative_gate_without_case(self):
        reason, claimed, _ = _extract_gate({
            "evidence_gate": {"authoritative": True,
                              "reason": "confidence_below_threshold",
                              "created_case": False,
                              "confidence": "medium"},
        })
        self.assertEqual(reason, "confidence_below_threshold")
        self.assertFalse(claimed)

    def test_non_authoritative_gate_falls_back_to_lineage(self):
        reason, claimed, case_id = _extract_gate({
            "evidence_gate": {"authoritative": False,
                              "reason": "tampered"},
            "research_lineage": {"gate_reason": "evidence_rules_met",
                                 "case_id": "case-l-1"},
        })
        self.assertEqual(reason, "evidence_rules_met")
        self.assertTrue(claimed)
        self.assertEqual(case_id, "case-l-1")

    def test_legacy_lineage_only_shape(self):
        reason, claimed, case_id = _extract_gate({
            "research_lineage": {"gate_reason": "gate_not_claimed",
                                 "case_id": ""},
        })
        self.assertEqual(reason, "gate_not_claimed")
        self.assertFalse(claimed)
        self.assertEqual(case_id, "")

    def test_empty_structured_is_fail_closed(self):
        reason, claimed, case_id = _extract_gate({})
        self.assertEqual(reason, "")
        self.assertFalse(claimed)
        self.assertEqual(case_id, "")


class TestObjectiveMapping(unittest.TestCase):
    """Gate-authoritative mapping semantics (rule 5)."""

    def test_gate_met_with_case_is_resolved(self):
        state, reason, _ = _map_objective_outcome(
            _job(), None, {"state": "RESOLVED"},
            "evidence_rules_met", "case-1")
        self.assertEqual(state, "RESOLVED")
        self.assertEqual(reason, "evidence_rules_met")

    def test_hunt_blocked_beats_unclaimed_gate(self):
        state, reason, _ = _map_objective_outcome(
            _job(), None,
            {"state": "BLOCKED",
             "termination_reason": "no_authorized_observation_"
                                   "can_reduce_uncertainty"},
            "confidence_below_threshold", "")
        self.assertEqual(state, "BLOCKED")
        self.assertIn("no_authorized", reason)

    def test_completed_without_claim_is_rejected(self):
        state, reason, _ = _map_objective_outcome(
            _job(), None, {"state": "RESOLVED"},
            "gate_not_claimed", "")
        self.assertEqual(state, "REJECTED")
        self.assertEqual(reason, "gate_not_claimed")

    def test_unfinished_job_is_not_terminal(self):
        state, _, _ = _map_objective_outcome(
            _job(status="RUNNING"), None, {}, "", "")
        self.assertEqual(state, "")


class TestModelCorrection(unittest.TestCase):
    """CampaignObjective.correct() — narrow, evidence-bound, terminal."""

    def test_rejected_to_resolved_with_evidence(self):
        o = _objective("REJECTED")
        before_rev = o.revision
        o.correct("RESOLVED", reason=REASON,
                  detail="evidence_gate created_case=true case-1")
        self.assertEqual(o.state, "RESOLVED")
        self.assertEqual(o.revision, before_rev + 1)
        self.assertTrue(o.termination_reason.startswith(
            "authoritative_gate_correction"))
        self.assertTrue(o.is_terminal)

    def test_corrected_state_can_never_execute(self):
        o = _objective("REJECTED")
        o.correct("RESOLVED", reason=REASON, detail="ev")
        self.assertIn(o.state, OBJECTIVE_TERMINAL)
        self.assertNotEqual(o.state, "READY")  # candidates are READY-only

    def test_normal_transition_still_blocks_terminal_edit(self):
        # the correction path is separate; the state machine is unchanged
        o = _objective("REJECTED")
        with self.assertRaises(CampaignStateError):
            o.transition("RESOLVED", reason="anything")

    def test_rejects_wrong_pair(self):
        o = _objective("READY")
        with self.assertRaises(CampaignStateError):
            o.correct("RESOLVED", reason=REASON, detail="ev")
        o2 = _objective("REJECTED")
        with self.assertRaises(CampaignStateError):
            o2.correct("BLOCKED", reason=REASON, detail="ev")

    def test_rejects_reason_without_prefix(self):
        o = _objective("REJECTED")
        with self.assertRaises(CampaignStateError):
            o.correct("RESOLVED", reason="looks authoritative", detail="ev")

    def test_rejects_missing_evidence(self):
        o = _objective("REJECTED")
        with self.assertRaises(CampaignStateError):
            o.correct("RESOLVED", reason=REASON, detail="   ")


class TestStoreCorrection(unittest.TestCase):
    """Store API: guards + auditable transition row."""

    def setUp(self):
        import tempfile
        # ALWAYS isolated: a bare CampaignStore() resolves to the real
        # runtime base dir — never allowed in unit tests.
        self.tmp = tempfile.mkdtemp(prefix="camp-fix-store-")
        self.store = CampaignStore(self.tmp)

    def _seed_rejected(self) -> CampaignObjective:
        from backend.research_agents.campaign.models import Campaign
        camp = Campaign(
            campaign_id="cmp-fix-seed",
            program="dell", scope_ref="watch:scope:dell/www.dell.com",
            campaign_objective="seed",
            target_context={"program": "dell", "subdomain": "www.dell.com",
                            "url": "https://www.dell.com/"},
            provenance={"created_by": "campaign-correction-test"},
        )
        self.store.create_campaign(camp)
        # seed an executed-and-rejected objective directly (correction
        # targets outcomes as recorded after a real run)
        o = CampaignObjective(
            objective_id="obj-seed", campaign_id=camp.campaign_id,
            category="XSS", scope_ref=camp.scope_ref,
            research_question="q?", hypothesis="h?",
            state="REJECTED", priority=80,
            termination_reason="gate_not_claimed",
        )
        self.store.add_objective(o)
        return self.store.get_objective("obj-seed")

    def test_correct_happy_path_is_persisted_and_audited(self):
        self._seed_rejected()
        fixed = self.store.correct_objective_state(
            "obj-seed", new_state="RESOLVED", reason=REASON,
            evidence="evidence_gate authoritative created_case=true "
                     "case-1 evidence_rules_met rows=20")
        self.assertEqual(fixed.state, "RESOLVED")
        reloaded = self.store.get_objective("obj-seed")
        self.assertEqual(reloaded.state, "RESOLVED")
        self.assertTrue(reloaded.is_terminal)
        from backend.research_agents.campaign.store import _FILE_TRANSITIONS
        rows = list(self.store._lines(
            self.store._path(_FILE_TRANSITIONS)))
        kinds = [r.get("kind") for r in rows]
        self.assertIn("objective_correction", kinds)
        corr = [r for r in rows
                if r.get("kind") == "objective_correction"][-1]
        self.assertEqual(corr.get("old"), "REJECTED")
        self.assertEqual(corr.get("new"), "RESOLVED")
        self.assertTrue(corr.get("reason", "").startswith(
            "authoritative_gate_correction"))
        self.assertTrue(corr.get("detail"))
        self.assertTrue(corr.get("actor"))

    def test_store_guards_wrong_pair(self):
        self._seed_rejected()
        with self.assertRaises(CampaignStoreError):
            self.store.correct_objective_state(
                "obj-seed", new_state="BLOCKED", reason=REASON,
                evidence="ev")
        with self.assertRaises(CampaignStoreError):
            # no evidence -> refused
            self.store.correct_objective_state(
                "obj-seed", new_state="RESOLVED", reason=REASON,
                evidence="")

    def test_store_rejects_unknown_objective(self):
        with self.assertRaises(CampaignStoreError):
            self.store.correct_objective_state(
                "obj-nope", new_state="RESOLVED", reason=REASON,
                evidence="ev")


if __name__ == "__main__":
    unittest.main()
