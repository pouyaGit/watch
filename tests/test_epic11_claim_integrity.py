"""EPIC11 — claim / evidence integrity layer unit tests.

Covers the evidence taxonomy, the per-class verification contracts, claim
evaluation, the hardened Evidence Gate mapping and the persisted-record
projection.  No network, no LLM, no production writes: every store is a
tmp-dir store and every evidence row is an in-memory dict.

The central invariant: a claim is SUPPORTED only by persisted,
non-duplicate evidence of the required types — never by row counts,
storage types, confidence labels or model output.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.capabilities import capability_for  # noqa: E402
from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import contracts as ct  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import projection  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.models import ResearchJob  # noqa: E402
from tests.finding_fixtures import (  # noqa: E402
    contract_evidence,
    inventory_evidence,
)

AUTH = ct.AuthorizationContext(
    scope_ref="watch:scope:dell/www.dell.com",
    authorization_ref="watch:scope:dell/www.dell.com",
    authorization_ids=("auth-1",),
    execution_mode="production")


def _row(signal: str, *, ref: str = "obs-1", job: str = "job-1",
         category: str = "XSS", **extra) -> dict:
    return {"id": f"ev-{signal}-{ref}", "job_id": job, "type": "observation",
            "signal": signal, "category": category, "confidence": "high",
            "observation_ref": ref, "detail": f"{signal} on {ref}", **extra}


class TestEvidenceTaxonomy(unittest.TestCase):
    def test_known_signals_map_to_closed_types(self):
        for signal, expected in (
                ("xss_parameter_inventory", tx.PARAMETER_OBSERVED),
                ("reflection_observed", tx.REFLECTION_OBSERVED),
                ("output_context_identified", tx.OUTPUT_CONTEXT_IDENTIFIED),
                ("dom_sink_identified", tx.DOM_SINK_IDENTIFIED),
                ("controlled_input_sent", tx.CONTROLLED_INPUT_SENT),
                ("payload_execution", tx.PAYLOAD_EXECUTION),
                ("exploitability_established",
                 tx.EXPLOITABILITY_ESTABLISHED),
                ("impact_established", tx.IMPACT_ESTABLISHED),
                ("authorization_confirmed", tx.AUTHORIZATION_CONFIRMED),
                ("knowledge_reference", tx.KNOWLEDGE_REFERENCE)):
            item = tx.classify_row(_row(signal))
            self.assertEqual(item.evidence_type, expected, signal)

    def test_unknown_signal_is_unclassified_and_satisfies_nothing(self):
        item = tx.classify_row(_row("totally_unknown_signal"))
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)
        self.assertTrue(item.unclassified_reason)
        self.assertEqual(item.stage, tx.STAGE_AUXILIARY)
        self.assertFalse(item.is_stage_evidence)

    def test_explicit_evidence_type_honored_only_inside_vocabulary(self):
        ok = tx.classify_row(_row("", evidence_type="REFLECTION_OBSERVED"))
        self.assertEqual(ok.evidence_type, tx.REFLECTION_OBSERVED)
        bad = tx.classify_row(_row("", evidence_type="MADE_UP_TYPE"))
        self.assertEqual(bad.evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_negative_and_not_tested_stay_distinct(self):
        neg = tx.classify_row(_row("reflection_not_observed"))
        self.assertEqual(neg.evidence_type, tx.NEGATIVE_EVIDENCE)
        self.assertEqual(neg.negative_kind, tx.NOT_OBSERVED)
        untested = tx.classify_row(_row("not_tested"))
        self.assertEqual(untested.negative_kind, tx.NOT_TESTED)
        self.assertNotEqual(neg.negative_kind, untested.negative_kind)

    def test_duplicate_events_collapse_and_record_their_twin(self):
        rows = [_row("xss_parameter_inventory", ref="urls:1", job="j1"),
                _row("xss_parameter_inventory", ref="urls:1", job="j2"),
                _row("xss_parameter_inventory", ref="urls:2", job="j2")]
        items = tx.classify_rows(rows)
        self.assertEqual(len(items), 3)
        self.assertEqual(len(tx.unique_items(items)), 2)
        dupes = [i for i in items if i.is_duplicate]
        self.assertEqual(len(dupes), 1)
        self.assertTrue(dupes[0].duplicate_of)

    def test_stage_reached_ignores_duplicates_and_auxiliary(self):
        rows = contract_evidence()
        rows.append(dict(rows[0]))          # duplicate of the strongest row
        items = tx.classify_rows(rows)
        self.assertEqual(tx.stage_reached(items), tx.STAGE_EXPLOITABILITY)


class TestVerificationContracts(unittest.TestCase):
    # informational classes that can never reach a confirmed state
    NON_CONFIRMABLE = ("RECON", "CVE_RESEARCH")

    def test_every_class_contract_confirms_only_with_stage4_evidence(self):
        for key in ct.CONTRACTS:
            contract = ct.contract_for(key)
            if key in self.NON_CONFIRMABLE:
                self.assertNotIn("vulnerability_confirmed",
                                 [c.claim_type for c in contract.claims], key)
                continue
            self.assertIn("vulnerability_confirmed",
                          [c.claim_type for c in contract.claims], key)
            confirmation = contract.confirmation_claim
            groups = [set(g) for g in confirmation.required_groups]
            self.assertTrue(
                any(g & tx.CONFIRMATION_EVIDENCE for g in groups), key)
            self.assertTrue(confirmation.requires_authorization, key)

    def test_informational_classes_can_never_be_confirmed(self):
        for key in self.NON_CONFIRMABLE:
            ev = cl.evaluate_rows(
                key, [{"id": "ev-1", "job_id": "j", "type": "observation",
                       "signal": "surface_row", "category": key,
                       "observation_ref": "urls:1"}],
                authorization=AUTH)
            self.assertFalse(ev.confirmed, key)

    def test_unknown_class_falls_back_to_generic_contract(self):
        self.assertIs(ct.contract_for("something_new"), ct.GENERIC)

    def test_lookup_is_case_insensitive(self):
        self.assertIs(ct.contract_for("xss"), ct.XSS)

    def test_inventory_never_satisfies_the_xss_confirmation(self):
        ev = cl.evaluate_rows("XSS", inventory_evidence(), authorization=AUTH)
        self.assertEqual(ev.status, cl.STATE_VERIFICATION_PENDING)
        self.assertFalse(ev.confirmed)
        self.assertEqual(ev.gate_reason, ct.R_MISSING_REFLECTION)

    def test_reason_codes_are_closed_and_explicit(self):
        for reason in ct.GATE_REASONS:
            self.assertTrue(ig.gate_reason_is_explicit(reason), reason)
        self.assertTrue(ig.gate_reason_is_explicit("insufficient_xss_evidence"))
        self.assertFalse(ig.gate_reason_is_explicit("looks_fine_to_me"))

    def test_impact_claims_are_separate_from_confirmation(self):
        spec = ct.contract_for("XSS").claim("impact_established")
        self.assertTrue(spec.impact_claim)
        self.assertEqual(spec.required_groups, ((tx.IMPACT_ESTABLISHED,),))


class TestClaimEvaluation(unittest.TestCase):
    """The §5 ladder: parameter -> controlled -> reflection -> execution."""

    def _eval(self, rows):
        return cl.evaluate_rows("XSS", rows, authorization=AUTH)

    def test_stage1_only_parks_at_missing_reflection(self):
        ev = self._eval(inventory_evidence())
        self.assertEqual(ev.stage_reached, tx.STAGE_OBSERVED)
        self.assertEqual(ev.gate_reason, ct.R_MISSING_REFLECTION)
        self.assertIn("clm-vulnerability_confirmed", ev.unsupported_claims)
        matrix = {r["claim_type"]: r["status"] for r in ev.claim_matrix()}
        self.assertEqual(matrix["parameter_observed"], "SUPPORTED")
        self.assertEqual(matrix["reflection_observed"], "MISSING")
        self.assertEqual(matrix["vulnerability_confirmed"], "MISSING")

    def test_controlled_input_without_reflection_is_still_pending(self):
        rows = inventory_evidence() + [_row("controlled_input_sent",
                                           ref="ctl-1")]
        ev = self._eval(rows)
        self.assertEqual(ev.stage_reached, tx.STAGE_CONTROLLED)
        self.assertEqual(ev.gate_reason, ct.R_MISSING_REFLECTION)
        self.assertFalse(ev.confirmed)

    def test_reflection_without_execution_is_potential_not_verified(self):
        rows = inventory_evidence() + [
            _row("controlled_input_sent", ref="ctl-2"),
            _row("reflection_observed", ref="ref-1"),
        ]
        ev = self._eval(rows)
        self.assertEqual(ev.stage_reached, tx.STAGE_REFLECTION)
        self.assertEqual(ev.gate_reason, ct.R_MISSING_PAYLOAD)
        self.assertFalse(ev.confirmed)

    def test_authorized_execution_evidence_confirms(self):
        rows = inventory_evidence() + [
            _row("controlled_input_sent", ref="ctl-3"),
            _row("reflection_observed", ref="ref-2"),
            _row("output_context_identified", ref="ctx-1"),
            _row("payload_execution", ref="exec-1"),
        ]
        ev = self._eval(rows)
        self.assertTrue(ev.confirmed)
        self.assertEqual(ev.status, cl.STATE_VERIFIED_ELIGIBLE)
        self.assertEqual(ev.gate_reason, "claim_supported")

    def test_contradicting_evidence_rejects_and_stops_confirmation(self):
        rows = inventory_evidence() + [
            _row("controlled_input_sent", ref="ctl-4"),
            _row("reflection_observed", ref="ref-3"),
            _row("output_context_identified", ref="ctx-2"),
            _row("payload_execution", ref="exec-2"),
            _row("reflection_not_observed", ref="neg-1"),
        ]
        ev = self._eval(rows)
        self.assertEqual(ev.status, cl.STATE_REJECTED)
        self.assertFalse(ev.confirmed)
        matrix = {r["claim_type"]: r["status"] for r in ev.claim_matrix()}
        self.assertEqual(matrix["reflection_observed"], "CONTRADICTED")

    def test_duplicate_events_never_inflate_support(self):
        rows = inventory_evidence()
        doubled = rows + [dict(r) for r in rows]
        self.assertEqual(self._eval(rows).unique_observations,
                         self._eval(doubled).unique_observations)
        self.assertGreater(self._eval(doubled).duplicate_events, 0)

    def test_empty_evidence_is_pending_with_no_evidence_reason(self):
        ev = self._eval([])
        self.assertEqual(ev.status, cl.STATE_VERIFICATION_PENDING)
        self.assertEqual(ev.gate_reason, ct.R_NO_EVIDENCE)
        self.assertEqual(ev.unsupported_claims,
                         [c.claim_id for c in ev.claims])

    def test_missing_authorization_blocks(self):
        rows = inventory_evidence() + [
            _row("controlled_input_sent", ref="ctl-5"),
            _row("reflection_observed", ref="ref-4"),
            _row("output_context_identified", ref="ctx-3"),
            _row("payload_execution", ref="exec-3"),
        ]
        item = tx.classify_row(_row("payload_execution", ref="exec-3"))
        self.assertTrue(item.is_confirmation_evidence)
        ev = cl.evaluate_rows("XSS", rows)          # no authorization ctx
        self.assertEqual(ev.status, cl.STATE_BLOCKED)
        self.assertEqual(ev.gate_reason, ct.R_MISSING_AUTHORIZATION)

    def test_evaluation_payload_is_json_serialisable_and_advisory_free(self):
        import json
        payload = self._eval(inventory_evidence()).to_dict()
        self.assertEqual(payload["advisory_only_fields_used"], [])
        self.assertIn("claim_evidence_matrix", payload)
        json.dumps(payload)                     # must not raise


class TestIntegrityGateMapping(unittest.TestCase):
    def test_inventory_only_maps_to_verification_pending(self):
        decision = ig.evaluate_integrity(
            vulnerability_class="XSS", rows=inventory_evidence(),
            authorization=AUTH, runtime_gate_reason="evidence_rules_met",
            runtime_gate_claimed_case=True)
        self.assertEqual(decision.authoritative_state, ig.VERIFICATION_PENDING)
        self.assertEqual(decision.candidate_state, ig.VERIFICATION_PENDING)
        self.assertEqual(decision.verification_state, "INCONCLUSIVE")
        self.assertEqual(decision.gate_reason, ct.R_MISSING_REFLECTION)
        self.assertFalse(decision.confirmed)
        self.assertIn("parameter_observed",
                      str(decision.claim_integrity.get(
                          "claim_evidence_matrix")))
        self.assertTrue(decision.runtime_gate_claimed_case)

    def test_contract_satisfying_evidence_maps_to_verified(self):
        decision = ig.evaluate_integrity(
            vulnerability_class="XSS", rows=contract_evidence(),
            authorization=AUTH)
        self.assertEqual(decision.authoritative_state, ig.VERIFIED)
        self.assertTrue(ig.claim_integrity_supported(decision.claim_integrity))

    def test_claim_integrity_supported_fails_closed(self):
        for payload in (None, {}, {"status": "VERIFIED_ELIGIBLE"},
                        {"authoritative_state": "VERIFICATION_PENDING",
                         "confirmation_status": "SUPPORTED"},
                        {"claim_confirmed": False}):
            self.assertFalse(ig.claim_integrity_supported(payload), payload)

    def test_gate_record_reason_is_preserved_and_reported(self):
        decision = ig.decide(cl.evaluate_rows("XSS", inventory_evidence(),
                                              authorization=AUTH),
                             runtime_gate_reason="evidence_rules_met",
                             runtime_gate_claimed_case=True)
        self.assertIn("runtime evidence gate claimed a case",
                      " ".join(decision.limitations))


class TestPersistedProjection(unittest.TestCase):
    """§16/§22: history preserved, current view corrected."""

    def test_persisted_verified_with_inventory_only_is_corrected(self):
        proj = projection.project(
            candidate={"candidate_id": "cand-7c229c48c455",
                       "vulnerability_class": "XSS",
                       "lifecycle_state": "VERIFIED",
                       "scope_ref": "watch:scope:dell/www.dell.com"},
            evidence_rows=inventory_evidence(),
            persisted_state="VERIFIED")
        self.assertEqual(proj.integrity_state, projection.INTEGRITY_UNSUPPORTED)
        self.assertEqual(proj.authoritative_state, ig.VERIFICATION_PENDING)
        self.assertEqual(proj.gate_reason, ct.R_MISSING_REFLECTION)
        self.assertEqual(proj.stage_reached, tx.STAGE_OBSERVED)
        self.assertTrue(proj.claim_evidence_matrix)
        self.assertIn("preserved as history", " ".join(proj.limitations))

    def test_persisted_verified_with_contract_evidence_is_consistent(self):
        proj = projection.project(
            candidate={"candidate_id": "cand-ok",
                       "vulnerability_class": "XSS",
                       "lifecycle_state": "READY_FOR_REVIEW",
                       "scope_ref": "watch:scope:dell/www.dell.com"},
            evidence_rows=contract_evidence(),
            persisted_state="READY_FOR_REVIEW")
        self.assertEqual(proj.integrity_state, projection.INTEGRITY_OK)

    def test_non_verified_persisted_state_is_never_flagged(self):
        proj = projection.project(
            candidate={"candidate_id": "cand-pending",
                       "vulnerability_class": "XSS",
                       "lifecycle_state": "VERIFICATION_PENDING",
                       "scope_ref": "watch:scope:dell/www.dell.com"},
            evidence_rows=inventory_evidence())
        self.assertEqual(proj.integrity_state, projection.INTEGRITY_OK)


class TestRuntimeEvidenceGateHardening(unittest.TestCase):
    """§6: the runtime gate itself must refuse the inventory-only claim."""

    def _job(self) -> ResearchJob:
        return ResearchJob(
            id="job-xss-49b9d40fd5", candidate_id="cand-7c229c48c455",
            category="XSS",
            endpoint="https://www.dell.com/support", parameter="q",
            priority_score=10, agent_category="XSS", program="dell",
            subdomain="www.dell.com", url="https://www.dell.com/support",
            mission="parameter-inventory",
            authorization_ref="watch:scope:dell/www.dell.com",
            execution_mode="production", assigned_agent="xss-agent")

    def _analysis(self) -> dict:
        return {"confidence": "high",
                "hypotheses": [{"hypothesis": "reflection-capable input"}],
                "evidence_candidates": [], "insufficient_evidence": False}

    def test_parameter_inventory_alone_cannot_claim_a_case(self):
        from backend.research_agents.runtime import evaluate_case_creation
        job = self._job()
        rows = [dict(r, job_id=job.id) for r in inventory_evidence()]
        decision = evaluate_case_creation(capability_for("XSS"), job,
                                          self._analysis(), rows)
        self.assertFalse(decision.create)
        self.assertEqual(decision.reason, ct.R_MISSING_REFLECTION)
        self.assertIsNone(decision.case)

    def test_xss_capability_declares_claim_grade_evidence(self):
        req = capability_for("XSS").evidence_requirements
        self.assertEqual(set(req.signal_evidence_any_of),
                         {tx.REFLECTION_OBSERVED,
                          tx.OUTPUT_CONTEXT_IDENTIFIED,
                          tx.DOM_SINK_IDENTIFIED})

    def test_reflection_evidence_still_reaches_the_case_threshold(self):
        from backend.research_agents.runtime import evaluate_case_creation
        job = self._job()
        rows = [dict(r, job_id=job.id)
                for r in inventory_evidence() + [
                    _row("controlled_input_sent", ref="c1"),
                    _row("reflection_observed", ref="r1")]]
        decision = evaluate_case_creation(capability_for("XSS"), job,
                                          self._analysis(), rows)
        self.assertTrue(decision.create)
        self.assertEqual(decision.reason, "evidence_rules_met")


if __name__ == "__main__":
    unittest.main()
