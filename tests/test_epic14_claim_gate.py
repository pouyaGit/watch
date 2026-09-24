"""EPIC14 §10/§11/§12 — claim evaluation, the Evidence Gate and the chain.

The invariant under test: a mismatched or untrusted row contributes NO
confirmation evidence, so it can never turn a claim SUPPORTED, a gate verdict
VERIFIED, or a chain stage SATISFIED.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import claims as cl  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification import projection as pj  # noqa: E402
from tests.epic14_fixtures import (  # noqa: E402
    ATTACKS, SCOPE, advisory_confirmation, authorization, duplicate_forgeries,
    forged_declared_type, forged_exploitability, forged_provenance, inventory,
    legit_chain, legit_context, legit_execution, legit_reflection,
    legacy_confirmation, row, unknown_signal_strong_type)


def evaluate(rows, *, cls: str = "XSS", auth=True):
    return cl.evaluate_rows(cls, rows,
                            authorization=authorization() if auth else None)


def decision(rows, *, cls: str = "XSS", auth=True):
    return ig.decide(evaluate(rows, cls=cls, auth=auth))


def chain(rows, *, cls: str = "XSS"):
    return en.evaluate_chain(cls, rows, authorization=authorization())


class TestMismatchedEvidenceIsExcluded(unittest.TestCase):
    """§10: row 2 contributes no confirmation evidence and is reported."""

    def test_the_forged_row_contributes_no_confirmation_evidence(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        self.assertEqual(evaluation.confirmation_claim.status,
                         cl.CLAIM_UNSUPPORTED)
        self.assertEqual(len(evaluation.excluded_evidence), 1)
        self.assertEqual(evaluation.excluded_evidence[0]["reason"],
                         cl.REASON_MISMATCHED_EVIDENCE)

    def test_the_forged_row_is_recorded_with_both_types(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        entry = evaluation.excluded_evidence[0]
        self.assertEqual(entry["declared_evidence_type"],
                         tx.PAYLOAD_EXECUTION)
        self.assertEqual(entry["authoritative_evidence_type"],
                         tx.PARAMETER_OBSERVED)

    def test_the_forged_row_is_reported_as_a_mismatch(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        self.assertEqual(len(evaluation.evidence_mismatches), 1)

    def test_the_confirmation_claim_stays_unsupported(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        self.assertEqual(evaluation.confirmation_claim.status,
                         cl.CLAIM_UNSUPPORTED)

    def test_the_forged_type_is_not_in_the_evidence_items(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        types = {i["evidence_type"] for i in evaluation.evidence_items}
        self.assertNotIn(tx.PAYLOAD_EXECUTION, types)

    def test_the_authoritative_type_is_in_the_evidence_items(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        types = {i["evidence_type"] for i in evaluation.evidence_items}
        self.assertIn(tx.PARAMETER_OBSERVED, types)

    def test_the_declared_type_is_still_visible_for_audit(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        declared = {i.get("declared_evidence_type")
                    for i in evaluation.evidence_items}
        self.assertIn(tx.PAYLOAD_EXECUTION, declared)

    def test_the_evaluation_states_the_mismatch_in_its_limitations(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        joined = " ".join(evaluation.limitations)
        self.assertIn("declared an evidence type", joined)

    def test_the_evaluation_states_the_invariant(self):
        evaluation = evaluate(inventory())
        joined = " ".join(evaluation.limitations)
        self.assertIn("authoritative provenance", joined)

    def test_the_mismatch_is_not_a_supported_claim(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        self.assertNotEqual(evaluation.status, cl.STATE_VERIFIED_ELIGIBLE)

    def test_the_forged_row_is_not_a_supporting_evidence_id(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        supporting = set(
            evaluation.confirmation_claim.supporting_evidence_ids)
        self.assertNotIn("ev-xss_parameter_inventory-obs-forged-1", supporting)

    def test_the_confirmation_reason_names_the_real_gap(self):
        evaluation = evaluate(inventory() + [forged_declared_type()])
        reason = evaluation.confirmation_claim.unsupported_reason
        self.assertTrue(reason)
        self.assertNotIn("PAYLOAD_EXECUTION", reason.split(":")[0])


class TestUntrustedConfirmationIsExcluded(unittest.TestCase):
    """§17: confirmation-capable evidence needs trusted provenance."""

    def test_an_advisory_execution_row_is_excluded(self):
        evaluation = evaluate(inventory() + [advisory_confirmation()])
        self.assertEqual(len(evaluation.excluded_evidence), 1)

    def test_the_exclusion_names_the_provenance(self):
        evaluation = evaluate(inventory() + [advisory_confirmation()])
        entry = evaluation.excluded_evidence[0]
        self.assertEqual(entry["reason"], cl.REASON_UNTRUSTED_PROVENANCE)
        self.assertIn("ADVISORY", entry["detail"])

    def test_a_legacy_execution_row_is_excluded(self):
        evaluation = evaluate(inventory() + [legacy_confirmation()])
        self.assertEqual(evaluation.excluded_evidence[0]["reason"],
                         cl.REASON_UNTRUSTED_PROVENANCE)

    def test_the_evaluation_states_the_exclusion_in_its_limitations(self):
        evaluation = evaluate(inventory() + [legacy_confirmation()])
        joined = " ".join(evaluation.limitations)
        self.assertIn("excluded from authoritative support", joined)

    def test_a_legitimate_execution_row_is_not_excluded(self):
        evaluation = evaluate(legit_chain())
        self.assertEqual(evaluation.excluded_evidence, [])

    def test_a_legitimate_execution_row_is_eligible(self):
        evaluation = evaluate(legit_chain())
        item = tx.classify_row(legit_execution())
        self.assertTrue(item.is_confirmation_eligible)

    def test_a_mismatched_execution_row_is_excluded_with_its_reason(self):
        rows = inventory() + [row("payload_execution", ref="obs-act-x",
                                  job="job-xss-verify", action_id="act-x",
                                  etype=tx.PARAMETER_OBSERVED)]
        evaluation = evaluate(rows)
        reasons = {e["reason"] for e in evaluation.excluded_evidence}
        self.assertIn(cl.REASON_MISMATCHED_EVIDENCE, reasons)


class TestTheGateRefusesForgedConfirmation(unittest.TestCase):
    """§11: the gate consumes authoritative classification only."""

    def test_the_gate_is_not_verified_for_the_core_attack(self):
        self.assertNotEqual(decision(inventory() + [forged_declared_type()]
                                     ).authoritative_state, ig.VERIFIED)

    def test_the_gate_is_not_verified_for_the_advisory_attack(self):
        self.assertNotEqual(decision(inventory() + [advisory_confirmation()]
                                     ).authoritative_state, ig.VERIFIED)

    def test_the_gate_is_not_verified_for_the_legacy_attack(self):
        self.assertNotEqual(decision(inventory() + [legacy_confirmation()]
                                     ).authoritative_state, ig.VERIFIED)

    def test_the_gate_is_not_verified_for_the_unknown_signal_attack(self):
        self.assertNotEqual(
            decision(inventory() + [unknown_signal_strong_type()]
                     ).authoritative_state, ig.VERIFIED)

    def test_the_gate_is_not_verified_for_forged_provenance(self):
        self.assertNotEqual(decision(inventory() + [forged_provenance()]
                                     ).authoritative_state, ig.VERIFIED)

    def test_the_gate_is_not_verified_for_duplicate_forgeries(self):
        self.assertNotEqual(decision(inventory() + duplicate_forgeries()
                                     ).authoritative_state, ig.VERIFIED)

    def test_the_gate_still_verifies_a_legitimate_chain(self):
        self.assertEqual(decision(legit_chain()).authoritative_state,
                         ig.VERIFIED)

    def test_the_gate_carries_the_mismatches(self):
        result = decision(inventory() + [forged_declared_type()])
        self.assertEqual(len(result.evidence_mismatches), 1)

    def test_the_gate_carries_the_exclusions(self):
        result = decision(inventory() + [advisory_confirmation()])
        self.assertEqual(len(result.excluded_evidence), 1)

    def test_the_gate_limitations_name_the_classification_rule(self):
        result = decision(inventory() + [forged_declared_type()])
        joined = " ".join(result.limitations)
        self.assertIn("classified evidence from its signals", joined)

    def test_the_gate_decision_dict_exposes_the_mismatch(self):
        payload = decision(inventory() + [forged_declared_type()]).to_dict()
        self.assertTrue(payload["evidence_mismatches"])

    def test_the_gate_decision_dict_exposes_the_exclusion(self):
        payload = decision(inventory() + [advisory_confirmation()]).to_dict()
        self.assertTrue(payload["excluded_evidence"])

    def test_the_gate_never_confirms_without_authorization(self):
        self.assertNotEqual(
            decision(legit_chain(), auth=False).authoritative_state,
            ig.VERIFIED)


class TestTheFullAttackMatrix(unittest.TestCase):
    """§19: none of the attacks may produce a confirmed vulnerability."""

    def test_no_attack_confirms_at_the_gate(self):
        for label, forged in ATTACKS.items():
            result = decision(inventory() + forged)
            self.assertNotEqual(result.authoritative_state, ig.VERIFIED,
                                label)

    def test_no_attack_confirms_in_the_chain(self):
        for label, forged in ATTACKS.items():
            state = chain(inventory() + forged)
            self.assertFalse(state.confirmed, label)

    def test_no_attack_produces_an_optimistic_badge(self):
        for label, forged in ATTACKS.items():
            badge = pj.badge_for(chain(inventory() + forged))
            self.assertFalse(badge["optimistic"], label)

    #: attacks that fabricate a *consistent* row shape (signal and type
    #: agree).  They are refused by the required-evidence rule and by the
    #: persistence attestation, not by a mismatch — see the documented
    #: residual boundary test below.
    CONSISTENT_SHAPE = {"forged_provenance_class", "duplicate_forged_rows"}

    def test_every_mislabelled_attack_keeps_the_execution_stage_unsatisfied(self):
        for label, forged in ATTACKS.items():
            if label in self.CONSISTENT_SHAPE:
                continue
            state = chain(inventory() + forged)
            execution = state.stage("execution")
            if execution is not None:
                self.assertNotEqual(execution.status, ch.STAGE_SATISFIED,
                                    label)

    def test_a_consistent_shape_forgery_never_becomes_a_confirmed_finding(self):
        """The stage view may accept a plausible row; the verdict may not."""
        for label in sorted(self.CONSISTENT_SHAPE):
            state = chain(inventory() + ATTACKS[label])
            self.assertFalse(state.confirmed, label)
            self.assertNotEqual(state.verdict, ig.VERIFIED, label)
            self.assertFalse(pj.badge_for(state)["optimistic"], label)

    def test_every_attack_leaves_the_confirmation_claim_unsupported(self):
        for label, forged in ATTACKS.items():
            evaluation = evaluate(inventory() + forged)
            self.assertNotEqual(evaluation.confirmation_claim.status,
                                cl.CLAIM_SUPPORTED, label)

    def test_every_attack_is_either_recorded_or_fails_on_missing_evidence(self):
        """Each attack is safe; most leave an explicit audit record.

        The one exception is documented rather than hidden: a row whose
        metadata *agrees* with its signal (``signal=payload_execution``) is
        structurally indistinguishable from a real observation row, so there
        is nothing to record — it is refused by the required-evidence rule
        instead (the XSS confirmation needs reflection AND context too).
        """
        recorded = {"parameter_signal_plus_execution_stamp",
                    "reflection_signal_plus_exploitability_stamp",
                    "advisory_row_with_confirmation_signal",
                    "unknown_signal_with_strong_type",
                    "legacy_row_without_provenance",
                    "mislabelled_advisory_pair",
                    "context_stamp_on_reflection_signal",
                    "weaker_stamp_on_execution_signal"}
        for label, forged in ATTACKS.items():
            evaluation = evaluate(inventory() + forged)
            has_record = bool(evaluation.evidence_mismatches
                              or evaluation.excluded_evidence)
            if label in recorded:
                self.assertTrue(has_record, label)
            else:
                self.assertNotEqual(evaluation.confirmation_claim.status,
                                    cl.CLAIM_SUPPORTED, label)
                self.assertFalse(evaluation.evidence_mismatches, label)

    def test_a_row_that_agrees_with_its_signal_is_structurally_plausible(self):
        """Documented residual boundary: shape forgery, not metadata forgery.

        EPIC14 closes the *metadata* trust boundary.  A row that fabricates a
        consistent shape is caught by the required-evidence rule and by the
        persistence attestation, not by a mismatch — stated, not hidden.
        """
        item = tx.classify_row(forged_provenance())
        self.assertFalse(item.has_mismatch)
        self.assertEqual(item.provenance_class, tx.PROVENANCE_OBSERVATION)
        self.assertEqual(item.evidence_type, tx.PAYLOAD_EXECUTION)

    def test_a_consistent_forgery_still_cannot_confirm_alone(self):
        evaluation = evaluate(inventory() + [forged_provenance()])
        self.assertNotEqual(evaluation.confirmation_claim.status,
                            cl.CLAIM_SUPPORTED)


class TestChainConsumesTheAuthoritativeResult(unittest.TestCase):
    """§12: EPIC12 consumes EPIC11's mismatch detection."""

    def test_the_chain_reports_the_authoritative_mismatch(self):
        state = chain(inventory() + [forged_declared_type()])
        self.assertTrue(state.evidence_mismatches)

    def test_the_chain_mismatch_names_both_types(self):
        state = chain(inventory() + [forged_declared_type()])
        entry = state.evidence_mismatches[0]
        self.assertEqual(entry["declared_evidence_type"],
                         tx.PAYLOAD_EXECUTION)
        self.assertEqual(entry["authoritative_evidence_type"],
                         tx.PARAMETER_OBSERVED)

    def test_the_chain_reports_the_classifier_version(self):
        state = chain(inventory() + [forged_declared_type()])
        self.assertEqual(state.classifier_version,
                         tx.AUTHORITATIVE_CLASSIFIER_VERSION)

    def test_the_chain_carries_the_exclusions(self):
        state = chain(inventory() + [advisory_confirmation()])
        self.assertTrue(state.excluded_evidence)

    def test_the_chain_state_dict_exposes_the_mismatch(self):
        payload = chain(inventory() + [forged_declared_type()]).to_dict()
        self.assertTrue(payload["evidence_mismatches"])
        self.assertEqual(payload["classifier_version"],
                         tx.AUTHORITATIVE_CLASSIFIER_VERSION)

    def test_the_chain_no_longer_diverges_for_the_advisory_case(self):
        """The gate and the chain now agree: no divergence to report."""
        state = chain(inventory() + [advisory_confirmation()])
        self.assertEqual(state.divergence, ())

    def test_the_chain_reports_the_mismatch_as_a_divergence(self):
        """§12: the chain surfaces the authoritative mismatch it consumed."""
        state = chain(inventory() + [forged_declared_type()])
        self.assertTrue(any("evidence_type_mismatch" in d
                            for d in state.divergence), state.divergence)

    def test_the_divergence_token_names_the_signal_and_the_types(self):
        state = chain(inventory() + [forged_declared_type()])
        token = [d for d in state.divergence
                 if "evidence_type_mismatch" in d][0]
        self.assertIn("xss_parameter_inventory", token)
        self.assertIn(tx.PAYLOAD_EXECUTION, token)
        self.assertIn(tx.PARAMETER_OBSERVED, token)

    def test_the_chain_reaches_the_same_verdict_as_the_gate(self):
        for rows in (inventory(), legit_chain(),
                     inventory() + [forged_declared_type()],
                     inventory() + [advisory_confirmation()]):
            state = chain(rows)
            self.assertEqual(state.verdict,
                             decision(rows).authoritative_state)

    def test_the_legitimate_chain_reaches_the_execution_stage(self):
        state = chain(legit_chain())
        self.assertEqual(state.stage("execution").status, ch.STAGE_SATISFIED)

    def test_the_forged_chain_does_not_reach_the_execution_stage(self):
        state = chain(inventory() + [forged_declared_type()])
        self.assertNotEqual(state.stage("execution").status,
                            ch.STAGE_SATISFIED)

    def test_the_forged_row_does_not_advance_the_furthest_stage(self):
        base = chain(inventory())
        forged = chain(inventory() + [forged_declared_type()])
        self.assertEqual(base.furthest_stage, forged.furthest_stage)


class TestSocProjectionVisibility(unittest.TestCase):
    """§5: the mismatch is visible to the SOC projection."""

    def test_the_projection_carries_a_trust_boundary_block(self):
        state = chain(inventory() + [forged_declared_type()])
        payload = pj.project_chain(state)
        self.assertIn("trust_boundary", payload)

    def test_the_projection_counts_the_mismatch(self):
        state = chain(inventory() + [forged_declared_type()])
        block = pj.project_chain(state)["trust_boundary"]
        self.assertEqual(block["mismatch_count"], 1)

    def test_the_projection_names_the_mismatch_class(self):
        state = chain(inventory() + [forged_declared_type()])
        block = pj.project_chain(state)["trust_boundary"]
        self.assertIn(tx.MISMATCH_STRONGER, block["mismatch_classes"])

    def test_the_projection_is_not_clean_for_a_forged_set(self):
        state = chain(inventory() + [forged_declared_type()])
        self.assertFalse(
            pj.project_chain(state)["trust_boundary"]["clean"])

    def test_the_projection_is_clean_for_a_legitimate_set(self):
        state = chain(legit_chain())
        self.assertTrue(pj.project_chain(state)["trust_boundary"]["clean"])

    def test_the_projection_counts_the_exclusions(self):
        state = chain(inventory() + [advisory_confirmation()])
        block = pj.project_chain(state)["trust_boundary"]
        self.assertEqual(block["excluded_confirmation_count"], 1)

    def test_the_projection_states_the_invariant(self):
        state = chain(inventory())
        block = pj.project_chain(state)["trust_boundary"]
        self.assertIn("authoritative provenance", block["statement"])

    def test_the_projection_marks_authoritative(self):
        state = chain(inventory())
        self.assertTrue(
            pj.project_chain(state)["trust_boundary"]["authoritative"])

    def test_the_projection_reports_the_classifier_version(self):
        state = chain(inventory())
        block = pj.project_chain(state)["trust_boundary"]
        self.assertEqual(block["classifier_version"],
                         tx.AUTHORITATIVE_CLASSIFIER_VERSION)

    def test_a_verified_verdict_with_a_mismatch_is_not_a_clean_badge(self):
        """A verified set that also carries a lying row is not presented green."""
        rows = legit_chain() + [forged_declared_type()]
        state = chain(rows)
        badge = pj.badge_for(state)
        self.assertFalse(badge["optimistic"])
        self.assertIn(badge["state"], (pj.BADGE_INCONSISTENT,
                                       pj.BADGE_PENDING, pj.BADGE_BLOCKED))

    def test_a_legitimate_verified_set_is_a_verified_badge(self):
        badge = pj.badge_for(chain(legit_chain()))
        self.assertEqual(badge["state"], pj.BADGE_VERIFIED)
        self.assertFalse(badge["optimistic"])


class TestCrossClassTrustBoundary(unittest.TestCase):
    """§18: the same invariant holds for every class with a contract."""

    CLASSES = ("XSS", "SSRF", "SQLI", "IDOR", "JWT", "OAUTH")

    def test_a_forged_confirmation_never_confirms_in_any_class(self):
        for cls in self.CLASSES:
            rows = [row("xss_parameter_inventory", ref="r1", category=cls),
                    row("reflection_observed", ref="r2", category=cls,
                        etype=tx.PAYLOAD_EXECUTION)]
            result = decision(rows, cls=cls)
            self.assertNotEqual(result.authoritative_state, ig.VERIFIED, cls)

    def test_a_forged_stamp_is_recorded_in_any_class(self):
        for cls in self.CLASSES:
            rows = [row("response_observed", ref="r1", category=cls,
                        etype=tx.PAYLOAD_EXECUTION)]
            evaluation = evaluate(rows, cls=cls)
            self.assertTrue(evaluation.evidence_mismatches, cls)

    def test_cors_has_a_chain_but_no_own_contract(self):
        """§18 finding: CORS/OPEN_REDIRECT resolve to the GENERIC contract."""
        from backend.research_agents.finding.integrity import contracts as ct
        self.assertIn("CORS", ch.CHAINS)
        self.assertNotIn("CORS", ct.CONTRACTS)
        self.assertEqual(ct.contract_for("CORS").vulnerability_class,
                         "GENERIC")

    def test_open_redirect_has_a_chain_but_no_own_contract(self):
        from backend.research_agents.finding.integrity import contracts as ct
        self.assertIn("OPEN_REDIRECT", ch.CHAINS)
        self.assertNotIn("OPEN_REDIRECT", ct.CONTRACTS)
        self.assertEqual(ct.contract_for("OPEN_REDIRECT").vulnerability_class,
                         "GENERIC")

    def test_a_forged_open_redirect_confirmation_row_cannot_confirm(self):
        rows = [row("response_observed", ref="r1", category="OPEN_REDIRECT",
                    etype=tx.PAYLOAD_EXECUTION)]
        self.assertNotEqual(
            decision(rows, cls="OPEN_REDIRECT").authoritative_state,
            ig.VERIFIED)

    def test_a_forged_cors_confirmation_row_cannot_confirm(self):
        rows = [row("response_observed", ref="r1", category="CORS",
                    etype=tx.PAYLOAD_EXECUTION)]
        self.assertNotEqual(decision(rows, cls="CORS").authoritative_state,
                            ig.VERIFIED)

    def test_cve_research_has_no_confirmation_claim(self):
        from backend.research_agents.finding.integrity import contracts as ct
        contract = ct.contract_for("CVE_RESEARCH")
        self.assertFalse([c for c in contract.claims
                          if c.claim_type == "vulnerability_confirmed"])

    def test_a_knowledge_row_never_confirms_cve_research(self):
        rows = [{"id": "k1", "type": "knowledge",
                 "signal": "knowledge_reference", "source": "cve_research",
                 "detail": "CVE-2024-0001"},
                {"id": "k2", "type": "llm_insight", "signal":
                 "payload_execution", "detail": "exploitable"}]
        self.assertNotEqual(decision(rows, cls="CVE_RESEARCH"
                                     ).authoritative_state, ig.VERIFIED)

    def test_every_contract_class_keeps_the_epic11_vocabulary(self):
        from backend.research_agents.finding.integrity import contracts as ct
        for cls in self.CLASSES:
            contract = ct.contract_for(cls)
            for claim in contract.claims:
                for evidence_type in claim.required_evidence_types:
                    self.assertIn(evidence_type, tx.EVIDENCE_TYPE_SET, cls)


if __name__ == "__main__":
    unittest.main()
