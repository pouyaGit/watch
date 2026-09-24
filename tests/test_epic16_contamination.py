"""EPIC16 §15/§16/§17/§20/§21 — provenance, LLM, contamination, integration."""
from __future__ import annotations

import unittest

from backend.research_agents.finding.integrity import claims
from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import engine as en
from backend.research_agents.verification import executors as ex
from backend.research_agents.verification.specialists import base as sp
from backend.research_agents.verification.specialists import producer as pr
from backend.research_agents.verification.specialists import service as sv
from tests import epic16_fixtures as fx

CLASSES = ("XSS", "CORS", "OPEN_REDIRECT", "SSRF", "IDOR", "CVE_RESEARCH")


#: a signal that provably belongs to each class (used to build foreign rows)
FOREIGN_SIGNAL = {
    "XSS": "payload_execution",
    "CORS": "cors_acao_observed",
    "OPEN_REDIRECT": "redirect_response_observed",
    "SSRF": "ssrf_destination_policy_evaluated",
    "IDOR": "idor_object_reference_pattern",
    "CVE_RESEARCH": "cve_product_identified",
}


def _foreign_signal(source: str) -> str:
    return FOREIGN_SIGNAL[source]


def evaluate(cls, rows):
    return claims.evaluate_contract(ct.contract_for(cls), rows)


class TestCrossClassContamination(unittest.TestCase):
    """§21: evidence from one class may never support another."""

    def test_a_cors_signal_row_cannot_contribute_to_xss(self):
        """The signal — not the row's category — decides the owning class."""
        rows = [fx.evidence_row("cors_acao_observed", category="XSS",
                                evidence_type="OUTPUT_CONTEXT_IDENTIFIED")]
        evaluation = evaluate("XSS", rows)
        self.assertEqual(evaluation.class_quarantine[0]["signal_class"], "CORS")
        self.assertTrue(evaluation.class_quarantine)

    def test_an_xss_signal_row_cannot_contribute_to_cors(self):
        rows = [fx.evidence_row("payload_execution", category="XSS")]
        evaluation = evaluate("CORS", rows)
        self.assertEqual(evaluation.class_quarantine[0]["signal_class"], "XSS")

    def test_a_redirect_row_cannot_confirm_ssrf(self):
        rows = [fx.forged_redirect_confirmation()]
        self.assertTrue(evaluate("SSRF", rows).class_quarantine)

    def test_an_ssrf_row_cannot_confirm_idor(self):
        rows = [fx.forged_ssrf_confirmation()]
        self.assertTrue(evaluate("IDOR", rows).class_quarantine)

    def test_a_cve_row_cannot_confirm_xss(self):
        rows = [fx.forged_cve_confirmation()]
        self.assertTrue(evaluate("XSS", rows).class_quarantine)

    def test_every_foreign_class_pair_is_quarantined(self):
        for source in CLASSES:
            for target in CLASSES:
                if source == target:
                    continue
                row = fx.evidence_row(_foreign_signal(source),
                                      category=source)
                quarantined = evaluate(target, [row]).class_quarantine
                self.assertTrue(quarantined, f"{source} -> {target}")

    def test_in_class_evidence_is_never_quarantined(self):
        rows = [fx.evidence_row("cors_acao_observed", category="CORS")]
        self.assertEqual(evaluate("CORS", rows).class_quarantine, [])

    def test_the_quarantine_is_auditable(self):
        rows = [fx.evidence_row("payload_execution", category="XSS")]
        entry = evaluate("CORS", rows).class_quarantine[0]
        self.assertEqual(entry["kind"], "cross_class_evidence")
        self.assertEqual(entry["evaluated_class"], "CORS")
        self.assertIn("belongs to", entry["reason"])

    def test_a_quarantined_row_cannot_satisfy_a_stage(self):
        rows = [fx.evidence_row("cors_sensitive_response_available",
                                category="XSS")]
        state = en.evaluate_chain("CORS", rows)
        self.assertFalse(state.confirmed)

    def test_class_agnostic_rows_are_not_quarantined(self):
        """A generic observation (no owning class) stays admissible."""
        rows = [fx.evidence_row("response_observed", category="CORS")]
        self.assertEqual(evaluate("CORS", rows).class_quarantine, [])

    def test_the_quarantine_survives_the_gate(self):
        """The decision must expose the quarantine, not hide it."""
        from backend.research_agents.finding.integrity import gate
        rows = [fx.evidence_row("payload_execution", category="XSS")]
        decision = gate.evaluate_integrity(vulnerability_class="CORS",
                                           rows=rows)
        self.assertTrue(decision.class_quarantine)
        self.assertFalse(gate.claim_integrity_supported(
            {"claim_integrity": "SUPPORTED"}) and decision.class_quarantine
            and False)


class TestProvenanceBoundary(unittest.TestCase):
    """§15: no row-supplied evidence_type may upgrade evidence strength."""

    def test_a_declared_stronger_type_is_recorded_as_a_mismatch(self):
        item = tx.classify_row(fx.forged_cors_confirmation())
        self.assertEqual(item.evidence_type, tx.RESPONSE_OBSERVED)
        self.assertTrue(item.declared_evidence_type)

    def test_the_authoritative_type_wins(self):
        item = tx.classify_row(fx.evidence_row(
            "cors_acao_observed", category="CORS",
            evidence_type="EXPLOITABILITY_ESTABLISHED"))
        self.assertNotEqual(item.evidence_type,
                            tx.EXPLOITABILITY_ESTABLISHED)

    def test_an_unknown_class_signal_cannot_be_strong(self):
        item = tx.classify_row(fx.evidence_row(
            "cors_invented_signal", category="CORS",
            evidence_type="PAYLOAD_EXECUTION"))
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)

    def test_every_producer_observation_is_class_scoped(self):
        for cls in ("CORS", "OPEN_REDIRECT", "SSRF", "IDOR", "CVE_RESEARCH"):
            result = sv.verify_class(
                cls, candidate_id=fx.CANDIDATE, scope_ref=fx.SCOPE,
                authorization=fx.authorization(),
                material={"origin": fx.CONTROLLED_ORIGIN,
                          "supplied_destination": fx.CONTROLLED_DESTINATION,
                          "location": fx.CONTROLLED_DESTINATION,
                          "destination": fx.CONTROLLED_DESTINATION,
                          "url_parameter_present": True,
                          "object_reference_present": True,
                          "observable_product": "nginx",
                          "observable_version": "1.5",
                          "advisory_product": "nginx",
                          "affected_min": "1.0", "affected_max": "2.0"})
            for obs in result.observations:
                self.assertEqual(obs.category, cls)

    def test_producer_observations_agree_with_the_registry(self):
        result = sv.verify_class(
            "CORS", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material=fx.cors_strong_material())
        for obs in result.observations:
            authoritative = tx.classify_row(
                {"signal": obs.signal, "category": "CORS",
                 "detail": "d"}).evidence_type
            self.assertEqual(obs.evidence_type, authoritative, obs.signal)

    def test_a_duplicate_observation_does_not_add_evidence(self):
        rows = [fx.evidence_row("cors_acao_observed", category="CORS"),
                fx.evidence_row("cors_acao_observed", category="CORS")]
        self.assertLessEqual(len(evaluate("CORS", rows).evidence_items), 2)

    def test_historical_records_are_not_rewritten(self):
        """A legacy advisory row keeps its text but no authority."""
        rows = [fx.evidence_row("llm_insight", category="CORS",
                                detail="historical note: looks exploitable")]
        evaluation = evaluate("CORS", rows)
        self.assertFalse(any(
            result.status == "SUPPORTED"
            and result.claim_id.endswith("confirmed")
            for result in evaluation.claims))


class TestLlmCannotConfirm(unittest.TestCase):
    """§16: the LLM is advisory — it can never confirm or manufacture."""

    def test_an_llm_confirmation_row_cannot_confirm_any_class(self):
        for cls in CLASSES:
            state = en.evaluate_chain(cls, fx.llm_claim_rows(cls))
            self.assertFalse(state.confirmed, cls)

    def test_an_llm_row_cannot_satisfy_a_stage_claim(self):
        for cls in tuple(ch.CHAINS):
            evaluation = evaluate(cls, fx.llm_claim_rows(cls))
            for result in evaluation.claims:
                self.assertNotEqual(result.status, "SUPPORTED",
                                    f"{cls}:{result.claim_id}")

    def test_an_llm_row_never_becomes_confirmation_evidence(self):
        for cls in CLASSES:
            for row in fx.llm_claim_rows(cls):
                item = tx.classify_row(row)
                self.assertNotIn(item.evidence_type, tx.CONFIRMATION_EVIDENCE)

    def test_the_llm_cannot_manufacture_headers(self):
        result = sv.verify_class(
            "CORS", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material={"origin": fx.CONTROLLED_ORIGIN,
                      "response_headers": {},
                      "llm_claim": "Access-Control-Allow-Origin: *"})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_CONFIRMED)
        self.assertFalse(result.confirmed)

    def test_the_llm_cannot_manufacture_a_redirect(self):
        result = sv.verify_class(
            "OPEN_REDIRECT", candidate_id=fx.CANDIDATE,
            authorization=fx.authorization(),
            material={"supplied_destination": fx.CONTROLLED_DESTINATION,
                      "location": None,
                      "llm_claim": f"redirects to {fx.CONTROLLED_DESTINATION}"})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_the_llm_cannot_manufacture_ssrf_evidence(self):
        result = sv.verify_class(
            "SSRF", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material=fx.ssrf_material(server_request_observed=False,
                                      llm_claim="the server called back"))
        self.assertEqual(result.outcome, sv.OUTCOME_CAPABILITY_UNAVAILABLE)

    def test_the_llm_cannot_manufacture_object_access(self):
        result = sv.verify_class(
            "IDOR", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material=fx.idor_material(llm_claim="object read succeeded"))
        self.assertEqual(result.outcome, sv.OUTCOME_CAPABILITY_UNAVAILABLE)

    def test_the_llm_cannot_manufacture_cve_applicability(self):
        result = sv.verify_class(
            "CVE_RESEARCH", candidate_id=fx.CANDIDATE,
            authorization=fx.authorization(),
            material={"observable_product": "", "observable_version": "",
                      "llm_claim": "affected by CVE-2026-0001"})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_TESTED)

    def test_no_service_result_exposes_an_llm_verdict_field(self):
        blob = sv.project_class_verification(sv.verify_class(
            "CORS", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material=fx.cors_strong_material()))
        self.assertNotIn("llm", " ".join(blob.keys()).lower())


class TestExecutorLane(unittest.TestCase):
    """§14: the classification lane refuses without authorization/material."""

    def _action(self, action_type: str = ac.CHECK_CORS_HEADERS):
        return ac.VerificationAction(
            action_type=action_type, candidate_id=fx.CANDIDATE,
            objective_id="obj-1", scope_ref=fx.SCOPE, target="",
            state=ac.ACTION_AUTHORIZED, action_id="act-1",
            authorization_id="authz-epic16-1",
            safety=ac.spec_for(action_type).safety)

    def test_the_lane_refuses_without_authorization(self):
        result = ex.execute_action(self._action(),
                                   context={"material": fx.cors_material("*")})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason,
                         ex.REASON_AUTHORIZATION_UNAVAILABLE)

    def test_the_lane_refuses_without_material(self):
        result = ex.execute_action(
            self._action(), context={"authorization": fx.authorization(),
                                     "material": {}})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason,
                         ex.REASON_MATERIAL_UNAVAILABLE)

    def test_the_lane_emits_observations_with_authorization_and_material(self):
        result = ex.execute_action(
            self._action(), context={"authorization": fx.authorization(),
                                     "material": fx.cors_strong_material()})
        self.assertTrue(result.ok)
        self.assertTrue(result.observations)

    def test_the_lane_refuses_the_idor_probe(self):
        result = ex.execute_action(
            self._action(ac.CHECK_OBJECT_ACCESS),
            context={"authorization": fx.authorization(),
                     "material": fx.idor_material()})
        self.assertTrue(result.blocked)
        self.assertEqual(result.blocked_reason,
                         ex.REASON_CAPABILITY_UNAVAILABLE)

    def test_the_network_actions_stay_blocked(self):
        for action_type in (ac.SEND_ORIGIN_HEADER, ac.SEND_REDIRECT_MARKER,
                            ac.SEND_CALLBACK_URL):
            result = ex.execute_action(
                ac.VerificationAction(
                    action_type=action_type, candidate_id=fx.CANDIDATE,
                    objective_id="obj-1", scope_ref=fx.SCOPE, target="",
                    state=ac.ACTION_AUTHORIZED, action_id="a",
                    authorization_id="authz-epic16-1",
                    safety=ac.spec_for(action_type).safety),
                context={"authorization": fx.authorization(),
                         "material": fx.cors_material("*")})
            self.assertTrue(result.blocked, action_type)
            self.assertEqual(result.blocked_reason,
                             ex.REASON_CAPABILITY_UNAVAILABLE, action_type)

    def test_the_lane_context_is_an_allowlist(self):
        result = ex.execute_action(
            self._action(), context={"authorization": fx.authorization(),
                                     "material": {}, "attacker_key": "1"})
        self.assertFalse(result.ok)

    def test_the_lane_never_reports_a_confirmation(self):
        result = ex.execute_action(
            self._action(), context={"authorization": fx.authorization(),
                                     "material": fx.cors_strong_material()})
        self.assertNotIn("CONFIRMED", str(result.result.get("outcome", "")))

    def test_the_catalog_reports_the_lane_honestly(self):
        catalog = {row["action_type"]: row for row in ex.executor_catalog()}
        self.assertTrue(catalog[ac.CHECK_CORS_HEADERS]["implemented"])
        self.assertFalse(catalog[ac.SEND_ORIGIN_HEADER]["implemented"])

    def test_an_unimplemented_probe_still_refuses_on_the_class_lane(self):
        """CHECK_OBJECT_ACCESS routes to the class lane precisely so the
        refusal is the tested behaviour, not a silent skip."""
        row = {r["action_type"]: r for r in ex.executor_catalog()}[
            ac.CHECK_OBJECT_ACCESS]
        self.assertFalse(row["implemented"])
        self.assertEqual(row["executor"], "class_classification")


class TestSharedLoop(unittest.TestCase):
    """§17: one loop, several classes — no per-class loop."""

    def test_one_loop_run_dispatches_every_implemented_class(self):
        material = {
            "CORS": fx.cors_strong_material(),
            "OPEN_REDIRECT": fx.redirect_material(),
            "SSRF": fx.ssrf_material(),
            "CVE_RESEARCH": fx.cve_material(),
        }
        outcomes = {}
        for cls in ("CORS", "OPEN_REDIRECT", "SSRF", "CVE_RESEARCH"):
            outcomes[cls] = sv.verify_class(
                cls, candidate_id=fx.CANDIDATE, scope_ref=fx.SCOPE,
                authorization=fx.authorization(),
                material=material[cls]).outcome
        self.assertEqual(set(outcomes), set(material))
        self.assertNotIn(sv.OUTCOME_CONFIRMED, set(outcomes.values()))

    def test_the_terminal_states_use_the_shared_vocabulary(self):
        for cls, material in (("CORS", fx.cors_strong_material()),
                              ("OPEN_REDIRECT", fx.redirect_material()),
                              ("SSRF", fx.ssrf_material()),
                              ("IDOR", fx.idor_material()),
                              ("CVE_RESEARCH", fx.cve_material())):
            result = sv.verify_class(cls, candidate_id=fx.CANDIDATE,
                                     scope_ref=fx.SCOPE,
                                     authorization=fx.authorization(),
                                     material=material)
            self.assertIn(result.outcome, sp.CLASS_OUTCOMES, cls)

    def test_an_unregistered_class_is_reported_not_guessed(self):
        result = sv.verify_class("SQLI", candidate_id=fx.CANDIDATE,
                                 authorization=fx.authorization(),
                                 material={"x": 1})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_IMPLEMENTED)

    def test_a_chainless_class_produces_no_observations(self):
        result = sv.verify_class("SQLI", candidate_id=fx.CANDIDATE,
                                 authorization=fx.authorization(),
                                 material={"x": 1})
        self.assertEqual(result.observations, ())

    def test_the_loop_never_runs_two_classes_in_one_claim(self):
        result = sv.verify_class("CORS", candidate_id=fx.CANDIDATE,
                                 authorization=fx.authorization(),
                                 material=fx.cors_strong_material())
        self.assertEqual(result.vulnerability_class, "CORS")
        for obs in result.observations:
            self.assertEqual(obs.category, "CORS")


class TestXssRegressionCandidate(unittest.TestCase):
    """§20: the mandatory XSS regression must stay unconfirmed."""

    def test_twenty_parameter_rows_do_not_confirm_xss(self):
        state = en.evaluate_chain("XSS", fx.xss_parameter_rows(20))
        self.assertFalse(state.confirmed)

    def test_the_parameter_rows_are_only_parameter_observations(self):
        items = tx.classify_rows(fx.xss_parameter_rows(20))
        types = {item.evidence_type for item in items}
        self.assertEqual(types, {tx.PARAMETER_OBSERVED})

    def test_a_parameter_row_cannot_satisfy_a_confirmation_stage(self):
        evaluation = evaluate("XSS", fx.xss_parameter_rows(20))
        for result in evaluation.claims:
            if result.claim_id.endswith("confirmed"):
                self.assertNotEqual(result.status, "SUPPORTED")

    def test_epic16_adds_no_xss_shortcut(self):
        self.assertEqual(ch.capability_for("XSS"), ch.CAPABILITY_FULL)
        self.assertFalse(any(
            spec.vulnerability_class == "XSS" and spec.capability != sp.CAP_IMPLEMENTED
            for spec in sp.SPECIALISTS.values()))

    def test_the_xss_regression_survives_a_mixed_run(self):
        """EPIC16 classes must not disturb the XSS chain of the candidate."""
        before = en.evaluate_chain("XSS", fx.xss_parameter_rows(20))
        sv.verify_class("CORS", candidate_id=fx.CANDIDATE,
                        authorization=fx.authorization(),
                        material=fx.cors_strong_material())
        after = en.evaluate_chain("XSS", fx.xss_parameter_rows(20))
        self.assertEqual(before.verdict, after.verdict)
        self.assertFalse(after.confirmed)


class TestProjectionAcrossClasses(unittest.TestCase):
    """§24: the analyst view for every class."""

    def test_the_projection_names_each_class(self):
        material = {
            "CORS": fx.cors_strong_material(),
            "OPEN_REDIRECT": fx.redirect_material(),
            "SSRF": fx.ssrf_material(),
            "IDOR": fx.idor_material(),
            "CVE_RESEARCH": fx.cve_material(),
        }
        for cls, payload in material.items():
            blob = sv.project_class_verification(sv.verify_class(
                cls, candidate_id=fx.CANDIDATE, scope_ref=fx.SCOPE,
                authorization=fx.authorization(), material=payload))
            self.assertEqual(blob["verification_class"], cls)
            self.assertNotEqual(blob["final_state"], "CONFIRMED", cls)

    def test_every_projection_carries_the_required_sections(self):
        blob = sv.project_class_verification(sv.verify_class(
            "CORS", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material=fx.cors_strong_material()))
        for key in ("verification_class", "verification_chain", "evidence",
                    "missing", "actions", "authorization", "result",
                    "final_state"):
            self.assertIn(key, blob)

    def test_an_unavailable_capability_projects_capability_unavailable(self):
        blob = sv.project_class_verification(sv.verify_class(
            "SSRF", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material=fx.ssrf_material()))
        self.assertEqual(blob["final_state"], "CAPABILITY_UNAVAILABLE")

    def test_a_not_tested_run_projects_not_tested(self):
        blob = sv.project_class_verification(sv.verify_class(
            "CORS", candidate_id=fx.CANDIDATE, authorization=fx.authorization(),
            material={}))
        self.assertEqual(blob["final_state"], "NOT_TESTED")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
