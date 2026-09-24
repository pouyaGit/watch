"""EPIC16 §4/§5/§6/§21 — the CORS verification chain and its attacks."""
from __future__ import annotations

import unittest

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification.specialists import base as sp
from backend.research_agents.verification.specialists import classifiers as cl
from backend.research_agents.verification.specialists import producer as pr
from backend.research_agents.verification.specialists import service as sv
from tests import epic16_fixtures as fx

ORIGIN = fx.CONTROLLED_ORIGIN


def cors(acao=None, *, acac=None, credentials=False, sensitive=False,
         origin=ORIGIN):
    return cl.classify_cors(origin, fx.cors_material(
        acao, acac=acac, origin=origin, credentials_relevant=credentials,
        sensitive_response_declared=sensitive)["response_headers"],
        credentials_relevant=credentials,
        sensitive_response_declared=sensitive)


def run(material, **kw):
    kw.setdefault("authorization", fx.authorization())
    return sv.verify_class("CORS", candidate_id=fx.CANDIDATE,
                           scope_ref=fx.SCOPE, material=material, **kw)


class TestAcaoDistinctions(unittest.TestCase):
    """§4: the seven states must be distinguishable, not merged."""

    def test_absent_acao(self):
        self.assertEqual(cors(None).acao_class, cl.ACAO_ABSENT)

    def test_empty_acao_is_absent(self):
        self.assertEqual(cors("").acao_class, cl.ACAO_ABSENT)

    def test_wildcard_acao(self):
        self.assertEqual(cors("*").acao_class, cl.ACAO_WILDCARD)

    def test_exact_origin_is_not_our_origin(self):
        a = cors("https://app.example.test")
        self.assertEqual(a.acao_class, cl.ACAO_EXACT_ORIGIN)
        self.assertFalse(a.origin_accepted)

    def test_reflected_arbitrary_origin(self):
        a = cors(ORIGIN)
        self.assertEqual(a.acao_class, cl.ACAO_REFLECTED_ARBITRARY)
        self.assertTrue(a.origin_accepted)

    def test_null_origin_requires_the_null_origin(self):
        self.assertEqual(cors("null").acao_class, cl.ACAO_NULL)
        self.assertFalse(cors("null").origin_accepted)
        self.assertTrue(cors("null", origin="null").origin_accepted)

    def test_origin_list_is_its_own_class(self):
        self.assertEqual(cors("https://a.test, https://b.test").acao_class,
                         cl.ACAO_ORIGIN_LIST)

    def test_a_malformed_acao_is_not_accepted(self):
        a = cors("not-an-origin")
        self.assertEqual(a.acao_class, cl.ACAO_MALFORMED)
        self.assertFalse(a.origin_accepted)

    def test_the_header_lookup_is_case_insensitive(self):
        a = cl.classify_cors(ORIGIN, {"access-control-allow-origin": ORIGIN})
        self.assertEqual(a.acao_class, cl.ACAO_REFLECTED_ARBITRARY)

    def test_every_declared_acao_class_is_reachable(self):
        seen = {cors(None).acao_class, cors("*").acao_class,
                cors("https://x.test").acao_class, cors(ORIGIN).acao_class,
                cors("null").acao_class, cors("https://a.test, b").acao_class,
                cors("junk").acao_class}
        self.assertEqual(seen, set(cl.CORS_ORIGIN_CLASSES))


class TestWildcardIsNotExploitable(unittest.TestCase):
    """§4/§6: ACAO: * is never automatically exploitable."""

    def test_wildcard_alone_is_not_confirmed(self):
        a = cors("*", credentials=True, sensitive=True)
        self.assertFalse(a.origin_accepted)
        self.assertEqual(a.exploitable_state, "NOT_CONFIRMED")

    def test_wildcard_cannot_carry_credentials(self):
        a = cors("*", acac="true", credentials=True)
        self.assertFalse(a.credentials_allowed)
        self.assertIn(cl.REASON_WILDCARD_NOT_CREDENTIABLE,
                      a.terminal_reasons)

    def test_wildcard_without_credentials_relevance_is_not_confirmed(self):
        self.assertEqual(cors("*").exploitable_state, "NOT_CONFIRMED")

    def test_wildcard_never_reaches_the_credentials_stage(self):
        a = cors("*", acac="true", credentials=True, sensitive=True)
        self.assertNotIn("credentials_evaluated", a.stages_satisfied)

    def test_wildcard_is_not_pending(self):
        self.assertNotEqual(cors("*", credentials=True).exploitable_state,
                            "PENDING")


class TestReflectedOrigin(unittest.TestCase):
    """§4/§6: reflection is a state, never the verdict."""

    def test_reflection_without_credentials_is_not_confirmed(self):
        a = cors(ORIGIN, credentials=False, sensitive=True)
        self.assertEqual(a.exploitable_state, "NOT_CONFIRMED")

    def test_reflection_with_credentials_without_sensitivity_is_not_confirmed(self):
        a = cors(ORIGIN, acac="true", credentials=True, sensitive=False)
        self.assertEqual(a.exploitable_state, "NOT_CONFIRMED")

    def test_reflection_with_credentials_and_sensitivity_is_pending(self):
        a = cors(ORIGIN, acac="true", credentials=True, sensitive=True)
        self.assertEqual(a.exploitable_state, "PENDING")

    def test_credentials_without_the_acac_header_are_not_allowed(self):
        a = cors(ORIGIN, credentials=True, sensitive=True)
        self.assertFalse(a.credentials_allowed)

    def test_acac_true_without_acceptance_is_not_allowed(self):
        a = cors("https://other.test", acac="true", credentials=True)
        self.assertFalse(a.credentials_allowed)

    def test_the_assessment_never_claims_confirmation(self):
        self.assertFalse(cors(ORIGIN, acac="true", credentials=True,
                              sensitive=True).confirmed_eligible)


class TestControlledOriginPolicy(unittest.TestCase):
    """§5: only our own non-real controlled origin may be claimed."""

    def test_an_arbitrary_origin_is_refused(self):
        a = cl.classify_cors("https://evil.example.com", {})
        self.assertEqual(a.refusal, cl.REASON_INVALID_ORIGIN)

    def test_a_real_looking_origin_is_refused(self):
        a = cl.classify_cors("https://www.dell.com", {"Access-Control-Allow"
                                                      "-Origin": "https://www.dell.com"})
        self.assertEqual(a.refusal, cl.REASON_INVALID_ORIGIN)
        self.assertEqual(a.exploitable_state, "NOT_TESTED")

    def test_an_empty_origin_is_refused(self):
        self.assertEqual(cl.classify_cors("", {}).refusal,
                         cl.REASON_NO_ORIGIN_SUPPLIED)

    def test_a_non_https_controlled_origin_is_refused(self):
        a = cl.classify_cors("http://controlled-hermes-origin"
                            ".hermes-verification.invalid", {})
        self.assertEqual(a.refusal, cl.REASON_INVALID_ORIGIN)

    def test_a_refused_origin_produces_no_observations(self):
        self.assertEqual(cl.classify_cors("https://evil.test", {}).signals, ())

    def test_the_controlled_origin_never_resolves(self):
        self.assertIn(".invalid", ORIGIN)


class TestCorsEvidenceProduction(unittest.TestCase):
    """§15: the producer emits exactly the classified state."""

    def test_absent_acao_emits_a_negative(self):
        rows = [o.to_dict() for o in pr.producer_for("CORS").build(
            cors(None, credentials=True), action_id="CHECK_CORS_HEADERS",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        signals = {r["signal"] for r in rows}
        self.assertIn("cors_acao_absent", signals)

    def test_reflection_emits_an_acceptance_observation(self):
        rows = [o.to_dict() for o in pr.producer_for("CORS").build(
            cors(ORIGIN), action_id="CHECK_CORS_HEADERS",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        by_signal = {r["signal"]: r for r in rows}
        self.assertEqual(
            by_signal["cors_arbitrary_origin_accepted"]["evidence_type"],
            tx.OUTPUT_CONTEXT_IDENTIFIED)

    def test_credentials_allowed_is_the_credentialed_read_stage(self):
        rows = [o.to_dict() for o in pr.producer_for("CORS").build(
            cors(ORIGIN, acac="true", credentials=True), action_id="a",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        by_signal = {r["signal"]: r for r in rows}
        self.assertEqual(by_signal["cors_credentials_allowed"]["evidence_type"],
                         tx.PAYLOAD_EXECUTION)
        self.assertEqual(
            by_signal["cors_credentials_allowed"]["provenance"]
            ["stage_semantics"],
            "cors_credentialed_read_not_code_execution")

    def test_every_observation_carries_the_class(self):
        for material in (fx.cors_material(None), fx.cors_material(ORIGIN),
                         fx.cors_material("*")):
            result = run(material)
            for obs in result.observations:
                self.assertEqual(obs.category, "CORS")

    def test_every_observation_carries_producer_provenance(self):
        result = run(fx.cors_strong_material())
        for obs in result.observations:
            self.assertEqual(obs.provenance["producer"],
                             pr.CLASS_PRODUCER_VERSION)
            self.assertEqual(obs.provenance["classifier"], cl.RULE_VERSION)

    def test_a_refusal_yields_only_a_not_tested_observation(self):
        rows = pr.producer_for("CORS").build(
            cl.classify_cors("https://evil.test", {}),
            action_id="a", candidate_id=fx.CANDIDATE, objective_id="o1")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].not_tested)

    def test_confidence_is_never_assumed(self):
        result = run(fx.cors_material(ORIGIN))
        for obs in result.observations:
            self.assertIn(obs.confidence,
                          ("deterministic", "observed", "unknown"))


class TestCorsServiceOutcomes(unittest.TestCase):
    """§18: the outcome vocabulary must be used honestly."""

    def test_no_authorization_is_blocked(self):
        result = sv.verify_class("CORS", authorization=None,
                                 material=fx.cors_material(ORIGIN))
        self.assertEqual(result.outcome, sv.OUTCOME_BLOCKED)

    def test_an_expired_authorization_is_blocked(self):
        result = sv.verify_class("CORS", authorization=fx.authorization(
            expired=True), material=fx.cors_material(ORIGIN))
        self.assertEqual(result.outcome, sv.OUTCOME_BLOCKED)

    def test_no_material_is_not_tested(self):
        result = run({})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_TESTED)

    def test_a_refused_origin_is_not_tested(self):
        result = run(fx.cors_material(ORIGIN, origin="https://evil.test"))
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_TESTED)

    def test_absent_acao_is_not_confirmed(self):
        result = run(fx.cors_material(None, credentials_relevant=True))
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_wildcard_is_not_confirmed(self):
        result = run(fx.cors_material("*", credentials_relevant=True))
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_the_strongest_state_is_pending_never_confirmed(self):
        result = run(fx.cors_strong_material())
        self.assertEqual(result.outcome, sv.OUTCOME_PENDING)
        self.assertFalse(result.confirmed)

    def test_the_strongest_state_names_the_missing_stage(self):
        result = run(fx.cors_strong_material())
        self.assertIn("EXPLOITABILITY_ESTABLISHED", result.reason)

    def test_the_strongest_state_needs_the_browser_stage(self):
        result = run(fx.cors_strong_material())
        self.assertIn(tx.EXPLOITABILITY_ESTABLISHED,
                      result.chain_state["next_stage_missing_types"])

    def test_the_strongest_state_produces_no_confirmation_evidence(self):
        result = run(fx.cors_strong_material())
        self.assertFalse(result.produces_confirmation_evidence)

    def test_no_cors_run_can_confirm(self):
        for material in (fx.cors_material(None), fx.cors_material("*"),
                         fx.cors_material(ORIGIN), fx.cors_strong_material()):
            self.assertFalse(run(material).confirmed)

    def test_blocked_records_the_capability_blocker(self):
        result = sv.verify_class("CORS", authorization=None, material={})
        self.assertTrue(result.blockers)

    def test_the_result_reports_the_class_capability(self):
        self.assertEqual(run(fx.cors_material(ORIGIN)).capability,
                         sp.CAP_LIMITED)

    def test_the_authorization_reference_is_preserved(self):
        result = run(fx.cors_material(ORIGIN))
        self.assertEqual(result.authorization_id, "authz-epic16-1")


class TestCorsAdversarial(unittest.TestCase):
    """§21 CORS attacks: fake evidence, injection, cross-class."""

    def test_a_declared_exploitability_on_a_header_row_is_a_mismatch(self):
        item = tx.classify_row(fx.evidence_row(
            "cors_acao_observed", category="CORS",
            evidence_type="EXPLOITABILITY_ESTABLISHED"))
        self.assertEqual(item.evidence_type, tx.RESPONSE_OBSERVED)
        self.assertTrue(item.declared_evidence_type)

    def test_a_forged_cors_confirmation_row_cannot_confirm(self):
        rows = [fx.forged_cors_confirmation()]
        state = __import__("backend.research_agents.verification.engine",
                           fromlist=["x"]).evaluate_chain("CORS", rows)
        self.assertFalse(state.confirmed)

    def test_an_llm_asserted_cors_confirmation_cannot_confirm(self):
        engine = __import__("backend.research_agents.verification.engine",
                            fromlist=["x"])
        state = engine.evaluate_chain("CORS", fx.llm_claim_rows("CORS"))
        self.assertFalse(state.confirmed)

    def test_an_xss_row_cannot_satisfy_a_cors_stage(self):
        engine = __import__("backend.research_agents.verification.engine",
                            fromlist=["x"])
        rows = [fx.evidence_row("xss_parameter_inventory", category="XSS"),
                fx.evidence_row("payload_execution", category="XSS")]
        state = engine.evaluate_chain("CORS", rows)
        self.assertFalse(state.confirmed)

    def test_a_header_observation_alone_never_satisfies_confirmation(self):
        rows = [fx.evidence_row("cors_acao_observed", category="CORS")]
        engine = __import__("backend.research_agents.verification.engine",
                            fromlist=["x"])
        self.assertFalse(engine.evaluate_chain("CORS", rows).confirmed)

    def test_a_missing_origin_field_is_not_tested(self):
        result = run({"response_headers": {"Access-Control-Allow-Origin": "*"}})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_TESTED)

    def test_unexpected_header_types_do_not_crash_the_classifier(self):
        a = cl.classify_cors(ORIGIN, {"Access-Control-Allow-Origin": 1234})
        self.assertIn(a.acao_class, cl.CORS_ORIGIN_CLASSES)

    def test_a_none_valued_header_is_treated_as_absent(self):
        self.assertEqual(cl.classify_cors(
            ORIGIN, {"Access-Control-Allow-Origin": None}).acao_class,
            cl.ACAO_ABSENT)

    def test_duplicate_observations_do_not_add_evidence(self):
        first = run(fx.cors_strong_material())
        second = run(fx.cors_strong_material())
        self.assertEqual(first.evidence_types, second.evidence_types)

    def test_the_class_scope_quarantine_applies_to_cors(self):
        from backend.research_agents.finding.integrity import claims
        rows = [fx.evidence_row("payload_execution", category="XSS",
                                evidence_type="PAYLOAD_EXECUTION"),
                fx.evidence_row("cors_acao_observed", category="CORS")]
        evaluation = claims.evaluate_contract(
            __import__("backend.research_agents.finding.integrity.contracts",
                       fromlist=["x"]).contract_for("CORS"), rows)
        self.assertTrue(any("XSS" in str(item) or "signal_class" in str(item)
                            for item in evaluation.class_quarantine))


class TestCorsProjection(unittest.TestCase):
    """§24: the analyst view must not be optimistic."""

    def test_the_projection_names_the_class_and_chain(self):
        blob = sv.project_class_verification(run(fx.cors_strong_material()))
        self.assertEqual(blob["verification_class"], "CORS")
        self.assertEqual(blob["verification_chain"],
                         ch.chain_for("CORS").chain_id)

    def test_the_projection_shows_pending_not_confirmed(self):
        blob = sv.project_class_verification(run(fx.cors_strong_material()))
        self.assertEqual(blob["final_state"], "PENDING")
        self.assertNotEqual(blob["final_state"], "CONFIRMED")

    def test_the_projection_lists_the_blockers(self):
        blob = sv.project_class_verification(run(fx.cors_material(ORIGIN)))
        self.assertTrue(blob["blockers"])

    def test_the_projection_lists_the_missing_confirmation_requirements(self):
        blob = sv.project_class_verification(run(fx.cors_material(ORIGIN)))
        self.assertTrue(blob["missing"])

    def test_a_blocked_run_projects_blocked(self):
        blob = sv.project_class_verification(sv.verify_class(
            "CORS", authorization=None, material=fx.cors_material(ORIGIN)))
        self.assertEqual(blob["final_state"], "BLOCKED")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
