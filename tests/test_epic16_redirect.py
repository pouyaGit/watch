"""EPIC16 §7/§8/§21 — the open-redirect verification chain and its attacks."""
from __future__ import annotations

import unittest

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification.specialists import classifiers as cl
from backend.research_agents.verification.specialists import producer as pr
from backend.research_agents.verification.specialists import service as sv
from backend.research_agents.verification import engine as en
from tests import epic16_fixtures as fx

DEST = fx.CONTROLLED_DESTINATION


def classify(location=None, *, supplied=DEST, request_url=""):
    return cl.classify_redirect(supplied, location, request_url=request_url)


def run(location=None, **kw):
    kw.setdefault("material", fx.redirect_material(location))
    kw.setdefault("authorization", fx.authorization())
    return sv.verify_class("OPEN_REDIRECT", candidate_id=fx.CANDIDATE,
                           scope_ref=fx.SCOPE, **kw)


class TestRedirectDistinctions(unittest.TestCase):
    """§8: parameter-ignored / normalized / restricted / relative / same-origin
    / external are distinct states."""

    def test_no_location_header(self):
        self.assertEqual(classify(None).classification, cl.REDIRECT_NO_LOCATION)

    def test_an_empty_location_is_no_location(self):
        self.assertEqual(classify("").classification, cl.REDIRECT_NO_LOCATION)

    def test_a_relative_target_is_relative_only(self):
        self.assertEqual(classify("/login").classification,
                         cl.REDIRECT_RELATIVE_ONLY)

    def test_a_dot_relative_target_is_normalized(self):
        self.assertEqual(classify("login").classification,
                         cl.REDIRECT_DESTINATION_NORMALIZED)

    def test_an_ignored_parameter_is_detected(self):
        a = classify("https://www.dell.com/go",
                     request_url="https://www.dell.com/go")
        self.assertEqual(a.classification, cl.REDIRECT_PARAMETER_IGNORED)

    def test_a_same_host_other_path_is_normalized(self):
        a = classify("https://www.dell.com/x",
                     request_url="https://www.dell.com/go?next=x")
        self.assertEqual(a.classification, cl.REDIRECT_DESTINATION_NORMALIZED)

    def test_a_protocol_relative_same_host_target_is_same_origin(self):
        a = classify("//www.dell.com/other",
                     request_url="https://www.dell.com/go")
        self.assertEqual(a.classification, cl.REDIRECT_SAME_ORIGIN)

    def test_a_controlled_destination_is_external_accepted(self):
        a = classify(DEST)
        self.assertEqual(a.classification, cl.REDIRECT_EXTERNAL_ACCEPTED)
        self.assertTrue(a.destination_controlled)

    def test_an_uncontrolled_external_target_is_out_of_scope(self):
        a = classify("https://evil.example.com/x")
        self.assertEqual(a.classification, cl.REDIRECT_EXTERNAL_OUT_OF_SCOPE)

    def test_an_unsafe_scheme_is_its_own_state(self):
        self.assertEqual(classify("file:///etc/passwd").classification,
                         cl.REDIRECT_UNSAFE_SCHEME)

    def test_every_declared_state_is_reachable(self):
        seen = {classify(None).classification, classify("/a").classification,
                classify("a").classification,
                classify("https://www.dell.com/go",
                         request_url="https://www.dell.com/go").classification,
                classify("https://www.dell.com/x",
                         request_url="https://www.dell.com/g").classification,
                classify("//www.dell.com/other",
                         request_url="https://www.dell.com/g").classification,
                classify(DEST).classification,
                classify("https://evil.test/x").classification,
                classify("gopher://x/").classification}
        self.assertEqual(seen, set(cl.REDIRECT_CLASSES))

    def test_a_302_alone_is_never_the_finding(self):
        a = classify("/login")
        self.assertEqual(a.exploitable_state, "NOT_CONFIRMED")

    def test_the_assessment_has_no_confirmed_property(self):
        self.assertFalse(hasattr(classify(DEST), "confirmed"))


class TestUnsafeSuppliedDestinations(unittest.TestCase):
    """§7/§10: the SUPPLIED destination is policy-checked before any use."""

    CASES = ("http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/",
             "http://[::1]/", "http://10.1.2.3/", "http://192.168.0.9/",
             "http://172.20.5.5/", "http://169.254.169.254/latest/meta-data/",
             "http://metadata.google.internal/", "file:///etc/passwd",
             "gopher://x:70/_", "ftp://files.internal/",
             "http://internal.corp.local/", "http://evil.invalid:8443/")

    def test_every_unsafe_destination_is_refused(self):
        for destination in self.CASES:
            policy = cl.evaluate_destination(destination)
            self.assertFalse(policy.allowed, destination)

    def test_a_refused_destination_makes_the_run_not_tested(self):
        for destination in self.CASES:
            a = cl.classify_redirect(destination, "https://x.invalid/")
            self.assertTrue(a.refusal, destination)

    def test_a_refused_destination_produces_a_not_tested_observation(self):
        rows = pr.producer_for("OPEN_REDIRECT").build(
            cl.classify_redirect("http://127.0.0.1/", "http://127.0.0.1/x"),
            action_id="CHECK_REDIRECT_LOCATION", candidate_id=fx.CANDIDATE,
            objective_id="o1")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].not_tested)
        self.assertFalse(rows[0].negative)

    def test_an_empty_destination_is_refused(self):
        self.assertFalse(cl.evaluate_destination("").allowed)

    def test_a_destination_without_scheme_is_refused(self):
        self.assertFalse(cl.evaluate_destination("www.dell.com/x").allowed)

    def test_an_unparseable_destination_is_refused(self):
        self.assertFalse(cl.evaluate_destination("http://[bad").allowed)

    def test_the_controlled_destination_is_allowed(self):
        self.assertTrue(cl.evaluate_destination(DEST).allowed)

    def test_an_out_of_scope_destination_is_refused_when_a_scope_is_given(self):
        policy = cl.evaluate_destination(DEST, scope_hosts=("www.dell.com",))
        self.assertFalse(policy.allowed)
        self.assertEqual(policy.decision, "REJECTED_OUT_OF_SCOPE")


class TestRedirectEvidence(unittest.TestCase):
    """§15: the producer reflects exactly the classified state."""

    def test_an_accepted_controlled_destination_emits_the_strongest_signal(self):
        rows = {o.signal: o.to_dict() for o in pr.producer_for("OPEN_REDIRECT")
                .build(classify(DEST), action_id="a", candidate_id=fx.CANDIDATE,
                       objective_id="o1")}
        self.assertIn("redirect_external_destination_accepted", rows)
        self.assertEqual(
            rows["redirect_external_destination_accepted"]["evidence_type"],
            tx.PAYLOAD_EXECUTION)

    def test_a_relative_target_emits_a_negative(self):
        rows = [o.to_dict() for o in pr.producer_for("OPEN_REDIRECT").build(
            classify("/login"), action_id="a", candidate_id=fx.CANDIDATE,
            objective_id="o1")]
        self.assertIn("redirect_relative_only", {r["signal"] for r in rows})

    def test_an_ignored_parameter_emits_a_negative(self):
        rows = [o.to_dict() for o in pr.producer_for("OPEN_REDIRECT").build(
            classify("https://www.dell.com/go",
                     request_url="https://www.dell.com/go"), action_id="a",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        self.assertIn("redirect_parameter_ignored",
                      {r["signal"] for r in rows})

    def test_an_out_of_scope_target_emits_a_negative(self):
        rows = [o.to_dict() for o in pr.producer_for("OPEN_REDIRECT").build(
            classify("https://evil.test/x"), action_id="a",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        self.assertIn("redirect_external_destination_rejected",
                      {r["signal"] for r in rows})

    def test_the_terminal_destination_is_never_followed(self):
        for state in (fx.redirect_material(DEST), fx.redirect_material("/x"),
                      fx.redirect_material("https://evil.test/x")):
            result = run(**{"material": state})
            for obs in result.observations:
                self.assertNotIn("terminal_offsite", obs.signal)

    def test_every_observation_carries_the_class(self):
        result = run(DEST)
        for obs in result.observations:
            self.assertEqual(obs.category, "OPEN_REDIRECT")


class TestRedirectOutcomes(unittest.TestCase):
    """§18: NOT_TESTED / NOT_CONFIRMED / BLOCKED / PENDING are distinct."""

    def test_no_authorization_is_blocked(self):
        result = sv.verify_class("OPEN_REDIRECT", authorization=None,
                                 material=fx.redirect_material(DEST))
        self.assertEqual(result.outcome, sv.OUTCOME_BLOCKED)

    def test_no_material_is_not_tested(self):
        self.assertEqual(run(material={}).outcome, sv.OUTCOME_NOT_TESTED)

    def test_an_unsafe_supplied_destination_is_not_tested(self):
        result = run(material=fx.redirect_material("https://x.invalid/",
                                                   supplied="http://127.0.0.1/"))
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_TESTED)

    def test_a_relative_target_is_not_confirmed(self):
        self.assertEqual(run("/login").outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_a_normalized_target_is_not_confirmed(self):
        self.assertEqual(run("https://www.dell.com/x",
                             material=fx.redirect_material(
                                 "https://www.dell.com/x",
                                 request_url="https://www.dell.com/g")
                             ).outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_an_out_of_scope_target_is_not_confirmed(self):
        self.assertEqual(run("https://evil.test/x").outcome,
                         sv.OUTCOME_NOT_CONFIRMED)

    def test_a_missing_location_is_not_confirmed(self):
        self.assertEqual(run(None).outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_a_controlled_target_is_pending_never_confirmed(self):
        result = run(DEST)
        self.assertEqual(result.outcome, sv.OUTCOME_PENDING)
        self.assertFalse(result.confirmed)

    def test_no_redirect_run_can_confirm(self):
        for location in (None, "/x", DEST, "https://evil.test/x"):
            self.assertFalse(run(location).confirmed)

    def test_a_controlled_target_produces_no_confirmation_evidence(self):
        self.assertFalse(run(DEST).produces_confirmation_evidence)


class TestRedirectAdversarial(unittest.TestCase):
    """§21: fake Location evidence, out-of-scope escapes, cross-class rows."""

    def test_a_declared_exploitability_location_row_is_a_mismatch(self):
        item = tx.classify_row(fx.forged_redirect_confirmation())
        self.assertEqual(item.evidence_type, tx.RESPONSE_OBSERVED)
        self.assertTrue(item.declared_evidence_type)

    def test_a_forged_redirect_confirmation_cannot_confirm(self):
        state = en.evaluate_chain("OPEN_REDIRECT",
                                  [fx.forged_redirect_confirmation()])
        self.assertFalse(state.confirmed)

    def test_an_llm_redirect_confirmation_cannot_confirm(self):
        state = en.evaluate_chain("OPEN_REDIRECT",
                                  fx.llm_claim_rows("OPEN_REDIRECT"))
        self.assertFalse(state.confirmed)

    def test_an_xss_row_cannot_satisfy_a_redirect_stage(self):
        rows = [fx.evidence_row("payload_execution", category="XSS",
                                evidence_type="PAYLOAD_EXECUTION")]
        self.assertFalse(en.evaluate_chain("OPEN_REDIRECT", rows).confirmed)

    def test_a_double_slash_controlled_target_is_detected(self):
        a = classify("//" + DEST.split("//", 1)[1])
        self.assertEqual(a.classification, cl.REDIRECT_EXTERNAL_ACCEPTED)

    def test_a_target_containing_the_token_in_a_query_is_still_detected(self):
        a = classify("https://evil.test/?u=" + DEST)
        self.assertTrue(a.destination_controlled)

    def test_an_unsafe_redirect_scheme_is_never_probed(self):
        policy = cl.evaluate_destination("gopher://127.0.0.1:70/_")
        self.assertEqual(policy.decision, "REJECTED_SCHEME")

    def test_a_non_standard_port_is_rejected(self):
        policy = cl.evaluate_destination("http://example.test:8080/")
        self.assertEqual(policy.decision, "REJECTED_PORT")

    def test_a_port_80_or_443_target_is_allowed(self):
        for destination in ("http://example.test:80/",
                            "https://example.test:443/"):
            self.assertIn(cl.evaluate_destination(destination).decision,
                          ("ALLOWED_CONTROLLED_DESTINATION",
                           "REJECTED_OUT_OF_SCOPE"), destination)

    def test_the_scope_option_rejects_an_unlisted_host(self):
        policy = cl.evaluate_destination("https://evil.test/",
                                         scope_hosts=("www.dell.com",))
        self.assertFalse(policy.allowed)

    def test_lowercase_and_uppercase_hosts_are_treated_the_same(self):
        a = cl.evaluate_destination("HTTP://LOCALHOST/")
        self.assertFalse(a.allowed)

    def test_a_trailing_dot_internal_name_is_still_internal(self):
        self.assertFalse(cl.evaluate_destination("http://localhost./").allowed)


class TestRedirectProjection(unittest.TestCase):
    def test_the_projection_is_never_confirmed(self):
        blob = sv.project_class_verification(run(DEST))
        self.assertEqual(blob["final_state"], "PENDING")

    def test_the_projection_names_the_class(self):
        blob = sv.project_class_verification(run(DEST))
        self.assertEqual(blob["verification_class"], "OPEN_REDIRECT")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
