"""EPIC16 §9/§10/§11/§12/§21 — SSRF safety, IDOR capability, CVE research."""
from __future__ import annotations

import unittest

from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import engine as en
from backend.research_agents.verification.specialists import base as sp
from backend.research_agents.verification.specialists import classifiers as cl
from backend.research_agents.verification.specialists import producer as pr
from backend.research_agents.verification.specialists import service as sv
from tests import epic16_fixtures as fx

DEST = fx.CONTROLLED_DESTINATION


def ssrf(destination=DEST, **kw):
    kw.setdefault("material", fx.ssrf_material(destination))
    kw.setdefault("authorization", fx.authorization())
    return sv.verify_class("SSRF", candidate_id=fx.CANDIDATE,
                           scope_ref=fx.SCOPE, **kw)


def idor(**kw):
    kw.setdefault("material", fx.idor_material())
    kw.setdefault("authorization", fx.authorization())
    return sv.verify_class("IDOR", candidate_id=fx.CANDIDATE,
                           scope_ref=fx.SCOPE, **kw)


def cve(**kw):
    kw.setdefault("material", fx.cve_material())
    kw.setdefault("authorization", fx.authorization())
    return sv.verify_class("CVE_RESEARCH", candidate_id=fx.CANDIDATE,
                           scope_ref=fx.SCOPE, **kw)


class TestSsrfDestinationPolicy(unittest.TestCase):
    """§10: every internal/metadata/unsafe destination must be refused."""

    LOOPBACK = ("http://127.0.0.1/", "http://127.1.2.3/",
                "https://127.0.0.1:443/", "http://[::1]/", "http://[::1]:80/")
    RFC1918 = ("http://10.0.0.1/", "http://10.255.255.254/",
               "http://172.16.0.1/", "http://172.31.255.1/",
               "http://192.168.1.1/", "http://192.168.255.254/")
    LINK_LOCAL = ("http://169.254.1.1/", "http://169.254.169.254/",
                  "http://[fe80::1]/")
    METADATA = ("http://169.254.169.254/latest/meta-data/",
                "http://169.254.170.2/v2/credentials",
                "http://100.100.100.200/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.goog/", "http://instance-data/",
                "http://[fd00:ec2::254]/")
    SCHEMES = ("file:///etc/passwd", "gopher://127.0.0.1:70/_",
               "ftp://127.0.0.1/", "dict://127.0.0.1:11211/",
               "ldap://127.0.0.1/", "data:text/plain,hi",
               "javascript:alert(1)", "tftp://127.0.0.1/")

    def test_loopback_is_refused(self):
        for destination in self.LOOPBACK:
            self.assertFalse(cl.evaluate_destination(destination).allowed,
                             destination)

    def test_rfc1918_is_refused(self):
        for destination in self.RFC1918:
            self.assertFalse(cl.evaluate_destination(destination).allowed,
                             destination)

    def test_link_local_is_refused(self):
        for destination in self.LINK_LOCAL:
            self.assertFalse(cl.evaluate_destination(destination).allowed,
                             destination)

    def test_metadata_is_refused(self):
        for destination in self.METADATA:
            policy = cl.evaluate_destination(destination)
            self.assertFalse(policy.allowed, destination)
            self.assertTrue(policy.metadata_target, destination)

    def test_unsafe_schemes_are_refused(self):
        for destination in self.SCHEMES:
            policy = cl.evaluate_destination(destination)
            self.assertFalse(policy.allowed, destination)
            self.assertTrue(policy.unsafe_scheme, destination)

    def test_the_unspecified_address_is_refused(self):
        self.assertFalse(cl.evaluate_destination("http://0.0.0.0/").allowed)

    def test_arbitrary_ports_are_refused(self):
        for destination in ("http://example.test:22/",
                            "http://example.test:6379/",
                            "http://example.test:9200/"):
            self.assertEqual(cl.evaluate_destination(destination).decision,
                             "REJECTED_PORT", destination)

    def test_localhost_names_are_refused(self):
        for host in ("localhost", "localhost.localdomain", "x.localhost",
                     "db.internal", "printer.local"):
            self.assertFalse(cl.evaluate_destination(f"http://{host}/").allowed,
                             host)

    def test_a_dns_rebinding_style_name_is_refused_or_out_of_scope(self):
        for host in ("127.0.0.1.nip.io", "localtest.me", "spoofed.localhost"):
            policy = cl.evaluate_destination(f"http://{host}/",
                                             scope_hosts=("www.dell.com",))
            self.assertFalse(policy.allowed, host)

    def test_a_redirect_to_an_internal_destination_is_refused(self):
        policy = cl.evaluate_destination("http://169.254.169.254/")
        self.assertEqual(policy.decision, "REJECTED_METADATA")

    def test_ipv6_loopback_and_mapped_forms_are_refused(self):
        for destination in ("http://[::1]/", "http://[0:0:0:0:0:0:0:1]/"):
            self.assertFalse(cl.evaluate_destination(destination).allowed,
                             destination)

    def test_a_public_controlled_destination_is_allowed(self):
        self.assertTrue(cl.evaluate_destination(DEST).allowed)


class TestSsrfNoProbing(unittest.TestCase):
    """§9: no SSRF probe is ever performed by this runtime."""

    def test_active_verification_is_capability_unavailable(self):
        self.assertEqual(ssrf().outcome, sv.OUTCOME_CAPABILITY_UNAVAILABLE)

    def test_no_callback_capability_is_recorded(self):
        self.assertIn("no_controlled_callback_capability", ssrf().reason)

    def test_the_specialist_declares_the_blocker(self):
        self.assertTrue(sp.SPECIALISTS["SSRF"].blockers)

    def test_the_network_actions_are_not_implemented(self):
        for action in (ac.SEND_CALLBACK_URL, ac.OBSERVE_SERVER_RESPONSE,
                       ac.ASSESS_SSRF_IMPACT):
            self.assertNotIn(action, ac.IMPLEMENTED_ACTIONS, action)

    def test_a_claimed_server_request_still_cannot_be_confirmed(self):
        result = ssrf(**{"material": fx.ssrf_material(
            DEST, server_request_observed=True,
            destination_interaction=True,
            security_relevant_response=True)})
        self.assertEqual(result.outcome, sv.OUTCOME_CAPABILITY_UNAVAILABLE)
        self.assertFalse(result.confirmed)

    def test_a_faked_server_request_observation_cannot_confirm(self):
        rows = [fx.evidence_row("ssrf_server_side_request_observed",
                                category="SSRF")]
        self.assertFalse(en.evaluate_chain("SSRF", rows).confirmed)

    def test_a_url_parameter_alone_is_not_ssrf(self):
        assessment = cl.classify_ssrf(DEST, url_parameter_present=True)
        self.assertEqual(assessment.exploitable_state,
                         "CAPABILITY_UNAVAILABLE")
        self.assertFalse(assessment.server_request_observed)

    def test_the_assessment_never_contains_an_internal_probe(self):
        for material in (fx.ssrf_material("http://169.254.169.254/"),
                         fx.ssrf_material("http://10.0.0.1/")):
            result = ssrf(**{"material": material})
            for obs in result.observations:
                self.assertNotIn("accessed", obs.signal)

    def test_an_unsafe_destination_still_emits_no_positive_access(self):
        result = ssrf(**{"material": fx.ssrf_material("http://127.0.0.1/")})
        for obs in result.observations:
            self.assertNotEqual(obs.evidence_type, tx.IMPACT_ESTABLISHED)

    def test_an_unauthorized_ssrf_run_is_blocked(self):
        result = sv.verify_class("SSRF", authorization=None,
                                 material=fx.ssrf_material(DEST))
        self.assertEqual(result.outcome, sv.OUTCOME_BLOCKED)


class TestSsrfEvidence(unittest.TestCase):
    def test_the_policy_evaluation_is_an_observation(self):
        rows = [o.to_dict() for o in pr.producer_for("SSRF").build(
            cl.classify_ssrf(DEST, url_parameter_present=True),
            action_id="CHECK_CALLBACK_INTERACTION",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        self.assertIn("ssrf_destination_policy_evaluated",
                      {r["signal"] for r in rows})

    def test_an_internal_destination_emits_a_metadata_negative(self):
        rows = [o.to_dict() for o in pr.producer_for("SSRF").build(
            cl.classify_ssrf("http://169.254.169.254/"),
            action_id="a", candidate_id=fx.CANDIDATE, objective_id="o1")]
        self.assertIn("ssrf_metadata_destination_rejected",
                      {r["signal"] for r in rows})

    def test_an_unsafe_scheme_emits_its_own_negative(self):
        rows = [o.to_dict() for o in pr.producer_for("SSRF").build(
            cl.classify_ssrf("gopher://127.0.0.1/"), action_id="a",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        self.assertIn("ssrf_unsafe_scheme_rejected",
                      {r["signal"] for r in rows})

    def test_an_unresolved_lane_emits_a_not_tested(self):
        rows = pr.producer_for("SSRF").build(
            cl.classify_ssrf(DEST, url_parameter_present=True),
            action_id="a", candidate_id=fx.CANDIDATE, objective_id="o1")
        self.assertTrue(any(row.not_tested for row in rows))

    def test_every_observation_carries_the_class(self):
        for obs in ssrf().observations:
            self.assertEqual(obs.category, "SSRF")


class TestIdorCapability(unittest.TestCase):
    """§11: no fake IDOR without a second authorized identity."""

    def test_one_identity_is_unavailable(self):
        capability = cl.classify_idor(object_reference_present=True,
                                      authorized_identities=1)
        self.assertEqual(capability.capability, "CAPABILITY_UNAVAILABLE")

    def test_zero_identities_is_unavailable(self):
        self.assertEqual(cl.classify_idor().capability,
                         "CAPABILITY_UNAVAILABLE")

    def test_identity_switching_alone_is_not_enough(self):
        capability = cl.classify_idor(authorized_identities=2,
                                      identity_switching=True)
        self.assertFalse(capability.second_context_available)

    def test_ownership_semantics_alone_is_not_enough(self):
        capability = cl.classify_idor(authorized_identities=2,
                                      ownership_semantics=True)
        self.assertFalse(capability.second_context_available)

    def test_the_full_capability_is_recognised(self):
        capability = cl.classify_idor(authorized_identities=2,
                                      identity_switching=True,
                                      ownership_semantics=True)
        self.assertTrue(capability.second_context_available)
        self.assertEqual(capability.capability, "AVAILABLE")

    def test_the_runtime_reports_unavailable(self):
        self.assertEqual(idor().outcome, sv.OUTCOME_CAPABILITY_UNAVAILABLE)

    def test_the_runtime_names_the_missing_capability(self):
        blockers = " ".join(sp.SPECIALISTS["IDOR"].blockers)
        self.assertIn("second authorized identity", blockers)
        self.assertIn("identity-switching", blockers)

    def test_the_reason_names_every_missing_capability(self):
        capability = cl.classify_idor()
        for name in ("second_authorized_identity",
                     "controlled_identity_switching",
                     "object_ownership_semantics"):
            self.assertIn(name, capability.reason)

    def test_the_object_access_action_is_not_implemented(self):
        self.assertNotIn(ac.CHECK_OBJECT_ACCESS, ac.IMPLEMENTED_ACTIONS)

    def test_the_object_access_action_requires_authorization(self):
        self.assertTrue(ac.spec_for(ac.CHECK_OBJECT_ACCESS)
                        .requires_authorization)

    def test_an_object_reference_alone_is_not_idor(self):
        assessment = cl.classify_idor(object_reference_present=True)
        self.assertEqual(assessment.signals, ("idor_object_reference_pattern",))

    def test_a_fake_cross_object_row_cannot_confirm(self):
        rows = [fx.forged_idor_confirmation()]
        self.assertFalse(en.evaluate_chain("IDOR", rows).confirmed)

    def test_the_idor_run_records_no_cross_object_access(self):
        result = idor(**{"material": fx.idor_material(
            authorized_identities=2, identity_switching=True,
            ownership_semantics=True)})
        for obs in result.observations:
            self.assertNotIn("cross_object_access", obs.signal)

    def test_the_idor_chain_declares_the_second_context_stage(self):
        self.assertIn("second_context",
                      {stage.key for stage in ch.IDOR_CHAIN.stages})

    def test_no_idor_run_can_confirm(self):
        self.assertFalse(idor().confirmed)


class TestCveResearch(unittest.TestCase):
    """§12: applicability only — never a confirmed CVE."""

    def test_a_wrong_product_is_detected(self):
        state = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="1.5",
            advisory_product="apache", affected_min="1", affected_max="2").state
        self.assertEqual(state, cl.CVE_WRONG_PRODUCT)

    def test_an_unknown_product_is_detected(self):
        self.assertEqual(cl.classify_cve_applicability().state,
                         cl.CVE_PRODUCT_UNKNOWN)

    def test_an_unknown_version_is_detected(self):
        state = cl.classify_cve_applicability(observable_product="nginx",
                                              advisory_product="nginx").state
        self.assertEqual(state, cl.CVE_VERSION_UNKNOWN)

    def test_an_ambiguous_version_is_detected(self):
        state = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="latest",
            advisory_product="nginx", affected_min="1", affected_max="2").state
        self.assertEqual(state, cl.CVE_VERSION_AMBIGUOUS)

    def test_a_version_below_the_range_is_not_affected(self):
        state = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="0.9",
            advisory_product="nginx", affected_min="1.0",
            affected_max="2.0").state
        self.assertEqual(state, cl.CVE_VERSION_NOT_AFFECTED)

    def test_a_version_above_the_range_is_not_affected(self):
        state = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="3.1",
            advisory_product="nginx", affected_min="1.0",
            affected_max="2.0").state
        self.assertEqual(state, cl.CVE_VERSION_NOT_AFFECTED)

    def test_an_in_range_version_is_applicable(self):
        state = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="1.9",
            advisory_product="nginx", affected_min="1.0",
            affected_max="2.0").state
        self.assertEqual(state, cl.CVE_APPLICABILITY_CONFIRMED)

    def test_applicability_is_never_confirmatory(self):
        assessment = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="1.9",
            advisory_product="nginx", affected_min="1.0", affected_max="2.0")
        self.assertFalse(assessment.confirmatory)

    def test_an_advisory_only_match_is_unresolved(self):
        state = cl.classify_cve_applicability(
            observable_product="nginx", observable_version="1.9",
            advisory_product="nginx").state
        self.assertEqual(state, cl.CVE_APPLICABILITY_UNRESOLVED)

    def test_the_service_never_confirms_a_cve(self):
        result = cve()
        self.assertFalse(result.confirmed)
        self.assertEqual(result.outcome, sv.OUTCOME_INCONCLUSIVE)

    def test_a_not_affected_version_is_a_negative_outcome(self):
        result = cve(**{"material": fx.cve_material(observable_version="9.9")})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_a_wrong_product_is_a_negative_outcome(self):
        result = cve(**{"material": fx.cve_material(advisory_product="apache")})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_CONFIRMED)

    def test_an_unresolved_version_is_not_tested(self):
        result = cve(**{"material": fx.cve_material(
            observable_product="nginx", observable_version="latest",
            affected_min="", affected_max="")})
        self.assertEqual(result.outcome, sv.OUTCOME_NOT_TESTED)

    def test_the_cve_chain_has_no_confirmation_stage(self):
        for stage in ch.CVE_RESEARCH_CHAIN.stages:
            self.assertFalse(stage.required_for_confirmation)

    def test_a_fake_cve_exploit_row_cannot_confirm(self):
        rows = [fx.forged_cve_confirmation()]
        self.assertFalse(en.evaluate_chain("CVE_RESEARCH", rows).confirmed)

    def test_the_cve_contract_declares_no_confirmation_claim(self):
        from backend.research_agents.finding.integrity import contracts as ct
        with self.assertRaises(KeyError):
            ct.contract_for("CVE_RESEARCH").confirmation_claim

    def test_the_cve_producer_never_emits_a_confirmation_type(self):
        rows = [o.to_dict() for o in pr.producer_for("CVE_RESEARCH").build(
            cl.classify_cve_applicability(
                observable_product="nginx", observable_version="1.9",
                advisory_product="nginx", affected_min="1.0",
                affected_max="2.0"), action_id="a",
            candidate_id=fx.CANDIDATE, objective_id="o1")]
        for row in rows:
            self.assertNotIn(row["evidence_type"], tx.CONFIRMATION_EVIDENCE)

    def test_an_llm_cve_confirmation_cannot_confirm(self):
        rows = fx.llm_claim_rows("CVE_RESEARCH")
        self.assertFalse(en.evaluate_chain("CVE_RESEARCH", rows).confirmed)

    def test_every_observation_carries_the_class(self):
        for obs in cve().observations:
            self.assertEqual(obs.category, "CVE_RESEARCH")


class TestCrossClassQuarantineForTheseClasses(unittest.TestCase):
    """§21: evidence from one class may never support another."""

    def _evaluate(self, cls, rows):
        from backend.research_agents.finding.integrity import claims, contracts
        return claims.evaluate_contract(contracts.contract_for(cls), rows)

    def test_an_xss_confirmation_row_is_quarantined_from_ssrf(self):
        rows = [fx.evidence_row("payload_execution", category="XSS",
                                evidence_type="PAYLOAD_EXECUTION"),
                fx.evidence_row("ssrf_url_parameter", category="SSRF")]
        evaluation = self._evaluate("SSRF", rows)
        self.assertTrue(evaluation.class_quarantine)

    def test_an_idor_row_is_quarantined_from_cve_research(self):
        rows = [fx.forged_idor_confirmation(),
                fx.evidence_row("cve_product_identified",
                                category="CVE_RESEARCH")]
        evaluation = self._evaluate("CVE_RESEARCH", rows)
        self.assertTrue(evaluation.class_quarantine)

    def test_a_quarantined_row_does_not_enter_evidence_items(self):
        rows = [fx.forged_idor_confirmation(),
                fx.evidence_row("cve_product_identified",
                                category="CVE_RESEARCH")]
        evaluation = self._evaluate("CVE_RESEARCH", rows)
        signals = {str(item.get("raw_signal") or item.get("signal"))
                   for item in evaluation.evidence_items}
        self.assertNotIn("idor_object_reference_pattern", signals)
        self.assertIn("cve_product_identified", signals)

    def test_a_quarantine_entry_names_both_classes(self):
        rows = [fx.forged_idor_confirmation(),
                fx.evidence_row("cve_product_identified",
                                category="CVE_RESEARCH")]
        entry = self._evaluate("CVE_RESEARCH", rows).class_quarantine[0]
        self.assertEqual(entry["evaluated_class"], "CVE_RESEARCH")
        self.assertEqual(entry["signal_class"], "IDOR")

    def test_in_class_evidence_is_not_quarantined(self):
        rows = [fx.evidence_row("cve_product_identified",
                                category="CVE_RESEARCH")]
        evaluation = self._evaluate("CVE_RESEARCH", rows)
        self.assertEqual(evaluation.class_quarantine, [])

    def test_the_quarantine_does_not_change_the_authoritative_types(self):
        rows = [fx.forged_idor_confirmation()]
        evaluation = self._evaluate("CVE_RESEARCH", rows)
        self.assertEqual(evaluation.evidence_items, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
