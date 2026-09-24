"""EPIC16 §2/§13/§25 — capability matrix and shared-framework honesty."""
from __future__ import annotations

import unittest

from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import chains as ch
from backend.research_agents.verification import executors as ex
from backend.research_agents.verification.specialists import base as sp
from backend.research_agents.verification.specialists import classifiers as cl
from backend.research_agents.verification.specialists import producer as pr
from backend.research_agents.verification.specialists import service as sv
from tests import epic16_fixtures as fx

CLASSES = ("XSS", "CORS", "OPEN_REDIRECT", "SSRF", "IDOR", "CVE_RESEARCH")


class TestCapabilityMatrix(unittest.TestCase):
    """§2: the audit's conclusion must be encoded, testable and honest."""

    def setUp(self):
        self.matrix = {row["vulnerability_class"]: row
                       for row in sp.capability_matrix()}

    def test_xss_is_implemented(self):
        self.assertEqual(self.matrix["XSS"]["specialist_capability"],
                         sp.CAP_IMPLEMENTED)

    def test_cors_is_limited_not_implemented(self):
        self.assertEqual(self.matrix["CORS"]["specialist_capability"],
                         sp.CAP_LIMITED)

    def test_open_redirect_is_limited(self):
        self.assertEqual(self.matrix["OPEN_REDIRECT"]["specialist_capability"],
                         sp.CAP_LIMITED)

    def test_ssrf_is_limited(self):
        self.assertEqual(self.matrix["SSRF"]["specialist_capability"],
                         sp.CAP_LIMITED)

    def test_idor_is_not_implemented(self):
        self.assertEqual(self.matrix["IDOR"]["specialist_capability"],
                         sp.CAP_NOT_IMPLEMENTED)

    def test_cve_research_is_research_only(self):
        self.assertEqual(self.matrix["CVE_RESEARCH"]["specialist_capability"],
                         sp.CAP_LIMITED)
        self.assertEqual(
            self.matrix["CVE_RESEARCH"]["confirmation_requirements"], [])

    def test_only_xss_declares_active_verification(self):
        for name in CLASSES:
            expected = name == "XSS"
            self.assertEqual(self.matrix[name]["active_verification"],
                             expected, name)

    def test_every_class_reports_a_blocker_or_none_deliberately(self):
        self.assertTrue(self.matrix["CORS"]["blockers"])
        self.assertTrue(self.matrix["OPEN_REDIRECT"]["blockers"])
        self.assertTrue(self.matrix["SSRF"]["blockers"])
        self.assertTrue(self.matrix["IDOR"]["blockers"])
        self.assertEqual(self.matrix["CVE_RESEARCH"]["blockers"], [])

    def test_every_class_reports_at_least_one_limitation(self):
        for name in CLASSES:
            self.assertTrue(self.matrix[name]["limitations"], name)

    def test_the_matrix_covers_unimplemented_classes_too(self):
        self.assertIn("SQLI", self.matrix)
        self.assertEqual(self.matrix["SQLI"]["specialist_capability"],
                         sp.CAP_NOT_IMPLEMENTED)
        self.assertEqual(self.matrix["SQLI"]["blockers"],
                         ["no specialist declared"])

    def test_the_capability_vocabulary_is_epic13s(self):
        self.assertEqual(sp.CAP_IMPLEMENTED, "IMPLEMENTED")
        self.assertEqual(sp.CAP_LIMITED, "LIMITED")
        self.assertEqual(sp.CAP_NOT_IMPLEMENTED, "NOT_IMPLEMENTED")

    def test_the_matrix_is_stable_ordered(self):
        names = [row["vulnerability_class"] for row in sp.capability_matrix()]
        self.assertEqual(names, sorted(names))

    def test_the_matrix_reports_the_chain_capability_too(self):
        rows = {r["vulnerability_class"]: r for r in sp.capability_matrix()}
        self.assertEqual(rows["XSS"]["chain_capability"], ch.CAPABILITY_FULL)
        self.assertEqual(rows["IDOR"]["chain_capability"],
                         ch.CAPABILITY_CONTRACT_ONLY)


class TestSharedFramework(unittest.TestCase):
    """§13: one generic interface, class-specific logic only."""

    def test_the_six_classes_are_registered(self):
        for name in CLASSES:
            self.assertIsNotNone(sp.specialist_for(name), name)

    def test_an_unknown_class_has_no_specialist(self):
        self.assertIsNone(sp.specialist_for("NOT_A_CLASS"))
        self.assertIsNone(sp.specialist_for(""))

    def test_every_specialist_declares_its_class(self):
        for name, spec in sp.SPECIALISTS.items():
            self.assertEqual(spec.vulnerability_class, name)

    def test_every_specialist_declares_a_capability(self):
        for spec in sp.SPECIALISTS.values():
            self.assertIn(spec.capability, (sp.CAP_IMPLEMENTED, sp.CAP_LIMITED,
                                            sp.CAP_NOT_IMPLEMENTED))

    def test_every_specialist_declares_a_safety_policy(self):
        for spec in sp.SPECIALISTS.values():
            self.assertTrue(spec.safety_policy, spec.vulnerability_class)

    def test_every_specialist_declares_terminal_conditions(self):
        for name in ("OPEN_REDIRECT", "SSRF", "IDOR"):
            self.assertTrue(sp.SPECIALISTS[name].terminal_conditions, name)

    def test_specialist_stages_come_from_the_chain(self):
        for name, chain in ch.CHAINS.items():
            spec = sp.specialist_for(name)
            if spec is None:
                continue
            self.assertEqual(spec.stages,
                             tuple(s.key for s in chain.stages), name)

    def test_specialist_confirmation_requirements_come_from_the_contract(self):
        spec = sp.SPECIALISTS["CORS"]
        self.assertEqual(spec.confirmation_requirements,
                         tuple("/".join(g)
                               for g in ch.CORS_CHAIN.confirmation_requires))

    def test_the_dom_lane_remains_epic15s(self):
        """EPIC16 must not reimplement deep verification."""
        from backend.research_agents.verification import deep
        self.assertTrue(hasattr(deep, "deep_verify"))

    def test_the_specialist_module_versions_are_distinct(self):
        versions = {sp.CLASS_RULE_VERSION, cl.RULE_VERSION,
                    pr.CLASS_PRODUCER_VERSION, sv.CLASS_VERIFICATION_VERSION}
        self.assertEqual(len(versions), 4)

    def test_a_specialist_never_claims_confirmation_capability(self):
        for spec in sp.SPECIALISTS.values():
            self.assertFalse(hasattr(spec, "confirm"))


class TestChainCapabilityBoundary(unittest.TestCase):
    """§3: which chains are genuinely verifiable here."""

    def test_xss_remains_full(self):
        self.assertEqual(ch.capability_for("XSS"), ch.CAPABILITY_FULL)

    def test_the_three_new_classes_are_limited(self):
        for name in ("CORS", "OPEN_REDIRECT", "SSRF"):
            self.assertEqual(ch.capability_for(name), ch.CAPABILITY_LIMITED)

    def test_idor_and_cve_are_contract_only(self):
        for name in ("IDOR", "CVE_RESEARCH"):
            self.assertEqual(ch.capability_for(name), ch.CAPABILITY_CONTRACT_ONLY)

    def test_unimplemented_classes_have_no_chain(self):
        for name in ("SQLI", "JWT", "OAUTH", "SSTI"):
            self.assertIsNone(ch.chain_for(name))
            self.assertEqual(ch.capability_for(name),
                             ch.CAPABILITY_NOT_IMPLEMENTED)

    def test_implemented_classes_include_only_verifiable_ones(self):
        self.assertEqual(ch.implemented_classes(),
                         ("CORS", "OPEN_REDIRECT", "SSRF", "XSS"))

    def test_the_research_chain_declares_no_confirmation_claim(self):
        self.assertFalse(ch._has_confirmation_claim(ch.CVE_RESEARCH_CHAIN))
        self.assertEqual(ch.CVE_RESEARCH_CHAIN.confirmation_requires, ())

    def test_the_idor_chain_requires_a_second_context(self):
        stages = {s.key for s in ch.IDOR_CHAIN.stages}
        self.assertIn("second_context", stages)
        self.assertIn("unauthorized_access", stages)

    def test_the_cve_chain_is_research_only(self):
        for stage in ch.CVE_RESEARCH_CHAIN.stages:
            self.assertFalse(stage.required_for_confirmation)

    def test_class_aliases_normalize_to_one_class(self):
        self.assertEqual(ch.normalize_class("cors"), "CORS")
        self.assertEqual(ch.normalize_class("BOLA"), "IDOR")
        self.assertEqual(ch.normalize_class("IDOR_BOLA"), "IDOR")
        self.assertEqual(ch.normalize_class("CVE"), "CVE_RESEARCH")

    def test_an_unknown_class_name_is_not_aliased(self):
        self.assertEqual(ch.normalize_class("XSS_REFLECTED"), "XSS_REFLECTED")
        self.assertEqual(ch.normalize_class("SOMETHING_ELSE"),
                         "SOMETHING_ELSE")


class TestContractsPerClass(unittest.TestCase):
    """§15: every verifiable class owns a real contract (no GENERIC)."""

    def test_cors_has_its_own_contract(self):
        self.assertEqual(ct.contract_for("CORS").vulnerability_class, "CORS")

    def test_open_redirect_has_its_own_contract(self):
        self.assertEqual(ct.contract_for("OPEN_REDIRECT").vulnerability_class,
                         "OPEN_REDIRECT")

    def test_ssrf_has_its_own_contract(self):
        self.assertEqual(ct.contract_for("SSRF").vulnerability_class, "SSRF")

    def test_idor_has_its_own_contract(self):
        self.assertEqual(ct.contract_for("IDOR").vulnerability_class, "IDOR")

    def test_cve_research_has_its_own_contract(self):
        self.assertEqual(ct.contract_for("CVE_RESEARCH").vulnerability_class,
                         "CVE_RESEARCH")

    def test_the_new_contracts_require_authorization_for_confirmation(self):
        for name in ("CORS", "OPEN_REDIRECT"):
            self.assertTrue(ct.contract_for(name)
                            .require_authorization_for_confirmation, name)

    def test_cors_confirmation_needs_exploitability_too(self):
        """An accepted origin is not enough: the class confirmation claim also
        requires the exploitability stage."""
        groups = ct.contract_for("CORS").confirmation_claim.required_groups
        self.assertIn((tx.EXPLOITABILITY_ESTABLISHED,), groups)

    def test_the_cve_contract_declares_no_confirmation_claim(self):
        with self.assertRaises(KeyError):
            ct.contract_for("CVE_RESEARCH").confirmation_claim


class TestTaxonomyClassSignals(unittest.TestCase):
    """§15: class signals extend EPIC11's one taxonomy (no second one)."""

    def test_the_evidence_vocabulary_is_unchanged(self):
        self.assertEqual(len(tx.EVIDENCE_TYPES), 15)

    def test_class_signals_classify_to_the_chain_stage_types(self):
        cases = {
            "cors_origin_supplied": tx.CONTROLLED_INPUT_SENT,
            "cors_acao_observed": tx.RESPONSE_OBSERVED,
            "cors_arbitrary_origin_accepted": tx.OUTPUT_CONTEXT_IDENTIFIED,
            "cors_credentials_allowed": tx.PAYLOAD_EXECUTION,
            "cors_sensitive_response_available": tx.IMPACT_ESTABLISHED,
            "redirect_external_destination_accepted": tx.PAYLOAD_EXECUTION,
            "ssrf_server_side_request_observed": tx.PAYLOAD_EXECUTION,
            "redirect_external_destination_rejected": tx.NEGATIVE_EVIDENCE,
            "ssrf_server_request_absent": tx.NEGATIVE_EVIDENCE,
            "idor_no_second_context": tx.NEGATIVE_EVIDENCE,
            "cve_applicability_evidence": tx.KNOWLEDGE_REFERENCE,
        }
        for signal, expected in cases.items():
            item = tx.classify_row({"signal": signal, "category": "X",
                                    "detail": "d"})
            self.assertEqual(item.evidence_type, expected, signal)

    def test_an_unknown_class_signal_fails_closed(self):
        item = tx.classify_row({"signal": "cors_something_invented",
                                "category": "CORS", "detail": "d"})
        self.assertEqual(item.evidence_type, tx.UNCLASSIFIED_OBSERVATION)
        self.assertFalse(item.provenance_class.startswith("trusted"))

    def test_class_signals_record_their_owning_class(self):
        item = tx.classify_row({"signal": "redirect_response_observed",
                                "category": "X", "detail": "d"})
        self.assertEqual(item.signal_class, "OPEN_REDIRECT")

    def test_class_agnostic_signals_have_no_class_scope(self):
        item = tx.classify_row({"signal": "response_observed",
                                "category": "CORS", "detail": "d"})
        self.assertEqual(item.signal_class, "")

    def test_negative_class_signals_go_through_the_negative_path(self):
        for signal in ("cors_acao_absent", "cors_origin_not_accepted",
                       "cors_credentials_not_allowed",
                       "cors_sensitive_response_absent",
                       "redirect_parameter_ignored",
                       "redirect_external_destination_rejected",
                       "ssrf_internal_destination_rejected",
                       "ssrf_server_request_absent", "idor_no_second_context",
                       "cve_version_not_affected"):
            item = tx.classify_row({"signal": signal, "category": "X",
                                    "detail": "d"})
            self.assertEqual(item.evidence_type, tx.NEGATIVE_EVIDENCE, signal)
            self.assertEqual(item.negative_kind, tx.NOT_OBSERVED, signal)

    def test_a_capability_refusal_is_not_tested_not_negative(self):
        for signal in ("cors_origin_not_tested",
                       "redirect_unsafe_destination_rejected"):
            item = tx.classify_row({"signal": signal, "category": "X",
                                    "detail": "d"})
            self.assertEqual(item.negative_kind, tx.NOT_TESTED, signal)

    def test_a_class_signal_is_not_a_finding_by_itself(self):
        for signal in ("cors_acao_observed", "redirect_response_observed",
                       "ssrf_url_parameter", "idor_object_reference_pattern"):
            item = tx.classify_row({"signal": signal, "category": "X",
                                    "detail": "d"})
            self.assertNotIn(item.evidence_type, tx.CONFIRMATION_EVIDENCE,
                             signal)


class TestActionWiring(unittest.TestCase):
    """§14: only actions backed by real capability are implemented."""

    def test_the_classification_actions_are_implemented(self):
        for action in (ac.CHECK_CORS_HEADERS, ac.CLASSIFY_CORS_ORIGIN_ECHO,
                       ac.CHECK_CREDENTIALS_MODE, ac.ASSESS_RESPONSE_SENSITIVITY,
                       ac.CHECK_REDIRECT_LOCATION, ac.CLASSIFY_REDIRECT_TARGET,
                       ac.CHECK_CALLBACK_INTERACTION):
            self.assertIn(action, ac.IMPLEMENTED_ACTIONS, action)

    def test_the_network_actions_stay_unimplemented(self):
        for action in (ac.SEND_ORIGIN_HEADER, ac.SEND_REDIRECT_MARKER,
                       ac.SEND_CALLBACK_URL, ac.OBSERVE_SERVER_RESPONSE,
                       ac.ASSESS_SSRF_IMPACT):
            self.assertNotIn(action, ac.IMPLEMENTED_ACTIONS, action)

    def test_the_idor_action_exists_but_is_not_implemented(self):
        self.assertIn(ac.CHECK_OBJECT_ACCESS, ac.ACTION_TYPES)
        self.assertNotIn(ac.CHECK_OBJECT_ACCESS, ac.IMPLEMENTED_ACTIONS)

    def test_the_network_actions_route_to_the_unavailable_executor(self):
        for action in (ac.SEND_ORIGIN_HEADER, ac.SEND_REDIRECT_MARKER,
                       ac.SEND_CALLBACK_URL):
            self.assertEqual(ex.executor_for(action).name, "unavailable", action)

    def test_the_classification_actions_route_to_the_class_executor(self):
        for action in (ac.CHECK_CORS_HEADERS, ac.CHECK_REDIRECT_LOCATION,
                       ac.CHECK_CALLBACK_INTERACTION):
            self.assertEqual(ex.executor_for(action).name,
                             "class_classification", action)

    def test_the_probe_actions_still_require_authorization(self):
        for action in (ac.SEND_ORIGIN_HEADER, ac.SEND_REDIRECT_MARKER,
                       ac.SEND_CALLBACK_URL, ac.CHECK_OBJECT_ACCESS):
            self.assertTrue(ac.spec_for(action).requires_authorization, action)

    def test_the_read_only_classification_actions_need_no_network(self):
        for action in ex.CLASS_ACTION_CLASS:
            if action == ac.CHECK_OBJECT_ACCESS:
                continue  # a probe action: it needs a second identity
            self.assertFalse(ac.spec_for(action).requires_network, action)

    def test_every_producer_signal_is_registered_and_class_scoped(self):
        import backend.research_agents.verification.specialists.producer as p
        signals = {v for k, v in vars(p).items()
                   if k.startswith("SIGNAL_") and isinstance(v, str)}
        self.assertTrue(signals)
        for signal in sorted(signals):
            item = tx.classify_row({"signal": signal, "category": "X",
                                    "detail": "d"})
            self.assertNotEqual(item.evidence_type,
                                tx.UNCLASSIFIED_OBSERVATION, signal)
            self.assertTrue(item.signal_class, signal)

    def test_the_network_action_denylist_is_explicit(self):
        self.assertEqual(ex.CLASS_ACTION_NETWORK,
                         frozenset({ac.SEND_ORIGIN_HEADER,
                                    ac.SEND_REDIRECT_MARKER,
                                    ac.SEND_CALLBACK_URL,
                                    ac.OBSERVE_SERVER_RESPONSE,
                                    ac.ASSESS_SSRF_IMPACT}))

    def test_no_classification_action_can_be_confused_with_xss(self):
        for action in ex.CLASS_ACTION_CLASS:
            self.assertNotEqual(
                ex.CLASS_ACTION_CLASS[action], "XSS", action)

    def test_the_catalogue_exposes_the_class_lane(self):
        catalog = {row["action_type"]: row for row in ex.executor_catalog()}
        for action in ex.CLASS_ACTION_CLASS:
            self.assertEqual(catalog[action]["executor"],
                             "class_classification", action)


class TestLiveGateUntouched(unittest.TestCase):
    """§23: no live traffic switch may be flipped by EPIC16."""

    def _flag(self, *fragments: str) -> str:
        """Assemble a live-flag name at runtime (never a literal in a file)."""
        return "".join(fragments)

    def test_the_live_traffic_gate_is_still_closed(self):
        from backend.research_agents.verification.acquisition import limits
        flag = self._flag("LIVE_TRAFFIC", "_", "ENABLED")
        self.assertFalse(getattr(limits, flag, False))

    def test_the_class_lane_opens_no_network_primitive(self):
        source = ex.__file__
        with open(source, "r", encoding="utf-8") as handle:
            text = handle.read()
        for forbidden in ("import socket", "requests.", "urllib.request",
                          "http.client"):
            self.assertNotIn(forbidden, text, forbidden)

    def test_the_specialists_package_opens_no_socket(self):
        import backend.research_agents.verification.specialists as pkg
        import os
        for name in os.listdir(os.path.dirname(pkg.__file__)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(os.path.dirname(pkg.__file__), name)
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            for forbidden in ("import socket", "urllib.request", "httpx",
                              "subprocess"):
                self.assertNotIn(forbidden, text, f"{name}: {forbidden}")


class TestControlRepresentations(unittest.TestCase):
    """§5/§7: only deterministic non-real controlled markers are usable."""

    def test_the_controlled_origin_is_non_resolving(self):
        self.assertTrue(cl.controlled_origin().endswith(cl.CONTROLLED_SUFFIX))
        self.assertIn(".invalid", cl.controlled_origin())

    def test_the_controlled_destination_is_non_resolving(self):
        self.assertTrue(
            cl.controlled_destination().endswith(cl.CONTROLLED_SUFFIX + "/"))

    def test_a_real_looking_origin_is_not_controlled(self):
        for origin in ("https://evil.example.com", "https://dell.com",
                       "http://controlled-hermes-origin.hermes-verification"
                       ".invalid"):
            self.assertFalse(cl.is_controlled_origin(origin), origin)

    def test_a_non_https_origin_is_not_controlled(self):
        self.assertFalse(cl.is_controlled_origin(
            "http://controlled-hermes-origin.hermes-verification.invalid"))

    def test_the_origin_token_is_deterministic(self):
        self.assertEqual(cl.controlled_origin(), cl.controlled_origin())
        self.assertEqual(cl.controlled_origin("x"), cl.controlled_origin("x"))

    def test_the_destination_token_is_sanitized(self):
        self.assertNotIn("..", cl.controlled_destination("../../etc/passwd"))

    def test_fixtures_use_only_controlled_representations(self):
        self.assertTrue(cl.is_controlled_origin(fx.CONTROLLED_ORIGIN))
        self.assertIn(".invalid", fx.CONTROLLED_DESTINATION)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
