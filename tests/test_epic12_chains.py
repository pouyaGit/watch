"""EPIC12 §3/§4/§10/§11-§13 — verification chain model tests.

Pins the chain vocabulary, the XSS chain's six stages, the contract derivation
(the chain must never restate or weaken the EPIC11 contract) and the honest
capability states of the reference chains.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import contracts as ct  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import chains as ch  # noqa: E402


class TestChainVocabulary(unittest.TestCase):
    def test_capability_states_are_closed(self):
        self.assertEqual(ch.CAPABILITY_STATES,
                         ("FULL", "CONTRACT_ONLY", "NOT_IMPLEMENTED"))

    def test_stage_states_are_closed(self):
        self.assertEqual(ch.STAGE_STATES,
                         ("SATISFIED", "MISSING", "NOT_TESTED",
                          "CONTRADICTED", "NOT_APPLICABLE"))

    def test_rule_version_present(self):
        self.assertTrue(ch.CHAIN_RULE_VERSION.startswith("epic12-"))

    def test_only_xss_is_fully_implemented(self):
        self.assertEqual(ch.implemented_classes(), ("XSS",))

    def test_reference_chains_are_contract_only(self):
        for chain in ch.REFERENCE_CHAINS:
            self.assertEqual(chain.capability, ch.CAPABILITY_CONTRACT_ONLY)
            self.assertTrue(chain.reference)
            self.assertFalse(chain.implemented)

    def test_future_classes_have_no_chain(self):
        for cls in ch.FUTURE_CLASSES:
            self.assertIsNone(ch.chain_for(cls))
            self.assertEqual(ch.capability_for(cls),
                             ch.CAPABILITY_NOT_IMPLEMENTED)


class TestChainRegistry(unittest.TestCase):
    def test_known_classes_resolve(self):
        for cls in ("XSS", "CORS", "OPEN_REDIRECT", "SSRF"):
            self.assertIsNotNone(ch.chain_for(cls), cls)

    def test_aliases_resolve_without_inventing_classes(self):
        for alias in ("reflected_xss", "dom-xss", "CROSS SITE SCRIPTING"):
            self.assertEqual(ch.normalize_class(alias), "XSS")

    def test_unknown_class_normalizes_but_has_no_chain(self):
        self.assertEqual(ch.normalize_class("something else"),
                         "SOMETHING_ELSE")
        self.assertIsNone(ch.chain_for("something else"))

    def test_none_and_empty_are_safe(self):
        self.assertIsNone(ch.chain_for(None))
        self.assertIsNone(ch.chain_for(""))

    def test_catalog_covers_every_declared_chain(self):
        catalog = ch.chain_catalog()
        ids = {c["chain_id"] for c in catalog}
        self.assertIn("chain-xss", ids)
        self.assertIn("chain-cors", ids)
        self.assertIn("chain-ssrf", ids)
        self.assertIn("chain-open_redirect", ids)

    def test_catalog_marks_future_classes_not_implemented(self):
        catalog = {c["vulnerability_class"]: c for c in ch.chain_catalog()}
        for cls in ch.FUTURE_CLASSES:
            self.assertEqual(catalog[cls]["capability"],
                             ch.CAPABILITY_NOT_IMPLEMENTED)
            self.assertEqual(catalog[cls]["stages"], [])


class TestContractDerivation(unittest.TestCase):
    """The chain must DERIVE its confirmation requirement from EPIC11."""

    def test_xss_chain_confirmation_requires_the_contract_groups(self):
        chain = ch.XSS_CHAIN
        self.assertEqual(chain.confirmation_requires,
                         tuple(ct.XSS.confirmation_claim.required_groups))

    def test_min_unique_observations_matches_the_contract(self):
        self.assertEqual(ch.XSS_CHAIN.min_unique_observations,
                         ct.XSS.confirmation_claim.min_unique_observations)
        self.assertGreaterEqual(ch.XSS_CHAIN.min_unique_observations, 2)

    def test_contract_id_matches(self):
        self.assertEqual(ch.XSS_CHAIN.contract_id, ct.XSS.contract_id)

    def test_every_reference_chain_derives_its_contract(self):
        for chain in ch.REFERENCE_CHAINS:
            self.assertEqual(chain.contract_id,
                             ct.contract_for(chain.vulnerability_class)
                             .contract_id)

    def test_confirmation_evidence_types_stay_authoritative(self):
        # the chain may not widen what can confirm
        for chain in ch.CHAINS.values():
            for group in chain.confirmation_requires:
                for evidence_type in group:
                    self.assertIn(evidence_type, tx.EVIDENCE_TYPE_SET)
        self.assertEqual(tx.CONFIRMATION_EVIDENCE,
                         frozenset({tx.PAYLOAD_EXECUTION,
                                    tx.EXPLOITABILITY_ESTABLISHED}))

    def test_chain_does_not_redefine_epic11_stage_numbers(self):
        for stage in ch.XSS_CHAIN.ordered():
            self.assertEqual(stage.stage, tx.EVIDENCE_STAGE[
                stage.required_evidence_types[0]])


class TestXssChain(unittest.TestCase):
    def test_six_ordered_stages(self):
        self.assertEqual([s.key for s in ch.XSS_CHAIN.ordered()],
                         ["parameter", "reflection", "context", "sink",
                          "execution", "exploitability"])

    def test_stage_orders_are_contiguous(self):
        self.assertEqual([s.order for s in ch.XSS_CHAIN.ordered()],
                         [1, 2, 3, 4, 5, 6])

    def test_required_evidence_uses_epic11_types(self):
        expected = {
            "parameter": (tx.PARAMETER_OBSERVED,),
            "reflection": (tx.REFLECTION_OBSERVED,),
            "context": (tx.OUTPUT_CONTEXT_IDENTIFIED,),
            "sink": (tx.DOM_SINK_IDENTIFIED,),
            "execution": (tx.PAYLOAD_EXECUTION,),
            "exploitability": (tx.EXPLOITABILITY_ESTABLISHED,),
        }
        for key, types in expected.items():
            stage = ch.XSS_CHAIN.stage(key)
            self.assertIsNotNone(stage, key)
            self.assertEqual(stage.required_evidence_types, types, key)

    def test_every_stage_has_allowed_actions(self):
        for stage in ch.XSS_CHAIN.ordered():
            self.assertTrue(stage.allowed_actions, stage.key)

    def test_sink_stage_is_conditional_and_not_required(self):
        sink = ch.XSS_CHAIN.stage("sink")
        self.assertTrue(sink.conditional)
        self.assertFalse(sink.required_for_confirmation)
        self.assertEqual(sink.applies_when, "dom_variant")

    def test_confirmation_stage_keys(self):
        self.assertEqual(ch.XSS_CHAIN.confirmation_stage_keys,
                         ("parameter", "reflection", "context", "execution",
                          "exploitability"))

    def test_limitations_state_parameter_discovery_is_not_confirmation(self):
        blob = " ".join(ch.XSS_CHAIN.limitations).lower()
        self.assertIn("parameter discovery is not vulnerability confirmation",
                      blob)
        self.assertIn("a reflected parameter is not automatically xss", blob)

    def test_action_types_for_xss_are_declared(self):
        actions = ch.action_types_for("XSS")
        self.assertIn("CHECK_REFLECTION", actions)
        self.assertIn("DELIVER_CONTROLLED_PAYLOAD", actions)
        self.assertEqual(len(actions), len(set(actions)))

    def test_evidence_types_for_xss_are_closed(self):
        for evidence_type in ch.evidence_types_for("XSS"):
            self.assertIn(evidence_type, tx.EVIDENCE_TYPE_SET)

    def test_to_dict_is_json_safe(self):
        import json
        blob = json.dumps(ch.XSS_CHAIN.to_dict(), sort_keys=True)
        self.assertIn("chain-xss", blob)


class TestReferenceChainShallowConfirmation(unittest.TestCase):
    """§11-§13: a shallow observation must never satisfy these chains."""

    def test_cors_requires_credential_and_sensitivity_stages(self):
        keys = [s.key for s in ch.CORS_CHAIN.ordered()]
        self.assertIn("credentials_evaluated", keys)
        self.assertIn("sensitive_response_available", keys)
        self.assertIn("browser_exploitability", keys)

    def test_cors_limitation_states_header_is_not_exploitable_cors(self):
        blob = " ".join(ch.CORS_CHAIN.limitations).lower()
        self.assertIn("a cors header is not automatically exploitable cors",
                      blob)

    def test_open_redirect_requires_terminal_destination(self):
        keys = [s.key for s in ch.OPEN_REDIRECT_CHAIN.ordered()]
        self.assertEqual(keys[0], "redirect_input")
        self.assertIn("destination_attacker_controlled", keys)
        self.assertIn("terminal_redirect_confirmed", keys)

    def test_ssrf_requires_server_side_request_evidence(self):
        keys = [s.key for s in ch.SSRF_CHAIN.ordered()]
        self.assertIn("server_side_request", keys)
        self.assertIn("controlled_interaction", keys)
        blob = " ".join(ch.SSRF_CHAIN.limitations).lower()
        self.assertIn("a url-shaped parameter is not ssrf", blob)

    def test_every_reference_stage_is_required_for_confirmation(self):
        for chain in ch.REFERENCE_CHAINS:
            for stage in chain.ordered():
                self.assertTrue(stage.required_for_confirmation,
                                f"{chain.vulnerability_class}:{stage.key}")

    def test_reference_chains_use_only_epic11_evidence_types(self):
        for chain in ch.REFERENCE_CHAINS:
            for stage in chain.ordered():
                for evidence_type in stage.required_evidence_types:
                    self.assertIn(evidence_type, tx.EVIDENCE_TYPE_SET)


if __name__ == "__main__":
    unittest.main()
