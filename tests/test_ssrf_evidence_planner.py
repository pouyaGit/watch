"""tests/test_ssrf_evidence_planner.py — Stage R40.4 tests.

Deterministic, offline tests for the SSRF evidence planner:

- exact evidence-category, state and limitation vocabularies
- required evidence categories per hypothesis type
- complete / partial / unknown evidence planning states
- no collection, no network, no DNS behavior
- malformed and empty input handling
- JSON serialization, schema validation
- research_only always true

No network, no DNS, no LLM, no subprocess, no sockets, no browser, no
payloads, no target interaction, no Mongo writes, no persistence, no
execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import ssrf_evidence_planner as planner
from ai.knowledge import ssrf_hypothesis_planner
from ai.schemas import ssrf_evidence_plan as schema


def evidence(context=None, hypotheses=None):
    return planner.plan_ssrf_evidence(context, hypotheses)


class TestSSRFEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SSRF_EVIDENCE_ITEMS),
            {"SERVER_FETCH_BEHAVIOR", "URL_PARSING_CONTEXT",
             "HOST_VALIDATION", "IP_RANGE_VALIDATION",
             "REDIRECT_POLICY", "PROTOCOL_RESTRICTION",
             "DNS_RESOLUTION_BEHAVIOR", "DESTINATION_RESTRICTION",
             "APPLICATION_BEHAVIOR", "CLOUD_BOUNDARY_CONTEXT",
             "UNKNOWN"},
        )

    def test_evidence_states_are_exact(self):
        self.assertEqual(
            set(schema.EVIDENCE_STATES),
            {"COMPLETE", "PARTIAL", "UNKNOWN"},
        )

    def test_limitations_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SSRF_EVIDENCE_LIMITATIONS),
            {"NO_COLLECTION_PERFORMED", "NO_NETWORK_REQUESTS",
             "NO_DNS_RESOLUTION", "EVIDENCE_REQUIRED",
             "INSUFFICIENT_CONTEXT"},
        )

    def test_server_fetch_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "server_side_fetch": "OBSERVED",
             "protocol_context": "HTTPS", "redirect_behavior": "FOLLOWED",
             "hostname_validation": "PRESENT",
             "ip_validation": "PRESENT",
             "allowlist_behavior": "PRESENT",
             "encoding_behavior": "NORMALIZED"},
        )
        self.assertIn(
            "SERVER_FETCH_BEHAVIOR", result["evidence_items"]
        )
        self.assertIn("APPLICATION_BEHAVIOR", result["evidence_items"])
        self.assertEqual(result["evidence_state"], "COMPLETE")
        self.assertEqual(result["confidence"], "HIGH")

    def test_url_validation_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "hostname_validation": "ABSENT"},
        )
        self.assertIn("URL_PARSING_CONTEXT", result["evidence_items"])
        self.assertIn("HOST_VALIDATION", result["evidence_items"])

    def test_ip_validation_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "server_side_fetch": "OBSERVED",
             "ip_validation": "ABSENT"},
        )
        self.assertIn("IP_RANGE_VALIDATION", result["evidence_items"])

    def test_redirect_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "REDIRECT_TARGET",
             "redirect_behavior": "FOLLOWED"},
        )
        self.assertIn("REDIRECT_POLICY", result["evidence_items"])

    def test_protocol_evidence(self):
        result = evidence(
            {"input_location": "PATH", "url_handling": "PATH_OR_URL",
             "protocol_context": "GOPHER"},
        )
        self.assertIn("PROTOCOL_RESTRICTION", result["evidence_items"])

    def test_dns_rebinding_evidence(self):
        result = evidence(
            {"input_location": "HEADER", "url_handling": "HOST_ONLY",
             "hostname_validation": "ABSENT",
             "ip_validation": "PRESENT"},
        )
        self.assertIn(
            "DNS_RESOLUTION_BEHAVIOR", result["evidence_items"]
        )
        self.assertIn("HOST_VALIDATION", result["evidence_items"])

    def test_internal_address_evidence(self):
        result = evidence(
            {"input_location": "HEADER", "url_handling": "HOST_ONLY",
             "hostname_validation": "ABSENT",
             "ip_validation": "ABSENT"},
        )
        self.assertIn(
            "INTERNAL_ADDRESS_RESTRICTION_REVIEW",
            [item["hypothesis_type"]
             for item in ssrf_hypothesis_planner.plan_ssrf_hypotheses(
                 {"input_location": "HEADER", "url_handling": "HOST_ONLY",
                  "hostname_validation": "ABSENT",
                  "ip_validation": "ABSENT"}
             )],
        )
        self.assertIn("IP_RANGE_VALIDATION", result["evidence_items"])
        self.assertIn(
            "DESTINATION_RESTRICTION", result["evidence_items"]
        )

    def test_cloud_boundary_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "server_side_fetch": "OBSERVED",
             "hostname_validation": "ABSENT",
             "ip_validation": "ABSENT",
             "allowlist_behavior": "ABSENT"},
        )
        self.assertIn(
            "CLOUD_BOUNDARY_CONTEXT", result["evidence_items"]
        )
        self.assertIn(
            "DESTINATION_RESTRICTION", result["evidence_items"]
        )

    def test_webhook_evidence(self):
        result = evidence(
            {"input_location": "BODY",
             "url_handling": "WEBHOOK_TARGET"},
        )
        self.assertIn("APPLICATION_BEHAVIOR", result["evidence_items"])
        self.assertIn("URL_PARSING_CONTEXT", result["evidence_items"])

    def test_unknown_evidence_state(self):
        result = evidence()
        self.assertEqual(result["evidence_items"], ["UNKNOWN"])
        self.assertEqual(result["evidence_state"], "UNKNOWN")
        self.assertEqual(result["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", result["limitations"])

    def test_partial_evidence_is_partial(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "server_side_fetch": "OBSERVED"}
        )
        self.assertEqual(result["evidence_state"], "PARTIAL")
        self.assertEqual(result["confidence"], "LOW")

    def test_unobserved_fetch_never_complete(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "server_side_fetch": "NOT_OBSERVED",
             "protocol_context": "HTTPS", "redirect_behavior": "FOLLOWED",
             "hostname_validation": "ABSENT",
             "ip_validation": "PRESENT",
             "allowlist_behavior": "PRESENT",
             "encoding_behavior": "NORMALIZED"},
        )
        self.assertNotEqual(result["evidence_state"], "COMPLETE")

    def test_limitations_always_record_no_collection(self):
        for context in (None, {"input_location": "QUERY"}):
            result = evidence(context)
            self.assertIn(
                "NO_COLLECTION_PERFORMED", result["limitations"]
            )
            self.assertIn(
                "NO_NETWORK_REQUESTS", result["limitations"]
            )
            self.assertIn(
                "NO_DNS_RESOLUTION", result["limitations"]
            )
            self.assertIn("EVIDENCE_REQUIRED", result["limitations"])

    def test_items_deduped_across_hypotheses(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL",
             "server_side_fetch": "OBSERVED",
             "hostname_validation": "ABSENT"},
        )
        items = result["evidence_items"]
        self.assertEqual(len(items), len(set(items)))

    def test_malformed_hypotheses_filtered(self):
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL"},
            ["junk", 42, {"hypothesis_type": "NOPE"}],
        )
        self.assertEqual(result["evidence_items"], ["UNKNOWN"])
        self.assertEqual(result["evidence_state"], "UNKNOWN")

    def test_single_hypothesis_dict_accepted(self):
        hypotheses = ssrf_hypothesis_planner.plan_ssrf_hypotheses(
            {"input_location": "QUERY", "url_handling": "FULL_URL"}
        )
        result = evidence(
            {"input_location": "QUERY", "url_handling": "FULL_URL"},
            hypotheses[0],
        )
        self.assertIn("SERVER_FETCH_BEHAVIOR", result["evidence_items"])

    def test_deterministic_output_and_json(self):
        context = {
            "input_location": "QUERY",
            "url_handling": "FULL_URL",
            "server_side_fetch": "OBSERVED",
            "hostname_validation": "ABSENT",
        }
        first = evidence(context)
        second = evidence(context)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), dict)

    def test_research_only_always_true(self):
        self.assertIs(evidence()["research_only"], True)
        with self.assertRaises(ValidationError):
            schema.SSRFEvidencePlan(research_only=False)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "evidence_items": ["SERVER_FETCH_BEHAVIOR"],
            "evidence_state": "PARTIAL",
            "confidence": "LOW",
            "limitations": ["NO_COLLECTION_PERFORMED"],
        }
        for key, value in (
            ("evidence_items", ["COLLECT_IT"]),
            ("evidence_state", "DONE"),
            ("confidence", "CERTAIN"),
            ("limitations", ["COLLECTED"]),
        ):
            with self.assertRaises(ValidationError):
                schema.SSRFEvidencePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SSRFEvidencePlan(**base, collection="x")

    def test_schema_forces_rule_version(self):
        plan = schema.SSRFEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r40-4")

    def test_no_collection_fields(self):
        result = evidence({"input_location": "QUERY"})
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "evidence_items", "evidence_state",
             "confidence", "limitations", "research_only"},
        )
        for key in ("request", "response", "dns_query", "socket",
                    "payload", "collection"):
            self.assertNotIn(key, result)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SSRF_EVIDENCE_PLANNER_RULE_VERSION, "r40-4"
        )
        self.assertEqual(evidence()["rule_version"], "r40-4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
