"""tests/test_ssrf_hypothesis_planner.py — Stage R40.3 tests.

Deterministic, offline tests for the SSRF hypothesis planner:

- exact hypothesis-type, signal and limitation vocabularies
- deterministic hypothesis generation from bounded context
- confidence and priority mapping, safety caps without observed fetch
- redirect/protocol/DNS/webhook/cloud review branches
- no exploit claims, no vulnerability confirmation, no payloads
- malformed/empty input handling, JSON serialization
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

from ai.knowledge import ssrf_hypothesis_planner as planner
from ai.schemas import ssrf_hypothesis as schema


def hypotheses(**context):
    return planner.plan_ssrf_hypotheses(context)


class TestSSRFHypothesisPlanner(unittest.TestCase):
    def test_hypothesis_types_are_exact(self):
        self.assertEqual(
            set(schema.HYPOTHESIS_TYPES),
            {"SERVER_SIDE_FETCH_ANALYSIS", "URL_VALIDATION_REVIEW",
             "IP_VALIDATION_REVIEW", "REDIRECT_HANDLING_REVIEW",
             "PROTOCOL_HANDLING_REVIEW", "DNS_REBINDING_REVIEW",
             "INTERNAL_ADDRESS_RESTRICTION_REVIEW",
             "CLOUD_METADATA_BOUNDARY_REVIEW", "WEBHOOK_FETCH_REVIEW",
             "UNKNOWN"},
        )

    def test_limitations_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SSRF_HYPOTHESIS_LIMITATIONS),
            {"NO_EXPLOIT_CLAIM", "NO_VULNERABILITY_CONFIRMATION",
             "HYPOTHESIS_ONLY", "EVIDENCE_REQUIRED",
             "INSUFFICIENT_CONTEXT"},
        )

    def test_no_exploit_claims(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="FOLLOWED",
            hostname_validation="ABSENT",
            ip_validation="ABSENT",
            allowlist_behavior="ABSENT",
            encoding_behavior="NORMALIZED",
        )
        self.assertTrue(result)
        for plan in result:
            self.assertIn("NO_EXPLOIT_CLAIM", plan["limitations"])
            self.assertIn(
                "NO_VULNERABILITY_CONFIRMATION", plan["limitations"]
            )
            self.assertIn("HYPOTHESIS_ONLY", plan["limitations"])
            self.assertIn("EVIDENCE_REQUIRED", plan["limitations"])
            self.assertIn(plan["hypothesis_type"], schema.HYPOTHESIS_TYPES)

    def test_observed_fetch_high_confidence(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="FOLLOWED",
            hostname_validation="ABSENT",
            ip_validation="PRESENT",
            allowlist_behavior="PRESENT",
            encoding_behavior="NORMALIZED",
        )
        first = result[0]
        self.assertEqual(
            first["hypothesis_type"], "SERVER_SIDE_FETCH_ANALYSIS"
        )
        self.assertEqual(first["confidence"], "HIGH")
        self.assertEqual(first["priority"], "HIGH")

    def test_unobserved_fetch_stays_low(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="NOT_OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="NOT_FOLLOWED",
            hostname_validation="PRESENT",
            ip_validation="PRESENT",
            allowlist_behavior="PRESENT",
            encoding_behavior="NORMALIZED",
        )
        analysis = [
            item for item in result
            if item["hypothesis_type"] == "SERVER_SIDE_FETCH_ANALYSIS"
        ]
        self.assertEqual(len(analysis), 1)
        self.assertEqual(analysis[0]["confidence"], "LOW")
        self.assertNotIn(
            "HIGH",
            [item["confidence"] for item in result],
        )

    def test_lone_url_parameter_low(self):
        result = hypotheses(
            input_location="QUERY", url_handling="FULL_URL"
        )
        self.assertEqual(
            result[0]["hypothesis_type"], "SERVER_SIDE_FETCH_ANALYSIS"
        )
        self.assertEqual(result[0]["confidence"], "LOW")

    def test_priority_matches_confidence(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="FOLLOWED",
            hostname_validation="ABSENT",
            ip_validation="PRESENT",
            allowlist_behavior="PRESENT",
            encoding_behavior="NORMALIZED",
        )
        for plan in result:
            self.assertEqual(plan["priority"], plan["confidence"])

    def test_url_validation_review(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            hostname_validation="ABSENT",
        )
        review = [
            item for item in result
            if item["hypothesis_type"] == "URL_VALIDATION_REVIEW"
        ]
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0]["confidence"], "MEDIUM")

    def test_ip_validation_review(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            ip_validation="ABSENT",
        )
        types = [item["hypothesis_type"] for item in result]
        self.assertIn("IP_VALIDATION_REVIEW", types)

    def test_redirect_handling_review(self):
        followed = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            redirect_behavior="FOLLOWED",
        )
        review = [
            item for item in followed
            if item["hypothesis_type"] == "REDIRECT_HANDLING_REVIEW"
        ]
        self.assertEqual(review[0]["confidence"], "MEDIUM")
        target = hypotheses(
            input_location="QUERY", url_handling="REDIRECT_TARGET"
        )
        review = [
            item for item in target
            if item["hypothesis_type"] == "REDIRECT_HANDLING_REVIEW"
        ]
        self.assertEqual(review[0]["confidence"], "LOW")

    def test_protocol_handling_review_non_http(self):
        result = hypotheses(
            input_location="PATH",
            url_handling="PATH_OR_URL",
            server_side_fetch="OBSERVED",
            protocol_context="FILE",
        )
        review = [
            item for item in result
            if item["hypothesis_type"] == "PROTOCOL_HANDLING_REVIEW"
        ]
        self.assertEqual(review[0]["confidence"], "MEDIUM")
        self.assertIn(
            "PROTOCOL_NON_HTTP", review[0]["supporting_signals"]
        )
        self.assertNotIn(
            "PROTOCOL_HANDLING_REVIEW",
            [item["hypothesis_type"] for item in hypotheses(
                input_location="PATH", protocol_context="HTTPS"
            )],
        )

    def test_dns_rebinding_review(self):
        result = hypotheses(
            input_location="HEADER",
            url_handling="HOST_ONLY",
            server_side_fetch="OBSERVED",
            hostname_validation="ABSENT",
            ip_validation="PRESENT",
        )
        types = [item["hypothesis_type"] for item in result]
        self.assertIn("DNS_REBINDING_REVIEW", types)
        self.assertNotIn(
            "INTERNAL_ADDRESS_RESTRICTION_REVIEW", types
        )

    def test_internal_address_restriction_review(self):
        result = hypotheses(
            input_location="HEADER",
            url_handling="HOST_ONLY",
            server_side_fetch="OBSERVED",
            hostname_validation="ABSENT",
            ip_validation="ABSENT",
        )
        types = [item["hypothesis_type"] for item in result]
        self.assertIn("INTERNAL_ADDRESS_RESTRICTION_REVIEW", types)
        self.assertNotIn("DNS_REBINDING_REVIEW", types)

    def test_cloud_metadata_review_requires_observed_fetch(self):
        observed = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            hostname_validation="ABSENT",
            ip_validation="ABSENT",
            allowlist_behavior="ABSENT",
        )
        types = [item["hypothesis_type"] for item in observed]
        self.assertIn("CLOUD_METADATA_BOUNDARY_REVIEW", types)
        self.assertIn("INTERNAL_ADDRESS_RESTRICTION_REVIEW", types)

        not_observed = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="NOT_OBSERVED",
            hostname_validation="ABSENT",
            ip_validation="ABSENT",
            allowlist_behavior="ABSENT",
        )
        types = [item["hypothesis_type"] for item in not_observed]
        self.assertNotIn("CLOUD_METADATA_BOUNDARY_REVIEW", types)

    def test_webhook_fetch_review(self):
        result = hypotheses(
            input_location="BODY",
            url_handling="WEBHOOK_TARGET",
            server_side_fetch="OBSERVED",
            allowlist_behavior="PRESENT",
        )
        review = [
            item for item in result
            if item["hypothesis_type"] == "WEBHOOK_FETCH_REVIEW"
        ]
        self.assertEqual(len(review), 1)
        self.assertEqual(review[0]["confidence"], "MEDIUM")

    def test_full_context_hypothesis_order(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="FOLLOWED",
            hostname_validation="ABSENT",
            ip_validation="ABSENT",
            allowlist_behavior="ABSENT",
            encoding_behavior="NORMALIZED",
        )
        self.assertEqual(
            [item["hypothesis_type"] for item in result],
            ["SERVER_SIDE_FETCH_ANALYSIS", "URL_VALIDATION_REVIEW",
             "IP_VALIDATION_REVIEW", "REDIRECT_HANDLING_REVIEW",
             "INTERNAL_ADDRESS_RESTRICTION_REVIEW",
             "CLOUD_METADATA_BOUNDARY_REVIEW"],
        )

    def test_signals_are_closed_and_deduplicated(self):
        result = hypotheses(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
        )
        for plan in result:
            signals = plan["supporting_signals"]
            self.assertEqual(len(signals), len(set(signals)))
            for signal in signals:
                self.assertIn(signal, schema.SSRF_SIGNALS)

    def test_fully_unknown_context(self):
        result = hypotheses()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(result[0]["confidence"], "UNKNOWN")
        self.assertEqual(result[0]["priority"], "UNKNOWN")
        self.assertEqual(
            result[0]["supporting_signals"], ["CONTEXT_UNKNOWN"]
        )
        self.assertIn(
            "INSUFFICIENT_CONTEXT", result[0]["limitations"]
        )

    def test_malformed_context_is_unknown(self):
        for bad in (None, "", 42, [], "NOPE"):
            result = planner.plan_ssrf_hypotheses(bad)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["hypothesis_type"], "UNKNOWN")

    def test_deterministic_output_and_json(self):
        kwargs = {
            "input_location": "QUERY",
            "url_handling": "FULL_URL",
            "server_side_fetch": "OBSERVED",
            "hostname_validation": "ABSENT",
        }
        first = hypotheses(**kwargs)
        second = hypotheses(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), list)

    def test_research_only_always_true(self):
        for plan in hypotheses(url_handling="FULL_URL"):
            self.assertIs(plan["research_only"], True)
        with self.assertRaises(ValidationError):
            schema.SSRFHypothesisPlan(
                hypothesis_type="URL_VALIDATION_REVIEW",
                research_only=False,
            )

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "hypothesis_type": "URL_VALIDATION_REVIEW",
            "supporting_signals": ["URL_HANDLING_OBSERVED"],
            "confidence": "LOW",
            "priority": "LOW",
            "limitations": ["NO_EXPLOIT_CLAIM"],
        }
        for key, value in (
            ("hypothesis_type", "SCAN_TARGET"),
            ("confidence", "CERTAIN"),
            ("priority", "URGENT"),
            ("supporting_signals", ["NOT_A_SIGNAL"]),
            ("limitations", ["VULNERABLE"]),
        ):
            with self.assertRaises(ValidationError):
                schema.SSRFHypothesisPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SSRFHypothesisPlan(**base, payload="x")

    def test_schema_forces_rule_version(self):
        plan = schema.SSRFHypothesisPlan(
            rule_version="r99-9",
            hypothesis_type="URL_VALIDATION_REVIEW",
        )
        self.assertEqual(plan.rule_version, "r40-3")

    def test_no_ssrf_payload_content(self):
        blob = json.dumps(
            hypotheses(
                input_location="QUERY",
                url_handling="FULL_URL",
                server_side_fetch="OBSERVED",
                hostname_validation="ABSENT",
                ip_validation="ABSENT",
                allowlist_behavior="ABSENT",
            )
        ).lower()
        for marker in (
            "http://", "https://", "169.254", "127.0.0.1", "localhost",
            "metadata.google", "curl", "wget", "socket", "subprocess",
            "shell",
        ):
            self.assertNotIn(marker, blob)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SSRF_HYPOTHESIS_PLANNER_RULE_VERSION, "r40-3"
        )
        self.assertEqual(hypotheses()[0]["rule_version"], "r40-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
