"""tests/test_ssrf_context_analyzer.py — Stage R40.2 tests.

Deterministic, offline tests for the SSRF context analyzer:

- exact closed vocabularies (input, URL handling, fetch, protocol,
  redirect, validation, encoding)
- deterministic classification and malformed-input degradation
- confidence calculation with the server-side-fetch safety cap
- distinction between possible SSRF-relevant input and confirmed
  server-side fetch behavior
- JSON serialization, schema validation
- research_only always true, no network/DNS behavior

No network, no DNS, no LLM, no subprocess, no sockets, no browser, no
payloads, no target interaction, no Mongo writes, no persistence, no
execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import ssrf_context_analyzer as analyzer
from ai.schemas import ssrf_context_analysis as schema


class TestSSRFContextAnalyzer(unittest.TestCase):
    def test_input_location_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.INPUT_LOCATIONS),
            {"QUERY", "BODY", "HEADER", "COOKIE", "PATH", "UNKNOWN"},
        )

    def test_url_handling_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.URL_HANDLING_VALUES),
            {"FULL_URL", "HOST_ONLY", "PATH_OR_URL", "REDIRECT_TARGET",
             "WEBHOOK_TARGET", "RESOURCE_URL", "UNKNOWN"},
        )

    def test_server_side_fetch_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SERVER_SIDE_FETCH_STATES),
            {"OBSERVED", "NOT_OBSERVED", "UNKNOWN"},
        )

    def test_protocol_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.PROTOCOL_CONTEXTS),
            {"HTTP", "HTTPS", "FILE", "FTP", "GOPHER", "OTHER", "UNKNOWN"},
        )

    def test_redirect_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.REDIRECT_BEHAVIORS),
            {"FOLLOWED", "NOT_FOLLOWED", "UNKNOWN"},
        )

    def test_validation_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.VALIDATION_STATES),
            {"PRESENT", "ABSENT", "UNKNOWN"},
        )

    def test_encoding_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.ENCODING_BEHAVIORS),
            {"NORMALIZED", "ENCODED", "PARTIAL", "UNKNOWN"},
        )

    def test_classification_preserved(self):
        plan = analyzer.analyze_ssrf_context(
            input_location="BODY",
            url_handling="WEBHOOK_TARGET",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="FOLLOWED",
            hostname_validation="ABSENT",
            ip_validation="PRESENT",
            allowlist_behavior="PRESENT",
            encoding_behavior="ENCODED",
        )
        self.assertEqual(plan["input_location"], "BODY")
        self.assertEqual(plan["url_handling"], "WEBHOOK_TARGET")
        self.assertEqual(plan["server_side_fetch"], "OBSERVED")
        self.assertEqual(plan["protocol_context"], "HTTPS")
        self.assertEqual(plan["redirect_behavior"], "FOLLOWED")
        self.assertEqual(plan["hostname_validation"], "ABSENT")
        self.assertEqual(plan["ip_validation"], "PRESENT")
        self.assertEqual(plan["allowlist_behavior"], "PRESENT")
        self.assertEqual(plan["encoding_behavior"], "ENCODED")

    def test_lowercase_normalized(self):
        plan = analyzer.analyze_ssrf_context(
            input_location="query",
            url_handling="full_url",
            server_side_fetch="observed",
            protocol_context="http",
            redirect_behavior="not_followed",
            hostname_validation="present",
            ip_validation="present",
            allowlist_behavior="present",
            encoding_behavior="encoded",
        )
        self.assertEqual(plan["input_location"], "QUERY")
        self.assertEqual(plan["url_handling"], "FULL_URL")
        self.assertEqual(plan["server_side_fetch"], "OBSERVED")
        self.assertEqual(plan["encoding_behavior"], "ENCODED")

    def test_malformed_values_become_unknown(self):
        for bad in (None, "", "NOPE", 42, ["QUERY"]):
            plan = analyzer.analyze_ssrf_context(
                input_location=bad,
                url_handling=bad,
                server_side_fetch=bad,
                protocol_context=bad,
                redirect_behavior=bad,
                hostname_validation=bad,
                ip_validation=bad,
                allowlist_behavior=bad,
                encoding_behavior=bad,
            )
            for key in (
                "input_location", "url_handling", "server_side_fetch",
                "protocol_context", "redirect_behavior",
                "hostname_validation", "ip_validation",
                "allowlist_behavior", "encoding_behavior",
            ):
                self.assertEqual(plan[key], "UNKNOWN", (key, repr(bad)))
            self.assertEqual(plan["context_confidence"], "UNKNOWN")

    def test_lone_url_parameter_is_not_a_fetch(self):
        plan = analyzer.analyze_ssrf_context(
            input_location="QUERY", url_handling="FULL_URL"
        )
        self.assertEqual(plan["context_confidence"], "LOW")
        self.assertTrue(analyzer.ssrf_input_possible(plan))
        self.assertFalse(analyzer.server_side_fetch_confirmed(plan))

    def test_unobserved_fetch_capped_at_low(self):
        plan = analyzer.analyze_ssrf_context(
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
        self.assertEqual(plan["context_confidence"], "LOW")
        self.assertFalse(analyzer.server_side_fetch_confirmed(plan))

    def test_unknown_fetch_capped_at_low(self):
        plan = analyzer.analyze_ssrf_context(
            input_location="QUERY",
            url_handling="FULL_URL",
            protocol_context="HTTPS",
            redirect_behavior="NOT_FOLLOWED",
            hostname_validation="PRESENT",
            ip_validation="PRESENT",
            allowlist_behavior="PRESENT",
            encoding_behavior="NORMALIZED",
        )
        self.assertEqual(plan["context_confidence"], "LOW")

    def test_observed_fetch_confidence_mapping(self):
        full = dict(
            input_location="QUERY",
            url_handling="FULL_URL",
            server_side_fetch="OBSERVED",
            protocol_context="HTTPS",
            redirect_behavior="NOT_FOLLOWED",
            hostname_validation="PRESENT",
            ip_validation="PRESENT",
            allowlist_behavior="PRESENT",
            encoding_behavior="NORMALIZED",
        )
        self.assertEqual(
            analyzer.analyze_ssrf_context(**full)["context_confidence"],
            "HIGH",
        )
        partial = dict(full)
        del partial["encoding_behavior"]
        del partial["allowlist_behavior"]
        del partial["redirect_behavior"]
        del partial["protocol_context"]
        self.assertEqual(
            analyzer.analyze_ssrf_context(**partial)[
                "context_confidence"
            ],
            "MEDIUM",
        )
        minimal = dict(full)
        del minimal["encoding_behavior"]
        del minimal["allowlist_behavior"]
        del minimal["redirect_behavior"]
        del minimal["protocol_context"]
        del minimal["ip_validation"]
        self.assertEqual(
            analyzer.analyze_ssrf_context(**minimal)[
                "context_confidence"
            ],
            "LOW",
        )

    def test_observed_fetch_medium_confidence(self):
        plan = analyzer.analyze_ssrf_context(
            input_location="HEADER",
            url_handling="HOST_ONLY",
            server_side_fetch="OBSERVED",
            protocol_context="HTTP",
            redirect_behavior="NOT_FOLLOWED",
        )
        self.assertEqual(plan["context_confidence"], "MEDIUM")

    def test_confidence_recomputed_for_partial_dict(self):
        self.assertEqual(
            analyzer.ssrf_context_confidence_of(
                {"input_location": "QUERY", "url_handling": "FULL_URL"}
            ),
            "LOW",
        )
        self.assertEqual(
            analyzer.ssrf_context_confidence_of({}), "UNKNOWN"
        )

    def test_fetch_confirmed_requires_observed(self):
        self.assertFalse(analyzer.server_side_fetch_confirmed(None))
        self.assertFalse(
            analyzer.server_side_fetch_confirmed(
                {"server_side_fetch": "NOT_OBSERVED",
                 "url_handling": "FULL_URL"}
            )
        )
        self.assertTrue(
            analyzer.server_side_fetch_confirmed(
                {"server_side_fetch": "OBSERVED"}
            )
        )

    def test_input_possible_requires_location_or_url(self):
        self.assertFalse(analyzer.ssrf_input_possible(None))
        self.assertFalse(
            analyzer.ssrf_input_possible(
                {"server_side_fetch": "OBSERVED"}
            )
        )
        self.assertTrue(
            analyzer.ssrf_input_possible({"input_location": "PATH"})
        )
        self.assertTrue(
            analyzer.ssrf_input_possible(
                {"url_handling": "RESOURCE_URL"}
            )
        )

    def test_deterministic_output_and_json(self):
        kwargs = {
            "input_location": "QUERY",
            "url_handling": "FULL_URL",
            "server_side_fetch": "OBSERVED",
        }
        first = analyzer.analyze_ssrf_context(**kwargs)
        second = analyzer.analyze_ssrf_context(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            analyzer.analyze_ssrf_context()["research_only"], True
        )
        with self.assertRaises(ValidationError):
            schema.SSRFContextAnalysisPlan(research_only=False)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "input_location": "QUERY",
            "url_handling": "FULL_URL",
            "server_side_fetch": "OBSERVED",
            "protocol_context": "HTTPS",
            "redirect_behavior": "FOLLOWED",
            "hostname_validation": "PRESENT",
            "ip_validation": "PRESENT",
            "allowlist_behavior": "PRESENT",
            "encoding_behavior": "NORMALIZED",
            "context_confidence": "HIGH",
        }
        for key, value in (
            ("input_location", "FORM"),
            ("url_handling", "URLISH"),
            ("server_side_fetch", "MAYBE"),
            ("protocol_context", "SMTP"),
            ("redirect_behavior", "SOMETIMES"),
            ("hostname_validation", "MAYBE"),
            ("ip_validation", "MAYBE"),
            ("allowlist_behavior", "MAYBE"),
            ("encoding_behavior", "SOMETIMES"),
            ("context_confidence", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.SSRFContextAnalysisPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SSRFContextAnalysisPlan(**base, fetch_url="x")

    def test_schema_forces_rule_version(self):
        plan = schema.SSRFContextAnalysisPlan(
            rule_version="r99-9", input_location="QUERY"
        )
        self.assertEqual(plan.rule_version, "r40-2")

    def test_no_network_fields(self):
        plan = analyzer.analyze_ssrf_context()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "input_location", "url_handling",
             "server_side_fetch", "protocol_context",
             "redirect_behavior", "hostname_validation", "ip_validation",
             "allowlist_behavior", "encoding_behavior",
             "context_confidence", "research_only"},
        )
        for key in ("ip_address", "hostname", "url", "socket", "response"):
            self.assertNotIn(key, plan)

    def test_exact_rule_version(self):
        self.assertEqual(
            analyzer.SSRF_CONTEXT_ANALYZER_RULE_VERSION, "r40-2"
        )
        self.assertEqual(
            analyzer.analyze_ssrf_context()["rule_version"], "r40-2"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
