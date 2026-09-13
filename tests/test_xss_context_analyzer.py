"""tests/test_xss_context_analyzer.py — Stage R39.2 tests.

Deterministic, offline tests for the XSS context analyzer:

- exact closed vocabularies (input, output, reflection, encoding,
  framework)
- reflection/encoding/output-context handling and malformed input
- deterministic context confidence mapping
- JSON serialization, schema validation
- research_only always true, no payload generation

No network, no DNS, no LLM, no subprocess, no browser, no payloads, no
target interaction, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import xss_context_analyzer as analyzer
from ai.schemas import xss_context_analysis as schema


class TestXSSContextAnalyzer(unittest.TestCase):
    def test_input_location_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.INPUT_LOCATIONS),
            {"QUERY", "BODY", "HEADER", "COOKIE", "UNKNOWN"},
        )

    def test_output_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.OUTPUT_CONTEXTS),
            {"HTML", "ATTRIBUTE", "JAVASCRIPT", "DOM", "UNKNOWN"},
        )

    def test_reflection_state_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.REFLECTION_STATES),
            {"REFLECTED", "NOT_OBSERVED", "UNKNOWN"},
        )

    def test_encoding_state_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.ENCODING_STATES),
            {"ENCODED", "PARTIAL", "NONE_OBSERVED", "UNKNOWN"},
        )

    def test_framework_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.FRAMEWORK_CONTEXTS),
            {"NONE_OBSERVED", "GENERIC", "REACT", "VUE", "ANGULAR",
             "JQUERY", "UNKNOWN"},
        )

    def test_reflection_states_preserved(self):
        for state in ("REFLECTED", "NOT_OBSERVED"):
            plan = analyzer.analyze_xss_context(reflection_state=state)
            self.assertEqual(plan["reflection_state"], state)

    def test_encoding_states_preserved(self):
        for state in ("ENCODED", "PARTIAL", "NONE_OBSERVED"):
            plan = analyzer.analyze_xss_context(encoding_state=state)
            self.assertEqual(plan["encoding_state"], state)

    def test_output_contexts_preserved(self):
        for state in ("HTML", "ATTRIBUTE", "JAVASCRIPT", "DOM"):
            plan = analyzer.analyze_xss_context(output_context=state)
            self.assertEqual(plan["output_context"], state)

    def test_input_locations_preserved(self):
        for state in ("QUERY", "BODY", "HEADER", "COOKIE"):
            plan = analyzer.analyze_xss_context(input_location=state)
            self.assertEqual(plan["input_location"], state)

    def test_malformed_values_become_unknown(self):
        for bad in (None, "", "NOPE", 42, ["HTML"]):
            plan = analyzer.analyze_xss_context(
                input_location=bad,
                output_context=bad,
                reflection_state=bad,
                encoding_state=bad,
                framework_context=bad,
            )
            self.assertEqual(plan["input_location"], "UNKNOWN", repr(bad))
            self.assertEqual(plan["output_context"], "UNKNOWN", repr(bad))
            self.assertEqual(plan["reflection_state"], "UNKNOWN",
                             repr(bad))
            self.assertEqual(plan["encoding_state"], "UNKNOWN",
                             repr(bad))
            self.assertEqual(plan["framework_context"], "UNKNOWN",
                             repr(bad))

    def test_lowercase_normalized(self):
        plan = analyzer.analyze_xss_context(
            input_location="query",
            output_context="dom",
            reflection_state="reflected",
            encoding_state="none_observed",
            framework_context="react",
        )
        self.assertEqual(plan["input_location"], "QUERY")
        self.assertEqual(plan["output_context"], "DOM")
        self.assertEqual(plan["reflection_state"], "REFLECTED")
        self.assertEqual(plan["encoding_state"], "NONE_OBSERVED")
        self.assertEqual(plan["framework_context"], "REACT")

    def test_confidence_mapping(self):
        cases = (
            ({}, "UNKNOWN"),
            ({"input_location": "QUERY"}, "LOW"),
            ({"input_location": "QUERY", "output_context": "HTML"}, "LOW"),
            ({"input_location": "QUERY", "output_context": "HTML",
              "reflection_state": "REFLECTED"}, "MEDIUM"),
            ({"input_location": "QUERY", "output_context": "HTML",
              "reflection_state": "REFLECTED",
              "encoding_state": "PARTIAL"}, "MEDIUM"),
            ({"input_location": "QUERY", "output_context": "HTML",
              "reflection_state": "REFLECTED",
              "encoding_state": "PARTIAL",
              "framework_context": "GENERIC"}, "HIGH"),
        )
        for kwargs, expected in cases:
            plan = analyzer.analyze_xss_context(**kwargs)
            self.assertEqual(plan["context_confidence"], expected,
                             repr(kwargs))

    def test_context_is_known(self):
        self.assertFalse(analyzer.context_is_known(None))
        self.assertFalse(analyzer.context_is_known({}))
        self.assertTrue(
            analyzer.context_is_known({"input_location": "QUERY"})
        )

    def test_deterministic_output(self):
        kwargs = {
            "input_location": "QUERY",
            "output_context": "HTML",
            "reflection_state": "REFLECTED",
        }
        first = analyzer.analyze_xss_context(**kwargs)
        second = analyzer.analyze_xss_context(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = analyzer.analyze_xss_context(
            input_location="QUERY", output_context="DOM"
        )
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            analyzer.analyze_xss_context()["research_only"], True
        )
        with self.assertRaises(ValidationError):
            schema.XSSContextAnalysisPlan(research_only=False)

    def test_schema_rejects_bad_values_and_extra_fields(self):
        base = {
            "input_location": "QUERY",
            "output_context": "HTML",
            "reflection_state": "REFLECTED",
            "encoding_state": "PARTIAL",
            "framework_context": "GENERIC",
            "context_confidence": "HIGH",
        }
        for key, value in (
            ("input_location", "PATH"),
            ("output_context", "CSS"),
            ("reflection_state", "MAYBE"),
            ("encoding_state", "SOMETIMES"),
            ("framework_context", "SVELTE"),
            ("context_confidence", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.XSSContextAnalysisPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.XSSContextAnalysisPlan(**base, payload="x")

    def test_schema_forces_rule_version(self):
        plan = schema.XSSContextAnalysisPlan(
            rule_version="r99-9",
            input_location="QUERY",
        )
        self.assertEqual(plan.rule_version, "r39-2")

    def test_no_payload_fields(self):
        plan = analyzer.analyze_xss_context(
            input_location="QUERY", output_context="HTML"
        )
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "input_location", "output_context",
             "reflection_state", "encoding_state", "framework_context",
             "context_confidence", "research_only"},
        )
        for key in ("payload", "execution", "sink", "source", "http"):
            self.assertNotIn(key, plan)

    def test_exact_rule_version(self):
        self.assertEqual(
            analyzer.XSS_CONTEXT_ANALYZER_RULE_VERSION, "r39-2"
        )
        self.assertEqual(
            analyzer.analyze_xss_context()["rule_version"], "r39-2"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
