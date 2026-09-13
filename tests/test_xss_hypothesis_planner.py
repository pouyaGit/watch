"""tests/test_xss_hypothesis_planner.py — Stage R39.3 tests.

Deterministic, offline tests for the XSS hypothesis planner:

- exact hypothesis-type, signal and limitation vocabularies
- deterministic hypothesis generation from bounded context
- confidence and priority mapping
- DOM-flow and storage-flow branches
- no exploit claims, no vulnerability confirmation
- malformed/empty input handling, JSON serialization
- research_only always true

No network, no DNS, no LLM, no subprocess, no browser, no payloads, no
target interaction, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import xss_hypothesis_planner as planner
from ai.schemas import xss_hypothesis as schema


def hypotheses(**context):
    return planner.plan_xss_hypotheses(context)


class TestXSSHypothesisPlanner(unittest.TestCase):
    def test_hypothesis_types_are_exact(self):
        self.assertEqual(
            set(schema.HYPOTHESIS_TYPES),
            {"REFLECTION_ANALYSIS", "DOM_FLOW_ANALYSIS",
             "STORAGE_FLOW_ANALYSIS", "CONTEXT_REVIEW", "UNKNOWN"},
        )

    def test_limitations_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.XSS_HYPOTHESIS_LIMITATIONS),
            {"NO_EXPLOIT_CLAIM", "NO_VULNERABILITY_CONFIRMATION",
             "HYPOTHESIS_ONLY", "EVIDENCE_REQUIRED",
             "INSUFFICIENT_CONTEXT"},
        )

    def test_no_exploit_claims(self):
        result = hypotheses(
            input_location="QUERY",
            output_context="HTML",
            reflection_state="REFLECTED",
            encoding_state="NONE_OBSERVED",
            framework_context="GENERIC",
        )
        self.assertTrue(result)
        for plan in result:
            self.assertIn("NO_EXPLOIT_CLAIM", plan["limitations"])
            self.assertIn(
                "NO_VULNERABILITY_CONFIRMATION", plan["limitations"]
            )
            self.assertIn("HYPOTHESIS_ONLY", plan["limitations"])
            self.assertIn(
                plan["hypothesis_type"], schema.HYPOTHESIS_TYPES
            )
            self.assertNotIn("CONFIRMED", json.dumps(plan).upper())

    def test_reflected_confidence_mapping(self):
        cases = (
            ("NONE_OBSERVED", "HIGH"),
            ("PARTIAL", "MEDIUM"),
            ("ENCODED", "LOW"),
            ("UNKNOWN", "LOW"),
        )
        for encoding, expected in cases:
            result = hypotheses(
                input_location="QUERY",
                output_context="HTML",
                reflection_state="REFLECTED",
                encoding_state=encoding,
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["hypothesis_type"],
                             "REFLECTION_ANALYSIS")
            self.assertEqual(result[0]["confidence"], expected, encoding)

    def test_priority_matches_confidence(self):
        for encoding in ("NONE_OBSERVED", "PARTIAL", "ENCODED", "UNKNOWN"):
            result = hypotheses(
                reflection_state="REFLECTED",
                encoding_state=encoding,
            )
            self.assertEqual(
                result[0]["priority"], result[0]["confidence"], encoding
            )

    def test_not_observed_storage_flow(self):
        for location in ("BODY", "COOKIE"):
            result = hypotheses(
                input_location=location,
                output_context="HTML",
                reflection_state="NOT_OBSERVED",
            )
            self.assertEqual(
                result[0]["hypothesis_type"], "STORAGE_FLOW_ANALYSIS"
            )
            self.assertEqual(result[0]["confidence"], "LOW")

    def test_not_observed_context_review(self):
        result = hypotheses(
            input_location="QUERY",
            output_context="HTML",
            reflection_state="NOT_OBSERVED",
        )
        self.assertEqual(
            result[0]["hypothesis_type"], "CONTEXT_REVIEW"
        )
        self.assertEqual(result[0]["confidence"], "LOW")

    def test_unknown_reflection_dom_flow(self):
        result = hypotheses(
            input_location="QUERY",
            output_context="DOM",
        )
        self.assertEqual(
            result[0]["hypothesis_type"], "DOM_FLOW_ANALYSIS"
        )
        self.assertEqual(result[0]["confidence"], "UNKNOWN")
        self.assertIn(
            "INSUFFICIENT_CONTEXT", result[0]["limitations"]
        )

    def test_dom_output_adds_secondary_hypothesis(self):
        result = hypotheses(
            input_location="QUERY",
            output_context="DOM",
            reflection_state="REFLECTED",
            encoding_state="NONE_OBSERVED",
            framework_context="GENERIC",
        )
        types = [item["hypothesis_type"] for item in result]
        self.assertEqual(
            types, ["REFLECTION_ANALYSIS", "DOM_FLOW_ANALYSIS"]
        )
        self.assertEqual(result[1]["confidence"], "MEDIUM")
        self.assertEqual(result[1]["priority"], "MEDIUM")

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

    def test_signals_are_closed_and_deduplicated(self):
        result = hypotheses(
            input_location="QUERY",
            output_context="DOM",
            reflection_state="REFLECTED",
            encoding_state="NONE_OBSERVED",
            framework_context="REACT",
        )
        for plan in result:
            signals = plan["supporting_signals"]
            self.assertEqual(len(signals), len(set(signals)))
            for signal in signals:
                self.assertIn(signal, schema.XSS_SIGNALS)
        self.assertIn("FRAMEWORK_PRESENT",
                      result[0]["supporting_signals"])

    def test_malformed_context_is_unknown(self):
        for bad in (None, "", 42, [], "NOPE"):
            result = planner.plan_xss_hypotheses(bad)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["hypothesis_type"], "UNKNOWN")

    def test_deterministic_output(self):
        kwargs = {
            "input_location": "QUERY",
            "output_context": "DOM",
            "reflection_state": "REFLECTED",
            "encoding_state": "PARTIAL",
        }
        first = hypotheses(**kwargs)
        second = hypotheses(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        result = hypotheses(reflection_state="REFLECTED")
        self.assertIsInstance(json.loads(json.dumps(result)), list)

    def test_research_only_always_true(self):
        for plan in hypotheses(reflection_state="REFLECTED"):
            self.assertIs(plan["research_only"], True)
        with self.assertRaises(ValidationError):
            schema.XSSHypothesisPlan(
                hypothesis_type="CONTEXT_REVIEW",
                research_only=False,
            )

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "hypothesis_type": "CONTEXT_REVIEW",
            "supporting_signals": ["OUTPUT_HTML"],
            "confidence": "LOW",
            "priority": "LOW",
            "limitations": ["NO_EXPLOIT_CLAIM"],
        }
        for key, value in (
            ("hypothesis_type", "EXPLOIT_IT"),
            ("confidence", "CERTAIN"),
            ("priority", "URGENT"),
            ("supporting_signals", ["NOT_A_SIGNAL"]),
            ("limitations", ["VULNERABLE"]),
        ):
            with self.assertRaises(ValidationError):
                schema.XSSHypothesisPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.XSSHypothesisPlan(**base, payload="x")

    def test_schema_forces_rule_version(self):
        plan = schema.XSSHypothesisPlan(
            rule_version="r99-9",
            hypothesis_type="CONTEXT_REVIEW",
        )
        self.assertEqual(plan.rule_version, "r39-3")

    def test_no_execution_vocabulary(self):
        blob = json.dumps(
            hypotheses(
                input_location="QUERY",
                output_context="HTML",
                reflection_state="REFLECTED",
                encoding_state="NONE_OBSERVED",
            )
        ).lower()
        for marker in (
            "http://", "https://", "nuclei", "sqlmap", "subprocess",
            "shell", "browser", "fuzzer", "worker", "scheduler",
        ):
            self.assertNotIn(marker, blob)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.XSS_HYPOTHESIS_PLANNER_RULE_VERSION, "r39-3"
        )
        self.assertEqual(
            hypotheses()[0]["rule_version"], "r39-3"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
