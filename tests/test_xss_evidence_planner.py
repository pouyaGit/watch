"""tests/test_xss_evidence_planner.py — Stage R39.4 tests.

Deterministic, offline tests for the XSS evidence planner:

- exact evidence-item, state and limitation vocabularies
- required evidence items per hypothesis type
- complete / partial / unknown evidence planning states
- malformed and empty input handling
- JSON serialization, schema validation
- research_only always true, evidence planning only (no collection)

No network, no DNS, no LLM, no subprocess, no browser, no payloads, no
target interaction, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import xss_evidence_planner as planner
from ai.knowledge import xss_hypothesis_planner
from ai.schemas import xss_evidence_plan as schema


def evidence(context=None, hypotheses=None):
    return planner.plan_xss_evidence(context, hypotheses)


class TestXSSEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.XSS_EVIDENCE_ITEMS),
            {"REFLECTION_CONTEXT", "OUTPUT_ENCODING_CONTEXT",
             "SINK_CONTEXT", "SOURCE_CONTEXT", "APPLICATION_BEHAVIOR",
             "UNKNOWN"},
        )

    def test_evidence_states_are_exact(self):
        self.assertEqual(
            set(schema.EVIDENCE_STATES),
            {"COMPLETE", "PARTIAL", "UNKNOWN"},
        )

    def test_limitations_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.XSS_EVIDENCE_LIMITATIONS),
            {"NO_COLLECTION_PERFORMED", "EVIDENCE_REQUIRED",
             "INSUFFICIENT_CONTEXT"},
        )

    def test_reflection_analysis_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "HTML",
             "reflection_state": "REFLECTED",
             "encoding_state": "NONE_OBSERVED",
             "framework_context": "GENERIC"},
        )
        self.assertEqual(
            result["evidence_items"],
            ["REFLECTION_CONTEXT", "OUTPUT_ENCODING_CONTEXT"],
        )
        self.assertEqual(result["evidence_state"], "COMPLETE")
        self.assertEqual(result["confidence"], "HIGH")

    def test_dom_flow_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "DOM",
             "reflection_state": "REFLECTED",
             "encoding_state": "NONE_OBSERVED"},
        )
        self.assertIn("SOURCE_CONTEXT", result["evidence_items"])
        self.assertIn("SINK_CONTEXT", result["evidence_items"])

    def test_storage_flow_evidence(self):
        result = evidence(
            {"input_location": "BODY", "output_context": "HTML",
             "reflection_state": "NOT_OBSERVED"},
        )
        self.assertEqual(
            result["evidence_items"],
            ["APPLICATION_BEHAVIOR", "REFLECTION_CONTEXT"],
        )

    def test_context_review_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "HTML",
             "reflection_state": "NOT_OBSERVED"},
        )
        self.assertEqual(
            result["evidence_items"],
            ["OUTPUT_ENCODING_CONTEXT", "SINK_CONTEXT"],
        )

    def test_unknown_evidence_state(self):
        result = evidence()
        self.assertEqual(result["evidence_items"], ["UNKNOWN"])
        self.assertEqual(result["evidence_state"], "UNKNOWN")
        self.assertEqual(result["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", result["limitations"])

    def test_incomplete_evidence_is_partial(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "HTML",
             "reflection_state": "REFLECTED"}
        )
        self.assertEqual(result["evidence_state"], "PARTIAL")
        self.assertEqual(result["confidence"], "LOW")

    def test_partial_planning_for_low_confidence_hypotheses(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "HTML",
             "reflection_state": "REFLECTED",
             "encoding_state": "ENCODED",
             "framework_context": "REACT"},
        )
        self.assertEqual(result["evidence_state"], "PARTIAL")
        self.assertEqual(result["confidence"], "LOW")

    def test_limitations_always_record_no_collection(self):
        for context in (None, {"input_location": "QUERY"}):
            result = evidence(context)
            self.assertIn(
                "NO_COLLECTION_PERFORMED", result["limitations"]
            )
            self.assertIn("EVIDENCE_REQUIRED", result["limitations"])

    def test_items_deduped_across_hypotheses(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "DOM",
             "reflection_state": "REFLECTED",
             "encoding_state": "NONE_OBSERVED",
             "framework_context": "GENERIC"},
        )
        items = result["evidence_items"]
        self.assertEqual(len(items), len(set(items)))
        self.assertEqual(
            items,
            ["REFLECTION_CONTEXT", "OUTPUT_ENCODING_CONTEXT",
             "SOURCE_CONTEXT", "SINK_CONTEXT"],
        )

    def test_malformed_hypotheses_filtered(self):
        result = evidence(
            {"input_location": "QUERY", "output_context": "DOM"},
            ["junk", 42, {"hypothesis_type": "NOPE"}],
        )
        self.assertEqual(result["evidence_items"], ["UNKNOWN"])
        self.assertEqual(result["evidence_state"], "UNKNOWN")

    def test_single_hypothesis_dict_accepted(self):
        hypotheses = xss_hypothesis_planner.plan_xss_hypotheses(
            {"reflection_state": "REFLECTED",
             "encoding_state": "NONE_OBSERVED"}
        )
        result = evidence(
            {"reflection_state": "REFLECTED",
             "encoding_state": "NONE_OBSERVED"},
            hypotheses[0],
        )
        self.assertEqual(
            result["evidence_items"],
            ["REFLECTION_CONTEXT", "OUTPUT_ENCODING_CONTEXT"],
        )

    def test_deterministic_output(self):
        context = {
            "input_location": "QUERY",
            "output_context": "DOM",
            "reflection_state": "REFLECTED",
        }
        first = evidence(context)
        second = evidence(context)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        result = evidence({"input_location": "QUERY"})
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_research_only_always_true(self):
        self.assertIs(evidence()["research_only"], True)
        with self.assertRaises(ValidationError):
            schema.XSSEvidencePlan(research_only=False)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "evidence_items": ["REFLECTION_CONTEXT"],
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
                schema.XSSEvidencePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.XSSEvidencePlan(**base, collection="x")

    def test_schema_forces_rule_version(self):
        plan = schema.XSSEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r39-4")

    def test_no_collection_fields(self):
        result = evidence({"input_location": "QUERY"})
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "evidence_items", "evidence_state",
             "confidence", "limitations", "research_only"},
        )
        for key in ("request", "response", "collection", "http", "payload"):
            self.assertNotIn(key, result)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.XSS_EVIDENCE_PLANNER_RULE_VERSION, "r39-4"
        )
        self.assertEqual(evidence()["rule_version"], "r39-4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
