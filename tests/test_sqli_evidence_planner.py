"""tests/test_sqli_evidence_planner.py — Stage R41.4 tests.

Deterministic, offline tests for the SQLi evidence planner:

- exact evidence-category, state and limitation vocabularies
- required evidence categories per hypothesis type
- complete / partial / unknown evidence planning states
- deduplication and deterministic ordering
- no collection, no SQL, no database, no network behavior
- malformed and empty input handling
- JSON serialization, schema validation
- research_only always true

No SQL, no database, no network, no LLM, no subprocess, no sqlmap, no
sockets, no browser, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import sqli_evidence_planner as planner
from ai.knowledge import sqli_hypothesis_planner
from ai.schemas import sqli_evidence_plan as schema


def evidence(context=None, hypotheses=None):
    return planner.plan_sqli_evidence(context, hypotheses)


class TestSQLIEvidencePlanner(unittest.TestCase):
    def test_evidence_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SQLI_EVIDENCE_ITEMS),
            {"QUERY_CONSTRUCTION", "PARAMETERIZATION",
             "INPUT_VALIDATION", "TYPE_HANDLING", "ORM_QUERY_CONTEXT",
             "RAW_QUERY_CONTEXT", "ERROR_BEHAVIOR", "BOOLEAN_BEHAVIOR",
             "TIMING_BEHAVIOR", "ORDER_BY_CONTEXT",
             "IDENTIFIER_CONTEXT", "STORED_PROCEDURE_CONTEXT",
             "DATABASE_CONTEXT", "APPLICATION_BEHAVIOR", "UNKNOWN"},
        )

    def test_evidence_states_are_exact(self):
        self.assertEqual(
            set(schema.EVIDENCE_STATES),
            {"COMPLETE", "PARTIAL", "UNKNOWN"},
        )

    def test_limitations_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SQLI_EVIDENCE_LIMITATIONS),
            {"NO_COLLECTION_PERFORMED", "NO_SQL_EXECUTION",
             "NO_NETWORK_REQUESTS", "NO_PAYLOAD_GENERATION",
             "EVIDENCE_REQUIRED", "INSUFFICIENT_CONTEXT"},
        )

    def test_construction_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "data_flow": "RAW_QUERY",
             "input_handling": "CONCATENATED"},
        )
        self.assertIn("QUERY_CONSTRUCTION", result["evidence_items"])
        self.assertIn("PARAMETERIZATION", result["evidence_items"])
        self.assertIn("RAW_QUERY_CONTEXT", result["evidence_items"])

    def test_input_validation_evidence(self):
        result = evidence(
            {"input_location": "BODY", "input_handling": "SANITIZED"},
        )
        self.assertIn("INPUT_VALIDATION", result["evidence_items"])

    def test_orm_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "data_flow": "ORM"},
        )
        self.assertIn("ORM_QUERY_CONTEXT", result["evidence_items"])

    def test_stored_procedure_evidence(self):
        result = evidence(
            {"input_location": "QUERY",
             "data_flow": "STORED_PROCEDURE"},
        )
        self.assertIn(
            "STORED_PROCEDURE_CONTEXT", result["evidence_items"]
        )

    def test_type_handling_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "type_handling": "WEAK"},
        )
        self.assertIn("TYPE_HANDLING", result["evidence_items"])

    def test_error_behavior_evidence(self):
        result = evidence(
            {"input_location": "QUERY",
             "error_behavior": "DATABASE_ERROR_OBSERVED"},
        )
        self.assertIn("ERROR_BEHAVIOR", result["evidence_items"])

    def test_boolean_and_timing_evidence(self):
        boolean = evidence(
            {"input_location": "QUERY",
             "behavioral_signal": "BOOLEAN_RELEVANT"},
        )
        self.assertIn("BOOLEAN_BEHAVIOR", boolean["evidence_items"])
        timing = evidence(
            {"input_location": "QUERY",
             "behavioral_signal": "TIMING_RELEVANT"},
        )
        self.assertIn("TIMING_BEHAVIOR", timing["evidence_items"])

    def test_order_by_and_identifier_evidence(self):
        order_by = evidence(
            {"input_location": "QUERY", "query_context": "ORDER_BY"},
        )
        self.assertIn("ORDER_BY_CONTEXT", order_by["evidence_items"])
        identifier = evidence(
            {"input_location": "PATH", "parameter_type": "IDENTIFIER"},
        )
        self.assertIn(
            "IDENTIFIER_CONTEXT", identifier["evidence_items"]
        )

    def test_database_evidence(self):
        result = evidence(
            {"input_location": "QUERY", "database_context": "SQLITE"},
        )
        self.assertIn("DATABASE_CONTEXT", result["evidence_items"])

    def test_unknown_evidence_state(self):
        result = evidence()
        self.assertEqual(result["evidence_items"], ["UNKNOWN"])
        self.assertEqual(result["evidence_state"], "UNKNOWN")
        self.assertEqual(result["confidence"], "UNKNOWN")
        self.assertIn("INSUFFICIENT_CONTEXT", result["limitations"])

    def test_partial_evidence_is_partial(self):
        result = evidence(
            {"input_location": "QUERY", "parameter_type": "STRING"}
        )
        self.assertEqual(result["evidence_state"], "PARTIAL")
        self.assertEqual(result["confidence"], "LOW")

    def test_parameterized_context_never_complete(self):
        result = evidence(
            {"input_location": "QUERY", "parameter_type": "STRING",
             "data_flow": "QUERY_BUILDER", "query_context": "WHERE",
             "database_context": "POSTGRESQL",
             "input_handling": "PARAMETERIZED",
             "type_handling": "STRONG",
             "error_behavior": "NO_ERROR_OBSERVED",
             "behavioral_signal": "NONE_OBSERVED"},
        )
        self.assertNotEqual(result["evidence_state"], "COMPLETE")

    def test_strong_context_is_complete(self):
        result = evidence(
            {"input_location": "QUERY", "parameter_type": "STRING",
             "data_flow": "RAW_QUERY", "query_context": "WHERE",
             "database_context": "POSTGRESQL",
             "input_handling": "CONCATENATED",
             "type_handling": "WEAK",
             "error_behavior": "NO_ERROR_OBSERVED",
             "behavioral_signal": "NONE_OBSERVED"},
        )
        self.assertEqual(result["evidence_state"], "COMPLETE")
        self.assertEqual(result["confidence"], "HIGH")

    def test_limitations_always_record_no_collection(self):
        for context in (None, {"input_location": "QUERY"}):
            result = evidence(context)
            self.assertIn(
                "NO_COLLECTION_PERFORMED", result["limitations"]
            )
            self.assertIn("NO_SQL_EXECUTION", result["limitations"])
            self.assertIn(
                "NO_NETWORK_REQUESTS", result["limitations"]
            )
            self.assertIn(
                "NO_PAYLOAD_GENERATION", result["limitations"]
            )
            self.assertIn("EVIDENCE_REQUIRED", result["limitations"])

    def test_items_deduped_in_canonical_order(self):
        result = evidence(
            {"input_location": "QUERY", "parameter_type": "IDENTIFIER",
             "data_flow": "RAW_QUERY", "query_context": "ORDER_BY",
             "input_handling": "CONCATENATED",
             "type_handling": "WEAK"},
        )
        items = result["evidence_items"]
        self.assertEqual(len(items), len(set(items)))
        self.assertEqual(
            items,
            ["QUERY_CONSTRUCTION", "APPLICATION_BEHAVIOR",
             "PARAMETERIZATION", "TYPE_HANDLING",
             "RAW_QUERY_CONTEXT", "ORDER_BY_CONTEXT",
             "IDENTIFIER_CONTEXT"],
        )

    def test_malformed_hypotheses_filtered(self):
        result = evidence(
            {"input_location": "QUERY"},
            ["junk", 42, {"hypothesis_type": "NOPE"}],
        )
        self.assertEqual(result["evidence_items"], ["UNKNOWN"])
        self.assertEqual(result["evidence_state"], "UNKNOWN")

    def test_single_hypothesis_dict_accepted(self):
        hypotheses = sqli_hypothesis_planner.plan_sqli_hypotheses(
            {"input_location": "QUERY", "data_flow": "ORM"}
        )
        result = evidence(
            {"input_location": "QUERY", "data_flow": "ORM"},
            hypotheses[0],
        )
        self.assertIn("ORM_QUERY_CONTEXT", result["evidence_items"])

    def test_deterministic_output_and_json(self):
        context = {
            "input_location": "QUERY",
            "data_flow": "RAW_QUERY",
            "input_handling": "CONCATENATED",
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
            schema.SQLIEvidencePlan(research_only=False)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "evidence_items": ["QUERY_CONSTRUCTION"],
            "evidence_state": "PARTIAL",
            "confidence": "LOW",
            "limitations": ["NO_COLLECTION_PERFORMED"],
        }
        for key, value in (
            ("evidence_items", ["RUN_QUERY"]),
            ("evidence_state", "DONE"),
            ("confidence", "CERTAIN"),
            ("limitations", ["COLLECTED"]),
        ):
            with self.assertRaises(ValidationError):
                schema.SQLIEvidencePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SQLIEvidencePlan(**base, query="SELECT 1")

    def test_schema_forces_rule_version(self):
        plan = schema.SQLIEvidencePlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r41-4")

    def test_no_collection_fields(self):
        result = evidence({"input_location": "QUERY"})
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "evidence_items", "evidence_state",
             "confidence", "limitations", "research_only"},
        )
        for key in ("query", "sql", "connection", "dsn", "payload",
                    "collection", "request"):
            self.assertNotIn(key, result)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SQLI_EVIDENCE_PLANNER_RULE_VERSION, "r41-4"
        )
        self.assertEqual(evidence()["rule_version"], "r41-4")


if __name__ == "__main__":
    unittest.main(verbosity=2)
