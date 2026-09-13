"""tests/test_sqli_hypothesis_planner.py — Stage R41.3 tests.

Deterministic, offline tests for the SQLi hypothesis planner:

- exact hypothesis-type, signal and limitation vocabularies
- deterministic hypothesis generation and canonical ordering
- parameterization / ORM / raw-query / stored-procedure branches
- query-context, identifier, type, database, error, boolean/timing signals
- safety flags and no payload/SQL content
- malformed/empty input handling, JSON serialization
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

from ai.knowledge import sqli_hypothesis_planner as planner
from ai.schemas import sqli_hypothesis as schema


def hypotheses(**context):
    return planner.plan_sqli_hypotheses(context)


def types(result):
    return [item["hypothesis_type"] for item in result]


def confidence_of(result, hypothesis_type):
    for item in result:
        if item["hypothesis_type"] == hypothesis_type:
            return item["confidence"]
    return None


class TestSQLIHypothesisPlanner(unittest.TestCase):
    def test_hypothesis_types_are_exact(self):
        self.assertEqual(
            set(schema.HYPOTHESIS_TYPES),
            {"QUERY_CONSTRUCTION_REVIEW", "PARAMETERIZATION_REVIEW",
             "INPUT_HANDLING_REVIEW", "TYPE_HANDLING_REVIEW",
             "ORM_QUERY_REVIEW", "RAW_QUERY_REVIEW",
             "ERROR_SIGNAL_REVIEW", "BOOLEAN_DIFFERENTIAL_REVIEW",
             "TIMING_SIGNAL_REVIEW", "ORDER_BY_INJECTION_REVIEW",
             "IDENTIFIER_HANDLING_REVIEW", "STORED_PROCEDURE_REVIEW",
             "DATABASE_SPECIFIC_REVIEW", "UNKNOWN"},
        )

    def test_limitations_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SQLI_HYPOTHESIS_LIMITATIONS),
            {"NO_EXPLOIT_CLAIM", "NO_VULNERABILITY_CONFIRMATION",
             "HYPOTHESIS_ONLY", "EVIDENCE_REQUIRED",
             "INSUFFICIENT_CONTEXT"},
        )

    def test_safety_flags_on_every_hypothesis(self):
        result = hypotheses(
            input_location="QUERY",
            parameter_type="IDENTIFIER",
            data_flow="RAW_QUERY",
            query_context="ORDER_BY",
            database_context="MYSQL",
            input_handling="CONCATENATED",
            type_handling="NONE_OBSERVED",
            error_behavior="DATABASE_ERROR_OBSERVED",
            behavioral_signal="DIFFERENTIAL",
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
            self.assertEqual(plan["priority"], plan["confidence"])

    def test_construction_and_parameterization_reviews(self):
        result = hypotheses(
            input_location="QUERY",
            input_handling="CONCATENATED",
            data_flow="DIRECT_QUERY",
            parameter_type="STRING",
        )
        self.assertIn("QUERY_CONSTRUCTION_REVIEW", types(result))
        self.assertIn("PARAMETERIZATION_REVIEW", types(result))

    def test_sanitized_input_handling_review(self):
        result = hypotheses(
            input_location="BODY", input_handling="SANITIZED"
        )
        self.assertIn("INPUT_HANDLING_REVIEW", types(result))
        self.assertIn("PARAMETERIZATION_REVIEW", types(result))
        self.assertNotIn("QUERY_CONSTRUCTION_REVIEW", types(result))

    def test_parameterized_review_is_low(self):
        result = hypotheses(
            input_location="QUERY",
            input_handling="PARAMETERIZED",
            data_flow="QUERY_BUILDER",
        )
        self.assertIn("PARAMETERIZATION_REVIEW", types(result))
        self.assertEqual(
            confidence_of(result, "PARAMETERIZATION_REVIEW"), "LOW"
        )

    def test_orm_query_review(self):
        result = hypotheses(
            input_location="QUERY",
            parameter_type="STRING",
            data_flow="ORM",
            database_context="POSTGRESQL",
        )
        self.assertIn("ORM_QUERY_REVIEW", types(result))

    def test_raw_query_review(self):
        result = hypotheses(
            input_location="QUERY", data_flow="RAW_QUERY"
        )
        self.assertIn("RAW_QUERY_REVIEW", types(result))
        self.assertNotIn("ORM_QUERY_REVIEW", types(result))

    def test_stored_procedure_review(self):
        result = hypotheses(
            input_location="BODY", data_flow="STORED_PROCEDURE"
        )
        self.assertIn("STORED_PROCEDURE_REVIEW", types(result))

    def test_query_context_review(self):
        result = hypotheses(input_location="QUERY", query_context="ORDER_BY")
        self.assertIn("ORDER_BY_INJECTION_REVIEW", types(result))

        where = hypotheses(input_location="QUERY", query_context="WHERE")
        self.assertNotIn("ORDER_BY_INJECTION_REVIEW", types(where))

    def test_identifier_handling_review(self):
        result = hypotheses(
            input_location="PATH", parameter_type="IDENTIFIER"
        )
        self.assertIn("IDENTIFIER_HANDLING_REVIEW", types(result))

    def test_type_handling_review(self):
        for state in ("WEAK", "NONE_OBSERVED"):
            result = hypotheses(
                input_location="QUERY", type_handling=state
            )
            self.assertIn("TYPE_HANDLING_REVIEW", types(result), state)
        strong = hypotheses(input_location="QUERY", type_handling="STRONG")
        self.assertNotIn("TYPE_HANDLING_REVIEW", types(strong))

    def test_database_specific_review(self):
        result = hypotheses(
            input_location="QUERY", database_context="MSSQL"
        )
        self.assertIn("DATABASE_SPECIFIC_REVIEW", types(result))

    def test_error_signal_review(self):
        result = hypotheses(
            input_location="QUERY",
            error_behavior="DATABASE_ERROR_OBSERVED",
        )
        self.assertIn("ERROR_SIGNAL_REVIEW", types(result))
        application_only = hypotheses(
            input_location="QUERY",
            error_behavior="APPLICATION_ERROR_ONLY",
        )
        self.assertNotIn("ERROR_SIGNAL_REVIEW", types(application_only))

    def test_boolean_and_timing_reviews(self):
        boolean = hypotheses(
            input_location="QUERY", behavioral_signal="BOOLEAN_RELEVANT"
        )
        self.assertIn("BOOLEAN_DIFFERENTIAL_REVIEW", types(boolean))
        differential = hypotheses(
            input_location="QUERY", behavioral_signal="DIFFERENTIAL"
        )
        self.assertIn(
            "BOOLEAN_DIFFERENTIAL_REVIEW", types(differential)
        )
        timing = hypotheses(
            input_location="QUERY", behavioral_signal="TIMING_RELEVANT"
        )
        self.assertIn("TIMING_SIGNAL_REVIEW", types(timing))
        self.assertNotIn(
            "BOOLEAN_DIFFERENTIAL_REVIEW", types(timing)
        )

    def test_canonical_ordering(self):
        result = hypotheses(
            input_location="QUERY",
            parameter_type="IDENTIFIER",
            data_flow="RAW_QUERY",
            query_context="ORDER_BY",
            database_context="MYSQL",
            input_handling="CONCATENATED",
            type_handling="WEAK",
            error_behavior="DATABASE_ERROR_OBSERVED",
            behavioral_signal="TIMING_RELEVANT",
        )
        self.assertEqual(
            types(result),
            ["QUERY_CONSTRUCTION_REVIEW", "PARAMETERIZATION_REVIEW",
             "TYPE_HANDLING_REVIEW", "RAW_QUERY_REVIEW",
             "ERROR_SIGNAL_REVIEW", "TIMING_SIGNAL_REVIEW",
             "ORDER_BY_INJECTION_REVIEW",
             "IDENTIFIER_HANDLING_REVIEW",
             "DATABASE_SPECIFIC_REVIEW"],
        )

    def test_high_confidence_requires_strong_context(self):
        weak = hypotheses(
            input_location="QUERY",
            parameter_type="STRING",
            data_flow="ORM",
            database_context="MYSQL",
            input_handling="PARAMETERIZED",
        )
        self.assertNotIn("HIGH", [item["confidence"]
                                  for item in weak])
        strong = hypotheses(
            input_location="QUERY",
            parameter_type="STRING",
            data_flow="RAW_QUERY",
            query_context="WHERE",
            database_context="MYSQL",
            input_handling="CONCATENATED",
            type_handling="WEAK",
            error_behavior="NO_ERROR_OBSERVED",
            behavioral_signal="NONE_OBSERVED",
        )
        self.assertIn("HIGH", [item["confidence"] for item in strong])

    def test_signals_are_closed_and_deduplicated(self):
        result = hypotheses(
            input_location="QUERY",
            data_flow="RAW_QUERY",
            input_handling="RAW",
        )
        for plan in result:
            signals = plan["supporting_signals"]
            self.assertEqual(len(signals), len(set(signals)))
            for signal in signals:
                self.assertIn(signal, schema.SQLI_SIGNALS)

    def test_fully_unknown_context(self):
        result = hypotheses()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hypothesis_type"], "UNKNOWN")
        self.assertEqual(result[0]["confidence"], "UNKNOWN")
        self.assertEqual(
            result[0]["supporting_signals"], ["CONTEXT_UNKNOWN"]
        )
        self.assertIn(
            "INSUFFICIENT_CONTEXT", result[0]["limitations"]
        )

    def test_malformed_context_is_unknown(self):
        for bad in (None, "", 42, [], "NOPE"):
            result = planner.plan_sqli_hypotheses(bad)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["hypothesis_type"], "UNKNOWN")

    def test_deterministic_output_and_json(self):
        kwargs = {
            "input_location": "QUERY",
            "data_flow": "RAW_QUERY",
            "input_handling": "CONCATENATED",
        }
        first = hypotheses(**kwargs)
        second = hypotheses(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), list)

    def test_research_only_always_true(self):
        for plan in hypotheses(input_location="QUERY"):
            self.assertIs(plan["research_only"], True)
        with self.assertRaises(ValidationError):
            schema.SQLIHypothesisPlan(
                hypothesis_type="PARAMETERIZATION_REVIEW",
                research_only=False,
            )

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "hypothesis_type": "PARAMETERIZATION_REVIEW",
            "supporting_signals": ["HANDLING_PARAMETERIZED"],
            "confidence": "LOW",
            "priority": "LOW",
            "limitations": ["NO_EXPLOIT_CLAIM"],
        }
        for key, value in (
            ("hypothesis_type", "EXECUTE_SQL"),
            ("confidence", "CERTAIN"),
            ("priority", "URGENT"),
            ("supporting_signals", ["NOT_A_SIGNAL"]),
            ("limitations", ["VULNERABLE"]),
        ):
            with self.assertRaises(ValidationError):
                schema.SQLIHypothesisPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SQLIHypothesisPlan(**base, payload="' OR 1=1")

    def test_schema_forces_rule_version(self):
        plan = schema.SQLIHypothesisPlan(
            rule_version="r99-9",
            hypothesis_type="PARAMETERIZATION_REVIEW",
        )
        self.assertEqual(plan.rule_version, "r41-3")

    def test_no_sql_payload_content(self):
        blob = json.dumps(
            hypotheses(
                input_location="QUERY",
                parameter_type="IDENTIFIER",
                data_flow="RAW_QUERY",
                query_context="ORDER_BY",
                input_handling="CONCATENATED",
                error_behavior="DATABASE_ERROR_OBSERVED",
            )
        ).lower()
        for marker in (
            "' or ", " or 1=1", "union select", "drop table",
            "insert into", "sleep(", "waitfor delay", "sqlmap",
            "concat(",
        ):
            self.assertNotIn(marker, blob)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SQLI_HYPOTHESIS_PLANNER_RULE_VERSION, "r41-3"
        )
        self.assertEqual(hypotheses()[0]["rule_version"], "r41-3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
