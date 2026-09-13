"""tests/test_sqli_context_analyzer.py — Stage R41.2 tests.

Deterministic, offline tests for the SQLi context analyzer:

- exact closed vocabularies (input, parameter, data flow, query, database,
  handling, type, error, behavioral)
- deterministic classification and malformed-input degradation
- confidence model: parameter-only / database-only / ORM-only low behavior,
  unsafe-construction requirement for HIGH confidence
- possible-input vs observed-unsafe-construction distinction
- JSON serialization, schema validation
- research_only always true, no SQL/database/network behavior

No SQL, no database, no network, no LLM, no subprocess, no sqlmap, no
sockets, no browser, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import sqli_context_analyzer as analyzer
from ai.schemas import sqli_context_analysis as schema


FULL_PARAMETERIZED = {
    "input_location": "QUERY",
    "parameter_type": "STRING",
    "data_flow": "QUERY_BUILDER",
    "query_context": "WHERE",
    "database_context": "POSTGRESQL",
    "input_handling": "PARAMETERIZED",
    "type_handling": "STRONG",
    "error_behavior": "NO_ERROR_OBSERVED",
    "behavioral_signal": "NONE_OBSERVED",
}


class TestSQLIContextAnalyzer(unittest.TestCase):
    def test_input_location_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.INPUT_LOCATIONS),
            {"QUERY", "BODY", "HEADER", "COOKIE", "PATH", "UNKNOWN"},
        )

    def test_parameter_type_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.PARAMETER_TYPES),
            {"STRING", "INTEGER", "BOOLEAN", "SORT", "FILTER", "SEARCH",
             "IDENTIFIER", "UNKNOWN"},
        )

    def test_data_flow_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.DATA_FLOWS),
            {"DIRECT_QUERY", "QUERY_BUILDER", "ORM", "STORED_PROCEDURE",
             "RAW_QUERY", "UNKNOWN"},
        )

    def test_query_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.QUERY_CONTEXTS),
            {"WHERE", "ORDER_BY", "LIMIT", "OFFSET", "SELECT", "INSERT",
             "UPDATE", "DELETE", "UNKNOWN"},
        )

    def test_database_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.DATABASE_CONTEXTS),
            {"MYSQL", "POSTGRESQL", "MSSQL", "SQLITE", "ORACLE",
             "UNKNOWN"},
        )

    def test_input_handling_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.INPUT_HANDLING_STATES),
            {"PARAMETERIZED", "SANITIZED", "ESCAPED", "CONCATENATED",
             "RAW", "UNKNOWN"},
        )

    def test_type_handling_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.TYPE_HANDLING_STATES),
            {"STRONG", "WEAK", "CAST", "NONE_OBSERVED", "UNKNOWN"},
        )

    def test_error_behavior_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.ERROR_BEHAVIORS),
            {"DATABASE_ERROR_OBSERVED", "APPLICATION_ERROR_ONLY",
             "NO_ERROR_OBSERVED", "UNKNOWN"},
        )

    def test_behavioral_signal_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.BEHAVIORAL_SIGNALS),
            {"DIFFERENTIAL", "TIMING_RELEVANT", "BOOLEAN_RELEVANT",
             "NONE_OBSERVED", "UNKNOWN"},
        )

    def test_classification_preserved(self):
        plan = analyzer.analyze_sqli_context(
            input_location="BODY",
            parameter_type="IDENTIFIER",
            data_flow="ORM",
            query_context="ORDER_BY",
            database_context="MYSQL",
            input_handling="CONCATENATED",
            type_handling="WEAK",
            error_behavior="DATABASE_ERROR_OBSERVED",
            behavioral_signal="BOOLEAN_RELEVANT",
        )
        self.assertEqual(plan["input_location"], "BODY")
        self.assertEqual(plan["parameter_type"], "IDENTIFIER")
        self.assertEqual(plan["data_flow"], "ORM")
        self.assertEqual(plan["query_context"], "ORDER_BY")
        self.assertEqual(plan["database_context"], "MYSQL")
        self.assertEqual(plan["input_handling"], "CONCATENATED")
        self.assertEqual(plan["type_handling"], "WEAK")
        self.assertEqual(plan["error_behavior"], "DATABASE_ERROR_OBSERVED")
        self.assertEqual(plan["behavioral_signal"], "BOOLEAN_RELEVANT")

    def test_lowercase_normalized(self):
        plan = analyzer.analyze_sqli_context(
            input_location="query",
            parameter_type="string",
            data_flow="raw_query",
            query_context="where",
            database_context="sqlite",
            input_handling="concatenated",
            type_handling="weak",
            error_behavior="database_error_observed",
            behavioral_signal="differential",
        )
        self.assertEqual(plan["input_location"], "QUERY")
        self.assertEqual(plan["data_flow"], "RAW_QUERY")
        self.assertEqual(plan["database_context"], "SQLITE")
        self.assertEqual(plan["error_behavior"],
                         "DATABASE_ERROR_OBSERVED")

    def test_malformed_values_become_unknown(self):
        for bad in (None, "", "NOPE", 42, ["WHERE"]):
            plan = analyzer.analyze_sqli_context(
                input_location=bad,
                parameter_type=bad,
                data_flow=bad,
                query_context=bad,
                database_context=bad,
                input_handling=bad,
                type_handling=bad,
                error_behavior=bad,
                behavioral_signal=bad,
            )
            for key in (
                "input_location", "parameter_type", "data_flow",
                "query_context", "database_context", "input_handling",
                "type_handling", "error_behavior", "behavioral_signal",
            ):
                self.assertEqual(plan[key], "UNKNOWN", (key, repr(bad)))
            self.assertEqual(plan["context_confidence"], "UNKNOWN")

    def test_parameter_alone_is_low_not_high(self):
        plan = analyzer.analyze_sqli_context(
            input_location="QUERY", parameter_type="STRING"
        )
        self.assertEqual(plan["context_confidence"], "LOW")
        self.assertNotEqual(plan["context_confidence"], "HIGH")
        self.assertTrue(analyzer.sqli_input_possible(plan))
        self.assertFalse(analyzer.strong_construction_observed(plan))

    def test_database_alone_is_unknown(self):
        plan = analyzer.analyze_sqli_context(database_context="ORACLE")
        self.assertEqual(plan["context_confidence"], "UNKNOWN")
        self.assertNotEqual(plan["context_confidence"], "HIGH")

    def test_orm_alone_is_not_high(self):
        plan = analyzer.analyze_sqli_context(data_flow="ORM")
        self.assertNotEqual(plan["context_confidence"], "HIGH")
        self.assertEqual(plan["context_confidence"], "UNKNOWN")

    def test_search_box_alone_not_high(self):
        plan = analyzer.analyze_sqli_context(
            input_location="QUERY", parameter_type="SEARCH"
        )
        self.assertNotEqual(plan["context_confidence"], "HIGH")

    def test_full_parameterized_context_capped_at_medium(self):
        plan = analyzer.analyze_sqli_context(**FULL_PARAMETERIZED)
        self.assertEqual(plan["context_confidence"], "MEDIUM")
        self.assertTrue(analyzer.parameterization_observed(plan))
        self.assertFalse(analyzer.strong_construction_observed(plan))

    def test_full_sanitized_context_capped_at_medium(self):
        context = dict(FULL_PARAMETERIZED)
        context["input_handling"] = "SANITIZED"
        plan = analyzer.analyze_sqli_context(**context)
        self.assertEqual(plan["context_confidence"], "MEDIUM")

    def test_concatenated_handling_enables_high(self):
        context = dict(FULL_PARAMETERIZED)
        context["input_handling"] = "CONCATENATED"
        plan = analyzer.analyze_sqli_context(**context)
        self.assertEqual(plan["context_confidence"], "HIGH")
        self.assertTrue(analyzer.strong_construction_observed(plan))

    def test_raw_query_flow_enables_high(self):
        context = dict(FULL_PARAMETERIZED)
        context["data_flow"] = "RAW_QUERY"
        plan = analyzer.analyze_sqli_context(**context)
        self.assertEqual(plan["context_confidence"], "HIGH")
        self.assertTrue(analyzer.strong_construction_observed(plan))

    def test_strong_construction_with_few_facts_is_medium(self):
        plan = analyzer.analyze_sqli_context(
            input_location="QUERY",
            input_handling="RAW",
            data_flow="DIRECT_QUERY",
            query_context="WHERE",
            parameter_type="INTEGER",
        )
        self.assertEqual(plan["context_confidence"], "MEDIUM")

    def test_confidence_recomputed_for_partial_dict(self):
        self.assertEqual(
            analyzer.sqli_context_confidence_of(
                {"input_location": "QUERY", "parameter_type": "STRING"}
            ),
            "LOW",
        )
        self.assertEqual(
            analyzer.sqli_context_confidence_of({}), "UNKNOWN"
        )
        self.assertEqual(
            analyzer.sqli_context_confidence_of(
                {"input_location": "QUERY", "input_handling": "RAW",
                 "data_flow": "DIRECT_QUERY", "parameter_type": "INTEGER",
                 "query_context": "WHERE", "type_handling": "WEAK",
                 "error_behavior": "NO_ERROR_OBSERVED",
                 "behavioral_signal": "NONE_OBSERVED"}
            ),
            "HIGH",
        )

    def test_strong_construction_requires_evidence(self):
        self.assertFalse(analyzer.strong_construction_observed(None))
        self.assertFalse(
            analyzer.strong_construction_observed(
                {"input_handling": "PARAMETERIZED", "data_flow": "ORM"}
            )
        )
        self.assertTrue(
            analyzer.strong_construction_observed(
                {"input_handling": "CONCATENATED"}
            )
        )
        self.assertTrue(
            analyzer.strong_construction_observed(
                {"data_flow": "RAW_QUERY"}
            )
        )

    def test_parameterization_observed(self):
        self.assertFalse(analyzer.parameterization_observed(None))
        self.assertTrue(
            analyzer.parameterization_observed(
                {"input_handling": "PARAMETERIZED"}
            )
        )

    def test_input_possible(self):
        self.assertFalse(analyzer.sqli_input_possible(None))
        self.assertTrue(
            analyzer.sqli_input_possible({"input_location": "PATH"})
        )
        self.assertTrue(
            analyzer.sqli_input_possible({"parameter_type": "SORT"})
        )

    def test_deterministic_output_and_json(self):
        first = analyzer.analyze_sqli_context(**FULL_PARAMETERIZED)
        second = analyzer.analyze_sqli_context(**FULL_PARAMETERIZED)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            analyzer.analyze_sqli_context()["research_only"], True
        )
        with self.assertRaises(ValidationError):
            schema.SQLIContextAnalysisPlan(research_only=False)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "input_location": "QUERY",
            "parameter_type": "STRING",
            "data_flow": "RAW_QUERY",
            "query_context": "WHERE",
            "database_context": "MYSQL",
            "input_handling": "CONCATENATED",
            "type_handling": "WEAK",
            "error_behavior": "DATABASE_ERROR_OBSERVED",
            "behavioral_signal": "TIMING_RELEVANT",
            "context_confidence": "HIGH",
        }
        for key, value in (
            ("input_location", "FORM"),
            ("parameter_type", "FLOAT"),
            ("data_flow", "MAGIC"),
            ("query_context", "GROUP_BY"),
            ("database_context", "MARIADB"),
            ("input_handling", "TRUSTED"),
            ("type_handling", "LOOSE"),
            ("error_behavior", "MAYBE"),
            ("behavioral_signal", "SOMETIMES"),
            ("context_confidence", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.SQLIContextAnalysisPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SQLIContextAnalysisPlan(**base, payload="' OR 1=1")

    def test_schema_forces_rule_version(self):
        plan = schema.SQLIContextAnalysisPlan(
            rule_version="r99-9", input_location="QUERY"
        )
        self.assertEqual(plan.rule_version, "r41-2")

    def test_no_sql_or_connection_fields(self):
        plan = analyzer.analyze_sqli_context()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "input_location", "parameter_type",
             "data_flow", "query_context", "database_context",
             "input_handling", "type_handling", "error_behavior",
             "behavioral_signal", "context_confidence", "research_only"},
        )
        for key in ("query", "sql", "connection", "dsn", "payload",
                    "response", "database_name"):
            self.assertNotIn(key, plan)

    def test_exact_rule_version(self):
        self.assertEqual(
            analyzer.SQLI_CONTEXT_ANALYZER_RULE_VERSION, "r41-2"
        )
        self.assertEqual(
            analyzer.analyze_sqli_context()["rule_version"], "r41-2"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
