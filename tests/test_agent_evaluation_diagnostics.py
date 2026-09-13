"""tests/test_agent_evaluation_diagnostics.py — Stage R42.4 tests.

Deterministic, offline tests for evaluation diagnostics:

- closed diagnostic catalog completeness
- deterministic construction, deduplication and ordering
- unknown/malformed diagnostic references dropped
- structured diagnostic fields and closed vocabularies
- schema validation
- no payload or exploit instructions in diagnostic text

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_evaluation_diagnostics import (
    build_agent_evaluation_diagnostics,
    collect_evaluation_diagnostics,
)
from ai.schemas import agent_evaluation_diagnostic as schema
from ai.schemas.agent_evaluation_rule import EVALUATION_DIMENSIONS


def raw(code, reference=""):
    return {"diagnostic_code": code, "evidence_reference": reference}


class TestAgentEvaluationDiagnostics(unittest.TestCase):
    def test_catalog_is_complete_and_closed(self):
        self.assertEqual(
            set(schema.DIAGNOSTIC_CATALOG), set(schema.DIAGNOSTIC_CODES)
        )
        for code, entry in schema.DIAGNOSTIC_CATALOG.items():
            dimension, severity, message, hint = entry
            self.assertIn(dimension, EVALUATION_DIMENSIONS, code)
            self.assertIn(severity, schema.DIAGNOSTIC_SEVERITIES, code)
            self.assertTrue(message, code)
            self.assertTrue(hint, code)

    def test_severity_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.DIAGNOSTIC_SEVERITIES),
            {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
        )

    def test_build_full_diagnostics(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [raw("MISSING_REQUIRED_FIELD", "result")]
        )
        self.assertEqual(len(diagnostics), 1)
        entry = diagnostics[0]
        self.assertEqual(entry["diagnostic_code"], "MISSING_REQUIRED_FIELD")
        self.assertEqual(entry["dimension"], "STRUCTURAL_VALIDITY")
        self.assertEqual(entry["severity"], "HIGH")
        self.assertEqual(entry["evidence_reference"], "result")
        self.assertTrue(entry["message"])
        self.assertTrue(entry["remediation_hint"])
        self.assertEqual(entry["rule_version"], "r42-4")

    def test_unknown_and_malformed_dropped(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [
                raw("NOT_A_CODE"),
                "nope",
                42,
                None,
                {"evidence_reference": "x"},
                raw("CONTEXT_TOO_SPARSE"),
            ]
        )
        self.assertEqual(
            [entry["diagnostic_code"] for entry in diagnostics],
            ["CONTEXT_TOO_SPARSE"],
        )

    def test_duplicates_deduped(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [
                raw("UNSUPPORTED_HYPOTHESIS", "hypotheses[0]"),
                raw("UNSUPPORTED_HYPOTHESIS", "hypotheses[0]"),
                raw("UNSUPPORTED_HYPOTHESIS", "hypotheses[1]"),
            ]
        )
        self.assertEqual(len(diagnostics), 2)

    def test_deterministic_ordering(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [
                raw("GOVERNANCE_UNKNOWN", "g"),
                raw("CONTEXT_TOO_SPARSE", "c"),
                raw("CONTEXT_TOO_SPARSE", "a"),
                raw("RESEARCH_ONLY_FALSE", "r"),
                raw("MISSING_REQUIRED_FIELD", "m"),
            ]
        )
        self.assertEqual(
            [
                (entry["diagnostic_code"], entry["evidence_reference"])
                for entry in diagnostics
            ],
            [
                ("MISSING_REQUIRED_FIELD", "m"),
                ("CONTEXT_TOO_SPARSE", "a"),
                ("CONTEXT_TOO_SPARSE", "c"),
                ("RESEARCH_ONLY_FALSE", "r"),
                ("GOVERNANCE_UNKNOWN", "g"),
            ],
        )

    def test_missing_reference_is_empty(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [raw("GOVERNANCE_UNKNOWN")]
        )
        self.assertEqual(diagnostics[0]["evidence_reference"], "")

    def test_collect_from_outcomes(self):
        outcomes = [
            {
                "dimension": "SAFETY_COMPLIANCE",
                "diagnostics": [raw("RESEARCH_ONLY_FALSE", "research_only")],
            },
            {
                "dimension": "CONTEXT_COMPLETENESS",
                "diagnostics": [raw("CONTEXT_TOO_SPARSE", "context")],
            },
            "nope",
        ]
        diagnostics = collect_evaluation_diagnostics(outcomes)
        self.assertEqual(
            [entry["diagnostic_code"] for entry in diagnostics],
            ["CONTEXT_TOO_SPARSE", "RESEARCH_ONLY_FALSE"],
        )

    def test_no_payload_content(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [raw(code) for code in schema.DIAGNOSTIC_CODES]
        )
        blob = json.dumps(diagnostics).lower()
        for marker in (
            "select ", "union ", " or 1=1", "payload", "exploit(",
            "sqlmap", "curl", "http://", "https://", "169.254",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "diagnostic_code": "MISSING_REQUIRED_FIELD",
            "dimension": "STRUCTURAL_VALIDITY",
            "severity": "HIGH",
            "message": "m",
        }
        for key, value in (
            ("diagnostic_code", "NOT_A_CODE"),
            ("dimension", "NOT_A_DIMENSION"),
            ("severity", "SEVERE"),
        ):
            with self.assertRaises(ValidationError):
                schema.AgentEvaluationDiagnosticPlan(
                    **{**base, key: value}
                )
        with self.assertRaises(ValidationError):
            schema.AgentEvaluationDiagnosticPlan(**base, payload="x")

    def test_schema_forces_rule_version(self):
        plan = schema.AgentEvaluationDiagnosticPlan(
            rule_version="r99-9",
            diagnostic_code="GOVERNANCE_UNKNOWN",
            dimension="GOVERNANCE_COMPLETENESS",
            severity="INFO",
            message="m",
        )
        self.assertEqual(plan.rule_version, "r42-4")

    def test_deterministic_output(self):
        items = [
            raw("CONFIDENCE_OVERSTATED", "result_confidence"),
            raw("PROVENANCE_INCOMPLETE", "provenance"),
        ]
        first = build_agent_evaluation_diagnostics(items)
        second = build_agent_evaluation_diagnostics(items)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        diagnostics = build_agent_evaluation_diagnostics(
            [raw("CONTEXT_TOO_SPARSE")]
        )
        self.assertIsInstance(json.loads(json.dumps(diagnostics)), list)

    def test_non_list_input(self):
        self.assertEqual(
            build_agent_evaluation_diagnostics(None), []
        )
        self.assertEqual(build_agent_evaluation_diagnostics({}), [])
        self.assertEqual(collect_evaluation_diagnostics(None), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
