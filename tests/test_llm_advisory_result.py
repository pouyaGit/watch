"""tests/test_llm_advisory_result.py — Stage R45.5 tests.

Deterministic, offline tests for the advisory result contract and export:

- exact result key set and advisory rule version
- R42 evaluation integration without recomputation
- R43 collaboration integration without recomputation
- R44 learning signal integration without recomputation
- source reference, provenance and governance preservation
- rejected provider output excluded with diagnostics preserved
- deterministic serialization and repeated execution equality
- R45 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.knowledge.llm_advisory_export import (
    export_llm_advisory,
    run_llm_advisory,
)
from ai.knowledge.llm_provider import MockLLMProvider
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.schemas import llm_advisory_result as schema


ROOT = Path(__file__).resolve().parents[1]

R45_MODULES = (
    "ai/schemas/llm_advisory_input.py",
    "ai/schemas/llm_advisory_policy.py",
    "ai/schemas/llm_provider.py",
    "ai/schemas/llm_advisory_result.py",
    "ai/knowledge/llm_advisory_input.py",
    "ai/knowledge/llm_advisory_policy.py",
    "ai/knowledge/llm_provider.py",
    "ai/knowledge/llm_advisory_request_builder.py",
    "ai/knowledge/llm_advisory_validator.py",
    "ai/knowledge/llm_advisory_export.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "selenium", "playwright", "pyppeteer", "sqlite3",
    "sqlalchemy", "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap",
    "nuclei", "openai", "ollama", "litellm", "anthropic", "openrouter",
    "curl", "pycurl",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "socket.",
    "urllib.",
    "requests.",
    "httpx.",
    "aiohttp.",
    "selenium.",
    "playwright.",
    "sqlite3.",
    "sqlalchemy.",
    "sqlmap.",
    "nuclei.",
    "openai.",
)


def dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_module(relative_path):
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = dotted_name(node.func)
                if name.startswith(FORBIDDEN_CALL_PREFIXES):
                    calls.add(name)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    return imports, calls


AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16


def r38_result(agent_id=AGENT_A, category="XSS", **over):
    base = {
        "rule_version": "r38-5",
        "agent_id": agent_id,
        "agent_category": category,
        "status": "COMPLETED",
        "confidence": "HIGH",
        "findings_summary": "NO_FINDINGS",
        "evidence_summary": "EVIDENCE_NONE",
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": True,
    }
    base.update(over)
    return base


def evaluation_result():
    return evaluate_agent_result(r38_result())


def learning_signals():
    return extract_learning_signals(
        classify_research_feedback_events(
            [
                build_research_feedback_event(
                    source_agent=AGENT_A,
                    source_category="XSS",
                    outcome_type="EVIDENCE_OBSERVATION",
                    observed_issue="ISSUE_MISSING_EVIDENCE_REQUIREMENT",
                )
            ]
        )
    )


def conflict_collaboration():
    return export_multi_agent_collaboration(
        [
            r38_result(AGENT_A, "XSS"),
            r38_result(AGENT_B, "SSRF", confidence="LOW"),
        ]
    )


class UnsafeMockProvider:
    """Test-only provider that returns forbidden advisory content."""

    provider_kind = "MOCK"

    def complete(self, request):
        response = MockLLMProvider().complete(request)
        response["summary"] = "The vulnerability is confirmed."
        return response


class TestLLMAdvisoryResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        result = export_llm_advisory()
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "advisory_rule_version", "advisory_id",
             "advisory_mode", "summary", "insights", "recommendations",
             "source_refs", "provenance", "governance",
             "validation_state", "validation_diagnostics", "safety_state",
             "limitations", "research_only", "deterministic"},
        )
        self.assertEqual(result["rule_version"], "r45-5")
        self.assertEqual(result["advisory_rule_version"], "r45-5")
        self.assertIs(result["research_only"], True)
        self.assertIs(result["deterministic"], True)

    def test_r42_integration_preserves_evaluation(self):
        evaluation = evaluation_result()
        result = export_llm_advisory(evaluation_result=evaluation)
        self.assertEqual(result["advisory_mode"], "EXPLANATION")
        self.assertEqual(
            result["source_refs"],
            [{"layer": "R42", "reference": "r42-5"}],
        )
        self.assertEqual(
            result["provenance"]["source_layers"], ["R42"]
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "PARTIAL"
        )
        insight = [
            item for item in result["insights"]
            if item["insight_code"] == "EVALUATION_STATE"
        ]
        self.assertEqual(len(insight), 1)
        self.assertIn(evaluation["overall_rating"], insight[0]["text"])
        self.assertIn(evaluation["safety_state"], insight[0]["text"])

    def test_r43_integration_preserves_collaboration(self):
        collaboration = conflict_collaboration()
        self.assertGreater(len(collaboration["conflicts"]), 0)
        result = export_llm_advisory(
            collaboration_result=collaboration
        )
        self.assertEqual(result["advisory_mode"], "CONFLICT_EXPLANATION")
        self.assertEqual(
            result["source_refs"],
            [{"layer": "R43", "reference": "r43-6"}],
        )
        collaboration_insight = [
            item for item in result["insights"]
            if item["insight_code"] == "COLLABORATION_STATE"
        ]
        self.assertEqual(len(collaboration_insight), 1)
        self.assertIn(
            str(len(collaboration["participating_agents"])),
            collaboration_insight[0]["text"],
        )
        conflict_insight = [
            item for item in result["insights"]
            if item["insight_code"] == "CONFLICT_STATE"
        ]
        self.assertEqual(len(conflict_insight), 1)
        self.assertIn(
            "CONFIDENCE_CONFLICT", conflict_insight[0]["text"]
        )

    def test_r44_integration_preserves_learning_signals(self):
        signals = learning_signals()
        self.assertTrue(signals)
        result = export_llm_advisory(learning_signals=signals)
        self.assertEqual(result["advisory_mode"], "LEARNING_SUMMARY")
        self.assertEqual(
            result["source_refs"],
            [{"layer": "R44", "reference": "r44-3"}],
        )
        learning_insight = [
            item for item in result["insights"]
            if item["insight_code"] == "LEARNING_STATE"
        ]
        self.assertEqual(len(learning_insight), 1)
        self.assertIn(
            signals[0]["signal_type"], learning_insight[0]["text"]
        )
        self.assertTrue(
            any(
                item["recommendation_code"] == "APPLY_LEARNING_AS_ADVISORY"
                for item in result["recommendations"]
            )
        )

    def test_multi_layer_provenance_complete(self):
        result = export_llm_advisory(
            evaluation_result=evaluation_result(),
            collaboration_result=conflict_collaboration(),
            learning_signals=learning_signals(),
        )
        self.assertEqual(
            result["source_refs"],
            [
                {"layer": "R42", "reference": "r42-5"},
                {"layer": "R43", "reference": "r43-6"},
                {"layer": "R44", "reference": "r44-3"},
            ],
        )
        self.assertEqual(
            result["provenance"]["source_layers"],
            ["R42", "R43", "R44"],
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "COMPLETE"
        )
        self.assertEqual(
            result["advisory_mode"], "CONFLICT_EXPLANATION"
        )

    def test_governance_visibility_preserved(self):
        collaboration = conflict_collaboration()
        result = export_llm_advisory(
            collaboration_result=collaboration
        )
        governance_state = collaboration["governance_summary"][
            "governance_state"
        ]
        self.assertEqual(
            result["governance"]["governance_state"], governance_state
        )
        self.assertIs(
            result["governance"]["reference_present"],
            governance_state != "UNKNOWN",
        )
        explicit = export_llm_advisory(governance_state="MIXED")
        self.assertEqual(
            explicit["governance"]["governance_state"], "MIXED"
        )
        self.assertIs(
            explicit["governance"]["reference_present"], True
        )
        self.assertIs(explicit["governance"]["research_only"], True)

    def test_explicit_safety_state_propagates(self):
        self.assertEqual(
            export_llm_advisory(safety_state="DEGRADED")["safety_state"],
            "DEGRADED",
        )
        self.assertEqual(
            export_llm_advisory(safety_state="FAILED")["safety_state"],
            "FAILED",
        )
        self.assertEqual(
            export_llm_advisory()["safety_state"], "PASS"
        )

    def test_rejected_provider_output_is_excluded(self):
        result = export_llm_advisory(
            evaluation_result=evaluation_result(),
            provider=UnsafeMockProvider(),
        )
        self.assertEqual(result["validation_state"], "REJECTED")
        self.assertEqual(result["summary"], "")
        self.assertEqual(result["insights"], [])
        self.assertEqual(result["recommendations"], [])
        self.assertEqual(result["safety_state"], "FAILED")
        self.assertTrue(result["validation_diagnostics"])
        diagnostic_codes = [
            item["violation_code"]
            for item in result["validation_diagnostics"]
        ]
        self.assertIn(
            "VULNERABILITY_CONFIRMATION_CLAIM", diagnostic_codes
        )
        self.assertEqual(
            result["source_refs"],
            [{"layer": "R42", "reference": "r42-5"}],
        )

    def test_deterministic_serialization(self):
        runs = [
            export_llm_advisory(
                evaluation_result=evaluation_result(),
                collaboration_result=conflict_collaboration(),
                learning_signals=learning_signals(),
            )
            for _ in range(3)
        ]
        first = json.dumps(runs[0], sort_keys=True)
        for run in runs[1:]:
            self.assertEqual(json.dumps(run, sort_keys=True), first)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())
        self.assertNotIn("runtime_id", first.lower())

    def test_repeated_execution_equality(self):
        first = export_llm_advisory(
            learning_signals=learning_signals(),
            research_context={"research_question": "q"},
        )
        second = export_llm_advisory(
            learning_signals=learning_signals(),
            research_context={"research_question": "q"},
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first["advisory_id"], second["advisory_id"]
        )

    def test_export_alias(self):
        evaluation = evaluation_result()
        self.assertEqual(
            json.dumps(
                export_llm_advisory(evaluation_result=evaluation),
                sort_keys=True,
            ),
            json.dumps(
                run_llm_advisory(evaluation_result=evaluation),
                sort_keys=True,
            ),
        )

    def test_result_limitations(self):
        result = export_llm_advisory()
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_VULNERABILITY_CONFIRMATION",
            "NO_EXPLOIT_GENERATION",
            "ADVISORY_ONLY",
            "DETERMINISTIC_MOCK_RESPONSE",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_result_model_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryResultPlan(advisory_mode="EXPLOITATION")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryResultPlan(safety_state="NOPE")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryResultPlan(validation_state="NOPE")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryResultPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryResultPlan(deterministic=False)
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryResultPlan(unexpected="x")

    def test_result_model_forces_rule_versions(self):
        plan = schema.LLMAdvisoryResultPlan(
            rule_version="r99-9", advisory_rule_version="r99-9"
        )
        self.assertEqual(plan.rule_version, "r45-5")
        self.assertEqual(plan.advisory_rule_version, "r45-5")

    def test_json_serializable(self):
        result = export_llm_advisory(
            evaluation_result=evaluation_result()
        )
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R45_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("llm_advisory", backend_source)
        self.assertNotIn("llm_provider", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
