"""tests/test_llm_advisory_input.py — Stage R45.1 tests.

Deterministic, offline tests for the LLM advisory input contract:

- valid advisory input and exact key set
- malformed input handling and structural flags
- extra field rejection and research_only enforcement
- deterministic advisory ids with no runtime identity
- R42/R43/R44 consumption without recomputation
- R45 AST safety scan

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
from ai.knowledge.llm_advisory_input import (
    build_llm_advisory_input,
    derive_llm_advisory_id,
)
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.schemas import llm_advisory_input as schema


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


def r38_result(**over):
    base = {
        "rule_version": "r38-5",
        "agent_id": "sa-" + "a" * 16,
        "agent_category": "SSRF",
        "status": "COMPLETED",
        "confidence": "HIGH",
        "findings_summary": "NO_FINDINGS",
        "evidence_summary": "EVIDENCE_NONE",
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": True,
    }
    base.update(over)
    return base


def feedback_event(category="XSS"):
    return build_research_feedback_event(
        source_agent="sa-" + "a" * 16,
        source_category=category,
        outcome_type="EVIDENCE_OBSERVATION",
        observed_issue="ISSUE_MISSING_EVIDENCE_REQUIREMENT",
    )


def learning_signals():
    return extract_learning_signals(
        classify_research_feedback_events([feedback_event()])
    )


class TestLLMAdvisoryInput(unittest.TestCase):
    def test_key_set_is_exact(self):
        result = build_llm_advisory_input()
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "advisory_id", "source_layer",
             "research_context", "evaluation_summary",
             "collaboration_summary", "learning_signals",
             "governance_state", "safety_state", "limitations",
             "research_only", "structural_flags"},
        )

    def test_valid_advisory_input(self):
        evaluation = evaluate_agent_result(r38_result())
        result = build_llm_advisory_input(
            evaluation_result=evaluation,
            learning_signals=learning_signals(),
            research_context={
                "research_question": "How strong is the evidence?",
                "context_fact_count": 2,
            },
        )
        self.assertEqual(result["rule_version"], "r45-1")
        self.assertEqual(result["source_layer"], "MULTI")
        self.assertTrue(schema.ADVISORY_ID_RE.match(result["advisory_id"]))
        self.assertIs(result["research_only"], True)
        self.assertEqual(result["structural_flags"], [])
        self.assertTrue(result["evaluation_summary"]["present"])
        self.assertEqual(
            result["evaluation_summary"]["overall_score"],
            evaluation["overall_score"],
        )
        self.assertEqual(
            result["evaluation_summary"]["overall_rating"],
            evaluation["overall_rating"],
        )
        self.assertEqual(len(result["learning_signals"]), 1)
        for code in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_VULNERABILITY_CONFIRMATION",
            "NO_EXPLOIT_GENERATION",
            "ADVISORY_ONLY",
        ):
            self.assertIn(code, result["limitations"])

    def test_source_layer_derivation(self):
        evaluation = evaluate_agent_result(r38_result())
        self.assertEqual(
            build_llm_advisory_input(
                evaluation_result=evaluation
            )["source_layer"],
            "R42",
        )
        self.assertEqual(
            build_llm_advisory_input(
                learning_signals=learning_signals()
            )["source_layer"],
            "R44",
        )
        self.assertEqual(
            build_llm_advisory_input()["source_layer"], "UNKNOWN"
        )

    def test_explicit_source_layer_and_invalid_layer(self):
        result = build_llm_advisory_input(source_layer="R42")
        self.assertEqual(result["source_layer"], "R42")
        malformed = build_llm_advisory_input(source_layer="NOPE")
        self.assertIn(
            schema.FLAG_UNKNOWN_SOURCE_LAYER,
            malformed["structural_flags"],
        )

    def test_deterministic_advisory_id(self):
        first = build_llm_advisory_input(
            learning_signals=learning_signals()
        )
        second = build_llm_advisory_input(
            learning_signals=learning_signals()
        )
        self.assertEqual(first["advisory_id"], second["advisory_id"])
        other = build_llm_advisory_input(source_layer="R44")
        self.assertNotEqual(first["advisory_id"], other["advisory_id"])
        self.assertEqual(
            first["advisory_id"],
            derive_llm_advisory_id(
                {
                    "source_layer": first["source_layer"],
                    "research_context": first["research_context"],
                    "evaluation_summary": first["evaluation_summary"],
                    "collaboration_summary": first[
                        "collaboration_summary"
                    ],
                    "learning_signals": first["learning_signals"],
                    "governance_state": first["governance_state"],
                    "safety_state": first["safety_state"],
                }
            ),
        )

    def test_supplied_valid_advisory_id_preserved(self):
        supplied = "adv-" + "0" * 16
        result = build_llm_advisory_input(advisory_id=supplied)
        self.assertEqual(result["advisory_id"], supplied)

    def test_invalid_advisory_id_flagged_and_regenerated(self):
        result = build_llm_advisory_input(advisory_id="not-an-id")
        self.assertIn(
            schema.FLAG_INVALID_ADVISORY_ID, result["structural_flags"]
        )
        self.assertTrue(schema.ADVISORY_ID_RE.match(result["advisory_id"]))

    def test_malformed_input_is_flagged(self):
        result = build_llm_advisory_input(
            evaluation_result=["nope"],
            collaboration_result=42,
            learning_signals="nope",
        )
        self.assertIn(
            schema.FLAG_MALFORMED_EVALUATION_SUMMARY,
            result["structural_flags"],
        )
        self.assertIn(
            schema.FLAG_MALFORMED_COLLABORATION_SUMMARY,
            result["structural_flags"],
        )
        self.assertIn(
            schema.FLAG_MALFORMED_LEARNING_SIGNALS,
            result["structural_flags"],
        )
        self.assertFalse(result["evaluation_summary"]["present"])
        self.assertFalse(result["collaboration_summary"]["present"])
        self.assertEqual(result["learning_signals"], [])
        self.assertIs(result["research_only"], True)

    def test_invalid_rule_version_flagged(self):
        evaluation = evaluate_agent_result(r38_result())
        evaluation["rule_version"] = "bad"
        result = build_llm_advisory_input(evaluation_result=evaluation)
        self.assertIn(
            schema.FLAG_INVALID_RULE_VERSION, result["structural_flags"]
        )

    def test_nondeterministic_input_flagged(self):
        evaluation = evaluate_agent_result(r38_result())
        evaluation["timestamp"] = "now"
        result = build_llm_advisory_input(evaluation_result=evaluation)
        self.assertIn(
            schema.FLAG_NON_DETERMINISTIC_INPUT,
            result["structural_flags"],
        )
        serialized = json.dumps(result, sort_keys=True).lower()
        self.assertNotIn("timestamp", serialized)
        self.assertNotIn("uuid", serialized)
        self.assertNotIn("runtime_id", serialized)

    def test_collaboration_summary_counts_preserved(self):
        collaboration = export_multi_agent_collaboration(
            [r38_result(agent_category="XSS")]
        )
        result = build_llm_advisory_input(
            collaboration_result=collaboration
        )
        summary = result["collaboration_summary"]
        self.assertTrue(summary["present"])
        self.assertEqual(
            summary["participant_count"],
            len(collaboration["participating_agents"]),
        )
        self.assertEqual(
            summary["conflict_count"], len(collaboration["conflicts"])
        )
        self.assertEqual(
            summary["reference_rule_version"], "r43-6"
        )

    def test_governance_and_safety_projection(self):
        result = build_llm_advisory_input(
            governance_state="MIXED", safety_state="DEGRADED"
        )
        self.assertEqual(result["governance_state"], "MIXED")
        self.assertEqual(result["safety_state"], "DEGRADED")
        malformed = build_llm_advisory_input(
            governance_state="NOPE", safety_state="NOPE"
        )
        self.assertIn(
            schema.FLAG_INVALID_ENUM_VALUE, malformed["structural_flags"]
        )
        self.assertEqual(malformed["governance_state"], "UNKNOWN")
        self.assertEqual(malformed["safety_state"], "UNKNOWN")

    def test_extra_field_rejection(self):
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(payload="x")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(timestamp="now")

    def test_research_only_enforcement(self):
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(research_only=False)
        self.assertIs(
            schema.LLMAdvisoryInputPlan(research_only=True).research_only,
            True,
        )
        self.assertIs(
            build_llm_advisory_input()["research_only"], True
        )

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(source_layer="NOPE")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(governance_state="NOPE")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(safety_state="NOPE")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryInputPlan(advisory_id="nope")

    def test_schema_forces_rule_version(self):
        plan = schema.LLMAdvisoryInputPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r45-1")

    def test_deterministic_serialization(self):
        runs = [
            build_llm_advisory_input(
                evaluation_result=evaluate_agent_result(r38_result()),
                learning_signals=learning_signals(),
            )
            for _ in range(3)
        ]
        first = json.dumps(runs[0], sort_keys=True)
        for run in runs[1:]:
            self.assertEqual(json.dumps(run, sort_keys=True), first)

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
