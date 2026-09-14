"""tests/test_llm_advisory_policy.py — Stage R45.2 tests.

Deterministic, offline tests for the advisory policy layer:

- closed allowed and forbidden advisory mode vocabularies
- deterministic mode selection precedence
- forbidden mode rejection with preserved diagnostics
- policy model fixed values and validation
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

from ai.knowledge.llm_advisory_policy import (
    AdvisoryPolicyError,
    ForbiddenAdvisoryModeError,
    build_advisory_policy,
    is_allowed_advisory_mode,
    is_forbidden_advisory_mode,
    resolve_advisory_mode,
    select_advisory_mode,
)
from ai.schemas import llm_advisory_policy as schema


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


def advisory_input(
    evaluation=False,
    collaboration=False,
    conflict_count=0,
    signals=0,
):
    return {
        "evaluation_summary": {"present": evaluation},
        "collaboration_summary": {
            "present": collaboration,
            "conflict_count": conflict_count,
        },
        "learning_signals": [
            {"signal_type": "REQUIRE_MORE_EVIDENCE"}
        ] * signals,
    }


class TestLLMAdvisoryPolicy(unittest.TestCase):
    def test_allowed_modes_are_exact(self):
        self.assertEqual(
            schema.ADVISORY_MODES,
            ("SUMMARY", "EXPLANATION", "RESEARCH_PRIORITY",
             "CONFLICT_EXPLANATION", "LEARNING_SUMMARY"),
        )

    def test_forbidden_modes_are_exact(self):
        self.assertEqual(
            schema.FORBIDDEN_ADVISORY_MODES,
            ("EXPLOITATION", "EXECUTION", "PAYLOAD_GENERATION",
             "VULNERABILITY_CONFIRMATION", "ATTACK_PLANNING"),
        )
        self.assertEqual(
            set(schema.ADVISORY_MODES) & set(schema.FORBIDDEN_ADVISORY_MODES),
            set(),
        )

    def test_mode_order_is_deterministic(self):
        self.assertEqual(
            list(schema.ADVISORY_MODE_ORDER.values()),
            list(range(len(schema.ADVISORY_MODES))),
        )

    def test_mode_selection_precedence(self):
        conflict = advisory_input(
            evaluation=True, collaboration=True, conflict_count=1,
            signals=1,
        )
        self.assertEqual(
            select_advisory_mode(conflict), "CONFLICT_EXPLANATION"
        )
        learning = advisory_input(evaluation=True, signals=1)
        self.assertEqual(
            select_advisory_mode(learning), "LEARNING_SUMMARY"
        )
        priority = advisory_input(evaluation=True, collaboration=True)
        self.assertEqual(
            select_advisory_mode(priority), "RESEARCH_PRIORITY"
        )
        explanation = advisory_input(evaluation=True)
        self.assertEqual(
            select_advisory_mode(explanation), "EXPLANATION"
        )
        self.assertEqual(select_advisory_mode({}), "SUMMARY")
        self.assertEqual(select_advisory_mode(None), "SUMMARY")

    def test_mode_selection_is_deterministic(self):
        sample = advisory_input(
            evaluation=True, collaboration=True, conflict_count=2
        )
        runs = [select_advisory_mode(sample) for _ in range(5)]
        self.assertEqual(runs, ["CONFLICT_EXPLANATION"] * 5)

    def test_is_allowed_and_is_forbidden(self):
        for mode in schema.ADVISORY_MODES:
            self.assertTrue(is_allowed_advisory_mode(mode))
            self.assertFalse(is_forbidden_advisory_mode(mode))
        for mode in schema.FORBIDDEN_ADVISORY_MODES:
            self.assertTrue(is_forbidden_advisory_mode(mode))
            self.assertFalse(is_allowed_advisory_mode(mode))
        self.assertFalse(is_allowed_advisory_mode("NOPE"))
        self.assertFalse(is_forbidden_advisory_mode("NOPE"))

    def test_resolve_honors_allowed_mode(self):
        self.assertEqual(
            resolve_advisory_mode({}, requested_mode="EXPLANATION"),
            "EXPLANATION",
        )
        self.assertEqual(
            resolve_advisory_mode(
                advisory_input(evaluation=True), requested_mode="SUMMARY"
            ),
            "SUMMARY",
        )

    def test_resolve_rejects_forbidden_modes(self):
        for mode in schema.FORBIDDEN_ADVISORY_MODES:
            with self.assertRaises(ForbiddenAdvisoryModeError) as caught:
                resolve_advisory_mode({}, requested_mode=mode)
            diagnostic = caught.exception.diagnostic
            self.assertEqual(diagnostic["policy_state"], "FORBIDDEN")
            self.assertEqual(diagnostic["advisory_mode"], mode)
            self.assertEqual(
                diagnostic["allowed_modes"], list(schema.ADVISORY_MODES)
            )

    def test_resolve_rejects_unknown_mode(self):
        with self.assertRaises(AdvisoryPolicyError) as caught:
            resolve_advisory_mode({}, requested_mode="NOT_A_MODE")
        self.assertEqual(
            caught.exception.diagnostic["policy_state"], "UNKNOWN"
        )

    def test_build_advisory_policy(self):
        policy = build_advisory_policy()
        self.assertEqual(
            set(policy.keys()),
            {"rule_version", "allowed_modes", "forbidden_modes",
             "default_mode", "max_insights", "max_recommendations",
             "limitations", "deterministic", "research_only"},
        )
        self.assertEqual(policy["rule_version"], "r45-2")
        self.assertEqual(policy["allowed_modes"], list(schema.ADVISORY_MODES))
        self.assertEqual(
            policy["forbidden_modes"], list(schema.FORBIDDEN_ADVISORY_MODES)
        )
        self.assertEqual(policy["default_mode"], "SUMMARY")
        self.assertIs(policy["deterministic"], True)
        self.assertIs(policy["research_only"], True)
        self.assertEqual(
            json.dumps(build_advisory_policy(), sort_keys=True),
            json.dumps(policy, sort_keys=True),
        )

    def test_policy_model_forces_fixed_values(self):
        plan = schema.LLMAdvisoryPolicyPlan(
            rule_version="r99-9",
            allowed_modes=["EXPLOITATION"],
            forbidden_modes=[],
            limitations=[],
        )
        self.assertEqual(plan.rule_version, "r45-2")
        self.assertEqual(plan.allowed_modes, list(schema.ADVISORY_MODES))
        self.assertEqual(
            plan.forbidden_modes, list(schema.FORBIDDEN_ADVISORY_MODES)
        )
        self.assertEqual(plan.default_mode, "SUMMARY")
        self.assertEqual(plan.max_insights, schema.MAX_INSIGHTS)
        self.assertEqual(
            plan.max_recommendations, schema.MAX_RECOMMENDATIONS
        )
        self.assertEqual(
            plan.limitations, list(schema.ADVISORY_POLICY_LIMITATIONS)
        )

    def test_policy_model_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryPolicyPlan(default_mode="EXPLOITATION")
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryPolicyPlan(max_insights=99)
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryPolicyPlan(max_recommendations=99)
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryPolicyPlan(deterministic=False)
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryPolicyPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.LLMAdvisoryPolicyPlan(unexpected="x")

    def test_policy_no_forbidden_authority(self):
        policy = build_advisory_policy()
        for forbidden in schema.FORBIDDEN_ADVISORY_MODES:
            self.assertNotIn(forbidden, policy["allowed_modes"])
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_VULNERABILITY_CONFIRMATION",
            "NO_EXPLOIT_GENERATION",
            "ADVISORY_ONLY",
        ):
            self.assertIn(limitation, policy["limitations"])

    def test_json_serializable(self):
        self.assertIsInstance(
            json.loads(json.dumps(build_advisory_policy())), dict
        )

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
