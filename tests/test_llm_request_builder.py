"""tests/test_llm_request_builder.py — Stage R45.4 tests.

Deterministic, offline tests for the advisory request builder:

- deterministic request representation and fingerprints
- advisory policy applied to mode selection
- forbidden and unknown requested modes rejected
- unsupported provider kinds rejected
- no exploitation prompts, credentials or raw runtime data
- source reference and governance preservation
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
from ai.knowledge.llm_advisory_input import build_llm_advisory_input
from ai.knowledge.llm_advisory_policy import (
    ForbiddenAdvisoryModeError,
    AdvisoryPolicyError,
)
from ai.knowledge.llm_advisory_request_builder import (
    ADVISORY_MODE_INSTRUCTIONS,
    advisory_request_fingerprint,
    build_llm_advisory_request,
    collect_advisory_source_refs,
    serialize_advisory_request,
)
from ai.knowledge.llm_provider import UnsupportedProviderError
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.schemas.llm_advisory_policy import ADVISORY_MODES


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


def evaluation_result():
    return evaluate_agent_result(r38_result())


class TestLLMRequestBuilder(unittest.TestCase):
    def test_request_key_set_is_exact(self):
        request = build_llm_advisory_request(build_llm_advisory_input())
        self.assertEqual(
            set(request.keys()),
            {"rule_version", "advisory_id", "advisory_mode",
             "provider_kind", "source_layer", "instruction", "sections",
             "source_refs", "limitations", "research_only",
             "deterministic"},
        )
        self.assertEqual(request["rule_version"], "r45-3")
        self.assertIs(request["research_only"], True)
        self.assertIs(request["deterministic"], True)

    def test_deterministic_request_generation(self):
        advisory_input = build_llm_advisory_input(
            evaluation_result=evaluation_result(),
            learning_signals=learning_signals(),
        )
        first = build_llm_advisory_request(advisory_input)
        second = build_llm_advisory_request(advisory_input)
        self.assertEqual(
            serialize_advisory_request(first),
            serialize_advisory_request(second),
        )
        self.assertEqual(
            advisory_request_fingerprint(first),
            advisory_request_fingerprint(second),
        )
        other = build_llm_advisory_request(
            build_llm_advisory_input(source_layer="R42")
        )
        self.assertNotEqual(
            advisory_request_fingerprint(first),
            advisory_request_fingerprint(other),
        )

    def test_mode_selection_is_applied(self):
        signals_only = build_llm_advisory_request(
            build_llm_advisory_input(learning_signals=learning_signals())
        )
        self.assertEqual(
            signals_only["advisory_mode"], "LEARNING_SUMMARY"
        )
        conflict = build_llm_advisory_request(
            build_llm_advisory_input(
                collaboration_result=conflict_collaboration()
            )
        )
        self.assertEqual(
            conflict["advisory_mode"], "CONFLICT_EXPLANATION"
        )
        explanation = build_llm_advisory_request(
            build_llm_advisory_input(
                evaluation_result=evaluation_result()
            )
        )
        self.assertEqual(explanation["advisory_mode"], "EXPLANATION")
        self.assertEqual(
            build_llm_advisory_request(
                build_llm_advisory_input()
            )["advisory_mode"],
            "SUMMARY",
        )

    def test_requested_allowed_mode_is_honored(self):
        for mode in ADVISORY_MODES:
            request = build_llm_advisory_request(
                build_llm_advisory_input(), requested_mode=mode
            )
            self.assertEqual(request["advisory_mode"], mode)
            self.assertEqual(
                request["instruction"], ADVISORY_MODE_INSTRUCTIONS[mode]
            )

    def test_forbidden_requested_mode_is_rejected(self):
        for mode in (
            "EXPLOITATION",
            "EXECUTION",
            "PAYLOAD_GENERATION",
            "VULNERABILITY_CONFIRMATION",
            "ATTACK_PLANNING",
        ):
            with self.assertRaises(ForbiddenAdvisoryModeError) as caught:
                build_llm_advisory_request(
                    build_llm_advisory_input(), requested_mode=mode
                )
            self.assertEqual(
                caught.exception.diagnostic["advisory_mode"], mode
            )
            self.assertEqual(
                caught.exception.diagnostic["policy_state"], "FORBIDDEN"
            )

    def test_unknown_requested_mode_is_rejected(self):
        with self.assertRaises(AdvisoryPolicyError):
            build_llm_advisory_request(
                build_llm_advisory_input(), requested_mode="NOPE"
            )

    def test_unsupported_provider_is_rejected(self):
        for kind in ("OPENAI", "OPENROUTER", "OLLAMA", "LOCAL", "NOPE"):
            with self.assertRaises(UnsupportedProviderError):
                build_llm_advisory_request(
                    build_llm_advisory_input(), provider_kind=kind
                )

    def test_sections_are_bounded(self):
        request = build_llm_advisory_request(
            build_llm_advisory_input(
                evaluation_result=evaluation_result(),
                learning_signals=learning_signals(),
                research_context={
                    "research_question": "q",
                    "credentials": "should-be-dropped",
                },
            )
        )
        sections = request["sections"]
        self.assertEqual(
            set(sections.keys()),
            {"research_context", "evaluation_summary",
             "collaboration_summary", "learning_signals",
             "governance_state", "safety_state"},
        )
        self.assertEqual(
            set(sections["research_context"].keys()),
            {"research_question", "research_focus", "context_fact_count",
             "source_layers", "research_only"},
        )
        self.assertNotIn("credentials", json.dumps(sections))

    def test_source_refs_preserved(self):
        advisory_input = build_llm_advisory_input(
            evaluation_result=evaluation_result(),
            collaboration_result=conflict_collaboration(),
            learning_signals=learning_signals(),
        )
        request = build_llm_advisory_request(advisory_input)
        self.assertEqual(
            request["source_refs"],
            [
                {"layer": "R42", "reference": "r42-5"},
                {"layer": "R43", "reference": "r43-6"},
                {"layer": "R44", "reference": "r44-3"},
            ],
        )
        self.assertEqual(
            collect_advisory_source_refs(advisory_input),
            request["source_refs"],
        )

    def test_instructions_are_fixed_and_not_exploitation_prompts(self):
        for mode in ADVISORY_MODES:
            instruction = ADVISORY_MODE_INSTRUCTIONS[mode]
            self.assertTrue(instruction)
            lowered = instruction.lower()
            for token in (
                "payload:",
                "attack sequence",
                "execute this",
                "ignore previous",
                "system prompt",
            ):
                self.assertNotIn(token, lowered)

    def test_request_exposes_no_secrets(self):
        request = build_llm_advisory_request(
            build_llm_advisory_input(
                evaluation_result=evaluation_result()
            )
        )
        serialized = serialize_advisory_request(request).lower()
        for token in (
            "api_key", "apikey", "authorization", "bearer ",
            "password", "private key",
        ):
            self.assertNotIn(token, serialized)

    def test_serialize_is_canonical_json(self):
        request = build_llm_advisory_request(
            build_llm_advisory_input(learning_signals=learning_signals())
        )
        self.assertEqual(
            serialize_advisory_request(request),
            json.dumps(
                request, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True,
            ),
        )

    def test_request_model_rejects_bad_values(self):
        from ai.schemas import llm_provider as provider_schema

        with self.assertRaises(ValidationError):
            provider_schema.LLMProviderRequestPlan(
                advisory_mode="EXPLOITATION"
            )
        with self.assertRaises(ValidationError):
            provider_schema.LLMProviderRequestPlan(
                provider_kind="OPENAI"
            )
        with self.assertRaises(ValidationError):
            provider_schema.LLMProviderRequestPlan(research_only=False)
        with self.assertRaises(ValidationError):
            provider_schema.LLMProviderRequestPlan(deterministic=False)
        with self.assertRaises(ValidationError):
            provider_schema.LLMProviderRequestPlan(unexpected="x")

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
