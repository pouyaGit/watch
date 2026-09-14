"""tests/test_llm_advisory_validator.py — Stage R45.6 tests.

Deterministic, offline tests for the advisory response validator:

- valid response validation and deterministic format checks
- forbidden output category detection (confirm / exploit / execute /
  payload / attack planning)
- forbidden mode, research_only and determinism enforcement
- mode, identity and source-reference agreement with the request
- reject without sanitizing; diagnostics preserved
- R45 AST safety scan

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import ast
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.knowledge.llm_advisory_export import export_llm_advisory
from ai.knowledge.llm_advisory_input import build_llm_advisory_input
from ai.knowledge.llm_advisory_request_builder import (
    build_llm_advisory_request,
)
from ai.knowledge.llm_advisory_validator import (
    AdvisoryValidationError,
    advisory_safety_state,
    detect_forbidden_claims,
    require_valid_advisory_response,
    validate_advisory_response,
    validate_advisory_result,
)
from ai.knowledge.llm_provider import MockLLMProvider
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.schemas.llm_advisory_policy import MAX_ADVISORY_TEXT_LEN


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
        "agent_category": "XSS",
        "status": "COMPLETED",
        "confidence": "HIGH",
        "findings_summary": "NO_FINDINGS",
        "evidence_summary": "EVIDENCE_NONE",
        "limitations": ["NO_EXECUTION_PERFORMED"],
        "research_only": True,
    }
    base.update(over)
    return base


def good_pair():
    signals = extract_learning_signals(
        classify_research_feedback_events(
            [
                build_research_feedback_event(
                    source_agent="sa-" + "a" * 16,
                    source_category="XSS",
                    outcome_type="EVIDENCE_OBSERVATION",
                    observed_issue="ISSUE_MISSING_EVIDENCE_REQUIREMENT",
                )
            ]
        )
    )
    advisory_input = build_llm_advisory_input(
        evaluation_result=evaluate_agent_result(r38_result()),
        learning_signals=signals,
    )
    request = build_llm_advisory_request(advisory_input)
    response = MockLLMProvider().complete(request)
    return request, response


def codes(validation):
    return [
        violation["violation_code"]
        for violation in validation["violations"]
    ]


class TestLLMAdvisoryValidator(unittest.TestCase):
    def test_valid_response_passes(self):
        request, response = good_pair()
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "PASS")
        self.assertEqual(validation["violations"], [])
        self.assertEqual(validation["violation_count"], 0)
        self.assertIs(validation["research_only"], True)
        self.assertIs(validation["deterministic"], True)
        self.assertEqual(validation["rule_version"], "r45-6")

    def test_missing_required_fields_rejected(self):
        request, response = good_pair()
        without_summary = dict(response)
        without_summary.pop("summary")
        validation = validate_advisory_response(
            without_summary, request
        )
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("MISSING_REQUIRED_FIELD", codes(validation))
        self.assertEqual(
            validate_advisory_response(None, request)[
                "validation_state"
            ],
            "REJECTED",
        )

    def test_forbidden_advisory_mode_rejected(self):
        request, response = good_pair()
        response["advisory_mode"] = "EXPLOITATION"
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("FORBIDDEN_ADVISORY_MODE", codes(validation))

    def test_vulnerability_confirmation_rejected(self):
        request, response = good_pair()
        response["summary"] = "The vulnerability is confirmed."
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn(
            "VULNERABILITY_CONFIRMATION_CLAIM", codes(validation)
        )

    def test_exploit_language_rejected(self):
        request, response = good_pair()
        response["summary"] = "Exploitation was successful on the endpoint."
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("EXPLOIT_CONFIRMATION_CLAIM", codes(validation))
        response["summary"] = "The target was successfully exploited."
        self.assertIn(
            "EXPLOIT_CONFIRMATION_CLAIM",
            codes(validate_advisory_response(response, request)),
        )

    def test_execution_instruction_rejected(self):
        request, response = good_pair()
        response["insights"][0]["text"] = "Execute this command to continue."
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("EXECUTION_INSTRUCTION", codes(validation))

    def test_payload_content_rejected(self):
        request, response = good_pair()
        response["recommendations"][0]["text"] = (
            "Send this payload to the endpoint."
        )
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("PAYLOAD_CONTENT", codes(validation))
        response["summary"] = "payload: <script>alert(1)</script>"
        self.assertIn(
            "PAYLOAD_CONTENT",
            codes(validate_advisory_response(response, request)),
        )

    def test_exploitation_guidance_rejected(self):
        request, response = good_pair()
        response["recommendations"][0]["text"] = (
            "Generate an exploit for the target."
        )
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("EXPLOITATION_GUIDANCE", codes(validation))

    def test_attack_planning_rejected(self):
        request, response = good_pair()
        response["summary"] = "Bypass authentication using the login form."
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("ATTACK_PLANNING", codes(validation))
        response["summary"] = "Step 1: attack the login form."
        self.assertIn(
            "ATTACK_PLANNING",
            codes(validate_advisory_response(response, request)),
        )

    def test_detect_forbidden_claims_helper(self):
        found = detect_forbidden_claims("The vulnerability is confirmed.")
        self.assertIn(
            ("VULNERABILITY_CONFIRMATION_CLAIM", "SAFETY"), found
        )
        self.assertEqual(
            detect_forbidden_claims(
                "Research confidence remains bounded by evidence state."
            ),
            [],
        )
        self.assertEqual(detect_forbidden_claims(""), [])

    def test_research_only_and_determinism_enforced(self):
        request, response = good_pair()
        response["research_only"] = False
        validation = validate_advisory_response(response, request)
        self.assertIn("RESEARCH_ONLY_FALSE", codes(validation))
        response["research_only"] = True
        response["deterministic"] = False
        validation = validate_advisory_response(response, request)
        self.assertIn("NON_DETERMINISTIC_OUTPUT", codes(validation))

    def test_mode_identity_and_reference_mismatches(self):
        request, response = good_pair()
        response["advisory_mode"] = "SUMMARY"
        self.assertIn(
            "ADVISORY_MODE_MISMATCH",
            codes(validate_advisory_response(response, request)),
        )
        response["advisory_mode"] = request["advisory_mode"]
        response["advisory_id"] = "adv-" + "f" * 16
        self.assertIn(
            "ADVISORY_ID_MISMATCH",
            codes(validate_advisory_response(response, request)),
        )
        response["advisory_id"] = request["advisory_id"]
        response["source_refs"] = [{"layer": "R42", "reference": "r99-9"}]
        self.assertIn(
            "UNKNOWN_SOURCE_REFERENCE",
            codes(validate_advisory_response(response, request)),
        )

    def test_unbounded_text_rejected(self):
        request, response = good_pair()
        response["summary"] = "x" * (MAX_ADVISORY_TEXT_LEN + 1)
        self.assertIn(
            "UNBOUNDED_TEXT",
            codes(validate_advisory_response(response, request)),
        )

    def test_nondeterministic_output_rejected(self):
        request, response = good_pair()
        response["timestamp"] = "now"
        self.assertIn(
            "NON_DETERMINISTIC_OUTPUT",
            codes(validate_advisory_response(response, request)),
        )

    def test_validation_is_deterministic(self):
        request, response = good_pair()
        first = validate_advisory_response(response, request)
        second = validate_advisory_response(response, request)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_unsupported_provider_kind_rejected(self):
        request, response = good_pair()
        response["provider_kind"] = "OPENAI"
        validation = validate_advisory_response(response, request)
        self.assertIn(
            "UNSUPPORTED_PROVIDER_KIND", codes(validation)
        )

    def test_validation_is_read_only_and_rejects_not_sanitizes(self):
        request, response = good_pair()
        response["summary"] = "The vulnerability is confirmed."
        snapshot = copy.deepcopy(response)
        validation = validate_advisory_response(response, request)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertEqual(response, snapshot)
        self.assertEqual(response["summary"],
                         "The vulnerability is confirmed.")

    def test_require_valid_raises_with_preserved_diagnostics(self):
        request, response = good_pair()
        require_valid_advisory_response(response, request)
        response["summary"] = "Exploitation was successful."
        with self.assertRaises(AdvisoryValidationError) as caught:
            require_valid_advisory_response(response, request)
        validation = caught.exception.validation
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn(
            "EXPLOIT_CONFIRMATION_CLAIM", codes(validation)
        )

    def test_validate_exported_result(self):
        result = export_llm_advisory(
            evaluation_result=evaluate_agent_result(r38_result())
        )
        validation = validate_advisory_result(result)
        self.assertEqual(validation["validation_state"], "PASS")
        tampered = copy.deepcopy(result)
        tampered["summary"] = "The vulnerability is confirmed."
        self.assertEqual(
            validate_advisory_result(tampered)["validation_state"],
            "REJECTED",
        )

    def test_rejected_result_must_not_contain_content(self):
        bad = {
            "rule_version": "r45-5",
            "advisory_rule_version": "r45-5",
            "advisory_id": "adv-" + "0" * 16,
            "advisory_mode": "SUMMARY",
            "summary": "leftover content",
            "insights": [],
            "recommendations": [],
            "limitations": [],
            "safety_state": "FAILED",
            "validation_state": "REJECTED",
            "validation_diagnostics": [
                {
                    "rule_version": "r45-6",
                    "violation_code": "PAYLOAD_CONTENT",
                    "category": "CONTENT",
                    "severity": "HIGH",
                    "field": "summary",
                }
            ],
            "research_only": True,
            "deterministic": True,
        }
        validation = validate_advisory_result(bad)
        self.assertEqual(validation["validation_state"], "REJECTED")
        self.assertIn("REJECTED_CONTENT_PRESENT", codes(validation))
        bad["summary"] = ""
        bad["validation_diagnostics"] = []
        validation = validate_advisory_result(bad)
        self.assertIn("MISSING_DIAGNOSTICS", codes(validation))

    def test_advisory_safety_state(self):
        passing = {"validation_state": "PASS"}
        rejected = {"validation_state": "REJECTED"}
        self.assertEqual(advisory_safety_state("PASS", passing), "PASS")
        self.assertEqual(
            advisory_safety_state("DEGRADED", passing), "DEGRADED"
        )
        self.assertEqual(
            advisory_safety_state("FAILED", passing), "FAILED"
        )
        self.assertEqual(
            advisory_safety_state("PASS", rejected), "FAILED"
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
