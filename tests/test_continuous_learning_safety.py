"""tests/test_continuous_learning_safety.py — Stage R57 safety tests.

Deterministic, offline safety tests for continuous learning:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  database, LLM provider, dynamic loading, randomness, wall-clock or
  file-system imports/calls; no URLs
- advisory-only invariants: nothing auto-applies, nothing modifies agents,
  rules, thresholds or strategies, nothing authorizes execution
- human decisions are workflow feedback, never truth labels
- safety rejection of forbidden autonomous/execution requests
- no mutation of R42-R56 inputs and no field injection upstream
- R38-R56 contracts are unchanged
- backend/deployment non-integration

No real API calls, no network, no LLM, no subprocess, no sockets, no browser,
no SQL, no database, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import ast
import inspect
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.continuous_learning import (
    aggregate_learning_patterns,
    build_calibration_recommendations,
    build_continuous_learning_result,
    build_learning_signals,
)
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.knowledge.finding_correlation import correlate_findings
from ai.knowledge.human_review import create_human_review
from ai.knowledge.research_prioritization import prioritize, prioritize_findings

from tests.test_continuous_learning import (
    FINDING_ONE,
    AGENT_A,
    diagnostic,
    evaluation,
    finding_intelligence,
)
from tests.test_research_priority import duplicate_findings
from tests.test_research_priority_rules import finding

ROOT = Path(__file__).resolve().parents[1]

R57_MODULES = (
    "ai/schemas/continuous_learning.py",
    "ai/schemas/learning_pattern.py",
    "ai/schemas/calibration_recommendation.py",
    "ai/schemas/continuous_learning_result.py",
    "ai/knowledge/continuous_learning_rules.py",
    "ai/knowledge/continuous_learning.py",
)

FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "http",
    "urllib",
    "requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "pycurl",
    "asyncio",
    "threading",
    "multiprocessing",
    "concurrent",
    "importlib",
    "ctypes",
    "shutil",
    "ssl",
    "os",
    "dns",
    "selenium",
    "playwright",
    "pyppeteer",
    "paramiko",
    "sqlite3",
    "sqlalchemy",
    "psycopg",
    "psycopg2",
    "pymysql",
    "MySQLdb",
    "sqlmap",
    "nuclei",
    "curl",
    "openai",
    "anthropic",
    "litellm",
    "ollama",
    "pkgutil",
    "stevedore",
    "random",
    "uuid",
    "time",
    "datetime",
}

FORBIDDEN_CALLS = {
    "__import__",
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "setattr",
    "delattr",
    "globals",
    "locals",
}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "os.environ",
    "importlib.",
    "socket.",
    "urllib.",
    "requests.",
    "httpx.",
    "sqlite3.",
    "sqlalchemy.",
    "psycopg2.",
    "pymysql.",
    "random.",
    "uuid.",
    "time.",
    "datetime.",
    "sys.modules",
)

FORBIDDEN_PROVIDER_MODULES = (
    "ai.providers",
    "ai.knowledge.llm_provider",
    "ai.knowledge.llm_advisory_export",
)

FORBIDDEN_ENGINE_MODULES = (
    "ai.knowledge.agent_orchestrator",
    "ai.knowledge.finding_builder",
    "ai.knowledge.finding_correlation",
    "ai.knowledge.research_prioritization",
    "ai.knowledge.human_review",
)

FORBIDDEN_CLAIM_MARKERS = (
    "VULNERABILITY_CONFIRMED",
    "CONFIRMED_EXPLOIT",
    "EXPLOIT_CONFIRMED",
    "IS_VULNERABLE",
    "VULNERABILITY_FOUND",
    "EXECUTE_EXPLOIT",
    "RUN_PAYLOAD",
)

FORBIDDEN_OUTPUT_KEYS = {
    "command",
    "commands",
    "payload",
    "payloads",
    "script",
    "shell",
    "execute",
    "attack",
    "exploit",
    "notification",
    "notifications",
    "webhook",
    "url",
    "target_url",
    "apply_strategy",
    "modify_agent",
    "modify_rule",
    "update_threshold",
    "set_threshold",
}


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
    full_modules = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
                full_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
                full_modules.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = dotted_name(node.func)
                if name.startswith(FORBIDDEN_CALL_PREFIXES):
                    calls.add(name)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    return imports, full_modules, calls


def output_keys(payload):
    keys = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            keys.add(str(key).lower())
            keys |= output_keys(value)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            keys |= output_keys(item)
    return keys


class TestStaticSafety(unittest.TestCase):
    def test_no_forbidden_imports_or_calls(self):
        for relative in R57_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R57_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                for forbidden in FORBIDDEN_PROVIDER_MODULES:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )

    def test_no_network_urls(self):
        for relative in R57_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R57_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_r57_does_not_import_engines_or_specialists(self):
        for relative in R57_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                self.assertFalse(
                    module.startswith("ai.knowledge.xss_")
                    or module.startswith("ai.knowledge.ssrf_")
                    or module.startswith("ai.knowledge.sqli")
                    or module.startswith("ai.knowledge.idor_bola_")
                    or module.startswith("ai.knowledge.jwt_authentication_")
                    or module.startswith("ai.knowledge.oauth_")
                    or module.startswith("ai.knowledge.api_security_")
                    or module.startswith("ai.knowledge.cve_research_")
                    or module in FORBIDDEN_ENGINE_MODULES,
                    f"{relative}: {module}",
                )

    def test_public_api_has_no_dangerous_parameters(self):
        for function in (
            build_continuous_learning_result,
            build_learning_signals,
            aggregate_learning_patterns,
            build_calibration_recommendations,
        ):
            parameters = set(inspect.signature(function).parameters)
            for forbidden in (
                "api_key",
                "credential",
                "credentials",
                "token",
                "secret",
                "password",
                "authorization",
                "provider",
                "command",
                "payload",
                "script",
                "url",
            ):
                self.assertNotIn(forbidden, parameters, function.__name__)


class TestAdvisoryInvariants(unittest.TestCase):
    def full_result(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "DEFER",
                }
            ],
        )
        return build_continuous_learning_result(
            evaluation_results=[
                evaluation(
                    diagnostics=[diagnostic("MISSING_EVIDENCE_REQUIREMENT")]
                )
            ],
            finding_intelligence=finding_intelligence([first, second]),
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )

    def test_result_is_advisory_only(self):
        result = self.full_result()
        self.assertTrue(result["advisory"])
        self.assertTrue(result["human_authority"])
        self.assertFalse(result["auto_applies"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["research_only"])
        self.assertTrue(result["deterministic"])

    def test_output_has_no_executable_keys(self):
        result = self.full_result()
        keys = output_keys(result)
        self.assertEqual(keys & FORBIDDEN_OUTPUT_KEYS, set())

    def test_output_never_asserts_execution_or_confirmation(self):
        serialized = json.dumps(self.full_result(), sort_keys=True)
        self.assertNotIn('"execution_authorized": true', serialized)
        self.assertNotIn('"vulnerability_confirmed": true', serialized)
        self.assertNotIn('"auto_applies": true', serialized)
        self.assertNotIn('"modifies_agents": true', serialized)
        self.assertNotIn('"modifies_rules": true', serialized)
        self.assertNotIn('"modifies_thresholds": true', serialized)
        self.assertNotIn('"modifies_strategies": true', serialized)
        self.assertNotIn('"confirmation_state": "CONFIRMED"', serialized)

    def test_every_recommendation_is_advisory(self):
        result = self.full_result()
        self.assertTrue(result["calibration_recommendations"])
        for recommendation in result["calibration_recommendations"]:
            self.assertTrue(recommendation["advisory"])
            self.assertTrue(recommendation["safety_boundary_preserved"])
            self.assertTrue(recommendation["human_authority_preserved"])
            self.assertFalse(recommendation["auto_applies"])
            self.assertFalse(recommendation["modifies_agents"])
            self.assertFalse(recommendation["modifies_rules"])
            self.assertFalse(recommendation["modifies_thresholds"])
            self.assertFalse(recommendation["modifies_strategies"])
            self.assertFalse(recommendation["execution_authorized"])

    def test_every_pattern_is_advisory(self):
        result = self.full_result()
        self.assertTrue(result["patterns"])
        for pattern in result["patterns"]:
            self.assertTrue(pattern["advisory"])
            self.assertFalse(pattern["auto_applies"])
            self.assertFalse(pattern["modifies_agents"])
            self.assertFalse(pattern["modifies_rules"])

    def test_no_autonomous_self_modification_helpers(self):
        for relative in R57_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for forbidden in (
                "def apply_",
                "def modify_",
                "def update_agent",
                "def update_rule",
                "def set_threshold",
                "def persist_",
            ):
                self.assertNotIn(forbidden, source, relative)


class TestHumanDecisionNotTruthLabel(unittest.TestCase):
    def test_approval_keeps_workflow_semantics(self):
        raw = finding("XSS", AGENT_A, finding_id_value=FINDING_ONE)
        correlation = correlate_findings([raw])
        prioritization = prioritize_findings(
            [raw], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                }
            ],
        )
        result = build_continuous_learning_result(
            prioritization_result=prioritization,
            correlation_result=correlation,
            human_review_result=review,
        )
        approvals = [
            signal
            for signal in result["signals"]
            if signal["signal_type"] == "HUMAN_APPROVED_RESEARCH"
        ]
        self.assertEqual(len(approvals), 1)
        signal = approvals[0]
        self.assertEqual(signal["feedback_kind"], "WORKFLOW_FEEDBACK")
        self.assertTrue(signal["workflow_feedback"])
        self.assertFalse(signal["truth_label"])
        self.assertEqual(signal["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(signal["decision_context"]["human_authority"])
        self.assertFalse(
            signal["decision_context"]["vulnerability_confirmed"]
        )
        self.assertFalse(signal["decision_context"]["execution_authorized"])

    def test_reject_does_not_make_a_finding_false(self):
        raw = finding("XSS", AGENT_A, finding_id_value=FINDING_ONE)
        correlation = correlate_findings([raw])
        prioritization = prioritize_findings(
            [raw], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "REJECT"}
            ],
        )
        result = build_continuous_learning_result(
            prioritization_result=prioritization,
            correlation_result=correlation,
            human_review_result=review,
        )
        rejections = [
            signal
            for signal in result["signals"]
            if signal["signal_type"] == "HUMAN_REJECTED_WORKFLOW"
        ]
        self.assertEqual(len(rejections), 1)
        self.assertFalse(rejections[0]["truth_label"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn('"finding_is_false": true', serialized)
        self.assertNotIn('"truth_label": true', serialized)


class TestSafetyRejection(unittest.TestCase):
    def test_unsafe_layer_inputs_are_skipped_and_preserved(self):
        unsafe = evaluation()
        unsafe["execution_authorized"] = True
        result = build_continuous_learning_result(
            evaluation_results=[unsafe]
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["signals"], [])
        self.assertEqual(
            result["skipped_inputs"][0]["reason"], "SAFETY_BLOCKED"
        )
        self.assertTrue(result["errors"])

    def test_forbidden_instruction_text_is_skipped(self):
        result = build_continuous_learning_result(
            feedback_result={
                "rule_version": "r52-5",
                "note": "AUTONOMOUS_EXECUTION: DISABLE_SAFETY",
                "classifications": [],
            }
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(
            result["skipped_inputs"][0]["reason"], "SAFETY_BLOCKED"
        )

    def test_unsafe_input_produces_no_behavior_change(self):
        unsafe = evaluation()
        unsafe["auto_applies"] = True
        result = build_continuous_learning_result(
            evaluation_results=[unsafe]
        )
        for recommendation in result["calibration_recommendations"]:
            self.assertFalse(recommendation["auto_applies"])
        for pattern in result["patterns"]:
            self.assertFalse(pattern["auto_applies"])


class TestContractIsolation(unittest.TestCase):
    def test_upstream_outputs_are_not_mutated(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
            }
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        correlation = correlate_findings(intelligence["findings"])
        prioritization = prioritize_findings(
            intelligence["findings"], correlation_result=correlation
        )
        finding_id = prioritization["ranked_findings"][0]["finding_id"]
        review = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {
                    "finding_id": finding_id,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                }
            ],
        )
        snapshots = {
            "orchestration": json.dumps(orchestration, sort_keys=True),
            "intelligence": json.dumps(intelligence, sort_keys=True),
            "correlation": json.dumps(correlation, sort_keys=True),
            "prioritization": json.dumps(prioritization, sort_keys=True),
            "review": json.dumps(review, sort_keys=True),
        }
        build_continuous_learning_result(
            orchestration_result=orchestration,
            finding_intelligence=intelligence,
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        self.assertEqual(
            json.dumps(orchestration, sort_keys=True),
            snapshots["orchestration"],
        )
        self.assertEqual(
            json.dumps(intelligence, sort_keys=True),
            snapshots["intelligence"],
        )
        self.assertEqual(
            json.dumps(correlation, sort_keys=True),
            snapshots["correlation"],
        )
        self.assertEqual(
            json.dumps(prioritization, sort_keys=True),
            snapshots["prioritization"],
        )
        self.assertEqual(
            json.dumps(review, sort_keys=True), snapshots["review"]
        )

    def test_r55_output_has_no_r57_keys(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize(
            findings=[first, second], correlation_result=correlation
        )
        for key in (
            "signals",
            "patterns",
            "calibration_recommendations",
            "learning_id",
            "auto_applies",
        ):
            self.assertNotIn(key, prioritization)
        self.assertEqual(prioritization["rule_version"], "r55-2")

    def test_r56_output_has_no_r57_keys(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization
        )
        for key in (
            "signals",
            "patterns",
            "calibration_recommendations",
        ):
            self.assertNotIn(key, review)
        self.assertEqual(review["rule_version"], "r56-3")

    def test_upstream_engines_still_work(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        review = create_human_review(
            prioritization_result=prioritization
        )
        self.assertEqual(correlation["rule_version"], "r54-2")
        self.assertEqual(prioritization["rule_version"], "r55-2")
        self.assertEqual(review["rule_version"], "r56-3")

    def test_backend_does_not_import_r57(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("continuous_learning", text, str(path))
            self.assertNotIn("calibration_recommendation", text, str(path))
            self.assertNotIn("learning_pattern", text, str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
