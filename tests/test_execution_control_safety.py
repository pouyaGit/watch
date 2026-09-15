"""tests/test_execution_control_safety.py — Stage R58 safety tests.

Deterministic, offline safety tests for the R58 controlled execution gate:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  DNS, database, LLM provider, dynamic loading, randomness, UUID or
  wall-clock imports/calls; no URLs
- no dangerous public-API parameters and no autonomous modification helpers
- per-category safety rejection: exploit authorization, vulnerability
  confirmation, payload generation, attack planning, command execution,
  arbitrary code execution, network execution, scanner execution, browser
  automation, subprocess execution, autonomous authorization, policy bypass
  and human-approval bypass
- unsafe requests are never downgraded into safe requests
- output never asserts execution, exploitation or confirmation
- upstream R38-R57 contracts are unchanged and never carry R58 keys
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

from ai.knowledge.continuous_learning import build_continuous_learning_result
from ai.knowledge.execution_control import (
    build_controlled_execution_plan,
    build_execution_request,
    evaluate_execution_control,
    export_execution_control,
    validate_execution_authorization,
)
from ai.schemas.execution_control_result import (
    CONTROL_OUTCOME_DENY,
    SAFETY_REASON_ATTACK_PLANNING,
    SAFETY_REASON_AUTONOMOUS_AUTHORIZATION,
    SAFETY_REASON_BROWSER_AUTOMATION,
    SAFETY_REASON_CODE_EXECUTION,
    SAFETY_REASON_COMMAND_EXECUTION,
    SAFETY_REASON_EXPLOIT_AUTHORIZATION,
    SAFETY_REASON_HUMAN_APPROVAL_BYPASS,
    SAFETY_REASON_NETWORK_EXECUTION,
    SAFETY_REASON_PAYLOAD_GENERATION,
    SAFETY_REASON_POLICY_BYPASS,
    SAFETY_REASON_SCANNER_EXECUTION,
    SAFETY_REASON_SUBPROCESS_EXECUTION,
    SAFETY_REASON_VULNERABILITY_CONFIRMATION,
)
from tests.test_execution_request import (
    ACTION,
    APPROVE,
    FINDING_ONE,
    SCOPE,
    TARGET,
    approval_context,
    decision_for,
    pipeline,
    valid_request,
)

ROOT = Path(__file__).resolve().parents[1]

R58_MODULES = (
    "ai/schemas/execution_request.py",
    "ai/schemas/controlled_execution_authorization.py",
    "ai/schemas/controlled_execution_plan.py",
    "ai/schemas/execution_control_result.py",
    "ai/knowledge/execution_control_rules.py",
    "ai/knowledge/execution_control.py",
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
    "ai.knowledge.continuous_learning",
)

FORBIDDEN_CLAIM_MARKERS = (
    "CONFIRMED_EXPLOIT",
    "EXPLOIT_CONFIRMED",
    "IS_VULNERABLE",
    "VULNERABILITY_FOUND",
    "RUN_PAYLOAD",
    "CREATE_EXPLOIT",
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
    "subprocess",
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


def unsafe_request(**flags):
    raw = {
        "finding_id": FINDING_ONE,
        "action_type": ACTION,
        "action_scope": SCOPE,
        "target_reference": TARGET,
        "purpose": "unsafe claim",
        "requested_by": "HUMAN",
    }
    raw.update(flags)
    return build_execution_request(request=raw)


class TestStaticSafety(unittest.TestCase):
    def test_no_forbidden_imports_or_calls(self):
        for relative in R58_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(imports & FORBIDDEN_MODULES, set(), relative)
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R58_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                for forbidden in FORBIDDEN_PROVIDER_MODULES:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )

    def test_no_network_urls(self):
        for relative in R58_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R58_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_r58_does_not_import_upstream_engines(self):
        for relative in R58_MODULES:
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

    def test_no_wall_clock_or_randomness_helpers(self):
        for relative in R58_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "datetime.now",
                "datetime.utcnow",
                "uuid4",
                "uuid.uuid4",
                "random.",
            ):
                self.assertNotIn(forbidden, source, f"{relative}: {forbidden}")

    def test_public_api_has_no_dangerous_parameters(self):
        for function in (
            build_execution_request,
            validate_execution_authorization,
            build_controlled_execution_plan,
            evaluate_execution_control,
            export_execution_control,
        ):
            parameters = set(inspect.signature(function).parameters)
            for forbidden in (
                "api_key",
                "credential",
                "credentials",
                "token",
                "secret",
                "password",
                "command",
                "payload",
                "script",
                "url",
                "network",
                "scanner",
                "browser",
                "subprocess",
                "shell",
            ):
                self.assertNotIn(forbidden, parameters, function.__name__)

    def test_no_autonomous_self_modification_helpers(self):
        for relative in R58_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for forbidden in (
                "def apply_",
                "def modify_",
                "def update_agent",
                "def update_rule",
                "def set_threshold",
                "def persist_",
                "def execute_",
                "def run_command",
                "def launch_",
                "def scan_target",
            ):
                self.assertNotIn(forbidden, source, relative)


class TestSafetyRejection(unittest.TestCase):
    def assert_safety_reason(self, reasons, expected):
        request = unsafe_request(**{reasons: True})
        self.assertEqual(request["request_state"], "BLOCKED")
        self.assertIn(expected, request["safety_context"]["safety_reasons"])
        result = evaluate_execution_control(request)
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertIn(expected, result["safety_reasons"])
        self.assertFalse(result["execution_authorized"])

    def test_exploit_authorization_rejected(self):
        self.assert_safety_reason(
            "exploit_authorized", SAFETY_REASON_EXPLOIT_AUTHORIZATION
        )

    def test_vulnerability_confirmation_rejected(self):
        self.assert_safety_reason(
            "vulnerability_confirmed",
            SAFETY_REASON_VULNERABILITY_CONFIRMATION,
        )

    def test_payload_generation_rejected(self):
        self.assert_safety_reason(
            "generate_payload", SAFETY_REASON_PAYLOAD_GENERATION
        )

    def test_attack_planning_rejected(self):
        self.assert_safety_reason(
            "attack_plan", SAFETY_REASON_ATTACK_PLANNING
        )

    def test_command_execution_rejected(self):
        self.assert_safety_reason(
            "command", SAFETY_REASON_COMMAND_EXECUTION
        )

    def test_arbitrary_code_execution_rejected(self):
        self.assert_safety_reason(
            "execute_code", SAFETY_REASON_CODE_EXECUTION
        )

    def test_network_execution_rejected(self):
        self.assert_safety_reason(
            "network_execution", SAFETY_REASON_NETWORK_EXECUTION
        )

    def test_scanner_execution_rejected(self):
        self.assert_safety_reason(
            "run_scanner", SAFETY_REASON_SCANNER_EXECUTION
        )

    def test_browser_automation_rejected(self):
        self.assert_safety_reason(
            "browser_automation", SAFETY_REASON_BROWSER_AUTOMATION
        )

    def test_subprocess_rejected(self):
        self.assert_safety_reason(
            "subprocess", SAFETY_REASON_SUBPROCESS_EXECUTION
        )

    def test_autonomous_authorization_rejected(self):
        self.assert_safety_reason(
            "auto_authorize", SAFETY_REASON_AUTONOMOUS_AUTHORIZATION
        )

    def test_policy_bypass_rejected(self):
        self.assert_safety_reason(
            "disable_safety", SAFETY_REASON_POLICY_BYPASS
        )

    def test_human_approval_bypass_rejected(self):
        self.assert_safety_reason(
            "bypass_human", SAFETY_REASON_HUMAN_APPROVAL_BYPASS
        )

    def test_free_text_execution_claims_are_rejected(self):
        request = unsafe_request(purpose="please EXECUTE_EXPLOIT the target")
        self.assertEqual(request["request_state"], "BLOCKED")
        self.assertIn(
            SAFETY_REASON_EXPLOIT_AUTHORIZATION,
            request["safety_context"]["safety_reasons"],
        )

    def test_negated_markers_are_not_false_positives(self):
        request = unsafe_request(
            purpose="NO_NETWORK_EXECUTION; PREVENT_PAYLOAD_GENERATION"
        )
        self.assertEqual(request["request_state"], "REQUESTED")
        self.assertEqual(request["safety_context"]["safety_reasons"], [])

    def test_unsafe_request_is_not_downgraded(self):
        request = unsafe_request(network_execution=True)
        self.assertEqual(request["request_state"], "BLOCKED")
        self.assertNotEqual(request["request_state"], "REQUESTED")
        self.assertIn("UNSAFE_REQUEST", request["request_rejection_codes"])

    def test_safety_reasons_are_closed_and_stable(self):
        request = unsafe_request(network_execution=True)
        first = request["safety_context"]["safety_reasons"]
        second = unsafe_request(
            network_execution=True
        )["safety_context"]["safety_reasons"]
        self.assertEqual(first, second)


class TestOutputSafety(unittest.TestCase):
    def allowed_result(self):
        _, _, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        return evaluate_execution_control(
            valid_request(decision=decision),
            human_review_result=review,
            authorization_context=approval_context(decision),
            preconditions_met=True,
        )

    def test_output_has_no_executable_keys(self):
        keys = output_keys(self.allowed_result())
        self.assertEqual(keys & FORBIDDEN_OUTPUT_KEYS, set())

    def test_output_never_asserts_execution(self):
        serialized = json.dumps(self.allowed_result(), sort_keys=True)
        self.assertNotIn('"execution_performed": true', serialized)
        self.assertNotIn('"external_executor_present": true', serialized)
        self.assertNotIn('"exploit_authorized": true', serialized)
        self.assertNotIn('"vulnerability_confirmed": true', serialized)
        self.assertNotIn('"confirmation_state": "CONFIRMED"', serialized)

    def test_authorization_is_not_execution(self):
        result = self.allowed_result()
        self.assertTrue(result["execution_authorized"])
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["external_executor_present"])
        self.assertIn("AUTHORIZATION_IS_NOT_EXECUTION", result["limitations"])

    def test_blocks_reference_never_serializes_authority(self):
        _, _, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        result = evaluate_execution_control(
            valid_request(decision=decision),
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertFalse(result["execution_authorized"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn('"execution_authorized": true', serialized)

    def test_no_runtime_network_or_subprocess(self):
        import socket
        import subprocess

        original_socket = socket.socket
        original_popen = subprocess.Popen

        def forbidden(*args, **kwargs):
            raise AssertionError("R58 attempted real execution")

        socket.socket = forbidden
        subprocess.Popen = forbidden
        try:
            result = self.allowed_result()
        finally:
            socket.socket = original_socket
            subprocess.Popen = original_popen
        self.assertEqual(result["control_outcome"], "ALLOW")


class TestUpstreamIsolation(unittest.TestCase):
    def test_upstream_outputs_never_carry_r58_keys(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        learning = build_continuous_learning_result(
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        for payload in (correlation, prioritization, review, learning):
            for key in (
                "control_outcome",
                "controlled_execution_plan",
                "execution_control_result",
                "safety_reasons",
                "allow_reasons",
                "block_reasons",
            ):
                self.assertNotIn(key, payload)

    def test_upstream_rule_versions_unchanged(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        learning = build_continuous_learning_result(
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        self.assertEqual(correlation["rule_version"], "r54-2")
        self.assertEqual(prioritization["rule_version"], "r55-2")
        self.assertEqual(review["rule_version"], "r56-3")
        self.assertEqual(learning["rule_version"], "r57-4")

    def test_backend_does_not_import_r58(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("execution_control", text, str(path))
            self.assertNotIn("controlled_execution", text, str(path))
            self.assertNotIn("execution_request", text, str(path))

    def test_no_deployment_files_reference_r58(self):
        for relative in (
            "docker-compose.yml",
            "Dockerfile",
            ".github/workflows",
        ):
            path = ROOT / relative
            if not path.exists():
                continue
            if path.is_dir():
                for nested in path.rglob("*"):
                    if nested.is_file():
                        text = nested.read_text(
                            encoding="utf-8", errors="ignore"
                        )
                        self.assertNotIn(
                            "execution_control", text, str(nested)
                        )
            else:
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn("execution_control", text, relative)


if __name__ == "__main__":
    unittest.main(verbosity=2)
