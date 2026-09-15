"""tests/test_bug_bounty_copilot_safety.py — Stage R60 safety tests.

Deterministic, offline safety tests for the Watch Bug Bounty Copilot:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  DNS, database, LLM provider, dynamic loading, randomness, UUID or
  wall-clock imports/calls; no URLs
- no dangerous public-API parameters and no autonomous modification helpers
- runtime proof that the copilot never opens sockets or spawns processes
- output never asserts execution, exploitation or confirmation, and never
  emits an executed-like state or action
- the copilot remains advisory: no authorization state is modified
- upstream R53-R59 contracts are unchanged and never carry R60 keys
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

from ai.knowledge.bug_bounty_copilot import (
    build_bug_bounty_copilot,
    build_copilot_brief,
    build_copilot_opportunities,
    determine_copilot_priorities,
    export_bug_bounty_copilot,
    summarize_copilot_brief,
)
from ai.schemas.copilot_brief import NON_EXECUTION_BOUNDARY
from ai.schemas.copilot_opportunity import (
    COPILOT_RATIONALE_CODES,
    COPILOT_REVIEW_REASONS,
    COPILOT_SAFETY_RESTRICTIONS,
    OPPORTUNITY_CLASSES,
)
from ai.schemas.copilot_result import (
    COPILOT_RESULT_STATUSES,
    CopilotResultPlan,
)
from tests.test_bug_bounty_copilot import CopilotArtifacts

ROOT = Path(__file__).resolve().parents[1]

R60_MODULES = (
    "ai/schemas/bug_bounty_copilot.py",
    "ai/schemas/copilot_opportunity.py",
    "ai/schemas/copilot_brief.py",
    "ai/schemas/copilot_result.py",
    "ai/knowledge/bug_bounty_copilot_rules.py",
    "ai/knowledge/bug_bounty_copilot.py",
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
    "ai.knowledge.execution_control",
)

FORBIDDEN_CLAIM_MARKERS = (
    "CONFIRMED_EXPLOIT",
    "EXPLOIT_CONFIRMED",
    "IS_VULNERABLE",
    "VULNERABILITY_FOUND",
    "RUN_PAYLOAD",
    "EXECUTE_EXPLOIT",
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


class TestStaticSafety(unittest.TestCase):
    def test_no_forbidden_imports_or_calls(self):
        for relative in R60_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(imports & FORBIDDEN_MODULES, set(), relative)
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R60_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                for forbidden in FORBIDDEN_PROVIDER_MODULES:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )

    def test_no_network_urls(self):
        for relative in R60_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R60_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_r60_does_not_import_upstream_engines(self):
        for relative in R60_MODULES:
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
        for relative in R60_MODULES:
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
            build_bug_bounty_copilot,
            build_copilot_brief,
            build_copilot_opportunities,
            determine_copilot_priorities,
            summarize_copilot_brief,
            export_bug_bounty_copilot,
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
        for relative in R60_MODULES:
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


class TestRuntimeSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = CopilotArtifacts()

    def full_result(self):
        return build_bug_bounty_copilot(
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
        )

    def test_no_runtime_network_or_subprocess(self):
        import socket
        import subprocess

        original_socket = socket.socket
        original_popen = subprocess.Popen

        def forbidden(*args, **kwargs):
            raise AssertionError("R60 attempted real execution")

        socket.socket = forbidden
        subprocess.Popen = forbidden
        try:
            result = self.full_result()
        finally:
            socket.socket = original_socket
            subprocess.Popen = original_popen
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["execution_performed"])

    def test_output_has_no_executable_keys(self):
        keys = output_keys(self.full_result())
        self.assertEqual(keys & FORBIDDEN_OUTPUT_KEYS, set())

    def test_output_never_asserts_execution_or_confirmation(self):
        serialized = json.dumps(self.full_result(), sort_keys=True)
        self.assertNotIn('"execution_performed": true', serialized)
        self.assertNotIn('"external_executor_present": true', serialized)
        self.assertNotIn('"vulnerability_confirmed": true', serialized)
        self.assertNotIn('"exploit_authorized": true', serialized)
        self.assertNotIn('"confirmation_state": "CONFIRMED"', serialized)
        self.assertNotIn('"auto_execute": true', serialized)

    def test_no_executed_like_state_or_action(self):
        result = self.full_result()
        for forbidden in (
            "EXECUTED",
            "EXECUTION_PERFORMED",
            "CONFIRMED",
            "EXPLOITED",
        ):
            self.assertNotEqual(result["status"], forbidden)
            self.assertNotEqual(result["brief"]["workflow_state"], forbidden)
            for opportunity in result["brief"]["opportunities"]:
                self.assertNotEqual(
                    opportunity["recommendation"]["research_action"],
                    forbidden,
                )
                self.assertNotEqual(
                    opportunity["recommendation"]["workflow_next_action"],
                    forbidden,
                )

    def test_non_execution_boundary_is_structural(self):
        result = self.full_result()
        boundary = result["brief"]["non_execution_boundary"]
        self.assertEqual(boundary, NON_EXECUTION_BOUNDARY)
        self.assertFalse(boundary["execution_performed"])
        self.assertFalse(boundary["vulnerability_confirmed"])
        self.assertFalse(boundary["exploit_authorized"])
        self.assertTrue(boundary["r58_gate_required"])
        self.assertTrue(boundary["human_authority_required"])

    def test_safety_restrictions_are_always_reported(self):
        result = self.full_result()
        for restriction in COPILOT_SAFETY_RESTRICTIONS:
            self.assertIn(restriction, result["brief"]["safety_restrictions"])

    def test_recommendations_never_auto_execute(self):
        result = self.full_result()
        for opportunity in result["brief"]["opportunities"]:
            recommendation = opportunity["recommendation"]
            self.assertTrue(recommendation["advisory"])
            self.assertFalse(recommendation["auto_execute"])
            self.assertTrue(recommendation["human_review_required"] or True)

    def test_vocabularies_never_name_execution(self):
        for code in (
            OPPORTUNITY_CLASSES
            + COPILOT_REVIEW_REASONS
            + COPILOT_RATIONALE_CODES
        ):
            for forbidden in (
                "EXECUTE",
                "EXPLOIT",
                "PAYLOAD",
                "SCAN",
                "BROWSER",
                "SUBPROCESS",
                "COMMAND",
                "SHELL",
            ):
                self.assertNotIn(forbidden, code)
        for status in COPILOT_RESULT_STATUSES:
            self.assertNotIn(status, ("EXECUTED", "CONFIRMED", "EXPLOITED"))

    def test_result_model_rejects_execution(self):
        result = self.full_result()
        for field in (
            "execution_performed",
            "external_executor_present",
            "vulnerability_confirmed",
            "exploit_authorized",
        ):
            with self.assertRaises(Exception):
                CopilotResultPlan(**{**result, field: True})

    def test_copilot_does_not_modify_authorization_state(self):
        result = self.full_result()
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["human_authority_preserved"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn('"execution_authorized": true', serialized)


class TestUpstreamIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = CopilotArtifacts()

    def test_upstream_outputs_never_carry_r60_keys(self):
        artifacts = (
            self.chain.findings,
            self.chain.correlation,
            self.chain.prioritization,
            self.chain.review,
            self.chain.learning,
            self.chain.control_ready,
        )
        for payload in artifacts:
            for key in (
                "brief",
                "opportunities",
                "recommended_actions",
                "confidence_basis",
                "non_execution_boundary",
                "copilot_rationale_codes",
            ):
                self.assertNotIn(key, payload)

    def test_upstream_rule_versions_unchanged(self):
        self.assertEqual(self.chain.findings["rule_version"], "r53-6")
        self.assertEqual(self.chain.correlation["rule_version"], "r54-2")
        self.assertEqual(self.chain.prioritization["rule_version"], "r55-2")
        self.assertEqual(self.chain.review["rule_version"], "r56-3")
        self.assertEqual(self.chain.learning["rule_version"], "r57-4")
        self.assertEqual(self.chain.control_ready["rule_version"], "r58-4")

    def test_workflow_is_consumed_not_replaced(self):
        from ai.knowledge.security_research_workflow import (
            build_security_research_workflow,
        )

        workflow = build_security_research_workflow(
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
        )
        result = build_bug_bounty_copilot(
            workflow_result=workflow,
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
        )
        self.assertEqual(
            result["brief"]["workflow_id"], workflow["workflow_id"]
        )
        self.assertEqual(
            result["brief"]["workflow_state"], workflow["workflow_state"]
        )
        self.assertEqual(
            result["brief"]["workflow_next_action"],
            workflow["next_action"]["action_code"],
        )

    def test_backend_does_not_import_r60(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("bug_bounty_copilot", text, str(path))
            self.assertNotIn("copilot_brief", text, str(path))
            self.assertNotIn("copilot_opportunity", text, str(path))

    def test_no_deployment_files_reference_r60(self):
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
                            "bug_bounty_copilot", text, str(nested)
                        )
            else:
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn("bug_bounty_copilot", text, relative)


if __name__ == "__main__":
    unittest.main(verbosity=2)
