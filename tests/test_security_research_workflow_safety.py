"""tests/test_security_research_workflow_safety.py — Stage R59 safety tests.

Deterministic, offline safety tests for the R59 end-to-end workflow:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  DNS, database, LLM provider, dynamic loading, randomness, UUID or
  wall-clock imports/calls; no URLs
- no dangerous public-API parameters and no autonomous modification helpers
- runtime proof that the workflow never opens sockets or spawns processes
- output never asserts execution, exploitation or confirmation and never
  emits an executed-like workflow state
- upstream R38-R58 contracts are unchanged and never carry R59 keys
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

from ai.knowledge.security_research_workflow import (
    advance_security_research_workflow,
    build_security_research_workflow,
    build_security_research_workflow_summary,
    determine_next_workflow_action,
    export_security_research_workflow,
)
from ai.schemas.security_research_workflow import (
    SecurityResearchWorkflowRequestPlan,
)
from ai.schemas.security_research_workflow_result import (
    FORBIDDEN_STATES,
    SecurityResearchWorkflowResultPlan,
)
from ai.schemas.workflow_next_action import WorkflowNextActionPlan
from ai.schemas.workflow_stage import WorkflowStagePlan
from tests.test_security_research_workflow import ChainArtifacts

ROOT = Path(__file__).resolve().parents[1]

R59_MODULES = (
    "ai/schemas/security_research_workflow.py",
    "ai/schemas/workflow_stage.py",
    "ai/schemas/workflow_next_action.py",
    "ai/schemas/security_research_workflow_result.py",
    "ai/knowledge/security_research_workflow_rules.py",
    "ai/knowledge/security_research_workflow.py",
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
        for relative in R59_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(imports & FORBIDDEN_MODULES, set(), relative)
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R59_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                for forbidden in FORBIDDEN_PROVIDER_MODULES:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )

    def test_no_network_urls(self):
        for relative in R59_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R59_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_r59_does_not_import_upstream_engines(self):
        for relative in R59_MODULES:
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
        for relative in R59_MODULES:
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
            build_security_research_workflow,
            advance_security_research_workflow,
            determine_next_workflow_action,
            build_security_research_workflow_summary,
            export_security_research_workflow,
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
        for relative in R59_MODULES:
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
        cls.chain = ChainArtifacts()

    def test_no_runtime_network_or_subprocess(self):
        import socket
        import subprocess

        original_socket = socket.socket
        original_popen = subprocess.Popen

        def forbidden(*args, **kwargs):
            raise AssertionError("R59 attempted real execution")

        socket.socket = forbidden
        subprocess.Popen = forbidden
        try:
            result = build_security_research_workflow(
                **self.chain.partial("learning"),
                execution_control_result=self.chain.control_ready,
            )
        finally:
            socket.socket = original_socket
            subprocess.Popen = original_popen
        self.assertEqual(result["workflow_state"], "COMPLETED")
        self.assertFalse(result["execution_performed"])

    def test_output_has_no_executable_keys(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        keys = output_keys(result)
        self.assertEqual(keys & FORBIDDEN_OUTPUT_KEYS, set())

    def test_output_never_asserts_execution_or_confirmation(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_control_result=self.chain.control_ready,
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn('"execution_performed": true', serialized)
        self.assertNotIn('"external_executor_present": true', serialized)
        self.assertNotIn('"vulnerability_confirmed": true', serialized)
        self.assertNotIn('"exploit_authorized": true', serialized)
        self.assertNotIn('"confirmation_state": "CONFIRMED"', serialized)

    def test_no_executed_like_workflow_state(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        for forbidden in FORBIDDEN_STATES:
            self.assertNotEqual(result["workflow_state"], forbidden)
        self.assertIn(
            "WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE",
            result["limitations"],
        )

    def test_next_action_is_advisory(self):
        result = build_security_research_workflow(
            **self.chain.partial("human")
        )
        action = result["next_action"]
        self.assertTrue(action["advisory"])
        self.assertFalse(action["auto_execute"])
        self.assertTrue(action["human_authority_required"])
        self.assertIn(
            "NOT_AN_EXECUTION_INSTRUCTION", action["limitations"]
        )

    def test_models_never_declare_executed_like_states(self):
        from ai.schemas.security_research_workflow_result import (
            WORKFLOW_STATES,
        )
        from ai.schemas.workflow_stage import WORKFLOW_STAGE_STATUSES

        for forbidden in FORBIDDEN_STATES:
            self.assertNotIn(forbidden, WORKFLOW_STATES)
            self.assertNotIn(forbidden, WORKFLOW_STAGE_STATUSES)


class TestUpstreamIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = ChainArtifacts()

    def test_upstream_outputs_never_carry_r59_keys(self):
        artifacts = (
            self.chain.orchestration,
            self.chain.evaluations[0],
            self.chain.collaboration,
            self.chain.feedback,
            self.chain.findings,
            self.chain.correlation,
            self.chain.prioritization,
            self.chain.review,
            self.chain.learning,
            self.chain.control_ready,
        )
        for payload in artifacts:
            for key in (
                "workflow_state",
                "workflow_id",
                "next_action",
                "next_action_reason",
                "completed_stages",
                "blocked_stages",
                "current_stage",
            ):
                self.assertNotIn(key, payload)

    def test_upstream_rule_versions_unchanged(self):
        self.assertEqual(self.chain.orchestration["rule_version"], "r52-6")
        self.assertEqual(self.chain.evaluations[0]["rule_version"], "r42-5")
        self.assertEqual(self.chain.collaboration["rule_version"], "r43-6")
        self.assertEqual(self.chain.feedback["rule_version"], "r52-5")
        self.assertEqual(self.chain.findings["rule_version"], "r53-6")
        self.assertEqual(self.chain.correlation["rule_version"], "r54-2")
        self.assertEqual(self.chain.prioritization["rule_version"], "r55-2")
        self.assertEqual(self.chain.review["rule_version"], "r56-3")
        self.assertEqual(self.chain.learning["rule_version"], "r57-4")
        self.assertEqual(self.chain.control_ready["rule_version"], "r58-4")

    def test_workflow_does_not_mutate_upstream(self):
        snapshots = {
            "orchestration": json.dumps(
                self.chain.orchestration, sort_keys=True
            ),
            "findings": json.dumps(self.chain.findings, sort_keys=True),
            "review": json.dumps(self.chain.review, sort_keys=True),
            "learning": json.dumps(self.chain.learning, sort_keys=True),
            "control": json.dumps(
                self.chain.control_ready, sort_keys=True
            ),
        }
        build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(
            json.dumps(self.chain.orchestration, sort_keys=True),
            snapshots["orchestration"],
        )
        self.assertEqual(
            json.dumps(self.chain.findings, sort_keys=True),
            snapshots["findings"],
        )
        self.assertEqual(
            json.dumps(self.chain.review, sort_keys=True),
            snapshots["review"],
        )
        self.assertEqual(
            json.dumps(self.chain.learning, sort_keys=True),
            snapshots["learning"],
        )
        self.assertEqual(
            json.dumps(self.chain.control_ready, sort_keys=True),
            snapshots["control"],
        )

    def test_backend_does_not_import_r59(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("security_research_workflow", text, str(path))
            self.assertNotIn("workflow_next_action", text, str(path))
            self.assertNotIn("workflow_stage", text, str(path))

    def test_no_deployment_files_reference_r59(self):
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
                            "security_research_workflow", text, str(nested)
                        )
            else:
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn(
                    "security_research_workflow", text, relative
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
