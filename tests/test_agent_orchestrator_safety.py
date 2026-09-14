"""tests/test_agent_orchestrator_safety.py — Stage R52 safety tests.

Deterministic, offline safety tests for the agent orchestrator:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  database or LLM SDK imports in R52
- no direct provider import/instantiation; the R51 bridge is the only
  provider-facing surface and only through its structured API
- no recursive orchestration and no dynamic code loading
- advisory is opt-in and defaults to the deterministic mock provider
- no real provider call during any test (guarded transport)
- no secrets in orchestration output
- R39-R50 specialists gain no network capability

No real API calls, no network, no LLM, no subprocess, no sockets, no browser,
no SQL, no database, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.llm_provider import MockLLMProvider
from ai.providers import BRIDGE_KEYS
from ai.providers.http_transport import UrllibHttpTransport
from ai.providers.provider_registry import select_provider


ROOT = Path(__file__).resolve().parents[1]

R52_MODULES = (
    "ai/schemas/agent_orchestrator_registry.py",
    "ai/schemas/agent_orchestrator_context.py",
    "ai/schemas/agent_orchestrator_policy.py",
    "ai/schemas/agent_orchestrator_result.py",
    "ai/knowledge/specialist_registry.py",
    "ai/knowledge/specialist_eligibility.py",
    "ai/knowledge/orchestration_policy.py",
    "ai/knowledge/specialist_invoker.py",
    "ai/knowledge/agent_orchestrator.py",
)

SPECIALIST_MODULE_PREFIXES = (
    "xss_",
    "ssrf_",
    "sqli_",
    "idor_bola_",
    "jwt_authentication_",
    "oauth_",
    "api_security_",
    "cve_research_",
    "security_agent_",
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
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "importlib.",
    "socket.",
    "urllib.",
    "requests.",
    "httpx.",
    "sqlite3.",
    "sqlalchemy.",
    "psycopg2.",
    "pymysql.",
)

FORBIDDEN_PROVIDER_MODULES = (
    "ai.providers.openrouter_provider",
    "ai.providers.openai_provider",
    "ai.providers.provider_registry",
    "ai.providers.real_provider",
    "ai.providers.http_transport",
)

FORBIDDEN_PROVIDER_NAMES = (
    "OpenRouterProvider",
    "OpenAIProvider",
    "RealAdvisoryProvider",
    "UrllibHttpTransport",
    "select_provider",
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
    attributes = set()
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
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)
    return imports, full_modules, calls, attributes


def xss_context():
    return {
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "encoding_state": "NONE_OBSERVED",
    }


class TestStaticSafety(unittest.TestCase):
    def test_no_forbidden_imports_or_calls(self):
        for relative in R52_MODULES:
            imports, _, calls, _ = scan_module(relative)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_forbidden_provider_imports(self):
        for relative in R52_MODULES:
            _, full_modules, _, _ = scan_module(relative)
            for module in FORBIDDEN_PROVIDER_MODULES:
                self.assertNotIn(module, full_modules, relative)

    def test_no_provider_constructors_or_selection_in_r52_source(self):
        for relative in R52_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for name in FORBIDDEN_PROVIDER_NAMES:
                self.assertNotIn(name, source, f"{relative}: {name}")

    def test_only_orchestrator_references_the_r51_bridge(self):
        bridge_modules = []
        for relative in R52_MODULES:
            _, full_modules, _, _ = scan_module(relative)
            if "ai.providers.advisory_bridge" in full_modules:
                bridge_modules.append(relative)
        self.assertEqual(
            bridge_modules, ["ai/knowledge/agent_orchestrator.py"]
        )

    def test_no_network_urls_in_r52(self):
        for relative in R52_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R52_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_no_recursive_orchestration(self):
        source = (ROOT / "ai/knowledge/agent_orchestrator.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and (
                node.name == "orchestrate_research"
            ):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and (
                        isinstance(child.func, ast.Name)
                        and child.func.id == "orchestrate_research"
                    ):
                        self.fail("orchestrate_research calls itself")

    def test_no_dynamic_code_loading(self):
        for relative in R52_MODULES:
            imports, _, calls, _ = scan_module(relative)
            self.assertNotIn("importlib", imports, relative)
            self.assertEqual(
                calls & {"__import__", "eval", "exec", "compile", "open"},
                set(),
                relative,
            )

    def test_no_subprocess_or_shell_or_scanner_imports(self):
        for relative in R52_MODULES:
            imports, _, _, _ = scan_module(relative)
            self.assertNotIn("subprocess", imports)
            self.assertNotIn("os", imports)
            for scanner in ("selenium", "playwright", "nuclei", "sqlmap"):
                self.assertNotIn(scanner, imports, relative)

    def test_specialists_gain_no_network_or_provider_capability(self):
        knowledge_modules = []
        schema_modules = []
        for path in sorted((ROOT / "ai" / "knowledge").glob("*.py")):
            if path.name.startswith(SPECIALIST_MODULE_PREFIXES):
                knowledge_modules.append(
                    path.relative_to(ROOT).as_posix()
                )
        for path in sorted((ROOT / "ai" / "schemas").glob("*.py")):
            if path.name.startswith(SPECIALIST_MODULE_PREFIXES):
                schema_modules.append(path.relative_to(ROOT).as_posix())
        self.assertTrue(knowledge_modules)
        self.assertTrue(schema_modules)
        for relative in knowledge_modules + schema_modules:
            imports, full_modules, _, _ = scan_module(relative)
            self.assertEqual(imports & FORBIDDEN_MODULES, set(), relative)
            for provider_module in FORBIDDEN_PROVIDER_MODULES:
                self.assertNotIn(provider_module, full_modules, relative)
            self.assertNotIn("ai.providers.advisory_bridge", full_modules,
                             relative)

    def test_orchestrator_public_api_has_no_credentials(self):
        import inspect

        from ai.knowledge.agent_orchestrator import orchestrate_research

        parameters = set(
            inspect.signature(orchestrate_research).parameters
        )
        for forbidden in (
            "api_key",
            "credential",
            "credentials",
            "token",
            "secret",
            "password",
            "authorization",
        ):
            self.assertNotIn(forbidden, parameters)


class TestAdvisoryBoundary(unittest.TestCase):
    def test_advisory_disabled_never_touches_the_bridge(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.export_real_llm_advisory"
        ) as bridge:
            orchestrate_research(research_context=xss_context())
        bridge.assert_not_called()

    def test_advisory_enabled_defaults_to_mock_provider(self):
        calls = []

        def recording_select(explicit_kind, **kwargs):
            calls.append(explicit_kind)
            return select_provider(explicit_kind, **kwargs)

        with mock.patch(
            "ai.providers.advisory_bridge.select_provider",
            side_effect=recording_select,
        ):
            result = orchestrate_research(
                research_context=xss_context(),
                policy={"advisory_enabled": True},
            )
        self.assertEqual(result["advisory_result"]["provider_state"], "OK")
        self.assertEqual(calls, ["MOCK"])

    def test_no_real_transport_is_used(self):
        def exploding_send(self, spec):
            raise AssertionError("real transport must not be used")

        with mock.patch.object(
            UrllibHttpTransport, "send", exploding_send
        ):
            result = orchestrate_research(
                research_context=xss_context(),
                policy={"advisory_enabled": True},
                advisory_provider=None,
            )
        self.assertEqual(result["advisory_result"]["provider_state"], "OK")

    def test_credentials_never_cross_the_provider_boundary(self):
        secret = "Authorization: Bearer sk-live-secret-value-123456"
        captured = {}

        class CapturingProvider(MockLLMProvider):
            def complete(self, request=None):
                captured["request"] = request
                return super().complete(request)

        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
            security_agent_input={
                "research_context": {"raw": secret},
                "authorization_context": {"header": secret},
            },
            advisory_provider=CapturingProvider(),
        )
        serialized_request = json.dumps(captured.get("request"), sort_keys=True)
        self.assertNotIn(secret, serialized_request)
        self.assertNotIn("sk-live-secret-value", serialized_request)
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))
        self.assertEqual(result["advisory_result"]["provider_state"], "OK")


class TestOutputSafety(unittest.TestCase):
    def test_advisory_envelope_is_bounded(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
        )
        advisory = result["advisory_result"]
        self.assertEqual(set(advisory.keys()), set(BRIDGE_KEYS))

    def test_secrets_never_appear_in_output(self):
        secret = "sk-not-a-real-secret-0123456789abcdef"
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
            security_agent_input={
                "authorization_context": {"note": secret},
            },
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, serialized)

    def test_no_finding_like_output_is_produced(self):
        result = orchestrate_research(research_context=xss_context())
        serialized = json.dumps(result, sort_keys=True).upper()
        for marker in FORBIDDEN_CLAIM_MARKERS:
            self.assertNotIn(marker, serialized)
        self.assertNotIn("FINDINGS_SUMMARY", serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
