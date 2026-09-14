"""tests/test_llm_provider_safety.py — Stage R51 security tests.

Deterministic, offline security tests for the R51 real provider layer:

- forbidden advisory modes rejected before any provider call
- unsafe provider output rejected by the R45 validator (never sanitized)
- provider output cannot bypass R45 or trigger execution
- API keys / authorization headers / cookies / tokens never cross
- context allowlisting and data minimization
- provider errors are infrastructure-only, never findings
- AST/static isolation: network only in the transport module

No real API calls, no network, no LLM, no subprocess, no sockets, no
browser, no SQL, no database, no payloads, no Mongo writes, no
persistence, no execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.llm_advisory_export import export_llm_advisory
from ai.knowledge.llm_advisory_policy import (
    FORBIDDEN_ADVISORY_MODES,
    AdvisoryPolicyError,
)
from ai.knowledge.llm_provider import MockLLMProvider
from ai.providers import (
    BRIDGE_KEYS,
    export_real_llm_advisory,
    HttpTransport,
    HttpResponseSpec,
)
from ai.providers.http_transport import (
    UrllibHttpTransport,
    _NoRedirectHandler,
)
from ai.providers.provider_errors import ProviderCallError


ROOT = Path(__file__).resolve().parents[1]

SECRET = "not-a-real-provider-credential-1234567890"

PROVIDER_MODULES = (
    "ai/providers/__init__.py",
    "ai/providers/provider_errors.py",
    "ai/providers/http_transport.py",
    "ai/providers/context_allowlist.py",
    "ai/providers/prompt_builder.py",
    "ai/providers/real_provider.py",
    "ai/providers/openrouter_provider.py",
    "ai/providers/openai_provider.py",
    "ai/providers/provider_registry.py",
    "ai/providers/advisory_bridge.py",
)

SPECIALIST_PREFIXES = (
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

NETWORK_MODULES = {
    "urllib", "http", "socket", "ssl", "requests", "httpx", "aiohttp",
    "urllib3", "pycurl",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "socket.",
    "requests.",
    "httpx.",
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


def scan_file(path: Path) -> tuple[set, set, set]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    full_modules = set()
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
    return imports, calls, full_modules


class RecordingTransport(HttpTransport):
    transport_kind = "RECORDING"

    def __init__(self, status=200, content=None):
        self.status = status
        self.content = content
        self.requests = []

    def send(self, spec):
        self.requests.append(spec)
        payload = {
            "choices": [{"message": {"content": self.content or ""}}]
        }
        return HttpResponseSpec(
            status_code=self.status, body_text=json.dumps(payload)
        )


def success_content():
    return json.dumps(
        {
            "summary": "Bounded advisory summary.",
            "insights": [],
            "recommendations": [],
        }
    )


def provider_environ():
    return {
        "OPENROUTER_API_KEY": SECRET,
        "OPENROUTER_MODEL": "vendor/model",
    }


def r38_result():
    return {
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


def run_bridge(**over):
    defaults = {
        "evaluation_result": evaluate_agent_result(r38_result()),
        "provider_kind": "OPENROUTER",
        "transport": RecordingTransport(200, success_content()),
        "environ": provider_environ(),
    }
    defaults.update(over)
    return export_real_llm_advisory(**defaults)


class TestProviderSafety(unittest.TestCase):
    def test_forbidden_advisory_modes_rejected_before_call(self):
        for mode in FORBIDDEN_ADVISORY_MODES:
            transport = RecordingTransport(200, success_content())
            with self.assertRaises(AdvisoryPolicyError):
                run_bridge(
                    requested_mode=mode, transport=transport,
                )
            self.assertEqual(transport.requests, [])
        self.assertEqual(
            set(FORBIDDEN_ADVISORY_MODES),
            {
                "EXPLOITATION",
                "EXECUTION",
                "PAYLOAD_GENERATION",
                "VULNERABILITY_CONFIRMATION",
                "ATTACK_PLANNING",
            },
        )

    def test_unsafe_provider_output_rejected_not_sanitized(self):
        unsafe_texts = (
            "The vulnerability is confirmed.",
            "Exploitation was successful.",
            "Execute this command to proceed.",
            "Send this payload to the endpoint.",
            "Step 1: exploit the login form.",
            "Bypass authentication with this request.",
            "Build an exploit for the target.",
        )
        for text in unsafe_texts:
            content = json.dumps(
                {
                    "summary": text,
                    "insights": [],
                    "recommendations": [],
                }
            )
            result = run_bridge(
                transport=RecordingTransport(200, content)
            )
            self.assertEqual(result["provider_state"], "REJECTED", text)
            self.assertEqual(
                result["provider_error"]["error_code"],
                "UNSAFE_OUTPUT_REJECTED",
            )
            advisory = result["advisory_result"]
            self.assertEqual(advisory["summary"], "")
            self.assertEqual(advisory["insights"], [])
            self.assertEqual(advisory["recommendations"], [])
            self.assertEqual(advisory["validation_state"], "REJECTED")
            self.assertEqual(advisory["safety_state"], "FAILED")
            self.assertTrue(advisory["validation_diagnostics"])

    def test_rejected_output_is_never_present(self):
        content = json.dumps(
            {
                "summary": "The vulnerability is confirmed.",
                "insights": [],
                "recommendations": [],
            }
        )
        result = run_bridge(transport=RecordingTransport(200, content))
        serialized = json.dumps(result)
        self.assertNotIn("vulnerability is confirmed", serialized)

    def test_provider_error_is_not_a_finding(self):
        result = run_bridge(
            transport=RecordingTransport(401, "{}"),
        )
        self.assertEqual(result["provider_state"], "ERROR")
        self.assertIsNone(result["advisory_result"])
        self.assertEqual(
            result["provider_error"]["error_category"],
            "AUTHENTICATION_ERROR",
        )
        serialized = json.dumps(result).lower()
        for token in ("finding", "hypothesis", "vulnerab", "exploit"):
            self.assertNotIn(token, serialized)

    def test_api_key_never_in_serialized_results(self):
        for transport in (
            RecordingTransport(200, success_content()),
            RecordingTransport(200, json.dumps({
                "summary": "The vulnerability is confirmed.",
                "insights": [],
                "recommendations": [],
            })),
            RecordingTransport(401, "{}"),
        ):
            result = run_bridge(transport=transport)
            serialized = json.dumps(result)
            self.assertNotIn(SECRET, serialized)
            self.assertNotIn("Authorization", serialized)
            self.assertNotIn("Bearer", serialized)

    def test_context_secrets_rejected_before_provider_call(self):
        secret_contexts = (
            {"research_question": "Authorization: Bearer " + SECRET},
            {"research_question": "Cookie: session=" + SECRET},
            {"research_question": "api_key=" + SECRET},
            {"research_question": "sk-" + SECRET},
            {"research_question": "token=" + SECRET},
            {"research_question": "password=" + SECRET},
            {"research_question": "connect to https://internal.test/api"},
            {"research_question": "<script>alert(1)</script>"},
        )
        for context in secret_contexts:
            transport = RecordingTransport(200, success_content())
            result = run_bridge(
                research_context=context, transport=transport
            )
            self.assertEqual(result["provider_state"], "ERROR", context)
            self.assertEqual(
                result["provider_error"]["error_category"],
                "SAFETY_VALIDATION_ERROR",
                context,
            )
            self.assertEqual(
                result["provider_error"]["error_code"],
                "UNSAFE_CONTEXT_REJECTED",
            )
            self.assertEqual(transport.requests, [])
            self.assertNotIn(SECRET, json.dumps(result))

    def test_envelope_has_no_prompt_or_raw_body(self):
        result = run_bridge()
        self.assertEqual(set(result.keys()), set(BRIDGE_KEYS))
        serialized = json.dumps(result).lower()
        for token in ("messages", "prompt", "choices", "raw_body"):
            self.assertNotIn(token, serialized)

    def test_bridge_success_still_passes_r45_validation(self):
        result = run_bridge()
        self.assertEqual(result["provider_state"], "OK")
        advisory = result["advisory_result"]
        self.assertEqual(advisory["validation_state"], "PASS")
        self.assertEqual(advisory["safety_state"], "PASS")
        self.assertIs(advisory["research_only"], True)

    def test_mock_provider_remains_offline_and_safe(self):
        provider = MockLLMProvider()
        descriptor = provider.describe()
        self.assertIs(descriptor["network_access"], False)
        self.assertIs(descriptor["credentials_used"], False)
        result = export_llm_advisory(
            evaluation_result=evaluate_agent_result(r38_result())
        )
        self.assertEqual(result["validation_state"], "PASS")
        self.assertEqual(result["safety_state"], "PASS")

    def test_transport_refuses_redirects(self):
        handler = _NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(None, None, 302, "", {}, "https://x")
        )
        described = json.dumps(UrllibHttpTransport().describe())
        self.assertIn('"redirects_followed": false', described)

    def test_no_execution_primitives_in_provider_layer(self):
        for relative_path in PROVIDER_MODULES:
            _imports, calls, _full = scan_file(ROOT / relative_path)
            self.assertEqual(
                calls & FORBIDDEN_CALLS, set(), relative_path
            )

    def test_only_transport_imports_network_modules(self):
        allowed = {"ai/providers/http_transport.py"}
        for relative_path in PROVIDER_MODULES:
            imports, _calls, _full = scan_file(ROOT / relative_path)
            if relative_path in allowed:
                self.assertIn("urllib", imports, relative_path)
                continue
            self.assertEqual(
                imports & NETWORK_MODULES, set(), relative_path
            )

    def test_no_logging_or_print_in_provider_layer(self):
        for relative_path in PROVIDER_MODULES:
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertNotIn("import logging", source, relative_path)
            self.assertNotIn("print(", source, relative_path)

    def test_specialists_have_no_network_or_provider_imports(self):
        for directory in ("ai/knowledge", "ai/schemas"):
            for path in (ROOT / directory).glob("*.py"):
                if not path.name.startswith(SPECIALIST_PREFIXES):
                    continue
                imports, _calls, full = scan_file(path)
                self.assertEqual(
                    imports & NETWORK_MODULES, set(), str(path)
                )
                provider_imports = {
                    module
                    for module in full
                    if module.startswith("ai.providers")
                }
                self.assertEqual(provider_imports, set(), str(path))

    def test_unsafe_output_cannot_set_safety_flags(self):
        content = json.dumps(
            {
                "summary": "ok",
                "insights": [],
                "recommendations": [],
                "research_only": False,
            }
        )
        result = run_bridge(transport=RecordingTransport(200, content))
        self.assertEqual(result["provider_state"], "ERROR")
        self.assertEqual(
            result["provider_error"]["error_code"],
            "INVALID_PROVIDER_RESPONSE",
        )

    def test_provider_is_not_imported_by_specialist_tests(self):
        for relative_path in (
            "tests/test_cve_research_agent_result.py",
            "tests/test_api_security_agent_result.py",
            "tests/test_oauth_agent_result.py",
        ):
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertNotIn("ai.providers", source, relative_path)

    def test_error_envelope_carries_no_status_internals(self):
        result = run_bridge(transport=RecordingTransport(503, "{}"))
        error = result["provider_error"]
        self.assertEqual(
            set(error.keys()),
            {"rule_version", "provider_kind", "error_category",
             "error_code", "status_code", "retryable", "attempts",
             "model", "safe_message", "research_only", "deterministic"},
        )
        self.assertEqual(error["error_category"], "PROVIDER_ERROR")
        self.assertEqual(error["error_code"], "PROVIDER_TRANSIENT_ERROR")


if __name__ == "__main__":
    unittest.main(verbosity=2)
