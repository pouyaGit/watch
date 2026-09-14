"""tests/test_finding_safety.py — Stage R53 safety tests.

Deterministic, offline safety tests for finding intelligence:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  database or LLM provider imports
- no direct provider import, no dynamic code loading, no URLs
- confirmation is impossible: every finding is NOT_CONFIRMED
- business impact is never asserted; assumptions are never recorded
- unsupported claims cannot become confirmed findings
- R52/R39-R50 contracts are consumed, never modified

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

from pydantic import ValidationError

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.schemas.finding_assessment import (
    CONFIRMATION_NOT_CONFIRMED,
    FindingAssessmentPlan,
)

from tests.test_finding_builder import (  # noqa: E402
    AGENT_XSS,
    evaluation,
    xss_entry,
    xss_result,
)

ROOT = Path(__file__).resolve().parents[1]

R53_MODULES = (
    "ai/schemas/finding_identity.py",
    "ai/schemas/finding_context.py",
    "ai/schemas/finding_hypothesis.py",
    "ai/schemas/finding_evidence.py",
    "ai/schemas/finding_assessment.py",
    "ai/schemas/finding_result.py",
    "ai/knowledge/finding_reasoning.py",
    "ai/knowledge/finding_state.py",
    "ai/knowledge/finding_builder.py",
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
    "ai.providers",
    "ai.knowledge.llm_provider",
    "ai.knowledge.llm_advisory_export",
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


class TestStaticSafety(unittest.TestCase):
    def test_no_forbidden_imports_or_calls(self):
        for relative in R53_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R53_MODULES:
            _, full_modules, _ = scan_module(relative)
            for forbidden in FORBIDDEN_PROVIDER_MODULES:
                for module in full_modules:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )
            self.assertNotIn("openai", {
                module for module in full_modules
            })

    def test_no_network_urls_in_r53(self):
        for relative in R53_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R53_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_no_specialist_logic_is_imported(self):
        for relative in R53_MODULES:
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
                    or module.startswith("ai.knowledge.cve_research_"),
                    f"{relative}: {module}",
                )

    def test_public_api_has_no_credentials(self):
        from ai.knowledge.finding_builder import build_finding_intelligence

        parameters = set(
            inspect.signature(build_finding_intelligence).parameters
        )
        for forbidden in (
            "api_key",
            "credential",
            "credentials",
            "token",
            "secret",
            "password",
            "authorization",
            "provider",
        ):
            self.assertNotIn(forbidden, parameters)


class TestConfirmationIsImpossible(unittest.TestCase):
    def test_confirmation_state_is_forced(self):
        with self.assertRaises(ValidationError):
            FindingAssessmentPlan(confirmation_state="CONFIRMED")
        plan = FindingAssessmentPlan()
        self.assertEqual(
            plan.confirmation_state, CONFIRMATION_NOT_CONFIRMED
        )

    def test_every_finding_is_not_confirmed(self):
        for status in ("COMPLETED", "ANALYZING", "CREATED"):
            result = build_finding_intelligence(
                specialist_results=[
                    xss_entry(xss_result({"status": status}))
                ],
                evaluation_results=[evaluation()],
            )
            for finding in result["findings"]:
                self.assertEqual(
                    finding["assessment"]["confirmation_state"],
                    CONFIRMATION_NOT_CONFIRMED,
                )

    def test_business_impact_is_never_asserted(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        for finding in result["findings"]:
            self.assertFalse(
                finding["assessment"]["business_impact_asserted"]
            )
        with self.assertRaises(ValidationError):
            FindingAssessmentPlan(business_impact_asserted=True)

    def test_observed_impact_is_never_produced(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        self.assertEqual(
            result["findings"][0]["assessment"]["impact_state"],
            "POTENTIAL",
        )

    def test_assumptions_are_never_recorded(self):
        result = build_finding_intelligence(
            specialist_results=[xss_entry()]
        )
        self.assertFalse(
            result["findings"][0]["evidence"]["assumptions_recorded"]
        )

    def test_unsupported_claims_never_become_findings(self):
        unsafe = xss_result(
            {
                "limitations": [
                    "NO_EXECUTION_PERFORMED",
                    "VULNERABILITY_CONFIRMED",
                ]
            }
        )
        result = build_finding_intelligence(
            specialist_results=[xss_entry(unsafe)]
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["skipped_candidates"][0]["reason"], "FORBIDDEN_CLAIM"
        )
        serialized = json.dumps(result, sort_keys=True).upper()
        for marker in FORBIDDEN_CLAIM_MARKERS:
            self.assertNotIn(marker, serialized)

    def test_unsupported_claims_cannot_create_findings_without_evaluation(self):
        unsafe = xss_result(
            {
                "hypotheses": [
                    {
                        "rule_version": "r39-3",
                        "hypothesis_type": "IS_VULNERABLE",
                        "supporting_signals": [],
                        "confidence": "HIGH",
                        "priority": "HIGH",
                        "limitations": [],
                    }
                ]
            }
        )
        result = build_finding_intelligence(
            specialist_results=[xss_entry(unsafe)]
        )
        self.assertEqual(result["findings"], [])


class TestContractIsolation(unittest.TestCase):
    def test_r52_output_does_not_contain_r53_keys(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        for key in (
            "findings",
            "intelligence_id",
            "skipped_candidates",
        ):
            self.assertNotIn(key, orchestration)
        self.assertEqual(
            orchestration["rule_version"], "r52-6"
        )

    def test_r53_consumes_orchestration_without_replacing_it(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
            }
        )
        snapshot = json.dumps(orchestration, sort_keys=True)
        result = build_finding_intelligence(
            orchestration_result=orchestration
        )
        self.assertEqual(
            json.dumps(orchestration, sort_keys=True), snapshot
        )
        self.assertEqual(result["rule_version"], "r53-6")
        self.assertEqual(
            result["findings"][0]["identity"]["agent_id"],
            orchestration["specialist_results"][0]["agent_id"],
        )

    def test_r53_builder_does_not_import_the_orchestrator(self):
        _, full_modules, _ = scan_module(
            "ai/knowledge/finding_builder.py"
        )
        self.assertNotIn("ai.knowledge.agent_orchestrator", full_modules)
        self.assertNotIn("ai.knowledge.specialist_invoker", full_modules)
        self.assertNotIn("ai.knowledge.specialist_eligibility",
                         full_modules)

    def test_no_secrets_in_finding_output(self):
        secret = "not-a-real-secret-0123456789abcdef"
        result = build_finding_intelligence(
            specialist_results=[xss_entry()],
            evaluation_results=[evaluation()],
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("sk-", serialized)
        self.assertNotIn("Bearer ", serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
