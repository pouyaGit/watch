"""tests/test_research_prioritization_safety.py — Stage R55 safety tests.

Deterministic, offline safety tests for research prioritization:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  database, LLM provider, dynamic loading, randomness, wall-clock or
  file-system imports/calls; no URLs
- priority is not confidence: no confidence inflation, NOT_CONFIRMED
- safety deferral never boosts or drops unsafe findings
- no mutation of R53/R54 inputs and no field injection upstream
- R38-R54 contracts are unchanged
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
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.knowledge.finding_correlation import (
    correlate,
    correlate_findings,
)
from ai.knowledge.research_prioritization import (
    prioritize,
    prioritize_correlated_findings,
    prioritize_finding_intelligence,
    prioritize_findings,
)

from tests.test_research_priority import (
    conflicting_findings,
    duplicate_findings,
    independent_findings,
    related_findings,
)
from tests.test_research_priority_rules import finding

ROOT = Path(__file__).resolve().parents[1]

R55_MODULES = (
    "ai/schemas/research_priority.py",
    "ai/schemas/research_priority_result.py",
    "ai/knowledge/research_priority_rules.py",
    "ai/knowledge/research_prioritization.py",
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
}

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
    "random.",
    "uuid.",
    "time.",
    "datetime.",
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
    "ai.knowledge.finding_correlation_rules",
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
        for relative in R55_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R55_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                for forbidden in FORBIDDEN_PROVIDER_MODULES:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )

    def test_no_network_urls(self):
        for relative in R55_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R55_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_r55_does_not_import_engines_or_specialists(self):
        for relative in R55_MODULES:
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

    def test_public_api_has_no_credentials(self):
        for function in (
            prioritize,
            prioritize_findings,
            prioritize_finding_intelligence,
            prioritize_correlated_findings,
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
            ):
                self.assertNotIn(forbidden, parameters, function.__name__)


class TestConfidenceAndConfirmationSafety(unittest.TestCase):
    def test_no_confidence_inflation_for_every_classification(self):
        pairs = (
            duplicate_findings(),
            related_findings(),
            conflicting_findings(),
            independent_findings(),
        )
        for first, second in pairs:
            before = (
                first["assessment"]["confidence"],
                second["assessment"]["confidence"],
            )
            result = prioritize_findings([first, second])
            self.assertEqual(result["confidence_effect"], "NONE")
            self.assertIn(
                "CONFIDENCE_NOT_UPGRADED", result["limitations"]
            )
            for plan in result["ranked_findings"]:
                self.assertEqual(plan["confidence_effect"], "NONE")
                self.assertIn(
                    "CONFIDENCE_NOT_UPGRADED", plan["limitations"]
                )
            self.assertEqual(
                (
                    first["assessment"]["confidence"],
                    second["assessment"]["confidence"],
                ),
                before,
            )

    def test_confirmation_state_is_never_confirmed(self):
        result = prioritize_findings([finding("XSS")])
        for plan in result["ranked_findings"]:
            self.assertEqual(
                plan["confirmation_state"], "NOT_CONFIRMED"
            )
        self.assertIn("NOT_CONFIRMED", result["limitations"])

    def test_correlation_does_not_upgrade_confidence(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        result = prioritize_findings(
            [first, second], correlation_result=correlation
        )
        self.assertEqual(result["confidence_effect"], "NONE")
        self.assertEqual(correlation["confidence_effect"], "NONE")

    def test_no_secrets_in_output(self):
        result = prioritize_findings([finding("XSS")])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("sk-", serialized)
        self.assertNotIn("Bearer ", serialized)
        self.assertNotIn("Authorization:", serialized)


class TestSafetyDeferralBoundary(unittest.TestCase):
    def test_unsafe_findings_are_deferred_not_deleted(self):
        unsafe = finding("XSS", confirmation_state="CONFIRMED")
        result = prioritize_findings([unsafe])
        self.assertEqual(result["ranked_findings"], [])
        self.assertEqual(len(result["deferred_findings"]), 1)
        self.assertEqual(
            result["deferred_findings"][0]["finding_id"],
            unsafe["identity"]["finding_id"],
        )
        self.assertIn(
            "SAFETY_DEFERRED",
            result["deferred_findings"][0]["priority_reasons"],
        )

    def test_deferred_plans_are_never_boosted(self):
        result = prioritize_findings(
            [
                finding("XSS", confirmation_state="CONFIRMED"),
                finding("XSS", research_only=False),
            ]
        )
        for plan in result["deferred_findings"]:
            self.assertEqual(plan["priority_score"], 0)
            self.assertEqual(plan["priority_band"], "DEFERRED")
            self.assertEqual(plan["ranking_position"], 0)
            values = {
                factor["value"] for factor in plan["priority_factors"]
            }
            self.assertNotIn("SAFETY_ELIGIBLE", values)

    def test_unsafe_findings_never_in_ranked_set(self):
        result = prioritize_findings(
            [
                finding(
                    "XSS",
                    "sa-" + "1" * 16,
                    finding_id_value="fnd-" + "1" * 16,
                    confirmation_state="CONFIRMED",
                ),
                finding(
                    "XSS",
                    "sa-" + "2" * 16,
                    finding_id_value="fnd-" + "2" * 16,
                    safety_state="FAILED",
                ),
            ]
        )
        self.assertEqual(result["ranked_findings"], [])
        self.assertEqual(len(result["deferred_findings"]), 2)


class TestContractIsolation(unittest.TestCase):
    def test_r53_intelligence_is_not_mutated(self):
        orchestration = orchestrate_research(
            research_context={
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
            }
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        snapshot = json.dumps(intelligence, sort_keys=True)
        result = prioritize_finding_intelligence(intelligence)
        self.assertEqual(
            json.dumps(intelligence, sort_keys=True), snapshot
        )
        self.assertEqual(result["rule_version"], "r55-2")

    def test_r53_output_has_no_r55_keys(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        for key in (
            "ranked_findings",
            "deferred_findings",
            "prioritization_id",
            "priority_score",
        ):
            self.assertNotIn(key, intelligence)
        self.assertEqual(intelligence["rule_version"], "r53-6")

    def test_r54_output_has_no_r55_keys(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        for key in (
            "ranked_findings",
            "deferred_findings",
            "prioritization_id",
        ):
            self.assertNotIn(key, correlation)
        self.assertEqual(correlation["rule_version"], "r54-2")

    def test_r52_output_has_no_r55_keys(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        for key in (
            "ranked_findings",
            "deferred_findings",
            "priority_score",
        ):
            self.assertNotIn(key, orchestration)
        self.assertEqual(orchestration["rule_version"], "r52-6")

    def test_upstream_engines_still_work(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        correlation = correlate(finding_intelligence=intelligence)
        self.assertEqual(intelligence["rule_version"], "r53-6")
        self.assertEqual(correlation["rule_version"], "r54-2")

    def test_backend_does_not_import_r55(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("research_prioritization", text, str(path))
            self.assertNotIn("prioritize_findings", text, str(path))
            self.assertNotIn("prioritization_id", text, str(path))
            self.assertNotIn("research_priority_rules", text, str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
