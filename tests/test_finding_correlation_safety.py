"""tests/test_finding_correlation_safety.py — Stage R54 safety tests.

Deterministic, offline safety tests for finding correlation:

- AST/static isolation: no network, subprocess, shell, browser, scanner,
  database or LLM provider imports; no dynamic loading; no URLs
- no confidence inflation and the NOT_CONFIRMED invariant
- no mutation of R53 finding intelligence
- R43 vocabulary/semantic reuse without modifying R43 behavior
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
    correlate_finding_intelligence,
    correlate_findings,
)
from ai.knowledge.hypothesis_correlator import correlate_hypotheses
from ai.schemas.finding_correlation import (
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_INDEPENDENT,
    RELATIONSHIP_RELATED,
    RELATIONSHIP_TYPES,
    RELATIONSHIP_UNKNOWN,
)
from ai.schemas.hypothesis_correlation import (
    CORRELATION_TYPES,
    CORRELATION_DUPLICATE,
)

from tests.test_finding_correlation import (
    AGENT_A,
    AGENT_B,
    conflicting_findings,
    duplicate_findings,
    independent_findings,
    related_findings,
)
from tests.test_finding_correlation_rules import finding

ROOT = Path(__file__).resolve().parents[1]

R54_MODULES = (
    "ai/schemas/finding_correlation.py",
    "ai/schemas/finding_correlation_result.py",
    "ai/knowledge/finding_correlation_rules.py",
    "ai/knowledge/finding_correlation.py",
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
        for relative in R54_MODULES:
            imports, _, calls = scan_module(relative)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative)

    def test_no_provider_or_llm_sdk_imports(self):
        for relative in R54_MODULES:
            _, full_modules, _ = scan_module(relative)
            for module in full_modules:
                for forbidden in FORBIDDEN_PROVIDER_MODULES:
                    self.assertFalse(
                        module == forbidden
                        or module.startswith(forbidden + "."),
                        f"{relative}: {module}",
                    )

    def test_no_network_urls(self):
        for relative in R54_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("http://", source, relative)
            self.assertNotIn("https://", source, relative)

    def test_no_forbidden_claim_markers(self):
        for relative in R54_MODULES:
            source = (ROOT / relative).read_text(encoding="utf-8")
            for marker in FORBIDDEN_CLAIM_MARKERS:
                self.assertNotIn(marker, source, f"{relative}: {marker}")

    def test_r54_does_not_import_specialists_or_orchestrator(self):
        for relative in R54_MODULES:
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
                    or module == "ai.knowledge.agent_orchestrator"
                    or module == "ai.knowledge.finding_builder",
                    f"{relative}: {module}",
                )

    def test_public_api_has_no_credentials(self):
        for function in (
            correlate,
            correlate_findings,
            correlate_finding_intelligence,
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


class TestR43Compatibility(unittest.TestCase):
    def test_vocabulary_is_reused_not_redefined(self):
        self.assertEqual(RELATIONSHIP_TYPES, CORRELATION_TYPES)
        self.assertEqual(RELATIONSHIP_DUPLICATE, CORRELATION_DUPLICATE)
        _, full_modules, _ = scan_module(
            "ai/schemas/finding_correlation.py"
        )
        self.assertIn("ai.schemas.hypothesis_correlation", full_modules)
        _, rules_modules, _ = scan_module(
            "ai/knowledge/finding_correlation_rules.py"
        )
        self.assertIn("ai.schemas.collaboration_conflict", rules_modules)
        self.assertIn(
            "ai.knowledge.collaboration_conflict_analyzer", rules_modules
        )

    def test_r43_correlator_still_works(self):
        groups = correlate_hypotheses(None)
        self.assertEqual(groups, [])

    def test_relationship_types_are_closed(self):
        self.assertEqual(
            set(RELATIONSHIP_TYPES),
            {
                RELATIONSHIP_DUPLICATE,
                RELATIONSHIP_RELATED,
                RELATIONSHIP_INDEPENDENT,
                RELATIONSHIP_CONFLICTING,
                RELATIONSHIP_UNKNOWN,
            },
        )


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
            result = correlate_findings([first, second])
            self.assertEqual(result["confidence_effect"], "NONE")
            self.assertIn(
                "CONFIDENCE_NOT_UPGRADED", result["limitations"]
            )
            relationship = result["relationships"][0]
            self.assertEqual(relationship["confidence_effect"], "NONE")
            self.assertIn(
                "CONFIDENCE_NOT_UPGRADED", relationship["limitations"]
            )
            for cluster in result["clusters"]:
                self.assertEqual(cluster["confidence_effect"], "NONE")
                self.assertIn(
                    "CONFIDENCE_NOT_UPGRADED", cluster["limitations"]
                )
            self.assertEqual(
                (
                    first["assessment"]["confidence"],
                    second["assessment"]["confidence"],
                ),
                before,
            )

    def test_confirmation_state_is_preserved_and_never_confirmed(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        for reference in result["finding_references"]:
            self.assertEqual(
                reference["confirmation_state"], "NOT_CONFIRMED"
            )
        self.assertIn("NOT_CONFIRMED", result["limitations"])
        serialized = json.dumps(result, sort_keys=True).upper()
        for marker in FORBIDDEN_CLAIM_MARKERS:
            self.assertNotIn(marker, serialized)

    def test_unsafe_inputs_never_reach_relationships(self):
        unsafe = finding(
            "XSS", AGENT_A, confirmation_state="CONFIRMED"
        )
        result = correlate_findings([unsafe])
        self.assertEqual(result["finding_references"], [])
        self.assertEqual(len(result["relationships"]), 0)
        self.assertEqual(
            result["skipped_findings"][0]["reason"],
            "UNSAFE_CONFIRMATION",
        )

    def test_no_secrets_in_output(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("sk-", serialized)
        self.assertNotIn("Bearer ", serialized)
        self.assertNotIn("Authorization:", serialized)


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
        result = correlate_finding_intelligence(intelligence)
        self.assertEqual(
            json.dumps(intelligence, sort_keys=True), snapshot
        )
        self.assertEqual(result["rule_version"], "r54-2")

    def test_r52_output_has_no_r54_keys(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        for key in (
            "relationships",
            "clusters",
            "correlation_id",
            "finding_references",
        ):
            self.assertNotIn(key, orchestration)
        self.assertEqual(orchestration["rule_version"], "r52-6")

    def test_r53_output_has_no_r54_keys(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        for key in ("relationships", "clusters", "correlation_id"):
            self.assertNotIn(key, intelligence)
        self.assertEqual(intelligence["rule_version"], "r53-6")

    def test_backend_does_not_import_r54(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("finding_correlation", text, str(path))
            self.assertNotIn("correlate_findings", text, str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
