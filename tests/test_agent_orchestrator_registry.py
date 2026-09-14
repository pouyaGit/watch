"""tests/test_agent_orchestrator_registry.py — Stage R52.1/R52.2 tests.

Deterministic, offline tests for the orchestrator specialist registry,
context normalization and eligibility/selection:

- closed registry, canonical R38 categories, no invented capability
- canonical deterministic ordering
- context normalization bounds
- relevance-only eligibility (no keyword-only confirmation)
- automatic and explicit selection
- unknown/disabled/ineligible explicit rejection (fail closed)
- maximum specialist limit
- registry/schema immutability of caller inputs

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import inspect
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    AGENT_ID_RE,
    CATEGORY_UNKNOWN,
)
from ai.schemas.agent_orchestrator_context import (
    ORCHESTRATION_CONTEXT_KEYS,
    AgentOrchestrationContextPlan,
    context_value_is_known,
    sanitize_orchestration_context,
)
from ai.schemas.agent_orchestrator_registry import (
    CANONICAL_SPECIALIST_ORDER,
    MAX_ENTRIES,
    REGISTRY_ENTRY_KEYS,
    REGISTRY_STATES,
    REGISTRY_VALID,
    SPECIALIST_CATEGORIES,
    AgentOrchestratorRegistryPlan,
    sanitize_registry_entry,
)
from ai.knowledge.specialist_eligibility import (
    SPECIALIST_SIGNAL_KEYS,
    SpecialistSelectionError,
    analyze_specialist_eligibility,
    matched_signal_keys,
    select_specialists,
    specialist_is_eligible,
)
from ai.knowledge.specialist_invoker import SPECIALIST_INVOKERS
from ai.knowledge.specialist_registry import (
    SPECIALIST_CONTEXT_KEYS,
    SPECIALIST_PRIORITY,
    build_specialist_registry,
    enabled_categories,
    registry_entry,
    specialist_agent_id,
    specialist_name,
)
from ai.knowledge.xss_context_analyzer import analyze_xss_context
from ai.knowledge.ssrf_context_analyzer import analyze_ssrf_context
from ai.knowledge.sqli_context_analyzer import analyze_sqli_context
from ai.knowledge.idor_bola_context_analyzer import analyze_idor_bola_context
from ai.knowledge.jwt_authentication_context_analyzer import (
    analyze_jwt_authentication_context,
)
from ai.knowledge.oauth_context_analyzer import analyze_oauth_context
from ai.knowledge.api_security_context_analyzer import (
    analyze_api_security_context,
)
from ai.knowledge.cve_research_context_analyzer import (
    analyze_cve_research_context,
)


ROOT = Path(__file__).resolve().parents[1]


def xss_context():
    return {
        "input_location": "QUERY",
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "encoding_state": "NONE_OBSERVED",
        "framework_context": "GENERIC",
    }


def multi_context():
    return {
        "input_location": "QUERY",
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "encoding_state": "NONE_OBSERVED",
        "framework_context": "GENERIC",
        "parameter_type": "QUERY_PARAM",
        "query_context": "DATABASE_QUERY",
        "data_flow": "RAW_QUERY",
        "object_reference": "OBSERVED",
        "resource_type": "OBJECT",
        "token_format": "JWT",
        "signing_algorithm": "HS256",
        "flow": "AUTHORIZATION_CODE",
        "oauth_version": "2.0",
        "api_type": "REST",
        "api_versioning": "URL",
        "cve_metadata": "CVE-2021-44228",
        "affected_product": "log4j",
    }


def auto_policy(**over):
    policy = {"mode": "AUTOMATIC", "max_specialists": 8}
    policy.update(over)
    return policy


class TestSpecialistRegistry(unittest.TestCase):
    def test_registry_is_closed_and_canonical(self):
        registry = build_specialist_registry()
        self.assertEqual(registry["registry_state"], REGISTRY_VALID)
        self.assertEqual(len(registry["entries"]), MAX_ENTRIES)
        categories = [entry["category"] for entry in registry["entries"]]
        self.assertEqual(categories, list(CANONICAL_SPECIALIST_ORDER))
        self.assertEqual(
            set(SPECIALIST_CATEGORIES), set(CANONICAL_SPECIALIST_ORDER)
        )
        self.assertEqual(len(set(categories)), len(categories))
        for category in categories:
            self.assertIn(category, AGENT_CATEGORIES)
            self.assertNotEqual(category, CATEGORY_UNKNOWN)

    def test_registry_entry_keys_are_bounded(self):
        registry = build_specialist_registry()
        for entry in registry["entries"]:
            self.assertEqual(
                tuple(entry.keys()), REGISTRY_ENTRY_KEYS
            )
            self.assertIn(registry["registry_state"], REGISTRY_STATES)
            self.assertTrue(registry["research_only"])

    def test_no_invented_capability(self):
        registry = build_specialist_registry()
        for entry in registry["entries"]:
            for capability in entry["capabilities"]:
                self.assertIn(capability, ALLOWED_CAPABILITIES)
                self.assertNotIn(capability, PROHIBITED_CAPABILITIES)
            self.assertLessEqual(len(entry["capabilities"]), 6)

    def test_specialist_identity_is_real_and_deterministic(self):
        for category in CANONICAL_SPECIALIST_ORDER:
            name = specialist_name(category)
            agent_id = specialist_agent_id(category)
            self.assertTrue(name)
            self.assertTrue(AGENT_ID_RE.match(agent_id))
            self.assertEqual(name, specialist_name(category))
            self.assertEqual(agent_id, specialist_agent_id(category))

    def test_invocation_table_is_closed_and_static(self):
        self.assertEqual(
            list(SPECIALIST_INVOKERS.keys()),
            list(CANONICAL_SPECIALIST_ORDER),
        )
        for invoker in SPECIALIST_INVOKERS.values():
            self.assertTrue(callable(invoker))

    def test_priority_is_fixed_and_ordered(self):
        registry = build_specialist_registry()
        priorities = [entry["priority"] for entry in registry["entries"]]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual(
            priorities,
            [SPECIALIST_PRIORITY[c] for c in CANONICAL_SPECIALIST_ORDER],
        )

    def test_declared_contexts_match_analyzer_signatures(self):
        analyzers = {
            "XSS": analyze_xss_context,
            "SSRF": analyze_ssrf_context,
            "SQLI": analyze_sqli_context,
            "IDOR": analyze_idor_bola_context,
            "JWT": analyze_jwt_authentication_context,
            "OAUTH": analyze_oauth_context,
            "RECON": analyze_api_security_context,
            "CVE_RESEARCH": analyze_cve_research_context,
        }
        for category, analyzer in analyzers.items():
            declared = list(SPECIALIST_CONTEXT_KEYS[category])
            actual = list(inspect.signature(analyzer).parameters)
            self.assertEqual(declared, actual, category)
        union: list[str] = []
        for category in CANONICAL_SPECIALIST_ORDER:
            for key in SPECIALIST_CONTEXT_KEYS[category]:
                if key not in union:
                    union.append(key)
        self.assertEqual(sorted(union), sorted(ORCHESTRATION_CONTEXT_KEYS))

    def test_registry_disabled_state(self):
        registry = build_specialist_registry(disabled_categories=["JWT"])
        self.assertFalse(registry_entry("JWT", registry)["enabled"])
        self.assertNotIn("JWT", enabled_categories(registry))
        self.assertEqual(len(enabled_categories(registry)), 7)

    def test_registry_schema_rejects_unknown_category(self):
        with self.assertRaises(ValidationError):
            AgentOrchestratorRegistryPlan(
                entries=[
                    {
                        "category": "NOT_A_CATEGORY",
                        "specialist_name": "bogus",
                        "agent_id": "",
                        "capabilities": [],
                        "supported_contexts": [],
                        "priority": 10,
                        "enabled": True,
                    }
                ],
                registry_state=REGISTRY_VALID,
            )

    def test_sanitize_entry_bounds(self):
        entry = sanitize_registry_entry(
            {
                "category": "xss",
                "specialist_name": "  spaced  name ",
                "agent_id": "bogus",
                "capabilities": ["ANALYZE_CONTEXT", "EXECUTE_EXPLOIT"],
                "supported_contexts": ["output_context", "Bad Key"],
                "priority": 1000,
                "enabled": True,
            }
        )
        self.assertEqual(entry["category"], "XSS")
        self.assertEqual(entry["agent_id"], "")
        self.assertEqual(entry["capabilities"], ["ANALYZE_CONTEXT"])
        self.assertEqual(entry["supported_contexts"], ["output_context"])
        self.assertEqual(entry["priority"], 100)


class TestContextNormalization(unittest.TestCase):
    def test_known_keys_are_retained_and_bounded(self):
        context = sanitize_orchestration_context(xss_context())
        self.assertEqual(context["output_context"], "HTML")
        plan = AgentOrchestrationContextPlan(
            context=context,
            known_key_count=5,
            dropped_key_count=0,
        )
        self.assertTrue(plan.research_only)
        self.assertEqual(plan.context["reflection_state"], "REFLECTED")

    def test_unknown_and_nondeterministic_keys_are_dropped(self):
        context = sanitize_orchestration_context(
            {
                "output_context": "HTML",
                "timestamp": "2026-01-01",
                "uuid": "abc",
                "arbitrary_key": "value",
            }
        )
        self.assertEqual(context, {"output_context": "HTML"})

    def test_context_values_are_bounded(self):
        context = sanitize_orchestration_context(
            {
                "output_context": "x" * 500,
                "framework_context": ["GENERIC"] * 100,
                "reflection_state": {"nested": "not allowed"},
            }
        )
        self.assertEqual(len(context["output_context"]), 160)
        self.assertEqual(len(context["framework_context"]), 16)
        self.assertNotIn("reflection_state", context)

    def test_known_value_rules(self):
        self.assertFalse(context_value_is_known(""))
        self.assertFalse(context_value_is_known("UNKNOWN"))
        self.assertFalse(context_value_is_known(" unknown "))
        self.assertTrue(context_value_is_known("HTML"))
        self.assertTrue(context_value_is_known(["HTML"]))
        self.assertFalse(context_value_is_known([]))
        self.assertTrue(context_value_is_known(True))
        self.assertFalse(context_value_is_known(False))

    def test_toolkit_top_level_text(self):
        self.assertEqual(sanitize_orchestration_context(None), {})
        self.assertEqual(sanitize_orchestration_context("not-a-dict"), {})
        self.assertEqual(sanitize_orchestration_context([1, 2]), {})

    def test_context_plan_rejects_research_only_false(self):
        with self.assertRaises(ValidationError):
            AgentOrchestrationContextPlan(
                context={}, known_key_count=0, research_only=False
            )


class TestEligibility(unittest.TestCase):
    def test_xss_context_selects_only_xss(self):
        analysis = analyze_specialist_eligibility(xss_context())
        self.assertEqual(analysis["eligible_categories"], ["XSS"])
        self.assertIn("SSRF", analysis["ineligible_categories"])

    def test_shared_keys_never_make_a_specialist_eligible(self):
        for context in (
            {"input_location": "QUERY"},
            {"authentication_mechanism": "BEARER"},
            {"issuer_validation": "PRESENT"},
            {"authorization_boundary": "ENFORCED"},
            {"token_exposure": "OBSERVED"},
        ):
            analysis = analyze_specialist_eligibility(context)
            self.assertEqual(analysis["eligible_categories"], [])

    def test_specialist_specific_contexts(self):
        cases = {
            "SSRF": {"server_side_fetch": "OBSERVED"},
            "SQLI": {"query_context": "DATABASE_QUERY"},
            "IDOR": {"object_reference": "OBSERVED"},
            "JWT": {"token_format": "JWT"},
            "OAUTH": {"flow": "AUTHORIZATION_CODE"},
            "RECON": {"api_type": "REST"},
            "CVE_RESEARCH": {"cve_metadata": "CVE-2021-44228"},
        }
        for category, context in cases.items():
            analysis = analyze_specialist_eligibility(context)
            self.assertEqual(
                analysis["eligible_categories"], [category], context
            )

    def test_jwt_and_oauth_are_disambiguated(self):
        jwt = analyze_specialist_eligibility({"token_format": "JWT"})
        oauth = analyze_specialist_eligibility(
            {"flow": "AUTHORIZATION_CODE"}
        )
        self.assertEqual(jwt["eligible_categories"], ["JWT"])
        self.assertEqual(oauth["eligible_categories"], ["OAUTH"])
        self.assertNotIn("issuer_validation", SPECIALIST_SIGNAL_KEYS["JWT"])
        self.assertNotIn("issuer_validation", SPECIALIST_SIGNAL_KEYS["OAUTH"])

    def test_signal_keys_reporting_is_relevance_only(self):
        analysis = analyze_specialist_eligibility(xss_context())
        self.assertEqual(
            analysis["signal_keys"]["XSS"],
            [
                "output_context",
                "reflection_state",
                "encoding_state",
                "framework_context",
            ],
        )
        self.assertTrue(analysis["relevance_only"])
        self.assertEqual(
            matched_signal_keys("XSS", {"output_context": "HTML"}),
            ["output_context"],
        )
        self.assertTrue(specialist_is_eligible("XSS", xss_context()))
        self.assertFalse(specialist_is_eligible("SSRF", xss_context()))

    def test_eligibility_is_order_independent(self):
        first = analyze_specialist_eligibility(multi_context())
        reordered = dict(reversed(list(multi_context().items())))
        second = analyze_specialist_eligibility(reordered)
        self.assertEqual(
            first["eligible_categories"], second["eligible_categories"]
        )
        self.assertEqual(first["signal_keys"], second["signal_keys"])


class TestSelection(unittest.TestCase):
    def test_automatic_selection_is_canonical(self):
        analysis = analyze_specialist_eligibility(multi_context())
        selection = select_specialists(analysis, auto_policy())
        self.assertEqual(
            selection["selected_specialists"],
            [c for c in CANONICAL_SPECIALIST_ORDER
             if c in analysis["eligible_categories"]],
        )
        self.assertEqual(selection["limit_exceeded_specialists"], [])

    def test_automatic_max_specialists_limit(self):
        analysis = analyze_specialist_eligibility(multi_context())
        selection = select_specialists(
            analysis, auto_policy(max_specialists=2)
        )
        self.assertEqual(len(selection["selected_specialists"]), 2)
        exceeded = [
            item
            for item in selection["skipped_specialists"]
            if item["reason"] == "MAX_SPECIALISTS_EXCEEDED"
        ]
        self.assertEqual(
            [item["category"] for item in exceeded],
            selection["limit_exceeded_specialists"],
        )
        self.assertTrue(selection["limit_exceeded_specialists"])

    def test_explicit_selection_is_canonical_and_filtered(self):
        analysis = analyze_specialist_eligibility(multi_context())
        selection = select_specialists(
            analysis,
            {
                "mode": "EXPLICIT",
                "allowed_categories": ["SQLI", "XSS"],
                "max_specialists": 8,
            },
        )
        self.assertEqual(
            selection["selected_specialists"], ["XSS", "SQLI"]
        )
        reasons = {
            item["category"]: item["reason"]
            for item in selection["skipped_specialists"]
        }
        self.assertEqual(reasons["JWT"], "NOT_REQUESTED")

    def test_explicit_unknown_category_fails_closed(self):
        analysis = analyze_specialist_eligibility(multi_context())
        with self.assertRaises(SpecialistSelectionError):
            select_specialists(
                analysis,
                {
                    "mode": "EXPLICIT",
                    "allowed_categories": ["BOGUS"],
                    "max_specialists": 8,
                },
            )

    def test_explicit_ineligible_category_fails_closed(self):
        analysis = analyze_specialist_eligibility(xss_context())
        with self.assertRaises(SpecialistSelectionError) as ctx:
            select_specialists(
                analysis,
                {
                    "mode": "EXPLICIT",
                    "allowed_categories": ["SSRF"],
                    "max_specialists": 8,
                },
            )
        self.assertEqual(ctx.exception.reason, "INELIGIBLE")
        self.assertEqual(
            ctx.exception.error_category, "SPECIALIST_SELECTION_ERROR"
        )

    def test_explicit_disabled_category_fails_closed(self):
        analysis = analyze_specialist_eligibility(xss_context())
        registry = build_specialist_registry(disabled_categories=["XSS"])
        with self.assertRaises(SpecialistSelectionError) as ctx:
            select_specialists(
                analysis,
                {
                    "mode": "EXPLICIT",
                    "allowed_categories": ["XSS"],
                    "max_specialists": 8,
                },
                registry,
            )
        self.assertEqual(ctx.exception.reason, "DISABLED")

    def test_explicit_over_limit_fails_closed(self):
        analysis = analyze_specialist_eligibility(multi_context())
        with self.assertRaises(SpecialistSelectionError) as ctx:
            select_specialists(
                analysis,
                {
                    "mode": "EXPLICIT",
                    "allowed_categories": ["XSS", "SQLI"],
                    "max_specialists": 1,
                },
            )
        self.assertEqual(ctx.exception.error_category, "LIMIT_EXCEEDED")

    def test_selection_is_deterministic_and_json_safe(self):
        analysis = analyze_specialist_eligibility(multi_context())
        first = select_specialists(analysis, auto_policy())
        second = select_specialists(analysis, auto_policy())
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
