"""tests/test_security_agent_registry.py — Stage R38.6 tests.

Deterministic, offline tests for the static security agent registry:

- exact registry state vocabulary and static registry contents
- closed categories/maturities and allowed-only capabilities
- caller-supplied entry bounding, filtering and state downgrades
- malformed and empty input handling
- JSON serialization, schema validation
- research_only always true, no plugin/dynamic discovery behaviour

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_registry as builder
from ai.knowledge.security_agent_identity import compute_agent_id
from ai.schemas import security_agent_capability as capability_schema
from ai.schemas import security_agent_identity as identity_schema
from ai.schemas import security_agent_registry as schema


def entry(category="XSS", maturity="RESEARCH", capabilities=None,
          agent_name=None):
    name = agent_name or f"{category.lower()}-agent"
    return {
        "agent_id": compute_agent_id(category, name, "UNKNOWN"),
        "category": category,
        "maturity": maturity,
        "capabilities": list(
            capabilities
            if capabilities is not None
            else ["ANALYZE_CONTEXT"]
        ),
    }


class TestSecurityAgentRegistry(unittest.TestCase):
    def test_registry_state_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.REGISTRY_STATES), {"VALID", "PARTIAL", "UNKNOWN"}
        )

    def test_entry_key_set_is_exact(self):
        self.assertEqual(
            set(schema.REGISTRY_ENTRY_KEYS),
            {"agent_id", "category", "maturity", "capabilities"},
        )

    def test_static_registry_is_valid(self):
        plan = builder.build_security_agent_registry()
        self.assertEqual(plan["registry_state"], "VALID")
        self.assertEqual(plan["research_only"], True)
        self.assertEqual(
            [item["category"] for item in plan["registered_agents"]],
            list(builder.STATIC_CATEGORIES),
        )

    def test_static_entries_use_closed_vocabularies(self):
        for item in builder.static_registry_entries():
            self.assertIn(item["category"],
                          identity_schema.AGENT_CATEGORIES)
            self.assertIn(item["maturity"],
                          identity_schema.AGENT_MATURITIES)
            self.assertTrue(
                identity_schema.AGENT_ID_RE.match(item["agent_id"])
            )
            for capability in item["capabilities"]:
                self.assertIn(
                    capability,
                    capability_schema.ALLOWED_CAPABILITIES,
                )
                self.assertNotIn(
                    capability,
                    capability_schema.PROHIBITED_CAPABILITIES,
                )

    def test_static_registry_is_deterministic(self):
        first = builder.build_security_agent_registry()
        second = builder.build_security_agent_registry()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_empty_entries_yields_unknown(self):
        for empty in ([], (), "not-a-list"):
            plan = builder.build_security_agent_registry(empty)
            self.assertEqual(plan["registry_state"], "UNKNOWN",
                             repr(empty))
            self.assertEqual(plan["registered_agents"], [])

    def test_partial_entries_yield_partial(self):
        plan = builder.build_security_agent_registry(
            [entry("XSS"), {"agent_id": "bad", "category": "XSS"}]
        )
        self.assertEqual(plan["registry_state"], "PARTIAL")
        self.assertEqual(len(plan["registered_agents"]), 1)

    def test_all_invalid_entries_yield_unknown(self):
        plan = builder.build_security_agent_registry(
            [
                {"agent_id": "bad", "category": "XSS"},
                {"agent_id": "sa-" + "a" * 16, "category": "NOPE"},
                "not-a-dict",
            ]
        )
        self.assertEqual(plan["registry_state"], "UNKNOWN")
        self.assertEqual(plan["registered_agents"], [])

    def test_valid_caller_entry_is_accepted(self):
        plan = builder.build_security_agent_registry([entry("SSRF")])
        self.assertEqual(plan["registry_state"], "VALID")
        self.assertEqual(plan["registered_agents"][0]["category"], "SSRF")

    def test_prohibited_capabilities_are_filtered(self):
        item = entry("XSS", capabilities=[
            "ANALYZE_CONTEXT", "EXECUTE_EXPLOIT", "NOT_A_CAPABILITY",
        ])
        plan = builder.build_security_agent_registry([item])
        registered = plan["registered_agents"][0]
        self.assertEqual(registered["capabilities"], ["ANALYZE_CONTEXT"])

    def test_invalid_maturity_becomes_unknown(self):
        item = entry("XSS", maturity="PRODUCTION")
        plan = builder.build_security_agent_registry([item])
        self.assertEqual(
            plan["registered_agents"][0]["maturity"], "UNKNOWN"
        )

    def test_duplicate_entries_are_deduped(self):
        plan = builder.build_security_agent_registry(
            [entry("XSS"), entry("XSS")]
        )
        self.assertEqual(len(plan["registered_agents"]), 1)

    def test_entries_are_bounded(self):
        many = [
            {
                "agent_id": f"sa-{index:016x}",
                "category": "XSS",
                "maturity": "RESEARCH",
                "capabilities": ["ANALYZE_CONTEXT"],
            }
            for index in range(40)
        ]
        plan = builder.build_security_agent_registry(many)
        self.assertEqual(len(plan["registered_agents"]), schema.MAX_ENTRIES)

    def test_input_is_not_mutated(self):
        item = entry("JWT")
        before = copy.deepcopy(item)
        builder.build_security_agent_registry([item])
        self.assertEqual(item, before)

    def test_json_serializable(self):
        plan = builder.build_security_agent_registry()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        plan = builder.build_security_agent_registry()
        self.assertIs(plan["research_only"], True)

    def test_no_execution_content(self):
        blob = json.dumps(
            builder.build_security_agent_registry()
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "subprocess", "shell", "browser",
            "worker", "scheduler", "plugin", "timestamp",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        good = entry("XSS")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentRegistryPlan(
                registered_agents=[good], registry_state="MAYBE"
            )
        with self.assertRaises(ValidationError):
            schema.SecurityAgentRegistryPlan(
                registered_agents=[good], registry_state="VALID",
                discovered_at="now",
            )
        for bad in (
            {"agent_id": "bad", "category": "XSS"},
            {"agent_id": "sa-" + "a" * 16, "category": "NOPE"},
            "not-a-dict",
        ):
            with self.assertRaises(ValidationError):
                schema.SecurityAgentRegistryPlan(
                    registered_agents=[bad], registry_state="VALID"
                )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentRegistryPlan(
            rule_version="r99-9",
            registered_agents=[],
            registry_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r38-6")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentRegistryPlan(
                registered_agents=[],
                registry_state="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            builder.SECURITY_AGENT_REGISTRY_BUILDER_RULE_VERSION, "r38-6"
        )
        self.assertEqual(
            builder.build_security_agent_registry()["rule_version"],
            "r38-6",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
