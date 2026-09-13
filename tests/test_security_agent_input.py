"""tests/test_security_agent_input.py — Stage R38.3 tests.

Deterministic, offline tests for the security agent input contract:

- fixed read-only contract shape and empty/unknown blocks
- missing critical authorization context stays unknown (never permissive)
- input immutability (caller data is never mutated)
- malformed and empty input handling, bounded blocks, redaction
- JSON serialization, schema validation
- research_only always true, no execution context

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_input_validator as validator
from ai.schemas import security_agent_input as schema


def identity():
    return {
        "rule_version": "r38-1",
        "agent_id": "sa-" + "a" * 16,
        "agent_name": "xss-agent",
        "category": "XSS",
        "version": "UNKNOWN",
        "maturity": "RESEARCH",
        "description": "",
        "research_only": True,
    }


class TestSecurityAgentInput(unittest.TestCase):
    def test_contract_key_set_is_exact(self):
        plan = validator.validate_security_agent_input()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "agent_identity", "research_context",
             "memory_context", "strategy_context", "orchestration_context",
             "authorization_context", "governance_context", "research_only"},
        )

    def test_empty_input_has_empty_blocks(self):
        plan = validator.validate_security_agent_input()
        for key in ("research_context", "memory_context", "strategy_context",
                    "orchestration_context", "authorization_context",
                    "governance_context"):
            self.assertEqual(plan[key], {}, key)
        self.assertEqual(plan["agent_identity"]["category"], "")
        self.assertEqual(plan["rule_version"], "r38-3")

    def test_missing_authorization_context_stays_unknown(self):
        plan = validator.validate_security_agent_input(
            research_context={"topic": "xss"}
        )
        self.assertEqual(plan["authorization_context"], {})
        self.assertEqual(plan["governance_context"], {})
        self.assertNotIn("permitted", json.dumps(plan).lower())
        self.assertNotIn("unrestricted", json.dumps(plan).lower())

    def test_malformed_blocks_degrade_to_empty(self):
        for bad in (None, "", 42, [], "not-a-block", object()):
            plan = validator.validate_security_agent_input(
                research_context=bad, authorization_context=bad
            )
            self.assertEqual(plan["research_context"], {}, repr(bad))
            self.assertEqual(plan["authorization_context"], {}, repr(bad))

    def test_input_is_not_mutated(self):
        research = {"topic": "xss", "tags": ["a", "b"]}
        identity_block = identity()
        research_before = copy.deepcopy(research)
        identity_before = copy.deepcopy(identity_block)
        validator.validate_security_agent_input(
            agent_identity=identity_block, research_context=research
        )
        self.assertEqual(research, research_before)
        self.assertEqual(identity_block, identity_before)

    def test_agent_identity_is_bounded(self):
        plan = validator.validate_security_agent_input(
            agent_identity={
                "category": "XSS",
                "agent_id": "sa-" + "b" * 16,
                "agent_name": "custom",
                "injected": {"nested": True},
            }
        )
        block = plan["agent_identity"]
        self.assertEqual(block["category"], "XSS")
        self.assertEqual(block["agent_name"], "custom")
        self.assertNotIn("injected", block)

    def test_nested_values_are_dropped(self):
        plan = validator.validate_security_agent_input(
            research_context={
                "nested": {"a": 1},
                "mixed": [1, {"b": 2}, "ok"],
                "topic": "xss",
            }
        )
        block = plan["research_context"]
        self.assertNotIn("nested", block)
        self.assertEqual(block["mixed"], ["1", "ok"])
        self.assertEqual(block["topic"], "xss")

    def test_secret_like_values_are_redacted(self):
        plan = validator.validate_security_agent_input(
            research_context={
                "note": "token=SECRETVALUE",
                "endpoint": "https://user:pass@example.test/x",
            }
        )
        blob = json.dumps(plan)
        self.assertNotIn("SECRETVALUE", blob)
        self.assertNotIn("user:pass", blob)

    def test_blocks_are_bounded(self):
        big = {f"k{index:03d}": index for index in range(80)}
        plan = validator.validate_security_agent_input(research_context=big)
        self.assertLessEqual(
            len(plan["research_context"]), schema.MAX_CONTEXT_KEYS
        )
        many = {"items": [f"i{index}" for index in range(80)]}
        plan = validator.validate_security_agent_input(research_context=many)
        self.assertLessEqual(
            len(plan["research_context"]["items"]),
            schema.MAX_CONTEXT_LIST,
        )

    def test_deterministic_output(self):
        kwargs = {
            "agent_identity": identity(),
            "research_context": {"topic": "xss"},
            "authorization_context": {"scope": "research"},
        }
        first = validator.validate_security_agent_input(**kwargs)
        second = validator.validate_security_agent_input(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = validator.validate_security_agent_input(
            research_context={"topic": "xss"}
        )
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        plan = validator.validate_security_agent_input(
            authorization_context={"research_only": False}
        )
        self.assertIs(plan["research_only"], True)

    def test_no_execution_content(self):
        blob = json.dumps(
            validator.validate_security_agent_input()
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "subprocess", "shell", "browser",
            "worker", "scheduler", "timestamp",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_extra_fields(self):
        with self.assertRaises(ValidationError):
            schema.SecurityAgentInputPlan(execution_context={"x": 1})
        with self.assertRaises(ValidationError):
            schema.SecurityAgentInputPlan(agent_id="sa-" + "a" * 16)

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentInputPlan(
            rule_version="r99-9", research_only=True
        )
        self.assertEqual(plan.rule_version, "r38-3")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentInputPlan(research_only=False)

    def test_exact_rule_version(self):
        self.assertEqual(validator.SECURITY_AGENT_INPUT_RULE_VERSION,
                         "r38-3")
        self.assertEqual(
            validator.validate_security_agent_input()["rule_version"],
            "r38-3",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
