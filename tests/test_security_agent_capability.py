"""tests/test_security_agent_capability.py — Stage R38.2 tests.

Deterministic, offline tests for the security agent capability planner:

- exact allowed/prohibited capability vocabularies
- category -> capability mapping
- prohibited capability enforcement (always explicit, never allowed)
- capability states (VALID / PARTIAL / UNKNOWN)
- malformed and empty input handling
- no mutation, JSON serialization, schema validation
- research_only always true, no execution capability

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_capability as sac
from ai.schemas import security_agent_capability as schema
from ai.schemas import security_agent_identity as identity_schema


class TestSecurityAgentCapability(unittest.TestCase):
    def test_allowed_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.ALLOWED_CAPABILITIES),
            {"ANALYZE_CONTEXT", "ANALYZE_PATTERN", "CREATE_HYPOTHESIS",
             "REQUEST_EVIDENCE", "GENERATE_EXPLANATION",
             "RANK_FINDINGS"},
        )

    def test_prohibited_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.PROHIBITED_CAPABILITIES),
            {"EXECUTE_EXPLOIT", "RUN_PAYLOAD", "BYPASS_AUTH",
             "MODIFY_TARGET", "AUTOMATE_ATTACK"},
        )

    def test_vocabularies_are_disjoint(self):
        self.assertEqual(
            set(schema.ALLOWED_CAPABILITIES)
            & set(schema.PROHIBITED_CAPABILITIES),
            set(),
        )

    def test_every_category_has_capabilities(self):
        for category in identity_schema.AGENT_CATEGORIES:
            if category == "UNKNOWN":
                continue
            plan = sac.plan_security_agent_capabilities(category)
            self.assertEqual(plan["agent_category"], category)
            self.assertEqual(plan["capability_state"], "VALID")
            self.assertTrue(plan["allowed_capabilities"])
            self.assertEqual(
                plan["prohibited_capabilities"],
                list(schema.PROHIBITED_CAPABILITIES),
            )

    def test_prohibited_capabilities_always_explicit(self):
        for category in ("XSS", "SSRF", "SQLI", "IDOR", "JWT", "OAUTH",
                         "CVE_RESEARCH", "RECON", None):
            plan = sac.plan_security_agent_capabilities(category)
            self.assertEqual(
                plan["prohibited_capabilities"],
                list(schema.PROHIBITED_CAPABILITIES),
                repr(category),
            )

    def test_no_prohibited_code_in_allowed(self):
        for category in identity_schema.AGENT_CATEGORIES:
            plan = sac.plan_security_agent_capabilities(category)
            overlap = set(plan["allowed_capabilities"]) & set(
                schema.PROHIBITED_CAPABILITIES
            )
            self.assertEqual(overlap, set(), category)

    def test_unknown_category_state(self):
        for value in (None, "", "NOPE", "UNKNOWN"):
            plan = sac.plan_security_agent_capabilities(value)
            self.assertEqual(plan["agent_category"], "UNKNOWN",
                             repr(value))
            self.assertEqual(plan["capability_state"], "UNKNOWN")
            self.assertEqual(plan["allowed_capabilities"], [])

    def test_analyze_only_capabilities(self):
        for category in sac.CATEGORY_CAPABILITIES:
            for capability in sac.CATEGORY_CAPABILITIES[category]:
                self.assertIn(capability, schema.ALLOWED_CAPABILITIES)

    def test_deterministic_output(self):
        first = sac.plan_security_agent_capabilities("XSS")
        second = sac.plan_security_agent_capabilities("XSS")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = sac.plan_security_agent_capabilities("SQLI")
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            sac.plan_security_agent_capabilities()["research_only"], True
        )

    def test_no_execution_content(self):
        blob = json.dumps(
            [
                sac.plan_security_agent_capabilities(category)
                for category in identity_schema.AGENT_CATEGORIES
            ]
        ).lower()
        for marker in (
            "http://", "https://", "fuzz", "nuclei", "sqlmap",
            "shell", "subprocess", "browser", "dispatch", "worker",
            "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        base = {
            "agent_category": "XSS",
            "allowed_capabilities": ["ANALYZE_CONTEXT"],
            "prohibited_capabilities": ["EXECUTE_EXPLOIT"],
            "capability_state": "VALID",
        }
        for key, value in (
            ("agent_category", "NOPE"),
            ("allowed_capabilities", ["EXECUTE_EXPLOIT"]),
            ("prohibited_capabilities", ["ANALYZE_CONTEXT"]),
            ("capability_state", "MAYBE"),
        ):
            with self.assertRaises(ValidationError):
                schema.SecurityAgentCapabilityPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SecurityAgentCapabilityPlan(**base, severity="HIGH")

    def test_schema_rejects_overlap(self):
        with self.assertRaises(ValidationError):
            schema.SecurityAgentCapabilityPlan(
                agent_category="XSS",
                allowed_capabilities=["ANALYZE_CONTEXT"],
                prohibited_capabilities=["ANALYZE_CONTEXT"],
                capability_state="VALID",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentCapabilityPlan(
            rule_version="r99-9",
            agent_category="UNKNOWN",
            allowed_capabilities=[],
            prohibited_capabilities=["EXECUTE_EXPLOIT"],
            capability_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r38-2")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentCapabilityPlan(
                agent_category="UNKNOWN",
                allowed_capabilities=[],
                prohibited_capabilities=["EXECUTE_EXPLOIT"],
                capability_state="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            sac.SECURITY_AGENT_CAPABILITY_PLANNER_RULE_VERSION, "r38-2"
        )
        self.assertEqual(
            sac.plan_security_agent_capabilities("XSS")["rule_version"],
            "r38-2",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
