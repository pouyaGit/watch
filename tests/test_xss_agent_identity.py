"""tests/test_xss_agent_identity.py — Stage R39.1 tests.

Deterministic, offline tests for the XSS specialist agent identity:

- fixed XSS category and R38-conformant agent ids
- maturity vocabulary and malformed handling
- supported-context vocabulary and validation
- R38 SecurityAgentIdentity conformance
- malformed/empty input, JSON serialization
- research_only always true, no execution content

No network, no DNS, no LLM, no subprocess, no browser, no payloads, no
target interaction, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import xss_agent_identity as planner
from ai.schemas import security_agent_identity as r38_identity
from ai.schemas import xss_agent_identity as schema


class TestXSSAgentIdentity(unittest.TestCase):
    def test_category_is_fixed_to_xss(self):
        plan = planner.plan_xss_agent_identity()
        self.assertEqual(plan["category"], "XSS")
        self.assertEqual(
            planner.plan_xss_agent_identity()["category"],
            schema.XSS_CATEGORY,
        )
        with self.assertRaises(ValidationError):
            schema.XSSAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="xss-agent",
                category="SSRF",
            )

    def test_maturity_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.XSS_AGENT_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE", "UNKNOWN"},
        )
        self.assertEqual(
            set(schema.XSS_KNOWN_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE"},
        )
        with self.assertRaises(ValidationError):
            schema.XSSAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="xss-agent",
                category="XSS",
                maturity="PRODUCTION",
            )

    def test_maturity_normalized_and_unknown(self):
        for value in ("experimental", "Research", "STABLE"):
            plan = planner.plan_xss_agent_identity(maturity=value)
            self.assertEqual(plan["maturity"], value.upper())
        for value in (None, "", "PRODUCTION", "UNKNOWN"):
            plan = planner.plan_xss_agent_identity(maturity=value)
            self.assertEqual(plan["maturity"], "UNKNOWN", repr(value))

    def test_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.XSS_SUPPORTED_CONTEXTS),
            {"REFLECTED", "STORED", "DOM", "UNKNOWN"},
        )
        with self.assertRaises(ValidationError):
            schema.XSSAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="xss-agent",
                category="XSS",
                supported_contexts=["REFLECTED", "NOPE"],
            )

    def test_default_contexts(self):
        plan = planner.plan_xss_agent_identity()
        self.assertEqual(
            plan["supported_contexts"], ["REFLECTED", "STORED", "DOM"]
        )
        self.assertNotIn("CONTEXT_UNKNOWN", plan["limitations"])

    def test_invalid_contexts_filtered_or_unknown(self):
        plan = planner.plan_xss_agent_identity(
            supported_contexts=["REFLECTED", "NOPE", "DOM"]
        )
        self.assertEqual(plan["supported_contexts"], ["REFLECTED", "DOM"])
        plan = planner.plan_xss_agent_identity(
            supported_contexts=["NOPE", "WRONG"]
        )
        self.assertEqual(plan["supported_contexts"], ["UNKNOWN"])
        self.assertIn("CONTEXT_UNKNOWN", plan["limitations"])

    def test_deterministic_agent_id(self):
        first = planner.plan_xss_agent_identity()
        second = planner.plan_xss_agent_identity()
        self.assertEqual(first["agent_id"], second["agent_id"])
        self.assertTrue(
            r38_identity.AGENT_ID_RE.match(first["agent_id"])
        )
        self.assertEqual(
            planner.compute_xss_agent_id("xss-agent", "2.0"),
            first["agent_id"],
        )

    def test_agent_id_changes_with_version(self):
        old = planner.plan_xss_agent_identity(version="1.0")["agent_id"]
        new = planner.plan_xss_agent_identity(version="2.0")["agent_id"]
        self.assertNotEqual(old, new)

    def test_every_known_maturity_accepted(self):
        for maturity in schema.XSS_KNOWN_MATURITIES:
            plan = planner.plan_xss_agent_identity(maturity=maturity)
            self.assertEqual(plan["maturity"], maturity)

    def test_r38_conformance(self):
        plan = planner.plan_xss_agent_identity(maturity="RESEARCH")
        projected = planner.xss_agent_identity_to_r38(plan)
        validated = r38_identity.SecurityAgentIdentityPlan(**projected)
        self.assertEqual(validated.category, "XSS")
        self.assertIn(
            validated.category, r38_identity.AGENT_CATEGORIES
        )
        self.assertIn(
            validated.maturity, r38_identity.AGENT_MATURITIES
        )
        self.assertTrue(
            r38_identity.AGENT_ID_RE.match(validated.agent_id)
        )
        self.assertIs(validated.research_only, True)

    def test_malformed_identity_projects_to_defaults(self):
        for bad in (None, "", 42, [], {"agent_id": "bad"}):
            projected = planner.xss_agent_identity_to_r38(bad)
            validated = r38_identity.SecurityAgentIdentityPlan(**projected)
            self.assertEqual(validated.category, "XSS")
            self.assertTrue(
                r38_identity.AGENT_ID_RE.match(validated.agent_id)
            )

    def test_deterministic_output(self):
        first = planner.plan_xss_agent_identity()
        second = planner.plan_xss_agent_identity()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = planner.plan_xss_agent_identity()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            planner.plan_xss_agent_identity()["research_only"], True
        )
        with self.assertRaises(ValidationError):
            schema.XSSAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="xss-agent",
                category="XSS",
                research_only=False,
            )

    def test_schema_forces_rule_version_and_rejects_extra(self):
        plan = schema.XSSAgentIdentityPlan(
            rule_version="r99-9",
            agent_id="sa-" + "a" * 16,
            agent_name="xss-agent",
            category="XSS",
            maturity="RESEARCH",
        )
        self.assertEqual(plan.rule_version, "r39-1")
        with self.assertRaises(ValidationError):
            schema.XSSAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="xss-agent",
                category="XSS",
                exploit="x",
            )

    def test_no_execution_content(self):
        blob = json.dumps(
            planner.plan_xss_agent_identity()
        ).lower()
        for marker in (
            "http://", "https://", "nuclei", "sqlmap", "subprocess",
            "shell", "browser", "fuzzer", "worker", "scheduler",
            "timestamp", "api_key",
        ):
            self.assertNotIn(marker, blob)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.XSS_AGENT_IDENTITY_PLANNER_RULE_VERSION, "r39-1"
        )
        self.assertEqual(
            planner.plan_xss_agent_identity()["rule_version"], "r39-1"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
