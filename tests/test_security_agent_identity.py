"""tests/test_security_agent_identity.py — Stage R38.1 tests.

Deterministic, offline tests for the security agent identity planner:

- identity validation and deterministic agent ids
- exact category and maturity vocabularies
- unknown categories/maturities remain UNKNOWN
- malformed and empty input handling
- no mutation, JSON serialization, schema validation
- research_only always true, no execution content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_identity as sai
from ai.schemas import security_agent_identity as schema


class TestSecurityAgentIdentity(unittest.TestCase):
    def test_categories_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.AGENT_CATEGORIES),
            {"XSS", "SSRF", "SQLI", "IDOR", "JWT", "OAUTH",
             "CVE_RESEARCH", "RECON", "UNKNOWN"},
        )

    def test_maturity_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.AGENT_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE", "UNKNOWN"},
        )

    def test_known_identity(self):
        plan = sai.plan_security_agent_identity(
            "XSS", maturity="RESEARCH", version="1.0"
        )
        self.assertEqual(plan["category"], "XSS")
        self.assertEqual(plan["agent_name"], "xss-agent")
        self.assertEqual(plan["maturity"], "RESEARCH")
        self.assertEqual(plan["version"], "1.0")
        self.assertTrue(schema.AGENT_ID_RE.match(plan["agent_id"]))

    def test_unknown_category_stays_unknown(self):
        for value in (None, "", "NOPE", "xss-sql"):
            plan = sai.plan_security_agent_identity(value)
            self.assertEqual(plan["category"], "UNKNOWN", repr(value))
            self.assertEqual(plan["agent_name"], "unknown-agent")

    def test_unknown_maturity_stays_unknown(self):
        for value in (None, "", "PRODUCTION"):
            plan = sai.plan_security_agent_identity("XSS", maturity=value)
            self.assertEqual(plan["maturity"], "UNKNOWN", repr(value))

    def test_lowercase_category_normalized(self):
        plan = sai.plan_security_agent_identity("ssrf")
        self.assertEqual(plan["category"], "SSRF")

    def test_deterministic_agent_id(self):
        first = sai.plan_security_agent_identity("JWT")
        second = sai.plan_security_agent_identity("JWT")
        self.assertEqual(first["agent_id"], second["agent_id"])
        self.assertEqual(
            sai.compute_agent_id("JWT", "jwt-agent", "UNKNOWN"),
            first["agent_id"],
        )

    def test_agent_id_changes_with_identity(self):
        xss = sai.plan_security_agent_identity("XSS")["agent_id"]
        ssrf = sai.plan_security_agent_identity("SSRF")["agent_id"]
        self.assertNotEqual(xss, ssrf)

    def test_every_category_has_identity(self):
        for category in schema.AGENT_CATEGORIES:
            plan = sai.plan_security_agent_identity(category)
            self.assertEqual(plan["category"], category)
            self.assertTrue(schema.AGENT_ID_RE.match(plan["agent_id"]))

    def test_deterministic_output(self):
        first = sai.plan_security_agent_identity("RECON")
        second = sai.plan_security_agent_identity("RECON")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = sai.plan_security_agent_identity("XSS")
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            sai.plan_security_agent_identity()["research_only"], True
        )

    def test_descriptions_are_redacted(self):
        plan = sai.plan_security_agent_identity(
            "XSS", description="token=SECRETVALUE"
        )
        self.assertNotIn("SECRETVALUE", json.dumps(plan))

    def test_no_execution_content(self):
        blob = json.dumps(
            [
                sai.plan_security_agent_identity(category)
                for category in schema.AGENT_CATEGORIES
            ]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
            "timestamp", "api_key",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.SecurityAgentIdentityPlan(
                agent_id="not-an-id", agent_name="x", category="XSS"
            )
        with self.assertRaises(ValidationError):
            schema.SecurityAgentIdentityPlan(
                agent_id="sa-" + "a" * 16, agent_name="x",
                category="NOPE",
            )
        with self.assertRaises(ValidationError):
            schema.SecurityAgentIdentityPlan(
                agent_id="sa-" + "a" * 16, agent_name="x",
                category="XSS", maturity="PRODUCTION",
            )
        with self.assertRaises(ValidationError):
            schema.SecurityAgentIdentityPlan(
                agent_id="sa-" + "a" * 16, agent_name="x",
                category="XSS", severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentIdentityPlan(
            rule_version="r99-9",
            agent_id="sa-" + "a" * 16,
            agent_name="xss-agent",
            category="XSS",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r38-1")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="xss-agent",
                category="XSS",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            sai.SECURITY_AGENT_IDENTITY_PLANNER_RULE_VERSION, "r38-1"
        )
        self.assertEqual(
            sai.plan_security_agent_identity()["rule_version"], "r38-1"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
