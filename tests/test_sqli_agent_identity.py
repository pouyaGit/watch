"""tests/test_sqli_agent_identity.py — Stage R41.1 tests.

Deterministic, offline tests for the SQLi specialist agent identity:

- fixed SQLI category and R38-conformant agent ids
- maturity, supported-context, capability and lifecycle restrictions
- R38 SecurityAgentIdentity conformance
- malformed/empty input handling, JSON serialization
- research_only always true, no execution content

No SQL, no database, no network, no LLM, no subprocess, no sqlmap, no
sockets, no browser, no payloads, no Mongo writes, no persistence, no
execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import sqli_agent_identity as planner
from ai.schemas import security_agent_capability as r38_capability
from ai.schemas import security_agent_identity as r38_identity
from ai.schemas import sqli_agent_identity as schema


class TestSQLIAgentIdentity(unittest.TestCase):
    def test_category_is_fixed_to_sqli(self):
        plan = planner.plan_sqli_agent_identity()
        self.assertEqual(plan["category"], "SQLI")
        self.assertEqual(plan["category"], schema.SQLI_CATEGORY)
        with self.assertRaises(ValidationError):
            schema.SQLIAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="sqli-agent",
                category="XSS",
            )

    def test_maturity_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SQLI_AGENT_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE", "UNKNOWN"},
        )
        self.assertEqual(
            set(schema.SQLI_KNOWN_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE"},
        )
        with self.assertRaises(ValidationError):
            schema.SQLIAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="sqli-agent",
                category="SQLI",
                maturity="PRODUCTION",
            )

    def test_maturity_normalized_and_unknown(self):
        for value in ("experimental", "Research", "STABLE"):
            plan = planner.plan_sqli_agent_identity(maturity=value)
            self.assertEqual(plan["maturity"], value.upper())
        for value in (None, "", "PRODUCTION", "UNKNOWN"):
            plan = planner.plan_sqli_agent_identity(maturity=value)
            self.assertEqual(plan["maturity"], "UNKNOWN", repr(value))

    def test_supported_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SQLI_SUPPORTED_CONTEXTS),
            {"WHERE", "ORDER_BY", "LIMIT", "OFFSET", "SELECT", "INSERT",
             "UPDATE", "DELETE", "UNKNOWN"},
        )
        with self.assertRaises(ValidationError):
            schema.SQLIAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="sqli-agent",
                category="SQLI",
                supported_contexts=["WHERE", "NOPE"],
            )

    def test_default_scope(self):
        plan = planner.plan_sqli_agent_identity()
        self.assertEqual(
            plan["supported_contexts"],
            ["WHERE", "ORDER_BY", "LIMIT", "OFFSET", "SELECT", "INSERT",
             "UPDATE", "DELETE"],
        )
        self.assertNotIn("SCOPE_UNKNOWN", plan["limitations"])

    def test_invalid_contexts_filtered_or_unknown(self):
        plan = planner.plan_sqli_agent_identity(
            supported_contexts=["WHERE", "NOPE", "ORDER_BY"]
        )
        self.assertEqual(plan["supported_contexts"], ["WHERE", "ORDER_BY"])
        plan = planner.plan_sqli_agent_identity(
            supported_contexts=["NOPE", "WRONG"]
        )
        self.assertEqual(plan["supported_contexts"], ["UNKNOWN"])
        self.assertIn("SCOPE_UNKNOWN", plan["limitations"])

    def test_capabilities_are_analysis_only(self):
        plan = planner.plan_sqli_agent_identity()
        self.assertEqual(
            plan["supported_capabilities"],
            list(r38_capability.ALLOWED_CAPABILITIES),
        )
        for capability in plan["supported_capabilities"]:
            self.assertIn(capability, r38_capability.ALLOWED_CAPABILITIES)
            self.assertNotIn(
                capability, r38_capability.PROHIBITED_CAPABILITIES
            )

    def test_prohibited_capabilities_rejected(self):
        with self.assertRaises(ValidationError):
            schema.SQLIAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="sqli-agent",
                category="SQLI",
                supported_capabilities=["ANALYZE_CONTEXT",
                                        "EXECUTE_EXPLOIT"],
            )
        for prohibited in r38_capability.PROHIBITED_CAPABILITIES:
            with self.assertRaises(ValidationError):
                schema.SQLIAgentIdentityPlan(
                    agent_id="sa-" + "a" * 16,
                    agent_name="sqli-agent",
                    category="SQLI",
                    supported_capabilities=[prohibited],
                )

    def test_prohibited_capabilities_filtered_by_planner(self):
        plan = planner.plan_sqli_agent_identity(
            supported_capabilities=[
                "ANALYZE_CONTEXT", "RUN_PAYLOAD", "MODIFY_TARGET",
                "NOT_A_CAPABILITY",
            ]
        )
        self.assertEqual(
            plan["supported_capabilities"], ["ANALYZE_CONTEXT"]
        )

    def test_lifecycle_restricted_to_identity_states(self):
        self.assertEqual(
            set(schema.SQLI_IDENTITY_LIFECYCLE_STATES),
            {"CREATED", "PLANNED"},
        )
        self.assertEqual(
            planner.plan_sqli_agent_identity()["lifecycle_state"],
            "PLANNED",
        )
        self.assertEqual(
            planner.plan_sqli_agent_identity(
                lifecycle_state="created"
            )["lifecycle_state"],
            "CREATED",
        )
        for bad in ("ANALYZING", "COMPLETED", "FAILED", "RUNNING"):
            self.assertEqual(
                planner.plan_sqli_agent_identity(
                    lifecycle_state=bad
                )["lifecycle_state"],
                "PLANNED",
                bad,
            )
            with self.assertRaises(ValidationError):
                schema.SQLIAgentIdentityPlan(
                    agent_id="sa-" + "a" * 16,
                    agent_name="sqli-agent",
                    category="SQLI",
                    lifecycle_state=bad,
                )

    def test_deterministic_agent_id(self):
        first = planner.plan_sqli_agent_identity()
        second = planner.plan_sqli_agent_identity()
        self.assertEqual(first["agent_id"], second["agent_id"])
        self.assertTrue(
            r38_identity.AGENT_ID_RE.match(first["agent_id"])
        )
        self.assertEqual(
            planner.compute_sqli_agent_id("sqli-agent", "1.0"),
            first["agent_id"],
        )

    def test_agent_id_changes_with_version(self):
        old = planner.plan_sqli_agent_identity(version="1.0")["agent_id"]
        new = planner.plan_sqli_agent_identity(version="1.1")["agent_id"]
        self.assertNotEqual(old, new)

    def test_r38_conformance(self):
        plan = planner.plan_sqli_agent_identity(maturity="RESEARCH")
        projected = planner.sqli_agent_identity_to_r38(plan)
        validated = r38_identity.SecurityAgentIdentityPlan(**projected)
        self.assertEqual(validated.category, "SQLI")
        self.assertIn(validated.category, r38_identity.AGENT_CATEGORIES)
        self.assertIn(validated.maturity, r38_identity.AGENT_MATURITIES)
        self.assertTrue(
            r38_identity.AGENT_ID_RE.match(validated.agent_id)
        )
        self.assertIs(validated.research_only, True)

    def test_malformed_identity_projects_to_defaults(self):
        for bad in (None, "", 42, [], {"agent_id": "bad"}):
            projected = planner.sqli_agent_identity_to_r38(bad)
            validated = r38_identity.SecurityAgentIdentityPlan(**projected)
            self.assertEqual(validated.category, "SQLI")
            self.assertTrue(
                r38_identity.AGENT_ID_RE.match(validated.agent_id)
            )

    def test_deterministic_output_and_json(self):
        first = planner.plan_sqli_agent_identity()
        second = planner.plan_sqli_agent_identity()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            planner.plan_sqli_agent_identity()["research_only"], True
        )
        with self.assertRaises(ValidationError):
            schema.SQLIAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="sqli-agent",
                category="SQLI",
                research_only=False,
            )

    def test_schema_forces_rule_version_and_rejects_extra(self):
        plan = schema.SQLIAgentIdentityPlan(
            rule_version="r99-9",
            agent_id="sa-" + "a" * 16,
            agent_name="sqli-agent",
            category="SQLI",
            maturity="RESEARCH",
        )
        self.assertEqual(plan.rule_version, "r41-1")
        with self.assertRaises(ValidationError):
            schema.SQLIAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="sqli-agent",
                category="SQLI",
                payload="' OR 1=1 --",
            )

    def test_no_execution_content(self):
        blob = json.dumps(planner.plan_sqli_agent_identity()).lower()
        for marker in (
            "select ", "union ", "drop ", "insert into", "1=1",
            "sqlmap", "sqlite3", "psycopg", "pymysql", "sqlalchemy",
            "subprocess", "socket", "shell", "timestamp", "api_key",
        ):
            self.assertNotIn(marker, blob)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SQLI_AGENT_IDENTITY_PLANNER_RULE_VERSION, "r41-1"
        )
        self.assertEqual(
            planner.plan_sqli_agent_identity()["rule_version"], "r41-1"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
