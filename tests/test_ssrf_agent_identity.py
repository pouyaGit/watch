"""tests/test_ssrf_agent_identity.py — Stage R40.1 tests.

Deterministic, offline tests for the SSRF specialist agent identity:

- fixed SSRF category and R38-conformant agent ids
- maturity, supported-context, capability and lifecycle restrictions
- R38 SecurityAgentIdentity conformance
- malformed/empty input handling, JSON serialization
- research_only always true, no execution content

No network, no DNS, no LLM, no subprocess, no sockets, no browser, no
payloads, no target interaction, no Mongo writes, no persistence, no
execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import ssrf_agent_identity as planner
from ai.schemas import security_agent_capability as r38_capability
from ai.schemas import security_agent_identity as r38_identity
from ai.schemas import ssrf_agent_identity as schema


class TestSSRFAgentIdentity(unittest.TestCase):
    def test_category_is_fixed_to_ssrf(self):
        plan = planner.plan_ssrf_agent_identity()
        self.assertEqual(plan["category"], "SSRF")
        self.assertEqual(plan["category"], schema.SSRF_CATEGORY)
        with self.assertRaises(ValidationError):
            schema.SSRFAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="ssrf-agent",
                category="XSS",
            )

    def test_maturity_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SSRF_AGENT_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE", "UNKNOWN"},
        )
        self.assertEqual(
            set(schema.SSRF_KNOWN_MATURITIES),
            {"EXPERIMENTAL", "RESEARCH", "STABLE"},
        )
        with self.assertRaises(ValidationError):
            schema.SSRFAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="ssrf-agent",
                category="SSRF",
                maturity="PRODUCTION",
            )

    def test_maturity_normalized_and_unknown(self):
        for value in ("experimental", "Research", "STABLE"):
            plan = planner.plan_ssrf_agent_identity(maturity=value)
            self.assertEqual(plan["maturity"], value.upper())
        for value in (None, "", "PRODUCTION", "UNKNOWN"):
            plan = planner.plan_ssrf_agent_identity(maturity=value)
            self.assertEqual(plan["maturity"], "UNKNOWN", repr(value))

    def test_supported_context_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.SSRF_SUPPORTED_CONTEXTS),
            {"FULL_URL", "HOST_ONLY", "PATH_OR_URL", "REDIRECT_TARGET",
             "WEBHOOK_TARGET", "RESOURCE_URL", "UNKNOWN"},
        )
        with self.assertRaises(ValidationError):
            schema.SSRFAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="ssrf-agent",
                category="SSRF",
                supported_contexts=["FULL_URL", "NOPE"],
            )

    def test_default_scope(self):
        plan = planner.plan_ssrf_agent_identity()
        self.assertEqual(
            plan["supported_contexts"],
            ["FULL_URL", "HOST_ONLY", "PATH_OR_URL", "REDIRECT_TARGET",
             "WEBHOOK_TARGET", "RESOURCE_URL"],
        )
        self.assertNotIn("SCOPE_UNKNOWN", plan["limitations"])

    def test_invalid_contexts_filtered_or_unknown(self):
        plan = planner.plan_ssrf_agent_identity(
            supported_contexts=["FULL_URL", "NOPE", "WEBHOOK_TARGET"]
        )
        self.assertEqual(
            plan["supported_contexts"], ["FULL_URL", "WEBHOOK_TARGET"]
        )
        plan = planner.plan_ssrf_agent_identity(
            supported_contexts=["NOPE", "WRONG"]
        )
        self.assertEqual(plan["supported_contexts"], ["UNKNOWN"])
        self.assertIn("SCOPE_UNKNOWN", plan["limitations"])

    def test_capabilities_are_analysis_only(self):
        plan = planner.plan_ssrf_agent_identity()
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
            schema.SSRFAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="ssrf-agent",
                category="SSRF",
                supported_capabilities=["ANALYZE_CONTEXT",
                                        "EXECUTE_EXPLOIT"],
            )
        for prohibited in r38_capability.PROHIBITED_CAPABILITIES:
            with self.assertRaises(ValidationError):
                schema.SSRFAgentIdentityPlan(
                    agent_id="sa-" + "a" * 16,
                    agent_name="ssrf-agent",
                    category="SSRF",
                    supported_capabilities=[prohibited],
                )

    def test_prohibited_capabilities_filtered_by_planner(self):
        plan = planner.plan_ssrf_agent_identity(
            supported_capabilities=[
                "ANALYZE_CONTEXT", "RUN_PAYLOAD", "BYPASS_AUTH",
                "NOT_A_CAPABILITY",
            ]
        )
        self.assertEqual(
            plan["supported_capabilities"], ["ANALYZE_CONTEXT"]
        )

    def test_lifecycle_restricted_to_identity_states(self):
        self.assertEqual(
            set(schema.SSRF_IDENTITY_LIFECYCLE_STATES),
            {"CREATED", "PLANNED"},
        )
        self.assertEqual(
            planner.plan_ssrf_agent_identity()["lifecycle_state"],
            "PLANNED",
        )
        self.assertEqual(
            planner.plan_ssrf_agent_identity(
                lifecycle_state="created"
            )["lifecycle_state"],
            "CREATED",
        )
        for bad in ("ANALYZING", "COMPLETED", "FAILED", "RUNNING"):
            self.assertEqual(
                planner.plan_ssrf_agent_identity(
                    lifecycle_state=bad
                )["lifecycle_state"],
                "PLANNED",
                bad,
            )
            with self.assertRaises(ValidationError):
                schema.SSRFAgentIdentityPlan(
                    agent_id="sa-" + "a" * 16,
                    agent_name="ssrf-agent",
                    category="SSRF",
                    lifecycle_state=bad,
                )

    def test_deterministic_agent_id(self):
        first = planner.plan_ssrf_agent_identity()
        second = planner.plan_ssrf_agent_identity()
        self.assertEqual(first["agent_id"], second["agent_id"])
        self.assertTrue(
            r38_identity.AGENT_ID_RE.match(first["agent_id"])
        )
        self.assertEqual(
            planner.compute_ssrf_agent_id("ssrf-agent", "1.0"),
            first["agent_id"],
        )

    def test_agent_id_changes_with_version(self):
        old = planner.plan_ssrf_agent_identity(version="1.0")["agent_id"]
        new = planner.plan_ssrf_agent_identity(version="1.1")["agent_id"]
        self.assertNotEqual(old, new)

    def test_r38_conformance(self):
        plan = planner.plan_ssrf_agent_identity(maturity="RESEARCH")
        projected = planner.ssrf_agent_identity_to_r38(plan)
        validated = r38_identity.SecurityAgentIdentityPlan(**projected)
        self.assertEqual(validated.category, "SSRF")
        self.assertIn(validated.category, r38_identity.AGENT_CATEGORIES)
        self.assertIn(validated.maturity, r38_identity.AGENT_MATURITIES)
        self.assertTrue(
            r38_identity.AGENT_ID_RE.match(validated.agent_id)
        )
        self.assertIs(validated.research_only, True)

    def test_malformed_identity_projects_to_defaults(self):
        for bad in (None, "", 42, [], {"agent_id": "bad"}):
            projected = planner.ssrf_agent_identity_to_r38(bad)
            validated = r38_identity.SecurityAgentIdentityPlan(**projected)
            self.assertEqual(validated.category, "SSRF")
            self.assertTrue(
                r38_identity.AGENT_ID_RE.match(validated.agent_id)
            )

    def test_deterministic_output_and_json(self):
        first = planner.plan_ssrf_agent_identity()
        second = planner.plan_ssrf_agent_identity()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertIsInstance(json.loads(json.dumps(first)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            planner.plan_ssrf_agent_identity()["research_only"], True
        )
        with self.assertRaises(ValidationError):
            schema.SSRFAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="ssrf-agent",
                category="SSRF",
                research_only=False,
            )

    def test_schema_forces_rule_version_and_rejects_extra(self):
        plan = schema.SSRFAgentIdentityPlan(
            rule_version="r99-9",
            agent_id="sa-" + "a" * 16,
            agent_name="ssrf-agent",
            category="SSRF",
            maturity="RESEARCH",
        )
        self.assertEqual(plan.rule_version, "r40-1")
        with self.assertRaises(ValidationError):
            schema.SSRFAgentIdentityPlan(
                agent_id="sa-" + "a" * 16,
                agent_name="ssrf-agent",
                category="SSRF",
                fetch_target="http://127.0.0.1/",
            )

    def test_no_execution_content(self):
        blob = json.dumps(planner.plan_ssrf_agent_identity()).lower()
        for marker in (
            "http://", "https://", "169.254", "127.0.0.1", "localhost",
            "socket", "subprocess", "shell", "curl", "wget", "nuclei",
            "sqlmap", "timestamp", "api_key",
        ):
            self.assertNotIn(marker, blob)

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SSRF_AGENT_IDENTITY_PLANNER_RULE_VERSION, "r40-1"
        )
        self.assertEqual(
            planner.plan_ssrf_agent_identity()["rule_version"], "r40-1"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
