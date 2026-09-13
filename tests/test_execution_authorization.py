"""tests/test_execution_authorization.py — Stage R36.2 tests.

Deterministic, offline tests for the execution authorization planner plus
hermetic backend integration for the R36 boundary:

- exact decision vocabulary
- deterministic authorization precedence
- BLOCK cannot be overridden, HUMAN_APPROVAL_REQUIRED cannot be bypassed
- malformed/empty context -> UNKNOWN
- deterministic output, no mutation, JSON serialization
- schema validation, research_only
- backend additive fields for R36.1-R36.7 (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import execution_authorization_planner as eap
from ai.knowledge.relevance import AssetRecord
from ai.schemas import execution_authorization_plan as schema
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1560"

STRATEGY = {
    "rule_version": "r34-4",
    "ready": True,
    "strategy": {"strategy_type": "VERSION_FIRST",
                 "confidence_level": "HIGH"},
    "path": {"primary_path": "VERIFY_VERSION"},
    "budget": {"budget_state": "CONTINUE"},
    "research_only": True,
}
ORCHESTRATION = {
    "rule_version": "r35-4",
    "ready": True,
    "roles": {"primary_role": "VERSION_ANALYSIS"},
    "workflow": {"nodes": ["ANALYZE_VERSION", "COLLECT_EVIDENCE_PLAN"]},
    "coordination": {"coordination_mode": "SEQUENTIAL"},
    "research_only": True,
}


def authorize(policy):
    plan = eap.plan_execution_policy(STRATEGY, ORCHESTRATION, policy)
    return eap.plan_execution_authorization(
        STRATEGY, ORCHESTRATION, plan
    )


class TestAuthorizationPrecedence(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.AUTHORIZATION_DECISIONS),
            {"ALLOW", "ALLOW_WITH_LIMITS", "REQUIRE_HUMAN_APPROVAL",
             "BLOCK", "UNKNOWN"},
        )

    def test_blocked_policy_blocks(self):
        auth = authorize("BLOCKED")
        self.assertEqual(auth["decision"], "BLOCK")
        self.assertEqual(auth["decision_reason"], "POLICY_BLOCKED")
        self.assertEqual(auth["limitations"], ["BLOCKED"])

    def test_human_approval_required_is_never_bypassed(self):
        auth = authorize("HUMAN_APPROVAL_REQUIRED")
        self.assertEqual(auth["decision"], "REQUIRE_HUMAN_APPROVAL")
        self.assertEqual(auth["decision_reason"],
                         "HUMAN_APPROVAL_REQUIRED")

    def test_research_only_allows_with_limits(self):
        auth = authorize("RESEARCH_ONLY")
        self.assertEqual(auth["decision"], "ALLOW_WITH_LIMITS")
        self.assertEqual(auth["decision_reason"], "RESEARCH_ONLY_LIMITS")
        self.assertEqual(auth["limitations"], ["RESEARCH_ONLY"])

    def test_passive_only_allows_with_limits(self):
        auth = authorize("PASSIVE_ONLY")
        self.assertEqual(auth["decision"], "ALLOW_WITH_LIMITS")
        self.assertEqual(auth["decision_reason"], "PASSIVE_ONLY_LIMITS")

    def test_active_allowed_with_valid_context_allows(self):
        auth = authorize("ACTIVE_ALLOWED")
        self.assertEqual(auth["decision"], "ALLOW")
        self.assertEqual(auth["decision_reason"], "ACTIVE_ALLOWED_VALID")
        self.assertEqual(auth["limitations"], [])

    def test_missing_policy_is_unknown(self):
        auth = eap.plan_execution_authorization(
            STRATEGY, ORCHESTRATION, None
        )
        self.assertEqual(auth["decision"], "UNKNOWN")
        self.assertEqual(auth["decision_reason"], "UNKNOWN_POLICY")

    def test_malformed_context_is_unknown(self):
        for args in (
            (None, None, eap.plan_execution_policy()),
            (STRATEGY, None, eap.plan_execution_policy()),
            (None, ORCHESTRATION, eap.plan_execution_policy()),
            ({"strategy": {"strategy_type": "NOPE"}}, ORCHESTRATION,
             eap.plan_execution_policy()),
            (STRATEGY, {"roles": {"primary_role": "NOPE"},
                        "workflow": {"nodes": []}},
             eap.plan_execution_policy()),
        ):
            auth = eap.plan_execution_authorization(*args)
            self.assertEqual(auth["decision"], "UNKNOWN", repr(args))
            self.assertIn("UNKNOWN_CONTEXT", auth["limitations"])

    def test_active_allowed_requires_valid_context(self):
        policy = eap.plan_execution_policy(
            STRATEGY, ORCHESTRATION, "ACTIVE_ALLOWED"
        )
        auth = eap.plan_execution_authorization(None, None, policy)
        self.assertEqual(auth["decision"], "UNKNOWN")

    def test_context_validator(self):
        self.assertTrue(
            eap.authorization_context_valid(STRATEGY, ORCHESTRATION)
        )
        self.assertFalse(eap.authorization_context_valid(None, ORCHESTRATION))
        self.assertFalse(
            eap.authorization_context_valid(
                STRATEGY, {"roles": {"primary_role": "VERSION_ANALYSIS"}}
            )
        )

    def test_deterministic_output(self):
        first = authorize("BLOCKED")
        second = authorize("BLOCKED")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        strategy = copy.deepcopy(STRATEGY)
        orchestration = copy.deepcopy(ORCHESTRATION)
        policy = eap.plan_execution_policy(
            strategy, orchestration, "BLOCKED"
        )
        eap.plan_execution_authorization(strategy, orchestration, policy)
        self.assertEqual(strategy, STRATEGY)
        self.assertEqual(orchestration, ORCHESTRATION)

    def test_source_snapshots_do_not_alias_inputs(self):
        auth = authorize("BLOCKED")
        auth["source_strategy"]["ready"] = False
        auth["source_orchestration"]["nodes"].clear()
        self.assertTrue(STRATEGY["ready"])
        self.assertEqual(len(ORCHESTRATION["workflow"]["nodes"]), 2)

    def test_json_serializable(self):
        auth = authorize("BLOCKED")
        self.assertIsInstance(json.loads(json.dumps(auth)), dict)

    def test_research_only_always_true(self):
        for value in (None, "BLOCKED"):
            auth = authorize(value)
            self.assertIs(auth["research_only"], True)

    def test_schema_rejects_bad_values(self):
        base = {
            "decision": "BLOCK",
            "decision_reason": "POLICY_BLOCKED",
            "policy": "BLOCKED",
        }
        for key, value in (
            ("decision", "EXECUTE"),
            ("decision_reason", "BECAUSE"),
            ("policy", "RUN_EVERYTHING"),
        ):
            with self.assertRaises(ValidationError):
                schema.ExecutionAuthorizationPlan(
                    **{**base, key: value}
                )
        with self.assertRaises(ValidationError):
            schema.ExecutionAuthorizationPlan(
                **base, limitations=["RUN_SCAN"]
            )
        with self.assertRaises(ValidationError):
            schema.ExecutionAuthorizationPlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ExecutionAuthorizationPlan(
            rule_version="r99-9",
            decision="BLOCK",
            decision_reason="POLICY_BLOCKED",
            policy="BLOCKED",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-2")
        with self.assertRaises(ValidationError):
            schema.ExecutionAuthorizationPlan(
                decision="BLOCK",
                decision_reason="POLICY_BLOCKED",
                policy="BLOCKED",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            eap.EXECUTION_AUTHORIZATION_PLANNER_RULE_VERSION, "r36-2"
        )
        self.assertEqual(authorize("BLOCKED")["rule_version"], "r36-2")

    def test_no_operational_execution_vocabulary(self):
        blob = json.dumps(
            [authorize(value) for value in (
                "RESEARCH_ONLY", "PASSIVE_ONLY", "ACTIVE_ALLOWED",
                "HUMAN_APPROVAL_REQUIRED", "BLOCKED", "UNKNOWN",
            )]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R36.1-R36.7
# ---------------------------------------------------------------------------


def _projection(
    *,
    paths=(),
    components=(),
    provenance=(),
    versions=(),
    associations=(),
    parameters=(),
    parameter_paths=(),
):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": list(components),
        "plugins": [],
        "versions": [
            {"value": value, "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"}
            for value in versions
        ],
        "version_associations": list(associations),
        "parameters": [
            {"value": value, "source": "PARAMETER_INVENTORY",
             "evidence_type": "STRUCTURED_PARAMETER"}
            for value in parameters
        ],
        "paths": [
            {"value": value, "source": "ENDPOINT_INVENTORY",
             "evidence_type": "STRUCTURED_ENDPOINT"}
            for value in paths
        ],
        "component_provenance": list(provenance),
        "parameter_paths": list(parameter_paths),
        "sources": [],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(components=(), parameters=(), versions=()):
    document = SimpleNamespace(
        components=list(components),
        parameters=list(parameters),
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": [], "affected_versions": []},
        "research": {"affected_versions": list(versions)},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class TestBackendIntegration(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()

    def tearDown(self):
        acm.clear_cache()

    def _match(self, inventory, *, components=(), parameters=(),
               versions=()):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ), mock.patch.object(
            acm, "_contexts",
            return_value=_contexts(components, parameters, versions),
        ):
            return acm.build_matches(cve=CVE, program="dell")["items"][0]

    def test_backend_additive_fields_and_rule_versions(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key, version in (
            ("execution_policy_plan", "r36-1"),
            ("execution_authorization_plan", "r36-2"),
            ("scope_capability_gate_plan", "r36-3"),
            ("execution_risk_plan", "r36-4"),
            ("human_approval_gate_plan", "r36-5"),
            ("execution_boundary_plan", "r36-6"),
            ("research_execution_authorization_export_plan", "r36-7"),
        ):
            self.assertEqual(item[key]["rule_version"], version)
            self.assertIs(item[key]["research_only"], True)
        for key in (
            "execution_policy_plan_rule_version",
            "execution_authorization_plan_rule_version",
            "scope_capability_gate_plan_rule_version",
            "execution_risk_plan_rule_version",
            "human_approval_gate_plan_rule_version",
            "execution_boundary_plan_rule_version",
            "research_execution_authorization_export_plan_rule_version",
        ):
            self.assertIn(key, item)
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["research_orchestration_export_plan_rule_version"], "r35-4"
        )

    def test_backend_default_policy_is_research_only(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["execution_policy_plan"]["policy"], "RESEARCH_ONLY"
        )
        self.assertEqual(
            item["execution_authorization_plan"]["decision"],
            "ALLOW_WITH_LIMITS",
        )
        self.assertEqual(
            item["execution_boundary_plan"]["boundary_state"],
            "RESEARCH_ONLY",
        )
        self.assertFalse(
            item["execution_boundary_plan"]["execution_performed"]
        )
        self.assertFalse(
            item["execution_boundary_plan"]["execution_permitted"]
        )
        # The global (non-component) support scope is conservatively UNKNOWN,
        # so the authorization export is not ready.
        export = item["research_execution_authorization_export_plan"]
        self.assertFalse(export["ready"])
        self.assertIn("UNKNOWN_SCOPE", export["limitations"])
        self.assertIn("MISSING_SCOPE", export["limitations"])

    def test_backend_scope_gate_is_conservative_without_component_scope(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        gate = item["scope_capability_gate_plan"]
        self.assertEqual(gate["scope"], "UNKNOWN")
        self.assertEqual(gate["scope_certainty"], "UNKNOWN")
        self.assertFalse(gate["authorized"])

    def test_backend_immediate_plan_boundary(self):
        item = self._match(
            _projection(
                paths=["/assets/ckeditor/config.js"],
                components=[{
                    "value": "CKEditor",
                    "source": "COMPONENT_INVENTORY",
                    "evidence_type": "STRUCTURED_COMPONENT",
                }],
                versions=["1.2.3"],
                associations=[{
                    "version": "1.2.3",
                    "technology_family": "CKEditor",
                    "component": "CKEditor",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }],
            ),
            components=["CKEditor", "/assets/ckeditor/config.js"],
            versions=["<=1.2.3"],
        )
        self.assertEqual(
            item["scope_capability_gate_plan"]["scope"],
            "UNKNOWN",
        )
        self.assertEqual(
            item["scope_capability_gate_plan"]["scope_certainty"],
            "UNKNOWN",
        )
        self.assertFalse(
            item["scope_capability_gate_plan"]["authorized"]
        )
        self.assertFalse(
            item["human_approval_gate_plan"]["required"]
        )
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "research_strategy_export_plan",
            "research_orchestration_export_plan",
            "agent_role_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["execution_policy_plan"],
            item["research_execution_authorization_export_plan"],
        )

    def test_backend_money_score_unchanged(self):
        from backend import research_economics

        before = research_economics.build_economics()
        self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        after = research_economics.build_economics()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
