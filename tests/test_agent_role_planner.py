"""tests/test_agent_role_planner.py — Stage R35.1 tests.

Deterministic, offline tests for the agent role planner plus hermetic backend
integration for the R35 orchestration layer:

- deterministic output
- every strategy -> role mapping
- empty strategy and invalid input
- no mutation, JSON serialization, vocabulary validation
- research_only always true, no operational execution content
- backend additive fields for R35.1-R35.4 (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import agent_role_planner as arp
from ai.knowledge.relevance import AssetRecord
from ai.schemas import agent_role_plan as schema
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1560"


def strategy(strategy_type="UNKNOWN", confidence="UNKNOWN"):
    return {
        "rule_version": "r34-1",
        "strategy_type": strategy_type,
        "strategy_reason": "MALFORMED_INPUT",
        "historical_basis": "MALFORMED_INPUT",
        "confidence_level": confidence,
        "blockers": [],
        "research_only": True,
    }


class TestRoleMappings(unittest.TestCase):
    def test_every_strategy_maps(self):
        expectations = (
            ("IDENTITY_FIRST",
             ["ASSET_ANALYSIS", "IDENTITY_ANALYSIS"],
             "IDENTITY_STRATEGY"),
            ("VERSION_FIRST",
             ["VERSION_ANALYSIS", "EVIDENCE_ANALYSIS"],
             "VERSION_STRATEGY"),
            ("TECHNOLOGY_FIRST",
             ["TECHNOLOGY_ANALYSIS", "EVIDENCE_ANALYSIS"],
             "TECHNOLOGY_STRATEGY"),
            ("EVIDENCE_FIRST",
             ["EVIDENCE_ANALYSIS", "HISTORY_ANALYSIS"],
             "EVIDENCE_STRATEGY"),
            ("SCOPE_FIRST",
             ["ASSET_ANALYSIS", "EVIDENCE_ANALYSIS"],
             "SCOPE_STRATEGY"),
            ("HUMAN_REVIEW_FIRST", ["HUMAN_REVIEW"],
             "HUMAN_REVIEW_STRATEGY"),
            ("DEFERRED", ["HUMAN_REVIEW"], "DEFERRED_STRATEGY"),
            ("UNKNOWN", ["HISTORY_ANALYSIS"], "UNKNOWN_STRATEGY"),
        )
        for strategy_type, roles, reason in expectations:
            plan = arp.plan_agent_roles(strategy(strategy_type, "HIGH"))
            self.assertEqual(plan["required_roles"], roles, strategy_type)
            self.assertEqual(plan["primary_role"], roles[0], strategy_type)
            self.assertEqual(plan["role_reason"], reason, strategy_type)
            self.assertEqual(plan["confidence_level"], "HIGH")

    def test_deferred_human_review(self):
        plan = arp.plan_agent_roles(strategy("DEFERRED", "LOW"))
        self.assertEqual(plan["required_roles"], ["HUMAN_REVIEW"])
        self.assertEqual(plan["primary_role"], "HUMAN_REVIEW")

    def test_confidence_passthrough(self):
        for confidence in ("HIGH", "MEDIUM", "LOW"):
            plan = arp.plan_agent_roles(
                strategy("VERSION_FIRST", confidence)
            )
            self.assertEqual(plan["confidence_level"], confidence)

    def test_invalid_confidence_defaults_unknown(self):
        plan = arp.plan_agent_roles(
            strategy("VERSION_FIRST", "CERTAIN")
        )
        self.assertEqual(plan["confidence_level"], "UNKNOWN")

    def test_empty_strategy(self):
        for value in (None, {}, [], "x", 0):
            plan = arp.plan_agent_roles(value)
            self.assertEqual(plan["required_roles"],
                             ["HISTORY_ANALYSIS"], repr(value))
            self.assertEqual(plan["role_reason"], "UNKNOWN_STRATEGY")
            self.assertEqual(plan["confidence_level"], "UNKNOWN")

    def test_unrecognized_strategy(self):
        plan = arp.plan_agent_roles(
            {"strategy_type": "WIN_FIRST", "confidence_level": "HIGH"}
        )
        self.assertEqual(plan["required_roles"], ["HISTORY_ANALYSIS"])
        self.assertEqual(plan["role_reason"], "UNKNOWN_STRATEGY")

    def test_deterministic_output(self):
        plan = strategy("VERSION_FIRST", "HIGH")
        first = arp.plan_agent_roles(plan)
        second = arp.plan_agent_roles(plan)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        plan = strategy("TECHNOLOGY_FIRST", "MEDIUM")
        before = copy.deepcopy(plan)
        arp.plan_agent_roles(plan)
        self.assertEqual(plan, before)

    def test_primary_role_is_first_required_role(self):
        for strategy_type in (
            "IDENTITY_FIRST", "VERSION_FIRST", "TECHNOLOGY_FIRST",
            "EVIDENCE_FIRST", "SCOPE_FIRST", "HUMAN_REVIEW_FIRST",
            "DEFERRED", "UNKNOWN",
        ):
            plan = arp.plan_agent_roles(strategy(strategy_type, "HIGH"))
            self.assertEqual(plan["primary_role"],
                             plan["required_roles"][0], strategy_type)

    def test_json_serializable(self):
        plan = arp.plan_agent_roles(strategy("VERSION_FIRST", "HIGH"))
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        for value in (None, strategy("VERSION_FIRST", "HIGH")):
            plan = arp.plan_agent_roles(value)
            self.assertIs(plan["research_only"], True)

    def test_no_operational_execution_content(self):
        blob = json.dumps(
            [
                arp.plan_agent_roles(strategy(name, "HIGH"))
                for name in (
                    "EVIDENCE_FIRST", "IDENTITY_FIRST",
                    "TECHNOLOGY_FIRST", "VERSION_FIRST", "SCOPE_FIRST",
                    "HUMAN_REVIEW_FIRST", "DEFERRED", "UNKNOWN",
                )
            ]
        ).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body", "dispatch",
            "worker", "scheduler", "execute",
        ):
            self.assertNotIn(marker, blob)

    def test_vocabulary_is_closed(self):
        self.assertEqual(
            set(schema.AGENT_ROLES),
            {
                "ASSET_ANALYSIS", "IDENTITY_ANALYSIS",
                "TECHNOLOGY_ANALYSIS", "VERSION_ANALYSIS",
                "EVIDENCE_ANALYSIS", "HISTORY_ANALYSIS",
                "HUMAN_REVIEW",
            },
        )
        pattern = set()
        for roles, _reason in arp.STRATEGY_ROLES.values():
            pattern.update(roles)
        self.assertTrue(pattern.issubset(set(schema.AGENT_ROLES)))

    def test_schema_rejects_bad_values(self):
        base = {
            "required_roles": ["VERSION_ANALYSIS"],
            "primary_role": "VERSION_ANALYSIS",
            "role_reason": "VERSION_STRATEGY",
            "confidence_level": "HIGH",
        }
        for key, value in (
            ("required_roles", ["RUN_SCAN"]),
            ("primary_role", "EXECUTOR"),
            ("role_reason", "BECAUSE"),
            ("confidence_level", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.AgentRolePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.AgentRolePlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.AgentRolePlan(
            rule_version="r99-9",
            required_roles=["HUMAN_REVIEW"],
            primary_role="HUMAN_REVIEW",
            role_reason="UNKNOWN_STRATEGY",
            confidence_level="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r35-1")
        with self.assertRaises(ValidationError):
            schema.AgentRolePlan(
                required_roles=["HUMAN_REVIEW"],
                primary_role="HUMAN_REVIEW",
                role_reason="UNKNOWN_STRATEGY",
                confidence_level="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(arp.AGENT_ROLE_PLANNER_RULE_VERSION, "r35-1")
        plan = arp.plan_agent_roles()
        self.assertEqual(plan["rule_version"], "r35-1")


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R35.1-R35.4
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
            ("agent_role_plan", "r35-1"),
            ("research_workflow_graph_plan", "r35-2"),
            ("agent_coordination_plan", "r35-3"),
            ("research_orchestration_export_plan", "r35-4"),
        ):
            self.assertEqual(item[key]["rule_version"], version)
            self.assertIs(item[key]["research_only"], True)
        for key in (
            "agent_role_plan_rule_version",
            "research_workflow_graph_plan_rule_version",
            "agent_coordination_plan_rule_version",
            "research_orchestration_export_plan_rule_version",
        ):
            self.assertIn(key, item)
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["research_strategy_export_plan_rule_version"], "r34-4"
        )

    def test_backend_immediate_plan_orchestration(self):
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
            item["agent_role_plan"]["required_roles"],
            ["EVIDENCE_ANALYSIS", "HISTORY_ANALYSIS"],
        )
        self.assertEqual(
            item["research_workflow_graph_plan"]["nodes"],
            ["COLLECT_EVIDENCE_PLAN", "REVIEW_HISTORY"],
        )
        self.assertEqual(
            item["agent_coordination_plan"]["coordination_mode"],
            "SEQUENTIAL",
        )
        self.assertTrue(
            item["research_orchestration_export_plan"]["ready"]
        )
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_review_gate(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["agent_role_plan"]["required_roles"], ["HUMAN_REVIEW"]
        )
        self.assertEqual(
            item["research_workflow_graph_plan"]["nodes"], ["STOP"]
        )
        self.assertEqual(
            item["agent_coordination_plan"]["coordination_mode"],
            "REVIEW_GATE",
        )
        self.assertIn(
            "DEFERRED_STRATEGY",
            item["research_orchestration_export_plan"]["limitations"],
        )

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "research_strategy_plan",
            "research_strategy_export_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["agent_role_plan"],
            item["research_orchestration_export_plan"],
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
