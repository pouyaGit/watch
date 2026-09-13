"""tests/test_decision_provenance.py — Stage R37.1 tests.

Deterministic, offline tests for the decision provenance tracker plus
hermetic backend integration for the R37 governance layer:

- deterministic decision ids
- provenance completeness / partial / unknown
- malformed and empty input handling
- no mutation, JSON serialization, closed vocabulary validation
- research_only always true, no execution content
- backend additive fields for R37.1-R37.5 (no live Mongo)

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

from ai.knowledge import decision_provenance_tracker as dpt
from ai.knowledge.relevance import AssetRecord
from ai.schemas import decision_provenance as schema
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
    "research_only": True,
}
AUTHORIZATION = {
    "rule_version": "r36-2",
    "decision": "ALLOW_WITH_LIMITS",
    "decision_reason": "RESEARCH_ONLY_LIMITS",
    "policy": "RESEARCH_ONLY",
    "limitations": [],
    "source_strategy": {},
    "source_orchestration": {},
    "research_only": True,
}
POLICY = {
    "rule_version": "r36-1",
    "policy": "RESEARCH_ONLY",
    "policy_reason": "RESEARCH_DEFAULT",
    "constraints": [],
    "research_only": True,
}
RISK = {"rule_version": "r36-4", "risk_level": "MEDIUM",
        "risk_reason": "LIMITED_AUTHORIZATION", "risk_factors": [],
        "authorization_authoritative": True, "research_only": True}
APPROVAL = {"rule_version": "r36-5", "approval_state": "NOT_REQUIRED",
            "approval_reason": "RESEARCH_ONLY_NOT_REQUIRED",
            "required": False, "research_only": True}
BOUNDARY = {"rule_version": "r36-6", "boundary_state": "RESEARCH_ONLY",
            "authorization_result": "ALLOW_WITH_LIMITS",
            "allowed_capabilities": [], "scope": "UNKNOWN",
            "human_approval_required": False, "risk_level": "MEDIUM",
            "constraints": [], "blocked_conditions": [],
            "source_strategy": "VERSION_FIRST", "source_orchestration": {},
            "limitations": [], "execution_permitted": False,
            "execution_performed": False, "research_only": True}


def track(**over):
    kwargs = dict(
        strategy_export=STRATEGY,
        orchestration_export=ORCHESTRATION,
        authorization_plan=AUTHORIZATION,
        policy_plan=POLICY,
        risk_plan=RISK,
        approval_plan=APPROVAL,
        boundary_plan=BOUNDARY,
    )
    kwargs.update(over)
    return dpt.track_decision_provenance(**kwargs)


class TestDecisionProvenance(unittest.TestCase):
    def test_complete_provenance(self):
        plan = track()
        self.assertEqual(plan["provenance_state"], "COMPLETE")
        self.assertEqual(
            plan["contributing_signals"],
            ["STRATEGY", "ORCHESTRATION", "AUTHORIZATION", "POLICY",
             "RISK", "APPROVAL", "BOUNDARY"],
        )
        self.assertTrue(plan["decision_id"].startswith("dp-"))

    def test_partial_provenance(self):
        plan = track(strategy_export=None, policy_plan=None)
        self.assertEqual(plan["provenance_state"], "PARTIAL")
        self.assertNotIn("STRATEGY", plan["contributing_signals"])
        self.assertIn("ORCHESTRATION", plan["contributing_signals"])
        self.assertIn("AUTHORIZATION", plan["contributing_signals"])

    def test_unknown_provenance(self):
        plan = dpt.track_decision_provenance()
        self.assertEqual(plan["provenance_state"], "UNKNOWN")
        self.assertEqual(plan["contributing_signals"], [])

    def test_deterministic_decision_id(self):
        first = track()
        second = track()
        self.assertEqual(first["decision_id"], second["decision_id"])
        self.assertEqual(dpt.compute_decision_id(
            STRATEGY, ORCHESTRATION, AUTHORIZATION, POLICY, RISK,
            APPROVAL, BOUNDARY,
        ), first["decision_id"])

    def test_decision_id_changes_with_context(self):
        base = track()["decision_id"]
        changed = track(authorization_plan={
            **AUTHORIZATION, "decision": "BLOCK"
        })["decision_id"]
        self.assertNotEqual(base, changed)

    def test_empty_decision_id_is_stable(self):
        first = dpt.track_decision_provenance()["decision_id"]
        second = dpt.track_decision_provenance()["decision_id"]
        self.assertEqual(first, second)
        self.assertTrue(schema.DECISION_ID_RE.match(first))

    def test_malformed_inputs(self):
        for value in (None, {}, [], "x", 0):
            plan = track(
                strategy_export=value,
                orchestration_export=value,
                authorization_plan=value,
                policy_plan=value,
                risk_plan=value,
                approval_plan=value,
                boundary_plan=value,
            )
            self.assertEqual(plan["provenance_state"], "UNKNOWN",
                             repr(value))

    def test_deterministic_output(self):
        first = track()
        second = track()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        inputs = (
            STRATEGY, ORCHESTRATION, AUTHORIZATION, POLICY, RISK,
            APPROVAL, BOUNDARY,
        )
        snapshots = tuple(copy.deepcopy(value) for value in inputs)
        track()
        for before, after in zip(snapshots, inputs):
            self.assertEqual(before, after)

    def test_source_snapshots_do_not_alias_inputs(self):
        plan = track()
        plan["source_strategy"]["strategy_type"] = "NOPE"
        self.assertEqual(STRATEGY["strategy"]["strategy_type"],
                         "VERSION_FIRST")

    def test_json_serializable(self):
        self.assertIsInstance(json.loads(json.dumps(track())), dict)

    def test_research_only_always_true(self):
        self.assertIs(track()["research_only"], True)
        self.assertIs(
            dpt.track_decision_provenance()["research_only"], True
        )

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.DecisionProvenancePlan(
                decision_id="not-a-token",
                provenance_state="COMPLETE",
            )
        with self.assertRaises(ValidationError):
            schema.DecisionProvenancePlan(
                decision_id="dp-" + "a" * 16,
                provenance_state="MAYBE",
            )
        with self.assertRaises(ValidationError):
            schema.DecisionProvenancePlan(
                decision_id="dp-" + "a" * 16,
                provenance_state="COMPLETE",
                contributing_signals=["RUN_SCAN"],
            )
        with self.assertRaises(ValidationError):
            schema.DecisionProvenancePlan(
                decision_id="dp-" + "a" * 16,
                provenance_state="COMPLETE",
                severity="HIGH",
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.DecisionProvenancePlan(
            rule_version="r99-9",
            decision_id="dp-" + "a" * 16,
            provenance_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r37-1")
        with self.assertRaises(ValidationError):
            schema.DecisionProvenancePlan(
                decision_id="dp-" + "a" * 16,
                provenance_state="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            dpt.DECISION_PROVENANCE_TRACKER_RULE_VERSION, "r37-1"
        )
        self.assertEqual(track()["rule_version"], "r37-1")

    def test_no_execution_content(self):
        blob = json.dumps(track()).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
            "timestamp",
        ):
            self.assertNotIn(marker, blob)


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo) — covers R37.1-R37.5
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
            ("decision_provenance_plan", "r37-1"),
            ("governance_rule_trace_plan", "r37-2"),
            ("research_audit_event_plan", "r37-3"),
            ("research_explanation_plan", "r37-4"),
            ("research_governance_export_plan", "r37-5"),
        ):
            self.assertEqual(item[key]["rule_version"], version)
            self.assertIs(item[key]["research_only"], True)
        for key in (
            "decision_provenance_plan_rule_version",
            "governance_rule_trace_plan_rule_version",
            "research_audit_event_plan_rule_version",
            "research_explanation_plan_rule_version",
            "research_governance_export_plan_rule_version",
        ):
            self.assertIn(key, item)
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(
            item["research_execution_authorization_export_plan_rule_version"],
            "r36-7",
        )

    def test_backend_default_governance_chain(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["decision_provenance_plan"]["provenance_state"],
            "COMPLETE",
        )
        self.assertEqual(
            item["governance_rule_trace_plan"]["trace_state"], "COMPLETE"
        )
        self.assertEqual(
            item["research_audit_event_plan"]["audit_state"], "VALID"
        )
        self.assertEqual(
            item["research_explanation_plan"]["explanation_state"],
            "COMPLETE",
        )
        governance = item["research_governance_export_plan"]
        self.assertIs(governance["ready"], True)
        self.assertEqual(governance["limitations"], [])
        # The path-only fixture is the terminal blocked candidate.
        self.assertEqual(item["hunt_priority"]["priority"], "DEFER")
        self.assertTrue(item["hunt_priority"]["blocked"])

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "execution_authorization_plan",
            "execution_boundary_plan",
            "research_execution_authorization_export_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["decision_provenance_plan"],
            item["research_governance_export_plan"],
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
