"""Full offline integration test: R61 fixture -> R31-R38 -> R59 -> R60.

No MongoDB, no network, no target interaction. The chain is driven entirely by
the R61 sanitized fixture and the injected-inventory seam.
"""

from __future__ import annotations

import unittest
from unittest import mock

from tests.local_e2e import r62_bridge as br
from tests.local_e2e import recon_snapshot as rs
from tests.local_e2e.fake_mongo import client_from_fixture, load_fixture

CVE = "CVE-2024-27956"

FIXTURE = load_fixture()
SNAPSHOT = rs.build_snapshot("indeed", client=client_from_fixture(FIXTURE))
PIPELINE = br.pipeline(SNAPSHOT, cve=CVE)


class TestFullOfflinePipeline(unittest.TestCase):
    def test_all_chain_stages_are_present(self):
        for key in (
            "inventory",
            "r31",
            "specialist_signals",
            "research_context",
            "intelligence_context",
            "workflow",
            "copilot",
        ):
            self.assertIsNotNone(PIPELINE[key], key)
        self.assertEqual(PIPELINE["inventory"]["program"], "indeed")
        self.assertEqual(PIPELINE["r31"]["cve_id"], CVE)

    def test_r31_r38_layers_are_available(self):
        item = PIPELINE["r31"]
        for key in (
            "hunt_priority",
            "hunt_actionability",
            "hunt_action_plan",
            "evidence_quality",
            "evidence_acquisition_plan",
            "evidence_prioritization_plan",
            "evidence_confidence_plan",
            "evidence_decision_plan",
            "evidence_research_loop_plan",
            "evidence_research_outcome_plan",
            "evidence_feedback_calibration_plan",
            "research_intelligence_summary_plan",
            "research_consistency_validation_plan",
            "research_intelligence_export_plan",
            "research_memory_snapshot",
            "research_history_plan",
            "research_pattern_plan",
            "research_memory_export_plan",
            "research_pattern_intelligence_plan",
            "historical_candidate_ranking_plan",
            "research_efficiency_plan",
            "research_learning_export_plan",
            "research_strategy_plan",
            "research_path_plan",
            "research_budget_plan",
            "research_strategy_export_plan",
            "agent_role_plan",
            "research_workflow_graph_plan",
            "agent_coordination_plan",
            "research_orchestration_export_plan",
            "execution_policy_plan",
            "execution_authorization_plan",
            "scope_capability_gate_plan",
            "execution_risk_plan",
            "human_approval_gate_plan",
            "execution_boundary_plan",
            "research_execution_authorization_export_plan",
            "decision_provenance_plan",
            "governance_rule_trace_plan",
            "research_audit_event_plan",
            "research_explanation_plan",
            "research_governance_export_plan",
            "security_agent_framework_plan",
        ):
            self.assertIn(key, item, key)

    def test_r31_r38_rule_versions_are_real(self):
        versions = PIPELINE["intelligence_context"]["r31_rule_versions"]
        self.assertEqual(versions["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(versions["evidence_quality_rule_version"], "r31-9")
        self.assertEqual(
            versions["research_intelligence_export_plan_rule_version"],
            "r31-22",
        )
        self.assertEqual(
            versions["research_memory_export_plan_rule_version"], "r32-4"
        )
        self.assertEqual(
            versions["research_learning_export_plan_rule_version"], "r33-4"
        )
        self.assertEqual(
            versions["research_strategy_export_plan_rule_version"], "r34-4"
        )
        self.assertEqual(
            versions["research_orchestration_export_plan_rule_version"],
            "r35-4",
        )
        self.assertEqual(
            versions[
                "research_execution_authorization_export_plan_rule_version"
            ],
            "r36-7",
        )
        self.assertEqual(
            versions["research_governance_export_plan_rule_version"],
            "r37-5",
        )
        self.assertEqual(
            versions["security_agent_framework_plan_rule_version"], "r38-7"
        )

    def test_workflow_reaches_research_ready(self):
        workflow = PIPELINE["workflow"]
        self.assertEqual(workflow["rule_version"], "r59-4")
        self.assertEqual(workflow["workflow_state"], "RESEARCH_READY")
        self.assertEqual(workflow["safety_status"], "RESEARCH_ONLY")
        self.assertTrue(workflow["advisory"])
        self.assertFalse(workflow["execution_performed"])

    def test_copilot_brief_is_advisory_only(self):
        copilot = PIPELINE["copilot"]
        self.assertTrue(copilot["advisory"])
        self.assertEqual(copilot["status"], "COMPLETED")
        self.assertFalse(copilot["execution_performed"])
        self.assertFalse(copilot["external_executor_present"])
        self.assertFalse(copilot["vulnerability_confirmed"])
        self.assertFalse(copilot["exploit_authorized"])
        self.assertEqual(copilot["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(copilot["brief"]["opportunity_count"], 0)
        self.assertEqual(copilot["brief"]["workflow_next_action"], "RUN_RESEARCH_ANALYSIS")

    def test_full_pipeline_is_deterministic(self):
        second = br.pipeline(SNAPSHOT, cve=CVE)
        for key in (
            "inventory",
            "r31",
            "specialist_signals",
            "research_context",
            "intelligence_context",
            "workflow",
            "copilot",
        ):
            self.assertEqual(
                br.canonical_json(PIPELINE[key]),
                br.canonical_json(second[key]),
                key,
            )

    def test_full_pipeline_never_reads_mongo_or_network(self):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            side_effect=AssertionError("mongo must not be read"),
        ), mock.patch(
            "backend.observed_inventory._fetch_documents",
            side_effect=AssertionError("mongo must not be read"),
        ), mock.patch(
            "pymongo.MongoClient",
            side_effect=AssertionError("mongo client must not be created"),
        ):
            pipeline = br.pipeline(SNAPSHOT, cve=CVE)
        self.assertEqual(pipeline["inventory"]["program"], "indeed")
        self.assertFalse(pipeline["copilot"]["execution_performed"])

    def test_copilot_accepts_contexts_without_workflow_result(self):
        from ai.knowledge.bug_bounty_copilot import build_bug_bounty_copilot

        copilot = build_bug_bounty_copilot(
            {"copilot_id": "r62-standalone"},
            target_reference="indeed",
            research_context=PIPELINE["research_context"],
            intelligence_context=PIPELINE["intelligence_context"],
        )
        self.assertTrue(copilot["advisory"])
        self.assertFalse(copilot["vulnerability_confirmed"])


if __name__ == "__main__":
    unittest.main()
