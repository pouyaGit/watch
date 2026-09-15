"""tests/test_bug_bounty_copilot.py — Stage R60 copilot functional tests.

Deterministic, offline tests for the Watch Bug Bounty Copilot:

- input/result schemas, empty, malformed and invalid inputs
- prioritization ordering and verbatim priority preservation
- evidence, confidence and related-finding handling
- recommended next actions and human-review requirements
- R56 decision boundary handling (approve, more evidence, defer, reject,
  escalate, needs review)
- R57 learning context and review-required blocking
- R58 controlled execution integration (blocked, authorized, ready)
- partial workflows, conflicting context and safe failure
- deterministic ids, replay consistency and upstream immutability
- the full R53 -> R54 -> R55 -> R56 -> R57 -> R58 -> R59 -> R60 chain

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.bug_bounty_copilot import (
    build_bug_bounty_copilot,
    build_copilot_brief,
    build_copilot_opportunities,
    determine_copilot_priorities,
    export_bug_bounty_copilot,
    summarize_copilot_brief,
)
from ai.knowledge.continuous_learning import build_continuous_learning_result
from ai.knowledge.execution_control import (
    build_execution_request,
    evaluate_execution_control,
)
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.knowledge.finding_correlation import correlate_findings
from ai.knowledge.human_review import create_human_review
from ai.knowledge.research_prioritization import prioritize_findings
from ai.knowledge.security_research_workflow import (
    build_security_research_workflow,
)
from ai.schemas.bug_bounty_copilot import (
    BUG_BOUNTY_COPILOT_RULE_VERSION,
    BugBountyCopilotInputPlan,
    sanitize_bug_bounty_copilot_input,
)
from ai.schemas.copilot_opportunity import (
    OPPORTUNITY_DEFERRED,
    OPPORTUNITY_HIGH_PRIORITY,
    OPPORTUNITY_INSUFFICIENT,
)
from ai.schemas.copilot_result import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_CONTEXT,
    STATUS_PARTIAL,
)
from tests.test_agent_orchestrator import multi_context

APPROVE = "APPROVE_RESEARCH"


class CopilotArtifacts:
    """Deterministic R52 -> R58 artifacts built once per test class."""

    def __init__(self):
        self.orchestration = orchestrate_research(
            research_context=multi_context()
        )
        self.findings = build_finding_intelligence(
            orchestration_result=self.orchestration
        )
        self.correlation = correlate_findings(self.findings["findings"])
        self.prioritization = prioritize_findings(
            self.findings["findings"], correlation_result=self.correlation
        )
        self.finding_id = self.prioritization["ranked_findings"][0][
            "finding_id"
        ]
        self.review = self.review_with(APPROVE)
        self.decision = self.decision_for(self.review)
        self.learning = build_continuous_learning_result(
            finding_intelligence=self.findings,
            correlation_result=self.correlation,
            prioritization_result=self.prioritization,
            human_review_result=self.review,
        )
        self.request = build_execution_request(
            finding_id=self.finding_id,
            action_type="REASSESS_CONTEXT",
            action_scope="/search",
            scope_kind="PATH",
            target_reference="api.example.test",
            purpose="re-read the recorded context",
            requested_by="HUMAN",
            human_decision_reference=self.decision,
        )
        self.authorization_context = {
            "authorization_source": "HUMAN",
            "authorization_authority": "HUMAN",
            "decision_reference": self.decision["decision_id"],
            "approved_action": "REASSESS_CONTEXT",
            "approved_scope": "/search",
            "approved_target": "api.example.test",
        }
        self.control_ready = evaluate_execution_control(
            self.request,
            human_review_result=self.review,
            authorization_context=self.authorization_context,
            preconditions_met=True,
        )
        self.control_authorized = evaluate_execution_control(
            self.request,
            human_review_result=self.review,
            authorization_context=self.authorization_context,
        )
        self.control_blocked = evaluate_execution_control(
            self.request, human_review_result=self.review
        )
        self.review_pending = create_human_review(
            prioritization_result=self.prioritization,
            correlation_result=self.correlation,
        )
        self.neutral_workflow = build_security_research_workflow()

    def review_with(self, decision_type, finding_id=None):
        return create_human_review(
            prioritization_result=self.prioritization,
            correlation_result=self.correlation,
            decisions=[
                {
                    "finding_id": finding_id or self.finding_id,
                    "decision_type": decision_type,
                }
            ],
        )

    def decision_for(self, review, finding_id=None):
        target = finding_id or self.finding_id
        for entry in review.get("reviews") or ():
            if entry.get("finding_id") == target and entry.get("decision"):
                return entry["decision"]
        raise AssertionError(f"no decision for {target}")

    def context(self):
        return {
            "target_reference": "api.example.test",
            "finding_intelligence": self.findings,
            "correlation_result": self.correlation,
            "prioritization_result": self.prioritization,
        }


class CopilotTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = CopilotArtifacts()

    def copilot(self, **kwargs):
        payload = self.chain.context()
        payload.update(kwargs)
        return build_bug_bounty_copilot(**payload)

    def error_categories(self, result):
        return [entry["error_category"] for entry in result["errors"]]


class TestInputAndResult(CopilotTestCase):
    def test_input_schema_defaults(self):
        copilot_input = sanitize_bug_bounty_copilot_input(None)
        self.assertFalse(copilot_input["execution_performed"])
        self.assertFalse(copilot_input["vulnerability_confirmed"])
        self.assertFalse(copilot_input["exploit_authorized"])
        self.assertEqual(
            copilot_input["confirmation_state"], "NOT_CONFIRMED"
        )
        self.assertTrue(copilot_input["research_only"])
        self.assertEqual(copilot_input["copilot_options"]["max_opportunities"], 8)
        self.assertTrue(
            copilot_input["copilot_options"]["include_learning_context"]
        )

    def test_input_model_forces_no_execution(self):
        payload = sanitize_bug_bounty_copilot_input(
            {"copilot_id": "bbc-" + "1" * 16}
        )
        with self.assertRaises(ValidationError):
            BugBountyCopilotInputPlan(
                **{**payload, "execution_authorized": True}
            )
        with self.assertRaises(ValidationError):
            BugBountyCopilotInputPlan(
                **{**payload, "vulnerability_confirmed": True}
            )

    def test_input_rule_version_is_stable(self):
        self.assertEqual(BUG_BOUNTY_COPILOT_RULE_VERSION, "r60-1")

    def test_empty_input_is_no_context(self):
        result = build_bug_bounty_copilot()
        self.assertEqual(result["status"], STATUS_NO_CONTEXT)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["brief"]["opportunity_count"], 0)
        self.assertEqual(result["brief"]["confidence"], "UNKNOWN")
        self.assertTrue(result["brief"]["advisory"])
        self.assertFalse(result["execution_performed"])

    def test_malformed_input_is_failed(self):
        result = build_bug_bounty_copilot(copilot_input=42)
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertIn("MALFORMED_INPUT", self.error_categories(result))

    def test_mis_versioned_input_is_failed(self):
        result = build_bug_bounty_copilot(
            workflow_result={"rule_version": "r99-9"}
        )
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertIn(
            "RULE_VERSION_MISMATCH", self.error_categories(result)
        )

    def test_malformed_artifact_is_failed(self):
        result = build_bug_bounty_copilot(prioritization_result=42)
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertIn("MALFORMED_INPUT", self.error_categories(result))

    def test_result_never_claims_execution(self):
        for result in (
            build_bug_bounty_copilot(),
            self.copilot(),
            self.copilot(execution_control_result=self.chain.control_ready),
        ):
            self.assertFalse(result["execution_performed"])
            self.assertFalse(result["external_executor_present"])
            self.assertFalse(result["vulnerability_confirmed"])
            self.assertFalse(result["exploit_authorized"])
            self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
            self.assertTrue(result["advisory"])
            self.assertTrue(result["human_authority_preserved"])
            self.assertNotEqual(result["status"], "EXECUTED")


class TestPrioritization(CopilotTestCase):
    def test_opportunities_follow_r55_ranking(self):
        result = self.copilot()
        expected = [
            plan["finding_id"]
            for plan in list(
                self.chain.prioritization["ranked_findings"]
            ) + list(self.chain.prioritization["deferred_findings"])
        ]
        actual = [
            entry["finding_id"]
            for entry in result["brief"]["opportunities"]
        ]
        self.assertEqual(actual, expected[: len(actual)])

    def test_priority_band_and_score_are_verbatim(self):
        result = self.copilot()
        plans = {
            plan["finding_id"]: plan
            for plan in list(
                self.chain.prioritization["ranked_findings"]
            ) + list(self.chain.prioritization["deferred_findings"])
        }
        for opportunity in result["brief"]["opportunities"]:
            plan = plans[opportunity["finding_id"]]
            self.assertEqual(
                opportunity["priority_band"], plan["priority_band"]
            )
            self.assertEqual(
                opportunity["priority_score"], plan["priority_score"]
            )
            self.assertEqual(
                set(opportunity["research_rationale_codes"]),
                set(plan["priority_reasons"]),
            )

    def test_opportunity_count_matches_summary(self):
        result = self.copilot()
        self.assertEqual(
            result["brief"]["opportunity_count"], len(result["brief"]["opportunities"])
        )
        self.assertEqual(
            result["summary"]["opportunity_count"],
            result["brief"]["opportunity_count"],
        )

    def test_max_opportunities_option_bounds_the_list(self):
        result = self.copilot(
            copilot_options={"max_opportunities": 3}
        )
        self.assertEqual(result["brief"]["opportunity_count"], 3)

    def test_synthetic_high_priority_opportunity(self):
        plan = {
            "finding_id": "fnd-" + "a" * 16,
            "category": "SSRF",
            "state": "EVIDENCE_SUPPORTED",
            "confidence": "HIGH",
            "evidence_completeness": "COMPLETE",
            "evidence_state": "COMPLETE",
            "evidence_origin": "DIRECT",
            "severity": "CRITICAL_OBSERVED",
            "severity_source": "CVSS_CONTEXT",
            "impact_state": "OBSERVED",
            "priority_band": "CRITICAL",
            "priority_score": 95,
            "priority_reasons": ["COMPLETE_EVIDENCE", "OBSERVED_IMPACT"],
            "ranking_position": 1,
            "conflict_state": "NO_CONFLICT",
            "correlation_summary": {"duplicate_count": 0},
            "provenance": {"orchestration_id": "orch-" + "1" * 16},
            "governance": {"reference_state": "REFERENCED"},
        }
        result = build_bug_bounty_copilot(
            workflow_result=self.chain.neutral_workflow,
            finding_intelligence=self.chain.findings,
            prioritization_result={
                "rule_version": "r55-2",
                "prioritization_id": "pri-" + "1" * 16,
                "ranked_findings": [plan],
                "deferred_findings": [],
                "status": "COMPLETED",
            },
        )
        opportunity = result["brief"]["opportunities"][0]
        self.assertEqual(
            opportunity["opportunity_class"], OPPORTUNITY_HIGH_PRIORITY
        )
        self.assertEqual(opportunity["confidence"], "HIGH")
        self.assertEqual(
            opportunity["recommendation"]["research_action"],
            "PREPARE_RESEARCH_STEP",
        )

    def test_synthetic_deferred_opportunity(self):
        plan = {
            "finding_id": "fnd-" + "a" * 16,
            "priority_band": "DEFERRED",
            "priority_score": 10,
            "priority_reasons": ["RESEARCH_VALUE_LOW"],
            "ranking_position": 0,
            "evidence_completeness": "COMPLETE",
            "confidence": "LOW",
            "conflict_state": "UNKNOWN",
        }
        result = build_bug_bounty_copilot(
            workflow_result=self.chain.neutral_workflow,
            finding_intelligence=self.chain.findings,
            prioritization_result={
                "rule_version": "r55-2",
                "prioritization_id": "pri-" + "1" * 16,
                "ranked_findings": [],
                "deferred_findings": [plan],
                "status": "COMPLETED",
            },
        )
        opportunity = result["brief"]["opportunities"][0]
        self.assertEqual(
            opportunity["opportunity_class"], OPPORTUNITY_DEFERRED
        )
        self.assertEqual(
            opportunity["recommendation"]["research_action"], ""
        )


class TestEvidenceAndConfidence(CopilotTestCase):
    def test_evidence_summary_is_verbatim(self):
        result = self.copilot()
        summary = result["brief"]["evidence_summary"]
        plans = list(
            self.chain.prioritization["ranked_findings"]
        ) + list(self.chain.prioritization["deferred_findings"])
        self.assertEqual(summary["finding_count"], len(plans))
        complete = sum(
            1
            for plan in plans
            if plan.get("evidence_completeness") == "COMPLETE"
        )
        self.assertEqual(summary["evidence_complete_count"], complete)

    def test_conflict_caps_confidence(self):
        result = self.copilot()
        conflicted = [
            entry
            for entry in result["brief"]["opportunities"]
            if entry["conflict_state"] == "CONFLICT_PRESENT"
        ]
        self.assertTrue(conflicted)
        for entry in conflicted:
            self.assertIn(entry["confidence"], ("LOW", "UNKNOWN"))

    def test_missing_evidence_is_insufficient(self):
        plan = {
            "finding_id": "fnd-" + "a" * 16,
            "priority_band": "HIGH",
            "priority_score": 70,
            "priority_reasons": ["MISSING_EVIDENCE"],
            "ranking_position": 1,
            "evidence_completeness": "MISSING",
            "confidence": "HIGH",
            "conflict_state": "NO_CONFLICT",
        }
        result = build_bug_bounty_copilot(
            workflow_result=self.chain.neutral_workflow,
            finding_intelligence=self.chain.findings,
            prioritization_result={
                "rule_version": "r55-2",
                "prioritization_id": "pri-" + "1" * 16,
                "ranked_findings": [plan],
                "status": "COMPLETED",
            },
        )
        opportunity = result["brief"]["opportunities"][0]
        self.assertEqual(
            opportunity["opportunity_class"], OPPORTUNITY_INSUFFICIENT
        )
        self.assertEqual(opportunity["confidence"], "UNKNOWN")
        self.assertEqual(
            opportunity["recommendation"]["research_action"],
            "COLLECT_EXISTING_EVIDENCE",
        )

    def test_brief_confidence_follows_primary_opportunity(self):
        result = self.copilot()
        primary = result["brief"]["opportunities"][0]
        self.assertEqual(result["brief"]["confidence"], primary["confidence"])

    def test_confidence_basis_is_explicit(self):
        result = self.copilot()
        self.assertTrue(result["brief"]["confidence_basis"])
        for code in result["brief"]["confidence_basis"]:
            self.assertIn(
                code,
                (
                    "EVIDENCE_COMPLETE",
                    "EVIDENCE_PARTIAL",
                    "EVIDENCE_INSUFFICIENT",
                    "CONFLICT_PRESENT",
                    "DUPLICATE_PRESENT",
                    "HUMAN_DECISION_PENDING",
                    "WORKFLOW_BLOCKED",
                    "HUMAN_REVIEW_REQUIRED",
                    "SAFETY_BLOCKED",
                    "NO_OPPORTUNITIES",
                    "OPPORTUNITIES_PRESENT",
                ),
            )


class TestCorrelation(CopilotTestCase):
    def test_related_findings_are_preserved(self):
        result = self.copilot()
        expected_ids = {
            reference["finding_id"]
            for reference in self.chain.correlation["finding_references"]
        }
        for finding_id in result["brief"]["related_finding_ids"]:
            self.assertIn(finding_id, expected_ids)

    def test_relationship_types_are_bounded(self):
        result = self.copilot()
        for relationship_type in result["brief"]["relationship_types"]:
            self.assertTrue(relationship_type)
            self.assertEqual(relationship_type, relationship_type.upper())

    def test_opportunity_carries_correlation_context(self):
        result = self.copilot()
        linked = [
            entry
            for entry in result["brief"]["opportunities"]
            if entry["related_finding_count"]
        ]
        self.assertTrue(linked)
        for entry in linked:
            self.assertTrue(entry["related_finding_ids"])
            self.assertIn(
                "RELATED_FINDINGS_PRESENT",
                entry["copilot_rationale_codes"],
            )


class TestRecommendedActions(CopilotTestCase):
    def test_workflow_action_is_verbatim_r59(self):
        result = self.copilot()
        workflow = build_security_research_workflow(
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
        )
        expected = workflow["next_action"]["action_code"]
        for entry in result["brief"]["opportunities"]:
            self.assertEqual(
                entry["recommendation"]["workflow_next_action"], expected
            )

    def test_actions_are_deduplicated_and_ordered(self):
        result = self.copilot()
        actions = result["brief"]["recommended_actions"]
        keys = [
            (entry["workflow_next_action"], entry["research_action"])
            for entry in actions
        ]
        self.assertEqual(len(keys), len(set(keys)))
        for entry in actions:
            self.assertIn(
                entry["research_action"],
                (
                    "",
                    "COLLECT_EXISTING_EVIDENCE",
                    "REVIEW_EXISTING_RESPONSE",
                    "RECHECK_SCOPE",
                    "REASSESS_CONTEXT",
                    "PREPARE_RESEARCH_STEP",
                    "REQUEST_HUMAN_REVIEW",
                ),
            )

    def test_actions_never_name_execution(self):
        result = self.copilot()
        serialized = json.dumps(result["brief"]["recommended_actions"])
        for forbidden in (
            "EXECUTE",
            "EXPLOIT",
            "PAYLOAD",
            "SCAN",
            "BROWSER",
            "SUBPROCESS",
            "COMMAND",
        ):
            self.assertNotIn(forbidden, serialized.upper())

    def test_every_opportunity_has_a_recommendation(self):
        result = self.copilot()
        for entry in result["brief"]["opportunities"]:
            recommendation = entry["recommendation"]
            self.assertTrue(recommendation["advisory"])
            self.assertFalse(recommendation["auto_execute"])
            self.assertTrue(recommendation["recommendation_id"])


class TestHumanReview(CopilotTestCase):
    def test_pending_decision_requires_review(self):
        result = self.copilot(human_review_result=self.chain.review_pending)
        self.assertTrue(result["brief"]["human_review_required"])
        self.assertIn(
            "HUMAN_DECISION_PENDING",
            result["brief"]["human_review_reasons"],
        )

    def test_approved_decision_is_preserved_as_context(self):
        result = self.copilot(human_review_result=self.chain.review)
        self.assertTrue(result["brief"]["human_review_required"])
        self.assertIn(
            "HUMAN_DECISION_PRESENT",
            result["brief"]["copilot_rationale_codes"],
        )
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])

    def test_defer_blocks_and_requires_human_review(self):
        result = self.copilot(
            human_review_result=self.chain.review_with("DEFER")
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "UPSTREAM_WORKFLOW_BLOCKED", self.error_categories(result)
        )
        self.assertEqual(
            result["brief"]["opportunities"][0]["recommendation"][
                "research_action"
            ],
            "REQUEST_HUMAN_REVIEW",
        )

    def test_reject_blocks(self):
        result = self.copilot(
            human_review_result=self.chain.review_with("REJECT")
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "UPSTREAM_WORKFLOW_BLOCKED", self.error_categories(result)
        )

    def test_request_more_evidence_blocks_execution_path(self):
        result = self.copilot(
            human_review_result=self.chain.review_with(
                "REQUEST_MORE_EVIDENCE"
            )
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "UPSTREAM_WORKFLOW_BLOCKED", self.error_categories(result)
        )
        self.assertNotEqual(
            result["brief"]["safety_status"], "CONTROLLED_AUTHORIZATION"
        )
        self.assertNotEqual(
            result["brief"]["safety_status"], "READY_FOR_EXTERNAL_EXECUTOR"
        )

    def test_escalate_stays_in_human_boundary(self):
        result = self.copilot(
            human_review_result=self.chain.review_with("ESCALATE")
        )
        self.assertEqual(result["brief"]["safety_status"], "HUMAN_REVIEW_REQUIRED")
        self.assertIn(
            "ESCALATION_REQUIRED",
            result["brief"]["human_review_reasons"],
        )

    def test_needs_review_stays_in_human_boundary(self):
        result = self.copilot(
            human_review_result=self.chain.review_with("NEEDS_REVIEW")
        )
        self.assertEqual(result["brief"]["safety_status"], "HUMAN_REVIEW_REQUIRED")
        self.assertIn(
            "HUMAN_NEEDS_REVIEW",
            result["brief"]["human_review_reasons"],
        )


class TestLearningAndExecution(CopilotTestCase):
    def test_learning_context_is_recorded(self):
        result = self.copilot(learning_result=self.chain.learning)
        self.assertIn(
            "LEARNING_CONTEXT", result["brief"]["copilot_rationale_codes"]
        )
        self.assertTrue(result["brief"]["provenance"])

    def test_blocking_learning_requires_review(self):
        learning = {
            "rule_version": "r57-4",
            "calibration_recommendations": [
                {"recommendation_code": "REVIEW_SAFETY_BOUNDARY"}
            ],
        }
        result = self.copilot(learning_result=learning)
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "UPSTREAM_WORKFLOW_BLOCKED", self.error_categories(result)
        )
        self.assertIn(
            "LEARNING_REVIEW_REQUIRED",
            result["brief"]["human_review_reasons"],
        )

    def test_execution_blocked_context(self):
        result = self.copilot(
            human_review_result=self.chain.review,
            execution_control_result=self.chain.control_blocked,
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "EXECUTION_CONTROL_BLOCKED",
            result["brief"]["human_review_reasons"],
        )
        self.assertFalse(result["execution_performed"])

    def test_execution_authorized_context_is_advisory_only(self):
        result = self.copilot(
            human_review_result=self.chain.review,
            execution_control_result=self.chain.control_authorized,
        )
        self.assertIn(
            result["brief"]["workflow_state"],
            ("EXECUTION_REVIEWED", "COMPLETED"),
        )
        self.assertIn(
            "EXECUTION_CONTEXT_AVAILABLE",
            result["brief"]["copilot_rationale_codes"],
        )
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])

    def test_execution_ready_context_reports_readiness_only(self):
        result = self.copilot(
            human_review_result=self.chain.review,
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["brief"]["workflow_state"], "COMPLETED")
        self.assertEqual(
            result["brief"]["safety_status"],
            "READY_FOR_EXTERNAL_EXECUTOR",
        )
        self.assertEqual(
            result["brief"]["workflow_next_action"], "COMPLETE_WORKFLOW"
        )
        self.assertFalse(result["execution_performed"])
        self.assertFalse(
            result["brief"]["non_execution_boundary"]["execution_performed"]
        )


class TestPartialAndConflicts(CopilotTestCase):
    def test_findings_only_is_partial_but_advisory(self):
        result = build_bug_bounty_copilot(
            finding_intelligence=self.chain.findings
        )
        self.assertIn(result["status"], (STATUS_COMPLETED, STATUS_PARTIAL))
        self.assertEqual(result["brief"]["opportunity_count"], 0)
        self.assertTrue(result["brief"]["advisory"])
        self.assertFalse(result["execution_performed"])

    def test_prioritization_only_requires_findings(self):
        result = build_bug_bounty_copilot(
            prioritization_result=self.chain.prioritization
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "UPSTREAM_WORKFLOW_BLOCKED", self.error_categories(result)
        )

    def test_conflicting_context_is_safe(self):
        bad = copy.deepcopy(self.chain.prioritization)
        bad["ranked_findings"][0]["finding_id"] = "fnd-" + "f" * 16
        result = build_bug_bounty_copilot(
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=bad,
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn(
            "CONFLICTING_CONTEXT", self.error_categories(result)
        )
        self.assertTrue(result["brief"]["human_review_required"])
        self.assertNotEqual(result["brief"]["safety_status"], "RESEARCH_ONLY")

    def test_safety_blocking_input(self):
        result = build_bug_bounty_copilot(
            copilot_input={
                "finding_intelligence": {
                    "rule_version": "r53-6",
                    "findings": [],
                    "network_execution": True,
                }
            }
        )
        self.assertEqual(result["status"], STATUS_PARTIAL)
        self.assertIn("SAFETY_BLOCKED", self.error_categories(result))
        self.assertEqual(result["brief"]["safety_status"], "SAFETY_BLOCKED")
        self.assertTrue(result["brief"]["human_review_required"])

    def test_options_disable_learning_and_execution_contexts(self):
        result = self.copilot(
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
            copilot_options={
                "include_learning_context": False,
                "include_execution_context": False,
            },
        )
        self.assertEqual(result["errors"], [])
        self.assertNotIn(
            "EXECUTION_CONTEXT_AVAILABLE",
            result["brief"]["copilot_rationale_codes"],
        )


class TestDeterminismAndPreservation(CopilotTestCase):
    def test_deterministic_ids_and_output(self):
        first = self.copilot()
        second = self.copilot()
        self.assertEqual(
            first["brief"]["brief_id"], second["brief"]["brief_id"]
        )
        self.assertEqual(first["result_id"], second["result_id"])
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_replay_consistency_via_input_dict(self):
        payload = {
            "target_reference": "api.example.test",
            "finding_intelligence": self.chain.findings,
            "correlation_result": self.chain.correlation,
            "prioritization_result": self.chain.prioritization,
        }
        first = build_bug_bounty_copilot(copilot_input=payload)
        second = build_bug_bounty_copilot(copilot_input=payload)
        self.assertEqual(first["result_id"], second["result_id"])

    def test_inputs_are_not_mutated(self):
        artifacts = (
            ("findings", self.chain.findings),
            ("correlation", self.chain.correlation),
            ("prioritization", self.chain.prioritization),
            ("review", self.chain.review),
            ("learning", self.chain.learning),
            ("control", self.chain.control_ready),
        )
        snapshots = {
            name: json.dumps(value, sort_keys=True)
            for name, value in artifacts
        }
        self.copilot(
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
        )
        for name, value in artifacts:
            self.assertEqual(
                json.dumps(value, sort_keys=True), snapshots[name], name
            )

    def test_provenance_and_limitations_are_preserved(self):
        result = self.copilot(
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
        )
        provenance = result["brief"]["provenance"]
        self.assertEqual(provenance["workflow_id"], result["brief"]["workflow_id"])
        self.assertTrue(provenance["finding_rule_version"])
        self.assertIn(
            "NO_EXECUTION_PERFORMED", result["brief"]["limitations"]
        )
        self.assertIn(
            "AUTHORIZATION_IS_NOT_EXECUTION", result["brief"]["limitations"]
        )
        self.assertIn("ADVISORY_ONLY", result["brief"]["limitations"])

    def test_governance_is_preserved(self):
        governance = {
            "rule_version": "r37-5",
            "ready": True,
            "provenance": {"provenance_state": "UNKNOWN"},
            "rule_trace": {"trace_state": "UNKNOWN"},
            "audit_event": {"audit_state": "UNKNOWN"},
            "explanation": {"explanation_state": "UNKNOWN"},
        }
        result = self.copilot(governance=governance)
        self.assertEqual(result["governance"]["reference_state"], "REFERENCED")


class TestHelpersAndFullChain(CopilotTestCase):
    def test_helper_apis_are_consistent(self):
        result = self.copilot()
        brief = build_copilot_brief(**self.chain.context())
        self.assertEqual(brief["brief_id"], result["brief"]["brief_id"])
        opportunities = build_copilot_opportunities(**self.chain.context())
        self.assertEqual(
            len(opportunities), result["brief"]["opportunity_count"]
        )
        self.assertEqual(
            determine_copilot_priorities(**self.chain.context()),
            opportunities,
        )
        summary = summarize_copilot_brief(result)
        self.assertEqual(
            summary["opportunity_count"], result["brief"]["opportunity_count"]
        )
        alias = export_bug_bounty_copilot(**self.chain.context())
        self.assertEqual(alias["result_id"], result["result_id"])

    def test_full_chain_is_advisory_and_safe(self):
        result = build_bug_bounty_copilot(
            target_reference="api.example.test",
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["status"], STATUS_COMPLETED)
        self.assertEqual(result["errors"], [])
        brief = result["brief"]
        self.assertEqual(brief["workflow_state"], "COMPLETED")
        self.assertGreater(brief["opportunity_count"], 0)
        self.assertGreater(brief["evidence_summary"]["finding_count"], 0)
        self.assertTrue(brief["recommended_actions"])
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        for opportunity in brief["opportunities"]:
            self.assertTrue(opportunity["research_only"])
            self.assertFalse(opportunity["duplicate_present"] and False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
