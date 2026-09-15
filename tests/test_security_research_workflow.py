"""tests/test_security_research_workflow.py — Stage R59 workflow tests.

Deterministic, offline tests for the R59 end-to-end security research
workflow:

- request and result schemas
- closed workflow state machine and stage statuses
- partial workflows at every stage boundary
- human decision handling (approve, more evidence, defer, reject, escalate,
  needs review)
- R57 learning integration and review-required blocking
- R58 controlled execution integration (blocked, authorized, ready)
- deterministic ids, stable ordering, replay consistency
- provenance/governance/limitation preservation and input immutability
- valid, invalid and unsupported stage transitions
- the full Specialist -> R42 -> R43 -> R44 -> R53 -> R54 -> R55 -> R56 ->
  R57 -> R58 -> R59 chain
- empty, malformed and conflicting inputs

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_orchestrator import orchestrate_research
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
    advance_security_research_workflow,
    build_security_research_workflow,
    build_security_research_workflow_summary,
    determine_next_workflow_action,
    export_security_research_workflow,
)
from ai.schemas.security_research_workflow import (
    SECURITY_RESEARCH_WORKFLOW_RULE_VERSION,
    SecurityResearchWorkflowRequestPlan,
    sanitize_workflow_options,
    sanitize_workflow_request,
)
from ai.schemas.security_research_workflow_result import (
    ERROR_EXECUTION_CONTROL_BLOCKED,
    ERROR_HUMAN_DECISION_REQUIRED,
    ERROR_LEARNING_REVIEW_REQUIRED,
    ERROR_MALFORMED_INPUT,
    ERROR_MISSING_REQUIRED_STAGE,
    ERROR_RULE_VERSION_MISMATCH,
    ERROR_SAFETY_BLOCKED,
    ERROR_STAGE_ORDER_INVALID,
    ERROR_UNSUPPORTED_TRANSITION,
    ERROR_WORKFLOW_CONFLICT,
    HUMAN_STATUS_DECIDED,
    HUMAN_STATUS_PENDING,
    SAFETY_STATUS_CONTROLLED_AUTHORIZATION,
    SAFETY_STATUS_HUMAN_REVIEW_REQUIRED,
    SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    SAFETY_STATUS_RESEARCH_ONLY,
    SAFETY_STATUS_SAFETY_BLOCKED,
    STATE_AWAITING_HUMAN_DECISION,
    STATE_BLOCKED,
    STATE_COLLABORATED,
    STATE_COMPLETED,
    STATE_EXECUTION_REVIEWED,
    STATE_FEEDBACK_ANALYZED,
    STATE_FINDINGS_BUILT,
    STATE_FINDINGS_CORRELATED,
    STATE_HUMAN_DECIDED,
    STATE_INITIALIZED,
    STATE_INVALID,
    STATE_LEARNING_UPDATED,
    STATE_PRIORITIZED,
    STATE_RESEARCH_READY,
    STATE_SPECIALISTS_EVALUATED,
    SecurityResearchWorkflowResultPlan,
    WORKFLOW_STATES,
)
from ai.schemas.workflow_next_action import (
    ACTION_BLOCK_WORKFLOW,
    ACTION_BUILD_FINDINGS,
    ACTION_COMPLETE_WORKFLOW,
    ACTION_CORRELATE_FINDINGS,
    ACTION_PRIORITIZE_RESEARCH,
    ACTION_REQUEST_HUMAN_REVIEW,
    ACTION_REVIEW_EXECUTION_CONTROL,
    ACTION_RUN_COLLABORATION,
    ACTION_RUN_EVALUATION,
    ACTION_RUN_FEEDBACK_ANALYSIS,
    ACTION_RUN_RESEARCH_ANALYSIS,
    ACTION_UPDATE_LEARNING,
    ACTION_WAIT_FOR_HUMAN_DECISION,
)
from ai.schemas.workflow_stage import (
    STAGE_COLLABORATION,
    STAGE_CORRELATION,
    STAGE_EVALUATION,
    STAGE_EXECUTION_CONTROL,
    STAGE_FEEDBACK,
    STAGE_FINDING,
    STAGE_HUMAN_REVIEW,
    STAGE_LEARNING,
    STAGE_PRIORITIZATION,
    STAGE_SPECIALIST_RESEARCH,
    STAGE_STATUS_COMPLETED,
    STAGE_STATUS_SKIPPED,
    WORKFLOW_STAGE_ORDER,
)
from tests.test_agent_orchestrator import multi_context

APPROVE = "APPROVE_RESEARCH"


class ChainArtifacts:
    """Deterministic R52 -> R58 artifacts built once per test class."""

    def __init__(self):
        self.orchestration = orchestrate_research(
            research_context=multi_context()
        )
        self.specialists = self.orchestration["specialist_results"]
        self.evaluations = self.orchestration["evaluation_results"]
        self.collaboration = self.orchestration["collaboration_result"]
        self.feedback = self.orchestration["feedback_result"]
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
        self.second_finding_id = self.prioritization["ranked_findings"][1][
            "finding_id"
        ]
        self.review_pending = create_human_review(
            prioritization_result=self.prioritization,
            correlation_result=self.correlation,
        )
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
            learning_result=self.learning,
        )
        self.control_authorized = evaluate_execution_control(
            self.request,
            human_review_result=self.review,
            authorization_context=self.authorization_context,
        )
        self.control_blocked = evaluate_execution_control(
            self.request, human_review_result=self.review
        )

    def review_with(self, decision_type, finding_id=None, rationale=None):
        decision = {
            "finding_id": finding_id or self.finding_id,
            "decision_type": decision_type,
        }
        if rationale:
            decision["rationale_codes"] = list(rationale)
        return create_human_review(
            prioritization_result=self.prioritization,
            correlation_result=self.correlation,
            decisions=[decision],
        )

    def multi_decision_review(self, decisions):
        return create_human_review(
            prioritization_result=self.prioritization,
            correlation_result=self.correlation,
            decisions=list(decisions),
        )

    def decision_for(self, review, finding_id=None):
        target = finding_id or self.finding_id
        for entry in review.get("reviews") or ():
            if (
                entry.get("finding_id") == target
                and entry.get("decision")
            ):
                return entry["decision"]
        raise AssertionError(f"no decision for {target}")

    def partial(self, levels):
        """Return the kwargs for a partial workflow up to ``levels``."""

        mapping = {
            "specialists": {"specialist_results": self.specialists},
            "evaluations": {
                "specialist_results": self.specialists,
                "evaluation_results": self.evaluations,
            },
            "collaboration": {
                "specialist_results": self.specialists,
                "evaluation_results": self.evaluations,
                "collaboration_result": self.collaboration,
            },
            "feedback": {
                "specialist_results": self.specialists,
                "evaluation_results": self.evaluations,
                "collaboration_result": self.collaboration,
                "feedback_result": self.feedback,
            },
            "findings": {"finding_intelligence": self.findings},
            "correlation": {
                "finding_intelligence": self.findings,
                "correlation_result": self.correlation,
            },
            "prioritization": {
                "finding_intelligence": self.findings,
                "correlation_result": self.correlation,
                "prioritization_result": self.prioritization,
            },
            "pending_human": {
                "finding_intelligence": self.findings,
                "correlation_result": self.correlation,
                "prioritization_result": self.prioritization,
                "human_review_result": self.review_pending,
            },
            "human": {
                "finding_intelligence": self.findings,
                "correlation_result": self.correlation,
                "prioritization_result": self.prioritization,
                "human_review_result": self.review,
            },
            "learning": {
                "finding_intelligence": self.findings,
                "correlation_result": self.correlation,
                "prioritization_result": self.prioritization,
                "human_review_result": self.review,
                "learning_result": self.learning,
            },
        }
        return mapping[levels]


class WorkflowTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = ChainArtifacts()

    def stage_status(self, result, stage_type):
        for stage in result["stages"]:
            if stage["stage_type"] == stage_type:
                return stage["stage_status"]
        raise AssertionError(f"stage not found: {stage_type}")

    def stage_metadata(self, result, stage_type):
        for stage in result["stages"]:
            if stage["stage_type"] == stage_type:
                return stage["deterministic_metadata"]
        raise AssertionError(f"stage not found: {stage_type}")

    def error_categories(self, result):
        return [entry["error_category"] for entry in result["errors"]]

    def assert_no_execution_claims(self, result):
        self.assertEqual(result["workflow_state"], result["workflow_state"])
        for forbidden in (
            "EXECUTED",
            "EXECUTION_PERFORMED",
            "CONFIRMED",
            "VULNERABILITY_CONFIRMED",
            "EXPLOITED",
        ):
            self.assertNotEqual(result["workflow_state"], forbidden)
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["external_executor_present"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        for stage in result["stages"]:
            self.assertFalse(stage["execution_performed"])
            self.assertFalse(stage["vulnerability_confirmed"])
            self.assertFalse(stage["exploit_authorized"])


class TestSchemas(WorkflowTestCase):
    def test_request_schema_defaults(self):
        request = sanitize_workflow_request(None)
        self.assertFalse(request["execution_requested"])
        self.assertFalse(request["execution_authorized"])
        self.assertFalse(request["vulnerability_confirmed"])
        self.assertEqual(request["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(request["research_only"])
        self.assertTrue(request["workflow_options"]["require_human_decision"])
        self.assertTrue(request["workflow_options"]["stage_order_fixed"])

    def test_request_model_forces_flags(self):
        with self.assertRaises(ValidationError):
            SecurityResearchWorkflowRequestPlan(
                **{
                    **sanitize_workflow_request(None),
                    "workflow_id": "wfr-" + "1" * 16,
                    "execution_authorized": True,
                }
            )

    def test_request_id_must_be_valid(self):
        with self.assertRaises(ValidationError):
            SecurityResearchWorkflowRequestPlan(
                **{
                    **sanitize_workflow_request(None),
                    "workflow_id": "bogus",
                }
            )

    def test_options_are_bounded(self):
        options = sanitize_workflow_options(
            {
                "enable_learning": False,
                "enable_execution_review": "yes",
                "require_human_decision": False,
                "unknown": True,
            }
        )
        self.assertFalse(options["enable_learning"])
        self.assertFalse(options["enable_execution_review"])
        self.assertTrue(options["require_human_decision"])
        self.assertNotIn("unknown", options)

    def test_request_rule_version_is_stable(self):
        self.assertEqual(SECURITY_RESEARCH_WORKFLOW_RULE_VERSION, "r59-1")

    def test_result_schema_round_trip(self):
        result = build_security_research_workflow()
        model = SecurityResearchWorkflowResultPlan(**result)
        self.assertEqual(model.workflow_state, STATE_INITIALIZED)
        self.assertEqual(len(model.stages), 10)

    def test_result_model_forbids_execution_and_confirmation(self):
        result = build_security_research_workflow()
        for field in (
            "execution_performed",
            "external_executor_present",
            "vulnerability_confirmed",
            "exploit_authorized",
        ):
            with self.assertRaises(ValidationError):
                SecurityResearchWorkflowResultPlan(**{**result, field: True})

    def test_result_model_forbids_executed_like_states(self):
        result = build_security_research_workflow()
        for forbidden in ("EXECUTED", "CONFIRMED", "EXPLOITED"):
            with self.assertRaises(ValidationError):
                SecurityResearchWorkflowResultPlan(
                    **{**result, "workflow_state": forbidden}
                )

    def test_state_vocabulary_has_no_executed_state(self):
        for state in WORKFLOW_STATES:
            self.assertNotEqual(state, "EXECUTED")
        self.assertEqual(len(WORKFLOW_STATES), 15)


class TestStateMachine(WorkflowTestCase):
    def test_empty_input_is_initialized(self):
        result = build_security_research_workflow()
        self.assertEqual(result["workflow_state"], STATE_INITIALIZED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_RUN_RESEARCH_ANALYSIS
        )
        self.assertEqual(result["errors"], [])

    def test_research_input_is_research_ready(self):
        result = build_security_research_workflow(
            research_context={"output_context": "HTML"}
        )
        self.assertEqual(result["workflow_state"], STATE_RESEARCH_READY)
        self.assertEqual(
            self.stage_status(result, STAGE_SPECIALIST_RESEARCH), "READY"
        )

    def test_specialist_only_recommends_evaluation(self):
        result = build_security_research_workflow(
            specialist_results=self.chain.specialists
        )
        self.assertEqual(result["workflow_state"], STATE_RESEARCH_READY)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_RUN_EVALUATION
        )

    def test_evaluation_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("evaluations")
        )
        self.assertEqual(result["workflow_state"], STATE_SPECIALISTS_EVALUATED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_RUN_COLLABORATION
        )

    def test_collaboration_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("collaboration")
        )
        self.assertEqual(result["workflow_state"], STATE_COLLABORATED)
        self.assertEqual(
            result["next_action"]["action_code"],
            ACTION_RUN_FEEDBACK_ANALYSIS,
        )

    def test_feedback_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("feedback")
        )
        self.assertEqual(result["workflow_state"], STATE_FEEDBACK_ANALYZED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_BUILD_FINDINGS
        )

    def test_finding_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("findings")
        )
        self.assertEqual(result["workflow_state"], STATE_FINDINGS_BUILT)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_CORRELATE_FINDINGS
        )

    def test_correlation_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("correlation")
        )
        self.assertEqual(result["workflow_state"], STATE_FINDINGS_CORRELATED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_PRIORITIZE_RESEARCH
        )

    def test_prioritization_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization")
        )
        self.assertEqual(result["workflow_state"], STATE_PRIORITIZED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_REQUEST_HUMAN_REVIEW
        )

    def test_human_review_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("human")
        )
        self.assertEqual(result["workflow_state"], STATE_HUMAN_DECIDED)
        self.assertEqual(
            self.stage_status(result, STAGE_HUMAN_REVIEW),
            STAGE_STATUS_COMPLETED,
        )
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_UPDATE_LEARNING
        )

    def test_orchestration_bundle_reaches_feedback_stage(self):
        result = build_security_research_workflow(
            orchestration_result=self.chain.orchestration
        )
        self.assertEqual(result["workflow_state"], STATE_FEEDBACK_ANALYZED)
        for stage_type in (
            STAGE_SPECIALIST_RESEARCH,
            STAGE_EVALUATION,
            STAGE_COLLABORATION,
            STAGE_FEEDBACK,
        ):
            self.assertEqual(
                self.stage_status(result, stage_type),
                STAGE_STATUS_COMPLETED,
            )

    def test_learning_stage_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        self.assertEqual(result["workflow_state"], STATE_LEARNING_UPDATED)
        self.assertEqual(
            result["next_action"]["action_code"],
            ACTION_REVIEW_EXECUTION_CONTROL,
        )

    def test_execution_authorized_stage(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_control_result=self.chain.control_authorized,
        )
        self.assertEqual(result["workflow_state"], STATE_EXECUTION_REVIEWED)
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_CONTROLLED_AUTHORIZATION
        )
        self.assertEqual(
            result["execution_control_reference"]["status"], "ALLOW"
        )
        self.assertFalse(result["execution_performed"])

    def test_execution_ready_stage(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["workflow_state"], STATE_COMPLETED)
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        )
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_COMPLETE_WORKFLOW
        )
        self.assertEqual(
            result["summary"]["execution_control_status"],
            "READY_FOR_EXTERNAL_EXECUTOR",
        )

    def test_pending_review_is_awaiting_human_decision(self):
        result = build_security_research_workflow(
            **self.chain.partial("pending_human")
        )
        self.assertEqual(
            result["workflow_state"], STATE_AWAITING_HUMAN_DECISION
        )
        self.assertEqual(
            result["next_action"]["action_code"],
            ACTION_WAIT_FOR_HUMAN_DECISION,
        )
        self.assertEqual(
            result["summary"]["human_decision_status"], HUMAN_STATUS_PENDING
        )

    def test_no_findings_completes_the_workflow(self):
        result = build_security_research_workflow(
            finding_intelligence={
                "rule_version": "r53-6",
                "status": "NO_FINDINGS",
                "findings": [],
            }
        )
        self.assertEqual(result["workflow_state"], STATE_COMPLETED)
        self.assertEqual(result["next_action_reason"], "NO_FINDINGS_PRODUCED")
        self.assertEqual(result["summary"]["finding_count"], 0)

    def test_options_can_skip_learning_and_execution(self):
        result = build_security_research_workflow(
            **self.chain.partial("human"),
            workflow_options={
                "enable_learning": False,
                "enable_execution_review": False,
            },
        )
        self.assertEqual(
            self.stage_status(result, STAGE_LEARNING), STAGE_STATUS_SKIPPED
        )
        self.assertEqual(
            self.stage_status(result, STAGE_EXECUTION_CONTROL),
            STAGE_STATUS_SKIPPED,
        )
        self.assertEqual(result["workflow_state"], STATE_HUMAN_DECIDED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_COMPLETE_WORKFLOW
        )


class TestHumanDecisionHandling(WorkflowTestCase):
    def test_request_more_evidence_blocks(self):
        review = self.chain.review_with("REQUEST_MORE_EVIDENCE")
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            human_review_result=review,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(
            result["next_action"]["action_code"],
            ACTION_RUN_RESEARCH_ANALYSIS,
        )
        self.assertEqual(
            result["next_action_reason"], "HUMAN_REQUESTED_MORE_EVIDENCE"
        )

    def test_defer_blocks(self):
        review = self.chain.review_with("DEFER")
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            human_review_result=review,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(
            result["next_action"]["action_code"],
            ACTION_WAIT_FOR_HUMAN_DECISION,
        )

    def test_reject_blocks(self):
        review = self.chain.review_with("REJECT")
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            human_review_result=review,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_BLOCK_WORKFLOW
        )

    def test_escalate_stays_in_human_boundary(self):
        review = self.chain.review_with("ESCALATE")
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            human_review_result=review,
        )
        self.assertEqual(
            result["workflow_state"], STATE_AWAITING_HUMAN_DECISION
        )
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_REQUEST_HUMAN_REVIEW
        )

    def test_needs_review_stays_in_human_boundary(self):
        review = self.chain.review_with("NEEDS_REVIEW")
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            human_review_result=review,
        )
        self.assertEqual(
            result["workflow_state"], STATE_AWAITING_HUMAN_DECISION
        )
        self.assertEqual(result["next_action_reason"], "HUMAN_NEEDS_REVIEW")

    def test_approve_does_not_confirm_or_authorize_exploitation(self):
        result = build_security_research_workflow(
            **self.chain.partial("human")
        )
        self.assertEqual(result["workflow_state"], STATE_HUMAN_DECIDED)
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(result["summary"]["human_decision_status"], HUMAN_STATUS_DECIDED)
        self.assertEqual(
            result["summary"]["human_decision_type"], APPROVE
        )

    def test_conflicting_decisions_are_blocked(self):
        review = self.chain.multi_decision_review(
            [
                {"finding_id": self.chain.finding_id, "decision_type": APPROVE},
                {
                    "finding_id": self.chain.second_finding_id,
                    "decision_type": "DEFER",
                },
            ]
        )
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            human_review_result=review,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(result["next_action_reason"], "WORKFLOW_CONFLICT")
        self.assertIn(ERROR_WORKFLOW_CONFLICT, self.error_categories(result))


class TestLearningAndExecutionBoundaries(WorkflowTestCase):
    def test_r57_learning_integration(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        self.assertEqual(
            self.stage_status(result, STAGE_LEARNING),
            STAGE_STATUS_COMPLETED,
        )
        self.assertGreaterEqual(
            result["summary"]["learning_pattern_count"], 0
        )
        self.assertEqual(
            result["learning_reference"]["rule_version"], "r57-4"
        )

    def test_r57_blocking_recommendation_blocks(self):
        learning = {
            "rule_version": "r57-4",
            "calibration_recommendations": [
                {"recommendation_code": "REQUEST_MORE_EVIDENCE"}
            ],
        }
        result = build_security_research_workflow(
            **self.chain.partial("human"),
            learning_result=learning,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(
            result["next_action_reason"], "LEARNING_BLOCKING_RECOMMENDATION"
        )
        self.assertIn(
            ERROR_LEARNING_REVIEW_REQUIRED, self.error_categories(result)
        )

    def test_r57_safety_review_blocks(self):
        learning = {
            "rule_version": "r57-4",
            "calibration_recommendations": [
                {"recommendation_code": "REVIEW_SAFETY_BOUNDARY"}
            ],
        }
        result = build_security_research_workflow(
            **self.chain.partial("human"),
            learning_result=learning,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(
            self.stage_status(result, STAGE_LEARNING), "BLOCKED"
        )

    def test_r58_blocked_integration(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_control_result=self.chain.control_blocked,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(result["next_action_reason"], "EXECUTION_BLOCKED")
        self.assertIn(
            ERROR_EXECUTION_CONTROL_BLOCKED, self.error_categories(result)
        )

    def test_r58_public_api_authorized_path(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_request=self.chain.request,
            authorization_context=self.chain.authorization_context,
        )
        self.assertEqual(result["workflow_state"], STATE_EXECUTION_REVIEWED)
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_CONTROLLED_AUTHORIZATION
        )
        self.assertEqual(result["errors"], [])

    def test_r58_public_api_blocked_path(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_request=self.chain.request,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertIn(
            ERROR_EXECUTION_CONTROL_BLOCKED, self.error_categories(result)
        )

    def test_execution_review_without_human_decision_requires_human(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            execution_request=self.chain.request,
            authorization_context=self.chain.authorization_context,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertIn(
            ERROR_HUMAN_DECISION_REQUIRED, self.error_categories(result)
        )
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_HUMAN_REVIEW_REQUIRED
        )

    def test_execution_control_requires_human_boundary(self):
        result = build_security_research_workflow(
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["workflow_state"], STATE_INVALID)
        self.assertIn(
            ERROR_MISSING_REQUIRED_STAGE, self.error_categories(result)
        )


class TestErrorsAndConflicts(WorkflowTestCase):
    def test_malformed_request_is_invalid(self):
        result = build_security_research_workflow(workflow_request=42)
        self.assertEqual(result["workflow_state"], STATE_INVALID)
        self.assertIn(ERROR_MALFORMED_INPUT, self.error_categories(result))

    def test_mis_versioned_artifact_is_invalid(self):
        result = build_security_research_workflow(
            correlation_result={"rule_version": "r99-9"}
        )
        self.assertEqual(result["workflow_state"], STATE_INVALID)
        self.assertIn(
            ERROR_RULE_VERSION_MISMATCH, self.error_categories(result)
        )

    def test_correlation_without_findings_is_missing_stage(self):
        result = build_security_research_workflow(
            correlation_result=self.chain.correlation
        )
        self.assertEqual(result["workflow_state"], STATE_INVALID)
        self.assertIn(
            ERROR_MISSING_REQUIRED_STAGE, self.error_categories(result)
        )

    def test_human_review_without_prioritization_is_missing_stage(self):
        result = build_security_research_workflow(
            human_review_result=self.chain.review
        )
        self.assertEqual(result["workflow_state"], STATE_INVALID)
        self.assertIn(
            ERROR_MISSING_REQUIRED_STAGE, self.error_categories(result)
        )

    def test_learning_without_human_boundary_is_missing_stage(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization"),
            learning_result=self.chain.learning,
        )
        self.assertEqual(result["workflow_state"], STATE_INVALID)
        self.assertIn(
            ERROR_MISSING_REQUIRED_STAGE, self.error_categories(result)
        )

    def test_orchestration_plus_standalone_is_conflict(self):
        result = build_security_research_workflow(
            orchestration_result=self.chain.orchestration,
            evaluation_results=self.chain.evaluations,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertIn(
            ERROR_WORKFLOW_CONFLICT, self.error_categories(result)
        )

    def test_safety_blocking(self):
        result = build_security_research_workflow(
            workflow_request={
                "finding_intelligence": {
                    "rule_version": "r53-6",
                    "status": "COMPLETED",
                    "findings": [],
                    "network_execution": True,
                }
            }
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertEqual(result["safety_status"], SAFETY_STATUS_SAFETY_BLOCKED)
        self.assertIn(ERROR_SAFETY_BLOCKED, self.error_categories(result))

    def test_unsupported_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("human")
        )
        advanced = advance_security_research_workflow(
            result, stage_type=STAGE_HUMAN_REVIEW
        )
        self.assertEqual(advanced["workflow_state"], result["workflow_state"])
        self.assertIn(
            ERROR_UNSUPPORTED_TRANSITION, self.error_categories(advanced)
        )

    def test_stage_order_invalid_transition(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization")
        )
        advanced = advance_security_research_workflow(
            result, stage_type=STAGE_EXECUTION_CONTROL
        )
        self.assertIn(
            ERROR_STAGE_ORDER_INVALID, self.error_categories(advanced)
        )

    def test_malformed_transition_stage(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization")
        )
        advanced = advance_security_research_workflow(
            result, stage_type="NOT_A_STAGE"
        )
        self.assertIn(
            ERROR_MALFORMED_INPUT, self.error_categories(advanced)
        )


class TestTransitions(WorkflowTestCase):
    def test_valid_transition_chain(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization")
        )
        result = advance_security_research_workflow(
            result,
            stage_type=STAGE_HUMAN_REVIEW,
            stage_status="COMPLETED",
            stage_facts={
                "decision_present": True,
                "decision_type": APPROVE,
            },
            reason="HUMAN_DECIDED",
        )
        self.assertEqual(result["workflow_state"], STATE_HUMAN_DECIDED)
        result = advance_security_research_workflow(
            result,
            stage_type=STAGE_LEARNING,
            stage_status="COMPLETED",
            stage_facts={"pattern_count": 1, "recommendation_count": 1},
        )
        self.assertEqual(result["workflow_state"], STATE_LEARNING_UPDATED)
        result = advance_security_research_workflow(
            result,
            stage_type=STAGE_EXECUTION_CONTROL,
            stage_status="COMPLETED",
            stage_facts={
                "control_outcome": "ALLOW",
                "execution_status": "READY_FOR_EXTERNAL_EXECUTOR",
                "execution_ready": True,
                "safety_result": "PASS",
            },
        )
        self.assertEqual(result["workflow_state"], STATE_COMPLETED)
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        )
        self.assertFalse(result["execution_performed"])

    def test_advance_from_terminal_state_is_refused(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning"),
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["workflow_state"], STATE_COMPLETED)
        advanced = advance_security_research_workflow(
            result, stage_type=STAGE_EXECUTION_CONTROL
        )
        self.assertIn(
            ERROR_UNSUPPORTED_TRANSITION, self.error_categories(advanced)
        )

    def test_advance_does_not_mutate_input(self):
        result = build_security_research_workflow(
            **self.chain.partial("prioritization")
        )
        snapshot = json.dumps(result, sort_keys=True)
        advance_security_research_workflow(
            result,
            stage_type=STAGE_HUMAN_REVIEW,
            stage_status="COMPLETED",
            stage_facts={"decision_present": True, "decision_type": APPROVE},
        )
        self.assertEqual(json.dumps(result, sort_keys=True), snapshot)


class TestDeterminismAndPreservation(WorkflowTestCase):
    def test_deterministic_ids_and_output(self):
        first = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        second = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        self.assertEqual(first["workflow_id"], second["workflow_id"])
        self.assertEqual(first["result_id"], second["result_id"])
        self.assertEqual(
            [stage["stage_id"] for stage in first["stages"]],
            [stage["stage_id"] for stage in second["stages"]],
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_stable_stage_ordering(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        self.assertEqual(
            [stage["stage_type"] for stage in result["stages"]],
            list(WORKFLOW_STAGE_ORDER),
        )

    def test_content_derived_workflow_id(self):
        first = build_security_research_workflow(
            **self.chain.partial("findings")
        )
        second = build_security_research_workflow(
            research_context={"different": "input"}
        )
        self.assertNotEqual(first["workflow_id"], second["workflow_id"])

    def test_replay_consistency(self):
        payload = {
            "rule_version": "r59-1",
            **self.chain.partial("learning"),
        }
        first = build_security_research_workflow(workflow_request=payload)
        second = build_security_research_workflow(workflow_request=payload)
        self.assertEqual(first["result_id"], second["result_id"])
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_inputs_are_not_mutated(self):
        artifacts = (
            ("orchestration", self.chain.orchestration),
            ("findings", self.chain.findings),
            ("correlation", self.chain.correlation),
            ("prioritization", self.chain.prioritization),
            ("review", self.chain.review),
            ("learning", self.chain.learning),
            ("control", self.chain.control_ready),
        )
        snapshots = {
            name: json.dumps(value, sort_keys=True) for name, value in artifacts
        }
        build_security_research_workflow(
            orchestration_result=self.chain.orchestration,
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
        )
        for name, value in artifacts:
            self.assertEqual(
                json.dumps(value, sort_keys=True), snapshots[name], name
            )

    def test_provenance_preservation(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        provenance = result["provenance"]
        self.assertEqual(provenance["finding_rule_version"], "r53-6")
        self.assertEqual(provenance["correlation_rule_version"], "r54-2")
        self.assertEqual(provenance["priority_rule_version"], "r55-2")
        self.assertEqual(provenance["decision_rule_version"], "r56-3")
        self.assertEqual(provenance["learning_rule_version"], "r57-4")
        self.assertEqual(
            provenance["orchestration_id"],
            self.chain.orchestration["orchestration_id"],
        )

    def test_governance_preservation(self):
        governance = {
            "rule_version": "r37-5",
            "ready": True,
            "provenance": {"provenance_state": "UNKNOWN"},
            "rule_trace": {"trace_state": "UNKNOWN"},
            "audit_event": {"audit_state": "UNKNOWN"},
            "explanation": {"explanation_state": "UNKNOWN"},
        }
        result = build_security_research_workflow(
            **self.chain.partial("learning"), governance=governance
        )
        self.assertEqual(result["governance"]["reference_state"], "REFERENCED")
        self.assertTrue(result["governance"]["ready"])

    def test_limitation_preservation(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_VULNERABILITY_CONFIRMATION",
            "RESEARCH_ONLY",
            "ADVISORY_ONLY",
            "HUMAN_AUTHORITY_REQUIRED",
            "AUTHORIZATION_IS_NOT_EXECUTION",
            "WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE",
            "PARTIAL_WORKFLOW_SUPPORTED",
            "NO_WALL_CLOCK_METADATA",
            "LEARNING_NOT_AUTHORIZATION",
            "EXECUTION_GATE_ONLY",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_rule_version_references_preserved(self):
        result = build_security_research_workflow(
            **self.chain.partial("learning")
        )
        self.assertEqual(result["finding_reference"]["rule_version"], "r53-6")
        self.assertEqual(
            result["correlation_reference"]["rule_version"], "r54-2"
        )
        self.assertEqual(
            result["priority_reference"]["rule_version"], "r55-2"
        )
        self.assertEqual(
            result["human_decision_reference"]["rule_version"], "r56-3"
        )
        self.assertEqual(
            result["learning_reference"]["rule_version"], "r57-4"
        )
        self.assertEqual(result["rule_version"], "r59-4")

    def test_helpers_are_consistent(self):
        result = build_security_research_workflow(
            **self.chain.partial("human")
        )
        action = determine_next_workflow_action(result)
        self.assertEqual(action["action_code"], ACTION_UPDATE_LEARNING)
        summary = build_security_research_workflow_summary(result)
        self.assertEqual(summary["workflow_state"], STATE_HUMAN_DECIDED)
        alias = export_security_research_workflow(
            **self.chain.partial("human")
        )
        self.assertEqual(alias["result_id"], result["result_id"])

    def test_no_execution_claims_anywhere(self):
        results = (
            build_security_research_workflow(),
            build_security_research_workflow(
                **self.chain.partial("learning")
            ),
            build_security_research_workflow(
                **self.chain.partial("learning"),
                execution_control_result=self.chain.control_ready,
            ),
            build_security_research_workflow(
                **self.chain.partial("learning"),
                execution_control_result=self.chain.control_blocked,
            ),
        )
        for result in results:
            self.assert_no_execution_claims(result)

    def test_summary_counts_do_not_invent_findings(self):
        result = build_security_research_workflow(
            orchestration_result=self.chain.orchestration,
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
        )
        summary = result["summary"]
        self.assertEqual(
            summary["finding_count"], len(self.chain.findings["findings"])
        )
        self.assertEqual(
            summary["specialists_completed"], len(self.chain.specialists)
        )
        self.assertEqual(
            summary["evaluation_count"], len(self.chain.evaluations)
        )


class TestFullChain(WorkflowTestCase):
    def test_full_end_to_end_chain(self):
        result = build_security_research_workflow(
            orchestration_result=self.chain.orchestration,
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["workflow_state"], STATE_COMPLETED)
        self.assertEqual(
            result["completed_stages"], list(WORKFLOW_STAGE_ORDER)
        )
        self.assertEqual(result["pending_stages"], [])
        self.assertEqual(result["blocked_stages"], [])
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        )
        self.assertEqual(
            result["next_action"]["action_code"], ACTION_COMPLETE_WORKFLOW
        )
        self.assertEqual(
            result["next_action"]["reason"], "EXECUTION_READY_FOR_EXTERNAL_EXECUTOR"
        )
        self.assert_no_execution_claims(result)
        summary = result["summary"]
        self.assertGreater(summary["specialists_completed"], 0)
        self.assertGreater(summary["finding_count"], 0)
        self.assertGreater(summary["correlated_finding_count"], 0)
        self.assertEqual(summary["human_decision_status"], HUMAN_STATUS_DECIDED)

    def test_full_chain_without_ready_preconditions(self):
        result = build_security_research_workflow(
            orchestration_result=self.chain.orchestration,
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=self.chain.review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_authorized,
        )
        self.assertEqual(result["workflow_state"], STATE_EXECUTION_REVIEWED)
        self.assertEqual(
            result["safety_status"], SAFETY_STATUS_CONTROLLED_AUTHORIZATION
        )
        self.assertFalse(result["execution_performed"])

    def test_full_chain_with_request_more_evidence_never_reaches_execution(self):
        review = self.chain.review_with("REQUEST_MORE_EVIDENCE")
        result = build_security_research_workflow(
            orchestration_result=self.chain.orchestration,
            finding_intelligence=self.chain.findings,
            correlation_result=self.chain.correlation,
            prioritization_result=self.chain.prioritization,
            human_review_result=review,
            learning_result=self.chain.learning,
            execution_control_result=self.chain.control_ready,
        )
        self.assertEqual(result["workflow_state"], STATE_BLOCKED)
        self.assertNotEqual(
            result["safety_status"], SAFETY_STATUS_CONTROLLED_AUTHORIZATION
        )
        self.assertNotEqual(
            result["safety_status"], SAFETY_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        )
        self.assert_no_execution_claims(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
