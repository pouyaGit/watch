"""tests/test_controlled_execution.py — Stage R58 control and plan tests.

Deterministic, offline tests for the R58 gate and declarative plan:

- declarative plan generation with no execution, network or command steps
- plan status transitions (NOT_REQUESTED / REQUESTED / BLOCKED / AUTHORIZED /
  READY_FOR_EXTERNAL_EXECUTOR / EXPIRED / INVALID) and no EXECUTED state
- control outcomes (ALLOW / DENY / NOT_REQUESTED / INVALID)
- blocked and authorized plans; READY_FOR_EXTERNAL_EXECUTOR semantics
- deterministic ids, byte-identical output and stable ordering
- provenance/governance/audit/limitation preservation
- empty, malformed and unsupported inputs
- full R53 -> R54 -> R55 -> R56 -> R57 -> R58 integration

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.continuous_learning import build_continuous_learning_result
from ai.knowledge.execution_control import (
    build_controlled_execution_plan,
    build_execution_request,
    evaluate_execution_control,
    export_execution_control,
    validate_execution_authorization,
)
from ai.schemas.controlled_execution_plan import (
    CONTROLLED_EXECUTION_PLAN_RULE_VERSION,
    CONTROLLED_EXECUTION_PLAN_STATUSES,
    PLAN_STATUS_AUTHORIZED,
    PLAN_STATUS_BLOCKED,
    PLAN_STATUS_EXPIRED,
    PLAN_STATUS_INVALID,
    PLAN_STATUS_NOT_REQUESTED,
    PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR,
    PLAN_STATUS_REQUESTED,
    STEP_ASSERT_SAFETY_CONSTRAINTS,
    STEP_RECONFIRM_CONTEXT_SUMMARY,
    STEP_VERIFY_HUMAN_AUTHORIZATION,
    ControlledExecutionPlan,
)
from ai.schemas.execution_control_result import (
    CONTROL_OUTCOME_ALLOW,
    CONTROL_OUTCOME_DENY,
    CONTROL_OUTCOME_INVALID,
    CONTROL_OUTCOME_NOT_REQUESTED,
    EXECUTION_CONTROL_RESULT_RULE_VERSION,
    EXECUTION_CONTROL_STATUSES,
    ExecutionControlResultPlan,
    REASON_AUTHORIZATION_MISSING,
    REASON_DECISION_DOES_NOT_AUTHORIZE,
    REASON_R57_RECOMMENDATION_REVIEW,
    SAFETY_BLOCKED,
    SAFETY_PASS,
)
from tests.test_execution_request import (
    ACTION,
    APPROVE,
    FINDING_ONE,
    SCOPE,
    TARGET,
    approval_context,
    decision_for,
    pipeline,
    raw_finding,
    valid_request,
)

LEARNING_BLOCKING = {
    "rule_version": "r57-4",
    "calibration_recommendations": [
        {"recommendation_code": "REQUEST_MORE_EVIDENCE"}
    ],
}


def approved(decision_type=APPROVE):
    correlation, prioritization, review = pipeline(
        decisions=[
            {
                "finding_id": FINDING_ONE,
                "decision_type": decision_type,
            }
        ]
    )
    decision = decision_for(review, FINDING_ONE)
    return correlation, prioritization, review, decision


class TestPlanDeclarative(unittest.TestCase):
    def test_plan_is_declarative_and_never_executes(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        plan = build_controlled_execution_plan(
            request,
            execution_authorization=authorization,
            preconditions_met=True,
        )
        self.assertTrue(plan["plan_declarative"])
        self.assertFalse(plan["execution_performed"])
        self.assertFalse(plan["external_executor_present"])
        self.assertEqual(plan["external_executor_state"], "ABSENT")
        self.assertTrue(plan["ordered_steps"])
        for step in plan["ordered_steps"]:
            self.assertEqual(step["execution_mode"], "DECLARATIVE_ONLY")
            self.assertTrue(step["declarative"])
            self.assertFalse(step["performs_network_io"])
            self.assertFalse(step["executes_commands"])
            self.assertFalse(step["requires_external_executor"])

    def test_plan_step_order_is_stable(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        plan = build_controlled_execution_plan(
            request, execution_authorization=authorization
        )
        self.assertEqual(
            [step["step_code"] for step in plan["ordered_steps"]],
            [
                STEP_RECONFIRM_CONTEXT_SUMMARY,
                STEP_VERIFY_HUMAN_AUTHORIZATION,
                STEP_ASSERT_SAFETY_CONSTRAINTS,
            ],
        )

    def test_plan_declares_preconditions_safety_and_stop_conditions(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        plan = build_controlled_execution_plan(
            request, execution_authorization=authorization
        )
        self.assertIn("HUMAN_AUTHORIZATION_VALID", plan["preconditions"])
        self.assertIn("NO_NETWORK_IO", plan["safety_checks"])
        self.assertIn("NO_PAYLOAD_GENERATION", plan["safety_checks"])
        self.assertIn("AUTHORIZATION_REVOKED", plan["stop_conditions"])
        self.assertIn("SCOPE_CHANGED", plan["stop_conditions"])
        self.assertTrue(plan["rollback"]["abort_supported"])
        self.assertFalse(plan["rollback"]["rollback_supported"])

    def test_plan_status_vocabulary_has_no_executed_state(self):
        for status in CONTROLLED_EXECUTION_PLAN_STATUSES:
            self.assertNotEqual(status, "EXECUTED")

    def test_plan_model_rejects_execution(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        plan = build_controlled_execution_plan(request)
        with self.assertRaises(Exception):
            ControlledExecutionPlan(**{**plan, "execution_performed": True})
        with self.assertRaises(Exception):
            ControlledExecutionPlan(
                **{**plan, "external_executor_present": True}
            )


class TestPlanStatusTransitions(unittest.TestCase):
    def test_missing_request_is_not_requested(self):
        plan = build_controlled_execution_plan()
        self.assertEqual(
            plan["execution_status"], PLAN_STATUS_NOT_REQUESTED
        )

    def test_malformed_request_is_invalid(self):
        plan = build_controlled_execution_plan(42)
        self.assertEqual(plan["execution_status"], PLAN_STATUS_INVALID)

    def test_request_without_authorization_is_requested(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        plan = build_controlled_execution_plan(request)
        self.assertEqual(plan["execution_status"], PLAN_STATUS_REQUESTED)

    def test_blocked_authorization_blocks_plan(self):
        _, _, review, decision = approved("DEFER")
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        plan = build_controlled_execution_plan(
            request, execution_authorization=authorization
        )
        self.assertEqual(plan["execution_status"], PLAN_STATUS_BLOCKED)

    def test_authorized_plan_without_preconditions_stays_authorized(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        plan = build_controlled_execution_plan(
            request, execution_authorization=authorization
        )
        self.assertEqual(plan["execution_status"], PLAN_STATUS_AUTHORIZED)

    def test_ready_for_external_executor_when_authorized_and_ready(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        plan = build_controlled_execution_plan(
            request,
            execution_authorization=authorization,
            preconditions_met=True,
        )
        self.assertEqual(
            plan["execution_status"], PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        )
        self.assertFalse(plan["execution_performed"])
        self.assertFalse(plan["external_executor_present"])
        self.assertEqual(
            plan["authorization_reference"]["authorization_status"],
            "AUTHORIZED",
        )

    def test_expired_authorization_expires_plan(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        authorization = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, validity={"validity_state": "EXPIRED"}
            ),
        )
        plan = build_controlled_execution_plan(
            request, execution_authorization=authorization
        )
        self.assertEqual(plan["execution_status"], PLAN_STATUS_EXPIRED)

    def test_blocked_request_blocks_plan(self):
        request = valid_request()
        request = build_execution_request(
            request={
                **request,
                "network_execution": True,
            }
        )
        plan = build_controlled_execution_plan(request)
        self.assertEqual(plan["execution_status"], PLAN_STATUS_BLOCKED)


class TestControlOutcomes(unittest.TestCase):
    def test_empty_input_is_not_requested(self):
        result = evaluate_execution_control()
        self.assertEqual(result["status"], "NOT_REQUESTED")
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_NOT_REQUESTED)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["execution_performed"])

    def test_malformed_input_is_invalid(self):
        result = evaluate_execution_control(42)
        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_INVALID)
        self.assertTrue(result["errors"])
        self.assertFalse(result["execution_performed"])

    def test_missing_authorization_denies(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request, human_review_result=review
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertIn(REASON_AUTHORIZATION_MISSING, result["block_reasons"])
        self.assertFalse(result["execution_authorized"])

    def test_valid_authorization_allows_controlled_eligibility(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_ALLOW)
        self.assertTrue(result["execution_authorized"])
        self.assertEqual(result["safety_result"], SAFETY_PASS)
        self.assertEqual(result["block_reasons"], [])
        self.assertTrue(result["allow_reasons"])
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["external_executor_present"])

    def test_blocking_decision_denies_even_with_exact_context(self):
        _, _, review, decision = approved("REQUEST_MORE_EVIDENCE")
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertIn(
            REASON_DECISION_DOES_NOT_AUTHORIZE, result["block_reasons"]
        )

    def test_unsafe_request_denies_with_safety_evidence(self):
        request = build_execution_request(
            request={
                "finding_id": FINDING_ONE,
                "action_type": ACTION,
                "action_scope": SCOPE,
                "target_reference": TARGET,
                "purpose": "unsafe",
                "requested_by": "HUMAN",
                "subprocess": True,
            }
        )
        result = evaluate_execution_control(request)
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertEqual(result["safety_result"], SAFETY_BLOCKED)
        self.assertTrue(result["safety_reasons"])

    def test_unsupported_action_is_invalid_or_blocked(self):
        request = valid_request(action="RUN_SCANNER")
        result = evaluate_execution_control(request)
        self.assertIn(request["request_state"], ("INVALID", "BLOCKED"))
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertFalse(result["execution_authorized"])

    def test_control_result_has_no_executed_state(self):
        for status in EXECUTION_CONTROL_STATUSES:
            self.assertNotEqual(status, "EXECUTED")

    def test_control_model_forces_no_execution(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        with self.assertRaises(Exception):
            ExecutionControlResultPlan(
                **{**result, "execution_performed": True}
            )
        with self.assertRaises(Exception):
            ExecutionControlResultPlan(
                **{**result, "vulnerability_confirmed": True}
            )

    def test_export_alias(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        first = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        second = export_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(first["control_id"], second["control_id"])


class TestDeterminism(unittest.TestCase):
    def test_control_id_and_audit_are_deterministic(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        first = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        second = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(first["control_id"], second["control_id"])
        self.assertEqual(
            first["audit"]["audit_id"], second["audit"]["audit_id"]
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_control_id_changes_with_inputs(self):
        _, _, review, decision = approved()
        first = evaluate_execution_control(
            valid_request(decision=decision),
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        second = evaluate_execution_control(
            valid_request(decision=decision, scope="/api/v2/users"),
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_scope="/api/v2/users"
            ),
        )
        self.assertNotEqual(first["control_id"], second["control_id"])

    def test_stable_ordering_with_shuffled_layer_inputs(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        request = valid_request(decision=decision)
        context = approval_context(decision)
        first = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=context,
            correlation_result=correlation,
            prioritization_result=prioritization,
        )
        second = evaluate_execution_control(
            request,
            prioritization_result=prioritization,
            authorization_context=context,
            correlation_result=correlation,
            human_review_result=review,
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_inputs_are_not_mutated(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        request = valid_request(decision=decision)
        snapshots = {
            "request": json.dumps(request, sort_keys=True),
            "review": json.dumps(review, sort_keys=True),
            "priority": json.dumps(prioritization, sort_keys=True),
            "correlation": json.dumps(correlation, sort_keys=True),
        }
        evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            correlation_result=correlation,
            prioritization_result=prioritization,
        )
        self.assertEqual(
            json.dumps(request, sort_keys=True), snapshots["request"]
        )
        self.assertEqual(
            json.dumps(review, sort_keys=True), snapshots["review"]
        )
        self.assertEqual(
            json.dumps(prioritization, sort_keys=True), snapshots["priority"]
        )
        self.assertEqual(
            json.dumps(correlation, sort_keys=True), snapshots["correlation"]
        )


class TestAuditability(unittest.TestCase):
    def test_audit_preserves_decision_context_and_reasons(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        audit = result["audit"]
        self.assertEqual(audit["request_id"], request["request_id"])
        self.assertEqual(audit["decision_id"], decision["decision_id"])
        self.assertEqual(
            audit["authorization_id"], result["authorization_id"]
        )
        self.assertEqual(audit["action_type"], ACTION)
        self.assertEqual(audit["target_reference"], TARGET)
        self.assertEqual(audit["action_scope"], SCOPE)
        self.assertEqual(audit["finding_id"], FINDING_ONE)
        self.assertEqual(audit["safety_result"], SAFETY_PASS)
        self.assertEqual(audit["control_outcome"], CONTROL_OUTCOME_ALLOW)
        self.assertTrue(audit["outcome_reasons"])
        self.assertEqual(audit["audit_state"], "VALID")

    def test_audit_preserves_block_reason(self):
        _, _, review, decision = approved("DEFER")
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertIn(
            REASON_DECISION_DOES_NOT_AUTHORIZE,
            result["audit"]["outcome_reasons"],
        )

    def test_audit_has_no_secrets_or_credentials(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        serialized = json.dumps(
            evaluate_execution_control(
                request,
                human_review_result=review,
                authorization_context=approval_context(decision),
            ),
            sort_keys=True,
        ).lower()
        for forbidden in (
            "api_key",
            "apikey",
            "password",
            "credential",
            "secret",
            "bearer ",
            "token=",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_provenance_and_governance_are_preserved(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            correlation_result=correlation,
            prioritization_result=prioritization,
        )
        provenance = result["provenance"]
        self.assertEqual(provenance["request_id"], request["request_id"])
        self.assertEqual(
            provenance["authorization_id"], result["authorization_id"]
        )
        self.assertEqual(provenance["finding_id"], FINDING_ONE)
        self.assertEqual(provenance["decision_id"], decision["decision_id"])
        self.assertEqual(provenance["rule_version"], "r58-6")
        self.assertIn("rule_version", result["governance"])

    def test_limitations_are_preserved(self):
        _, _, review, decision = approved()
        result = evaluate_execution_control(
            valid_request(decision=decision),
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "RESEARCH_ONLY",
            "EXTERNAL_EXECUTOR_ABSENT",
            "AUTHORIZATION_IS_NOT_EXECUTION",
            "NO_LLM_INVOLVEMENT",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_rule_versions_are_stable(self):
        self.assertEqual(EXECUTION_CONTROL_RESULT_RULE_VERSION, "r58-4")
        self.assertEqual(CONTROLLED_EXECUTION_PLAN_RULE_VERSION, "r58-3")


class TestR53ToR57Integration(unittest.TestCase):
    def test_full_pipeline_authorizes_exact_research_action(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        learning = build_continuous_learning_result(
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        request = build_execution_request(
            finding_id=FINDING_ONE,
            action_type=ACTION,
            action_scope=SCOPE,
            scope_kind="PATH",
            target_reference=TARGET,
            purpose="Re-read the recorded context summary",
            requested_by="AI_ADVISORY",
            human_decision_reference=decision,
            priority_reference=prioritization,
            correlation_reference=correlation,
            finding_reference=decision["finding_reference"],
        )
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result=learning,
            correlation_result=correlation,
            prioritization_result=prioritization,
            preconditions_met=True,
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_ALLOW)
        self.assertEqual(result["safety_result"], SAFETY_PASS)
        self.assertEqual(
            result["execution_status"], PLAN_STATUS_READY_FOR_EXTERNAL_EXECUTOR
        )
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])

    def test_learning_blocking_recommendation_denies(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result=LEARNING_BLOCKING,
        )
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertIn(
            REASON_R57_RECOMMENDATION_REVIEW, result["block_reasons"]
        )

    def test_upstream_outputs_are_not_mutated_by_r58(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review, FINDING_ONE)
        learning = build_continuous_learning_result(
            correlation_result=correlation,
            prioritization_result=prioritization,
            human_review_result=review,
        )
        snapshots = {
            "correlation": json.dumps(correlation, sort_keys=True),
            "prioritization": json.dumps(prioritization, sort_keys=True),
            "review": json.dumps(review, sort_keys=True),
            "learning": json.dumps(learning, sort_keys=True),
        }
        evaluate_execution_control(
            valid_request(decision=decision),
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result=learning,
            correlation_result=correlation,
            prioritization_result=prioritization,
        )
        self.assertEqual(
            json.dumps(correlation, sort_keys=True),
            snapshots["correlation"],
        )
        self.assertEqual(
            json.dumps(prioritization, sort_keys=True),
            snapshots["prioritization"],
        )
        self.assertEqual(
            json.dumps(review, sort_keys=True), snapshots["review"]
        )
        self.assertEqual(
            json.dumps(learning, sort_keys=True), snapshots["learning"]
        )

    def test_upstream_rule_versions_unchanged(self):
        correlation, prioritization, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        self.assertEqual(correlation["rule_version"], "r54-2")
        self.assertEqual(prioritization["rule_version"], "r55-2")
        self.assertEqual(review["rule_version"], "r56-3")
        finding_record = raw_finding()
        self.assertEqual(finding_record["rule_version"], "r53-6")

    def test_confirmed_observed_state_is_not_exploitation(self):
        record = raw_finding()
        record["state"] = "CONFIRMED_OBSERVED"
        intelligence = {"rule_version": "r53-6", "findings": [record]}
        request = valid_request()
        result = evaluate_execution_control(
            request, finding_intelligence=intelligence
        )
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_DENY)
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertFalse(result["exploit_authorized"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")

    def test_mis_versioned_context_fails_closed(self):
        _, _, review, decision = approved()
        request = valid_request(decision=decision)
        result = evaluate_execution_control(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result={"rule_version": "r99-9"},
        )
        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["control_outcome"], CONTROL_OUTCOME_INVALID)
        self.assertFalse(result["execution_authorized"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
