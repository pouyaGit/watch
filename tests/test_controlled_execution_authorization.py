"""tests/test_controlled_execution_authorization.py — Stage R58.2 tests.

Deterministic, offline tests for the R58 controlled execution authorization:

- authorization schema and forced authority/confirmation invariants
- explicit human authorization requirement (AI, missing, ambiguous rejected)
- exact action / target / scope / finding / decision matching
- R56 decision semantics: APPROVE_RESEARCH, REQUEST_MORE_EVIDENCE, DEFER,
  REJECT, ESCALATE and NEEDS_REVIEW
- R53/R54/R55/R57 inputs can never authorize execution
- explicit deterministic validity (no wall clock) and replay consistency
- provenance/governance preservation and input immutability

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.execution_control import (
    build_execution_request,
    validate_execution_authorization,
)
from ai.schemas.controlled_execution_authorization import (
    AUTHORIZATION_STATUS_AUTHORIZED,
    AUTHORIZATION_STATUS_BLOCKED,
    AUTHORIZATION_STATUS_EXPIRED,
    AUTHORIZATION_STATUS_INVALID,
    AUTHORIZATION_STATUS_NOT_REQUESTED,
    CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION,
    CONSTRAINT_NO_NETWORK_EXECUTION,
    CONSTRAINT_RESEARCH_ONLY_ACTION,
    ControlledExecutionAuthorizationPlan,
    sanitize_execution_authorization,
)
from ai.schemas.execution_control_result import (
    REASON_ACTION_MISMATCH,
    REASON_AI_AUTHORIZATION_REJECTED,
    REASON_AUTHORIZATION_AMBIGUOUS,
    REASON_AUTHORIZATION_EXPIRED,
    REASON_AUTHORIZATION_MISSING,
    REASON_DECISION_DOES_NOT_AUTHORIZE,
    REASON_DECISION_MISMATCH,
    REASON_ESCALATION_REVIEW_REQUIRED,
    REASON_FINDING_MISMATCH,
    REASON_HUMAN_DECISION_PENDING,
    REASON_R57_RECOMMENDATION_REVIEW,
    REASON_SCOPE_MISMATCH,
    REASON_TARGET_MISMATCH,
)
from tests.test_execution_request import (
    ACTION,
    APPROVE,
    FINDING_ONE,
    FINDING_TWO,
    SCOPE,
    TARGET,
    approval_context,
    decision_for,
    pipeline,
    raw_finding,
    valid_request,
)

LEARNING_INFO = {
    "rule_version": "r57-4",
    "calibration_recommendations": [
        {"recommendation_code": "PRESERVE_SUCCESS_PATTERN"}
    ],
}
LEARNING_BLOCKING = {
    "rule_version": "r57-4",
    "calibration_recommendations": [
        {"recommendation_code": "REQUEST_MORE_EVIDENCE"}
    ],
}
LEARNING_SAFETY_BLOCKING = {
    "rule_version": "r57-4",
    "calibration_recommendations": [
        {"recommendation_code": "REVIEW_SAFETY_BOUNDARY"}
    ],
}


def approved_review(
    decision_type=APPROVE,
    finding_id_value=FINDING_ONE,
    rationale_codes=None,
):
    decision_record = {
        "finding_id": finding_id_value,
        "decision_type": decision_type,
    }
    if rationale_codes:
        decision_record["rationale_codes"] = list(rationale_codes)
    correlation, prioritization, review = pipeline(
        decisions=[decision_record]
    )
    decision = decision_for(review, finding_id_value)
    return correlation, prioritization, review, decision


def check_blocked(test_case, record, reason):
    test_case.assertEqual(record["authorization_status"], "BLOCKED")
    test_case.assertIn(reason, record["rejection_codes"])
    test_case.assertFalse(record["execution_authorized"])


class TestAuthorizationSchema(unittest.TestCase):
    def test_default_projection_is_fail_closed(self):
        projected = sanitize_execution_authorization(None)
        self.assertEqual(
            projected["authorization_status"],
            AUTHORIZATION_STATUS_NOT_REQUESTED,
        )
        self.assertFalse(projected["execution_authorized"])
        self.assertFalse(projected["exploit_authorized"])
        self.assertFalse(projected["vulnerability_confirmed"])
        self.assertEqual(projected["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(projected["human_authority"])

    def test_rule_version_is_stable(self):
        self.assertEqual(
            CONTROLLED_EXECUTION_AUTHORIZATION_RULE_VERSION, "r58-2"
        )

    def test_model_rejects_authorized_ai_source(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        with self.assertRaises(ValidationError):
            ControlledExecutionAuthorizationPlan(
                **{
                    **record,
                    "authorization_source": "AI",
                    "authorization_authority": "HUMAN",
                    "human_authority": False,
                }
            )

    def test_model_rejects_execution_authorized_when_blocked(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request, human_review_result=review
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        with self.assertRaises(ValidationError):
            ControlledExecutionAuthorizationPlan(
                **{**record, "execution_authorized": True}
            )

    def test_model_forces_exploit_and_confirmation_flags(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        with self.assertRaises(ValidationError):
            ControlledExecutionAuthorizationPlan(
                **{**record, "exploit_authorized": True}
            )
        with self.assertRaises(ValidationError):
            ControlledExecutionAuthorizationPlan(
                **{**record, "vulnerability_confirmed": True}
            )


class TestHumanAuthorization(unittest.TestCase):
    def test_explicit_human_authorization_is_accepted(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(
            record["authorization_status"], AUTHORIZATION_STATUS_AUTHORIZED
        )
        self.assertTrue(record["execution_authorized"])
        self.assertTrue(record["human_authority"])
        self.assertEqual(record["authorization_source"], "HUMAN")
        self.assertEqual(record["authorization_authority"], "HUMAN")
        self.assertEqual(record["rejection_codes"], [])
        self.assertTrue(record["allow_reasons"])
        self.assertIn(
            CONSTRAINT_RESEARCH_ONLY_ACTION, record["approval_constraints"]
        )
        self.assertIn(
            CONSTRAINT_NO_NETWORK_EXECUTION, record["approval_constraints"]
        )

    def test_ai_originated_authorization_is_rejected(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, authorization_source="AI"
            ),
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_AI_AUTHORIZATION_REJECTED, record["rejection_codes"]
        )
        self.assertFalse(record["execution_authorized"])
        self.assertFalse(record["human_authority"])

    def test_non_human_authority_is_rejected(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, authorization_authority="SYSTEM"
            ),
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_AI_AUTHORIZATION_REJECTED, record["rejection_codes"]
        )

    def test_missing_authorization_is_rejected(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request, human_review_result=review
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_AUTHORIZATION_MISSING, record["rejection_codes"]
        )
        self.assertFalse(record["execution_authorized"])

    def test_missing_human_decision_is_rejected(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request, authorization_context=approval_context(decision)
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_AUTHORIZATION_MISSING, record["rejection_codes"]
        )

    def test_pending_review_is_rejected(self):
        correlation, prioritization, review = pipeline(decisions=None)
        request = valid_request()
        record = validate_execution_authorization(
            request, human_review_result=review
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_HUMAN_DECISION_PENDING, record["rejection_codes"]
        )

    def test_ambiguous_authorization_is_rejected(self):
        _, _, review, first = approved_review()
        _, _, _, second = approved_review(
            rationale_codes=["EVIDENCE_SUFFICIENT"]
        )
        self.assertNotEqual(first["decision_id"], second["decision_id"])
        request = valid_request(decision=first)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            human_decision=second,
            authorization_context=approval_context(first),
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_AUTHORIZATION_AMBIGUOUS, record["rejection_codes"]
        )

    def test_conflicting_context_is_ambiguous(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            approved_scope="/api/v2/other",
        )
        self.assertEqual(record["authorization_status"], "BLOCKED")
        self.assertIn(
            REASON_AUTHORIZATION_AMBIGUOUS, record["rejection_codes"]
        )


class TestExactMatching(unittest.TestCase):
    def test_action_mismatch(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_action="COLLECT_EXISTING_EVIDENCE"
            ),
        )
        check_blocked(self,record, REASON_ACTION_MISMATCH)

    def test_target_mismatch(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_target="other.example.test"
            ),
        )
        check_blocked(self,record, REASON_TARGET_MISMATCH)

    def test_scope_mismatch(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_scope="/api/v1"
            ),
        )
        check_blocked(self,record, REASON_SCOPE_MISMATCH)

    def test_broader_scope_does_not_expand(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_scope="/"
            ),
        )
        check_blocked(self,record, REASON_SCOPE_MISMATCH)

    def test_wildcard_scope_is_rejected(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_scope="/*"
            ),
        )
        check_blocked(self,record, "WILDCARD_SCOPE_NOT_ALLOWED")

    def test_finding_mismatch(self):
        _, _, review, decision = approved_review()
        request = build_execution_request(
            finding_id=FINDING_TWO,
            action_type=ACTION,
            action_scope=SCOPE,
            scope_kind="PATH",
            target_reference=TARGET,
            purpose="wrong finding",
            requested_by="HUMAN",
            human_decision_reference=decision,
        )
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            human_decision=decision,
            authorization_context=approval_context(decision),
        )
        check_blocked(self,record, REASON_FINDING_MISMATCH)

    def test_decision_mismatch(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, decision_reference="hdc-" + "a" * 16
            ),
        )
        check_blocked(self,record, REASON_DECISION_MISMATCH)

    def test_request_decision_reference_mismatch(self):
        _, _, review, decision = approved_review()
        other = "hdc-" + "b" * 16
        request = build_execution_request(
            finding_id=FINDING_ONE,
            action_type=ACTION,
            action_scope=SCOPE,
            scope_kind="PATH",
            target_reference=TARGET,
            purpose="stale reference",
            requested_by="HUMAN",
            human_decision_reference={
                "decision_id": other,
                "finding_id": FINDING_ONE,
                "decision_type": APPROVE,
            },
        )
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, decision_reference=other
            ),
        )
        check_blocked(self,record, REASON_DECISION_MISMATCH)


class TestDecisionSemantics(unittest.TestCase):
    def test_approve_research_alone_does_not_authorize(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request, human_review_result=review
        )
        check_blocked(self,record, REASON_AUTHORIZATION_MISSING)
        self.assertEqual(decision["decision_type"], APPROVE)

    def test_approve_authorizes_only_the_exact_structured_action(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        exact = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(exact["authorization_status"], "AUTHORIZED")
        other = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, approved_action="PREPARE_RESEARCH_STEP"
            ),
        )
        check_blocked(self,other, REASON_ACTION_MISMATCH)

    def test_request_more_evidence_blocks(self):
        _, _, review, decision = approved_review("REQUEST_MORE_EVIDENCE")
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        check_blocked(self,record, REASON_DECISION_DOES_NOT_AUTHORIZE)

    def test_defer_blocks(self):
        _, _, review, decision = approved_review("DEFER")
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        check_blocked(self,record, REASON_DECISION_DOES_NOT_AUTHORIZE)

    def test_reject_blocks(self):
        _, _, review, decision = approved_review("REJECT")
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        check_blocked(self,record, REASON_DECISION_DOES_NOT_AUTHORIZE)

    def test_needs_review_blocks(self):
        _, _, review, decision = approved_review("NEEDS_REVIEW")
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        check_blocked(self,record, REASON_DECISION_DOES_NOT_AUTHORIZE)

    def test_escalate_requires_review(self):
        _, _, review, decision = approved_review("ESCALATE")
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        check_blocked(self,record, REASON_ESCALATION_REVIEW_REQUIRED)


class TestContextIntelligenceCannotAuthorize(unittest.TestCase):
    def test_r57_recommendation_cannot_authorize(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request, learning_result=LEARNING_INFO
        )
        check_blocked(self,record, REASON_AUTHORIZATION_MISSING)
        self.assertIn("LEARNING_NOT_AUTHORIZATION", record["limitations"])

    def test_r57_blocking_recommendation_blocks_even_with_authorization(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result=LEARNING_BLOCKING,
        )
        check_blocked(self,record, REASON_R57_RECOMMENDATION_REVIEW)

    def test_r57_safety_recommendation_blocks(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result=LEARNING_SAFETY_BLOCKING,
        )
        check_blocked(self,record, REASON_R57_RECOMMENDATION_REVIEW)

    def test_r57_informational_recommendation_neither_authorizes_nor_blocks(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
            learning_result=LEARNING_INFO,
        )
        self.assertEqual(record["authorization_status"], "AUTHORIZED")

    def test_priority_cannot_authorize(self):
        priority = {
            "prioritization_id": "pri-" + "a" * 16,
            "priority_rule_version": "r55-3",
            "priority_score": 99,
            "priority_band": "CRITICAL",
            "ranking_position": 1,
            "priority_reasons": ["EVIDENCE_COMPLETE"],
        }
        request = build_execution_request(
            finding_id=FINDING_ONE,
            action_type=ACTION,
            action_scope=SCOPE,
            scope_kind="PATH",
            target_reference=TARGET,
            purpose="critical priority",
            requested_by="AI_ADVISORY",
            priority_reference=priority,
        )
        record = validate_execution_authorization(request)
        check_blocked(self,record, REASON_AUTHORIZATION_MISSING)
        self.assertIn("PRIORITY_NOT_AUTHORIZATION", record["limitations"])
        self.assertFalse(record["execution_authorized"])

    def test_finding_state_cannot_authorize(self):
        record = raw_finding()
        record["state"] = "CONFIRMED_OBSERVED"
        intelligence = {"rule_version": "r53-6", "findings": [record]}
        request = build_execution_request(
            finding_id=FINDING_ONE,
            action_type=ACTION,
            action_scope=SCOPE,
            scope_kind="PATH",
            target_reference=TARGET,
            purpose="confirmed observation",
            requested_by="AI_ADVISORY",
        )
        authorization = validate_execution_authorization(
            request, finding_intelligence=intelligence
        )
        check_blocked(self,authorization, REASON_AUTHORIZATION_MISSING)
        self.assertFalse(authorization["vulnerability_confirmed"])
        self.assertIn(
            "FINDING_NOT_CONFIRMATION", authorization["limitations"]
        )

    def test_correlation_cannot_authorize(self):
        correlation, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request, correlation_result=correlation
        )
        check_blocked(self,record, REASON_AUTHORIZATION_MISSING)
        self.assertIn(
            "CORRELATION_NOT_AUTHORIZATION", record["limitations"]
        )


class TestValidityAndReplay(unittest.TestCase):
    def test_expired_authorization_is_not_authorized(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, validity={"validity_state": "EXPIRED"}
            ),
        )
        self.assertEqual(
            record["authorization_status"], AUTHORIZATION_STATUS_EXPIRED
        )
        self.assertIn(
            REASON_AUTHORIZATION_EXPIRED, record["rejection_codes"]
        )
        self.assertFalse(record["execution_authorized"])

    def test_invalid_validity_is_not_authorized(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(
                decision, validity={"validity_state": "INVALID"}
            ),
        )
        self.assertEqual(
            record["authorization_status"], AUTHORIZATION_STATUS_INVALID
        )
        self.assertFalse(record["execution_authorized"])

    def test_validity_defaults_to_valid_without_wall_clock(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(record["validity"]["validity_state"], "VALID")
        self.assertEqual(
            record["validity"]["validity_basis"], "DEFAULT_VALID_NO_EXPIRY"
        )
        self.assertFalse(record["validity"]["expires"])

    def test_replay_is_consistent(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        first = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        second = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(first["authorization_id"], second["authorization_id"])
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_replay_of_blocked_authorization_is_consistent(self):
        _, _, review, decision = approved_review("DEFER")
        request = valid_request(decision=decision)
        first = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        second = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(first["authorization_status"], "BLOCKED")
        self.assertEqual(first["authorization_id"], second["authorization_id"])


class TestProvenanceAndImmutability(unittest.TestCase):
    def test_provenance_and_governance_are_preserved(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        record = validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=approval_context(decision),
        )
        self.assertEqual(
            record["provenance"]["decision_rule_version"], "r56-1"
        )
        self.assertEqual(record["provenance"]["decision_id"], decision["decision_id"])
        self.assertIn("rule_version", record["governance"])

    def test_inputs_are_not_mutated(self):
        _, _, review, decision = approved_review()
        request = valid_request(decision=decision)
        request_snapshot = json.dumps(request, sort_keys=True)
        review_snapshot = json.dumps(review, sort_keys=True)
        context = approval_context(decision)
        context_snapshot = json.dumps(context, sort_keys=True)
        validate_execution_authorization(
            request,
            human_review_result=review,
            authorization_context=context,
        )
        self.assertEqual(json.dumps(request, sort_keys=True), request_snapshot)
        self.assertEqual(json.dumps(review, sort_keys=True), review_snapshot)
        self.assertEqual(json.dumps(context, sort_keys=True), context_snapshot)

    def test_missing_request_is_not_requested(self):
        record = validate_execution_authorization()
        self.assertEqual(
            record["authorization_status"],
            AUTHORIZATION_STATUS_NOT_REQUESTED,
        )
        self.assertFalse(record["execution_authorized"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
