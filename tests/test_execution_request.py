"""tests/test_execution_request.py — Stage R58 execution request tests.

Deterministic, offline tests for the R58 execution request contract:

- closed safe action vocabulary (no exploit actions)
- bounded scope/target/requester/purpose handling
- fail-closed request states and structured rejection codes
- wildcard and unsafe-input rejection without downgrade
- forced research-only/authorization flags and confirmation invariants
- deterministic ids and byte-identical output
- schema validation, R53-R56 reference preservation and input immutability

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

from ai.knowledge.finding_correlation import correlate_findings
from ai.knowledge.human_review import create_human_review
from ai.knowledge.research_prioritization import prioritize_findings
from ai.schemas.execution_request import (
    ACTION_COLLECT_EXISTING_EVIDENCE,
    ACTION_PREPARE_RESEARCH_STEP,
    ACTION_REASSESS_CONTEXT,
    ACTION_RECHECK_SCOPE,
    ACTION_REQUEST_HUMAN_REVIEW,
    ACTION_REVIEW_EXISTING_RESPONSE,
    ACTION_UNSPECIFIED,
    EXECUTION_ACTIONS,
    EXECUTION_REQUEST_REJECTION_CODES,
    EXECUTION_REQUEST_RULE_VERSION,
    EXECUTION_REQUESTERS,
    REJECTION_ACTION_NOT_SUPPORTED,
    REJECTION_FINDING_ID_REQUIRED,
    REJECTION_MALFORMED_REQUEST,
    REJECTION_PURPOSE_REQUIRED,
    REJECTION_SCOPE_REQUIRED,
    REJECTION_TARGET_REQUIRED,
    REJECTION_UNSAFE_REQUEST,
    REJECTION_WILDCARD_SCOPE,
    REQUEST_ID_RE,
    REQUEST_STATE_BLOCKED,
    REQUEST_STATE_INVALID,
    REQUEST_STATE_NOT_REQUESTED,
    REQUEST_STATE_REQUESTED,
    REQUESTER_AI_ADVISORY,
    REQUESTER_HUMAN,
    ExecutionRequestPlan,
    execution_request_plan_projection,
    normalize_execution_scope,
    normalize_target_reference,
    sanitize_execution_request,
)
from ai.schemas.execution_control_result import SAFETY_REASON_NETWORK_EXECUTION
from tests.test_research_priority_rules import finding

FINDING_ONE = "fnd-" + "1" * 16
FINDING_TWO = "fnd-" + "2" * 16
AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16

APPROVE = "APPROVE_RESEARCH"
ACTION = ACTION_REASSESS_CONTEXT
SCOPE = "/api/v1/users"
TARGET = "api.example.test"


def raw_finding(finding_id_value=FINDING_ONE, agent=AGENT_A, path="/a"):
    return finding(
        "XSS",
        agent,
        finding_id_value=finding_id_value,
        context={"endpoint_path": path},
    )


def pipeline(decisions=None, findings=None):
    """Run the R53-R56 chain and return (correlation, priority, review)."""

    records = findings or [raw_finding()]
    correlation = correlate_findings(records)
    prioritization = prioritize_findings(
        records, correlation_result=correlation
    )
    review = create_human_review(
        prioritization_result=prioritization,
        correlation_result=correlation,
        decisions=decisions,
    )
    return correlation, prioritization, review


def decision_for(review, finding_id_value=FINDING_ONE):
    for entry in review.get("reviews") or ():
        if entry.get("finding_id") == finding_id_value and entry.get("decision"):
            return entry["decision"]
    raise AssertionError(f"no decision for {finding_id_value}")


def valid_request(
    *,
    finding_id_value=FINDING_ONE,
    action=ACTION,
    scope=SCOPE,
    target=TARGET,
    purpose="Re-read the recorded context summary",
    requested_by=REQUESTER_HUMAN,
    decision=None,
    **kwargs,
):
    from ai.knowledge.execution_control import build_execution_request

    return build_execution_request(
        finding_id=finding_id_value,
        action_type=action,
        action_scope=scope,
        scope_kind="PATH",
        target_reference=target,
        purpose=purpose,
        requested_by=requested_by,
        human_decision_reference=decision,
        **kwargs,
    )


def approval_context(decision, **overrides):
    context = {
        "authorization_source": "HUMAN",
        "authorization_authority": "HUMAN",
        "decision_reference": decision["decision_id"],
        "approved_action": ACTION,
        "approved_scope": SCOPE,
        "approved_target": TARGET,
    }
    context.update(overrides)
    return context


class TestActionVocabulary(unittest.TestCase):
    def test_action_vocabulary_is_exact_and_closed(self):
        self.assertEqual(
            EXECUTION_ACTIONS,
            (
                ACTION_COLLECT_EXISTING_EVIDENCE,
                ACTION_REVIEW_EXISTING_RESPONSE,
                ACTION_RECHECK_SCOPE,
                ACTION_REASSESS_CONTEXT,
                ACTION_PREPARE_RESEARCH_STEP,
                ACTION_REQUEST_HUMAN_REVIEW,
            ),
        )

    def test_no_exploit_or_attack_actions_exist(self):
        for forbidden in (
            "EXPLOIT",
            "PAYLOAD",
            "ATTACK",
            "EXECUTE",
            "SCAN",
            "BROWSE",
            "SUBPROCESS",
            "DEPLOY",
        ):
            for action in EXECUTION_ACTIONS:
                self.assertNotIn(forbidden, action)

    def test_unsupported_action_is_not_silently_mapped(self):
        request = valid_request(action="RUN_SCANNER")
        self.assertEqual(request["action_type"], ACTION_UNSPECIFIED)
        self.assertEqual(request["requested_action_type"], "RUN_SCANNER")
        self.assertIn(
            REJECTION_ACTION_NOT_SUPPORTED,
            request["request_rejection_codes"],
        )
        self.assertIn(
            request["request_state"],
            (REQUEST_STATE_INVALID, REQUEST_STATE_BLOCKED),
        )

    def test_unknown_action_is_unspecified_not_another_action(self):
        request = valid_request(action="REASSESS_CONTEXT_COPY")
        self.assertEqual(request["action_type"], ACTION_UNSPECIFIED)
        self.assertNotIn(request["action_type"], EXECUTION_ACTIONS)


class TestRequestStates(unittest.TestCase):
    def test_valid_request_is_requested(self):
        request = valid_request()
        self.assertEqual(request["request_state"], REQUEST_STATE_REQUESTED)
        self.assertTrue(request["execution_requested"])
        self.assertEqual(request["request_rejection_codes"], [])

    def test_not_requested_when_execution_not_requested(self):
        from ai.knowledge.execution_control import build_execution_request

        request = build_execution_request(
            finding_id=FINDING_ONE,
            action_type=ACTION,
            action_scope=SCOPE,
            target_reference=TARGET,
            purpose="no execution",
            requested_by=REQUESTER_HUMAN,
            execution_requested=False,
        )
        self.assertEqual(request["request_state"], REQUEST_STATE_NOT_REQUESTED)
        self.assertFalse(request["execution_requested"])

    def test_missing_fields_fail_closed(self):
        from ai.knowledge.execution_control import build_execution_request

        request = build_execution_request()
        self.assertEqual(request["request_state"], REQUEST_STATE_INVALID)
        for code in (
            REJECTION_FINDING_ID_REQUIRED,
            REJECTION_ACTION_NOT_SUPPORTED,
            REJECTION_SCOPE_REQUIRED,
            REJECTION_TARGET_REQUIRED,
            REJECTION_PURPOSE_REQUIRED,
        ):
            self.assertIn(code, request["request_rejection_codes"])

    def test_malformed_request_fails_closed(self):
        from ai.knowledge.execution_control import build_execution_request

        request = build_execution_request(request=42)
        self.assertEqual(request["request_state"], REQUEST_STATE_INVALID)
        self.assertIn(
            REJECTION_MALFORMED_REQUEST, request["request_rejection_codes"]
        )

    def test_wildcard_scope_is_blocked(self):
        request = valid_request(scope="/*")
        self.assertEqual(request["request_state"], REQUEST_STATE_BLOCKED)
        self.assertIn(
            REJECTION_WILDCARD_SCOPE, request["request_rejection_codes"]
        )

    def test_wildcard_target_is_blocked(self):
        request = valid_request(target="*.example.test")
        self.assertEqual(request["request_state"], REQUEST_STATE_BLOCKED)

    def test_unsafe_input_is_blocked_not_downgraded(self):
        from ai.knowledge.execution_control import build_execution_request

        request = build_execution_request(
            request={
                "finding_id": FINDING_ONE,
                "action_type": ACTION,
                "action_scope": SCOPE,
                "target_reference": TARGET,
                "purpose": "unsafe",
                "requested_by": REQUESTER_HUMAN,
                "network_execution": True,
            }
        )
        self.assertEqual(request["request_state"], REQUEST_STATE_BLOCKED)
        self.assertIn(
            REJECTION_UNSAFE_REQUEST, request["request_rejection_codes"]
        )
        self.assertIn(
            SAFETY_REASON_NETWORK_EXECUTION,
            request["safety_context"]["safety_reasons"],
        )
        self.assertEqual(request["safety_context"]["safety_state"], "BLOCKED")


class TestForcedInvariants(unittest.TestCase):
    def test_authorization_and_confirmation_are_never_claimed(self):
        request = valid_request()
        self.assertFalse(request["execution_authorized"])
        self.assertFalse(request["vulnerability_confirmed"])
        self.assertFalse(request["exploit_authorized"])
        self.assertEqual(request["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(request["research_only"])
        self.assertTrue(request["deterministic"])

    def test_model_rejects_authorized_request(self):
        request = valid_request()
        with self.assertRaises(ValidationError):
            ExecutionRequestPlan(**{**request, "execution_authorized": True})

    def test_model_rejects_bad_request_id(self):
        request = valid_request()
        with self.assertRaises(ValidationError):
            ExecutionRequestPlan(**{**request, "request_id": "bogus"})

    def test_model_rejects_unknown_action(self):
        request = valid_request()
        with self.assertRaises(ValidationError):
            ExecutionRequestPlan(**{**request, "action_type": "RUN_SCANNER"})


class TestDeterminismAndReferences(unittest.TestCase):
    def test_request_id_is_deterministic_and_content_derived(self):
        first = valid_request()
        second = valid_request()
        self.assertEqual(first["request_id"], second["request_id"])
        self.assertTrue(REQUEST_ID_RE.match(first["request_id"]))
        changed = valid_request(scope="/api/v2/users")
        self.assertNotEqual(first["request_id"], changed["request_id"])

    def test_output_is_byte_identical(self):
        first = valid_request()
        second = valid_request()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_upstream_references_are_preserved(self):
        _, _, review = pipeline(
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": APPROVE,
                    "rationale_codes": ["EVIDENCE_SUFFICIENT"],
                }
            ]
        )
        decision = decision_for(review)
        request = valid_request(decision=decision)
        self.assertEqual(
            request["human_decision_reference"]["decision_id"],
            decision["decision_id"],
        )
        self.assertEqual(
            request["human_decision_reference"]["decision_type"], APPROVE
        )
        self.assertTrue(
            request["human_decision_reference"]["human_authority"]
        )
        self.assertEqual(
            request["priority_reference"]["prioritization_id"],
            decision["priority_reference"]["prioritization_id"],
        )
        self.assertEqual(
            request["correlation_reference"]["correlation_id"],
            decision["correlation_reference"]["correlation_id"],
        )
        self.assertEqual(
            request["finding_reference"]["finding_rule_version"], "r53-6"
        )
        self.assertEqual(
            request["provenance"]["decision_rule_version"], "r56-1"
        )

    def test_input_is_not_mutated(self):
        _, _, review = pipeline(
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": APPROVE}
            ]
        )
        decision = decision_for(review)
        snapshot = json.dumps(review, sort_keys=True)
        valid_request(decision=decision)
        self.assertEqual(json.dumps(review, sort_keys=True), snapshot)

    def test_ai_may_recommend_but_never_authorize(self):
        request = valid_request(requested_by=REQUESTER_AI_ADVISORY)
        self.assertEqual(request["request_state"], REQUEST_STATE_REQUESTED)
        self.assertTrue(request["execution_requested"])
        self.assertFalse(request["execution_authorized"])

    def test_normalizers_are_exact(self):
        self.assertEqual(
            normalize_execution_scope("  /api/v1/users  "), "/api/v1/users"
        )
        self.assertEqual(
            normalize_target_reference(" api.example.test "),
            "api.example.test",
        )

    def test_sanitizer_defaults_are_fail_closed(self):
        projected = sanitize_execution_request(None)
        self.assertEqual(projected["request_state"], REQUEST_STATE_INVALID)
        self.assertEqual(projected["action_type"], ACTION_UNSPECIFIED)

    def test_sanitizer_never_invents_a_valid_action(self):
        projected = sanitize_execution_request(
            {"action_type": "EXECUTE_EXPLOIT", "finding_id": FINDING_ONE}
        )
        self.assertEqual(projected["action_type"], ACTION_UNSPECIFIED)
        self.assertNotIn(projected["action_type"], EXECUTION_ACTIONS)

    def test_projection_round_trips(self):
        request = valid_request()
        model = ExecutionRequestPlan(**request)
        self.assertEqual(
            execution_request_plan_projection(model)["request_id"],
            request["request_id"],
        )

    def test_rejection_vocabulary_is_closed_and_deduplicated(self):
        self.assertEqual(
            len(set(EXECUTION_REQUEST_REJECTION_CODES)),
            len(EXECUTION_REQUEST_REJECTION_CODES),
        )
        self.assertIn(REQUESTER_HUMAN, EXECUTION_REQUESTERS)
        self.assertEqual(
            EXECUTION_REQUEST_REJECTION_CODES[0], "FINDING_ID_REQUIRED"
        )

    def test_request_rule_version_is_stable(self):
        request = valid_request()
        self.assertEqual(
            request["rule_version"], EXECUTION_REQUEST_RULE_VERSION
        )
        self.assertEqual(EXECUTION_REQUEST_RULE_VERSION, "r58-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
