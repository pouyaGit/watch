"""tests/test_workflow_next_action.py — Stage R59 next-action tests.

Deterministic, offline tests for the R59 next-action recommendation:

- closed advisory action vocabulary
- no action names an execution, exploit, payload, scan or browser concept
- fixed action -> stage mapping
- forced advisory/no-auto-execute/human-authority invariants
- closed reasons and deterministic action ids
- fail-closed sanitizers and model round trips

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.security_research_workflow_rules import next_action_id
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
    ACTION_STAGE,
    ACTION_UPDATE_LEARNING,
    ACTION_WAIT_FOR_HUMAN_DECISION,
    BLOCKING_ACTIONS,
    REASON_EXECUTION_BLOCKED,
    REASON_SAFETY_BLOCKED,
    REASON_WORKFLOW_INVALID,
    WORKFLOW_NEXT_ACTION_LIMITATIONS,
    WORKFLOW_NEXT_ACTION_REASONS,
    WORKFLOW_NEXT_ACTION_RULE_VERSION,
    WORKFLOW_NEXT_ACTIONS,
    WorkflowNextActionPlan,
    sanitize_workflow_next_action,
    workflow_next_action_plan_projection,
)
from ai.schemas.workflow_stage import WORKFLOW_STAGE_ORDER

WORKFLOW_ID = "wfr-" + "2" * 16


class TestActionVocabulary(unittest.TestCase):
    def test_action_vocabulary_is_exact_and_closed(self):
        self.assertEqual(
            WORKFLOW_NEXT_ACTIONS,
            (
                ACTION_RUN_RESEARCH_ANALYSIS,
                ACTION_RUN_EVALUATION,
                ACTION_RUN_COLLABORATION,
                ACTION_RUN_FEEDBACK_ANALYSIS,
                ACTION_BUILD_FINDINGS,
                ACTION_CORRELATE_FINDINGS,
                ACTION_PRIORITIZE_RESEARCH,
                ACTION_REQUEST_HUMAN_REVIEW,
                ACTION_WAIT_FOR_HUMAN_DECISION,
                ACTION_UPDATE_LEARNING,
                ACTION_REVIEW_EXECUTION_CONTROL,
                ACTION_BLOCK_WORKFLOW,
                ACTION_COMPLETE_WORKFLOW,
            ),
        )

    def test_no_action_names_an_execution_concept(self):
        for action in WORKFLOW_NEXT_ACTIONS:
            for forbidden in (
                "EXPLOIT",
                "PAYLOAD",
                "ATTACK",
                "SCAN",
                "BROWSER",
                "COMMAND",
                "EXECUTE",
                "SUBPROCESS",
                "EXFILTRATE",
            ):
                self.assertNotIn(forbidden, action)

    def test_action_stage_mapping_targets_valid_stages(self):
        for action, stage in ACTION_STAGE.items():
            self.assertIn(action, WORKFLOW_NEXT_ACTIONS)
            if stage:
                self.assertIn(stage, WORKFLOW_STAGE_ORDER)

    def test_blocking_actions_are_closed(self):
        for action in BLOCKING_ACTIONS:
            self.assertIn(action, WORKFLOW_NEXT_ACTIONS)

    def test_rule_version_is_stable(self):
        self.assertEqual(WORKFLOW_NEXT_ACTION_RULE_VERSION, "r59-3")

    def test_reason_vocabulary_is_closed_and_deduplicated(self):
        self.assertEqual(
            len(set(WORKFLOW_NEXT_ACTION_REASONS)),
            len(WORKFLOW_NEXT_ACTION_REASONS),
        )
        for reason in (
            REASON_WORKFLOW_INVALID,
            REASON_SAFETY_BLOCKED,
            REASON_EXECUTION_BLOCKED,
        ):
            self.assertIn(reason, WORKFLOW_NEXT_ACTION_REASONS)

    def test_no_execution_instruction_limitation_is_always_present(self):
        self.assertIn(
            "NOT_AN_EXECUTION_INSTRUCTION",
            WORKFLOW_NEXT_ACTION_LIMITATIONS,
        )
        self.assertIn(
            "HUMAN_AUTHORITY_REQUIRED", WORKFLOW_NEXT_ACTION_LIMITATIONS
        )


class TestActionModel(unittest.TestCase):
    def action(self, **overrides):
        action = sanitize_workflow_next_action(
            {
                "rule_version": "r59-3",
                "action_id": next_action_id(
                    WORKFLOW_ID, ACTION_RUN_EVALUATION, "EVALUATION_MISSING"
                ),
                "action_code": ACTION_RUN_EVALUATION,
                "stage_type": "EVALUATION",
                "reason": "EVALUATION_MISSING",
                "execution_blocked": False,
                "provenance": {"workflow_id": WORKFLOW_ID},
                "limitations": list(WORKFLOW_NEXT_ACTION_LIMITATIONS),
            }
        )
        action.update(overrides)
        return action

    def test_valid_action_round_trips(self):
        action = self.action()
        model = WorkflowNextActionPlan(**action)
        self.assertEqual(
            workflow_next_action_plan_projection(model)["action_id"],
            action["action_id"],
        )

    def test_action_id_is_deterministic(self):
        first = next_action_id(
            WORKFLOW_ID, ACTION_RUN_EVALUATION, "EVALUATION_MISSING"
        )
        second = next_action_id(
            WORKFLOW_ID, ACTION_RUN_EVALUATION, "EVALUATION_MISSING"
        )
        other = next_action_id(
            WORKFLOW_ID, ACTION_RUN_EVALUATION, "COLLABORATION_MISSING"
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_model_forces_advisory_invariants(self):
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(**self.action(advisory=False))
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(
                **self.action(human_authority_required=False)
            )
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(**self.action(auto_execute=True))
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(**self.action(research_only=False))

    def test_model_rejects_unknown_action_code(self):
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(
                **self.action(action_code="EXECUTE_EXPLOIT")
            )

    def test_model_rejects_bad_action_id(self):
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(**self.action(action_id="bogus"))

    def test_model_rejects_invalid_reason(self):
        with self.assertRaises(ValidationError):
            WorkflowNextActionPlan(**self.action(reason="EXECUTE_NOW"))

    def test_sanitizer_defaults_are_fail_closed(self):
        action = sanitize_workflow_next_action(None)
        self.assertEqual(action["action_code"], ACTION_BLOCK_WORKFLOW)
        self.assertEqual(action["reason"], REASON_WORKFLOW_INVALID)
        self.assertTrue(action["advisory"])
        self.assertFalse(action["auto_execute"])
        self.assertTrue(action["execution_blocked"])

    def test_sanitizer_never_invents_another_action(self):
        action = sanitize_workflow_next_action(
            {"action_code": "RUN_SCANNER", "reason": "EXECUTE_NOW"}
        )
        self.assertEqual(action["action_code"], ACTION_BLOCK_WORKFLOW)
        self.assertEqual(action["reason"], "UNKNOWN_REASON")

    def test_limitations_are_ordered(self):
        action = self.action(
            limitations=list(reversed(WORKFLOW_NEXT_ACTION_LIMITATIONS))
        )
        model = WorkflowNextActionPlan(**action)
        ordered = [
            code
            for code in WORKFLOW_NEXT_ACTION_LIMITATIONS
            if code in set(model.limitations)
        ]
        self.assertEqual(model.limitations, ordered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
