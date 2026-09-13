"""tests/test_human_approval_gate.py — Stage R36.5 tests.

Deterministic, offline tests for the human approval gate:

- exact closed approval-state vocabulary
- derivation from policy/authorization
- explicit approval state transitions
- malformed input handling
- deterministic output, no mutation, JSON serialization
- schema validation, research_only, no execution vocabulary

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no messaging/notification system.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.human_approval_gate import plan_human_approval
from ai.schemas import human_approval_gate as schema


def policy(value):
    return {
        "rule_version": "r36-1",
        "policy": value,
        "policy_reason": "X",
        "constraints": [],
        "research_only": True,
    }


def authorization(decision):
    return {
        "rule_version": "r36-2",
        "decision": decision,
        "decision_reason": "X",
        "policy": "RESEARCH_ONLY",
        "limitations": [],
        "source_strategy": {},
        "source_orchestration": {},
        "research_only": True,
    }


class TestHumanApprovalGate(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.APPROVAL_STATES),
            {"NOT_REQUIRED", "PENDING", "APPROVED", "REJECTED",
             "EXPIRED", "UNKNOWN"},
        )

    def test_human_approval_required_defaults_pending(self):
        plan = plan_human_approval(
            policy("HUMAN_APPROVAL_REQUIRED"),
            authorization("REQUIRE_HUMAN_APPROVAL"),
        )
        self.assertEqual(plan["approval_state"], "PENDING")
        self.assertEqual(plan["approval_reason"], "APPROVAL_PENDING")
        self.assertTrue(plan["required"])

    def test_explicit_state_transitions(self):
        expectations = (
            ("PENDING", "APPROVAL_PENDING"),
            ("APPROVED", "APPROVAL_APPROVED"),
            ("REJECTED", "APPROVAL_REJECTED"),
            ("EXPIRED", "APPROVAL_EXPIRED"),
        )
        for state, reason in expectations:
            plan = plan_human_approval(
                policy("HUMAN_APPROVAL_REQUIRED"),
                authorization("REQUIRE_HUMAN_APPROVAL"),
                explicit_state=state,
            )
            self.assertEqual(plan["approval_state"], state)
            self.assertEqual(plan["approval_reason"], reason)
            self.assertTrue(plan["required"])

    def test_invalid_explicit_state_defaults_pending(self):
        for value in ("MAYBE", "", None, 0):
            plan = plan_human_approval(
                policy("HUMAN_APPROVAL_REQUIRED"),
                authorization("REQUIRE_HUMAN_APPROVAL"),
                explicit_state=value,
            )
            self.assertEqual(plan["approval_state"], "PENDING",
                             repr(value))

    def test_blocked_needs_no_approval(self):
        plan = plan_human_approval(
            policy("BLOCKED"), authorization("BLOCK")
        )
        self.assertEqual(plan["approval_state"], "NOT_REQUIRED")
        self.assertEqual(plan["approval_reason"], "BLOCKED_NO_ACTION")
        self.assertFalse(plan["required"])

    def test_research_only_not_required(self):
        plan = plan_human_approval(
            policy("RESEARCH_ONLY"),
            authorization("ALLOW_WITH_LIMITS"),
        )
        self.assertEqual(plan["approval_state"], "NOT_REQUIRED")
        self.assertEqual(plan["approval_reason"],
                         "RESEARCH_ONLY_NOT_REQUIRED")
        self.assertFalse(plan["required"])

    def test_authorized_not_required(self):
        plan = plan_human_approval(
            policy("ACTIVE_ALLOWED"), authorization("ALLOW")
        )
        self.assertEqual(plan["approval_state"], "NOT_REQUIRED")
        self.assertEqual(plan["approval_reason"],
                         "AUTHORIZED_NOT_REQUIRED")

    def test_unknown_context_is_unknown(self):
        plan = plan_human_approval()
        self.assertEqual(plan["approval_state"], "UNKNOWN")
        self.assertEqual(plan["approval_reason"], "UNKNOWN_CONTEXT")
        self.assertFalse(plan["required"])

    def test_explicit_state_never_overrides_block(self):
        plan = plan_human_approval(
            policy("BLOCKED"),
            authorization("BLOCK"),
            explicit_state="APPROVED",
        )
        self.assertEqual(plan["approval_state"], "NOT_REQUIRED")

    def test_no_mutation_of_inputs(self):
        pol = policy("HUMAN_APPROVAL_REQUIRED")
        auth = authorization("REQUIRE_HUMAN_APPROVAL")
        snapshots = (copy.deepcopy(pol), copy.deepcopy(auth))
        plan_human_approval(pol, auth, "APPROVED")
        self.assertEqual(pol, snapshots[0])
        self.assertEqual(auth, snapshots[1])

    def test_deterministic_output(self):
        args = (
            policy("HUMAN_APPROVAL_REQUIRED"),
            authorization("REQUIRE_HUMAN_APPROVAL"),
        )
        first = plan_human_approval(*args)
        second = plan_human_approval(*args)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = plan_human_approval()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(plan_human_approval()["research_only"], True)

    def test_schema_rejects_bad_values(self):
        base = {
            "approval_state": "PENDING",
            "approval_reason": "APPROVAL_PENDING",
        }
        for key, value in (
            ("approval_state", "WAITING_FOR_MANAGER"),
            ("approval_reason", "BECAUSE"),
        ):
            with self.assertRaises(ValidationError):
                schema.HumanApprovalGatePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.HumanApprovalGatePlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.HumanApprovalGatePlan(
            rule_version="r99-9",
            approval_state="UNKNOWN",
            approval_reason="UNKNOWN_CONTEXT",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r36-5")
        with self.assertRaises(ValidationError):
            schema.HumanApprovalGatePlan(
                approval_state="UNKNOWN",
                approval_reason="UNKNOWN_CONTEXT",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.HUMAN_APPROVAL_GATE_RULE_VERSION,
                         "r36-5")
        self.assertEqual(plan_human_approval()["rule_version"], "r36-5")

    def test_no_notification_or_execution_vocabulary(self):
        blob = json.dumps(
            [
                plan_human_approval(
                    policy("HUMAN_APPROVAL_REQUIRED"),
                    authorization("REQUIRE_HUMAN_APPROVAL"),
                    state,
                )
                for state in schema.DETERMINABLE_STATES
            ]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
            "email", "webhook", "notification", "database", "mongo",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
