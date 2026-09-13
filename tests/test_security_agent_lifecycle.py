"""tests/test_security_agent_lifecycle.py — Stage R38.4 tests.

Deterministic, offline tests for the conceptual security agent lifecycle:

- exact closed state vocabulary
- legal transition rules and terminal states
- invalid transition detection
- malformed and empty input handling
- JSON serialization, schema validation, no timestamps
- research_only always true, no runtime/execution content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_lifecycle as planner
from ai.schemas import security_agent_lifecycle as schema


class TestSecurityAgentLifecycle(unittest.TestCase):
    def test_state_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.LIFECYCLE_STATES),
            {"CREATED", "PLANNED", "ANALYZING", "WAITING_EVIDENCE",
             "COMPLETED", "FAILED", "UNKNOWN"},
        )

    def test_validation_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.LIFECYCLE_VALIDATIONS),
            {"VALID", "INVALID", "UNKNOWN"},
        )

    def test_terminal_states_allow_no_transitions(self):
        for state in ("COMPLETED", "FAILED", "UNKNOWN"):
            plan = planner.plan_security_agent_lifecycle(state)
            self.assertEqual(plan["allowed_transitions"], [], state)

    def test_created_transitions_only_to_planned(self):
        plan = planner.plan_security_agent_lifecycle("CREATED")
        self.assertEqual(plan["allowed_transitions"], ["PLANNED"])
        self.assertEqual(plan["previous_state"], "NONE")
        self.assertEqual(plan["lifecycle_state"], "VALID")

    def test_transition_table_matches_planner(self):
        for state, expected in planner.TRANSITIONS.items():
            if state == "UNKNOWN":
                continue
            plan = planner.plan_security_agent_lifecycle(state)
            self.assertEqual(
                plan["allowed_transitions"], list(expected), state
            )

    def test_valid_transitions(self):
        for current, previous in (
            ("PLANNED", "CREATED"),
            ("ANALYZING", "PLANNED"),
            ("WAITING_EVIDENCE", "ANALYZING"),
            ("ANALYZING", "WAITING_EVIDENCE"),
            ("COMPLETED", "ANALYZING"),
            ("FAILED", "WAITING_EVIDENCE"),
        ):
            plan = planner.plan_security_agent_lifecycle(current, previous)
            self.assertEqual(
                plan["lifecycle_state"], "VALID", f"{previous}->{current}"
            )
            self.assertEqual(plan["previous_state"], previous)

    def test_invalid_transitions(self):
        for current, previous in (
            ("CREATED", "PLANNED"),
            ("CREATED", "COMPLETED"),
            ("PLANNED", "ANALYZING"),
            ("PLANNED", "COMPLETED"),
            ("ANALYZING", "CREATED"),
            ("ANALYZING", "ANALYZING"),
            ("WAITING_EVIDENCE", "PLANNED"),
            ("COMPLETED", "PLANNED"),
        ):
            plan = planner.plan_security_agent_lifecycle(current, previous)
            self.assertEqual(
                plan["lifecycle_state"], "INVALID",
                f"{previous}->{current}",
            )

    def test_previous_none_is_valid(self):
        plan = planner.plan_security_agent_lifecycle("PLANNED", "NONE")
        self.assertEqual(plan["lifecycle_state"], "VALID")
        self.assertEqual(plan["previous_state"], "NONE")

    def test_unknown_current_state(self):
        for value in (None, "", "RUNNING"):
            plan = planner.plan_security_agent_lifecycle(value)
            self.assertEqual(plan["current_state"], "UNKNOWN", repr(value))
            self.assertEqual(plan["allowed_transitions"], [])
            self.assertEqual(plan["lifecycle_state"], "UNKNOWN")
            self.assertEqual(plan["previous_state"], "NONE")

    def test_unknown_previous_state(self):
        plan = planner.plan_security_agent_lifecycle("ANALYZING", "NOPE")
        self.assertEqual(plan["current_state"], "ANALYZING")
        self.assertEqual(plan["previous_state"], "NONE")
        self.assertEqual(plan["lifecycle_state"], "UNKNOWN")

    def test_lowercase_normalized(self):
        plan = planner.plan_security_agent_lifecycle("analyzing", "planned")
        self.assertEqual(plan["current_state"], "ANALYZING")
        self.assertEqual(plan["previous_state"], "PLANNED")
        self.assertEqual(plan["lifecycle_state"], "VALID")

    def test_no_timestamps_and_fixed_keys(self):
        plan = planner.plan_security_agent_lifecycle("CREATED")
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "current_state", "previous_state",
             "allowed_transitions", "lifecycle_state", "research_only"},
        )
        self.assertNotIn("timestamp", json.dumps(plan).lower())

    def test_deterministic_output(self):
        first = planner.plan_security_agent_lifecycle("ANALYZING", "PLANNED")
        second = planner.plan_security_agent_lifecycle("ANALYZING", "PLANNED")
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = planner.plan_security_agent_lifecycle("COMPLETED")
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        plan = planner.plan_security_agent_lifecycle()
        self.assertIs(plan["research_only"], True)

    def test_no_execution_content(self):
        blob = json.dumps(
            [
                planner.plan_security_agent_lifecycle(state)
                for state in schema.LIFECYCLE_STATES
            ]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "subprocess", "shell", "browser",
            "worker", "scheduler", "docker", "systemd", "timestamp",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        base = {
            "current_state": "CREATED",
            "previous_state": "NONE",
            "allowed_transitions": ["PLANNED"],
            "lifecycle_state": "VALID",
        }
        for key, value in (
            ("current_state", "RUNNING"),
            ("previous_state", "RUNNING"),
            ("allowed_transitions", ["RUNNING"]),
            ("lifecycle_state", "MAYBE"),
        ):
            with self.assertRaises(ValidationError):
                schema.SecurityAgentLifecyclePlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SecurityAgentLifecyclePlan(**base, started_at="now")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentLifecyclePlan(
            rule_version="r99-9",
            current_state="UNKNOWN",
            previous_state="NONE",
            allowed_transitions=[],
            lifecycle_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r38-4")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentLifecyclePlan(
                current_state="UNKNOWN",
                previous_state="NONE",
                allowed_transitions=[],
                lifecycle_state="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            planner.SECURITY_AGENT_LIFECYCLE_PLANNER_RULE_VERSION, "r38-4"
        )
        self.assertEqual(
            planner.plan_security_agent_lifecycle("CREATED")["rule_version"],
            "r38-4",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
