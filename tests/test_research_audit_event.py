"""tests/test_research_audit_event.py — Stage R37.3 tests.

Deterministic, offline tests for the research audit event builder:

- event types and sources per governance state
- audit states (VALID / INVALID / UNKNOWN)
- malformed and empty input handling
- no runtime timestamps
- no mutation, JSON serialization, closed vocabulary validation
- research_only always true, no execution content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.research_audit_event_builder import (
    build_research_audit_event,
)
from ai.schemas import research_audit_event as schema


def provenance(state="COMPLETE", signals=("STRATEGY", "ORCHESTRATION",
                                           "AUTHORIZATION")):
    return {
        "rule_version": "r37-1",
        "decision_id": "dp-" + "a" * 16,
        "source_strategy": {"strategy_type": "VERSION_FIRST"},
        "source_orchestration": {"primary_role": "VERSION_ANALYSIS"},
        "source_authorization": {"decision": "ALLOW_WITH_LIMITS"},
        "contributing_signals": list(signals),
        "provenance_state": state,
        "research_only": True,
    }


def authorization(decision="ALLOW_WITH_LIMITS"):
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


class TestResearchAuditEvent(unittest.TestCase):
    def test_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.AUDIT_EVENT_TYPES),
            {
                "STRATEGY_CREATED", "WORKFLOW_CREATED",
                "AUTHORIZATION_DECIDED", "APPROVAL_REQUIRED",
                "BLOCK_APPLIED", "UNKNOWN",
            },
        )
        self.assertEqual(
            set(schema.AUDIT_STATES), {"VALID", "INVALID", "UNKNOWN"}
        )

    def test_every_event_type(self):
        expectations = (
            ("ALLOW", "AUTHORIZATION_DECIDED", "AUTHORIZATION",
             "AUTHORIZATION_RECORDED"),
            ("ALLOW_WITH_LIMITS", "AUTHORIZATION_DECIDED",
             "AUTHORIZATION", "AUTHORIZATION_RECORDED"),
            ("REQUIRE_HUMAN_APPROVAL", "APPROVAL_REQUIRED",
             "AUTHORIZATION", "APPROVAL_GATE_RECORDED"),
            ("BLOCK", "BLOCK_APPLIED", "AUTHORIZATION",
             "BLOCK_RECORDED"),
        )
        for decision, event, source, summary in expectations:
            plan = build_research_audit_event(
                provenance(), authorization(decision), {}
            )
            self.assertEqual(plan["event_type"], event, decision)
            self.assertEqual(plan["event_source"], source, decision)
            self.assertEqual(plan["event_summary"], summary, decision)

    def test_workflow_created_without_decision(self):
        plan = build_research_audit_event(
            provenance(signals=("STRATEGY", "ORCHESTRATION")),
            authorization("UNKNOWN"),
            {},
        )
        self.assertEqual(plan["event_type"], "WORKFLOW_CREATED")
        self.assertEqual(plan["event_source"], "ORCHESTRATION")

    def test_strategy_created_without_workflow(self):
        plan = build_research_audit_event(
            provenance(state="PARTIAL", signals=("STRATEGY",)),
            authorization("UNKNOWN"),
            {},
        )
        self.assertEqual(plan["event_type"], "STRATEGY_CREATED")
        self.assertEqual(plan["event_source"], "STRATEGY")

    def test_valid_audit_state(self):
        plan = build_research_audit_event(
            provenance(), authorization("ALLOW"), {}
        )
        self.assertEqual(plan["audit_state"], "VALID")

    def test_partial_provenance_is_valid(self):
        plan = build_research_audit_event(
            provenance(state="PARTIAL", signals=("STRATEGY",)),
            authorization("ALLOW"),
            {},
        )
        self.assertEqual(plan["audit_state"], "VALID")

    def test_invalid_audit_state(self):
        plan = build_research_audit_event(
            provenance(state="UNKNOWN", signals=()), {}, {}
        )
        self.assertEqual(plan["audit_state"], "INVALID")

    def test_unknown_audit_state(self):
        plan = build_research_audit_event()
        self.assertEqual(plan["event_type"], "UNKNOWN")
        self.assertEqual(plan["event_source"], "UNKNOWN")
        self.assertEqual(plan["event_summary"], "UNKNOWN")
        self.assertEqual(plan["audit_state"], "UNKNOWN")

    def test_related_fields(self):
        plan = build_research_audit_event(
            provenance(), authorization("BLOCK"), {}
        )
        self.assertEqual(plan["related_strategy"], "VERSION_FIRST")
        self.assertEqual(plan["related_authorization"], "BLOCK")

    def test_malformed_inputs(self):
        for value in (None, {}, [], "x"):
            plan = build_research_audit_event(value, value, value)
            self.assertEqual(plan["event_type"], "UNKNOWN", repr(value))
            self.assertEqual(plan["audit_state"], "UNKNOWN", repr(value))

    def test_no_runtime_timestamps(self):
        plan = build_research_audit_event(
            provenance(), authorization("ALLOW"), {}
        )
        blob = json.dumps(plan).lower()
        for marker in ("timestamp", "time", "date", "epoch", "utc"):
            self.assertNotIn(marker, blob)

    def test_deterministic_output(self):
        first = build_research_audit_event(
            provenance(), authorization("BLOCK"), {}
        )
        second = build_research_audit_event(
            provenance(), authorization("BLOCK"), {}
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        inputs = (provenance(), authorization("BLOCK"), {})
        snapshots = tuple(copy.deepcopy(value) for value in inputs)
        build_research_audit_event(*inputs)
        for before, after in zip(snapshots, inputs):
            self.assertEqual(before, after)

    def test_json_serializable(self):
        plan = build_research_audit_event()
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        self.assertIs(
            build_research_audit_event()["research_only"], True
        )

    def test_schema_rejects_bad_values(self):
        base = {
            "event_type": "BLOCK_APPLIED",
            "event_source": "AUTHORIZATION",
            "event_summary": "BLOCK_RECORDED",
            "related_authorization": "BLOCK",
            "audit_state": "VALID",
        }
        for key, value in (
            ("event_type", "EXECUTION_STARTED"),
            ("event_source", "RUNTIME"),
            ("event_summary", "DEPLOYED"),
            ("related_authorization", "RUN"),
            ("audit_state", "MAYBE"),
        ):
            with self.assertRaises(ValidationError):
                schema.ResearchAuditEventPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.ResearchAuditEventPlan(**base, severity="HIGH")

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchAuditEventPlan(
            rule_version="r99-9",
            event_type="UNKNOWN",
            event_source="UNKNOWN",
            event_summary="UNKNOWN",
            related_authorization="UNKNOWN",
            audit_state="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r37-3")
        with self.assertRaises(ValidationError):
            schema.ResearchAuditEventPlan(
                event_type="UNKNOWN",
                event_source="UNKNOWN",
                event_summary="UNKNOWN",
                related_authorization="UNKNOWN",
                audit_state="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(schema.RESEARCH_AUDIT_EVENT_RULE_VERSION,
                         "r37-3")
        self.assertEqual(
            build_research_audit_event()["rule_version"], "r37-3"
        )

    def test_no_execution_content(self):
        blob = json.dumps(
            build_research_audit_event(
                provenance(), authorization("BLOCK"), {}
            )
        ).lower()
        for marker in (
            "http://", "https://", "payload", "exploit", "fuzz",
            "nuclei", "sqlmap", "shell", "subprocess", "browser",
            "dispatch", "worker", "scheduler", "docker", "systemd",
        ):
            self.assertNotIn(marker, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
