"""tests/test_research_learning_memory.py — Stage R44.4 tests.

Deterministic, offline tests for research learning memory:

- repeated event aggregation into patterns
- occurrence counts, supporting events and confidence escalation
- pattern ids, memory states, ordering
- no automatic rule change or agent tuning
- schema validation and deterministic serialization

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.research_feedback_event import (
    build_research_feedback_event,
)
from ai.knowledge.research_learning_memory_export import (
    export_research_learning_memory,
)
from ai.schemas import research_learning_memory as schema


def event(agent="sa-" + "a" * 16, category="XSS", **over):
    kwargs = {
        "source_agent": agent,
        "source_category": category,
        "outcome_type": "EVIDENCE_OBSERVATION",
        "observed_issue": "ISSUE_MISSING_EVIDENCE_REQUIREMENT",
    }
    kwargs.update(over)
    return build_research_feedback_event(**kwargs)


def classification(
    classification_type="EVIDENCE_GAP",
    category="XSS",
    confidence="MEDIUM",
):
    return {
        "rule_version": "r44-2",
        "classification": classification_type,
        "subject": category,
        "source_agent": "sa-" + "a" * 16,
        "feedback_id": "fb-" + "a" * 16,
        "reasons": [],
        "supporting_signals": [],
        "confidence": confidence,
        "limitations": [],
    }


class TestResearchLearningMemory(unittest.TestCase):
    def test_aggregation_repeated_events(self):
        first = event(agent="sa-" + "1" * 16)
        second = event(agent="sa-" + "2" * 16)
        memory = export_research_learning_memory(
            [first, second],
            [classification(), classification()],
        )
        self.assertEqual(len(memory["patterns"]), 1)
        pattern = memory["patterns"][0]
        self.assertEqual(pattern["occurrence_count"], 2)
        self.assertEqual(
            pattern["supporting_events"],
            [first["feedback_id"], second["feedback_id"]],
        )
        self.assertEqual(pattern["pattern_type"], "EVIDENCE_GAP")
        self.assertEqual(pattern["source_category"], "XSS")
        self.assertTrue(
            schema.PATTERN_ID_RE.match(pattern["pattern_id"])
        )

    def test_pattern_id_deterministic(self):
        first = export_research_learning_memory(
            [event()], [classification()]
        )
        second = export_research_learning_memory(
            [event()], [classification()]
        )
        self.assertEqual(
            first["patterns"][0]["pattern_id"],
            second["patterns"][0]["pattern_id"],
        )

    def test_confidence_escalation(self):
        low = export_research_learning_memory(
            [event(agent="sa-" + "1" * 16)],
            [classification(confidence="LOW")],
        )
        self.assertEqual(
            low["patterns"][0]["confidence"], "LOW"
        )
        medium = export_research_learning_memory(
            [
                event(agent="sa-" + "1" * 16),
                event(agent="sa-" + "2" * 16),
            ],
            [classification(confidence="MEDIUM"),
             classification(confidence="MEDIUM")],
        )
        self.assertEqual(
            medium["patterns"][0]["confidence"], "MEDIUM"
        )
        high = export_research_learning_memory(
            [
                event(agent="sa-" + "1" * 16),
                event(agent="sa-" + "2" * 16),
                event(agent="sa-" + "3" * 16),
            ],
            [classification(confidence="HIGH"),
             classification(confidence="HIGH"),
             classification(confidence="HIGH")],
        )
        self.assertEqual(high["patterns"][0]["confidence"], "HIGH")

    def test_memory_state_complete(self):
        memory = export_research_learning_memory(
            [event()], [classification()]
        )
        self.assertEqual(memory["memory_state"], "COMPLETE")

    def test_memory_state_partial_for_unknown(self):
        memory = export_research_learning_memory(
            [event(outcome_type="UNKNOWN",
                   observed_issue="NONE_OBSERVED")],
        )
        self.assertEqual(memory["patterns"][0]["pattern_type"], "UNKNOWN")
        self.assertEqual(memory["memory_state"], "PARTIAL")

    def test_memory_state_unknown_without_events(self):
        memory = export_research_learning_memory([])
        self.assertEqual(memory["patterns"], [])
        self.assertEqual(memory["memory_state"], "UNKNOWN")

    def test_multiple_patterns_ordering(self):
        events = [
            event(agent="sa-" + "1" * 16, category="XSS"),
            event(agent="sa-" + "2" * 16, category="SSRF"),
        ]
        classifications = [
            classification("EVIDENCE_GAP", "XSS"),
            classification("PROVENANCE_ISSUE", "SSRF"),
        ]
        memory = export_research_learning_memory(events, classifications)
        self.assertEqual(
            [pattern["source_category"]
             for pattern in memory["patterns"]],
            ["XSS", "SSRF"],
        )

    def test_automatic_computation(self):
        memory = export_research_learning_memory(
            [event()],
        )
        self.assertEqual(
            memory["patterns"][0]["pattern_type"], "EVIDENCE_GAP"
        )

    def test_no_automatic_tuning_limitations(self):
        memory = export_research_learning_memory(
            [event()], [classification()]
        )
        for code in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_RULE_MODIFICATION",
            "NO_AUTOMATIC_AGENT_TUNING",
            "ADVISORY_ONLY",
        ):
            self.assertIn(code, memory["limitations"])
        for code in (
            "NO_EXECUTION_PERFORMED",
            "NO_AUTOMATIC_AGENT_TUNING",
            "ADVISORY_ONLY",
        ):
            self.assertIn(
                code, memory["patterns"][0]["limitations"]
            )
        self.assertIs(memory["research_only"], True)

    def test_deterministic_output(self):
        events = [
            event(agent="sa-" + "1" * 16),
            event(agent="sa-" + "2" * 16, category="SSRF"),
        ]
        classifications = [
            classification("EVIDENCE_GAP", "XSS"),
            classification("PROVENANCE_ISSUE", "SSRF"),
        ]
        first = export_research_learning_memory(events, classifications)
        second = export_research_learning_memory(events, classifications)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        memory = export_research_learning_memory([event()])
        self.assertIsInstance(json.loads(json.dumps(memory)), dict)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchLearningMemoryPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.ResearchLearningMemoryPlan(memory_state="DONE")
        with self.assertRaises(ValidationError):
            schema.ResearchLearningMemoryPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.LearningPatternPlan(pattern_type="NOT_A_PATTERN")
        with self.assertRaises(ValidationError):
            schema.LearningPatternPlan(source_category="NOPE")

    def test_schema_forces_rule_version(self):
        plan = schema.ResearchLearningMemoryPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r44-4")
        self.assertEqual(
            export_research_learning_memory([])["rule_version"], "r44-4"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
