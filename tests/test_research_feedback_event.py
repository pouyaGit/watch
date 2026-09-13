"""tests/test_research_feedback_event.py — Stage R44.1 tests.

Deterministic, offline tests for the research feedback event contract:

- valid event projection from R42 evaluation and R43 collaboration outputs
- malformed input handling and structural flags
- deterministic feedback id handling, attribution preservation
- extra-field rejection, JSON serialization, determinism

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.research_feedback_event import (
    build_research_feedback_event,
)
from ai.knowledge.sqli_agent_result_export import (
    export_sqli_agent_result,
)
from ai.schemas import research_feedback_event as schema


def rich_sqli():
    return export_sqli_agent_result(
        input_location="QUERY",
        parameter_type="IDENTIFIER",
        data_flow="RAW_QUERY",
        query_context="ORDER_BY",
        database_context="MYSQL",
        input_handling="CONCATENATED",
        type_handling="NONE_OBSERVED",
        error_behavior="DATABASE_ERROR_OBSERVED",
        behavioral_signal="TIMING_RELEVANT",
    )


class TestResearchFeedbackEvent(unittest.TestCase):
    def test_valid_event_projection(self):
        result = rich_sqli()
        evaluation = evaluate_agent_result(result)
        collaboration = export_multi_agent_collaboration([result])
        event = build_research_feedback_event(
            evaluation_result=evaluation,
            collaboration_result=collaboration,
            outcome_type="QUALITY_OBSERVATION",
            observed_issue="NONE_OBSERVED",
            observed_success="NONE_OBSERVED",
            confidence="MEDIUM",
        )
        self.assertEqual(event["rule_version"], "r44-1")
        self.assertTrue(schema.FEEDBACK_ID_RE.match(event["feedback_id"]))
        self.assertEqual(event["source_category"], "SQLI")
        self.assertNotEqual(event["source_agent"], "")
        self.assertIs(
            event["evaluation_reference"]["present"], True
        )
        self.assertIs(
            event["collaboration_reference"]["present"], True
        )
        self.assertEqual(event["outcome_type"], "QUALITY_OBSERVATION")
        self.assertIs(event["research_only"], True)
        self.assertEqual(event["structural_flags"], [])

    def test_evaluation_reference_fields(self):
        evaluation = evaluate_agent_result(rich_sqli())
        event = build_research_feedback_event(
            evaluation_result=evaluation,
            outcome_type="QUALITY_OBSERVATION",
        )
        reference = event["evaluation_reference"]
        self.assertEqual(
            reference["overall_score"], evaluation["overall_score"]
        )
        self.assertEqual(
            reference["overall_rating"], evaluation["overall_rating"]
        )
        self.assertEqual(
            reference["safety_state"], evaluation["safety_state"]
        )
        self.assertIs(reference["dimension_scores_present"], True)
        self.assertNotEqual(reference["confidence_score"], 0)
        self.assertNotEqual(reference["evidence_score"], 0)

    def test_collaboration_reference_fields(self):
        result = rich_sqli()
        collaboration = export_multi_agent_collaboration([result])
        event = build_research_feedback_event(
            collaboration_result=collaboration,
            outcome_type="CONFLICT_OBSERVATION",
        )
        reference = event["collaboration_reference"]
        self.assertEqual(reference["participant_count"], 1)
        self.assertEqual(reference["conflict_count"], 0)
        self.assertEqual(reference["duplicate_group_count"], 0)
        self.assertEqual(
            reference["merged_evidence_state"],
            collaboration["merged_evidence"]["evidence_state"],
        )

    def test_malformed_inputs_do_not_crash(self):
        event = build_research_feedback_event(
            evaluation_result="nope",
            collaboration_result=42,
            provenance="bad",
            governance_reference=[],
        )
        flags = event["structural_flags"]
        self.assertIn("MALFORMED_EVALUATION_REFERENCE", flags)
        self.assertIn("MALFORMED_COLLABORATION_REFERENCE", flags)
        self.assertIn("MALFORMED_PROVENANCE", flags)
        self.assertIn("MALFORMED_GOVERNANCE", flags)
        self.assertIs(event["research_only"], True)

    def test_missing_outcome_type_flagged(self):
        event = build_research_feedback_event()
        self.assertIn(
            "MISSING_REQUIRED_FIELD", event["structural_flags"]
        )
        self.assertEqual(event["outcome_type"], "UNKNOWN")

    def test_unknown_category_flagged(self):
        event = build_research_feedback_event(
            outcome_type="QUALITY_OBSERVATION"
        )
        self.assertIn(
            "UNKNOWN_SOURCE_CATEGORY", event["structural_flags"]
        )
        event = build_research_feedback_event(
            source_category="NOPE", outcome_type="QUALITY_OBSERVATION"
        )
        self.assertIn("INVALID_ENUM_VALUE", event["structural_flags"])

    def test_invalid_enum_flagged(self):
        event = build_research_feedback_event(
            source_category="XSS",
            outcome_type="NOT_AN_OUTCOME",
            observed_issue="NOT_AN_ISSUE",
            observed_success="NOT_A_SUCCESS",
        )
        self.assertIn("INVALID_ENUM_VALUE", event["structural_flags"])
        self.assertEqual(event["outcome_type"], "UNKNOWN")
        self.assertEqual(event["observed_issue"], "UNKNOWN")
        self.assertEqual(event["observed_success"], "UNKNOWN")

    def test_nondeterministic_marker_flagged(self):
        evaluation = evaluate_agent_result(rich_sqli())
        evaluation["created_at"] = "now"
        event = build_research_feedback_event(
            evaluation_result=evaluation,
            outcome_type="QUALITY_OBSERVATION",
        )
        self.assertIn(
            "NON_DETERMINISTIC_INPUT", event["structural_flags"]
        )

    def test_feedback_id_deterministic(self):
        kwargs = {
            "source_category": "SQLI",
            "outcome_type": "QUALITY_OBSERVATION",
            "observed_issue": "ISSUE_NO_HYPOTHESES",
            "source_agent": "sa-" + "a" * 16,
        }
        first = build_research_feedback_event(**kwargs)
        second = build_research_feedback_event(**kwargs)
        self.assertEqual(
            first["feedback_id"], second["feedback_id"]
        )

    def test_caller_feedback_id_accepted(self):
        provided = "fb-" + "a" * 16
        event = build_research_feedback_event(
            source_category="XSS",
            outcome_type="QUALITY_OBSERVATION",
            feedback_id=provided,
        )
        self.assertEqual(event["feedback_id"], provided)

    def test_invalid_feedback_id_recomputed(self):
        event = build_research_feedback_event(
            source_category="XSS",
            outcome_type="QUALITY_OBSERVATION",
            feedback_id="not-a-feedback-id",
        )
        self.assertTrue(
            schema.FEEDBACK_ID_RE.match(event["feedback_id"])
        )

    def test_deterministic_output(self):
        kwargs = {
            "source_category": "SSRF",
            "outcome_type": "EVIDENCE_OBSERVATION",
            "observed_issue": "ISSUE_MISSING_EVIDENCE_REQUIREMENT",
            "confidence": "MEDIUM",
        }
        first = build_research_feedback_event(**kwargs)
        second = build_research_feedback_event(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertNotIn("timestamp", json.dumps(first).lower())

    def test_json_serializable(self):
        event = build_research_feedback_event(
            source_category="XSS",
            outcome_type="QUALITY_OBSERVATION",
        )
        self.assertIsInstance(json.loads(json.dumps(event)), dict)

    def test_schema_rejects_extra_and_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackEventPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackEventPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackEventPlan(source_category="NOPE")
        with self.assertRaises(ValidationError):
            schema.ResearchFeedbackEventPlan(
                outcome_type="NOT_AN_OUTCOME"
            )

    def test_schema_forces_rule_version(self):
        plan = schema.ResearchFeedbackEventPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r44-1")

    def test_exact_rule_version(self):
        event = build_research_feedback_event(
            source_category="XSS",
            outcome_type="QUALITY_OBSERVATION",
        )
        self.assertEqual(event["rule_version"], "r44-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
