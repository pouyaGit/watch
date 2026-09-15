"""tests/test_copilot_brief.py — Stage R60.3 / R60.4 brief and result tests.

Deterministic, offline tests for the copilot brief and result contracts:

- closed confidence-basis, status and error vocabularies
- fixed non-execution boundary and always-present safety restrictions
- forced advisory / human-authority / no-execution invariants
- human-review requirement consistency
- deterministic ids, bounds and model round trips

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.bug_bounty_copilot_rules import (
    brief_id,
    copilot_summary,
)
from ai.schemas.copilot_brief import (
    BASIS_NO_OPPORTUNITIES,
    BRIEF_ID_RE,
    CONFIDENCE_BASES,
    COPILOT_BRIEF_LIMITATIONS,
    COPILOT_BRIEF_RULE_VERSION,
    NON_EXECUTION_BOUNDARY,
    CopilotBriefPlan,
    copilot_brief_plan_projection,
    sanitize_copilot_brief,
    sanitize_evidence_summary,
    sanitize_recommended_actions,
)
from ai.schemas.copilot_opportunity import COPILOT_SAFETY_RESTRICTIONS
from ai.schemas.copilot_result import (
    COPILOT_ERROR_CATEGORIES,
    COPILOT_RESULT_RULE_VERSION,
    COPILOT_RESULT_STATUSES,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_CONTEXT,
    STATUS_PARTIAL,
    CopilotResultPlan,
    copilot_result_plan_projection,
    sanitize_copilot_error,
    sanitize_copilot_result,
    sanitize_copilot_summary,
)

WORKFLOW_ID = "wfr-" + "1" * 16


def valid_brief(**overrides):
    payload = {
        "rule_version": COPILOT_BRIEF_RULE_VERSION,
        "brief_id": brief_id(
            "bbc-" + "1" * 16, WORKFLOW_ID, [], []
        ),
        "target_reference": "api.example.test",
        "workflow_id": WORKFLOW_ID,
        "workflow_state": "PRIORITIZED",
        "workflow_safety_status": "RESEARCH_ONLY",
        "workflow_next_action": "REQUEST_HUMAN_REVIEW",
        "workflow_next_action_reason": "HUMAN_DECISION_MISSING",
        "confidence": "MEDIUM",
        "confidence_basis": ["OPPORTUNITIES_PRESENT"],
        "human_review_required": True,
        "human_review_reasons": ["HUMAN_DECISION_PENDING"],
        "safety_status": "HUMAN_REVIEW_REQUIRED",
    }
    payload.update(overrides)
    return payload


class TestBriefVocabulary(unittest.TestCase):
    def test_rule_version_is_stable(self):
        self.assertEqual(COPILOT_BRIEF_RULE_VERSION, "r60-3")

    def test_confidence_bases_are_closed(self):
        self.assertEqual(
            len(set(CONFIDENCE_BASES)), len(CONFIDENCE_BASES)
        )
        self.assertIn(BASIS_NO_OPPORTUNITIES, CONFIDENCE_BASES)

    def test_limitations_are_closed(self):
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "ADVISORY_ONLY",
            "RESEARCH_ONLY",
            "AUTHORIZATION_IS_NOT_EXECUTION",
            "WORKFLOW_STATE_IS_NOT_VULNERABILITY_STATE",
            "HUMAN_AUTHORITY_REQUIRED",
            "R58_GATE_REQUIRED",
            "NO_LLM_INVOLVEMENT",
        ):
            self.assertIn(limitation, COPILOT_BRIEF_LIMITATIONS)

    def test_non_execution_boundary_is_fixed(self):
        self.assertFalse(NON_EXECUTION_BOUNDARY["execution_performed"])
        self.assertFalse(NON_EXECUTION_BOUNDARY["external_executor_present"])
        self.assertFalse(NON_EXECUTION_BOUNDARY["vulnerability_confirmed"])
        self.assertFalse(NON_EXECUTION_BOUNDARY["exploit_authorized"])
        self.assertEqual(
            NON_EXECUTION_BOUNDARY["confirmation_state"], "NOT_CONFIRMED"
        )
        self.assertTrue(NON_EXECUTION_BOUNDARY["r58_gate_required"])
        self.assertTrue(NON_EXECUTION_BOUNDARY["human_authority_required"])

    def test_result_vocabularies_are_closed(self):
        self.assertEqual(COPILOT_RESULT_RULE_VERSION, "r60-4")
        self.assertEqual(
            COPILOT_RESULT_STATUSES,
            (STATUS_COMPLETED, STATUS_PARTIAL, STATUS_NO_CONTEXT, STATUS_FAILED),
        )
        for category in (
            "INVALID_INPUT",
            "MALFORMED_INPUT",
            "RULE_VERSION_MISMATCH",
            "SAFETY_BLOCKED",
            "CONFLICTING_CONTEXT",
            "WORKFLOW_CONTEXT_UNAVAILABLE",
            "UPSTREAM_WORKFLOW_BLOCKED",
        ):
            self.assertIn(category, COPILOT_ERROR_CATEGORIES)


class TestBriefModel(unittest.TestCase):
    def test_valid_brief_round_trips(self):
        brief = sanitize_copilot_brief(valid_brief())
        model = CopilotBriefPlan(**brief)
        projected = copilot_brief_plan_projection(model)
        self.assertEqual(projected["brief_id"], brief["brief_id"])
        self.assertTrue(projected["advisory"])
        self.assertTrue(projected["human_authority_preserved"])
        self.assertFalse(
            projected["non_execution_boundary"]["execution_performed"]
        )

    def test_safety_restrictions_are_always_present(self):
        brief = CopilotBriefPlan(**sanitize_copilot_brief(valid_brief()))
        for restriction in COPILOT_SAFETY_RESTRICTIONS:
            self.assertIn(restriction, brief.safety_restrictions)

    def test_model_rejects_bad_brief_id(self):
        with self.assertRaises(ValidationError):
            CopilotBriefPlan(**{**sanitize_copilot_brief(valid_brief()), "brief_id": "bogus"})

    def test_model_rejects_unknown_safety_status(self):
        with self.assertRaises(ValidationError):
            CopilotBriefPlan(
                **{
                    **sanitize_copilot_brief(valid_brief()),
                    "safety_status": "SAFE_TO_EXECUTE",
                }
            )

    def test_model_rejects_unknown_workflow_state(self):
        with self.assertRaises(ValidationError):
            CopilotBriefPlan(
                **{
                    **sanitize_copilot_brief(valid_brief()),
                    "workflow_state": "EXECUTED",
                }
            )

    def test_review_requirements_need_reasons(self):
        with self.assertRaises(ValidationError):
            CopilotBriefPlan(
                **{
                    **sanitize_copilot_brief(valid_brief()),
                    "human_review_required": True,
                    "human_review_reasons": [],
                }
            )

    def test_opportunity_count_must_match(self):
        with self.assertRaises(ValidationError):
            CopilotBriefPlan(
                **{
                    **sanitize_copilot_brief(valid_brief()),
                    "opportunity_count": 3,
                    "opportunities": [],
                }
            )

    def test_sanitizer_defaults_are_fail_closed(self):
        brief = sanitize_copilot_brief(None)
        self.assertEqual(brief["confidence"], "UNKNOWN")
        self.assertTrue(brief["human_review_required"])
        self.assertEqual(brief["safety_status"], "RESEARCH_ONLY")
        self.assertTrue(brief["safety_restrictions"])

    def test_brief_id_is_deterministic(self):
        first = brief_id("bbc-" + "1" * 16, WORKFLOW_ID, [], [])
        second = brief_id("bbc-" + "1" * 16, WORKFLOW_ID, [], [])
        other = brief_id("bbc-" + "1" * 16, WORKFLOW_ID, ["bco-1"], [])
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(BRIEF_ID_RE.match(first))

    def test_evidence_summary_is_bounded(self):
        summary = sanitize_evidence_summary(
            {
                "finding_count": 3,
                "evidence_complete_count": 1,
                "evidence_partial_count": 1,
                "evidence_incomplete_count": 1,
                "conflict_count": 2,
                "duplicate_count": 0,
                "related_finding_count": 4,
                "invented_severity": "CRITICAL",
            }
        )
        self.assertEqual(summary["finding_count"], 3)
        self.assertNotIn("invented_severity", summary)

    def test_recommended_actions_are_bounded_and_valid(self):
        actions = sanitize_recommended_actions(
            [
                {
                    "finding_id": "fnd-" + "1" * 16,
                    "workflow_next_action": "PRIORITIZE_RESEARCH",
                    "research_action": "REASSESS_CONTEXT",
                    "priority_band": "HIGH",
                    "human_review_required": True,
                },
                {
                    "finding_id": "fnd-" + "2" * 16,
                    "workflow_next_action": "EXECUTE_NOW",
                    "research_action": "RUN_SCANNER",
                },
            ]
        )
        self.assertEqual(len(actions), 1)
        self.assertEqual(
            actions[0]["research_action"], "REASSESS_CONTEXT"
        )


class TestResultModel(unittest.TestCase):
    def test_valid_result_round_trips(self):
        result = sanitize_copilot_result(
            {
                "rule_version": COPILOT_RESULT_RULE_VERSION,
                "result_id": "bbr-" + "1" * 16,
                "status": STATUS_COMPLETED,
                "brief": valid_brief(),
            }
        )
        model = CopilotResultPlan(**result)
        projected = copilot_result_plan_projection(model)
        self.assertEqual(projected["status"], STATUS_COMPLETED)
        self.assertFalse(projected["execution_performed"])
        self.assertFalse(projected["vulnerability_confirmed"])
        self.assertEqual(projected["confirmation_state"], "NOT_CONFIRMED")

    def test_model_forces_advisory_flags(self):
        result = sanitize_copilot_result(
            {
                "rule_version": COPILOT_RESULT_RULE_VERSION,
                "result_id": "bbr-" + "1" * 16,
                "status": STATUS_COMPLETED,
                "brief": valid_brief(),
            }
        )
        for field in (
            "execution_performed",
            "external_executor_present",
            "vulnerability_confirmed",
            "exploit_authorized",
        ):
            with self.assertRaises(ValidationError):
                CopilotResultPlan(**{**result, field: True})
        with self.assertRaises(ValidationError):
            CopilotResultPlan(**{**result, "advisory": False})

    def test_failed_status_requires_errors(self):
        result = sanitize_copilot_result(
            {
                "rule_version": COPILOT_RESULT_RULE_VERSION,
                "result_id": "bbr-" + "1" * 16,
                "status": STATUS_FAILED,
                "brief": valid_brief(),
            }
        )
        with self.assertRaises(ValidationError):
            CopilotResultPlan(**{**result, "status": STATUS_FAILED})

    def test_errors_are_closed(self):
        self.assertEqual(sanitize_copilot_error(None), {})
        self.assertEqual(
            sanitize_copilot_error({"error_category": "NOT_A_CATEGORY"}), {}
        )
        projected = sanitize_copilot_error(
            {
                "error_category": "SAFETY_BLOCKED",
                "message": "blocked",
            }
        )
        self.assertEqual(projected["error_category"], "SAFETY_BLOCKED")

    def test_sanitizer_defaults_are_fail_closed(self):
        result = sanitize_copilot_result(None)
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["brief"]["human_review_required"])

    def test_summary_is_bounded(self):
        summary = sanitize_copilot_summary(
            {
                "opportunity_count": 4,
                "high_priority_count": 1,
                "recommended_action_count": 2,
                "human_review_required": True,
                "confidence": "MEDIUM",
                "workflow_state": "PRIORITIZED",
                "safety_status": "HUMAN_REVIEW_REQUIRED",
                "error_count": 1,
                "invented": True,
            }
        )
        self.assertEqual(summary["opportunity_count"], 4)
        self.assertNotIn("invented", summary)

    def test_copilot_summary_helper(self):
        summary = copilot_summary(
            {
                "opportunities": [{"opportunity_class": "HIGH_PRIORITY_RESEARCH"}],
                "recommended_actions": [],
                "human_review_required": False,
                "confidence": "HIGH",
                "workflow_state": "PRIORITIZED",
                "safety_status": "RESEARCH_ONLY",
            },
            [],
        )
        self.assertEqual(summary["high_priority_count"], 1)
        self.assertEqual(summary["confidence"], "HIGH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
