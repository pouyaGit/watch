"""tests/test_copilot_opportunity.py — Stage R60.2 opportunity tests.

Deterministic, offline tests for the copilot opportunity and recommendation
contract:

- closed opportunity-class, review-reason and rationale vocabularies
- verbatim reuse of R55 priority reasons and R58/R59 action vocabularies
- forced advisory-only / no-auto-execute / research-only invariants
- bounded confidence, evidence, priority and correlation projections
- deterministic ids and model round trips

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.bug_bounty_copilot_rules import (
    opportunity_id,
    recommendation_id,
)
from ai.schemas.copilot_opportunity import (
    COPILOT_OPPORTUNITY_RULE_VERSION,
    COPILOT_RATIONALE_CODES,
    COPILOT_REVIEW_REASONS,
    COPILOT_SAFETY_RESTRICTIONS,
    OPPORTUNITY_BLOCKED,
    OPPORTUNITY_CLASSES,
    OPPORTUNITY_DEFERRED,
    OPPORTUNITY_HIGH_PRIORITY,
    OPPORTUNITY_INSUFFICIENT,
    OPPORTUNITY_PRIORITY,
    OPPORTUNITY_STANDARD,
    CopilotOpportunityPlan,
    CopilotRecommendationPlan,
    copilot_opportunity_plan_projection,
    sanitize_copilot_opportunity,
    sanitize_copilot_recommendation,
)
from ai.schemas.execution_request import EXECUTION_ACTIONS
from ai.schemas.research_priority import PRIORITY_REASONS
from ai.schemas.workflow_next_action import WORKFLOW_NEXT_ACTIONS

FINDING_ID = "fnd-" + "1" * 16


def valid_opportunity(**overrides):
    payload = {
        "rule_version": COPILOT_OPPORTUNITY_RULE_VERSION,
        "opportunity_id": opportunity_id(FINDING_ID, "HIGH", 1),
        "finding_id": FINDING_ID,
        "category": "XSS",
        "specialist_name": "xss",
        "agent_id": "sa-" + "a" * 16,
        "finding_state": "EVIDENCE_SUPPORTED",
        "confidence": "MEDIUM",
        "evidence_state": "COMPLETE",
        "evidence_completeness": "COMPLETE",
        "evidence_origin": "DIRECT",
        "severity": "HIGH",
        "severity_source": "CVSS_CONTEXT",
        "impact_state": "POTENTIAL",
        "priority_band": "HIGH",
        "priority_score": 71,
        "ranking_position": 1,
        "opportunity_class": OPPORTUNITY_HIGH_PRIORITY,
        "conflict_state": "NO_CONFLICT",
        "duplicate_present": False,
        "related_finding_count": 1,
        "related_finding_ids": ["fnd-" + "2" * 16],
        "relationship_types": ["RELATED"],
        "research_rationale_codes": [
            "COMPLETE_EVIDENCE",
            "STRONG_CONTEXT",
        ],
        "copilot_rationale_codes": [
            "ELEVATED_PRIORITY",
            "EVIDENCE_COMPLETE",
        ],
        "recommendation": {
            "recommendation_id": recommendation_id(
                FINDING_ID, "PRIORITIZE_RESEARCH", "PREPARE_RESEARCH_STEP"
            ),
            "workflow_next_action": "PRIORITIZE_RESEARCH",
            "research_action": "PREPARE_RESEARCH_STEP",
            "human_review_required": False,
            "review_reasons": [],
        },
        "safety_status": "RESEARCH_ONLY",
    }
    payload.update(overrides)
    return payload


class TestOpportunityVocabulary(unittest.TestCase):
    def test_opportunity_classes_are_closed(self):
        self.assertEqual(
            OPPORTUNITY_CLASSES,
            (
                OPPORTUNITY_HIGH_PRIORITY,
                OPPORTUNITY_PRIORITY,
                OPPORTUNITY_STANDARD,
                OPPORTUNITY_DEFERRED,
                OPPORTUNITY_BLOCKED,
                OPPORTUNITY_INSUFFICIENT,
            ),
        )

    def test_review_reasons_reuse_r56_codes(self):
        for reused in (
            "EVIDENCE_INCOMPLETE",
            "CONFLICT_REQUIRES_RESOLUTION",
            "DUPLICATE_RESEARCH_OVERLAP",
            "GOVERNANCE_REVIEW_REQUIRED",
            "PROVENANCE_INCOMPLETE",
            "SEVERITY_CONTEXT_REQUIRED",
            "ESCALATION_REQUIRED",
        ):
            self.assertIn(reused, COPILOT_REVIEW_REASONS)
        for copilot_specific in (
            "HUMAN_DECISION_PENDING",
            "HUMAN_NEEDS_REVIEW",
            "LEARNING_REVIEW_REQUIRED",
            "EXECUTION_CONTROL_BLOCKED",
            "INVALID_UPSTREAM_CONTEXT",
            "LOW_CONFIDENCE",
            "MISSING_EVIDENCE",
            "CONFLICTED_FINDING_STATE",
        ):
            self.assertIn(copilot_specific, COPILOT_REVIEW_REASONS)
        self.assertEqual(
            len(set(COPILOT_REVIEW_REASONS)), len(COPILOT_REVIEW_REASONS)
        )

    def test_rationale_vocabulary_is_closed(self):
        self.assertEqual(
            len(set(COPILOT_RATIONALE_CODES)),
            len(COPILOT_RATIONALE_CODES),
        )
        for code in (
            "HIGH_PRIORITY",
            "EVIDENCE_COMPLETE",
            "RELATED_FINDINGS_PRESENT",
            "HUMAN_REVIEW_REQUIRED",
            "SAFETY_BLOCKED",
        ):
            self.assertIn(code, COPILOT_RATIONALE_CODES)

    def test_safety_restrictions_are_closed_and_explicit(self):
        for restriction in (
            "NO_NETWORK_EXECUTION",
            "NO_SCANNER_EXECUTION",
            "NO_BROWSER_AUTOMATION",
            "NO_SUBPROCESS_EXECUTION",
            "NO_PAYLOAD_GENERATION",
            "NO_ATTACK_PLANNING",
            "NO_EXPLOIT_AUTHORIZATION",
            "NO_VULNERABILITY_CONFIRMATION",
            "HUMAN_AUTHORITY_REQUIRED",
            "R58_GATE_REQUIRED",
        ):
            self.assertIn(restriction, COPILOT_SAFETY_RESTRICTIONS)

    def test_rule_version_is_stable(self):
        self.assertEqual(COPILOT_OPPORTUNITY_RULE_VERSION, "r60-2")

    def test_priority_reasons_are_reused_verbatim(self):
        opportunity = sanitize_copilot_opportunity(
            valid_opportunity(
                research_rationale_codes=[
                    "COMPLETE_EVIDENCE",
                    "NOT_A_REAL_REASON",
                ]
            )
        )
        for code in opportunity["research_rationale_codes"]:
            self.assertIn(code, PRIORITY_REASONS)
        self.assertNotIn("NOT_A_REAL_REASON", opportunity["research_rationale_codes"])


class TestRecommendationModel(unittest.TestCase):
    def test_recommendation_is_advisory_only(self):
        recommendation = sanitize_copilot_recommendation(
            {
                "recommendation_id": recommendation_id(
                    FINDING_ID, "PRIORITIZE_RESEARCH", "REASSESS_CONTEXT"
                ),
                "workflow_next_action": "PRIORITIZE_RESEARCH",
                "research_action": "REASSESS_CONTEXT",
            }
        )
        model = CopilotRecommendationPlan(**recommendation)
        self.assertTrue(model.advisory)
        self.assertFalse(model.auto_execute)
        self.assertTrue(model.research_only)

    def test_unknown_actions_are_dropped(self):
        recommendation = sanitize_copilot_recommendation(
            {
                "workflow_next_action": "RUN_SCANNER",
                "research_action": "EXECUTE_EXPLOIT",
            }
        )
        self.assertEqual(recommendation["workflow_next_action"], "")
        self.assertEqual(recommendation["research_action"], "")

    def test_research_action_reuses_r58_vocabulary(self):
        for action in (
            "COLLECT_EXISTING_EVIDENCE",
            "REVIEW_EXISTING_RESPONSE",
            "RECHECK_SCOPE",
            "REASSESS_CONTEXT",
            "PREPARE_RESEARCH_STEP",
            "REQUEST_HUMAN_REVIEW",
        ):
            self.assertIn(action, EXECUTION_ACTIONS)

    def test_workflow_action_reuses_r59_vocabulary(self):
        recommendation = sanitize_copilot_recommendation(
            {"workflow_next_action": "COMPLETE_WORKFLOW"}
        )
        self.assertIn(
            recommendation["workflow_next_action"], WORKFLOW_NEXT_ACTIONS
        )

    def test_model_rejects_auto_execute(self):
        recommendation = sanitize_copilot_recommendation(
            {"workflow_next_action": "BLOCK_WORKFLOW"}
        )
        with self.assertRaises(ValidationError):
            CopilotRecommendationPlan(
                **{**recommendation, "auto_execute": True}
            )

    def test_default_recommendation_is_fail_closed(self):
        recommendation = sanitize_copilot_recommendation(None)
        self.assertTrue(recommendation["human_review_required"])
        self.assertIn(
            "INVALID_UPSTREAM_CONTEXT", recommendation["review_reasons"]
        )


class TestOpportunityModel(unittest.TestCase):
    def test_valid_opportunity_round_trips(self):
        opportunity = sanitize_copilot_opportunity(valid_opportunity())
        model = CopilotOpportunityPlan(**opportunity)
        projected = copilot_opportunity_plan_projection(model)
        self.assertEqual(
            projected["opportunity_id"], opportunity["opportunity_id"]
        )
        self.assertEqual(projected["recommendation"]["advisory"], True)

    def test_ids_are_deterministic(self):
        first = opportunity_id(FINDING_ID, "HIGH", 1)
        second = opportunity_id(FINDING_ID, "HIGH", 1)
        other = opportunity_id(FINDING_ID, "MEDIUM", 2)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        rec_first = recommendation_id(
            FINDING_ID, "PRIORITIZE_RESEARCH", "REASSESS_CONTEXT"
        )
        self.assertEqual(
            rec_first,
            recommendation_id(
                FINDING_ID, "PRIORITIZE_RESEARCH", "REASSESS_CONTEXT"
            ),
        )

    def test_model_rejects_bad_opportunity_id(self):
        with self.assertRaises(ValidationError):
            CopilotOpportunityPlan(
                **{
                    **sanitize_copilot_opportunity(valid_opportunity()),
                    "opportunity_id": "bogus",
                }
            )

    def test_model_rejects_unknown_class(self):
        with self.assertRaises(ValidationError):
            CopilotOpportunityPlan(
                **{
                    **sanitize_copilot_opportunity(valid_opportunity()),
                    "opportunity_class": "VULNERABLE",
                }
            )

    def test_model_rejects_blocked_with_research_action(self):
        opportunity = sanitize_copilot_opportunity(
            valid_opportunity(opportunity_class=OPPORTUNITY_BLOCKED)
        )
        with self.assertRaises(ValidationError):
            CopilotOpportunityPlan(
                **{
                    **opportunity,
                    "recommendation": {
                        **opportunity["recommendation"],
                        "research_action": "REASSESS_CONTEXT",
                    },
                }
            )

    def test_sanitizer_defaults_are_fail_closed(self):
        opportunity = sanitize_copilot_opportunity(None)
        self.assertEqual(
            opportunity["opportunity_class"], OPPORTUNITY_INSUFFICIENT
        )
        self.assertTrue(
            opportunity["recommendation"]["human_review_required"]
        )
        self.assertEqual(opportunity["priority_band"], "DEFERRED")
        self.assertEqual(opportunity["confidence"], "UNKNOWN")

    def test_confidence_is_bounded(self):
        opportunity = sanitize_copilot_opportunity(
            valid_opportunity(confidence="CERTAIN", priority_score=1000)
        )
        self.assertEqual(opportunity["confidence"], "UNKNOWN")
        self.assertEqual(opportunity["priority_score"], 100)

    def test_related_ids_are_validated(self):
        opportunity = sanitize_copilot_opportunity(
            valid_opportunity(
                related_finding_ids=[
                    "fnd-" + "2" * 16,
                    "not-a-finding",
                    "fnd-" + "2" * 16,
                ]
            )
        )
        self.assertEqual(
            opportunity["related_finding_ids"], ["fnd-" + "2" * 16]
        )

    def test_limitations_are_ordered_and_present(self):
        opportunity = sanitize_copilot_opportunity(valid_opportunity())
        self.assertTrue(opportunity["limitations"])
        self.assertIn("NO_EXECUTION_PERFORMED", opportunity["limitations"])
        self.assertIn("ADVISORY_ONLY", opportunity["limitations"])

    def test_opportunity_never_confirms_or_authorizes(self):
        opportunity = sanitize_copilot_opportunity(valid_opportunity())
        serialized = str(opportunity)
        self.assertNotIn("vulnerability_confirmed", serialized)
        self.assertNotIn("exploit_authorized", serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
