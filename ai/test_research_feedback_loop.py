"""Focused tests for the R73 research feedback / iteration loop.

All tests are offline and pure: R73 consumes real R70 action plans, real R71
acquisition plans and real R72 readiness records built from
validated-hypothesis-shaped mappings. New evidence bundles are synthetic and
bounded. No provider, Mongo, network or file system access happens here.
"""

from __future__ import annotations

import json
import unittest

from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_feedback_loop import (
    EFFECT_CONTRADICTS,
    EFFECT_INVALIDATES,
    EFFECT_PROVIDES,
    EVIDENCE_EFFECTS,
    EVIDENCE_REF_KINDS,
    EVIDENCE_SOURCES,
    FEEDBACK_GAP_REDUCED,
    FEEDBACK_GAP_REMAINS,
    FEEDBACK_INVALIDATED,
    FEEDBACK_NEW_CONTRADICTING,
    FEEDBACK_NEW_SUPPORTING,
    FEEDBACK_NO_CHANGE,
    FEEDBACK_REQUIRES_REVIEW,
    FEEDBACK_STATES,
    HYPOTHESIS_STATES,
    NEXT_CONTINUE,
    NEXT_HUMAN_REVIEW,
    NEXT_ITERATIONS,
    NEXT_STOP,
    REASON_CODES,
    REASON_MISSING_EVIDENCE_ACQUIRED,
    REASON_NO_RELEVANT_EVIDENCE,
    REJECTION_AMBIGUOUS_EVIDENCE,
    REJECTION_CODES,
    REJECTION_SENSITIVE_EVIDENCE,
    REJECTION_UNKNOWN_HYPOTHESIS,
    REJECTION_UNKNOWN_INVALIDATED_REF,
    REJECTION_UNKNOWN_REQUIREMENT,
    RULE_VERSION,
    SOURCE_ACQUISITION_RULE_VERSION,
    SOURCE_ACTION_RULE_VERSION,
    SOURCE_READINESS_RULE_VERSION,
    STATE_REFINE,
    STATE_RETAIN,
    STATE_STOP,
    STATE_UNRESOLVED,
    STATE_WEAKEN,
    ResearchFeedbackError,
    evaluate_research_iteration,
)
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PARAM = "parameter:client"
RESPONSE_REF = "response:jobs-response-1"
AUTH_REF = "authorization:owner-comparison-1"
STATUS_REF = "status:404-on-other-principal"


def observation(ref: str, fact: str = "") -> dict:
    return {
        "ref": ref,
        "fact": fact or f"observed {ref.partition(':')[2]}",
        "source": "context",
    }


def signal(name: str, detail: str = "") -> dict:
    return {"signal": name, "detail": detail, "source": "watch_derived"}


def hypothesis(
    *,
    category: str = "IDOR",
    title: str = "Object reference may cross authorization boundaries",
    observations: list[dict] | None = None,
    signals: list[dict] | None = None,
) -> dict:
    if observations is None:
        observations = [observation(PATH_OBJECT), observation(PARAM)]
    if signals is None:
        signals = [signal("IDOR", "object_reference=PATH_PARAMETER")]
    return {
        "title": title,
        "category": category,
        "priority": "MEDIUM",
        "confidence": "MEDIUM",
        "evidence": {
            "observations": observations,
            "derived_signals": signals,
        },
        "selected_evidence_refs": ["E1", "E2"],
        "inference": "Structural observation only; behavior was not observed.",
        "why_interesting": "Uncertainty depends on behavior evidence.",
        "missing_evidence": ["Whether authorization behavior exists"],
        "next_safe_action": "Review stored records for the endpoint.",
    }


def chain(hypotheses):
    action_plan = plan_research_actions(hypotheses)
    acquisition_plan = plan_evidence_acquisition(action_plan)
    readiness_plan = plan_decision_readiness(action_plan, acquisition_plan)
    return action_plan, acquisition_plan, readiness_plan


def evaluate(hypotheses, new_evidence=None, **kwargs) -> dict:
    action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
    return evaluate_research_iteration(
        hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
        new_evidence=new_evidence,
        **kwargs,
    )


def first(result: dict) -> dict:
    return result["iterations"][0]


def provides(hypothesis_ref: str, kind: str, ref: str) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": kind,
        "effect": EFFECT_PROVIDES,
        "source": "STORED_RESPONSE",
        "observations": [observation(ref)],
    }


def contradicts(hypothesis_ref: str, kind: str, ref: str) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": kind,
        "effect": EFFECT_CONTRADICTS,
        "source": "STORED_RESPONSE",
        "observations": [observation(ref)],
    }


def invalidates(hypothesis_ref: str, ref: str) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "effect": EFFECT_INVALIDATES,
        "source": "HUMAN_REVIEW",
        "invalidates_refs": [ref],
    }


STRUCTURAL = [hypothesis()]
PARTIAL = [
    hypothesis(
        observations=[
            observation(PATH_OBJECT),
            observation(PARAM),
            observation(STATUS_REF),
        ]
    )
]
COMPLETE = [
    hypothesis(
        observations=[
            observation(PATH_OBJECT),
            observation(RESPONSE_REF),
            observation(AUTH_REF),
        ]
    )
]


class TestNoChangeAndGapRemains(unittest.TestCase):
    def test_no_new_evidence_reports_gap_remaining(self):
        result = evaluate(STRUCTURAL)
        iteration = first(result)
        self.assertEqual(result["rejections"], [])
        self.assertEqual(iteration["feedback_state"], FEEDBACK_GAP_REMAINS)
        self.assertEqual(iteration["current_state"], STATE_UNRESOLVED)
        self.assertEqual(iteration["next_iteration"], NEXT_CONTINUE)
        self.assertEqual(iteration["reason"], REASON_NO_RELEVANT_EVIDENCE)
        self.assertEqual(iteration["evidence_delta"], [])
        self.assertEqual(
            iteration["remaining_decision_requirements"],
            ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"],
        )
        self.assertFalse(iteration["human_review_required"])

    def test_no_new_evidence_on_complete_record_is_no_change(self):
        result = evaluate(COMPLETE)
        iteration = first(result)
        self.assertEqual(iteration["previous_state"], STATE_STOP)
        self.assertEqual(iteration["feedback_state"], FEEDBACK_NO_CHANGE)
        self.assertEqual(iteration["current_state"], STATE_RETAIN)
        self.assertEqual(iteration["next_iteration"], NEXT_HUMAN_REVIEW)
        self.assertTrue(iteration["human_review_required"])

    def test_deterministic_transition(self):
        hypotheses = STRUCTURAL
        first_run = evaluate(hypotheses)
        second_run = evaluate(hypotheses)
        self.assertEqual(json.dumps(first_run), json.dumps(second_run))


class TestEvidenceDeltaTransitions(unittest.TestCase):
    def test_gap_reduction_missing_to_available(self):
        new = {
            "items": [
                provides("H1", "AUTHORIZATION_OUTCOME", AUTH_REF),
            ]
        }
        result = evaluate(STRUCTURAL, new)
        iteration = first(result)
        self.assertEqual(iteration["feedback_state"], FEEDBACK_GAP_REDUCED)
        self.assertEqual(iteration["current_state"], STATE_REFINE)
        self.assertEqual(iteration["next_iteration"], NEXT_CONTINUE)
        self.assertEqual(
            iteration["reason"], REASON_MISSING_EVIDENCE_ACQUIRED
        )
        self.assertEqual(iteration["newly_available_requirements"], ["AUTHORIZATION_OUTCOME"])
        self.assertEqual(
            iteration["evidence_delta"],
            [
                {
                    "requirement_kind": "AUTHORIZATION_OUTCOME",
                    "from_status": "MISSING",
                    "to_status": "AVAILABLE",
                    "cause": "NEW_EVIDENCE",
                    "hypothesis_ref": "H1",
                }
            ],
        )
        self.assertEqual(
            iteration["remaining_decision_requirements"],
            ["OWNERSHIP_BINDING"],
        )

    def test_gap_completion_transitions_to_human_review(self):
        new = {
            "items": [
                provides("H1", "AUTHORIZATION_OUTCOME", AUTH_REF),
                provides("H1", "OWNERSHIP_BINDING", RESPONSE_REF),
            ]
        }
        result = evaluate(STRUCTURAL, new)
        iteration = first(result)
        self.assertEqual(
            iteration["feedback_state"], FEEDBACK_REQUIRES_REVIEW
        )
        self.assertEqual(iteration["current_state"], STATE_STOP)
        self.assertEqual(iteration["next_iteration"], NEXT_HUMAN_REVIEW)
        self.assertTrue(iteration["human_review_required"])
        self.assertEqual(iteration["remaining_decision_requirements"], [])

    def test_supporting_evidence_for_available_requirement(self):
        new = {
            "items": [
                provides("H1", "OBJECT_REFERENCE", "path:/another/{id}"),
            ]
        }
        result = evaluate(STRUCTURAL, new)
        iteration = first(result)
        self.assertEqual(
            iteration["feedback_state"], FEEDBACK_NEW_SUPPORTING
        )
        self.assertEqual(iteration["current_state"], STATE_RETAIN)
        self.assertEqual(iteration["next_iteration"], NEXT_CONTINUE)
        self.assertEqual(iteration["evidence_delta"], [])

    def test_contradiction_weakens_with_remaining_evidence(self):
        new = {
            "items": [
                contradicts(
                    "H1", "OWNERSHIP_BINDING", "response:ownership-consistent"
                )
            ]
        }
        result = evaluate(PARTIAL, new)
        iteration = first(result)
        self.assertEqual(
            iteration["feedback_state"], FEEDBACK_NEW_CONTRADICTING
        )
        self.assertEqual(iteration["current_state"], STATE_WEAKEN)
        self.assertEqual(iteration["next_iteration"], NEXT_CONTINUE)
        self.assertIn(
            "AUTHORIZATION_OUTCOME", iteration["unchanged_requirements"]
        )

    def test_contradiction_removing_basis_stops(self):
        new = {
            "items": [
                contradicts("H1", "AUTHORIZATION_OUTCOME", RESPONSE_REF)
            ]
        }
        result = evaluate(STRUCTURAL, new)
        iteration = first(result)
        self.assertEqual(
            iteration["feedback_state"], FEEDBACK_NEW_CONTRADICTING
        )
        self.assertEqual(iteration["current_state"], STATE_STOP)
        self.assertEqual(iteration["next_iteration"], NEXT_STOP)
        self.assertEqual(iteration["reason"], "CONTRADICTING_EVIDENCE")
        self.assertTrue(iteration["human_review_required"])

    def test_invalidation_with_remaining_basis_refines(self):
        new = {"items": [invalidates("H1", PATH_OBJECT)]}
        result = evaluate(COMPLETE, new)
        iteration = first(result)
        self.assertEqual(iteration["feedback_state"], FEEDBACK_INVALIDATED)
        self.assertEqual(iteration["current_state"], STATE_REFINE)
        self.assertEqual(iteration["next_iteration"], NEXT_CONTINUE)
        self.assertEqual(
            iteration["evidence_delta"],
            [
                {
                    "requirement_kind": "OBJECT_REFERENCE",
                    "from_status": "AVAILABLE",
                    "to_status": "MISSING",
                    "cause": "INVALIDATION",
                    "hypothesis_ref": "H1",
                }
            ],
        )
        self.assertTrue(iteration["human_review_required"])

    def test_invalidation_removing_decision_basis_stops(self):
        new = {"items": [invalidates("H1", AUTH_REF)]}
        result = evaluate(COMPLETE, new)
        iteration = first(result)
        self.assertEqual(iteration["feedback_state"], FEEDBACK_INVALIDATED)
        self.assertEqual(iteration["current_state"], STATE_UNRESOLVED)
        self.assertEqual(iteration["next_iteration"], NEXT_STOP)
        self.assertEqual(
            set(iteration["invalidated_requirements"]),
            {"AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"},
        )
        self.assertEqual(
            iteration["changed_evidence_refs"], [AUTH_REF]
        )

    def test_ambiguous_redacted_references_are_rejected(self):
        hypotheses = [
            hypothesis(
                observations=[
                    observation(PATH_OBJECT),
                    observation("authorization:owner-a"),
                    observation("authorization:owner-b"),
                ]
            )
        ]
        new = {"items": [invalidates("H1", "authorization:owner-a")]}
        result = evaluate(hypotheses, new)
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_AMBIGUOUS_EVIDENCE],
        )
        self.assertEqual(first(result)["evidence_delta"], [])


class TestCorrelationAndAttribution(unittest.TestCase):
    def test_correlated_hypotheses_stay_correlated(self):
        hypotheses = [
            hypothesis(title="First IDOR"),
            hypothesis(
                title="Second IDOR",
                observations=[
                    observation("path:/orders/{id}"),
                    observation("parameter:order"),
                ],
            ),
        ]
        new = {"items": [provides("H2", "AUTHORIZATION_OUTCOME", AUTH_REF)]}
        result = evaluate(hypotheses, new)
        self.assertEqual(len(result["iterations"]), 1)
        iteration = first(result)
        self.assertEqual(iteration["hypothesis_refs"], ["H1", "H2"])
        self.assertEqual(iteration["hypothesis_count"], 2)
        self.assertEqual(
            iteration["evidence_delta"][0]["hypothesis_ref"], "H2"
        )
        self.assertEqual(
            [entry["hypothesis_ref"] for entry in iteration["evidence_items"]],
            ["H2"],
        )

    def test_skill_refs_are_propagated(self):
        iteration = first(evaluate(STRUCTURAL))
        self.assertEqual(iteration["skill_refs"], ["idor-bola"])


class TestValidationAndFailClosed(unittest.TestCase):
    def test_unknown_hypothesis_rejected(self):
        new = {"items": [provides("H9", "AUTHORIZATION_OUTCOME", AUTH_REF)]}
        result = evaluate(STRUCTURAL, new)
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_UNKNOWN_HYPOTHESIS],
        )
        self.assertEqual(first(result)["feedback_state"], FEEDBACK_GAP_REMAINS)

    def test_unknown_requirement_rejected(self):
        new = {"items": [provides("H1", "NOT_A_REQUIREMENT", AUTH_REF)]}
        result = evaluate(STRUCTURAL, new)
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_UNKNOWN_REQUIREMENT],
        )

    def test_unknown_invalidated_ref_rejected(self):
        new = {"items": [invalidates("H1", "response:never-seen-before")]}
        result = evaluate(STRUCTURAL, new)
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_UNKNOWN_INVALIDATED_REF],
        )

    def test_sensitive_evidence_rejected(self):
        secret = "supersecretvalue12345"
        item = provides("H1", "AUTHORIZATION_OUTCOME", AUTH_REF)
        item["observations"] = [
            observation(
                "authorization:owner-comparison-1",
                f"authorization token={secret}",
            )
        ]
        result = evaluate(STRUCTURAL, {"items": [item]})
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_SENSITIVE_EVIDENCE],
        )
        text = json.dumps(result)
        self.assertNotIn(secret, text)
        self.assertNotIn("://", text)

    def test_malformed_items_fail_closed(self):
        result = evaluate(
            STRUCTURAL,
            {"items": ["nope", 42, {"hypothesis_ref": "H1", "effect": "WAT"}]},
        )
        codes = [entry["code"] for entry in result["rejections"]]
        self.assertEqual(len(codes), 3)
        self.assertTrue(all(code in REJECTION_CODES for code in codes))
        self.assertEqual(first(result)["evidence_delta"], [])

    def test_evidence_identity_is_preserved(self):
        new = {
            "items": [
                provides("H1", "AUTHORIZATION_OUTCOME", AUTH_REF),
            ]
        }
        iteration = first(evaluate(STRUCTURAL, new))
        self.assertEqual(iteration["changed_evidence_refs"], [AUTH_REF])
        for ref in iteration["changed_evidence_refs"]:
            self.assertIn(ref.partition(":")[0], EVIDENCE_REF_KINDS)

    def test_empty_inputs_fail_closed(self):
        result = evaluate_research_iteration(None)
        self.assertEqual(result["iterations"], [])
        self.assertEqual(result["summary"]["iteration_count"], 0)
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        malformed = evaluate_research_iteration(
            None, action_plan=[1], acquisition_plan={"plans": [2]},
            readiness_plan={"records": [3]}, new_evidence={"items": [4]},
        )
        self.assertEqual(malformed["iterations"], [])

    def test_limit_is_validated_and_applied(self):
        hypotheses = [
            hypothesis(title="First IDOR"),
            hypothesis(
                title="Recon",
                category="RECON",
                observations=[observation("path:/api/v1/jobs/search")],
                signals=[signal("RECON", "api_type=REST")],
            ),
        ]
        action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
        limited = evaluate_research_iteration(
            hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
            limit=1,
        )
        self.assertEqual(len(limited["iterations"]), 1)
        self.assertEqual(limited["iterations"][0]["iteration_id"], "I1")
        empty = evaluate_research_iteration(
            hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
            limit=0,
        )
        self.assertEqual(empty["iterations"], [])
        with self.assertRaises(ResearchFeedbackError):
            evaluate_research_iteration(
                hypotheses,
                action_plan=action_plan,
                acquisition_plan=acquisition_plan,
                readiness_plan=readiness_plan,
                limit=-1,
            )
        with self.assertRaises(ResearchFeedbackError):
            evaluate_research_iteration(
                hypotheses,
                action_plan=action_plan,
                acquisition_plan=acquisition_plan,
                readiness_plan=readiness_plan,
                limit=True,
            )


class TestVocabulariesAndSafety(unittest.TestCase):
    def test_closed_vocabularies(self):
        iteration = first(evaluate(STRUCTURAL))
        self.assertEqual(RULE_VERSION, "r73-1")
        self.assertEqual(
            (SOURCE_ACTION_RULE_VERSION, SOURCE_ACQUISITION_RULE_VERSION,
             SOURCE_READINESS_RULE_VERSION),
            ("r70-1", "r71-1", "r72-1"),
        )
        self.assertIn(iteration["feedback_state"], FEEDBACK_STATES)
        self.assertIn(iteration["current_state"], HYPOTHESIS_STATES)
        self.assertIn(iteration["next_iteration"], NEXT_ITERATIONS)
        self.assertIn(iteration["reason"], REASON_CODES)
        self.assertIn(EFFECT_PROVIDES, EVIDENCE_EFFECTS)
        self.assertIn(EFFECT_CONTRADICTS, EVIDENCE_EFFECTS)
        self.assertIn(EFFECT_INVALIDATES, EVIDENCE_EFFECTS)
        for source in EVIDENCE_SOURCES:
            self.assertTrue(source)

    def test_safety_flags_forced(self):
        result = evaluate(STRUCTURAL)
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertTrue(result["research_only"])
        for iteration in result["iterations"]:
            self.assertEqual(iteration["safety"], SAFETY_BLOCK)
            self.assertEqual(iteration["confirmation_state"], "NOT_CONFIRMED")
            self.assertTrue(iteration["advisory"])
            self.assertTrue(iteration["research_only"])
            self.assertFalse(iteration["safety"]["execution_performed"])
            self.assertFalse(iteration["safety"]["vulnerability_confirmed"])
            self.assertFalse(iteration["safety"]["exploit_authorized"])
            self.assertTrue(iteration["safety"]["human_authority_required"])

    def test_no_confirmation_or_execution_semantics(self):
        result = evaluate(STRUCTURAL)
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        payload = json.loads(json.dumps(result))
        payload.pop("safety", None)
        for iteration in payload["iterations"]:
            iteration.pop("safety", None)
        text = json.dumps(payload).replace("NOT_CONFIRMED", "")
        for forbidden in (
            "CONFIRMED",
            "VULNERABLE",
            "EXPLOITABLE",
            "EXPLOIT",
            "PAYLOAD",
            "CURL ",
            "SQLMAP",
            "NUCLEI",
            "HTTP://",
            "HTTPS://",
            "://",
            "SK-",
            "BEARER",
        ):
            self.assertNotIn(forbidden, text.upper(), forbidden)

    def test_summary_reports_bands(self):
        result = evaluate(STRUCTURAL)
        summary = result["summary"]
        self.assertEqual(summary["iteration_count"], 1)
        self.assertEqual(summary["covered_plans"], 1)
        self.assertEqual(summary["covered_hypotheses"], 1)
        self.assertEqual(summary["feedback_bands"][FEEDBACK_GAP_REMAINS], 1)
        self.assertEqual(summary["hypothesis_state_bands"][STATE_UNRESOLVED], 1)
        self.assertEqual(summary["next_iteration_bands"][NEXT_CONTINUE], 1)
        self.assertFalse(summary["human_review_required"])
        self.assertEqual(summary["top_iteration_id"], "I1")
        self.assertEqual(summary["top_feedback_state"], FEEDBACK_GAP_REMAINS)


if __name__ == "__main__":
    unittest.main()
