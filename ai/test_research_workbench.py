"""Focused tests for the R77 human research workbench (presentation only).

All tests are offline and pure: R77 consumes real R70-R76 stage outputs built
from validated-hypothesis-shaped mappings. External evidence packages are
synthetic and bounded. No provider, Mongo, network or file system access
happens here.
"""

from __future__ import annotations

import json
import unittest

from ai.knowledge.research_case_workspace import (
    build_research_case,
    update_research_case,
)
from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_evidence_intake import intake_and_reevaluate
from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)
from ai.knowledge.research_workbench import (
    ACTION_CONTINUE_RESEARCH,
    ACTION_HUMAN_REVIEW,
    ACTION_PROVIDE_EVIDENCE,
    ACTION_REVIEW_CONFLICT,
    ACTION_REVIEW_EVIDENCE,
    ACTION_STOP,
    ERROR_LIMIT_INVALID,
    ERROR_MALFORMED_CASE,
    EXTERNAL_EVIDENCE_MESSAGE,
    HUMAN_REVIEW_REASONS,
    REVIEW_CONFLICT,
    REVIEW_READINESS,
    RULE_VERSION,
    WORKFLOW_ACTIONS,
    ResearchWorkbenchError,
    build_research_workbench,
    build_workbench_set,
    summarize_workbenches,
)

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PARAM = "parameter:client"
RESPONSE_REF = "response:jobs-response-1"
EXTERNAL_A = "authorization:external-owner-comparison-a"
EXTERNAL_B = "response:external-ownership-binding-b"


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
        "category": "IDOR",
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
    iteration_plan = evaluate_research_iteration(
        hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )
    return action_plan, acquisition_plan, readiness_plan, iteration_plan


def synthetic_item(
    ref: str,
    *,
    hypothesis_ref: str = "H1",
    requirement_kind: str = "AUTHORIZATION_OUTCOME",
    effect: str = "PROVIDES",
) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": requirement_kind,
        "effect": effect,
        "source": "HUMAN_REVIEW",
        "evidence_ref": ref,
        "observations": [
            {"ref": ref, "fact": f"synthetic {ref.partition(':')[2]}"}
        ],
    }


def synthetic_package(*items) -> dict:
    return {"package_version": "r74-1", "items": list(items)}


def case_with(hypotheses, *items):
    action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
        hypotheses
    )
    intake = None
    provenance = None
    if items:
        intake = intake_and_reevaluate(
            synthetic_package(*items),
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        provenance = analyze_evidence_provenance(
            intake,
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
    case = build_research_case(
        action_plan,
        acquisition_plan,
        readiness_plan,
        iteration_plan,
        program="indeed",
        evidence_intake=intake,
        evidence_provenance=provenance,
    )
    return case, action_plan, acquisition_plan, provenance


def workbench_for(hypotheses, *items, **kwargs):
    case, action_plan, acquisition_plan, provenance = case_with(
        hypotheses, *items
    )
    kwargs.setdefault("action_plan", action_plan)
    kwargs.setdefault("acquisition_plan", acquisition_plan)
    if provenance is not None:
        kwargs.setdefault("evidence_provenance", provenance)
    return build_research_workbench(case, **kwargs)


class TestWorkbenchCreation(unittest.TestCase):
    def test_workbench_creation(self):
        workbench = workbench_for([hypothesis()])
        self.assertEqual(workbench["workbench_version"], RULE_VERSION)
        self.assertEqual(RULE_VERSION, "r77-1")
        self.assertEqual(
            workbench["case_ref"], "case-indeed-a1-object-authorization"
        )
        self.assertEqual(workbench["program"], "indeed")
        self.assertEqual(workbench["category"], "IDOR")
        self.assertEqual(workbench["gap_id"], "OBJECT_AUTHORIZATION")
        self.assertIn("OBJECT_AUTHORIZATION", workbench["title"])

    def test_current_state(self):
        workbench = workbench_for([hypothesis()])
        current = workbench["current_state"]
        self.assertEqual(current["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(current["readiness"], "INSUFFICIENT")
        self.assertEqual(current["decision"], "NEEDS_EVIDENCE")
        self.assertEqual(current["feedback"], "EVIDENCE_GAP_REMAINS")
        self.assertEqual(current["hypothesis_state"], "UNRESOLVED")
        self.assertEqual(current["next_iteration"], "CONTINUE")
        self.assertFalse(current["human_review_required"])

    def test_deterministic_output(self):
        case, action_plan, acquisition_plan, provenance = case_with(
            [hypothesis()]
        )
        first = build_research_workbench(
            case, action_plan=action_plan, acquisition_plan=acquisition_plan
        )
        second = build_research_workbench(
            case, action_plan=action_plan, acquisition_plan=acquisition_plan
        )
        self.assertEqual(json.dumps(first), json.dumps(second))

    def test_input_immutability(self):
        case, action_plan, acquisition_plan, _ = case_with([hypothesis()])
        before = (
            json.dumps(case),
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
        )
        build_research_workbench(
            case, action_plan=action_plan, acquisition_plan=acquisition_plan
        )
        after = (
            json.dumps(case),
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
        )
        self.assertEqual(before, after)


class TestKnownAndMissing(unittest.TestCase):
    def test_known_evidence(self):
        workbench = workbench_for([hypothesis()])
        known = workbench["what_we_know"]
        self.assertEqual(known["available_count"], 2)
        self.assertEqual(
            sorted(known["available_requirement_kinds"]),
            ["OBJECT_REFERENCE", "WATCH_SIGNAL"],
        )
        self.assertEqual(known["accepted_evidence_count"], 0)
        self.assertEqual(known["provenance_state"], "NOT_PROVIDED")

    def test_supporting_refs_from_accepted_evidence(self):
        workbench = workbench_for(
            [hypothesis()], synthetic_item(EXTERNAL_A)
        )
        known = workbench["what_we_know"]
        self.assertEqual(known["accepted_evidence_count"], 1)
        self.assertEqual(known["supporting_evidence_refs"], [EXTERNAL_A])

    def test_missing_evidence(self):
        workbench = workbench_for([hypothesis()])
        missing = workbench["what_is_missing"]
        self.assertEqual(
            missing["missing_requirement_kinds"],
            ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"],
        )
        self.assertEqual(
            missing["decision_critical_missing"],
            ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"],
        )
        self.assertEqual(missing["acquisition_plan_ref"], "P1")
        self.assertTrue(missing["stopping_condition"])
        self.assertEqual(missing["detail_state"], "AVAILABLE")
        self.assertTrue(missing["requirement_details"])

    def test_missing_reduced_after_evidence(self):
        workbench = workbench_for(
            [hypothesis()], synthetic_item(EXTERNAL_A)
        )
        self.assertEqual(
            workbench["what_is_missing"]["decision_critical_missing"],
            ["OWNERSHIP_BINDING"],
        )

    def test_what_to_do_next(self):
        workbench = workbench_for([hypothesis()])
        next_up = workbench["what_to_do_next"]
        self.assertTrue(next_up["objective"])
        self.assertTrue(next_up["recommended_action"])
        self.assertEqual(
            next_up["acquisition_method"], "AUTHORIZATION_BEHAVIOR_REVIEW"
        )
        self.assertTrue(next_up["sources"])
        self.assertTrue(next_up["expected_result"])
        self.assertTrue(next_up["stopping_condition"])
        self.assertEqual(next_up["next_iteration"], "CONTINUE")

    def test_action_and_acquisition_references(self):
        workbench = workbench_for([hypothesis()])
        self.assertEqual(
            workbench["case_ref"], "case-indeed-a1-object-authorization"
        )
        self.assertEqual(
            workbench["what_is_missing"]["acquisition_plan_ref"], "P1"
        )
        self.assertTrue(workbench["what_to_do_next"]["recommended_action"])


class TestHypothesesAndWhy(unittest.TestCase):
    def test_hypotheses_presentation(self):
        workbench = workbench_for([hypothesis(title="Possible IDOR")])
        item = workbench["hypotheses"][0]
        self.assertEqual(item["hypothesis_ref"], "H1")
        self.assertEqual(item["title"], "Possible IDOR")
        self.assertEqual(item["category"], "IDOR")
        self.assertEqual(item["priority"], "MEDIUM")
        self.assertEqual(item["confidence"], "MEDIUM")
        self.assertEqual(item["evidence_state"], "STRUCTURE_AND_SIGNAL")
        self.assertEqual(item["hypothesis_state"], "UNRESOLVED")
        self.assertEqual(item["detail_state"], "AVAILABLE")

    def test_correlated_hypotheses(self):
        workbench = workbench_for(
            [hypothesis(title="First IDOR"), hypothesis(title="Second IDOR")]
        )
        self.assertEqual(len(workbench["hypotheses"]), 2)
        self.assertEqual(
            [item["hypothesis_ref"] for item in workbench["hypotheses"]],
            ["H1", "H2"],
        )

    def test_hypotheses_missing_stage_absent_state(self):
        workbench = workbench_for([hypothesis()], action_plan=None)
        item = workbench["hypotheses"][0]
        self.assertEqual(item["detail_state"], "UNAVAILABLE")
        self.assertEqual(item["title"], "")
        self.assertEqual(workbench["why_interesting"]["state"], "UNAVAILABLE")

    def test_why_interesting_reuses_r70_reasons(self):
        workbench = workbench_for([hypothesis()], action_plan=None)
        self.assertEqual(workbench["why_interesting"]["state"], "UNAVAILABLE")
        self.assertEqual(workbench["why_interesting"]["reasons"], [])
        reused = workbench_for([hypothesis()])
        self.assertEqual(reused["why_interesting"]["state"], "AVAILABLE")
        self.assertTrue(reused["why_interesting"]["reasons"])


class TestReviewAndConflicts(unittest.TestCase):
    def test_human_review_on_ready_case(self):
        workbench = workbench_for(
            [hypothesis()],
            synthetic_item(EXTERNAL_A),
            synthetic_item(EXTERNAL_B, requirement_kind="OWNERSHIP_BINDING"),
        )
        current = workbench["current_state"]
        self.assertEqual(current["status"], "READY_FOR_HUMAN_REVIEW")
        review = workbench["human_review"]
        self.assertTrue(review["required"])
        self.assertIn(REVIEW_READINESS, review["reasons"])
        for reason in review["reasons"]:
            self.assertIn(reason, HUMAN_REVIEW_REASONS)

    def test_conflict_displayed_not_resolved(self):
        workbench = workbench_for(
            [hypothesis()],
            synthetic_item(EXTERNAL_A),
            synthetic_item(EXTERNAL_B, effect="CONTRADICTS"),
        )
        conflicts = workbench["conflicts"]
        self.assertEqual(conflicts["count"], 1)
        self.assertFalse(conflicts["resolved"])
        self.assertIn("AUTHORIZATION_OUTCOME", conflicts["requirement_kinds"])
        self.assertTrue(conflicts["preserved"])
        self.assertTrue(conflicts["preserved"][0]["existing_evidence_refs"])
        self.assertTrue(conflicts["preserved"][0]["new_evidence_refs"])
        self.assertIn(REVIEW_CONFLICT, workbench["human_review"]["reasons"])
        self.assertNotIn("winner", json.dumps(workbench).lower())

    def test_stop_case(self):
        hypotheses = [hypothesis()]
        action_plan, acquisition_plan, readiness_plan, _ = chain(hypotheses)
        iteration_plan = evaluate_research_iteration(
            hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
            new_evidence={
                "items": [
                    {
                        "hypothesis_ref": "H1",
                        "requirement_kind": "AUTHORIZATION_OUTCOME",
                        "effect": "CONTRADICTS",
                        "source": "HUMAN_REVIEW",
                        "observations": [observation(RESPONSE_REF)],
                    }
                ]
            },
        )
        case = build_research_case(
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            program="indeed",
        )
        workbench = build_research_workbench(
            case, action_plan=action_plan, acquisition_plan=acquisition_plan
        )
        self.assertEqual(
            workbench["current_state"]["status"], "STOPPED"
        )
        self.assertTrue(workbench["human_review"]["required"])
        actions = [step["action"] for step in workbench["next_steps"]]
        self.assertIn(ACTION_STOP, actions)


class TestNextStepsAndActions(unittest.TestCase):
    def test_waiting_case_next_steps(self):
        workbench = workbench_for([hypothesis()])
        actions = [step["action"] for step in workbench["next_steps"]]
        self.assertEqual(
            actions, [ACTION_PROVIDE_EVIDENCE, ACTION_CONTINUE_RESEARCH]
        )
        self.assertLessEqual(len(actions), 3)

    def test_ready_case_next_steps(self):
        workbench = workbench_for(
            [hypothesis()],
            synthetic_item(EXTERNAL_A),
            synthetic_item(EXTERNAL_B, requirement_kind="OWNERSHIP_BINDING"),
        )
        actions = [step["action"] for step in workbench["next_steps"]]
        self.assertIn(ACTION_HUMAN_REVIEW, actions)
        self.assertIn(ACTION_REVIEW_EVIDENCE, actions)

    def test_conflict_case_next_steps(self):
        workbench = workbench_for(
            [hypothesis()],
            synthetic_item(EXTERNAL_A),
            synthetic_item(EXTERNAL_B, effect="CONTRADICTS"),
        )
        actions = [step["action"] for step in workbench["next_steps"]]
        self.assertIn(ACTION_REVIEW_CONFLICT, actions)
        self.assertLessEqual(len(actions), 3)

    def test_workflow_actions_are_closed(self):
        workbench = workbench_for([hypothesis()])
        self.assertEqual(
            workbench["workflow_actions"], WORKFLOW_ACTIONS
        )
        for step in workbench["next_steps"]:
            self.assertIn(step["action"], WORKFLOW_ACTIONS)

    def test_evidence_input_placeholder(self):
        workbench = workbench_for([hypothesis()])
        placeholder = workbench["evidence_input"]
        self.assertEqual(placeholder["action"], ACTION_PROVIDE_EVIDENCE)
        self.assertFalse(placeholder["accepted"])
        self.assertEqual(placeholder["message"], EXTERNAL_EVIDENCE_MESSAGE)
        self.assertIn("R74 intake contract", placeholder["message"])


class TestHistoryAndFailClosed(unittest.TestCase):
    def test_history_bounded(self):
        workbench = workbench_for([hypothesis()])
        self.assertEqual(len(workbench["history"]), 1)
        self.assertFalse(workbench["history_truncated"])

    def test_history_truncation_respected(self):
        hypotheses = [hypothesis()]
        case, action_plan, acquisition_plan, provenance = case_with(
            hypotheses, synthetic_item(EXTERNAL_A)
        )
        readiness_plan = plan_decision_readiness(
            action_plan, acquisition_plan
        )
        iteration_plan = evaluate_research_iteration(
            hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        updated = update_research_case(
            case,
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
        )
        self.assertEqual(updated["iteration_count"], 2)
        workbench = build_research_workbench(
            updated,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            limit=1,
        )
        self.assertEqual(len(workbench["history"]), 1)
        self.assertTrue(workbench["history_truncated"])

    def test_malformed_case_rejected(self):
        for bad in (None, {}, {"case_id": "x"}, {"case_id": "x", "status": ""}):
            with self.subTest(case=bad):
                with self.assertRaises(ResearchWorkbenchError) as caught:
                    build_research_workbench(bad)
                self.assertEqual(caught.exception.code, ERROR_MALFORMED_CASE)

    def test_limit_validation(self):
        case, action_plan, acquisition_plan, _ = case_with([hypothesis()])
        for bad in (0, -1, True):
            with self.subTest(limit=bad):
                with self.assertRaises(ResearchWorkbenchError) as caught:
                    build_research_workbench(
                        case,
                        action_plan=action_plan,
                        acquisition_plan=acquisition_plan,
                        limit=bad,
                    )
                self.assertEqual(caught.exception.code, ERROR_LIMIT_INVALID)

    def test_workbench_set_and_summary(self):
        case, action_plan, acquisition_plan, _ = case_with([hypothesis()])
        workbench_set = build_workbench_set(
            [case],
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
        )
        self.assertEqual(workbench_set["status"], "BUILT")
        self.assertEqual(workbench_set["workbench_count"], 1)
        summary = workbench_set["summary"]
        self.assertEqual(summary["workbench_count"], 1)
        self.assertEqual(
            summary["status_bands"]["WAITING_FOR_EVIDENCE"], 1
        )
        empty = build_workbench_set([])
        self.assertEqual(empty["status"], "NO_CASES")
        self.assertEqual(summarize_workbenches([])["workbench_count"], 0)


class TestSafety(unittest.TestCase):
    def test_safety_flags(self):
        workbench = workbench_for([hypothesis()])
        self.assertEqual(workbench["safety"], SAFETY_BLOCK)
        self.assertEqual(workbench["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(workbench["advisory"])
        self.assertTrue(workbench["research_only"])
        self.assertFalse(workbench["safety"]["execution_performed"])
        self.assertFalse(workbench["safety"]["vulnerability_confirmed"])
        self.assertFalse(workbench["safety"]["exploit_authorized"])
        self.assertTrue(workbench["safety"]["human_authority_required"])

    def test_no_security_verdict_or_execution_semantics(self):
        workbench = workbench_for(
            [hypothesis()],
            synthetic_item(EXTERNAL_A),
            synthetic_item(EXTERNAL_B, effect="CONTRADICTS"),
        )
        payload = json.loads(json.dumps(workbench))
        payload.pop("safety", None)
        payload["current_state"].pop("confirmation_state", None)
        payload["human_review"].pop("confirmation_state", None)
        text = (
            json.dumps(payload)
            .upper()
            .replace("NOT_CONFIRMED", "")
            .replace("VULNERABILITY_CONFIRMED", "")
        )
        for forbidden in (
            "CONFIRMED",
            "VULNERABLE",
            "EXPLOITABLE",
            "PAYLOAD",
            "SQLMAP",
            "NUCLEI",
            "CURL ",
            "HTTP://",
            "HTTPS://",
            "://",
            "SK-",
            "BEARER",
        ):
            self.assertNotIn(forbidden, text, forbidden)

    def test_sensitive_data_excluded(self):
        secret = "supersecretvalue12345"
        workbench = workbench_for([hypothesis()])
        text = json.dumps(workbench)
        self.assertNotIn(secret, text)
        self.assertNotIn("://", text)
        self.assertNotIn("Bearer", text)

    def test_no_stage_calls_in_module(self):
        import inspect

        import ai.knowledge.research_workbench as module

        source = inspect.getsource(module)
        for forbidden in (
            "plan_research_actions(",
            "plan_evidence_acquisition(",
            "plan_decision_readiness(",
            "evaluate_research_iteration(",
            "intake_and_reevaluate(",
            "analyze_evidence_provenance(",
            "build_research_cases(",
        ):
            self.assertNotIn(forbidden, source, forbidden)


if __name__ == "__main__":
    unittest.main()
