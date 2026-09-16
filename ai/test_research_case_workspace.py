"""Focused tests for the R76 research case workspace (aggregation state).

All tests are offline and pure: R76 consumes real R70/R71/R72/R73/R74/R75
stage outputs built from validated-hypothesis-shaped mappings. External
evidence packages are synthetic and bounded. No provider, Mongo, network or
file system access happens here.
"""

from __future__ import annotations

import json
import unittest

from ai.knowledge.research_case_workspace import (
    CASE_ACTIVE,
    CASE_ERROR_CODES,
    CASE_READY_FOR_HUMAN_REVIEW,
    CASE_STATUSES,
    CASE_STOPPED,
    CASE_WAITING_FOR_EVIDENCE,
    ERROR_GAP_MISMATCH,
    ERROR_LIMIT_INVALID,
    ERROR_MALFORMED_STAGE_INPUT,
    ERROR_ORPHAN_FEEDBACK,
    ERROR_ORPHAN_PROVENANCE,
    ERROR_ORPHAN_READINESS,
    ERROR_PROGRAM_MISMATCH,
    ERROR_SENSITIVE_CASE_INPUT,
    ERROR_UNKNOWN_ACTION_REF,
    RULE_VERSION,
    STOPPING_BASIS_REMOVED,
    STOPPING_CONFLICT,
    STOPPING_DECISION_COMPLETE,
    STOPPING_NONE,
    STOPPING_REASONS,
    ResearchCaseError,
    build_research_case,
    build_research_cases,
    case_id_for,
    summarize_research_case,
    summarize_research_cases,
    update_research_case,
)
from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_evidence_intake import (
    intake_and_reevaluate,
)
from ai.knowledge.research_evidence_provenance import (
    analyze_evidence_provenance,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PATH_RECON = "path:/api/internal/brand/theme/style-sheet"
PARAM = "parameter:client"
RESPONSE_REF = "response:jobs-response-1"
AUTH_REF = "authorization:owner-comparison-1"
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
        "observations": [{"ref": ref, "fact": f"synthetic {ref.partition(':')[2]}"}],
    }


def synthetic_package(*items) -> dict:
    return {"package_version": "r74-1", "items": list(items)}


def with_evidence(hypotheses, *items):
    action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
        hypotheses
    )
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
    return action_plan, acquisition_plan, readiness_plan, iteration_plan, intake, provenance


def build(hypotheses=None, **kwargs):
    hypotheses = hypotheses or [hypothesis()]
    action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
        hypotheses
    )
    kwargs.setdefault("program", "indeed")
    return build_research_case(
        action_plan, acquisition_plan, readiness_plan, iteration_plan, **kwargs
    ), (action_plan, acquisition_plan, readiness_plan, iteration_plan)


class TestCaseCreation(unittest.TestCase):
    def test_case_creation_and_references(self):
        case, _ = build()
        self.assertEqual(case["case_version"], RULE_VERSION)
        self.assertEqual(RULE_VERSION, "r76-1")
        self.assertEqual(case["program"], "indeed")
        self.assertEqual(case["action_ref"], "A1")
        self.assertEqual(case["hypothesis_refs"], ["H1"])
        self.assertEqual(case["hypothesis_count"], 1)
        self.assertEqual(case["category"], "IDOR")
        self.assertEqual(case["gap_id"], "OBJECT_AUTHORIZATION")
        self.assertEqual(case["action"]["action_ref"], "A1")
        self.assertEqual(case["acquisition"]["plan_ref"], "P1")
        self.assertEqual(case["readiness"]["readiness_ref"], "R1")
        self.assertEqual(case["feedback"]["iteration_ref"], "I1")

    def test_deterministic_case_identity(self):
        first, _ = build()
        second, _ = build()
        self.assertEqual(first["case_id"], second["case_id"])
        self.assertEqual(
            first["case_id"], "case-indeed-a1-object-authorization"
        )
        other, _ = build(program="other")
        self.assertNotEqual(first["case_id"], other["case_id"])
        self.assertNotEqual(
            case_id_for("indeed", "A1", "OBJECT_AUTHORIZATION"),
            case_id_for("indeed", "A2", "OBJECT_AUTHORIZATION"),
        )

    def test_deterministic_output(self):
        first, _ = build()
        second, _ = build()
        self.assertEqual(json.dumps(first), json.dumps(second))

    def test_initial_status_is_waiting_for_evidence(self):
        case, _ = build()
        self.assertEqual(case["status"], CASE_WAITING_FOR_EVIDENCE)
        self.assertEqual(case["stopping_reason"], STOPPING_NONE)
        self.assertEqual(
            case["readiness"]["sufficiency_state"], "INSUFFICIENT"
        )
        self.assertEqual(case["feedback"]["next_iteration"], "CONTINUE")

    def test_correlated_hypotheses_remain_one_case(self):
        hypotheses = [
            hypothesis(title="First IDOR"),
            hypothesis(title="Second IDOR"),
        ]
        case, _ = build(hypotheses)
        self.assertEqual(case["hypothesis_refs"], ["H1", "H2"])
        self.assertEqual(case["hypothesis_count"], 2)

    def test_evidence_counts(self):
        case, _ = build()
        evidence = case["evidence"]
        self.assertEqual(evidence["available_count"], 2)
        self.assertEqual(evidence["missing_count"], 2)
        self.assertEqual(evidence["decision_missing_count"], 2)
        self.assertEqual(
            sorted(evidence["available_requirement_kinds"]),
            ["OBJECT_REFERENCE", "WATCH_SIGNAL"],
        )
        self.assertEqual(
            sorted(evidence["missing_requirement_kinds"]),
            ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"],
        )
        self.assertEqual(evidence["accepted_evidence_count"], 0)
        self.assertEqual(evidence["rejected_evidence_count"], 0)
        self.assertEqual(evidence["intake_state"], "NOT_PROVIDED")

    def test_closed_vocabularies(self):
        case, _ = build()
        self.assertIn(case["status"], CASE_STATUSES)
        self.assertIn(case["stopping_reason"], STOPPING_REASONS)
        for code in CASE_ERROR_CODES:
            self.assertTrue(code)

    def test_safety_flags(self):
        case, _ = build()
        self.assertEqual(case["safety"], SAFETY_BLOCK)
        self.assertEqual(case["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(case["advisory"])
        self.assertTrue(case["research_only"])
        self.assertFalse(case["safety"]["execution_performed"])
        self.assertFalse(case["safety"]["vulnerability_confirmed"])
        self.assertFalse(case["safety"]["exploit_authorized"])
        self.assertTrue(case["safety"]["human_authority_required"])

    def test_no_confirmation_semantics(self):
        case, _ = build()
        payload = json.loads(json.dumps(case))
        payload.pop("safety", None)
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
            "HTTP://",
            "HTTPS://",
            "://",
        ):
            self.assertNotIn(forbidden, text, forbidden)


class TestStatusTransitions(unittest.TestCase):
    def test_active_transition_with_partial_evidence(self):
        hypotheses = [hypothesis()]
        (
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            intake,
            provenance,
        ) = with_evidence(hypotheses, synthetic_item(EXTERNAL_A))
        case = build_research_case(
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            program="indeed",
            evidence_intake=intake,
            evidence_provenance=provenance,
        )
        self.assertEqual(case["status"], CASE_ACTIVE)
        self.assertEqual(case["stopping_reason"], STOPPING_NONE)
        self.assertEqual(
            case["readiness"]["sufficiency_state"], "PARTIALLY_SUFFICIENT"
        )
        self.assertEqual(
            case["feedback"]["feedback_state"], "EVIDENCE_GAP_REDUCED"
        )
        self.assertEqual(case["evidence"]["accepted_evidence_count"], 1)
        self.assertEqual(case["evidence"]["intake_state"], "ACCEPTED")
        self.assertFalse(case["human_review_required"])

    def test_ready_for_human_review_transition(self):
        hypotheses = [hypothesis()]
        (
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            intake,
            provenance,
        ) = with_evidence(
            hypotheses,
            synthetic_item(EXTERNAL_A),
            synthetic_item(
                EXTERNAL_B, requirement_kind="OWNERSHIP_BINDING"
            ),
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
        self.assertEqual(case["status"], CASE_READY_FOR_HUMAN_REVIEW)
        self.assertEqual(
            case["stopping_reason"], STOPPING_DECISION_COMPLETE
        )
        self.assertEqual(
            case["readiness"]["sufficiency_state"], "SUFFICIENT_FOR_REVIEW"
        )
        self.assertTrue(case["human_review_required"])

    def test_stopped_transition_on_removed_basis(self):
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
        self.assertEqual(case["status"], CASE_STOPPED)
        self.assertEqual(case["stopping_reason"], STOPPING_BASIS_REMOVED)

    def test_conflict_requires_human_review_without_changing_readiness(self):
        hypotheses = [hypothesis()]
        (
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            intake,
            provenance,
        ) = with_evidence(
            hypotheses,
            synthetic_item(EXTERNAL_A),
            synthetic_item(EXTERNAL_B, effect="CONTRADICTS"),
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
        self.assertEqual(case["status"], CASE_READY_FOR_HUMAN_REVIEW)
        self.assertEqual(case["stopping_reason"], STOPPING_CONFLICT)
        self.assertTrue(case["human_review_required"])
        self.assertEqual(case["provenance"]["conflict_count"], 1)
        self.assertIn(
            "AUTHORIZATION_OUTCOME",
            case["provenance"]["conflicting_requirement_kinds"],
        )
        self.assertEqual(
            case["readiness"]["sufficiency_state"], "PARTIALLY_SUFFICIENT"
        )
        self.assertNotIn("winner", json.dumps(case).lower())

    def test_intake_counts_include_rejections(self):
        hypotheses = [hypothesis()]
        (
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            intake,
            provenance,
        ) = with_evidence(
            hypotheses,
            synthetic_item(EXTERNAL_A),
            synthetic_item("response:orphan", hypothesis_ref="H9"),
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
        self.assertEqual(case["evidence"]["accepted_evidence_count"], 1)
        self.assertEqual(case["evidence"]["rejected_evidence_count"], 1)
        self.assertEqual(case["evidence"]["intake_state"], "PARTIAL")
        self.assertEqual(case["provenance"]["record_count"], 2)


class TestHistory(unittest.TestCase):
    def test_update_appends_history_and_preserves_identity(self):
        hypotheses = [hypothesis()]
        case, stages = build(hypotheses)
        action_plan, acquisition_plan, readiness_plan, _ = stages
        (
            _,
            _,
            _,
            updated_iteration,
            intake,
            provenance,
        ) = with_evidence(hypotheses, synthetic_item(EXTERNAL_A))
        updated = update_research_case(
            case,
            action_plan,
            acquisition_plan,
            readiness_plan,
            updated_iteration,
            evidence_intake=intake,
            evidence_provenance=provenance,
        )
        self.assertEqual(updated["case_id"], case["case_id"])
        self.assertEqual(updated["iteration_count"], 2)
        self.assertEqual(len(updated["history"]), 2)
        self.assertEqual(updated["history"][0]["status"], CASE_WAITING_FOR_EVIDENCE)
        self.assertEqual(updated["history"][-1]["status"], CASE_ACTIVE)
        self.assertEqual(updated["status"], CASE_ACTIVE)
        self.assertEqual(
            updated["current_iteration"]["status"], CASE_ACTIVE
        )
        self.assertFalse(updated["history_truncated"])

    def test_history_limit_truncation(self):
        hypotheses = [hypothesis()]
        case, stages = build(hypotheses, limit=2)
        action_plan, acquisition_plan, readiness_plan, _ = stages
        (
            _,
            _,
            _,
            updated_iteration,
            intake,
            provenance,
        ) = with_evidence(hypotheses, synthetic_item(EXTERNAL_A))
        current = case
        for _ in range(3):
            current = update_research_case(
                current,
                action_plan,
                acquisition_plan,
                readiness_plan,
                updated_iteration,
                evidence_intake=intake,
                evidence_provenance=provenance,
            )
        self.assertEqual(current["iteration_count"], 4)
        self.assertEqual(len(current["history"]), 2)
        self.assertTrue(current["history_truncated"])
        self.assertEqual(
            current["current_iteration"]["iteration_number"], 4
        )

    def test_update_program_mismatch(self):
        case, stages = build()
        action_plan, acquisition_plan, readiness_plan, iteration_plan = stages
        with self.assertRaises(ResearchCaseError) as caught:
            update_research_case(
                case,
                action_plan,
                acquisition_plan,
                readiness_plan,
                iteration_plan,
                program="other-program",
            )
        self.assertEqual(caught.exception.code, ERROR_PROGRAM_MISMATCH)

    def test_update_gap_mismatch(self):
        case, stages = build()
        action_plan, acquisition_plan, readiness_plan, iteration_plan = stages
        broken_action = dict(action_plan["actions"][0])
        broken_action["gap_id"] = "ENDPOINT_BEHAVIOR"
        with self.assertRaises(ResearchCaseError) as caught:
            update_research_case(
                case,
                {"actions": [broken_action]},
                acquisition_plan,
                readiness_plan,
                iteration_plan,
            )
        self.assertEqual(caught.exception.code, ERROR_GAP_MISMATCH)


class TestFailClosed(unittest.TestCase):
    def test_orphan_readiness_rejected(self):
        action_plan, acquisition_plan, _, iteration_plan = chain([hypothesis()])
        with self.assertRaises(ResearchCaseError) as caught:
            build_research_case(
                action_plan,
                acquisition_plan,
                {},
                iteration_plan,
                program="indeed",
            )
        self.assertEqual(caught.exception.code, ERROR_ORPHAN_READINESS)

    def test_orphan_feedback_rejected(self):
        action_plan, acquisition_plan, readiness_plan, _ = chain([hypothesis()])
        with self.assertRaises(ResearchCaseError) as caught:
            build_research_case(
                action_plan,
                acquisition_plan,
                readiness_plan,
                {},
                program="indeed",
            )
        self.assertEqual(caught.exception.code, ERROR_ORPHAN_FEEDBACK)

    def test_orphan_provenance_rejected(self):
        action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
            [hypothesis()]
        )
        with self.assertRaises(ResearchCaseError) as caught:
            build_research_case(
                action_plan,
                acquisition_plan,
                readiness_plan,
                iteration_plan,
                program="indeed",
                evidence_provenance={"records": [{"provenance_id": "PR1"}]},
            )
        self.assertEqual(caught.exception.code, ERROR_ORPHAN_PROVENANCE)

    def test_unknown_action_ref_rejected(self):
        case, _ = build()
        action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
            [hypothesis()]
        )
        with self.assertRaises(ResearchCaseError) as caught:
            build_research_case(
                action_plan,
                acquisition_plan,
                readiness_plan,
                iteration_plan,
                program="indeed",
                action_ref="A9",
            )
        self.assertEqual(caught.exception.code, ERROR_UNKNOWN_ACTION_REF)

    def test_malformed_input_rejected(self):
        with self.assertRaises(ResearchCaseError) as caught:
            build_research_cases(program="indeed")
        self.assertEqual(caught.exception.code, ERROR_MALFORMED_STAGE_INPUT)

    def test_sensitive_program_rejected(self):
        action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
            [hypothesis()]
        )
        for program in ("http://target.example", "10.0.0.7"):
            with self.subTest(program=program):
                with self.assertRaises(ResearchCaseError) as caught:
                    build_research_case(
                        action_plan,
                        acquisition_plan,
                        readiness_plan,
                        iteration_plan,
                        program=program,
                    )
                self.assertEqual(
                    caught.exception.code, ERROR_SENSITIVE_CASE_INPUT
                )

    def test_limit_validation(self):
        action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
            [hypothesis()]
        )
        for bad in (0, -1, True):
            with self.subTest(limit=bad):
                with self.assertRaises(ResearchCaseError) as caught:
                    build_research_case(
                        action_plan,
                        acquisition_plan,
                        readiness_plan,
                        iteration_plan,
                        program="indeed",
                        limit=bad,
                    )
                self.assertEqual(caught.exception.code, ERROR_LIMIT_INVALID)


class TestAggregation(unittest.TestCase):
    def test_workspace_and_case_summaries(self):
        hypotheses = [
            hypothesis(title="IDOR"),
            hypothesis(
                title="Recon",
                category="RECON",
                observations=[observation(PATH_RECON)],
                signals=[signal("RECON", "api_type=REST")],
            ),
        ]
        action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
            hypotheses
        )
        cases = build_research_cases(
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            program="indeed",
        )
        self.assertEqual(len(cases), 2)
        workspace = summarize_research_cases(cases)
        self.assertEqual(workspace["case_count"], 2)
        self.assertEqual(workspace["covered_hypotheses"], 2)
        self.assertEqual(
            workspace["status_bands"][CASE_WAITING_FOR_EVIDENCE], 2
        )
        self.assertFalse(workspace["human_review_required"])
        summary = summarize_research_case(cases[0])
        self.assertEqual(summary["rule_version"] if "rule_version" in summary else summary["case_version"], "R76-1")
        self.assertEqual(summary["status"], CASE_WAITING_FOR_EVIDENCE)
        self.assertEqual(summary["confirmation_state"], "NOT_CONFIRMED")

    def test_inputs_are_not_mutated(self):
        hypotheses = [hypothesis()]
        action_plan, acquisition_plan, readiness_plan, iteration_plan = chain(
            hypotheses
        )
        before = (
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
            json.dumps(readiness_plan),
            json.dumps(iteration_plan),
        )
        build_research_case(
            action_plan,
            acquisition_plan,
            readiness_plan,
            iteration_plan,
            program="indeed",
        )
        after = (
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
            json.dumps(readiness_plan),
            json.dumps(iteration_plan),
        )
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
