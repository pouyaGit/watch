"""Focused R80 tests: submission boundary + downstream composition.

Hermetic tests run on a real-shaped chain; the real-artifact tests run against
the existing R80/R77 artifact when present. Every package is labelled
NON-REAL/OFFLINE. No target interaction, no persistence, no Mongo writes.
"""

from __future__ import annotations

import inspect
import json
import unittest
from pathlib import Path

from ai.knowledge.research_case_workspace import build_research_case
from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_evidence_submission import (
    RULE_VERSION as SUBMISSION_RULE_VERSION,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)
from tests.local_e2e import r78_case_walkthrough as r78
from tests.local_e2e import r80_research_evidence_submission as r80

ARTIFACT = Path(r78.REAL_ARTIFACT_DEFAULT)
ARTIFACT_AVAILABLE = ARTIFACT.is_file()

PATH_RECON = "path:/api/internal/brand/theme/style-sheet"


def _observation(ref: str, fact: str = "") -> dict:
    return {
        "ref": ref,
        "fact": fact or f"observed {ref.partition(':')[2]}",
        "source": "context",
    }


def _signal(name: str, detail: str = "") -> dict:
    return {"signal": name, "detail": detail, "source": "watch_derived"}


def hermetic_stages() -> dict:
    hypotheses = [
        {
            "title": "Versioned internal REST API surface",
            "category": "RECON",
            "priority": "MEDIUM",
            "confidence": "MEDIUM",
            "evidence": {
                "observations": [_observation(PATH_RECON)],
                "derived_signals": [_signal("RECON", "api_type=REST")],
            },
            "selected_evidence_refs": ["E1"],
            "inference": "Structural observation only.",
            "why_interesting": "Uncertainty depends on behavior evidence.",
            "missing_evidence": ["HTTP method and auth requirement"],
            "next_safe_action": "Review stored records for the endpoint.",
        }
    ]
    action_plan = plan_research_actions(hypotheses)
    acquisition_plan = plan_evidence_acquisition(action_plan)
    readiness_plan = plan_decision_readiness(action_plan, acquisition_plan)
    iteration_plan = evaluate_research_iteration(
        hypotheses,
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
    )
    return {
        "hypotheses": hypotheses,
        "action_plan": action_plan,
        "acquisition_plan": acquisition_plan,
        "readiness_plan": readiness_plan,
        "iteration_plan": iteration_plan,
        "case": case,
    }


class TestDownstreamComposition(unittest.TestCase):
    def test_partial_submission_updates_case_and_workbench(self):
        stages = hermetic_stages()
        result = r80.run_submission_path(
            stages,
            stages["case"],
            [r80.submission_item(r80.METHOD_REF)],
        )
        self.assertEqual(result["submission"]["status"], "ACCEPTED")
        case = result["case"]
        self.assertEqual(case["case_id"], stages["case"]["case_id"])
        self.assertEqual(case["status"], "ACTIVE")
        self.assertEqual(
            case["readiness"]["sufficiency_state"], "PARTIALLY_SUFFICIENT"
        )
        self.assertEqual(len(case["history"]), 2)
        workbench = result["workbench"]
        self.assertIn(
            "METHOD_AUTH",
            workbench["what_we_know"]["available_requirement_kinds"],
        )
        self.assertEqual(
            workbench["what_is_missing"]["decision_critical_missing"],
            ["RESPONSE_BEHAVIOR"],
        )

    def test_complete_submission_reaches_human_review(self):
        stages = hermetic_stages()
        partial = r80.run_submission_path(
            stages,
            stages["case"],
            [r80.submission_item(r80.METHOD_REF)],
        )
        complete = r80.run_submission_path(
            partial["effective_stages"],
            partial["case"],
            [
                r80.submission_item(r80.METHOD_REF),
                r80.submission_item(
                    r80.RESPONSE_REF, kind="RESPONSE_BEHAVIOR"
                ),
            ],
            previous_provenance=partial["provenance"],
        )
        case = complete["case"]
        self.assertEqual(case["status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(
            case["stopping_reason"], "DECISION_EVIDENCE_COMPLETE"
        )
        workbench = complete["workbench"]
        self.assertEqual(
            workbench["current_state"]["status"], "READY_FOR_HUMAN_REVIEW"
        )
        self.assertEqual(
            workbench["what_is_missing"]["decision_critical_missing"], []
        )
        self.assertTrue(workbench["human_review"]["required"])

    def test_rejected_submission_does_not_touch_case(self):
        stages = hermetic_stages()
        base = json.dumps(stages["case"])
        result = r80.run_submission_path(
            stages,
            stages["case"],
            [r80.submission_item(r80.METHOD_REF)],
            case_ref="case-other",
        )
        self.assertIsNone(result["case"])
        self.assertIsNone(result["provenance"])
        self.assertEqual(json.dumps(stages["case"]), base)

    def test_conflict_preserved_through_boundary(self):
        stages = hermetic_stages()
        partial = r80.run_submission_path(
            stages,
            stages["case"],
            [r80.submission_item("response:nonreal-test-prior-1")],
        )
        contradiction = r80.run_submission_path(
            stages,
            stages["case"],
            [
                r80.submission_item(
                    "response:nonreal-test-conflict-1", effect="CONTRADICTS"
                )
            ],
            previous_provenance=partial["provenance"],
        )
        records = contradiction["provenance"]["records"]
        self.assertEqual(records[0]["conflict_state"], "CONFLICTING")
        self.assertEqual(
            records[0]["relation_to_previous"], "CONTRADICTS_EXISTING"
        )
        self.assertFalse(
            contradiction["workbench"]["conflicts"]["resolved"]
        )
        self.assertTrue(
            contradiction["workbench"]["human_review"]["required"]
        )

    def test_negative_submissions_all_pass(self):
        stages = hermetic_stages()
        results = r80.negative_submissions(stages, stages["case"])
        for name, entry in results.items():
            self.assertTrue(entry["passed"], name)
            self.assertEqual(entry["label"], "NON-REAL/OFFLINE")

    def test_validate_structure_with_injected_availability(self):
        result = r80.validate(
            stages=hermetic_stages(),
            availability={
                "status": "REAL_EVIDENCE_NOT_AVAILABLE",
                "reason": "test",
                "checks": {},
                "values_copied": False,
            },
        )
        self.assertEqual(result["rule_version"], "r80-1")
        self.assertEqual(
            result["real_evidence"]["status"], "REAL_EVIDENCE_NOT_AVAILABLE"
        )
        self.assertEqual(
            result["partial_submission"]["case_status"], "ACTIVE"
        )
        self.assertEqual(
            result["complete_submission"]["case_status"],
            "READY_FOR_HUMAN_REVIEW",
        )
        self.assertTrue(result["complete_submission"]["human_review_required"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["research_only"])

    def test_fixtures_are_labelled_and_safe(self):
        item = r80.submission_item(r80.METHOD_REF)
        text = json.dumps(item)
        self.assertIn("NON-REAL/OFFLINE", text)
        self.assertNotIn("://", text)
        self.assertNotIn("Bearer", text)

    def test_determinism_and_input_immutability(self):
        stages = hermetic_stages()
        before = (
            json.dumps(stages["case"]),
            json.dumps(stages["action_plan"]),
        )
        first = r80.validate(
            stages=stages,
            availability={"status": "REAL_EVIDENCE_NOT_AVAILABLE", "checks": {}},
        )
        second = r80.validate(
            stages=hermetic_stages(),
            availability={"status": "REAL_EVIDENCE_NOT_AVAILABLE", "checks": {}},
        )
        after = (
            json.dumps(stages["case"]),
            json.dumps(stages["action_plan"]),
        )
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(before, after)

    def test_safety_and_no_persistence(self):
        result = r80.validate(
            stages=hermetic_stages(),
            availability={"status": "REAL_EVIDENCE_NOT_AVAILABLE", "checks": {}},
        )
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        source = inspect.getsource(r80)
        for forbidden in (
            "write_text(",
            "persist_result(",
            "insert_one(",
            "update_one(",
            "import subprocess",
            "import socket",
            "import requests",
            "from pymongo",
        ):
            self.assertNotIn(forbidden, source, forbidden)

    def test_submission_rule_version(self):
        self.assertEqual(SUBMISSION_RULE_VERSION, "r80-1")


@unittest.skipUnless(
    ARTIFACT_AVAILABLE, "real R77 artifact not present in this environment"
)
class TestRealArtifactSubmission(unittest.TestCase):
    def test_real_case_submission_transitions(self):
        result = r80.validate()
        self.assertEqual(
            result["primary_case"]["case_id"], r80.PRIMARY_CASE_ID
        )
        self.assertIn(
            result["real_evidence"]["status"],
            (
                "REAL_EVIDENCE_NOT_AVAILABLE",
                "NOT_CHECKED",
                "REAL_EVIDENCE_AVAILABLE",
            ),
        )
        self.assertEqual(
            result["partial_submission"]["case_status"], "ACTIVE"
        )
        self.assertEqual(
            result["complete_submission"]["case_status"],
            "READY_FOR_HUMAN_REVIEW",
        )
        self.assertEqual(
            result["complete_submission"]["workbench_missing"], []
        )
        self.assertTrue(result["complete_submission"]["human_review_required"])
        self.assertFalse(result["real_evidence"]["values_copied"])
        for name, entry in result["negative_submissions"].items():
            self.assertTrue(entry["passed"], name)

    def test_artifact_untouched(self):
        before = ARTIFACT.read_bytes()
        r80.validate()
        self.assertEqual(before, ARTIFACT.read_bytes())


if __name__ == "__main__":
    unittest.main()
