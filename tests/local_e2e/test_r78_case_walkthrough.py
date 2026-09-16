"""Focused tests for the R78 first real research case walkthrough.

The suite is offline and pure. Artifact-based tests run against the existing
real R77 artifact when present and skip otherwise; hermetic tests use a
bounded synthetic real-shaped chain so the walkthrough logic is always
exercised. No provider, network, Mongo or persistence access happens here.
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
from ai.knowledge.research_evidence_intake import (
    intake_and_reevaluate,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import plan_research_actions
from tests.local_e2e import r78_case_walkthrough as r78

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


def _hypothesis() -> dict:
    return {
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


def hermetic_stages() -> dict:
    hypotheses = [_hypothesis()]
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
        "artifact_path": "",
        "source": "synthetic",
        "program": "indeed",
        "research_run_version": "r77-1",
        "case_id": case["case_id"],
        "case": case,
        "hypotheses": hypotheses,
        "action_plan": action_plan,
        "acquisition_plan": acquisition_plan,
        "readiness_plan": readiness_plan,
        "iteration_plan": iteration_plan,
        "evidence_intake": {},
        "evidence_provenance": {},
        "research_case_workspace": {"cases": [case]},
        "research_workbench": {},
    }


def roundtrip_chain(stages: dict) -> dict:
    partial = r78.run_evidence_roundtrip(
        stages, r78.synthetic_method_auth_package()
    )
    partial_case = r78.update_case_with_evidence(stages, stages["case"], partial)
    partial_stages = r78.effective_stages(stages, partial)
    complete = r78.run_evidence_roundtrip(
        partial_stages,
        r78.synthetic_complete_package(),
        previous_provenance=partial["provenance"],
    )
    complete_case = r78.update_case_with_evidence(
        partial_stages, partial_case, complete
    )
    conflict = r78.run_evidence_roundtrip(
        partial_stages,
        r78.synthetic_conflict_package(),
        previous_provenance=partial["provenance"],
    )
    conflict_case = r78.update_case_with_evidence(
        partial_stages, partial_case, conflict
    )
    return {
        "partial": partial,
        "partial_case": partial_case,
        "partial_stages": partial_stages,
        "complete": complete,
        "complete_case": complete_case,
        "conflict": conflict,
        "conflict_case": conflict_case,
    }


class TestHermeticWalkthrough(unittest.TestCase):
    def test_researcher_action_from_existing_plan(self):
        action = r78.researcher_action(hermetic_stages())
        self.assertEqual(action["acquisition_method"], "HTTP_BEHAVIOR_REVIEW")
        kinds = [item["requirement_kind"] for item in action["requirements"]]
        self.assertEqual(kinds, ["METHOD_AUTH", "RESPONSE_BEHAVIOR"])
        for item in action["requirements"]:
            self.assertTrue(item["decision_critical"])
            self.assertTrue(item["description"])
        self.assertTrue(action["objective"])
        self.assertTrue(action["stopping_condition"])
        self.assertTrue(action["sources"])

    def test_partial_roundtrip(self):
        stages = hermetic_stages()
        partial = r78.run_evidence_roundtrip(
            stages, r78.synthetic_method_auth_package()
        )
        self.assertEqual(partial["package_status"], "ACCEPTED")
        self.assertEqual(partial["accepted_count"], 1)
        self.assertEqual(partial["rejections"], [])
        relations = [
            record["relation_to_previous"]
            for record in partial["provenance"]["records"]
        ]
        self.assertEqual(relations, ["NEW"])
        record = partial["readiness_after"]["records"][0]
        self.assertEqual(record["sufficiency_state"], "PARTIALLY_SUFFICIENT")
        self.assertEqual(record["decision_state"], "NEEDS_EVIDENCE")
        iteration = partial["iteration"]
        self.assertEqual(iteration["feedback_state"], "EVIDENCE_GAP_REDUCED")
        self.assertEqual(iteration["current_state"], "REFINE")
        self.assertEqual(iteration["next_iteration"], "CONTINUE")

    def test_complete_roundtrip_and_duplicate(self):
        chain = roundtrip_chain(hermetic_stages())
        complete = chain["complete"]
        self.assertEqual(complete["package_status"], "ACCEPTED")
        record = complete["readiness_after"]["records"][0]
        self.assertEqual(record["sufficiency_state"], "SUFFICIENT_FOR_REVIEW")
        self.assertEqual(record["decision_state"], "READY_FOR_HUMAN_REVIEW")
        iteration = complete["iteration"]
        self.assertEqual(
            iteration["feedback_state"], "HYPOTHESIS_REQUIRES_REVIEW"
        )
        self.assertEqual(iteration["current_state"], "STOP")
        self.assertEqual(iteration["next_iteration"], "HUMAN_REVIEW")
        relations = [
            record["relation_to_previous"]
            for record in complete["provenance"]["records"]
        ]
        self.assertIn("DUPLICATE", relations)
        self.assertIn("NEW", relations)

    def test_case_update_preserves_identity(self):
        stages = hermetic_stages()
        chain = roundtrip_chain(stages)
        updated = chain["partial_case"]
        base = stages["case"]
        self.assertEqual(updated["case_id"], base["case_id"])
        self.assertEqual(updated["action_ref"], base["action_ref"])
        self.assertEqual(updated["gap_id"], base["gap_id"])
        self.assertEqual(
            updated["hypothesis_refs"], base["hypothesis_refs"]
        )
        self.assertEqual(updated["iteration_count"], 2)
        self.assertEqual(len(updated["history"]), 2)
        self.assertEqual(updated["status"], "ACTIVE")
        self.assertEqual(
            updated["history"][0]["status"], "WAITING_FOR_EVIDENCE"
        )
        self.assertEqual(updated["history"][1]["status"], "ACTIVE")

    def test_workbench_after_update(self):
        stages = hermetic_stages()
        chain = roundtrip_chain(stages)
        partial_workbench = r78.render_workbench(
            stages, chain["partial_case"], chain["partial"]["provenance"]
        )
        known = partial_workbench["what_we_know"]
        self.assertIn("METHOD_AUTH", known["available_requirement_kinds"])
        self.assertEqual(
            partial_workbench["what_is_missing"]["decision_critical_missing"],
            ["RESPONSE_BEHAVIOR"],
        )
        complete_workbench = r78.render_workbench(
            stages, chain["complete_case"], chain["complete"]["provenance"]
        )
        self.assertEqual(
            complete_workbench["current_state"]["status"],
            "READY_FOR_HUMAN_REVIEW",
        )
        self.assertEqual(
            complete_workbench["what_is_missing"]["decision_critical_missing"],
            [],
        )
        self.assertTrue(complete_workbench["human_review"]["required"])
        actions = [
            step["action"] for step in complete_workbench["next_steps"]
        ]
        self.assertIn("HUMAN_REVIEW", actions)

    def test_conflict_scenario_preserved(self):
        chain = roundtrip_chain(hermetic_stages())
        conflict = chain["conflict"]
        record = conflict["provenance"]["records"][0]
        self.assertEqual(
            record["relation_to_previous"], "CONTRADICTS_EXISTING"
        )
        self.assertEqual(record["conflict_state"], "CONFLICTING")
        conflicts = conflict["provenance"]["conflicts"]
        self.assertEqual(len(conflicts), 1)
        self.assertTrue(conflicts[0]["existing_evidence_refs"])
        self.assertTrue(conflicts[0]["new_evidence_refs"])
        case = chain["conflict_case"]
        self.assertEqual(case["status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(
            case["stopping_reason"], "CONFLICT_REQUIRES_HUMAN_REVIEW"
        )
        self.assertTrue(case["human_review_required"])
        workbench = r78.render_workbench(
            hermetic_stages(), case, conflict["provenance"]
        )
        self.assertFalse(workbench["conflicts"]["resolved"])
        self.assertIn(
            "CONFLICT_REQUIRES_HUMAN_REVIEW",
            workbench["human_review"]["reasons"],
        )
        self.assertNotIn("winner", json.dumps(workbench).lower())

    def test_stopped_scenario(self):
        stopped = r78.build_stopped_case(hermetic_stages())
        self.assertEqual(stopped["case"]["status"], "STOPPED")
        self.assertEqual(
            stopped["case"]["stopping_reason"], "RESEARCH_BASIS_REMOVED"
        )
        workbench = stopped["workbench"]
        self.assertEqual(workbench["current_state"]["status"], "STOPPED")
        actions = [step["action"] for step in workbench["next_steps"]]
        self.assertIn("STOP", actions)
        self.assertTrue(workbench["human_review"]["required"])

    def test_synthetic_packages_are_safe(self):
        for package in (
            r78.synthetic_method_auth_package(),
            r78.synthetic_complete_package(),
            r78.synthetic_conflict_package(),
        ):
            text = json.dumps(package)
            self.assertNotIn("://", text)
            self.assertNotIn("sk-", text)
            self.assertNotIn("Bearer", text)
            self.assertIn(r78.SYNTHETIC_LABEL, text)
            for item in package["items"]:
                self.assertEqual(item["source"], "HUMAN_REVIEW")
                self.assertTrue(item["evidence_ref"].partition(":")[0])
                self.assertIn(
                    item["requirement_kind"],
                    ("METHOD_AUTH", "RESPONSE_BEHAVIOR"),
                )

    def test_inputs_are_not_mutated(self):
        stages = hermetic_stages()
        before = (
            json.dumps(stages["case"]),
            json.dumps(stages["action_plan"]),
            json.dumps(stages["acquisition_plan"]),
            json.dumps(stages["readiness_plan"]),
        )
        roundtrip_chain(stages)
        after = (
            json.dumps(stages["case"]),
            json.dumps(stages["action_plan"]),
            json.dumps(stages["acquisition_plan"]),
            json.dumps(stages["readiness_plan"]),
        )
        self.assertEqual(before, after)

    def test_module_does_not_rerun_research_or_persist(self):
        source = inspect.getsource(r78)
        for forbidden in (
            "plan_research_actions(",
            "plan_evidence_acquisition(",
            "plan_decision_readiness(",
            "write_text(",
            "persist_result(",
            "import subprocess",
            "import socket",
            "import requests",
            "from pymongo",
            "from openai",
        ):
            self.assertNotIn(forbidden, source, forbidden)


@unittest.skipUnless(
    ARTIFACT_AVAILABLE, "real R77 artifact not present in this environment"
)
class TestRealArtifactWalkthrough(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stages = r78.load_real_case()

    def test_real_case_identity_and_stages(self):
        stages = self.stages
        self.assertEqual(stages["case_id"], r78.REAL_CASE_ID)
        self.assertEqual(stages["program"], "indeed")
        case = stages["case"]
        self.assertEqual(case["action_ref"], "A1")
        self.assertEqual(case["gap_id"], "ENDPOINT_BEHAVIOR")
        self.assertEqual(case["hypothesis_refs"], ["H1"])
        self.assertEqual(case["readiness"]["readiness_ref"], "R1")
        self.assertEqual(case["feedback"]["iteration_ref"], "I1")
        self.assertEqual(case["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(
            case["readiness"]["blocking_codes"],
            ["METHOD_AUTH", "RESPONSE_BEHAVIOR"],
        )

    def test_full_walkthrough_transitions(self):
        result = r78.walkthrough()
        self.assertEqual(result["rule_version"], "r78-1")
        self.assertEqual(
            result["real"]["case_id"], r78.REAL_CASE_ID
        )
        self.assertEqual(
            result["partial"]["readiness_after"]["records"][0][
                "sufficiency_state"
            ],
            "PARTIALLY_SUFFICIENT",
        )
        self.assertEqual(
            result["complete"]["readiness_after"]["records"][0][
                "sufficiency_state"
            ],
            "SUFFICIENT_FOR_REVIEW",
        )
        self.assertEqual(
            result["conflict"]["provenance"]["conflicts"][0][
                "requirement_kind"
            ],
            "METHOD_AUTH",
        )
        self.assertEqual(
            result["stopped"]["case"]["status"], "STOPPED"
        )
        self.assertEqual(
            result["stopped"]["case"]["stopping_reason"],
            "RESEARCH_BASIS_REMOVED",
        )

    def test_artifact_untouched_by_walkthrough(self):
        path = Path(self.stages["artifact_path"])
        before = path.read_bytes()
        r78.walkthrough(path)
        self.assertEqual(before, path.read_bytes())

    def test_synthetic_boundary_labels(self):
        result = r78.walkthrough()
        self.assertEqual(result["synthetic_label"], "SYNTHETIC/OFFLINE")
        text = json.dumps(result)
        self.assertNotIn("://", text)
        self.assertNotIn("sk-", text)
        self.assertNotIn("Bearer", text)
        self.assertNotIn("vulnerable", text.lower())
        self.assertNotIn("exploitable", text.lower())


if __name__ == "__main__":
    unittest.main()
