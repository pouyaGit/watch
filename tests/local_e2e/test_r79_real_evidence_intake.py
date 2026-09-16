"""Focused tests for the R79 real researcher evidence intake validation.

Tests are offline and pure. Archive-availability tests use injected stubs or
the real read-only environment when present; every evidence package used here
is clearly labelled NON-REAL/OFFLINE. No target interaction, no persistence,
no Mongo writes.
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
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)
from tests.local_e2e import r78_case_walkthrough as r78
from tests.local_e2e import r79_real_evidence_intake as r79

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
        "artifact_path": "",
        "source": "hermetic",
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


class _FakeCollection:
    def __init__(self, counts: dict | None = None):
        self.counts = counts or {}

    def count_documents(self, query):
        keys = sorted(query.keys())
        for candidate_keys, value in self.counts.items():
            if sorted(candidate_keys) == keys:
                return value
        return 0


class _FakeDatabase:
    def __init__(self, counts: dict):
        self.counts = counts

    def __getitem__(self, name):
        return _FakeCollection(self.counts.get(name, {}))


class _FakeClient:
    def __init__(self, counts: dict):
        self.counts = counts

    def get_default_database(self):
        return _FakeDatabase(self.counts)


def empty_client() -> _FakeClient:
    return _FakeClient(
        {
            "endpoints": {},
            "http": {},
            "urls": {},
        }
    )


def method_client() -> _FakeClient:
    return _FakeClient(
        {
            "endpoints": {
                (
                    "program_name",
                    "method",
                    "path",
                ): 1
            },
        }
    )


class TestR74InputContract(unittest.TestCase):
    def test_contract_documentation(self):
        contract = r79.R74_INPUT_CONTRACT
        self.assertEqual(contract["package_version"], "r74-1")
        for field in ("package_version", "items"):
            self.assertIn(field, contract["required_package_fields"])
        for field in (
            "hypothesis_ref",
            "requirement_kind",
            "effect",
            "source",
        ):
            self.assertIn(field, contract["required_item_fields"])
        self.assertEqual(
            contract["allowed_effects"],
            ("PROVIDES", "CONTRADICTS", "INVALIDATES"),
        )
        for source in (
            "EXISTING_CONTEXT",
            "STORED_RESPONSE",
            "HUMAN_REVIEW",
            "WATCH_DERIVED",
            "AUTHORIZED_TEST_CONTEXT",
        ):
            self.assertIn(source, contract["allowed_sources"])
        self.assertIn("METHOD_AUTH", contract["requirement_association"])
        self.assertIn("RESPONSE_BEHAVIOR", contract["requirement_association"])


class TestAvailabilityCheck(unittest.TestCase):
    def test_not_checked_without_uri(self):
        result = r79.real_evidence_availability(mongo_uri="")
        self.assertEqual(result["status"], r79.NOT_CHECKED)
        self.assertEqual(result["reason"], "NO_MONGO_URI")

    def test_not_available_with_empty_archive(self):
        result = r79.real_evidence_availability(empty_client())
        self.assertEqual(result["status"], r79.REAL_NOT_AVAILABLE)
        self.assertEqual(result["checks"]["method_observations"], 0)
        self.assertEqual(result["checks"]["response_observations"], 0)
        self.assertFalse(result["values_copied"])
        text = json.dumps(result)
        self.assertNotIn("://", text)
        self.assertNotIn("http://", text)

    def test_available_when_method_observation_exists(self):
        client = _FakeClient(
            {"endpoints": {("program_name", "method", "path"): 2}}
        )
        result = r79.real_evidence_availability(client)
        self.assertEqual(result["status"], r79.REAL_AVAILABLE)
        self.assertEqual(result["checks"]["method_observations"], 2)

    def test_available_when_response_observation_exists(self):
        client = _FakeClient(
            {"http": {("program_name", "status_code", "url"): 3}}
        )
        result = r79.real_evidence_availability(client)
        self.assertEqual(result["status"], r79.REAL_AVAILABLE)
        self.assertEqual(result["checks"]["response_observations"], 3)

    def test_availability_never_copies_values(self):
        result = r79.real_evidence_availability(empty_client())
        self.assertFalse(result["values_copied"])
        text = json.dumps(result)
        self.assertNotIn("://", text)
        self.assertNotIn("authorization", text.lower())


class TestNonRealContractPath(unittest.TestCase):
    def test_non_real_packages_are_labelled_and_safe(self):
        for package in (
            r79.non_real_partial_package(),
            r79.non_real_complete_package(),
            r79.non_real_conflict_package(),
        ):
            text = json.dumps(package)
            self.assertIn(r79.NON_REAL_LABEL, text)
            self.assertNotIn("://", text)
            self.assertNotIn("sk-", text)
            self.assertNotIn("Bearer", text)
            for item in package["items"]:
                self.assertEqual(item["source"], "HUMAN_REVIEW")
                self.assertIn(
                    item["requirement_kind"],
                    ("METHOD_AUTH", "RESPONSE_BEHAVIOR"),
                )

    def test_offline_contract_transitions(self):
        result = r79.validate_real_evidence_intake(
            stages=hermetic_stages(),
            availability={
                "status": r79.REAL_NOT_AVAILABLE,
                "reason": "test",
                "checks": {},
                "values_copied": False,
            },
        )
        self.assertEqual(result["rule_version"], "r79-1")
        self.assertFalse(result["real_evidence_available"])
        self.assertEqual(
            result["real_evidence_status"], r79.REAL_NOT_AVAILABLE
        )
        contract = result["non_real_contract_validation"]
        self.assertEqual(contract["label"], r79.NON_REAL_LABEL)
        partial = contract["partial"]
        self.assertEqual(partial["package_status"], "ACCEPTED")
        self.assertEqual(partial["sufficiency_after"], "PARTIALLY_SUFFICIENT")
        self.assertEqual(partial["feedback_state"], "EVIDENCE_GAP_REDUCED")
        self.assertEqual(partial["hypothesis_state"], "REFINE")
        self.assertEqual(partial["next_iteration"], "CONTINUE")
        self.assertEqual(partial["relations"], ["NEW"])
        complete = contract["complete"]
        self.assertEqual(complete["sufficiency_after"], "SUFFICIENT_FOR_REVIEW")
        self.assertEqual(complete["decision_after"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(
            complete["feedback_state"], "HYPOTHESIS_REQUIRES_REVIEW"
        )
        self.assertEqual(complete["next_iteration"], "HUMAN_REVIEW")
        self.assertIn("DUPLICATE", complete["relations"])
        self.assertTrue(contract["case_updates"]["identity_preserved"])
        workbench = contract["workbench"]
        self.assertEqual(workbench["before"]["status"], "WAITING_FOR_EVIDENCE")
        self.assertEqual(workbench["before"]["missing"], ["METHOD_AUTH", "RESPONSE_BEHAVIOR"])
        self.assertEqual(workbench["after_partial"]["status"], "ACTIVE")
        self.assertEqual(workbench["after_partial"]["missing"], ["RESPONSE_BEHAVIOR"])
        self.assertEqual(
            workbench["after_complete"]["status"], "READY_FOR_HUMAN_REVIEW"
        )
        self.assertEqual(workbench["after_complete"]["missing"], [])
        self.assertTrue(workbench["after_complete"]["human_review"])
        self.assertIn(
            "HUMAN_REVIEW", workbench["after_complete"]["next"]
        )

    def test_negative_validations(self):
        result = r79.validate_real_evidence_intake(
            stages=hermetic_stages(),
            availability={"status": r79.REAL_NOT_AVAILABLE, "checks": {}},
        )
        negatives = result["negative_validations"]
        for name in (
            "missing_required_field",
            "invalid_canonical_reference",
            "sensitive_data",
            "duplicate_evidence",
            "contradictory_evidence",
        ):
            self.assertIn(name, negatives)
            self.assertTrue(negatives[name]["passed"], name)
            self.assertEqual(negatives[name]["label"], r79.NON_REAL_LABEL)
        contradiction = negatives["contradictory_evidence"]
        self.assertEqual(contradiction["conflict_state"], "CONFLICTING")
        self.assertEqual(contradiction["conflict_count"], 1)
        self.assertFalse(contradiction["resolved"])
        text = json.dumps(negatives)
        self.assertNotIn(r79.SENSITIVE_FACT, text)
        self.assertNotIn("://", text)

    def test_deterministic_output(self):
        first = r79.validate_real_evidence_intake(
            stages=hermetic_stages(),
            availability={"status": r79.REAL_NOT_AVAILABLE, "checks": {}},
        )
        second = r79.validate_real_evidence_intake(
            stages=hermetic_stages(),
            availability={"status": r79.REAL_NOT_AVAILABLE, "checks": {}},
        )
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_inputs_are_not_mutated(self):
        stages = hermetic_stages()
        before = (
            json.dumps(stages["case"]),
            json.dumps(stages["action_plan"]),
            json.dumps(stages["acquisition_plan"]),
        )
        r79.validate_real_evidence_intake(
            stages=stages,
            availability={"status": r79.REAL_NOT_AVAILABLE, "checks": {}},
        )
        after = (
            json.dumps(stages["case"]),
            json.dumps(stages["action_plan"]),
            json.dumps(stages["acquisition_plan"]),
        )
        self.assertEqual(before, after)

    def test_safety_and_no_persistence(self):
        result = r79.validate_real_evidence_intake(
            stages=hermetic_stages(),
            availability={"status": r79.REAL_NOT_AVAILABLE, "checks": {}},
        )
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["research_only"])
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        source = inspect.getsource(r79)
        for forbidden in (
            "write_text(",
            "persist_result(",
            "insert_one(",
            "insert_many(",
            "update_one(",
            "update_many(",
            "delete_one(",
            "delete_many(",
            "bulk_write(",
            "import subprocess",
            "import socket",
            "import requests",
            "from openai",
        ):
            self.assertNotIn(forbidden, source, forbidden)

    def test_no_real_relabelling(self):
        result = r79.validate_real_evidence_intake(
            stages=hermetic_stages(),
            availability={
                "status": r79.REAL_NOT_AVAILABLE,
                "reason": "no genuine observations",
                "checks": {},
            },
        )
        self.assertFalse(result["real_evidence_available"])
        self.assertEqual(
            result["real_evidence_status"], r79.REAL_NOT_AVAILABLE
        )
        text = json.dumps(result)
        self.assertNotIn("://", text)
        self.assertNotIn("Bearer", text)


@unittest.skipUnless(
    ARTIFACT_AVAILABLE, "real R77 artifact not present in this environment"
)
class TestRealArtifactRun(unittest.TestCase):
    def test_real_case_and_honest_availability(self):
        result = r79.validate_real_evidence_intake()
        self.assertEqual(
            result["primary_case"]["case_id"], r79.PRIMARY_CASE_ID
        )
        self.assertEqual(
            result["primary_case"]["blocking_codes"],
            ["METHOD_AUTH", "RESPONSE_BEHAVIOR"],
        )
        self.assertIn(
            result["real_evidence_status"],
            (r79.REAL_NOT_AVAILABLE, r79.NOT_CHECKED, r79.REAL_AVAILABLE),
        )
        if result["real_evidence_status"] != r79.REAL_AVAILABLE:
            self.assertFalse(result["real_evidence_available"])
        self.assertFalse(result["availability"]["values_copied"])

    def test_artifact_untouched(self):
        before = ARTIFACT.read_bytes()
        r79.validate_real_evidence_intake()
        self.assertEqual(before, ARTIFACT.read_bytes())

    def test_negative_validations_on_real_stages(self):
        result = r79.validate_real_evidence_intake()
        for name, entry in result["negative_validations"].items():
            self.assertTrue(entry["passed"], name)


if __name__ == "__main__":
    unittest.main()
