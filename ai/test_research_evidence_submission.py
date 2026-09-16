"""Focused tests for the R80 evidence submission boundary (adapter only).

All tests are offline and pure: the boundary consumes a hermetic real-shaped
chain and delegates to the existing R74 authority. Every package is clearly
labelled NON-REAL/OFFLINE. No provider, network, Mongo or persistence access.
"""

from __future__ import annotations

import inspect
import json
import unittest

from ai.knowledge.research_case_workspace import build_research_case
from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_evidence_submission import (
    ERROR_CASE_MISMATCH,
    ERROR_CASE_REF_REQUIRED,
    ERROR_CASE_STATE_UNAVAILABLE,
    ERROR_EXECUTION_CONTENT,
    ERROR_HYPOTHESIS_NOT_IN_CASE,
    ERROR_MALFORMED_ENVELOPE,
    ERROR_SENSITIVE_SUBMISSION,
    ERROR_SUBMISSION_TOO_LARGE,
    ERROR_SUBMITTER_NOT_ALLOWED,
    ERROR_UNKNOWN_CASE,
    ERROR_UNKNOWN_REQUIREMENT_FOR_CASE,
    ERROR_UNSUPPORTED_SUBMISSION_VERSION,
    REJECTION_CODES,
    RULE_VERSION,
    STATUS_SUBMISSION_REJECTED,
    SUBMISSION_VERSION,
    submit_research_evidence,
)
from ai.knowledge.research_feedback_loop import evaluate_research_iteration
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)

PATH_RECON = "path:/api/internal/brand/theme/style-sheet"
SECRET = "supersecretvalue12345"


def observation(ref: str, fact: str = "") -> dict:
    return {
        "ref": ref,
        "fact": fact or f"observed {ref.partition(':')[2]}",
        "source": "context",
    }


def signal(name: str, detail: str = "") -> dict:
    return {"signal": name, "detail": detail, "source": "watch_derived"}


def hermetic_chain() -> dict:
    hypotheses = [
        {
            "title": "Versioned internal REST API surface",
            "category": "RECON",
            "priority": "MEDIUM",
            "confidence": "MEDIUM",
            "evidence": {
                "observations": [observation(PATH_RECON)],
                "derived_signals": [signal("RECON", "api_type=REST")],
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


def submission_item(
    ref: str,
    *,
    kind: str = "METHOD_AUTH",
    effect: str = "PROVIDES",
    hypothesis_ref: str = "H1",
    source: str = "HUMAN_REVIEW",
) -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": kind,
        "effect": effect,
        "source": source,
        "evidence_ref": ref,
        "observations": [
            {
                "ref": ref,
                "fact": f"NON-REAL/OFFLINE submission fixture for {kind}",
            }
        ],
    }


def envelope(items, *, chain: dict, case_ref=None, submitted_by="", version=SUBMISSION_VERSION):
    return {
        "submission_version": version,
        "case_ref": chain["case"]["case_id"] if case_ref is None else case_ref,
        "submitted_by": submitted_by,
        "items": list(items),
    }


def submit(items, chain, **kwargs) -> dict:
    return submit_research_evidence(
        envelope(items, chain=chain, **kwargs),
        case=chain["case"],
        hypotheses=chain["hypotheses"],
        action_plan=chain["action_plan"],
        acquisition_plan=chain["acquisition_plan"],
        readiness_plan=chain["readiness_plan"],
    )


def code_of(result: dict) -> str:
    return (result.get("rejections") or [{}])[0].get("code", "")


class TestValidSubmission(unittest.TestCase):
    def test_valid_submission_delegates_to_r74(self):
        chain = hermetic_chain()
        result = submit([submission_item("response:nonreal-submit-1")], chain)
        self.assertEqual(result["rule_version"], RULE_VERSION)
        self.assertEqual(result["rule_version"], "r80-1")
        self.assertEqual(result["submission_version"], SUBMISSION_VERSION)
        self.assertEqual(result["status"], "ACCEPTED")
        self.assertEqual(result["case_ref"], chain["case"]["case_id"])
        self.assertEqual(result["item_count"], 1)
        self.assertEqual(result["rejections"], [])
        intake = result["intake"]
        self.assertIsInstance(intake, dict)
        self.assertEqual(intake["rule_version"], "r74-1")
        self.assertEqual(intake["accepted_external_evidence"], 1)
        self.assertIn("reevaluation", intake)
        record = intake["reevaluation"]["readiness_after"]["records"][0]
        self.assertEqual(record["sufficiency_state"], "PARTIALLY_SUFFICIENT")

    def test_complete_submission_transitions_readiness(self):
        chain = hermetic_chain()
        result = submit(
            [
                submission_item("response:nonreal-submit-2"),
                submission_item(
                    "response:nonreal-submit-3", kind="RESPONSE_BEHAVIOR"
                ),
            ],
            chain,
        )
        self.assertEqual(result["status"], "ACCEPTED")
        record = result["intake"]["reevaluation"]["readiness_after"]["records"][0]
        self.assertEqual(record["sufficiency_state"], "SUFFICIENT_FOR_REVIEW")
        self.assertEqual(record["decision_state"], "READY_FOR_HUMAN_REVIEW")
        feedback = result["intake"]["reevaluation"]["feedback"]["iterations"][0]
        self.assertEqual(feedback["feedback_state"], "HYPOTHESIS_REQUIRES_REVIEW")
        self.assertEqual(feedback["next_iteration"], "HUMAN_REVIEW")

    def test_submitter_label_is_bounded_and_optional(self):
        chain = hermetic_chain()
        with_label = submit(
            [submission_item("response:nonreal-submit-4")],
            chain,
            submitted_by="authorized-researcher-1",
        )
        self.assertEqual(with_label["submitted_by"], "authorized-researcher-1")
        without = submit([submission_item("response:nonreal-submit-4")], chain)
        self.assertEqual(without["submitted_by"], "")

    def test_delegated_rejections_surface_from_r74(self):
        chain = hermetic_chain()
        result = submit(
            [
                submission_item(
                    "response:nonreal-submit-5", source="RANDOM_PROCESS"
                )
            ],
            chain,
        )
        self.assertEqual(result["status"], "REJECTED")
        self.assertIn(
            "INVALID_EVIDENCE_SOURCE",
            [entry["code"] for entry in result["intake"]["rejections"]],
        )

    def test_duplicate_items_delegated(self):
        chain = hermetic_chain()
        result = submit(
            [
                submission_item("response:nonreal-dup-1"),
                submission_item("response:nonreal-dup-1"),
            ],
            chain,
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn(
            "DUPLICATE_EVIDENCE",
            [entry["code"] for entry in result["intake"]["rejections"]],
        )

    def test_contradicting_item_is_not_judged_by_the_boundary(self):
        chain = hermetic_chain()
        result = submit(
            [
                submission_item(
                    "response:nonreal-contradict-1", effect="CONTRADICTS"
                )
            ],
            chain,
        )
        self.assertEqual(result["status"], "ACCEPTED")
        self.assertEqual(result["rejections"], [])


class TestBindingRejections(unittest.TestCase):
    def test_wrong_case_ref_rejected(self):
        chain = hermetic_chain()
        result = submit(
            [submission_item("response:nonreal-wrongcase-1")],
            chain,
            case_ref="case-somewhere-else",
        )
        self.assertEqual(result["status"], STATUS_SUBMISSION_REJECTED)
        self.assertEqual(code_of(result), ERROR_CASE_MISMATCH)
        self.assertIsNone(result["intake"])

    def test_missing_case_ref_rejected(self):
        chain = hermetic_chain()
        result = submit(
            [submission_item("response:nonreal-nocase-1")], chain, case_ref=""
        )
        self.assertEqual(code_of(result), ERROR_CASE_REF_REQUIRED)

    def test_unknown_case_rejected(self):
        chain = hermetic_chain()
        result = submit_research_evidence(
            envelope(
                [submission_item("response:nonreal-unknowncase-1")],
                chain=chain,
            ),
            case={},
        )
        self.assertEqual(code_of(result), ERROR_UNKNOWN_CASE)

    def test_unsupported_version_rejected(self):
        chain = hermetic_chain()
        result = submit(
            [submission_item("response:nonreal-version-1")],
            chain,
            version="r99-9",
        )
        self.assertEqual(code_of(result), ERROR_UNSUPPORTED_SUBMISSION_VERSION)

    def test_requirement_not_in_case_rejected(self):
        chain = hermetic_chain()
        result = submit(
            [
                submission_item(
                    "response:nonreal-wrongreq-1", kind="TOKEN_VALIDATION"
                )
            ],
            chain,
        )
        self.assertEqual(
            code_of(result), ERROR_UNKNOWN_REQUIREMENT_FOR_CASE
        )
        self.assertIsNone(result["intake"])

    def test_hypothesis_not_in_case_rejected(self):
        chain = hermetic_chain()
        result = submit(
            [
                submission_item(
                    "response:nonreal-wronghyp-1", hypothesis_ref="H9"
                )
            ],
            chain,
        )
        self.assertEqual(code_of(result), ERROR_HYPOTHESIS_NOT_IN_CASE)

    def test_case_state_unavailable_rejected(self):
        chain = hermetic_chain()
        result = submit_research_evidence(
            envelope(
                [submission_item("response:nonreal-nostate-1")],
                chain=chain,
            ),
            case=chain["case"],
        )
        self.assertEqual(code_of(result), ERROR_CASE_STATE_UNAVAILABLE)

    def test_malformed_envelopes_rejected(self):
        chain = hermetic_chain()
        cases = (
            None,
            "not-a-submission",
            {
                "submission_version": SUBMISSION_VERSION,
                "case_ref": chain["case"]["case_id"],
                "items": "nope",
            },
            {
                "submission_version": SUBMISSION_VERSION,
                "case_ref": chain["case"]["case_id"],
                "items": [],
            },
            {
                "submission_version": SUBMISSION_VERSION,
                "case_ref": chain["case"]["case_id"],
                "items": ["not-a-mapping"],
            },
        )
        for envelope_payload in cases:
            with self.subTest(envelope=envelope_payload):
                result = submit_research_evidence(
                    envelope_payload,
                    case=chain["case"],
                    hypotheses=chain["hypotheses"],
                    action_plan=chain["action_plan"],
                    acquisition_plan=chain["acquisition_plan"],
                    readiness_plan=chain["readiness_plan"],
                )
                self.assertEqual(
                    code_of(result), ERROR_MALFORMED_ENVELOPE
                )

    def test_oversized_submission_rejected(self):
        chain = hermetic_chain()
        items = [
            submission_item(f"response:nonreal-bulk-{index}")
            for index in range(17)
        ]
        result = submit(items, chain)
        self.assertEqual(code_of(result), ERROR_SUBMISSION_TOO_LARGE)


class TestBoundarySafety(unittest.TestCase):
    def test_submitter_personal_data_rejected(self):
        chain = hermetic_chain()
        for label in (
            "researcher@example.com",
            "+1 555 010 9999",
            "http://profile.example",
            "10.0.0.7",
        ):
            with self.subTest(label=label):
                result = submit(
                    [submission_item("response:nonreal-sub-1")],
                    chain,
                    submitted_by=label,
                )
                self.assertEqual(code_of(result), ERROR_SUBMITTER_NOT_ALLOWED)

    def test_sensitive_evidence_rejected_before_r74(self):
        chain = hermetic_chain()
        packages = (
            [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "METHOD_AUTH",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "observations": [
                        {
                            "ref": "response:nonreal-sensitive-1",
                            "fact": f"authorization token={SECRET}",
                        }
                    ],
                }
            ],
            [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "METHOD_AUTH",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "observations": [
                        {
                            "ref": "response:token=abc123",
                            "fact": "stored observation",
                        }
                    ],
                }
            ],
            [
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "METHOD_AUTH",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "observations": [
                        {
                            "ref": "response:nonreal-sensitive-2",
                            "fact": "http://target.example/path",
                        }
                    ],
                }
            ],
        )
        for items in packages:
            with self.subTest(items=items):
                result = submit(items, chain)
                self.assertEqual(
                    code_of(result), ERROR_SENSITIVE_SUBMISSION
                )
                self.assertIsNone(result["intake"])
                text = json.dumps(result)
                self.assertNotIn(SECRET, text)
                self.assertNotIn("://", text)

    def test_execution_content_rejected(self):
        chain = hermetic_chain()
        for fact in ("curl target", "sqlmap -u target", "nuclei -u x"):
            with self.subTest(fact=fact):
                result = submit(
                    [
                        {
                            "hypothesis_ref": "H1",
                            "requirement_kind": "METHOD_AUTH",
                            "effect": "PROVIDES",
                            "source": "HUMAN_REVIEW",
                            "observations": [
                                {
                                    "ref": "response:nonreal-exec-1",
                                    "fact": fact,
                                }
                            ],
                        }
                    ],
                    chain,
                )
                self.assertEqual(code_of(result), ERROR_EXECUTION_CONTENT)


class TestSafetyAndDeterminism(unittest.TestCase):
    def test_determinism_and_input_immutability(self):
        chain = hermetic_chain()
        first_envelope = envelope(
            [submission_item("response:nonreal-determinism-1")], chain=chain
        )
        before = (
            json.dumps(first_envelope),
            json.dumps(chain["case"]),
            json.dumps(chain["action_plan"]),
        )
        first = submit_research_evidence(
            first_envelope,
            case=chain["case"],
            hypotheses=chain["hypotheses"],
            action_plan=chain["action_plan"],
            acquisition_plan=chain["acquisition_plan"],
            readiness_plan=chain["readiness_plan"],
        )
        second = submit_research_evidence(
            envelope(
                [submission_item("response:nonreal-determinism-1")],
                chain=chain,
            ),
            case=chain["case"],
            hypotheses=chain["hypotheses"],
            action_plan=chain["action_plan"],
            acquisition_plan=chain["acquisition_plan"],
            readiness_plan=chain["readiness_plan"],
        )
        after = (
            json.dumps(first_envelope),
            json.dumps(chain["case"]),
            json.dumps(chain["action_plan"]),
        )
        self.assertEqual(json.dumps(first), json.dumps(second))
        self.assertEqual(before, after)

    def test_safety_flags(self):
        chain = hermetic_chain()
        result = submit([submission_item("response:nonreal-safety-1")], chain)
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(result["advisory"])
        self.assertTrue(result["research_only"])
        self.assertFalse(result["safety"]["execution_performed"])
        self.assertFalse(result["safety"]["vulnerability_confirmed"])
        self.assertFalse(result["safety"]["exploit_authorized"])
        self.assertTrue(result["safety"]["human_authority_required"])
        rejected = submit(
            [submission_item("response:nonreal-safety-2")],
            chain,
            case_ref="other",
        )
        self.assertEqual(rejected["safety"], SAFETY_BLOCK)

    def test_rejection_codes_are_closed(self):
        for code in REJECTION_CODES:
            self.assertTrue(code)

    def test_module_is_adapter_only(self):
        import ai.knowledge.research_evidence_submission as module

        source = inspect.getsource(module)
        for forbidden in (
            "plan_research_actions(",
            "plan_evidence_acquisition(",
            "plan_decision_readiness(",
            "evaluate_research_iteration(",
            "analyze_evidence_provenance(",
            "build_research_cases(",
            "update_research_case(",
            "write_text(",
            "persist_result(",
            "insert_one(",
            "update_one(",
            "import subprocess",
            "import socket",
            "import requests",
            "from pymongo",
            "from openai",
        ):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertIn("intake_and_reevaluate(", source)


if __name__ == "__main__":
    unittest.main()
