"""Focused tests for the R74 external evidence intake adapter.

All tests are offline and pure: R74 consumes real R70 action plans, real R71
acquisition plans and real R72 readiness records built from
validated-hypothesis-shaped mappings. External evidence packages are synthetic
and bounded. No provider, Mongo, network or file system access happens here.
"""

from __future__ import annotations

import json
import unittest

from ai.knowledge.research_decision_readiness_planner import (
    plan_decision_readiness,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    SOURCE_AUTHORIZED_TEST_CONTEXT,
    plan_evidence_acquisition,
)
from ai.knowledge.research_evidence_intake import (
    INTAKE_REJECTION_CODES,
    INTAKE_SOURCES,
    INTAKE_SOURCE_TO_BUNDLE_SOURCE,
    MAX_FACT_CHARS,
    MAX_PACKAGE_ITEMS,
    MAX_REF_CHARS,
    PACKAGE_STATUSES,
    PACKAGE_VERSION,
    REJECTION_AMBIGUOUS_EVIDENCE,
    REJECTION_DUPLICATE_EVIDENCE,
    REJECTION_EXECUTION_INSTRUCTION,
    REJECTION_INVALID_EVIDENCE_REF,
    REJECTION_INVALID_SOURCE,
    REJECTION_MALFORMED_EVIDENCE,
    REJECTION_PACKAGE_TOO_LARGE,
    REJECTION_SENSITIVE_EVIDENCE,
    REJECTION_UNKNOWN_HYPOTHESIS,
    REJECTION_UNKNOWN_INVALIDATED_REF,
    REJECTION_UNKNOWN_REQUIREMENT,
    REJECTION_UNSUPPORTED_EFFECT,
    REJECTION_UNSUPPORTED_PACKAGE_VERSION,
    RULE_VERSION,
    SOURCE_ACQUISITION_RULE_VERSION,
    SOURCE_ACTION_RULE_VERSION,
    SOURCE_FEEDBACK_RULE_VERSION,
    SOURCE_READINESS_RULE_VERSION,
    STATUS_ACCEPTED,
    STATUS_NOT_PROVIDED,
    STATUS_PARTIAL,
    STATUS_REJECTED,
    intake_and_reevaluate,
    normalize_evidence_package,
)
from ai.knowledge.research_feedback_loop import (
    EVIDENCE_REF_KINDS,
    SOURCE_STORED_RESPONSE,
)
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)
from tests.local_e2e import r64_research as r64

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PATH_RECON = "path:/api/internal/brand/theme/style-sheet"
PARAM = "parameter:client"
RESPONSE_REF = "response:jobs-response-1"
AUTH_REF = "authorization:owner-comparison-1"
STATUS_REF = "status:404-on-other-principal"
EXTERNAL_AUTH = "authorization:external-owner-comparison-1"
EXTERNAL_RESPONSE = "response:external-ownership-binding-1"


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


def evaluate(hypotheses, package):
    action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
    return intake_and_reevaluate(
        package,
        hypotheses=hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )


def package(*items, version: str = PACKAGE_VERSION) -> dict:
    return {"package_version": version, "items": list(items)}


def item(
    requirement_kind: str,
    ref: str,
    *,
    hypothesis_ref: str = "H1",
    effect: str = "PROVIDES",
    source: str = "HUMAN_REVIEW",
    **extra,
) -> dict:
    payload = {
        "hypothesis_ref": hypothesis_ref,
        "requirement_kind": requirement_kind,
        "effect": effect,
        "source": source,
        "evidence_ref": ref,
        "observations": [{"ref": ref, "fact": f"external {ref.partition(':')[2]}"}],
    }
    payload.update(extra)
    return payload


def invalidating(ref: str, *, hypothesis_ref: str = "H1") -> dict:
    return {
        "hypothesis_ref": hypothesis_ref,
        "effect": "INVALIDATES",
        "source": "HUMAN_REVIEW",
        "invalidates_refs": [ref],
    }


STRUCTURAL = [hypothesis()]
COMPLETE = [
    hypothesis(
        observations=[
            observation(PATH_OBJECT),
            observation(RESPONSE_REF),
            observation(AUTH_REF),
        ]
    )
]


class TestValidIntake(unittest.TestCase):
    def test_provides_is_accepted_and_reevaluates(self):
        result = evaluate(
            STRUCTURAL, package(item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH))
        )
        self.assertEqual(result["rule_version"], RULE_VERSION)
        self.assertEqual(RULE_VERSION, "r74-1")
        self.assertEqual(
            (SOURCE_ACTION_RULE_VERSION, SOURCE_ACQUISITION_RULE_VERSION,
             SOURCE_READINESS_RULE_VERSION, SOURCE_FEEDBACK_RULE_VERSION),
            ("r70-1", "r71-1", "r72-1", "r73-1"),
        )
        self.assertEqual(result["package_status"], STATUS_ACCEPTED)
        self.assertEqual(result["accepted_external_evidence"], 1)
        self.assertEqual(result["rejections"], [])
        accepted = result["accepted_items"][0]
        self.assertEqual(accepted["intake_id"], "EI1")
        self.assertEqual(accepted["hypothesis_ref"], "H1")
        self.assertEqual(accepted["requirement_kind"], "AUTHORIZATION_OUTCOME")
        self.assertEqual(accepted["effect"], "PROVIDES")
        self.assertEqual(accepted["source"], "HUMAN_REVIEW")
        self.assertEqual(
            result["summary"]["top_readiness_before"], "INSUFFICIENT"
        )
        self.assertEqual(
            result["summary"]["top_readiness_after"], "PARTIALLY_SUFFICIENT"
        )
        self.assertEqual(
            result["summary"]["top_feedback_state"], "EVIDENCE_GAP_REDUCED"
        )
        self.assertEqual(result["summary"]["top_current_state"], "REFINE")
        self.assertEqual(result["summary"]["top_next_iteration"], "CONTINUE")

    def test_contradicts_is_accepted(self):
        result = evaluate(
            STRUCTURAL,
            package(item("AUTHORIZATION_OUTCOME", RESPONSE_REF, effect="CONTRADICTS")),
        )
        self.assertEqual(result["package_status"], STATUS_ACCEPTED)
        iteration = result["reevaluation"]["feedback"]["iterations"][0]
        self.assertEqual(
            iteration["feedback_state"], "NEW_CONTRADICTING_EVIDENCE"
        )
        self.assertIn(
            iteration["current_state"], ("STOP", "WEAKEN")
        )

    def test_invalidates_is_accepted(self):
        result = evaluate(
            COMPLETE, package(invalidating(AUTH_REF))
        )
        self.assertEqual(result["package_status"], STATUS_ACCEPTED)
        delta = result["reevaluation"]["feedback"]["iterations"][0][
            "evidence_delta"
        ]
        self.assertEqual(
            {entry["requirement_kind"] for entry in delta},
            {"AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"},
        )
        self.assertTrue(
            all(entry["cause"] == "INVALIDATION" for entry in delta)
        )
        self.assertEqual(
            result["summary"]["top_readiness_after"], "INSUFFICIENT"
        )

    def test_full_completion_transitions_to_human_review(self):
        result = evaluate(
            STRUCTURAL,
            package(
                item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH),
                item("OWNERSHIP_BINDING", EXTERNAL_RESPONSE),
            ),
        )
        self.assertEqual(result["accepted_external_evidence"], 2)
        self.assertEqual(
            [entry["intake_id"] for entry in result["accepted_items"]],
            ["EI1", "EI2"],
        )
        self.assertEqual(
            result["summary"]["top_readiness_after"], "SUFFICIENT_FOR_REVIEW"
        )
        self.assertEqual(
            result["summary"]["top_feedback_state"],
            "HYPOTHESIS_REQUIRES_REVIEW",
        )
        self.assertEqual(result["summary"]["top_current_state"], "STOP")
        self.assertEqual(
            result["summary"]["top_next_iteration"], "HUMAN_REVIEW"
        )

    def test_authorized_test_context_source_is_mapped(self):
        result = evaluate(
            STRUCTURAL,
            package(
                item(
                    "AUTHORIZATION_OUTCOME",
                    EXTERNAL_AUTH,
                    source=SOURCE_AUTHORIZED_TEST_CONTEXT,
                )
            ),
        )
        self.assertEqual(result["package_status"], STATUS_ACCEPTED)
        self.assertEqual(
            result["accepted_items"][0]["source"],
            SOURCE_AUTHORIZED_TEST_CONTEXT,
        )
        self.assertEqual(
            result["accepted_items"][0]["bundle_source"],
            SOURCE_STORED_RESPONSE,
        )
        self.assertEqual(
            result["bundle"]["items"][0]["source"], SOURCE_STORED_RESPONSE
        )

    def test_empty_package_is_accepted_noop(self):
        result = evaluate(STRUCTURAL, package())
        self.assertEqual(result["package_status"], STATUS_ACCEPTED)
        self.assertEqual(result["accepted_external_evidence"], 0)
        self.assertEqual(result["reevaluation"]["transitions"], [])
        self.assertEqual(
            result["summary"]["top_feedback_state"], "EVIDENCE_GAP_REMAINS"
        )


class TestPackageValidation(unittest.TestCase):
    def test_missing_package_is_not_provided(self):
        result = evaluate(STRUCTURAL, None)
        self.assertEqual(result["package_status"], STATUS_NOT_PROVIDED)
        self.assertEqual(result["accepted_external_evidence"], 0)
        self.assertEqual(result["rejections"], [])
        self.assertIn(result["package_status"], PACKAGE_STATUSES)

    def test_malformed_package_is_rejected(self):
        result = evaluate(STRUCTURAL, ["not-a-package"])
        self.assertEqual(result["package_status"], STATUS_REJECTED)
        self.assertEqual(
            [entry["code"] for entry in result["package_rejections"]],
            [REJECTION_MALFORMED_EVIDENCE],
        )

    def test_unsupported_package_version(self):
        result = evaluate(STRUCTURAL, package(version="r99-9"))
        self.assertEqual(result["package_status"], STATUS_REJECTED)
        self.assertEqual(
            [entry["code"] for entry in result["package_rejections"]],
            [REJECTION_UNSUPPORTED_PACKAGE_VERSION],
        )

    def test_package_too_large(self):
        items = [
            item("AUTHORIZATION_OUTCOME", f"authorization:ref-{index}")
            for index in range(MAX_PACKAGE_ITEMS + 1)
        ]
        result = evaluate(STRUCTURAL, package(*items))
        self.assertEqual(result["package_status"], STATUS_REJECTED)
        self.assertEqual(
            [entry["code"] for entry in result["package_rejections"]],
            [REJECTION_PACKAGE_TOO_LARGE],
        )

    def test_items_must_be_a_list(self):
        result = evaluate(
            STRUCTURAL, {"package_version": PACKAGE_VERSION, "items": "nope"}
        )
        self.assertEqual(result["package_status"], STATUS_REJECTED)

    def test_partial_acceptance(self):
        result = evaluate(
            STRUCTURAL,
            package(
                item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH),
                item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH, hypothesis_ref="H9"),
            ),
        )
        self.assertEqual(result["package_status"], STATUS_PARTIAL)
        self.assertEqual(result["accepted_external_evidence"], 1)
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_UNKNOWN_HYPOTHESIS],
        )

    def test_all_rejected_package(self):
        result = evaluate(
            STRUCTURAL,
            package(item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH, hypothesis_ref="H9")),
        )
        self.assertEqual(result["package_status"], STATUS_REJECTED)
        self.assertEqual(result["accepted_external_evidence"], 0)

    def test_unknown_requirement_rejected(self):
        result = evaluate(
            STRUCTURAL,
            package(item("NOT_A_REQUIREMENT", EXTERNAL_AUTH)),
        )
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_UNKNOWN_REQUIREMENT],
        )

    def test_invalid_effect_and_source_rejected(self):
        bad_effect = evaluate(
            STRUCTURAL,
            package(
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "AUTHORIZATION_OUTCOME",
                    "effect": "CONFIRMS",
                    "source": "HUMAN_REVIEW",
                    "observations": [observation(EXTERNAL_AUTH)],
                }
            ),
        )
        self.assertEqual(
            [entry["code"] for entry in bad_effect["rejections"]],
            [REJECTION_UNSUPPORTED_EFFECT],
        )
        bad_source = evaluate(
            STRUCTURAL,
            package(
                item(
                    "AUTHORIZATION_OUTCOME",
                    EXTERNAL_AUTH,
                    source="RANDOM_PROCESS",
                )
            ),
        )
        self.assertEqual(
            [entry["code"] for entry in bad_source["rejections"]],
            [REJECTION_INVALID_SOURCE],
        )

    def test_invalid_evidence_ref_rejected(self):
        for ref in ("not-a-ref", "unknownkind:value", ":value", "response:"):
            with self.subTest(ref=ref):
                result = evaluate(
                    STRUCTURAL,
                    package(item("AUTHORIZATION_OUTCOME", ref)),
                )
                self.assertEqual(
                    [entry["code"] for entry in result["rejections"]],
                    [REJECTION_INVALID_EVIDENCE_REF],
                )

    def test_unknown_invalidated_ref_rejected(self):
        result = evaluate(
            STRUCTURAL, package(invalidating("response:never-seen"))
        )
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_UNKNOWN_INVALIDATED_REF],
        )

    def test_ambiguous_redacted_refs_rejected(self):
        hypotheses = [
            hypothesis(
                observations=[
                    observation(PATH_OBJECT),
                    observation("authorization:owner-a"),
                    observation("authorization:owner-b"),
                ]
            )
        ]
        result = evaluate(hypotheses, package(invalidating("authorization:owner-a")))
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_AMBIGUOUS_EVIDENCE],
        )

    def test_duplicate_evidence_rejected(self):
        result = evaluate(
            STRUCTURAL,
            package(
                item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH),
                item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH),
            ),
        )
        self.assertEqual(result["package_status"], STATUS_PARTIAL)
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_DUPLICATE_EVIDENCE],
        )
        self.assertEqual(result["accepted_external_evidence"], 1)

    def test_rejection_codes_are_closed(self):
        result = evaluate(
            STRUCTURAL,
            package(
                "nope",
                item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH, hypothesis_ref="H9"),
                item("NOPE", EXTERNAL_AUTH),
            ),
        )
        for entry in result["rejections"]:
            self.assertIn(entry["code"], INTAKE_REJECTION_CODES)
        for key in ("accepted_items", "bundle"):
            self.assertIn(key, result)


class TestSensitiveAndExecutionGates(unittest.TestCase):
    def test_sensitive_evidence_rejected(self):
        secret = "supersecretvalue12345"
        cases = (
            ("response:token=abc123", "fact"),
            ("response:http://target.example/x", "fact"),
            ("response:10.0.0.7", "fact"),
            ("response:507f1f77bcf86cd799439011", "fact"),
            ("response:ok", f"authorization token={secret}"),
        )
        for ref, fact in cases:
            with self.subTest(ref=ref):
                result = evaluate(
                    STRUCTURAL,
                    package(
                        item(
                            "AUTHORIZATION_OUTCOME",
                            ref,
                            observations=[{"ref": ref, "fact": fact}],
                        )
                    ),
                )
                self.assertIn(
                    REJECTION_SENSITIVE_EVIDENCE,
                    [entry["code"] for entry in result["rejections"]],
                )
                text = json.dumps(result)
                self.assertNotIn(secret, text)
                self.assertNotIn("://", text)

    def test_execution_instructions_rejected(self):
        for text in ("curl target", "sqlmap -u target", "nuclei -u x"):
            with self.subTest(text=text):
                result = evaluate(
                    STRUCTURAL,
                    package(
                        item(
                            "AUTHORIZATION_OUTCOME",
                            "response:stored-observation",
                            observations=[
                                {
                                    "ref": "response:stored-observation",
                                    "fact": text,
                                }
                            ],
                        )
                    ),
                )
                self.assertEqual(
                    [entry["code"] for entry in result["rejections"]],
                    [REJECTION_EXECUTION_INSTRUCTION],
                )


class TestNormalizationAndDeterminism(unittest.TestCase):
    def test_bounded_strings(self):
        long_fact = "x" * (MAX_FACT_CHARS + 50)
        result = evaluate(
            STRUCTURAL,
            package(
                item(
                    "AUTHORIZATION_OUTCOME",
                    EXTERNAL_AUTH,
                    observations=[
                        {"ref": EXTERNAL_AUTH, "fact": long_fact}
                    ],
                )
            ),
        )
        accepted = result["accepted_items"][0]
        self.assertLessEqual(
            len(accepted["observations"][0]["fact"]), MAX_FACT_CHARS
        )

    def test_overlong_ref_rejected(self):
        long_ref = "response:" + "y" * (MAX_REF_CHARS + 10)
        result = evaluate(
            STRUCTURAL, package(item("AUTHORIZATION_OUTCOME", long_ref))
        )
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_INVALID_EVIDENCE_REF],
        )

    def test_too_many_observations_rejected(self):
        observations = [
            {"ref": f"response:r{index}", "fact": "f"} for index in range(9)
        ]
        result = evaluate(
            STRUCTURAL,
            package(
                {
                    "hypothesis_ref": "H1",
                    "requirement_kind": "AUTHORIZATION_OUTCOME",
                    "effect": "PROVIDES",
                    "source": "HUMAN_REVIEW",
                    "observations": observations,
                }
            ),
        )
        self.assertEqual(
            [entry["code"] for entry in result["rejections"]],
            [REJECTION_MALFORMED_EVIDENCE],
        )

    def test_canonical_intake_ids_and_deterministic_order(self):
        result = evaluate(
            STRUCTURAL,
            package(
                item("OWNERSHIP_BINDING", "response:z-last"),
                item("AUTHORIZATION_OUTCOME", "authorization:a-first"),
            ),
        )
        accepted = result["accepted_items"]
        self.assertEqual(
            [entry["intake_id"] for entry in accepted], ["EI1", "EI2"]
        )
        self.assertEqual(
            [entry["requirement_kind"] for entry in accepted],
            ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"],
        )
        repeat = evaluate(
            STRUCTURAL,
            package(
                item("OWNERSHIP_BINDING", "response:z-last"),
                item("AUTHORIZATION_OUTCOME", "authorization:a-first"),
            ),
        )
        self.assertEqual(json.dumps(result), json.dumps(repeat))

    def test_r68_compatibility_of_reference_vocabulary(self):
        for kind in r64.REF_KINDS + r64.CORROBORATING_REF_KINDS:
            self.assertIn(kind, EVIDENCE_REF_KINDS, kind)
        result = evaluate(
            STRUCTURAL,
            package(item("AUTHORIZATION_OUTCOME", "response:r68-canonical-1")),
        )
        self.assertEqual(result["package_status"], STATUS_ACCEPTED)

    def test_inputs_are_not_mutated(self):
        hypotheses = STRUCTURAL
        action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
        before = (
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
            json.dumps(readiness_plan),
        )
        intake_and_reevaluate(
            package(item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH)),
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        after = (
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
            json.dumps(readiness_plan),
        )
        self.assertEqual(before, after)

    def test_correlation_is_preserved(self):
        hypotheses = [
            hypothesis(title="First IDOR"),
            hypothesis(title="Second IDOR"),
        ]
        result = evaluate(
            hypotheses,
            package(item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH, hypothesis_ref="H2")),
        )
        feedback = result["reevaluation"]["feedback"]
        self.assertEqual(len(feedback["iterations"]), 1)
        self.assertEqual(
            feedback["iterations"][0]["hypothesis_refs"], ["H1", "H2"]
        )
        self.assertEqual(len(result["reevaluation"]["transitions"]), 1)


class TestSafety(unittest.TestCase):
    def test_safety_flags_forced(self):
        result = evaluate(
            STRUCTURAL, package(item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH))
        )
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertTrue(result["research_only"])
        self.assertEqual(result["summary"]["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(result["safety"]["execution_performed"])
        self.assertFalse(result["safety"]["vulnerability_confirmed"])
        self.assertFalse(result["safety"]["exploit_authorized"])
        self.assertTrue(result["safety"]["human_authority_required"])

    def test_no_confirmation_or_execution_semantics(self):
        result = evaluate(
            STRUCTURAL, package(item("AUTHORIZATION_OUTCOME", EXTERNAL_AUTH))
        )
        payload = json.loads(json.dumps(result))
        payload.pop("safety", None)
        payload["reevaluation"]["feedback"].pop("safety", None)
        for iteration in payload["reevaluation"]["feedback"]["iterations"]:
            iteration.pop("safety", None)
        text = (
            json.dumps(payload)
            .upper()
            .replace("NOT_CONFIRMED", "")
            .replace("VULNERABILITY_CONFIRMED", "")
            .replace("IS CONFIRMED", "")
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

    def test_sources_vocabulary_is_closed(self):
        self.assertIn(SOURCE_AUTHORIZED_TEST_CONTEXT, INTAKE_SOURCES)
        self.assertEqual(
            set(INTAKE_SOURCE_TO_BUNDLE_SOURCE), set(INTAKE_SOURCES)
        )
        for key in INTAKE_REJECTION_CODES:
            self.assertTrue(key)


if __name__ == "__main__":
    unittest.main()
