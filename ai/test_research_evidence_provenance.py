"""Focused tests for the R75 evidence provenance / conflict analysis layer.

All tests are offline and pure: R75 consumes real R70/R71/R72 state and real
R74 intake results built from validated-hypothesis-shaped mappings. External
evidence packages are synthetic and bounded. No provider, Mongo, network or
file system access happens here.
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
from ai.knowledge.research_evidence_intake import (
    RULE_VERSION as INTAKE_RULE_VERSION,
    STATUS_NOT_PROVIDED,
    normalize_evidence_package,
)
from ai.knowledge.research_evidence_provenance import (
    CONFLICT_PRESENT,
    PROVENANCE_COMPLETE,
    PROVENANCE_INVALID,
    PROVENANCE_MISSING,
    PROVENANCE_PARTIAL,
    PROVENANCE_STATES,
    RELATION_CONFLICTING,
    RELATION_CONTRADICTS_EXISTING,
    RELATION_DUPLICATE,
    RELATION_INVALIDATES_EXISTING,
    RELATION_NEW,
    RELATION_NONE,
    RELATION_SUPPORTS_EXISTING,
    RELATIONSHIPS,
    RULE_VERSION,
    SOURCE_INTAKE_RULE_VERSION,
    analyze_evidence_provenance,
)
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PARAM = "parameter:client"
STATUS_REF = "status:404-on-other-principal"
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
    return action_plan, acquisition_plan, readiness_plan


def intake_of(hypotheses, package):
    action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
    return normalize_evidence_package(
        package,
        hypotheses=hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
    )


def provenance(
    hypotheses,
    package,
    *,
    previous=None,
    intake_result=None,
):
    action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
    return analyze_evidence_provenance(
        intake_result,
        package=None if intake_result is not None else package,
        hypotheses=hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
        previous_provenance=previous,
    )


def package(*items, version: str = "r74-1") -> dict:
    return {"package_version": version, "items": list(items)}


def item(
    ref: str,
    *,
    requirement_kind: str = "AUTHORIZATION_OUTCOME",
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
        "observations": [{"ref": ref, "fact": f"synthetic {ref.partition(':')[2]}"}],
    }
    payload.update(extra)
    return payload


STRUCTURAL = [hypothesis()]
INTERNAL_AVAILABLE = [
    hypothesis(
        observations=[
            observation(PATH_OBJECT),
            observation(STATUS_REF),
        ]
    )
]


class TestProvenanceStates(unittest.TestCase):
    def test_complete_provenance(self):
        result = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_COMPLETE)
        self.assertEqual(record["evidence_ref"], EXTERNAL_A)
        self.assertEqual(record["evidence_refs"], [EXTERNAL_A])
        self.assertEqual(record["source"], "HUMAN_REVIEW")
        self.assertEqual(record["effect"], "PROVIDES")
        self.assertEqual(result["summary"]["complete_provenance"], 1)

    def test_partial_provenance_signal_only(self):
        payload = {
            "hypothesis_ref": "H1",
            "requirement_kind": "AUTHORIZATION_OUTCOME",
            "effect": "PROVIDES",
            "source": "WATCH_DERIVED",
            "derived_signals": [signal("IDOR", "object_reference=PATH_PARAMETER")],
        }
        result = provenance(STRUCTURAL, package(payload))
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_PARTIAL)
        self.assertEqual(record["relation_to_previous"], RELATION_NEW)

    def test_missing_provenance_from_rejection(self):
        result = provenance(
            STRUCTURAL, package(item(EXTERNAL_A, requirement_kind="NOT_A_REQ"))
        )
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_MISSING)
        self.assertEqual(record["relation_to_previous"], RELATION_NONE)
        self.assertEqual(record["evidence_refs"], [])
        self.assertEqual(result["summary"]["missing_provenance"], 1)

    def test_invalid_provenance_from_rejection(self):
        payload = item(EXTERNAL_A)
        payload["observations"] = [
            {"ref": EXTERNAL_A, "fact": "curl target.example"}
        ]
        result = provenance(STRUCTURAL, package(payload))
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_INVALID)
        self.assertEqual(result["summary"]["invalid_provenance"], 1)

    def test_package_rejection_becomes_invalid_record(self):
        result = provenance(STRUCTURAL, package(version="r99-9"))
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_INVALID)
        self.assertEqual(record["evidence_id"], "XP1")
        self.assertEqual(record["reason"], "UNSUPPORTED_PACKAGE_VERSION")

    def test_states_are_closed(self):
        for package_payload in (
            package(item(EXTERNAL_A)),
            package(item(EXTERNAL_A, requirement_kind="NOPE")),
            package("malformed"),
        ):
            result = provenance(STRUCTURAL, package_payload)
            for record in result["records"]:
                self.assertIn(record["provenance_state"], PROVENANCE_STATES)
                self.assertIn(record["relation_to_previous"], RELATIONSHIPS)


class TestRelationships(unittest.TestCase):
    def test_new_evidence(self):
        result = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        self.assertEqual(
            result["records"][0]["relation_to_previous"], RELATION_NEW
        )

    def test_duplicate_against_previous_provenance(self):
        first = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        second = provenance(
            STRUCTURAL, package(item(EXTERNAL_A)), previous=first
        )
        record = second["records"][0]
        self.assertEqual(
            record["relation_to_previous"], RELATION_DUPLICATE
        )
        self.assertFalse(record["human_review_required"])
        self.assertEqual(record["conflict_state"], "NONE")

    def test_in_package_duplicate_becomes_invalid_duplicate(self):
        result = provenance(
            STRUCTURAL, package(item(EXTERNAL_A), item(EXTERNAL_A))
        )
        self.assertEqual(len(result["records"]), 2)
        relations = {
            record["relation_to_previous"] for record in result["records"]
        }
        self.assertIn(RELATION_NEW, relations)
        self.assertIn(RELATION_DUPLICATE, relations)
        duplicate = [
            record
            for record in result["records"]
            if record["relation_to_previous"] == RELATION_DUPLICATE
        ][0]
        self.assertEqual(duplicate["provenance_state"], PROVENANCE_INVALID)
        self.assertEqual(duplicate["reason"], "DUPLICATE_EVIDENCE")

    def test_supports_existing_vs_previous_provenance(self):
        first = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        second = provenance(
            STRUCTURAL, package(item(EXTERNAL_B)), previous=first
        )
        self.assertEqual(
            second["records"][0]["relation_to_previous"],
            RELATION_SUPPORTS_EXISTING,
        )
        self.assertFalse(second["summary"]["human_review_required"])

    def test_supports_existing_vs_internal_evidence(self):
        result = provenance(
            INTERNAL_AVAILABLE, package(item(EXTERNAL_A))
        )
        record = result["records"][0]
        self.assertEqual(
            record["relation_to_previous"], RELATION_SUPPORTS_EXISTING
        )
        self.assertEqual(record["conflict_state"], "NONE")

    def test_contradicts_existing_internal_evidence(self):
        result = provenance(
            INTERNAL_AVAILABLE,
            package(item(EXTERNAL_B, effect="CONTRADICTS")),
        )
        record = result["records"][0]
        self.assertEqual(
            record["relation_to_previous"], RELATION_CONTRADICTS_EXISTING
        )
        self.assertEqual(record["conflict_state"], CONFLICT_PRESENT)
        self.assertTrue(record["human_review_required"])
        self.assertEqual(len(result["conflicts"]), 1)
        conflict = result["conflicts"][0]
        self.assertTrue(conflict["existing_evidence_refs"])
        self.assertEqual(conflict["new_evidence_refs"], [EXTERNAL_B])

    def test_conflicting_prior_contradiction(self):
        contradiction = provenance(
            STRUCTURAL,
            package(item(EXTERNAL_B, effect="CONTRADICTS")),
        )
        result = provenance(
            STRUCTURAL, package(item(EXTERNAL_A)), previous=contradiction
        )
        record = result["records"][0]
        self.assertEqual(
            record["relation_to_previous"], RELATION_CONFLICTING
        )
        self.assertEqual(record["conflict_state"], CONFLICT_PRESENT)
        self.assertTrue(record["human_review_required"])
        self.assertEqual(
            record["conflict_basis"]["existing_evidence_refs"], [EXTERNAL_B]
        )
        self.assertEqual(
            record["conflict_basis"]["new_evidence_refs"], [EXTERNAL_A]
        )

    def test_in_package_conflict_detected(self):
        result = provenance(
            STRUCTURAL,
            package(
                item(EXTERNAL_A),
                item(EXTERNAL_B, effect="CONTRADICTS"),
            ),
        )
        self.assertEqual(len(result["conflicts"]), 1)
        relations = {
            record["relation_to_previous"] for record in result["records"]
        }
        self.assertTrue(
            relations & {RELATION_CONFLICTING, RELATION_CONTRADICTS_EXISTING}
        )
        self.assertTrue(result["summary"]["human_review_required"])

    def test_invalidates_existing(self):
        result = provenance(
            INTERNAL_AVAILABLE,
            package(
                {
                    "hypothesis_ref": "H1",
                    "effect": "INVALIDATES",
                    "source": "HUMAN_REVIEW",
                    "invalidates_refs": [STATUS_REF],
                }
            ),
        )
        record = result["records"][0]
        self.assertEqual(
            record["relation_to_previous"], RELATION_INVALIDATES_EXISTING
        )
        self.assertEqual(record["evidence_refs"], [STATUS_REF])
        self.assertEqual(record["conflict_state"], "NONE")
        self.assertFalse(record["human_review_required"])

    def test_cross_hypothesis_isolation(self):
        hypotheses = [
            hypothesis(title="First IDOR"),
            hypothesis(title="Second IDOR"),
        ]
        result = provenance(
            hypotheses,
            package(
                item(EXTERNAL_A, hypothesis_ref="H1"),
                item(EXTERNAL_B, hypothesis_ref="H2", effect="CONTRADICTS"),
            ),
        )
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["conflicts"], [])
        self.assertFalse(result["summary"]["human_review_required"])
        relations = {
            record["relation_to_previous"] for record in result["records"]
        }
        self.assertEqual(relations, {RELATION_NEW})

    def test_correlated_hypotheses_share_the_research_unit(self):
        hypotheses = [
            hypothesis(title="First IDOR"),
            hypothesis(title="Second IDOR"),
        ]
        result = provenance(
            hypotheses,
            package(
                item(EXTERNAL_A, hypothesis_ref="H1"),
                item(EXTERNAL_B, hypothesis_ref="H2"),
            ),
        )
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(
            {record["hypothesis_ref"] for record in result["records"]},
            {"H1", "H2"},
        )
        for record in result["records"]:
            self.assertEqual(record["requirement_kind"], "AUTHORIZATION_OUTCOME")


class TestSafetyAndFailClosed(unittest.TestCase):
    def test_sensitive_evidence_never_leaks(self):
        secret = "supersecretvalue12345"
        payload = item(EXTERNAL_A)
        payload["observations"] = [
            {
                "ref": EXTERNAL_A,
                "fact": f"authorization token={secret}",
            }
        ]
        result = provenance(STRUCTURAL, package(payload))
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_INVALID)
        text = json.dumps(result)
        self.assertNotIn(secret, text)
        self.assertNotIn("://", text)

    def test_malformed_package_is_bounded(self):
        result = provenance(STRUCTURAL, ["not-a-package"])
        self.assertEqual(len(result["records"]), 1)
        record = result["records"][0]
        self.assertEqual(record["provenance_state"], PROVENANCE_INVALID)
        self.assertEqual(record["relation_to_previous"], RELATION_NONE)
        self.assertEqual(record["evidence_refs"], [])

    def test_no_not_provided_package(self):
        result = provenance(STRUCTURAL, None)
        self.assertEqual(result["package_status"], STATUS_NOT_PROVIDED)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["conflicts"], [])
        self.assertFalse(result["summary"]["human_review_required"])

    def test_safety_flags_forced(self):
        result = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertTrue(result["research_only"])
        self.assertEqual(
            result["summary"]["confirmation_state"], "NOT_CONFIRMED"
        )
        for record in result["records"]:
            self.assertEqual(record["safety"], SAFETY_BLOCK)
            self.assertEqual(record["confirmation_state"], "NOT_CONFIRMED")
            self.assertTrue(record["advisory"])
            self.assertTrue(record["research_only"])
        self.assertFalse(result["safety"]["execution_performed"])
        self.assertFalse(result["safety"]["vulnerability_confirmed"])
        self.assertFalse(result["safety"]["exploit_authorized"])
        self.assertTrue(result["safety"]["human_authority_required"])

    def test_no_confirmation_semantics(self):
        result = provenance(
            INTERNAL_AVAILABLE,
            package(
                item(EXTERNAL_B, effect="CONTRADICTS"),
                item(EXTERNAL_A),
            ),
        )
        payload = json.loads(json.dumps(result))
        payload.pop("safety", None)
        for record in payload["records"]:
            record.pop("safety", None)
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
            "WINNER",
            "RESOLVED",
            "PAYLOAD",
            "HTTP://",
            "HTTPS://",
            "://",
        ):
            self.assertNotIn(forbidden, text, forbidden)

    def test_conflict_is_not_auto_resolved(self):
        result = provenance(
            INTERNAL_AVAILABLE,
            package(item(EXTERNAL_B, effect="CONTRADICTS")),
        )
        record = result["records"][0]
        self.assertEqual(record["conflict_state"], CONFLICT_PRESENT)
        self.assertIn("no automatic resolution", record["conflict_basis"]["note"])
        self.assertNotIn("winner", json.dumps(record).lower())
        self.assertNotIn("resolved", json.dumps(record).lower())
        self.assertTrue(record["human_review_required"])


class TestDeterminismAndIntegration(unittest.TestCase):
    def test_deterministic_output_and_stable_ids(self):
        payload = package(
            item(EXTERNAL_B, requirement_kind="OWNERSHIP_BINDING"),
            item(EXTERNAL_A),
        )
        first = provenance(STRUCTURAL, payload)
        second = provenance(STRUCTURAL, payload)
        self.assertEqual(json.dumps(first), json.dumps(second))
        self.assertEqual(
            [record["provenance_id"] for record in first["records"]],
            ["PR1", "PR2"],
        )
        self.assertEqual(
            [record["evidence_id"] for record in first["records"]],
            ["EI1", "EI2"],
        )

    def test_inputs_are_not_mutated(self):
        hypotheses = STRUCTURAL
        action_plan, acquisition_plan, readiness_plan = chain(hypotheses)
        intake = normalize_evidence_package(
            package(item(EXTERNAL_A)),
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        before = (
            json.dumps(intake),
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
            json.dumps(readiness_plan),
        )
        analyze_evidence_provenance(
            intake,
            hypotheses=hypotheses,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        after = (
            json.dumps(intake),
            json.dumps(action_plan),
            json.dumps(acquisition_plan),
            json.dumps(readiness_plan),
        )
        self.assertEqual(before, after)

    def test_raw_package_mode_matches_intake_result_mode(self):
        payload = package(item(EXTERNAL_A))
        from_intake = provenance(
            STRUCTURAL, payload, intake_result=intake_of(STRUCTURAL, payload)
        )
        from_package = provenance(STRUCTURAL, payload)
        self.assertEqual(json.dumps(from_intake), json.dumps(from_package))

    def test_limit_is_validated_and_applied(self):
        payload = package(
            item(EXTERNAL_A),
            item(EXTERNAL_B, requirement_kind="OWNERSHIP_BINDING"),
        )
        action_plan, acquisition_plan, readiness_plan = chain(STRUCTURAL)
        intake = normalize_evidence_package(
            payload,
            hypotheses=STRUCTURAL,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
        )
        limited = analyze_evidence_provenance(
            intake,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
            limit=1,
        )
        self.assertEqual(len(limited["records"]), 1)
        self.assertEqual(limited["records"][0]["provenance_id"], "PR1")
        empty = analyze_evidence_provenance(
            intake,
            action_plan=action_plan,
            acquisition_plan=acquisition_plan,
            readiness_plan=readiness_plan,
            limit=0,
        )
        self.assertEqual(empty["records"], [])
        for bad in (-1, True):
            with self.assertRaises(ValueError):
                analyze_evidence_provenance(
                    intake,
                    action_plan=action_plan,
                    acquisition_plan=acquisition_plan,
                    readiness_plan=readiness_plan,
                    limit=bad,
                )

    def test_rule_versions(self):
        result = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        self.assertEqual(RULE_VERSION, "r75-1")
        self.assertEqual(result["rule_version"], "r75-1")
        self.assertEqual(SOURCE_INTAKE_RULE_VERSION, INTAKE_RULE_VERSION)
        self.assertEqual(
            result["source_intake_rule_version"], "r74-1"
        )
        for key, expected in (
            ("source_action_rule_version", "r70-1"),
            ("source_acquisition_rule_version", "r71-1"),
            ("source_readiness_rule_version", "r72-1"),
            ("source_feedback_rule_version", "r73-1"),
        ):
            self.assertEqual(result[key], expected)

    def test_evidence_refs_stay_canonical(self):
        result = provenance(STRUCTURAL, package(item(EXTERNAL_A)))
        record = result["records"][0]
        for ref in record["evidence_refs"]:
            self.assertEqual(ref.partition(":")[0], "authorization")
        self.assertIn(
            "authorization",
            {ref.partition(":")[0] for ref in record["evidence_refs"]},
        )


if __name__ == "__main__":
    unittest.main()
