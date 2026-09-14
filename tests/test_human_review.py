"""tests/test_human_review.py — Stage R56 builder and integration tests.

Deterministic, offline tests for human review recording:

- review creation for ranked and deferred R55 findings
- every decision type, state and transition
- HUMAN authority, ADVISORY AI role and never-authorized invariants
- rationale preservation and explicit absence
- evidence requests and escalations (recorded only)
- conflict and duplicate review without silent resolution or deletion
- immutable R55 priority and preserved provenance/governance
- decision history and supersession
- review batches and explicit review order
- stable ids, deterministic output and shuffled-decision equivalence
- malformed/empty/minimal inputs and fail-closed behavior
- R53 -> R55 -> R56 and R54 -> R56 integration
- input immutability

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.finding_correlation import correlate_findings
from ai.knowledge.human_review import (
    create_human_review,
    create_review_batch,
    export_human_review,
    record_human_decision,
    review_finding,
)
from ai.knowledge.research_prioritization import prioritize_findings
from ai.schemas.human_decision import (
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_PENDING,
    HUMAN_DECISION_TYPES,
    HUMAN_DECISION_STATES,
    OPTION_EXECUTION_PLACEHOLDER,
    RATIONALE_STATE_NOT_PROVIDED,
    RATIONALE_STATE_PROVIDED,
    TRANSITION_REASONS,
)
from ai.schemas.human_decision_result import (
    HUMAN_REVIEW_SKIP_REASONS,
    HUMAN_REVIEW_STATUSES,
    REJECTION_AUTOMATED_AUTHORITY,
    REJECTION_DUPLICATE_DECISION,
    REJECTION_EXECUTION_AUTHORIZATION,
    REJECTION_EXPLOIT_AUTHORIZATION,
    REJECTION_FINDING_NOT_FOUND,
    REJECTION_INVALID_TRANSITION,
    REJECTION_MISSING_FINDING_ID,
    REJECTION_UNKNOWN_DECISION,
    REJECTION_VULNERABILITY_CONFIRMATION,
)
from ai.schemas.human_review import REVIEW_STATES
from ai.schemas.research_priority import PRIORITY_BANDS

from tests.test_research_priority import (
    conflicting_findings,
    critical_finding,
    duplicate_findings,
    related_findings,
)
from tests.test_research_priority_rules import finding

FINDING_ONE = "fnd-" + "1" * 16
FINDING_TWO = "fnd-" + "2" * 16


def priority_result(findings=None, correlation_result=None):
    if findings is None:
        findings = [critical_finding(FINDING_ONE)]
    return prioritize_findings(
        findings, correlation_result=correlation_result
    )


def review_for(result, finding_id):
    for review in result["reviews"]:
        if review["finding_id"] == finding_id:
            return review
    raise AssertionError(f"review not found: {finding_id}")


class TestCreateHumanReview(unittest.TestCase):
    def test_empty_input_is_no_findings(self):
        result = create_human_review()
        self.assertEqual(result["status"], "NO_FINDINGS")
        self.assertEqual(result["reviews"], [])
        self.assertEqual(result["decision_authority"], "HUMAN")
        self.assertEqual(result["ai_role"], "ADVISORY")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")

    def test_minimal_input_is_pending(self):
        prioritization = priority_result()
        result = create_human_review(prioritization_result=prioritization)
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(len(result["reviews"]), 1)
        review = result["reviews"][0]
        self.assertEqual(review["review_state"], DECISION_STATE_PENDING)
        self.assertEqual(review["decision"], {})
        self.assertIn("PENDING_HUMAN_DECISION", review["limitations"])
        self.assertIn("PENDING_HUMAN_DECISION", result["limitations"])

    def test_all_ranked_findings_are_reviewed(self):
        first = critical_finding(FINDING_ONE)
        second = finding(
            "XSS", "sa-" + "2" * 16, finding_id_value=FINDING_TWO
        )
        prioritization = priority_result([first, second])
        result = create_human_review(prioritization_result=prioritization)
        self.assertEqual(len(result["reviews"]), 2)
        self.assertEqual(
            [review["finding_id"] for review in result["reviews"]],
            [
                plan["finding_id"]
                for plan in prioritization["ranked_findings"]
            ],
        )

    def test_all_decided_is_completed(self):
        prioritization = priority_result()
        decisions = [
            {
                "finding_id": FINDING_ONE,
                "decision_type": "APPROVE_RESEARCH",
                "rationale_codes": ["EVIDENCE_SUFFICIENT"],
            }
        ]
        result = create_human_review(
            prioritization_result=prioritization, decisions=decisions
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(
            result["reviews"][0]["review_state"], DECISION_STATE_DECIDED
        )

    def test_partial_when_only_some_decided(self):
        first = critical_finding(FINDING_ONE)
        second = finding(
            "XSS", "sa-" + "2" * 16, finding_id_value=FINDING_TWO
        )
        prioritization = priority_result([first, second])
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["summary"]["decided_count"], 1)
        self.assertEqual(result["summary"]["pending_count"], 1)

    def test_every_decision_type_is_recorded(self):
        for decision_type in HUMAN_DECISION_TYPES:
            prioritization = priority_result()
            payload = {
                "finding_id": FINDING_ONE,
                "decision_type": decision_type,
                "rationale_codes": ["OTHER"],
            }
            if decision_type == "REQUEST_MORE_EVIDENCE":
                payload["evidence_request"] = {
                    "requested_evidence_type": "EVIDENCE_CONTEXT_COMPLETION"
                }
            if decision_type == "ESCALATE":
                payload["escalation"] = {
                    "escalation_target": "HUMAN_ANALYST_REVIEW"
                }
            result = create_human_review(
                prioritization_result=prioritization,
                decisions=[payload],
            )
            review = result["reviews"][0]
            self.assertEqual(
                review["decision"]["decision_type"], decision_type
            )
            self.assertIn(decision_type, HUMAN_DECISION_TYPES)
            self.assertEqual(
                result["summary"]["decision_type_counts"][decision_type], 1
            )

    def test_status_vocabulary_is_closed(self):
        result = create_human_review()
        self.assertIn(result["status"], HUMAN_REVIEW_STATUSES)
        self.assertEqual(result["rule_version"], "r56-3")
        self.assertEqual(result["review_rule_version"], "r56-2")
        self.assertEqual(result["decision_rule_version"], "r56-1")


class TestAuthorityBoundary(unittest.TestCase):
    def assert_rejected(self, decision, rejection):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization, decisions=[decision]
        )
        self.assertEqual(result["status"], "PARTIAL")
        invalid = result["invalid_decisions"][0]
        self.assertEqual(invalid["rejection_reason"], rejection)
        self.assertEqual(invalid["decision_state"], "INVALID")
        review = result["reviews"][0]
        self.assertEqual(review["review_state"], DECISION_STATE_PENDING)
        self.assertEqual(review["decision"], {})
        return result

    def test_automated_authority_is_rejected(self):
        base = {"finding_id": FINDING_ONE, "decision_type": "APPROVE_RESEARCH"}
        for key, value in (
            ("decision_source", "AI"),
            ("decision_authority", "AUTOMATED"),
            ("ai_role", "PRIMARY"),
        ):
            rejected = dict(base)
            rejected[key] = value
            self.assert_rejected(rejected, REJECTION_AUTOMATED_AUTHORITY)

    def test_execution_authorization_is_rejected(self):
        self.assert_rejected(
            {
                "finding_id": FINDING_ONE,
                "decision_type": "APPROVE_RESEARCH",
                "execution_authorized": True,
            },
            REJECTION_EXECUTION_AUTHORIZATION,
        )

    def test_vulnerability_confirmation_is_rejected(self):
        self.assert_rejected(
            {
                "finding_id": FINDING_ONE,
                "decision_type": "APPROVE_RESEARCH",
                "vulnerability_confirmed": True,
            },
            REJECTION_VULNERABILITY_CONFIRMATION,
        )
        self.assert_rejected(
            {
                "finding_id": FINDING_ONE,
                "decision_type": "APPROVE_RESEARCH",
                "confirmation_state": "CONFIRMED",
            },
            REJECTION_VULNERABILITY_CONFIRMATION,
        )

    def test_exploit_authorization_is_rejected(self):
        for key in (
            "exploit_authorized",
            "payload_authorized",
            "exploitation_authorized",
        ):
            self.assert_rejected(
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                    key: True,
                },
                REJECTION_EXPLOIT_AUTHORIZATION,
            )

    def test_unknown_decision_is_rejected(self):
        self.assert_rejected(
            {
                "finding_id": FINDING_ONE,
                "decision_type": "RUN_SCANNER",
            },
            REJECTION_UNKNOWN_DECISION,
        )

    def test_rejected_decisions_are_preserved_not_deleted(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                    "execution_authorized": True,
                }
            ],
        )
        self.assertEqual(len(result["invalid_decisions"]), 1)
        self.assertEqual(result["invalid_decisions"][0]["finding_id"],
                         FINDING_ONE)
        self.assertTrue(result["invalid_decisions"][0]["research_only"])


class TestRationaleHandling(unittest.TestCase):
    def test_rationale_is_preserved(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "DEFER",
                    "rationale_codes": ["CONFLICT_REQUIRES_RESOLUTION"],
                    "rationale_note": "Wait for the conflict review.",
                }
            ],
        )
        review = result["reviews"][0]
        rationale = review["decision"]["rationale"]
        self.assertEqual(
            rationale["rationale_codes"], ["CONFLICT_REQUIRES_RESOLUTION"]
        )
        self.assertEqual(
            rationale["rationale_note"], "Wait for the conflict review."
        )
        self.assertEqual(
            review["audit"]["decision_rationale_state"],
            RATIONALE_STATE_PROVIDED,
        )

    def test_missing_rationale_is_explicit(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        review = result["reviews"][0]
        self.assertEqual(
            review["decision"]["rationale"]["rationale_state"],
            RATIONALE_STATE_NOT_PROVIDED,
        )
        self.assertIn("RATIONALE_NOT_PROVIDED", review["limitations"])
        self.assertIn("RATIONALE_NOT_PROVIDED", result["limitations"])

    def test_note_is_bounded_and_never_interpreted(self):
        prioritization = priority_result()
        note = "curl http://example.invalid/; rm -rf / " + "z" * 500
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "DEFER",
                    "rationale_note": note,
                }
            ],
        )
        stored = result["reviews"][0]["decision"]["rationale"][
            "rationale_note"
        ]
        self.assertLessEqual(len(stored), 240)
        self.assertIn("curl http://example.invalid/", stored)
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn('"command"', serialized)
        self.assertNotIn('"executed"', serialized)


class TestEvidenceAndEscalation(unittest.TestCase):
    def test_evidence_request_is_structured(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                    "rationale_codes": ["EVIDENCE_INCOMPLETE"],
                    "evidence_request": {
                        "requested_evidence_type": (
                            "EVIDENCE_HYPOTHESIS_STRENGTHENING"
                        ),
                        "priority": "HIGH",
                        "originating_reference": "REFLECTION_CONTEXT",
                    },
                }
            ],
        )
        review = result["reviews"][0]
        request = review["decision"]["evidence_request"]
        self.assertEqual(
            request["requested_evidence_type"],
            "EVIDENCE_HYPOTHESIS_STRENGTHENING",
        )
        self.assertEqual(request["source_finding_id"], FINDING_ONE)
        self.assertEqual(request["priority"], "HIGH")
        self.assertEqual(
            review["audit"]["evidence_references"],
            [
                "requested:EVIDENCE_HYPOTHESIS_STRENGTHENING",
                f"source:{FINDING_ONE}",
            ],
        )
        self.assertIn(
            "EVIDENCE_REQUEST_RECORDED_ONLY", review["limitations"]
        )
        self.assertEqual(result["summary"]["evidence_request_count"], 1)

    def test_escalation_is_structured(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "ESCALATE",
                    "escalation": {
                        "escalation_target": "SECURITY_REVIEW_BOARD",
                        "reason": "ESCALATION_REQUIRED",
                    },
                }
            ],
        )
        review = result["reviews"][0]
        escalation = review["decision"]["escalation"]
        self.assertEqual(
            escalation["escalation_target"], "SECURITY_REVIEW_BOARD"
        )
        self.assertEqual(escalation["finding_id"], FINDING_ONE)
        self.assertIn(escalation["priority_band"], PRIORITY_BANDS)
        self.assertEqual(result["summary"]["escalation_count"], 1)
        self.assertIn("ESCALATION_RECORDED_ONLY", review["limitations"])

    def test_malformed_evidence_request_is_rejected(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                    "evidence_request": {
                        "requested_evidence_type": "NOT_A_TYPE"
                    },
                }
            ],
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(
            result["invalid_decisions"][0]["rejection_reason"],
            "MALFORMED_EVIDENCE_REFERENCE",
        )


class TestConflictAndDuplicate(unittest.TestCase):
    def test_conflict_review_preserves_both_sides(self):
        first, second = conflicting_findings()
        correlation = correlate_findings([first, second])
        prioritization = priority_result(
            [first, second], correlation_result=correlation
        )
        result = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"},
                {"finding_id": FINDING_TWO, "decision_type": "ESCALATE"},
            ],
        )
        self.assertEqual(len(result["reviews"]), 2)
        self.assertEqual(
            result["batch"]["conflict_finding_ids"],
            [FINDING_ONE, FINDING_TWO],
        )
        self.assertIn("CONFLICT_PRESENT", result["limitations"])
        for review in result["reviews"]:
            self.assertEqual(
                review["correlation_reference"]["conflict_state"],
                "CONFLICT_PRESENT",
            )
            self.assertIn("CONFLICT_PRESENT", review["limitations"])
        self.assertEqual(result["summary"]["conflict_review_count"], 2)

    def test_duplicate_review_preserves_both_findings(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = priority_result(
            [first, second], correlation_result=correlation
        )
        result = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
        )
        self.assertEqual(len(result["reviews"]), 2)
        self.assertEqual(
            result["batch"]["duplicate_finding_ids"],
            [FINDING_ONE, FINDING_TWO],
        )
        self.assertIn("DUPLICATE_PRESENT", result["limitations"])
        self.assertEqual(result["summary"]["duplicate_review_count"], 2)

    def test_related_review_is_context(self):
        first, second = related_findings()
        correlation = correlate_findings([first, second])
        prioritization = priority_result(
            [first, second], correlation_result=correlation
        )
        result = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
        )
        for review in result["reviews"]:
            self.assertIn(
                "RELATED",
                review["correlation_reference"]["relationship_types"],
            )


class TestPriorityPreservation(unittest.TestCase):
    def test_priority_reference_is_immutable(self):
        prioritization = priority_result()
        plan = prioritization["ranked_findings"][0]
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                }
            ],
        )
        review = result["reviews"][0]
        reference = review["priority_reference"]
        self.assertEqual(reference["priority_score"], plan["priority_score"])
        self.assertEqual(reference["priority_band"], plan["priority_band"])
        self.assertEqual(
            reference["ranking_position"], plan["ranking_position"]
        )
        self.assertEqual(
            reference["prioritization_id"],
            prioritization["prioritization_id"],
        )
        self.assertTrue(review["priority_immutable"])
        self.assertTrue(review["recommendation_preserved"])

    def test_human_decision_does_not_mutate_r55(self):
        prioritization = priority_result()
        snapshot = json.dumps(prioritization, sort_keys=True)
        create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "REJECT"}
            ],
        )
        self.assertEqual(
            json.dumps(prioritization, sort_keys=True), snapshot
        )

    def test_recommendation_and_decision_are_separate(self):
        prioritization = priority_result()
        plan = prioritization["ranked_findings"][0]
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "REQUEST_MORE_EVIDENCE",
                }
            ],
        )
        review = result["reviews"][0]
        self.assertEqual(plan["priority_band"], "CRITICAL")
        self.assertEqual(
            review["decision"]["decision_type"], "REQUEST_MORE_EVIDENCE"
        )
        self.assertEqual(review["priority_reference"]["priority_band"],
                         "CRITICAL")


class TestProvenanceAndGovernance(unittest.TestCase):
    def test_provenance_is_preserved(self):
        prioritization = priority_result()
        result = create_human_review(prioritization_result=prioritization)
        provenance = result["provenance"]
        self.assertEqual(provenance["priority_rule_version"], "r55-3")
        self.assertEqual(provenance["rule_version"], "r56-3")
        self.assertEqual(provenance["decision_source"], "HUMAN")
        review = result["reviews"][0]
        review_provenance = review["provenance"]
        self.assertEqual(
            review_provenance["prioritization_id"],
            prioritization["prioritization_id"],
        )
        self.assertEqual(review_provenance["decision_source"], "HUMAN")
        self.assertTrue(review_provenance["deterministic"])

    def test_correlation_identity_is_preserved(self):
        first, second = related_findings()
        correlation = correlate_findings([first, second])
        prioritization = priority_result(
            [first, second], correlation_result=correlation
        )
        result = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
        )
        self.assertEqual(
            result["provenance"]["correlation_id"],
            correlation["correlation_id"],
        )
        self.assertEqual(
            result["provenance"]["correlation_rule_version"], "r54-1"
        )
        for review in result["reviews"]:
            self.assertEqual(
                review["correlation_reference"]["correlation_id"],
                correlation["correlation_id"],
            )

    def test_r53_and_r54_rule_versions_are_preserved(self):
        first, second = duplicate_findings()
        correlation = correlate_findings([first, second])
        prioritization = priority_result(
            [first, second], correlation_result=correlation
        )
        result = create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
        )
        self.assertEqual(result["provenance"]["finding_rule_version"], "r53-6")
        for review in result["reviews"]:
            self.assertEqual(
                review["provenance"]["finding_rule_version"], "r53-6"
            )
            self.assertEqual(
                review["provenance"]["correlation_rule_version"], "r54-1"
            )

    def test_governance_is_preserved(self):
        prioritization = priority_result([critical_finding(FINDING_ONE)])
        result = create_human_review(prioritization_result=prioritization)
        self.assertEqual(
            result["governance"]["governance_state"],
            "CONSISTENT_REFERENCED",
        )
        self.assertEqual(
            result["governance"]["referenced_finding_ids"], [FINDING_ONE]
        )
        review = result["reviews"][0]
        self.assertEqual(
            review["governance"]["reference_state"], "REFERENCED"
        )

    def test_unknown_governance_is_visible(self):
        weak = finding("XSS", "sa-" + "9" * 16, finding_id_value=FINDING_ONE)
        prioritization = priority_result([weak])
        result = create_human_review(prioritization_result=prioritization)
        self.assertEqual(
            result["governance"]["governance_state"], "UNKNOWN"
        )
        self.assertIn("GOVERNANCE_UNKNOWN", result["limitations"])


class TestHistoryAndTransitions(unittest.TestCase):
    def test_supersession_preserves_history(self):
        prioritization = priority_result()
        first = record_human_decision(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={
                "finding_id": FINDING_ONE,
                "decision_type": "APPROVE_RESEARCH",
                "rationale_codes": ["EVIDENCE_SUFFICIENT"],
            },
        )
        second = record_human_decision(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={
                "finding_id": FINDING_ONE,
                "decision_type": "DEFER",
                "rationale_codes": ["CONFLICT_REQUIRES_RESOLUTION"],
            },
            previous_review=first["reviews"][0],
        )
        review = second["reviews"][0]
        self.assertEqual(review["review_state"], DECISION_STATE_DECIDED)
        self.assertEqual(
            review["decision"]["decision_type"], "DEFER"
        )
        self.assertEqual(len(review["decision_history"]), 1)
        self.assertEqual(
            review["previous_decision"]["decision_type"],
            "APPROVE_RESEARCH",
        )
        self.assertEqual(
            review["transition"]["transition_reason"],
            "DECISION_SUPERSEDED",
        )
        self.assertIn(
            "DECISION_HISTORY_PRESENT", review["limitations"]
        )

    def test_expired_transition_is_rejected(self):
        prioritization = priority_result()
        expired = {
            "review_id": "hrv-" + "c" * 16,
            "finding_id": FINDING_ONE,
            "review_state": DECISION_STATE_EXPIRED,
            "decision": {},
        }
        result = record_human_decision(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={
                "finding_id": FINDING_ONE,
                "decision_type": "DEFER",
            },
            previous_review=expired,
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(
            result["invalid_decisions"][0]["rejection_reason"],
            REJECTION_INVALID_TRANSITION,
        )
        self.assertEqual(
            result["reviews"][0]["review_state"], DECISION_STATE_PENDING
        )

    def test_expired_review_is_recorded_without_decision(self):
        prioritization = priority_result()
        result = record_human_decision(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={"finding_id": FINDING_ONE, "decision_state": "EXPIRED"},
        )
        review = result["reviews"][0]
        self.assertEqual(review["review_state"], DECISION_STATE_EXPIRED)
        self.assertEqual(review["decision"], {})
        self.assertIn("REVIEW_EXPIRED", review["limitations"])

    def test_transition_reasons_are_closed(self):
        prioritization = priority_result()
        result = record_human_decision(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={"finding_id": FINDING_ONE, "decision_type": "DEFER"},
        )
        self.assertIn(
            result["reviews"][0]["transition"]["transition_reason"],
            TRANSITION_REASONS,
        )


class TestReviewBatch(unittest.TestCase):
    def two_finding_prioritization(self):
        first = critical_finding(FINDING_ONE)
        second = finding(
            "XSS", "sa-" + "2" * 16, finding_id_value=FINDING_TWO
        )
        return priority_result([first, second])

    def test_default_order_follows_r55_ranking(self):
        prioritization = self.two_finding_prioritization()
        result = create_review_batch(
            prioritization_result=prioritization
        )
        expected = [
            plan["finding_id"]
            for plan in prioritization["ranked_findings"]
        ]
        self.assertEqual(result["batch"]["review_order"], expected)
        self.assertTrue(result["batch"]["batch_id"].startswith("hrb-"))

    def test_explicit_review_order_is_honored(self):
        prioritization = self.two_finding_prioritization()
        result = create_review_batch(
            prioritization_result=prioritization,
            review_order=[FINDING_TWO, FINDING_ONE],
        )
        self.assertEqual(
            result["batch"]["review_order"], [FINDING_TWO, FINDING_ONE]
        )
        self.assertEqual(
            result["batch"]["finding_ids"], sorted([FINDING_ONE, FINDING_TWO])
        )
        self.assertEqual(result["errors"], [])

    def test_invalid_review_order_fails_closed(self):
        prioritization = self.two_finding_prioritization()
        result = create_review_batch(
            prioritization_result=prioritization,
            review_order=[FINDING_ONE],
        )
        self.assertTrue(
            any(
                error["error_category"] == "INVALID_REVIEW_ORDER"
                for error in result["errors"]
            )
        )
        self.assertEqual(
            result["batch"]["review_order"],
            [
                plan["finding_id"]
                for plan in prioritization["ranked_findings"]
            ],
        )

    def test_ranked_snapshot_is_immutable(self):
        prioritization = self.two_finding_prioritization()
        result = create_review_batch(
            prioritization_result=prioritization
        )
        snapshot = result["batch"]["ranked_snapshot"]
        self.assertEqual(len(snapshot), 2)
        for item in snapshot:
            plan = next(
                plan
                for plan in prioritization["ranked_findings"]
                if plan["finding_id"] == item["finding_id"]
            )
            self.assertEqual(item["priority_score"], plan["priority_score"])
            self.assertEqual(item["priority_band"], plan["priority_band"])
        self.assertTrue(result["batch"]["priority_immutable"])

    def test_batch_decisions_summary(self):
        prioritization = self.two_finding_prioritization()
        result = create_review_batch(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        summary = {
            item["finding_id"]: item
            for item in result["batch"]["decisions_by_finding"]
        }
        self.assertEqual(
            summary[FINDING_ONE]["decision_state"], DECISION_STATE_DECIDED
        )
        self.assertEqual(
            summary[FINDING_TWO]["decision_state"], DECISION_STATE_PENDING
        )


class TestReviewFindingAndRecord(unittest.TestCase):
    def test_review_finding_records_one_review(self):
        prioritization = priority_result()
        result = review_finding(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={"finding_id": FINDING_ONE, "decision_type": "DEFER"},
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(len(result["reviews"]), 1)
        self.assertEqual(result["reviews"][0]["finding_id"], FINDING_ONE)

    def test_review_unknown_finding_fails_closed(self):
        prioritization = priority_result()
        result = review_finding(
            finding_id=FINDING_TWO,
            prioritization_result=prioritization,
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"], "NOT_FOUND"
        )

    def test_previous_review_mismatch_fails_closed(self):
        prioritization = priority_result()
        previous = {
            "review_id": "hrv-" + "d" * 16,
            "finding_id": FINDING_TWO,
            "review_state": DECISION_STATE_DECIDED,
        }
        result = record_human_decision(
            finding_id=FINDING_ONE,
            prioritization_result=prioritization,
            decision={"finding_id": FINDING_ONE, "decision_type": "DEFER"},
            previous_review=previous,
        )
        self.assertEqual(result["status"], "FAILED")

    def test_export_alias(self):
        prioritization = priority_result()
        direct = create_human_review(prioritization_result=prioritization)
        alias = export_human_review(prioritization_result=prioritization)
        self.assertEqual(direct, alias)


class TestInputHandling(unittest.TestCase):
    def test_invalid_prioritization_type_fails_closed(self):
        result = create_human_review(prioritization_result=42)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_wrong_rule_version_fails_closed(self):
        result = create_human_review(
            prioritization_result={"rule_version": "r99-9", "findings": []}
        )
        self.assertEqual(result["status"], "FAILED")

    def test_malformed_plan_list_fails_closed(self):
        result = create_human_review(
            prioritization_result={
                "rule_version": "r55-2",
                "ranked_findings": "nope",
            }
        )
        self.assertEqual(result["status"], "FAILED")

    def test_malformed_correlation_fails_closed(self):
        prioritization = priority_result()
        self.assertEqual(
            create_human_review(
                prioritization_result=prioritization,
                correlation_result=42,
            )["status"],
            "FAILED",
        )
        self.assertEqual(
            create_human_review(
                prioritization_result=prioritization,
                correlation_result={"rule_version": "r99-9"},
            )["status"],
            "FAILED",
        )

    def test_unsupported_plan_is_skipped(self):
        prioritization = priority_result()
        malformed = dict(prioritization["ranked_findings"][0])
        malformed["category"] = "NOT_A_CATEGORY"
        result = create_human_review(
            prioritization_result={
                "rule_version": "r55-2",
                "prioritization_id": prioritization["prioritization_id"],
                "ranked_findings": [malformed],
                "deferred_findings": [],
            }
        )
        self.assertEqual(result["reviews"], [])
        self.assertEqual(result["skipped_findings"][0]["reason"],
                         "UNSUPPORTED_CATEGORY")
        self.assertEqual(result["status"], "PARTIAL")

    def test_malformed_plan_entry_is_skipped(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result={
                "rule_version": "r55-2",
                "prioritization_id": prioritization["prioritization_id"],
                "ranked_findings": [None, "x"],
                "deferred_findings": [],
            }
        )
        reasons = {
            item["reason"] for item in result["skipped_findings"]
        }
        self.assertEqual(reasons, {"MALFORMED_PRIORITY"})
        self.assertEqual(result["status"], "PARTIAL")

    def test_missing_finding_id_is_rejected(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[{"decision_type": "DEFER"}],
        )
        self.assertEqual(
            result["invalid_decisions"][0]["rejection_reason"],
            REJECTION_MISSING_FINDING_ID,
        )

    def test_unknown_finding_decision_is_rejected(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_TWO, "decision_type": "DEFER"}
            ],
        )
        self.assertEqual(
            result["invalid_decisions"][0]["rejection_reason"],
            REJECTION_FINDING_NOT_FOUND,
        )
        self.assertTrue(
            any(
                error["error_category"] == "NOT_FOUND"
                for error in result["errors"]
            )
        )

    def test_duplicate_decisions_are_rejected(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"},
                {"finding_id": FINDING_ONE, "decision_type": "REJECT"},
            ],
        )
        self.assertEqual(
            result["invalid_decisions"][0]["rejection_reason"],
            REJECTION_DUPLICATE_DECISION,
        )
        self.assertEqual(
            result["reviews"][0]["decision"]["decision_type"], "DEFER"
        )

    def test_malformed_decision_entry_is_rejected(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=["not-a-mapping"],
        )
        self.assertEqual(
            result["invalid_decisions"][0]["rejection_reason"],
            "MALFORMED_DECISION",
        )

    def test_decisions_mapping_uses_keys(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions={
                FINDING_ONE: {"decision_type": "APPROVE_RESEARCH"}
            },
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(
            result["reviews"][0]["decision"]["finding_id"], FINDING_ONE
        )

    def test_skip_reasons_are_closed(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result={
                "rule_version": "r55-2",
                "ranked_findings": [None],
                "deferred_findings": [],
            }
        )
        for item in result["skipped_findings"]:
            self.assertIn(item["reason"], HUMAN_REVIEW_SKIP_REASONS)

    def test_review_states_are_closed(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        for review in result["reviews"]:
            self.assertIn(review["review_state"], REVIEW_STATES)
        self.assertIn(result["reviews"][0]["review_state"],
                      HUMAN_DECISION_STATES)


class TestDeferredFindings(unittest.TestCase):
    def test_deferred_findings_are_reviewable(self):
        unsafe = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value=FINDING_ONE,
            confirmation_state="CONFIRMED",
        )
        safe = critical_finding(FINDING_TWO)
        prioritization = priority_result([unsafe, safe])
        self.assertEqual(
            len(prioritization["deferred_findings"]), 1
        )
        result = create_human_review(prioritization_result=prioritization)
        self.assertEqual(len(result["reviews"]), 2)
        deferred_review = review_for(result, FINDING_ONE)
        self.assertEqual(
            deferred_review["priority_reference"]["priority_band"],
            "DEFERRED",
        )
        self.assertIn("SAFETY_DEFERRED", result["limitations"])
        self.assertEqual(
            deferred_review["decision"]["decision_source"]
            if deferred_review["decision"]
            else "HUMAN",
            "HUMAN",
        )

    def test_deferred_review_decision_stays_not_confirmed(self):
        unsafe = finding(
            "XSS",
            "sa-" + "1" * 16,
            finding_id_value=FINDING_ONE,
            confirmation_state="CONFIRMED",
        )
        prioritization = priority_result([unsafe])
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                }
            ],
        )
        self.assertEqual(result["status"], "COMPLETED")
        review = result["reviews"][0]
        self.assertEqual(review["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(
            review["decision"]["confirmation_state"], "NOT_CONFIRMED"
        )
        self.assertFalse(review["decision"]["vulnerability_confirmed"])
        self.assertFalse(review["decision"]["execution_authorized"])


class TestDeterminismAndImmutability(unittest.TestCase):
    def test_byte_identical_output(self):
        prioritization = priority_result()
        decisions = [
            {
                "finding_id": FINDING_ONE,
                "decision_type": "REQUEST_MORE_EVIDENCE",
                "rationale_codes": ["EVIDENCE_INCOMPLETE"],
            }
        ]
        first = create_human_review(
            prioritization_result=prioritization, decisions=decisions
        )
        second = create_human_review(
            prioritization_result=prioritization, decisions=decisions
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertEqual(
            first["review_result_id"], second["review_result_id"]
        )

    def test_shuffled_decisions_produce_identical_output(self):
        first = critical_finding(FINDING_ONE)
        second = finding(
            "XSS", "sa-" + "2" * 16, finding_id_value=FINDING_TWO
        )
        prioritization = priority_result([first, second])
        decisions = [
            {"finding_id": FINDING_ONE, "decision_type": "DEFER"},
            {"finding_id": FINDING_TWO, "decision_type": "REJECT"},
        ]
        forward = create_human_review(
            prioritization_result=prioritization, decisions=decisions
        )
        backward = create_human_review(
            prioritization_result=prioritization,
            decisions=list(reversed(decisions)),
        )
        self.assertEqual(
            json.dumps(forward, sort_keys=True),
            json.dumps(backward, sort_keys=True),
        )

    def test_ids_are_stable_across_calls(self):
        prioritization = priority_result()
        first = create_human_review(prioritization_result=prioritization)
        second = create_human_review(prioritization_result=prioritization)
        self.assertEqual(first["review_result_id"], second["review_result_id"])
        self.assertEqual(
            first["reviews"][0]["review_id"],
            second["reviews"][0]["review_id"],
        )
        self.assertEqual(
            first["batch"]["batch_id"], second["batch"]["batch_id"]
        )

    def test_correlation_input_is_not_mutated(self):
        first, second = conflicting_findings()
        correlation = correlate_findings([first, second])
        prioritization = priority_result(
            [first, second], correlation_result=correlation
        )
        snapshot = json.dumps(correlation, sort_keys=True)
        create_human_review(
            prioritization_result=prioritization,
            correlation_result=correlation,
        )
        self.assertEqual(
            json.dumps(correlation, sort_keys=True), snapshot
        )

    def test_prioritization_input_is_not_mutated(self):
        prioritization = priority_result()
        snapshot = json.dumps(prioritization, sort_keys=True)
        create_review_batch(prioritization_result=prioritization)
        self.assertEqual(
            json.dumps(prioritization, sort_keys=True), snapshot
        )


class TestSafetyInvariants(unittest.TestCase):
    def test_all_outputs_are_never_confirmed(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {
                    "finding_id": FINDING_ONE,
                    "decision_type": "APPROVE_RESEARCH",
                }
            ],
        )
        self.assertEqual(result["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["vulnerability_confirmed"])
        self.assertEqual(result["confidence_effect"], "NONE")
        review = result["reviews"][0]
        self.assertEqual(review["confirmation_state"], "NOT_CONFIRMED")
        self.assertFalse(review["execution_authorized"])
        self.assertFalse(review["vulnerability_confirmed"])
        self.assertEqual(review["ai_role"], "ADVISORY")
        decision = review["decision"]
        for key in (
            "confirmation_state",
        ):
            self.assertEqual(decision[key], "NOT_CONFIRMED")
        for key in (
            "execution_authorized",
            "vulnerability_confirmed",
            "exploit_authorized",
        ):
            self.assertFalse(decision[key])

    def test_audit_lists_not_authorized_actions(self):
        prioritization = priority_result()
        result = create_human_review(
            prioritization_result=prioritization,
            decisions=[
                {"finding_id": FINDING_ONE, "decision_type": "DEFER"}
            ],
        )
        audit = result["reviews"][0]["audit"]
        self.assertFalse(audit["execution_authorized"])
        self.assertEqual(audit["confirmation_state"], "NOT_CONFIRMED")
        self.assertIn("EXECUTION_NOT_AUTHORIZED", audit["not_authorized"])
        self.assertIn(
            "VULNERABILITY_CONFIRMATION_NOT_AUTHORIZED",
            audit["not_authorized"],
        )
        self.assertIn(
            "EXPLOIT_AUTHORIZATION_NOT_AUTHORIZED", audit["not_authorized"]
        )

    def test_execution_option_is_never_enabled(self):
        prioritization = priority_result()
        result = create_human_review(prioritization_result=prioritization)
        options = {
            item["option"]: item
            for item in result["reviews"][0]["decision_options"]
        }
        self.assertFalse(options[OPTION_EXECUTION_PLACEHOLDER]["enabled"])
        for option, item in options.items():
            if option == OPTION_EXECUTION_PLACEHOLDER:
                continue
            self.assertTrue(item["enabled"])
            self.assertEqual(item["disabled_reason"], "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
