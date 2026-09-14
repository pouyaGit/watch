"""tests/test_human_decision.py — Stage R56.1–R56.4 tests.

Deterministic, offline tests for the human decision contract and rules:

- closed decision, state, authority, rationale, evidence, escalation,
  not-authorized, option and transition vocabularies
- enforced HUMAN authority, ADVISORY AI role and never-authorized flags
- fail-closed rejection of automated authority and execution/confirmation/
  exploit authorization
- deterministic decision/review/audit/batch/result ids
- rationale as data (closed codes, bounded note, explicit absence)
- evidence request and escalation records (no collection, no notification)
- audit representation and limitation generation
- closed transitions (valid and invalid)

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.human_decision_rules import (
    audit_id,
    authority_rejection,
    batch_id,
    build_decision,
    build_review,
    decision_id,
    decision_options,
    decision_summary,
    finding_reference,
    priority_reference,
    result_id,
    review_id,
    transition_for,
)
from ai.schemas.human_decision import (
    AI_ROLE_ADVISORY,
    ALLOWED_TRANSITIONS,
    DECISION_AUTHORITY_HUMAN,
    DECISION_OPTION_CODES,
    DECISION_SOURCE_HUMAN,
    DECISION_STATE_DECIDED,
    DECISION_STATE_EXPIRED,
    DECISION_STATE_INVALID,
    DECISION_STATE_PENDING,
    DECISION_TYPE_TO_OPTION,
    EVIDENCE_REQUEST_TYPES,
    ESCALATION_TARGETS,
    HUMAN_DECISION_LIMITATIONS,
    HUMAN_DECISION_STATES,
    HUMAN_DECISION_TYPES,
    HUMAN_RATIONALE_CODES,
    HumanDecisionOptionPlan,
    HumanDecisionPlan,
    HumanEvidenceRequestPlan,
    HumanRationalePlan,
    NOT_AUTHORIZED_CODES,
    OPTION_EXECUTION_PLACEHOLDER,
    PRIORITY_BANDS,
    RATIONALE_NOT_PROVIDED,
    RATIONALE_STATE_NOT_PROVIDED,
    RATIONALE_STATE_PROVIDED,
    TRANSITION_REASONS,
    not_authorized_projection,
    sanitize_decision_option,
    sanitize_decision_rationale,
    sanitize_escalation,
    sanitize_evidence_request,
    sanitize_human_audit,
    sanitize_human_decision,
    sanitize_human_governance,
    sanitize_human_provenance,
)
from ai.schemas.human_decision_result import (
    DECISION_REJECTION_REASONS,
    REJECTION_AUTOMATED_AUTHORITY,
    REJECTION_EXECUTION_AUTHORIZATION,
    REJECTION_EXPLOIT_AUTHORIZATION,
    REJECTION_INVALID_TRANSITION,
    REJECTION_MALFORMED_DECISION,
    REJECTION_MALFORMED_EVIDENCE_REFERENCE,
    REJECTION_UNKNOWN_DECISION,
    REJECTION_VULNERABILITY_CONFIRMATION,
)
from ai.schemas.human_review import (
    HumanDecisionAuditEntryPlan,
    HumanReviewPlan,
)
from tests.test_research_priority import critical_finding

FINDING_ID = "fnd-" + "1" * 16


def plan_for(finding=None):
    from ai.knowledge.research_prioritization import prioritize_findings

    finding = finding or critical_finding(FINDING_ID)
    result = prioritize_findings([finding])
    return result, result["ranked_findings"][0]


def valid_decision(**overrides):
    payload = {
        "rule_version": "r56-1",
        "decision_id": "hdc-" + "a" * 16,
        "finding_id": FINDING_ID,
        "decision_type": "APPROVE_RESEARCH",
        "decision_state": DECISION_STATE_DECIDED,
        "decision_source": DECISION_SOURCE_HUMAN,
        "decision_authority": DECISION_AUTHORITY_HUMAN,
        "ai_role": AI_ROLE_ADVISORY,
        "human_authority": True,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
        "exploit_authorized": False,
        "confirmation_state": "NOT_CONFIRMED",
        "priority_reference": {
            "prioritization_id": "pri-" + "b" * 16,
            "priority_rule_version": "r55-3",
            "priority_score": 85,
            "priority_band": "CRITICAL",
            "ranking_position": 1,
            "priority_reasons": ["COMPLETE_EVIDENCE"],
        },
        "rationale": {
            "rationale_state": RATIONALE_STATE_PROVIDED,
            "rationale_codes": ["EVIDENCE_SUFFICIENT"],
            "rationale_note": "",
        },
        "research_only": True,
        "deterministic": True,
    }
    payload.update(overrides)
    return payload


class TestVocabulary(unittest.TestCase):
    def test_decision_types_are_closed(self):
        self.assertEqual(
            set(HUMAN_DECISION_TYPES),
            {
                "APPROVE_RESEARCH",
                "REQUEST_MORE_EVIDENCE",
                "DEFER",
                "REJECT",
                "ESCALATE",
                "NEEDS_REVIEW",
            },
        )

    def test_decision_states_are_closed(self):
        self.assertEqual(
            set(HUMAN_DECISION_STATES),
            {"PENDING_HUMAN_REVIEW", "DECIDED", "EXPIRED", "INVALID"},
        )

    def test_authority_vocabulary_is_human_only(self):
        self.assertEqual(DECISION_SOURCE_HUMAN, "HUMAN")
        self.assertEqual(DECISION_AUTHORITY_HUMAN, "HUMAN")
        self.assertEqual(AI_ROLE_ADVISORY, "ADVISORY")

    def test_rationale_codes_are_closed(self):
        self.assertEqual(
            len(HUMAN_RATIONALE_CODES), len(set(HUMAN_RATIONALE_CODES))
        )
        self.assertIn(RATIONALE_NOT_PROVIDED, HUMAN_RATIONALE_CODES)

    def test_evidence_request_types_are_closed(self):
        self.assertEqual(
            len(EVIDENCE_REQUEST_TYPES), len(set(EVIDENCE_REQUEST_TYPES))
        )

    def test_escalation_targets_and_reasons_are_closed(self):
        self.assertEqual(
            len(ESCALATION_TARGETS), len(set(ESCALATION_TARGETS))
        )
        self.assertIn("HUMAN_ANALYST_REVIEW", ESCALATION_TARGETS)
        self.assertIn("ESCALATION_UNKNOWN", ESCALATION_TARGETS)

    def test_not_authorized_codes_are_closed(self):
        self.assertEqual(
            len(NOT_AUTHORIZED_CODES), len(set(NOT_AUTHORIZED_CODES))
        )
        self.assertIn("EXECUTION_NOT_AUTHORIZED", NOT_AUTHORIZED_CODES)
        self.assertIn(
            "VULNERABILITY_CONFIRMATION_NOT_AUTHORIZED",
            NOT_AUTHORIZED_CODES,
        )

    def test_option_codes_are_closed(self):
        self.assertEqual(
            len(DECISION_OPTION_CODES), len(set(DECISION_OPTION_CODES))
        )
        self.assertEqual(
            set(DECISION_TYPE_TO_OPTION), set(HUMAN_DECISION_TYPES)
        )

    def test_transition_vocabulary_is_closed(self):
        self.assertEqual(
            set(ALLOWED_TRANSITIONS), set(HUMAN_DECISION_STATES)
        )
        self.assertIn(
            DECISION_STATE_DECIDED,
            ALLOWED_TRANSITIONS[DECISION_STATE_PENDING],
        )
        self.assertEqual(
            ALLOWED_TRANSITIONS[DECISION_STATE_EXPIRED], ()
        )
        self.assertEqual(
            ALLOWED_TRANSITIONS[DECISION_STATE_INVALID], ()
        )
        for reason in TRANSITION_REASONS:
            self.assertTrue(reason)

    def test_limitations_are_closed(self):
        self.assertEqual(
            len(HUMAN_DECISION_LIMITATIONS),
            len(set(HUMAN_DECISION_LIMITATIONS)),
        )
        self.assertIn("AI_ADVISORY_ONLY", HUMAN_DECISION_LIMITATIONS)
        self.assertIn(
            "HUMAN_DECISION_DOES_NOT_CONFIRM", HUMAN_DECISION_LIMITATIONS
        )

    def test_rejection_reasons_are_closed(self):
        self.assertEqual(
            len(DECISION_REJECTION_REASONS),
            len(set(DECISION_REJECTION_REASONS)),
        )
        for reason in (
            REJECTION_AUTOMATED_AUTHORITY,
            REJECTION_EXECUTION_AUTHORIZATION,
            REJECTION_VULNERABILITY_CONFIRMATION,
            REJECTION_EXPLOIT_AUTHORIZATION,
        ):
            self.assertIn(reason, DECISION_REJECTION_REASONS)


class TestAuthorityEnforcement(unittest.TestCase):
    def test_valid_request_passes_authority_check(self):
        self.assertEqual(
            authority_rejection(
                {"decision_type": "APPROVE_RESEARCH"}
            ),
            "",
        )
        self.assertEqual(
            authority_rejection(
                {
                    "decision_source": "HUMAN",
                    "decision_authority": "HUMAN",
                    "ai_role": "ADVISORY",
                }
            ),
            "",
        )

    def test_automated_authority_is_rejected(self):
        for payload in (
            {"decision_source": "AI"},
            {"decision_source": "AUTOMATED"},
            {"decision_authority": "AUTOMATED"},
            {"ai_role": "PRIMARY"},
            {"ai_role": "AUTHORITY"},
        ):
            self.assertEqual(
                authority_rejection(payload),
                REJECTION_AUTOMATED_AUTHORITY,
                payload,
            )

    def test_execution_authorization_is_rejected(self):
        for key in (
            "execution_authorized",
            "execute",
            "execution_allowed",
            "execution_authorization",
        ):
            self.assertEqual(
                authority_rejection({key: True}),
                REJECTION_EXECUTION_AUTHORIZATION,
                key,
            )

    def test_vulnerability_confirmation_is_rejected(self):
        for key in (
            "vulnerability_confirmed",
            "confirmed",
            "is_vulnerable",
            "vulnerability_confirmation",
        ):
            self.assertEqual(
                authority_rejection({key: True}),
                REJECTION_VULNERABILITY_CONFIRMATION,
                key,
            )
        self.assertEqual(
            authority_rejection({"confirmation_state": "CONFIRMED"}),
            REJECTION_VULNERABILITY_CONFIRMATION,
        )

    def test_exploit_authorization_is_rejected(self):
        for key in (
            "exploit_authorized",
            "exploit_authorization",
            "exploitation_authorized",
            "payload_authorized",
            "payload_authorization",
        ):
            self.assertEqual(
                authority_rejection({key: True}),
                REJECTION_EXPLOIT_AUTHORIZATION,
                key,
            )

    def test_malformed_request_is_rejected(self):
        self.assertEqual(
            authority_rejection("nope"), REJECTION_MALFORMED_DECISION
        )


class TestDecisionPlanInvariants(unittest.TestCase):
    def test_valid_plan_round_trips(self):
        plan = HumanDecisionPlan(**valid_decision())
        self.assertEqual(plan.decision_source, "HUMAN")
        self.assertEqual(plan.decision_authority, "HUMAN")
        self.assertEqual(plan.ai_role, "ADVISORY")
        self.assertFalse(plan.execution_authorized)
        self.assertFalse(plan.vulnerability_confirmed)
        self.assertFalse(plan.exploit_authorized)
        self.assertEqual(plan.confirmation_state, "NOT_CONFIRMED")
        self.assertTrue(plan.research_only)
        self.assertTrue(plan.deterministic)

    def test_automated_source_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(decision_source="AI"))

    def test_non_human_authority_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(
                **valid_decision(decision_authority="AUTOMATED")
            )

    def test_primary_ai_role_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(ai_role="PRIMARY"))

    def test_execution_authorization_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(
                **valid_decision(execution_authorized=True)
            )

    def test_vulnerability_confirmation_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(
                **valid_decision(vulnerability_confirmed=True)
            )
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(
                **valid_decision(confirmation_state="CONFIRMED")
            )

    def test_exploit_authorization_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(exploit_authorized=True))

    def test_malformed_ids_are_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(decision_id="bad"))
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(finding_id="bad"))

    def test_unknown_decision_type_is_rejected(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(decision_type="LAUNCH"))

    def test_research_only_and_deterministic_are_enforced(self):
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(research_only=False))
        with self.assertRaises(ValidationError):
            HumanDecisionPlan(**valid_decision(deterministic=False))

    def test_sanitizer_forces_invariants(self):
        projected = sanitize_human_decision(
            {
                "finding_id": FINDING_ID,
                "decision_type": "APPROVE_RESEARCH",
                "decision_source": "AI",
                "decision_authority": "AUTOMATED",
                "ai_role": "PRIMARY",
                "execution_authorized": True,
                "vulnerability_confirmed": True,
                "exploit_authorized": True,
                "confirmation_state": "CONFIRMED",
                "research_only": False,
                "deterministic": False,
            }
        )
        self.assertEqual(projected["decision_source"], "HUMAN")
        self.assertEqual(projected["decision_authority"], "HUMAN")
        self.assertEqual(projected["ai_role"], "ADVISORY")
        self.assertFalse(projected["execution_authorized"])
        self.assertFalse(projected["vulnerability_confirmed"])
        self.assertFalse(projected["exploit_authorized"])
        self.assertEqual(projected["confirmation_state"], "NOT_CONFIRMED")
        self.assertTrue(projected["research_only"])
        self.assertTrue(projected["deterministic"])

    def test_execution_option_can_never_be_enabled(self):
        with self.assertRaises(ValidationError):
            HumanDecisionOptionPlan(
                option=OPTION_EXECUTION_PLACEHOLDER, enabled=True
            )
        projected = sanitize_decision_option(
            {
                "option": OPTION_EXECUTION_PLACEHOLDER,
                "enabled": True,
                "disabled_reason": "",
            }
        )
        self.assertFalse(projected["enabled"])
        self.assertTrue(projected["disabled_reason"])

    def test_default_options_disable_execution_placeholder(self):
        options = decision_options()
        codes = {item["option"]: item for item in options}
        self.assertEqual(
            set(codes), set(DECISION_OPTION_CODES)
        )
        self.assertFalse(codes[OPTION_EXECUTION_PLACEHOLDER]["enabled"])
        self.assertTrue(
            codes[OPTION_EXECUTION_PLACEHOLDER]["disabled_reason"]
        )
        for option, item in codes.items():
            if option == OPTION_EXECUTION_PLACEHOLDER:
                continue
            self.assertTrue(item["enabled"])


class TestRationale(unittest.TestCase):
    def test_missing_rationale_is_explicit(self):
        rationale = sanitize_decision_rationale(None)
        self.assertEqual(
            rationale["rationale_state"], RATIONALE_STATE_NOT_PROVIDED
        )
        self.assertEqual(
            rationale["rationale_codes"], [RATIONALE_NOT_PROVIDED]
        )
        self.assertEqual(rationale["rationale_note"], "")

    def test_codes_only_rationale_is_provided(self):
        rationale = sanitize_decision_rationale(
            {"rationale_codes": ["EVIDENCE_INCOMPLETE"]}
        )
        self.assertEqual(
            rationale["rationale_state"], RATIONALE_STATE_PROVIDED
        )

    def test_note_only_rationale_is_provided(self):
        rationale = sanitize_decision_rationale(
            {"rationale_note": "Human context."}
        )
        self.assertEqual(
            rationale["rationale_state"], RATIONALE_STATE_PROVIDED
        )

    def test_unknown_codes_are_dropped(self):
        rationale = sanitize_decision_rationale(
            {"rationale_codes": ["EVIDENCE_INCOMPLETE", "NOT_A_CODE"]}
        )
        self.assertEqual(
            rationale["rationale_codes"], ["EVIDENCE_INCOMPLETE"]
        )

    def test_note_is_bounded_and_sanitized_as_data(self):
        note = "line1\nline2\r\n" + "x" * 500
        rationale = sanitize_decision_rationale({"rationale_note": note})
        self.assertLessEqual(len(rationale["rationale_note"]), 240)
        self.assertNotIn("\n", rationale["rationale_note"])
        self.assertNotIn("\r", rationale["rationale_note"])

    def test_rationale_plan_model_bounds_note(self):
        plan = HumanRationalePlan(
            rationale_state=RATIONALE_STATE_PROVIDED,
            rationale_codes=["OTHER"],
            rationale_note="y" * 500,
        )
        self.assertLessEqual(len(plan.rationale_note), 240)


class TestEvidenceAndEscalation(unittest.TestCase):
    def test_invalid_evidence_type_falls_back_to_unknown(self):
        request = sanitize_evidence_request(
            {"requested_evidence_type": "NOT_A_TYPE"}
        )
        self.assertEqual(request["requested_evidence_type"], "EVIDENCE_UNKNOWN")

    def test_invalid_source_finding_id_is_cleared(self):
        request = sanitize_evidence_request(
            {"source_finding_id": "not-a-finding"}
        )
        self.assertEqual(request["source_finding_id"], "")

    def test_evidence_plan_model_rejects_malformed_source(self):
        with self.assertRaises(ValidationError):
            HumanEvidenceRequestPlan(source_finding_id="not-a-finding")

    def test_escalation_defaults_are_explicit(self):
        escalation = sanitize_escalation(None)
        self.assertEqual(
            escalation["escalation_target"], "ESCALATION_UNKNOWN"
        )
        self.assertEqual(
            escalation["reason"], "REASON_NOT_SPECIFIED"
        )
        self.assertFalse(escalation["research_only"] is False)

    def test_escalation_priority_band_is_closed(self):
        escalation = sanitize_escalation(
            {"priority_band": "NOT_A_BAND"}
        )
        self.assertIn(escalation["priority_band"], PRIORITY_BANDS)


class TestAuditAndProvenance(unittest.TestCase):
    def test_audit_always_lists_not_authorized(self):
        audit = sanitize_human_audit(None)
        self.assertFalse(audit["execution_authorized"])
        self.assertEqual(audit["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(audit["not_authorized"], list(NOT_AUTHORIZED_CODES))

    def test_audit_model_enforces_invariants(self):
        entry = HumanDecisionAuditEntryPlan(
            finding_id=FINDING_ID,
            audit_state="UNKNOWN",
        )
        self.assertFalse(entry.execution_authorized)
        self.assertEqual(entry.confirmation_state, "NOT_CONFIRMED")
        self.assertEqual(entry.not_authorized, list(NOT_AUTHORIZED_CODES))
        with self.assertRaises(ValidationError):
            HumanDecisionAuditEntryPlan(
                finding_id=FINDING_ID, execution_authorized=True
            )
        with self.assertRaises(ValidationError):
            HumanDecisionAuditEntryPlan(
                finding_id=FINDING_ID, confirmation_state="CONFIRMED"
            )

    def test_provenance_forces_human_source(self):
        provenance = sanitize_human_provenance(
            {"decision_source": "AI", "category": "XSS"}
        )
        self.assertEqual(provenance["decision_source"], "HUMAN")
        self.assertEqual(provenance["category"], "XSS")
        self.assertTrue(provenance["deterministic"])

    def test_governance_reuses_r53_shape(self):
        governance = sanitize_human_governance(
            {"reference_state": "REFERENCED", "ready": True}
        )
        self.assertEqual(governance["reference_state"], "REFERENCED")
        self.assertTrue(governance["ready"])

    def test_not_authorized_projection_is_stable(self):
        self.assertEqual(
            not_authorized_projection(), list(NOT_AUTHORIZED_CODES)
        )
        self.assertEqual(
            not_authorized_projection(), not_authorized_projection()
        )


class TestDeterministicIds(unittest.TestCase):
    def test_decision_id_is_deterministic(self):
        first = decision_id(
            FINDING_ID,
            "pri-" + "b" * 16,
            "APPROVE_RESEARCH",
            ["EVIDENCE_SUFFICIENT"],
            "",
            "",
            "",
        )
        second = decision_id(
            FINDING_ID,
            "pri-" + "b" * 16,
            "APPROVE_RESEARCH",
            ["EVIDENCE_SUFFICIENT"],
            "",
            "",
            "",
        )
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("hdc-"))

    def test_decision_id_changes_with_content(self):
        first = decision_id(
            FINDING_ID, "pri-" + "b" * 16, "DEFER", [], "", "", ""
        )
        second = decision_id(
            FINDING_ID, "pri-" + "b" * 16, "REJECT", [], "", "", ""
        )
        third = decision_id(
            FINDING_ID,
            "pri-" + "b" * 16,
            "DEFER",
            ["OTHER"],
            "",
            "",
            "",
        )
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)

    def test_other_ids_are_deterministic(self):
        self.assertEqual(
            review_id(FINDING_ID, "pri-" + "b" * 16, "DECIDED"),
            review_id(FINDING_ID, "pri-" + "b" * 16, "DECIDED"),
        )
        self.assertEqual(
            audit_id(FINDING_ID, "DEFER", "VALID"),
            audit_id(FINDING_ID, "DEFER", "VALID"),
        )
        self.assertEqual(
            batch_id("pri-" + "b" * 16, [FINDING_ID], ["hrv-" + "c" * 16]),
            batch_id("pri-" + "b" * 16, [FINDING_ID], ["hrv-" + "c" * 16]),
        )
        self.assertEqual(
            result_id("pri-" + "b" * 16, [], []),
            result_id("pri-" + "b" * 16, [], []),
        )


class TestTransitions(unittest.TestCase):
    def test_pending_to_decided(self):
        transition = transition_for(
            DECISION_STATE_PENDING, DECISION_STATE_DECIDED, has_previous=False
        )
        self.assertTrue(transition["allowed"])
        self.assertEqual(
            transition["transition_reason"], "INITIAL_DECISION"
        )

    def test_decided_to_decided_supersession(self):
        transition = transition_for(
            DECISION_STATE_DECIDED, DECISION_STATE_DECIDED, has_previous=True
        )
        self.assertTrue(transition["allowed"])
        self.assertEqual(
            transition["transition_reason"], "DECISION_SUPERSEDED"
        )

    def test_pending_to_expired(self):
        transition = transition_for(
            DECISION_STATE_PENDING, DECISION_STATE_EXPIRED, has_previous=False
        )
        self.assertTrue(transition["allowed"])
        self.assertEqual(
            transition["transition_reason"], "REVIEW_EXPIRED"
        )

    def test_terminal_states_reject_transitions(self):
        for state in (DECISION_STATE_EXPIRED, DECISION_STATE_INVALID):
            transition = transition_for(
                state, DECISION_STATE_DECIDED, has_previous=True
            )
            self.assertFalse(transition["allowed"])
            self.assertEqual(
                transition["transition_reason"], "TRANSITION_REJECTED"
            )


class TestBuildDecision(unittest.TestCase):
    def setUp(self):
        result, plan = plan_for()
        self.result = result
        self.plan = plan
        self.priority_ref = priority_reference(
            plan,
            result["prioritization_id"],
            result["priority_rule_version"],
        )
        self.finding_ref = finding_reference(plan)
        self.provenance = {
            "finding_rule_version": "r53-6",
            "correlation_rule_version": "",
            "priority_rule_version": result["priority_rule_version"],
            "decisor_rule_version": "r56-1",
            "prioritization_id": result["prioritization_id"],
            "correlation_id": "",
            "orchestration_id": "orch-" + "1" * 16,
            "agent_id": plan["agent_id"],
            "category": plan["category"],
            "decision_source": "HUMAN",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }
        self.correlation_ref = {}

    def build(self, request, **overrides):
        return build_decision(
            request,
            finding_id=FINDING_ID,
            plan=self.plan,
            priority_reference_value=self.priority_ref,
            correlation_reference_value=self.correlation_ref,
            finding_reference_value=self.finding_ref,
            provenance_value=self.provenance,
            governance=sanitize_human_governance(
                self.plan.get("governance")
            ),
            **overrides,
        )

    def test_approved_decision_builds(self):
        decision, rejection = self.build(
            {"decision_type": "APPROVE_RESEARCH"}
        )
        self.assertEqual(rejection, "")
        self.assertEqual(decision["decision_type"], "APPROVE_RESEARCH")
        self.assertEqual(decision["finding_id"], FINDING_ID)
        self.assertEqual(
            decision["priority_reference"]["priority_score"],
            self.plan["priority_score"],
        )
        self.assertEqual(
            decision["priority_reference"]["priority_band"],
            self.plan["priority_band"],
        )
        self.assertEqual(decision["decision_options"][-1]["option"],
                         OPTION_EXECUTION_PLACEHOLDER)

    def test_automated_authority_is_rejected_and_not_repaired(self):
        decision, rejection = self.build(
            {"decision_type": "APPROVE_RESEARCH", "decision_source": "AI"}
        )
        self.assertEqual(rejection, REJECTION_AUTOMATED_AUTHORITY)
        self.assertEqual(decision, {})

    def test_execution_authorization_is_rejected(self):
        _, rejection = self.build(
            {"decision_type": "APPROVE_RESEARCH", "execution_authorized": True}
        )
        self.assertEqual(rejection, REJECTION_EXECUTION_AUTHORIZATION)

    def test_vulnerability_confirmation_is_rejected(self):
        _, rejection = self.build(
            {
                "decision_type": "APPROVE_RESEARCH",
                "vulnerability_confirmed": True,
            }
        )
        self.assertEqual(
            rejection, REJECTION_VULNERABILITY_CONFIRMATION
        )

    def test_exploit_authorization_is_rejected(self):
        _, rejection = self.build(
            {"decision_type": "APPROVE_RESEARCH", "exploit_authorized": True}
        )
        self.assertEqual(rejection, REJECTION_EXPLOIT_AUTHORIZATION)

    def test_unknown_decision_type_is_rejected(self):
        _, rejection = self.build({"decision_type": "RUN_EXPLOIT"})
        self.assertEqual(rejection, REJECTION_UNKNOWN_DECISION)

    def test_malformed_evidence_request_is_rejected(self):
        _, rejection = self.build(
            {
                "decision_type": "REQUEST_MORE_EVIDENCE",
                "evidence_request": {
                    "requested_evidence_type": "NOT_A_TYPE"
                },
            }
        )
        self.assertEqual(
            rejection, REJECTION_MALFORMED_EVIDENCE_REFERENCE
        )

    def test_evidence_request_is_structured_and_recorded_only(self):
        decision, rejection = self.build(
            {
                "decision_type": "REQUEST_MORE_EVIDENCE",
                "evidence_request": {
                    "requested_evidence_type": "EVIDENCE_CONTEXT_COMPLETION",
                    "priority": "HIGH",
                },
            }
        )
        self.assertEqual(rejection, "")
        request = decision["evidence_request"]
        self.assertEqual(
            request["requested_evidence_type"], "EVIDENCE_CONTEXT_COMPLETION"
        )
        self.assertEqual(request["source_finding_id"], FINDING_ID)
        self.assertEqual(request["priority"], "HIGH")
        self.assertIn(
            "EVIDENCE_REQUEST_RECORDED_ONLY", decision["limitations"]
        )

    def test_escalation_is_structured_and_recorded_only(self):
        decision, rejection = self.build(
            {
                "decision_type": "ESCALATE",
                "escalation": {"escalation_target": "GOVERNANCE_REVIEW"},
            }
        )
        self.assertEqual(rejection, "")
        self.assertEqual(
            decision["escalation"]["escalation_target"],
            "GOVERNANCE_REVIEW",
        )
        self.assertEqual(
            decision["escalation"]["finding_id"], FINDING_ID
        )
        self.assertIn(
            "ESCALATION_RECORDED_ONLY", decision["limitations"]
        )

    def test_rationale_absence_is_explicit(self):
        decision, rejection = self.build(
            {"decision_type": "DEFER"}
        )
        self.assertEqual(rejection, "")
        self.assertEqual(
            decision["rationale"]["rationale_state"],
            RATIONALE_STATE_NOT_PROVIDED,
        )
        self.assertIn(
            "RATIONALE_NOT_PROVIDED", decision["limitations"]
        )
        self.assertEqual(
            decision["audit"]["decision_rationale_state"],
            RATIONALE_STATE_NOT_PROVIDED,
        )

    def test_rationale_is_preserved(self):
        decision, _ = self.build(
            {
                "decision_type": "REJECT",
                "rationale_codes": ["FAILS_RESEARCH_SCOPE"],
                "rationale_note": "Outside the program research scope.",
            }
        )
        self.assertEqual(
            decision["rationale"]["rationale_codes"],
            ["FAILS_RESEARCH_SCOPE"],
        )
        self.assertEqual(
            decision["rationale"]["rationale_note"],
            "Outside the program research scope.",
        )

    def test_decision_id_is_content_derived(self):
        first, _ = self.build({"decision_type": "DEFER"})
        second, _ = self.build({"decision_type": "DEFER"})
        third, _ = self.build({"decision_type": "REJECT"})
        self.assertEqual(first["decision_id"], second["decision_id"])
        self.assertNotEqual(first["decision_id"], third["decision_id"])


class TestBuildReview(unittest.TestCase):
    def setUp(self):
        result, plan = plan_for()
        self.result = result
        self.plan = plan
        self.provenance = {
            "finding_rule_version": "r53-6",
            "correlation_rule_version": "",
            "priority_rule_version": result["priority_rule_version"],
            "decisor_rule_version": "r56-1",
            "prioritization_id": result["prioritization_id"],
            "correlation_id": "",
            "orchestration_id": "orch-" + "1" * 16,
            "agent_id": plan["agent_id"],
            "category": plan["category"],
            "decision_source": "HUMAN",
            "source_stages": [],
            "deterministic": True,
            "research_only": True,
        }

    def build(self, request=None, previous_review=None):
        return build_review(
            finding_id=FINDING_ID,
            plan=self.plan,
            prioritization_id=self.result["prioritization_id"],
            correlation_reference_value={},
            provenance_value=self.provenance,
            governance=sanitize_human_governance(
                self.plan.get("governance")
            ),
            request=request,
            previous_review=previous_review,
        )

    def test_pending_review_has_no_decision(self):
        review, rejection = self.build()
        self.assertEqual(rejection, "")
        self.assertEqual(
            review["review_state"], DECISION_STATE_PENDING
        )
        self.assertEqual(review["decision"], {})
        self.assertTrue(review["priority_immutable"])
        self.assertIn(
            "PENDING_HUMAN_DECISION", review["limitations"]
        )
        self.assertEqual(review["audit"]["audit_state"], "UNKNOWN")

    def test_decided_review_audit_is_valid(self):
        review, rejection = self.build(
            {"decision_type": "APPROVE_RESEARCH"}
        )
        self.assertEqual(rejection, "")
        self.assertEqual(review["review_state"], DECISION_STATE_DECIDED)
        self.assertEqual(review["audit"]["audit_state"], "VALID")
        self.assertEqual(
            review["audit"]["human_decision_type"], "APPROVE_RESEARCH"
        )

    def test_rejected_request_leaves_review_pending(self):
        review, rejection = self.build(
            {"decision_type": "APPROVE_RESEARCH", "execution_authorized": True}
        )
        self.assertEqual(rejection, REJECTION_EXECUTION_AUTHORIZATION)
        self.assertEqual(
            review["review_state"], DECISION_STATE_PENDING
        )
        self.assertEqual(review["decision"], {})

    def test_expired_review_records_no_decision(self):
        review, rejection = self.build({"decision_state": "EXPIRED"})
        self.assertEqual(rejection, "")
        self.assertEqual(review["review_state"], DECISION_STATE_EXPIRED)
        self.assertEqual(review["decision"], {})
        self.assertIn("REVIEW_EXPIRED", review["limitations"])

    def test_supersession_preserves_history(self):
        first, _ = self.build({"decision_type": "APPROVE_RESEARCH"})
        second, rejection = self.build(
            {
                "decision_type": "DEFER",
                "rationale_codes": ["CONFLICT_REQUIRES_RESOLUTION"],
            },
            previous_review=first,
        )
        self.assertEqual(rejection, "")
        self.assertEqual(second["transition"]["from_state"], "DECIDED")
        self.assertEqual(second["transition"]["to_state"], "DECIDED")
        self.assertEqual(
            second["transition"]["transition_reason"],
            "DECISION_SUPERSEDED",
        )
        self.assertEqual(len(second["decision_history"]), 1)
        self.assertEqual(
            second["previous_decision"]["decision_type"],
            "APPROVE_RESEARCH",
        )
        self.assertIn("DECISION_HISTORY_PRESENT", second["limitations"])

    def test_expired_cannot_transition(self):
        review = dict(
            HumanReviewPlan(
                **{
                    "review_id": "hrv-" + "c" * 16,
                    "finding_id": FINDING_ID,
                    "review_state": "EXPIRED",
                }
            ).model_dump(mode="json")
        )
        result, rejection = self.build(
            {"decision_type": "DEFER"}, previous_review=review
        )
        self.assertEqual(rejection, REJECTION_INVALID_TRANSITION)
        self.assertEqual(result["decision"], {})

    def test_decision_summary_is_bounded(self):
        review, _ = self.build({"decision_type": "DEFER"})
        summary = decision_summary(review["decision"])
        self.assertEqual(summary["decision_type"], "DEFER")
        self.assertEqual(summary["decision_state"], "DECIDED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
