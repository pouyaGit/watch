"""Focused tests for the R72 evidence sufficiency / decision readiness planner.

All tests are offline and pure: R72 consumes real R70 action plans and real R71
acquisition plans built from validated-hypothesis-shaped mappings. No provider,
Mongo, network or file system access happens here.
"""

from __future__ import annotations

import json
import unittest

from ai.knowledge.research_decision_readiness_planner import (
    ACQUISITION_NOT_REQUIRED,
    ACQUISITION_PLANNED,
    ACQUISITION_STATUSES,
    ACQUISITION_UNAVAILABLE,
    BASIS_ALL_REQUIRED_EVIDENCE_AVAILABLE,
    BASIS_NO_DECISION_EVIDENCE,
    BASIS_NO_REQUIREMENTS,
    BASIS_PARTIAL_DECISION_EVIDENCE,
    BLOCKER_NO_REQUIRED_EVIDENCE,
    CLASS_DECISION,
    CLASS_SUPPORT,
    DECISION_BASIS_CODES,
    DECISION_NEEDS_EVIDENCE,
    DECISION_READY_FOR_HUMAN_REVIEW,
    DECISION_REMAINS_UNRESOLVED,
    DECISION_STATES,
    INSTRUCTION_ACQUIRE,
    INSTRUCTION_CODES,
    INSTRUCTION_REVIEW,
    INSTRUCTION_UNRESOLVED,
    REQUIREMENT_CLASSES,
    RULE_VERSION,
    SUFFICIENCY_INSUFFICIENT,
    SUFFICIENCY_PARTIAL,
    SUFFICIENCY_STATES,
    SUFFICIENCY_SUFFICIENT_FOR_REVIEW,
    DecisionReadinessError,
    plan_decision_readiness,
    requirement_class_of,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    plan_evidence_acquisition,
)
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PATH_RECON = "path:/api/v1/jobs/search"
PARAM = "parameter:client"
RESPONSE_REF = "response:jobs-response-1"
AUTH_REF = "authorization:owner-comparison-1"
STATUS_REF = "status:404-on-other-principal"


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
    priority: str = "MEDIUM",
    confidence: str = "MEDIUM",
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
        "priority": priority,
        "confidence": confidence,
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


def readiness_for(hypotheses, **kwargs) -> dict:
    action_plan = plan_research_actions(hypotheses)
    acquisition_plan = plan_evidence_acquisition(action_plan)
    return plan_decision_readiness(action_plan, acquisition_plan, **kwargs)


def first_record(hypotheses, **kwargs) -> dict:
    return readiness_for(hypotheses, **kwargs)["records"][0]


class TestReadinessModel(unittest.TestCase):
    def test_plan_becomes_readiness_record(self):
        result = readiness_for([hypothesis()])
        self.assertEqual(result["rule_version"], RULE_VERSION)
        self.assertEqual(RULE_VERSION, "r72-1")
        self.assertEqual(result["source_action_rule_version"], "r70-1")
        self.assertEqual(result["source_acquisition_rule_version"], "r71-1")
        self.assertEqual(len(result["records"]), 1)
        record = result["records"][0]
        self.assertEqual(record["readiness_id"], "R1")
        self.assertEqual(record["order"], 1)
        self.assertEqual(record["plan_ref"], "P1")
        self.assertEqual(record["action_ref"], "A1")
        self.assertEqual(record["gap_id"], "OBJECT_AUTHORIZATION")
        self.assertEqual(record["category"], "IDOR")
        self.assertIn(record["evidence_state"], ("STRUCTURE_AND_SIGNAL",))
        for field in (
            "evidence_gap",
            "stop_condition",
            "decision_basis",
            "next_decision_step",
        ):
            self.assertTrue(record[field], field)

    def test_required_evidence_is_classified(self):
        record = first_record([hypothesis()])
        classes = {
            entry["requirement_kind"]: entry["requirement_class"]
            for entry in record["required_evidence"]
        }
        self.assertEqual(classes["OBJECT_REFERENCE"], CLASS_SUPPORT)
        self.assertEqual(classes["WATCH_SIGNAL"], CLASS_SUPPORT)
        self.assertEqual(classes["AUTHORIZATION_OUTCOME"], CLASS_DECISION)
        self.assertEqual(classes["OWNERSHIP_BINDING"], CLASS_DECISION)

    def test_unknown_requirement_kind_is_decision_class(self):
        self.assertEqual(requirement_class_of("TOTALLY_NEW"), CLASS_DECISION)
        for kind in ("OBJECT_REFERENCE", "WATCH_SIGNAL"):
            self.assertEqual(requirement_class_of(kind), CLASS_SUPPORT)
        for kind in ("AUTHORIZATION_OUTCOME", "COMPONENT_BINDING"):
            self.assertEqual(requirement_class_of(kind), CLASS_DECISION)

    def test_hypothesis_titles_are_carried(self):
        record = first_record([hypothesis(title="Possible IDOR")])
        self.assertEqual(record["hypothesis_titles"], ["Possible IDOR"])


class TestSufficiency(unittest.TestCase):
    def test_structural_only_is_insufficient_even_when_high(self):
        record = first_record(
            [hypothesis(priority="HIGH", confidence="HIGH")]
        )
        self.assertEqual(
            record["sufficiency_state"], SUFFICIENCY_INSUFFICIENT
        )
        self.assertEqual(record["decision_state"], DECISION_NEEDS_EVIDENCE)
        self.assertEqual(
            record["decision_basis"]["code"], BASIS_NO_DECISION_EVIDENCE
        )
        self.assertEqual(record["decision_basis"]["decision_satisfied"], 0)

    def test_partial_decision_evidence_is_partially_sufficient(self):
        record = first_record(
            [
                hypothesis(
                    observations=[
                        observation(PATH_OBJECT),
                        observation(PARAM),
                        observation(STATUS_REF),
                    ]
                )
            ]
        )
        self.assertEqual(
            record["sufficiency_state"], SUFFICIENCY_PARTIAL
        )
        self.assertEqual(record["decision_state"], DECISION_NEEDS_EVIDENCE)
        self.assertEqual(
            record["decision_basis"]["code"],
            BASIS_PARTIAL_DECISION_EVIDENCE,
        )
        self.assertIn(
            "OWNERSHIP_BINDING", record["blocking_codes"]
        )
        self.assertNotIn(
            "AUTHORIZATION_OUTCOME", record["blocking_codes"]
        )

    def test_all_required_evidence_is_sufficient_for_review(self):
        record = first_record(
            [
                hypothesis(
                    observations=[
                        observation(PATH_OBJECT),
                        observation(RESPONSE_REF),
                        observation(AUTH_REF),
                    ]
                )
            ]
        )
        self.assertEqual(
            record["sufficiency_state"], SUFFICIENCY_SUFFICIENT_FOR_REVIEW
        )
        self.assertEqual(
            record["decision_state"], DECISION_READY_FOR_HUMAN_REVIEW
        )
        self.assertEqual(
            record["acquisition_status"], ACQUISITION_NOT_REQUIRED
        )
        self.assertEqual(record["blocking_requirements"], [])
        self.assertEqual(record["blocking_codes"], [])
        self.assertEqual(
            record["decision_basis"]["code"],
            BASIS_ALL_REQUIRED_EVIDENCE_AVAILABLE,
        )
        self.assertEqual(
            record["next_decision_step"]["instruction"], INSTRUCTION_REVIEW
        )

    def test_missing_support_is_not_blocking(self):
        record = first_record(
            [
                hypothesis(
                    observations=[
                        observation(PATH_OBJECT),
                        observation(RESPONSE_REF),
                        observation(AUTH_REF),
                    ],
                    signals=[],
                )
            ]
        )
        self.assertEqual(
            record["sufficiency_state"], SUFFICIENCY_SUFFICIENT_FOR_REVIEW
        )
        self.assertEqual(record["blocking_codes"], [])
        self.assertIn(
            "WATCH_SIGNAL", record["non_blocking_missing_requirements"]
        )
        self.assertEqual(record["acquisition_status"], ACQUISITION_PLANNED)

    def test_vocabularies_are_closed(self):
        record = first_record([hypothesis()])
        self.assertIn(record["sufficiency_state"], SUFFICIENCY_STATES)
        self.assertIn(record["decision_state"], DECISION_STATES)
        self.assertIn(record["acquisition_status"], ACQUISITION_STATUSES)
        self.assertIn(record["decision_basis"]["code"], DECISION_BASIS_CODES)
        self.assertIn(
            record["next_decision_step"]["instruction"], INSTRUCTION_CODES
        )
        for entry in record["required_evidence"]:
            self.assertIn(entry["requirement_class"], REQUIREMENT_CLASSES)


class TestBlockingAndIntegration(unittest.TestCase):
    def test_blocking_requirements_identify_missing_decision_kinds(self):
        record = first_record([hypothesis()])
        self.assertEqual(
            record["blocking_codes"],
            ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"],
        )
        kinds = [entry["requirement_kind"] for entry in record["blocking_requirements"]]
        self.assertEqual(kinds, ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"])
        for entry in record["blocking_requirements"]:
            self.assertEqual(entry["requirement_class"], CLASS_DECISION)
            self.assertTrue(entry["description"])

    def test_next_decision_step_references_r71_plan(self):
        action_plan = plan_research_actions([hypothesis()])
        acquisition_plan = plan_evidence_acquisition(action_plan)
        record = plan_decision_readiness(action_plan, acquisition_plan)[
            "records"
        ][0]
        step = record["next_decision_step"]
        self.assertEqual(step["instruction"], INSTRUCTION_ACQUIRE)
        self.assertEqual(step["plan_ref"], acquisition_plan["plans"][0]["plan_id"])
        self.assertEqual(
            step["action_ref"], acquisition_plan["plans"][0]["action_ref"]
        )
        self.assertEqual(
            step["targets"], ["AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"]
        )
        self.assertEqual(
            step["sources"],
            acquisition_plan["plans"][0]["acquisition_sources"],
        )

    def test_stop_condition_comes_from_r71_plan(self):
        action_plan = plan_research_actions([hypothesis()])
        acquisition_plan = plan_evidence_acquisition(action_plan)
        record = plan_decision_readiness(action_plan, acquisition_plan)[
            "records"
        ][0]
        self.assertEqual(
            record["stop_condition"],
            acquisition_plan["plans"][0]["stopping_condition"],
        )

    def test_correlation_is_preserved(self):
        result = readiness_for(
            [
                hypothesis(title="First IDOR"),
                hypothesis(title="Second IDOR"),
            ]
        )
        self.assertEqual(len(result["records"]), 1)
        record = result["records"][0]
        self.assertEqual(record["hypothesis_refs"], ["H1", "H2"])
        self.assertEqual(record["hypothesis_count"], 2)
        self.assertEqual(result["summary"]["covered_hypotheses"], 2)

    def test_category_aware_readiness(self):
        cases = {
            "IDOR": ("AUTHORIZATION_OUTCOME", (PATH_OBJECT, "IDOR")),
            "SSRF": ("FETCH_BEHAVIOR", ("parameter:url", "SSRF")),
            "XSS": ("RESPONSE_CONTEXT", ("parameter:q", "XSS")),
            "SQLI": ("QUERY_RESPONSE", ("parameter:q", "SQLI")),
            "JWT": ("VALIDATION_ARTIFACT", ("token:jwt-artifact", "JWT")),
            "OAUTH": ("FLOW_ARTIFACT", ("parameter:state", "")),
            "RECON": ("RESPONSE_BEHAVIOR", (PATH_RECON, "RECON")),
            "CVE_RESEARCH": ("COMPONENT_BINDING", ("technology:nginx", "")),
        }
        for category, (blocker, (ref, signal_name)) in cases.items():
            with self.subTest(category=category):
                observations = [observation(ref)]
                if category == "CVE_RESEARCH":
                    observations.append(observation("version:1.24.0"))
                signals = (
                    [signal(signal_name, "detail")] if signal_name else []
                )
                record = first_record(
                    [
                        hypothesis(
                            category=category,
                            observations=observations,
                            signals=signals,
                        )
                    ]
                )
                self.assertEqual(
                    record["decision_state"], DECISION_NEEDS_EVIDENCE
                )
                self.assertIn(blocker, record["blocking_codes"])
                self.assertEqual(
                    requirement_class_of(blocker), CLASS_DECISION
                )

    def test_statuses_flow_from_r71(self):
        record = first_record([hypothesis()])
        statuses = {
            entry["requirement_kind"]: entry["status"]
            for entry in record["required_evidence"]
        }
        self.assertEqual(statuses["OBJECT_REFERENCE"], "AVAILABLE")
        self.assertEqual(statuses["WATCH_SIGNAL"], "AVAILABLE")
        self.assertEqual(statuses["AUTHORIZATION_OUTCOME"], "MISSING")
        available = {
            entry["requirement_kind"] for entry in record["available_evidence"]
        }
        self.assertEqual(available, {"OBJECT_REFERENCE", "WATCH_SIGNAL"})


class TestEvidenceStatesAndSummary(unittest.TestCase):
    def test_corroborating_evidence_state(self):
        record = first_record(
            [
                hypothesis(
                    observations=[
                        observation(PATH_OBJECT),
                        observation(RESPONSE_REF),
                        observation(AUTH_REF),
                    ]
                )
            ]
        )
        self.assertEqual(record["evidence_state"], "CORROBORATED")

    def test_derived_only_evidence_state(self):
        record = first_record(
            [
                hypothesis(
                    observations=[],
                    signals=[signal("IDOR", "object_reference=PATH_PARAMETER")],
                )
            ]
        )
        self.assertEqual(record["evidence_state"], "DERIVED_ONLY")

    def test_summary_reports_bands(self):
        result = readiness_for(
            [
                hypothesis(),
                hypothesis(
                    category="RECON",
                    observations=[observation(PATH_RECON)],
                    signals=[signal("RECON", "api_type=REST")],
                ),
            ]
        )
        summary = result["summary"]
        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["covered_plans"], 2)
        self.assertEqual(summary["covered_actions"], 2)
        self.assertEqual(summary["covered_hypotheses"], 2)
        self.assertEqual(summary["sufficiency_bands"][SUFFICIENCY_INSUFFICIENT], 2)
        self.assertEqual(summary["decision_bands"][DECISION_NEEDS_EVIDENCE], 2)
        self.assertEqual(summary["top_readiness_id"], "R1")
        self.assertEqual(summary["top_sufficiency_state"], SUFFICIENCY_INSUFFICIENT)


class TestFailClosedAndSafety(unittest.TestCase):
    def test_deterministic_output(self):
        hypotheses = [
            hypothesis(),
            hypothesis(
                category="RECON",
                observations=[observation(PATH_RECON)],
                signals=[signal("RECON", "api_type=REST")],
            ),
        ]
        first = readiness_for(hypotheses)
        second = readiness_for(hypotheses)
        self.assertEqual(json.dumps(first), json.dumps(second))

    def test_empty_inputs_fail_closed(self):
        result = plan_decision_readiness(None, None)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["summary"]["record_count"], 0)
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        malformed = plan_decision_readiness(["x", 3], {"plans": ["x", 7]})
        self.assertEqual(malformed["records"], [])

    def test_plan_without_required_evidence_is_unresolved(self):
        broken = {"plans": [{"plan_id": "P1", "action_ref": "A1"}]}
        record = plan_decision_readiness(None, broken)["records"][0]
        self.assertEqual(
            record["sufficiency_state"], SUFFICIENCY_INSUFFICIENT
        )
        self.assertEqual(
            record["decision_state"], DECISION_REMAINS_UNRESOLVED
        )
        self.assertEqual(
            record["acquisition_status"], ACQUISITION_UNAVAILABLE
        )
        self.assertEqual(
            record["blocking_codes"], [BLOCKER_NO_REQUIRED_EVIDENCE]
        )
        self.assertEqual(
            record["decision_basis"]["code"], BASIS_NO_REQUIREMENTS
        )
        self.assertEqual(
            record["next_decision_step"]["instruction"],
            INSTRUCTION_UNRESOLVED,
        )

    def test_unknown_status_defaults_to_missing(self):
        broken = {
            "plans": [
                {
                    "plan_id": "P1",
                    "action_ref": "A1",
                    "required_evidence": [
                        {
                            "requirement_kind": "AUTHORIZATION_OUTCOME",
                            "status": "BANANA",
                            "description": "x",
                        }
                    ],
                }
            ]
        }
        record = plan_decision_readiness(None, broken)["records"][0]
        self.assertEqual(
            record["required_evidence"][0]["status"], "MISSING"
        )
        self.assertEqual(record["decision_state"], DECISION_NEEDS_EVIDENCE)

    def test_limit_is_validated_and_applied(self):
        action_plan = plan_research_actions(
            [
                hypothesis(),
                hypothesis(
                    category="RECON",
                    observations=[observation(PATH_RECON)],
                    signals=[signal("RECON", "api_type=REST")],
                ),
            ]
        )
        acquisition_plan = plan_evidence_acquisition(action_plan)
        limited = plan_decision_readiness(
            action_plan, acquisition_plan, limit=1
        )
        self.assertEqual(len(limited["records"]), 1)
        self.assertEqual(limited["records"][0]["readiness_id"], "R1")
        empty = plan_decision_readiness(action_plan, acquisition_plan, limit=0)
        self.assertEqual(empty["records"], [])
        with self.assertRaises(DecisionReadinessError):
            plan_decision_readiness(action_plan, acquisition_plan, limit=-1)
        with self.assertRaises(DecisionReadinessError):
            plan_decision_readiness(action_plan, acquisition_plan, limit=True)

    def test_safety_flags_forced(self):
        result = readiness_for([hypothesis()])
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertTrue(result["research_only"])
        for record in result["records"]:
            self.assertEqual(record["safety"], SAFETY_BLOCK)
            self.assertEqual(record["confirmation_state"], "NOT_CONFIRMED")
            self.assertTrue(record["advisory"])
            self.assertTrue(record["research_only"])
            self.assertFalse(record["safety"]["execution_performed"])
            self.assertFalse(record["safety"]["vulnerability_confirmed"])
            self.assertFalse(record["safety"]["exploit_authorized"])
            self.assertTrue(record["safety"]["human_authority_required"])

    def test_no_confirmation_or_execution_semantics(self):
        result = readiness_for(
            [
                hypothesis(),
                hypothesis(category="RECON", observations=[observation(PATH_RECON)]),
            ]
        )
        payload = json.loads(json.dumps(result))
        payload.pop("safety", None)
        for record in payload["records"]:
            record.pop("safety", None)
        text = json.dumps(payload)
        scrubbed = text.replace("NOT_CONFIRMED", "")
        for forbidden in (
            "CONFIRMED",
            "VULNERABLE",
            "EXPLOITABLE",
            "EXPLOIT",
            "PAYLOAD",
            "CURL ",
            "SQLMAP",
            "NUCLEI",
            "HTTP://",
            "HTTPS://",
            "://",
            "SK-",
            "BEARER",
        ):
            self.assertNotIn(forbidden, scrubbed.upper(), forbidden)

    def test_sensitive_data_hygiene(self):
        secret = "supersecretvalue12345"
        record = first_record(
            [
                hypothesis(
                    observations=[
                        observation(PATH_OBJECT),
                        observation(
                            "authorization:token=supersecretvalue12345",
                            f"authorization token={secret}",
                        ),
                    ]
                )
            ]
        )
        text = json.dumps(record)
        self.assertNotIn(secret, text)
        self.assertNotIn("://", text)
        for entry in record["blocking_requirements"]:
            self.assertLessEqual(len(entry["description"]), 320)


if __name__ == "__main__":
    unittest.main()
