"""tests/test_research_consistency_validator.py — Stage R31.21 tests.

Deterministic, offline tests for the research consistency validator:

- deterministic output
- valid full chain
- decision/lifecycle, lifecycle/outcome, outcome/feedback, outcome/summary
  mismatches
- missing mandatory stages and invalid vocabulary values
- unknown (no input at all) and malformed input handling
- no mutation of the R31.13-R31.20 inputs
- closed vocabulary enforcement, JSON serialization
- research_only always true, no operational attack content

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import evidence_acquisition_planner as eap
from ai.knowledge import evidence_confidence_aggregator as eca
from ai.knowledge import evidence_decision_planner as edp
from ai.knowledge import evidence_feedback_calibration_planner as efp
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import evidence_research_loop_planner as erl
from ai.knowledge import evidence_research_outcome_tracker as eot
from ai.knowledge import research_consistency_validator as rcv
from ai.knowledge import research_intelligence_summary_planner as risp
from ai.schemas import research_consistency_validation as schema

CVE = "CVE-2026-1560"

TARGETS_BY_METHOD = {
    eap.EXISTING_EVIDENCE_REVIEW: eap.TARGET_EXISTING_EVIDENCE,
    eap.COMPONENT_IDENTITY_LOOKUP: eap.TARGET_COMPONENT_IDENTITY,
    eap.VERSION_LOOKUP: eap.TARGET_VERSION,
    eap.SCOPE_EVIDENCE_REVIEW: eap.TARGET_SCOPE,
    eap.PATH_EVIDENCE_REVIEW: eap.TARGET_PATH,
    eap.PARAMETER_EVIDENCE_REVIEW: eap.TARGET_PARAMETER,
    eap.HTTP_BEHAVIOR_REVIEW: eap.TARGET_HTTP_BEHAVIOR,
    eap.TECHNOLOGY_EVIDENCE_REVIEW: eap.TARGET_TECHNOLOGY,
    eap.MANUAL_RESEARCH: eap.TARGET_EXISTING_EVIDENCE,
}


def acquisition_plan(method, target=None, **over):
    if target is None:
        if method == eap.NO_ACQUISITION:
            target = eap.TARGET_NONE
        else:
            target = TARGETS_BY_METHOD[method]
    plan = {
        "rule_version": "r31-13",
        "acquisition_method": method,
        "acquisition_rank": 0,
        "evidence_target": target,
        "evidence_gap": "GAP_NONE",
        "completion_condition": "EXISTING_EVIDENCE_REVIEWED",
        "reason_codes": ["SOURCE_ACTION"],
        "source_action": "VERIFY_EXISTING_EVIDENCE",
        "source_actionability": "IMMEDIATE_VERIFICATION",
        "source_priority": "P0",
        "source_hunt_score": 96,
        "confidence": "HIGH",
        "estimated_effort": "LOW",
        "acquisition_order_key": [0, 0, -96],
        "research_only": True,
    }
    plan.update(over)
    return plan


def chain(method, **over):
    acquisition = acquisition_plan(method, **over)
    prioritization = epp.plan_evidence_prioritization(acquisition)
    confidence = eca.aggregate_evidence_confidence(
        acquisition, prioritization
    )
    decision = edp.plan_evidence_decision(
        acquisition, prioritization, confidence
    )
    loop = erl.plan_evidence_research_loop(
        acquisition, prioritization, confidence, decision
    )
    outcome = eot.track_evidence_research_outcome(
        acquisition, prioritization, confidence, decision, loop
    )
    feedback = efp.plan_evidence_feedback_calibration(
        acquisition, prioritization, confidence, decision, loop, outcome
    )
    summary = risp.plan_research_intelligence_summary(
        acquisition, prioritization, confidence, decision, loop, outcome,
        feedback,
    )
    validation = rcv.validate_research_consistency(
        acquisition, prioritization, confidence, decision, loop, outcome,
        feedback, summary,
    )
    return {
        "acquisition": acquisition,
        "prioritization": prioritization,
        "confidence": confidence,
        "decision": decision,
        "loop": loop,
        "outcome": outcome,
        "feedback": feedback,
        "summary": summary,
        "validation": validation,
    }


def validate(data):
    return rcv.validate_research_consistency(
        data.get("acquisition"),
        data.get("prioritization"),
        data.get("confidence"),
        data.get("decision"),
        data.get("loop"),
        data.get("outcome"),
        data.get("feedback"),
        data.get("summary"),
    )


# ---------------------------------------------------------------------------
# valid chain
# ---------------------------------------------------------------------------


class TestValidChain(unittest.TestCase):
    def test_valid_chain_for_every_method(self):
        for method in TARGETS_BY_METHOD:
            data = chain(method)
            validation = data["validation"]
            self.assertEqual(validation["validation_status"],
                             schema.VALIDATION_VALID, method)
            self.assertTrue(validation["valid"], method)
            self.assertEqual(validation["detected_issues"], [], method)
            self.assertEqual(validation["checked_stages"],
                             list(schema.CHECKED_STAGES), method)

    def test_valid_deferred_chain(self):
        data = chain(eap.NO_ACQUISITION)
        self.assertEqual(data["outcome"]["outcome"], "DEFERRED")
        self.assertEqual(data["validation"]["validation_status"],
                         schema.VALIDATION_VALID)

    def test_checked_stages_are_closed_and_ordered(self):
        validation = chain(eap.VERSION_LOOKUP)["validation"]
        self.assertEqual(
            validation["checked_stages"],
            [
                "R31_13_ACQUISITION",
                "R31_14_PRIORITIZATION",
                "R31_15_CONFIDENCE",
                "R31_16_DECISION",
                "R31_17_LOOP",
                "R31_18_OUTCOME",
                "R31_19_FEEDBACK",
                "R31_20_SUMMARY",
            ],
        )


# ---------------------------------------------------------------------------
# mismatches
# ---------------------------------------------------------------------------


class TestMismatches(unittest.TestCase):
    def test_decision_lifecycle_mismatch(self):
        data = chain(eap.EXISTING_EVIDENCE_REVIEW)
        data["loop"] = dict(data["loop"])
        data["loop"]["lifecycle_state"] = "WAITING_FOR_EVIDENCE"
        validation = validate(data)
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_INVALID)
        self.assertIn(schema.DECISION_LIFECYCLE_MISMATCH,
                      validation["detected_issues"])

    def test_lifecycle_outcome_mismatch(self):
        data = chain(eap.VERSION_LOOKUP)
        data["outcome"] = dict(data["outcome"])
        data["outcome"]["outcome"] = "DEFERRED"
        validation = validate(data)
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_INVALID)
        self.assertIn(schema.LIFECYCLE_OUTCOME_MISMATCH,
                      validation["detected_issues"])

    def test_outcome_feedback_mismatch(self):
        data = chain(eap.VERSION_LOOKUP)
        data["feedback"] = dict(data["feedback"])
        data["feedback"]["feedback_type"] = "DEFER_SIGNAL"
        validation = validate(data)
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_INVALID)
        self.assertIn(schema.OUTCOME_FEEDBACK_MISMATCH,
                      validation["detected_issues"])

    def test_outcome_summary_mismatch(self):
        data = chain(eap.VERSION_LOOKUP)
        data["summary"] = dict(data["summary"])
        data["summary"]["research_status"] = "COMPLETE"
        validation = validate(data)
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_INVALID)
        self.assertIn(schema.OUTCOME_SUMMARY_MISMATCH,
                      validation["detected_issues"])

    def test_multiple_mismatches_are_reported(self):
        data = chain(eap.EXISTING_EVIDENCE_REVIEW)
        data["loop"] = dict(data["loop"])
        data["outcome"] = dict(data["outcome"])
        data["feedback"] = dict(data["feedback"])
        data["loop"]["lifecycle_state"] = "WAITING_FOR_EVIDENCE"
        data["outcome"]["outcome"] = "DEFERRED"
        data["feedback"]["feedback_type"] = "SUCCESS_SIGNAL"
        validation = validate(data)
        self.assertFalse(validation["valid"])
        self.assertIn(schema.DECISION_LIFECYCLE_MISMATCH,
                      validation["detected_issues"])
        self.assertIn(schema.LIFECYCLE_OUTCOME_MISMATCH,
                      validation["detected_issues"])
        self.assertIn(schema.OUTCOME_FEEDBACK_MISMATCH,
                      validation["detected_issues"])


# ---------------------------------------------------------------------------
# missing stages and invalid vocabulary
# ---------------------------------------------------------------------------


class TestMissingAndInvalid(unittest.TestCase):
    def test_missing_stage_reported(self):
        data = chain(eap.VERSION_LOOKUP)
        data["prioritization"] = None
        validation = validate(data)
        self.assertFalse(validation["valid"])
        self.assertIn(schema.MISSING_PRIORITIZATION_PLAN,
                      validation["detected_issues"])

    def test_all_missing_is_unknown(self):
        validation = rcv.validate_research_consistency()
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_UNKNOWN)
        self.assertFalse(validation["valid"])
        for issue in (
            schema.MISSING_ACQUISITION_PLAN,
            schema.MISSING_PRIORITIZATION_PLAN,
            schema.MISSING_CONFIDENCE_PLAN,
            schema.MISSING_DECISION_PLAN,
            schema.MISSING_LOOP_PLAN,
            schema.MISSING_OUTCOME_PLAN,
            schema.MISSING_FEEDBACK_PLAN,
            schema.MISSING_SUMMARY_PLAN,
        ):
            self.assertIn(issue, validation["detected_issues"])

    def test_partial_input_is_invalid_not_unknown(self):
        validation = rcv.validate_research_consistency(
            acquisition_plan(eap.VERSION_LOOKUP)
        )
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_INVALID)
        self.assertIn(schema.MISSING_DECISION_PLAN,
                      validation["detected_issues"])

    def test_invalid_vocabulary_values(self):
        data = chain(eap.VERSION_LOOKUP)
        data["acquisition"] = dict(data["acquisition"])
        data["confidence"] = dict(data["confidence"])
        data["decision"] = dict(data["decision"])
        data["loop"] = dict(data["loop"])
        data["outcome"] = dict(data["outcome"])
        data["feedback"] = dict(data["feedback"])
        data["summary"] = dict(data["summary"])
        data["acquisition"]["acquisition_method"] = "DEPLOY_EXPLOIT"
        data["confidence"]["confidence_level"] = "CERTAIN"
        data["confidence"]["confidence_category"] = "EXPLOITABLE"
        data["decision"]["decision"] = "SHIP_IT"
        data["loop"]["lifecycle_state"] = "RUNNING"
        data["outcome"]["outcome"] = "WINNER"
        data["feedback"]["feedback_type"] = "WIN_SIGNAL"
        data["summary"]["research_status"] = "DONE"
        validation = validate(data)
        self.assertFalse(validation["valid"])
        for issue in (
            schema.INVALID_ACQUISITION_METHOD,
            schema.INVALID_CONFIDENCE_LEVEL,
            schema.INVALID_CONFIDENCE_CATEGORY,
            schema.INVALID_DECISION,
            schema.INVALID_LIFECYCLE_STATE,
            schema.INVALID_OUTCOME,
            schema.INVALID_FEEDBACK_TYPE,
            schema.INVALID_RESEARCH_STATUS,
        ):
            self.assertIn(issue, validation["detected_issues"])

    def test_invalid_summary_status_does_not_trigger_mismatch(self):
        data = chain(eap.VERSION_LOOKUP)
        data["summary"] = dict(data["summary"])
        data["summary"]["research_status"] = "DONE"
        validation = validate(data)
        self.assertIn(schema.INVALID_RESEARCH_STATUS,
                      validation["detected_issues"])
        self.assertNotIn(schema.OUTCOME_SUMMARY_MISMATCH,
                         validation["detected_issues"])

    def test_malformed_non_dict_inputs(self):
        validation = rcv.validate_research_consistency(
            "x", [], 0, None, "loop", 1, "fb", "summary"
        )
        self.assertEqual(validation["validation_status"],
                         schema.VALIDATION_UNKNOWN)
        self.assertFalse(validation["valid"])


# ---------------------------------------------------------------------------
# determinism, no mutation, output shape
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_deterministic_output(self):
        data = chain(eap.VERSION_LOOKUP)
        first = validate(data)
        second = validate(data)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_no_mutation_of_inputs(self):
        data = chain(eap.PARAMETER_EVIDENCE_REVIEW)
        snapshots = {
            key: copy.deepcopy(value)
            for key, value in data.items()
            if key != "validation"
        }
        validate(data)
        for key, before in snapshots.items():
            self.assertEqual(data[key], before, key)

    def test_json_serializable(self):
        validation = chain(eap.VERSION_LOOKUP)["validation"]
        self.assertIsInstance(json.loads(json.dumps(validation)), dict)

    def test_research_only_always_true(self):
        validation = chain(eap.VERSION_LOOKUP)["validation"]
        self.assertIs(validation["research_only"], True)
        self.assertIs(
            rcv.validate_research_consistency()["research_only"], True
        )

    def test_closed_vocabulary(self):
        for method in TARGETS_BY_METHOD:
            validation = chain(method)["validation"]
            self.assertIn(validation["validation_status"],
                          schema.VALIDATION_STATUSES)
            for issue in validation["detected_issues"]:
                self.assertIn(issue, schema.DETECTED_ISSUES)
            for stage in validation["checked_stages"]:
                self.assertIn(stage, schema.CHECKED_STAGES)
        invalid = chain(eap.VERSION_LOOKUP)
        invalid["decision"] = dict(invalid["decision"])
        invalid["decision"]["decision"] = "SHIP_IT"
        validation = validate(invalid)
        for issue in validation["detected_issues"]:
            self.assertIn(issue, schema.DETECTED_ISSUES)

    def test_schema_rejects_invalid_status(self):
        with self.assertRaises(ValidationError):
            schema.ResearchConsistencyValidationPlan(
                valid=True, validation_status="PERFECT"
            )

    def test_schema_rejects_invalid_issue_and_stage(self):
        with self.assertRaises(ValidationError):
            schema.ResearchConsistencyValidationPlan(
                valid=False,
                validation_status="INVALID",
                detected_issues=["DEPLOY_EXPLOIT"],
            )
        with self.assertRaises(ValidationError):
            schema.ResearchConsistencyValidationPlan(
                valid=False,
                validation_status="INVALID",
                checked_stages=["NOT_A_STAGE"],
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.ResearchConsistencyValidationPlan(
            rule_version="r99-9",
            valid=True,
            validation_status="VALID",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r31-21")
        with self.assertRaises(ValidationError):
            schema.ResearchConsistencyValidationPlan(
                valid=True,
                validation_status="VALID",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            rcv.RESEARCH_CONSISTENCY_VALIDATOR_RULE_VERSION, "r31-21"
        )
        validation = chain(eap.VERSION_LOOKUP)["validation"]
        self.assertEqual(validation["rule_version"], "r31-21")

    def test_bounded_issues(self):
        plan = schema.ResearchConsistencyValidationPlan(
            valid=False,
            validation_status="INVALID",
            detected_issues=[schema.MISSING_LOOP_PLAN] * 64,
        )
        self.assertLessEqual(len(plan.detected_issues),
                             schema.MAX_ISSUES)

    def test_no_operational_attack_content(self):
        payload = json.dumps(chain(eap.VERSION_LOOKUP)).lower()
        for marker in (
            "payload", "exploit", "fuzz", "nuclei", "sqlmap",
            "curl ", "wget ", "bypass", "request body",
        ):
            self.assertNotIn(marker, payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
