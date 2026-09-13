"""tests/test_evidence_feedback_calibration_planner.py — Stage R31.19 tests.

Deterministic, offline tests for the evidence feedback calibration planner:

- deterministic output
- all feedback mappings (SUCCESS / CONTINUE / EVIDENCE_GAP / DEFER / UNKNOWN)
- remaining_need -> improvement_area mapping
- unknown and malformed input handling
- no mutation of the R31.13-R31.18 inputs
- closed vocabulary enforcement (planner + pydantic schema)
- bounded, privacy-safe, JSON-serializable output
- plan-only: research_only always true, no operational attack content
- hermetic backend integration (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any research action.
"""
import copy
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import evidence_acquisition_planner as eap
from ai.knowledge import evidence_confidence_aggregator as eca
from ai.knowledge import evidence_decision_planner as edp
from ai.knowledge import evidence_feedback_calibration_planner as efp
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import evidence_research_loop_planner as erl
from ai.knowledge import evidence_research_outcome_tracker as eot
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_confidence as conf_schema
from ai.schemas import evidence_feedback_calibration as schema
from ai.schemas import evidence_research_loop as loop_schema
from ai.schemas import evidence_research_outcome as out_schema
from ai.schemas.hunt_queue import HUNT_RULE_VERSION, hunt_item_projection
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

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
        "reason": "bounded reason",
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


def bundle(method, **over):
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
    return (
        acquisition, prioritization, confidence, decision, loop, outcome,
        feedback,
    )


def quality(level="HIGH", *, consistency="CONSISTENT", conflicts=(),
            gaps=(), strength="STRONG"):
    return {
        "evidence_quality": level,
        "evidence_strength": strength,
        "evidence_consistency": consistency,
        "evidence_gaps": list(gaps),
        "conflicts": list(conflicts),
    }


def ppr(*, exact_path=False, parameter=False, scoped=True):
    rows = []
    if exact_path:
        rows.append({"evidence_type": "EXACT_PATH", "result": "MATCH",
                     "component_scoped": scoped})
    if parameter:
        rows.append({"evidence_type": "EXACT_PARAMETER", "result": "MATCH",
                     "component_scoped": scoped})
    return {
        "evidence": rows,
        "summary": {
            "path_match": exact_path,
            "parameter_match": parameter,
            "method": {"evidence_type": "HTTP_METHOD", "result": "NO_MATCH"},
        },
    }


def immediate_fixture(**over):
    base = dict(
        evidence_quality=quality("HIGH"),
        strongest_match_type="COMPONENT",
        strongest_confidence="HIGH",
        asset_match_state="CONFIRMED",
        matched_component="CKEditor",
        evidence_provenance="EXPLICIT",
        support_scope="COMPONENT_SCOPED",
        version_state="MATCH",
        version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
        version_normalization={
            "rows": [{"comparison": "MATCH", "cve_kind": "EXACT",
                      "cve_evidence_class": "EXACT_OBSERVED"}],
            "observed_versions": [{}],
        },
        path_parameter_relevance=ppr(exact_path=True, parameter=True),
        cve_id=CVE,
    )
    base.update(over)
    return base


def p1_fixture(*, gaps=(), **over):
    base = dict(
        evidence_quality=quality("MEDIUM", strength="SUPPORTING",
                                 gaps=list(gaps)),
        strongest_match_type="PLUGIN",
        strongest_confidence="MEDIUM",
        asset_match_state="SUPPORTED",
        matched_component="wp-smushit",
        evidence_provenance="EXPLICIT",
        cve_id=CVE,
    )
    base.update(over)
    return base


def full_chain(fixture, *, provenance=None, scope=None, strongest=None):
    """Build R31.10 -> ... -> R31.19 outputs with the real engines."""

    hp_result = hp.evaluate_hunt_priority(**fixture)
    ha_result = ha.evaluate_hunt_actionability(
        hp_result,
        evidence_provenance=provenance,
        support_scope=scope,
    )
    action_plan = pl.plan_hunt_action(
        hp_result,
        ha_result,
        evidence_provenance=provenance,
        support_scope=scope,
        strongest_match_type=strongest,
    )
    acquisition = eap.plan_evidence_acquisition(
        hp_result,
        ha_result,
        action_plan,
        evidence_provenance=provenance,
        support_scope=scope,
        strongest_match_type=strongest,
    )
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
    return (
        hp_result, ha_result, action_plan, acquisition,
        prioritization, confidence, decision, loop, outcome, feedback,
    )


# ---------------------------------------------------------------------------
# 2: all feedback mappings
# ---------------------------------------------------------------------------


class TestFeedbackMappings(unittest.TestCase):
    def test_2_success_signal(self):
        (_, _, _, _, _, outcome, feedback) = bundle(
            eap.EXISTING_EVIDENCE_REVIEW
        )
        self.assertEqual(outcome["outcome"], out_schema.OUTCOME_COMPLETED)
        self.assertEqual(feedback["feedback_type"],
                         schema.FEEDBACK_SUCCESS)
        self.assertEqual(feedback["signal_strength"], schema.STRENGTH_HIGH)
        self.assertEqual(feedback["improvement_area"], schema.AREA_NONE)
        self.assertEqual(feedback["outcome"],
                         out_schema.OUTCOME_COMPLETED)
        self.assertEqual(feedback["confidence_level"],
                         conf_schema.CONFIDENCE_HIGH)

    def test_2_continue_signal(self):
        for method, area in (
            (eap.COMPONENT_IDENTITY_LOOKUP, schema.AREA_IDENTITY),
            (eap.VERSION_LOOKUP, schema.AREA_VERSION),
            (eap.SCOPE_EVIDENCE_REVIEW, schema.AREA_SCOPE),
        ):
            (_, _, _, _, _, outcome, feedback) = bundle(method)
            self.assertEqual(outcome["outcome"],
                             out_schema.OUTCOME_IN_PROGRESS)
            self.assertEqual(feedback["feedback_type"],
                             schema.FEEDBACK_CONTINUE, method)
            self.assertEqual(feedback["signal_strength"],
                             schema.STRENGTH_MEDIUM, method)
            self.assertEqual(feedback["improvement_area"], area, method)

    def test_2_evidence_gap_signal(self):
        for method, area in (
            (eap.PATH_EVIDENCE_REVIEW, schema.AREA_PATH),
            (eap.PARAMETER_EVIDENCE_REVIEW, schema.AREA_PARAMETER),
            (eap.HTTP_BEHAVIOR_REVIEW, schema.AREA_HTTP_BEHAVIOR),
            (eap.TECHNOLOGY_EVIDENCE_REVIEW, schema.AREA_TECHNOLOGY),
            (eap.MANUAL_RESEARCH, schema.AREA_HUMAN_RESEARCH),
        ):
            (_, _, _, _, _, outcome, feedback) = bundle(method)
            self.assertEqual(outcome["outcome"],
                             out_schema.OUTCOME_WAITING_FOR_EVIDENCE)
            self.assertEqual(feedback["feedback_type"],
                             schema.FEEDBACK_EVIDENCE_GAP, method)
            self.assertEqual(feedback["signal_strength"],
                             schema.STRENGTH_HIGH, method)
            self.assertEqual(feedback["improvement_area"], area, method)

    def test_2_defer_signal(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
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
        self.assertEqual(outcome["outcome"], out_schema.OUTCOME_DEFERRED)
        self.assertEqual(feedback["feedback_type"], schema.FEEDBACK_DEFER)
        self.assertEqual(feedback["signal_strength"], schema.STRENGTH_LOW)
        self.assertEqual(feedback["improvement_area"], schema.AREA_UNKNOWN)

    def test_2_unknown_signal(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None, None, None, None,
            {"outcome": "UNKNOWN", "remaining_need": "UNKNOWN"},
        )
        self.assertEqual(feedback["feedback_type"],
                         schema.FEEDBACK_UNKNOWN)
        self.assertEqual(feedback["signal_strength"],
                         schema.STRENGTH_UNKNOWN)
        self.assertEqual(feedback["improvement_area"], schema.AREA_PROCESS)
        self.assertEqual(feedback["outcome"], out_schema.OUTCOME_UNKNOWN)

    def test_2_real_engine_chain_all_outcomes(self):
        (_, _, _, _, _, _, _, loop, outcome,
         feedback) = full_chain(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_COMPLETED)
        self.assertEqual(outcome["outcome"], out_schema.OUTCOME_COMPLETED)
        self.assertEqual(feedback["feedback_type"], schema.FEEDBACK_SUCCESS)

    def test_2_outcome_feedback_table_is_closed(self):
        self.assertEqual(
            set(efp.OUTCOME_FEEDBACK),
            set(out_schema.OUTCOMES),
        )
        for outcome, row in efp.OUTCOME_FEEDBACK.items():
            self.assertIn(row[0], schema.FEEDBACK_TYPES, outcome)
            self.assertIn(row[1], schema.SIGNAL_STRENGTHS, outcome)
            if row[2] is not None:
                self.assertIn(row[2], schema.IMPROVEMENT_AREAS, outcome)


# ---------------------------------------------------------------------------
# 3: remaining_need mapping
# ---------------------------------------------------------------------------


class TestRemainingNeedMapping(unittest.TestCase):
    def test_3_all_remaining_needs_map(self):
        expectations = (
            (out_schema.NEED_NONE, schema.AREA_NONE),
            (out_schema.NEED_IDENTITY, schema.AREA_IDENTITY),
            (out_schema.NEED_VERSION, schema.AREA_VERSION),
            (out_schema.NEED_SCOPE, schema.AREA_SCOPE),
            (out_schema.NEED_PATH, schema.AREA_PATH),
            (out_schema.NEED_PARAMETER, schema.AREA_PARAMETER),
            (out_schema.NEED_HTTP_BEHAVIOR, schema.AREA_HTTP_BEHAVIOR),
            (out_schema.NEED_TECHNOLOGY, schema.AREA_TECHNOLOGY),
            (out_schema.NEED_HUMAN_RESEARCH, schema.AREA_HUMAN_RESEARCH),
            (out_schema.NEED_UNKNOWN, schema.AREA_UNKNOWN),
        )
        for need, area in expectations:
            feedback = efp.plan_evidence_feedback_calibration(
                None, None, None, None, None,
                {"outcome": "WAITING_FOR_EVIDENCE", "remaining_need": need},
            )
            self.assertEqual(feedback["improvement_area"], area, need)

    def test_3_invalid_remaining_need_maps_unknown(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None, None, None, None,
            {"outcome": "WAITING_FOR_EVIDENCE", "remaining_need": "MONEY"},
        )
        self.assertEqual(feedback["improvement_area"], schema.AREA_UNKNOWN)

    def test_3_completed_forces_area_none(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None, None, None, None,
            {"outcome": "COMPLETED", "remaining_need": "VERSION"},
        )
        self.assertEqual(feedback["improvement_area"], schema.AREA_NONE)

    def test_3_mapping_table_is_closed(self):
        self.assertEqual(
            set(efp.REMAINING_NEED_TO_IMPROVEMENT.values()),
            set(schema.IMPROVEMENT_AREAS) - {schema.AREA_PROCESS},
        )
        for value in efp.REMAINING_NEED_TO_IMPROVEMENT:
            self.assertIn(value, out_schema.REMAINING_NEEDS)


# ---------------------------------------------------------------------------
# 4-5: unknown and malformed input handling
# ---------------------------------------------------------------------------


class TestUnknownAndMalformed(unittest.TestCase):
    def test_4_unknown_outcome(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None, None, None, None, {"outcome": "UNKNOWN"}
        )
        self.assertEqual(feedback["feedback_type"],
                         schema.FEEDBACK_UNKNOWN)
        self.assertEqual(feedback["signal_strength"],
                         schema.STRENGTH_UNKNOWN)
        self.assertEqual(feedback["improvement_area"], schema.AREA_PROCESS)
        self.assertEqual(feedback["outcome"], out_schema.OUTCOME_UNKNOWN)

    def test_5_missing_inputs(self):
        for values in (
            (None, None, None, None, None, None),
            ({}, {}, {}, {}, {}, {}),
            ("x", [], 0, None, "loop", 1),
        ):
            feedback = efp.plan_evidence_feedback_calibration(*values)
            self.assertEqual(feedback["feedback_type"],
                             schema.FEEDBACK_UNKNOWN, repr(values))
            self.assertEqual(feedback["signal_strength"],
                             schema.STRENGTH_UNKNOWN)
            self.assertEqual(feedback["improvement_area"],
                             schema.AREA_PROCESS)
            self.assertEqual(feedback["outcome"],
                             out_schema.OUTCOME_UNKNOWN)
            self.assertEqual(feedback["confidence_level"],
                             conf_schema.CONFIDENCE_UNKNOWN)

    def test_5_unrecognized_outcome(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None, None, None, None, {"outcome": "SHIP_IT"}
        )
        self.assertEqual(feedback["feedback_type"],
                         schema.FEEDBACK_UNKNOWN)
        self.assertEqual(feedback["outcome"], out_schema.OUTCOME_UNKNOWN)

    def test_5_lowercase_outcome_is_normalized(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None, None, None, None, {"outcome": "completed"}
        )
        self.assertEqual(feedback["feedback_type"], schema.FEEDBACK_SUCCESS)
        self.assertEqual(feedback["signal_strength"], schema.STRENGTH_HIGH)
        self.assertEqual(feedback["improvement_area"], schema.AREA_NONE)

    def test_5_confidence_level_falls_back_to_confidence_plan(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None,
            {"confidence_level": "LOW"},
            None, None,
            {"outcome": "WAITING_FOR_EVIDENCE",
             "remaining_need": "PATH"},
        )
        self.assertEqual(feedback["confidence_level"],
                         conf_schema.CONFIDENCE_LOW)


# ---------------------------------------------------------------------------
# 1, 6: determinism and no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_1_repeated_output_is_byte_identical(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         _) = bundle(eap.VERSION_LOOKUP)
        first = efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        second = efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_1_key_insertion_order_does_not_matter(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         _) = bundle(eap.PATH_EVIDENCE_REVIEW)
        shuffled = dict(reversed(list(outcome.items())))
        first = efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        second = efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, shuffled
        )
        self.assertEqual(first, second)

    def test_1_stable_feedback_across_all_methods(self):
        feedbacks = [bundle(method)[6] for method in TARGETS_BY_METHOD]
        repeated = [bundle(method)[6] for method in TARGETS_BY_METHOD]
        self.assertEqual(
            json.dumps(feedbacks, sort_keys=True),
            json.dumps(repeated, sort_keys=True),
        )

    def test_6_no_mutation_of_inputs(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         _) = bundle(eap.PARAMETER_EVIDENCE_REVIEW)
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
            copy.deepcopy(decision),
            copy.deepcopy(loop),
            copy.deepcopy(outcome),
        )
        efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])
        self.assertEqual(loop, snapshots[4])
        self.assertEqual(outcome, snapshots[5])

    def test_6_no_mutation_of_terminal_inputs(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
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
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
            copy.deepcopy(decision),
            copy.deepcopy(loop),
            copy.deepcopy(outcome),
        )
        efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])
        self.assertEqual(loop, snapshots[4])
        self.assertEqual(outcome, snapshots[5])

    def test_6_source_snapshots_do_not_alias_inputs(self):
        (acquisition, prioritization, confidence, decision, loop, outcome,
         feedback) = bundle(eap.VERSION_LOOKUP)
        feedback["source_acquisition_plan"]["acquisition_rank"] = 99
        feedback["source_priority_plan"]["items"].clear()
        feedback["source_confidence_plan"]["limiting_factor"] = "NONE"
        feedback["source_decision_plan"]["decision"] = "SHIP_IT"
        feedback["source_loop_plan"]["lifecycle_state"] = "COMPLETED"
        feedback["source_outcome_plan"]["outcome"] = "COMPLETED"
        self.assertEqual(acquisition["acquisition_rank"], 0)
        self.assertEqual(len(prioritization["items"]), 1)
        self.assertEqual(confidence["limiting_factor"], "VERSION")
        self.assertEqual(decision["decision"], "CONTINUE_RESEARCH")
        self.assertEqual(loop["lifecycle_state"], "RESEARCH_ACTIVE")
        self.assertEqual(outcome["outcome"], "IN_PROGRESS")


# ---------------------------------------------------------------------------
# 7: closed vocabulary validation
# ---------------------------------------------------------------------------


class TestClosedVocabulary(unittest.TestCase):
    def _feedbacks(self):
        results = [bundle(method)[6] for method in TARGETS_BY_METHOD]
        results.append(efp.plan_evidence_feedback_calibration())
        results.append(efp.plan_evidence_feedback_calibration(
            None, None, None, None, None,
            {"outcome": "UNKNOWN"},
        ))
        return results

    def test_7_output_fields_are_closed(self):
        for result in self._feedbacks():
            self.assertIn(result["feedback_type"], schema.FEEDBACK_TYPES)
            self.assertIn(result["signal_strength"],
                          schema.SIGNAL_STRENGTHS)
            self.assertIn(result["improvement_area"],
                          schema.IMPROVEMENT_AREAS)
            self.assertIn(result["outcome"], out_schema.OUTCOMES)
            self.assertIn(result["confidence_level"],
                          conf_schema.CONFIDENCE_LEVELS)
            for code in result["blockers"]:
                self.assertIn(code, conf_schema.CONFIDENCE_BLOCKERS)

    def test_7_schema_rejects_invalid_feedback_type(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="WIN_SIGNAL",
                signal_strength="HIGH",
                improvement_area="NONE",
                outcome="COMPLETED",
                confidence_level="HIGH",
            )

    def test_7_schema_rejects_invalid_signal_strength(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="SUCCESS_SIGNAL",
                signal_strength="CERTAIN",
                improvement_area="NONE",
                outcome="COMPLETED",
                confidence_level="HIGH",
            )

    def test_7_schema_rejects_invalid_improvement_area(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="SUCCESS_SIGNAL",
                signal_strength="HIGH",
                improvement_area="MONEY",
                outcome="COMPLETED",
                confidence_level="HIGH",
            )

    def test_7_schema_rejects_invalid_outcome(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="SUCCESS_SIGNAL",
                signal_strength="HIGH",
                improvement_area="NONE",
                outcome="SHIP_IT",
                confidence_level="HIGH",
            )

    def test_7_schema_rejects_invalid_confidence_level(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="SUCCESS_SIGNAL",
                signal_strength="HIGH",
                improvement_area="NONE",
                outcome="COMPLETED",
                confidence_level="CERTAIN",
            )

    def test_7_schema_rejects_invalid_blocker(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="UNKNOWN",
                signal_strength="UNKNOWN",
                improvement_area="PROCESS",
                outcome="UNKNOWN",
                confidence_level="UNKNOWN",
                blockers=["DEPLOY_EXPLOIT"],
            )

    def test_7_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="SUCCESS_SIGNAL",
                signal_strength="HIGH",
                improvement_area="NONE",
                outcome="COMPLETED",
                confidence_level="HIGH",
                severity="CRITICAL",
            )

    def test_7_schema_forces_rule_version_and_research_only(self):
        result = schema.EvidenceFeedbackCalibrationPlan(
            rule_version="r99-9",
            feedback_type="SUCCESS_SIGNAL",
            signal_strength="HIGH",
            improvement_area="NONE",
            outcome="COMPLETED",
            confidence_level="HIGH",
            research_only=True,
        )
        self.assertEqual(result.rule_version, "r31-19")
        with self.assertRaises(ValidationError):
            schema.EvidenceFeedbackCalibrationPlan(
                feedback_type="SUCCESS_SIGNAL",
                signal_strength="HIGH",
                improvement_area="NONE",
                outcome="COMPLETED",
                confidence_level="HIGH",
                research_only=False,
            )

    def test_7_exact_rule_version(self):
        self.assertEqual(
            efp.EVIDENCE_FEEDBACK_CALIBRATION_PLANNER_RULE_VERSION,
            "r31-19",
        )
        self.assertEqual(efp.RULE_VERSION, "r31-19")
        feedback = efp.plan_evidence_feedback_calibration()
        self.assertEqual(feedback["rule_version"], "r31-19")

    def test_7_bounded_blockers(self):
        plan = schema.EvidenceFeedbackCalibrationPlan(
            feedback_type="UNKNOWN",
            signal_strength="UNKNOWN",
            improvement_area="PROCESS",
            outcome="UNKNOWN",
            confidence_level="UNKNOWN",
            blockers=[conf_schema.BLOCKER_NO_ACQUISITION_PLANNED] * 64,
        )
        self.assertLessEqual(len(plan.blockers), schema.MAX_BLOCKERS)

    def test_7_blocker_flow_and_filtering(self):
        feedback = efp.plan_evidence_feedback_calibration(
            None, None,
            {"limiting_factor": "VERSION",
             "blockers": ["SCOPE_EVIDENCE_MISSING"]},
            None,
            {"blockers": ["VERSION_EVIDENCE_MISSING"]},
            {"outcome": "IN_PROGRESS",
             "remaining_need": "VERSION",
             "blockers": ["DEPLOY_EXPLOIT"]},
        )
        self.assertIn("VERSION_EVIDENCE_MISSING", feedback["blockers"])
        self.assertIn("SCOPE_EVIDENCE_MISSING", feedback["blockers"])
        self.assertNotIn("DEPLOY_EXPLOIT", feedback["blockers"])


# ---------------------------------------------------------------------------
# 8-10: JSON, research_only, no operational content
# ---------------------------------------------------------------------------


FORBIDDEN_OPERATIONAL_MARKERS = (
    "payload",
    "exploit",
    "fuzz",
    "nuclei",
    "sqlmap",
    "curl ",
    "wget ",
    "bypass",
    "request body",
    "<script",
    "union select",
    " or 1=1",
    "{{",
    "}}",
)


class TestOutputShape(unittest.TestCase):
    def _feedbacks(self):
        results = [bundle(method)[6] for method in TARGETS_BY_METHOD]
        results.append(efp.plan_evidence_feedback_calibration())
        return results

    def test_8_json_serializable(self):
        for result in self._feedbacks():
            self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_9_research_only_always_true(self):
        for result in self._feedbacks():
            self.assertIs(result["research_only"], True)

    def test_10_no_operational_attack_content(self):
        blob = json.dumps(self._feedbacks()).lower()
        for marker in FORBIDDEN_OPERATIONAL_MARKERS:
            self.assertNotIn(marker, blob)

    def test_10_source_snapshots_are_sanitized(self):
        acquisition = acquisition_plan(
            eap.MANUAL_RESEARCH,
            source_action="token=SECRETVALUE",
            source_actionability="Bearer abc123",
            reason_codes=["https://user:hunter2@x.test/p?token=SECRET"],
        )
        prioritization = epp.plan_evidence_prioritization(acquisition)
        confidence = {
            "confidence_level": "LOW",
            "confidence_category": "RESEARCH_INCOMPLETE",
            "limiting_factor": "HUMAN_RESEARCH",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
            "research_only": True,
        }
        decision = {
            "decision": "REQUIRE_MORE_EVIDENCE",
            "confidence_level": "LOW",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        loop = {
            "lifecycle_state": "WAITING_FOR_EVIDENCE",
            "transition_reason": "NEED_MORE_EVIDENCE",
            "decision": "REQUIRE_MORE_EVIDENCE",
            "confidence_level": "LOW",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        outcome = {
            "outcome": "WAITING_FOR_EVIDENCE",
            "remaining_need": "HUMAN_RESEARCH",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        feedback = efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        blob = json.dumps(feedback)
        for token in ("SECRETVALUE", "abc123", "hunter2", "SECRET"):
            self.assertNotIn(token, blob)

    def test_10_source_snapshots_are_bounded(self):
        acquisition = acquisition_plan(
            eap.VERSION_LOOKUP,
            reason_codes=[f"CODE_{index}" for index in range(64)],
        )
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
        for key in feedback["source_outcome_plan"]:
            self.assertIn(key, schema.SOURCE_OUTCOME_KEYS)
        json.dumps(feedback)


# ---------------------------------------------------------------------------
# Regression / integration
# ---------------------------------------------------------------------------


class TestR31Regression(unittest.TestCase):
    def test_r3113_r3118_rule_versions_unchanged(self):
        self.assertEqual(
            eap.EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION, "r31-13"
        )
        self.assertEqual(
            epp.EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION, "r31-14"
        )
        self.assertEqual(
            eca.EVIDENCE_CONFIDENCE_AGGREGATOR_RULE_VERSION, "r31-15"
        )
        self.assertEqual(
            edp.EVIDENCE_DECISION_PLANNER_RULE_VERSION, "r31-16"
        )
        self.assertEqual(
            erl.EVIDENCE_RESEARCH_LOOP_PLANNER_RULE_VERSION, "r31-17"
        )
        self.assertEqual(
            eot.EVIDENCE_RESEARCH_OUTCOME_TRACKER_RULE_VERSION, "r31-18"
        )

    def test_upstream_plans_unchanged_by_calibration(self):
        (_, _, _, acquisition, prioritization, confidence, decision, loop,
         outcome, feedback) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
            copy.deepcopy(decision),
            copy.deepcopy(loop),
            copy.deepcopy(outcome),
        )
        efp.plan_evidence_feedback_calibration(
            acquisition, prioritization, confidence, decision, loop, outcome
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])
        self.assertEqual(loop, snapshots[4])
        self.assertEqual(outcome, snapshots[5])
        self.assertEqual(feedback["feedback_type"],
                         schema.FEEDBACK_CONTINUE)

    def test_r29_queue_has_no_feedback_field(self):
        action = {
            "lead_id": "rl-" + "a" * 16,
            "cve_id": CVE,
            "program": "dell",
            "money_score": 73,
            "priority": "HIGH",
            "opportunity_class": "HIGH_VALUE",
            "current_status": "READY",
            "recommended_action": "VERIFY",
            "confidence": "HIGH",
            "evidence_quality": "HIGH",
            "estimated_minutes": 45,
            "why_now": ["strong match"],
            "blockers": [],
            "next_step": "verify",
        }
        outcomes = SimpleNamespace(
            accepted=0, duplicate=0, wasted_time=0, rejected=0,
            terminal_attempts=0, attempts=0, latest_outcome=None,
            data_quality="NONE",
        )
        sessions = SimpleNamespace(
            session_status="NONE", in_progress_sessions=0, actual_time=0,
            average_actual_minutes=0, total_sessions=0, planned_time=0,
            latest_session_status="NONE",
        )
        items = [hq.build_hunt_item(action, outcomes, sessions)]
        projection = hunt_item_projection(hq.rank_hunt_queue(items)[0])
        self.assertNotIn("evidence_feedback_calibration_plan", projection)
        self.assertNotIn(
            "evidence_feedback_calibration_plan_rule_version", projection
        )
        self.assertEqual(HUNT_RULE_VERSION, "r29-1")


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo)
# ---------------------------------------------------------------------------


def _projection(
    *,
    paths=(),
    components=(),
    provenance=(),
    versions=(),
    associations=(),
    parameters=(),
    parameter_paths=(),
):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": list(components),
        "plugins": [],
        "versions": [
            {"value": value, "source": "TECHNOLOGY_INVENTORY",
             "evidence_type": "STRUCTURED_TECHNOLOGY"}
            for value in versions
        ],
        "version_associations": list(associations),
        "parameters": [
            {"value": value, "source": "PARAMETER_INVENTORY",
             "evidence_type": "STRUCTURED_PARAMETER"}
            for value in parameters
        ],
        "paths": [
            {"value": value, "source": "ENDPOINT_INVENTORY",
             "evidence_type": "STRUCTURED_ENDPOINT"}
            for value in paths
        ],
        "component_provenance": list(provenance),
        "parameter_paths": list(parameter_paths),
        "sources": [],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(components=(), parameters=(), versions=()):
    document = SimpleNamespace(
        components=list(components),
        parameters=list(parameters),
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": [], "affected_versions": []},
        "research": {"affected_versions": list(versions)},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class TestBackendIntegration(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()

    def tearDown(self):
        acm.clear_cache()

    def _match(self, inventory, *, components=(), parameters=(),
               versions=()):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ), mock.patch.object(
            acm, "_contexts",
            return_value=_contexts(components, parameters, versions),
        ):
            return acm.build_matches(cve=CVE, program="dell")["items"][0]

    def test_backend_additive_fields_and_rule_versions(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan_rule_version"],
            "r31-19",
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["rule_version"],
            "r31-19",
        )
        self.assertIs(
            item["evidence_feedback_calibration_plan"]["research_only"],
            True,
        )
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(item["hunt_actionability_rule_version"], "r31-11")
        self.assertEqual(item["hunt_action_plan_rule_version"], "r31-12")
        self.assertEqual(
            item["evidence_acquisition_plan_rule_version"], "r31-13"
        )
        self.assertEqual(
            item["evidence_prioritization_plan_rule_version"], "r31-14"
        )
        self.assertEqual(
            item["evidence_confidence_plan_rule_version"], "r31-15"
        )
        self.assertEqual(
            item["evidence_decision_plan_rule_version"], "r31-16"
        )
        self.assertEqual(
            item["evidence_research_loop_plan_rule_version"], "r31-17"
        )
        self.assertEqual(
            item["evidence_research_outcome_plan_rule_version"], "r31-18"
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["outcome"],
            item["evidence_research_outcome_plan"]["outcome"],
        )

    def test_backend_immediate_plan_success_signal(self):
        item = self._match(
            _projection(
                paths=["/assets/ckeditor/config.js"],
                components=[{
                    "value": "CKEditor",
                    "source": "COMPONENT_INVENTORY",
                    "evidence_type": "STRUCTURED_COMPONENT",
                }],
                versions=["1.2.3"],
                associations=[{
                    "version": "1.2.3",
                    "technology_family": "CKEditor",
                    "component": "CKEditor",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }],
            ),
            components=["CKEditor", "/assets/ckeditor/config.js"],
            versions=["<=1.2.3"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.P0)
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["feedback_type"],
            schema.FEEDBACK_SUCCESS,
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["signal_strength"],
            schema.STRENGTH_HIGH,
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["improvement_area"],
            schema.AREA_NONE,
        )
        # Existing projections are not altered by the calibration.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_defer_signal(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["feedback_type"],
            schema.FEEDBACK_DEFER,
        )
        self.assertEqual(
            item["evidence_feedback_calibration_plan"]["signal_strength"],
            schema.STRENGTH_LOW,
        )

    def test_backend_existing_fields_not_overwritten(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for key in (
            "hunt_priority",
            "hunt_actionability",
            "hunt_action_plan",
            "evidence_acquisition_plan",
            "evidence_prioritization_plan",
            "evidence_confidence_plan",
            "evidence_decision_plan",
            "evidence_research_loop_plan",
            "evidence_research_outcome_plan",
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_feedback_calibration_plan"],
            item["evidence_research_outcome_plan"],
        )

    def test_backend_money_score_unchanged(self):
        from backend import research_economics

        before = research_economics.build_economics()
        self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        after = research_economics.build_economics()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
