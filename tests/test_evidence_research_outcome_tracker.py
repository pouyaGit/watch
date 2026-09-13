"""tests/test_evidence_research_outcome_tracker.py — Stage R31.18 tests.

Deterministic, offline tests for the evidence research outcome tracker:

- deterministic output
- COMPLETED / IN_PROGRESS / WAITING_FOR_EVIDENCE / DEFERRED outcomes
- UNKNOWN and malformed input handling
- complete remaining_need mapping
- no mutation of the R31.13-R31.17 inputs
- closed vocabulary enforcement (tracker + pydantic schema)
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
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import evidence_research_loop_planner as erl
from ai.knowledge import evidence_research_outcome_tracker as eot
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_confidence as conf_schema
from ai.schemas import evidence_decision as dec_schema
from ai.schemas import evidence_research_loop as loop_schema
from ai.schemas import evidence_research_outcome as schema
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
    return (
        acquisition, prioritization, confidence, decision, loop, outcome,
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
    """Build R31.10 -> ... -> R31.18 outputs with the real engines."""

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
    return (
        hp_result, ha_result, action_plan, acquisition,
        prioritization, confidence, decision, loop, outcome,
    )


# ---------------------------------------------------------------------------
# 2-5: outcome mapping
# ---------------------------------------------------------------------------


class TestOutcomes(unittest.TestCase):
    def test_2_completed_outcome(self):
        (_, _, _, _, loop, outcome) = bundle(
            eap.EXISTING_EVIDENCE_REVIEW
        )
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_COMPLETED)
        self.assertEqual(outcome["outcome"], schema.OUTCOME_COMPLETED)
        self.assertEqual(outcome["outcome_category"],
                         schema.CATEGORY_EVIDENCE_ACCEPTED)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_COMPLETE)
        self.assertEqual(outcome["remaining_need"], schema.NEED_NONE)

    def test_2_completed_via_real_engine_chain(self):
        (_, _, _, _, _, _, _, loop, outcome) = full_chain(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_COMPLETED)
        self.assertEqual(outcome["outcome"], schema.OUTCOME_COMPLETED)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_COMPLETE)

    def test_3_in_progress_outcome(self):
        for method, need in (
            (eap.COMPONENT_IDENTITY_LOOKUP, schema.NEED_IDENTITY),
            (eap.VERSION_LOOKUP, schema.NEED_VERSION),
            (eap.SCOPE_EVIDENCE_REVIEW, schema.NEED_SCOPE),
        ):
            (_, _, _, _, loop, outcome) = bundle(method)
            self.assertEqual(loop["lifecycle_state"],
                             loop_schema.LIFECYCLE_RESEARCH_ACTIVE)
            self.assertEqual(outcome["outcome"],
                             schema.OUTCOME_IN_PROGRESS, method)
            self.assertEqual(outcome["outcome_category"],
                             schema.CATEGORY_RESEARCH_CONTINUING, method)
            self.assertEqual(outcome["completion_state"],
                             schema.COMPLETION_PARTIAL, method)
            self.assertEqual(outcome["remaining_need"], need, method)

    def test_3_in_progress_via_real_engine_chain(self):
        (_, _, _, _, _, _, _, loop, outcome) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_RESEARCH_ACTIVE)
        self.assertEqual(outcome["outcome"], schema.OUTCOME_IN_PROGRESS)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_PARTIAL)
        self.assertEqual(outcome["remaining_need"], schema.NEED_VERSION)

    def test_4_waiting_for_evidence_outcome(self):
        for method, need in (
            (eap.PATH_EVIDENCE_REVIEW, schema.NEED_PATH),
            (eap.PARAMETER_EVIDENCE_REVIEW, schema.NEED_PARAMETER),
            (eap.HTTP_BEHAVIOR_REVIEW, schema.NEED_HTTP_BEHAVIOR),
            (eap.TECHNOLOGY_EVIDENCE_REVIEW, schema.NEED_TECHNOLOGY),
            (eap.MANUAL_RESEARCH, schema.NEED_HUMAN_RESEARCH),
        ):
            (_, _, _, _, loop, outcome) = bundle(method)
            self.assertEqual(
                loop["lifecycle_state"],
                loop_schema.LIFECYCLE_WAITING_FOR_EVIDENCE, method,
            )
            self.assertEqual(outcome["outcome"],
                             schema.OUTCOME_WAITING_FOR_EVIDENCE, method)
            self.assertEqual(outcome["outcome_category"],
                             schema.CATEGORY_MORE_EVIDENCE_REQUIRED, method)
            self.assertEqual(outcome["completion_state"],
                             schema.COMPLETION_INCOMPLETE, method)
            self.assertEqual(outcome["remaining_need"], need, method)

    def test_4_waiting_via_real_engine_chain(self):
        (_, _, _, _, _, _, _, loop, outcome) = full_chain(
            p1_fixture(gaps=["path: no matching observed path evidence"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_WAITING_FOR_EVIDENCE)
        self.assertEqual(outcome["outcome"],
                         schema.OUTCOME_WAITING_FOR_EVIDENCE)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_INCOMPLETE)
        self.assertEqual(outcome["remaining_need"], schema.NEED_PATH)

    def test_5_deferred_outcome(self):
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
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_DEFERRED)
        self.assertEqual(outcome["outcome"], schema.OUTCOME_DEFERRED)
        self.assertEqual(outcome["outcome_category"],
                         schema.CATEGORY_RESEARCH_PAUSED)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_NONE)
        self.assertEqual(outcome["remaining_need"], schema.NEED_UNKNOWN)

    def test_5_deferred_via_real_engine_chain(self):
        (_, _, _, _, _, _, _, loop, outcome) = full_chain(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_DEFERRED)
        self.assertEqual(outcome["outcome"], schema.OUTCOME_DEFERRED)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_NONE)


# ---------------------------------------------------------------------------
# 6: UNKNOWN / malformed handling
# ---------------------------------------------------------------------------


class TestUnknownAndMalformed(unittest.TestCase):
    def test_6_unknown_lifecycle_yields_invalid_state(self):
        outcome = eot.track_evidence_research_outcome(
            None, None, None, None, {"lifecycle_state": "UNKNOWN"}
        )
        self.assertEqual(outcome["outcome"], schema.OUTCOME_UNKNOWN)
        self.assertEqual(outcome["outcome_category"],
                         schema.CATEGORY_INVALID_STATE)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_UNKNOWN)
        self.assertEqual(outcome["remaining_need"], schema.NEED_UNKNOWN)

    def test_6_unknown_via_real_engine_chain(self):
        (_, _, _, _, _, _, _, loop, outcome) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        forged = dict(loop)
        forged["lifecycle_state"] = "UNKNOWN"
        outcome = eot.track_evidence_research_outcome(
            None, None, None, None, forged
        )
        self.assertEqual(outcome["outcome"], schema.OUTCOME_UNKNOWN)
        self.assertEqual(outcome["outcome_category"],
                         schema.CATEGORY_INVALID_STATE)

    def test_6_missing_inputs_yield_invalid_state(self):
        for values in (
            (None, None, None, None, None),
            ({}, {}, {}, {}, {}),
            ("x", [], 0, None, "loop"),
        ):
            outcome = eot.track_evidence_research_outcome(*values)
            self.assertEqual(outcome["outcome"],
                             schema.OUTCOME_UNKNOWN, repr(values))
            self.assertEqual(outcome["outcome_category"],
                             schema.CATEGORY_INVALID_STATE)
            self.assertEqual(outcome["completion_state"],
                             schema.COMPLETION_UNKNOWN)
            self.assertEqual(outcome["remaining_need"],
                             schema.NEED_UNKNOWN)

    def test_6_reserved_lifecycle_states_are_invalid(self):
        for lifecycle in ("INITIAL", "EVIDENCE_READY", "RUNNING"):
            outcome = eot.track_evidence_research_outcome(
                None, None, None, None,
                {"lifecycle_state": lifecycle},
            )
            self.assertEqual(outcome["outcome"],
                             schema.OUTCOME_UNKNOWN, lifecycle)
            self.assertEqual(outcome["outcome_category"],
                             schema.CATEGORY_INVALID_STATE, lifecycle)

    def test_6_lowercase_lifecycle_is_normalized(self):
        outcome = eot.track_evidence_research_outcome(
            None, None, None, None,
            {"lifecycle_state": "completed"},
        )
        self.assertEqual(outcome["outcome"], schema.OUTCOME_COMPLETED)
        self.assertEqual(outcome["completion_state"],
                         schema.COMPLETION_COMPLETE)


# ---------------------------------------------------------------------------
# 7: remaining_need mapping
# ---------------------------------------------------------------------------


class TestRemainingNeedMapping(unittest.TestCase):
    def test_7_all_limiting_factors_map(self):
        expectations = (
            (conf_schema.LIMITING_NONE, schema.NEED_NONE),
            (conf_schema.LIMITING_COMPONENT_IDENTITY, schema.NEED_IDENTITY),
            (conf_schema.LIMITING_VERSION, schema.NEED_VERSION),
            (conf_schema.LIMITING_SCOPE, schema.NEED_SCOPE),
            (conf_schema.LIMITING_PATH, schema.NEED_PATH),
            (conf_schema.LIMITING_PARAMETER, schema.NEED_PARAMETER),
            (conf_schema.LIMITING_HTTP_BEHAVIOR,
             schema.NEED_HTTP_BEHAVIOR),
            (conf_schema.LIMITING_TECHNOLOGY, schema.NEED_TECHNOLOGY),
            (conf_schema.LIMITING_HUMAN_RESEARCH,
             schema.NEED_HUMAN_RESEARCH),
            (conf_schema.LIMITING_UPSTREAM_PLAN, schema.NEED_UNKNOWN),
        )
        for limiting, need in expectations:
            outcome = eot.track_evidence_research_outcome(
                None, None,
                {"limiting_factor": limiting},
                None,
                {"lifecycle_state": "WAITING_FOR_EVIDENCE"},
            )
            self.assertEqual(outcome["remaining_need"], need, limiting)

    def test_7_unknown_limiting_factor_maps_to_unknown(self):
        outcome = eot.track_evidence_research_outcome(
            None, None,
            {"limiting_factor": "MONEY"},
            None,
            {"lifecycle_state": "WAITING_FOR_EVIDENCE"},
        )
        self.assertEqual(outcome["remaining_need"], schema.NEED_UNKNOWN)

    def test_7_completed_forces_remaining_none(self):
        outcome = eot.track_evidence_research_outcome(
            None, None,
            {"limiting_factor": "VERSION"},
            None,
            {"lifecycle_state": "COMPLETED"},
        )
        self.assertEqual(outcome["outcome"], schema.OUTCOME_COMPLETED)
        self.assertEqual(outcome["remaining_need"], schema.NEED_NONE)

    def test_7_mapping_table_is_closed(self):
        self.assertEqual(
            set(eot.LIMITING_TO_REMAINING_NEED.values()),
            set(schema.REMAINING_NEEDS),
        )
        for value in eot.LIMITING_TO_REMAINING_NEED:
            self.assertIn(value, conf_schema.LIMITING_FACTORS)


# ---------------------------------------------------------------------------
# 1, 8: determinism and no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_1_repeated_output_is_byte_identical(self):
        (acquisition, prioritization, confidence, decision, loop,
         _) = bundle(eap.VERSION_LOOKUP)
        first = eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        second = eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_1_key_insertion_order_does_not_matter(self):
        (acquisition, prioritization, confidence, decision, loop,
         _) = bundle(eap.PATH_EVIDENCE_REVIEW)
        shuffled = dict(reversed(list(loop.items())))
        first = eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        second = eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, shuffled
        )
        self.assertEqual(first, second)

    def test_1_stable_outcomes_across_all_methods(self):
        outcomes = [bundle(method)[5] for method in TARGETS_BY_METHOD]
        repeated = [bundle(method)[5] for method in TARGETS_BY_METHOD]
        self.assertEqual(
            json.dumps(outcomes, sort_keys=True),
            json.dumps(repeated, sort_keys=True),
        )

    def test_8_no_mutation_of_inputs(self):
        (acquisition, prioritization, confidence, decision, loop,
         _) = bundle(eap.PARAMETER_EVIDENCE_REVIEW)
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
            copy.deepcopy(decision),
            copy.deepcopy(loop),
        )
        eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])
        self.assertEqual(loop, snapshots[4])

    def test_8_no_mutation_of_terminal_inputs(self):
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
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
            copy.deepcopy(decision),
            copy.deepcopy(loop),
        )
        eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])
        self.assertEqual(loop, snapshots[4])

    def test_8_source_snapshots_do_not_alias_inputs(self):
        (acquisition, prioritization, confidence, decision, loop,
         outcome) = bundle(eap.VERSION_LOOKUP)
        outcome["source_acquisition_plan"]["acquisition_rank"] = 99
        outcome["source_priority_plan"]["items"].clear()
        outcome["source_confidence_plan"]["limiting_factor"] = "NONE"
        outcome["source_decision_plan"]["decision"] = "SHIP_IT"
        outcome["source_loop_plan"]["lifecycle_state"] = "COMPLETED"
        self.assertEqual(acquisition["acquisition_rank"], 0)
        self.assertEqual(len(prioritization["items"]), 1)
        self.assertEqual(confidence["limiting_factor"], "VERSION")
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_CONTINUE_RESEARCH)
        self.assertEqual(loop["lifecycle_state"],
                         loop_schema.LIFECYCLE_RESEARCH_ACTIVE)


# ---------------------------------------------------------------------------
# 9: closed vocabulary validation
# ---------------------------------------------------------------------------


class TestClosedVocabulary(unittest.TestCase):
    def _outcomes(self):
        results = [bundle(method)[5] for method in TARGETS_BY_METHOD]
        results.append(eot.track_evidence_research_outcome())
        results.append(eot.track_evidence_research_outcome(
            None, None, None, None, {"lifecycle_state": "UNKNOWN"}
        ))
        return results

    def test_9_output_fields_are_closed(self):
        for result in self._outcomes():
            self.assertIn(result["outcome"], schema.OUTCOMES)
            self.assertIn(result["outcome_category"],
                          schema.OUTCOME_CATEGORIES)
            self.assertIn(result["completion_state"],
                          schema.COMPLETION_STATES)
            self.assertIn(result["remaining_need"],
                          schema.REMAINING_NEEDS)
            for code in result["blockers"]:
                self.assertIn(code, conf_schema.CONFIDENCE_BLOCKERS)

    def test_9_schema_rejects_invalid_outcome(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="WINNER",
                outcome_category="EVIDENCE_ACCEPTED",
                completion_state="COMPLETE",
                remaining_need="NONE",
            )

    def test_9_schema_rejects_invalid_category(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="COMPLETED",
                outcome_category="EXPLOITABLE",
                completion_state="COMPLETE",
                remaining_need="NONE",
            )

    def test_9_schema_rejects_invalid_completion_state(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="COMPLETED",
                outcome_category="EVIDENCE_ACCEPTED",
                completion_state="DONE",
                remaining_need="NONE",
            )

    def test_9_schema_rejects_invalid_remaining_need(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="COMPLETED",
                outcome_category="EVIDENCE_ACCEPTED",
                completion_state="COMPLETE",
                remaining_need="MONEY",
            )

    def test_9_schema_rejects_invalid_blocker(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="UNKNOWN",
                outcome_category="INVALID_STATE",
                completion_state="UNKNOWN",
                remaining_need="UNKNOWN",
                blockers=["DEPLOY_EXPLOIT"],
            )

    def test_9_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="COMPLETED",
                outcome_category="EVIDENCE_ACCEPTED",
                completion_state="COMPLETE",
                remaining_need="NONE",
                severity="CRITICAL",
            )

    def test_9_schema_forces_rule_version_and_research_only(self):
        result = schema.EvidenceResearchOutcomePlan(
            rule_version="r99-9",
            outcome="COMPLETED",
            outcome_category="EVIDENCE_ACCEPTED",
            completion_state="COMPLETE",
            remaining_need="NONE",
            research_only=True,
        )
        self.assertEqual(result.rule_version, "r31-18")
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchOutcomePlan(
                outcome="COMPLETED",
                outcome_category="EVIDENCE_ACCEPTED",
                completion_state="COMPLETE",
                remaining_need="NONE",
                research_only=False,
            )

    def test_9_exact_rule_version(self):
        self.assertEqual(
            eot.EVIDENCE_RESEARCH_OUTCOME_TRACKER_RULE_VERSION, "r31-18"
        )
        self.assertEqual(eot.RULE_VERSION, "r31-18")
        outcome = eot.track_evidence_research_outcome()
        self.assertEqual(outcome["rule_version"], "r31-18")

    def test_9_bounded_blockers(self):
        plan = schema.EvidenceResearchOutcomePlan(
            outcome="UNKNOWN",
            outcome_category="INVALID_STATE",
            completion_state="UNKNOWN",
            remaining_need="UNKNOWN",
            blockers=[conf_schema.BLOCKER_NO_ACQUISITION_PLANNED] * 64,
        )
        self.assertLessEqual(len(plan.blockers), schema.MAX_BLOCKERS)

    def test_9_blocker_flow_and_filtering(self):
        outcome = eot.track_evidence_research_outcome(
            None, None,
            {"limiting_factor": "VERSION",
             "blockers": ["SCOPE_EVIDENCE_MISSING"]},
            {"blockers": ["DEPLOY_EXPLOIT"]},
            {"lifecycle_state": "WAITING_FOR_EVIDENCE",
             "blockers": ["VERSION_EVIDENCE_MISSING"]},
        )
        self.assertIn("VERSION_EVIDENCE_MISSING", outcome["blockers"])
        self.assertIn("SCOPE_EVIDENCE_MISSING", outcome["blockers"])
        self.assertNotIn("DEPLOY_EXPLOIT", outcome["blockers"])

    def test_9_lifecycle_table_is_closed(self):
        self.assertEqual(
            set(eot.LIFECYCLE_OUTCOMES),
            {
                loop_schema.LIFECYCLE_COMPLETED,
                loop_schema.LIFECYCLE_RESEARCH_ACTIVE,
                loop_schema.LIFECYCLE_WAITING_FOR_EVIDENCE,
                loop_schema.LIFECYCLE_DEFERRED,
            },
        )


# ---------------------------------------------------------------------------
# 10-12: JSON, research_only, no operational content
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
    def _outcomes(self):
        results = [bundle(method)[5] for method in TARGETS_BY_METHOD]
        results.append(eot.track_evidence_research_outcome())
        return results

    def test_10_json_serializable(self):
        for result in self._outcomes():
            self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_11_research_only_always_true(self):
        for result in self._outcomes():
            self.assertIs(result["research_only"], True)

    def test_12_no_operational_attack_content(self):
        blob = json.dumps(self._outcomes()).lower()
        for marker in FORBIDDEN_OPERATIONAL_MARKERS:
            self.assertNotIn(marker, blob)

    def test_12_source_snapshots_are_sanitized(self):
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
        outcome = eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        blob = json.dumps(outcome)
        for token in ("SECRETVALUE", "abc123", "hunter2", "SECRET"):
            self.assertNotIn(token, blob)

    def test_12_source_snapshots_are_bounded(self):
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
        for key in outcome["source_loop_plan"]:
            self.assertIn(key, schema.SOURCE_LOOP_KEYS)
        json.dumps(outcome)


# ---------------------------------------------------------------------------
# Regression / integration
# ---------------------------------------------------------------------------


class TestR31Regression(unittest.TestCase):
    def test_r3113_r3117_rule_versions_unchanged(self):
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

    def test_upstream_plans_unchanged_by_tracker(self):
        (_, _, _, acquisition, prioritization, confidence, decision, loop,
         outcome) = full_chain(
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
        )
        eot.track_evidence_research_outcome(
            acquisition, prioritization, confidence, decision, loop
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])
        self.assertEqual(loop, snapshots[4])
        self.assertEqual(outcome["outcome"], schema.OUTCOME_IN_PROGRESS)

    def test_r29_queue_has_no_outcome_field(self):
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
        self.assertNotIn("evidence_research_outcome_plan", projection)
        self.assertNotIn(
            "evidence_research_outcome_plan_rule_version", projection
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
            item["evidence_research_outcome_plan_rule_version"], "r31-18"
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["rule_version"],
            "r31-18",
        )
        self.assertIs(
            item["evidence_research_outcome_plan"]["research_only"], True
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
            item["evidence_research_outcome_plan"]["outcome"],
            schema.OUTCOME_DEFERRED,
        )

    def test_backend_immediate_plan_completes_outcome(self):
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
            item["evidence_research_outcome_plan"]["outcome"],
            schema.OUTCOME_COMPLETED,
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["outcome_category"],
            schema.CATEGORY_EVIDENCE_ACCEPTED,
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["completion_state"],
            schema.COMPLETION_COMPLETE,
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["remaining_need"],
            schema.NEED_NONE,
        )
        # Existing projections are not altered by the tracker.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_deferred_outcome(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["outcome"],
            schema.OUTCOME_DEFERRED,
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["outcome_category"],
            schema.CATEGORY_RESEARCH_PAUSED,
        )
        self.assertEqual(
            item["evidence_research_outcome_plan"]["completion_state"],
            schema.COMPLETION_NONE,
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
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_research_outcome_plan"],
            item["evidence_research_loop_plan"],
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
