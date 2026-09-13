"""tests/test_evidence_research_loop_planner.py — Stage R31.17 tests.

Deterministic, offline tests for the evidence research loop planner:

- deterministic output
- ACCEPT / CONTINUE / REQUIRE_MORE / DEFER lifecycle transitions
- UNKNOWN decision and malformed input handling
- no mutation of the R31.13/R31.14/R31.15/R31.16 inputs
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
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import evidence_research_loop_planner as erl
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_confidence as conf_schema
from ai.schemas import evidence_decision as dec_schema
from ai.schemas import evidence_research_loop as schema
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
    return acquisition, prioritization, confidence, decision, loop


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
    """Build R31.10 -> ... -> R31.17 outputs with the real engines."""

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
    return (
        hp_result, ha_result, action_plan, acquisition,
        prioritization, confidence, decision, loop,
    )


# ---------------------------------------------------------------------------
# 2-5: lifecycle transitions
# ---------------------------------------------------------------------------


class TestTransitions(unittest.TestCase):
    def test_2_accept_evidence_completes_loop(self):
        _, _, _, decision, loop = bundle(eap.EXISTING_EVIDENCE_REVIEW)
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_ACCEPT_EVIDENCE)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_COMPLETED)
        self.assertEqual(loop["next_phase"], schema.PHASE_NONE)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_EVIDENCE_ACCEPTED)
        self.assertEqual(loop["decision"],
                         dec_schema.DECISION_ACCEPT_EVIDENCE)
        self.assertEqual(loop["confidence_level"],
                         conf_schema.CONFIDENCE_HIGH)

    def test_2_accept_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision,
         loop) = full_chain(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_ACCEPT_EVIDENCE)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_COMPLETED)
        self.assertEqual(loop["next_phase"], schema.PHASE_NONE)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_EVIDENCE_ACCEPTED)

    def test_3_continue_research_activates_loop(self):
        for method in (
            eap.COMPONENT_IDENTITY_LOOKUP,
            eap.VERSION_LOOKUP,
            eap.SCOPE_EVIDENCE_REVIEW,
        ):
            _, _, confidence, decision, loop = bundle(method)
            self.assertEqual(decision["decision"],
                             dec_schema.DECISION_CONTINUE_RESEARCH)
            self.assertEqual(loop["lifecycle_state"],
                             schema.LIFECYCLE_RESEARCH_ACTIVE, method)
            self.assertEqual(
                loop["next_phase"],
                schema.PHASE_EVIDENCE_COLLECTION_PLANNING, method,
            )
            self.assertEqual(
                loop["transition_reason"],
                schema.REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE, method,
            )
            self.assertEqual(loop["confidence_level"],
                             conf_schema.CONFIDENCE_MEDIUM, method)

    def test_3_continue_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision,
         loop) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_CONTINUE_RESEARCH)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_RESEARCH_ACTIVE)
        self.assertEqual(loop["next_phase"],
                         schema.PHASE_EVIDENCE_COLLECTION_PLANNING)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_CONTINUE_AFTER_MEDIUM_CONFIDENCE)

    def test_4_require_more_evidence_waits(self):
        for method in (
            eap.PATH_EVIDENCE_REVIEW,
            eap.PARAMETER_EVIDENCE_REVIEW,
            eap.HTTP_BEHAVIOR_REVIEW,
            eap.TECHNOLOGY_EVIDENCE_REVIEW,
            eap.MANUAL_RESEARCH,
        ):
            _, _, confidence, decision, loop = bundle(method)
            self.assertEqual(decision["decision"],
                             dec_schema.DECISION_REQUIRE_MORE_EVIDENCE)
            self.assertEqual(loop["lifecycle_state"],
                             schema.LIFECYCLE_WAITING_FOR_EVIDENCE, method)
            self.assertEqual(
                loop["next_phase"],
                schema.PHASE_EVIDENCE_COLLECTION_PLANNING, method,
            )
            self.assertEqual(loop["transition_reason"],
                             schema.REASON_NEED_MORE_EVIDENCE, method)
            self.assertEqual(loop["confidence_level"],
                             conf_schema.CONFIDENCE_LOW, method)

    def test_4_require_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision,
         loop) = full_chain(
            p1_fixture(gaps=["path: no matching observed path evidence"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_REQUIRE_MORE_EVIDENCE)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_WAITING_FOR_EVIDENCE)
        self.assertEqual(loop["next_phase"],
                         schema.PHASE_EVIDENCE_COLLECTION_PLANNING)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_NEED_MORE_EVIDENCE)

    def test_5_defer_research_defers_loop(self):
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
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_DEFER_RESEARCH)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_DEFERRED)
        self.assertEqual(loop["next_phase"], schema.PHASE_NONE)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_RESEARCH_DEFERRED)

    def test_5_defer_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision,
         loop) = full_chain(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_DEFER_RESEARCH)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_DEFERRED)
        self.assertEqual(loop["next_phase"], schema.PHASE_NONE)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_RESEARCH_DEFERRED)


# ---------------------------------------------------------------------------
# 6-7: UNKNOWN and malformed input handling
# ---------------------------------------------------------------------------


class TestUnknownAndMalformed(unittest.TestCase):
    def test_6_unknown_decision_yields_invalid_input(self):
        loop = erl.plan_evidence_research_loop(
            None, None, None, {"decision": "UNKNOWN"}
        )
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_UNKNOWN)
        self.assertEqual(loop["next_phase"], schema.PHASE_UNKNOWN)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_INVALID_INPUT)
        self.assertEqual(loop["decision"], dec_schema.DECISION_UNKNOWN)

    def test_6_unknown_decision_via_real_engine_chain(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        confidence = {
            "confidence_level": "UNKNOWN",
            "confidence_category": "RESEARCH_INCOMPLETE",
            "limiting_factor": "UPSTREAM_PLAN",
            "blockers": [],
        }
        decision = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_UNKNOWN)
        loop = erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_UNKNOWN)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_INVALID_INPUT)

    def test_7_missing_inputs_yield_invalid_input(self):
        for values in (
            (None, None, None, None),
            ({}, {}, {}, {}),
            ("x", [], 0, None),
        ):
            loop = erl.plan_evidence_research_loop(*values)
            self.assertEqual(loop["lifecycle_state"],
                             schema.LIFECYCLE_UNKNOWN, repr(values))
            self.assertEqual(loop["next_phase"], schema.PHASE_UNKNOWN)
            self.assertEqual(loop["transition_reason"],
                             schema.REASON_INVALID_INPUT)
            self.assertEqual(loop["decision"],
                             dec_schema.DECISION_UNKNOWN)
            self.assertEqual(loop["confidence_level"],
                             conf_schema.CONFIDENCE_UNKNOWN)

    def test_7_unrecognized_decision_yields_invalid_input(self):
        loop = erl.plan_evidence_research_loop(
            None, None, None, {"decision": "SHIP_IT"}
        )
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_UNKNOWN)
        self.assertEqual(loop["transition_reason"],
                         schema.REASON_INVALID_INPUT)
        self.assertEqual(loop["decision"], dec_schema.DECISION_UNKNOWN)

    def test_7_lowercase_decision_is_normalized(self):
        loop = erl.plan_evidence_research_loop(
            None, None, None, {"decision": "accept_evidence"}
        )
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_COMPLETED)
        self.assertEqual(loop["decision"],
                         dec_schema.DECISION_ACCEPT_EVIDENCE)


# ---------------------------------------------------------------------------
# 1, 8: determinism and no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_1_repeated_output_is_byte_identical(self):
        acquisition, prioritization, confidence, decision, _ = bundle(
            eap.VERSION_LOOKUP
        )
        first = erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        second = erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_1_key_insertion_order_does_not_matter(self):
        acquisition, prioritization, confidence, decision, _ = bundle(
            eap.PATH_EVIDENCE_REVIEW
        )
        shuffled = dict(reversed(list(decision.items())))
        first = erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        second = erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, shuffled
        )
        self.assertEqual(first, second)

    def test_1_stable_transitions_across_all_methods(self):
        loops = [bundle(method)[4] for method in TARGETS_BY_METHOD]
        repeated = [bundle(method)[4] for method in TARGETS_BY_METHOD]
        self.assertEqual(
            json.dumps(loops, sort_keys=True),
            json.dumps(repeated, sort_keys=True),
        )

    def test_8_no_mutation_of_inputs(self):
        (acquisition, prioritization, confidence, decision,
         _) = bundle(eap.PARAMETER_EVIDENCE_REVIEW)
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        confidence_snapshot = copy.deepcopy(confidence)
        decision_snapshot = copy.deepcopy(decision)
        erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)
        self.assertEqual(confidence, confidence_snapshot)
        self.assertEqual(decision, decision_snapshot)

    def test_8_no_mutation_of_terminal_inputs(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        confidence = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        decision = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
            copy.deepcopy(decision),
        )
        erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])
        self.assertEqual(decision, snapshots[3])

    def test_8_source_snapshots_do_not_alias_inputs(self):
        (acquisition, prioritization, confidence, decision,
         loop) = bundle(eap.VERSION_LOOKUP)
        loop["source_acquisition_plan"]["acquisition_rank"] = 99
        loop["source_priority_plan"]["items"].clear()
        loop["source_confidence_plan"]["confidence_level"] = "LOW"
        loop["source_decision_plan"]["decision"] = "SHIP_IT"
        self.assertEqual(acquisition["acquisition_rank"], 0)
        self.assertEqual(len(prioritization["items"]), 1)
        self.assertEqual(confidence["confidence_level"], "MEDIUM")
        self.assertEqual(decision["decision"],
                         dec_schema.DECISION_CONTINUE_RESEARCH)


# ---------------------------------------------------------------------------
# 9: closed vocabulary validation
# ---------------------------------------------------------------------------


class TestClosedVocabulary(unittest.TestCase):
    def _loops(self):
        results = [bundle(method)[4] for method in TARGETS_BY_METHOD]
        results.append(erl.plan_evidence_research_loop(None, None, None,
                                                       None))
        results.append(erl.plan_evidence_research_loop(
            None, None, None, {"decision": "UNKNOWN"}
        ))
        return results

    def test_9_output_fields_are_closed(self):
        for result in self._loops():
            self.assertIn(result["lifecycle_state"],
                          schema.LIFECYCLE_STATES)
            self.assertIn(result["next_phase"], schema.NEXT_PHASES)
            self.assertIn(result["transition_reason"],
                          schema.TRANSITION_REASONS)
            self.assertIn(result["decision"], dec_schema.DECISIONS)
            self.assertIn(result["confidence_level"],
                          conf_schema.CONFIDENCE_LEVELS)
            for code in result["blockers"]:
                self.assertIn(code, conf_schema.CONFIDENCE_BLOCKERS)

    def test_9_schema_rejects_invalid_lifecycle_state(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="RUNNING",
                next_phase="NONE",
                transition_reason="EVIDENCE_ACCEPTED",
                decision="ACCEPT_EVIDENCE",
                confidence_level="HIGH",
            )

    def test_9_schema_rejects_invalid_next_phase(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="COMPLETED",
                next_phase="EXECUTE",
                transition_reason="EVIDENCE_ACCEPTED",
                decision="ACCEPT_EVIDENCE",
                confidence_level="HIGH",
            )

    def test_9_schema_rejects_invalid_transition_reason(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="COMPLETED",
                next_phase="NONE",
                transition_reason="BECAUSE",
                decision="ACCEPT_EVIDENCE",
                confidence_level="HIGH",
            )

    def test_9_schema_rejects_invalid_decision(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="COMPLETED",
                next_phase="NONE",
                transition_reason="EVIDENCE_ACCEPTED",
                decision="SHIP_IT",
                confidence_level="HIGH",
            )

    def test_9_schema_rejects_invalid_confidence_level(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="COMPLETED",
                next_phase="NONE",
                transition_reason="EVIDENCE_ACCEPTED",
                decision="ACCEPT_EVIDENCE",
                confidence_level="CERTAIN",
            )

    def test_9_schema_rejects_invalid_blocker(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="UNKNOWN",
                next_phase="UNKNOWN",
                transition_reason="INVALID_INPUT",
                decision="UNKNOWN",
                confidence_level="UNKNOWN",
                blockers=["DEPLOY_EXPLOIT"],
            )

    def test_9_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="COMPLETED",
                next_phase="NONE",
                transition_reason="EVIDENCE_ACCEPTED",
                decision="ACCEPT_EVIDENCE",
                confidence_level="HIGH",
                severity="CRITICAL",
            )

    def test_9_schema_forces_rule_version_and_research_only(self):
        result = schema.EvidenceResearchLoopPlan(
            rule_version="r99-9",
            lifecycle_state="COMPLETED",
            next_phase="NONE",
            transition_reason="EVIDENCE_ACCEPTED",
            decision="ACCEPT_EVIDENCE",
            confidence_level="HIGH",
            research_only=True,
        )
        self.assertEqual(result.rule_version, "r31-17")
        with self.assertRaises(ValidationError):
            schema.EvidenceResearchLoopPlan(
                lifecycle_state="COMPLETED",
                next_phase="NONE",
                transition_reason="EVIDENCE_ACCEPTED",
                decision="ACCEPT_EVIDENCE",
                confidence_level="HIGH",
                research_only=False,
            )

    def test_9_exact_rule_version(self):
        self.assertEqual(
            erl.EVIDENCE_RESEARCH_LOOP_PLANNER_RULE_VERSION, "r31-17"
        )
        self.assertEqual(erl.RULE_VERSION, "r31-17")
        loop = erl.plan_evidence_research_loop(None, None, None, None)
        self.assertEqual(loop["rule_version"], "r31-17")

    def test_9_bounded_blockers(self):
        plan = schema.EvidenceResearchLoopPlan(
            lifecycle_state="UNKNOWN",
            next_phase="UNKNOWN",
            transition_reason="INVALID_INPUT",
            decision="UNKNOWN",
            confidence_level="UNKNOWN",
            blockers=[conf_schema.BLOCKER_NO_ACQUISITION_PLANNED] * 64,
        )
        self.assertLessEqual(len(plan.blockers), schema.MAX_BLOCKERS)

    def test_9_blocker_flow_and_filtering(self):
        decision = {
            "decision": "CONTINUE_RESEARCH",
            "confidence_level": "MEDIUM",
            "blockers": [
                "VERSION_EVIDENCE_MISSING", "DEPLOY_EXPLOIT",
            ],
        }
        loop = erl.plan_evidence_research_loop(
            None, None, {"blockers": ["SCOPE_EVIDENCE_MISSING"]}, decision
        )
        self.assertIn("VERSION_EVIDENCE_MISSING", loop["blockers"])
        self.assertIn("SCOPE_EVIDENCE_MISSING", loop["blockers"])
        self.assertNotIn("DEPLOY_EXPLOIT", loop["blockers"])

    def test_9_decision_transition_table_is_closed(self):
        self.assertEqual(
            erl.DECISION_LIFECYCLE_STATES,
            {
                "ACCEPT_EVIDENCE": "COMPLETED",
                "CONTINUE_RESEARCH": "RESEARCH_ACTIVE",
                "REQUIRE_MORE_EVIDENCE": "WAITING_FOR_EVIDENCE",
                "DEFER_RESEARCH": "DEFERRED",
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
    def _loops(self):
        results = [bundle(method)[4] for method in TARGETS_BY_METHOD]
        results.append(erl.plan_evidence_research_loop(None, None, None,
                                                       None))
        return results

    def test_10_json_serializable(self):
        for result in self._loops():
            self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_11_research_only_always_true(self):
        for result in self._loops():
            self.assertIs(result["research_only"], True)

    def test_12_no_operational_attack_content(self):
        blob = json.dumps(self._loops()).lower()
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
            "evidence_completeness": "MINIMAL",
            "priority_alignment": "ALIGNED",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
            "research_only": True,
        }
        decision = {
            "decision": "REQUIRE_MORE_EVIDENCE",
            "confidence_level": "LOW",
            "blockers": ["HUMAN_RESEARCH_REQUIRED"],
        }
        loop = erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        blob = json.dumps(loop)
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
        for key in loop["source_decision_plan"]:
            self.assertIn(key, schema.SOURCE_DECISION_KEYS)
        json.dumps(loop)


# ---------------------------------------------------------------------------
# Regression / integration
# ---------------------------------------------------------------------------


class TestR31Regression(unittest.TestCase):
    def test_r3113_r3114_r3115_r3116_rule_versions_unchanged(self):
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

    def test_upstream_plans_unchanged_by_loop(self):
        (_, _, _, acquisition, prioritization, confidence, decision,
         loop) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        confidence_snapshot = copy.deepcopy(confidence)
        decision_snapshot = copy.deepcopy(decision)
        erl.plan_evidence_research_loop(
            acquisition, prioritization, confidence, decision
        )
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)
        self.assertEqual(confidence, confidence_snapshot)
        self.assertEqual(decision, decision_snapshot)
        self.assertEqual(loop["lifecycle_state"],
                         schema.LIFECYCLE_RESEARCH_ACTIVE)

    def test_r29_queue_has_no_loop_field(self):
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
        self.assertNotIn("evidence_research_loop_plan", projection)
        self.assertNotIn(
            "evidence_research_loop_plan_rule_version", projection
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
            item["evidence_research_loop_plan_rule_version"], "r31-17"
        )
        self.assertEqual(
            item["evidence_research_loop_plan"]["rule_version"], "r31-17"
        )
        self.assertIs(
            item["evidence_research_loop_plan"]["research_only"], True
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
            item["evidence_research_loop_plan"]["decision"],
            item["evidence_decision_plan"]["decision"],
        )

    def test_backend_immediate_plan_completes_loop(self):
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
            item["evidence_research_loop_plan"]["lifecycle_state"],
            schema.LIFECYCLE_COMPLETED,
        )
        self.assertEqual(
            item["evidence_research_loop_plan"]["next_phase"],
            schema.PHASE_NONE,
        )
        self.assertEqual(
            item["evidence_research_loop_plan"]["transition_reason"],
            schema.REASON_EVIDENCE_ACCEPTED,
        )
        # Existing projections are not altered by the loop.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_defers_loop(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_research_loop_plan"]["lifecycle_state"],
            schema.LIFECYCLE_DEFERRED,
        )
        self.assertEqual(
            item["evidence_research_loop_plan"]["next_phase"],
            schema.PHASE_NONE,
        )
        self.assertEqual(
            item["evidence_research_loop_plan"]["transition_reason"],
            schema.REASON_RESEARCH_DEFERRED,
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
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_research_loop_plan"],
            item["evidence_decision_plan"],
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
