"""tests/test_evidence_decision_planner.py — Stage R31.16 tests.

Deterministic, offline tests for the evidence decision planner:

- deterministic output
- ACCEPT_EVIDENCE / CONTINUE_RESEARCH / REQUIRE_MORE_EVIDENCE / DEFER_RESEARCH
- malformed and inconsistent input handling
- all confidence-category -> decision-reason mappings and blocker pass-through
- no mutation of the R31.13/R31.14/R31.15 inputs
- closed vocabulary enforcement (planner + pydantic schema)
- bounded, privacy-safe, JSON-serializable output
- plan-only: research_only always true, no operational attack content
- hermetic backend integration (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any action.
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
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_confidence as conf_schema
from ai.schemas import evidence_decision as schema
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
    return acquisition, prioritization, confidence, decision


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
    """Build R31.10 -> ... -> R31.16 outputs with the real engines."""

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
    return (
        hp_result, ha_result, action_plan, acquisition,
        prioritization, confidence, decision,
    )


# ---------------------------------------------------------------------------
# 2-5: decision paths
# ---------------------------------------------------------------------------


class TestDecisionPaths(unittest.TestCase):
    def test_2_accept_evidence_path(self):
        _, _, confidence, decision = bundle(
            eap.EXISTING_EVIDENCE_REVIEW
        )
        self.assertEqual(confidence["confidence_level"],
                         conf_schema.CONFIDENCE_HIGH)
        self.assertEqual(confidence["confidence_category"],
                         conf_schema.CATEGORY_SUFFICIENT_EVIDENCE)
        self.assertEqual(decision["decision"],
                         schema.DECISION_ACCEPT_EVIDENCE)
        self.assertEqual(decision["next_state"], schema.NEXT_STATE_COMPLETE)
        self.assertEqual(decision["decision_reason"],
                         schema.REASON_EVIDENCE_SUFFICIENT)
        self.assertEqual(decision["confidence_level"],
                         conf_schema.CONFIDENCE_HIGH)
        self.assertEqual(decision["required_evidence"],
                         conf_schema.LIMITING_NONE)
        self.assertEqual(decision["blockers"], [])

    def test_2_accept_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision) = full_chain(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(confidence["confidence_level"],
                         conf_schema.CONFIDENCE_HIGH)
        self.assertEqual(decision["decision"],
                         schema.DECISION_ACCEPT_EVIDENCE)
        self.assertEqual(decision["next_state"], schema.NEXT_STATE_COMPLETE)

    def test_3_continue_research_path(self):
        for method, reason, required in (
            (eap.COMPONENT_IDENTITY_LOOKUP,
             schema.REASON_MISSING_IDENTITY,
             conf_schema.LIMITING_COMPONENT_IDENTITY),
            (eap.VERSION_LOOKUP,
             schema.REASON_MISSING_VERSION,
             conf_schema.LIMITING_VERSION),
            (eap.SCOPE_EVIDENCE_REVIEW,
             schema.REASON_MISSING_SCOPE,
             conf_schema.LIMITING_SCOPE),
        ):
            _, _, confidence, decision = bundle(method)
            self.assertEqual(confidence["confidence_level"],
                             conf_schema.CONFIDENCE_MEDIUM)
            self.assertEqual(decision["decision"],
                             schema.DECISION_CONTINUE_RESEARCH, method)
            self.assertEqual(decision["next_state"],
                             schema.NEXT_STATE_ACTIVE_RESEARCH, method)
            self.assertEqual(decision["decision_reason"], reason, method)
            self.assertEqual(decision["required_evidence"], required,
                             method)

    def test_3_continue_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(confidence["confidence_level"],
                         conf_schema.CONFIDENCE_MEDIUM)
        self.assertEqual(decision["decision"],
                         schema.DECISION_CONTINUE_RESEARCH)
        self.assertEqual(decision["decision_reason"],
                         schema.REASON_MISSING_VERSION)
        self.assertEqual(decision["required_evidence"],
                         conf_schema.LIMITING_VERSION)

    def test_4_require_more_evidence_path(self):
        for method, reason, required in (
            (eap.PATH_EVIDENCE_REVIEW,
             schema.REASON_MISSING_PATH,
             conf_schema.LIMITING_PATH),
            (eap.PARAMETER_EVIDENCE_REVIEW,
             schema.REASON_MISSING_PARAMETER,
             conf_schema.LIMITING_PARAMETER),
            (eap.HTTP_BEHAVIOR_REVIEW,
             schema.REASON_MISSING_HTTP_BEHAVIOR,
             conf_schema.LIMITING_HTTP_BEHAVIOR),
            (eap.TECHNOLOGY_EVIDENCE_REVIEW,
             schema.REASON_MISSING_TECHNOLOGY,
             conf_schema.LIMITING_TECHNOLOGY),
        ):
            _, _, confidence, decision = bundle(method)
            self.assertEqual(confidence["confidence_level"],
                             conf_schema.CONFIDENCE_LOW)
            self.assertEqual(decision["decision"],
                             schema.DECISION_REQUIRE_MORE_EVIDENCE, method)
            self.assertEqual(decision["next_state"],
                             schema.NEXT_STATE_WAITING_FOR_EVIDENCE, method)
            self.assertEqual(decision["decision_reason"], reason, method)
            self.assertEqual(decision["required_evidence"], required,
                             method)

    def test_4_require_more_evidence_manual_research(self):
        _, _, confidence, decision = bundle(eap.MANUAL_RESEARCH)
        self.assertEqual(confidence["confidence_category"],
                         conf_schema.CATEGORY_RESEARCH_INCOMPLETE)
        self.assertEqual(decision["decision"],
                         schema.DECISION_REQUIRE_MORE_EVIDENCE)
        self.assertEqual(decision["decision_reason"],
                         schema.REASON_HUMAN_RESEARCH_REQUIRED)
        self.assertEqual(decision["required_evidence"],
                         conf_schema.LIMITING_HUMAN_RESEARCH)

    def test_4_require_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision) = full_chain(
            p1_fixture(gaps=["path: no matching observed path evidence"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(confidence["confidence_level"],
                         conf_schema.CONFIDENCE_LOW)
        self.assertEqual(decision["decision"],
                         schema.DECISION_REQUIRE_MORE_EVIDENCE)
        self.assertEqual(decision["next_state"],
                         schema.NEXT_STATE_WAITING_FOR_EVIDENCE)

    def test_5_defer_research_path(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        confidence = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        decision = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        self.assertEqual(decision["decision"],
                         schema.DECISION_DEFER_RESEARCH)
        self.assertEqual(decision["next_state"], schema.NEXT_STATE_DEFERRED)
        self.assertEqual(decision["decision_reason"],
                         schema.REASON_NO_PLAN_AVAILABLE)
        self.assertEqual(decision["required_evidence"],
                         conf_schema.LIMITING_UPSTREAM_PLAN)
        self.assertIn(conf_schema.BLOCKER_NO_ACQUISITION_PLANNED,
                      decision["blockers"])

    def test_5_defer_via_real_engine_chain(self):
        (_, _, _, _, _, confidence, decision) = full_chain(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(confidence["confidence_level"],
                         conf_schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(decision["decision"],
                         schema.DECISION_DEFER_RESEARCH)
        self.assertEqual(decision["next_state"], schema.NEXT_STATE_DEFERRED)

    def test_5_none_acquisition_beats_forged_high_confidence(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
        forged_confidence = {
            "rule_version": "r31-15",
            "confidence_level": "HIGH",
            "confidence_category": "SUFFICIENT_EVIDENCE",
            "limiting_factor": "NONE",
            "evidence_completeness": "COMPLETE",
            "priority_alignment": "ALIGNED",
            "blockers": [],
            "research_only": True,
        }
        decision = edp.plan_evidence_decision(
            acquisition, {}, forged_confidence
        )
        self.assertEqual(decision["decision"],
                         schema.DECISION_DEFER_RESEARCH)
        self.assertEqual(decision["next_state"], schema.NEXT_STATE_DEFERRED)


# ---------------------------------------------------------------------------
# 6: malformed inputs
# ---------------------------------------------------------------------------


class TestMalformedInputs(unittest.TestCase):
    def test_6_missing_all_inputs_unknown(self):
        for values in ((None, None, None), ({}, {}, {}), ("x", [], 0)):
            decision = edp.plan_evidence_decision(*values)
            self.assertEqual(decision["decision"],
                             schema.DECISION_UNKNOWN, repr(values))
            self.assertEqual(decision["next_state"],
                             schema.NEXT_STATE_UNKNOWN)
            self.assertEqual(decision["decision_reason"],
                             schema.REASON_NO_PLAN_AVAILABLE)
            self.assertEqual(decision["confidence_level"],
                             conf_schema.CONFIDENCE_UNKNOWN)
            self.assertIn(conf_schema.BLOCKER_MALFORMED_ACQUISITION_PLAN,
                          decision["blockers"])

    def test_6_unknown_acquisition_method_unknown(self):
        acquisition = acquisition_plan("DEPLOY_EXPLOIT", target="VERSION")
        decision = edp.plan_evidence_decision(acquisition, {}, {})
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertIn(
            conf_schema.BLOCKER_UNKNOWN_ACQUISITION_METHOD,
            decision["blockers"],
        )

    def test_6_target_mismatch_unknown(self):
        acquisition = acquisition_plan(
            eap.VERSION_LOOKUP, target=eap.TARGET_PATH
        )
        decision = edp.plan_evidence_decision(acquisition, {}, {})
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertIn(
            conf_schema.BLOCKER_MALFORMED_ACQUISITION_PLAN,
            decision["blockers"],
        )

    def test_6_missing_confidence_plan_unknown(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        decision = edp.plan_evidence_decision(
            acquisition, prioritization, None
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertEqual(decision["next_state"],
                         schema.NEXT_STATE_UNKNOWN)
        self.assertEqual(decision["confidence_level"],
                         conf_schema.CONFIDENCE_UNKNOWN)

    def test_6_invalid_confidence_level_unknown(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        decision = edp.plan_evidence_decision(
            acquisition,
            prioritization,
            {"confidence_level": "CERTAIN",
             "confidence_category": "VERSION_LIMITED"},
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)

    def test_6_invalid_confidence_category_unknown(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        decision = edp.plan_evidence_decision(
            acquisition,
            prioritization,
            {"confidence_level": "MEDIUM",
             "confidence_category": "EXPLOITABLE"},
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)

    def test_6_high_with_wrong_category_never_accepted(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        decision = edp.plan_evidence_decision(
            acquisition,
            prioritization,
            {"confidence_level": "HIGH",
             "confidence_category": "VERSION_LIMITED",
             "limiting_factor": "VERSION"},
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertEqual(decision["confidence_level"],
                         conf_schema.CONFIDENCE_HIGH)
        self.assertNotEqual(decision["decision"],
                            schema.DECISION_ACCEPT_EVIDENCE)

    def test_6_medium_without_prioritized_item_unknown(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        decision = edp.plan_evidence_decision(
            acquisition,
            {"rule_version": "r31-14", "items": [], "research_only": True},
            {"confidence_level": "MEDIUM",
             "confidence_category": "VERSION_LIMITED",
             "limiting_factor": "VERSION"},
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertIn(
            conf_schema.BLOCKER_MISSING_PRIORITIZATION_ITEM,
            decision["blockers"],
        )

    def test_6_low_without_prioritized_item_unknown(self):
        acquisition = acquisition_plan(eap.PATH_EVIDENCE_REVIEW)
        decision = edp.plan_evidence_decision(
            acquisition,
            None,
            {"confidence_level": "LOW",
             "confidence_category": "PATH_LIMITED",
             "limiting_factor": "PATH"},
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertIn(
            conf_schema.BLOCKER_MISSING_PRIORITIZATION_ITEM,
            decision["blockers"],
        )

    def test_6_research_incomplete_without_manual_method(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        decision = edp.plan_evidence_decision(
            acquisition,
            prioritization,
            {"confidence_level": "UNKNOWN",
             "confidence_category": "RESEARCH_INCOMPLETE",
             "limiting_factor": "UPSTREAM_PLAN"},
        )
        self.assertEqual(decision["decision"], schema.DECISION_UNKNOWN)
        self.assertEqual(decision["decision_reason"],
                         schema.REASON_NO_PLAN_AVAILABLE)


# ---------------------------------------------------------------------------
# 7: blocker / reason mappings
# ---------------------------------------------------------------------------


class TestBlockerMappings(unittest.TestCase):
    def test_7_all_category_reasons(self):
        expectations = (
            (eap.EXISTING_EVIDENCE_REVIEW, "HIGH", "SUFFICIENT_EVIDENCE",
             schema.REASON_EVIDENCE_SUFFICIENT),
            (eap.COMPONENT_IDENTITY_LOOKUP, "MEDIUM", "IDENTITY_LIMITED",
             schema.REASON_MISSING_IDENTITY),
            (eap.VERSION_LOOKUP, "MEDIUM", "VERSION_LIMITED",
             schema.REASON_MISSING_VERSION),
            (eap.SCOPE_EVIDENCE_REVIEW, "MEDIUM", "SCOPE_LIMITED",
             schema.REASON_MISSING_SCOPE),
            (eap.PATH_EVIDENCE_REVIEW, "LOW", "PATH_LIMITED",
             schema.REASON_MISSING_PATH),
            (eap.PARAMETER_EVIDENCE_REVIEW, "LOW", "PARAMETER_LIMITED",
             schema.REASON_MISSING_PARAMETER),
            (eap.HTTP_BEHAVIOR_REVIEW, "LOW", "BEHAVIOR_LIMITED",
             schema.REASON_MISSING_HTTP_BEHAVIOR),
            (eap.TECHNOLOGY_EVIDENCE_REVIEW, "LOW", "TECHNOLOGY_LIMITED",
             schema.REASON_MISSING_TECHNOLOGY),
            (eap.MANUAL_RESEARCH, "LOW", "RESEARCH_INCOMPLETE",
             schema.REASON_HUMAN_RESEARCH_REQUIRED),
        )
        for method, level, category, reason in expectations:
            acquisition = acquisition_plan(method)
            prioritization = epp.plan_evidence_prioritization(
                acquisition
            )
            decision = edp.plan_evidence_decision(
                acquisition,
                prioritization,
                {"confidence_level": level,
                 "confidence_category": category,
                 "limiting_factor": "NONE"},
            )
            self.assertEqual(decision["decision_reason"], reason, method)

    def test_7_all_confidence_blockers_flow_through(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        for code in conf_schema.CONFIDENCE_BLOCKERS:
            decision = edp.plan_evidence_decision(
                acquisition,
                prioritization,
                {"confidence_level": "MEDIUM",
                 "confidence_category": "VERSION_LIMITED",
                 "limiting_factor": "VERSION",
                 "blockers": [code]},
            )
            self.assertIn(code, decision["blockers"], code)

    def test_7_unknown_upstream_blockers_are_dropped(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        decision = edp.plan_evidence_decision(
            acquisition,
            prioritization,
            {"confidence_level": "MEDIUM",
             "confidence_category": "VERSION_LIMITED",
             "limiting_factor": "VERSION",
             "blockers": ["DEPLOY_EXPLOIT", "NOT_A_BLOCKER"]},
        )
        self.assertEqual(decision["blockers"], [])

    def test_7_reason_vocabulary_is_closed(self):
        expected = {
            "EVIDENCE_SUFFICIENT", "HIGH_CONFIDENCE", "MISSING_IDENTITY",
            "MISSING_VERSION", "MISSING_SCOPE", "MISSING_PATH",
            "MISSING_PARAMETER", "MISSING_HTTP_BEHAVIOR",
            "MISSING_TECHNOLOGY", "HUMAN_RESEARCH_REQUIRED",
            "NO_PLAN_AVAILABLE",
        }
        self.assertEqual(set(schema.DECISION_REASONS), expected)


# ---------------------------------------------------------------------------
# 1, 8: determinism and no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndMutation(unittest.TestCase):
    def test_1_repeated_output_is_byte_identical(self):
        acquisition, prioritization, confidence, _ = bundle(
            eap.VERSION_LOOKUP
        )
        first = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        second = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_1_key_insertion_order_does_not_matter(self):
        acquisition, prioritization, confidence, _ = bundle(
            eap.PATH_EVIDENCE_REVIEW
        )
        shuffled = dict(reversed(list(confidence.items())))
        first = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        second = edp.plan_evidence_decision(
            acquisition, prioritization, shuffled
        )
        self.assertEqual(first, second)

    def test_1_stable_decisions_across_all_methods(self):
        decisions = [bundle(method)[3] for method in TARGETS_BY_METHOD]
        repeated = [bundle(method)[3] for method in TARGETS_BY_METHOD]
        self.assertEqual(
            json.dumps(decisions, sort_keys=True),
            json.dumps(repeated, sort_keys=True),
        )

    def test_8_no_mutation_of_inputs(self):
        acquisition, prioritization, confidence, _ = bundle(
            eap.PARAMETER_EVIDENCE_REVIEW
        )
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        confidence_snapshot = copy.deepcopy(confidence)
        edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)
        self.assertEqual(confidence, confidence_snapshot)

    def test_8_no_mutation_of_terminal_inputs(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        confidence = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        snapshots = (
            copy.deepcopy(acquisition),
            copy.deepcopy(prioritization),
            copy.deepcopy(confidence),
        )
        edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        self.assertEqual(acquisition, snapshots[0])
        self.assertEqual(prioritization, snapshots[1])
        self.assertEqual(confidence, snapshots[2])

    def test_8_source_snapshots_do_not_alias_inputs(self):
        acquisition, prioritization, confidence, decision = bundle(
            eap.VERSION_LOOKUP
        )
        decision["source_acquisition_plan"]["acquisition_rank"] = 99
        decision["source_priority_plan"]["items"].clear()
        decision["source_confidence_plan"]["confidence_level"] = "LOW"
        self.assertEqual(acquisition["acquisition_rank"], 0)
        self.assertEqual(len(prioritization["items"]), 1)
        self.assertEqual(confidence["confidence_level"], "MEDIUM")


# ---------------------------------------------------------------------------
# 9: closed vocabulary validation
# ---------------------------------------------------------------------------


class TestClosedVocabulary(unittest.TestCase):
    def _decisions(self):
        results = [bundle(method)[3] for method in TARGETS_BY_METHOD]
        results.append(edp.plan_evidence_decision(None, None, None))
        results.append(edp.plan_evidence_decision(
            acquisition_plan(eap.NO_ACQUISITION)
        ))
        return results

    def test_9_output_fields_are_closed(self):
        for result in self._decisions():
            self.assertIn(result["decision"], schema.DECISIONS)
            self.assertIn(result["decision_reason"],
                          schema.DECISION_REASONS)
            self.assertIn(result["confidence_level"],
                          conf_schema.CONFIDENCE_LEVELS)
            self.assertIn(result["next_state"], schema.NEXT_STATES)
            self.assertIn(result["required_evidence"],
                          conf_schema.LIMITING_FACTORS)
            for code in result["blockers"]:
                self.assertIn(code, conf_schema.CONFIDENCE_BLOCKERS)

    def test_9_schema_rejects_invalid_decision(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="SHIP_IT",
                decision_reason="EVIDENCE_SUFFICIENT",
                confidence_level="HIGH",
                next_state="COMPLETE",
                required_evidence="NONE",
            )

    def test_9_schema_rejects_invalid_reason(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="ACCEPT_EVIDENCE",
                decision_reason="LOOKS_GOOD",
                confidence_level="HIGH",
                next_state="COMPLETE",
                required_evidence="NONE",
            )

    def test_9_schema_rejects_invalid_confidence_level(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="ACCEPT_EVIDENCE",
                decision_reason="EVIDENCE_SUFFICIENT",
                confidence_level="CERTAIN",
                next_state="COMPLETE",
                required_evidence="NONE",
            )

    def test_9_schema_rejects_invalid_next_state(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="ACCEPT_EVIDENCE",
                decision_reason="EVIDENCE_SUFFICIENT",
                confidence_level="HIGH",
                next_state="DONE",
                required_evidence="NONE",
            )

    def test_9_schema_rejects_invalid_required_evidence(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="ACCEPT_EVIDENCE",
                decision_reason="EVIDENCE_SUFFICIENT",
                confidence_level="HIGH",
                next_state="COMPLETE",
                required_evidence="MONEY",
            )

    def test_9_schema_rejects_invalid_blocker(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="UNKNOWN",
                decision_reason="NO_PLAN_AVAILABLE",
                confidence_level="UNKNOWN",
                next_state="UNKNOWN",
                required_evidence="UPSTREAM_PLAN",
                blockers=["DEPLOY_EXPLOIT"],
            )

    def test_9_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="UNKNOWN",
                decision_reason="NO_PLAN_AVAILABLE",
                confidence_level="UNKNOWN",
                next_state="UNKNOWN",
                required_evidence="UPSTREAM_PLAN",
                severity="CRITICAL",
            )

    def test_9_schema_forces_rule_version_and_research_only(self):
        result = schema.EvidenceDecisionPlan(
            rule_version="r99-9",
            decision="ACCEPT_EVIDENCE",
            decision_reason="EVIDENCE_SUFFICIENT",
            confidence_level="HIGH",
            next_state="COMPLETE",
            required_evidence="NONE",
            research_only=True,
        )
        self.assertEqual(result.rule_version, "r31-16")
        with self.assertRaises(ValidationError):
            schema.EvidenceDecisionPlan(
                decision="ACCEPT_EVIDENCE",
                decision_reason="EVIDENCE_SUFFICIENT",
                confidence_level="HIGH",
                next_state="COMPLETE",
                required_evidence="NONE",
                research_only=False,
            )

    def test_9_exact_rule_version(self):
        self.assertEqual(
            edp.EVIDENCE_DECISION_PLANNER_RULE_VERSION, "r31-16"
        )
        self.assertEqual(edp.RULE_VERSION, "r31-16")
        decision = edp.plan_evidence_decision(None, None, None)
        self.assertEqual(decision["rule_version"], "r31-16")

    def test_9_bounded_blockers(self):
        plan = schema.EvidenceDecisionPlan(
            decision="UNKNOWN",
            decision_reason="NO_PLAN_AVAILABLE",
            confidence_level="UNKNOWN",
            next_state="UNKNOWN",
            required_evidence="UPSTREAM_PLAN",
            blockers=[conf_schema.BLOCKER_NO_ACQUISITION_PLANNED] * 64,
        )
        self.assertLessEqual(len(plan.blockers), schema.MAX_BLOCKERS)


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
    def _decisions(self):
        results = [bundle(method)[3] for method in TARGETS_BY_METHOD]
        results.append(edp.plan_evidence_decision(None, None, None))
        return results

    def test_10_json_serializable(self):
        for result in self._decisions():
            self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_11_research_only_always_true(self):
        for result in self._decisions():
            self.assertIs(result["research_only"], True)

    def test_12_no_operational_attack_content(self):
        blob = json.dumps(self._decisions()).lower()
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
        decision = edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        blob = json.dumps(decision)
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
        self.assertIn("source_acquisition_plan", decision)
        self.assertIn("source_priority_plan", decision)
        self.assertIn("source_confidence_plan", decision)
        for key in decision["source_confidence_plan"]:
            self.assertIn(key, schema.SOURCE_CONFIDENCE_KEYS)
        json.dumps(decision)


# ---------------------------------------------------------------------------
# Regression / integration
# ---------------------------------------------------------------------------


class TestR31Regression(unittest.TestCase):
    def test_r3113_r3114_r3115_rule_versions_unchanged(self):
        self.assertEqual(
            eap.EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION, "r31-13"
        )
        self.assertEqual(
            epp.EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION, "r31-14"
        )
        self.assertEqual(
            eca.EVIDENCE_CONFIDENCE_AGGREGATOR_RULE_VERSION, "r31-15"
        )

    def test_upstream_plans_unchanged_by_decision(self):
        (_, _, _, acquisition, prioritization, confidence,
         decision) = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        confidence_snapshot = copy.deepcopy(confidence)
        edp.plan_evidence_decision(
            acquisition, prioritization, confidence
        )
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)
        self.assertEqual(confidence, confidence_snapshot)
        self.assertEqual(decision["decision"],
                         schema.DECISION_CONTINUE_RESEARCH)

    def test_r29_queue_has_no_decision_field(self):
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
        self.assertNotIn("evidence_decision_plan", projection)
        self.assertNotIn(
            "evidence_decision_plan_rule_version", projection
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
            item["evidence_decision_plan_rule_version"], "r31-16"
        )
        self.assertEqual(
            item["evidence_decision_plan"]["rule_version"], "r31-16"
        )
        self.assertIs(
            item["evidence_decision_plan"]["research_only"], True
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
            item["evidence_decision_plan"]["confidence_level"],
            item["evidence_confidence_plan"]["confidence_level"],
        )

    def test_backend_immediate_plan_accepts_evidence(self):
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
            item["evidence_decision_plan"]["decision"],
            schema.DECISION_ACCEPT_EVIDENCE,
        )
        self.assertEqual(
            item["evidence_decision_plan"]["next_state"],
            schema.NEXT_STATE_COMPLETE,
        )
        self.assertEqual(
            item["evidence_decision_plan"]["required_evidence"],
            conf_schema.LIMITING_NONE,
        )
        # Existing projections are not altered by the decision.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_defers_research(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_decision_plan"]["decision"],
            schema.DECISION_DEFER_RESEARCH,
        )
        self.assertEqual(
            item["evidence_decision_plan"]["next_state"],
            schema.NEXT_STATE_DEFERRED,
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
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_decision_plan"],
            item["evidence_confidence_plan"],
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
