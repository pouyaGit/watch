"""tests/test_evidence_confidence_aggregator.py — Stage R31.15 tests.

Deterministic, offline tests for the evidence confidence aggregator:

- deterministic, stable output
- all R31.13 acquisition method mappings (raw and via the real engine chain)
- terminal NONE and malformed/missing/misaligned plan handling
- no mutation of the R31.13/R31.14 inputs
- closed vocabulary enforcement (aggregator + pydantic schema)
- bounded, privacy-safe, JSON-serializable output
- plan-only: research_only always true, no operational attack content
- hermetic backend integration (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any acquisition method.
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
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_confidence as schema
from ai.schemas.evidence_prioritization import (
    SOURCE_PLAN_KEYS as SOURCE_ACQUISITION_PLAN_KEYS,
)
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

EXPECTED_BY_METHOD = {
    eap.EXISTING_EVIDENCE_REVIEW: (
        schema.CONFIDENCE_HIGH,
        schema.CATEGORY_SUFFICIENT_EVIDENCE,
        schema.COMPLETENESS_COMPLETE,
        schema.LIMITING_NONE,
    ),
    eap.COMPONENT_IDENTITY_LOOKUP: (
        schema.CONFIDENCE_MEDIUM,
        schema.CATEGORY_IDENTITY_LIMITED,
        schema.COMPLETENESS_PARTIAL,
        schema.LIMITING_COMPONENT_IDENTITY,
    ),
    eap.VERSION_LOOKUP: (
        schema.CONFIDENCE_MEDIUM,
        schema.CATEGORY_VERSION_LIMITED,
        schema.COMPLETENESS_PARTIAL,
        schema.LIMITING_VERSION,
    ),
    eap.SCOPE_EVIDENCE_REVIEW: (
        schema.CONFIDENCE_MEDIUM,
        schema.CATEGORY_SCOPE_LIMITED,
        schema.COMPLETENESS_PARTIAL,
        schema.LIMITING_SCOPE,
    ),
    eap.PATH_EVIDENCE_REVIEW: (
        schema.CONFIDENCE_LOW,
        schema.CATEGORY_PATH_LIMITED,
        schema.COMPLETENESS_MINIMAL,
        schema.LIMITING_PATH,
    ),
    eap.PARAMETER_EVIDENCE_REVIEW: (
        schema.CONFIDENCE_LOW,
        schema.CATEGORY_PARAMETER_LIMITED,
        schema.COMPLETENESS_MINIMAL,
        schema.LIMITING_PARAMETER,
    ),
    eap.HTTP_BEHAVIOR_REVIEW: (
        schema.CONFIDENCE_LOW,
        schema.CATEGORY_BEHAVIOR_LIMITED,
        schema.COMPLETENESS_MINIMAL,
        schema.LIMITING_HTTP_BEHAVIOR,
    ),
    eap.TECHNOLOGY_EVIDENCE_REVIEW: (
        schema.CONFIDENCE_LOW,
        schema.CATEGORY_TECHNOLOGY_LIMITED,
        schema.COMPLETENESS_MINIMAL,
        schema.LIMITING_TECHNOLOGY,
    ),
    eap.MANUAL_RESEARCH: (
        schema.CONFIDENCE_LOW,
        schema.CATEGORY_RESEARCH_INCOMPLETE,
        schema.COMPLETENESS_MINIMAL,
        schema.LIMITING_HUMAN_RESEARCH,
    ),
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
    """Build R31.10 -> ... -> R31.15 outputs with the real engines."""

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
    return (
        hp_result, ha_result, action_plan, acquisition,
        prioritization, confidence,
    )


# ---------------------------------------------------------------------------
# 3: all acquisition method mappings
# ---------------------------------------------------------------------------


class TestMethodMappings(unittest.TestCase):
    def test_3_every_method_maps_to_confidence(self):
        for method in eap.ACQUISITION_METHODS:
            if method == eap.NO_ACQUISITION:
                continue
            acquisition = acquisition_plan(method)
            prioritization = epp.plan_evidence_prioritization(acquisition)
            result = eca.aggregate_evidence_confidence(
                acquisition, prioritization
            )
            expected = EXPECTED_BY_METHOD[method]
            self.assertEqual(result["confidence_level"], expected[0],
                             method)
            self.assertEqual(result["confidence_category"], expected[1],
                             method)
            self.assertEqual(result["evidence_completeness"], expected[2],
                             method)
            self.assertEqual(result["limiting_factor"], expected[3],
                             method)
            self.assertEqual(result["priority_alignment"],
                             schema.ALIGNMENT_ALIGNED, method)

    def test_3_method_confidence_levels_are_documented(self):
        self.assertEqual(
            eca.METHOD_CONFIDENCE_LEVELS[eap.EXISTING_EVIDENCE_REVIEW],
            schema.CONFIDENCE_HIGH,
        )
        for method in (
            eap.COMPONENT_IDENTITY_LOOKUP,
            eap.VERSION_LOOKUP,
            eap.SCOPE_EVIDENCE_REVIEW,
        ):
            self.assertEqual(
                eca.METHOD_CONFIDENCE_LEVELS[method],
                schema.CONFIDENCE_MEDIUM,
            )
        for method in (
            eap.PATH_EVIDENCE_REVIEW,
            eap.PARAMETER_EVIDENCE_REVIEW,
            eap.HTTP_BEHAVIOR_REVIEW,
            eap.TECHNOLOGY_EVIDENCE_REVIEW,
            eap.MANUAL_RESEARCH,
        ):
            self.assertEqual(
                eca.METHOD_CONFIDENCE_LEVELS[method],
                schema.CONFIDENCE_LOW,
            )
        # Terminal NONE is handled as UNKNOWN outside the mapping table.
        self.assertNotIn(eap.NO_ACQUISITION, eca.METHOD_CONFIDENCE)

    def test_3_real_engine_chain_every_method(self):
        p3 = dict(
            evidence_quality=quality("LOW", strength="WEAK"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
            cve_id=CVE,
        )
        cases = (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED", None,
             eap.EXISTING_EVIDENCE_REVIEW),
            (p1_fixture(
                gaps=["component: no observed component/plugin identity"]),
             "EXPLICIT", "GLOBAL", None,
             eap.COMPONENT_IDENTITY_LOOKUP),
            (p1_fixture(gaps=["version: no observed version available"]),
             "EXPLICIT", "GLOBAL", None, eap.VERSION_LOOKUP),
            (p1_fixture(
                gaps=["scope: no component-scoped support available"]),
             "EXPLICIT", "GLOBAL", None, eap.SCOPE_EVIDENCE_REVIEW),
            (p1_fixture(
                gaps=["path: no matching observed path evidence"]),
             "EXPLICIT", "GLOBAL", None, eap.PATH_EVIDENCE_REVIEW),
            (p1_fixture(
                gaps=["parameter: no matching observed parameter evidence"]),
             "EXPLICIT", "GLOBAL", None,
             eap.PARAMETER_EVIDENCE_REVIEW),
            (p1_fixture(gaps=["method: no structured method evidence"]),
             "EXPLICIT", "GLOBAL", None, eap.HTTP_BEHAVIOR_REVIEW),
            (p1_fixture(), "EXPLICIT", "GLOBAL", "TECHNOLOGY",
             eap.TECHNOLOGY_EVIDENCE_REVIEW),
            (p1_fixture(), "EXPLICIT", "GLOBAL", None,
             eap.MANUAL_RESEARCH),
            (immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH"),
             "EXPLICIT", "COMPONENT_SCOPED", None,
             eap.NO_ACQUISITION),
        )
        for fixture, provenance, scope, strongest, expected_method in cases:
            (_, _, _, acquisition, prioritization,
             confidence) = full_chain(
                fixture, provenance=provenance, scope=scope,
                strongest=strongest,
            )
            self.assertEqual(
                acquisition["acquisition_method"], expected_method
            )
            if expected_method == eap.NO_ACQUISITION:
                self.assertEqual(confidence["confidence_level"],
                                 schema.CONFIDENCE_UNKNOWN)
                self.assertEqual(
                    confidence["confidence_category"],
                    schema.CATEGORY_RESEARCH_INCOMPLETE,
                )
                self.assertEqual(
                    confidence["blockers"],
                    [schema.BLOCKER_NO_ACQUISITION_PLANNED],
                )
            else:
                expected = EXPECTED_BY_METHOD[expected_method]
                self.assertEqual(confidence["confidence_level"],
                                 expected[0])
                self.assertEqual(confidence["confidence_category"],
                                 expected[1])
                self.assertEqual(confidence["evidence_completeness"],
                                 expected[2])
                self.assertEqual(confidence["limiting_factor"],
                                 expected[3])
                self.assertEqual(confidence["priority_alignment"],
                                 schema.ALIGNMENT_ALIGNED)


# ---------------------------------------------------------------------------
# 4: terminal NONE handling
# ---------------------------------------------------------------------------


class TestTerminalNone(unittest.TestCase):
    def test_4_none_method_unknown(self):
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.NO_ACQUISITION),
            epp.plan_evidence_prioritization(
                acquisition_plan(eap.NO_ACQUISITION)
            ),
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(result["confidence_category"],
                         schema.CATEGORY_RESEARCH_INCOMPLETE)
        self.assertEqual(result["evidence_completeness"],
                         schema.COMPLETENESS_NONE)
        self.assertEqual(result["limiting_factor"],
                         schema.LIMITING_UPSTREAM_PLAN)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_NOT_APPLICABLE)
        self.assertEqual(result["blockers"],
                         [schema.BLOCKER_NO_ACQUISITION_PLANNED])

    def test_4_none_method_ignores_stale_prioritization(self):
        stale = {
            "rule_version": "r31-14",
            "items": [{
                "evidence_target": "VERSION",
                "acquisition_method": "VERSION_LOOKUP",
                "priority_rank": 3,
                "priority_reason": "PRIORITY_VERSION",
                "uncertainty_category": "VERSION_UNCERTAINTY",
                "dependency_level": 1,
                "completion_importance": "CRITICAL",
            }],
            "research_only": True,
        }
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.NO_ACQUISITION), stale
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_NOT_APPLICABLE)

    def test_4_blocked_chain_is_unknown(self):
        (_, _, _, acquisition, prioritization,
         confidence) = full_chain(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(confidence["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)


# ---------------------------------------------------------------------------
# 5: malformed input handling
# ---------------------------------------------------------------------------


class TestMalformedInput(unittest.TestCase):
    def test_5_missing_both_plans_unknown(self):
        for acquisition in (None, {}, "not-a-plan", [], 0):
            result = eca.aggregate_evidence_confidence(acquisition)
            self.assertEqual(result["confidence_level"],
                             schema.CONFIDENCE_UNKNOWN, repr(acquisition))
            self.assertEqual(result["confidence_category"],
                             schema.CATEGORY_RESEARCH_INCOMPLETE)
            self.assertEqual(result["evidence_completeness"],
                             schema.COMPLETENESS_NONE)
            self.assertIn(schema.BLOCKER_MALFORMED_ACQUISITION_PLAN,
                          result["blockers"])

    def test_5_unknown_method_unknown(self):
        result = eca.aggregate_evidence_confidence(
            acquisition_plan("DEPLOY_EXPLOIT", target="VERSION"),
            {"rule_version": "r31-14", "items": []},
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(result["blockers"],
                         [schema.BLOCKER_UNKNOWN_ACQUISITION_METHOD])
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_NOT_APPLICABLE)

    def test_5_target_mismatch_unknown(self):
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.VERSION_LOOKUP, target=eap.TARGET_PATH),
            {"rule_version": "r31-14", "items": []},
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(result["blockers"],
                         [schema.BLOCKER_MALFORMED_ACQUISITION_PLAN])

    def test_5_existing_method_without_prioritization_unknown(self):
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.EXISTING_EVIDENCE_REVIEW)
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(result["limiting_factor"],
                         schema.LIMITING_UPSTREAM_PLAN)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_NOT_APPLICABLE)
        self.assertEqual(result["blockers"],
                         [schema.BLOCKER_MISSING_PRIORITIZATION_ITEM])

    def test_5_existing_method_with_wrong_rank_unknown(self):
        acquisition = acquisition_plan(eap.EXISTING_EVIDENCE_REVIEW)
        forged = {
            "rule_version": "r31-14",
            "items": [{
                "evidence_target": "EXISTING_EVIDENCE",
                "acquisition_method": "EXISTING_EVIDENCE_REVIEW",
                "priority_rank": 8,
                "priority_reason": "PRIORITY_EXISTING_EVIDENCE",
                "uncertainty_category": "EXISTING_EVIDENCE_UNCERTAINTY",
                "dependency_level": 0,
                "completion_importance": "HIGH",
            }],
            "research_only": True,
        }
        result = eca.aggregate_evidence_confidence(acquisition, forged)
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_UNKNOWN)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_MISALIGNED)
        self.assertIn(schema.BLOCKER_PRIORITY_MISALIGNMENT,
                      result["blockers"])

    def test_5_medium_method_without_prioritization_stays_medium(self):
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.VERSION_LOOKUP)
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_MEDIUM)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_NOT_APPLICABLE)
        self.assertEqual(result["blockers"],
                         [schema.BLOCKER_VERSION_EVIDENCE_MISSING])

    def test_5_medium_method_with_wrong_rank_misaligned(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        forged = {
            "rule_version": "r31-14",
            "items": [{
                "evidence_target": "VERSION",
                "acquisition_method": "VERSION_LOOKUP",
                "priority_rank": 1,
                "priority_reason": "PRIORITY_VERSION",
                "uncertainty_category": "VERSION_UNCERTAINTY",
                "dependency_level": 1,
                "completion_importance": "CRITICAL",
            }],
            "research_only": True,
        }
        result = eca.aggregate_evidence_confidence(acquisition, forged)
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_MEDIUM)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_MISALIGNED)
        self.assertIn(schema.BLOCKER_PRIORITY_MISALIGNMENT,
                      result["blockers"])

    def test_5_medium_method_with_empty_items_misaligned(self):
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.VERSION_LOOKUP),
            {"rule_version": "r31-14", "items": [], "research_only": True},
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_MEDIUM)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_MISALIGNED)
        self.assertIn(schema.BLOCKER_MISSING_PRIORITIZATION_ITEM,
                      result["blockers"])

    def test_5_prioritization_items_malformed_entries_are_skipped(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        forged = {
            "rule_version": "r31-14",
            "items": ["not-a-dict", 42,
                      {"acquisition_method": "VERSION_LOOKUP",
                       "evidence_target": "VERSION",
                       "priority_rank": 3}],
            "research_only": True,
        }
        result = eca.aggregate_evidence_confidence(acquisition, forged)
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_ALIGNED)
        self.assertEqual(
            result["source_prioritization_plan"]["items"], []
        )


# ---------------------------------------------------------------------------
# 1–2: determinism and stability
# ---------------------------------------------------------------------------


class TestDeterminismAndStability(unittest.TestCase):
    def _pair(self, method):
        acquisition = acquisition_plan(method)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        return acquisition, prioritization

    def test_1_repeated_output_is_byte_identical(self):
        acquisition, prioritization = self._pair(eap.VERSION_LOOKUP)
        first = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        second = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_1_key_insertion_order_does_not_matter(self):
        acquisition, prioritization = self._pair(eap.PATH_EVIDENCE_REVIEW)
        shuffled = dict(reversed(list(acquisition.items())))
        first = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        second = eca.aggregate_evidence_confidence(
            shuffled, prioritization
        )
        self.assertEqual(first, second)

    def test_2_stable_confidence_result(self):
        results = [
            eca.aggregate_evidence_confidence(*self._pair(method))
            for method in EXPECTED_BY_METHOD
        ]
        repeated = [
            eca.aggregate_evidence_confidence(*self._pair(method))
            for method in EXPECTED_BY_METHOD
        ]
        self.assertEqual(
            json.dumps(results, sort_keys=True),
            json.dumps(repeated, sort_keys=True),
        )

    def test_2_high_requires_aligned_rank_one(self):
        acquisition = acquisition_plan(eap.EXISTING_EVIDENCE_REVIEW)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        self.assertEqual(
            prioritization["items"][0]["priority_rank"], 1
        )
        result = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        self.assertEqual(result["confidence_level"],
                         schema.CONFIDENCE_HIGH)
        self.assertEqual(result["blockers"], [])
        self.assertEqual(result["priority_alignment"],
                         schema.ALIGNMENT_ALIGNED)


# ---------------------------------------------------------------------------
# 6: no mutation of inputs
# ---------------------------------------------------------------------------


class TestNoMutation(unittest.TestCase):
    def test_6_no_mutation_of_inputs(self):
        acquisition = acquisition_plan(eap.PARAMETER_EVIDENCE_REVIEW)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        eca.aggregate_evidence_confidence(acquisition, prioritization)
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)

    def test_6_no_mutation_of_terminal_inputs(self):
        acquisition = acquisition_plan(eap.NO_ACQUISITION)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        eca.aggregate_evidence_confidence(acquisition, prioritization)
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)

    def test_6_source_snapshots_do_not_alias_inputs(self):
        acquisition = acquisition_plan(eap.VERSION_LOOKUP)
        prioritization = epp.plan_evidence_prioritization(acquisition)
        result = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        result["source_acquisition_plan"]["acquisition_rank"] = 99
        result["source_prioritization_plan"]["items"].clear()
        self.assertEqual(acquisition["acquisition_rank"], 0)
        self.assertEqual(len(prioritization["items"]), 1)


# ---------------------------------------------------------------------------
# 7: closed vocabulary validation
# ---------------------------------------------------------------------------


class TestClosedVocabulary(unittest.TestCase):
    def _results(self):
        results = []
        for method in EXPECTED_BY_METHOD:
            acquisition = acquisition_plan(method)
            results.append(eca.aggregate_evidence_confidence(
                acquisition, epp.plan_evidence_prioritization(acquisition)
            ))
        results.append(eca.aggregate_evidence_confidence(None, None))
        results.append(eca.aggregate_evidence_confidence(
            acquisition_plan(eap.NO_ACQUISITION)
        ))
        return results

    def test_7_output_fields_are_closed(self):
        for result in self._results():
            self.assertIn(result["confidence_level"],
                          schema.CONFIDENCE_LEVELS)
            self.assertIn(result["confidence_category"],
                          schema.CONFIDENCE_CATEGORIES)
            self.assertIn(result["limiting_factor"],
                          schema.LIMITING_FACTORS)
            self.assertIn(result["evidence_completeness"],
                          schema.EVIDENCE_COMPLETENESS_LEVELS)
            self.assertIn(result["priority_alignment"],
                          schema.PRIORITY_ALIGNMENTS)
            for code in result["blockers"]:
                self.assertIn(code, schema.CONFIDENCE_BLOCKERS)

    def test_7_schema_rejects_invalid_level(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="CERTAIN",
                confidence_category="SUFFICIENT_EVIDENCE",
                limiting_factor="NONE",
                evidence_completeness="COMPLETE",
                priority_alignment="ALIGNED",
            )

    def test_7_schema_rejects_invalid_category(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="HIGH",
                confidence_category="EXPLOITABLE",
                limiting_factor="NONE",
                evidence_completeness="COMPLETE",
                priority_alignment="ALIGNED",
            )

    def test_7_schema_rejects_invalid_limiting_factor(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="HIGH",
                confidence_category="SUFFICIENT_EVIDENCE",
                limiting_factor="MONEY",
                evidence_completeness="COMPLETE",
                priority_alignment="ALIGNED",
            )

    def test_7_schema_rejects_invalid_completeness(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="HIGH",
                confidence_category="SUFFICIENT_EVIDENCE",
                limiting_factor="NONE",
                evidence_completeness="FULL",
                priority_alignment="ALIGNED",
            )

    def test_7_schema_rejects_invalid_alignment(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="HIGH",
                confidence_category="SUFFICIENT_EVIDENCE",
                limiting_factor="NONE",
                evidence_completeness="COMPLETE",
                priority_alignment="SYNCED",
            )

    def test_7_schema_rejects_invalid_blocker(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="LOW",
                confidence_category="PATH_LIMITED",
                limiting_factor="PATH",
                evidence_completeness="MINIMAL",
                priority_alignment="ALIGNED",
                blockers=["DEPLOY_EXPLOIT"],
            )

    def test_7_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="HIGH",
                confidence_category="SUFFICIENT_EVIDENCE",
                limiting_factor="NONE",
                evidence_completeness="COMPLETE",
                priority_alignment="ALIGNED",
                severity="CRITICAL",
            )

    def test_7_schema_forces_rule_version_and_research_only(self):
        result = schema.EvidenceConfidencePlan(
            rule_version="r99-9",
            confidence_level="HIGH",
            confidence_category="SUFFICIENT_EVIDENCE",
            limiting_factor="NONE",
            evidence_completeness="COMPLETE",
            priority_alignment="ALIGNED",
            research_only=True,
        )
        self.assertEqual(result.rule_version, "r31-15")
        with self.assertRaises(ValidationError):
            schema.EvidenceConfidencePlan(
                confidence_level="HIGH",
                confidence_category="SUFFICIENT_EVIDENCE",
                limiting_factor="NONE",
                evidence_completeness="COMPLETE",
                priority_alignment="ALIGNED",
                research_only=False,
            )

    def test_7_exact_rule_version(self):
        self.assertEqual(
            eca.EVIDENCE_CONFIDENCE_AGGREGATOR_RULE_VERSION, "r31-15"
        )
        self.assertEqual(eca.RULE_VERSION, "r31-15")
        result = eca.aggregate_evidence_confidence(
            acquisition_plan(eap.VERSION_LOOKUP)
        )
        self.assertEqual(result["rule_version"], "r31-15")

    def test_7_bounded_blockers(self):
        plan = schema.EvidenceConfidencePlan(
            confidence_level="LOW",
            confidence_category="RESEARCH_INCOMPLETE",
            limiting_factor="UPSTREAM_PLAN",
            evidence_completeness="NONE",
            priority_alignment="NOT_APPLICABLE",
            blockers=[schema.BLOCKER_NO_ACQUISITION_PLANNED] * 64,
        )
        self.assertLessEqual(len(plan.blockers), schema.MAX_BLOCKERS)


# ---------------------------------------------------------------------------
# 8–10: JSON, research_only, no operational content
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
    def _results(self):
        results = [
            eca.aggregate_evidence_confidence(
                acquisition_plan(method),
                epp.plan_evidence_prioritization(
                    acquisition_plan(method)
                ),
            )
            for method in EXPECTED_BY_METHOD
        ]
        results.append(eca.aggregate_evidence_confidence(None, None))
        results.append(eca.aggregate_evidence_confidence(
            acquisition_plan(eap.NO_ACQUISITION)
        ))
        return results

    def test_8_json_serializable(self):
        for result in self._results():
            self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_9_research_only_always_true(self):
        for result in self._results():
            self.assertIs(result["research_only"], True)

    def test_10_no_operational_attack_content(self):
        blob = json.dumps(self._results()).lower()
        for marker in FORBIDDEN_OPERATIONAL_MARKERS:
            self.assertNotIn(marker, blob)

    def test_10_source_snapshots_are_sanitized(self):
        acquisition = acquisition_plan(
            eap.MANUAL_RESEARCH,
            source_action="token=SECRETVALUE",
            source_actionability="Bearer abc123",
            reason_codes=["https://user:hunter2@x.test/p?token=SECRET"],
        )
        result = eca.aggregate_evidence_confidence(acquisition)
        blob = json.dumps(result)
        for token in ("SECRETVALUE", "abc123", "hunter2", "SECRET"):
            self.assertNotIn(token, blob)

    def test_10_source_snapshots_are_bounded(self):
        acquisition = acquisition_plan(
            eap.VERSION_LOOKUP,
            reason_codes=[f"CODE_{index}" for index in range(64)],
        )
        prioritization = epp.plan_evidence_prioritization(acquisition)
        result = eca.aggregate_evidence_confidence(
            acquisition, prioritization
        )
        acquisition_snapshot = result["source_acquisition_plan"]
        for key in acquisition_snapshot:
            self.assertIn(key, SOURCE_ACQUISITION_PLAN_KEYS)
        for key in result["source_prioritization_plan"]:
            self.assertIn(key, schema.SOURCE_PRIORITIZATION_KEYS)
        self.assertLessEqual(
            len(acquisition_snapshot["reason_codes"]),
            schema.MAX_ITEMS * 2,
        )
        json.dumps(result)


# ---------------------------------------------------------------------------
# Regression / integration
# ---------------------------------------------------------------------------


class TestR31Regression(unittest.TestCase):
    def test_r3113_and_r3114_rule_versions_unchanged(self):
        self.assertEqual(
            eap.EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION, "r31-13"
        )
        self.assertEqual(
            epp.EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION, "r31-14"
        )

    def test_inputs_are_not_modified_by_aggregation(self):
        _, _, _, acquisition, prioritization, _ = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        acquisition_snapshot = copy.deepcopy(acquisition)
        prioritization_snapshot = copy.deepcopy(prioritization)
        eca.aggregate_evidence_confidence(acquisition, prioritization)
        self.assertEqual(acquisition, acquisition_snapshot)
        self.assertEqual(prioritization, prioritization_snapshot)

    def test_r29_queue_has_no_confidence_field(self):
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
        self.assertNotIn("evidence_confidence_plan", projection)
        self.assertNotIn(
            "evidence_confidence_plan_rule_version", projection
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
            item["evidence_confidence_plan_rule_version"], "r31-15"
        )
        self.assertEqual(
            item["evidence_confidence_plan"]["rule_version"], "r31-15"
        )
        self.assertIs(
            item["evidence_confidence_plan"]["research_only"], True
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
            item["evidence_confidence_plan"][
                "source_acquisition_plan"
            ]["acquisition_method"],
            item["evidence_acquisition_plan"]["acquisition_method"],
        )

    def test_backend_immediate_plan_confidence_high(self):
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
            item["evidence_confidence_plan"]["confidence_level"],
            schema.CONFIDENCE_HIGH,
        )
        self.assertEqual(
            item["evidence_confidence_plan"]["confidence_category"],
            schema.CATEGORY_SUFFICIENT_EVIDENCE,
        )
        self.assertEqual(
            item["evidence_confidence_plan"]["priority_alignment"],
            schema.ALIGNMENT_ALIGNED,
        )
        # Existing projections are not altered by aggregation.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_confidence_unknown(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_confidence_plan"]["confidence_level"],
            schema.CONFIDENCE_UNKNOWN,
        )
        self.assertEqual(
            item["evidence_confidence_plan"]["blockers"],
            [schema.BLOCKER_NO_ACQUISITION_PLANNED],
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
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_confidence_plan"],
            item["evidence_prioritization_plan"],
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
