"""tests/test_evidence_acquisition_planner.py — Stage R31.13 tests.

Deterministic, offline tests for the evidence acquisition planner:

- terminal handling (BLOCKED / LOW_VALUE_DEFERRED / terminal R31.12 action)
- deterministic acquisition mapping for every R31.12 action
- missing / unknown / conflicting R31.12 action plans
- R31.12 is the only gap selector (never independently recomputed)
- stable repeated output and stable acquisition ordering
- no mutation of the R31.10/R31.11/R31.12 projections
- regression: R31.10 priority/score, R31.11 actionability, R31.12 plan,
  R29 hunt queue, Money Score
- bounded, privacy-safe, JSON-serializable output
- plan-only: no operational attack content, research_only always true
- hermetic backend integration (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any acquisition method.
"""
import copy
import inspect
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import evidence_acquisition_planner as eap
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas.hunt_queue import HUNT_RULE_VERSION, hunt_item_projection
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1560"


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


def p3_fixture(**over):
    base = dict(
        evidence_quality=quality("LOW", strength="WEAK"),
        strongest_match_type="COMPONENT",
        strongest_confidence="MEDIUM",
        asset_match_state="SUPPORTED",
        matched_component="CKEditor",
        evidence_provenance="INFERRED",
        support_scope="GLOBAL",
        cve_id=CVE,
    )
    base.update(over)
    return base


def engines(fixture, *, provenance=None, scope=None, strongest=None):
    """Build R31.10..R31.13 outputs with the real upstream engines."""

    hp_result = hp.evaluate_hunt_priority(**fixture)
    ha_result = ha.evaluate_hunt_actionability(
        hp_result,
        evidence_provenance=provenance,
        support_scope=scope,
    )
    plan = pl.plan_hunt_action(
        hp_result,
        ha_result,
        evidence_provenance=provenance,
        support_scope=scope,
        strongest_match_type=strongest,
    )
    acquisition = eap.plan_evidence_acquisition(
        hp_result,
        ha_result,
        plan,
        evidence_provenance=provenance,
        support_scope=scope,
        strongest_match_type=strongest,
    )
    return hp_result, ha_result, plan, acquisition


# ---------------------------------------------------------------------------
# 1–2: terminal actionability states
# ---------------------------------------------------------------------------


class TestTerminalActionability(unittest.TestCase):
    def test_1_blocked_maps_to_none(self):
        _, ha_result, plan, acquisition = engines(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(ha_result["actionability"], ha.BLOCKED)
        self.assertEqual(plan["action"], pl.RESOLVE_BLOCKERS)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_NONE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_BLOCKERS_RESOLVED)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_BLOCKED])
        self.assertEqual(acquisition["confidence"],
                         eap.CONFIDENCE_HIGH)
        self.assertEqual(acquisition["estimated_effort"],
                         eap.EFFORT_UNKNOWN)

    def test_2_low_value_deferred_maps_to_none(self):
        _, ha_result, plan, acquisition = engines(
            p3_fixture(), provenance="INFERRED", scope="GLOBAL"
        )
        self.assertEqual(ha_result["actionability"],
                         ha.LOW_VALUE_DEFERRED)
        self.assertEqual(plan["action"], pl.DEFER)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_NONE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_REACTIVATE)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_DEFERRED])


# ---------------------------------------------------------------------------
# 3–11: deterministic action -> acquisition mapping
# ---------------------------------------------------------------------------


class TestDeterministicMapping(unittest.TestCase):
    def _acquisition(self, *gaps, **over):
        _, _, plan, acquisition = engines(
            p1_fixture(gaps=gaps, **over),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        return plan, acquisition

    def test_3_immediate_maps_to_existing_evidence_review(self):
        _, ha_result, plan, acquisition = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(ha_result["actionability"],
                         ha.IMMEDIATE_VERIFICATION)
        self.assertEqual(plan["action"], pl.VERIFY_EXISTING_EVIDENCE)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.EXISTING_EVIDENCE_REVIEW)
        self.assertEqual(acquisition["acquisition_rank"], 0)
        self.assertEqual(acquisition["evidence_target"],
                         eap.TARGET_EXISTING_EVIDENCE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_EXISTING_REVIEWED)
        self.assertEqual(acquisition["confidence"], eap.CONFIDENCE_HIGH)
        self.assertEqual(acquisition["estimated_effort"], eap.EFFORT_LOW)
        self.assertIn(eap.REASON_SOURCE_IMMEDIATE,
                      acquisition["reason_codes"])
        self.assertIn(eap.REASON_NO_ACQUISITION_REQUIRED,
                      acquisition["reason_codes"])

    def test_4_verify_version_maps_to_version_lookup(self):
        plan, acquisition = self._acquisition(
            "version: no observed version available"
        )
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.VERSION_LOOKUP)
        self.assertEqual(acquisition["acquisition_rank"], 1)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_VERSION)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_VERSION)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_VERSION_ESTABLISHED)
        self.assertIn(eap.REASON_SOURCE_ACTION,
                      acquisition["reason_codes"])
        self.assertIn(pl.GAP_VERSION, acquisition["reason_codes"])

    def test_5_verify_component_identity_maps_to_lookup(self):
        plan, acquisition = self._acquisition(
            "component: no observed component/plugin identity"
        )
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.COMPONENT_IDENTITY_LOOKUP)
        self.assertEqual(acquisition["acquisition_rank"], 2)
        self.assertEqual(acquisition["evidence_target"],
                         eap.TARGET_COMPONENT_IDENTITY)
        self.assertEqual(acquisition["evidence_gap"],
                         pl.GAP_COMPONENT_IDENTITY)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_IDENTITY_ESTABLISHED)

    def test_5_plugin_gap_still_component_identity(self):
        plan, acquisition = self._acquisition(
            remaining_blockers=["plugin_not_observed"]
        )
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.COMPONENT_IDENTITY_LOOKUP)

    def test_6_verify_scope_maps_to_scope_review(self):
        plan, acquisition = self._acquisition(
            "scope: no component-scoped support available"
        )
        self.assertEqual(plan["action"], pl.VERIFY_SCOPE)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.SCOPE_EVIDENCE_REVIEW)
        self.assertEqual(acquisition["acquisition_rank"], 3)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_SCOPE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_SCOPE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_SCOPE_ESTABLISHED)

    def test_7_verify_path_maps_to_path_review(self):
        plan, acquisition = self._acquisition(
            "path: no matching observed path evidence"
        )
        self.assertEqual(plan["action"], pl.VERIFY_PATH)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.PATH_EVIDENCE_REVIEW)
        self.assertEqual(acquisition["acquisition_rank"], 4)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_PATH)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_PATH)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_PATH_ESTABLISHED)

    def test_8_verify_parameter_maps_to_parameter_review(self):
        plan, acquisition = self._acquisition(
            "parameter: no matching observed parameter evidence"
        )
        self.assertEqual(plan["action"], pl.VERIFY_PARAMETER)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.PARAMETER_EVIDENCE_REVIEW)
        self.assertEqual(acquisition["acquisition_rank"], 5)
        self.assertEqual(acquisition["evidence_target"],
                         eap.TARGET_PARAMETER)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_PARAMETER)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_PARAMETER_ESTABLISHED)

    def test_9_collect_http_maps_to_http_review(self):
        plan, acquisition = self._acquisition(
            "method: no structured method evidence"
        )
        self.assertEqual(plan["action"], pl.COLLECT_HTTP_EVIDENCE)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.HTTP_BEHAVIOR_REVIEW)
        self.assertEqual(acquisition["acquisition_rank"], 6)
        self.assertEqual(acquisition["evidence_target"],
                         eap.TARGET_HTTP_BEHAVIOR)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_HTTP)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_HTTP_ESTABLISHED)

    def test_10_collect_technology_maps_to_technology_review(self):
        _, _, plan, acquisition = engines(
            p1_fixture(),
            provenance="EXPLICIT",
            scope="GLOBAL",
            strongest="TECHNOLOGY",
        )
        self.assertEqual(plan["action"], pl.COLLECT_TECHNOLOGY_EVIDENCE)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.TECHNOLOGY_EVIDENCE_REVIEW)
        self.assertEqual(acquisition["acquisition_rank"], 7)
        self.assertEqual(acquisition["evidence_target"],
                         eap.TARGET_TECHNOLOGY)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_TECHNOLOGY)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_TECHNOLOGY_ESTABLISHED)

    def test_11_manual_review_maps_to_manual_research(self):
        plan, acquisition = self._acquisition()
        self.assertEqual(plan["action"], pl.MANUAL_REVIEW)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.MANUAL_RESEARCH)
        self.assertEqual(acquisition["acquisition_rank"], 8)
        self.assertEqual(acquisition["evidence_target"],
                         eap.TARGET_EXISTING_EVIDENCE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_MANUAL_COMPLETED)
        self.assertIn(eap.REASON_SOURCE_ACTION,
                      acquisition["reason_codes"])

    def test_11_supporting_context_gap_still_maps_by_action(self):
        _, ha_result, plan, acquisition = engines(
            dict(
                evidence_quality=quality(
                    "MEDIUM", strength="SUPPORTING",
                    gaps=["version: no observed version available"],
                ),
                strongest_match_type="COMPONENT",
                strongest_confidence="MEDIUM",
                asset_match_state="SUPPORTED",
                matched_component="CKEditor",
                evidence_provenance="INFERRED",
                support_scope="GLOBAL",
                cve_id=CVE,
            ),
            provenance="INFERRED",
            scope="GLOBAL",
        )
        self.assertEqual(ha_result["actionability"],
                         ha.SUPPORTING_CONTEXT)
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertEqual(acquisition["acquisition_method"],
                         eap.VERSION_LOOKUP)


# ---------------------------------------------------------------------------
# 12–14: missing, unknown and conflicting action plans
# ---------------------------------------------------------------------------


class TestMalformedPlans(unittest.TestCase):
    def _state(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = ha.evaluate_hunt_actionability(
            hp_result, evidence_provenance="EXPLICIT",
            support_scope="GLOBAL",
        )
        return hp_result, ha_result

    def test_12_missing_plan_maps_to_none(self):
        hp_result, ha_result = self._state()
        for missing in (None, {}, "not-a-plan", []):
            acquisition = eap.plan_evidence_acquisition(
                hp_result, ha_result, missing
            )
            self.assertEqual(acquisition["acquisition_method"],
                             eap.NO_ACQUISITION)
            self.assertEqual(acquisition["evidence_target"],
                             eap.TARGET_NONE)
            self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
            self.assertEqual(acquisition["completion_condition"],
                             eap.CONDITION_REQUIRES_ACTION_PLAN)
            self.assertEqual(acquisition["reason_codes"],
                             [eap.REASON_ACTION_PLAN_MISSING])
            self.assertEqual(acquisition["confidence"],
                             eap.CONFIDENCE_LOW)
            self.assertEqual(acquisition["estimated_effort"],
                             eap.EFFORT_UNKNOWN)

    def test_12_missing_plan_with_immediate_state_is_none(self):
        hp_result = hp.evaluate_hunt_priority(**immediate_fixture())
        ha_result = ha.evaluate_hunt_actionability(
            hp_result, evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        acquisition = eap.plan_evidence_acquisition(
            hp_result, ha_result, None
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_ACTION_PLAN_MISSING])

    def test_13_unknown_action_maps_to_none(self):
        hp_result, ha_result = self._state()
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            ha_result,
            {"action": "DEPLOY_EXPLOIT", "evidence_gap": "GAP_VERSION"},
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_NONE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_REQUIRES_ACTION_PLAN)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_UNKNOWN_ACTION])
        self.assertEqual(acquisition["confidence"],
                         eap.CONFIDENCE_LOW)

    def test_13_blank_action_maps_to_none(self):
        hp_result, ha_result = self._state()
        acquisition = eap.plan_evidence_acquisition(
            hp_result, ha_result, {"action": "   "}
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_ACTION_PLAN_MISSING])

    def test_14_action_gap_mismatch_is_defensive_conflict(self):
        hp_result, ha_result = self._state()
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            ha_result,
            {
                "action": pl.VERIFY_VERSION,
                "evidence_gap": pl.GAP_PATH,
                "confidence": "HIGH",
                "estimated_effort": "MEDIUM",
                "action_order_key": [1, 1, -60],
            },
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["evidence_target"], eap.TARGET_NONE)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_REQUIRES_ACTION_PLAN)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_ACTION_PLAN_CONFLICT])
        self.assertEqual(acquisition["confidence"],
                         eap.CONFIDENCE_LOW)
        self.assertEqual(acquisition["estimated_effort"],
                         eap.EFFORT_UNKNOWN)

    def test_14_mismatch_is_never_reinterpreted(self):
        hp_result, ha_result = self._state()
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            ha_result,
            {
                "action": pl.COLLECT_HTTP_EVIDENCE,
                "evidence_gap": pl.GAP_TECHNOLOGY,
            },
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertIn(eap.REASON_ACTION_PLAN_CONFLICT,
                      acquisition["reason_codes"])
        self.assertNotIn(pl.GAP_TECHNOLOGY, acquisition["reason_codes"])
        self.assertNotIn(pl.GAP_HTTP, acquisition["reason_codes"])

    def test_14_manual_review_with_gap_is_conflict(self):
        hp_result, ha_result = self._state()
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            ha_result,
            {"action": pl.MANUAL_REVIEW, "evidence_gap": pl.GAP_PATH},
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_ACTION_PLAN_CONFLICT])

    def test_14_missing_gap_field_uses_action_pair(self):
        hp_result, ha_result = self._state()
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            ha_result,
            {"action": pl.VERIFY_VERSION},
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.VERSION_LOOKUP)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_VERSION)


# ---------------------------------------------------------------------------
# 15–16: terminal precedence
# ---------------------------------------------------------------------------


class TestTerminalPrecedence(unittest.TestCase):
    def test_15_blocker_overrides_every_gap(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            )
        )
        self.assertTrue(hp_result["blocked"])
        forged_state = {"actionability": ha.STRONG_MANUAL_REVIEW}
        forged_plan = {
            "action": pl.VERIFY_VERSION,
            "evidence_gap": pl.GAP_VERSION,
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result, forged_state, forged_plan
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_BLOCKERS_RESOLVED)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_BLOCKED])

    def test_15_blocked_state_overrides_every_gap(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        blocked_state = {"actionability": ha.BLOCKED}
        forged_plan = {
            "action": pl.COLLECT_TECHNOLOGY_EVIDENCE,
            "evidence_gap": pl.GAP_TECHNOLOGY,
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result, blocked_state, forged_plan
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_BLOCKED])

    def test_16_deferred_overrides_every_gap(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        deferred_state = {"actionability": ha.LOW_VALUE_DEFERRED}
        forged_plan = {
            "action": pl.VERIFY_PATH,
            "evidence_gap": pl.GAP_PATH,
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result, deferred_state, forged_plan
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(acquisition["completion_condition"],
                         eap.CONDITION_REACTIVATE)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_DEFERRED])

    def test_16_defer_action_is_terminal_for_planning(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        active_state = {"actionability": ha.STRONG_MANUAL_REVIEW}
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            active_state,
            {"action": pl.DEFER, "evidence_gap": pl.GAP_NONE},
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_DEFERRED])

    def test_16_resolve_blockers_action_is_terminal_for_planning(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        active_state = {"actionability": ha.STRONG_MANUAL_REVIEW}
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            active_state,
            {"action": pl.RESOLVE_BLOCKERS, "evidence_gap": pl.GAP_NONE},
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_SOURCE_BLOCKED])


# ---------------------------------------------------------------------------
# 17: R31.12 is the only gap selector
# ---------------------------------------------------------------------------


class TestGapAuthority(unittest.TestCase):
    def test_17_r3112_selected_gap_is_not_recomputed(self):
        # The R31.10 projection carries an explicit version-gap signal, but
        # R31.12 (forged here) selected a path gap. The planner must follow
        # R31.12 and must not re-derive the version gap.
        hp_result = hp.evaluate_hunt_priority(
            **p1_fixture(gaps=["version: no observed version available"])
        )
        active_state = {"actionability": ha.STRONG_MANUAL_REVIEW}
        forged_plan = {
            "action": pl.VERIFY_PATH,
            "evidence_gap": pl.GAP_PATH,
            "confidence": "HIGH",
            "estimated_effort": "LOW",
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result, active_state, forged_plan
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.PATH_EVIDENCE_REVIEW)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_PATH)
        self.assertNotIn(pl.GAP_VERSION, acquisition["reason_codes"])

    def test_17_technology_hint_never_overrides_r3112(self):
        # An explicit TECHNOLOGY strongest-match hint (which R31.12 would use)
        # cannot change a plan whose R31.12 action selected version.
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        active_state = {"actionability": ha.STRONG_MANUAL_REVIEW}
        plan = {
            "action": pl.VERIFY_VERSION,
            "evidence_gap": pl.GAP_VERSION,
            "confidence": "HIGH",
            "estimated_effort": "MEDIUM",
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result,
            active_state,
            plan,
            strongest_match_type="TECHNOLOGY",
            support_scope="GLOBAL",
            evidence_provenance="EXPLICIT",
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.VERSION_LOOKUP)
        self.assertEqual(acquisition["evidence_gap"], pl.GAP_VERSION)

    def test_17_module_never_calls_upstream_engines(self):
        source = inspect.getsource(eap)
        for forbidden in (
            "evaluate_hunt_priority(",
            "evaluate_hunt_actionability(",
            "plan_hunt_action(",
            "_detect_gaps",
        ):
            self.assertNotIn(forbidden, source)


# ---------------------------------------------------------------------------
# 18–19: determinism and ordering
# ---------------------------------------------------------------------------


class TestDeterminismAndOrdering(unittest.TestCase):
    def test_18_repeated_output_is_byte_identical(self):
        _, _, _, acquisition = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        first = json.dumps(acquisition, sort_keys=True)
        second = json.dumps(acquisition, sort_keys=True)
        self.assertEqual(first, second)

    def test_18_repeated_call_returns_equal_dict(self):
        hp_result, ha_result, plan, first = engines(
            p1_fixture(gaps=["path: no matching observed path evidence"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        second = eap.plan_evidence_acquisition(
            hp_result, ha_result, plan,
            evidence_provenance="EXPLICIT", support_scope="GLOBAL",
        )
        self.assertEqual(first, second)

    def test_19_acquisition_order_key_starts_with_rank(self):
        for fixture, provenance, scope in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED"),
            (p1_fixture(), "EXPLICIT", "GLOBAL"),
            (p3_fixture(), "INFERRED", "GLOBAL"),
        ):
            _, _, _, acquisition = engines(
                fixture, provenance=provenance, scope=scope
            )
            self.assertEqual(
                acquisition["acquisition_order_key"][0],
                acquisition["acquisition_rank"],
            )

    def test_19_acquisition_order_key_preserves_r3112_order(self):
        _, _, plan, acquisition = engines(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(
            acquisition["acquisition_order_key"][1:],
            plan["action_order_key"],
        )
        self.assertEqual(
            acquisition["acquisition_order_key"],
            [acquisition["acquisition_rank"]]
            + plan["action_order_key"],
        )

    def test_19_stable_sorting_between_candidates(self):
        explicit = dict(provenance="EXPLICIT", scope="GLOBAL")
        _, _, _, immediate = engines(
            immediate_fixture(), provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        _, _, _, version = engines(
            p1_fixture(gaps=["version: no observed version available"]),
            **explicit,
        )
        _, _, _, deferred = engines(
            p3_fixture(), provenance="INFERRED", scope="GLOBAL"
        )
        ordered = sorted(
            [("immediate", immediate), ("version", version),
             ("deferred", deferred)],
            key=lambda pair: pair[1]["acquisition_order_key"],
        )
        self.assertEqual(
            [label for label, _ in ordered],
            ["immediate", "version", "deferred"],
        )
        self.assertLess(immediate["acquisition_order_key"],
                        version["acquisition_order_key"])


# ---------------------------------------------------------------------------
# 20–22: no mutation of upstream projections
# ---------------------------------------------------------------------------


class TestNoMutation(unittest.TestCase):
    def setUp(self):
        self.hp_result, self.ha_result, self.plan, _ = engines(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )

    def test_20_no_mutation_of_hunt_priority(self):
        snapshot = copy.deepcopy(self.hp_result)
        eap.plan_evidence_acquisition(
            self.hp_result, self.ha_result, self.plan
        )
        self.assertEqual(self.hp_result, snapshot)

    def test_21_no_mutation_of_hunt_actionability(self):
        snapshot = copy.deepcopy(self.ha_result)
        eap.plan_evidence_acquisition(
            self.hp_result, self.ha_result, self.plan
        )
        self.assertEqual(self.ha_result, snapshot)

    def test_22_no_mutation_of_hunt_action_plan(self):
        snapshot = copy.deepcopy(self.plan)
        eap.plan_evidence_acquisition(
            self.hp_result, self.ha_result, self.plan
        )
        self.assertEqual(self.plan, snapshot)


# ---------------------------------------------------------------------------
# 23–27: regressions
# ---------------------------------------------------------------------------


class TestR3110Regression(unittest.TestCase):
    def test_23_exact_priority_and_score_snapshot(self):
        expectations = (
            (immediate_fixture(), "P0", 100, False),
            (p1_fixture(), "P1", 60, False),
            (
                dict(
                    evidence_quality=quality("MEDIUM",
                                             strength="SUPPORTING"),
                    strongest_match_type="COMPONENT",
                    strongest_confidence="MEDIUM",
                    asset_match_state="SUPPORTED",
                    matched_component="CKEditor",
                    evidence_provenance="INFERRED",
                    support_scope="GLOBAL",
                    cve_id=CVE,
                ),
                "P2",
                48,
                False,
            ),
            (p3_fixture(), "P3", 28, False),
            (
                immediate_fixture(
                    version_state="NO_MATCH",
                    version_association_state="VERSION_OBSERVED_NO_MATCH",
                ),
                "DEFER",
                0,
                True,
            ),
        )
        for kwargs, priority, score, blocked in expectations:
            result = hp.evaluate_hunt_priority(**kwargs)
            self.assertEqual(result["priority"], priority)
            self.assertEqual(result["hunt_score"], score)
            self.assertEqual(result["blocked"], blocked)

    def test_23_acquisition_planner_does_not_change_r3110(self):
        self.assertEqual(hp.HUNT_PRIORITY_RULE_VERSION, "r31-10")
        self.assertEqual(hp.RULE_VERSION, "r31-10")
        for fixture, provenance, scope in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED"),
            (p1_fixture(), "EXPLICIT", "GLOBAL"),
            (p3_fixture(), "INFERRED", "GLOBAL"),
        ):
            first = hp.evaluate_hunt_priority(**fixture)
            snapshot = copy.deepcopy(first)
            ha_result = ha.evaluate_hunt_actionability(
                first,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            plan = pl.plan_hunt_action(
                first, ha_result,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            eap.plan_evidence_acquisition(first, ha_result, plan)
            self.assertEqual(first, snapshot)
            second = hp.evaluate_hunt_priority(**fixture)
            self.assertEqual(
                json.dumps(first, sort_keys=True),
                json.dumps(second, sort_keys=True),
            )


class TestR3111Regression(unittest.TestCase):
    def test_24_rule_version_and_states_unchanged(self):
        self.assertEqual(ha.HUNT_ACTIONABILITY_RULE_VERSION, "r31-11")
        self.assertEqual(ha.RULE_VERSION, "r31-11")
        expectations = (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED",
             ha.IMMEDIATE_VERIFICATION),
            (p1_fixture(), "EXPLICIT", "GLOBAL",
             ha.STRONG_MANUAL_REVIEW),
            (
                dict(
                    evidence_quality=quality("MEDIUM",
                                             strength="SUPPORTING"),
                    strongest_match_type="COMPONENT",
                    strongest_confidence="MEDIUM",
                    asset_match_state="SUPPORTED",
                    matched_component="CKEditor",
                    evidence_provenance="INFERRED",
                    support_scope="GLOBAL",
                    cve_id=CVE,
                ),
                "INFERRED", "GLOBAL", ha.SUPPORTING_CONTEXT,
            ),
            (p3_fixture(), "INFERRED", "GLOBAL",
             ha.LOW_VALUE_DEFERRED),
            (
                immediate_fixture(
                    version_state="NO_MATCH",
                    version_association_state="VERSION_OBSERVED_NO_MATCH",
                ),
                "EXPLICIT", "COMPONENT_SCOPED", ha.BLOCKED,
            ),
        )
        for fixture, provenance, scope, expected in expectations:
            hp_result = hp.evaluate_hunt_priority(**fixture)
            before = ha.evaluate_hunt_actionability(
                hp_result,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            self.assertEqual(before["actionability"], expected)
            snapshot = copy.deepcopy(before)
            plan = pl.plan_hunt_action(
                hp_result, before,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            eap.plan_evidence_acquisition(hp_result, before, plan)
            self.assertEqual(before, snapshot)
            after = ha.evaluate_hunt_actionability(
                hp_result,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            self.assertEqual(
                json.dumps(before, sort_keys=True),
                json.dumps(after, sort_keys=True),
            )


class TestR3112Regression(unittest.TestCase):
    def test_25_rule_version_and_actions_unchanged(self):
        self.assertEqual(pl.HUNT_ACTION_PLANNER_RULE_VERSION, "r31-12")
        self.assertEqual(pl.RULE_VERSION, "r31-12")
        expectations = (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED", None,
             pl.VERIFY_EXISTING_EVIDENCE),
            (p1_fixture(gaps=("version: no observed version available",)),
             "EXPLICIT", "GLOBAL", None, pl.VERIFY_VERSION),
            (p1_fixture(), "EXPLICIT", "GLOBAL", None, pl.MANUAL_REVIEW),
            (p3_fixture(), "INFERRED", "GLOBAL", None, pl.DEFER),
            (
                immediate_fixture(
                    version_state="NO_MATCH",
                    version_association_state="VERSION_OBSERVED_NO_MATCH",
                ),
                "EXPLICIT", "COMPONENT_SCOPED", None,
                pl.RESOLVE_BLOCKERS,
            ),
        )
        for fixture, provenance, scope, strongest, expected in expectations:
            hp_result = hp.evaluate_hunt_priority(**fixture)
            ha_result = ha.evaluate_hunt_actionability(
                hp_result,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            plan = pl.plan_hunt_action(
                hp_result, ha_result,
                evidence_provenance=provenance,
                support_scope=scope,
                strongest_match_type=strongest,
            )
            self.assertEqual(plan["action"], expected)
            snapshot = copy.deepcopy(plan)
            eap.plan_evidence_acquisition(hp_result, ha_result, plan)
            self.assertEqual(plan, snapshot)

    def test_25_acquisition_plan_sources_match_r3112(self):
        hp_result, ha_result, plan, acquisition = engines(
            p1_fixture(gaps=["path: no matching observed path evidence"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(acquisition["source_action"], plan["action"])
        self.assertEqual(acquisition["source_actionability"],
                         ha_result["actionability"])
        self.assertEqual(acquisition["source_priority"],
                         hp_result["priority"])
        self.assertEqual(acquisition["source_hunt_score"],
                         hp_result["hunt_score"])


def _action(**over):
    base = {
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
    base.update(over)
    return base


class TestR29Regression(unittest.TestCase):
    def _snapshot(self):
        actions = [
            _action(),
            _action(
                lead_id="rl-" + "b" * 16,
                cve_id="CVE-2026-0001",
                opportunity_class="GOOD_OPPORTUNITY",
                confidence="MEDIUM",
                money_score=55,
            ),
            _action(
                lead_id="rl-" + "c" * 16,
                cve_id="CVE-2026-0002",
                current_status="BLOCKED",
                opportunity_class="BLOCKED",
                confidence="LOW",
                money_score=30,
            ),
        ]
        outcomes = SimpleNamespace(accepted=0, duplicate=0, wasted_time=0,
                                   rejected=0, terminal_attempts=0,
                                   attempts=0, latest_outcome=None,
                                   data_quality="NONE")
        sessions = SimpleNamespace(session_status="NONE",
                                   in_progress_sessions=0,
                                   actual_time=0,
                                   average_actual_minutes=0,
                                   total_sessions=0,
                                   planned_time=0,
                                   latest_session_status="NONE")
        items = [hq.build_hunt_item(action, outcomes, sessions)
                 for action in actions]
        ranked = hq.rank_hunt_queue(items)
        return {
            "items": [hunt_item_projection(item) for item in ranked],
            "summary": hq.build_hunt_summary(items),
            "classifications": [
                hq.classify_hunt_priority(action, outcomes, sessions)
                for action in actions
            ],
        }

    def test_26_hunt_queue_unchanged(self):
        before = self._snapshot()
        for fixture, provenance, scope in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED"),
            (p1_fixture(), "EXPLICIT", "GLOBAL"),
            (p3_fixture(), "INFERRED", "GLOBAL"),
        ):
            engines(fixture, provenance=provenance, scope=scope)
        after = self._snapshot()
        self.assertEqual(
            json.dumps(before, sort_keys=True),
            json.dumps(after, sort_keys=True),
        )

    def test_26_r29_items_have_no_acquisition_field(self):
        projection = self._snapshot()["items"][0]
        self.assertNotIn("evidence_acquisition_plan", projection)
        self.assertNotIn("evidence_acquisition_plan_rule_version", projection)
        self.assertEqual(HUNT_RULE_VERSION, "r29-1")


# ---------------------------------------------------------------------------
# 28–34: privacy, bounds, JSON, plan-only, vocabulary
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


class TestPrivacyAndBounds(unittest.TestCase):
    def test_28_privacy_no_secrets_in_output(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = {"actionability": "STRONG_MANUAL_REVIEW"}
        plan = {
            "action": pl.VERIFY_VERSION,
            "evidence_gap": pl.GAP_VERSION,
            "confidence": "HIGH",
            "estimated_effort": "MEDIUM",
            "action_order_key": [
                "https://user:hunter2@example.test/x?token=SECRET",
                "Authorization: Bearer abc123",
            ],
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result, ha_result, plan
        )
        blob = json.dumps(acquisition)
        for token in ("hunter2", "SECRET", "abc123", "Bearer abc123"):
            self.assertNotIn(token, blob)

    def test_28_privacy_unknown_action_is_redacted(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = {"actionability": "STRONG_MANUAL_REVIEW"}
        plan = {"action": "token=SECRETVALUE"}
        acquisition = eap.plan_evidence_acquisition(
            hp_result, ha_result, plan
        )
        blob = json.dumps(acquisition)
        self.assertNotIn("SECRETVALUE", blob)
        self.assertIn("[REDACTED]", blob)
        self.assertEqual(acquisition["reason_codes"],
                         [eap.REASON_UNKNOWN_ACTION])

    def test_28_privacy_secret_source_priority_is_redacted(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = {"actionability": "STRONG_MANUAL_REVIEW"}
        plan = {
            "action": pl.MANUAL_REVIEW,
            "evidence_gap": pl.GAP_NONE,
            "confidence": "LOW",
            "estimated_effort": "HIGH",
        }
        hp_result["priority"] = "password=hunter2"
        acquisition = eap.plan_evidence_acquisition(
            hp_result, ha_result, plan
        )
        self.assertNotIn("hunter2", json.dumps(acquisition))

    def test_29_bounded_output(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = {
            "actionability": ha.STRONG_MANUAL_REVIEW,
            "action_order_key": list(range(64)),
        }
        plan = {
            "action": pl.VERIFY_VERSION,
            "evidence_gap": pl.GAP_VERSION,
            "confidence": "HIGH",
            "estimated_effort": "MEDIUM",
            "action_order_key": list(range(64)),
        }
        acquisition = eap.plan_evidence_acquisition(
            hp_result, ha_result, plan
        )
        self.assertLessEqual(len(acquisition["reason_codes"]),
                             eap.MAX_REASON_CODES)
        self.assertLessEqual(len(acquisition["acquisition_order_key"]),
                             eap.MAX_ORDER_KEY + 1)
        json.dumps(acquisition)

    def test_30_json_serializable(self):
        _, _, _, acquisition = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertIsInstance(json.loads(json.dumps(acquisition)), dict)

    def test_31_research_only_always_true(self):
        cases = []
        for fixture, provenance, scope in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED"),
            (p1_fixture(), "EXPLICIT", "GLOBAL"),
            (p3_fixture(), "INFERRED", "GLOBAL"),
            (
                immediate_fixture(
                    version_state="NO_MATCH",
                    version_association_state="VERSION_OBSERVED_NO_MATCH",
                ),
                "EXPLICIT", "COMPONENT_SCOPED",
            ),
        ):
            cases.append(engines(
                fixture, provenance=provenance, scope=scope
            )[3])
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        active = {"actionability": ha.STRONG_MANUAL_REVIEW}
        cases.append(eap.plan_evidence_acquisition(hp_result, active, None))
        cases.append(eap.plan_evidence_acquisition(
            hp_result, active, {"action": "NOPE"}
        ))
        cases.append(eap.plan_evidence_acquisition(
            hp_result, active,
            {"action": pl.VERIFY_VERSION, "evidence_gap": pl.GAP_PATH},
        ))
        for acquisition in cases:
            self.assertIs(acquisition["research_only"], True)

    def test_32_no_operational_attack_content(self):
        outputs = []
        for fixture, provenance, scope, strongest in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED", None),
            (p1_fixture(), "EXPLICIT", "GLOBAL", None),
            (p1_fixture(), "EXPLICIT", "GLOBAL", "TECHNOLOGY"),
            (p3_fixture(), "INFERRED", "GLOBAL", None),
        ):
            outputs.append(engines(
                fixture, provenance=provenance, scope=scope,
                strongest=strongest,
            )[3])
        blob = json.dumps(outputs).lower()
        for marker in FORBIDDEN_OPERATIONAL_MARKERS:
            self.assertNotIn(marker, blob)

    def test_33_exact_rule_version(self):
        self.assertEqual(
            eap.EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION, "r31-13"
        )
        self.assertEqual(eap.RULE_VERSION, "r31-13")
        _, _, _, acquisition = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(acquisition["rule_version"], "r31-13")

    def test_34_closed_vocabulary_enforcement(self):
        supporting = dict(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
            cve_id=CVE,
        )
        for fixture, provenance, scope, strongest in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED", None),
            (p1_fixture(), "EXPLICIT", "GLOBAL", None),
            (p1_fixture(), "EXPLICIT", "GLOBAL", "TECHNOLOGY"),
            (supporting, "INFERRED", "GLOBAL", None),
            (p3_fixture(), "INFERRED", "GLOBAL", None),
        ):
            _, _, _, acquisition = engines(
                fixture, provenance=provenance, scope=scope,
                strongest=strongest,
            )
            self.assertIn(acquisition["acquisition_method"],
                          eap.ACQUISITION_METHODS)
            self.assertEqual(
                acquisition["acquisition_rank"],
                eap.ACQUISITION_RANKS[acquisition["acquisition_method"]],
            )
            self.assertIn(acquisition["evidence_target"],
                          eap.EVIDENCE_TARGETS)
            self.assertIn(acquisition["evidence_gap"],
                          pl.EVIDENCE_GAPS)
            self.assertIn(acquisition["completion_condition"],
                          eap.COMPLETION_CONDITIONS)
            self.assertIn(acquisition["estimated_effort"],
                          eap.ESTIMATED_EFFORTS)
            self.assertIn(acquisition["confidence"],
                          eap.ACQUISITION_CONFIDENCES)
            for code in acquisition["reason_codes"]:
                self.assertIn(code, eap.REASON_CODES)

    def test_34_reason_code_vocabulary_is_closed(self):
        expected = {
            "SOURCE_BLOCKED", "SOURCE_DEFERRED", "SOURCE_IMMEDIATE",
            "SOURCE_ACTION", "NO_ACQUISITION_REQUIRED",
            "ACTION_PLAN_CONFLICT", "ACTION_PLAN_MISSING", "UNKNOWN_ACTION",
            "GAP_VERSION", "GAP_COMPONENT_IDENTITY", "GAP_SCOPE",
            "GAP_PATH", "GAP_PARAMETER", "GAP_HTTP", "GAP_TECHNOLOGY",
        }
        self.assertEqual(set(eap.REASON_CODES), expected)

    def test_34_gap_vocabulary_not_duplicated(self):
        self.assertEqual(pl.EVIDENCE_GAPS, (
            "GAP_VERSION", "GAP_COMPONENT_IDENTITY", "GAP_SCOPE",
            "GAP_PATH", "GAP_PARAMETER", "GAP_HTTP", "GAP_TECHNOLOGY",
            "GAP_NONE",
        ))
        for gap in pl.EVIDENCE_GAPS:
            if gap != "GAP_NONE":
                self.assertIn(gap, eap.REASON_CODES)


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
            item["evidence_acquisition_plan_rule_version"], "r31-13"
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["rule_version"], "r31-13"
        )
        self.assertIn(
            item["evidence_acquisition_plan"]["acquisition_method"],
            eap.ACQUISITION_METHODS,
        )
        # R31.10/R31.11/R31.12 fields still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(item["hunt_actionability_rule_version"], "r31-11")
        self.assertEqual(item["hunt_action_plan_rule_version"], "r31-12")
        self.assertEqual(
            item["evidence_acquisition_plan"]["source_action"],
            item["hunt_action_plan"]["action"],
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["source_actionability"],
            item["hunt_actionability"]["actionability"],
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["source_priority"],
            item["hunt_priority"]["priority"],
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["source_hunt_score"],
            item["hunt_priority"]["hunt_score"],
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["acquisition_order_key"][1:],
            item["hunt_action_plan"]["action_order_key"],
        )

    def test_backend_immediate_plan_existing_evidence_review(self):
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
        self.assertEqual(item["hunt_actionability"]["actionability"],
                         ha.IMMEDIATE_VERIFICATION)
        self.assertEqual(item["hunt_action_plan"]["action"],
                         pl.VERIFY_EXISTING_EVIDENCE)
        self.assertEqual(
            item["evidence_acquisition_plan"]["acquisition_method"],
            eap.EXISTING_EVIDENCE_REVIEW,
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["evidence_target"],
            eap.TARGET_EXISTING_EVIDENCE,
        )
        # Existing projections are not altered by acquisition planning.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)
        self.assertEqual(
            item["hunt_actionability"]["reason_codes"],
            ["PRIORITY_P0", "VERIFICATION_READY"],
        )

    def test_backend_blocked_plan_none_acquisition(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.DEFER)
        self.assertEqual(item["hunt_actionability"]["actionability"],
                         ha.BLOCKED)
        self.assertEqual(item["hunt_action_plan"]["action"],
                         pl.RESOLVE_BLOCKERS)
        self.assertEqual(
            item["evidence_acquisition_plan"]["acquisition_method"],
            eap.NO_ACQUISITION,
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["completion_condition"],
            eap.CONDITION_BLOCKERS_RESOLVED,
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
            "evidence_quality",
            "version_normalization",
            "path_parameter_relevance",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_acquisition_plan"],
            item["hunt_action_plan"],
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
