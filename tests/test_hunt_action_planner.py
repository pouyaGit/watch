"""tests/test_hunt_action_planner.py — Stage R31.12 tests.

Deterministic, offline tests for the hunt action planner:

- terminal handling (BLOCKED / LOW_VALUE / IMMEDIATE)
- explicit evidence-gap selection and precedence (version, identity, scope,
  path, parameter, HTTP, technology)
- no-gap fallback to MANUAL_REVIEW
- inferred evidence can never select explicit verification
- blockers cannot be overridden
- stable repeated output and stable action ordering
- no mutation of the R31.10/R31.11 projections
- regression: R31.10 priority/score, R31.11 actionability, R29 hunt queue
- bounded, privacy-safe, JSON-serializable output
- hermetic backend integration (no live Mongo)

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence.
"""
import copy
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import asset_cve_matching as acm_engine
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


def p2_fixture(**over):
    base = dict(
        evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
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
    """Build R31.10, R31.11 and R31.12 outputs with the real engines."""

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
    return hp_result, ha_result, plan


# ---------------------------------------------------------------------------
# 1–3: terminal handling
# ---------------------------------------------------------------------------


class TestTerminalActions(unittest.TestCase):
    def test_1_blocked_maps_to_resolve_blockers(self):
        _, ha_result, plan = engines(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(ha_result["actionability"], ha.BLOCKED)
        self.assertEqual(plan["action"], pl.RESOLVE_BLOCKERS)
        self.assertEqual(plan["action_rank"], pl.ACTION_RANKS[
            pl.RESOLVE_BLOCKERS])
        self.assertEqual(plan["reason_codes"], [pl.REASON_SOURCE_BLOCKED])
        self.assertEqual(plan["evidence_gap"], pl.GAP_NONE)
        self.assertEqual(plan["confidence"], pl.CONFIDENCE_HIGH)

    def test_2_low_value_maps_to_defer(self):
        _, ha_result, plan = engines(
            p3_fixture(), provenance="INFERRED", scope="GLOBAL"
        )
        self.assertEqual(ha_result["actionability"],
                         ha.LOW_VALUE_DEFERRED)
        self.assertEqual(plan["action"], pl.DEFER)
        self.assertEqual(plan["reason_codes"],
                         [pl.REASON_SOURCE_LOW_VALUE])
        self.assertEqual(plan["evidence_gap"], pl.GAP_NONE)

    def test_3_immediate_maps_to_verify_existing_evidence(self):
        _, ha_result, plan = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(ha_result["actionability"],
                         ha.IMMEDIATE_VERIFICATION)
        self.assertEqual(plan["action"], pl.VERIFY_EXISTING_EVIDENCE)
        self.assertEqual(plan["action_rank"], 0)
        self.assertEqual(plan["estimated_effort"], pl.EFFORT_LOW)
        self.assertEqual(plan["confidence"], pl.CONFIDENCE_HIGH)
        self.assertEqual(plan["evidence_gap"], pl.GAP_NONE)

    def test_3_missing_actionability_defers(self):
        plan = pl.plan_hunt_action(
            hp.evaluate_hunt_priority(**p1_fixture())
        )
        self.assertEqual(plan["action"], pl.DEFER)
        self.assertIn(pl.REASON_MISSING_ACTIONABILITY,
                      plan["reason_codes"])
        self.assertEqual(plan["confidence"], pl.CONFIDENCE_LOW)

    def test_3_unrecognized_actionability_defers(self):
        plan = pl.plan_hunt_action(
            hp.evaluate_hunt_priority(**p1_fixture()),
            {"actionability": "NOT_A_STATE"},
        )
        self.assertEqual(plan["action"], pl.DEFER)
        self.assertIn(pl.REASON_UNRECOGNIZED_ACTIONABILITY,
                      plan["reason_codes"])


# ---------------------------------------------------------------------------
# 4–11: explicit evidence-gap selection (P1 / STRONG_MANUAL_REVIEW)
# ---------------------------------------------------------------------------


class TestExplicitGaps(unittest.TestCase):
    def _plan(self, *gaps, **over):
        _, _, plan = engines(
            p1_fixture(gaps=gaps, **over),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        return plan

    def test_4_version_gap(self):
        plan = self._plan("version: no observed version available")
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertEqual(plan["evidence_gap"], pl.GAP_VERSION)
        self.assertEqual(plan["estimated_effort"], pl.EFFORT_MEDIUM)
        self.assertEqual(plan["confidence"], pl.CONFIDENCE_HIGH)

    def test_4_version_gap_via_unresolved_code(self):
        plan = self._plan(
            version_normalization={"rows": [], "observed_versions": [{}]}
        )
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertEqual(plan["evidence_gap"], pl.GAP_VERSION)

    def test_4_version_gap_via_blocker_code(self):
        plan = self._plan(remaining_blockers=["version_unknown"])
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertEqual(plan["evidence_gap"], pl.GAP_VERSION)

    def test_5_component_identity_gap(self):
        plan = self._plan(
            "component: no observed component/plugin identity"
        )
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)
        self.assertEqual(plan["evidence_gap"],
                         pl.GAP_COMPONENT_IDENTITY)

    def test_5_component_identity_gap_via_identity_line(self):
        plan = self._plan("identity: no resolved CVE component identity")
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)

    def test_5_component_identity_gap_via_blocker_code(self):
        plan = self._plan(remaining_blockers=["plugin_not_observed"])
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)

    def test_6_scope_gap(self):
        plan = self._plan("scope: no component-scoped support available")
        self.assertEqual(plan["action"], pl.VERIFY_SCOPE)
        self.assertEqual(plan["evidence_gap"], pl.GAP_SCOPE)

    def test_6_scope_gap_via_provenance_line(self):
        plan = self._plan("provenance: component evidence is inferred only")
        self.assertEqual(plan["action"], pl.VERIFY_SCOPE)

    def test_6_scope_gap_via_inferred_unscoped_hint(self):
        _, _, plan = engines(
            p1_fixture(evidence_provenance="INFERRED"),
            provenance="INFERRED",
            scope="GLOBAL",
        )
        self.assertEqual(plan["action"], pl.VERIFY_SCOPE)
        self.assertEqual(plan["evidence_gap"], pl.GAP_SCOPE)

    def test_7_path_gap(self):
        plan = self._plan("path: no matching observed path evidence")
        self.assertEqual(plan["action"], pl.VERIFY_PATH)
        self.assertEqual(plan["evidence_gap"], pl.GAP_PATH)
        self.assertEqual(plan["estimated_effort"], pl.EFFORT_LOW)

    def test_8_parameter_gap(self):
        plan = self._plan(
            "parameter: no matching observed parameter evidence"
        )
        self.assertEqual(plan["action"], pl.VERIFY_PARAMETER)
        self.assertEqual(plan["evidence_gap"], pl.GAP_PARAMETER)

    def test_8_parameter_gap_via_blocker_code(self):
        plan = self._plan(remaining_blockers=["parameter_unknown"])
        self.assertEqual(plan["action"], pl.VERIFY_PARAMETER)

    def test_9_http_evidence_gap(self):
        plan = self._plan("method: no structured method evidence")
        self.assertEqual(plan["action"], pl.COLLECT_HTTP_EVIDENCE)
        self.assertEqual(plan["evidence_gap"], pl.GAP_HTTP)
        self.assertEqual(plan["estimated_effort"], pl.EFFORT_MEDIUM)

    def test_10_technology_gap_via_strongest_match_type(self):
        _, _, plan = engines(
            p1_fixture(),
            provenance="EXPLICIT",
            scope="GLOBAL",
            strongest="TECHNOLOGY",
        )
        self.assertEqual(plan["action"], pl.COLLECT_TECHNOLOGY_EVIDENCE)
        self.assertEqual(plan["evidence_gap"], pl.GAP_TECHNOLOGY)

    def test_10_technology_gap_via_blocker_code(self):
        plan = self._plan(remaining_blockers=["generic_technology_only"])
        self.assertEqual(plan["action"], pl.COLLECT_TECHNOLOGY_EVIDENCE)

    def test_11_no_explicit_gap_manual_review(self):
        plan = self._plan()
        self.assertEqual(plan["action"], pl.MANUAL_REVIEW)
        self.assertEqual(plan["evidence_gap"], pl.GAP_NONE)
        self.assertIn(pl.REASON_NO_EXPLICIT_GAP, plan["reason_codes"])
        self.assertEqual(plan["estimated_effort"], pl.EFFORT_HIGH)
        self.assertEqual(plan["confidence"], pl.CONFIDENCE_LOW)

    def test_11_gap_precedence_version_over_path(self):
        plan = self._plan(
            "version: comparison inconclusive",
            "path: no matching observed path evidence",
        )
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertIn(pl.REASON_MULTIPLE_GAPS, plan["reason_codes"])
        self.assertEqual(plan["confidence"], pl.CONFIDENCE_MEDIUM)

    def test_11_gap_precedence_identity_over_parameter(self):
        plan = self._plan(
            "component: no observed component/plugin identity",
            "parameter: no matching observed parameter evidence",
        )
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)

    def test_11_unknown_gap_lines_are_ignored(self):
        plan = self._plan("something: not a known gap prefix")
        self.assertEqual(plan["action"], pl.MANUAL_REVIEW)
        self.assertEqual(plan["evidence_gap"], pl.GAP_NONE)


# ---------------------------------------------------------------------------
# 12: SUPPORTING_CONTEXT deterministic action
# ---------------------------------------------------------------------------


class TestSupportingContext(unittest.TestCase):
    def test_12_supporting_context_with_gap_collects_evidence(self):
        _, ha_result, plan = engines(
            p2_fixture(
                evidence_quality=quality(
                    "MEDIUM", strength="SUPPORTING",
                    gaps=["version: no observed version available"],
                )
            ),
            provenance="INFERRED",
            scope="GLOBAL",
        )
        self.assertEqual(ha_result["actionability"],
                         ha.SUPPORTING_CONTEXT)
        self.assertEqual(plan["action"], pl.VERIFY_VERSION)
        self.assertEqual(plan["reason_codes"][0],
                         pl.REASON_SOURCE_SUPPORTING)

    def test_12_supporting_context_without_gap_manual_review(self):
        supporting = dict(
            evidence_quality=quality(
                "MEDIUM", strength="SUPPORTING",
                conflicts=[{"kind": "scope", "severity": "supporting"}],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            cve_id=CVE,
        )
        _, ha_result, plan = engines(
            supporting, provenance="EXPLICIT", scope="GLOBAL"
        )
        self.assertEqual(ha_result["actionability"],
                         ha.SUPPORTING_CONTEXT)
        self.assertEqual(plan["action"], pl.MANUAL_REVIEW)
        self.assertIn(pl.REASON_NO_EXPLICIT_GAP, plan["reason_codes"])


# ---------------------------------------------------------------------------
# 13–14: inferred evidence and terminal blockers
# ---------------------------------------------------------------------------


class TestDowngradeOnly(unittest.TestCase):
    def test_13_inferred_never_explicit_verification_scoped(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        forged = {
            "actionability": ha.IMMEDIATE_VERIFICATION,
            "action_order_key": [0, 0, -60],
        }
        plan = pl.plan_hunt_action(
            hp_result,
            forged,
            evidence_provenance="INFERRED",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertNotEqual(plan["action"], pl.VERIFY_EXISTING_EVIDENCE)
        self.assertEqual(plan["action"], pl.VERIFY_COMPONENT_IDENTITY)
        self.assertIn(pl.REASON_INFERRED_PROVENANCE,
                      plan["reason_codes"])

    def test_13_inferred_never_explicit_verification_unscoped(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        forged = {
            "actionability": ha.IMMEDIATE_VERIFICATION,
            "action_order_key": [0, 0, -60],
        }
        plan = pl.plan_hunt_action(
            hp_result,
            forged,
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertNotEqual(plan["action"], pl.VERIFY_EXISTING_EVIDENCE)
        self.assertEqual(plan["action"], pl.VERIFY_SCOPE)
        self.assertIn(pl.REASON_INFERRED_PROVENANCE,
                      plan["reason_codes"])

    def test_13_mixed_provenance_is_not_explicit(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        forged = {"actionability": ha.IMMEDIATE_VERIFICATION}
        plan = pl.plan_hunt_action(
            hp_result,
            forged,
            evidence_provenance="MIXED",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertNotEqual(plan["action"], pl.VERIFY_EXISTING_EVIDENCE)
        self.assertIn(pl.REASON_NON_EXPLICIT_PROVENANCE,
                      plan["reason_codes"])

    def test_13_unknown_provenance_is_not_explicit(self):
        hp_result = hp.evaluate_hunt_priority(
            **p1_fixture(
                evidence_provenance="INFERRED",
                support_scope="COMPONENT_SCOPED",
            )
        )
        forged = {"actionability": ha.IMMEDIATE_VERIFICATION}
        plan = pl.plan_hunt_action(hp_result, forged)
        self.assertNotEqual(plan["action"], pl.VERIFY_EXISTING_EVIDENCE)
        self.assertIn(pl.REASON_NON_EXPLICIT_PROVENANCE,
                      plan["reason_codes"])

    def test_14_blocked_never_overridden(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = ha.evaluate_hunt_actionability(hp_result)
        blocked_hp = dict(hp_result)
        blocked_hp["blocked"] = True
        blocked_hp["blocking_reasons"] = [hp.BLOCK_AUTHORITATIVE_CONFLICT]
        plan = pl.plan_hunt_action(
            blocked_hp,
            ha_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
            strongest_match_type="TECHNOLOGY",
        )
        self.assertEqual(plan["action"], pl.RESOLVE_BLOCKERS)
        self.assertEqual(plan["evidence_gap"], pl.GAP_NONE)

    def test_14_blocked_beats_every_explicit_gap(self):
        _, _, plan = engines(
            p2_fixture(
                evidence_quality=quality(
                    "LOW", strength="WEAK",
                    gaps=["version: no observed version available",
                          "path: no matching observed path evidence"],
                ),
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        self.assertEqual(plan["action"], pl.RESOLVE_BLOCKERS)


# ---------------------------------------------------------------------------
# 15–18: determinism, ordering, no mutation
# ---------------------------------------------------------------------------


class TestDeterminismAndOrdering(unittest.TestCase):
    def test_15_repeated_output_is_byte_identical(self):
        _, _, plan = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        first = json.dumps(plan, sort_keys=True)
        second = json.dumps(plan, sort_keys=True)
        self.assertEqual(first, second)

    def test_16_action_order_key_starts_with_rank(self):
        for fixture, provenance, scope in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED"),
            (p1_fixture(), "EXPLICIT", "GLOBAL"),
            (p3_fixture(), "INFERRED", "GLOBAL"),
        ):
            _, _, plan = engines(
                fixture, provenance=provenance, scope=scope
            )
            self.assertEqual(
                plan["action_order_key"][0], plan["action_rank"]
            )

    def test_16_preserves_r3111_order_key_exactly(self):
        _, ha_result, plan = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(
            plan["action_order_key"][1:],
            ha_result["action_order_key"],
        )

    def test_16_stable_sorting_between_candidates(self):
        explicit = dict(provenance="EXPLICIT", scope="GLOBAL")
        _, _, first = engines(
            p1_fixture(cve_id="CVE-2026-0001"), **explicit
        )
        _, _, second = engines(
            p1_fixture(cve_id="CVE-2026-0002"), **explicit
        )
        self.assertEqual(first["action"], second["action"])
        self.assertLess(first["action_order_key"],
                        second["action_order_key"])
        ordered = sorted(
            [
                ("blocked", engines(
                    immediate_fixture(
                        version_state="NO_MATCH",
                        version_association_state=(
                            "VERSION_OBSERVED_NO_MATCH"),
                    ),
                    provenance="EXPLICIT",
                    scope="COMPONENT_SCOPED",
                )[2]),
                ("immediate", engines(
                    immediate_fixture(),
                    provenance="EXPLICIT",
                    scope="COMPONENT_SCOPED",
                )[2]),
                ("manual", engines(
                    p1_fixture(), **explicit
                )[2]),
                ("defer", engines(
                    p3_fixture(), provenance="INFERRED", scope="GLOBAL"
                )[2]),
            ],
            key=lambda pair: pair[1]["action_order_key"],
        )
        self.assertEqual(
            [label for label, _ in ordered],
            ["immediate", "manual", "defer", "blocked"],
        )

    def test_17_no_mutation_of_hunt_priority(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        snapshot = copy.deepcopy(hp_result)
        ha_result = ha.evaluate_hunt_actionability(hp_result)
        pl.plan_hunt_action(hp_result, ha_result)
        self.assertEqual(hp_result, snapshot)

    def test_18_no_mutation_of_hunt_actionability(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        ha_result = ha.evaluate_hunt_actionability(hp_result)
        snapshot = copy.deepcopy(ha_result)
        pl.plan_hunt_action(hp_result, ha_result)
        self.assertEqual(ha_result, snapshot)


# ---------------------------------------------------------------------------
# 19–21: regressions
# ---------------------------------------------------------------------------


class TestR3110Regression(unittest.TestCase):
    def test_19_exact_priority_and_score_snapshot(self):
        expectations = (
            (immediate_fixture(), "P0", 100, False),
            (p1_fixture(), "P1", 60, False),
            (p2_fixture(), "P2", 48, False),
            (p3_fixture(), "P3", 28, False),
            (immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ), "DEFER", 0, True),
        )
        for kwargs, priority, score, blocked in expectations:
            result = hp.evaluate_hunt_priority(**kwargs)
            self.assertEqual(result["priority"], priority)
            self.assertEqual(result["hunt_score"], score)
            self.assertEqual(result["blocked"], blocked)

    def test_19_planner_does_not_change_r3110(self):
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
            pl.plan_hunt_action(
                first,
                ha_result,
                evidence_provenance=provenance,
                support_scope=scope,
            )
            self.assertEqual(first, snapshot)
            second = hp.evaluate_hunt_priority(**fixture)
            self.assertEqual(
                json.dumps(first, sort_keys=True),
                json.dumps(second, sort_keys=True),
            )


class TestR3111Regression(unittest.TestCase):
    def test_20_rule_version_and_states_unchanged(self):
        self.assertEqual(ha.HUNT_ACTIONABILITY_RULE_VERSION, "r31-11")
        self.assertEqual(ha.RULE_VERSION, "r31-11")
        expectations = (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED",
             ha.IMMEDIATE_VERIFICATION),
            (p1_fixture(), "EXPLICIT", "GLOBAL",
             ha.STRONG_MANUAL_REVIEW),
            (p2_fixture(), "INFERRED", "GLOBAL",
             ha.SUPPORTING_CONTEXT),
            (p3_fixture(), "INFERRED", "GLOBAL",
             ha.LOW_VALUE_DEFERRED),
            (immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ), "EXPLICIT", "COMPONENT_SCOPED", ha.BLOCKED),
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
            pl.plan_hunt_action(
                hp_result,
                before,
                evidence_provenance=provenance,
                support_scope=scope,
            )
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

    def test_21_hunt_queue_unchanged(self):
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

    def test_21_r29_items_have_no_plan_field(self):
        projection = self._snapshot()["items"][0]
        self.assertNotIn("hunt_action_plan", projection)
        self.assertNotIn("hunt_action_plan_rule_version", projection)
        self.assertEqual(HUNT_RULE_VERSION, "r29-1")


# ---------------------------------------------------------------------------
# 23–25: privacy, bounds, JSON
# ---------------------------------------------------------------------------


class TestPrivacyAndBounds(unittest.TestCase):
    def test_22_vocabulary_is_closed(self):
        for fixture, provenance, scope in (
            (immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED"),
            (p1_fixture(), "EXPLICIT", "GLOBAL"),
            (p3_fixture(), "INFERRED", "GLOBAL"),
        ):
            _, _, plan = engines(
                fixture, provenance=provenance, scope=scope
            )
            self.assertIn(plan["action"], pl.HUNT_ACTIONS)
            self.assertEqual(
                plan["action_rank"], pl.ACTION_RANKS[plan["action"]]
            )
            self.assertIn(plan["evidence_gap"], pl.EVIDENCE_GAPS)
            self.assertIn(plan["estimated_effort"],
                          pl.ESTIMATED_EFFORTS)
            self.assertIn(plan["confidence"], pl.PLAN_CONFIDENCES)
            for code in plan["reason_codes"]:
                self.assertIn(code, pl.REASON_CODES)

    def test_23_privacy_no_secrets_in_output(self):
        _, _, plan = engines(
            p1_fixture(
                gaps=["/download?token=SECRET",
                      "Authorization: Bearer abc123"],
                remaining_blockers=["password=hunter2"],
            ),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        blob = json.dumps(plan)
        for token in ("SECRET", "abc123", "hunter2", "Bearer abc123"):
            self.assertNotIn(token, blob)

    def test_23_privacy_rule_versions_are_sanitized(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        hp_result["rule_version"] = "token=SECRETVALUE"
        ha_result = ha.evaluate_hunt_actionability(hp_result)
        plan = pl.plan_hunt_action(hp_result, ha_result)
        blob = json.dumps(plan)
        self.assertNotIn("SECRETVALUE", blob)
        self.assertIn("[redacted]", blob)

    def test_24_bounded_output(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        hp_result["negative_reasons"] = [
            f"CODE_{index}(-1)" for index in range(64)
        ]
        hp_result["remaining_blocker_codes"] = (
            ["version_unknown"] * 64
        )
        hp_result["evidence_gaps"] = [
            f"path: gap {index}" for index in range(64)
        ]
        hp_result["tie_break_key"] = list(range(64))
        ha_result = ha.evaluate_hunt_actionability(hp_result)
        ha_result["action_order_key"] = list(range(64))
        plan = pl.plan_hunt_action(hp_result, ha_result)
        self.assertLessEqual(len(plan["reason_codes"]),
                             pl.MAX_REASON_CODES)
        self.assertLessEqual(len(plan["action_order_key"]),
                             pl.MAX_ORDER_KEY + 1)
        json.dumps(plan)

    def test_25_json_serializable(self):
        _, _, plan = engines(
            immediate_fixture(),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)


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
        self.assertEqual(item["hunt_action_plan_rule_version"], "r31-12")
        self.assertEqual(item["hunt_action_plan"]["rule_version"],
                         "r31-12")
        self.assertIn(item["hunt_action_plan"]["action"],
                      pl.HUNT_ACTIONS)
        # R31.10/R31.11 fields still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(item["hunt_actionability_rule_version"],
                         "r31-11")
        self.assertEqual(item["hunt_action_plan"]["source_priority"],
                         item["hunt_priority"]["priority"])
        self.assertEqual(
            item["hunt_action_plan"]["source_actionability"],
            item["hunt_actionability"]["actionability"],
        )

    def test_backend_immediate_plan_verify_existing_evidence(self):
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
        # Existing projections are not altered by planning.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)
        self.assertEqual(
            item["hunt_actionability"]["reason_codes"],
            ["PRIORITY_P0", "VERIFICATION_READY"],
        )

    def test_backend_blocked_plan_resolve_blockers(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.DEFER)
        self.assertEqual(item["hunt_actionability"]["actionability"],
                         ha.BLOCKED)
        self.assertEqual(item["hunt_action_plan"]["action"],
                         pl.RESOLVE_BLOCKERS)

    def test_backend_action_order_key_preserves_r3111(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["hunt_action_plan"]["action_order_key"][1:],
            item["hunt_actionability"]["action_order_key"],
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
