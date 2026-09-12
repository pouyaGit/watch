"""tests/test_hunt_actionability.py — Stage R31.11 tests.

Deterministic, offline tests for the hunt actionability refinement layer:

- immediate-verification classification and its downgrade guards
- strong manual-review / supporting-context / low-value / blocked states
- version mismatch, authoritative conflict and insufficient-evidence blocks
- observed-vs-inferred and provenance/scope refinement (never upgraded)
- stable action ordering and tie-breaking, repeated-run determinism
- bounded, privacy-safe, JSON-serializable output
- regression: R31.10 score/priority and R29 hunt queue remain unchanged
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
    """Strongest R31.10 candidate: explicit, scoped, exact observed version."""

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


def p1_fixture(**over):
    base = dict(
        evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
        strongest_match_type="PLUGIN",
        strongest_confidence="MEDIUM",
        asset_match_state="SUPPORTED",
        matched_component="wp-smushit",
        evidence_provenance="EXPLICIT",
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
    )
    base.update(over)
    return base


def defer_nonblocked_fixture(**over):
    """R31.10 DEFER without the terminal ``blocked`` flag (score < 20)."""

    base = dict(
        evidence_quality=quality(
            "LOW", strength="WEAK",
            conflicts=[{"kind": "scope", "severity": "supporting"}],
            gaps=["version: comparison inconclusive",
                  "path: none", "method: none"],
        ),
        strongest_match_type="COMPONENT",
        strongest_confidence="MEDIUM",
        asset_match_state="SUPPORTED",
        matched_component="CKEditor",
        evidence_provenance="INFERRED",
        support_scope="GLOBAL",
        version_state="UNKNOWN",
        version_normalization={"rows": [], "observed_versions": [{}]},
    )
    base.update(over)
    return base


def priority(**over):
    kwargs = immediate_fixture()
    kwargs.update(over)
    return hp.evaluate_hunt_priority(**kwargs)


# ---------------------------------------------------------------------------
# A: highest-confidence actionable candidate
# ---------------------------------------------------------------------------


class TestHighestConfidence(unittest.TestCase):
    def test_A_explicit_scoped_exact_is_immediate(self):
        result = ha.evaluate_hunt_actionability(
            priority(),
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"],
                         ha.IMMEDIATE_VERIFICATION)
        self.assertEqual(result["actionability_rank"], 0)
        self.assertEqual(result["reason_codes"],
                         ["PRIORITY_P0", "VERIFICATION_READY"])
        self.assertEqual(result["next_action"],
                         "VERIFY_WITH_EXISTING_EVIDENCE")
        self.assertFalse(result["blocked"])

    def test_A_actionability_vocabulary_closed(self):
        result = ha.evaluate_hunt_actionability(priority())
        self.assertIn(result["actionability"],
                      ha.HUNT_ACTIONABILITY_STATES)
        self.assertEqual(
            result["actionability_rank"],
            ha.ACTIONABILITY_RANKS[result["actionability"]],
        )
        self.assertEqual(result["next_action"],
                         ha.NEXT_ACTIONS[result["actionability"]])
        self.assertEqual(result["rule_version"], "r31-11")
        self.assertTrue(result["research_only"])

    def test_A_codes_are_closed(self):
        for fixture in (
            immediate_fixture(), p1_fixture(), p2_fixture(), p3_fixture(),
        ):
            result = ha.evaluate_hunt_actionability(
                hp.evaluate_hunt_priority(**fixture)
            )
            for code in result["reason_codes"]:
                self.assertIn(code, ha.REASON_CODES)

    def test_A_medium_quality_p0_is_downgraded(self):
        hp_result = hp.evaluate_hunt_priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
            version_state="MATCH",
            version_normalization={
                "rows": [{"comparison": "MATCH", "cve_kind": "EXACT",
                          "cve_evidence_class": "EXACT_OBSERVED"}],
                "observed_versions": [{}],
            },
            path_parameter_relevance=ppr(exact_path=True, parameter=True),
        )
        self.assertEqual(hp_result["priority"], hp.P0)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_QUALITY_NOT_HIGH, result["reason_codes"])

    def test_A_supporting_conflict_downgrades(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                evidence_quality=quality(
                    "HIGH", consistency="CONFLICTING",
                    conflicts=[{"kind": "scope", "severity": "supporting"}],
                )
            )
        )
        self.assertEqual(hp_result["priority"], hp.P0)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_EVIDENCE_INCONSISTENT,
                      result["reason_codes"])

    def test_A_remaining_blockers_downgrade(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(remaining_blockers=["version_unknown"])
        )
        self.assertEqual(hp_result["priority"], hp.P0)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_REMAINING_BLOCKERS,
                      result["reason_codes"])

    def test_A_global_family_match_has_no_strong_anchor(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                support_scope="GLOBAL",
                version_normalization={
                    "rows": [], "observed_versions": [{}],
                },
                path_parameter_relevance=ppr(),
            )
        )
        self.assertEqual(hp_result["priority"], hp.P0)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="GLOBAL",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_NO_STRONG_ANCHOR, result["reason_codes"])

    def test_A_mixed_provenance_downgrades(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(evidence_provenance="MIXED")
        )
        self.assertEqual(hp_result["priority"], hp.P0)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="MIXED",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_MIXED_PROVENANCE, result["reason_codes"])

    def test_A_unknown_provenance_cannot_be_immediate(self):
        bare = {
            "priority": "P0",
            "hunt_score": 90,
            "blocked": False,
            "evidence_quality": "HIGH",
            "evidence_consistency": "CONSISTENT",
            "tie_break_key": [0, -90, 0, -3, 0, 0, 0, CVE],
        }
        result = ha.evaluate_hunt_actionability(bare)
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_PROVENANCE_UNCONFIRMED,
                      result["reason_codes"])

    def test_A_downgrade_never_upgrades(self):
        strong = ha.evaluate_hunt_actionability(
            hp.evaluate_hunt_priority(**p1_fixture()),
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(strong["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        supporting = ha.evaluate_hunt_actionability(
            hp.evaluate_hunt_priority(**p2_fixture()),
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertEqual(supporting["actionability"],
                         ha.SUPPORTING_CONTEXT)


# ---------------------------------------------------------------------------
# B: medium / supporting candidates
# ---------------------------------------------------------------------------


class TestMediumSupporting(unittest.TestCase):
    def test_B_p1_is_strong_manual_review(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        self.assertEqual(hp_result["priority"], hp.P1)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="GLOBAL",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertEqual(result["reason_codes"],
                         ["PRIORITY_P1", "MANUAL_REVIEW_REQUIRED"])
        self.assertEqual(result["next_action"], "MANUAL_REVIEW")

    def test_B_p2_is_supporting_context(self):
        hp_result = hp.evaluate_hunt_priority(**p2_fixture())
        self.assertEqual(hp_result["priority"], hp.P2)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertEqual(result["actionability"],
                         ha.SUPPORTING_CONTEXT)
        self.assertEqual(result["reason_codes"],
                         ["PRIORITY_P2", "CONTEXT_ONLY"])
        self.assertEqual(result["next_action"], "COLLECT_MORE_EVIDENCE")


# ---------------------------------------------------------------------------
# C: weak / inferred candidates
# ---------------------------------------------------------------------------


class TestWeakInferred(unittest.TestCase):
    def test_C_p3_is_low_value_deferred(self):
        hp_result = hp.evaluate_hunt_priority(**p3_fixture())
        self.assertEqual(hp_result["priority"], hp.P3)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertEqual(result["actionability"],
                         ha.LOW_VALUE_DEFERRED)
        self.assertIn(ha.REASON_LOW_VALUE, result["reason_codes"])

    def test_C_nonblocked_defer_is_low_value(self):
        hp_result = hp.evaluate_hunt_priority(**defer_nonblocked_fixture())
        self.assertEqual(hp_result["priority"], hp.DEFER)
        self.assertFalse(hp_result["blocked"])
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertEqual(result["actionability"],
                         ha.LOW_VALUE_DEFERRED)
        self.assertFalse(result["blocked"])
        self.assertNotIn(ha.REASON_SOURCE_BLOCKED,
                         result["reason_codes"])

    def test_C_inferred_unscoped_code_is_detected_without_hint(self):
        hp_result = hp.evaluate_hunt_priority(**p3_fixture())
        result = ha.evaluate_hunt_actionability(hp_result)
        self.assertNotEqual(result["actionability"],
                            ha.IMMEDIATE_VERIFICATION)
        self.assertEqual(result["source_priority"], hp.P3)

    def test_C_inferred_scoped_p0_never_immediate(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(evidence_provenance="INFERRED")
        )
        self.assertEqual(hp_result["priority"], hp.P0)
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="INFERRED",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"],
                         ha.STRONG_MANUAL_REVIEW)
        self.assertIn(ha.REASON_INFERRED_PROVENANCE,
                      result["reason_codes"])

    def test_C_missing_signal(self):
        result = ha.evaluate_hunt_actionability(None)
        self.assertEqual(result["actionability"],
                         ha.LOW_VALUE_DEFERRED)
        self.assertIn(ha.REASON_MISSING_SIGNAL, result["reason_codes"])

    def test_C_unrecognized_priority(self):
        result = ha.evaluate_hunt_actionability({"priority": "PX"})
        self.assertEqual(result["actionability"],
                         ha.LOW_VALUE_DEFERRED)
        self.assertIn(ha.REASON_UNRECOGNIZED_PRIORITY,
                      result["reason_codes"])


# ---------------------------------------------------------------------------
# D: blocked candidates (terminal blockers preserved)
# ---------------------------------------------------------------------------


class TestBlocked(unittest.TestCase):
    def test_D_version_mismatch_is_blocked(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            )
        )
        self.assertTrue(hp_result["blocked"])
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"], ha.BLOCKED)
        self.assertEqual(result["reason_codes"], ["SOURCE_BLOCKED"])
        self.assertTrue(result["blocked"])
        self.assertIn(hp.BLOCK_VERSION_NO_MATCH,
                      result["source_blocking_reasons"])

    def test_D_authoritative_conflict_is_blocked(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                evidence_quality=quality(
                    "INSUFFICIENT", consistency="CONFLICTING",
                    conflicts=[{"kind": "component",
                                "severity": "authoritative"}],
                )
            )
        )
        result = ha.evaluate_hunt_actionability(hp_result)
        self.assertEqual(result["actionability"], ha.BLOCKED)
        self.assertIn(hp.BLOCK_AUTHORITATIVE_CONFLICT,
                      result["source_blocking_reasons"])

    def test_D_insufficient_evidence_is_blocked(self):
        hp_result = hp.evaluate_hunt_priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="",
            strongest_confidence="NONE",
            asset_match_state="UNKNOWN",
        )
        result = ha.evaluate_hunt_actionability(hp_result)
        self.assertEqual(result["actionability"], ha.BLOCKED)
        self.assertIn(hp.BLOCK_EVIDENCE_INSUFFICIENT,
                      result["source_blocking_reasons"])

    def test_D_blocked_flag_never_overridden(self):
        hp_result = hp.evaluate_hunt_priority(**p1_fixture())
        forged = dict(hp_result)
        forged["blocked"] = True
        forged["blocking_reasons"] = [hp.BLOCK_AUTHORITATIVE_CONFLICT]
        result = ha.evaluate_hunt_actionability(
            forged,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["actionability"], ha.BLOCKED)
        self.assertEqual(result["reason_codes"], ["SOURCE_BLOCKED"])

    def test_D_blocked_never_mutates_source(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            )
        )
        snapshot = copy.deepcopy(hp_result)
        ha.evaluate_hunt_actionability(hp_result)
        self.assertEqual(hp_result, snapshot)


# ---------------------------------------------------------------------------
# E: deterministic ordering / tie-breaking
# ---------------------------------------------------------------------------


class TestOrderingAndDeterminism(unittest.TestCase):
    def _candidate(self, fixture, hints, **over):
        kwargs = dict(fixture)
        kwargs.update(over)
        hp_result = hp.evaluate_hunt_priority(**kwargs)
        return ha.evaluate_hunt_actionability(hp_result, **hints)

    def _ranked(self):
        explicit = dict(evidence_provenance="EXPLICIT",
                        support_scope="COMPONENT_SCOPED")
        return [
            ("low", self._candidate(p3_fixture(), {
                "evidence_provenance": "INFERRED",
                "support_scope": "GLOBAL"})),
            ("blocked", self._candidate(
                immediate_fixture(
                    version_state="NO_MATCH",
                    version_association_state="VERSION_OBSERVED_NO_MATCH",
                ),
                explicit)),
            ("immediate", self._candidate(immediate_fixture(), explicit)),
            ("supporting", self._candidate(p2_fixture(), {
                "evidence_provenance": "INFERRED",
                "support_scope": "GLOBAL"})),
            ("strong", self._candidate(p1_fixture(), {
                "evidence_provenance": "EXPLICIT",
                "support_scope": "GLOBAL"})),
        ]

    def test_E_action_order_key_starts_with_rank(self):
        for label, result in self._ranked():
            self.assertEqual(
                result["action_order_key"][0],
                result["actionability_rank"],
                label,
            )

    def test_E_stable_sorting(self):
        ordered = sorted(self._ranked(),
                         key=lambda pair: pair[1]["action_order_key"])
        self.assertEqual(
            [label for label, _ in ordered],
            ["immediate", "strong", "supporting", "low", "blocked"],
        )

    def test_E_tie_break_within_state(self):
        first = self._candidate(
            p1_fixture(), {"evidence_provenance": "EXPLICIT"},
            cve_id="CVE-2026-0001",
        )
        second = self._candidate(
            p1_fixture(), {"evidence_provenance": "EXPLICIT"},
            cve_id="CVE-2026-0002",
        )
        self.assertEqual(first["actionability"],
                         second["actionability"])
        self.assertLess(first["action_order_key"],
                        second["action_order_key"])

    def test_E_repeated_evaluation_is_byte_identical(self):
        hp_result = hp.evaluate_hunt_priority(**immediate_fixture())
        first = json.dumps(
            ha.evaluate_hunt_actionability(
                hp_result,
                evidence_provenance="EXPLICIT",
                support_scope="COMPONENT_SCOPED",
            ),
            sort_keys=True,
        )
        second = json.dumps(
            ha.evaluate_hunt_actionability(
                hp_result,
                evidence_provenance="EXPLICIT",
                support_scope="COMPONENT_SCOPED",
            ),
            sort_keys=True,
        )
        self.assertEqual(first, second)

    def test_E_same_evidence_same_order_key(self):
        first = self._ranked()[2][1]
        second = self._candidate(immediate_fixture(), {
            "evidence_provenance": "EXPLICIT",
            "support_scope": "COMPONENT_SCOPED",
        })
        self.assertEqual(first["action_order_key"],
                         second["action_order_key"])


# ---------------------------------------------------------------------------
# F: bounds, privacy, structure
# ---------------------------------------------------------------------------


class TestBoundsAndPrivacy(unittest.TestCase):
    def test_F_bounds(self):
        hp_result = hp.evaluate_hunt_priority(
            **immediate_fixture(
                remaining_blockers=[f"b{index}" for index in range(40)]
            )
        )
        hp_result["tie_break_key"] = list(range(64))
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertLessEqual(len(result["reason_codes"]),
                             ha.MAX_REASON_CODES)
        self.assertLessEqual(len(result["source_remaining_blockers"]),
                             ha.MAX_SOURCE_CODES)
        self.assertLessEqual(len(result["source_blocking_reasons"]),
                             ha.MAX_SOURCE_CODES)
        self.assertLessEqual(len(result["action_order_key"]),
                             ha.MAX_ORDER_KEY + 1)
        json.dumps(result)

    def test_F_privacy_no_secrets_in_output(self):
        hp_result = hp.evaluate_hunt_priority(**immediate_fixture())
        hp_result["remaining_blocker_codes"] = [
            "/download?token=SECRET",
            "Authorization: Bearer abc123",
        ]
        hp_result["tie_break_key"] = [
            0, -1, 0, 0, 0, 0, 0, "password=hunter2",
        ]
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        blob = json.dumps(result)
        for token in ("SECRET", "abc123", "hunter2", "Bearer abc123"):
            self.assertNotIn(token, blob)

    def test_F_result_is_json_serializable(self):
        result = ha.evaluate_hunt_actionability(
            hp.evaluate_hunt_priority(**p2_fixture()),
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertIsInstance(json.loads(json.dumps(result)), dict)

    def test_F_source_fields_copied(self):
        hp_result = hp.evaluate_hunt_priority(**immediate_fixture())
        result = ha.evaluate_hunt_actionability(
            hp_result,
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(result["source_priority"], hp_result["priority"])
        self.assertEqual(result["source_hunt_score"],
                         hp_result["hunt_score"])
        self.assertEqual(result["source_priority_rank"],
                         hp_result["priority_rank"])
        self.assertEqual(result["source_rule_version"], "r31-10")


# ---------------------------------------------------------------------------
# G: R31.10 regression — score/priority unchanged
# ---------------------------------------------------------------------------


class TestR3110Regression(unittest.TestCase):
    def test_G_rule_version_unchanged(self):
        self.assertEqual(hp.HUNT_PRIORITY_RULE_VERSION, "r31-10")
        self.assertEqual(hp.RULE_VERSION, "r31-10")

    def test_G_exact_priority_and_score_snapshot(self):
        expectations = (
            (immediate_fixture(), "P0", 100, False),
            (p1_fixture(), "P1", 60, False),
            (p2_fixture(), "P2", 48, False),
            (p3_fixture(), "P3", 28, False),
            (defer_nonblocked_fixture(), "DEFER", 10, False),
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

    def test_G_actionability_does_not_change_r3110(self):
        fixtures = (
            immediate_fixture(),
            p1_fixture(),
            p2_fixture(),
            p3_fixture(),
            defer_nonblocked_fixture(),
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
        )
        for kwargs in fixtures:
            first = hp.evaluate_hunt_priority(**kwargs)
            snapshot = copy.deepcopy(first)
            ha.evaluate_hunt_actionability(first)
            self.assertEqual(first, snapshot)
            second = hp.evaluate_hunt_priority(**kwargs)
            self.assertEqual(
                json.dumps(first, sort_keys=True),
                json.dumps(second, sort_keys=True),
            )


# ---------------------------------------------------------------------------
# H: R29 regression — hunt queue unchanged
# ---------------------------------------------------------------------------


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

    def test_H_hunt_queue_unchanged_by_actionability(self):
        before = self._snapshot()
        for kwargs in (
            immediate_fixture(), p1_fixture(), p2_fixture(), p3_fixture(),
        ):
            ha.evaluate_hunt_actionability(
                hp.evaluate_hunt_priority(**kwargs)
            )
        after = self._snapshot()
        self.assertEqual(
            json.dumps(before, sort_keys=True),
            json.dumps(after, sort_keys=True),
        )

    def test_H_r29_vocabulary_and_version_unchanged(self):
        self.assertEqual(HUNT_RULE_VERSION, "r29-1")
        self.assertEqual(
            tuple(hq.HUNT_PRIORITY_ORDER),
            ("HUNT_NOW", "HUNT_NEXT", "VERIFY_FIRST", "RESEARCH_LATER",
             "SKIP_FOR_NOW"),
        )

    def test_H_r29_items_have_no_actionability_field(self):
        projection = self._snapshot()["items"][0]
        self.assertNotIn("hunt_actionability", projection)
        self.assertNotIn("hunt_actionability_rule_version", projection)
        self.assertIn("hunt_priority", projection)

    def test_H_r29_ordering_and_reasons_stable(self):
        before = self._snapshot()
        self.assertEqual(
            [item["hunt_priority"] for item in before["items"]],
            ["HUNT_NOW", "HUNT_NEXT", "VERIFY_FIRST"],
        )
        self.assertEqual(before["summary"]["total"], 3)
        self.assertEqual(
            before["summary"]["rule_version"], HUNT_RULE_VERSION)


# ---------------------------------------------------------------------------
# I: backend integration (hermetic; no live Mongo)
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

    def test_I_additive_fields_and_rule_versions(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["hunt_actionability_rule_version"], "r31-11")
        self.assertEqual(item["hunt_actionability"]["rule_version"],
                         "r31-11")
        self.assertIn(item["hunt_actionability"]["actionability"],
                      ha.HUNT_ACTIONABILITY_STATES)
        # R31.10 fields are still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(item["hunt_priority"]["rule_version"], "r31-10")

    def test_I_strong_fixture_is_immediate(self):
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
        self.assertEqual(
            item["hunt_actionability"]["reason_codes"],
            ["PRIORITY_P0", "VERIFICATION_READY"],
        )

    def test_I_defers_preserved(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.DEFER)
        self.assertEqual(item["hunt_actionability"]["actionability"],
                         ha.BLOCKED)
        self.assertTrue(item["hunt_actionability"]["blocked"])

    def test_I_r3110_fields_preserved(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        for field in (
            "hunt_priority",
            "hunt_priority_rule_version",
            "evidence_quality",
            "evidence_quality_rule_version",
            "version_normalization",
            "version_normalization_rule_version",
            "path_parameter_relevance",
            "path_parameter_relevance_rule_version",
        ):
            self.assertIn(field, item, field)
        self.assertEqual(item["evidence_quality_rule_version"], "r31-9")

    def test_I_money_score_unchanged(self):
        from backend import research_economics

        before = research_economics.build_economics()
        self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        after = research_economics.build_economics()
        self.assertEqual(before, after)

    def test_I_privacy_in_actionability_block(self):
        item = self._match(
            _projection(
                paths=["/download?token=SECRET"],
                parameters=["?token=SECRET"],
            ),
            components=["/download"],
            parameters=["token"],
        )
        blob = json.dumps(item["hunt_actionability"])
        self.assertNotIn("SECRET", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
