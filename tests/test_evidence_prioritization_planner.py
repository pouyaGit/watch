"""tests/test_evidence_prioritization_planner.py — Stage R31.14 tests.

Deterministic, offline tests for the evidence prioritization planner:

- deterministic output and stable priority ordering
- terminal NONE / missing / unknown / malformed acquisition handling
- every R31.13 acquisition method mapping (raw and via the real R31.13 engine)
- no mutation of the input acquisition plan
- closed vocabulary enforcement (planner + pydantic schema)
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
from ai.knowledge import evidence_prioritization_planner as epp
from ai.knowledge import hunt_action_planner as pl
from ai.knowledge import hunt_actionability as ha
from ai.knowledge import hunt_priority as hp
from ai.knowledge import hunt_queue as hq
from ai.knowledge.relevance import AssetRecord
from ai.schemas import evidence_prioritization as schema
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
    """Build R31.10 -> R31.11 -> R31.12 -> R31.13 -> R31.14 outputs."""

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
    return hp_result, ha_result, action_plan, acquisition, prioritization


# ---------------------------------------------------------------------------
# 4: every R31.13 acquisition method mapping
# ---------------------------------------------------------------------------


class TestMethodMapping(unittest.TestCase):
    def test_4_every_method_maps_to_priority_item(self):
        for method in eap.ACQUISITION_METHODS:
            if method == eap.NO_ACQUISITION:
                continue
            plan = epp.plan_evidence_prioritization(
                acquisition_plan(method)
            )
            self.assertEqual(len(plan["items"]), 1, method)
            item = plan["items"][0]
            expected_target, rank, reason, uncertainty, dependency, \
                importance = epp.METHOD_PRIORITY[method]
            self.assertEqual(item["acquisition_method"], method)
            self.assertEqual(item["evidence_target"], expected_target)
            self.assertEqual(item["priority_rank"], rank)
            self.assertEqual(item["priority_reason"], reason)
            self.assertEqual(item["uncertainty_category"], uncertainty)
            self.assertEqual(item["dependency_level"], dependency)
            self.assertEqual(item["completion_importance"], importance)

    def test_4_method_priority_ranks_are_documented(self):
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.EXISTING_EVIDENCE_REVIEW], 1
        )
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.COMPONENT_IDENTITY_LOOKUP], 2
        )
        self.assertEqual(epp.METHOD_PRIORITY_RANKS[eap.VERSION_LOOKUP], 3)
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.SCOPE_EVIDENCE_REVIEW], 4
        )
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.PATH_EVIDENCE_REVIEW], 5
        )
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.PARAMETER_EVIDENCE_REVIEW], 5
        )
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.HTTP_BEHAVIOR_REVIEW], 6
        )
        self.assertEqual(
            epp.METHOD_PRIORITY_RANKS[eap.TECHNOLOGY_EVIDENCE_REVIEW], 7
        )
        self.assertEqual(epp.METHOD_PRIORITY_RANKS[eap.MANUAL_RESEARCH], 8)

    def test_4_real_r3113_engine_every_method(self):
        fixtures = (
            (
                immediate_fixture(), "EXPLICIT", "COMPONENT_SCOPED", None,
                eap.EXISTING_EVIDENCE_REVIEW,
            ),
            (
                p1_fixture(
                    gaps=["component: no observed component/plugin identity"]
                ),
                "EXPLICIT", "GLOBAL", None,
                eap.COMPONENT_IDENTITY_LOOKUP,
            ),
            (
                p1_fixture(gaps=["version: no observed version available"]),
                "EXPLICIT", "GLOBAL", None, eap.VERSION_LOOKUP,
            ),
            (
                p1_fixture(
                    gaps=["scope: no component-scoped support available"]
                ),
                "EXPLICIT", "GLOBAL", None, eap.SCOPE_EVIDENCE_REVIEW,
            ),
            (
                p1_fixture(
                    gaps=["path: no matching observed path evidence"]
                ),
                "EXPLICIT", "GLOBAL", None, eap.PATH_EVIDENCE_REVIEW,
            ),
            (
                p1_fixture(
                    gaps=[
                        "parameter: no matching observed parameter evidence"
                    ]
                ),
                "EXPLICIT", "GLOBAL", None,
                eap.PARAMETER_EVIDENCE_REVIEW,
            ),
            (
                p1_fixture(gaps=["method: no structured method evidence"]),
                "EXPLICIT", "GLOBAL", None, eap.HTTP_BEHAVIOR_REVIEW,
            ),
            (
                p1_fixture(), "EXPLICIT", "GLOBAL", "TECHNOLOGY",
                eap.TECHNOLOGY_EVIDENCE_REVIEW,
            ),
            (
                p1_fixture(), "EXPLICIT", "GLOBAL", None,
                eap.MANUAL_RESEARCH,
            ),
        )
        for fixture, provenance, scope, strongest, expected in fixtures:
            _, _, _, acquisition, prioritization = full_chain(
                fixture, provenance=provenance, scope=scope,
                strongest=strongest,
            )
            self.assertEqual(
                acquisition["acquisition_method"], expected
            )
            self.assertEqual(len(prioritization["items"]), 1)
            item = prioritization["items"][0]
            self.assertEqual(item["acquisition_method"], expected)
            self.assertEqual(item["evidence_target"],
                             acquisition["evidence_target"])
            self.assertEqual(item["priority_rank"],
                             epp.METHOD_PRIORITY_RANKS[expected])


# ---------------------------------------------------------------------------
# 3: terminal handling
# ---------------------------------------------------------------------------


class TestTerminalHandling(unittest.TestCase):
    def test_3_none_method_empty_priority_list(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(eap.NO_ACQUISITION,
                             target=eap.TARGET_NONE)
        )
        self.assertEqual(plan["items"], [])
        self.assertTrue(plan["research_only"])
        self.assertEqual(plan["rule_version"], "r31-14")
        self.assertEqual(
            plan["source_acquisition_plan"]["acquisition_method"], "NONE"
        )

    def test_3_terminal_blocked_plan_is_empty(self):
        _, _, _, acquisition, prioritization = full_chain(
            immediate_fixture(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            ),
            provenance="EXPLICIT",
            scope="COMPONENT_SCOPED",
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(prioritization["items"], [])

    def test_3_terminal_deferred_plan_is_empty(self):
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
        _, _, _, acquisition, prioritization = full_chain(
            p3, provenance="INFERRED", scope="GLOBAL"
        )
        self.assertEqual(acquisition["acquisition_method"],
                         eap.NO_ACQUISITION)
        self.assertEqual(prioritization["items"], [])

    def test_3_missing_plan_is_empty(self):
        for missing in (None, {}, "not-a-plan", [], 0):
            plan = epp.plan_evidence_prioritization(missing)
            self.assertEqual(plan["items"], [], repr(missing))
            self.assertTrue(plan["research_only"])

    def test_3_unknown_method_is_empty(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan("DEPLOY_EXPLOIT", target="VERSION")
        )
        self.assertEqual(plan["items"], [])
        self.assertEqual(
            plan["source_acquisition_plan"]["acquisition_method"],
            "DEPLOY_EXPLOIT",
        )

    def test_3_target_method_mismatch_is_empty(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(eap.VERSION_LOOKUP, target=eap.TARGET_PATH)
        )
        self.assertEqual(plan["items"], [])

    def test_3_none_target_with_known_method_is_empty(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(eap.VERSION_LOOKUP, target=eap.TARGET_NONE)
        )
        self.assertEqual(plan["items"], [])


# ---------------------------------------------------------------------------
# 1–2: determinism and stable ordering
# ---------------------------------------------------------------------------


class TestDeterminismAndOrdering(unittest.TestCase):
    def test_1_repeated_output_is_byte_identical(self):
        plan = acquisition_plan(eap.VERSION_LOOKUP)
        first = epp.plan_evidence_prioritization(plan)
        second = epp.plan_evidence_prioritization(plan)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_1_repeated_call_after_mutation_of_copy(self):
        plan = acquisition_plan(eap.HTTP_BEHAVIOR_REVIEW)
        first = epp.plan_evidence_prioritization(plan)
        scratch = copy.deepcopy(plan)
        scratch["acquisition_method"] = "VERSION_LOOKUP"
        second = epp.plan_evidence_prioritization(plan)
        self.assertEqual(first, second)

    def test_2_priority_order_is_documented_sequence(self):
        self.assertEqual(
            epp.PRIORITY_ORDER,
            (
                eap.EXISTING_EVIDENCE_REVIEW,
                eap.COMPONENT_IDENTITY_LOOKUP,
                eap.VERSION_LOOKUP,
                eap.SCOPE_EVIDENCE_REVIEW,
                eap.PATH_EVIDENCE_REVIEW,
                eap.PARAMETER_EVIDENCE_REVIEW,
                eap.HTTP_BEHAVIOR_REVIEW,
                eap.TECHNOLOGY_EVIDENCE_REVIEW,
                eap.MANUAL_RESEARCH,
            ),
        )

    def test_2_ranks_are_non_decreasing_along_priority_order(self):
        ranks = [epp.METHOD_PRIORITY_RANKS[m] for m in epp.PRIORITY_ORDER]
        self.assertEqual(ranks, sorted(ranks))
        self.assertLess(
            epp.PRIORITY_ORDER.index(eap.PATH_EVIDENCE_REVIEW),
            epp.PRIORITY_ORDER.index(eap.PARAMETER_EVIDENCE_REVIEW),
        )

    def test_2_single_item_rank_matches_mapping(self):
        for method in epp.PRIORITY_ORDER:
            item = epp.plan_evidence_prioritization(
                acquisition_plan(method)
            )["items"][0]
            self.assertEqual(
                item["priority_rank"],
                epp.METHOD_PRIORITY_RANKS[method],
            )

    def test_2_item_ordering_is_stable_across_calls(self):
        items = [
            epp.plan_evidence_prioritization(
                acquisition_plan(method)
            )["items"][0]["priority_rank"]
            for method in epp.PRIORITY_ORDER
        ]
        repeated = [
            epp.plan_evidence_prioritization(
                acquisition_plan(method)
            )["items"][0]["priority_rank"]
            for method in epp.PRIORITY_ORDER
        ]
        self.assertEqual(items, repeated)
        self.assertEqual(items, sorted(items))


# ---------------------------------------------------------------------------
# 5: no mutation of the input acquisition plan
# ---------------------------------------------------------------------------


class TestNoMutation(unittest.TestCase):
    def test_5_no_mutation_of_input_plan(self):
        plan = acquisition_plan(
            eap.PARAMETER_EVIDENCE_REVIEW,
            reason_codes=["GAP_PARAMETER", "SOURCE_ACTION"],
            acquisition_order_key=[5, 1, -60],
        )
        snapshot = copy.deepcopy(plan)
        epp.plan_evidence_prioritization(plan)
        self.assertEqual(plan, snapshot)

    def test_5_no_mutation_of_terminal_plan(self):
        plan = acquisition_plan(eap.NO_ACQUISITION, target=eap.TARGET_NONE)
        snapshot = copy.deepcopy(plan)
        epp.plan_evidence_prioritization(plan)
        self.assertEqual(plan, snapshot)

    def test_5_source_snapshot_does_not_alias_input(self):
        plan = acquisition_plan(eap.VERSION_LOOKUP)
        result = epp.plan_evidence_prioritization(plan)
        result["source_acquisition_plan"]["acquisition_rank"] = 99
        self.assertEqual(plan["acquisition_rank"], 0)


# ---------------------------------------------------------------------------
# 6: closed vocabulary validation
# ---------------------------------------------------------------------------


class TestClosedVocabulary(unittest.TestCase):
    def test_6_output_fields_are_closed(self):
        for method in epp.PRIORITY_ORDER:
            plan = epp.plan_evidence_prioritization(
                acquisition_plan(method)
            )
            for item in plan["items"]:
                self.assertIn(item["acquisition_method"],
                              eap.ACQUISITION_METHODS)
                self.assertIn(item["evidence_target"], eap.EVIDENCE_TARGETS)
                self.assertIn(item["priority_reason"],
                              schema.PRIORITY_REASONS)
                self.assertIn(item["uncertainty_category"],
                              schema.UNCERTAINTY_CATEGORIES)
                self.assertIn(item["dependency_level"],
                              schema.DEPENDENCY_LEVELS)
                self.assertIn(item["completion_importance"],
                              schema.COMPLETION_IMPORTANCE_LEVELS)
                self.assertTrue(
                    schema.MIN_PRIORITY_RANK
                    <= item["priority_rank"]
                    <= schema.MAX_PRIORITY_RANK
                )

    def test_6_schema_rejects_invalid_priority_reason(self):
        with self.assertRaises(ValidationError):
            schema.EvidencePriorityItem(
                evidence_target="VERSION",
                acquisition_method="VERSION_LOOKUP",
                priority_rank=3,
                priority_reason="NOT_A_REASON",
                uncertainty_category="VERSION_UNCERTAINTY",
                dependency_level=1,
                completion_importance="CRITICAL",
            )

    def test_6_schema_rejects_invalid_uncertainty_category(self):
        with self.assertRaises(ValidationError):
            schema.EvidencePriorityItem(
                evidence_target="VERSION",
                acquisition_method="VERSION_LOOKUP",
                priority_rank=3,
                priority_reason="PRIORITY_VERSION",
                uncertainty_category="NOT_A_CATEGORY",
                dependency_level=1,
                completion_importance="CRITICAL",
            )

    def test_6_schema_rejects_invalid_dependency_level(self):
        with self.assertRaises(ValidationError):
            schema.EvidencePriorityItem(
                evidence_target="VERSION",
                acquisition_method="VERSION_LOOKUP",
                priority_rank=3,
                priority_reason="PRIORITY_VERSION",
                uncertainty_category="VERSION_UNCERTAINTY",
                dependency_level=9,
                completion_importance="CRITICAL",
            )

    def test_6_schema_rejects_invalid_completion_importance(self):
        with self.assertRaises(ValidationError):
            schema.EvidencePriorityItem(
                evidence_target="VERSION",
                acquisition_method="VERSION_LOOKUP",
                priority_rank=3,
                priority_reason="PRIORITY_VERSION",
                uncertainty_category="VERSION_UNCERTAINTY",
                dependency_level=1,
                completion_importance="URGENT",
            )

    def test_6_schema_rejects_invalid_rank(self):
        for rank in (0, 9, -1):
            with self.assertRaises(ValidationError):
                schema.EvidencePriorityItem(
                    evidence_target="VERSION",
                    acquisition_method="VERSION_LOOKUP",
                    priority_rank=rank,
                    priority_reason="PRIORITY_VERSION",
                    uncertainty_category="VERSION_UNCERTAINTY",
                    dependency_level=1,
                    completion_importance="CRITICAL",
                )

    def test_6_schema_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            schema.EvidencePrioritizationPlan(unexpected=True)

    def test_6_schema_forces_rule_version_and_research_only(self):
        plan = schema.EvidencePrioritizationPlan(
            rule_version="r99-9", research_only=True
        )
        self.assertEqual(plan.rule_version, "r31-14")
        with self.assertRaises(ValidationError):
            schema.EvidencePrioritizationPlan(research_only=False)

    def test_6_exact_rule_version(self):
        self.assertEqual(
            epp.EVIDENCE_PRIORITIZATION_PLANNER_RULE_VERSION, "r31-14"
        )
        self.assertEqual(epp.RULE_VERSION, "r31-14")
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(eap.VERSION_LOOKUP)
        )
        self.assertEqual(plan["rule_version"], "r31-14")

    def test_6_bounded_items(self):
        items = [
            schema.EvidencePriorityItem(
                evidence_target="VERSION",
                acquisition_method="VERSION_LOOKUP",
                priority_rank=3,
                priority_reason="PRIORITY_VERSION",
                uncertainty_category="VERSION_UNCERTAINTY",
                dependency_level=1,
                completion_importance="CRITICAL",
            )
            for _ in range(64)
        ]
        plan = schema.EvidencePrioritizationPlan(items=items)
        self.assertLessEqual(len(plan.items), schema.MAX_ITEMS)

    def test_6_source_plan_projection_drops_unknown_keys(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(
                eap.VERSION_LOOKUP,
                raw_url="https://example.test/?token=SECRET",
            )
        )
        self.assertNotIn("raw_url", plan["source_acquisition_plan"])
        self.assertNotIn("SECRET", json.dumps(plan))


# ---------------------------------------------------------------------------
# 7–9: JSON, research_only, no operational content
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
    def test_7_json_serializable(self):
        for method in epp.PRIORITY_ORDER:
            plan = epp.plan_evidence_prioritization(
                acquisition_plan(method)
            )
            self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_8_research_only_always_true(self):
        cases = [None, {}, acquisition_plan(eap.NO_ACQUISITION)]
        cases.extend(
            acquisition_plan(method) for method in epp.PRIORITY_ORDER
        )
        for case in cases:
            plan = epp.plan_evidence_prioritization(case)
            self.assertIs(plan["research_only"], True)

    def test_9_no_operational_attack_content(self):
        outputs = []
        for method in epp.PRIORITY_ORDER:
            outputs.append(
                epp.plan_evidence_prioritization(acquisition_plan(method))
            )
        outputs.append(epp.plan_evidence_prioritization(
            acquisition_plan(eap.NO_ACQUISITION)
        ))
        blob = json.dumps(outputs).lower()
        for marker in FORBIDDEN_OPERATIONAL_MARKERS:
            self.assertNotIn(marker, blob)

    def test_9_source_fields_are_sanitized(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(
                eap.MANUAL_RESEARCH,
                source_action="token=SECRETVALUE",
                source_actionability="Bearer abc123",
                reason_codes=["https://user:hunter2@x.test/p"],
            )
        )
        blob = json.dumps(plan)
        for token in ("SECRETVALUE", "abc123", "hunter2"):
            self.assertNotIn(token, blob)

    def test_9_bounded_source_snapshot(self):
        plan = epp.plan_evidence_prioritization(
            acquisition_plan(
                eap.VERSION_LOOKUP,
                reason_codes=[f"CODE_{index}" for index in range(64)],
            )
        )
        snapshot = plan["source_acquisition_plan"]
        self.assertLessEqual(
            len(snapshot["reason_codes"]), schema.MAX_REASON_CODES
        )
        for key in snapshot:
            self.assertIn(key, schema.SOURCE_PLAN_KEYS)
        json.dumps(plan)


# ---------------------------------------------------------------------------
# Regression / integration
# ---------------------------------------------------------------------------


class TestR31Regression(unittest.TestCase):
    def test_r3113_rule_version_unchanged(self):
        self.assertEqual(
            eap.EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION, "r31-13"
        )
        self.assertEqual(eap.RULE_VERSION, "r31-13")

    def test_r3113_plan_is_not_modified(self):
        _, _, _, acquisition, _ = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        snapshot = copy.deepcopy(acquisition)
        epp.plan_evidence_prioritization(acquisition)
        self.assertEqual(acquisition, snapshot)

    def test_source_snapshot_reflects_r3113(self):
        _, _, _, acquisition, prioritization = full_chain(
            p1_fixture(gaps=["version: no observed version available"]),
            provenance="EXPLICIT",
            scope="GLOBAL",
        )
        snapshot = prioritization["source_acquisition_plan"]
        self.assertEqual(
            snapshot["acquisition_method"],
            acquisition["acquisition_method"],
        )
        self.assertEqual(
            snapshot["evidence_target"], acquisition["evidence_target"]
        )
        self.assertEqual(
            snapshot["acquisition_rank"], acquisition["acquisition_rank"]
        )

    def _actions(self):
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
        return [base]

    def test_r29_queue_has_no_prioritization_field(self):
        action = self._actions()[0]
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
        self.assertNotIn("evidence_prioritization_plan", projection)
        self.assertNotIn(
            "evidence_prioritization_plan_rule_version", projection
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
            item["evidence_prioritization_plan_rule_version"], "r31-14"
        )
        self.assertEqual(
            item["evidence_prioritization_plan"]["rule_version"], "r31-14"
        )
        self.assertIs(
            item["evidence_prioritization_plan"]["research_only"], True
        )
        # Previous stages still present and unchanged.
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(item["hunt_actionability_rule_version"], "r31-11")
        self.assertEqual(item["hunt_action_plan_rule_version"], "r31-12")
        self.assertEqual(
            item["evidence_acquisition_plan_rule_version"], "r31-13"
        )
        self.assertEqual(
            item["evidence_prioritization_plan"]["source_acquisition_plan"][
                "acquisition_method"
            ],
            item["evidence_acquisition_plan"]["acquisition_method"],
        )

    def test_backend_immediate_plan_prioritization(self):
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
            item["evidence_acquisition_plan"]["acquisition_method"],
            eap.EXISTING_EVIDENCE_REVIEW,
        )
        plan = item["evidence_prioritization_plan"]
        self.assertEqual(len(plan["items"]), 1)
        self.assertEqual(
            plan["items"][0]["priority_reason"],
            schema.PRIORITY_EXISTING_EVIDENCE,
        )
        self.assertEqual(plan["items"][0]["priority_rank"], 1)
        # Existing projections are not altered by prioritization.
        self.assertEqual(item["hunt_priority"]["hunt_score"], 96)

    def test_backend_blocked_plan_empty_prioritization(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(
            item["evidence_acquisition_plan"]["acquisition_method"],
            eap.NO_ACQUISITION,
        )
        self.assertEqual(item["evidence_prioritization_plan"]["items"], [])

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
            "evidence_quality",
        ):
            self.assertIn(key, item)
        self.assertNotEqual(
            item["evidence_prioritization_plan"],
            item["evidence_acquisition_plan"],
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
