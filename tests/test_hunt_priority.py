"""tests/test_hunt_priority.py — Stage R31.10 tests.

Deterministic, offline tests for the evidence-aware hunt priority layer:

- all priority levels and R30.1 states
- version / path / parameter / method / identity / scope signals
- authoritative blockers and conflicts
- deterministic tie-breaking and repeated evaluation
- bounded, privacy-safe output
- false-positive guards (supporting evidence can never reach P0)
- hermetic backend integration and unchanged existing scores

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence.
"""
import json
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import asset_cve_matching as acm_engine
from ai.knowledge import hunt_priority as hp
from ai.knowledge.relevance import AssetRecord
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


def ppr(*, exact_path=False, prefix_path=False, parameter=False,
        method=False, path_match=None, parameter_match=None, scoped=True):
    rows = []
    if exact_path:
        rows.append({"evidence_type": "EXACT_PATH", "result": "MATCH",
                     "component_scoped": scoped})
    if prefix_path:
        rows.append({"evidence_type": "PATH_PREFIX", "result": "MATCH",
                     "component_scoped": scoped})
    if parameter:
        rows.append({"evidence_type": "EXACT_PARAMETER", "result": "MATCH",
                     "component_scoped": scoped})
    return {
        "evidence": rows,
        "summary": {
            "path_match": (
                exact_path or prefix_path
                if path_match is None else path_match
            ),
            "parameter_match": (
                parameter if parameter_match is None else parameter_match
            ),
            "method": {
                "evidence_type": "HTTP_METHOD",
                "result": "MATCH" if method else "NO_MATCH",
            },
        },
    }


def priority(**over):
    base = {
        "evidence_quality": quality("INSUFFICIENT"),
        "strongest_match_type": "",
        "strongest_confidence": "NONE",
        "asset_match_state": "UNKNOWN",
    }
    base.update(over)
    return hp.evaluate_hunt_priority(**base)


# ---------------------------------------------------------------------------
# A–D: evidence quality levels
# ---------------------------------------------------------------------------


class TestEvidenceQualityLevels(unittest.TestCase):
    def test_A_high_quality(self):
        result = priority(
            evidence_quality=quality("HIGH"),
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            version_state="MATCH",
            version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
            version_normalization={
                "rows": [{"comparison": "MATCH", "cve_kind": "EXACT",
                          "cve_evidence_class": "EXACT_OBSERVED"}],
                "observed_versions": [{}],
            },
        )
        self.assertEqual(result["priority"], hp.P0)
        self.assertGreaterEqual(result["hunt_score"], hp.THRESHOLD_P0)

    def test_B_medium_quality(self):
        result = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        self.assertEqual(result["priority"], hp.P1)

    def test_C_low_quality(self):
        result = priority(
            evidence_quality=quality("LOW", strength="WEAK"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertEqual(result["priority"], hp.P3)

    def test_D_insufficient(self):
        result = priority(evidence_quality=quality("INSUFFICIENT"))
        self.assertEqual(result["priority"], hp.DEFER)
        self.assertTrue(result["blocked"])
        self.assertIn(
            hp.BLOCK_EVIDENCE_INSUFFICIENT, result["blocking_reasons"]
        )


# ---------------------------------------------------------------------------
# E–H: R30.1 states
# ---------------------------------------------------------------------------


class TestR301States(unittest.TestCase):
    def test_E_confirmed(self):
        result = priority(
            evidence_quality=quality("HIGH"),
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            version_state="MATCH",
        )
        self.assertEqual(result["priority"], hp.P0)

    def test_F_supported(self):
        result = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="PLUGIN",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="wp-smushit",
            evidence_provenance="EXPLICIT",
        )
        self.assertEqual(result["priority"], hp.P1)

    def test_G_weak(self):
        result = priority(
            evidence_quality=quality("LOW", strength="WEAK"),
            strongest_match_type="COMPONENT",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        self.assertIn(result["priority"], (hp.P2, hp.P3))

    def test_G_technology_only_defers(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="TECHNOLOGY",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_H_unknown(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="",
            strongest_confidence="NONE",
            asset_match_state="UNKNOWN",
        )
        self.assertEqual(result["priority"], hp.DEFER)


# ---------------------------------------------------------------------------
# I–K: version signal
# ---------------------------------------------------------------------------


class TestVersionSignal(unittest.TestCase):
    def _base(self, **over):
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
        )
        base.update(over)
        return base

    def test_I_exact_version_match(self):
        result = priority(
            version_normalization={
                "rows": [{"comparison": "MATCH", "cve_kind": "EXACT",
                          "cve_evidence_class": "EXACT_OBSERVED"}],
                "observed_versions": [{}],
            },
            **self._base(),
        )
        self.assertEqual(result["priority"], hp.P0)
        self.assertIn(
            hp.REASON_EXACT_VERSION_MATCH,
            [item["code"] for item in result["adjustments"]],
        )

    def test_J_version_no_match_blocks(self):
        result = priority(
            **self._base(
                version_state="NO_MATCH",
                version_association_state="VERSION_OBSERVED_NO_MATCH",
            )
        )
        self.assertEqual(result["priority"], hp.DEFER)
        self.assertIn(hp.BLOCK_VERSION_NO_MATCH,
                      result["blocking_reasons"])

    def test_K_version_indeterminate_penalty(self):
        indeterminate = priority(
            **self._base(
                version_state="UNKNOWN",
                version_association_state="VERSION_ASSOCIATION_UNKNOWN",
                version_normalization={
                    "rows": [{"comparison": "INDETERMINATE",
                              "cve_kind": "RANGE"}],
                    "observed_versions": [{}],
                },
            )
        )
        exact = priority(
            **self._base(
                version_normalization={
                    "rows": [{"comparison": "MATCH", "cve_kind": "EXACT",
                              "cve_evidence_class": "EXACT_OBSERVED"}],
                    "observed_versions": [{}],
                },
            )
        )
        self.assertIn(
            hp.REASON_VERSION_UNRESOLVED,
            [item["code"] for item in indeterminate["adjustments"]],
        )
        self.assertLess(
            indeterminate["hunt_score"], exact["hunt_score"]
        )
        self.assertGreaterEqual(
            indeterminate["priority_rank"], exact["priority_rank"]
        )


# ---------------------------------------------------------------------------
# L–N: supporting signals alone
# ---------------------------------------------------------------------------


class TestSupportingSignals(unittest.TestCase):
    def test_L_path_match_alone(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="PATH",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
            path_parameter_relevance=ppr(exact_path=True),
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_M_parameter_match_alone(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="PARAMETER",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
            path_parameter_relevance=ppr(parameter=True),
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_N_method_match_alone(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            path_parameter_relevance=ppr(method=True),
        )
        self.assertEqual(result["priority"], hp.DEFER)


# ---------------------------------------------------------------------------
# O–R: scope and identity
# ---------------------------------------------------------------------------


class TestScopeAndIdentity(unittest.TestCase):
    def test_O_component_scoped_support_ranks_above_global(self):
        common = dict(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
        )
        scoped = priority(
            support_scope="COMPONENT_SCOPED",
            path_parameter_relevance=ppr(exact_path=True, scoped=True),
            **common,
        )
        global_only = priority(
            support_scope="GLOBAL",
            path_parameter_relevance=ppr(exact_path=True, scoped=False),
            **common,
        )
        self.assertEqual(scoped["priority"], hp.P1)
        self.assertIn(global_only["priority"], (hp.P2, hp.P3))
        self.assertGreater(scoped["hunt_score"], global_only["hunt_score"])

    def test_P_global_only_inferred_stays_low(self):
        result = priority(
            evidence_quality=quality("LOW", strength="WEAK"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
            path_parameter_relevance=ppr(exact_path=True, scoped=False),
        )
        self.assertIn(result["priority"], (hp.P3, hp.DEFER))
        self.assertNotEqual(result["priority"], hp.P0)

    def test_Q_explicit_component(self):
        result = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="PLUGIN",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="wp-smushit",
            evidence_provenance="EXPLICIT",
        )
        self.assertEqual(result["priority"], hp.P1)
        self.assertIn(
            hp.REASON_EXPLICIT_PROVENANCE,
            [item["code"] for item in result["adjustments"]],
        )

    def test_R_component_conflict_defers(self):
        result = priority(
            evidence_quality=quality(
                "INSUFFICIENT", consistency="CONFLICTING",
                conflicts=[{"kind": "component",
                            "severity": "authoritative"}],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
        )
        self.assertEqual(result["priority"], hp.DEFER)
        self.assertIn(hp.BLOCK_AUTHORITATIVE_CONFLICT,
                      result["blocking_reasons"])


# ---------------------------------------------------------------------------
# S–U: conflicts, blockers, gaps
# ---------------------------------------------------------------------------


class TestBlockersAndGaps(unittest.TestCase):
    def test_S_supporting_conflict_penalty(self):
        with_conflict = priority(
            evidence_quality=quality(
                "MEDIUM", strength="SUPPORTING",
                conflicts=[{"kind": "scope", "severity": "supporting"}],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        without_conflict = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        self.assertLess(
            with_conflict["hunt_score"], without_conflict["hunt_score"]
        )
        self.assertIn(
            hp.REASON_SUPPORTING_CONFLICT,
            [item["code"] for item in with_conflict["adjustments"]],
        )

    def test_T_remaining_blockers_reduce_score(self):
        clean = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        blocked = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            remaining_blockers=["version_unknown", "parameter_unknown"],
        )
        self.assertLess(blocked["hunt_score"], clean["hunt_score"])
        self.assertEqual(
            blocked["remaining_blocker_codes"],
            ["version_unknown", "parameter_unknown"],
        )

    def test_U_evidence_gaps_penalty(self):
        result = priority(
            evidence_quality=quality(
                "MEDIUM", strength="SUPPORTING",
                gaps=["version: no affected version",
                      "path: none", "method: none"],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        self.assertIn(
            hp.REASON_EVIDENCE_GAPS,
            [item["code"] for item in result["adjustments"]],
        )


# ---------------------------------------------------------------------------
# V–X: tie-breaking, determinism, bounds
# ---------------------------------------------------------------------------


class TestDeterminismAndBounds(unittest.TestCase):
    def test_V_tie_break_key_is_stable(self):
        first = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            cve_id="CVE-2026-0001",
        )
        second = priority(
            evidence_quality=quality("MEDIUM", strength="SUPPORTING"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            cve_id="CVE-2026-0002",
        )
        self.assertEqual(
            first["tie_break_key"][:-1], second["tie_break_key"][:-1]
        )
        self.assertLess(
            first["tie_break_key"][-1], second["tie_break_key"][-1]
        )

    def test_V_tie_break_orders_stronger_first(self):
        strong = priority(
            evidence_quality=quality("HIGH"),
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            version_state="MATCH",
        )
        weak = priority(
            evidence_quality=quality("LOW", strength="WEAK"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertLess(
            strong["tie_break_key"], weak["tie_break_key"]
        )

    def test_W_repeated_evaluation(self):
        kwargs = dict(
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
        first = json.dumps(
            hp.evaluate_hunt_priority(**kwargs), sort_keys=True
        )
        second = json.dumps(
            hp.evaluate_hunt_priority(**kwargs), sort_keys=True
        )
        self.assertEqual(first, second)

    def test_X_bounded_output(self):
        result = priority(
            evidence_quality=quality(
                "MEDIUM", strength="SUPPORTING",
                gaps=[f"gap_{index}" for index in range(40)],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            remaining_blockers=[f"blocker_{index}" for index in range(40)],
        )
        self.assertLessEqual(len(result["evidence_gaps"]), hp.MAX_GAPS)
        self.assertLessEqual(
            len(result["blocking_reasons"]), hp.MAX_BLOCKING_REASONS
        )
        self.assertLessEqual(
            len(result["positive_reasons"]), hp.MAX_POSITIVE_REASONS
        )
        self.assertLessEqual(
            len(result["remaining_blocker_codes"]),
            hp.MAX_BLOCKING_REASONS,
        )
        json.dumps(result)

    def test_Y_privacy_no_secrets_in_output(self):
        result = priority(
            evidence_quality=quality(
                "MEDIUM", strength="SUPPORTING",
                gaps=["/download?token=SECRET",
                      "Authorization: Bearer abc123"],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
            remaining_blockers=["password=hunter2"],
            cve_id="CVE-2026-1560",
        )
        blob = json.dumps(result)
        for token in ("SECRET", "abc123", "hunter2", "Bearer abc123"):
            self.assertNotIn(token, blob)

    def test_priority_vocabulary_is_closed(self):
        result = priority()
        self.assertIn(result["priority"], hp.HUNT_PRIORITIES)
        self.assertEqual(
            result["priority_rank"], hp.PRIORITY_RANKS[result["priority"]]
        )
        self.assertEqual(result["rule_version"], "r31-10")


# ---------------------------------------------------------------------------
# False-positive guards (required cases 1–12)
# ---------------------------------------------------------------------------


class TestFalsePositiveGuards(unittest.TestCase):
    def test_guard_1_path_alone_not_p0(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="PATH",
            path_parameter_relevance=ppr(exact_path=True),
        )
        self.assertNotEqual(result["priority"], hp.P0)
        self.assertEqual(result["priority"], hp.DEFER)

    def test_guard_2_parameter_alone_not_p0(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="PARAMETER",
            path_parameter_relevance=ppr(parameter=True),
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_guard_3_method_alone_not_p0(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            path_parameter_relevance=ppr(method=True),
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_guard_4_inferred_global_path_not_p0(self):
        result = priority(
            evidence_quality=quality("LOW", strength="WEAK"),
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
            path_parameter_relevance=ppr(exact_path=True, scoped=False),
        )
        self.assertNotEqual(result["priority"], hp.P0)
        self.assertNotEqual(result["priority"], hp.P1)

    def test_guard_5_version_no_match_blocks(self):
        result = priority(
            evidence_quality=quality("INSUFFICIENT"),
            strongest_match_type="COMPONENT",
            matched_component="CKEditor",
            version_association_state="VERSION_OBSERVED_NO_MATCH",
            path_parameter_relevance=ppr(
                exact_path=True, parameter=True
            ),
        )
        self.assertEqual(result["priority"], hp.DEFER)
        self.assertIn(hp.BLOCK_VERSION_NO_MATCH,
                      result["blocking_reasons"])

    def test_guard_6_authoritative_conflict_not_p0_or_p1(self):
        result = priority(
            evidence_quality=quality(
                "INSUFFICIENT", consistency="CONFLICTING",
                conflicts=[{"kind": "component",
                            "severity": "authoritative"}],
            ),
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
        )
        self.assertNotIn(
            result["priority"], (hp.P0, hp.P1)
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_guard_7_insufficient_with_blocker_defers(self):
        result = priority(
            evidence_quality=quality(
                "INSUFFICIENT",
                gaps=["version: authoritative NO_MATCH"],
            ),
            strongest_match_type="COMPONENT",
            matched_component="CKEditor",
        )
        self.assertEqual(result["priority"], hp.DEFER)

    def test_guard_8_explicit_version_scoped_path_reaches_p0(self):
        result = priority(
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
            path_parameter_relevance=ppr(
                exact_path=True, parameter=True, scoped=True
            ),
        )
        self.assertEqual(result["priority"], hp.P0)


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

    def test_additive_field_and_rule_version(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["hunt_priority_rule_version"], "r31-10")
        self.assertEqual(item["hunt_priority"]["rule_version"], "r31-10")
        self.assertIn(item["hunt_priority"]["priority"],
                      hp.HUNT_PRIORITIES)

    def test_path_only_defers(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.DEFER)

    def test_inferred_global_only_is_low_priority(self):
        item = self._match(
            _projection(
                paths=["/api/users"],
                components=[{
                    "value": "CKEditor",
                    "source": "COMPONENT_INVENTORY",
                    "evidence_type": "INFERRED_COMPONENT",
                }],
                provenance=[{
                    "value": "CKEditor",
                    "category": "COMPONENT",
                    "evidence_type": "INFERRED_COMPONENT",
                    "evidence_path": "/assets/ckeditor/ckeditor.js",
                    "scope_path": "/assets/ckeditor/",
                    "rule_id": "ckeditor",
                    "source": "COMPONENT_INVENTORY",
                }],
            ),
            components=["CKEditor", "/api/users"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.P3)

    def test_explicit_version_scoped_path_is_p0(self):
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

    def test_version_mismatch_defers(self):
        item = self._match(
            _projection(
                paths=["/assets/ckeditor/config.js"],
                components=[{
                    "value": "CKEditor",
                    "source": "COMPONENT_INVENTORY",
                    "evidence_type": "STRUCTURED_COMPONENT",
                }],
                versions=["2.0.0"],
                associations=[{
                    "version": "2.0.0",
                    "technology_family": "CKEditor",
                    "component": "CKEditor",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                }],
            ),
            components=["CKEditor", "/assets/ckeditor/config.js"],
            versions=["<=1.2.3"],
        )
        self.assertEqual(item["hunt_priority"]["priority"], hp.DEFER)
        self.assertIn(
            hp.BLOCK_VERSION_NO_MATCH,
            item["hunt_priority"]["blocking_reasons"],
        )

    def test_engine_fields_unchanged(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        engine = acm_engine.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            cve_components=["/wp-json/foo"],
            cve_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foo"],
        )
        for field in (
            "strongest_match_type",
            "strongest_confidence",
            "asset_match_state",
            "remaining_blockers",
            "version_state",
        ):
            self.assertEqual(item[field], engine[field], field)

    def test_privacy_in_adapter_priority_block(self):
        item = self._match(
            _projection(
                paths=["/download?token=SECRET"],
                parameters=["?token=SECRET"],
            ),
            components=["/download"],
            parameters=["token"],
        )
        blob = json.dumps(item["hunt_priority"])
        self.assertNotIn("SECRET", blob)

    def test_money_score_unchanged(self):
        from backend import research_economics

        before = research_economics.build_economics()
        self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        after = research_economics.build_economics()
        self.assertEqual(before, after)

    def test_r31_7_and_r31_8_evidence_unchanged(self):
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
        self.assertIn("version_normalization", item)
        self.assertIn("path_parameter_relevance", item)
        self.assertEqual(item["version_normalization_rule_version"],
                         "r31-7")
        self.assertEqual(item["path_parameter_relevance_rule_version"],
                         "r31-8")


class TestPerformanceGuard(unittest.TestCase):
    def test_ranking_cost_is_bounded(self):
        candidate = dict(
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
            path_parameter_relevance=ppr(exact_path=True),
            cve_id=CVE,
        )
        started = time.monotonic()
        for _ in range(1000):
            hp.evaluate_hunt_priority(**candidate)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
