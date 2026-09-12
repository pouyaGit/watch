"""tests/test_evidence_quality.py — Stage R31.9 tests.

Deterministic, offline tests for the additive evidence-quality layer:

- every dimension in isolation (A–Z required coverage)
- authoritative vs supporting classification
- conflict detection and preservation
- completeness model
- false-positive guards (supporting evidence can never escalate)
- version authority (R31.7/R30.3), scope authority (R31.5),
  path/parameter authority (R31.8)
- bounded, deterministic, privacy-safe output
- hermetic backend integration

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
from ai.knowledge import evidence_quality as eq
from ai.knowledge.relevance import AssetRecord
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1559"


def vn(comparison="", *, kind="EXACT", evidence_class="EXACT_OBSERVED",
       cve_versions=(), observed_versions=()):
    rows = []
    if comparison:
        rows.append({
            "comparison": comparison,
            "cve_kind": kind,
            "cve_evidence_class": evidence_class,
        })
    return {
        "rule_version": "r31-7",
        "rows": rows,
        "cve_versions": list(cve_versions),
        "observed_versions": list(observed_versions),
        "counts": {"rows": len(rows)},
    }


def ppr(*, path_match=False, parameter_match=False, scoped=True,
        method_result="", method_type="HTTP_METHOD"):
    rows = []
    if path_match:
        rows.append({
            "evidence_type": "EXACT_PATH",
            "result": "MATCH",
            "component_scoped": scoped,
        })
    if parameter_match:
        rows.append({
            "evidence_type": "EXACT_PARAMETER",
            "result": "MATCH",
            "component_scoped": scoped,
        })
    method = (
        {"evidence_type": method_type, "result": method_result}
        if method_type
        else {"evidence_type": "NO_EVIDENCE", "result": "INDETERMINATE"}
    )
    return {
        "rule_version": "r31-8",
        "evidence": rows,
        "summary": {
            "result": (
                "MATCH" if (path_match or parameter_match) else "NO_MATCH"
            ),
            "path_match": path_match,
            "parameter_match": parameter_match,
            "component_scoped": scoped,
            "method": method,
        },
    }


def quality(**over):
    base = {
        "strongest_match_type": "",
        "strongest_confidence": "NONE",
        "asset_match_state": "UNKNOWN",
        "evidence_provenance": "EXPLICIT",
        "support_scope": "GLOBAL",
        "version_state": "UNKNOWN",
        "version_association_state": "",
    }
    base.update(over)
    return eq.evaluate_evidence_quality(**base)


# ---------------------------------------------------------------------------
# A–E: identity / provenance dimensions
# ---------------------------------------------------------------------------


class TestIdentityDimensions(unittest.TestCase):
    def test_A_all_dimensions_absent(self):
        result = quality()
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertEqual(result["evidence_state"], eq.STATE_UNKNOWN)
        self.assertEqual(
            result["evidence_completeness"]["overall"],
            eq.COMPLETENESS_NOT_AVAILABLE,
        )
        self.assertEqual(
            result["dimensions"][eq.DIM_ASSET_IDENTITY]["state"],
            eq.STATE_UNKNOWN,
        )
        for name in eq.DIMENSION_ORDER:
            self.assertIn(name, result["dimensions"])

    def test_B_strong_explicit_identity(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="EXPLICIT",
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_MEDIUM)
        self.assertEqual(result["evidence_state"], eq.STATE_SUPPORTING)
        self.assertEqual(
            result["dimensions"][eq.DIM_COMPONENT_IDENTITY]["state"],
            eq.STATE_STRONG,
        )

    def test_C_inferred_identity_scoped_and_global(self):
        scoped = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="COMPONENT_SCOPED",
        )
        self.assertEqual(scoped["evidence_quality"], eq.LEVEL_MEDIUM)
        global_only = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
        )
        self.assertEqual(global_only["evidence_quality"], eq.LEVEL_LOW)
        self.assertEqual(global_only["evidence_state"], eq.STATE_WEAK)

    def test_D_explicit_component_identity(self):
        result = quality(
            strongest_match_type="PLUGIN",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="wp-smushit",
            evidence_provenance="EXPLICIT",
        )
        dim = result["dimensions"][eq.DIM_COMPONENT_IDENTITY]
        self.assertEqual(dim["state"], eq.STATE_STRONG)
        self.assertEqual(
            result["dimensions"][eq.DIM_COMPONENT_PROVENANCE]["state"],
            eq.STATE_STRONG,
        )

    def test_E_mixed_provenance(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="MIXED",
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_MEDIUM)
        self.assertEqual(
            result["dimensions"][eq.DIM_PROVENANCE]["state"],
            eq.STATE_SUPPORTING,
        )
        self.assertEqual(result["evidence_consistency"],
                         eq.CONSISTENCY_CONSISTENT)


# ---------------------------------------------------------------------------
# F–I: version dimensions
# ---------------------------------------------------------------------------


class TestVersionDimensions(unittest.TestCase):
    def test_F_exact_version_match(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            version_state="MATCH",
            version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
            evidence_provenance="EXPLICIT",
            version_normalization=vn(
                "MATCH", cve_versions=("1.2.3",),
                observed_versions=("1.2.3",),
            ),
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_HIGH)
        self.assertEqual(
            result["dimensions"][eq.DIM_VERSION_COMPATIBILITY]["state"],
            eq.STATE_STRONG,
        )

    def test_G_version_no_match(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            version_state="NO_MATCH",
            version_normalization=vn(
                "NO_MATCH", cve_versions=("<=1.0",),
                observed_versions=("2.0",),
            ),
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertIn(
            "version: authoritative NO_MATCH", result["evidence_gaps"]
        )

    def test_G_version_no_match_via_association_state(self):
        # R30.3 withholds non-matching observed versions from the engine, so
        # the association state carries the authoritative negative signal.
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            version_state="UNKNOWN",
            version_association_state="VERSION_OBSERVED_NO_MATCH",
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertIn(
            "version: authoritative NO_MATCH", result["evidence_gaps"]
        )

    def test_H_version_indeterminate(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            version_state="UNKNOWN",
            version_normalization=vn(
                "INDETERMINATE", cve_versions=("1.2",),
                observed_versions=("1.2.0",),
            ),
        )
        self.assertNotEqual(result["evidence_quality"], eq.LEVEL_HIGH)
        self.assertEqual(
            result["dimensions"][eq.DIM_VERSION_COMPATIBILITY]["state"],
            eq.STATE_UNKNOWN,
        )

    def test_I_version_unknown_is_not_available(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
        )
        self.assertEqual(
            result["dimensions"][eq.DIM_VERSION_COMPATIBILITY][
                "completeness"
            ],
            eq.COMPLETENESS_NOT_AVAILABLE,
        )
        self.assertEqual(
            result["dimensions"][eq.DIM_VERSION_EVIDENCE]["completeness"],
            eq.COMPLETENESS_NOT_AVAILABLE,
        )


# ---------------------------------------------------------------------------
# J–N: supporting dimensions
# ---------------------------------------------------------------------------


class TestSupportingDimensions(unittest.TestCase):
    def test_J_exact_path_match_alone(self):
        result = quality(
            strongest_match_type="PATH",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
            path_parameter_relevance=ppr(path_match=True),
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)

    def test_K_path_no_match_does_not_downgrade_strong_evidence(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            version_state="MATCH",
            version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
            evidence_provenance="EXPLICIT",
            path_parameter_relevance=ppr(),
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_HIGH)
        self.assertEqual(
            result["dimensions"][eq.DIM_PATH_RELEVANCE]["state"],
            eq.STATE_UNKNOWN,
        )

    def test_L_parameter_match_alone(self):
        result = quality(
            strongest_match_type="PARAMETER",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
            path_parameter_relevance=ppr(parameter_match=True),
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)

    def test_M_method_match_alone(self):
        result = quality(
            path_parameter_relevance=ppr(
                method_type="HTTP_METHOD", method_result="MATCH"
            ),
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertEqual(
            result["dimensions"][eq.DIM_METHOD_RELEVANCE]["state"],
            eq.STATE_SUPPORTING,
        )

    def test_N_no_method_evidence(self):
        result = quality()
        dim = result["dimensions"][eq.DIM_METHOD_RELEVANCE]
        self.assertEqual(dim["state"], eq.STATE_UNKNOWN)
        self.assertEqual(dim["completeness"],
                         eq.COMPLETENESS_NOT_AVAILABLE)


# ---------------------------------------------------------------------------
# O–P: scope compatibility
# ---------------------------------------------------------------------------


class TestScopeCompatibility(unittest.TestCase):
    def test_O_component_scoped_support(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="COMPONENT_SCOPED",
            path_parameter_relevance=ppr(path_match=True, scoped=True),
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_MEDIUM)
        self.assertEqual(
            result["dimensions"][eq.DIM_SCOPE]["state"], eq.STATE_STRONG
        )

    def test_P_global_only_support(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
            path_parameter_relevance=ppr(path_match=True, scoped=False),
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_LOW)
        self.assertEqual(result["evidence_consistency"],
                         eq.CONSISTENCY_CONFLICTING)
        self.assertTrue(
            any(record["kind"] == "scope"
                for record in result["conflicts"])
        )


# ---------------------------------------------------------------------------
# Q–S: conflicts
# ---------------------------------------------------------------------------


class TestConflicts(unittest.TestCase):
    def test_Q_authoritative_component_conflict(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            component_conflict=True,
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertEqual(result["evidence_state"], eq.STATE_CONFLICTING)
        self.assertEqual(result["conflicts"][0]["severity"],
                         "authoritative")

    def test_R_component_conflict_cannot_be_high(self):
        result = quality(
            strongest_match_type="PLUGIN",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="wp-smushit",
            version_state="MATCH",
            evidence_provenance="EXPLICIT",
            component_conflict=True,
        )
        self.assertNotEqual(result["evidence_quality"], eq.LEVEL_HIGH)
        self.assertEqual(result["evidence_state"], eq.STATE_CONFLICTING)

    def test_S_version_conflict(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            version_state="NO_MATCH",
            version_normalization=vn(
                "MATCH", cve_versions=("<=1.0",),
                observed_versions=("0.9",),
            ),
        )
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertTrue(
            any(record["kind"] == "version"
                for record in result["conflicts"])
        )


# ---------------------------------------------------------------------------
# T–W: false-positive guards
# ---------------------------------------------------------------------------


class TestFalsePositiveGuards(unittest.TestCase):
    def _version_mismatch_with_support(self, *, path=False, parameter=False):
        return quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            version_state="UNKNOWN",
            version_association_state="VERSION_OBSERVED_NO_MATCH",
            evidence_provenance="EXPLICIT",
            path_parameter_relevance=ppr(
                path_match=path, parameter_match=parameter
            ),
        )

    def test_T_path_cannot_override_version_mismatch(self):
        result = self._version_mismatch_with_support(path=True)
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)
        self.assertIn(
            "authoritative version NO_MATCH blocks this candidate",
            result["evidence_reasons"],
        )

    def test_U_parameter_cannot_override_version_mismatch(self):
        result = self._version_mismatch_with_support(parameter=True)
        self.assertEqual(result["evidence_quality"],
                         eq.LEVEL_INSUFFICIENT)

    def test_V_inferred_generic_path_cannot_be_high(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            evidence_provenance="INFERRED",
            support_scope="GLOBAL",
            path_parameter_relevance=ppr(
                path_match=True, parameter_match=True, scoped=False
            ),
        )
        self.assertNotEqual(result["evidence_quality"], eq.LEVEL_HIGH)
        self.assertIn(
            result["evidence_quality"],
            (eq.LEVEL_LOW, eq.LEVEL_INSUFFICIENT),
        )

    def test_W_explicit_version_and_scoped_path_is_high(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="HIGH",
            asset_match_state="CONFIRMED",
            matched_component="CKEditor",
            version_state="MATCH",
            version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
            evidence_provenance="EXPLICIT",
            support_scope="COMPONENT_SCOPED",
            path_parameter_relevance=ppr(path_match=True, scoped=True),
        )
        self.assertEqual(result["evidence_quality"], eq.LEVEL_HIGH)
        self.assertEqual(result["evidence_state"], eq.STATE_STRONG)
        self.assertEqual(result["evidence_strength"],
                         eq.STRENGTH_STRONG)


# ---------------------------------------------------------------------------
# X–Z: bounds, determinism, privacy
# ---------------------------------------------------------------------------


class TestBoundsDeterminismPrivacy(unittest.TestCase):
    def test_X_bounded_output(self):
        result = quality(
            strongest_match_type="PATH",
            strongest_confidence="LOW",
            asset_match_state="WEAK",
            remaining_blockers=[f"blocker_{index}" for index in range(50)],
            withheld_support=[f"withheld_{index}" for index in range(50)],
            path_parameter_relevance={
                "evidence": [
                    {"evidence_type": "AMBIGUOUS", "result": "INDETERMINATE"}
                    for _ in range(50)
                ],
                "summary": {},
            },
        )
        self.assertLessEqual(len(result["evidence_gaps"]), eq.MAX_GAPS)
        self.assertLessEqual(len(result["evidence_reasons"]), eq.MAX_REASONS)
        self.assertLessEqual(len(result["conflicts"]), eq.MAX_CONFLICTS)
        self.assertEqual(result["counts"]["gaps"], len(
            result["evidence_gaps"]
        ))

    def test_Y_deterministic_and_serializable(self):
        kwargs = {
            "strongest_match_type": "COMPONENT",
            "strongest_confidence": "HIGH",
            "asset_match_state": "CONFIRMED",
            "matched_component": "CKEditor",
            "version_state": "MATCH",
            "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
            "path_parameter_relevance": ppr(path_match=True),
            "version_normalization": vn(
                "MATCH", cve_versions=("1.2.3",),
                observed_versions=("1.2.3",),
            ),
        }
        first = json.dumps(quality(**kwargs), sort_keys=True)
        second = json.dumps(quality(**kwargs), sort_keys=True)
        self.assertEqual(first, second)

        def repeated(value):
            if isinstance(value, dict):
                return {key: repeated(item)
                        for key, item in value.items()}
            if isinstance(value, list):
                return [repeated(item) for item in value]
            return value

        self.assertEqual(
            json.loads(first), repeated(quality(**kwargs))
        )

    def test_Z_privacy_no_raw_values_copied(self):
        result = quality(
            strongest_match_type="COMPONENT",
            strongest_confidence="MEDIUM",
            asset_match_state="SUPPORTED",
            matched_component="CKEditor",
            path_parameter_relevance={
                "evidence": [{
                    "evidence_type": "EXACT_PATH",
                    "result": "MATCH",
                    "component_scoped": True,
                    "observed_path": "/download?token=SECRET",
                    "observed_parameter": "?token=SECRET",
                    "observed_method": "GET",
                }],
                "summary": {"path_match": True},
            },
        )
        blob = json.dumps(result)
        for token in ("SECRET", "token=SECRET", "?token"):
            self.assertNotIn(token, blob)

    def test_all_dimension_states_in_closed_vocabulary(self):
        result = quality()
        for name in eq.DIMENSION_ORDER:
            self.assertIn(result["dimensions"][name]["state"],
                          eq.EVIDENCE_STATES)
        self.assertIn(result["evidence_quality"],
                      eq.EVIDENCE_QUALITY_LEVELS)
        self.assertIn(result["evidence_strength"],
                      eq.EVIDENCE_STRENGTHS)
        self.assertIn(result["evidence_consistency"],
                      eq.EVIDENCE_CONSISTENCIES)


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
        self.assertEqual(item["evidence_quality_rule_version"], "r31-9")
        self.assertEqual(item["evidence_quality"]["rule_version"], "r31-9")
        self.assertIn(
            item["evidence_quality"]["evidence_quality"],
            eq.EVIDENCE_QUALITY_LEVELS,
        )

    def test_path_only_cannot_produce_high(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"]),
            components=["/wp-json/foo"],
        )
        self.assertEqual(item["strongest_match_type"], "PATH")
        self.assertEqual(
            item["evidence_quality"]["evidence_quality"],
            eq.LEVEL_INSUFFICIENT,
        )

    def test_inferred_global_only_is_low(self):
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
        self.assertEqual(item["support_scope"], "NONE")
        self.assertEqual(
            item["evidence_quality"]["evidence_quality"], eq.LEVEL_LOW
        )

    def test_explicit_version_scoped_path_is_high(self):
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
        self.assertEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(
            item["evidence_quality"]["evidence_quality"], eq.LEVEL_HIGH
        )

    def test_version_mismatch_remains_blocking(self):
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
        self.assertEqual(
            item["version_association_state"], "VERSION_OBSERVED_NO_MATCH"
        )
        self.assertEqual(
            item["evidence_quality"]["evidence_quality"],
            eq.LEVEL_INSUFFICIENT,
        )
        self.assertIn(
            "version: authoritative NO_MATCH",
            item["evidence_quality"]["evidence_gaps"],
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

    def test_privacy_in_adapter_quality_block(self):
        item = self._match(
            _projection(
                paths=["/download?token=SECRET"],
                parameters=["?token=SECRET"],
            ),
            components=["/download"],
            parameters=["token"],
        )
        blob = json.dumps(item["evidence_quality"])
        self.assertNotIn("SECRET", blob)


# ---------------------------------------------------------------------------
# Performance guard
# ---------------------------------------------------------------------------


class TestPerformanceGuard(unittest.TestCase):
    def test_quality_cost_is_bounded(self):
        candidate = {
            "strongest_match_type": "COMPONENT",
            "strongest_confidence": "HIGH",
            "asset_match_state": "CONFIRMED",
            "matched_component": "CKEditor",
            "version_state": "MATCH",
            "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
            "path_parameter_relevance": ppr(path_match=True),
            "version_normalization": vn(
                "MATCH", cve_versions=("1.2.3",),
                observed_versions=("1.2.3",),
            ),
        }
        started = time.monotonic()
        for _ in range(100):
            eq.evaluate_evidence_quality(**candidate)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
