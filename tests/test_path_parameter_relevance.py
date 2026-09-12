"""tests/test_path_parameter_relevance.py — Stage R31.8 tests.

Deterministic, offline tests for path/parameter/method relevance evidence:

- path normalization (query/fragment/repeated slashes/trailing slash)
- exact, prefix and pattern path evidence with segment boundaries
- exact parameter matching without substring collisions
- parameter sets, HTTP method evidence, missing/ambiguous inputs
- credential/value redaction and path-only evidence
- bounded, deterministic output
- component-scope compatibility with R31.5
- version evidence (R31.7) remains authoritative
- backend integration is additive and cannot promote confidence

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
from ai.knowledge import path_parameter_relevance as ppr
from ai.knowledge import version_normalization as vn
from ai.knowledge.relevance import AssetRecord
from ai.schemas.observed_inventory import inventory_id_for
from backend import asset_cve_matching as acm

CVE = "CVE-2026-1558"


def evaluate(**over):
    base = {
        "research_paths": (),
        "research_parameters": (),
        "research_methods": (),
        "observed_paths": (),
        "observed_parameters": (),
        "parameter_locations": None,
        "observed_methods": (),
        "component_scopes": (),
    }
    base.update(over)
    return ppr.evaluate_path_parameter_relevance(**base)


def rows(result, evidence_type=None):
    return [
        row for row in result["evidence"]
        if evidence_type is None or row["evidence_type"] == evidence_type
    ]


# ---------------------------------------------------------------------------
# A–H: path evidence
# ---------------------------------------------------------------------------


class TestPathRelevance(unittest.TestCase):
    def test_A_exact_path_match(self):
        result = evaluate(
            research_paths=["/wp-json/wp-responsive-images/v1/config"],
            observed_paths=["/wp-json/wp-responsive-images/v1/config"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["resolution_method"], ppr.METHOD_EXACT)
        self.assertEqual(result["summary"]["path_match"], True)

    def test_B_exact_path_mismatch(self):
        result = evaluate(
            research_paths=["/wp-json/wp-responsive-images/v1/config"],
            observed_paths=["/wp-json/other/v1/config"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)
        self.assertEqual(result["summary"]["result"],
                         ppr.COMPARISON_NO_MATCH)

    def test_C_segment_boundary_protection(self):
        result = evaluate(
            research_paths=["/foo"],
            observed_paths=["/notfoo/bar", "/foobar", "/foo/bar"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)

    def test_C_segment_boundary_prefix_is_not_substring(self):
        result = evaluate(
            research_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foobar", "/wp-json/foo/bar"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)

    def test_D_trailing_slash_normalization(self):
        for observed in (
            "/wp-json/foo",
            "/wp-json/foo/",
            "/wp-json//foo",
        ):
            with self.subTest(observed=observed):
                result = evaluate(
                    research_paths=["/wp-json/foo"],
                    observed_paths=[observed],
                )
                row = rows(result, ppr.ET_EXACT_PATH)[0]
                self.assertEqual(row["result"], ppr.COMPARISON_MATCH)

    def test_E_query_string_removal(self):
        result = evaluate(
            research_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foo?x=1&y=2"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertNotIn("?", row["observed_path"])
        self.assertNotIn("x=1", row["observed_path"])

    def test_F_fragment_removal(self):
        result = evaluate(
            research_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foo#section"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertNotIn("#", row["observed_path"])

    def test_G_exact_research_path_has_no_prefix_semantics(self):
        result = evaluate(
            research_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foo/bar"],
        )
        self.assertEqual(
            rows(result, ppr.ET_EXACT_PATH)[0]["result"],
            ppr.COMPARISON_NO_MATCH,
        )
        self.assertEqual(result["summary"]["path_match"], False)

    def test_G_explicit_subtree_prefix(self):
        result = evaluate(
            research_paths=["/wp-json/foo/"],
            observed_paths=["/wp-json/foo/bar"],
        )
        row = rows(result, ppr.ET_PATH_PREFIX)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["resolution_method"], ppr.METHOD_PREFIX)

    def test_G_explicit_pattern_subtree(self):
        result = evaluate(
            research_paths=["/wp-json/foo/*"],
            observed_paths=["/wp-json/foo/bar/baz"],
        )
        row = rows(result, ppr.ET_PATH_PATTERN)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["resolution_method"], ppr.METHOD_PATTERN)

    def test_G_explicit_subtree_no_observed(self):
        result = evaluate(
            research_paths=["/wp-json/foo/"],
            observed_paths=["/api/users"],
        )
        row = rows(result, ppr.ET_PATH_PREFIX)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)

    def test_H_unsupported_path_prose_is_unknown(self):
        result = evaluate(
            research_paths=["/wp-json/{id}/config", "see the docs"],
            observed_paths=["/wp-json/1/config"],
        )
        for row in result["evidence"]:
            self.assertEqual(row["result"], ppr.COMPARISON_INDETERMINATE)
            self.assertIn(
                row["evidence_type"], (ppr.ET_AMBIGUOUS, ppr.ET_UNKNOWN)
            )

    def test_H_empty_research_path_is_skipped(self):
        result = evaluate(research_paths=["", None], observed_paths=["/x"])
        self.assertEqual(rows(result, ppr.ET_UNKNOWN), [])


# ---------------------------------------------------------------------------
# I–L: parameter evidence
# ---------------------------------------------------------------------------


class TestParameterRelevance(unittest.TestCase):
    def test_I_exact_parameter_match(self):
        result = evaluate(
            research_parameters=["file"],
            observed_parameters=["file"],
        )
        row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["resolution_method"], ppr.METHOD_PARAMETER_EXACT)
        self.assertTrue(result["summary"]["parameter_match"])

    def test_I_parameter_name_extracted_from_value_pair(self):
        result = evaluate(
            research_parameters=["file"],
            observed_parameters=["?file=abc.txt"],
        )
        row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["observed_parameter"], "file")

    def test_J_parameter_mismatch(self):
        result = evaluate(
            research_parameters=["file"],
            observed_parameters=["src"],
        )
        row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)

    def test_K_parameter_substring_collision_protection(self):
        for observed in ("filename", "profile", "file_id"):
            with self.subTest(observed=observed):
                result = evaluate(
                    research_parameters=["file"],
                    observed_parameters=[observed],
                )
                row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
                self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)

    def test_K_explicitly_listed_equivalent_name_matches(self):
        # The research explicitly lists the name; separator normalization is
        # the existing project convention.
        result = evaluate(
            research_parameters=["file-id"],
            observed_parameters=["file_id"],
        )
        row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)

    def test_L_multiple_parameters_set_evidence(self):
        result = evaluate(
            research_parameters=["file", "src"],
            observed_parameters=["src"],
        )
        set_rows = rows(result, ppr.ET_PARAMETER_SET)
        self.assertEqual(len(set_rows), 1)
        self.assertEqual(set_rows[0]["result"], ppr.COMPARISON_MATCH)
        # One exact MATCH ('src') plus the PARAMETER_SET MATCH row.
        self.assertEqual(
            result["summary"]["counts"][ppr.COMPARISON_MATCH], 2
        )
        mismatches = rows(result, ppr.ET_EXACT_PARAMETER)
        results = {row["research_parameter"]: row["result"]
                   for row in mismatches}
        self.assertEqual(results["file"], ppr.COMPARISON_NO_MATCH)
        self.assertEqual(results["src"], ppr.COMPARISON_MATCH)


# ---------------------------------------------------------------------------
# M–O: HTTP method evidence
# ---------------------------------------------------------------------------


class TestMethodRelevance(unittest.TestCase):
    def test_M_method_match(self):
        result = evaluate(
            research_methods=["GET"],
            observed_methods=["get"],
        )
        row = rows(result, ppr.ET_HTTP_METHOD)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["resolution_method"], ppr.METHOD_METHOD_EXACT)
        self.assertEqual(result["summary"]["method"]["result"],
                         ppr.COMPARISON_MATCH)

    def test_N_method_mismatch(self):
        result = evaluate(
            research_methods=["POST"],
            observed_methods=["GET"],
        )
        row = rows(result, ppr.ET_HTTP_METHOD)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_NO_MATCH)
        self.assertEqual(result["summary"]["method"]["result"],
                         ppr.COMPARISON_NO_MATCH)

    def test_O_missing_research_method_is_no_evidence(self):
        result = evaluate(research_methods=[])
        method = result["summary"]["method"]
        self.assertEqual(method["evidence_type"], ppr.ET_NO_EVIDENCE)
        self.assertEqual(method["result"], ppr.COMPARISON_INDETERMINATE)
        self.assertEqual(rows(result, ppr.ET_HTTP_METHOD), [])

    def test_O_research_method_without_observed_methods(self):
        result = evaluate(research_methods=["GET"])
        method = result["summary"]["method"]
        self.assertEqual(method["evidence_type"], ppr.ET_HTTP_METHOD)
        self.assertEqual(method["result"], ppr.COMPARISON_INDETERMINATE)
        self.assertEqual(rows(result, ppr.ET_HTTP_METHOD), [])


# ---------------------------------------------------------------------------
# P–R: privacy and robustness
# ---------------------------------------------------------------------------


class TestPrivacyAndRobustness(unittest.TestCase):
    def test_P_sensitive_query_values_are_redacted(self):
        result = evaluate(
            research_paths=["/download"],
            research_parameters=["file"],
            observed_paths=["/download?token=SECRET&file=x"],
            observed_parameters=["?token=SECRET"],
        )
        blob = json.dumps(result)
        for token in ("SECRET", "token=SECRET"):
            self.assertNotIn(token, blob)
        self.assertIn("/download", blob)

    def test_Q_authorization_and_userinfo_redaction(self):
        result = evaluate(
            research_paths=["https://user:pass@example.com/admin"],
            research_parameters=["Authorization: Bearer abc123"],
            observed_paths=["https://user:pass@example.com/admin"],
            observed_parameters=["Authorization: Bearer abc123"],
        )
        blob = json.dumps(result)
        for token in ("pass", "abc123", "Bearer abc123", "user:pass"):
            self.assertNotIn(token, blob)

    def test_Q_secret_like_parameter_name_only_is_kept(self):
        result = evaluate(
            research_parameters=["api_key"],
            observed_parameters=["?api_key=SUPERSECRET"],
        )
        row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
        self.assertEqual(row["result"], ppr.COMPARISON_MATCH)
        self.assertEqual(row["observed_parameter"], "api_key")
        self.assertNotIn("SUPERSECRET", json.dumps(result))

    def test_R_empty_inputs(self):
        result = evaluate()
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["summary"]["result"],
                         ppr.STATE_NO_EVIDENCE)
        self.assertEqual(result["summary"]["counts"]["rows"], 0)
        self.assertEqual(result["rule_version"], "r31-8")

    def test_R_none_inputs(self):
        result = ppr.evaluate_path_parameter_relevance(
            research_paths=None,
            research_parameters=None,
            observed_paths=None,
            observed_parameters=None,
        )
        self.assertEqual(result["summary"]["result"],
                         ppr.STATE_NO_EVIDENCE)

    def test_S_malformed_paths_fail_soft(self):
        result = evaluate(
            research_paths=[123, "///", "\n/x", "/x?q=1", "/x#f"],
            observed_paths=[object(), "", "////", "/x"],
        )
        self.assertIn(
            result["summary"]["result"],
            (ppr.COMPARISON_MATCH, ppr.COMPARISON_INDETERMINATE),
        )
        json.dumps(result)

    def test_T_bounded_evidence_output(self):
        result = evaluate(
            research_paths=[f"/p{i}" for i in range(200)],
            research_parameters=[f"p{i}" for i in range(200)],
            observed_paths=["/p1", "/p2"],
            observed_parameters=["p1", "p2"],
            max_evidence=16,
        )
        self.assertLessEqual(len(result["evidence"]), 16)
        for row in result["evidence"]:
            self.assertLessEqual(len(row["reason"]), ppr.MAX_VALUE_LEN)

    def test_determinism_under_input_permutation(self):
        first = evaluate(
            research_paths=["/a", "/b"],
            research_parameters=["x", "y"],
            observed_paths=["/b", "/a"],
            observed_parameters=["y", "x"],
        )
        second = evaluate(
            research_paths=["/b", "/a"],
            research_parameters=["y", "x"],
            observed_paths=["/a", "/b"],
            observed_parameters=["x", "y"],
        )
        self.assertEqual(first["evidence"], second["evidence"])
        self.assertEqual(first["summary"], second["summary"])


# ---------------------------------------------------------------------------
# U: component scope compatibility
# ---------------------------------------------------------------------------


class TestComponentScope(unittest.TestCase):
    def test_U_component_scoped_evidence(self):
        result = evaluate(
            research_paths=["/assets/ckeditor/config.js"],
            research_parameters=["file"],
            observed_paths=["/assets/ckeditor/config.js"],
            observed_parameters=["file"],
            parameter_locations={"file": ["/assets/ckeditor/config.js"]},
            component_scopes=["/assets/ckeditor/"],
        )
        path_row = rows(result, ppr.ET_EXACT_PATH)[0]
        param_row = rows(result, ppr.ET_EXACT_PARAMETER)[0]
        self.assertTrue(path_row["component_scoped"])
        self.assertTrue(param_row["component_scoped"])
        self.assertTrue(result["summary"]["component_scoped"])

    def test_U_generic_path_is_not_component_scoped(self):
        result = evaluate(
            research_paths=["/api/users"],
            observed_paths=["/api/users"],
            component_scopes=["/assets/ckeditor/"],
        )
        row = rows(result, ppr.ET_EXACT_PATH)[0]
        self.assertFalse(row["component_scoped"])
        self.assertFalse(result["summary"]["component_scoped"])


# ---------------------------------------------------------------------------
# Backend integration (hermetic; no live Mongo)
# ---------------------------------------------------------------------------


def _projection(
    *,
    paths=(),
    parameters=(),
    parameter_paths=(),
    components=(),
    provenance=(),
    versions=(),
):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": list(components),
        "plugins": [],
        "versions": [
            {
                "value": version,
                "source": "TECHNOLOGY_INVENTORY",
                "evidence_type": "STRUCTURED_TECHNOLOGY",
            }
            for version in versions
        ],
        "version_associations": [],
        "parameters": [
            {
                "value": parameter,
                "source": "PARAMETER_INVENTORY",
                "evidence_type": "STRUCTURED_PARAMETER",
            }
            for parameter in parameters
        ],
        "paths": [
            {
                "value": path,
                "source": "ENDPOINT_INVENTORY",
                "evidence_type": "STRUCTURED_ENDPOINT",
            }
            for path in paths
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

    def test_X_additive_fields_present(self):
        item = self._match(
            _projection(
                paths=["/wp-json/wp-responsive-images/v1/config"],
                parameters=["file"],
                parameter_paths=[
                    {"parameter": "file",
                     "path": "/wp-json/wp-responsive-images/v1/config",
                     "source": "PARAMETER_INVENTORY"}
                ],
            ),
            components=["/wp-json/wp-responsive-images/v1/config"],
            parameters=["file"],
        )
        self.assertEqual(
            item["path_parameter_relevance_rule_version"], "r31-8"
        )
        relevance = item["path_parameter_relevance"]
        self.assertEqual(relevance["rule_version"], "r31-8")
        self.assertTrue(relevance["summary"]["path_match"])
        self.assertTrue(relevance["summary"]["parameter_match"])

    def test_X_engine_fields_unchanged(self):
        item = self._match(
            _projection(
                paths=["/wp-json/wp-responsive-images/v1/config"],
                parameters=["file"],
            ),
            components=["/wp-json/wp-responsive-images/v1/config"],
            parameters=["file"],
        )
        engine = acm_engine.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            cve_components=["/wp-json/wp-responsive-images/v1/config"],
            cve_parameters=["file"],
            observed_paths=["/wp-json/wp-responsive-images/v1/config"],
            observed_parameters=["file"],
        )
        for field in (
            "strongest_match_type",
            "strongest_confidence",
            "asset_match_state",
            "remaining_blockers",
            "version_state",
        ):
            self.assertEqual(item[field], engine[field], field)

    def test_U_adapter_scope_preserved_for_inferred_component(self):
        item = self._match(
            _projection(
                paths=["/assets/ckeditor/config.js", "/api/users"],
                components=[
                    {"value": "CKEditor",
                     "source": "COMPONENT_INVENTORY",
                     "evidence_type": "INFERRED_COMPONENT"}
                ],
                provenance=[
                    {"value": "CKEditor", "category": "COMPONENT",
                     "evidence_type": "INFERRED_COMPONENT",
                     "evidence_path": "/assets/ckeditor/ckeditor.js",
                     "scope_path": "/assets/ckeditor/",
                     "rule_id": "ckeditor",
                     "source": "COMPONENT_INVENTORY"}
                ],
            ),
            components=["CKEditor", "/assets/ckeditor/config.js"],
        )
        relevance = item["path_parameter_relevance"]
        path_rows = [
            row for row in relevance["evidence"]
            if row["evidence_type"] == ppr.ET_EXACT_PATH
        ]
        self.assertTrue(path_rows)
        self.assertTrue(all(row["component_scoped"] for row in path_rows))
        # The unrelated /api/users path is withheld by R31.5 gating and must
        # not appear as path evidence.
        self.assertFalse(
            any(row["observed_path"] == "/api/users"
                for row in relevance["evidence"])
        )
        self.assertEqual(item["support_scope"], "COMPONENT_SCOPED")

    def test_V_version_no_match_remains_authoritative(self):
        item = self._match(
            _projection(
                paths=["/wp-json/foo"],
                versions=["1.1"],
            ),
            components=["/wp-json/foo"],
            versions=["<=1.0"],
        )
        # R31.7 parsing and R30.3 association both report NO_MATCH; the
        # R31.8 path match does not rewrite the version dimension.
        self.assertEqual(
            vn.matches_constraint("1.1", "<=1.0"),
            vn.COMPARISON_NO_MATCH,
        )
        self.assertEqual(
            item["version_association_state"],
            "VERSION_OBSERVED_NO_MATCH",
        )
        self.assertTrue(
            item["path_parameter_relevance"]["summary"]["path_match"]
        )
        # Engine-visible fields match a direct engine call with the exact
        # inputs the adapter supplies (observed versions withheld by R30.3).
        engine = acm_engine.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            cve_components=["/wp-json/foo"],
            cve_versions=["<=1.0"],
            cve_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foo"],
        )
        for field in (
            "version_state",
            "strongest_match_type",
            "strongest_confidence",
            "asset_match_state",
        ):
            self.assertEqual(item[field], engine[field], field)

    def test_W_version_indeterminate_stays_indeterminate(self):
        item = self._match(
            _projection(paths=["/wp-json/foo"], versions=["1.2"]),
            components=["/wp-json/foo"],
            versions=["latest"],
        )
        relevance = item["path_parameter_relevance"]
        self.assertTrue(relevance["summary"]["path_match"])
        version_row = item["version_normalization"]["rows"][0]
        self.assertEqual(version_row["comparison"], "INDETERMINATE")
        self.assertEqual(item["version_state"], "UNKNOWN")
        engine = acm_engine.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            cve_components=["/wp-json/foo"],
            cve_versions=["latest"],
            cve_paths=["/wp-json/foo"],
            observed_paths=["/wp-json/foo"],
        )
        for field in (
            "version_state",
            "strongest_match_type",
            "strongest_confidence",
            "asset_match_state",
        ):
            self.assertEqual(item[field], engine[field], field)

    def test_P_adapter_relevance_evidence_has_no_secret_values(self):
        item = self._match(
            _projection(
                paths=["/download?token=SECRET"],
                parameters=["?token=SECRET"],
            ),
            components=["/download"],
            parameters=["token"],
        )
        # R31.8 evidence is path/name-only and value-free.
        relevance = json.dumps(item["path_parameter_relevance"])
        self.assertNotIn("SECRET", relevance)
        self.assertIn("/download", relevance)
        parameter_rows = [
            row for row in item["path_parameter_relevance"]["evidence"]
            if row["evidence_type"] == ppr.ET_EXACT_PARAMETER
        ]
        self.assertEqual(parameter_rows[0]["observed_parameter"], "token")
        # NOTE: legacy R30.1 fields are untouched by this stage; the
        # inventory collector already stores parameter names without values.


# ---------------------------------------------------------------------------
# Performance guard (representative scale; no timing assertion)
# ---------------------------------------------------------------------------


class TestPerformanceGuard(unittest.TestCase):
    def test_large_observed_corpus_is_linear_enough(self):
        observed_paths = [f"/svc/{i:06d}/item" for i in range(25000)]
        observed_paths += ["/wp-json/wp-responsive-images/v1/config"]
        observed_parameters = [f"p{i}" for i in range(1000)]
        observed_parameters += ["file"]
        research_paths = [
            "/wp-json/wp-responsive-images/v1/config",
            "/missing/path",
            "/other/route/",
        ]
        research_parameters = ["file", "missing"] + [
            f"p{i}" for i in range(10)
        ]
        started = time.monotonic()
        result = evaluate(
            research_paths=research_paths,
            research_parameters=research_parameters,
            research_methods=["GET"],
            observed_paths=observed_paths,
            observed_parameters=observed_parameters,
            parameter_locations={"file": [
                "/wp-json/wp-responsive-images/v1/config"
            ]},
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result["summary"]["result"],
                         ppr.COMPARISON_MATCH)
        self.assertLessEqual(
            len(result["evidence"]), ppr.MAX_EVIDENCE_ROWS
        )
        # Generous guard against accidental quadratic behavior.
        self.assertLess(elapsed, 20.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
