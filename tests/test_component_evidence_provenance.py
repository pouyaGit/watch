"""tests/test_component_evidence_provenance.py — Stage R31.5 tests.

Deterministic, offline tests for component/plugin evidence provenance and
component-scoped support:

- structured provenance propagation (evidence path + owning scope + rule id)
- path-only privacy guarantees
- inferred-only evidence cannot be promoted by unrelated global parameters
- explicit evidence keeps the existing R30.1 behavior
- component-scoped support may promote
- unrelated support does not promote
- MIXED evidence (explicit + inferred) keeps explicit semantics
- multiple inferred components stay isolated
- determinism under input permutation
- fail-soft malformed provenance
- bounded provenance

Mongo is mocked at the raw-document boundary or at
``backend.observed_inventory.get_inventory``; no network, no DNS, no LLM, no
subprocess, no target interaction, no persistence. The R30.1 engine is not
modified; this module never imports it for mutation.
"""
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import component_inference as ci
from ai.knowledge.relevance import AssetRecord
from ai.schemas.observed_inventory import (
    EVIDENCE_PROVENANCE_RULE_VERSION,
    ObservedAssetInventory,
    ObservedParameterPath,
    ObservedProvenance,
    inventory_id_for,
)
from backend import asset_cve_matching as acm
from backend import observed_inventory as backend_oi

CVE = "CVE-2026-9999"

_CKEDITOR_SCOPE = "/assets/ckeditor/"
_TINYMCE_SCOPE = "/assets/tinymce/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _item(value, source, evidence_type):
    return {"value": value, "source": source, "evidence_type": evidence_type}


def _prov(value, *, category="COMPONENT",
          evidence_type="INFERRED_COMPONENT", path, scope, rule_id):
    return {
        "value": value,
        "category": category,
        "evidence_type": evidence_type,
        "evidence_path": path,
        "scope_path": scope,
        "rule_id": rule_id,
        "source": "COMPONENT_INVENTORY",
    }


def _param_path(parameter, path):
    return {
        "parameter": parameter,
        "path": path,
        "source": "PARAMETER_INVENTORY",
    }


def _projection(
    *,
    component_items=(),
    plugin_items=(),
    component_provenance=(),
    parameter_paths=(),
    parameters=(),
    paths=(),
    technologies=(),
    versions=(),
):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": list(technologies),
        "products": [],
        "components": list(component_items),
        "plugins": list(plugin_items),
        "versions": list(versions),
        "version_associations": [],
        "parameters": list(parameters),
        "paths": list(paths),
        "component_provenance": list(component_provenance),
        "parameter_paths": list(parameter_paths),
        "sources": ["COMPONENT_INVENTORY"],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(cve_components=("CKEditor",), cve_parameters=("src",)):
    document = SimpleNamespace(
        components=list(cve_components),
        parameters=list(cve_parameters),
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": [], "affected_versions": []},
        "research": {},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class _ProvenanceTestCase(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()
        backend_oi.clear_cache()

    def tearDown(self):
        acm.clear_cache()
        backend_oi.clear_cache()

    def _match(self, inventory, *, cve_components=("CKEditor",),
               cve_parameters=("src",), program="dell"):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=inventory,
        ), mock.patch.object(
            acm, "_contexts",
            return_value=_contexts(cve_components, cve_parameters),
        ):
            return acm.build_matches(cve=CVE, program=program)["items"][0]


# ---------------------------------------------------------------------------
# Test 1 — provenance propagation (through the real backend read path)
# ---------------------------------------------------------------------------


class TestProvenancePropagation(_ProvenanceTestCase):
    DOCUMENTS = {
        "subdomains": [
            {
                "_id": "s1",
                "program_name": "dell",
                "subdomain": "a.dell.com",
                "scope": "dell.com",
                "providers": [],
            }
        ],
        "http": [],
        "urls": [
            {
                "_id": "u1",
                "program_name": "dell",
                "subdomain": "a.dell.com",
                "path": "/assets/ckeditor/ckeditor.js",
            }
        ],
        "endpoints": [
            {
                "_id": "e1",
                "program_name": "dell",
                "subdomain": "a.dell.com",
                "path": "/assets/ckeditor/config.js",
                "params": ["src"],
            }
        ],
    }

    def test_inferred_component_retains_structured_provenance(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=self.DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            inventory = backend_oi.get_inventory("dell")
        self.assertEqual(
            [item["value"] for item in inventory["components"]],
            ["CKEditor"],
        )
        provenance = inventory["component_provenance"]
        self.assertEqual(len(provenance), 1)
        entry = provenance[0]
        self.assertEqual(entry["value"], "CKEditor")
        self.assertEqual(entry["category"], "COMPONENT")
        self.assertEqual(entry["evidence_type"], "INFERRED_COMPONENT")
        self.assertEqual(
            entry["evidence_path"], "/assets/ckeditor/ckeditor.js"
        )
        self.assertEqual(entry["scope_path"], "/assets/ckeditor/")
        self.assertEqual(entry["rule_id"], "ckeditor")
        self.assertEqual(
            inventory["generated_from"].get(
                "evidence_provenance_rule_version"
            ),
            EVIDENCE_PROVENANCE_RULE_VERSION,
        )

    def test_parameter_path_linkage_emitted(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=self.DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            inventory = backend_oi.get_inventory("dell")
        pairs = [
            (item["parameter"], item["path"])
            for item in inventory["parameter_paths"]
        ]
        self.assertIn(("src", "/assets/ckeditor/config.js"), pairs)


# ---------------------------------------------------------------------------
# Test 2 — privacy (path-only)
# ---------------------------------------------------------------------------


class TestProvenancePrivacy(unittest.TestCase):
    def test_full_url_input_becomes_path_only(self):
        out = ci.infer_inventory_items(url_records=[
            {"url": "https://example.com/assets/ckeditor/ckeditor.js"},
        ])
        self.assertEqual(len(out["provenance"]), 1)
        entry = out["provenance"][0]
        self.assertEqual(
            entry["evidence_path"], "/assets/ckeditor/ckeditor.js"
        )
        self.assertEqual(entry["scope_path"], "/assets/ckeditor/")
        for field in ("evidence_path", "scope_path"):
            self.assertNotIn("://", entry[field])
            self.assertNotIn("example.com", entry[field])

    def test_schema_sanitizes_paths(self):
        entry = ObservedProvenance(
            value="CKEditor",
            category="COMPONENT",
            evidence_type="INFERRED_COMPONENT",
            evidence_path="https://example.com/assets/ckeditor/x.js?a=1#b",
            scope_path="//host/assets/ckeditor/?q=1",
            rule_id="ckeditor",
        )
        self.assertEqual(entry.evidence_path, "/assets/ckeditor/x.js")
        self.assertEqual(entry.scope_path, "/assets/ckeditor/")
        pair = ObservedParameterPath(
            parameter="src", path="http://10.0.0.1/api/users?x=1"
        )
        self.assertEqual(pair.path, "/api/users")


# ---------------------------------------------------------------------------
# Test 3 — false-positive regression (inferred + unrelated global parameter)
# ---------------------------------------------------------------------------


class TestInferredFalsePositiveGate(_ProvenanceTestCase):
    def _inferred_projection(self, *, support_path, include_scoped_path):
        paths = [_item("/api/users", "ENDPOINT_INVENTORY",
                       "STRUCTURED_ENDPOINT")]
        if include_scoped_path:
            paths.append(
                _item("/assets/ckeditor/config.js", "ENDPOINT_INVENTORY",
                      "STRUCTURED_ENDPOINT")
            )
        return _projection(
            component_items=[
                _item("CKEditor", "COMPONENT_INVENTORY",
                      "INFERRED_COMPONENT")
            ],
            component_provenance=[
                _prov(
                    "CKEditor",
                    path="/assets/ckeditor/ckeditor.js",
                    scope=_CKEDITOR_SCOPE,
                    rule_id="ckeditor",
                )
            ],
            parameter_paths=[_param_path("src", support_path)],
            parameters=[
                _item("src", "PARAMETER_INVENTORY",
                      "STRUCTURED_PARAMETER")
            ],
            paths=paths,
        )

    def test_unrelated_global_parameter_does_not_promote(self):
        item = self._match(
            self._inferred_projection(
                support_path="/api/users", include_scoped_path=False
            )
        )
        self.assertEqual(item["evidence_provenance"], "INFERRED")
        self.assertNotEqual(item["support_scope"], "COMPONENT_SCOPED")
        self.assertNotEqual(item["strongest_confidence"], "HIGH")
        self.assertNotEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(item["strongest_match_type"], "COMPONENT")
        self.assertTrue(
            any("src" in line for line in item["withheld_support"])
        )

    def test_scoped_parameter_promotes(self):
        item = self._match(
            self._inferred_projection(
                support_path="/assets/ckeditor/config.js",
                include_scoped_path=True,
            )
        )
        self.assertEqual(item["evidence_provenance"], "INFERRED")
        self.assertEqual(item["support_scope"], "COMPONENT_SCOPED")
        self.assertEqual(item["strongest_confidence"], "HIGH")
        self.assertEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(item["withheld_support"], [])


# ---------------------------------------------------------------------------
# Test 4 — explicit compatibility
# ---------------------------------------------------------------------------


class TestExplicitCompatibility(_ProvenanceTestCase):
    def _explicit_projection(self):
        return _projection(
            component_items=[
                _item("CKEditor", "COMPONENT_INVENTORY",
                      "STRUCTURED_COMPONENT")
            ],
            parameter_paths=[_param_path("src", "/api/users")],
            parameters=[
                _item("src", "PARAMETER_INVENTORY",
                      "STRUCTURED_PARAMETER")
            ],
            paths=[_item("/api/users", "ENDPOINT_INVENTORY",
                         "STRUCTURED_ENDPOINT")],
        )

    def test_explicit_component_keeps_high_confirmed(self):
        item = self._match(self._explicit_projection())
        self.assertEqual(item["evidence_provenance"], "EXPLICIT")
        self.assertEqual(item["support_scope"], "GLOBAL")
        self.assertEqual(item["strongest_confidence"], "HIGH")
        self.assertEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(item["withheld_support"], [])


# ---------------------------------------------------------------------------
# Test 7 — mixed evidence
# ---------------------------------------------------------------------------


class TestMixedEvidence(_ProvenanceTestCase):
    def test_explicit_plus_inferred_is_mixed_and_explicit_wins(self):
        projection = _projection(
            component_items=[
                _item("CKEditor", "COMPONENT_INVENTORY",
                      "STRUCTURED_COMPONENT")
            ],
            component_provenance=[
                _prov(
                    "CKEditor",
                    path="/assets/ckeditor/ckeditor.js",
                    scope=_CKEDITOR_SCOPE,
                    rule_id="ckeditor",
                )
            ],
            parameter_paths=[_param_path("src", "/api/users")],
            parameters=[
                _item("src", "PARAMETER_INVENTORY",
                      "STRUCTURED_PARAMETER")
            ],
            paths=[_item("/api/users", "ENDPOINT_INVENTORY",
                         "STRUCTURED_ENDPOINT")],
        )
        item = self._match(projection)
        self.assertEqual(item["evidence_provenance"], "MIXED")
        self.assertEqual(item["support_scope"], "GLOBAL")
        self.assertEqual(item["strongest_confidence"], "HIGH")
        self.assertEqual(item["asset_match_state"], "CONFIRMED")
        self.assertEqual(item["withheld_support"], [])


# ---------------------------------------------------------------------------
# Test 6 — unrelated support
# ---------------------------------------------------------------------------


class TestUnrelatedSupport(_ProvenanceTestCase):
    def test_unrelated_path_and_parameter_are_withheld(self):
        projection = _projection(
            component_items=[
                _item("CKEditor", "COMPONENT_INVENTORY",
                      "INFERRED_COMPONENT")
            ],
            component_provenance=[
                _prov(
                    "CKEditor",
                    path="/assets/ckeditor/ckeditor.js",
                    scope=_CKEDITOR_SCOPE,
                    rule_id="ckeditor",
                )
            ],
            parameter_paths=[_param_path("src", "/api/users")],
            parameters=[
                _item("src", "PARAMETER_INVENTORY",
                      "STRUCTURED_PARAMETER")
            ],
            paths=[_item("/api/users", "ENDPOINT_INVENTORY",
                         "STRUCTURED_ENDPOINT")],
        )
        item = self._match(projection)
        self.assertNotEqual(item["support_scope"], "COMPONENT_SCOPED")
        self.assertNotEqual(item["strongest_confidence"], "HIGH")
        self.assertNotEqual(item["asset_match_state"], "CONFIRMED")
        self.assertTrue(item["withheld_support"])


# ---------------------------------------------------------------------------
# Test 9 — multiple inferred components stay isolated
# ---------------------------------------------------------------------------


class TestMultipleInferredComponents(_ProvenanceTestCase):
    def _projection(self):
        return _projection(
            component_items=[
                _item("CKEditor", "COMPONENT_INVENTORY",
                      "INFERRED_COMPONENT"),
                _item("TinyMCE", "COMPONENT_INVENTORY",
                      "INFERRED_COMPONENT"),
            ],
            component_provenance=[
                _prov(
                    "CKEditor",
                    path="/assets/ckeditor/ckeditor.js",
                    scope=_CKEDITOR_SCOPE,
                    rule_id="ckeditor",
                ),
                _prov(
                    "TinyMCE",
                    path="/assets/tinymce/tinymce.js",
                    scope=_TINYMCE_SCOPE,
                    rule_id="tinymce",
                ),
            ],
            parameter_paths=[_param_path("src", "/assets/ckeditor/config.js")],
            parameters=[
                _item("src", "PARAMETER_INVENTORY",
                      "STRUCTURED_PARAMETER")
            ],
            paths=[
                _item("/assets/ckeditor/config.js", "ENDPOINT_INVENTORY",
                      "STRUCTURED_ENDPOINT")
            ],
        )

    def test_ckedtor_scoped_parameter_does_not_support_tinymce(self):
        item = self._match(self._projection(), cve_components=("TinyMCE",))
        self.assertEqual(item["evidence_provenance"], "INFERRED")
        self.assertNotEqual(item["strongest_confidence"], "HIGH")
        self.assertNotEqual(item["asset_match_state"], "CONFIRMED")
        self.assertTrue(
            any("src" in line for line in item["withheld_support"])
        )

    def test_ckedtor_scoped_parameter_supports_ckeditor(self):
        item = self._match(self._projection(), cve_components=("CKEditor",))
        self.assertEqual(item["support_scope"], "COMPONENT_SCOPED")
        self.assertEqual(item["strongest_confidence"], "HIGH")
        self.assertEqual(item["asset_match_state"], "CONFIRMED")


# ---------------------------------------------------------------------------
# Test 8 — determinism
# ---------------------------------------------------------------------------


class TestDeterminism(_ProvenanceTestCase):
    def _projection(self, reverse=False):
        components = [
            _item("CKEditor", "COMPONENT_INVENTORY", "INFERRED_COMPONENT"),
            _item("TinyMCE", "COMPONENT_INVENTORY", "INFERRED_COMPONENT"),
        ]
        provenance = [
            _prov("CKEditor", path="/assets/ckeditor/ckeditor.js",
                  scope=_CKEDITOR_SCOPE, rule_id="ckeditor"),
            _prov("TinyMCE", path="/assets/tinymce/tinymce.js",
                  scope=_TINYMCE_SCOPE, rule_id="tinymce"),
        ]
        parameters = [
            _item("src", "PARAMETER_INVENTORY", "STRUCTURED_PARAMETER"),
            _item("id", "PARAMETER_INVENTORY", "STRUCTURED_PARAMETER"),
        ]
        paths = [
            _item("/assets/ckeditor/config.js", "ENDPOINT_INVENTORY",
                  "STRUCTURED_ENDPOINT"),
            _item("/assets/tinymce/tinymce.js", "ENDPOINT_INVENTORY",
                  "STRUCTURED_ENDPOINT"),
        ]
        parameter_paths = [
            _param_path("src", "/assets/ckeditor/config.js"),
            _param_path("id", "/assets/tinymce/tinymce.js"),
        ]
        if reverse:
            components.reverse()
            provenance.reverse()
            parameters.reverse()
            paths.reverse()
            parameter_paths.reverse()
        return _projection(
            component_items=components,
            component_provenance=provenance,
            parameters=parameters,
            paths=paths,
            parameter_paths=parameter_paths,
        )

    def test_input_order_does_not_change_output(self):
        first = self._match(
            self._projection(), cve_components=("CKEditor", "TinyMCE")
        )
        second = self._match(
            self._projection(reverse=True),
            cve_components=("CKEditor", "TinyMCE"),
        )
        for field in (
            "strongest_match_type",
            "strongest_confidence",
            "asset_match_state",
            "evidence_provenance",
            "support_scope",
            "withheld_support",
            "evidence_provenance_rule_version",
        ):
            self.assertEqual(first[field], second[field], field)


# ---------------------------------------------------------------------------
# Test 10 — fail-soft malformed provenance
# ---------------------------------------------------------------------------


class TestFailSoft(_ProvenanceTestCase):
    def _malformed_projection(self):
        projection = _projection(
            technologies=[
                _item("WordPress", "TECHNOLOGY_INVENTORY",
                      "STRUCTURED_TECHNOLOGY")
            ],
            versions=[
                _item("6.8.3", "TECHNOLOGY_INVENTORY",
                      "STRUCTURED_TECHNOLOGY")
            ],
            parameters=[
                _item("src", "PARAMETER_INVENTORY",
                      "STRUCTURED_PARAMETER")
            ],
            paths=[_item("/x", "ENDPOINT_INVENTORY",
                         "STRUCTURED_ENDPOINT")],
        )
        projection["component_provenance"] = [
            None,
            {},
            "not-a-record",
            {"value": None, "category": "COMPONENT"},
            {"value": "x", "category": "BOGUS",
             "evidence_type": "INFERRED_COMPONENT",
             "evidence_path": "/x", "scope_path": "/x"},
            {"value": "CKEditor", "category": "COMPONENT",
             "evidence_type": "INFERRED_COMPONENT",
             "evidence_path": 12345, "scope_path": None, "rule_id": None},
        ]
        projection["parameter_paths"] = [
            None, {}, 42, {"parameter": None, "path": None},
            {"parameter": "src", "path": "http://example.com/a?b=1"},
        ]
        return projection

    def test_malformed_provenance_does_not_crash(self):
        item = self._match(self._malformed_projection())
        self.assertIn(
            item["evidence_provenance"],
            ("EXPLICIT", "INFERRED", "MIXED"),
        )
        self.assertIn(
            item["support_scope"], ("COMPONENT_SCOPED", "GLOBAL", "NONE")
        )

    def test_existing_categories_remain_intact(self):
        projection = self._malformed_projection()
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=projection,
        ):
            values = acm._inventory_values("dell")
        self.assertEqual(
            [v["value"] for v in projection["technologies"]],
            ["WordPress"],
        )
        self.assertEqual(values["technologies"], ["WordPress"])
        self.assertEqual(values["versions"], ["6.8.3"])
        self.assertEqual(values["parameters"], ["src"])
        self.assertEqual(values["paths"], ["/x"])


# ---------------------------------------------------------------------------
# Test 11 — bounded provenance
# ---------------------------------------------------------------------------


class TestBounds(unittest.TestCase):
    def test_provenance_bounded_by_max_items(self):
        letters = "abcdefghijklmnopqrstuvwxyz"

        def slug(index):
            out = ""
            n = index
            for _ in range(4):
                out = letters[n % 26] + out
                n //= 26
            return f"plugin-{out}"

        records = [
            {"path": f"/wp-content/plugins/{slug(index)}/"}
            for index in range(ci.MAX_ITEMS + 250)
        ]
        inferred = ci.infer_inventory_items(endpoint_records=records)
        inventory = ObservedAssetInventory(
            inventory_id=inventory_id_for("dell"), program="dell"
        )
        merged = ci.apply_inferred_items(inventory, inferred)
        self.assertLessEqual(
            len(merged.component_provenance), ci.MAX_ITEMS
        )
        self.assertLessEqual(len(merged.plugins), ci.MAX_ITEMS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
