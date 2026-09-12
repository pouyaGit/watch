"""tests/test_component_plugin_wiring.py — Stage R31.3 integration tests.

Verifies that R31.2 inferred components/plugins flow from the backend observed
inventory read path (``backend.observed_inventory``) into:

- the inventory projection (API + UI share this),
- CVE matching (``backend.asset_cve_matching``).

Mongo is mocked at the raw-document boundary (no Mongo connection, no writes).
No network, no DNS, no LLM, no subprocess, no target interaction, no Nuclei,
no browser, no PoC execution, no persistence.
"""
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from config import config
from fastapi.testclient import TestClient

from ai.knowledge.relevance import AssetRecord
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    SubdomainRecord,
    UrlRecord,
)
from backend import asset_cve_matching
from backend import observed_inventory as backend_oi

API_KEY = config().get("API_KEY", "")
CVE = "CVE-2026-9999"
DELL_LEAD = "rl-af7ecfba1a86fc83"

# Raw Mongo documents (same shape as the read-only projections).
MONGO_DOCUMENTS = {
    "subdomains": [
        {
            "_id": "s1",
            "program_name": "dell",
            "subdomain": "a.dell.com",
            "scope": "dell.com",
            "providers": [],
        }
    ],
    "http": [
        {
            "_id": "h1",
            "program_name": "dell",
            "subdomain": "a.dell.com",
            "tech": ["WordPress"],
        }
    ],
    "urls": [
        {
            "_id": "u1",
            "program_name": "dell",
            "subdomain": "a.dell.com",
            "path": "/wp-content/plugins/test-plugin/",
        }
    ],
    "endpoints": [
        {
            "_id": "e1",
            "program_name": "dell",
            "subdomain": "a.dell.com",
            "path": "/assets/ckeditor/plugins/",
        }
    ],
}


def _injected_records():
    return {
        "http_records": [
            HttpRecord(
                program_name="dell",
                subdomain="a.dell.com",
                tech=("WordPress",),
                record_id="h1",
            )
        ],
        "url_records": [
            UrlRecord(
                program_name="dell",
                subdomain="a.dell.com",
                path="/wp-content/plugins/test-plugin/",
                record_id="u1",
            )
        ],
        "endpoint_records": [
            EndpointRecord(
                program_name="dell",
                subdomain="a.dell.com",
                path="/assets/ckeditor/plugins/",
                record_id="e1",
            )
        ],
        "subdomain_records": [
            SubdomainRecord(
                program_name="dell",
                subdomain="a.dell.com",
                scope="dell.com",
                record_id="s1",
            )
        ],
    }


def _contexts_stub(asset_components=("CKEditor",)):
    """Synthetic CVE context matching the inferred component/plugin."""

    document = SimpleNamespace(
        components=["CKEditor"],
        parameters=[],
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {
            "id": CVE,
            "products": ["test-plugin"],
            "affected_versions": ["1.0"],
        },
        "research": {
            "affected_products": [],
            "affected_versions": ["1.0"],
        },
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [
                AssetRecord(
                    program="dell",
                    asset="dell.com",
                    components=tuple(asset_components),
                )
            ],
        }
    ]


class _WiringTestCase(unittest.TestCase):
    def setUp(self):
        backend_oi.clear_cache()
        asset_cve_matching.clear_cache()

    def tearDown(self):
        backend_oi.clear_cache()
        asset_cve_matching.clear_cache()


class TestInventoryWiring(_WiringTestCase):
    def _get_inventory(self, program="dell"):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            return backend_oi.get_inventory(program)

    def test_mongo_mocked_inference(self):
        inventory = self._get_inventory()
        self.assertIsNotNone(inventory)
        self.assertEqual(
            [item["value"] for item in inventory["plugins"]],
            ["test-plugin"],
        )
        self.assertEqual(
            [item["value"] for item in inventory["components"]],
            ["CKEditor"],
        )
        self.assertEqual(
            [item["evidence_type"] for item in inventory["plugins"]],
            ["INFERRED_PLUGIN"],
        )
        self.assertEqual(
            [item["evidence_type"] for item in inventory["components"]],
            ["INFERRED_COMPONENT"],
        )
        for item in inventory["plugins"] + inventory["components"]:
            self.assertEqual(item["source"], "COMPONENT_INVENTORY")
        self.assertTrue(
            any(
                "inferred from path" in line
                for line in inventory["evidence"]
            )
        )
        self.assertEqual(
            inventory["generated_from"]["component_inference_rule_version"],
            "r31-2",
        )

    def test_existing_categories_preserved(self):
        inventory = self._get_inventory()
        self.assertEqual(
            [item["value"] for item in inventory["technologies"]],
            ["WordPress"],
        )
        self.assertEqual(
            [item["value"] for item in inventory["versions"]], []
        )
        self.assertEqual(inventory["version_associations"], [])
        self.assertEqual(inventory["rule_version"], "r30-2")

    def test_injected_records_inference(self):
        inventory = backend_oi.get_inventory(
            "dell", records=_injected_records()
        )
        self.assertEqual(
            [item["value"] for item in inventory["plugins"]],
            ["test-plugin"],
        )
        self.assertEqual(
            [item["value"] for item in inventory["components"]],
            ["CKEditor"],
        )

    def test_build_inventory_and_summary(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            items = backend_oi.build_inventory("dell")
            summary = backend_oi.get_inventory_summary()
        self.assertEqual(len(items), 1)
        self.assertEqual(
            [row["value"] for row in items[0]["plugins"]],
            ["test-plugin"],
        )
        self.assertEqual(summary["by_program"]["dell"]["components"], 1)
        self.assertEqual(summary["by_program"]["dell"]["plugins"], 1)

    def test_deterministic(self):
        first = self._get_inventory()
        backend_oi.clear_cache()
        second = self._get_inventory()
        self.assertEqual(first, second)

    def test_inference_failure_is_fail_soft(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ), mock.patch.object(
            backend_oi, "infer_inventory_items",
            side_effect=RuntimeError("boom"),
        ):
            inventory = backend_oi.get_inventory("dell")
        self.assertEqual(
            [item["value"] for item in inventory["technologies"]],
            ["WordPress"],
        )
        self.assertEqual(inventory["components"], [])
        self.assertEqual(inventory["plugins"], [])


class TestCveMatchingConsumesInferred(_WiringTestCase):
    def test_component_and_plugin_match(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ), mock.patch.object(
            asset_cve_matching, "_contexts",
            return_value=_contexts_stub(),
        ):
            data = asset_cve_matching.build_matches(cve=CVE, program="dell")
        self.assertEqual(data["total"], 1)
        item = data["items"][0]
        match_types = {row["match_type"] for row in item["all_matches"]}
        self.assertIn("COMPONENT", match_types)
        self.assertIn("PLUGIN", match_types)
        self.assertIn(
            item["strongest_match_type"], ("COMPONENT", "PLUGIN")
        )
        self.assertNotEqual(item["strongest_match_type"], "TECHNOLOGY")
        self.assertEqual(item["matched_component"], "CKEditor")
        self.assertNotEqual(item["asset_match_confidence"], "NONE")

    def test_inferred_components_absent_without_wiring(self):
        # Without the R31.2 inference (pure R30.2 builder), no component or
        # plugin match can exist: proves the inferred evidence is the cause.
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value={
                "subdomains": MONGO_DOCUMENTS["subdomains"],
                "http": MONGO_DOCUMENTS["http"],
                "urls": [],
                "endpoints": [],
            },
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ), mock.patch.object(
            asset_cve_matching, "_contexts",
            return_value=_contexts_stub(asset_components=()),
        ):
            data = asset_cve_matching.build_matches(cve=CVE, program="dell")
        item = data["items"][0]
        match_types = {row["match_type"] for row in item["all_matches"]}
        self.assertNotIn("COMPONENT", match_types)
        self.assertNotIn("PLUGIN", match_types)


class TestApiServesInferred(_WiringTestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_inventory_route_serves_inferred(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            r = self._get("/api/research/inventory/dell")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn(
            "test-plugin",
            [item["value"] for item in body["plugins"]],
        )
        self.assertIn(
            "CKEditor",
            [item["value"] for item in body["components"]],
        )

    def test_no_target_identifier_leak(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            blob = json.dumps(
                self._get("/api/research/inventory/dell").json()
            ).lower()
        for token in ("http://", "https://", "a.dell.com", "example_url"):
            self.assertNotIn(token, blob)


class TestUiServesInferred(_WiringTestCase):
    @classmethod
    def setUpClass(cls):
        from api import app

        cls.client = TestClient(app)

    def _get(self, path, **params):
        if API_KEY:
            params["api_key"] = API_KEY
        return self.client.get(path, params=params)

    def test_lead_detail_inventory_panel_shows_inferred(self):
        with mock.patch.object(
            backend_oi, "_fetch_documents",
            return_value=MONGO_DOCUMENTS,
        ), mock.patch.object(
            backend_oi, "list_programs", return_value=["dell"]
        ):
            r = self._get(f"/ui/research/leads/{DELL_LEAD}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Observed asset inventory", r.text)
        panel = r.text.split("Observed asset inventory", 1)[1].split(
            "Why investigate", 1
        )[0]
        self.assertIn("test-plugin", panel)
        self.assertIn("CKEditor", panel)


class TestSafety(_WiringTestCase):
    def test_no_persistence_or_execution_tokens(self):
        from pathlib import Path

        source = (
            Path("/opt/watch") / "backend/observed_inventory.py"
        ).read_text(encoding="utf-8")
        for token in ("insert_one", "update_one", "delete_one",
                      "insert_many", "write_text", "json.dump",
                      "import subprocess", "subprocess.",
                      "import socket", "socket.",
                      "import requests", "requests.",
                      "selenium", "playwright", "os.system(",
                      "urlopen"):
            self.assertNotIn(token, source, token)

    def test_rule_versions_unchanged(self):
        from ai.knowledge.asset_cve_matching import RULE_VERSION as R301
        from ai.knowledge.observed_inventory import RULE_VERSION as R302
        from ai.knowledge.component_inference import RULE_VERSION as R312

        self.assertEqual(R301, "r30-1")
        self.assertEqual(R302, "r30-2")
        self.assertEqual(R312, "r31-2")

    def test_inferred_items_are_schema_valid(self):
        from ai.schemas.observed_inventory import (
            EVIDENCE_TYPES,
            ObservedAssetInventory,
        )

        inventory = backend_oi.get_inventory(
            "dell", records=_injected_records()
        )
        rebuilt = ObservedAssetInventory(**inventory)
        for item in rebuilt.components:
            self.assertIn(item.evidence_type, EVIDENCE_TYPES)
        for item in rebuilt.plugins:
            self.assertIn(item.evidence_type, EVIDENCE_TYPES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
