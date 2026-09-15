"""Integration test: sanitized snapshot -> existing inventory builder.

Proves that records reconstructed from a deterministic R61 snapshot feed
``backend.observed_inventory.build_inventory(program, records=...)`` without
MongoDB and that useful observed fields survive (technologies, versions,
parameters, paths, parameter/path evidence and inventory sources).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend.observed_inventory import build_inventory
from tests.local_e2e import recon_snapshot as rs
from tests.local_e2e.fake_mongo import FakeClient, client_from_fixture, load_fixture

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "indeed_raw_sample.json"


def inventory_from_snapshot(snapshot: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "snapshot.json"
        rs.save_snapshot(snapshot, path)
        loaded = rs.load_snapshot(path)
    records = rs.records_for_inventory(loaded)
    results = build_inventory(loaded["program"], records=records)
    if len(results) != 1:
        raise AssertionError("expected exactly one inventory projection")
    return results[0]


class TestSnapshotToInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = load_fixture(FIXTURE_PATH)
        cls.snapshot = rs.build_snapshot(
            "indeed", client=client_from_fixture(fixture)
        )
        cls.inventory = inventory_from_snapshot(cls.snapshot)

    def test_inventory_identity(self):
        inventory = self.inventory
        self.assertEqual(inventory["program"], "indeed")
        self.assertTrue(inventory["inventory_id"].startswith("inv-"))
        self.assertEqual(inventory["rule_version"], "r30-2")
        self.assertTrue(inventory["research_only"])

    def test_technologies_survive(self):
        values = {
            str(item["value"]).lower()
            for item in self.inventory["technologies"]
        }
        for expected in ("nginx", "jquery", "hsts", "cloudflare", "http"):
            self.assertIn(expected, values)

    def test_versions_survive(self):
        values = {
            str(item["value"]) for item in self.inventory["versions"]
        }
        self.assertIn("1.24.0", values)
        self.assertIn("3.5.1", values)

    def test_version_associations_survive(self):
        associations = self.inventory["version_associations"]
        pairs = {
            (entry["technology_family"].lower(), entry["version"])
            for entry in associations
        }
        self.assertIn(("nginx", "1.24.0"), pairs)
        self.assertIn(("jquery", "3.5.1"), pairs)
        for entry in associations:
            self.assertEqual(entry["source"], "TECHNOLOGY_INVENTORY")
            self.assertEqual(entry["evidence_type"], "STRUCTURED_TECHNOLOGY")

    def test_parameters_survive(self):
        values = {
            str(item["value"]) for item in self.inventory["parameters"]
        }
        for expected in ("co", "continue", "client", "kw", "sid"):
            self.assertIn(expected, values)

    def test_paths_survive(self):
        values = {str(item["value"]) for item in self.inventory["paths"]}
        for expected in (
            "/auth",
            "/notifications/api/{id}/getNotificationsCount",
            "/signals/log",
        ):
            self.assertIn(expected, values)

    def test_parameter_path_evidence_survives(self):
        pairs = {
            (entry["parameter"], entry["path"])
            for entry in self.inventory["parameter_paths"]
        }
        self.assertIn(("co", "/auth"), pairs)
        self.assertIn(("continue", "/auth"), pairs)
        self.assertIn(
            ("client", "/notifications/api/{id}/getNotificationsCount"),
            pairs,
        )

    def test_inventory_sources_survive(self):
        sources = set(self.inventory["sources"])
        self.assertIn("TECHNOLOGY_INVENTORY", sources)
        self.assertIn("PARAMETER_INVENTORY", sources)
        self.assertIn("ENDPOINT_INVENTORY", sources)

    def test_inventory_is_deterministic(self):
        first = json.dumps(self.inventory, sort_keys=True)
        second = json.dumps(
            inventory_from_snapshot(self.snapshot), sort_keys=True
        )
        self.assertEqual(first, second)

    def test_inventory_path_never_reads_mongo(self):
        records = rs.records_for_inventory(self.snapshot)
        with mock.patch(
            "backend.observed_inventory._fetch_documents",
            side_effect=AssertionError("mongo must not be read"),
        ):
            results = build_inventory("indeed", records=records)
        self.assertEqual(results[0]["program"], "indeed")

    def test_empty_records_never_fall_back_to_mongo(self):
        snapshot = rs.build_snapshot(
            "indeed", client=FakeClient({}), include_program=False
        )
        records = rs.records_for_inventory(snapshot)
        with mock.patch(
            "backend.observed_inventory._fetch_documents",
            side_effect=AssertionError("mongo must not be read"),
        ):
            results = build_inventory("indeed", records=records)
        self.assertEqual(results[0]["program"], "indeed")
        self.assertEqual(results[0]["technologies"], [])
        self.assertEqual(results[0]["paths"], [])


if __name__ == "__main__":
    unittest.main()
