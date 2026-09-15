"""Deterministic tests for the R61 real recon snapshot layer.

Coverage (A-N from the implementation task):

A. same input -> same snapshot
B. same input -> same record_ref
C. ``_id`` never appears in the serialized snapshot
D. ordering is deterministic
E. caps are enforced
F. program isolation is enforced
G. parameter provenance is preserved
H. ``x8_checked`` / ``hit_count`` are preserved
I. URL canonicalization is deterministic
J. original semantic params remain authoritative
K. snapshot loads without Mongo
L. loaded snapshot feeds the inventory builder through ``records=``
M. no DB writes occur
N. empty/malformed rows fail safely

All tests are offline: the snapshot builder is always given an injected
in-memory client, and the inventory injection never reads MongoDB.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    SubdomainRecord,
    UrlRecord,
)
from backend.observed_inventory import _Document, build_inventory
from tests.local_e2e import recon_snapshot as rs
from tests.local_e2e.fake_mongo import (
    FakeClient,
    client_from_fixture,
    load_fixture,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "indeed_raw_sample.json"


def build(program: str = "indeed", fixture: dict | None = None, **kwargs):
    if fixture is None:
        fixture = load_fixture(FIXTURE_PATH)
    return rs.build_snapshot(
        program,
        client=client_from_fixture(fixture),
        **kwargs,
    )


def collection_records(snapshot: dict, collection: str) -> list[dict]:
    return list(snapshot["collections"][collection]["records"])


def all_refs(snapshot: dict) -> dict[str, list[str]]:
    return {
        name: [
            record["record_ref"]
            for record in collection_records(snapshot, name)
        ]
        for name in snapshot["collections"]
    }


def endpoint_by_path(snapshot: dict, path: str) -> dict:
    for record in collection_records(snapshot, "endpoints"):
        if record["path"] == path:
            return record
    raise AssertionError(f"endpoint not found: {path}")


def url_by_path(snapshot: dict, path: str) -> dict:
    for record in collection_records(snapshot, "urls"):
        if record["path"] == path:
            return record
    raise AssertionError(f"url not found: {path}")


class TestSnapshotDeterminism(unittest.TestCase):
    def test_same_input_same_snapshot(self):
        first = rs.snapshot_to_json(build())
        second = rs.snapshot_to_json(build())
        self.assertEqual(first, second)

    def test_input_order_does_not_matter(self):
        fixture = load_fixture(FIXTURE_PATH)
        reordered = dict(fixture)
        for name in (
            "programs",
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            reordered[name] = list(reversed(fixture[name]))
        self.assertEqual(
            rs.snapshot_to_json(build(fixture=fixture)),
            rs.snapshot_to_json(build(fixture=reordered)),
        )

    def test_record_refs_are_stable(self):
        self.assertEqual(all_refs(build()), all_refs(build()))

    def test_record_refs_ignore_mongo_ids(self):
        fixture = load_fixture(FIXTURE_PATH)
        renamed = json.loads(json.dumps(fixture))
        counter = 0
        for name in (
            "programs",
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            for document in renamed[name]:
                counter += 1
                document["_id"] = f"totally-different-id-{counter:04d}"
        self.assertEqual(
            rs.snapshot_to_json(build(fixture=fixture)),
            rs.snapshot_to_json(build(fixture=renamed)),
        )

    def test_id_compatibility_shim_still_works(self):
        document = {
            "_id": "legacy-object-id",
            "program_name": "indeed",
            "subdomain": "www.indeed.com",
            "scope": "indeed.com",
            "ips": ["192.0.2.9"],
            "tech": ["nginx:1.24.0"],
            "status_code": 200,
            "url": "https://www.indeed.com/",
            "final_url": "",
        }
        record = HttpRecord.from_document(_Document(document))
        self.assertEqual(record.record_id, "legacy-object-id")
        self.assertEqual(record.tech, ("nginx:1.24.0",))

    def test_record_ref_is_collection_scoped(self):
        shared_key = ("www.indeed.com",)
        self.assertNotEqual(
            rs.record_ref("indeed", "subdomains", shared_key),
            rs.record_ref("indeed", "live_subdomains", shared_key),
        )


class TestNoIdExposure(unittest.TestCase):
    def test_id_key_and_values_never_serialized(self):
        fixture = load_fixture(FIXTURE_PATH)
        text = rs.snapshot_to_json(build(fixture=fixture))
        self.assertNotIn('"_id"', text)
        for name in (
            "programs",
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            for document in fixture[name]:
                if "_id" in document:
                    self.assertNotIn(document["_id"], text)

    def test_header_values_never_serialized(self):
        text = rs.snapshot_to_json(build())
        self.assertNotIn("fixture-secret-cookie", text)
        self.assertNotIn("Set-Cookie", text)

    def test_snapshot_records_use_rec_refs(self):
        snapshot = build()
        for name, records in snapshot["collections"].items():
            for record in records["records"]:
                self.assertTrue(
                    record["record_ref"].startswith("rec-"), name
                )
                self.assertNotIn("_id", record)


class TestCapsAndBounds(unittest.TestCase):
    def test_default_caps_are_the_documented_values(self):
        self.assertEqual(
            rs.DEFAULT_CAPS,
            {
                "subdomains": 500,
                "live_subdomains": 500,
                "http": 300,
                "urls": 1000,
                "endpoints": 1000,
            },
        )

    def test_caps_are_enforced(self):
        snapshot = build(
            caps={
                "subdomains": 1,
                "live_subdomains": 1,
                "http": 1,
                "urls": 1,
                "endpoints": 1,
            }
        )
        for name in rs.COLLECTIONS:
            self.assertEqual(
                len(collection_records(snapshot, name)),
                1,
                name,
            )
            self.assertEqual(
                snapshot["collections"][name]["stats"]["selected"], 1
            )
        self.assertEqual(snapshot["stats"]["total_selected"], 5)

    def test_zero_cap_yields_empty_collection(self):
        snapshot = build(caps={"endpoints": 0})
        self.assertEqual(collection_records(snapshot, "endpoints"), [])
        self.assertEqual(
            snapshot["collections"]["endpoints"]["stats"]["selected"], 0
        )

    def test_fetch_is_bounded_by_cap_times_factor(self):
        documents = [
            {
                "_id": f"ep-{index:02d}",
                "program_name": "indeed",
                "subdomain": f"host{index:02d}.indeed.com",
                "path": f"/p{index:02d}",
                "params": ["q"],
                "hit_count": index,
            }
            for index in range(10)
        ]
        snapshot = rs.build_snapshot(
            "indeed",
            client=FakeClient({"endpoints": documents}),
            caps={"endpoints": 2, "subdomains": 0, "live_subdomains": 0,
                  "http": 0, "urls": 0},
            fetch_factor=2,
        )
        stats = snapshot["collections"]["endpoints"]["stats"]
        self.assertEqual(stats["fetched"], 4)
        self.assertEqual(stats["selected"], 2)

    def test_caps_are_validated(self):
        for bad in (
            {"endpoints": -1},
            {"endpoints": True},
            {"endpoints": "5"},
            {"unknown": 1},
            ["endpoints"],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(rs.SnapshotError):
                    build(caps=bad)

    def test_fetch_factor_is_validated(self):
        for bad in (0, -3, True, "2"):
            with self.subTest(bad=bad):
                with self.assertRaises(rs.SnapshotError):
                    build(fetch_factor=bad)

    def test_unknown_collection_is_rejected(self):
        with self.assertRaises(rs.SnapshotError):
            build(collections=["endpoints", "secrets"])


class TestOrdering(unittest.TestCase):
    def test_output_ordering_is_deterministic(self):
        snapshot = build()
        endpoints = [
            (record["subdomain"], record["path"], record["record_ref"])
            for record in collection_records(snapshot, "endpoints")
        ]
        self.assertEqual(endpoints, sorted(endpoints))
        urls = [
            (record["subdomain"], record["url"], record["record_ref"])
            for record in collection_records(snapshot, "urls")
        ]
        self.assertEqual(urls, sorted(urls))
        subdomains = [
            record["subdomain"]
            for record in collection_records(snapshot, "subdomains")
        ]
        self.assertEqual(subdomains, sorted(subdomains))

    def test_endpoint_priority_prefers_params_provenance_and_hits(self):
        snapshot = build(caps={"endpoints": 2})
        paths = [
            record["path"]
            for record in collection_records(snapshot, "endpoints")
        ]
        self.assertEqual(
            sorted(paths),
            ["/auth", "/notifications/api/{id}/getNotificationsCount"],
        )

    def test_url_priority_prefers_params_then_interesting_paths(self):
        snapshot = build(caps={"urls": 2})
        urls = collection_records(snapshot, "urls")
        self.assertEqual(len(urls), 2)
        for record in urls:
            self.assertTrue(record["params"])


class TestProgramIsolation(unittest.TestCase):
    def test_only_requested_program_is_present(self):
        snapshot = build()
        for name, payload in snapshot["collections"].items():
            for record in payload["records"]:
                self.assertEqual(record["program_name"], "indeed", name)
        text = rs.snapshot_to_json(snapshot)
        self.assertNotIn("other-program", text)
        self.assertNotIn("www.other.example", text)

    def test_queries_are_program_scoped(self):
        fixture = load_fixture(FIXTURE_PATH)
        client = client_from_fixture(fixture)
        rs.build_snapshot("indeed", client=client)
        for name in (
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            calls = client._database[name].read_calls
            self.assertTrue(calls, name)
            for method, query, projection in calls:
                if method == "find":
                    self.assertEqual(query, {"program_name": "indeed"}, name)
                    self.assertEqual(projection.get("_id"), 0, name)

    def test_rogue_rows_are_filtered_and_defensively_counted(self):
        fixture = load_fixture(FIXTURE_PATH)
        client = client_from_fixture(fixture)
        for name in (
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            client._database[name].ignore_query = True
        snapshot = rs.build_snapshot("indeed", client=client)
        for name in (
            "subdomains",
            "live_subdomains",
            "http",
            "urls",
            "endpoints",
        ):
            self.assertGreaterEqual(
                snapshot["collections"][name]["stats"][
                    "skipped_other_program"
                ],
                1,
                name,
            )
            for record in snapshot["collections"][name]["records"]:
                self.assertEqual(record["program_name"], "indeed", name)

    def test_other_program_can_be_selected_explicitly(self):
        fixture = load_fixture(FIXTURE_PATH)
        snapshot = rs.build_snapshot(
            "other-program", client=client_from_fixture(fixture)
        )
        for name, payload in snapshot["collections"].items():
            for record in payload["records"]:
                self.assertEqual(record["program_name"], "other-program", name)
        self.assertGreaterEqual(
            snapshot["stats"]["total_selected"], 1
        )

    def test_program_metadata_is_preserved(self):
        snapshot = build()
        metadata = snapshot["program_metadata"]
        self.assertEqual(metadata["program_name"], "indeed")
        self.assertIn("indeed.com", metadata["scopes"])
        self.assertTrue(snapshot["read_only"])
        self.assertTrue(snapshot["research_only"])


class TestProvenanceAndFields(unittest.TestCase):
    def test_parameter_provenance_is_preserved(self):
        snapshot = build()
        auth = endpoint_by_path(snapshot, "/auth")
        self.assertEqual(
            auth["param_records"],
            [
                {
                    "name": "co",
                    "method": "GET",
                    "location": "query",
                    "source": "crawl",
                },
                {
                    "name": "continue",
                    "method": "GET",
                    "location": "query",
                    "source": "crawl",
                },
            ],
        )
        notifications = endpoint_by_path(
            snapshot, "/notifications/api/{id}/getNotificationsCount"
        )
        self.assertEqual(
            notifications["param_records"],
            [
                {"name": "client", "method": "GET", "location": "query",
                 "source": "crawl"},
                {"name": "kw", "method": "POST", "location": "body",
                 "source": "x8"},
                {"name": "sid", "method": "GET", "location": "query",
                 "source": "x8"},
            ],
        )

    def test_x8_and_hit_count_are_preserved(self):
        snapshot = build()
        auth = endpoint_by_path(snapshot, "/auth")
        self.assertTrue(auth["x8_checked"])
        self.assertEqual(auth["hit_count"], 49073)
        notifications = endpoint_by_path(
            snapshot, "/notifications/api/{id}/getNotificationsCount"
        )
        self.assertEqual(notifications["hit_count"], 10133)
        self.assertEqual(
            notifications["params_from_x8"], ["kw", "sid"]
        )

    def test_status_and_technology_are_preserved(self):
        snapshot = build()
        http_records = collection_records(snapshot, "http")
        by_subdomain = {
            record["subdomain"]: record for record in http_records
        }
        self.assertEqual(by_subdomain["www.indeed.com"]["status_code"], 200)
        self.assertIn(
            "nginx:1.24.0", by_subdomain["www.indeed.com"]["tech"]
        )
        self.assertEqual(
            by_subdomain["secure.indeed.com"]["status_code"], 403
        )
        self.assertEqual(
            by_subdomain["api.qa.indeed.net"]["status_code"], 503
        )


class TestUrlCanonicalization(unittest.TestCase):
    def test_escaped_ampersand_is_decoded(self):
        self.assertEqual(
            rs.canonicalize_url(
                "https://x.example/a?b=1\\u0026c=2"
            ),
            "https://x.example/a?b=1&c=2",
        )

    def test_double_escaped_ampersand_is_decoded(self):
        self.assertEqual(
            rs.canonicalize_url(
                "https://x.example/a?b=1\\\\u0026c=2"
            ),
            "https://x.example/a?b=1&c=2",
        )

    def test_html_ampersand_is_decoded(self):
        self.assertEqual(
            rs.canonicalize_url("https://x.example/?a=1&amp;b=2"),
            "https://x.example/?a=1&b=2",
        )

    def test_trailing_backslash_is_stripped(self):
        self.assertEqual(
            rs.canonicalize_url("https://x.example/?lang=vi\\"),
            "https://x.example/?lang=vi",
        )

    def test_percent_encoding_and_order_are_preserved(self):
        original = (
            "https://x.example/a?continue=https%3A%2F%2Fx.example%2F&hl=en"
        )
        self.assertEqual(rs.canonicalize_url(original), original)

    def test_canonicalization_is_idempotent(self):
        samples = (
            "https://x.example/a?b=1\\u0026c=2",
            "https://x.example/?a=1&amp;b=2",
            "https://x.example/?lang=vi\\",
            "https://x.example/a?continue=https%3A%2F%2Fx.example%2F",
        )
        for sample in samples:
            once = rs.canonicalize_url(sample)
            self.assertEqual(rs.canonicalize_url(once), once)

    def test_snapshot_urls_are_canonicalized(self):
        snapshot = build()
        signals = url_by_path(snapshot, "/signals/log")
        self.assertEqual(
            signals["url"],
            "https://www.indeed.com/signals/log?from=gnav&parentLogId=abc",
        )
        text = rs.snapshot_to_json(snapshot)
        self.assertNotIn("\\u0026", text)
        self.assertNotIn("&amp;", text)


class TestParamsAuthoritative(unittest.TestCase):
    def test_original_params_survive_html_entity_urls(self):
        snapshot = build()
        root = url_by_path(snapshot, "/")
        self.assertEqual(root["url"], "https://secure.indeed.com/?hl=en&co=us")
        self.assertEqual(root["params"], ["amp;co", "hl"])

    def test_params_are_not_rederived_from_urls(self):
        snapshot = build()
        signals = url_by_path(snapshot, "/signals/log")
        self.assertEqual(signals["params"], ["from", "parentLogId"])
        auth = url_by_path(snapshot, "/auth")
        self.assertEqual(auth["params"], ["continue", "hl"])
        self.assertNotIn("https%3A%2F%2Fwww.indeed.com%2F", auth["params"])


class TestOfflineReplay(unittest.TestCase):
    def test_save_and_load_roundtrip_without_mongo(self):
        snapshot = build()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            written = rs.save_snapshot(snapshot, path)
            self.assertTrue(written.exists())
            loaded = rs.load_snapshot(path)
        self.assertEqual(
            rs.snapshot_to_json(loaded), rs.snapshot_to_json(snapshot)
        )

    def test_load_rejects_malformed_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            with self.assertRaises(rs.SnapshotError):
                rs.load_snapshot(broken)
            wrong_version = Path(tmp) / "version.json"
            wrong_version.write_text(
                json.dumps({"snapshot_version": 99, "rule_version": "x"}),
                encoding="utf-8",
            )
            with self.assertRaises(rs.SnapshotError):
                rs.load_snapshot(wrong_version)

    def test_records_for_inventory_roundtrip(self):
        snapshot = build()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            rs.save_snapshot(snapshot, path)
            loaded = rs.load_snapshot(path)
        records = rs.records_for_inventory(loaded)
        self.assertTrue(
            all(isinstance(r, HttpRecord) for r in records["http_records"])
        )
        self.assertTrue(
            all(isinstance(r, UrlRecord) for r in records["url_records"])
        )
        self.assertTrue(
            all(
                isinstance(r, EndpointRecord)
                for r in records["endpoint_records"]
            )
        )
        self.assertTrue(
            all(
                isinstance(r, SubdomainRecord)
                for r in records["subdomain_records"]
            )
        )
        for record in records["endpoint_records"]:
            self.assertTrue(record.record_id.startswith("rec-"))
            self.assertTrue(
                all(
                    isinstance(entry, ParamRecord)
                    for entry in record.param_records
                )
            )

    def test_loaded_snapshot_feeds_inventory_builder(self):
        snapshot = build()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            rs.save_snapshot(snapshot, path)
            loaded = rs.load_snapshot(path)
        inventory = build_inventory(
            loaded["program"], records=rs.records_for_inventory(loaded)
        )
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["program"], "indeed")
        self.assertTrue(inventory[0]["technologies"])
        self.assertTrue(inventory[0]["paths"])


class TestNoDatabaseWrites(unittest.TestCase):
    def test_snapshot_build_performs_no_writes(self):
        fixture = load_fixture(FIXTURE_PATH)
        client = client_from_fixture(fixture)
        rs.build_snapshot("indeed", client=client)
        self.assertEqual(client.write_attempts, [])
        for name in client._database.list_collection_names():
            self.assertEqual(
                client._database[name].write_attempts, [], name
            )

    def test_injected_write_method_raises(self):
        client = FakeClient({"endpoints": []})
        with self.assertRaises(AssertionError):
            client["endpoints"].insert_one({})

    def test_module_source_has_no_write_or_network_tokens(self):
        source = Path(rs.__file__).read_text(encoding="utf-8")
        for token in (
            "insert_one",
            "insert_many",
            "update_one",
            "update_many",
            "delete_one",
            "delete_many",
            "replace_one",
            "bulk_write",
            "create_index",
            "ensure_index",
            "drop(",
            "find_one_and_",
            "import socket",
            "socket.socket",
            "urlopen",
            "requests.",
            "httpx.",
            "import subprocess",
            "subprocess.",
            "os.system",
            "Popen(",
        ):
            self.assertNotIn(token, source, token)


class TestMalformedAndEmpty(unittest.TestCase):
    def test_malformed_rows_are_counted_and_skipped(self):
        snapshot = build()
        self.assertGreaterEqual(
            snapshot["collections"]["endpoints"]["stats"]["malformed"], 1
        )
        self.assertGreaterEqual(
            snapshot["collections"]["subdomains"]["stats"]["malformed"], 1
        )
        for record in collection_records(snapshot, "endpoints"):
            self.assertNotEqual(record["path"], "/orphan")

    def test_malformed_endpoint_fields_fail_safe(self):
        snapshot = build()
        weird = endpoint_by_path(snapshot, "/weird")
        self.assertEqual(weird["params"], [])
        self.assertEqual(weird["params_from_crawl"], [])
        self.assertEqual(weird["params_from_x8"], [])
        self.assertFalse(weird["x8_checked"])
        self.assertEqual(weird["param_records"], [])
        self.assertEqual(weird["hit_count"], -1)

    def test_non_mapping_rows_are_ignored(self):
        client = FakeClient(
            {
                "subdomains": [
                    None,
                    "not-a-document",
                    5,
                    {
                        "program_name": "indeed",
                        "subdomain": "ok.indeed.com",
                        "scope": "indeed.com",
                        "providers": ["subfinder"],
                    },
                ]
            }
        )
        snapshot = rs.build_snapshot(
            "indeed",
            client=client,
            collections=["subdomains"],
            include_program=False,
        )
        records = collection_records(snapshot, "subdomains")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["subdomain"], "ok.indeed.com")
        self.assertEqual(
            snapshot["collections"]["subdomains"]["stats"]["fetched"], 1
        )

    def test_empty_input_yields_empty_snapshot(self):
        snapshot = rs.build_snapshot(
            "indeed", client=FakeClient({}), include_program=False
        )
        self.assertEqual(snapshot["stats"]["total_selected"], 0)
        self.assertEqual(snapshot["stats"]["total_fetched"], 0)
        self.assertIsNone(snapshot["program_metadata"])
        for name in rs.COLLECTIONS:
            self.assertEqual(collection_records(snapshot, name), [])

    def test_invalid_program_names_are_rejected(self):
        for bad in ("", "   ", None, 5, "bad\nname"):
            with self.subTest(bad=bad):
                with self.assertRaises(rs.SnapshotError):
                    build(program=bad)


if __name__ == "__main__":
    unittest.main()
