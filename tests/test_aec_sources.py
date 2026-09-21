"""EPIC6 Part 1+7: real-data adapter, provenance, source modes (RED first)."""

from __future__ import annotations

import json
import unittest

WATCH_RECORD = {
    "subdomain": "Shop.Example.com",
    "url": "/orders?order_id=",
    "endpoint": "/orders",
    "parameter": "order_id",
    "method": "GET",
    "location": "query",
    "technology": ["Flask", "PYTHON", "flask"],
    "versions": ["2.3.0"],
    "source": "watch",
    "id": "srv-1044",
    "last_update": "2026-09-01T10:00:00Z",
}


class TestOriginModes(unittest.TestCase):
    def test_origin_modes_exact(self):
        from aec.research import sources

        self.assertEqual(
            sources.ORIGIN_MODES,
            {"watch": "REAL_WATCH_DATA", "fixture": "OFFLINE_FIXTURE"},
        )

    def test_unknown_origin_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record(WATCH_RECORD, origin="live")

    def test_non_mapping_record_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record(["not", "a", "mapping"], origin="watch")


class TestNormalization(unittest.TestCase):
    def test_host_lowercased_only(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.host, "shop.example.com")

    def test_endpoint_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.endpoint, "/orders")

    def test_url_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.url, "/orders?order_id=")

    def test_parameter_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.parameter, "order_id")

    def test_technologies_sorted_deduped_lowercased(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.technologies, ("flask", "python"))

    def test_versions_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.versions, ("2.3.0",))

    def test_method_default_get(self):
        from aec.research import sources

        record = sources.normalize_record(
            {key: WATCH_RECORD[key] for key in ("subdomain", "endpoint")},
            origin="fixture",
        )
        self.assertEqual(record.method, "GET")

    def test_missing_host_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record({"endpoint": "/x"}, origin="watch")

    def test_missing_endpoint_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record({"subdomain": "a.example"}, origin="watch")

    def test_endpoint_falls_back_to_url(self):
        from aec.research import sources

        record = sources.normalize_record(
            {"subdomain": "a.example", "url": "/path?p=1"}, origin="watch")
        self.assertEqual(record.endpoint, "/path?p=1")


class TestProvenance(unittest.TestCase):
    def test_provenance_source(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.provenance["source"], "watch")

    def test_provenance_source_id_prefers_id(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.provenance["source_id"], "srv-1044")

    def test_provenance_source_id_falls_back_to_source_id_key(self):
        from aec.research import sources

        entry = dict(WATCH_RECORD)
        del entry["id"]
        entry["source_id"] = "srv-77"
        record = sources.normalize_record(entry, origin="watch")
        self.assertEqual(record.provenance["source_id"], "srv-77")

    def test_provenance_source_id_synthesized(self):
        from aec.research import sources

        entry = {"subdomain": "a.example", "endpoint": "/path"}
        record = sources.normalize_record(entry, origin="watch")
        self.assertEqual(record.provenance["source_id"], "a.example/path")

    def test_provenance_observed_at_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(
            record.provenance["observed_at"], "2026-09-01T10:00:00Z")

    def test_provenance_observed_at_unstated(self):
        from aec.research import sources

        entry = {k: WATCH_RECORD[k] for k in ("subdomain", "endpoint")}
        record = sources.normalize_record(entry, origin="watch")
        self.assertEqual(record.provenance["observed_at"], "unstated")

    def test_provenance_normalization_field(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.provenance["normalization"], "normalized")

    def test_source_mode_tagged(self):
        from aec.research import sources

        watch = sources.normalize_record(WATCH_RECORD, origin="watch")
        fixture = sources.normalize_record(WATCH_RECORD, origin="fixture")
        self.assertEqual(watch.source_mode, "REAL_WATCH_DATA")
        self.assertEqual(fixture.source_mode, "OFFLINE_FIXTURE")
        self.assertEqual(watch.provenance["classification"], "REAL_WATCH_DATA")
        self.assertEqual(
            fixture.provenance["classification"], "OFFLINE_FIXTURE")


class TestNoInference(unittest.TestCase):
    def test_no_category_inferred(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertNotIn("category", record.to_dict())
        self.assertEqual(
            sources.normalize_record(
                {"subdomain": "admin-panel.example.com", "endpoint": "/"},
                origin="watch",
            ).host,
            "admin-panel.example.com",
        )

    def test_no_severity_inferred(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertNotIn("severity", record.to_dict())

    def test_no_version_from_tech_names(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        self.assertEqual(record.versions, ("2.3.0",))

    def test_no_parameter_from_url(self):
        from aec.research import sources

        entry = {"subdomain": "a.example", "url": "/x?token=abc"}
        record = sources.normalize_record(entry, origin="watch")
        self.assertEqual(record.parameter, "")
        self.assertEqual(record.url, "/x?token=abc")

    def test_no_cve_text_inference(self):
        from aec.research import sources

        entry = {"subdomain": "a.example", "endpoint": "/x",
                 "technology": ["openssl"]}
        record = sources.normalize_record(entry, origin="watch")
        self.assertNotIn("cve", record.to_dict())


class TestBatch(unittest.TestCase):
    def test_batch_returns_records(self):
        from aec.research import sources

        records = sources.normalize_batch(
            [WATCH_RECORD, dict(WATCH_RECORD, subdomain="b.example")],
            origin="watch",
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].host, "shop.example.com")
        self.assertEqual(records[1].host, "b.example")

    def test_batch_raises_on_bad_entry(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_batch([WATCH_RECORD, "nope"], origin="watch")

    def test_batch_collects_refusals(self):
        from aec.research import sources

        records, refused = sources.normalize_batch(
            [WATCH_RECORD, "nope", {}], origin="watch", collect_refused=True)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(refused), 2)
        self.assertEqual(refused[0]["index"], "1")

    def test_batch_non_sequence_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_batch("scalar", origin="watch")

    def test_batch_source_mode_mixed_impossible(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_batch([WATCH_RECORD], origin="unknown")


class TestSerialization(unittest.TestCase):
    def test_record_to_dict_roundtrip(self):
        from aec.research import sources

        record = sources.normalize_record(WATCH_RECORD, origin="watch")
        document = record.to_dict()
        self.assertEqual(document["host"], "shop.example.com")
        self.assertEqual(document["technologies"], ["flask", "python"])
        self.assertEqual(document["source_mode"], "REAL_WATCH_DATA")

    def test_record_to_dict_json_stable(self):
        from aec.research import sources

        first = json.dumps(
            sources.normalize_record(WATCH_RECORD, origin="watch").to_dict(),
            sort_keys=True, separators=(",", ":"))
        second = json.dumps(
            sources.normalize_record(WATCH_RECORD, origin="watch").to_dict(),
            sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()