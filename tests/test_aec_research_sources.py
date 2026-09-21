"""Tests for aec/research (EPIC 6 Part 1+7: real-data adapter + provenance).

Normalizes Watch-domain record shapes as plain mappings (backend code
is never imported) with full provenance and an explicit origin label.
Classification is REAL_WATCH_DATA or OFFLINE_FIXTURE from the caller's
explicit origin only — never inferred from hostnames, paths, parameter
names, or any other content signal.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

RESEARCH_DIR = Path(__file__).resolve().parents[1] / "aec" / "research"
MODULES = ("models.py", "sources.py", "guard.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend", "requests", "httpx", "aiohttp",
})

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "EXPLOITABLE", "EXPLOIT",
    "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)


def watch_record(**overrides):
    entry = {
        "program": "pilot",
        "subdomain": "Shop.Example.COM",
        "url": "/orders?order_id=",
        "endpoint": "/orders",
        "parameter": "order_id",
        "method": "GET",
        "location": "query",
        "technology": ["PHP 8.2", "laravel"],
        "source": "watch",
        "last_update": "2026-09-20",
    }
    entry.update(overrides)
    return entry


class TestNormalizeRecord(unittest.TestCase):
    def test_watch_origin_classifies_real(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.source_mode, "REAL_WATCH_DATA")
        self.assertEqual(record.provenance["source"], "watch")

    def test_fixture_origin_classifies_fixture(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="fixture")
        self.assertEqual(record.source_mode, "OFFLINE_FIXTURE")

    def test_origin_required(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record(watch_record(), origin="")

    def test_unknown_origin_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record(watch_record(), origin="production-db")

    def test_non_mapping_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record("nope", origin="watch")

    def test_host_lowercased(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.host, "shop.example.com")

    def test_endpoint_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(endpoint="/API/Orders"), origin="watch")
        self.assertEqual(record.endpoint, "/API/Orders")

    def test_url_verbatim(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.url, "/orders?order_id=")

    def test_technology_normalized_case_only(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.technologies, ("laravel", "php 8.2"))

    def test_technology_never_invented(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(technology=[]), origin="watch")
        self.assertEqual(record.technologies, ())

    def test_versions_passthrough(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(versions=["php 8.2"]), origin="watch")
        self.assertEqual(record.versions, ("php 8.2",))

    def test_versions_default_empty(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.versions, ())

    def test_provenance_observed_at(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.provenance["observed_at"], "2026-09-20")

    def test_provenance_missing_observed_at(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(last_update=None), origin="watch")
        self.assertEqual(record.provenance["observed_at"], "unstated")

    def test_provenance_source_id(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertTrue(record.provenance["source_id"])

    def test_provenance_normalization_ok(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(record.provenance["normalization"], "normalized")

    def test_source_mode_in_provenance(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(
            record.provenance["classification"], "REAL_WATCH_DATA")

    def test_missing_endpoint_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record(watch_record(endpoint=""), origin="watch")

    def test_missing_host_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_record(watch_record(subdomain=""), origin="watch")

    def test_record_dict_keys(self):
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(
            sorted(record.to_dict()),
            ["endpoint", "host", "method", "parameter", "provenance",
             "source_mode", "technologies", "url", "versions"],
        )

    def test_records_are_frozen(self):
        import dataclasses
        from aec.research import sources

        record = sources.normalize_record(watch_record(), origin="watch")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.host = "other.com"


class TestNoInference(unittest.TestCase):
    def test_admin_path_adds_no_category(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(endpoint="/admin/users"), origin="watch")
        self.assertNotIn("category", record.to_dict())

    def test_id_parameter_adds_no_category(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(parameter="id"), origin="watch")
        self.assertNotIn("category", record.to_dict())

    def test_suspicious_name_adds_no_technology(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(subdomain="wordpress.example.com", technology=[]),
            origin="watch",
        )
        self.assertEqual(record.technologies, ())

    def test_cve_text_adds_nothing(self):
        from aec.research import sources

        record = sources.normalize_record(
            watch_record(notes="CVE-2024-1234 usable here"), origin="watch")
        self.assertNotIn("category", record.to_dict())
        self.assertEqual(record.technologies, ("laravel", "php 8.2"))

    def test_classification_ignores_content(self):
        from aec.research import sources

        scary = watch_record(
            endpoint="/admin", parameter="id", subdomain="prod.example.com")
        real = sources.normalize_record(scary, origin="watch")
        fixture = sources.normalize_record(scary, origin="fixture")
        self.assertEqual(real.source_mode, "REAL_WATCH_DATA")
        self.assertEqual(fixture.source_mode, "OFFLINE_FIXTURE")

    def test_same_content_same_record(self):
        from aec.research import sources

        first = sources.normalize_record(watch_record(), origin="watch")
        second = sources.normalize_record(watch_record(), origin="watch")
        self.assertEqual(first, second)


class TestNormalizeBatch(unittest.TestCase):
    def test_batch_normalizes_all(self):
        from aec.research import sources

        records = sources.normalize_batch(
            [watch_record(), watch_record(endpoint="/other")], origin="watch")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1].endpoint, "/other")

    def test_batch_skips_bad_with_report(self):
        from aec.research import sources

        records, refused = sources.normalize_batch(
            [watch_record(), watch_record(endpoint="")], origin="watch",
            collect_refused=True)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(refused), 1)

    def test_batch_non_sequence_refused(self):
        from aec.research import sources

        with self.assertRaises(ValueError):
            sources.normalize_batch("nope", origin="watch")


class TestGuard(unittest.TestCase):
    def test_fixture_record_not_production_claim(self):
        from aec.research import guard, sources

        record = sources.normalize_record(watch_record(), origin="fixture")
        self.assertFalse(guard.is_production_claim(record.to_dict()))

    def test_real_record_not_production_claim(self):
        from aec.research import guard, sources

        record = sources.normalize_record(watch_record(), origin="watch")
        self.assertFalse(guard.is_production_claim(record.to_dict()))

    def test_confirmed_claim_detected(self):
        from aec.research import guard

        self.assertTrue(guard.is_production_claim({"state": "CONFIRMED"}))

    def test_vulnerable_claim_detected(self):
        from aec.research import guard

        self.assertTrue(
            guard.is_production_claim({"label": "vulnerable"}))

    def test_ensure_raises_on_claim(self):
        from aec.research import guard

        with self.assertRaises(ValueError):
            guard.ensure_no_production_claim({"state": "CONFIRMED"}, "test")

    def test_ensure_passes_clean(self):
        from aec.research import guard, sources

        record = sources.normalize_record(watch_record(), origin="fixture")
        self.assertIsNone(
            guard.ensure_no_production_claim(record.to_dict(), "test"))

    def test_fixture_never_promotable(self):
        from aec.research import guard, sources

        record = sources.normalize_record(watch_record(), origin="fixture")
        self.assertFalse(guard.promotable_to_production(record.to_dict()))

    def test_real_needs_evidence_flag(self):
        from aec.research import guard, sources

        record = sources.normalize_record(watch_record(), origin="watch")
        # Without an authorized-evidence marker, real data is not
        # promotable either: promotion requires evidence + path.
        self.assertFalse(guard.promotable_to_production(record.to_dict()))

    def test_promotable_with_evidence_marker(self):
        from aec.research import guard, sources

        record = sources.normalize_record(watch_record(), origin="watch")
        document = record.to_dict()
        document["authorized_evidence"] = True
        self.assertFalse(guard.promotable_to_production(document))

    def test_mode_mismatch_detected(self):
        from aec.research import guard

        self.assertFalse(
            guard.same_source_mode("REAL_WATCH_DATA", "OFFLINE_FIXTURE"))
        self.assertTrue(
            guard.same_source_mode("REAL_WATCH_DATA", "REAL_WATCH_DATA"))


class TestSafetyGuards(unittest.TestCase):
    def test_no_forbidden_vocabulary_in_source(self):
        for name in MODULES:
            source = (RESEARCH_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((RESEARCH_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)


if __name__ == "__main__":
    unittest.main()
