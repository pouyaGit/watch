"""Focused offline tests for conservative reference URL canonicalization.

Covers the NEXT research-only engineering stage after the frozen
per-batch reference cache (which was intentionally whitespace-only):

- Cache-key-only canonicalization: fragments and clearly
  non-semantic tracking query parameters (``utm_*``, ``gclid``,
  ``fbclid``) are removed from the cache key, while the
  original discovered URL is exactly what reaches
  ``reference_fetch_fn`` / ``ReferenceCollector.fetch``.
- Semantic query parameters (``id``, ``token``, ``key``,
  ``page``, ``q``, unknown params, ...) always stay distinct.
- Non-tracking parameters keep their exact order, values, and
  percent-encoding; no host/path lowercasing, no trailing-slash
  normalization, no scheme normalization, no redirect merging.
- The cached value remains the verbatim ``ReferenceDocument``;
  its URL/content/hash/status are never rewritten.
- Scope stays strictly per-batch, in-memory, aggregate-only
  ``reference_cache: {hits}`` telemetry.

Strictly offline: no network, no subprocess, no Nuclei, no
browser, no DNS. All tests use fake ``reference_fetch_fn``
callables; no real ``ReferenceCollector`` HTTP requests occur.
"""

from __future__ import annotations

import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.researcher.reference_cache import (
    BatchReferenceCache,
    canonicalize_reference_url,
)


def _offline_guards():
    def _block(*args, **kwargs):
        raise AssertionError("network/subprocess forbidden in this test")

    return (
        patch.object(socket, "create_connection", _block),
        patch.object(socket, "socket", _block),
        patch.object(socket, "getaddrinfo", _block),
        patch.object(subprocess, "run", _block),
        patch.object(subprocess, "Popen", _block),
    )


def _doc(url: str, *, body: str = "body", hash_value: str = "h"):
    return {
        "url": url,
        "source_type": "github",
        "title": f"title {url}",
        "content": body,
        "status_code": 200,
        "content_hash": hash_value,
        "tags": [],
    }


def _recording_fetch(calls: list, *, body: str = "body"):
    """Fake fetch_fn: records the exact URL received, returns a doc keyed by it."""

    def fetch(url: str):
        calls.append(url)
        return _doc(url, body=body, hash_value=f"h-{len(calls)}")

    return fetch


class _BatchHarness:
    """Minimal run_cve_batch harness with offline guards."""

    def __init__(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def cleanup(self):
        self._tmpdir.cleanup()

    def run(self, research_fn, cve_ids, **kwargs):
        from ai.researcher.cve_batch import run_cve_batch

        guards = _offline_guards()
        for guard in guards:
            guard.start()
        try:
            return run_cve_batch(
                cve_ids,
                research_fn=research_fn,
                research_dir=self.tmp / "research",
                report_dir=self.tmp / "reports",
                retry_sleep_fn=lambda seconds: None,
                **kwargs,
            )
        finally:
            for guard in guards:
                guard.stop()


def _guarded(test_fn):
    """Decorator: run a cache unit test with socket/subprocess blocked."""

    def wrapper(self):
        guards = _offline_guards()
        for guard in guards:
            guard.start()
        try:
            return test_fn(self)
        finally:
            for guard in guards:
                guard.stop()

    return wrapper


class CanonicalizeUnitTests(unittest.TestCase):
    @_guarded
    def test_whitespace_still_stripped(self) -> None:
        self.assertEqual(
            canonicalize_reference_url("  https://x.test/a  "),
            "https://x.test/a",
        )

    @_guarded
    def test_empty_and_none_safe(self) -> None:
        self.assertEqual(canonicalize_reference_url(""), "")
        self.assertEqual(canonicalize_reference_url(None), "")
        self.assertEqual(canonicalize_reference_url("   "), "")

    @_guarded
    def test_fragment_removed(self) -> None:
        self.assertEqual(
            canonicalize_reference_url("https://example.test/a#one"),
            "https://example.test/a",
        )
        self.assertEqual(
            canonicalize_reference_url("https://example.test/a#one"),
            canonicalize_reference_url("https://example.test/a#two"),
        )
        self.assertEqual(
            canonicalize_reference_url("https://example.test/a#one"),
            canonicalize_reference_url("https://example.test/a"),
        )

    @_guarded
    def test_tracking_params_removed(self) -> None:
        base = "https://x.test/a?id=1"
        for tracking in (
            "utm_source=a",
            "utm_source=b",
            "utm_campaign=x",
            "utm_medium=y",
            "utm_term=z",
            "utm_content=w",
            "gclid=AAA",
            "gclid=BBB",
            "fbclid=CCC",
            "fbclid=DDD",
        ):
            with self.subTest(tracking=tracking):
                self.assertEqual(
                    canonicalize_reference_url(f"{base}&{tracking}"),
                    base,
                )

    @_guarded
    def test_tracking_only_url_collapses_to_bare_path(self) -> None:
        self.assertEqual(
            canonicalize_reference_url("https://x.test/a?utm_source=a"),
            "https://x.test/a",
        )
        self.assertEqual(
            canonicalize_reference_url("https://x.test/a?gclid=A&fbclid=B"),
            "https://x.test/a",
        )

    @_guarded
    def test_semantic_params_preserved(self) -> None:
        for param in (
            "id=1",
            "token=abc",
            "key=K",
            "page=2",
            "q=hello",
            "query=hello",
            "search=hello",
            "lang=en",
            "locale=en",
            "version=3",
            "unknownparam=zzz",
        ):
            with self.subTest(param=param):
                key = canonicalize_reference_url(f"https://x.test/a?{param}")
                self.assertEqual(key, f"https://x.test/a?{param}")

    @_guarded
    def test_must_remain_distinct(self) -> None:
        distinct_pairs = [
            ("https://x.test/a?id=1", "https://x.test/a?id=2"),
            ("https://x.test/a?token=a", "https://x.test/a?token=b"),
            ("https://x.test/a?key=a", "https://x.test/a?key=b"),
            ("https://x.test/a?page=1", "https://x.test/a?page=2"),
            ("https://x.test/a?q=a", "https://x.test/a?q=b"),
            ("https://x.test/a?zzz=1", "https://x.test/a?zzz=2"),
            ("https://x.test/a", "https://x.test/a?b=1"),
            ("https://x.test/a", "https://x.test/a/"),
            ("http://x.test/a", "https://x.test/a"),
            ("https://x.test/a", "https://X.test/a"),
            ("https://x.test/A", "https://x.test/a"),
        ]
        for first, second in distinct_pairs:
            with self.subTest(first=first, second=second):
                self.assertNotEqual(
                    canonicalize_reference_url(first),
                    canonicalize_reference_url(second),
                )

    @_guarded
    def test_query_order_not_changed(self) -> None:
        url = "https://x.test/a?b=2&a=1&id=9"
        self.assertEqual(canonicalize_reference_url(url), url)

    @_guarded
    def test_percent_encoding_not_rewritten(self) -> None:
        url = "https://x.test/a?redirect=https%3A%2F%2Fy.test%2Fb&id=%41%42"
        self.assertEqual(canonicalize_reference_url(url), url)
        url2 = "https://x.test/a%2Fb?x=%2F"
        self.assertEqual(canonicalize_reference_url(url2), url2)

    @_guarded
    def test_malformed_urls_do_not_crash(self) -> None:
        for bad in (":::not a url:::", "https://", "://missing-scheme", "\x00"):
            with self.subTest(bad=bad):
                result = canonicalize_reference_url(bad)
                self.assertIsInstance(result, str)


class FragmentCacheTests(unittest.TestCase):
    @_guarded
    def test_different_fragments_one_fetch_one_hit(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://example.test/a#one"
        second = "https://example.test/a#two"
        doc_one = cache.fetch(first)
        doc_two = cache.fetch(second)
        self.assertEqual(calls, [first])
        self.assertEqual(cache.hits, 1)
        self.assertIs(doc_two, doc_one)

    @_guarded
    def test_original_url_passed_to_fetch_unchanged(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        original = "https://example.test/a?utm_source=x#frag"
        cache.fetch(original)
        cache.fetch("https://example.test/a#other")
        self.assertEqual(calls, [original])
        self.assertEqual(cache.hits, 1)

    @_guarded
    def test_cached_document_not_rewritten(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://example.test/a#one"
        cache.fetch(first)
        stored = cache.state()["store"][canonicalize_reference_url(first)]
        self.assertEqual(stored["url"], first)


class TrackingCacheTests(unittest.TestCase):
    @_guarded
    def test_utm_source_variants_one_fetch(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://x.test/a?id=1&utm_source=a"
        cache.fetch(first)
        cache.fetch("https://x.test/a?id=1&utm_source=b")
        self.assertEqual(calls, [first])
        self.assertEqual(cache.hits, 1)

    @_guarded
    def test_utm_campaign_variants_one_fetch(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://x.test/a?utm_campaign=one"
        cache.fetch(first)
        cache.fetch("https://x.test/a?utm_campaign=two")
        self.assertEqual(calls, [first])
        self.assertEqual(cache.hits, 1)

    @_guarded
    def test_gclid_variants_one_fetch(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://x.test/a?gclid=AAA"
        cache.fetch(first)
        cache.fetch("https://x.test/a?gclid=BBB")
        self.assertEqual(calls, [first])
        self.assertEqual(cache.hits, 1)

    @_guarded
    def test_fbclid_variants_one_fetch(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://x.test/a?fbclid=AAA"
        cache.fetch(first)
        cache.fetch("https://x.test/a?fbclid=BBB")
        self.assertEqual(calls, [first])
        self.assertEqual(cache.hits, 1)


class SemanticCacheTests(unittest.TestCase):
    def _two_fetches_case(self, first: str, second: str) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        cache.fetch(first)
        cache.fetch(second)
        self.assertEqual(calls, [first, second])
        self.assertEqual(cache.hits, 0)

    @_guarded
    def test_id_differs(self) -> None:
        self._two_fetches_case(
            "https://x.test/a?id=1", "https://x.test/a?id=2"
        )

    @_guarded
    def test_token_differs(self) -> None:
        self._two_fetches_case(
            "https://x.test/a?token=a", "https://x.test/a?token=b"
        )

    @_guarded
    def test_key_differs(self) -> None:
        self._two_fetches_case(
            "https://x.test/a?key=a", "https://x.test/a?key=b"
        )

    @_guarded
    def test_page_differs(self) -> None:
        self._two_fetches_case(
            "https://x.test/a?page=1", "https://x.test/a?page=2"
        )

    @_guarded
    def test_q_differs(self) -> None:
        self._two_fetches_case(
            "https://x.test/a?q=a", "https://x.test/a?q=b"
        )

    @_guarded
    def test_unknown_param_differs(self) -> None:
        self._two_fetches_case(
            "https://x.test/a?zzz=1", "https://x.test/a?zzz=2"
        )


class MixedCacheTests(unittest.TestCase):
    @_guarded
    def test_tracking_plus_semantic(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://x.test/a?id=1&utm_source=a"
        cache.fetch(first)
        # Same semantic id, different tracking value: merge.
        cache.fetch("https://x.test/a?id=1&utm_source=b")
        self.assertEqual(calls, [first])
        self.assertEqual(cache.hits, 1)
        # Different semantic id, same tracking value: distinct.
        cache.fetch("https://x.test/a?id=2&utm_source=a")
        self.assertEqual(len(calls), 2)
        self.assertEqual(cache.hits, 1)

    @_guarded
    def test_query_order_preserved_on_fetch(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        ordered = "https://x.test/a?b=2&a=1"
        cache.fetch(ordered)
        cache.fetch("https://x.test/a?a=1&b=2")
        # Order is significant: no reordering means two fetches.
        self.assertEqual(calls, [ordered, "https://x.test/a?a=1&b=2"])
        self.assertEqual(cache.hits, 0)


class FetchSafetyTests(unittest.TestCase):
    @_guarded
    def test_empty_and_none_safe(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        self.assertIsNone(cache.fetch(""))
        self.assertIsNone(cache.fetch(None))
        self.assertIsNone(cache.fetch("   "))
        self.assertEqual(calls, [])
        self.assertEqual(cache.hits, 0)

    @_guarded
    def test_malformed_urls_do_not_crash(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        bad = ":::not a url:::"
        first = cache.fetch(bad)
        self.assertIsNotNone(first)
        second = cache.fetch(bad)
        self.assertIs(second, first)
        self.assertEqual(calls, [bad])
        self.assertEqual(cache.hits, 1)

    @_guarded
    def test_miss_not_cached(self) -> None:
        calls: list[str] = []

        def miss_once(url: str):
            calls.append(url)
            if len(calls) == 1:
                return None
            return _doc(url)

        cache = BatchReferenceCache(fetch_fn=miss_once)
        url = "https://example.test/flaky#frag"
        self.assertIsNone(cache.fetch(url))
        self.assertIsNotNone(cache.fetch(url))
        self.assertEqual(calls, [url, url])
        self.assertEqual(cache.hits, 0)


class CacheKeyOnlyRegressionTests(unittest.TestCase):
    @_guarded
    def test_fetch_receives_exact_discovered_url(self) -> None:
        """Canonicalization must be cache-key-only.

        Two discovered URLs that differ only by fragment and
        tracking parameters share one cache entry, but the fetch
        primitive receives the first discovered URL byte-for-byte
        (fragment and full query intact).
        """
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        first = "https://example.test/a?id=1&utm_source=first#one"
        second = "https://example.test/a?id=1&utm_source=second#two"
        cache.fetch(first)
        cache.fetch(second)
        self.assertEqual(calls, [first])
        self.assertEqual(calls[0], first)
        self.assertIn("#one", calls[0])
        self.assertIn("utm_source=first", calls[0])
        stored = cache.state()["store"][canonicalize_reference_url(first)]
        self.assertEqual(stored["url"], first)

    @_guarded
    def test_whitespace_url_still_works(self) -> None:
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        cache.fetch("  https://example.test/a  ")
        cache.fetch("https://example.test/a")
        self.assertEqual(calls, ["https://example.test/a"])
        self.assertEqual(cache.hits, 1)


class BatchIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def _ok_payload(self, cve_id: str) -> dict:
        return {
            "research_version": "cli-1",
            "mode": "research-only",
            "authoritative": False,
            "research_status": "completed",
            "llm_status": "ok",
            "outage_bucket": None,
            "outage_events": [],
            "retry_attempted": False,
            "retry_succeeded": None,
            "cve": {
                "id": cve_id,
                "vendor": [],
                "products": [],
                "cvss_score": None,
                "cvss_vector": None,
            },
            "research": {
                "title": f"ok {cve_id}",
                "summary": "offline fixture with no HTTP method.",
                "severity": "medium",
                "cve_ids": [cve_id],
                "affected_products": [],
                "affected_versions": [],
                "nuclei_candidate": False,
                "references": [],
                "evidence": [],
            },
            "output_path": f"/tmp/ai_data/research/{cve_id}.cli.json",
        }

    def _research_fn_with_cache(self, discoveries: dict, cache_box: dict):
        def research_fn(cve_id: str, skip_llm: bool = False) -> dict:
            from ai.researcher.research_context import build_research_contexts

            cache: BatchReferenceCache = cache_box["cache"]
            documents: list[dict] = []
            for url in discoveries.get(cve_id, []):
                doc = cache.fetch(url)
                if doc is None:
                    continue
                documents.append(
                    {
                        "url": doc["url"],
                        "source_type": "github",
                        "title": doc["title"],
                        "priority": 90,
                        "tags": ["nvd_reference"],
                        "content": doc["content"],
                    }
                )
            build_research_contexts(
                documents=documents,
                cve_id=cve_id,
                keywords=[cve_id],
            )
            return self._ok_payload(cve_id)

        return research_fn

    def test_canonical_merge_inside_one_batch(self) -> None:
        """Fragment/tracking variants merge within a single batch."""
        calls: list[str] = []
        cache = BatchReferenceCache(fetch_fn=_recording_fetch(calls))
        box = {"cache": cache}
        discoveries = {
            "CVE-2026-7001": ["https://example.test/a#one"],
            "CVE-2026-7002": ["https://example.test/a#two"],
        }
        aggregate = self.harness.run(
            self._research_fn_with_cache(discoveries, box),
            ["CVE-2026-7001", "CVE-2026-7002"],
            reference_cache=cache,
        )
        self.assertEqual(calls, ["https://example.test/a#one"])
        self.assertEqual(aggregate["reference_cache"], {"hits": 1})

    def test_no_cache_sharing_between_batches(self) -> None:
        """Two batch invocations never share canonicalized entries."""
        first_calls: list[str] = []
        second_calls: list[str] = []
        url_one = "https://example.test/shared#one"
        url_two = "https://example.test/shared#two"

        cache_one = BatchReferenceCache(
            fetch_fn=_recording_fetch(first_calls)
        )
        box_one = {"cache": cache_one}
        first = self.harness.run(
            self._research_fn_with_cache(
                {
                    "CVE-2026-7011": [url_one],
                    "CVE-2026-7012": [url_two],
                },
                box_one,
            ),
            ["CVE-2026-7011", "CVE-2026-7012"],
            reference_cache=cache_one,
        )
        self.assertEqual(first["reference_cache"], {"hits": 1})
        self.assertEqual(first_calls, [url_one])

        cache_two = BatchReferenceCache(
            fetch_fn=_recording_fetch(second_calls)
        )
        box_two = {"cache": cache_two}
        second = self.harness.run(
            self._research_fn_with_cache(
                {
                    "CVE-2026-7013": [url_one],
                    "CVE-2026-7014": [url_two],
                },
                box_two,
            ),
            ["CVE-2026-7013", "CVE-2026-7014"],
            reference_cache=cache_two,
        )
        # Fresh batch: fetches again, then one hit. Nothing leaks.
        self.assertEqual(second["reference_cache"], {"hits": 1})
        self.assertEqual(second_calls, [url_one])
        self.assertEqual(set(first_calls), {url_one})
        self.assertEqual(cache_one.hits, 1)
        self.assertEqual(cache_two.hits, 1)

    def test_default_batches_do_not_share(self) -> None:
        """Default (caller-owned) caches from two runs stay isolated."""

        def payload_fn(cve_id: str, skip_llm: bool = False) -> dict:
            return self._ok_payload(cve_id)

        first = self.harness.run(
            payload_fn, ["CVE-2026-7021", "CVE-2026-7022"]
        )
        second = self.harness.run(
            payload_fn, ["CVE-2026-7021", "CVE-2026-7022"]
        )
        self.assertEqual(first["reference_cache"], {"hits": 0})
        self.assertEqual(second["reference_cache"], {"hits": 0})


if __name__ == "__main__":
    unittest.main()
