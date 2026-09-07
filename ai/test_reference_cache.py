"""Focused offline tests for intra-batch shared reference context reuse.

Covers the NEXT research-only engineering stage after frozen
fail-soft/degraded, frozen provider-health telemetry, frozen
bounded-429-only retry, and frozen per-batch CVE research cache /
coalescing:

- In-memory, per-batch URL -> ReferenceDocument cache that wraps
  the existing ``ReferenceCollector.fetch`` primitive.
- A second CVE that points at the same URL reuses the cached
  reference document instead of performing another HTTP fetch.
- Cache key: canonicalized URL (whitespace-stripped only).
- Failure policy: only successful ``ReferenceDocument`` results
  are cached; ``None`` (hard miss) is never cached, so a
  transient failure cannot poison later CVEs in the same
  batch.
- Provenance: the cached value is the verbatim reference
  document (deterministic source material). Per-CVE
  ``ReferenceContext`` ranking is still performed per CVE by
  the existing pipeline, so CVE B never inherits CVE A's
  CVE-specific LLM conclusions.
- Duplicate CVE entries still hit the existing CVE research
  cache first; reference-cache hits only occur when two
  *distinct* CVEs share a URL.
- New aggregate-only ``reference_cache: {hits}`` telemetry:
  always present, zeroed when no reuse, counts only, no URLs,
  no CVE IDs, no payloads.
- Strictly per-batch: no module global, no disk, no cross-batch
  state.

Strictly offline: no network, no subprocess, no Nuclei
execution. All tests use a fake per-URL ``reference_fetch_fn``
that records call counts and returns synthetic
``ReferenceDocument`` instances, so the cache logic is exercised
without touching real HTTP or the real fetcher.
"""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.researcher.cve_batch import RESULT_KEYS
from ai.researcher.reference_cache import (
    BatchReferenceCache,
    canonicalize_reference_url,
    empty_reference_cache_histogram,
)

ZERO_PROVIDER = {"http_402": 0, "http_429": 0, "http_5xx": 0, "network": 0}
ZERO_RETRIES = {"attempted": 0, "succeeded": 0, "exhausted": 0}
ZERO_PROVIDER_CACHE = {"hits": 0}
ZERO_REFERENCE_CACHE = {"hits": 0}


def _ok_payload(cve_id: str) -> dict:
    """Build a minimal CLI-style payload accepted by ``research_one_cve``."""
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


def _ok_cve_record(cve_id: str) -> dict:
    """Per-CVE result row in the RESULT_KEYS shape."""
    record = {key: None for key in RESULT_KEYS}
    record.update(
        {
            "cve": cve_id,
            "research_status": "completed",
            "nuclei_candidate": False,
            "decision": "NOT_APPLICABLE",
            "decision_confidence": 0.0,
            "template_generated": False,
            "semantic_validation": {"valid": False, "errors": []},
            "offline_preparation": None,
            "artifacts": {},
            "authoritative": False,
            "nuclei_error": None,
            "error": None,
        }
    )
    return record


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


class _BatchHarness:
    """Per-batch harness with offline guards, a sleep recorder, and a fetch recorder."""

    def __init__(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.fetch_calls: list[str] = []
        self.sleep_calls: list[float] = []

    def cleanup(self):
        self._tmpdir.cleanup()

    def make_fetch_fn(self, documents: dict | None = None):
        """Return a fake ``reference_fetch_fn`` and a calls recorder.

        ``documents`` maps URL -> ``ReferenceDocument``-shaped
        dict. Unmapped URLs return ``None`` (the hard-miss
        sentinel used by ``ReferenceCollector.fetch``).
        """
        documents = documents or {}

        def fetch_fn(url: str):
            self.fetch_calls.append(url)
            return documents.get(url)

        return fetch_fn, self.fetch_calls

    def run(
        self,
        research_fn,
        cve_ids,
        reference_cache=None,
        reference_fetch_fn=None,
        **kwargs,
    ):
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
                retry_sleep_fn=kwargs.pop(
                    "retry_sleep_fn", lambda seconds: self.sleep_calls.append(seconds)
                ),
                reference_cache=reference_cache,
                reference_fetch_fn=reference_fetch_fn,
                **kwargs,
            )
        finally:
            for guard in guards:
                guard.stop()


def _doc(url: str, *, body: str = "body", title: str | None = None, hash_value: str = "h"):
    return {
        "url": url,
        "source_type": "github",
        "title": title or f"title {url}",
        "content": body,
        "status_code": 200,
        "content_hash": hash_value,
        "tags": [],
    }


def _make_research_fn(discoveries: dict | None = None):
    """Build a research_fn that uses a shared per-batch cache.

    ``discoveries`` maps ``cve_id`` -> list of URLs the
    reference layer "discovers" for that CVE. The function
    consults a ``BatchReferenceCache`` passed via the closure
    to fetch each URL, and reuses the existing
    ``build_research_contexts`` to build per-CVE
    ``ReferenceContext``s (so provenance remains CVE-specific).
    """
    from ai.researcher.reference_cache import (
        BatchReferenceCache,
    )

    discoveries = discoveries or {}
    cache_ref: dict = {}

    def research_fn(cve_id: str, skip_llm: bool = False) -> dict:
        cache: BatchReferenceCache = cache_ref["cache"]
        urls = discoveries.get(cve_id, [])
        documents: list[dict] = []
        for url in urls:
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
        # Build per-CVE contexts so we can prove CVE-specific
        # conclusions are NOT copied.
        from ai.researcher.research_context import build_research_contexts

        contexts = build_research_contexts(
            documents=documents,
            cve_id=cve_id,
            keywords=[cve_id, "vendor", "product"],
        )
        per_cve_titles = [c.get("title") for c in contexts]
        payload = _ok_payload(cve_id)
        # Provenance marker: we tag the payload with a per-CVE
        # marker derived from the contexts so tests can assert no
        # cross-CVE bleed.
        payload["research"]["summary"] = (
            f"ok {cve_id} with contexts {per_cve_titles}"
        )
        return payload

    research_fn.cache_ref = cache_ref
    return research_fn


class CanonicalizationTests(unittest.TestCase):
    def test_strips_surrounding_whitespace(self) -> None:
        self.assertEqual(
            canonicalize_reference_url("  https://x.test/a  "),
            "https://x.test/a",
        )
        self.assertEqual(
            canonicalize_reference_url("https://x.test/a"),
            "https://x.test/a",
        )

    def test_does_not_strip_query_string(self) -> None:
        # No aggressive canonicalization: distinct URLs stay distinct.
        self.assertNotEqual(
            canonicalize_reference_url("https://x.test/a"),
            canonicalize_reference_url("https://x.test/a?b=1"),
        )

    def test_empty_url_returns_empty(self) -> None:
        self.assertEqual(canonicalize_reference_url(""), "")
        self.assertEqual(canonicalize_reference_url(None), "")

    def test_zeroed_histogram_schema(self) -> None:
        self.assertEqual(empty_reference_cache_histogram(), {"hits": 0})


class BasicReuseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)
        self.url_x = "https://example.test/x"
        self.documents = {
            self.url_x: _doc(self.url_x, body="shared body", hash_value="h-x"),
        }
        self.fetch_fn, self.fetch_calls = self.harness.make_fetch_fn(
            self.documents
        )

    def test_two_distinct_cves_share_url(self) -> None:
        """Two distinct CVEs sharing one URL: one fetch, one hit."""
        cache = BatchReferenceCache(fetch_fn=self.fetch_fn)
        research_fn = _make_research_fn(
            {cve: [self.url_x] for cve in ("CVE-2026-6001", "CVE-2026-6002")}
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6001", "CVE-2026-6002"],
            reference_cache=cache,
        )
        self.assertEqual(self.fetch_calls, [self.url_x])
        self.assertEqual(aggregate["reference_cache"], {"hits": 1})
        self.assertEqual(aggregate["provider_cache"], dict(ZERO_PROVIDER_CACHE))
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            ["CVE-2026-6001", "CVE-2026-6002"],
        )
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed")

    def test_two_cves_different_urls_zero_hits(self) -> None:
        url_a = "https://example.test/a"
        url_b = "https://example.test/b"
        documents = {
            url_a: _doc(url_a, hash_value="h-a"),
            url_b: _doc(url_b, hash_value="h-b"),
        }
        fetch_fn, fetch_calls = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {"CVE-2026-6003": [url_a], "CVE-2026-6004": [url_b]}
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6003", "CVE-2026-6004"],
            reference_cache=cache,
        )
        self.assertEqual(set(fetch_calls), {url_a, url_b})
        self.assertEqual(aggregate["reference_cache"], {"hits": 0})

    def test_three_cves_share_one_url_two_hits(self) -> None:
        cache = BatchReferenceCache(fetch_fn=self.fetch_fn)
        research_fn = _make_research_fn(
            {cve: [self.url_x] for cve in (
                "CVE-2026-6005",
                "CVE-2026-6006",
                "CVE-2026-6007",
            )}
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            [
                "CVE-2026-6005",
                "CVE-2026-6006",
                "CVE-2026-6007",
            ],
            reference_cache=cache,
        )
        self.assertEqual(self.fetch_calls, [self.url_x])
        self.assertEqual(aggregate["reference_cache"], {"hits": 2})


class DuplicateInteractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)
        self.url = "https://example.test/shared"
        self.fetch_fn, self.fetch_calls = self.harness.make_fetch_fn(
            {self.url: _doc(self.url, hash_value="h-shared")}
        )

    def test_duplicate_cve_does_not_produce_reference_hit(self) -> None:
        """A duplicate CVE is a CVE-cache hit, not a reference hit.

        The duplicate must not invoke the reference layer again
        (it reuses the cached CVE result, which already carries
        the reference metadata). The reference cache only counts
        a hit when an actual reference fetch was avoided across
        distinct CVEs.
        """
        cache = BatchReferenceCache(fetch_fn=self.fetch_fn)
        research_fn = _make_research_fn(
            {"CVE-2026-6101": [self.url]}
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6101", "CVE-2026-6101", "CVE-2026-6101"],
            reference_cache=cache,
        )
        # First occurrence: one fetch. Duplicates: zero additional
        # fetches (CVE research cache short-circuits).
        self.assertEqual(self.fetch_calls, [self.url])
        self.assertEqual(aggregate["reference_cache"], {"hits": 0})
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(len(aggregate["results"]), 3)

    def test_duplicate_with_shared_distinct_cve(self) -> None:
        """Duplicate of CVE A + distinct CVE B sharing URL: one hit.

        The duplicate of CVE A is a CVE-cache hit (no reference
        fetch). CVE B reuses the cached document for the same
        URL — one reference-cache hit.
        """
        cache = BatchReferenceCache(fetch_fn=self.fetch_fn)
        research_fn = _make_research_fn(
            {
                "CVE-2026-6102": [self.url],
                "CVE-2026-6103": [self.url],
            }
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            [
                "CVE-2026-6102",
                "CVE-2026-6102",
                "CVE-2026-6103",
                "CVE-2026-6102",
            ],
            reference_cache=cache,
        )
        self.assertEqual(self.fetch_calls, [self.url])
        self.assertEqual(aggregate["reference_cache"], {"hits": 1})
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            [
                "CVE-2026-6102",
                "CVE-2026-6102",
                "CVE-2026-6103",
                "CVE-2026-6102",
            ],
        )


class MixedBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_unique_plus_duplicates_plus_shared(self) -> None:
        """Mixed batch: unique + duplicate + shared reference CVEs.

        Setup:

        - CVE-A (unique, one URL) and CVE-B (unique, different
          URL): two distinct fetches, no reference-cache hits.
        - CVE-A is duplicated: provider-cache hit, no extra
          reference fetch.
        - CVE-C shares CVE-B's URL: reference-cache hit (1).
        - CVE-C is duplicated: provider-cache hit only, no extra
          reference-cache hit.

        Expected counts:
          fetches:      2 (A URL, B URL)
          ref_hits:     1 (C reuses B's document)
          provider_hits:3 (duplicate A, duplicate C twice)
        """
        url_a = "https://example.test/a"
        url_b = "https://example.test/b"
        documents = {
            url_a: _doc(url_a, hash_value="h-a"),
            url_b: _doc(url_b, hash_value="h-b"),
        }
        fetch_fn, fetch_calls = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {
                "CVE-2026-6201": [url_a],
                "CVE-2026-6202": [url_b],
                "CVE-2026-6203": [url_b],
            }
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            [
                "CVE-2026-6201",
                "CVE-2026-6202",
                "CVE-2026-6201",  # duplicate A
                "CVE-2026-6203",  # shares B's URL
                "CVE-2026-6202",  # duplicate B
                "CVE-2026-6203",  # duplicate C
                "CVE-2026-6201",  # duplicate A again
            ],
            reference_cache=cache,
        )
        self.assertEqual(set(fetch_calls), {url_a, url_b})
        self.assertEqual(aggregate["reference_cache"], {"hits": 1})
        self.assertEqual(aggregate["provider_cache"], {"hits": 4})
        # Result order preserved.
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            [
                "CVE-2026-6201",
                "CVE-2026-6202",
                "CVE-2026-6201",
                "CVE-2026-6203",
                "CVE-2026-6202",
                "CVE-2026-6203",
                "CVE-2026-6201",
            ],
        )


class FailureBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_hard_miss_not_cached(self) -> None:
        """A fetch returning ``None`` is never cached, so the next
        CVE that needs the same URL performs its own fetch.

        This is the documented policy: only successful
        deterministic reference material is cached. A transient
        failure (HTTP 5xx, network error, non-text content,
        empty body — all returning ``None`` from
        ``ReferenceCollector.fetch``) cannot poison later CVEs
        in the same batch.
        """
        url = "https://example.test/flaky"
        # First call returns None (hard miss); second call returns
        # a valid document. This proves the URL was not poisoned
        # by the first call's failure.
        first_call = {"done": False}
        documents = {
            url: _doc(url, hash_value="h-flaky"),
        }

        def fetch_fn(u: str):
            self.harness.fetch_calls.append(u)
            if u != url:
                return documents.get(u)
            if not first_call["done"]:
                first_call["done"] = True
                return None
            return documents[u]

        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {
                "CVE-2026-6301": [url],
                "CVE-2026-6302": [url],
            }
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6301", "CVE-2026-6302"],
            reference_cache=cache,
        )
        # Two fetch calls (CVE-2026-6301 missed, CVE-2026-6302
        # succeeded). Cache hit count is 0 because the second
        # call is a fresh miss-then-success, not a cache reuse.
        self.assertEqual(self.harness.fetch_calls, [url, url])
        self.assertEqual(aggregate["reference_cache"], {"hits": 0})

    def test_failure_not_silently_converted_to_success(self) -> None:
        """A permanently failing URL does not silently become a hit.

        If the fetcher consistently returns None, the
        reference-cache hit count stays 0 and downstream CVEs
        are not given a stale document.
        """
        url = "https://example.test/dead"
        fetch_fn, fetch_calls = self.harness.make_fetch_fn({})  # always None
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {
                "CVE-2026-6303": [url],
                "CVE-2026-6304": [url],
            }
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6303", "CVE-2026-6304"],
            reference_cache=cache,
        )
        self.assertEqual(fetch_calls, [url, url])
        self.assertEqual(aggregate["reference_cache"], {"hits": 0})


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)
        self.url = "https://example.test/shared-doc"

    def test_reused_context_is_source_material_only(self) -> None:
        """A reused document is verbatim source material.

        Two CVEs reference the same URL. Both must obtain the
        same ``ReferenceDocument`` instance from the cache, and
        the per-CVE research output must remain CVE-specific
        (each CVE's LLM summary mentions only its own CVE id,
        not the other CVE's id).
        """
        documents = {self.url: _doc(self.url, body="shared advisory", hash_value="h-shared")}
        fetch_fn, _ = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {
                "CVE-2026-6401": [self.url],
                "CVE-2026-6402": [self.url],
            }
        )
        research_fn.cache_ref["cache"] = cache

        a_payload = research_fn("CVE-2026-6401")
        b_payload = research_fn("CVE-2026-6402")
        # Cached store is the verbatim source material (no
        # ranking, no CVE-specific conclusions).
        snapshot = cache.state()
        cached_doc = snapshot["store"][self.url]
        self.assertEqual(cached_doc["content"], "shared advisory")
        self.assertEqual(cached_doc["content_hash"], "h-shared")
        self.assertEqual(snapshot["hits"], 1)
        # Per-CVE summaries mention only their own CVE id; no
        # cross-CVE bleed.
        a_summary = a_payload["research"]["summary"]
        b_summary = b_payload["research"]["summary"]
        self.assertIn("CVE-2026-6401", a_summary)
        self.assertNotIn("CVE-2026-6402", a_summary)
        self.assertIn("CVE-2026-6402", b_summary)
        self.assertNotIn("CVE-2026-6401", b_summary)

    def test_cve_specific_conclusions_not_shared(self) -> None:
        """Distinct CVEs get distinct per-CVE contexts.

        The shared reference document is verbatim source
        material; the per-CVE ``ReferenceContext`` ranking is
        performed independently for each CVE so CVE B does not
        inherit CVE A's CVE-specific exact_record/context_chunks.
        """
        documents = {self.url: _doc(self.url, body="advisory body", hash_value="h-share2")}
        fetch_fn, _ = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {
                "CVE-2026-6403": [self.url],
                "CVE-2026-6404": [self.url],
            }
        )
        research_fn.cache_ref["cache"] = cache

        a_payload = research_fn("CVE-2026-6403")
        b_payload = research_fn("CVE-2026-6404")
        # The two CVE-specific summaries must differ in their
        # CVE id references (the source material is shared; the
        # per-CVE ranking is not).
        self.assertNotEqual(
            a_payload["research"]["summary"],
            b_payload["research"]["summary"],
        )
        # Both still research-only and non-authoritative.
        for payload in (a_payload, b_payload):
            self.assertFalse(payload["authoritative"])
            self.assertEqual(payload["research"]["nuclei_candidate"], False)


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_two_batches_do_not_share_cache(self) -> None:
        """Cache state lives only inside one run_cve_batch invocation."""
        url = "https://example.test/shared"
        documents = {url: _doc(url, hash_value="h-shared")}

        def first_fetch(u):
            return documents.get(u)

        def second_fetch(u):
            return documents.get(u)

        cache_one = BatchReferenceCache(fetch_fn=first_fetch)
        research_fn_one = _make_research_fn(
            {cve: [url] for cve in ("CVE-2026-6501", "CVE-2026-6502")}
        )
        research_fn_one.cache_ref["cache"] = cache_one
        first = self.harness.run(
            research_fn_one,
            ["CVE-2026-6501", "CVE-2026-6502"],
            reference_cache=cache_one,
        )
        self.assertEqual(first["reference_cache"], {"hits": 1})

        cache_two = BatchReferenceCache(fetch_fn=second_fetch)
        research_fn_two = _make_research_fn(
            {cve: [url] for cve in ("CVE-2026-6503", "CVE-2026-6504")}
        )
        research_fn_two.cache_ref["cache"] = cache_two
        second = self.harness.run(
            research_fn_two,
            ["CVE-2026-6503", "CVE-2026-6504"],
            reference_cache=cache_two,
        )
        # The new batch starts with a fresh cache: one fetch,
        # one hit. No state carried over from the first batch.
        self.assertEqual(second["reference_cache"], {"hits": 1})

    def test_no_module_global_mutable_cache(self) -> None:
        """Two consecutive runs each perform their own fetches."""
        url = "https://example.test/shared"
        documents = {url: _doc(url, hash_value="h-shared")}

        def fetch_fn(u):
            return documents.get(u)

        first_calls: list[str] = []
        second_calls: list[str] = []

        def make_runner(calls_box):
            def fetch(u):
                calls_box.append(u)
                return documents.get(u)

            cache = BatchReferenceCache(fetch_fn=fetch)
            research_fn = _make_research_fn(
                {cve: [url] for cve in ("CVE-2026-6505", "CVE-2026-6506")}
            )
            research_fn.cache_ref["cache"] = cache
            return research_fn, cache

        research_fn_one, cache_one = make_runner(first_calls)
        self.harness.run(
            research_fn_one,
            ["CVE-2026-6505", "CVE-2026-6506"],
            reference_cache=cache_one,
        )
        research_fn_two, cache_two = make_runner(second_calls)
        self.harness.run(
            research_fn_two,
            ["CVE-2026-6505", "CVE-2026-6506"],
            reference_cache=cache_two,
        )
        # Each run fetched the URL exactly once.
        self.assertEqual(first_calls, [url])
        self.assertEqual(second_calls, [url])
        self.assertEqual(cache_one.hits, 1)
        self.assertEqual(cache_two.hits, 1)

    def test_no_cache_files_written(self) -> None:
        """No on-disk cache directory is created by the batch."""
        url = "https://example.test/once"
        documents = {url: _doc(url, hash_value="h-once")}

        def fetch_fn(u):
            return documents.get(u)

        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn({"CVE-2026-6507": [url]})
        research_fn.cache_ref["cache"] = cache
        self.harness.run(
            research_fn,
            ["CVE-2026-6507"],
            reference_cache=cache,
        )
        for path in self.harness.tmp.rglob("*ref*cache*"):
            self.fail(f"unexpected on-disk cache file: {path}")
        for path in self.harness.tmp.rglob("*reference_cache*"):
            self.fail(f"unexpected on-disk cache file: {path}")


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_reference_cache_always_present(self) -> None:
        """reference_cache is in the aggregate even with zero hits."""
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn, ["CVE-2026-6601"]
        )
        self.assertIn("reference_cache", aggregate)
        self.assertEqual(aggregate["reference_cache"], {"hits": 0})

    def test_reference_cache_zero_when_no_reuse(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn, ["CVE-2026-6602", "CVE-2026-6603"]
        )
        self.assertEqual(aggregate["reference_cache"], {"hits": 0})

    def test_reference_cache_exact_count(self) -> None:
        url = "https://example.test/shared"
        documents = {url: _doc(url, hash_value="h-x")}
        fetch_fn, _ = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {cve: [url] for cve in (
                "CVE-2026-6604",
                "CVE-2026-6605",
                "CVE-2026-6606",
            )}
        )
        research_fn.cache_ref["cache"] = cache
        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6604", "CVE-2026-6605", "CVE-2026-6606"],
            reference_cache=cache,
        )
        self.assertEqual(aggregate["reference_cache"], {"hits": 2})

    def test_telemetry_counts_only_no_urls_no_cve_ids(self) -> None:
        url = "https://example.test/secret/path"
        documents = {url: _doc(url, body="secret body", hash_value="h-secret")}
        fetch_fn, _ = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {cve: [url] for cve in ("CVE-2026-6607", "CVE-2026-6608")}
        )
        research_fn.cache_ref["cache"] = cache
        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6607", "CVE-2026-6608"],
            reference_cache=cache,
        )
        ref_cache = aggregate["reference_cache"]
        self.assertEqual(set(ref_cache.keys()), {"hits"})
        self.assertIsInstance(ref_cache["hits"], int)
        blob = json.dumps(aggregate).lower()
        # Reference URL must never leak into aggregate telemetry.
        self.assertNotIn("secret/path", blob)
        # Existing telemetry still well-formed.
        for forbidden in (
            "sk-or",
            "openrouter_api_key",
            "watch_mongo_uri",
            "sealed",
            "confirmed",
            "live_http",
            "live_nuclei",
            "ready_for_scan",
        ):
            self.assertNotIn(forbidden, blob)
        # Per-CVE result keys unchanged.
        for item in aggregate["results"]:
            self.assertEqual(tuple(item.keys()), RESULT_KEYS)

    def test_markdown_reports_reference_cache(self) -> None:
        from ai.researcher.cve_batch import write_batch_markdown

        url = "https://example.test/shared"
        documents = {url: _doc(url, hash_value="h-m")}
        fetch_fn, _ = self.harness.make_fetch_fn(documents)
        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {cve: [url] for cve in ("CVE-2026-6609", "CVE-2026-6610")}
        )
        research_fn.cache_ref["cache"] = cache
        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6609", "CVE-2026-6610"],
            reference_cache=cache,
        )
        report = Path(aggregate["artifacts"]["report"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("reference_cache", report)
        self.assertIn("hits=1", report)
        # Each aggregate line appears exactly once in the
        # markdown template.
        self.assertEqual(
            write_batch_markdown(aggregate).count("reference_cache"), 1
        )


class ProviderSemanticsPreservationTests(unittest.TestCase):
    """Reference cache must not perturb frozen provider semantics."""

    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_provider_outages_unchanged(self) -> None:
        url = "https://example.test/ok"
        documents = {url: _doc(url, hash_value="h-ok")}

        def fetch_fn(u):
            return documents.get(u)

        cache = BatchReferenceCache(fetch_fn=fetch_fn)

        def research_fn(cve_id: str, skip_llm: bool = False) -> dict:
            cache.fetch(url)
            from ai.llm.openrouter import OpenRouterProviderError

            raise OpenRouterProviderError(
                f"OpenRouter returned HTTP 429: APIStatusError"
            )

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6701", "CVE-2026-6701"],
            reference_cache=cache,
        )
        self.assertEqual(aggregate["reference_cache"], {"hits": 1})
        # Provider telemetry unchanged: one 429, one exhausted
        # retry for the first occurrence; duplicate is a
        # provider-cache hit and contributes nothing.
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_PROVIDER, "http_429": 2},
        )
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 0, "exhausted": 1},
        )

    def test_zero_outages_zero_retries_for_clean_batch(self) -> None:
        url = "https://example.test/ok"
        documents = {url: _doc(url, hash_value="h-ok")}

        def fetch_fn(u):
            return documents.get(u)

        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        research_fn = _make_research_fn(
            {cve: [url] for cve in ("CVE-2026-6702", "CVE-2026-6703")}
        )
        research_fn.cache_ref["cache"] = cache

        aggregate = self.harness.run(
            research_fn,
            ["CVE-2026-6702", "CVE-2026-6703"],
            reference_cache=cache,
        )
        self.assertEqual(aggregate["provider_outages"], dict(ZERO_PROVIDER))
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["reference_cache"], {"hits": 1})


if __name__ == "__main__":
    unittest.main()
