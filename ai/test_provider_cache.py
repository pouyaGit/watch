"""Focused offline tests for the per-batch provider request coalescing cache.

Covers the NEXT research-only engineering stage after frozen
fail-soft/degraded, frozen provider-health telemetry, and the frozen
bounded-429-only retry policy:

- In-memory, per-batch cache of completed / completed_degraded
  outcomes, keyed by the existing normalized CVE identifier.
- A duplicate CVE inside one ``run_cve_batch`` invocation reuses the
  original research result (zero additional provider calls).
- Provider telemetry (``provider_outages`` / ``provider_retries``)
  remains tied to actual first-occurrence research events; cache hits
  are reported only through the new aggregate ``provider_cache``
  field.
- New ``provider_cache = {hits}`` aggregate: always present, zeroed
  when no hit, counts only, no CVE IDs / secrets / payloads.
- Single-CVE CLI path is unchanged (no cache).
- Two separate ``run_cve_batch`` invocations do not share cache state.

Hard-failure policy (documented and tested): the cache stores only
``completed`` and ``completed_degraded`` outcomes. A programming /
non-transient failure is intentionally NOT cached, so a duplicate of
a failed CVE simply re-runs the normal research flow. This prevents
cache poisoning and preserves the frozen ``failed`` contract.

Strictly offline: no network, no subprocess, no Nuclei execution.
"""

from __future__ import annotations

import inspect
import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.llm.openrouter import OpenRouterProviderError

ZERO_OUTAGES = {"http_402": 0, "http_429": 0, "http_5xx": 0, "network": 0}
ZERO_RETRIES = {"attempted": 0, "succeeded": 0, "exhausted": 0}


def _provider_error(status: int) -> OpenRouterProviderError:
    return OpenRouterProviderError(
        f"OpenRouter returned HTTP {status}: APIStatusError"
    )


def _network_error() -> OpenRouterProviderError:
    return OpenRouterProviderError(
        "OpenRouter connection error: APIConnectionError"
    )


def _ok_payload(cve_id: str) -> dict:
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
    """Batch runner with temp dirs, offline guards, and a no-sleep seam."""

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
                retry_sleep_fn=kwargs.pop(
                    "retry_sleep_fn", lambda seconds: None
                ),
                **kwargs,
            )
        finally:
            for guard in guards:
                guard.stop()


class BasicCoalescingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_two_identical_cves_one_execution(self) -> None:
        """Two identical CVEs: exactly one research execution, one hit."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn, ["CVE-2026-7001", "CVE-2026-7001"]
        )
        self.assertEqual(calls, ["CVE-2026-7001"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 1})
        self.assertEqual(len(aggregate["results"]), 2)
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed")
            self.assertFalse(item["authoritative"])
        # Input order preserved.
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            ["CVE-2026-7001", "CVE-2026-7001"],
        )

    def test_normalization_uses_existing_dedup(self) -> None:
        """Whitespace/case duplicates normalize and coalesce via cache."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7002", "  cve-2026-7002 ", "CVE-2026-7002"],
        )
        # Existing batch normalization (strip + upper) means the
        # three inputs collapse to one unique CVE; the second and
        # third occurrences are cache hits.
        self.assertEqual(calls, ["CVE-2026-7002"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(len(aggregate["results"]), 3)
        # cves_requested preserves the full original input list
        # (3 entries) under the documented A semantics.
        self.assertEqual(len(aggregate["cves_requested"]), 3)

    def test_cves_requested_keeps_original_list(self) -> None:
        """Duplicate A semantics: cves_requested stays original length."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-7003",
                "CVE-2026-7004",
                "CVE-2026-7003",
                "CVE-2026-7004",
                "CVE-2026-7003",
            ],
        )
        self.assertEqual(aggregate["provider_cache"]["hits"], 3)
        # cves_requested = the deduplicated unique list (existing
        # behavior); results keep the original input order including
        # duplicates.
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            [
                "CVE-2026-7003",
                "CVE-2026-7004",
                "CVE-2026-7003",
                "CVE-2026-7004",
                "CVE-2026-7003",
            ],
        )


class MultipleDuplicatesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_three_duplicates_one_execution_two_hits(self) -> None:
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7101"] * 3,
        )
        self.assertEqual(calls, ["CVE-2026-7101"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(len(aggregate["results"]), 3)
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed")

    def test_four_duplicates_one_execution_three_hits(self) -> None:
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7102"] * 4,
        )
        self.assertEqual(calls, ["CVE-2026-7102"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 3})


class MixedBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_unique_plus_duplicates(self) -> None:
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-7201",  # 1st: research
                "CVE-2026-7202",  # 1st: research
                "CVE-2026-7201",  # hit
                "CVE-2026-7203",  # 1st: research
                "CVE-2026-7202",  # hit
                "CVE-2026-7201",  # hit
            ],
        )
        # Three unique CVEs researched; three duplicate hits.
        self.assertEqual(
            calls,
            ["CVE-2026-7201", "CVE-2026-7202", "CVE-2026-7203"],
        )
        self.assertEqual(aggregate["provider_cache"], {"hits": 3})
        self.assertEqual(len(aggregate["results"]), 6)
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            [
                "CVE-2026-7201",
                "CVE-2026-7202",
                "CVE-2026-7201",
                "CVE-2026-7203",
                "CVE-2026-7202",
                "CVE-2026-7201",
            ],
        )

    def test_status_preserved_across_cache(self) -> None:
        """Completed vs completed_degraded statuses preserved exactly."""
        completed_calls: list[str] = []
        degraded_calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            if cve_id == "CVE-2026-7204":
                completed_calls.append(cve_id)
                return _ok_payload(cve_id)
            if cve_id == "CVE-2026-7205":
                degraded_calls.append(cve_id)
                raise _provider_error(503)
            raise AssertionError(f"unexpected CVE {cve_id}")

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-7204",
                "CVE-2026-7205",
                "CVE-2026-7204",
                "CVE-2026-7205",
                "CVE-2026-7204",
            ],
        )
        self.assertEqual(completed_calls, ["CVE-2026-7204"])
        self.assertEqual(degraded_calls, ["CVE-2026-7205"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 3})
        by_cve: dict[str, list[str]] = {}
        for item in aggregate["results"]:
            by_cve.setdefault(item["cve"], []).append(
                item["research_status"]
            )
        self.assertEqual(by_cve["CVE-2026-7204"], ["completed"] * 3)
        self.assertEqual(
            by_cve["CVE-2026-7205"], ["completed_degraded"] * 2
        )
        # nuclei_candidate / authoritative preserved per status.
        for item in aggregate["results"]:
            self.assertFalse(item["authoritative"])
            if item["research_status"] == "completed":
                self.assertEqual(
                    aggregate["results"][0]["nuclei_candidate"], False
                )


class RetryInteractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_429_then_success_then_duplicate(self) -> None:
        """First 429 retry success: duplicate reuses, no extra calls."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            if len(calls) == 1:
                raise _provider_error(429)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7301", "CVE-2026-7301", "CVE-2026-7301"],
        )
        # Exactly 2 provider calls (initial 429 + retry success).
        self.assertEqual(calls, ["CVE-2026-7301", "CVE-2026-7301"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 1, "exhausted": 0},
        )
        # Only the first 429 failure counted.
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 1},
        )
        # All three results completed (cache preserved the success).
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed")
            self.assertFalse(item["authoritative"])

    def test_429_exhausted_then_duplicate(self) -> None:
        """429 -> 429 exhausted: duplicate reuses degraded, no extra calls."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            raise _provider_error(429)

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7302", "CVE-2026-7302"],
        )
        self.assertEqual(calls, ["CVE-2026-7302", "CVE-2026-7302"])
        self.assertEqual(aggregate["provider_cache"], {"hits": 1})
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 0, "exhausted": 1},
        )
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 2},
        )
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed_degraded")
            self.assertFalse(item["authoritative"])

    def test_429_then_503_then_duplicate(self) -> None:
        """429 -> 503: duplicate reuses degraded, no extra calls."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            if len(calls) == 1:
                raise _provider_error(429)
            raise _provider_error(503)

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7303", "CVE-2026-7303", "CVE-2026-7303"],
        )
        self.assertEqual(
            calls, ["CVE-2026-7303", "CVE-2026-7303"]
        )
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 1, "http_5xx": 1},
        )
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed_degraded")

    def test_429_then_network_then_duplicate(self) -> None:
        """429 -> network: duplicate reuses degraded, no extra calls."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            if len(calls) == 1:
                raise _provider_error(429)
            raise _network_error()

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7304", "CVE-2026-7304"],
        )
        self.assertEqual(
            calls, ["CVE-2026-7304", "CVE-2026-7304"]
        )
        self.assertEqual(aggregate["provider_cache"], {"hits": 1})
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 1, "network": 1},
        )
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed_degraded")


class StatusPreservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_completed_preserved_through_cache(self) -> None:
        """Completed result keeps authoritative/research_only/nuclei flags.

        The cached value is the per-CVE result dict returned by
        ``research_one_cve`` (a ``RESULT_KEYS``-shaped record with a
        string ``cve``). We build a real CLI-style payload that
        ``research_one_cve`` can consume so the cache entry preserves
        the real semantic fields of the result.
        """
        from ai.researcher.cve_batch import RESULT_KEYS

        seen: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            seen.append(cve_id)
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
                    "summary": "offline fixture",
                    "severity": "high",
                    "cve_ids": [cve_id],
                    "affected_products": [],
                    "affected_versions": [],
                    "nuclei_candidate": True,
                    "nuclei_reason": "ok",
                    "references": [],
                    "evidence": [],
                },
                "output_path": f"/tmp/{cve_id}.cli.json",
            }

        aggregate = self.harness.run(
            fn, ["CVE-2026-7401", "CVE-2026-7401"]
        )
        # Exactly one research_fn call: duplicate reuses the result.
        self.assertEqual(seen, ["CVE-2026-7401"])
        # All three result entries share the exact same per-CVE
        # fields (status, nuclei_candidate default, artifacts).
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed")
            self.assertEqual(tuple(item.keys()), RESULT_KEYS)
            self.assertFalse(item["authoritative"])
            self.assertEqual(
                item["artifacts"]["research"],
                "/tmp/CVE-2026-7401.cli.json",
            )

    def test_completed_degraded_preserved_through_cache(self) -> None:
        """completed_degraded caches with nuclei_candidate=False."""
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(503)

        aggregate = self.harness.run(
            fn, ["CVE-2026-7402", "CVE-2026-7402"]
        )
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed_degraded")
            self.assertFalse(item["authoritative"])
            self.assertFalse(item["nuclei_candidate"])


class HardFailureTests(unittest.TestCase):
    """Documented policy: hard failures are NOT cached."""

    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_programming_error_not_cached_duplicate_replays(self) -> None:
        """Programming error stays failed; duplicate re-runs normally.

        This is the documented fail-safe behavior: a programming /
        non-transient failure is intentionally NOT cached, so a
        duplicate never inherits a poisoned result. The duplicate
        may therefore succeed if the underlying issue is transient
        (e.g. a flaky local file) — a strict no-poisoning invariant.
        """
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            if len(calls) == 1:
                raise TypeError("programmer bug on first call only")
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn, ["CVE-2026-7501", "CVE-2026-7501"]
        )
        # First call failed; second call re-ran and succeeded.
        self.assertEqual(
            calls, ["CVE-2026-7501", "CVE-2026-7501"]
        )
        self.assertEqual(aggregate["provider_cache"], {"hits": 0})
        # First entry failed, second entry completed — not poisoned.
        self.assertEqual(aggregate["results"][0]["research_status"], "failed")
        self.assertEqual(aggregate["results"][1]["research_status"], "completed")
        self.assertEqual(aggregate["failed"], 1)
        self.assertEqual(aggregate["completed"], 1)

    def test_persistent_hard_failure_stays_failed(self) -> None:
        """A persistently hard-failing CVE never caches; stays failed."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            raise TypeError("persistent programmer bug")

        aggregate = self.harness.run(
            fn,
            ["CVE-2026-7502", "CVE-2026-7502", "CVE-2026-7502"],
        )
        self.assertEqual(len(calls), 3)
        self.assertEqual(aggregate["provider_cache"], {"hits": 0})
        self.assertEqual(aggregate["failed"], 3)
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "failed")
        # No programming error bucket counted.
        self.assertEqual(aggregate["provider_outages"], dict(ZERO_OUTAGES))


class CacheScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_two_separate_batches_do_not_share_cache(self) -> None:
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        first = self.harness.run(fn, ["CVE-2026-7601"])
        second = self.harness.run(fn, ["CVE-2026-7601"])
        self.assertEqual(calls, ["CVE-2026-7601", "CVE-2026-7601"])
        self.assertEqual(first["provider_cache"], {"hits": 0})
        self.assertEqual(second["provider_cache"], {"hits": 0})

    def test_no_module_global_mutable_cache(self) -> None:
        """Cache state lives only inside one run_cve_batch invocation.

        Two consecutive invocations must each call the provider
        exactly once, proving there is no module-global state. The
        cache must be freshly created per call.
        """
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _ok_payload(cve_id)

        first = self.harness.run(
            fn, ["CVE-2026-7602", "CVE-2026-7602"]
        )
        second = self.harness.run(
            fn, ["CVE-2026-7602", "CVE-2026-7602"]
        )
        # Each run: 1 provider execution + 1 cache hit.
        self.assertEqual(calls, ["CVE-2026-7602", "CVE-2026-7602"])
        self.assertEqual(first["provider_cache"], {"hits": 1})
        self.assertEqual(second["provider_cache"], {"hits": 1})

    def test_cache_object_not_persisted_to_disk(self) -> None:
        """No ai_data cache directory or aggregate cache file is created."""
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        self.harness.run(fn, ["CVE-2026-7603", "CVE-2026-7603"])
        # The harness temp dir holds the normal batch artifacts
        # (research/<CVE>.batch.json, batch-<stamp>.json, etc.) and
        # nothing else.
        for path in self.harness.tmp.rglob("*cache*"):
            self.fail(f"unexpected cache file written: {path}")
        # No persistent state outside the temp dir.
        for path in Path.cwd().glob("ai_data/**/*cache*"):
            self.fail(f"unexpected on-disk cache: {path}")


class CliCacheTests(unittest.TestCase):
    def test_cli_single_cve_does_not_use_cache(self) -> None:
        """Single-CVE CLI path is unchanged: no per-batch cache imported.

        Proves the cache is a batch-only optimization by showing the
        CLI entry point does not consult or maintain any shared
        cache state, and the second invocation independently invokes
        the provider.
        """
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        cve = ResearchDocument(
            source_type="cve",
            title="CVE-2026-7701",
            content="fixture",
        )
        calls: list[int] = []

        class _CountingResearcher:
            def research(self, **kwargs):
                calls.append(1)
                from ai.schemas.research import ResearchResult

                return ResearchResult(
                    title="ok CVE-2026-7701",
                    summary="fixture",
                    severity="medium",
                    cve_ids=["CVE-2026-7701"],
                )

        for _ in range(2):
            with (
                patch.object(cli_mod, "_load_assets", return_value=([], None)),
                patch(
                    "ai.collectors.cve.CVECollector.get_by_ids",
                    return_value=[cve],
                ),
                patch(
                    "ai.correlator.candidates.candidate_assets",
                    return_value=[],
                ),
                patch("ai.collectors.discovery.ReferenceDiscovery"),
                patch(
                    "ai.collectors.discovery_fetch.fetch_discovered_sources",
                    return_value=[],
                ),
                patch(
                    "ai.researcher.research_context.build_research_contexts",
                    return_value=[],
                ),
                patch(
                    "ai.researcher.researcher.SecurityResearcher",
                    _CountingResearcher,
                ),
                patch.object(
                    cli_mod,
                    "RESEARCH_DIR",
                    Path(tempfile.mkdtemp()),
                ),
            ):
                cli_mod._research_single_cve("CVE-2026-7701")
        # Two CLI invocations: two provider calls. No persistent
        # cache.
        self.assertEqual(len(calls), 2)

    def test_cli_research_single_signature_unchanged(self) -> None:
        from ai import research_cli

        self.assertEqual(
            list(
                inspect.signature(
                    research_cli._research_single_cve
                ).parameters
            ),
            ["cve_id", "skip_llm"],
        )


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_provider_cache_always_present(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        aggregate = self.harness.run(fn, ["CVE-2026-7801"])
        self.assertIn("provider_cache", aggregate)
        self.assertEqual(aggregate["provider_cache"], {"hits": 0})

    def test_provider_cache_zero_for_unique_batch(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn, ["CVE-2026-7802", "CVE-2026-7803", "CVE-2026-7804"]
        )
        self.assertEqual(aggregate["provider_cache"], {"hits": 0})

    def test_provider_cache_exact_count(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-7805",
                "CVE-2026-7805",
                "CVE-2026-7806",
                "CVE-2026-7805",
                "CVE-2026-7807",
                "CVE-2026-7806",
            ],
        )
        self.assertEqual(aggregate["provider_cache"], {"hits": 3})

    def test_telemetry_counts_only_no_secrets_no_cve_ids(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            if cve_id == "CVE-2026-7808":
                raise _provider_error(429)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-7808",
                "CVE-2026-7808",
                "CVE-2026-7809",
            ],
        )
        cache = aggregate["provider_cache"]
        self.assertEqual(set(cache.keys()), {"hits"})
        self.assertIsInstance(cache["hits"], int)
        blob = json.dumps(aggregate).lower()
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
        # No per-CVE cache keys added to RESULT_KEYS.
        from ai.researcher.cve_batch import RESULT_KEYS

        for item in aggregate["results"]:
            self.assertEqual(tuple(item.keys()), RESULT_KEYS)

    def test_markdown_reports_cache_hits(self) -> None:
        from ai.researcher.cve_batch import write_batch_markdown

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn, ["CVE-2026-7810", "CVE-2026-7810"]
        )
        report = Path(aggregate["artifacts"]["report"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("provider_cache", report)
        self.assertIn("hits=1", report)
        self.assertEqual(
            write_batch_markdown(aggregate).count("provider_cache"), 1
        )

    def test_outage_retry_counts_unchanged_by_cache(self) -> None:
        """Provider telemetry only counts first-occurrence research."""
        calls: list[str] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            raise _provider_error(429)

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-7811",
                "CVE-2026-7811",
                "CVE-2026-7811",
            ],
        )
        # Only 2 provider calls (initial + exhausted retry) — not
        # doubled by the duplicate CVE.
        self.assertEqual(len(calls), 2)
        self.assertEqual(aggregate["provider_cache"], {"hits": 2})
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 2},
        )
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 0, "exhausted": 1},
        )


if __name__ == "__main__":
    unittest.main()
