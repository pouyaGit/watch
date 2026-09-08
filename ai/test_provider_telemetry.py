"""Focused offline tests for provider health telemetry (research-only).

Covers aggregate ``provider_outages`` histogram semantics:

- 402 -> http_402 / 429 -> http_429 / 5xx -> http_5xx
- timeout/network -> network
- non-transient/programming errors increment nothing
- successful LLM calls and --skip-llm increment nothing
- mixed batches produce the correct histogram
- no double counting when a CLI degraded payload reaches the batch
- zero-outage batches emit a zeroed histogram (stable schema)
- telemetry contains counts only (no payloads/secrets/text)

Strictly offline: no network, no subprocess, no live execution.
No retries, no second provider, no Nuclei execution.
"""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.llm.openrouter import OpenRouterProviderError
from ai.researcher.provider_errors import (
    OUTAGE_BUCKETS,
    classify_provider_failure,
    empty_outage_histogram,
    outage_bucket_for_info,
)


ZERO = {"http_402": 0, "http_429": 0, "http_5xx": 0, "network": 0}


def _provider_error(status: int) -> OpenRouterProviderError:
    return OpenRouterProviderError(
        f"OpenRouter returned HTTP {status}: APIStatusError"
    )


def _network_error() -> OpenRouterProviderError:
    return OpenRouterProviderError(
        "OpenRouter connection error: APIConnectionError"
    )


def _ok_payload(cve_id: str, skip_llm: bool = False) -> dict:
    return {
        "research_version": "cli-1",
        "mode": "research-only",
        "authoritative": False,
        "research_status": "completed",
        "llm_status": "ok",
        "outage_bucket": None,
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
    }


def _run_batch(research_fn, cve_ids, **kwargs):
    from ai.researcher.cve_batch import run_cve_batch

    tmpdir = kwargs.pop("_tmpdir")
    return run_cve_batch(
        cve_ids,
        research_fn=research_fn,
        research_dir=Path(tmpdir) / "research",
        report_dir=Path(tmpdir) / "reports",
        **kwargs,
    )


class OutageBucketMappingTests(unittest.TestCase):
    def test_bucket_keys_stable(self) -> None:
        self.assertEqual(
            tuple(empty_outage_histogram().keys()),
            ("http_402", "http_429", "http_5xx", "network"),
        )
        self.assertEqual(tuple(OUTAGE_BUCKETS), tuple(ZERO.keys()))

    def test_402_maps(self) -> None:
        info = classify_provider_failure(_provider_error(402))
        self.assertEqual(outage_bucket_for_info(info), "http_402")

    def test_429_maps(self) -> None:
        info = classify_provider_failure(_provider_error(429))
        self.assertEqual(outage_bucket_for_info(info), "http_429")

    def test_each_5xx_maps(self) -> None:
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                info = classify_provider_failure(_provider_error(status))
                self.assertEqual(outage_bucket_for_info(info), "http_5xx")

    def test_network_maps(self) -> None:
        info = classify_provider_failure(_network_error())
        self.assertTrue(info.transient)
        self.assertEqual(outage_bucket_for_info(info), "network")

    def test_non_transient_maps_to_none(self) -> None:
        for exc in (
            _provider_error(401),
            _provider_error(404),
            TypeError("boom"),
            ValueError("LLM returned invalid JSON: {oops"),
            RuntimeError("simulated research failure"),
        ):
            with self.subTest(exc=repr(exc)):
                info = classify_provider_failure(exc)
                self.assertFalse(info.transient)
                self.assertIsNone(outage_bucket_for_info(info))


class BatchTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._tmp = self._tmpdir.name

    def _run(self, research_fn, cve_ids, **kwargs):
        return _run_batch(
            research_fn, cve_ids, _tmpdir=self._tmp, **kwargs
        )

    def test_402_increments_http_402(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(402)

        aggregate = self._run(fn, ["CVE-2026-9101"])
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO, "http_402": 1},
        )
        self.assertEqual(
            aggregate["results"][0]["research_status"],
            "completed_degraded",
        )

    def test_429_increments_http_429(self) -> None:
        # Always-429 fake: initial failure + one exhausted retry =
        # two encountered failures (never merged, never inflated).
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(429)

        aggregate = self._run(
            fn, ["CVE-2026-9101"], retry_sleep_fn=lambda seconds: None
        )
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO, "http_429": 2},
        )
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 0, "exhausted": 1},
        )

    def test_each_5xx_increments_http_5xx(self) -> None:
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                def fn(cve_id: str, skip_llm: bool = False) -> dict:
                    raise _provider_error(status)

                with tempfile.TemporaryDirectory() as tmpdir:
                    aggregate = _run_batch(
                        fn, ["CVE-2026-9101"], _tmpdir=tmpdir
                    )
                self.assertEqual(
                    aggregate["provider_outages"],
                    {**ZERO, "http_5xx": 1},
                )

    def test_network_increments_network(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _network_error()

        aggregate = self._run(fn, ["CVE-2026-9101"])
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO, "network": 1},
        )
        self.assertEqual(
            aggregate["results"][0]["research_status"],
            "completed_degraded",
        )

    def test_programming_error_increments_nothing(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise RuntimeError("simulated research failure")

        aggregate = self._run(fn, ["CVE-2026-9101"])
        self.assertEqual(aggregate["provider_outages"], dict(ZERO))
        self.assertEqual(aggregate["results"][0]["research_status"], "failed")

    def test_success_increments_nothing(self) -> None:
        aggregate = self._run(_ok_payload, ["CVE-2026-9101"])
        self.assertEqual(aggregate["provider_outages"], dict(ZERO))
        self.assertEqual(aggregate["results"][0]["research_status"], "completed")

    def test_skip_llm_increments_nothing(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            payload = _ok_payload(cve_id)
            payload["research"] = {
                "skipped": True,
                "reason": "LLM research skipped by --skip-llm",
            }
            payload["llm_status"] = "skipped"
            return payload

        aggregate = self._run(fn, ["CVE-2026-9101"], skip_llm=True)
        self.assertEqual(aggregate["provider_outages"], dict(ZERO))

    def test_mixed_batch_histogram(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            if cve_id == "CVE-2026-9201":
                raise _provider_error(402)
            if cve_id == "CVE-2026-9202":
                raise _provider_error(429)
            if cve_id == "CVE-2026-9203":
                raise _provider_error(503)
            if cve_id == "CVE-2026-9204":
                raise _network_error()
            if cve_id == "CVE-2026-9205":
                raise RuntimeError("hard failure")
            return _ok_payload(cve_id)

        guards = (
            patch.object(
                socket, "create_connection", side_effect=AssertionError("net")
            ),
            patch.object(socket, "socket", side_effect=AssertionError("net")),
            patch.object(
                socket, "getaddrinfo", side_effect=AssertionError("net")
            ),
            patch.object(
                subprocess, "run", side_effect=AssertionError("proc")
            ),
            patch.object(
                subprocess, "Popen", side_effect=AssertionError("proc")
            ),
        )
        for guard in guards:
            guard.start()
        try:
            aggregate = self._run(
                fn,
                [
                    "CVE-2026-9201",
                    "CVE-2026-9202",
                    "CVE-2026-9203",
                    "CVE-2026-9204",
                    "CVE-2026-9205",
                    "CVE-2026-9206",
                ],
                retry_sleep_fn=lambda seconds: None,
            )
        finally:
            for guard in guards:
                guard.stop()

        self.assertEqual(
            aggregate["provider_outages"],
            {"http_402": 1, "http_429": 2, "http_5xx": 1, "network": 1},
        )
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 0, "exhausted": 1},
        )
        # Batch semantics preserved.
        self.assertEqual(aggregate["completed"], 1)
        self.assertEqual(aggregate["completed_degraded"], 4)
        self.assertEqual(aggregate["failed"], 1)
        self.assertEqual(aggregate["processed"], 5)

    def test_no_double_counting_cli_payload(self) -> None:
        """A CLI-stamped degraded payload is tallied exactly once per event.

        Under the bounded 429-only retry policy an always-429 CVE
        produces two outage EVENTS (initial + exhausted retry), so the
        aggregate counts http_429=2. The anti-double-counting
        invariant is that each event is tallied exactly once: the
        single ``outage_bucket`` stamp plus the ``outage_events`` list
        must not stack with the legacy message-fallback classifier
        into a third count.
        """
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        cve = ResearchDocument(
            source_type="cve",
            title="CVE-2026-9301",
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-9301",
            content="NVD fixture description with no HTTP method.",
            vendor=["fixture-vendor"],
            products=["fixture-product"],
        )

        class _FailingResearcher:
            def research(self, **kwargs):
                raise _provider_error(429)

        sleep_calls: list = []
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
                _FailingResearcher,
            ),
            patch.object(cli_mod, "RESEARCH_DIR", Path(self._tmp) / "cli"),
            patch(
                "ai.researcher.retry_policy.sleep_before_429_retry",
                side_effect=lambda *a, **k: sleep_calls.append((a, k)),
            ),
        ):
            payload = cli_mod._research_single_cve("CVE-2026-9301")

        # The CLI stamps exactly one bucket; fail-soft contract intact.
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["outage_bucket"], "http_429")
        self.assertEqual(
            payload["outage_events"], ["http_429", "http_429"]
        )
        self.assertFalse(payload["authoritative"])
        self.assertTrue(payload["research_only"])
        self.assertFalse(payload["research"]["nuclei_candidate"])
        # Single allowed retry slept exactly once (no real sleep: seam).
        self.assertEqual(len(sleep_calls), 1)

        # Passing that payload through the batch tallies each event
        # exactly once (2), with no third count from fallback
        # re-classification stacking on top of the stamps.
        aggregate = self._run(
            lambda cve_id, skip_llm=False: payload, ["CVE-2026-9301"]
        )
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO, "http_429": 2},
        )
        self.assertEqual(
            aggregate["results"][0]["research_status"],
            "completed_degraded",
        )
        self.assertEqual(sum(aggregate["provider_outages"].values()), 2)
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 1, "succeeded": 0, "exhausted": 1},
        )

    def test_zero_outage_batch_zeroed_histogram(self) -> None:
        aggregate = self._run(
            _ok_payload, ["CVE-2026-9401", "CVE-2026-9402"]
        )
        self.assertEqual(aggregate["provider_outages"], dict(ZERO))
        self.assertIn("provider_outages", aggregate)

    def test_telemetry_counts_only(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(429)

        aggregate = self._run(
            fn, ["CVE-2026-9501"], retry_sleep_fn=lambda seconds: None
        )
        outages = aggregate["provider_outages"]
        self.assertEqual(set(outages.keys()), set(ZERO.keys()))
        for value in outages.values():
            self.assertIsInstance(value, int)

        blob = json.dumps(aggregate).lower()
        self.assertNotIn("sk-or", blob)
        self.assertNotIn("openrouter_api_key", blob)
        self.assertNotIn("watch_mongo_uri", blob)
        self.assertNotIn("sealed", blob)
        self.assertNotIn("confirmed", blob)
        self.assertNotIn("live_http", blob)
        self.assertNotIn("live_nuclei", blob)
        # Per-CVE result keys unchanged (aggregate-only telemetry).
        from ai.researcher.cve_batch import RESULT_KEYS

        for item in aggregate["results"]:
            self.assertEqual(tuple(item.keys()), RESULT_KEYS)

    def test_markdown_reports_outages(self) -> None:
        from ai.researcher.cve_batch import write_batch_markdown

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(402)

        aggregate = self._run(fn, ["CVE-2026-9601"])
        report = Path(aggregate["artifacts"]["report"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("provider_outages", report)
        self.assertIn("http_402=1", report)
        self.assertEqual(
            write_batch_markdown(aggregate).count("provider_outages"), 1
        )


if __name__ == "__main__":
    unittest.main()
