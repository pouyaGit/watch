"""Focused offline tests for the bounded 429-only provider retry policy.

Covers the NEXT research-only stage after frozen fail-soft/degraded
mode and frozen aggregate provider-health telemetry:

- HTTP 429: exactly ONE retry after a small capped backoff.
- HTTP 402 / 5xx / network-timeout: NEVER retried.
- Programming / non-transient errors: NEVER retried, still ``failed``.
- ``--skip-llm``: no retry, unchanged behavior.
- Aggregate ``provider_retries`` telemetry
  (``attempted``/``succeeded``/``exhausted``) with the specified
  ``provider_outages`` counting semantics (initial failure always
  counted; a failed retry counts again; retry success erases nothing).
- Backoff seam: tests never sleep and never depend on timing.
- Exactly-one-retry invariant: an always-429 provider sees exactly
  two calls (initial + one retry), never a loop.

Strictly offline: sockets/DNS/subprocess are blocked, no Nuclei
execution, no target-side requests, no live state of any kind.
"""

from __future__ import annotations

import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.llm.openrouter import OpenRouterProviderError
from ai.researcher.retry_policy import (
    DEFAULT_RETRY_429_DELAY_SECONDS,
    MAX_RETRY_429_DELAY_SECONDS,
    clamp_retry_delay,
    empty_retry_histogram,
)

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
    """Batch runner with temp dirs, offline guards, and a sleep recorder."""

    def __init__(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.add_cleanup = None
        self.tmp = Path(self._tmpdir.name)
        self.sleep_calls: list[float] = []

    def cleanup(self):
        self._tmpdir.cleanup()

    def sleep_recorder(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)

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
                    "retry_sleep_fn", self.sleep_recorder
                ),
                **kwargs,
            )
        finally:
            for guard in guards:
                guard.stop()


class _CliHarness:
    """Single-CVE CLI runner with injected researcher script + sleep recorder."""

    def __init__(self, testcase: unittest.TestCase, tmp: str):
        self.testcase = testcase
        self.tmp = tmp
        self.sleep_calls: list = []

    def run(self, cve_id: str, script: list):
        """Run ``_research_single_cve``; ``script`` is one action per call.

        Each action is either an exception to raise or a
        ``ResearchResult`` to return. Returns ``(payload, calls)``
        where ``calls`` counts researcher invocations.
        """
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        calls: list[int] = []

        class _ScriptedResearcher:
            def research(self, **kwargs):
                calls.append(1)
                action = script[len(calls) - 1]
                if isinstance(action, BaseException):
                    raise action
                return action

        cve = ResearchDocument(
            source_type="cve",
            title=cve_id,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            content="NVD fixture description with no HTTP method.",
            vendor=["fixture-vendor"],
            products=["fixture-product"],
            references=["https://example.test/advisory"],
        )
        harness = self

        def _fake_sleep(*args, **kwargs):
            harness.sleep_calls.append((args, kwargs))
            return 2.0

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
                _ScriptedResearcher,
            ),
            patch.object(cli_mod, "RESEARCH_DIR", Path(self.tmp) / "cli"),
            patch(
                "ai.researcher.retry_policy.sleep_before_429_retry",
                side_effect=_fake_sleep,
            ),
        ):
            payload = cli_mod._research_single_cve(cve_id)
        return payload, calls


def _research_result():
    from ai.schemas.research import ResearchResult

    return ResearchResult(
        title="offline fixture research",
        summary="offline fixture summary with no HTTP method.",
        severity="medium",
        cve_ids=["CVE-2026-9901"],
    )


class RetryPolicyUnitTests(unittest.TestCase):
    def test_only_transient_429_is_retryable(self) -> None:
        from ai.researcher.provider_errors import classify_provider_failure

        self.assertTrue(
            __import__(
                "ai.researcher.retry_policy", fromlist=["is_retryable_429"]
            ).is_retryable_429(
                classify_provider_failure(_provider_error(429))
            )
        )
        for exc in (
            _provider_error(402),
            _provider_error(500),
            _provider_error(503),
            _network_error(),
            _provider_error(401),
            TypeError("boom"),
            RuntimeError("simulated research failure"),
        ):
            with self.subTest(exc=repr(exc)):
                from ai.researcher.retry_policy import is_retryable_429

                self.assertFalse(
                    is_retryable_429(classify_provider_failure(exc))
                )

    def test_retry_histogram_zeroed_schema(self) -> None:
        self.assertEqual(
            empty_retry_histogram(),
            {"attempted": 0, "succeeded": 0, "exhausted": 0},
        )

    def test_delay_defaults_bounded_and_capped(self) -> None:
        self.assertGreater(DEFAULT_RETRY_429_DELAY_SECONDS, 0)
        self.assertLessEqual(
            DEFAULT_RETRY_429_DELAY_SECONDS, MAX_RETRY_429_DELAY_SECONDS
        )
        self.assertEqual(clamp_retry_delay(9999), MAX_RETRY_429_DELAY_SECONDS)
        self.assertEqual(clamp_retry_delay(-3), 0.0)
        self.assertEqual(
            clamp_retry_delay("bogus"), DEFAULT_RETRY_429_DELAY_SECONDS
        )


class BatchRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_429_then_success(self) -> None:
        """Scenario 1: 429 first attempt -> retry succeeds."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            if len(calls) == 1:
                raise _provider_error(429)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertEqual(aggregate["provider_retries"], {**ZERO_RETRIES,
            "attempted": 1, "succeeded": 1})
        self.assertEqual(aggregate["provider_outages"], {**ZERO_OUTAGES,
            "http_429": 1})
        # Exactly one retry: two provider calls total.
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.harness.sleep_calls), 1)

    def test_429_then_429(self) -> None:
        """Scenario 2: 429 -> 429 exhausts the single retry."""
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(429)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertFalse(item["authoritative"])
        self.assertEqual(aggregate["provider_retries"], {**ZERO_RETRIES,
            "attempted": 1, "exhausted": 1})
        self.assertEqual(aggregate["provider_outages"], {**ZERO_OUTAGES,
            "http_429": 2})

    def test_429_then_503(self) -> None:
        """Scenario 3: 429 -> 503 degrades; both outages counted."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            if len(calls) == 1:
                raise _provider_error(429)
            raise _provider_error(503)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed_degraded"
        )
        self.assertEqual(aggregate["provider_retries"], {**ZERO_RETRIES,
            "attempted": 1, "exhausted": 1})
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 1, "http_5xx": 1},
        )
        self.assertEqual(len(calls), 2)

    def test_429_then_network(self) -> None:
        """Scenario 4: 429 -> network degrades; both outages counted."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            if len(calls) == 1:
                raise _provider_error(429)
            raise _network_error()

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed_degraded"
        )
        self.assertEqual(aggregate["provider_retries"], {**ZERO_RETRIES,
            "attempted": 1, "exhausted": 1})
        self.assertEqual(
            aggregate["provider_outages"],
            {**ZERO_OUTAGES, "http_429": 1, "network": 1},
        )

    def test_402_never_retried(self) -> None:
        """Scenario 5: 402 degrades immediately with no retry."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            raise _provider_error(402)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed_degraded"
        )
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["provider_outages"], {**ZERO_OUTAGES,
            "http_402": 1})
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_503_never_retried(self) -> None:
        """Scenario 6: 503 degrades immediately with no retry."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            raise _provider_error(503)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed_degraded"
        )
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["provider_outages"], {**ZERO_OUTAGES,
            "http_5xx": 1})
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_network_never_retried(self) -> None:
        """Scenario 7: network failure degrades immediately, no retry."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            raise _network_error()

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed_degraded"
        )
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["provider_outages"], {**ZERO_OUTAGES,
            "network": 1})
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_programming_error_failed_no_retry_no_outage(self) -> None:
        """Scenario 8: programming error stays failed, never retried."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            raise TypeError("programmer bug")

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(aggregate["results"][0]["research_status"], "failed")
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["provider_outages"], dict(ZERO_OUTAGES))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_success_first_attempt_no_retry(self) -> None:
        """Scenario 9: successful first attempt never retries."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            return _ok_payload(cve_id)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(aggregate["results"][0]["research_status"], "completed")
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["provider_outages"], dict(ZERO_OUTAGES))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_skip_llm_no_retry(self) -> None:
        """Scenario 10: --skip-llm performs no retry, counters zero."""
        seen: list[bool] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            seen.append(skip_llm)
            payload = _ok_payload(cve_id)
            payload["research"] = {
                "skipped": True,
                "reason": "LLM research skipped by --skip-llm",
            }
            payload["llm_status"] = "skipped"
            return payload

        aggregate = self.harness.run(
            fn, ["CVE-2026-9901"], skip_llm=True
        )
        self.assertEqual(aggregate["results"][0]["research_status"], "completed")
        self.assertEqual(aggregate["provider_retries"], dict(ZERO_RETRIES))
        self.assertEqual(aggregate["provider_outages"], dict(ZERO_OUTAGES))
        self.assertEqual(seen, [True])
        self.assertEqual(self.harness.sleep_calls, [])

    def test_mixed_multi_cve_batch(self) -> None:
        """Scenario 11: mixed batch produces exact aggregate counts."""
        calls: dict[str, int] = {}

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls[cve_id] = calls.get(cve_id, 0) + 1
            if cve_id == "CVE-2026-9911":
                # 429 then success-after-retry.
                if calls[cve_id] == 1:
                    raise _provider_error(429)
                return _ok_payload(cve_id)
            if cve_id == "CVE-2026-9912":
                # Always 429: initial + one exhausted retry.
                raise _provider_error(429)
            if cve_id == "CVE-2026-9913":
                raise _provider_error(402)
            if cve_id == "CVE-2026-9914":
                raise _provider_error(503)
            if cve_id == "CVE-2026-9915":
                raise _network_error()
            return _ok_payload(cve_id)

        aggregate = self.harness.run(
            fn,
            [
                "CVE-2026-9911",
                "CVE-2026-9912",
                "CVE-2026-9913",
                "CVE-2026-9914",
                "CVE-2026-9915",
                "CVE-2026-9916",
            ],
        )
        by_cve = {item["cve"]: item for item in aggregate["results"]}
        self.assertEqual(by_cve["CVE-2026-9911"]["research_status"], "completed")
        self.assertEqual(
            by_cve["CVE-2026-9912"]["research_status"], "completed_degraded"
        )
        self.assertEqual(
            by_cve["CVE-2026-9913"]["research_status"], "completed_degraded"
        )
        self.assertEqual(
            by_cve["CVE-2026-9914"]["research_status"], "completed_degraded"
        )
        self.assertEqual(
            by_cve["CVE-2026-9915"]["research_status"], "completed_degraded"
        )
        self.assertEqual(by_cve["CVE-2026-9916"]["research_status"], "completed")
        # attempted: 9911 (succeeded) + 9912 (exhausted) = 2.
        self.assertEqual(
            aggregate["provider_retries"],
            {"attempted": 2, "succeeded": 1, "exhausted": 1},
        )
        # Outages: 9911 initial 429 (retry succeeded, nothing erased);
        # 9912 initial + retry 429; 402; 5xx; network.
        self.assertEqual(
            aggregate["provider_outages"],
            {"http_402": 1, "http_429": 3, "http_5xx": 1, "network": 1},
        )
        self.assertEqual(aggregate["completed"], 2)
        self.assertEqual(aggregate["completed_degraded"], 4)
        self.assertEqual(aggregate["failed"], 0)
        self.assertEqual(aggregate["processed"], 6)
        # Per-CVE call counts prove the bound: retried CVEs saw
        # exactly 2 calls, all others exactly 1.
        self.assertEqual(
            calls,
            {
                "CVE-2026-9911": 2,
                "CVE-2026-9912": 2,
                "CVE-2026-9913": 1,
                "CVE-2026-9914": 1,
                "CVE-2026-9915": 1,
                "CVE-2026-9916": 1,
            },
        )
        self.assertEqual(len(self.harness.sleep_calls), 2)

    def test_exactly_one_retry_invariant(self) -> None:
        """Scenario 13: a fake that keeps returning 429 sees 2 calls."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            raise _provider_error(429)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.harness.sleep_calls), 1)
        self.assertEqual(aggregate["provider_retries"]["attempted"], 1)

    def test_429_then_programming_error_failed_not_hidden(self) -> None:
        """429 followed by a non-transient retry error fails loudly."""
        calls: list[int] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(1)
            if len(calls) == 1:
                raise _provider_error(429)
            raise TypeError("programmer bug on retry")

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "failed")
        self.assertIn("TypeError", item["error"] or "")
        # Initial 429 still counted; programming errors add no bucket.
        self.assertEqual(aggregate["provider_outages"], {**ZERO_OUTAGES,
            "http_429": 1})
        self.assertEqual(len(calls), 2)

    def test_retry_telemetry_counts_only_no_secrets(self) -> None:
        """Aggregate retry telemetry carries counts only, always present."""
        import json

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(429)

        aggregate = self.harness.run(fn, ["CVE-2026-9901"])
        retries = aggregate["provider_retries"]
        self.assertEqual(set(retries.keys()), {"attempted", "succeeded", "exhausted"})
        for value in retries.values():
            self.assertIsInstance(value, int)
        blob = json.dumps(aggregate).lower()
        for forbidden in (
            "sk-or",
            "openrouter_api_key",
            "watch_mongo_uri",
            "sealed",
            "confirmed",
            "live_http",
            "live_nuclei",
        ):
            self.assertNotIn(forbidden, blob)


class CliRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.harness = _CliHarness(self, self._tmpdir.name)

    def test_cli_429_then_success_completed(self) -> None:
        """CLI: 429 -> success yields completed + llm_status ok."""
        payload, calls = self.harness.run(
            "CVE-2026-9901", [_provider_error(429), _research_result()]
        )
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["llm_status"], "ok")
        self.assertIsNone(payload["llm_error"])
        self.assertTrue(payload["retry_attempted"])
        self.assertTrue(payload["retry_succeeded"])
        self.assertEqual(payload["outage_bucket"], "http_429")
        self.assertEqual(payload["outage_events"], ["http_429"])
        # Honest provenance: real LLM research preserved, not faked.
        self.assertEqual(
            payload["research"]["title"], "offline fixture research"
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.harness.sleep_calls), 1)

    def test_cli_429_then_429_degraded(self) -> None:
        """CLI: 429 -> 429 degrades with both events recorded."""
        payload, calls = self.harness.run(
            "CVE-2026-9901",
            [_provider_error(429), _provider_error(429)],
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["llm_status"], "unavailable")
        self.assertFalse(payload["authoritative"])
        self.assertTrue(payload["research_only"])
        self.assertFalse(payload["research"]["nuclei_candidate"])
        self.assertTrue(payload["retry_attempted"])
        self.assertFalse(payload["retry_succeeded"])
        self.assertEqual(
            payload["outage_events"], ["http_429", "http_429"]
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.harness.sleep_calls), 1)

    def test_cli_429_then_503_degraded(self) -> None:
        """CLI: 429 -> 503 degrades; outage events keep both failures."""
        payload, calls = self.harness.run(
            "CVE-2026-9901",
            [_provider_error(429), _provider_error(503)],
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(
            payload["outage_events"], ["http_429", "http_5xx"]
        )
        self.assertEqual(payload["outage_bucket"], "http_429")
        self.assertEqual(len(calls), 2)

    def test_cli_429_then_network_degraded(self) -> None:
        """CLI: 429 -> network degrades; both failures recorded."""
        payload, calls = self.harness.run(
            "CVE-2026-9901", [_provider_error(429), _network_error()]
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(
            payload["outage_events"], ["http_429", "network"]
        )
        self.assertEqual(len(calls), 2)

    def test_cli_402_no_retry_no_sleep(self) -> None:
        """CLI: 402 degrades immediately without sleeping."""
        payload, calls = self.harness.run(
            "CVE-2026-9901", [_provider_error(402)]
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertFalse(payload["retry_attempted"])
        self.assertIsNone(payload["retry_succeeded"])
        self.assertEqual(payload["outage_events"], ["http_402"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_cli_503_no_retry_no_sleep(self) -> None:
        """CLI: 503 degrades immediately without sleeping."""
        payload, calls = self.harness.run(
            "CVE-2026-9901", [_provider_error(503)]
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertFalse(payload["retry_attempted"])
        self.assertEqual(payload["outage_events"], ["http_5xx"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_cli_programming_error_raises_no_retry(self) -> None:
        """CLI: programming errors propagate, never retried."""
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        cve = ResearchDocument(
            source_type="cve",
            title="CVE-2026-9902",
            content="fixture",
        )

        class _BrokenResearcher:
            calls = 0

            def research(self, **kwargs):
                type(self).calls += 1
                raise TypeError("programmer bug")

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
                _BrokenResearcher,
            ),
            patch.object(
                cli_mod, "RESEARCH_DIR", Path(self._tmpdir.name) / "cli"
            ),
            patch(
                "ai.researcher.retry_policy.sleep_before_429_retry",
                side_effect=AssertionError("must not sleep"),
            ),
        ):
            with self.assertRaises(TypeError):
                cli_mod._research_single_cve("CVE-2026-9902")
        self.assertEqual(_BrokenResearcher.calls, 1)

    def test_cli_success_first_attempt_no_retry(self) -> None:
        """CLI: first-attempt success carries no retry markers."""
        payload, calls = self.harness.run(
            "CVE-2026-9901", [_research_result()]
        )
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["llm_status"], "ok")
        self.assertFalse(payload["retry_attempted"])
        self.assertIsNone(payload["retry_succeeded"])
        self.assertEqual(payload["outage_events"], [])
        self.assertIsNone(payload["outage_bucket"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.harness.sleep_calls, [])

    def test_cli_skip_llm_no_retry(self) -> None:
        """CLI: --skip-llm never retries and stamps no outage."""
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        cve = ResearchDocument(
            source_type="cve",
            title="CVE-2026-9903",
            content="fixture",
        )
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
            patch.object(
                cli_mod, "RESEARCH_DIR", Path(self._tmpdir.name) / "cli"
            ),
            patch(
                "ai.researcher.retry_policy.sleep_before_429_retry",
                side_effect=AssertionError("must not sleep"),
            ),
        ):
            payload = cli_mod._research_single_cve(
                "CVE-2026-9903", skip_llm=True
            )
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["llm_status"], "skipped")
        self.assertFalse(payload["retry_attempted"])
        self.assertIsNone(payload["retry_succeeded"])
        self.assertEqual(payload["outage_events"], [])


class RetrySeamTests(unittest.TestCase):
    """Scenario 12: the backoff seam fires once for 429, never otherwise."""

    def setUp(self) -> None:
        self.harness = _BatchHarness()
        self.addCleanup(self.harness.cleanup)

    def test_batch_sleep_called_once_with_configured_delay(self) -> None:
        seen: list[float] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(429)

        self.harness.run(
            fn,
            ["CVE-2026-9901"],
            retry_sleep_fn=seen.append,
            retry_429_delay=0.25,
        )
        self.assertEqual(seen, [0.25])

    def test_batch_delay_capped(self) -> None:
        seen: list[float] = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(429)

        self.harness.run(
            fn,
            ["CVE-2026-9901"],
            retry_sleep_fn=seen.append,
            retry_429_delay=9999,
        )
        self.assertEqual(seen, [MAX_RETRY_429_DELAY_SECONDS])

    def test_batch_no_sleep_without_429(self) -> None:
        for exc in (
            _provider_error(402),
            _provider_error(503),
            _network_error(),
            RuntimeError("hard failure"),
        ):
            with self.subTest(exc=repr(exc)):
                harness = _BatchHarness()
                try:

                    def fn(cve_id: str, skip_llm: bool = False) -> dict:
                        raise exc

                    harness.run(fn, ["CVE-2026-9901"])
                    self.assertEqual(harness.sleep_calls, [])
                finally:
                    harness.cleanup()


if __name__ == "__main__":
    unittest.main()
