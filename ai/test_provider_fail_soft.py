"""Focused offline tests for research provider fail-soft/degraded mode.

Covers:

- 402/429/5xx -> completed_degraded (never dropped)
- timeout/network failure -> completed_degraded
- programmer/unexpected error -> failed (never hidden)
- degraded result never claims LLM completion
- degraded result never creates authoritative/CONFIRMED state
- batch continues after provider failure
- deterministic fallback feeds a conservative Nuclei decision
- successful LLM path unchanged

Strictly offline: no network, no subprocess, no live execution.
"""

from __future__ import annotations

import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.llm.openrouter import OpenRouterProviderError
from ai.researcher.degraded import build_degraded_research
from ai.researcher.provider_errors import classify_provider_failure


def _provider_error(status: int) -> OpenRouterProviderError:
    return OpenRouterProviderError(
        f"OpenRouter returned HTTP {status}: APIStatusError"
    )


def _degraded_research_fn(cve_id: str, skip_llm: bool = False) -> dict:
    raise _provider_error(429)


class ClassifyTests(unittest.TestCase):
    def test_402_transient(self) -> None:
        info = classify_provider_failure(_provider_error(402))
        self.assertTrue(info.transient)
        self.assertEqual(info.status_code, 402)

    def test_429_transient(self) -> None:
        info = classify_provider_failure(_provider_error(429))
        self.assertTrue(info.transient)
        self.assertEqual(info.status_code, 429)

    def test_5xx_transient(self) -> None:
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                info = classify_provider_failure(_provider_error(status))
                self.assertTrue(info.transient)
                self.assertEqual(info.status_code, status)

    def test_401_not_transient(self) -> None:
        info = classify_provider_failure(_provider_error(401))
        self.assertFalse(info.transient)

    def test_network_timeout_transient(self) -> None:
        err = OpenRouterProviderError(
            "OpenRouter connection error: APIConnectionError"
        )
        self.assertTrue(classify_provider_failure(err).transient)

    def test_programmer_error_never_degraded(self) -> None:
        for exc in (
            TypeError("boom"),
            AttributeError("boom"),
            KeyError("boom"),
            ValueError("LLM returned invalid JSON: {oops"),
            RuntimeError("simulated research failure"),
        ):
            with self.subTest(exc=repr(exc)):
                self.assertFalse(classify_provider_failure(exc).transient)


class DegradedResultTests(unittest.TestCase):
    def test_degraded_never_claims_llm_completion(self) -> None:
        research = build_degraded_research(
            "CVE-2026-9001",
            llm_error="HTTP 429",
            description="NVD description fixture.",
            vendor=["fixture-vendor"],
            products=["fixture-product"],
            affected_versions=["1.0"],
            references=["https://example.test/advisory"],
        )
        blob = research.model_dump_json().lower()
        self.assertNotIn("llm completed", blob)
        self.assertIn("llm", (research.nuclei_reason or "").lower())
        self.assertIn("unavailable", blob)
        self.assertFalse(research.nuclei_candidate)
        self.assertIsNone(research.root_cause)
        self.assertEqual(research.detection_ideas, [])
        self.assertEqual(research.attack_requirements, [])
        self.assertEqual(research.impact, [])

    def test_degraded_never_authoritative_or_confirmed(self) -> None:
        research = build_degraded_research(
            "CVE-2026-9001", llm_error="HTTP 503"
        )
        self.assertFalse(research.nuclei_candidate)
        self.assertIsNone(research.public_exploit)
        self.assertIsNone(research.actively_exploited)
        self.assertEqual(research.bug_bounty_relevance, 0)
        self.assertIsNone(research.severity)
        self.assertIsNone(research.vulnerability_type)
        for item in research.evidence:
            lowered = item.lower()
            self.assertNotIn("confirmed: public exploit", lowered)
            self.assertNotIn("confirmed: actively exploited", lowered)


class BatchFailSoftTests(unittest.TestCase):
    def _run(self, research_fn, cve_ids, template_dir=None):
        from ai.researcher.cve_batch import run_cve_batch

        kwargs: dict = {
            "research_fn": research_fn,
            "research_dir": Path(self._tmp) / "research",
            "report_dir": Path(self._tmp) / "reports",
            # Never really sleep: the bounded 429 retry backoff goes
            # through this injectable seam (see retry_policy).
            "retry_sleep_fn": lambda seconds: None,
        }
        if template_dir is not None:
            kwargs["template_dir"] = template_dir
        return run_cve_batch(cve_ids, **kwargs)

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = self._tmpdir.name
        self.addCleanup(self._tmpdir.cleanup)

    def test_402_batch_degraded(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(402)

        aggregate = self._run(fn, ["CVE-2026-9001"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertEqual(aggregate["completed_degraded"], 1)
        self.assertEqual(aggregate["completed"], 0)
        self.assertEqual(aggregate["failed"], 0)
        self.assertEqual(aggregate["processed"], 1)

    def test_429_batch_degraded(self) -> None:
        aggregate = self._run(_degraded_research_fn, ["CVE-2026-9001"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertIn("degraded", (item["error"] or "").lower())
        self.assertFalse(item["authoritative"])

    def test_5xx_batch_degraded(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _provider_error(503)

        aggregate = self._run(fn, ["CVE-2026-9001"])
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed_degraded"
        )
        self.assertEqual(aggregate["failed"], 0)

    def test_unexpected_error_stays_failed(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise RuntimeError("simulated research failure")

        aggregate = self._run(fn, ["CVE-2026-9001"])
        self.assertEqual(aggregate["results"][0]["research_status"], "failed")
        self.assertEqual(aggregate["failed"], 1)
        self.assertEqual(aggregate["processed"], 0)

    def test_batch_continues_after_provider_failure(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            if cve_id == "CVE-2026-9001":
                raise _provider_error(429)
            if cve_id == "CVE-2026-9002":
                raise RuntimeError("hard failure")
            return {
                "research_version": "cli-1",
                "mode": "research-only",
                "authoritative": False,
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

        aggregate = self._run(
            fn, ["CVE-2026-9001", "CVE-2026-9002", "CVE-2026-9003"]
        )
        by_cve = {item["cve"]: item for item in aggregate["results"]}
        self.assertEqual(
            by_cve["CVE-2026-9001"]["research_status"], "completed_degraded"
        )
        self.assertEqual(by_cve["CVE-2026-9002"]["research_status"], "failed")
        self.assertEqual(by_cve["CVE-2026-9003"]["research_status"], "completed")
        self.assertEqual(aggregate["completed"], 1)
        self.assertEqual(aggregate["completed_degraded"], 1)
        self.assertEqual(aggregate["failed"], 1)
        self.assertEqual(aggregate["processed"], 2)

    def test_degraded_produces_conservative_nuclei_decision(self) -> None:
        with patch.object(socket, "create_connection", side_effect=AssertionError("net")), patch.object(
            subprocess, "run", side_effect=AssertionError("proc")
        ):
            aggregate = self._run(_degraded_research_fn, ["CVE-2026-9001"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertFalse(item["nuclei_candidate"])
        self.assertFalse(item["template_generated"])
        # Grounded-only material has no HTTP method/path -> NOT_APPLICABLE.
        self.assertEqual(item["decision"], "NOT_APPLICABLE")

    def test_successful_llm_path_unchanged(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return {
                "research_version": "cli-1",
                "mode": "research-only",
                "authoritative": False,
                "research_status": "completed",
                "llm_status": "ok",
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

        aggregate = self._run(fn, ["CVE-2026-9001"])
        item = aggregate["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertIsNone(item["error"])
        self.assertEqual(aggregate["completed"], 1)
        self.assertEqual(aggregate["completed_degraded"], 0)


class ResearchCliFailSoftTests(unittest.TestCase):
    def test_cli_single_cve_transient_uses_deterministic_fallback(self) -> None:
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        cve = ResearchDocument(
            source_type="cve",
            title="CVE-2026-9009",
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-9009",
            content="NVD fixture description with no HTTP method.",
            vendor=["fixture-vendor"],
            products=["fixture-product"],
            references=["https://example.test/advisory"],
        )

        class _FailingResearcher:
            def research(self, **kwargs):
                raise _provider_error(429)

        with (
            patch.object(
                cli_mod, "_load_assets", return_value=([], None)
            ),
            patch(
                "ai.collectors.cve.CVECollector.get_by_ids",
                return_value=[cve],
            ),
            patch(
                "ai.correlator.candidates.candidate_assets",
                return_value=[],
            ),
            patch(
                "ai.collectors.discovery.ReferenceDiscovery",
            ),
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
            patch.object(cli_mod, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
            # Bounded 429 retry backoff: injectable seam, never sleeps.
            patch(
                "ai.researcher.retry_policy.sleep_before_429_retry",
                return_value=2.0,
            ),
        ):
            payload = cli_mod._research_single_cve("CVE-2026-9009")

        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["llm_status"], "unavailable")
        self.assertFalse(payload["authoritative"])
        self.assertTrue(payload["research_only"])
        self.assertIn("unavailable", payload["research"]["summary"].lower())

    def test_cli_single_cve_unexpected_error_raises(self) -> None:
        import ai.research_cli as cli_mod
        from ai.schemas.source import ResearchDocument

        cve = ResearchDocument(
            source_type="cve",
            title="CVE-2026-9010",
            content="fixture",
        )

        class _BrokenResearcher:
            def research(self, **kwargs):
                raise TypeError("programmer bug")

        with (
            patch.object(
                cli_mod, "_load_assets", return_value=([], None)
            ),
            patch(
                "ai.collectors.cve.CVECollector.get_by_ids",
                return_value=[cve],
            ),
            patch(
                "ai.correlator.candidates.candidate_assets",
                return_value=[],
            ),
            patch(
                "ai.collectors.discovery.ReferenceDiscovery",
            ),
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
            patch.object(cli_mod, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
        ):
            with self.assertRaises(TypeError):
                cli_mod._research_single_cve("CVE-2026-9010")


if __name__ == "__main__":
    unittest.main()
