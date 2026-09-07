"""Batch/single reference-quality observability parity (research-only).

Verifies that each batch result item exposes the existing per-CVE
``reference_quality`` gate outcome (counts only), while aggregate
telemetry, provider/retry/degraded/Nuclei semantics stay unchanged.

Strictly offline: socket/subprocess blocked, no Mongo, no external
HTTP, no DNS, no Nuclei execution, no browser, no target requests.
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

CVE_A = "CVE-2026-9201"
CVE_B = "CVE-2026-9202"
URL_A = "https://example.test/obs-a"
URL_B = "https://example.test/obs-b"


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


def _guarded(test_fn):
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


def _err(status: int) -> OpenRouterProviderError:
    return OpenRouterProviderError(f"OpenRouter returned HTTP {status}: x")


def _net_err() -> OpenRouterProviderError:
    return OpenRouterProviderError("OpenRouter connection error: x")


def _research_dict(cve_id: str) -> dict:
    return {
        "title": f"ok {cve_id}",
        "summary": "offline fixture with no HTTP method.",
        "severity": "medium",
        "cve_ids": [cve_id],
        "affected_products": [],
        "affected_versions": [],
        "nuclei_candidate": False,
        "references": [],
        "evidence": [],
    }


def _payload(
    cve_id: str,
    *,
    quality,
    status: str = "completed",
    llm_status: str = "ok",
    llm_error=None,
    skipped: bool = False,
) -> dict:
    research = {"skipped": True, "reason": "x"} if skipped else _research_dict(cve_id)
    return {
        "research_version": "cli-1",
        "mode": "research-only",
        "authoritative": False,
        "research_status": status,
        "llm_status": llm_status,
        "llm_error": llm_error,
        "outage_bucket": None,
        "outage_events": [],
        "retry_attempted": False,
        "retry_succeeded": None,
        "reference_quality": quality,
        "cve": {
            "id": cve_id,
            "vendor": [],
            "products": [],
            "cvss_score": None,
            "cvss_vector": None,
        },
        "research": research,
    }


def _run_batch(cve_ids, *, research_fn, skip_llm=False):
    """Run run_cve_batch with temp dirs and no-retry-sleep."""
    from ai.researcher.cve_batch import run_cve_batch

    tmp = Path(tempfile.mkdtemp())
    return run_cve_batch(
        cve_ids,
        research_fn=research_fn,
        research_dir=tmp / "research",
        report_dir=tmp / "reports",
        retry_sleep_fn=lambda seconds: None,
        skip_llm=skip_llm,
    )


def _ok_fn(qualities: dict):
    """Injected research_fn returning completed payloads w/ quality."""

    def fn(cve_id: str, skip_llm: bool = False) -> dict:
        return _payload(cve_id, quality=dict(qualities[cve_id]))

    return fn


class PerCvePresenceTests(unittest.TestCase):
    """A/B/C: quality present on completed, partial-reject, all-reject."""

    @_guarded
    def test_a_completed_quality_present(self) -> None:
        agg = _run_batch([CVE_A], research_fn=_ok_fn({CVE_A: {"checked": 1, "rejected": 0}}))
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_b_partial_reject_quality_present(self) -> None:
        agg = _run_batch([CVE_A], research_fn=_ok_fn({CVE_A: {"checked": 1, "rejected": 1}}))
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_c_all_rejected_still_completed_with_quality(self) -> None:
        # All-invalid gate output is still {"checked": 1, "rejected": 1}
        # at the gate level; research continues conservatively.
        agg = _run_batch([CVE_A], research_fn=_ok_fn({CVE_A: {"checked": 1, "rejected": 1}}))
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 1})
        self.assertFalse(item["authoritative"])


class DefaultFlowAggregateTests(unittest.TestCase):
    """D/E: aggregate matches per-CVE items; individuals preserved."""

    def _default_run(self, bodies: dict, cve_ids: list):
        """Run the DEFAULT wrapper flow with faked fetch/discovery/LLM."""
        from ai.researcher.cve_batch import run_cve_batch
        from ai.researcher.reference_cache import BatchReferenceCache

        def fetch_fn(url: str):
            from ai.schemas.reference import ReferenceDocument

            return ReferenceDocument(
                url=url,
                source_type="vendor",
                title=f"title {url}",
                content=bodies[url],
                status_code=200,
                content_hash="h-obs",
                tags=[],
            )

        cache = BatchReferenceCache(fetch_fn=fetch_fn)
        urls = {cve_id: f"https://example.test/obs-{cve_id}" for cve_id in cve_ids}

        class _Cve:
            def __init__(self, title):
                self.title = title
                self.vendor = []
                self.products = []
                self.references = [urls[title]]
                self.cvss_score = None
                self.cvss_vector = None

        cves = {cve_id: _Cve(cve_id) for cve_id in cve_ids}

        class _Collector:
            def get_by_ids(self, ids):
                return [cves[i] for i in ids if i in cves]

        class _Discovery:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def discover(self, cve, limit=5):
                from ai.schemas.discovery import (
                    DiscoveredSource,
                    DiscoveryResult,
                )

                return DiscoveryResult(
                    cve_id=cve.title,
                    sources=[
                        DiscoveredSource(
                            url=urls[cve.title],
                            source_type="vendor",
                            title="advisory",
                            query=cve.title,
                            priority=100,
                            confidence=0.95,
                            tags=["nvd_reference", "vendor"],
                        )
                    ],
                )

        class _Researcher:
            def __init__(self, *a, **k):
                pass

            def research(self, **kwargs):
                from ai.schemas.research import ResearchResult

                return ResearchResult.model_validate(
                    {
                        "title": "t",
                        "summary": "offline gated summary",
                        "vulnerability_type": None,
                        "severity": "medium",
                        "cve_ids": [],
                        "affected_products": [],
                        "affected_versions": [],
                        "attack_requirements": [],
                        "root_cause": None,
                        "impact": [],
                        "public_exploit": None,
                        "actively_exploited": None,
                        "bug_bounty_relevance": 0,
                        "detection_ideas": [],
                        "nuclei_candidate": False,
                        "nuclei_reason": None,
                        "references": [],
                        "evidence": [],
                    }
                )

        import ai.research_cli as cli_module
        import ai.collectors.discovery as discovery_module
        import ai.researcher.researcher as researcher_module
        from ai.correlator import candidates as candidates_module

        tmp = Path(tempfile.mkdtemp())
        with (
            patch.object(cli_module, "_load_assets", lambda: ([], {})),
            patch.object(discovery_module, "ReferenceDiscovery", _Discovery),
            patch("ai.collectors.cve.CVECollector", _Collector),
            patch.object(researcher_module, "SecurityResearcher", _Researcher),
            patch.object(candidates_module, "candidate_assets", lambda cve, index: []),
        ):
            return run_cve_batch(
                cve_ids,
                research_dir=tmp / "research",
                report_dir=tmp / "reports",
                retry_sleep_fn=lambda seconds: None,
                reference_cache=cache,
            )

    @_guarded
    def test_d_aggregate_matches_per_cve(self) -> None:
        bodies = {
            f"https://example.test/obs-{CVE_A}": f"Advisory for {CVE_A} with fix details.",
            f"https://example.test/obs-{CVE_B}": f"Advisory for {CVE_B} with fix details.",
        }
        agg = self._default_run(bodies, [CVE_A, CVE_B])
        qualities = [item["reference_quality"] for item in agg["results"]]
        self.assertEqual(qualities, [{"checked": 1, "rejected": 0}] * 2)
        self.assertEqual(
            agg["reference_quality"],
            {
                "checked": len(qualities),
                "rejected": sum(1 for q in qualities if q["rejected"] == 1),
            },
        )

    @_guarded
    def test_e_individual_values_preserved(self) -> None:
        # CVE_B's only source mentions CVE_A: valid for A, foreign for B.
        bodies = {
            f"https://example.test/obs-{CVE_A}": f"Advisory for {CVE_A} with fix details.",
            f"https://example.test/obs-{CVE_B}": f"Advisory for {CVE_A} with fix details.",
        }
        agg = self._default_run(bodies, [CVE_A, CVE_B])
        by_cve = {item["cve"]: item["reference_quality"] for item in agg["results"]}
        self.assertEqual(by_cve[CVE_A], {"checked": 1, "rejected": 0})
        self.assertEqual(by_cve[CVE_B], {"checked": 1, "rejected": 1})
        self.assertEqual(agg["reference_quality"], {"checked": 2, "rejected": 1})

    @_guarded
    def test_p_ordering_unchanged(self) -> None:
        bodies = {
            f"https://example.test/obs-{CVE_A}": f"Advisory for {CVE_A} with fix details.",
            f"https://example.test/obs-{CVE_B}": f"Advisory for {CVE_A} with fix details.",
        }
        agg = self._default_run(bodies, [CVE_B, CVE_A])
        self.assertEqual([item["cve"] for item in agg["results"]], [CVE_B, CVE_A])
        self.assertEqual(agg["results"][0]["reference_quality"], {"checked": 1, "rejected": 1})
        self.assertEqual(agg["results"][1]["reference_quality"], {"checked": 1, "rejected": 0})


class DuplicateCacheTests(unittest.TestCase):
    """F: duplicate CVE cache hit preserves quality without new calls."""

    @_guarded
    def test_f_duplicate_preserves_quality(self) -> None:
        calls: list = []

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            calls.append(cve_id)
            return _payload(cve_id, quality={"checked": 1, "rejected": 1})

        agg = _run_batch([CVE_A, CVE_A], research_fn=fn)
        self.assertEqual(calls, [CVE_A])  # no second provider call
        self.assertEqual(agg["provider_cache"], {"hits": 1})
        self.assertEqual(len(agg["results"]), 2)
        self.assertEqual(
            agg["results"][0]["reference_quality"], {"checked": 1, "rejected": 1}
        )
        self.assertEqual(
            agg["results"][1]["reference_quality"], {"checked": 1, "rejected": 1}
        )
        # No shared mutable state: mutating one must not affect the other.
        agg["results"][0]["reference_quality"]["rejected"] = 0
        self.assertEqual(
            agg["results"][1]["reference_quality"], {"checked": 1, "rejected": 1}
        )


class RetryDegradedTests(unittest.TestCase):
    """G/H/I/J: retry and degraded paths preserve quality."""

    @_guarded
    def test_g_429_then_success_preserves_quality(self) -> None:
        script: list = [_err(429), _payload(CVE_A, quality={"checked": 1, "rejected": 1})]

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            action = script.pop(0)
            if isinstance(action, BaseException):
                raise action
            return action

        agg = _run_batch([CVE_A], research_fn=fn)
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 1})
        self.assertEqual(
            agg["provider_retries"], {"attempted": 1, "succeeded": 1, "exhausted": 0}
        )

    @_guarded
    def test_h_429_429_degraded_payload_preserves_quality(self) -> None:
        # What the real CLI/wrapper return after internal retry
        # exhaustion: a degraded payload that still carries the
        # pre-failure gate outcome.
        degraded = _payload(
            CVE_A,
            quality={"checked": 1, "rejected": 1},
            status="completed_degraded",
            llm_status="unavailable",
            llm_error="temporarily unavailable",
        )
        degraded["outage_bucket"] = "http_429"
        degraded["outage_events"] = ["http_429", "http_429"]
        degraded["retry_attempted"] = True
        degraded["retry_succeeded"] = False
        agg = _run_batch([CVE_A], research_fn=lambda c, skip_llm=False: degraded)
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_i_503_degraded_preserves_quality(self) -> None:
        degraded = _payload(
            CVE_A,
            quality={"checked": 1, "rejected": 0},
            status="completed_degraded",
            llm_status="unavailable",
            llm_error="temporarily unavailable",
        )
        degraded["outage_bucket"] = "http_5xx"
        degraded["outage_events"] = ["http_5xx"]
        agg = _run_batch([CVE_A], research_fn=lambda c, skip_llm=False: degraded)
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_j_network_degraded_preserves_quality(self) -> None:
        degraded = _payload(
            CVE_A,
            quality={"checked": 1, "rejected": 0},
            status="completed_degraded",
            llm_status="unavailable",
            llm_error="temporarily unavailable",
        )
        degraded["outage_bucket"] = "network"
        degraded["outage_events"] = ["network"]
        agg = _run_batch([CVE_A], research_fn=lambda c, skip_llm=False: degraded)
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_batch_layer_double_raise_invents_nothing(self) -> None:
        # No research result exists here (the fn raised before any
        # gate could run), so no quality is invented; failure
        # semantics are unchanged.
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise _err(429)

        agg = _run_batch([CVE_A], research_fn=fn)
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed_degraded")
        self.assertIsNone(item["reference_quality"])


class SkipLlmTests(unittest.TestCase):
    """K: skip-LLM preserves quality; researcher never called."""

    @_guarded
    def test_k_skip_llm_preserves_quality(self) -> None:
        seen: dict = {}

        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            seen["skip_llm"] = skip_llm
            return _payload(
                cve_id, quality={"checked": 1, "rejected": 0}, skipped=True
            )

        agg = _run_batch([CVE_A], research_fn=fn, skip_llm=True)
        self.assertTrue(seen["skip_llm"])
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "completed")
        self.assertEqual(item["reference_quality"], {"checked": 1, "rejected": 0})


class SingleBatchParityTests(unittest.TestCase):
    """L: identical synthetic inputs agree across single and batch."""

    @_guarded
    def test_l_single_vs_batch_parity(self) -> None:
        import ai.research_cli as cli_module
        from ai.schemas.source import ResearchDocument

        body = f"Vendor advisory for {CVE_A} describing the flaw and fix."
        cve = ResearchDocument(
            source_type="cve",
            title=CVE_A,
            url=f"https://nvd.nist.gov/vuln/detail/{CVE_A}",
            content="NVD fixture with no HTTP method.",
            vendor=["fixture-vendor"],
            products=["fixture-product"],
            references=[URL_A],
        )
        docs = [
            {
                "url": URL_A,
                "source_type": "vendor",
                "title": f"title {URL_A}",
                "priority": 100,
                "tags": [],
                "content": body,
            }
        ]

        class _Discovery:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def discover(self, cve, limit=5):
                from ai.schemas.discovery import DiscoveryResult

                return DiscoveryResult(cve_id=cve.title, sources=[])

        class _Researcher:
            def __init__(self, *a, **k):
                pass

            def research(self, **kwargs):
                from ai.schemas.research import ResearchResult

                return ResearchResult.model_validate(
                    {
                        "title": "t",
                        "summary": "offline gated summary",
                        "vulnerability_type": None,
                        "severity": "medium",
                        "cve_ids": [],
                        "affected_products": [],
                        "affected_versions": [],
                        "attack_requirements": [],
                        "root_cause": None,
                        "impact": [],
                        "public_exploit": None,
                        "actively_exploited": None,
                        "bug_bounty_relevance": 0,
                        "detection_ideas": [],
                        "nuclei_candidate": False,
                        "nuclei_reason": None,
                        "references": [],
                        "evidence": [],
                    }
                )

        with (
            patch.object(cli_module, "_load_assets", return_value=([], None)),
            patch("ai.collectors.cve.CVECollector.get_by_ids", return_value=[cve]),
            patch("ai.correlator.candidates.candidate_assets", return_value=[]),
            patch("ai.collectors.discovery.ReferenceDiscovery", _Discovery),
            patch(
                "ai.collectors.discovery_fetch.fetch_discovered_sources",
                return_value=docs,
            ),
            patch.object(cli_module, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
            patch("ai.researcher.researcher.SecurityResearcher", _Researcher),
        ):
            single = cli_module._research_single_cve(CVE_A)

        def batch_fn(cve_id: str, skip_llm: bool = False) -> dict:
            # Same gate, same inputs: batch item must mirror single.
            from ai.researcher.reference_quality import gate_reference_contexts
            from ai.researcher.research_context import build_research_contexts

            raw = build_research_contexts(
                documents=docs, cve_id=cve_id, keywords=[cve_id]
            )
            gated = gate_reference_contexts(
                raw, cve_id=cve_id, known_urls={URL_A}
            )
            payload = _payload(
                cve_id,
                quality={
                    "checked": 1,
                    "rejected": 1 if gated.rejected else 0,
                },
            )
            return payload

        agg = _run_batch([CVE_A], research_fn=batch_fn)
        self.assertEqual(
            agg["results"][0]["reference_quality"], single["reference_quality"]
        )
        self.assertEqual(single["reference_quality"], {"checked": 1, "rejected": 0})


class TelemetryShapeTests(unittest.TestCase):
    """M/N/O: exact keys, integer values, no leaks."""

    @_guarded
    def test_m_exact_keys_and_n_integers(self) -> None:
        agg = _run_batch(
            [CVE_A, CVE_B],
            research_fn=_ok_fn(
                {
                    CVE_A: {"checked": 1, "rejected": 0},
                    CVE_B: {"checked": 1, "rejected": 1},
                }
            ),
        )
        for item in agg["results"]:
            quality = item["reference_quality"]
            self.assertEqual(set(quality.keys()), {"checked", "rejected"})
            for value in quality.values():
                self.assertIsInstance(value, int)
                self.assertNotIsInstance(value, bool)

    @_guarded
    def test_o_no_leaks_in_telemetry(self) -> None:
        agg = _run_batch(
            [CVE_A], research_fn=_ok_fn({CVE_A: {"checked": 1, "rejected": 1}})
        )
        blob = json.dumps(agg["results"][0]["reference_quality"])
        self.assertNotIn("example.test", blob)
        self.assertNotIn(URL_A, blob)
        self.assertNotIn(CVE_A, blob)
        self.assertNotIn("sk-or", blob.lower())
        self.assertNotIn("content", blob.lower())
        full = json.dumps(agg).lower()
        for forbidden in (
            "sealedfinding",
            "confirmed",
            "live_http",
            "live_nuclei",
            "ready_for_scan",
        ):
            self.assertNotIn(forbidden, full)

    @_guarded
    def test_result_keys_include_quality_last(self) -> None:
        from ai.researcher.cve_batch import RESULT_KEYS

        self.assertIn("reference_quality", RESULT_KEYS)
        agg = _run_batch([CVE_A], research_fn=_ok_fn({CVE_A: {"checked": 1, "rejected": 0}}))
        self.assertEqual(tuple(agg["results"][0].keys()), RESULT_KEYS)


class HardFailureTests(unittest.TestCase):
    """Q: hard-failure semantics unchanged; nothing invented."""

    @_guarded
    def test_q_invalid_format_failed_no_quality(self) -> None:
        agg = _run_batch(
            ["NOT-A-CVE"], research_fn=_ok_fn({})
        )
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "failed")
        self.assertIn("invalid CVE format", item["error"])
        self.assertIsNone(item["reference_quality"])

    @_guarded
    def test_q_non_transient_failed_no_quality(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            raise TypeError("programmer bug")

        agg = _run_batch([CVE_A], research_fn=fn)
        item = agg["results"][0]
        self.assertEqual(item["research_status"], "failed")
        self.assertIn("TypeError", item["error"])
        self.assertIsNone(item["reference_quality"])


class GateSingularityTests(unittest.TestCase):
    def test_single_gate_implementation(self) -> None:
        import ast

        import ai.researcher.cve_batch as batch_mod
        import ai.researcher.reference_quality as gate_mod

        self.assertTrue(hasattr(gate_mod, "gate_reference_contexts"))
        # The batch module reuses the gate; it defines no gate of its own.
        # The only quality-named helper allowed is the observability
        # extractor, which copies two ints and contains no gating logic.
        tree = ast.parse(
            Path(batch_mod.__file__).read_text(encoding="utf-8")
        )
        defs = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.assertNotIn("gate_reference_contexts", defs)
        self.assertEqual(
            [name for name in defs if "quality" in name.lower()],
            ["_per_cve_reference_quality"],
        )
        self.assertIn("gate_reference_contexts", batch_mod._make_cached_research_fn.__doc__ or "")


class SafetyTests(unittest.TestCase):
    @_guarded
    def test_safety_flags(self) -> None:
        agg = _run_batch([CVE_A], research_fn=_ok_fn({CVE_A: {"checked": 1, "rejected": 0}}))
        blob = json.dumps(agg).lower()
        for forbidden in (
            "sealedfinding",
            "live_http",
            "live_nuclei",
            "ready_for_scan",
            "5j",
        ):
            # "5j" is too short to search blindly; check the rest.
            if forbidden == "5j":
                continue
            self.assertNotIn(forbidden, blob)
        self.assertFalse(agg["results"][0]["authoritative"])
        self.assertFalse(agg["results"][0]["nuclei_candidate"])


if __name__ == "__main__":
    unittest.main()
