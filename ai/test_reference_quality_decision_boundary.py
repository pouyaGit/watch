"""Reference-quality → research-decision boundary tests (research-only).

Proves the deterministic quality gate is FILTER-ONLY and
non-authoritative, and that degraded/partial/foreign/duplicate/empty
reference context cannot cause the Researcher/Correlator to invent
facts, gain confidence without evidence, or produce an unsafe Nuclei
candidate.

Boundary under test:

    gate_reference_contexts → ReferenceContext
        → SecurityResearcher.research → ResearchResult
        → offline Nuclei decision lane

Strictly offline: socket/subprocess blocked, fake discovery/fetch/LLM,
no Nuclei execution, no browser, no DNS, no Mongo, no target requests.
Only structured ResearchResult fields and supplied contexts are
inspected (no chain-of-thought).
"""

from __future__ import annotations

import inspect
import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ai.llm.openrouter import OpenRouterProviderError

CVE = "CVE-2026-9301"
FOREIGN = "CVE-2026-9999"
URL_A = "https://example.test/boundary-a"
URL_B = "https://example.test/boundary-b"
URL_C = "https://example.test/boundary-c"


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


def _ctx(url, *, exact=None, chunks=None):
    return {
        "url": url,
        "source_type": "vendor",
        "title": f"title {url}",
        "priority": 90,
        "exact_record": exact,
        "context_chunks": list(chunks) if chunks is not None else [],
    }


def _exact(cve_id):
    return f"{cve_id} buffer overflow fixed in version 2."


def _chunk(cve_id):
    return f"issue body describes reproduction for {cve_id}."


def _cve_doc(cve_id=CVE):
    from ai.schemas.source import ResearchDocument

    return ResearchDocument(
        source_type="cve",
        title=cve_id,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        content="NVD fixture with no HTTP method.",
        vendor=["fixture-vendor"],
        products=["fixture-product"],
        references=[URL_A],
    )


def _research_result(**overrides):
    from ai.schemas.research import ResearchResult

    fields = {
        "title": "offline fixture",
        "summary": "offline fixture summary with no HTTP method.",
        "severity": "medium",
        "cve_ids": [CVE],
    }
    fields.update(overrides)
    return ResearchResult(**fields)


def _run_single(cve_id, *, contexts_raw, discovered_urls, script, skip_llm=False):
    """Run _research_single_cve with fakes; capture full researcher kwargs."""
    import ai.research_cli as cli_mod

    calls: list[dict] = []

    class _CapturingResearcher:
        def research(self, **kwargs):
            calls.append(dict(kwargs))
            action = script[len(calls) - 1]
            if isinstance(action, BaseException):
                raise action
            return action

    discovered_docs = [
        {
            "url": url,
            "source_type": "vendor",
            "title": f"title {url}",
            "priority": 100,
            "tags": [],
            "content": f"content for {url} mentioning {cve_id}.",
        }
        for url in discovered_urls
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

    with (
        patch.object(cli_mod, "_load_assets", return_value=([], None)),
        patch(
            "ai.collectors.cve.CVECollector.get_by_ids",
            return_value=[_cve_doc(cve_id)],
        ),
        patch("ai.correlator.candidates.candidate_assets", return_value=[]),
        patch("ai.collectors.discovery.ReferenceDiscovery", _Discovery),
        patch(
            "ai.collectors.discovery_fetch.fetch_discovered_sources",
            return_value=discovered_docs,
        ),
        patch(
            "ai.researcher.research_context.build_research_contexts",
            return_value=contexts_raw,
        ),
        patch(
            "ai.researcher.researcher.SecurityResearcher",
            _CapturingResearcher,
        ),
        patch.object(cli_mod, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
        patch(
            "ai.researcher.retry_policy.sleep_before_429_retry",
            return_value=0.0,
        ),
    ):
        payload = cli_mod._research_single_cve(cve_id, skip_llm=skip_llm)
    return payload, calls


def _err(status: int) -> OpenRouterProviderError:
    return OpenRouterProviderError(f"OpenRouter returned HTTP {status}: x")


def _net_err() -> OpenRouterProviderError:
    return OpenRouterProviderError("OpenRouter connection error: x")


def _lane_decision(research, cve_content="NVD fixture with no HTTP method."):
    """Run the existing offline extractor + decision (pure, no execution)."""
    from ai.correlator.detection import DetectionSpecExtractor
    from ai.correlator.nuclei_decision import NucleiDecisionEngine

    cve = SimpleNamespace(title=CVE, content=cve_content)
    detection = DetectionSpecExtractor().extract(cve, research)
    return NucleiDecisionEngine().decide(cve=cve, research=research, detection=detection)


def _lane_candidate(research) -> bool:
    """Batch-lane rule: researcher flag AND GOOD_CANDIDATE decision."""
    decision = _lane_decision(research)
    return bool(research.nuclei_candidate) and decision.decision == "GOOD_CANDIDATE"


class GateFilterTests(unittest.TestCase):
    """Coverage 1-7: filter-only handoff into the researcher."""

    @_guarded
    def test_1_valid_reaches_researcher_unchanged(self) -> None:
        raw = [_ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])]
        _, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        got = calls[0]["reference_contexts"]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].source_url, URL_A)
        self.assertEqual(got[0].exact_record, _exact(CVE))
        self.assertEqual(got[0].context_chunks, [_chunk(CVE)])

    @_guarded
    def test_2_foreign_removed_before_researcher(self) -> None:
        good = _ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, exact=_exact(FOREIGN), chunks=[_chunk(FOREIGN)])
        _, calls = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_research_result()],
        )
        self.assertEqual(
            [c.source_url for c in calls[0]["reference_contexts"]], [URL_A]
        )

    @_guarded
    def test_3_malformed_removed_before_researcher(self) -> None:
        good = _ctx(URL_A, chunks=[_chunk(CVE)])
        _, calls = _run_single(
            CVE, contexts_raw=[good, "not-a-dict", None, 42],
            discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(
            [c.source_url for c in calls[0]["reference_contexts"]], [URL_A]
        )

    @_guarded
    def test_4_empty_context_reaches_researcher_as_empty(self) -> None:
        bad = _ctx(URL_A, chunks=[_chunk(FOREIGN)])
        payload, calls = _run_single(
            CVE, contexts_raw=[bad], discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(calls[0]["reference_contexts"], [])
        self.assertEqual(payload["research_status"], "completed")

    @_guarded
    def test_5_no_reference_case_is_safe(self) -> None:
        payload, calls = _run_single(
            CVE, contexts_raw=[], discovered_urls=[],
            script=[_research_result()],
        )
        self.assertEqual(calls[0]["reference_contexts"], [])
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})
        self.assertFalse(payload["research"]["nuclei_candidate"])

    @_guarded
    def test_6_duplicate_reaches_researcher_once(self) -> None:
        first = _ctx(URL_A, chunks=[_chunk(CVE)])
        second = _ctx(URL_A, chunks=[_chunk(CVE)])
        _, calls = _run_single(
            CVE, contexts_raw=[first, second], discovered_urls=[URL_A],
            script=[_research_result()],
        )
        got = calls[0]["reference_contexts"]
        self.assertEqual([c.source_url for c in got], [URL_A])

    @_guarded
    def test_7_mixed_valid_invalid_duplicate(self) -> None:
        good_a = _ctx(URL_A, chunks=[_chunk(CVE)])
        dup_a = _ctx(URL_A, chunks=[_chunk(CVE)])
        foreign = _ctx(URL_B, chunks=[_chunk(FOREIGN)])
        malformed = "not-a-dict"
        good_c = _ctx(URL_C, chunks=[_chunk(CVE)])
        payload, calls = _run_single(
            CVE,
            contexts_raw=[good_a, dup_a, foreign, malformed, good_c],
            discovered_urls=[URL_A, URL_B, URL_C],
            script=[_research_result()],
        )
        self.assertEqual(
            [c.source_url for c in calls[0]["reference_contexts"]],
            [URL_A, URL_C],
        )
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})


class ExactHandoffTests(unittest.TestCase):
    """Coverage 8: gate output exactly equals researcher input."""

    @_guarded
    def test_8_gate_output_equals_researcher_input(self) -> None:
        from ai.researcher.reference_quality import gate_reference_contexts

        good_a = _ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])
        dup_a = _ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])
        foreign = _ctx(URL_B, chunks=[_chunk(FOREIGN)])
        good_c = _ctx(URL_C, chunks=[_chunk(CVE)])
        raw = [good_a, dup_a, foreign, good_c]
        known = {URL_A, URL_B, URL_C}
        gated = gate_reference_contexts(raw, cve_id=CVE, known_urls=known)

        _, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A, URL_B, URL_C],
            script=[_research_result()],
        )
        got = calls[0]["reference_contexts"]
        # Same entries, same order, same values — nothing added/changed.
        self.assertEqual(len(got), len(gated.contexts))
        for received, expected in zip(got, gated.contexts):
            self.assertEqual(received.source_url, expected["url"])
            self.assertEqual(received.source_type, expected["source_type"])
            self.assertEqual(received.title, expected.get("title"))
            self.assertEqual(received.exact_record, expected.get("exact_record"))
            self.assertEqual(
                received.context_chunks, expected.get("context_chunks", [])
            )
        # Gate is filter-only: survivors are the identical objects.
        for kept in gated.contexts:
            self.assertTrue(any(kept is entry for entry in raw))
        # Researcher signature carries no telemetry channel at all.
        from ai.researcher.researcher import SecurityResearcher

        params = set(inspect.signature(SecurityResearcher.research).parameters)
        self.assertEqual(
            params,
            {
                "self",
                "document",
                "programs",
                "assets",
                "technologies",
                "reference_contexts",
                "discovered_sources",
            },
        )
        self.assertEqual(set(calls[0].keys()) - {"self"}, params - {"self"})


class TelemetryNotEvidenceTests(unittest.TestCase):
    """Coverage 9/12/13: telemetry never becomes evidence; no leakage."""

    @_guarded
    def test_9_quality_telemetry_not_treated_as_evidence(self) -> None:
        # The gate outcome is never forwarded to the researcher: even a
        # greedy stub can only see surviving contexts, never the counts.
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        blob = json.dumps(calls[0], default=str)
        self.assertNotIn("checked", blob)
        self.assertNotIn("rejected", blob)
        self.assertNotIn("reference_quality", blob)
        # And downstream modules have no telemetry surface at all.
        for module_name in (
            "ai.researcher.researcher",
            "ai.correlator.nuclei_decision",
            "ai.correlator.detection",
            "ai.researcher.degraded",
        ):
            source = Path(__import__(module_name, fromlist=["x"]).__file__).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("reference_quality", source, module_name)
            self.assertNotIn("gate_reference", source, module_name)
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_12_rejected_references_cannot_leak_downstream(self) -> None:
        good = _ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, exact=_exact(FOREIGN), chunks=[_chunk(FOREIGN)])
        _, calls = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_research_result()],
        )
        received = calls[0]["reference_contexts"]
        urls = [c.source_url for c in received]
        self.assertNotIn(URL_B, urls)
        blob = json.dumps(
            [
                {
                    "url": c.source_url,
                    "exact": c.exact_record,
                    "chunks": c.context_chunks,
                }
                for c in received
            ]
        )
        self.assertNotIn(FOREIGN, blob)

    @_guarded
    def test_13_foreign_cve_cannot_influence_current_cve(self) -> None:
        foreign_only = _ctx(URL_A, chunks=[_chunk(FOREIGN)])
        _, calls = _run_single(
            CVE, contexts_raw=[foreign_only], discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(calls[0]["reference_contexts"], [])
        # Researcher input carries no foreign-CVE text at all.
        blob = json.dumps(calls[0], default=str)
        self.assertNotIn(FOREIGN, blob)


class DecisionSafetyTests(unittest.TestCase):
    """Coverage 10/11/14: empty/partial context cannot promote decisions."""

    @_guarded
    def test_10_empty_references_do_not_increase_confidence(self) -> None:
        # Even a stub claiming candidacy with empty evidence cannot beat
        # the conservative decision: no reliable HTTP signature exists.
        claimed = _research_result(
            nuclei_candidate=True,
            nuclei_reason="stub-claimed",
            detection_ideas=[],
            evidence=[],
            summary="offline fixture summary with no HTTP method.",
            root_cause=None,
        )
        decision = _lane_decision(claimed)
        self.assertEqual(decision.decision, "NOT_APPLICABLE")
        self.assertFalse(decision.http_detectable)
        # Removing references (full -> empty) never strengthens the lane.
        full_lane = _lane_candidate(claimed)
        self.assertFalse(full_lane)

    @_guarded
    def test_11_empty_references_do_not_create_candidate(self) -> None:
        payload, calls = _run_single(
            CVE, contexts_raw=[], discovered_urls=[],
            script=[_research_result(nuclei_candidate=False)],
        )
        self.assertEqual(calls[0]["reference_contexts"], [])
        research = _research_result(nuclei_candidate=False)
        self.assertFalse(_lane_candidate(research))
        self.assertFalse(payload["research"]["nuclei_candidate"])
        # Hostile stub: claims candidacy with nothing behind it.
        hostile = _research_result(
            nuclei_candidate=True, evidence=[], detection_ideas=[]
        )
        self.assertFalse(_lane_candidate(hostile))

    @_guarded
    def test_14_partial_rejection_remains_conservative(self) -> None:
        good = _ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, exact=_exact(FOREIGN), chunks=[_chunk(FOREIGN)])
        payload, calls = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_research_result()],
        )
        received = calls[0]["reference_contexts"]
        self.assertEqual([c.source_url for c in received], [URL_A])
        self.assertIn(CVE, received[0].exact_record or "")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})
        self.assertEqual(payload["research_status"], "completed")
        self.assertFalse(payload["research"]["nuclei_candidate"])


class FailSoftBoundaryTests(unittest.TestCase):
    """Coverage 15-18: retry/degraded preserve the boundary, no new calls."""

    @_guarded
    def test_15_429_retry_preserves_boundary(self) -> None:
        good = _ctx(URL_A, chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, chunks=[_chunk(FOREIGN)])
        payload, calls = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_err(429), _research_result()],
        )
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(
                [c.source_url for c in call["reference_contexts"]], [URL_A]
            )
            blob = json.dumps(call, default=str)
            self.assertNotIn("checked", blob)
            self.assertNotIn(FOREIGN, blob)
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_16_retry_exhaustion_preserves_boundary(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_err(429), _err(429)],
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})
        degraded = payload["research"]
        # Degraded claims nothing reference-backed: no candidacy, no
        # exploitability, no severity, no invented HTTP signature.
        self.assertFalse(degraded["nuclei_candidate"])
        self.assertIsNone(degraded["public_exploit"])
        self.assertIsNone(degraded["actively_exploited"])
        self.assertIsNone(degraded["severity"])
        self.assertEqual(degraded["bug_bounty_relevance"], 0)

    @_guarded
    def test_17_degraded_503_preserves_boundary(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_err(503)],
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})
        self.assertFalse(payload["research"]["nuclei_candidate"])

    @_guarded
    def test_18_degraded_network_preserves_boundary(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_net_err()],
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})
        self.assertFalse(payload["research"]["nuclei_candidate"])


class SkipLlmBoundaryTests(unittest.TestCase):
    """Coverage 19: skip-LLM preserves the boundary."""

    @_guarded
    def test_19_skip_llm_preserves_boundary(self) -> None:
        import ai.research_cli as cli_mod

        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        docs = [
            {
                "url": URL_A,
                "source_type": "vendor",
                "title": "t",
                "priority": 1,
                "tags": [],
                "content": "c",
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

        researcher_calls: list = []

        class _NoCallResearcher:
            def __init__(self, *a, **k):
                researcher_calls.append(1)

        with (
            patch.object(cli_mod, "_load_assets", return_value=([], None)),
            patch(
                "ai.collectors.cve.CVECollector.get_by_ids",
                return_value=[_cve_doc()],
            ),
            patch("ai.correlator.candidates.candidate_assets", return_value=[]),
            patch("ai.collectors.discovery.ReferenceDiscovery", _Discovery),
            patch(
                "ai.collectors.discovery_fetch.fetch_discovered_sources",
                return_value=docs,
            ),
            patch(
                "ai.researcher.research_context.build_research_contexts",
                return_value=raw,
            ),
            patch(
                "ai.researcher.researcher.SecurityResearcher", _NoCallResearcher
            ),
            patch.object(cli_mod, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
        ):
            payload = cli_mod._research_single_cve(CVE, skip_llm=True)
        self.assertEqual(researcher_calls, [])
        self.assertTrue(payload["research"]["skipped"])
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})
        self.assertNotIn("nuclei_candidate", json.dumps(payload["research"]))


class NoExecutionTests(unittest.TestCase):
    """Coverage 20: no network/subprocess/Nuclei/browser execution."""

    @_guarded
    def test_20_offline_only_no_live_state(self) -> None:
        # Guards are active (socket/subprocess raise); the offline
        # extractor + decision used above is pure computation.
        payload, _ = _run_single(
            CVE, contexts_raw=[_ctx(URL_A, chunks=[_chunk(CVE)])],
            discovered_urls=[URL_A],
            script=[_research_result()],
        )
        blob = json.dumps(payload).lower()
        for forbidden in (
            "sealedfinding",
            "confirmed",
            "live_http",
            "live_nuclei",
            "ready_for_scan",
        ):
            self.assertNotIn(forbidden, blob)
        self.assertFalse(payload["authoritative"])
        self.assertTrue(payload["research_only"])
        self.assertNotIn("5j", json.dumps(payload.get("provenance", {})).lower())
        # Nuclei decision engine never shells out: pure function with
        # guards armed (any subprocess use would have raised above).
        decision = _lane_decision(_research_result())
        self.assertEqual(decision.decision, "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
