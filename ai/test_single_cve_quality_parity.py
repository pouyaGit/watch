"""Single-CVE / batch reference-quality parity tests (research-only).

Verifies that ``ai.research_cli._research_single_cve`` applies the SAME
deterministic ``gate_reference_contexts`` logic as the batch wrapper,
before ``SecurityResearcher`` receives context.

Strictly offline: socket/subprocess blocked, fake reference fetches,
no real ReferenceCollector HTTP, no Nuclei, no browser, no DNS.
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

CVE = "CVE-2026-9101"
URL_A = "https://example.test/parity-a"
URL_B = "https://example.test/parity-b"
URL_C = "https://example.test/parity-c"


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


def _research_result(cve_id=CVE):
    from ai.schemas.research import ResearchResult

    return ResearchResult(
        title="offline fixture",
        summary="offline fixture summary with no HTTP method.",
        severity="medium",
        cve_ids=[cve_id],
    )


def _run_single(cve_id, *, contexts_raw, discovered_urls, script, skip_llm=False):
    """Run _research_single_cve with fakes. Returns (payload, seen)."""
    import ai.research_cli as cli_mod

    seen: dict = {}
    calls: list = []

    class _CapturingResearcher:
        def research(self, **kwargs):
            calls.append(1)
            seen["contexts"] = list(kwargs.get("reference_contexts") or [])
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
            "ai.research_cli.fetch_discovered_sources"
            if hasattr(__import__("ai.research_cli", fromlist=["x"]), "fetch_discovered_sources")
            else "ai.collectors.discovery_fetch.fetch_discovered_sources",
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
        # Patch the fetch symbol at the module actually used by the CLI:
        # _research_single_cve imports fetch_discovered_sources from
        # ai.collectors.discovery_fetch at call time, so the patch above
        # on that path takes effect.
        payload = cli_mod._research_single_cve(cve_id, skip_llm=skip_llm)
    return payload, seen, calls


def _err(status: int) -> OpenRouterProviderError:
    return OpenRouterProviderError(f"OpenRouter returned HTTP {status}: x")


def _net_err() -> OpenRouterProviderError:
    return OpenRouterProviderError("OpenRouter connection error: x")


class BasicParityTests(unittest.TestCase):
    @_guarded
    def test_valid_context_passes(self) -> None:
        raw = [_ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])]
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(len(seen["contexts"]), 1)
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})
        self.assertEqual(payload["metadata"]["reference_context_count"], 1)

    @_guarded
    def test_foreign_context_rejected(self) -> None:
        good = _ctx(URL_A, exact=_exact(CVE), chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, exact=_exact("CVE-2026-9999"), chunks=[_chunk("CVE-2026-9999")])
        payload, seen, _ = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_research_result()],
        )
        self.assertEqual(
            [c.source_url for c in seen["contexts"]], [URL_A]
        )
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_all_invalid_continues_with_empty(self) -> None:
        bad = _ctx(URL_A, chunks=[_chunk("CVE-2026-9999")])
        payload, seen, _ = _run_single(
            CVE, contexts_raw=[bad], discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(seen["contexts"], [])
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})
        self.assertEqual(payload["metadata"]["reference_context_count"], 0)

    @_guarded
    def test_ordering_preserved(self) -> None:
        urls = [URL_A, URL_B, URL_C]
        raw = [_ctx(u, chunks=[f"note {u}"]) for u in urls]
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=urls,
            script=[_research_result()],
        )
        self.assertEqual([c.source_url for c in seen["contexts"]], urls)
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_exact_record_for_another_cve_rejected(self) -> None:
        raw = [_ctx(URL_A, exact=_exact("CVE-2026-9999"), chunks=[_chunk("CVE-2026-9999")])]
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(seen["contexts"], [])
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})


class SourceIntegrityTests(unittest.TestCase):
    @_guarded
    def test_unknown_url_rejected(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_B],
            script=[_research_result()],
        )
        self.assertEqual(seen["contexts"], [])
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_empty_content_rejected(self) -> None:
        raw = [_ctx(URL_A, exact=None, chunks=[])]
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(seen["contexts"], [])
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_malformed_context_safely_handled(self) -> None:
        raw = ["not-a-dict", None, 42]
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual(seen["contexts"], [])
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})


class DedupTests(unittest.TestCase):
    @_guarded
    def test_duplicate_collapsed(self) -> None:
        first = _ctx(URL_A, chunks=[_chunk(CVE)])
        second = _ctx(URL_A, chunks=[_chunk(CVE)])
        payload, seen, _ = _run_single(
            CVE, contexts_raw=[first, second], discovered_urls=[URL_A],
            script=[_research_result()],
        )
        self.assertEqual([c.source_url for c in seen["contexts"]], [URL_A])
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})

    @_guarded
    def test_canonical_duplicates_merge(self) -> None:
        u1 = "https://x.test/a?id=1&utm_source=a#one"
        u2 = "https://x.test/a?id=1&utm_source=b#two"
        first = _ctx(u1, chunks=[_chunk(CVE)])
        second = _ctx(u2, chunks=[_chunk(CVE)])
        payload, seen, _ = _run_single(
            CVE, contexts_raw=[first, second], discovered_urls=[u1, u2],
            script=[_research_result()],
        )
        self.assertEqual(len(seen["contexts"]), 1)
        self.assertEqual(seen["contexts"][0].source_url, u1)
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})


class LlmBoundaryTests(unittest.TestCase):
    @_guarded
    def test_researcher_receives_gated_context(self) -> None:
        good = _ctx(URL_A, chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, chunks=[_chunk("CVE-2026-9999")])
        _, seen, _ = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_research_result()],
        )
        self.assertEqual([c.source_url for c in seen["contexts"]], [URL_A])

    @_guarded
    def test_gate_executes_before_researcher(self) -> None:
        import ai.research_cli as cli_mod
        import ai.researcher.reference_quality as gate_mod

        order: list[str] = []
        real_gate = gate_mod.gate_reference_contexts

        def _spying_gate(*args, **kwargs):
            order.append("gate")
            return real_gate(*args, **kwargs)

        class _OrderResearcher:
            def research(self, **kwargs):
                order.append("research")
                return _research_result()

        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        docs = [{"url": URL_A, "source_type": "v", "title": "t",
                 "priority": 1, "tags": [], "content": "c"}]

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
            patch("ai.collectors.cve.CVECollector.get_by_ids",
                  return_value=[_cve_doc()]),
            patch("ai.correlator.candidates.candidate_assets", return_value=[]),
            patch("ai.collectors.discovery.ReferenceDiscovery", _Discovery),
            patch("ai.collectors.discovery_fetch.fetch_discovered_sources",
                  return_value=docs),
            patch("ai.researcher.research_context.build_research_contexts",
                  return_value=raw),
            patch("ai.researcher.reference_quality.gate_reference_contexts",
                  side_effect=_spying_gate),
            patch("ai.research_cli.gate_reference_contexts"
                  if hasattr(cli_mod, "gate_reference_contexts") else
                  "ai.researcher.reference_quality.gate_reference_contexts",
                  side_effect=_spying_gate),
            patch("ai.researcher.researcher.SecurityResearcher", _OrderResearcher),
            patch.object(cli_mod, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
        ):
            # The CLI imports the gate inside the function from
            # ai.researcher.reference_quality, so patch that target.
            with patch(
                "ai.researcher.reference_quality.gate_reference_contexts",
                side_effect=_spying_gate,
            ):
                cli_mod._research_single_cve(CVE)
        # At least one gate call happened before research.
        self.assertIn("gate", order)
        self.assertIn("research", order)
        self.assertLess(order.index("gate"), order.index("research"))

    @_guarded
    def test_gate_has_no_network_surface(self) -> None:
        import ast

        import ai.researcher.reference_quality as gate_module

        tree = ast.parse(Path(gate_module.__file__).read_text(encoding="utf-8"))
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        for forbidden in ("socket", "subprocess", "httpx", "requests",
                          "urllib", "openrouter"):
            self.assertFalse(
                any(p == forbidden or p.startswith(forbidden + ".") for p in imports),
                forbidden,
            )


class FailSoftTests(unittest.TestCase):
    @_guarded
    def test_429_retry_success_preserves_quality(self) -> None:
        good = _ctx(URL_A, chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, chunks=[_chunk("CVE-2026-9999")])
        payload, seen, calls = _run_single(
            CVE, contexts_raw=[good, bad], discovered_urls=[URL_A, URL_B],
            script=[_err(429), _research_result()],
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 1})
        self.assertEqual([c.source_url for c in seen["contexts"]], [URL_A])

    @_guarded
    def test_429_429_preserves_quality(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, _, calls = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_err(429), _err(429)],
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_503_preserves_quality(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, _, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_err(503)],
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})

    @_guarded
    def test_network_preserves_quality(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, _, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_net_err()],
        )
        self.assertEqual(payload["research_status"], "completed_degraded")
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})


class SkipTests(unittest.TestCase):
    @_guarded
    def test_skip_llm_unchanged_with_quality_present(self) -> None:
        import ai.research_cli as cli_mod

        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        docs = [{"url": URL_A, "source_type": "v", "title": "t",
                 "priority": 1, "tags": [], "content": "c"}]

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
            patch("ai.collectors.cve.CVECollector.get_by_ids",
                  return_value=[_cve_doc()]),
            patch("ai.correlator.candidates.candidate_assets", return_value=[]),
            patch("ai.collectors.discovery.ReferenceDiscovery", _Discovery),
            patch("ai.collectors.discovery_fetch.fetch_discovered_sources",
                  return_value=docs),
            patch("ai.researcher.research_context.build_research_contexts",
                  return_value=raw),
            patch("ai.researcher.researcher.SecurityResearcher", _NoCallResearcher),
            patch.object(cli_mod, "RESEARCH_DIR", Path(tempfile.mkdtemp())),
        ):
            payload = cli_mod._research_single_cve(CVE, skip_llm=True)
        self.assertTrue(payload["research"]["skipped"])
        self.assertEqual(payload["llm_status"], "skipped")
        self.assertEqual(payload["research_status"], "completed")
        self.assertEqual(researcher_calls, [])
        # Gate runs on the already-built contexts (no extra reference
        # or LLM work introduced); quality outcome is exposed.
        self.assertEqual(payload["reference_quality"], {"checked": 1, "rejected": 0})


class SignatureTests(unittest.TestCase):
    def test_signature_preserved(self) -> None:
        import ai.research_cli as cli_mod

        self.assertEqual(
            list(inspect.signature(cli_mod._research_single_cve).parameters),
            ["cve_id", "skip_llm"],
        )


class GateParityTests(unittest.TestCase):
    @_guarded
    def test_same_contexts_batch_and_single_agree(self) -> None:
        from ai.researcher.reference_quality import gate_reference_contexts

        good = _ctx(URL_A, chunks=[_chunk(CVE)])
        bad = _ctx(URL_B, chunks=[_chunk("CVE-2026-9999")])
        dup = _ctx(URL_A, chunks=[_chunk(CVE)])
        raw = [good, bad, dup]
        known = {URL_A, URL_B}
        direct = gate_reference_contexts(raw, cve_id=CVE, known_urls=known)
        payload, seen, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A, URL_B],
            script=[_research_result()],
        )
        self.assertEqual(
            [c.source_url for c in seen["contexts"]],
            [c["url"] for c in direct.contexts],
        )
        self.assertEqual(
            payload["reference_quality"]["rejected"], int(direct.rejected)
        )


class TelemetryTests(unittest.TestCase):
    @_guarded
    def test_telemetry_shape_and_secrecy(self) -> None:
        raw = [_ctx(URL_A, chunks=[_chunk(CVE)])]
        payload, _, _ = _run_single(
            CVE, contexts_raw=raw, discovered_urls=[URL_A],
            script=[_research_result()],
        )
        quality = payload["reference_quality"]
        self.assertEqual(set(quality.keys()), {"checked", "rejected"})
        self.assertEqual(quality, {"checked": 1, "rejected": 0})
        blob = json.dumps(quality)
        self.assertNotIn(URL_A, blob)
        self.assertNotIn(CVE, blob)
        self.assertNotIn("sk-or", blob.lower())
        full = json.dumps(payload).lower()
        for forbidden in ("sealedfinding", "confirmed", "live_http",
                          "live_nuclei", "ready_for_scan"):
            self.assertNotIn(forbidden, full)


if __name__ == "__main__":
    unittest.main()
