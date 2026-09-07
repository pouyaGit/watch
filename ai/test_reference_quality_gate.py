"""Focused offline tests for the reference-context quality gate.

Covers the research-only deterministic gate around the EXISTING
per-CVE ``ReferenceContext`` construction (existing
``build_research_contexts`` / ``ReferenceRanker`` pipeline reused,
ranking algorithm untouched):

- Identity: valid CVE context passes; another-CVE context is
  rejected; malformed/missing identity handled safely.
- Source integrity: known-URL documents pass; synthetic URLs,
  empty URLs, and empty content rejected; no hash algorithm
  invented (existing schema carries none — documented).
- Dedup: same-URL duplicates collapse to one entry (frozen
  canonical key); distinct references stay distinct; original
  source URLs unaltered.
- Cross-CVE isolation: shared ReferenceDocument reused; contexts
  remain CVE-specific; A-scoped material gated as B is dropped.
- Ranking: order and scores preserved; gate never reorders and
  never mutates entries.
- Failure: all-invalid becomes empty; no fabrication, no nuclei
  promotion, no authoritative state.
- LLM boundary: gate is deterministic with socket/subprocess
  blocked; gated contexts reach SecurityResearcher; gate itself
  never touches LLM/network/subprocess.
- Telemetry: zeroed aggregate, exact checked/rejected counts, no
  URLs/CVE IDs/secrets.

Strictly offline: socket/subprocess blocked, no real
``ReferenceCollector`` HTTP, no Nuclei, no browser, no DNS.
"""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.researcher.reference_quality import (
    empty_reference_quality_histogram,
    gate_reference_contexts,
)

CVE_A = "CVE-2026-8001"
CVE_B = "CVE-2026-8002"
URL_A = "https://example.test/advisory-a"
URL_B = "https://example.test/advisory-b"


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


def _ctx(url, *, exact=None, chunks=None, source_type="github", title=None):
    return {
        "url": url,
        "source_type": source_type,
        "title": title or f"title {url}",
        "priority": 90,
        "exact_record": exact,
        "context_chunks": list(chunks) if chunks is not None else [],
    }


def _vendor_exact(cve_id, suffix="buffer overflow in product"):
    return f"{cve_id} {suffix} fixed in version 2."


def _narrative_chunk(cve_id, body="issue body describes reproduction"):
    return f"{body} for {cve_id} with details."


class IdentityTests(unittest.TestCase):
    @_guarded
    def test_valid_cve_context_passes(self) -> None:
        entry = _ctx(
            URL_A,
            exact=_vendor_exact(CVE_A),
            chunks=[_vendor_exact(CVE_A)],
        )
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [entry])
        self.assertFalse(result.rejected)

    @_guarded
    def test_narrative_chunk_for_current_cve_passes(self) -> None:
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [entry])
        self.assertFalse(result.rejected)

    @_guarded
    def test_exact_record_for_another_cve_rejected(self) -> None:
        entry = _ctx(
            URL_A,
            exact=_vendor_exact(CVE_B),
            chunks=[_vendor_exact(CVE_B)],
        )
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_chunks_for_another_cve_rejected(self) -> None:
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_B)])
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_malformed_and_missing_identity_safe(self) -> None:
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        for bad_cve in ("", "   ", None):
            with self.subTest(cve=bad_cve):
                result = gate_reference_contexts(
                    [entry], cve_id=bad_cve, known_urls={URL_A}
                )
                self.assertEqual(result.contexts, [])
                self.assertTrue(result.rejected)
        # Empty input with missing identity stays empty, no crash.
        result = gate_reference_contexts([], cve_id=None)
        self.assertEqual(result.contexts, [])
        self.assertFalse(result.rejected)

    @_guarded
    def test_non_list_and_non_dict_input_safe(self) -> None:
        result = gate_reference_contexts(None, cve_id=CVE_A)
        self.assertEqual(result.contexts, [])
        self.assertFalse(result.rejected)
        result = gate_reference_contexts(
            ["not-a-dict", None, 42], cve_id=CVE_A
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)


class SourceIntegrityTests(unittest.TestCase):
    @_guarded
    def test_unknown_url_rejected(self) -> None:
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_B}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_no_known_urls_means_no_url_filter(self) -> None:
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        result = gate_reference_contexts([entry], cve_id=CVE_A)
        self.assertEqual(result.contexts, [entry])
        self.assertFalse(result.rejected)

    @_guarded
    def test_empty_url_rejected(self) -> None:
        for bad_url in ("", "   ", None, 123):
            with self.subTest(url=bad_url):
                entry = dict(
                    _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
                )
                entry["url"] = bad_url
                result = gate_reference_contexts([entry], cve_id=CVE_A)
                self.assertEqual(result.contexts, [])
                self.assertTrue(result.rejected)

    @_guarded
    def test_empty_content_rejected(self) -> None:
        entry = _ctx(URL_A, exact=None, chunks=[])
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)
        blank = _ctx(URL_A, exact=None, chunks=["", "   "])
        result = gate_reference_contexts(
            [blank], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_no_hash_algorithm_invented(self) -> None:
        """Existing ReferenceContext schema carries no hash/content.

        The gate must not invent hash validation: an entry with no
        hash fields passes on identity/source/content rules, and
        kept entries are byte-identical objects (nothing rewritten).
        """
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        self.assertNotIn("content_hash", entry)
        self.assertNotIn("content", entry)
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertIs(result.contexts[0], entry)

    @_guarded
    def test_non_list_chunks_rejected(self) -> None:
        entry = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        entry["context_chunks"] = "not-a-list"
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)


class DedupTests(unittest.TestCase):
    @_guarded
    def test_duplicate_same_url_collapses(self) -> None:
        first = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        second = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        result = gate_reference_contexts(
            [first, second], cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [first])
        self.assertIs(result.contexts[0], first)
        self.assertTrue(result.rejected)

    @_guarded
    def test_canonical_duplicates_merge_without_url_rewrite(self) -> None:
        """Frozen cache-key canonicalization dedups; source URL kept."""
        first = _ctx(
            "https://x.test/a?id=1&utm_source=a#one",
            chunks=[_narrative_chunk(CVE_A)],
        )
        second = _ctx(
            "https://x.test/a?id=1&utm_source=b#two",
            chunks=[_narrative_chunk(CVE_A)],
        )
        known = {first["url"], second["url"]}
        result = gate_reference_contexts(
            [first, second], cve_id=CVE_A, known_urls=known
        )
        self.assertEqual(len(result.contexts), 1)
        self.assertEqual(
            result.contexts[0]["url"],
            "https://x.test/a?id=1&utm_source=a#one",
        )
        self.assertTrue(result.rejected)

    @_guarded
    def test_different_references_remain_distinct(self) -> None:
        first = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        second = _ctx(URL_B, chunks=[_narrative_chunk(CVE_A)])
        result = gate_reference_contexts(
            [first, second], cve_id=CVE_A, known_urls={URL_A, URL_B}
        )
        self.assertEqual(result.contexts, [first, second])
        self.assertFalse(result.rejected)


class CrossCveTests(unittest.TestCase):
    @_guarded
    def test_shared_document_reused_but_contexts_isolated(self) -> None:
        """Same ReferenceDocument for A and B; gate scopes per CVE."""
        from ai.researcher.research_context import build_research_contexts

        shared_url = "https://example.test/shared"
        content = (
            f"Advisory text for {CVE_A} describing the flaw. "
            f"Separately, {CVE_B} is a different flaw in another product."
        )
        documents = [
            {
                "url": shared_url,
                "source_type": "vendor",
                "title": "shared advisory",
                "priority": 100,
                "tags": [],
                "content": content,
            }
        ]
        raw_a = build_research_contexts(
            documents=documents, cve_id=CVE_A, keywords=[CVE_A]
        )
        raw_b = build_research_contexts(
            documents=documents, cve_id=CVE_B, keywords=[CVE_B]
        )
        # Both CVEs independently build material from the shared doc.
        self.assertTrue(raw_a)
        self.assertTrue(raw_b)
        gated_a = gate_reference_contexts(
            raw_a, cve_id=CVE_A, known_urls={shared_url}
        )
        gated_b = gate_reference_contexts(
            raw_b, cve_id=CVE_B, known_urls={shared_url}
        )
        self.assertTrue(gated_a.contexts)
        self.assertTrue(gated_b.contexts)
        self.assertIn(CVE_A, json.dumps(gated_a.contexts))
        self.assertNotIn(CVE_B, json.dumps(gated_a.contexts))
        self.assertIn(CVE_B, json.dumps(gated_b.contexts))
        self.assertNotIn(CVE_A, json.dumps(gated_b.contexts))

    @_guarded
    def test_a_context_cannot_appear_in_b_via_shared_url(self) -> None:
        gated_as_b = gate_reference_contexts(
            [_ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])],
            cve_id=CVE_B,
            known_urls={URL_A},
        )
        self.assertEqual(gated_as_b.contexts, [])
        self.assertTrue(gated_as_b.rejected)


class RankingTests(unittest.TestCase):
    @_guarded
    def test_order_and_scores_preserved(self) -> None:
        entries = [
            _ctx(f"https://example.test/r{i}", chunks=[f"note {i}"])
            for i in range(4)
        ]
        for i, entry in enumerate(entries):
            entry["priority"] = 100 - i * 10
        known = {entry["url"] for entry in entries}
        before = [dict(entry) for entry in entries]
        result = gate_reference_contexts(
            entries, cve_id=CVE_A, known_urls=known
        )
        self.assertFalse(result.rejected)
        self.assertEqual(
            [entry["url"] for entry in result.contexts],
            [entry["url"] for entry in entries],
        )
        self.assertEqual(
            [entry["priority"] for entry in result.contexts],
            [100, 90, 80, 70],
        )
        for kept, original in zip(result.contexts, before):
            self.assertEqual(kept, original)
            self.assertIs(kept, entries[before.index(original)])

    @_guarded
    def test_partial_removal_keeps_relative_order(self) -> None:
        good_first = _ctx(URL_A, chunks=[_narrative_chunk(CVE_A)])
        bad = _ctx(URL_B, chunks=[_narrative_chunk(CVE_B)])
        good_last = _ctx(
            "https://example.test/c", chunks=[_narrative_chunk(CVE_A)]
        )
        known = {good_first["url"], bad["url"], good_last["url"]}
        result = gate_reference_contexts(
            [good_first, bad, good_last], cve_id=CVE_A, known_urls=known
        )
        self.assertEqual(result.contexts, [good_first, good_last])
        self.assertTrue(result.rejected)


class FailureBehaviorTests(unittest.TestCase):
    @_guarded
    def test_all_invalid_becomes_empty_without_fabrication(self) -> None:
        entries = [
            _ctx(URL_A, chunks=[_narrative_chunk(CVE_B)]),
            _ctx("https://example.test/unknown", chunks=["unscoped"]),
        ]
        result = gate_reference_contexts(
            entries, cve_id=CVE_A, known_urls={URL_A}
        )
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_empty_result_carries_no_claims(self) -> None:
        result = gate_reference_contexts(
            [_ctx(URL_A, chunks=[])], cve_id=CVE_A, known_urls={URL_A}
        )
        blob = json.dumps(result.contexts)
        for forbidden in (
            "exploit",
            "severity",
            "CONFIRMED",
            "authoritative",
            "nuclei",
            "payload",
        ):
            self.assertNotIn(forbidden, blob)


class LlmBoundaryTests(unittest.TestCase):
    @_guarded
    def test_gate_output_feeds_researcher_schema(self) -> None:
        """Gated dicts convert cleanly to ReferenceContext (LLM input)."""
        from ai.schemas.reference import ReferenceContext

        entry = _ctx(
            URL_A,
            exact=_vendor_exact(CVE_A),
            chunks=[_vendor_exact(CVE_A)],
        )
        result = gate_reference_contexts(
            [entry], cve_id=CVE_A, known_urls={URL_A}
        )
        converted = [
            ReferenceContext(
                source_url=item["url"],
                source_type=item["source_type"],
                title=item.get("title"),
                exact_record=item.get("exact_record"),
                context_chunks=item.get("context_chunks", []),
            )
            for item in result.contexts
        ]
        self.assertEqual(len(converted), 1)
        self.assertEqual(converted[0].source_url, URL_A)
        self.assertIn(CVE_A, converted[0].exact_record or "")

    @_guarded
    def test_gate_module_has_no_network_or_llm_surface(self) -> None:
        """AST check: gate code has no network/LLM/subprocess surface.

        (Docstring prose may name these concepts to forbid them;
        this check inspects actual imports and calls instead.)
        """
        import ast

        import ai.researcher.reference_quality as gate_module

        tree = ast.parse(
            Path(gate_module.__file__).read_text(encoding="utf-8")
        )
        imports: list[str] = []
        calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    calls.append(func.id)
                elif isinstance(func, ast.Attribute):
                    calls.append(func.attr)
        for forbidden in (
            "socket",
            "subprocess",
            "httpx",
            "requests",
            "urllib",
            "openrouter",
        ):
            self.assertFalse(
                any(
                    part == forbidden or part.startswith(forbidden + ".")
                    for part in imports
                ),
                f"forbidden import surface: {forbidden}",
            )
        for forbidden_call in (
            "generate",
            "SealedFinding",
            "Popen",
            "create_connection",
        ):
            self.assertNotIn(forbidden_call, calls)


class BatchTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmp = Path(self._tmpdir.name)

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

    def _run(self, research_fn, cve_ids, **kwargs):
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

    def test_zeroed_histogram_schema(self) -> None:
        self.assertEqual(
            empty_reference_quality_histogram(),
            {"checked": 0, "rejected": 0},
        )

    def test_custom_flow_reports_zeroed_quality(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return self._ok_payload(cve_id)

        aggregate = self._run(fn, ["CVE-2026-8101"])
        self.assertEqual(
            aggregate["reference_quality"], {"checked": 0, "rejected": 0}
        )

    def test_default_flow_counts_checked_and_rejected(self) -> None:
        """Default wrapper gates each CVE; mixed batch tallies exactly."""
        from ai.researcher.reference_cache import BatchReferenceCache

        shared_url = "https://example.test/q-shared"
        bodies = {
            # Mentions CVE-2026-8102 only: valid for it, foreign for
            # CVE-2026-8103 (whose discovery also yields this URL).
            shared_url: (
                "Vendor advisory for CVE-2026-8102 describing the flaw "
                "in detail with remediation guidance."
            ),
        }

        def fetch_fn(url: str):
            from ai.schemas.reference import ReferenceDocument

            body = bodies.get(url)
            if body is None:
                return None
            return ReferenceDocument(
                url=url,
                source_type="vendor",
                title=f"title {url}",
                content=body,
                status_code=200,
                content_hash="h-q",
                tags=[],
            )

        cache = BatchReferenceCache(fetch_fn=fetch_fn)

        class _Cve:
            def __init__(self, title):
                self.title = title
                self.vendor = []
                self.products = []
                self.references = [shared_url]
                self.cvss_score = None
                self.cvss_vector = None

        cves = {
            "CVE-2026-8102": _Cve("CVE-2026-8102"),
            "CVE-2026-8103": _Cve("CVE-2026-8103"),
        }

        class _Collector:
            def get_by_ids(self, ids):
                return [cves[i] for i in ids if i in cves]

        class _Discovery:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
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
                            url=shared_url,
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
            def __init__(self, *args, **kwargs):
                pass

            def research(self, **kwargs):
                contexts = kwargs.get("reference_contexts") or []
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
                        "references": [
                            c.source_url for c in contexts
                        ],
                        "evidence": [],
                    }
                )

        # Patch at the import sites used inside the wrapper.
        import ai.research_cli as cli_module
        import ai.collectors.discovery as discovery_module
        import ai.researcher.researcher as researcher_module
        from ai.correlator import candidates as candidates_module

        with (
            patch.object(cli_module, "_load_assets", lambda: ([], {})),
            patch.object(
                discovery_module, "ReferenceDiscovery", _Discovery
            ),
            patch("ai.collectors.cve.CVECollector", _Collector),
            patch.object(researcher_module, "SecurityResearcher", _Researcher),
            patch.object(
                candidates_module, "candidate_assets", lambda cve, index: []
            ),
        ):
            aggregate = self._run(
                None,
                ["CVE-2026-8102", "CVE-2026-8103"],
                reference_cache=cache,
            )
        # Both CVEs gated; the second CVE's contexts reference only
        # the first CVE, so exactly one rejection is tallied.
        self.assertEqual(
            aggregate["reference_quality"], {"checked": 2, "rejected": 1}
        )
        statuses = {
            item["cve"]: item["research_status"]
            for item in aggregate["results"]
        }
        self.assertEqual(
            statuses,
            {"CVE-2026-8102": "completed", "CVE-2026-8103": "completed"},
        )
        for item in aggregate["results"]:
            self.assertFalse(item["nuclei_candidate"])
            self.assertFalse(item["authoritative"])
        blob = json.dumps(aggregate).lower()
        self.assertNotIn(shared_url.split("//", 1)[1], blob)
        report = Path(aggregate["artifacts"]["report"]).read_text(
            encoding="utf-8"
        )
        self.assertIn("reference_quality", report)
        self.assertIn("checked=2", report)
        self.assertIn("rejected=1", report)

    def test_telemetry_has_no_urls_or_ids(self) -> None:
        def fn(cve_id: str, skip_llm: bool = False) -> dict:
            return self._ok_payload(cve_id)

        aggregate = self._run(fn, ["CVE-2026-8104", "CVE-2026-8105"])
        quality = aggregate["reference_quality"]
        self.assertEqual(set(quality.keys()), {"checked", "rejected"})
        self.assertTrue(
            all(isinstance(value, int) for value in quality.values())
        )
        # Counts only: the quality histogram carries no URLs, no
        # CVE IDs, no contents, no error payloads (two ints only).
        self.assertEqual(
            json.loads(json.dumps(quality)), {"checked": 0, "rejected": 0}
        )
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


if __name__ == "__main__":
    unittest.main()
