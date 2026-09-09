"""Provenance-gated technical GitHub fallback (research-only).

Covers the narrowly-scoped ``ReferenceRanker`` fallback that retains
directly-discovered GitHub blob/commit/issues/pull evidence even when the
fetched page contains no CVE identifier, while repository roots and
boilerplate stay rejectable through the UNCHANGED Reference Quality Gate
(Rule 4).

Strictly offline: socket/subprocess blocked, no real
``ReferenceCollector`` HTTP, no Nuclei, no browser, no DNS, no Mongo,
no LLM.
"""

from __future__ import annotations

import socket
import subprocess
import unittest
from unittest.mock import patch

from ai.collectors.reference_ranker import ReferenceRanker
from ai.researcher.research_context import build_research_contexts
from ai.researcher.reference_quality import gate_reference_contexts

CVE = "CVE-2026-78203"
FOREIGN = "CVE-2026-99999"

BLOB_URL = (
    "https://github.com/GhostManager/Ghostwriter/blob/v7.1.1/"
    "ghostwriter/reporting/views.py#L275-L315"
)
COMMIT_URL = (
    "https://github.com/GhostManager/Ghostwriter/commit/"
    "5b2a4a297e44c823c16f65b1ba101c742791cd0b"
)
ISSUE_URL = "https://github.com/bentoml/BentoML/issues/5644"
PULL_URL = "https://github.com/bentoml/BentoML/pull/5650/files"
ROOT_URL = "https://github.com/GhostManager/Ghostwriter"

# Representative vulnerable-code content: no CVE identifier, no vendor
# or product word, so neither the narrative branch nor the keyword
# fallback can fire — only the head slice can retain it.
PURE_CODE = (
    "from django import views\n"
    "class ReportTemplateSwap:\n"
    "    def post(self, request):\n"
    "        key = request.POST.get('docx_template')\n"
    "        tpl = ReportTemplate.objects.get(pk=key)\n"
    "        report.template = tpl\n"
    "        report.save()\n"
)

# Content carrying a vendor keyword but no CVE identifier: the existing
# keyword-anchored fallback should win over the head slice.
VENDOR_CODE = (
    "Ghostwriter report template swap handler.\n"
    + PURE_CODE
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


def _doc(url, *, content, source_type="github", tags=None, query=None):
    doc = {
        "url": url,
        "source_type": source_type,
        "title": f"title {url}",
        "priority": 90,
        "tags": [],
        "content": content,
    }
    if tags is not None:
        doc["discovery_tags"] = tags
    if query is not None:
        doc["discovery_query"] = query
    return doc


def _nvd(url, *, content, source_type="github"):
    return _doc(
        url,
        content=content,
        source_type=source_type,
        tags=["nvd_reference", "github"],
        query=CVE,
    )


def _build(doc, cve_id=CVE):
    return build_research_contexts(
        documents=[doc],
        cve_id=cve_id,
        keywords=[cve_id, "GhostManager", "Ghostwriter"],
    )[0]


def _gate(entry, cve_id=CVE):
    return gate_reference_contexts(
        [entry], cve_id=cve_id, known_urls={entry["url"]}
    )


class TechnicalShapeTests(unittest.TestCase):
    @_guarded
    def test_nvd_blob_cve_less_code_retained(self) -> None:
        """A: NVD blob + CVE-less code => one bounded chunk, exact None."""
        entry = _build(_nvd(BLOB_URL, content=PURE_CODE))
        self.assertIsNone(entry["exact_record"])
        self.assertEqual(len(entry["context_chunks"]), 1)
        self.assertIn("ReportTemplateSwap", entry["context_chunks"][0])

    @_guarded
    def test_nvd_commit_cve_less_content_retained(self) -> None:
        """B: NVD commit + CVE-less content => kept."""
        entry = _build(
            _nvd(COMMIT_URL, content="diff --git a/x b/x\n+ check applied")
        )
        self.assertIsNone(entry["exact_record"])
        self.assertEqual(len(entry["context_chunks"]), 1)

    @_guarded
    def test_nvd_issue_cve_less_body_retained(self) -> None:
        """C: NVD issue + CVE-less body => kept."""
        entry = _build(
            _nvd(
                ISSUE_URL,
                content="PoC: send img=http://100.64.1.1/internal "
                "and observe ConnectTimeout",
                source_type="github_issue",
            )
        )
        self.assertEqual(len(entry["context_chunks"]), 1)

    @_guarded
    def test_nvd_pull_cve_less_content_retained(self) -> None:
        """D: NVD pull + CVE-less content => kept."""
        entry = _build(_nvd(PULL_URL, content="Files changed: guard added"))
        self.assertEqual(len(entry["context_chunks"]), 1)

    @_guarded
    def test_repository_root_not_eligible(self) -> None:
        """E: repository root => no fallback (still Rule 4 dropped)."""
        for url in (
            "https://github.com/GhostManager/Ghostwriter",
            "https://github.com/GhostManager/Ghostwriter/",
            "https://github.com/GhostManager",
        ):
            with self.subTest(url=url):
                entry = _build(_nvd(url, content=PURE_CODE))
                self.assertEqual(entry["context_chunks"], [])
                result = _gate(entry)
                self.assertEqual(result.contexts, [])
                self.assertTrue(result.rejected)

    @_guarded
    def test_non_technical_github_urls_not_eligible(self) -> None:
        """F: search/topics/profile URLs => no fallback."""
        for url in (
            "https://github.com/search?q=ghostwriter&type=repositories",
            "https://github.com/topics/vulnerability",
            "https://github.com/geo-chen",
            "https://github.com/GhostManager/Ghostwriter/tree/v7.1.1/docs",
            "https://github.com/GhostManager/Ghostwriter/security/advisories",
        ):
            with self.subTest(url=url):
                entry = _build(_nvd(url, content=PURE_CODE))
                self.assertEqual(entry["context_chunks"], [])

    @_guarded
    def test_repo_named_like_technical_segment_not_eligible(self) -> None:
        """Segment boundaries: a repo named 'blob-store' must not match."""
        entry = _build(
            _nvd(
                "https://github.com/example/blob-store",
                content=PURE_CODE,
            )
        )
        self.assertEqual(entry["context_chunks"], [])

    @_guarded
    def test_non_github_host_with_blob_not_eligible(self) -> None:
        """G: non-github host + /blob/ => no fallback."""
        for url in (
            "https://example.test/org/repo/blob/main/x.py",
            "https://raw.githubusercontent.com/o/r/main/x.py",
            "https://gist.github.com/user/abc123",
            "https://www.github.com/o/r/blob/main/x.py",
            "https://ghe.example.test/o/r/blob/main/x.py",
        ):
            with self.subTest(url=url):
                entry = _build(_nvd(url, content=PURE_CODE))
                self.assertEqual(entry["context_chunks"], [])

    @_guarded
    def test_malformed_url_no_exception_no_fallback(self) -> None:
        """H: malformed URL => [] without raising."""
        for url in ("http://[::1", "not a url at all", "", "   "):
            with self.subTest(url=url):
                ranker = ReferenceRanker()
                chunks = ranker._technical_github_fallback(
                    url=url,
                    source_type="github",
                    discovery_tags=["nvd_reference"],
                    discovery_query=CVE,
                    text=PURE_CODE,
                    cve_id=CVE,
                    keywords=[CVE],
                )
                self.assertEqual(chunks, [])

    @_guarded
    def test_non_github_source_type_not_eligible(self) -> None:
        """Only GitHub narrative types qualify (blog/research do not)."""
        for source_type in ("blog", "research", "other", "vendor", ""):
            with self.subTest(source_type=source_type):
                entry = _build(
                    _doc(
                        BLOB_URL,
                        content=PURE_CODE,
                        source_type=source_type,
                        tags=["nvd_reference", "github"],
                        query=CVE,
                    )
                )
                self.assertEqual(entry["context_chunks"], [])


class ProvenancePredicateTests(unittest.TestCase):
    @_guarded
    def test_missing_provenance_preserves_legacy_behavior(self) -> None:
        """I: absent provenance => empty, exactly as before the change."""
        entry = _build(_doc(BLOB_URL, content=PURE_CODE))
        self.assertEqual(entry["context_chunks"], [])
        self.assertIsNone(entry["exact_record"])
        result = _gate(entry)
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_query_mismatch_no_fallback(self) -> None:
        """J: NVD tag for ANOTHER CVE => no fallback."""
        entry = _build(
            _doc(
                BLOB_URL,
                content=PURE_CODE,
                tags=["nvd_reference", "github"],
                query="CVE-2026-00001",
            )
        )
        self.assertEqual(entry["context_chunks"], [])

    @_guarded
    def test_product_only_search_provenance_no_fallback(self) -> None:
        """K: product-only search tags (no CVE tag) => no fallback."""
        entry = _build(
            _doc(
                BLOB_URL,
                content=PURE_CODE,
                tags=["github", "product_in_title"],
                query=f'"{CVE}" "Ghostwriter"',
            )
        )
        # Query contains the CVE but no CVE-correlated tag: denied.
        self.assertEqual(entry["context_chunks"], [])

    @_guarded
    def test_search_provenance_with_current_cve_tag_allowed(self) -> None:
        """L: CVE-tagged search provenance => fallback allowed."""
        for tags in (
            ["github", "cve_in_title"],
            ["github", "cve_in_body", "product_in_title"],
            ["github", "cve_in_repo_name"],
        ):
            with self.subTest(tags=tags):
                entry = _build(
                    _doc(
                        BLOB_URL,
                        content=PURE_CODE,
                        tags=tags,
                        query=f'"{CVE}" "Ghostwriter"',
                    )
                )
                self.assertEqual(len(entry["context_chunks"]), 1)

    @_guarded
    def test_priority_confidence_signal_alone_insufficient(self) -> None:
        """Ranking is not trust: signal-only tags => no fallback."""
        entry = _build(
            _doc(
                BLOB_URL,
                content=PURE_CODE,
                tags=["github", "security_research_signal"],
                query=f'"{CVE}" "Ghostwriter"',
            )
        )
        self.assertEqual(entry["context_chunks"], [])

    @_guarded
    def test_query_matching_is_case_insensitive(self) -> None:
        entry = _build(
            _doc(
                BLOB_URL,
                content=PURE_CODE,
                tags=["NVD_Reference", "github"],
                query=f"  {CVE.lower()}  ",
            )
        )
        self.assertEqual(len(entry["context_chunks"]), 1)


class GateInteractionTests(unittest.TestCase):
    @_guarded
    def test_foreign_cve_only_slice_rejected_by_rule3(self) -> None:
        """M: fallback slice naming only a foreign CVE => Rule 3 drops it."""
        content = (
            f"Advisory text for {FOREIGN} in another product. "
            "Ghostwriter word present for the keyword window."
        )
        entry = _build(_nvd(BLOB_URL, content=content))
        # The fallback IS produced upstream (non-empty chunk) ...
        self.assertTrue(entry["context_chunks"])
        # ... but the unchanged gate rejects it through Rule 3.
        result = _gate(entry)
        self.assertEqual(result.contexts, [])
        self.assertTrue(result.rejected)

    @_guarded
    def test_zero_cve_source_code_kept_after_fallback(self) -> None:
        """N: zero-CVE slice => kept via existing tolerance."""
        entry = _build(_nvd(BLOB_URL, content=PURE_CODE))
        result = _gate(entry)
        self.assertEqual(len(result.contexts), 1)
        self.assertFalse(result.rejected)

    @_guarded
    def test_narrative_success_path_unchanged(self) -> None:
        """CVE-bearing GitHub bodies still use the narrative chunk."""
        body = (
            "Description of the flaw. Reproduction steps for "
            f"{CVE} with curl commands and expected output. Footer"
        )
        entry = _build(_nvd(ISSUE_URL, content=body))
        self.assertEqual(len(entry["context_chunks"]), 1)
        self.assertIn(CVE, entry["context_chunks"][0])
        result = _gate(entry)
        self.assertFalse(result.rejected)


class ContentGuaranteeTests(unittest.TestCase):
    @_guarded
    def test_keyword_anchored_fallback_preferred(self) -> None:
        """O: vendor keyword present => keyword window, not head slice."""
        entry = _build(_nvd(BLOB_URL, content=VENDOR_CODE))
        self.assertEqual(len(entry["context_chunks"]), 1)
        self.assertIn("Ghostwriter", entry["context_chunks"][0])

    @_guarded
    def test_head_fallback_bounded(self) -> None:
        """P: head slice bounded by FALLBACK_CONTEXT_SIZE."""
        big = "x = 1  # no keywords here\n" * 5000
        entry = _build(_nvd(BLOB_URL, content=big))
        self.assertEqual(len(entry["context_chunks"]), 1)
        self.assertLessEqual(
            len(entry["context_chunks"][0]),
            ReferenceRanker.FALLBACK_CONTEXT_SIZE,
        )

    @_guarded
    def test_deterministic_repeated_execution(self) -> None:
        """Q: same bytes => same slice."""
        first = _build(_nvd(BLOB_URL, content=PURE_CODE))
        second = _build(_nvd(BLOB_URL, content=PURE_CODE))
        self.assertEqual(
            first["context_chunks"], second["context_chunks"]
        )

    @_guarded
    def test_no_claims_injected(self) -> None:
        """R: fallback adds no CVE/severity/exploit text."""
        entry = _build(_nvd(BLOB_URL, content=PURE_CODE))
        chunk = entry["context_chunks"][0]
        self.assertNotIn("CVE-", chunk)
        lowered = chunk.lower()
        for forbidden in (
            "severity",
            "exploit",
            "remediation",
            "fixes cve",
            "authoritative",
            "trusted",
            "verified",
        ):
            self.assertNotIn(forbidden, lowered)

    @_guarded
    def test_original_url_title_preserved(self) -> None:
        """S: URL/title survive untouched for LLM provenance."""
        entry = _build(_nvd(BLOB_URL, content=PURE_CODE))
        self.assertEqual(entry["url"], BLOB_URL)
        self.assertEqual(entry["title"], f"title {BLOB_URL}")
        self.assertEqual(entry["source_type"], "github")

    @_guarded
    def test_reference_context_conversion(self) -> None:
        """T: kept entries still convert to ReferenceContext."""
        from ai.schemas.reference import ReferenceContext

        entry = _build(_nvd(BLOB_URL, content=PURE_CODE))
        result = _gate(entry)
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
        self.assertEqual(converted[0].source_url, BLOB_URL)
        self.assertIsNone(converted[0].exact_record)

    @_guarded
    def test_empty_content_still_empty(self) -> None:
        """Whitespace-only pages cannot produce a slice."""
        entry = _build(_nvd(BLOB_URL, content="   \n  "))
        self.assertEqual(entry["context_chunks"], [])


class ProvenanceForwardingTests(unittest.TestCase):
    @_guarded
    def test_provenance_forwarded_but_not_persisted(self) -> None:
        """discovery_tags/query reach the ranker, never the output dict."""
        entry = _build(_nvd(BLOB_URL, content=PURE_CODE))
        self.assertNotIn("discovery_tags", entry)
        self.assertNotIn("discovery_query", entry)
        self.assertEqual(
            set(entry.keys()),
            {
                "url",
                "source_type",
                "title",
                "priority",
                "exact_record",
                "context_chunks",
            },
        )

    @_guarded
    def test_fetch_layer_forwards_provenance(self) -> None:
        """fetch_discovered_sources emits the ephemeral keys."""
        from unittest.mock import patch as mock_patch

        from ai.collectors.discovery_fetch import fetch_discovered_sources
        from ai.schemas.discovery import DiscoveredSource, DiscoveryResult

        class _Doc:
            url = BLOB_URL
            title = None
            content = "body text"
            # Stage R13 provenance surface (mirrors ReferenceDocument).
            content_hash = "a" * 64
            raw_content_hash = "b" * 64
            extraction_format = "text/html"
            extraction_status = "ok"

        class _Collector:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def fetch(self, url):
                return _Doc()

        discovery = DiscoveryResult(
            cve_id=CVE,
            sources=[
                DiscoveredSource(
                    url=BLOB_URL,
                    source_type="github",
                    title="blob",
                    query=CVE,
                    priority=90,
                    confidence=0.95,
                    tags=["nvd_reference", "github"],
                )
            ],
        )
        with mock_patch(
            "ai.collectors.discovery_fetch.ReferenceCollector",
            return_value=_Collector(),
        ):
            docs = fetch_discovered_sources(discovery, limit=5)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["discovery_tags"], ["nvd_reference", "github"])
        self.assertEqual(docs[0]["discovery_query"], CVE)
        # Stage R13: extraction provenance is forwarded alongside the
        # legacy keys; ok-status documents pass the hard-miss filter.
        self.assertEqual(docs[0]["extraction_status"], "ok")
        self.assertEqual(docs[0]["content_hash"], "a" * 64)
        self.assertEqual(docs[0]["raw_content_hash"], "b" * 64)
        self.assertEqual(docs[0]["extraction_format"], "text/html")
        # ReferenceDocument.tags confusion guard: the ephemeral keys are
        # distinct names, and the output still carries the legacy key.
        self.assertIn("tags", docs[0])


if __name__ == "__main__":
    unittest.main()
