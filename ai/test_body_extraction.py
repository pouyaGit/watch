"""Stage R13 tests: bounded body extraction + reference provenance."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.collectors import body_extraction as be
from ai.collectors.discovery_fetch import fetch_discovered_sources
from ai.schemas.discovery import DiscoveredSource, DiscoveryResult
from ai.schemas.reference import ReferenceDocument


class _FakeCollector:
    """Scripted stand-in for ReferenceCollector (no network)."""

    def __init__(self, docs):
        self._docs = list(docs)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def fetch(self, url):
        return self._docs.pop(0) if self._docs else None

    def close(self):
        pass


def _discovery(urls):
    return DiscoveryResult(
        cve_id="CVE-2024-5376",
        sources=[
            DiscoveredSource(
                url=url,
                source_type="github",
                title="t",
                query="q",
                priority=90,
                confidence=0.9,
                tags=[],
            )
            for url in urls
        ],
    )


class BodyExtractionTests(unittest.TestCase):
    def test_html_skips_script_style_and_captures_title(self):
        html = (
            b"<html><head><title>CVE Report</title>"
            b"<script>alert(1)</script><style>a{}</style></head>"
            b"<body><h1>Heading</h1><p>Body text</p>"
            b"<script>evil()</script></body></html>"
        )
        result = be.extract_html(html)
        self.assertEqual(result.extraction_status, "ok")
        self.assertEqual(result.extraction_format, "text/html")
        # Title is extracted separately by the collector path.
        parser = be.HTMLTextExtractor()
        parser.feed(html.decode("utf-8"))
        self.assertEqual(parser.title, "CVE Report")
        self.assertNotIn("alert", result.text)
        self.assertNotIn("evil", result.text)
        self.assertIn("Heading", result.text)

    def test_markdown_strips_formatting(self):
        result = be.extract_markdown(b"# Title\n**bold** and *italic*")
        self.assertEqual(result.extraction_status, "ok")
        self.assertNotIn("**", result.text)
        self.assertIn("bold", result.text)

    def test_plain_text_normalizes(self):
        result = be.extract_plain_text(b"  a   b\n\n\nc  ")
        self.assertEqual(result.text, "a b\n\nc")
        self.assertEqual(result.extraction_status, "ok")

    def test_hash_stability_and_match(self):
        a = be.extract_html(b"<p>same</p>")
        b = be.extract_html(b"<p>same</p>")
        self.assertEqual(a.content_hash, b.content_hash)
        self.assertEqual(
            a.content_hash,
            be.sha256_text(be.normalize_text("same")),
        )

    def test_malformed_pdf_fails_soft(self):
        result = be.extract_pdf(b"%PDF-1.4 not really a pdf")
        self.assertEqual(result.extraction_status, "failed")
        self.assertIsNone(result.content_hash)
        self.assertEqual(result.text, "")

    def test_binary_rejected_by_sniffer(self):
        self.assertIsNone(
            be.sniff_content_type("", "http://x/a.bin", b"\x00\x01\x02bin")
        )

    def test_pdf_magic_wins_over_header(self):
        self.assertEqual(
            be.sniff_content_type(
                "text/html", "http://x/a.html", b"%PDF-1.7 ..."
            ),
            "application/pdf",
        )

    def test_dispatcher_unsupported_format(self):
        result = be.extract_body(b"x", None)
        self.assertEqual(result.extraction_status, "failed")


class DiscoveryFetchHardMissTests(unittest.TestCase):
    def test_failed_extraction_is_hard_miss(self):
        failed = ReferenceDocument(
            url="http://x/a",
            source_type="github",
            content="",
            content_hash=None,
            raw_content_hash="c" * 64,
            extraction_format="application/pdf",
            extraction_status="failed",
        )
        with patch(
            "ai.collectors.discovery_fetch.ReferenceCollector",
            return_value=_FakeCollector([failed]),
        ):
            docs = fetch_discovered_sources(_discovery(["http://x/a"]))
        self.assertEqual(docs, [])

    def test_ok_extraction_passes_with_provenance(self):
        ok = ReferenceDocument(
            url="http://x/a",
            source_type="github",
            title="T",
            content="body",
            content_hash="a" * 64,
            raw_content_hash="b" * 64,
            extraction_format="text/html",
            extraction_status="ok",
        )
        with patch(
            "ai.collectors.discovery_fetch.ReferenceCollector",
            return_value=_FakeCollector([ok]),
        ):
            docs = fetch_discovered_sources(_discovery(["http://x/a"]))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["content_hash"], "a" * 64)
        self.assertEqual(docs[0]["extraction_status"], "ok")


class ArchiveBodyTests(unittest.TestCase):
    def test_write_reference_archive_carries_body(self):
        import ai.research_cli as cli
        from ai.schemas.reference import ReferenceContext

        contexts = [
            ReferenceContext(
                source_url="http://x/a",
                source_type="github",
                title="T",
                exact_record=None,
                context_chunks=["chunk"],
            )
        ]
        documents = [
            {
                "url": "http://x/a",
                "source_type": "github",
                "title": "T",
                "content": "extracted body",
                "content_hash": "a" * 64,
                "raw_content_hash": "b" * 64,
                "extraction_format": "text/html",
                "extraction_status": "ok",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            original = cli.RESEARCH_DIR
            cli.RESEARCH_DIR = Path(tmp)
            try:
                path = cli.write_reference_archive(
                    "CVE-2024-5376", contexts, documents
                )
                archive = json.loads(Path(path).read_text())
            finally:
                cli.RESEARCH_DIR = original
        record = archive["records"][0]
        self.assertEqual(record["body"], "extracted body")
        self.assertEqual(record["content_hash"], "a" * 64)
        self.assertEqual(record["raw_content_hash"], "b" * 64)
        self.assertEqual(record["extraction_format"], "text/html")
        self.assertEqual(record["extraction_status"], "ok")

    def test_refresh_fail_soft_preserves_metadata(self):
        from ai.research_cli import refresh_reference_archive

        with tempfile.TemporaryDirectory() as tmp:
            research_dir = Path(tmp)
            archive = {
                "archive_version": "references-1",
                "cve_id": "CVE-2024-5376",
                "records": [
                    {
                        "source_url": "http://x/a",
                        "source_type": "github",
                        "title": "Keep Me",
                        "exact_record": "exact",
                        "context_chunks": ["chunk"],
                        "content_hash": None,
                    }
                ],
            }
            (research_dir / "CVE-2024-5376.references.json").write_text(
                json.dumps(archive)
            )
            failed = ReferenceDocument(
                url="http://x/a",
                source_type="github",
                content="",
                content_hash=None,
                raw_content_hash="d" * 64,
                extraction_format="application/pdf",
                extraction_status="failed",
            )
            with patch.object(
                __import__("ai.research_cli", fromlist=["x"]),
                "RESEARCH_DIR",
                research_dir,
            ):
                summary = refresh_reference_archive(
                    "CVE-2024-5376", collector=_FakeCollector([failed])
                )
            updated = json.loads(
                (research_dir / "CVE-2024-5376.references.json").read_text()
            )["records"][0]
        self.assertEqual(summary["updated"], 0)
        self.assertEqual(updated["body"], "")
        self.assertIsNone(updated["content_hash"])
        self.assertEqual(updated["title"], "Keep Me")
        self.assertEqual(updated["exact_record"], "exact")
        self.assertEqual(updated["context_chunks"], ["chunk"])

    def test_ingestion_includes_body_and_backward_compat(self):
        from ai.knowledge.ingestion import build_reference_documents

        archive = {
            "records": [
                {
                    "source_url": "http://x/a",
                    "source_type": "github",
                    "title": "T",
                    "context_chunks": ["chunk"],
                    "body": "param first_name reflected",
                    "content_hash": "a" * 64,
                },
                {
                    "source_url": "http://x/b",
                    "source_type": "github",
                    "title": "Legacy",
                    "context_chunks": ["old"],
                },
            ]
        }
        docs = build_reference_documents("CVE-2024-5376", archive)
        self.assertEqual(len(docs), 2)
        self.assertIn("param first_name reflected", docs[0].content)
        self.assertIn("old", docs[1].content)
        self.assertNotIn("Reference content hash", docs[1].content)


class GitHubRewriteTests(unittest.TestCase):
    def test_blob_to_raw(self):
        from ai.collectors.reference import _github_raw_url

        self.assertEqual(
            _github_raw_url(
                "https://github.com/E1CHO/cve_hub/blob/main/"
                "College%20Management%20System%20-%20xss/file.pdf"
            ),
            "https://raw.githubusercontent.com/E1CHO/cve_hub/main/"
            "College%20Management%20System%20-%20xss/file.pdf",
        )
        self.assertIsNone(_github_raw_url("https://example.com/a/blob/b"))
        self.assertIsNone(
            _github_raw_url("https://github.com/owner/repo/other/x")
        )


if __name__ == "__main__":
    unittest.main()

