"""Focused offline tests for Stage R4 research-to-knowledge ingestion.

No network, no LLM, no subprocess, no Nuclei, no Mongo. Stores live in
temp dirs; the real ``ai_data/research/CVE-2026-1557.cli.json`` is used
as read-only sample input (never modified).
"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

REAL_RESEARCH_DIR = Path("ai_data/research")


def _payload(**overrides):
    base = {
        "research_version": "cli-1",
        "mode": "research-only",
        "authoritative": False,
        "cve": {
            "id": "CVE-2026-1557",
            "vendor": ["stuartbates"],
            "products": ["WP Responsive Images"],
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "metadata": {
            "programs": [],
            "assets": [],
            "technologies": ["WordPress"],
            "assessment_count": 0,
        },
        "research": {
            "title": "Sample synthesis title",
            "summary": "Sample summary.",
            "vulnerability_type": "Path Traversal (CWE-22)",
            "affected_products": ["WP Responsive Images"],
            "affected_versions": ["<=1.0"],
            "root_cause": "Unsanitized src parameter.",
            "evidence": ["CONFIRMED: something"],
            "references": ["https://example.com/advisory"],
        },
    }
    base.update(overrides)
    return base


class _Fixture:
    def __init__(self, tmp: TemporaryDirectory):
        from ai.knowledge.store import KnowledgeStore

        root = Path(tmp.name)
        self.research = root / "research"
        self.research.mkdir(parents=True)
        self.store = KnowledgeStore(root / "knowledge")

    def write_cli(self, cve="CVE-2026-1557", payload=None):
        self.research.joinpath(f"{cve}.cli.json").write_text(
            json.dumps(payload if payload is not None else _payload()),
            encoding="utf-8",
        )

    def write_refs(self, cve="CVE-2026-1557", records=None):
        if records is None:
            records = [
                {
                    "source_url": "https://example.com/advisory",
                    "source_type": "advisory",
                    "title": "Example advisory",
                    "exact_record": "exact",
                    "context_chunks": ["chunk one", "chunk two"],
                    "content_hash": "abc123",
                }
            ]
        self.research.joinpath(f"{cve}.references.json").write_text(
            json.dumps(
                {
                    "archive_version": "references-1",
                    "cve_id": cve,
                    "record_count": len(records),
                    "records": records,
                }
            ),
            encoding="utf-8",
        )


class CveIngestionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.fx = _Fixture(self._tmp)
        self.addCleanup(self._tmp.cleanup)

    def test_cve_research_ingestion(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        result = ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        self.assertEqual(result.cve_id, "CVE-2026-1557")
        self.assertEqual(len(result.knowledge_ids), 1)
        self.assertEqual(result.created, result.knowledge_ids)
        self.assertEqual(result.existing, [])
        stored = self.fx.store.get_by_id(result.knowledge_ids[0])
        self.assertIsNotNone(stored)
        self.assertIn("cve:CVE-2026-1557", stored.tags)

    def test_real_sample_artifact_ingests(self):
        from ai.knowledge.ingestion import ingest_cve_research

        result = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, REAL_RESEARCH_DIR
        )
        self.assertTrue(result.created)
        for document in result.documents:
            self.assertTrue(document.knowledge_id.startswith("kb-"))
            self.assertEqual(len(document.content_hash or ""), 64)

    def test_reference_archive_ingestion(self):
        from ai.knowledge.ingestion import ingest_reference_archive

        self.fx.write_refs()
        result = ingest_reference_archive(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        self.assertEqual(len(result.knowledge_ids), 1)
        stored = self.fx.store.get_by_id(result.knowledge_ids[0])
        self.assertEqual(stored.source_url, "https://example.com/advisory")
        self.assertEqual(stored.source_type, "advisory")
        self.assertIn("chunk one", stored.content)
        self.assertIn("abc123", stored.content)

    def test_cve_ingest_includes_references_when_present(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        self.fx.write_refs()
        result = ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        self.assertEqual(len(result.knowledge_ids), 2)
        self.assertEqual(result.knowledge_ids, sorted(result.knowledge_ids))

    def test_provenance_answers_where_from(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        self.fx.write_refs()
        result = ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        by_id = {d.knowledge_id: d for d in result.documents}
        urls = sorted(d.source_url for d in result.documents)
        self.assertIn("https://example.com/advisory", urls)
        self.assertTrue(any(u.startswith("local:") for u in urls))
        for kid, document in by_id.items():
            self.assertIn(f"cve:{result.cve_id}", document.tags)
            self.assertTrue(document.source_type)
            self.assertEqual(kid, document.knowledge_id)


class DeterminismTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.fx = _Fixture(self._tmp)
        self.addCleanup(self._tmp.cleanup)

    def test_deterministic_ids_and_hashes(self):
        from ai.knowledge.ingestion import (
            build_reference_documents,
            build_research_document,
        )

        self.fx.write_cli()
        self.fx.write_refs()
        payload = json.loads(
            self.fx.research.joinpath("CVE-2026-1557.cli.json").read_text()
        )
        archive = json.loads(
            self.fx.research.joinpath("CVE-2026-1557.references.json").read_text()
        )
        first = [
            build_research_document(
                "CVE-2026-1557",
                payload,
                self.fx.research / "CVE-2026-1557.cli.json",
            )
        ] + build_reference_documents("CVE-2026-1557", archive)
        second = [
            build_research_document(
                "CVE-2026-1557",
                payload,
                self.fx.research / "CVE-2026-1557.cli.json",
            )
        ] + build_reference_documents("CVE-2026-1557", archive)
        self.assertEqual(
            [d.content for d in first], [d.content for d in second]
        )

        from ai.knowledge.store import content_hash

        ids_first = [f"kb-{content_hash(d.content)[:16]}" for d in first]
        ids_second = [f"kb-{content_hash(d.content)[:16]}" for d in second]
        self.assertEqual(ids_first, ids_second)

    def test_idempotent_repeated_ingestion(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        self.fx.write_refs()
        first = ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        second = ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        self.assertTrue(first.created)
        self.assertEqual(second.created, [])
        self.assertEqual(first.knowledge_ids, second.knowledge_ids)
        dump = lambda docs: [
            d.model_dump(mode="json") for d in sorted(docs, key=lambda x: x.knowledge_id)
        ]
        self.assertEqual(dump(first.documents), dump(second.documents))

    def test_duplicate_handling_single_record(self):
        from ai.knowledge.ingestion import ingest_reference_archive

        self.fx.write_refs()
        ingest_reference_archive("CVE-2026-1557", self.fx.store, self.fx.research)
        again = ingest_reference_archive(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        self.assertEqual(again.created, [])
        self.assertEqual(len(self.fx.store.retrieve()), 1)


class EdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.fx = _Fixture(self._tmp)
        self.addCleanup(self._tmp.cleanup)

    def test_missing_optional_fields(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli(
            payload={"cve": {"id": "CVE-2026-1557"}, "research": {"title": "Sparse"}}
        )
        result = ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        self.assertEqual(len(result.knowledge_ids), 1)
        stored = self.fx.store.get_by_id(result.knowledge_ids[0])
        self.assertEqual(stored.evidence_quality, "UNKNOWN")
        self.assertEqual(stored.confidence, 0.0)

    def test_malformed_input(self):
        from ai.knowledge.ingestion import (
            ResearchIngestionError,
            ingest_cve_research,
            ingest_reference_archive,
        )

        with self.assertRaises(ResearchIngestionError):
            ingest_cve_research("not-a-cve", self.fx.store, self.fx.research)
        with self.assertRaises(ResearchIngestionError):
            ingest_cve_research("CVE-2026-9999", self.fx.store, self.fx.research)
        self.fx.research.joinpath("CVE-2026-1557.cli.json").write_text(
            "{broken", encoding="utf-8"
        )
        with self.assertRaises(ResearchIngestionError):
            ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        self.fx.research.joinpath("CVE-2026-1557.cli.json").write_text(
            "[1,2]", encoding="utf-8"
        )
        with self.assertRaises(ResearchIngestionError):
            ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)
        with self.assertRaises(ResearchIngestionError):
            ingest_reference_archive("CVE-2026-1557", self.fx.store, self.fx.research)

    def test_empty_input(self):
        from ai.knowledge.ingestion import (
            ResearchIngestionError,
            ingest_reference_archive,
        )

        self.fx.write_refs(records=[])
        result = ingest_reference_archive(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        self.assertEqual(result.knowledge_ids, [])
        self.assertEqual(self.fx.store.retrieve(), [])
        self.fx.write_cli(payload={})
        from ai.knowledge.ingestion import ingest_cve_research

        with self.assertRaises(ResearchIngestionError):
            ingest_cve_research("CVE-2026-1557", self.fx.store, self.fx.research)

    def test_records_without_source_identity_skipped(self):
        from ai.knowledge.ingestion import ingest_reference_archive

        self.fx.write_refs(records=[{"title": "No URL here", "context_chunks": []}])
        result = ingest_reference_archive(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        self.assertEqual(result.knowledge_ids, [])

    def test_dry_run_produces_no_writes(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        self.fx.write_refs()
        result = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, self.fx.research, dry_run=True
        )
        self.assertTrue(result.dry_run)
        self.assertEqual(len(result.knowledge_ids), 2)
        self.assertEqual(self.fx.store.retrieve(), [])
        self.assertFalse((Path(self._tmp.name) / "knowledge" / "index.json").exists())


class IsolationTests(unittest.TestCase):
    def test_no_network_or_subprocess(self):
        import re
        import sys

        import ai.knowledge.ingestion as ingestion

        source = Path(ingestion.__file__).read_text(encoding="utf-8")
        imports = [
            line for line in source.splitlines() if re.match(r"^(import|from)\s+", line)
        ]
        import_text = "\n".join(imports)
        for banned in (
            "socket",
            "urllib",
            "requests",
            "httpx",
            "subprocess",
            "ai.llm",
            "openrouter",
            "nuclei",
            "live_validation",
            "pymongo",
        ):
            self.assertNotIn(banned, import_text)

        blocked = ("socket", "urllib.request", "requests", "subprocess")
        saved = {name: sys.modules.get(name) for name in blocked}
        for name in blocked:
            sys.modules[name] = None  # type: ignore[assignment]
        try:
            with TemporaryDirectory() as tmp:
                from ai.knowledge.store import KnowledgeStore

                store = KnowledgeStore(Path(tmp) / "kb")
                ingestion.ingest_cve_research(
                    "CVE-2026-1557", store, REAL_RESEARCH_DIR
                )
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod


class XssIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.fx = _Fixture(self._tmp)
        self.addCleanup(self._tmp.cleanup)

    def test_xss_agent_sees_ingested_documents(self):
        from ai.knowledge.ingestion import ingest_cve_research
        from ai.researcher.xss_agent import rank_documents

        ingest_cve_research("CVE-2026-1557", self.fx.store, REAL_RESEARCH_DIR)
        ranked, _ = rank_documents(
            "wordpress plugin src parameter", store=self.fx.store
        )
        ingested = {d.knowledge_id for d in self.fx.store.retrieve()}
        seen = {m["knowledge_id"] for m in ranked}
        self.assertTrue(
            ingested & seen,
            "ingested research must be visible to the XSS agent pool",
        )

    def test_seed_plus_store_deduplication(self):
        from ai.researcher.xss_agent import _pool_documents, load_seed_documents

        seeds = load_seed_documents()
        from ai.schemas.knowledge import KnowledgeDocument

        duplicate = KnowledgeDocument.model_validate(
            {
                "knowledge_id": "placeholder",
                "title": "Different title, same bytes",
                "source_url": "https://example.com/other",
                "source_type": "writeup",
                "content": seeds[0].content,
            }
        )
        self.fx.store.ingest(duplicate)
        pool = _pool_documents(self.fx.store)
        ids = [str(d.knowledge_id) for d in pool]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(pool), len(seeds))


class CliIngestTests(unittest.TestCase):
    def test_kb_ingest_and_dry_run(self):
        from argparse import Namespace

        import ai.research_cli as cli

        with TemporaryDirectory() as tmp:
            from ai.knowledge.store import KnowledgeStore

            store = KnowledgeStore(Path(tmp) / "kb")
            research = Path(tmp) / "research"
            research.mkdir()
            research.joinpath("CVE-2026-1557.cli.json").write_text(
                json.dumps(_payload()), encoding="utf-8"
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.run_kb_ingest(
                    Namespace(
                        cve="CVE-2026-1557",
                        dry_run=True,
                        references_only=False,
                    ),
                    store=store,
                    research_dir=research,
                )
            self.assertEqual(code, 0)
            self.assertIn("DRY-RUN", buf.getvalue())
            self.assertEqual(store.retrieve(), [])

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.run_kb_ingest(
                    Namespace(
                        cve="CVE-2026-1557",
                        dry_run=False,
                        references_only=False,
                    ),
                    store=store,
                    research_dir=research,
                )
            self.assertEqual(code, 0)
            self.assertIn("INGESTED", buf.getvalue())
            self.assertEqual(len(store.retrieve()), 1)

    def test_kb_ingest_missing_cve_fails(self):
        from argparse import Namespace

        import ai.research_cli as cli

        with TemporaryDirectory() as tmp:
            from ai.knowledge.store import KnowledgeStore

            store = KnowledgeStore(Path(tmp) / "kb")
            buf, err = io.StringIO(), io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err):
                code = cli.run_kb_ingest(
                    Namespace(cve="CVE-2026-9999", dry_run=False, references_only=False),
                    store=store,
                    research_dir=Path(tmp) / "research",
                )
            self.assertEqual(code, 1)
            self.assertIn("ERROR", err.getvalue())

    def test_kb_ingest_parser(self):
        from ai.research_cli import build_parser

        args = build_parser().parse_args(
            ["kb", "ingest", "--cve", "CVE-2026-1557", "--dry-run"]
        )
        self.assertEqual(args.kb_command, "ingest")
        self.assertTrue(args.dry_run)


class IntelligenceIngestionTests(unittest.TestCase):
    """Stage R12: extraction flows through ingestion into the KB."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.fx = _Fixture(self._tmp)
        self.addCleanup(self._tmp.cleanup)

    def _xss_record(self):
        return [
            {
                "source_url": "https://example.org/reflected-writeup",
                "source_type": "writeup",
                "title": "Widget Shop reflected XSS writeup",
                "context_chunks": [
                    "CVE-2026-1557 is a reflected XSS in the 'q' "
                    "parameter rendered into an HTML attribute."
                ],
            }
        ]

    def test_ingestion_attaches_intelligence_and_provenance(self):
        from ai.knowledge.ingestion import ingest_cve_research
        from ai.knowledge.intelligence import INTELLIGENCE_RULE_VERSION

        self.fx.write_cli()
        self.fx.write_refs(records=self._xss_record())
        result = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        stored = {
            d.knowledge_id: d for d in (
                self.fx.store.get_by_id(k) for k in result.knowledge_ids
            )
        }
        ref = next(
            d for d in stored.values()
            if d.source_url == "https://example.org/reflected-writeup"
        )
        self.assertIn("reflected", ref.xss_types)
        self.assertIn("html_attribute", ref.contexts)
        self.assertIn("q", ref.parameters)
        self.assertIn("xss", ref.vulnerability_types)
        self.assertEqual([], [
            e.value for e in ref.aggregate.xss_types
            if e.value not in ("reflected",)
        ])
        self.assertTrue(ref.aggregate.xss_types[0].source_ids)
        traced = {
            (item.field, item.value) for item in ref.intelligence_evidence
        }
        self.assertIn(("xss_type", "reflected"), traced)
        self.assertIn(("context", "html_attribute"), traced)
        self.assertIn(("parameter", "q"), traced)
        for item in ref.intelligence_evidence:
            self.assertEqual(item.rule_version, INTELLIGENCE_RULE_VERSION)
            self.assertEqual(
                item.source_url, "https://example.org/reflected-writeup"
            )
            self.assertIn("CVE-2026-1557", item.evidence)
            self.assertTrue(item.rule_id)

    def test_reingest_merges_evidence_without_duplicates(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        self.fx.write_refs(records=self._xss_record())
        first = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        ref_url = "https://example.org/reflected-writeup"
        doc_a = next(
            d for d in (
                self.fx.store.get_by_id(k) for k in first.knowledge_ids
            )
            if d.source_url == ref_url
        )
        second = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        self.assertEqual(first.knowledge_ids, second.knowledge_ids)
        self.assertEqual(second.created, [])
        doc_b = self.fx.store.get_by_id(doc_a.knowledge_id)
        # Evidence survives re-ingestion and stays deduped and bounded.
        self.assertEqual(
            doc_a.intelligence_evidence, doc_b.intelligence_evidence
        )
        seen = {
            (i.field, i.value, i.rule_id, i.source_url, i.evidence)
            for i in doc_b.intelligence_evidence
        }
        self.assertEqual(len(seen), len(doc_b.intelligence_evidence))

    def test_non_xss_content_never_gains_xss_dimensions(self):
        from ai.knowledge.ingestion import ingest_cve_research

        self.fx.write_cli()
        result = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        for kid in result.knowledge_ids:
            document = self.fx.store.get_by_id(kid)
            self.assertEqual(document.xss_types, [])
            self.assertEqual(document.contexts, [])
            self.assertEqual(document.parameters, [])
            self.assertEqual(document.cwes, [])
            # Path Traversal (CWE-22) is explicit in the synthesis text.
            self.assertIn(
                "path_traversal", document.vulnerability_types
            )

    def test_xss_agent_consumes_ingested_intelligence(self):
        from ai.knowledge.ingestion import ingest_cve_research
        from ai.researcher.xss_agent import build_candidate

        # Negative control first: bundled seeds alone never describe a
        # stored XSS, so this query cannot reach RESEARCH_CANDIDATE
        # without actual ingested evidence.
        query = "stored XSS in the note attribute of widget shop"
        baseline = build_candidate(query)
        self.assertNotEqual(baseline.status, "RESEARCH_CANDIDATE")

        self.fx.write_cli()
        self.fx.write_refs(
            records=[
                {
                    "source_url": "https://example.org/stored-writeup",
                    "source_type": "writeup",
                    "title": "Widget Shop stored comments XSS",
                    "context_chunks": [
                        "CVE-2026-1557 is a stored XSS: the 'note' "
                        "parameter persists into an HTML attribute."
                    ],
                }
            ]
        )
        result = ingest_cve_research(
            "CVE-2026-1557", self.fx.store, self.fx.research
        )
        ref = next(
            d
            for d in (
                self.fx.store.get_by_id(k) for k in result.knowledge_ids
            )
            if d.source_url == "https://example.org/stored-writeup"
        )
        self.assertEqual(ref.xss_types, ["stored"])
        self.assertEqual(ref.contexts, ["html_attribute"])

        candidate = build_candidate(query, store=self.fx.store)
        self.assertEqual(candidate.status, "RESEARCH_CANDIDATE")
        top = candidate.source_evidence[0]
        self.assertEqual(top.knowledge_id, ref.knowledge_id)
        self.assertIn("xss_type exact match: stored", top.reasons)
        self.assertIn("context exact match: html_attribute", top.reasons)
        self.assertIn(ref.knowledge_id, candidate.references)


if __name__ == "__main__":
    unittest.main()
