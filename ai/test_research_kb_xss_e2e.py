"""Stage R6 end-to-end test: research artifact -> KB ingestion -> XSS agent.

Proves the deterministic integration chain on an isolated copy of the
real persisted CVE-2026-1557 artifact structure:

  <CVE>.cli.json --ingest--> KnowledgeStore --query--> candidate JSON

No network, no LLM, no subprocess, no Nuclei, no Mongo, no target
execution. All stores live in temp dirs; the real ``ai_data/`` tree is
read (artifact copy source) but never written — a snapshot guard
asserts that. Re-running ingestion converges (idempotency); re-running
the agent queries reproduces the exact persisted real-world candidate
ids (``xss-488f639165085224``, ``xss-0df931af429249e4``).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REAL_RESEARCH_DIR = Path("ai_data/research")
REAL_KB_DIR = Path("ai_data/knowledge")
REAL_XSS_DIR = REAL_RESEARCH_DIR / "xss"

CVE = "CVE-2026-1557"
SYNTHESIS_ID = "kb-609f38e9c57c0592"
XSS_QUERY = "reflected XSS wordpress plugin parameter"
XSS_CANDIDATE_ID = "xss-488f639165085224"
NON_XSS_QUERY = "WP Responsive Images path traversal src parameter file read"
NON_XSS_CANDIDATE_ID = "xss-0df931af429249e4"

FORBIDDEN_MODULES = {
    "socket",
    "urllib",
    "requests",
    "httpx",
    "subprocess",
    "ai.llm",
    "ai.execution",
    "ai.verification",
    "ai.live_validation",
    "nuclei",
    "pymongo",
    "mongo",
}
FORBIDDEN_NAMES = {"XssFinding", "XssFindings"}


def _snapshot(paths: list[Path]) -> dict[str, str]:
    """Filename -> sha256 for every file under the given dirs (or {})."""
    out: dict[str, str] = {}
    for root in paths:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file():
                out[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


class TestResearchKbXssE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        root = Path(self.tmp.name)
        self.research_dir = root / "research"
        self.research_dir.mkdir(parents=True)
        # Isolated copy of the REAL persisted artifact (bytes unchanged).
        shutil.copyfile(
            REAL_RESEARCH_DIR / f"{CVE}.cli.json",
            self.research_dir / f"{CVE}.cli.json",
        )
        from ai.knowledge.store import KnowledgeStore

        self.store = KnowledgeStore(root / "knowledge")
        self.xss_dir = root / "xss"
        # Guard: real data dirs must be byte-identical after the test.
        self._before = _snapshot([REAL_KB_DIR, REAL_XSS_DIR])

    def tearDown(self):
        self.assertEqual(
            _snapshot([REAL_KB_DIR, REAL_XSS_DIR]),
            self._before,
            "E2E test must never write to the real ai_data/ tree",
        )
        self.tmp.cleanup()

    # -- full chain ------------------------------------------------------
    def test_research_to_kb_to_candidate(self):
        from ai.knowledge.ingestion import ingest_research

        first = ingest_research(CVE, self.store, research_dir=self.research_dir)
        self.assertEqual(first.knowledge_ids, [SYNTHESIS_ID])
        self.assertEqual(first.created, [SYNTHESIS_ID])
        self.assertTrue(
            any("archive not present" in note for note in first.notes),
            first.notes,
        )

        # Idempotency: a second ingestion creates nothing and duplicates nothing.
        second = ingest_research(CVE, self.store, research_dir=self.research_dir)
        self.assertEqual(second.created, [])
        self.assertEqual(second.existing, [SYNTHESIS_ID])
        self.assertEqual(second.knowledge_ids, [SYNTHESIS_ID])
        from ai.knowledge.store import KnowledgeStore as _KS

        docs = self.store.retrieve()
        self.assertEqual(len(docs), 1)
        self.assertIsInstance(self.store, _KS)

        # Provenance preserved: local artifact source, CVE tag.
        doc = self.store.get_by_id(SYNTHESIS_ID)
        self.assertIsNotNone(doc)
        self.assertEqual(doc.source_type, "research")
        self.assertTrue(
            str(doc.source_url).endswith(f"{CVE}.cli.json"), doc.source_url
        )
        self.assertIn(f"cve:{CVE}", list(doc.tags or []))

        # XSS agent over the ingested KB: same verdict as the real run.
        from ai.researcher.xss_agent import (
            build_candidate,
            load_candidate,
            research_and_persist,
        )

        candidate = build_candidate(XSS_QUERY, store=self.store)
        self.assertEqual(candidate.candidate_id, XSS_CANDIDATE_ID)
        self.assertEqual(candidate.status, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(candidate.confidence, 0.35)
        evidence_ids = [e.knowledge_id for e in candidate.source_evidence]
        self.assertIn(SYNTHESIS_ID, evidence_ids)
        self.assertIn(SYNTHESIS_ID, list(candidate.references or []))
        # The ingested non-XSS doc contributes keyword reasons only: exact
        # type/context matches still come from the seed baseline.
        ingested = [
            e for e in candidate.source_evidence
            if e.knowledge_id == SYNTHESIS_ID
        ][0]
        self.assertTrue(ingested.reasons)
        self.assertFalse(
            [r for r in ingested.reasons if "exact match" in r],
            ingested.reasons,
        )
        self.assertIn(
            "injection context: no exact KB context match",
            list(candidate.unknowns or []),
        )

        # Persist + reload round-trip; repeat is byte-identical.
        saved, path = research_and_persist(
            XSS_QUERY, store=self.store, research_dir=self.xss_dir
        )
        self.assertEqual(saved.candidate_id, XSS_CANDIDATE_ID)
        self.assertEqual(path.name, f"{XSS_CANDIDATE_ID}.json")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        reloaded = load_candidate(XSS_CANDIDATE_ID, research_dir=self.xss_dir)
        self.assertEqual(reloaded["candidate_id"], XSS_CANDIDATE_ID)
        self.assertEqual(reloaded["status"], "INSUFFICIENT_EVIDENCE")
        _, path2 = research_and_persist(
            XSS_QUERY, store=self.store, research_dir=self.xss_dir
        )
        self.assertEqual(hashlib.sha256(path2.read_bytes()).hexdigest(), digest)

    def test_non_xss_research_is_rejected_not_laundered(self):
        from ai.knowledge.ingestion import ingest_research
        from ai.researcher.xss_agent import build_candidate

        ingest_research(CVE, self.store, research_dir=self.research_dir)
        candidate = build_candidate(NON_XSS_QUERY, store=self.store)
        self.assertEqual(candidate.candidate_id, NON_XSS_CANDIDATE_ID)
        self.assertEqual(candidate.status, "REJECTED")
        self.assertEqual(candidate.confidence, 0.0)
        self.assertEqual(list(candidate.source_evidence or []), [])
        # The CVE's presence in the KB must not manufacture an XSS claim.
        self.assertNotIn(SYNTHESIS_ID, list(candidate.references or []))

    def test_url_list_only_archive_creates_no_reference_documents(self):
        """R1-style backfill (URLs, no bodies) must not become KB documents."""
        archive = {
            "archive_version": "references-1",
            "cve_id": CVE,
            "completeness": "url-list-backfill",
            "records": [
                {
                    "source_url": "https://example.com/advisory",
                    "source_type": "other",
                    "title": None,
                    "exact_record": None,
                    "context_chunks": [],
                    "content_hash": None,
                }
            ],
        }
        (self.research_dir / f"{CVE}.references.json").write_text(
            json.dumps(archive), encoding="utf-8"
        )
        from ai.knowledge.ingestion import ingest_research

        result = ingest_research(CVE, self.store, research_dir=self.research_dir)
        self.assertEqual(result.knowledge_ids, [SYNTHESIS_ID])
        self.assertEqual(len(self.store.retrieve()), 1)

    def test_cli_workflow_reliable_offline(self):
        """kb ingest -> xss research through the real CLI entry points."""
        import argparse

        from ai.research_cli import run_kb_ingest, run_xss_research

        rc = run_kb_ingest(
            argparse.Namespace(
                cve=CVE, dry_run=False, references_only=False
            ),
            store=self.store,
            research_dir=self.research_dir,
        )
        self.assertEqual(rc, 0)
        rc = run_kb_ingest(
            argparse.Namespace(
                cve=CVE, dry_run=False, references_only=False
            ),
            store=self.store,
            research_dir=self.research_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.store.retrieve()), 1)
        rc = run_xss_research(
            argparse.Namespace(
                query=XSS_QUERY,
                xss_type=None,
                context=None,
                technologies=None,
                techniques=None,
                output=None,
            ),
            store=self.store,
            research_dir=self.xss_dir,
        )
        self.assertEqual(rc, 0)
        self.assertTrue((self.xss_dir / f"{XSS_CANDIDATE_ID}.json").exists())

    # -- safety ----------------------------------------------------------
    def test_no_execution_capability_with_blocked_modules(self):
        blocked = ("socket", "urllib.request", "requests", "subprocess")
        saved = {name: sys.modules.pop(name, None) for name in blocked}
        for name in blocked:
            sys.modules[name] = None  # type: ignore[assignment]
        try:
            from ai.knowledge.ingestion import ingest_research
            from ai.researcher.xss_agent import build_candidate

            ingest_research(CVE, self.store, research_dir=self.research_dir)
            candidate = build_candidate(XSS_QUERY, store=self.store)
            self.assertEqual(candidate.status, "INSUFFICIENT_EVIDENCE")
        finally:
            for name in blocked:
                if saved[name] is not None:
                    sys.modules[name] = saved[name]
                else:
                    sys.modules.pop(name, None)

    def test_no_forbidden_imports_or_legacy_findings(self):
        """AST scan: no network/execution/production imports or names.

        Docstring disclaimers (e.g. "no subprocess") are prose, not
        capability — only real imports and name usages count.
        """
        import ast

        for rel in ("ai/researcher/xss_agent.py", "ai/knowledge/ingestion.py"):
            tree = ast.parse(Path(rel).read_text(encoding="utf-8"))
            modules: set[str] = set()
            names: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.update(a.name.split(".")[0] for a in node.names)
                    modules.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        modules.add(node.module)
                        modules.add(node.module.split(".")[0])
                elif isinstance(node, ast.Name):
                    names.add(node.id)
            for token in FORBIDDEN_MODULES:
                top = token.split(".")[0]
                self.assertNotIn(
                    token, modules, f"{rel} imports {token!r}"
                )
                if "." not in token:
                    self.assertNotIn(
                        top, modules, f"{rel} imports {top!r}"
                    )
            for name in FORBIDDEN_NAMES:
                self.assertNotIn(name, names, f"{rel} uses {name!r}")


if __name__ == "__main__":
    unittest.main()
