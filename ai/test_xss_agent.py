"""Focused offline tests for the Stage R3 XSS research agent MVP.

No network, no LLM, no subprocess, no browser, no Nuclei, no Mongo.
Seed documents ship with the agent; store-backed tests use temp dirs.
"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory


class SeedTests(unittest.TestCase):
    def test_seed_covers_required_categories(self):
        from ai.researcher.xss_agent import SUPPORTED_CATEGORIES, load_seed_documents

        documents = load_seed_documents()
        self.assertGreaterEqual(len(documents), 3)
        covered = set()
        for document in documents:
            for t in document.xss_types:
                for c in document.contexts:
                    covered.add((t.lower().replace(" ", "_"), c.lower().replace(" ", "_")))
        for category in SUPPORTED_CATEGORIES:
            self.assertIn(category, covered, category)

    def test_seed_load_is_deterministic(self):
        from ai.researcher.xss_agent import load_seed_documents

        first = [d.knowledge_id for d in load_seed_documents()]
        second = [d.knowledge_id for d in load_seed_documents()]
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first))


class CategoryTests(unittest.TestCase):
    def _candidate(self, query, **kwargs):
        from ai.researcher.xss_agent import build_candidate

        return build_candidate(query, store=None, **kwargs)

    def test_reflected_html_attribute(self):
        candidate = self._candidate("reflected XSS in an HTML attribute")
        self.assertEqual(candidate.status, "RESEARCH_CANDIDATE")
        self.assertEqual(candidate.xss_type, "reflected")
        self.assertEqual(candidate.context, "html_attribute")
        self.assertTrue(candidate.references)
        reasons = [
            reason
            for item in candidate.source_evidence
            for reason in item.reasons
        ]
        self.assertIn("xss_type exact match: reflected", reasons)
        self.assertIn("context exact match: html_attribute", reasons)

    def test_reflected_script(self):
        candidate = self._candidate("reflected input inside a script block")
        self.assertEqual(candidate.status, "RESEARCH_CANDIDATE")
        self.assertEqual(candidate.xss_type, "reflected")
        self.assertEqual(candidate.context, "script")

    def test_dom_javascript(self):
        candidate = self._candidate("DOM XSS from location.hash to a sink")
        self.assertEqual(candidate.status, "RESEARCH_CANDIDATE")
        self.assertEqual(candidate.xss_type, "dom")
        self.assertEqual(candidate.context, "javascript")
        self.assertTrue(
            any(s.value == "innerhtml" for s in candidate.sinks),
            "sink explicitly stated in the seed must be extracted",
        )
        self.assertTrue(
            any(s.value == "location.hash" for s in candidate.sources),
            "source explicitly stated in the seed must be extracted",
        )

    def test_explicit_flags_select_category(self):
        candidate = self._candidate(
            "something reflected", xss_type="reflected", context="script"
        )
        self.assertEqual(candidate.status, "RESEARCH_CANDIDATE")
        self.assertEqual(candidate.context, "script")


class RankingTests(unittest.TestCase):
    def test_ranking_is_deterministic_and_explained(self):
        from ai.researcher.xss_agent import rank_documents

        first, _ = rank_documents("reflected attribute breakout")
        second, _ = rank_documents("reflected attribute breakout")
        self.assertEqual(
            [(m["knowledge_id"], m["score"]) for m in first],
            [(m["knowledge_id"], m["score"]) for m in second],
        )
        scores = [m["score"] for m in first]
        self.assertEqual(scores, sorted(scores, reverse=True))
        for match in first:
            self.assertTrue(match["reasons"], "every match must explain itself")
            self.assertTrue(match["knowledge_id"])
            self.assertTrue(match["title"])

    def test_tie_break_by_knowledge_id(self):
        from ai.researcher.xss_agent import rank_documents

        ranked, _ = rank_documents("xss")
        for left, right in zip(ranked, ranked[1:]):
            if left["score"] == right["score"]:
                self.assertLess(left["knowledge_id"], right["knowledge_id"])


class StatusTests(unittest.TestCase):
    def test_insufficient_evidence_for_weak_query(self):
        from ai.researcher.xss_agent import build_candidate

        # Type signal only: documents match, but no exact context match,
        # so the candidate cannot be completed.
        candidate = build_candidate("reflected")
        self.assertEqual(candidate.status, "INSUFFICIENT_EVIDENCE")
        self.assertTrue(candidate.unknowns)
        self.assertIsNone(candidate.test_idea)
        self.assertIn("NOT exploitability", candidate.disclaimer)

    def test_rejected_for_irrelevant_input(self):
        from ai.researcher.xss_agent import build_candidate

        candidate = build_candidate("SQL injection drop table union select")
        self.assertEqual(candidate.status, "REJECTED")
        self.assertEqual(candidate.confidence, 0.0)
        self.assertEqual(candidate.source_evidence, [])
        self.assertIsNone(candidate.vulnerability_pattern)

    def test_candidate_never_claims_exploitability(self):
        from ai.researcher.xss_agent import build_candidate

        candidate = build_candidate("reflected XSS in HTML attribute")
        text = json.dumps(candidate.model_dump(mode="json")).lower()
        self.assertNotIn("exploitabl", text.replace("not exploitability", "").replace("unconfirmed by design", ""))
        # The only allowed exploitability mentions are negations.
        for excerpt in ("not exploitability", "not a confirmation of exploitability"):
            self.assertIn(excerpt, text)

    def test_malformed_and_empty_input(self):
        from ai.researcher.xss_agent import XSSAgentError, build_candidate, load_candidate

        for bad in ("", "   ", None):
            with self.assertRaises(XSSAgentError):
                build_candidate(bad)
        with self.assertRaises(XSSAgentError):
            load_candidate("not-an-id")
        with self.assertRaises(XSSAgentError):
            load_candidate("xss-zzz")


class SerializationTests(unittest.TestCase):
    def test_stable_serialization_and_kb_references(self):
        from ai.researcher.xss_agent import build_candidate, candidate_to_json

        first = candidate_to_json(build_candidate("dom javascript sink"))
        second = candidate_to_json(build_candidate("dom javascript sink"))
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(
            sorted(payload["references"]),
            payload["references"],
            "references must be stably ordered",
        )
        evidenced = set()
        for item in payload["source_evidence"]:
            evidenced.add(item["knowledge_id"])
            self.assertTrue(item["reasons"])
        self.assertEqual(set(payload["references"]), evidenced)

    def test_repeated_persistence_is_byte_identical(self):
        from ai.researcher.xss_agent import research_and_persist

        with TemporaryDirectory() as tmp:
            _, first = research_and_persist(
                "reflected script breakout", research_dir=tmp
            )
            _, second = research_and_persist(
                "reflected script breakout", research_dir=tmp
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertNotIn(b"created_at", first.read_bytes())


class IsolationTests(unittest.TestCase):
    def test_no_network_or_subprocess(self):
        import re
        import sys

        import ai.researcher.xss_agent as agent

        source = Path(agent.__file__).read_text(encoding="utf-8")
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
            "selenium",
            "playwright",
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
            agent.build_candidate("reflected attribute xss")
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

    def test_store_documents_join_the_pool(self):
        import tempfile

        from ai.knowledge.store import KnowledgeStore
        from ai.researcher.xss_agent import rank_documents
        from ai.schemas.knowledge import KnowledgeDocument

        with tempfile.TemporaryDirectory() as tmp:
            store = KnowledgeStore(Path(tmp) / "knowledge")
            stored, _ = store.ingest(
                KnowledgeDocument.model_validate(
                    {
                        "knowledge_id": "placeholder",
                        "title": "Stored XSS in comment field",
                        "source_url": "https://research.example.test/stored",
                        "source_type": "writeup",
                        "technologies": [],
                        "xss_types": ["stored"],
                        "contexts": ["html_attribute"],
                        "content": "Local test doc about stored XSS.",
                    }
                )
            )
            ranked, _ = rank_documents("stored XSS", store=store)
            ids = [m["knowledge_id"] for m in ranked]
            self.assertIn(stored.knowledge_id, ids)


class CliTests(unittest.TestCase):
    def _main(self, argv, **kwargs):
        from ai.research_cli import main

        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(argv, **kwargs) if kwargs else main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_xss_search(self):
        code, out, err = self._main(["xss", "search", "--query", "reflected attribute"])
        self.assertEqual(code, 0, err)
        self.assertIn("MATCHES:", out)

    def test_xss_search_json(self):
        code, out, err = self._main(
            ["xss", "search", "--query", "dom sink", "--json"]
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(payload)
        self.assertIn("reasons", payload[0])

    def test_xss_research_and_show_and_list(self):
        with TemporaryDirectory() as tmp:
            import ai.research_cli as cli

            base = [None, None, None]
            # Route persistence at the temp dir via --output; list/show
            # need the same dir, so call run_* helpers directly.
            from argparse import Namespace

            args = Namespace(
                query="reflected HTML attribute breakout",
                xss_type=None,
                context=None,
                technologies=None,
                techniques=None,
                output=None,
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.run_xss_research(args, store=None, research_dir=tmp)
            self.assertEqual(code, 0)
            saved = [p for p in Path(tmp).glob("xss-*.json")]
            self.assertEqual(len(saved), 1)
            candidate_id = json.loads(saved[0].read_text())["candidate_id"]

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.run_xss_list(Namespace(), research_dir=tmp)
            self.assertEqual(code, 0)
            self.assertIn(candidate_id, buf.getvalue())

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.run_xss_show(
                    Namespace(candidate_id=candidate_id, json=False),
                    research_dir=tmp,
                )
            self.assertEqual(code, 0)
            self.assertIn("RESEARCH_CANDIDATE", buf.getvalue())
            _ = base

    def test_xss_research_empty_query_fails(self):
        code, _out, err = self._main(["xss", "research", "--query", "   "])
        self.assertEqual(code, 1)
        self.assertIn("ERROR", err)

    def test_xss_show_unknown_id_fails(self):
        code, _out, err = self._main(["xss", "show", "xss-0123456789abcdef"])
        self.assertEqual(code, 1)
        self.assertIn("ERROR", err)


if __name__ == "__main__":
    unittest.main()
