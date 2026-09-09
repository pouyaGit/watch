"""Focused offline tests for Stage R2 (deterministic read-only report).

No network, no LLM, no Nuclei execution, no Mongo. All fixtures live in
temporary directories; the real ``ai_data/`` tree is never touched.
"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace


CVE = "CVE-2026-1557"


def _research_payload(**overrides):
    payload = {
        "research_version": "cli-1",
        "mode": "research-only",
        "authoritative": False,
        "research_status": "completed",
        "llm_status": "ok",
        "cve": {
            "id": CVE,
            "vendor": ["stuartbates"],
            "products": ["WP Responsive Images"],
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "metadata": {
            "programs": ["dell"],
            "assets": ["example.dell.com"],
            "technologies": ["WordPress"],
            "assessment_count": 1,
        },
        "research": {
            "title": "WP Responsive Images plugin <=1.0 path traversal via 'src' parameter",
            "summary": "Unauthenticated path traversal in image_handler.php.",
            "vulnerability_type": "Path Traversal (CWE-22)",
            "severity": "High (CVSS 7.5)",
            "affected_products": ["WP Responsive Images (WordPress plugin)"],
            "affected_versions": ["<=1.0"],
            "attack_requirements": [
                "No authentication required (unauthenticated attack)",
                "Reach /wp-content/plugins/wp-responsive-images/image_handler.php",
            ],
            "root_cause": "Unsanitized 'src' parameter allows ../ traversal.",
            "impact": ["Arbitrary file read"],
            "public_exploit": True,
            "actively_exploited": None,
            "evidence": ["CONFIRMED: unauthenticated arbitrary file read via 'src'"],
            "references": ["https://example.com/advisory"],
        },
    }
    payload.update(overrides)
    return payload


def _references_archive(with_context=True):
    record = {
        "source_url": "https://example.com/advisory",
        "source_type": "advisory",
        "title": "Example advisory",
        "exact_record": "exact" if with_context else None,
        "context_chunks": ["chunk-one", "chunk-two"] if with_context else [],
        "content_hash": "abc123" if with_context else None,
    }
    return {
        "archive_version": "references-1",
        "cve_id": CVE,
        "record_count": 1,
        "records": [record],
    }


TEMPLATE_YAML = """id: CVE-2026-1557
info:
  name: test template
  author: watch-ai
  severity: high
"""

RESULTS_JSON = {
    "cve_id": CVE,
    "decision": "GOOD_CANDIDATE",
    "semantic_valid": True,
    "nuclei_valid": True,
    "run_results": [
        {"target": "a.example.com", "status": "DRY_RUN_ONLY"},
        {"target": "b.example.com", "status": "EXCLUDED"},
    ],
    "findings": [
        {"cve_id": CVE, "target": "a.example.com", "matched": False},
    ],
}


class _FakeStore:
    """Minimal KnowledgeStore-shaped stub (retrieve only)."""

    def __init__(self, docs):
        self._docs = docs

    def retrieve(self, **kwargs):
        assert kwargs == {}, f"renderer must use plain retrieve(), got {kwargs}"
        return list(self._docs)


def _kb_doc(knowledge_id, **overrides):
    base = {
        "knowledge_id": knowledge_id,
        "title": "WordPress path traversal notes",
        "summary": "Traversal via src parameter in plugins",
        "content": "wordpress traversal src plugin CVE-2026-1557 notes",
        "source_url": "https://kb.example.com/1",
        "source_type": "research-note",
        "evidence_quality": "secondary",
        "tags": ["wordpress", "traversal"],
        "technologies": ["WordPress"],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _Fixture:
    """Owned temp tree: research/, nuclei/{generated,results,findings}/, out/."""

    def __init__(self, tmp: TemporaryDirectory):
        self.tmp = tmp
        root = Path(tmp.name)
        self.research = root / "research"
        self.generated = root / "nuclei" / "generated"
        self.results = root / "nuclei" / "results"
        self.findings = root / "nuclei" / "findings"
        self.out = root / "reports"
        for d in (self.research, self.generated, self.results, self.findings, self.out):
            d.mkdir(parents=True)

    def kwargs(self, **extra):
        from ai.reports.renderer import build_report_for_cve  # noqa: F401

        base = {
            "research_dir": self.research,
            "reports_dir": self.out,
            "nuclei_generated_dir": self.generated,
            "nuclei_results_dir": self.results,
            "nuclei_findings_dir": self.findings,
            "store": _FakeStore([]),
        }
        base.update(extra)
        return base

    def write_research(self, payload=None):
        self.research.joinpath(f"{CVE}.cli.json").write_text(
            json.dumps(payload if payload is not None else _research_payload()),
            encoding="utf-8",
        )

    def write_references(self, archive=None):
        self.research.joinpath(f"{CVE}.references.json").write_text(
            json.dumps(archive if archive is not None else _references_archive()),
            encoding="utf-8",
        )

    def write_nuclei(self):
        self.generated.joinpath(f"{CVE}.yaml").write_text(TEMPLATE_YAML, encoding="utf-8")
        self.results.joinpath(f"{CVE}.json").write_text(
            json.dumps(RESULTS_JSON), encoding="utf-8"
        )
        self.findings.joinpath(f"{CVE}.json").write_text("[]", encoding="utf-8")


class RendererTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.fx = _Fixture(self._tmp)
        self.addCleanup(self._tmp.cleanup)

    def _build(self, **kwargs):
        from ai.reports.renderer import build_report_for_cve

        merged = self.fx.kwargs()
        merged.update(kwargs)
        return build_report_for_cve(CVE, **merged)

    def test_complete_report_sections(self):
        self.fx.write_research()
        self.fx.write_references()
        self.fx.write_nuclei()
        path = self._build(store=_FakeStore([_kb_doc("kb-aaa")]))
        text = path.read_text(encoding="utf-8")
        for heading in (
            "# Research Report — CVE-2026-1557",
            "## 1. CVE / Research Summary",
            "## 2. Vulnerability",
            "## 3. References",
            "## 4. Knowledge Base",
            "## 5. Nuclei",
            "## 6. Watch Relevance",
            "## 7. Limitations",
        ):
            self.assertIn(heading, text)
        self.assertIn("CWE-22", text)
        self.assertIn("GOOD\\_CANDIDATE", text)
        self.assertIn("kb-aaa", text)
        # No raw JSON dumps.
        self.assertNotIn('"research_version"', text)
        # Trust boundary present.
        self.assertIn("NOT a Watch finding", text)

    def test_missing_references_archive_fails_soft(self):
        self.fx.write_research()
        path = self._build()
        text = path.read_text(encoding="utf-8")
        self.assertIn("References archive: Not available", text)
        self.assertIn("references archive not persisted", text)

    def test_references_with_and_without_context(self):
        self.fx.write_research()
        archive = _references_archive(with_context=True)
        archive["records"].append(
            {
                "source_url": "https://example.com/bare",
                "source_type": "blog",
                "title": "Bare link",
                "exact_record": None,
                "context_chunks": [],
                "content_hash": None,
            }
        )
        archive["record_count"] = 2
        self.fx.write_references(archive)
        path = self._build()
        text = path.read_text(encoding="utf-8")
        self.assertIn("persisted context available (2 chunk(s))", text)
        self.assertIn("no persisted context", text)

    def test_empty_kb(self):
        self.fx.write_research()
        path = self._build(store=_FakeStore([]))
        text = path.read_text(encoding="utf-8")
        self.assertIn("knowledge store is empty", text)

    def test_populated_kb_match_and_nonmatch(self):
        self.fx.write_research()
        matching = _kb_doc("kb-aaa")
        unrelated = _kb_doc(
            "kb-zzz",
            title="Unrelated linux kernel notes",
            summary="scheduler internals",
            content="completely unrelated scheduler internals",
            tags=["kernel"],
            technologies=["Linux"],
        )
        path = self._build(store=_FakeStore([matching, unrelated]))
        text = path.read_text(encoding="utf-8")
        self.assertIn("matches: 1", text)
        self.assertIn("kb-aaa", text)
        self.assertNotIn("kb-zzz", text)

    def test_nuclei_present_and_absent(self):
        self.fx.write_research()
        self.fx.write_references()
        self.fx.write_nuclei()
        text = self._build().read_text(encoding="utf-8")
        self.assertIn("Template identity: CVE-2026-1557", text)
        self.assertIn("Semantic validation", text)
        self.assertIn("matched=0; unmatched=1", text)

        fx2_tmp = TemporaryDirectory()
        self.addCleanup(fx2_tmp.cleanup)
        fx2 = _Fixture(fx2_tmp)
        fx2.write_research()
        from ai.reports.renderer import build_report_for_cve

        path = build_report_for_cve(CVE, **fx2.kwargs())
        text2 = path.read_text(encoding="utf-8")
        self.assertIn("Generated template: Not available", text2)
        self.assertIn("Results artifact: Not available", text2)
        self.assertIn("no persisted Nuclei template", text2)

    def test_missing_optional_fields(self):
        payload = _research_payload()
        payload["cve"] = {"id": CVE}
        payload["metadata"] = {}
        payload["research"] = {"title": "Sparse title"}
        self.fx.write_research(payload)
        path = self._build()
        text = path.read_text(encoding="utf-8")
        self.assertIn("Unknown", text)
        self.assertIn("Not available", text)

    def test_deterministic_byte_identical(self):
        self.fx.write_research()
        self.fx.write_references()
        self.fx.write_nuclei()
        first = self._build(store=_FakeStore([_kb_doc("kb-aaa")])).read_bytes()
        second = self._build(store=_FakeStore([_kb_doc("kb-aaa")])).read_bytes()
        self.assertEqual(first, second)
        # No render-time timestamps leak into output.
        self.assertNotIn(b"generated_at", first)
        import re

        self.assertIsNone(re.search(rb"202\d-\d\d-\d\dT", first))

    def test_malicious_reference_text_cannot_alter_structure(self):
        self.fx.write_research()
        self.fx.write_references(
            {
                "archive_version": "references-1",
                "cve_id": CVE,
                "record_count": 1,
                "records": [
                    {
                        "source_url": "javascript:alert(1)",
                        "source_type": "x生きる",
                        "title": "# HACKED\n[evil](http://x)\n| a | b |",
                        "exact_record": None,
                        "context_chunks": [],
                        "content_hash": None,
                    }
                ],
            }
        )
        text = self._build().read_text(encoding="utf-8")
        # No raw heading/link/table injection from the title.
        self.assertNotIn("\n# HACKED", text)
        self.assertNotIn("[evil](http://x)", text)
        self.assertIn("invalid URL:", text)
        # The only top-level headings are the report's own.
        headings = [l for l in text.splitlines() if l.startswith("# ")]
        self.assertEqual(headings, [f"# Research Report — {CVE}"])

    def test_no_network_or_llm_from_renderer(self):
        import re

        import ai.reports.renderer as renderer

        source = Path(renderer.__file__).read_text(encoding="utf-8")
        # Only top-level imports count (lazy function-level imports and
        # prose mentions in docstrings are fine).
        imports = [
            line
            for line in source.splitlines()
            if re.match(r"^(import|from)\s+", line)
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
            "ai.live_validation",
            "pymongo",
        ):
            self.assertNotIn(banned, import_text)
        self.assertNotIn("KnowledgeStore", import_text)  # lazy import only
        # Render with network/LLM entry points blocked to prove purity.
        import sys

        self.fx.write_research()
        blocked = ("socket", "urllib.request", "requests", "subprocess")
        saved = {name: sys.modules.get(name) for name in blocked}
        for name in blocked:
            sys.modules[name] = None  # type: ignore[assignment]
        try:
            self._build()
        finally:
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

    def test_missing_cve_input_fails_clearly(self):
        from ai.reports.renderer import ReportError, build_report_for_cve

        with self.assertRaises(ReportError) as ctx:
            build_report_for_cve("CVE-2026-9999", **self.fx.kwargs())
        self.assertIn("missing CVE research JSON", str(ctx.exception))
        with self.assertRaises(ReportError):
            build_report_for_cve("not-a-cve", **self.fx.kwargs())

    def test_explicit_output_path(self):
        from ai.reports.renderer import build_report_for_cve

        self.fx.write_research()
        custom = Path(self._tmp.name) / "custom" / "r.md"
        out = build_report_for_cve(CVE, **self.fx.kwargs(), output=str(custom))
        self.assertEqual(out, custom)
        self.assertTrue(custom.exists())
        # Default path untouched.
        self.assertFalse((self.fx.out / f"{CVE}.md").exists())

    def test_cli_report_command(self):
        # End-to-end through the real CLI against the real ai_data/ tree
        # (CVE-2026-1557.cli.json exists there); output redirected to a
        # temp path via --output so the real tree is never written.
        from ai.research_cli import main

        dest = self.fx.out / f"{CVE}.md"
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(["report", "--cve", CVE, "--output", str(dest)])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("REPORTED", buf.getvalue())
        self.assertTrue(dest.exists())
        text = dest.read_text(encoding="utf-8")
        self.assertIn(f"# Research Report — {CVE}", text)

    def test_cli_missing_cve_returns_error(self):
        from ai.research_cli import main

        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = main(["report", "--cve", "CVE-2026-9999"])
        self.assertEqual(code, 1)
        self.assertIn("ERROR", err.getvalue())


if __name__ == "__main__":
    unittest.main()
