"""Focused offline tests for research-only batch CVE research.

Covers ``ai.researcher.cve_batch`` + the ``batch --cves/--file`` CLI
extension:

- multiple CVEs processed in one batch;
- one CVE failure does not abort the batch;
- deterministic per-CVE result structure;
- existing single-CVE research entry points still work;
- the Nuclei candidate path goes through ``prepare_offline()`` only;
- zero network access (sockets/DNS blocked);
- zero scanning subprocess execution (subprocess blocked);
- no authoritative / CONFIRMED / SealedFinding / 5J materialization.

Strictly offline: all research I/O is injected via fakes except the
real ``NucleiPipeline.prepare_offline`` lane exercised with the stored
CVE-2026-1557 template. Temporary output directories are used so
``ai_data/`` and ``agent-reports/`` are never touched.
"""

from __future__ import annotations

import ast
import inspect
import io
import json
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = REPO_ROOT / "ai_data/research/CVE-2026-1557.cli.json"
TEMPLATE_DIR = REPO_ROOT / "ai_data/nuclei/generated"

CANDIDATE_CVE = "CVE-2026-1557"
SYNTHETIC_CVES = ["CVE-2026-9001", "CVE-2026-9002"]


def _block(*args, **kwargs):
    raise AssertionError("network/subprocess is forbidden in this test")


def _synthetic_research(cve_id: str) -> dict:
    return {
        "title": f"Synthetic research for {cve_id}",
        "summary": f"Offline fixture summary for {cve_id} with no HTTP method.",
        "vulnerability_type": "buffer-overflow",
        "severity": "medium",
        "cve_ids": [cve_id],
        "affected_products": ["fixture-product"],
        "affected_versions": ["1.0"],
        "root_cause": "offline fixture",
        "nuclei_candidate": False,
        "nuclei_reason": None,
        "detection_ideas": [],
        "evidence": [],
        "references": [],
    }


def _payload(cve_id: str, research: dict, out_dir: Path) -> dict:
    return {
        "research_version": "cli-1",
        "mode": "research-only",
        "authoritative": False,
        "cve": {
            "id": cve_id,
            "vendor": ["fixture-vendor"],
            "products": ["fixture-product"],
            "cvss_score": 5.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        },
        "metadata": {},
        "research": research,
        "output_path": str(out_dir / f"{cve_id}.cli.json"),
    }


def _candidate_payload(out_dir: Path) -> dict:
    stored = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    payload = {
        "research_version": "cli-1",
        "mode": "research-only",
        "authoritative": False,
        "cve": stored["cve"],
        "metadata": stored.get("metadata", {}),
        "research": stored["research"],
        "output_path": str(out_dir / f"{CANDIDATE_CVE}.cli.json"),
    }
    return payload


class _BatchHarness:
    """Injectable fakes: research_fn + temp-dir pipeline factory."""

    def __init__(self, tmpdir: str, fail: set[str] | None = None):
        self.tmp = Path(tmpdir)
        self.fail = fail or set()
        self.research_dir = self.tmp / "research"
        self.report_dir = self.tmp / "reports"
        self.pipeline_base = self.tmp / "nuclei"
        self.offline_calls: list[str] = []
        self.watch_calls: list[str] = []

    def research_fn(self, cve_id: str, skip_llm: bool = False) -> dict:
        if cve_id in self.fail:
            raise RuntimeError(f"simulated research failure for {cve_id}")
        if cve_id == CANDIDATE_CVE:
            return _candidate_payload(self.research_dir)
        return _payload(cve_id, _synthetic_research(cve_id), self.research_dir)

    def pipeline_factory(self):
        from ai.researcher.nuclei_pipeline import NucleiPipeline

        harness = self
        base = self.pipeline_base

        class SpyPipeline(NucleiPipeline):
            def __init__(self):
                super().__init__(
                    output_dir=base / "generated",
                    result_dir=base / "results",
                    finding_dir=base / "findings",
                )

            def prepare_offline(self, **kwargs):
                harness.offline_calls.append(kwargs["cve"].title)
                return super().prepare_offline(**kwargs)

            def prepare_for_watch(self, **kwargs):
                harness.watch_calls.append("called")
                raise AssertionError(
                    "prepare_for_watch is forbidden in batch research"
                )

        return SpyPipeline()

    def run(self, cve_ids: list[str]):
        from ai.researcher.cve_batch import run_cve_batch

        return run_cve_batch(
            cve_ids,
            research_fn=self.research_fn,
            pipeline_factory=self.pipeline_factory,
            research_dir=self.research_dir,
            template_dir=TEMPLATE_DIR,
            report_dir=self.report_dir,
        )


def _offline_guards():
    return (
        patch.object(socket, "create_connection", _block),
        patch.object(socket, "socket", _block),
        patch.object(socket, "getaddrinfo", _block),
        patch.object(subprocess, "run", _block),
        patch.object(subprocess, "Popen", _block),
    )


class BatchMultipleCvesTests(unittest.TestCase):
    def test_multiple_cves_all_processed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            guards = _offline_guards()
            for guard in guards:
                guard.start()
            try:
                aggregate = harness.run(
                    [CANDIDATE_CVE, *SYNTHETIC_CVES]
                )
            finally:
                for guard in guards:
                    guard.stop()

        self.assertEqual(aggregate["processed"], 3)
        self.assertEqual(aggregate["failed"], 0)
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            [CANDIDATE_CVE, *SYNTHETIC_CVES],
        )
        for item in aggregate["results"]:
            self.assertEqual(item["research_status"], "completed")
            self.assertIsNone(item["error"])
            self.assertFalse(item["authoritative"])

    def test_one_failure_does_not_abort_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir, fail={SYNTHETIC_CVES[0]})
            aggregate = harness.run([CANDIDATE_CVE, *SYNTHETIC_CVES])

        self.assertEqual(aggregate["processed"], 2)
        self.assertEqual(aggregate["failed"], 1)
        by_cve = {item["cve"]: item for item in aggregate["results"]}
        # Order preserved; the bad CVE is recorded, the rest completed.
        self.assertEqual(
            [item["cve"] for item in aggregate["results"]],
            [CANDIDATE_CVE, *SYNTHETIC_CVES],
        )
        self.assertEqual(by_cve[SYNTHETIC_CVES[0]]["research_status"], "failed")
        self.assertIn("simulated research failure", by_cve[SYNTHETIC_CVES[0]]["error"])
        self.assertEqual(by_cve[CANDIDATE_CVE]["research_status"], "completed")
        self.assertEqual(by_cve[SYNTHETIC_CVES[1]]["research_status"], "completed")

    def test_invalid_cve_recorded_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            aggregate = harness.run(["not-a-cve", CANDIDATE_CVE])

        self.assertEqual(aggregate["processed"], 1)
        self.assertEqual(aggregate["failed"], 1)
        self.assertEqual(aggregate["results"][0]["research_status"], "failed")
        self.assertIn("invalid CVE format", aggregate["results"][0]["error"])
        self.assertEqual(aggregate["results"][1]["research_status"], "completed")


class BatchResultStructureTests(unittest.TestCase):
    def test_deterministic_result_structure(self) -> None:
        from ai.researcher.cve_batch import RESULT_KEYS

        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            first = harness.run([CANDIDATE_CVE, *SYNTHETIC_CVES])
            second = harness.run([CANDIDATE_CVE, *SYNTHETIC_CVES])

        for item in first["results"]:
            self.assertEqual(tuple(item.keys()), RESULT_KEYS)
            self.assertIn(
                item["research_status"], ("completed", "failed")
            )
            # Required fields present with the right shapes.
            self.assertIsInstance(item["cve"], str)
            self.assertIsInstance(item["nuclei_candidate"], bool)
            self.assertIsInstance(item["template_generated"], bool)
            self.assertIsInstance(item["artifacts"], dict)
            self.assertFalse(item["authoritative"])

        # Same inputs -> same per-CVE results (aggregate carries the
        # wall-clock timestamp, so only results are compared).
        self.assertEqual(first["results"], second["results"])

    def test_aggregate_files_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            aggregate = harness.run([CANDIDATE_CVE, SYNTHETIC_CVES[0]])

            aggregate_path = Path(aggregate["artifacts"]["aggregate"])
            report_path = Path(aggregate["artifacts"]["report"])
            self.assertTrue(aggregate_path.exists())
            self.assertTrue(report_path.exists())
            for cve_id in (CANDIDATE_CVE, SYNTHETIC_CVES[0]):
                per_cve = harness.research_dir / f"{cve_id}.batch.json"
                self.assertTrue(per_cve.exists())
                stored = json.loads(per_cve.read_text(encoding="utf-8"))
                self.assertEqual(stored["cve"], cve_id)

    def test_cli_parses_cves_and_file(self) -> None:
        from ai.research_cli import build_parser

        args = build_parser().parse_args(
            ["batch", "--cves", "CVE-2026-1557,CVE-2026-9001"]
        )
        self.assertEqual(args.cves, "CVE-2026-1557,CVE-2026-9001")
        self.assertIsNone(args.file)

        with tempfile.TemporaryDirectory() as tmpdir:
            cve_file = Path(tmpdir) / "cves.txt"
            cve_file.write_text(
                "# comment\nCVE-2026-1557\nCVE-2026-9001\n",
                encoding="utf-8",
            )
            args = build_parser().parse_args(["batch", "--file", str(cve_file)])
            self.assertEqual(args.file, str(cve_file))

    def test_cli_batch_delegates_and_reports_counts(self) -> None:
        from ai.research_cli import main

        fake_aggregate = {
            "processed": 1,
            "failed": 1,
            "results": [
                {
                    "cve": "CVE-2026-9001",
                    "research_status": "completed",
                    "error": None,
                },
                {
                    "cve": "CVE-2026-9002",
                    "research_status": "failed",
                    "error": "RuntimeError: boom",
                },
            ],
            "artifacts": {"aggregate": "agg.json", "report": "rep.md"},
        }
        with patch(
            "ai.researcher.cve_batch.run_cve_batch",
            return_value=fake_aggregate,
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(
                    ["batch", "--cves", "CVE-2026-9001,CVE-2026-9002"]
                )
        output = buf.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("processed=1 failed=1", output)
        self.assertIn("research-only", output)


class SingleCveStillWorksTests(unittest.TestCase):
    def test_single_cve_entry_points_unchanged(self) -> None:
        import inspect

        from ai import research_cli
        from ai.research_cli import build_parser

        # research --cve / --skip-llm surface preserved.
        args = build_parser().parse_args(
            ["research", "--cve", "CVE-2026-1557"]
        )
        self.assertEqual(args.cve, "CVE-2026-1557")
        self.assertFalse(args.skip_llm)
        args = build_parser().parse_args(
            ["research", "--cve", "CVE-2026-1557", "--skip-llm"]
        )
        self.assertTrue(args.skip_llm)

        # Legacy batch --days/--limit surface preserved.
        args = build_parser().parse_args(["batch"])
        self.assertEqual(args.days, 7)
        self.assertEqual(args.limit, 5)

        # Single-CVE worker signature preserved.
        self.assertEqual(
            list(inspect.signature(research_cli._research_single_cve).parameters),
            ["cve_id", "skip_llm"],
        )
        self.assertTrue(hasattr(research_cli, "run_research"))
        self.assertTrue(hasattr(research_cli, "run_batch"))

    def test_single_item_batch_via_injected_research(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            aggregate = harness.run([SYNTHETIC_CVES[0]])

        self.assertEqual(aggregate["processed"], 1)
        self.assertEqual(len(aggregate["results"]), 1)
        self.assertEqual(
            aggregate["results"][0]["research_status"], "completed"
        )


class NucleiOfflineLaneTests(unittest.TestCase):
    def test_candidate_path_uses_prepare_offline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            guards = _offline_guards()
            for guard in guards:
                guard.start()
            try:
                aggregate = harness.run([CANDIDATE_CVE])
            finally:
                for guard in guards:
                    guard.stop()

        # Only the offline lane was used; the live lane never ran.
        self.assertEqual(harness.offline_calls, [CANDIDATE_CVE])
        self.assertEqual(harness.watch_calls, [])

        item = aggregate["results"][0]
        self.assertTrue(item["nuclei_candidate"])
        self.assertEqual(item["decision"], "GOOD_CANDIDATE")
        self.assertGreaterEqual(item["decision_confidence"], 0.85)
        self.assertTrue(item["template_generated"])
        self.assertTrue(item["semantic_validation"]["valid"])
        self.assertEqual(item["semantic_validation"]["errors"], [])

        offline = item["offline_preparation"]
        self.assertEqual(offline["mode"], "research-only-offline")
        self.assertTrue(offline["offline"])
        self.assertFalse(offline["fingerprint_performed"])
        self.assertFalse(offline["nuclei_binary_validated"])
        # Empty offline selection: zero targets, zero executed commands.
        self.assertEqual(offline["target_count"], 0)
        self.assertEqual(offline["run_results"], [])
        self.assertIn("template", item["artifacts"])

    def test_non_candidate_path_skips_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            aggregate = harness.run([SYNTHETIC_CVES[0]])

        item = aggregate["results"][0]
        self.assertFalse(item["nuclei_candidate"])
        self.assertFalse(item["template_generated"])
        self.assertIsNone(item["offline_preparation"])
        self.assertEqual(harness.offline_calls, [])

    def test_prepare_for_watch_never_referenced(self) -> None:
        import ai.researcher.cve_batch as batch_mod

        source = inspect.getsource(batch_mod)
        tree = ast.parse(source)
        referenced = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                referenced.add(node.attr)
            elif isinstance(node, ast.Name):
                referenced.add(node.id)
        for forbidden in (
            "prepare_for_watch",
            "target_selector",
            "subprocess",
            "socket",
            "httpx",
            "SealedFinding",
            "CONFIRMED",
        ):
            self.assertNotIn(forbidden, referenced)


class BatchSafetyTests(unittest.TestCase):
    def _run_guarded(self, harness: _BatchHarness, cve_ids: list[str]):
        guards = _offline_guards()
        for guard in guards:
            guard.start()
        try:
            return harness.run(cve_ids)
        finally:
            for guard in guards:
                guard.stop()

    def test_zero_network_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir, fail={SYNTHETIC_CVES[1]})
            aggregate = self._run_guarded(
                harness, [CANDIDATE_CVE, *SYNTHETIC_CVES]
            )
        # Completed under a full socket/DNS block: no packet can leave.
        self.assertEqual(aggregate["processed"], 2)
        self.assertEqual(aggregate["failed"], 1)

    def test_zero_scanning_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            aggregate = self._run_guarded(
                harness, [CANDIDATE_CVE, SYNTHETIC_CVES[0]]
            )
        self.assertEqual(aggregate["processed"], 2)

    def test_no_authoritative_or_confirmed_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = _BatchHarness(tmpdir)
            aggregate = harness.run([CANDIDATE_CVE, *SYNTHETIC_CVES])

            blob = json.dumps(aggregate).lower()
            for forbidden in (
                "sealed",
                "confirmed",
                "5j",
                "live_http",
                "live_nuclei",
                "ready_for_scan",
            ):
                self.assertNotIn(forbidden, blob)

            for item in aggregate["results"]:
                self.assertFalse(item["authoritative"])
                self.assertNotEqual(item["research_status"], "CONFIRMED")
                offline = item["offline_preparation"] or {}
                for finding in offline.get("findings", []):
                    self.assertFalse(finding["matched"])

            # Written files carry no secrets and no authoritative state.
            canary = "batch-canary-9f31 secret-marker"
            with patch.dict(
                __import__("os").environ,
                {"BATCH_TEST_CANARY": canary},
                clear=False,
            ):
                for path in (
                    *harness.research_dir.glob("*.json"),
                    *harness.report_dir.glob("*.md"),
                ):
                    content = path.read_text(encoding="utf-8")
                    self.assertNotIn(canary, content)
                    lowered = content.lower()
                    self.assertNotIn("sealed", lowered)
                    self.assertNotIn("confirmed", lowered)
                    self.assertNotIn("openrouter_api_key", lowered)
                    self.assertNotIn("watch_mongo_uri", lowered)


if __name__ == "__main__":
    unittest.main()
