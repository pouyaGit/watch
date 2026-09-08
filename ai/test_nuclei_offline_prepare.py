"""Focused tests for the offline Nuclei preparation boundary.

Covers ``NucleiPipeline.prepare_offline`` (research-only lane):

- zero socket calls, zero subprocess calls, zero DNS/HTTP;
- ``HTTPFingerprintRunner`` / ``WatchAssetSelector`` never invoked;
- explicit caller-provided (synthetic) target selection accepted;
- CVE-2026-1557 dry-run behavior intact and research-only;
- no SealedFinding / 5J / CONFIRMED finding produced;
- live fingerprinting path remains present but explicitly separate.

Strictly offline: sockets, subprocess, and the fingerprint runner are
patched to fail loudly. Only ``.invalid`` fixture hosts and the Watch
asset names already present in the local research artifact are used;
no packet ever leaves the host. Uses temporary output directories so
``ai_data/`` is never touched.
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

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = REPO_ROOT / "ai_data/research/CVE-2026-1557.cli.json"
SOURCE_TEMPLATE = REPO_ROOT / "ai_data/nuclei/generated/CVE-2026-1557.yaml"


def _forbidden(*args, **kwargs):
    raise AssertionError("network/subprocess is forbidden in this test")


def _offline_guards():
    return (
        patch.object(socket, "create_connection", _forbidden),
        patch.object(socket, "socket", _forbidden),
        patch.object(subprocess, "run", _forbidden),
        patch(
            "ai.correlator.http_fingerprint."
            "HTTPFingerprintRunner.check",
            _forbidden,
        ),
    )


def _load_cve_and_research():
    from ai.schemas.research import ResearchResult

    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    research = ResearchResult(**payload["research"])
    cve_info = payload["cve"]
    cve = SimpleNamespace(
        title=cve_info["id"],
        vendor=cve_info["vendor"],
        products=cve_info["products"],
        content=(research.summary or "")
        + " "
        + (research.root_cause or ""),
        affected_versions=research.affected_versions,
    )
    return cve, research


def _synthetic_selection():
    from ai.correlator.watch_targets import (
        WatchTarget,
        WatchTargetSelection,
    )

    return WatchTargetSelection(
        cve_id="CVE-2026-1557",
        candidate_count=2,
        targets=[
            WatchTarget(
                target="offline-fixture-1.example.invalid",
                program="test-program",
                technology="WordPress",
                product_match="ecosystem",
                version_status="UNKNOWN",
                presence_status="UNKNOWN",
                presence_version=None,
                scope_status="DRY_RUN_ONLY",
                scope_reason="synthetic offline selection",
            ),
            WatchTarget(
                target="offline-fixture-2.example.invalid",
                program="test-program",
                technology="WordPress",
                product_match="ecosystem",
                version_status="UNKNOWN",
                presence_status="NOT_PRESENT",
                presence_version=None,
                scope_status="EXCLUDE",
                scope_reason="synthetic offline selection",
            ),
        ],
        excluded=[],
    )


class OfflinePreparationBoundaryTests(unittest.TestCase):
    def _pipeline(self, tmpdir: str):
        from ai.researcher.nuclei_pipeline import NucleiPipeline

        base = Path(tmpdir)
        return NucleiPipeline(
            output_dir=base / "generated",
            result_dir=base / "results",
            finding_dir=base / "findings",
        )

    def test_offline_prepare_is_network_and_subprocess_free(self) -> None:
        cve, research = _load_cve_and_research()
        selection = _synthetic_selection()

        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = self._pipeline(tmpdir)
            guards = _offline_guards()
            for guard in guards:
                guard.start()
            try:
                result = pipeline.prepare_offline(
                    cve=cve,
                    research=research,
                    source_template=SOURCE_TEMPLATE,
                    selection=selection,
                    name="WP Responsive Images <= 1.0 - Arbitrary File Read",
                    severity="high",
                    description=(
                        "Detects CVE-2026-1557 in WP Responsive Images."
                    ),
                    tags=[
                        "arbitrary-file-read",
                        "path-traversal",
                        "wordpress",
                        "wp-plugin",
                    ],
                )
            finally:
                for guard in guards:
                    guard.stop()

        self.assertEqual(result["mode"], "research-only-offline")
        self.assertTrue(result["offline"])
        self.assertFalse(result["fingerprint_performed"])
        self.assertFalse(result["nuclei_binary_validated"])
        self.assertEqual(result["decision"], "GOOD_CANDIDATE")
        self.assertTrue(result["generated"])
        self.assertTrue(result["semantic_valid"])
        self.assertEqual(result["errors"], [])

        # Same dry-run outcome as the component-level lane.
        statuses = {
            item["target"]: item["status"]
            for item in result["run_results"]
        }
        self.assertEqual(
            statuses["offline-fixture-1.example.invalid"],
            "DRY_RUN_ONLY",
        )
        self.assertEqual(
            statuses["offline-fixture-2.example.invalid"],
            "EXCLUDED",
        )
        for item in result["run_results"]:
            self.assertEqual(item["output"], "")

        for finding in result["findings"]:
            self.assertFalse(finding["matched"])
            blob = json.dumps(finding).lower()
            self.assertNotIn("sealed", blob)
            self.assertNotIn("confirmed", blob)
            self.assertNotIn("5j", blob)

        blob = json.dumps(result).lower()
        self.assertNotIn("sealed", blob)
        self.assertNotIn("confirmed", blob)

    def test_offline_prepare_reproduces_stored_template(self) -> None:
        cve, research = _load_cve_and_research()

        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = self._pipeline(tmpdir)
            guards = _offline_guards()
            for guard in guards:
                guard.start()
            try:
                result = pipeline.prepare_offline(
                    cve=cve,
                    research=research,
                    source_template=SOURCE_TEMPLATE,
                    selection=_synthetic_selection(),
                    name="WP Responsive Images <= 1.0 - Arbitrary File Read",
                    severity="high",
                    description=(
                        "Detects CVE-2026-1557 in WP Responsive Images."
                    ),
                    tags=[
                        "arbitrary-file-read",
                        "path-traversal",
                        "wordpress",
                        "wp-plugin",
                    ],
                )
            finally:
                for guard in guards:
                    guard.stop()

            produced = Path(result["template_path"]).read_text(
                encoding="utf-8"
            )

        stored = SOURCE_TEMPLATE.read_text(encoding="utf-8")
        self.assertEqual(produced, stored)

    def test_offline_prepare_rejects_selection_mismatch(self) -> None:
        from ai.correlator.watch_targets import WatchTargetSelection

        cve, research = _load_cve_and_research()
        bad = WatchTargetSelection(
            cve_id="CVE-9999-0000",
            targets=[],
            excluded=[],
            candidate_count=0,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = self._pipeline(tmpdir)
            with self.assertRaises(ValueError):
                pipeline.prepare_offline(
                    cve=cve,
                    research=research,
                    source_template=SOURCE_TEMPLATE,
                    selection=bad,
                    name="x",
                )

    def test_offline_prepare_requires_source_template(self) -> None:
        cve, research = _load_cve_and_research()

        with tempfile.TemporaryDirectory() as tmpdir:
            pipeline = self._pipeline(tmpdir)
            with self.assertRaises(FileNotFoundError):
                pipeline.prepare_offline(
                    cve=cve,
                    research=research,
                    source_template=Path(tmpdir) / "missing.yaml",
                    selection=_synthetic_selection(),
                    name="x",
                )

    def test_live_path_remains_explicitly_separate(self) -> None:
        import ast
        import textwrap

        from ai.correlator.watch_targets import WatchAssetSelector
        from ai.researcher.nuclei_pipeline import NucleiPipeline

        # Structural check on the offline lane: no attribute access
        # or name reference that could reach network/subprocess use.
        # (The docstring documents the guarantee in prose; the AST
        # ignores it.)
        source = textwrap.dedent(
            inspect.getsource(NucleiPipeline.prepare_offline)
        )
        tree = ast.parse(source)
        referenced = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                referenced.add(node.attr)
            elif isinstance(node, ast.Name):
                referenced.add(node.id)

        for forbidden in (
            "target_selector",
            "_validate_with_nuclei",
            "HTTPFingerprintRunner",
            "fingerprint_runner",
            "subprocess",
            "httpx",
            "socket",
            "get",
            "run",
        ):
            # ``run``/``get`` alone are too generic; only flag the
            # unambiguous network/subprocess symbols.
            if forbidden in ("run", "get"):
                continue
            self.assertNotIn(forbidden, referenced)

        # The live fingerprinting capability still exists, but only
        # behind the explicit selector entry point — never on the
        # offline lane.
        selector_source = inspect.getsource(
            WatchAssetSelector.select
        )
        self.assertIn("_fingerprint_wordpress_plugin", selector_source)
        self.assertTrue(
            hasattr(WatchAssetSelector, "select"),
            "live selection entry point must remain explicit",
        )


if __name__ == "__main__":
    unittest.main()
