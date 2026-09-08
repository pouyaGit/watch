"""Focused RESEARCH-ONLY validation of the CVE -> Nuclei candidate flow.

Uses the successful research artifact
``ai_data/research/CVE-2026-1557.cli.json`` and exercises only the
existing offline components:

- NucleiTemplateParser (YAML parsing, no execution)
- NucleiDecisionEngine (candidate decision)
- NucleiTemplateGenerator (YAML generation, no execution)
- NucleiSemanticValidator (spec round-trip check)
- NucleiRunner.dry_run / run(execute=False) (command construction only)

Strictly offline: sockets and subprocess are blocked for the whole
test case, so any live HTTP request or Nuclei execution attempt fails
the test. WatchAssetSelector.select is intentionally never called
(it can perform live HTTP fingerprinting); a synthetic offline
selection with non-READY scope states is used instead.

No 5J SealedFinding, no CONFIRMED finding, no live gate is touched.
"""

from __future__ import annotations

import json
import socket
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = REPO_ROOT / "ai_data/research/CVE-2026-1557.cli.json"
TEMPLATE = REPO_ROOT / "ai_data/nuclei/generated/CVE-2026-1557.yaml"

EXPECTED_PATH = "/wp-content/plugins/wp-responsive-images/image_handler.php"


def _block(*args, **kwargs):
    raise AssertionError("network/subprocess is forbidden in this test")


class Cve20261557ResearchOnlyFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
        cls.payload = payload
        cls.research_payload = payload["research"]

        from ai.schemas.research import ResearchResult

        cls.research = ResearchResult(**payload["research"])
        cve_info = payload["cve"]
        cls.cve = SimpleNamespace(
            title=cve_info["id"],
            vendor=cve_info["vendor"],
            products=cve_info["products"],
            content=(
                cls.research.summary or ""
            )
            + " "
            + (cls.research.root_cause or ""),
            affected_versions=cls.research.affected_versions,
        )

    def test_artifact_is_research_only(self) -> None:
        self.assertEqual(self.payload["mode"], "research-only")
        self.assertFalse(self.payload["authoritative"])
        self.assertTrue(self.research.nuclei_candidate)
        self.assertIn("CVE-2026-1557", self.research.cve_ids)

    def test_decision_is_good_candidate_offline(self) -> None:
        from ai.collectors.nuclei_template import NucleiTemplateParser
        from ai.correlator.nuclei_decision import NucleiDecisionEngine

        with patch.object(
            socket, "create_connection", _block
        ), patch.object(socket, "socket", _block), patch.object(
            subprocess, "run", _block
        ):
            detection = NucleiTemplateParser().parse(
                content=TEMPLATE.read_text(encoding="utf-8"),
                cve_id="CVE-2026-1557",
            )
            decision = NucleiDecisionEngine().decide(
                cve=self.cve,
                research=self.research,
                detection=detection,
            )

        self.assertEqual(decision.decision, "GOOD_CANDIDATE")
        self.assertTrue(decision.http_detectable)
        self.assertGreaterEqual(decision.confidence, 0.85)

    def test_generate_and_semantic_validate_offline(self) -> None:
        from ai.collectors.nuclei_template import NucleiTemplateParser
        from ai.correlator.nuclei_generator import NucleiTemplateGenerator
        from ai.correlator.nuclei_validator import NucleiSemanticValidator

        stored = TEMPLATE.read_text(encoding="utf-8")
        stored_data = yaml.safe_load(stored)

        with patch.object(
            socket, "create_connection", _block
        ), patch.object(socket, "socket", _block), patch.object(
            subprocess, "run", _block
        ):
            detection = NucleiTemplateParser().parse(
                content=stored,
                cve_id="CVE-2026-1557",
            )
            generated = NucleiTemplateGenerator().generate(
                detection,
                name=stored_data["info"]["name"],
                author=stored_data["info"]["author"],
                severity=stored_data["info"]["severity"],
                description=stored_data["info"]["description"],
                tags=[
                    tag
                    for tag in stored_data["info"]["tags"].split(",")
                    if tag not in ("cve", "generated", "watch-ai")
                ],
            )
            semantic = NucleiSemanticValidator().validate(
                detection,
                generated,
            )

        # Generator output must reproduce the stored research artifact.
        self.assertEqual(generated, stored)
        self.assertTrue(semantic.valid)
        self.assertEqual(semantic.errors, [])

    def test_template_content_is_safe_and_grounded(self) -> None:
        data = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

        self.assertEqual(data["id"], "CVE-2026-1557")
        raw = data["http"][0]["raw"][0]
        request_line = raw.splitlines()[0]
        self.assertTrue(request_line.startswith("GET "))
        self.assertIn(EXPECTED_PATH, request_line)
        self.assertIn("src=", request_line)
        # Single safe GET request; nothing destructive.
        self.assertNotRegex(raw.upper(), r"\b(DELETE|POST|PUT)\b")

        dsl = data["http"][0]["matchers"][0]["dsl"]
        joined = " ".join(dsl)
        self.assertIn("status_code==200", joined)
        self.assertIn("DB_NAME", joined)
        self.assertIn("DB_PASSWORD", joined)

        # No invented product/version detection claims: the template
        # carries no version comparison and references only the CVE id
        # plus the endpoint documented in the research evidence.
        self.assertNotIn("version", json.dumps(data).lower())

    def test_dry_run_never_executes_and_never_confirms(self) -> None:
        from ai.correlator.watch_targets import (
            WatchTarget,
            WatchTargetSelection,
        )
        from ai.researcher.nuclei_runner import NucleiRunner

        selection = WatchTargetSelection(
            cve_id="CVE-2026-1557",
            candidate_count=4,
            targets=[
                WatchTarget(
                    target=target,
                    program=program,
                    technology="WordPress",
                    product_match="ecosystem",
                    version_status="UNKNOWN",
                    presence_status=scope,
                    presence_version=None,
                    scope_status=scope,
                    scope_reason="offline synthetic selection",
                )
                for target, program, scope in (
                    ("hiringlab.indeed.com", "indeed", "EXCLUDE"),
                    ("indeedflex.com", "indeed", "EXCLUDE"),
                    (
                        "dellnetworkingvr.dell.com",
                        "dell",
                        "DRY_RUN_ONLY",
                    ),
                    ("dellservervr.dell.com", "dell", "DRY_RUN_ONLY"),
                )
            ],
            excluded=[],
        )
        runner = NucleiRunner()

        with patch.object(
            socket, "create_connection", _block
        ), patch.object(socket, "socket", _block), patch.object(
            subprocess, "run", _block
        ):
            dry_results = runner.dry_run(
                selection=selection,
                template_path=TEMPLATE,
            )
            gated_results = runner.run(
                selection=selection,
                template_path=TEMPLATE,
                execute=False,
            )
            findings = runner.to_findings(
                cve_id="CVE-2026-1557",
                template_id="CVE-2026-1557",
                severity="high",
                selection=selection,
                results=dry_results,
            )

        self.assertEqual(len(dry_results), 4)
        for result in dry_results:
            self.assertIn(result.status, ("DRY_RUN_ONLY", "EXCLUDED"))
            self.assertEqual(result.output, "")
            # Commands are constructed but never executed.
            self.assertIn("nuclei", result.command[0])
        for result in gated_results:
            self.assertEqual(result.status, "BLOCKED")

        # Research-only: nothing matched, nothing confirmed, and the
        # finding schema carries no authoritative/CONFIRMED state.
        self.assertEqual(len(findings), 4)
        for finding in findings:
            self.assertFalse(finding.matched)
            self.assertEqual(finding.raw_output, "")
            dump = finding.model_dump()
            self.assertNotIn("sealed", json.dumps(dump).lower())
            self.assertNotIn("confirmed", json.dumps(dump).lower())
            self.assertNotIn("5j", json.dumps(dump).lower())


if __name__ == "__main__":
    unittest.main()
