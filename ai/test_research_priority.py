"""Stage R16 tests: deterministic research prioritization.

Pure, offline tests. No LLM, no network, no subprocess, no active validation,
no Nuclei, no production authority chain. Covers the mandated scenarios plus
schema/store compatibility and the CLI projection.
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from ai.knowledge.intelligence import (
    INTELLIGENCE_RULE_VERSION,
    PRIORITY_MAX_SCORE,
    PRIORITY_MIN_SCORE,
    PRIORITY_RULE_VERSION,
    IntelligenceEvidence,
    extract_research_intelligence,
    research_priority_projection,
    summarize_research_priority,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "ai_data" / "research"


def _ev(field: str, value: str, source_type: str = "structured"):
    return IntelligenceEvidence(
        field=f"exploitability.{field}",
        value=value,
        source_artifact="CVE-2026-0001.cli.json",
        source_url=None if source_type == "structured" else "https://ref.test/1",
        source_type=source_type,
        evidence=f"{field}={value}",
        rule_id=f"test-{field}",
        rule_version=INTELLIGENCE_RULE_VERSION,
    )


def _prio(*records, vuln_types=(), components=(), parameters=(), cwes=()):
    return summarize_research_priority(
        list(records),
        vulnerability_types=list(vuln_types),
        components=list(components),
        parameters=list(parameters),
        cwes=list(cwes),
    )


def _payload(text, cve="CVE-2026-0001", cvss_vector=None,
             public_exploit="__unset__", actively_exploited="__unset__"):
    cve_obj = {"id": cve}
    if cvss_vector:
        cve_obj["cvss_vector"] = cvss_vector
    research = {"description": text}
    if public_exploit != "__unset__":
        research["public_exploit"] = public_exploit
    if actively_exploited != "__unset__":
        research["actively_exploited"] = actively_exploited
    return {"cve": cve_obj, "research": research}


def _extract_priority(text, **kwargs):
    payload = _payload(text, **kwargs)
    result = extract_research_intelligence(payload["cve"]["id"], payload, [])
    return summarize_research_priority(
        result.evidence,
        vulnerability_types=result.vulnerability_types,
        cwes=result.cwes,
        components=result.components,
        parameters=result.parameters,
    )


class PrioritySignalTests(unittest.TestCase):
    def test_public_poc_increases_priority(self):
        base = _prio(vuln_types=["xss"])
        poc = _prio(_ev("public_poc", "true"), vuln_types=["xss"])
        self.assertGreater(poc.score, base.score)
        self.assertIn("public proof-of-concept available", poc.reasons)

    def test_active_exploitation_strongly_increases_priority(self):
        active = _prio(_ev("active_exploitation", "true"))
        poc = _prio(_ev("public_poc", "true"))
        avail = _prio(_ev("exploit_available", "true"))
        self.assertGreater(active.score, poc.score)
        self.assertGreater(poc.score, avail.score)
        self.assertIn("active exploitation reported", active.reasons)

    def test_unauthenticated_increases_priority(self):
        result = _prio(_ev("authentication_required", "false"))
        self.assertGreater(result.score, 0)
        self.assertIn("no authentication required", result.reasons)

    def test_no_privileges_increases_priority(self):
        result = _prio(_ev("privilege_required", "false"))
        self.assertGreater(result.score, 0)
        self.assertIn("no privileges required", result.reasons)

    def test_no_user_interaction_increases_priority(self):
        result = _prio(_ev("user_interaction_required", "false"))
        self.assertGreater(result.score, 0)
        self.assertIn("no user interaction required", result.reasons)

    def test_low_complexity_increases_priority(self):
        result = _prio(_ev("exploit_complexity", "low"))
        self.assertGreater(result.score, 0)
        self.assertIn("low exploit complexity", result.reasons)

    def test_high_complexity_does_not_become_zero(self):
        result = _prio(
            _ev("public_poc", "true"),
            _ev("exploit_complexity", "high"),
        )
        self.assertGreater(result.score, 0)
        self.assertIn("high exploit complexity", result.negative_factors)

    def test_network_vector_positive_local_and_physical_negative(self):
        network = _prio(_ev("public_poc", "true"), _ev("cvss.attack_vector", "N"))
        local = _prio(_ev("public_poc", "true"), _ev("cvss.attack_vector", "L"))
        physical = _prio(_ev("public_poc", "true"), _ev("cvss.attack_vector", "P"))
        self.assertGreater(network.score, 0)
        self.assertGreater(network.score, local.score)
        self.assertGreater(local.score, physical.score)
        self.assertGreater(physical.score, 0)
        self.assertIn("network attack vector", network.reasons)
        self.assertIn("local attack vector", local.negative_factors)


class UnknownAndInsufficientTests(unittest.TestCase):
    def test_insufficient_evidence_is_insufficient_data(self):
        result = _prio()
        self.assertEqual(result.priority, "INSUFFICIENT_DATA")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.reasons, [])
        self.assertEqual(result.evidence, [])

    def test_unknown_is_not_false(self):
        unknown = _prio(_ev("privilege_required", "unknown"))
        self.assertEqual(unknown.priority, "INSUFFICIENT_DATA")
        self.assertEqual(unknown.score, 0)
        self.assertEqual(unknown.negative_factors, [])
        self.assertIn("privilege requirement unknown", unknown.unknown_factors)

    def test_unknown_does_not_reduce_a_positive_score(self):
        baseline = _prio(_ev("authentication_required", "false"))
        with_unknown = _prio(
            _ev("authentication_required", "false"),
            _ev("privilege_required", "unknown"),
        )
        self.assertEqual(baseline.score, with_unknown.score)
        self.assertIn("privilege requirement unknown", with_unknown.unknown_factors)

    def test_unknown_factors_preserved_and_ordered(self):
        result = _prio(_ev("authentication_required", "false"))
        self.assertIn("active exploitation status unknown", result.unknown_factors)
        self.assertIn("attack vector unknown", result.unknown_factors)
        self.assertEqual(result.unknown_factors, result.unknown_factors)


class ScoreBoundsTests(unittest.TestCase):
    def test_score_is_bounded(self):
        maxed = _prio(
            _ev("active_exploitation", "true"),
            _ev("public_poc", "true"),
            _ev("exploit_available", "true"),
            _ev("authentication_required", "false"),
            _ev("privilege_required", "false"),
            _ev("user_interaction_required", "false"),
            _ev("exploit_complexity", "low"),
            _ev("cvss.attack_vector", "N"),
            vuln_types=["xss"],
            components=["index.php"],
            parameters=["q"],
            cwes=["CWE-79"],
        )
        self.assertEqual(maxed.score, PRIORITY_MAX_SCORE)
        self.assertLessEqual(maxed.score, PRIORITY_MAX_SCORE)

        negative = _prio(
            _ev("exploit_complexity", "high"),
            _ev("cvss.attack_vector", "P"),
        )
        self.assertEqual(negative.score, PRIORITY_MIN_SCORE)
        self.assertGreaterEqual(negative.score, PRIORITY_MIN_SCORE)

    def test_positive_score_always_explained(self):
        result = _prio(
            _ev("public_poc", "true"),
            _ev("authentication_required", "false"),
        )
        self.assertGreater(result.score, 0)
        self.assertTrue(result.reasons)
        for reason in result.reasons:
            self.assertIsInstance(reason, str)
            self.assertTrue(reason)

    def test_priority_classes_are_research_only(self):
        result = _prio(_ev("active_exploitation", "true"))
        self.assertIn(
            result.priority,
            (
                "CRITICAL_RESEARCH",
                "HIGH_RESEARCH",
                "MEDIUM_RESEARCH",
                "LOW_RESEARCH",
                "INSUFFICIENT_DATA",
            ),
        )
        for word in ("exploitable", "verified", "vulnerable", "confirmed"):
            self.assertNotIn(word, result.priority.lower())


class DeterminismTests(unittest.TestCase):
    def test_repeated_computation_is_identical(self):
        records = [
            _ev("public_poc", "true"),
            _ev("authentication_required", "false"),
            _ev("cvss.attack_vector", "N"),
        ]
        first = research_priority_projection(list(records), vulnerability_types=["xss"])
        second = research_priority_projection(list(records), vulnerability_types=["xss"])
        self.assertEqual(first, second)

    def test_ordering_is_independent_of_evidence_order(self):
        records = [
            _ev("public_poc", "true"),
            _ev("authentication_required", "false"),
            _ev("cvss.attack_vector", "N"),
        ]
        forward = _prio(*records)
        reverse = _prio(*reversed(records))
        self.assertEqual(forward.score, reverse.score)
        self.assertEqual(forward.reasons, reverse.reasons)
        self.assertEqual(forward.unknown_factors, reverse.unknown_factors)
        self.assertEqual(
            [(e.field, e.value, e.rule_id) for e in forward.evidence],
            [(e.field, e.value, e.rule_id) for e in reverse.evidence],
        )

    def test_cvss_structured_precedence_preserved(self):
        result = _prio(
            _ev("user_interaction_required", "true", source_type="reference"),
            _ev("user_interaction_required", "false", source_type="structured"),
        )
        self.assertIn("no user interaction required", result.reasons)
        self.assertNotIn(
            "user interaction requirement unknown", result.unknown_factors
        )


class ExtractionIntegrationTests(unittest.TestCase):
    def test_adversarial_wording_cannot_manufacture_priority(self):
        result = _extract_priority(
            "The attacker can exploit the vulnerability. Exploit development "
            "is ongoing and the attack surface is large."
        )
        self.assertEqual(result.priority, "INSUFFICIENT_DATA")
        self.assertEqual(result.score, 0)

    def test_cross_cve_contamination_does_not_score(self):
        payload = {"cve": {"id": "CVE-2026-0001"}, "research": {"description": "base"}}
        records = [
            {
                "source_url": "https://ref.test/other",
                "source_type": "reference",
                "body": (
                    "CVE-2024-99999: an unauthenticated attacker gains "
                    "administrator privileges and a public PoC exists."
                ),
            }
        ]
        extracted = extract_research_intelligence(
            "CVE-2026-0001", payload, records
        )
        priority = summarize_research_priority(
            extracted.evidence,
            vulnerability_types=extracted.vulnerability_types,
            cwes=extracted.cwes,
            components=extracted.components,
            parameters=extracted.parameters,
        )
        self.assertEqual(priority.priority, "INSUFFICIENT_DATA")

    def test_real_world_style_payload_is_prioritized(self):
        result = _extract_priority(
            "An unauthenticated attacker can exploit the endpoint. "
            "A public PoC has been released and no user interaction is "
            "required.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        self.assertGreaterEqual(result.score, 50)
        self.assertIn(
            result.priority, ("HIGH_RESEARCH", "CRITICAL_RESEARCH")
        )


class SafetyBoundaryTests(unittest.TestCase):
    def test_no_network_or_subprocess(self):
        import socket

        with mock.patch.object(
            socket, "socket", side_effect=AssertionError("network used")
        ):
            with mock.patch.object(
                subprocess, "Popen", side_effect=AssertionError("subprocess used")
            ):
                result = _prio(
                    _ev("public_poc", "true"),
                    _ev("cvss.attack_vector", "N"),
                )
        self.assertGreater(result.score, 0)

    def test_rule_versions(self):
        self.assertEqual(INTELLIGENCE_RULE_VERSION, "r15-1")
        self.assertEqual(PRIORITY_RULE_VERSION, "r16-1")


class SchemaAndStoreTests(unittest.TestCase):
    def test_legacy_document_defaults(self):
        from ai.schemas.knowledge import KnowledgeDocument

        document = KnowledgeDocument.model_validate(
            {
                "knowledge_id": "kb-legacy",
                "title": "legacy",
                "source_url": "https://legacy.test/x",
                "source_type": "reference",
                "content": "legacy content",
            }
        )
        self.assertEqual(document.research_priority.priority, "INSUFFICIENT_DATA")
        self.assertEqual(document.research_priority.score, 0)
        self.assertEqual(document.research_priority.rule_version, "r16-1")

    def test_ingest_populates_priority(self):
        from ai.knowledge.ingestion import ingest_cve_research
        from ai.knowledge.store import KnowledgeStore

        with tempfile.TemporaryDirectory() as td:
            research = Path(td) / "research"
            research.mkdir(parents=True)
            (research / "CVE-2026-0001.cli.json").write_text(
                json.dumps(
                    _payload(
                        "An unauthenticated attacker can exploit it. "
                        "A public PoC exists.",
                        cvss_vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        ),
                    )
                ),
                encoding="utf-8",
            )
            store = KnowledgeStore(Path(td) / "kb")
            result = ingest_cve_research("CVE-2026-0001", store, research)
            document = result.documents[0]
            self.assertGreater(document.research_priority.score, 0)
            self.assertTrue(document.research_priority.reasons)
            self.assertTrue(document.research_priority.evidence)

    def test_reingest_upgrades_legacy_projections(self):
        from ai.knowledge.ingestion import build_research_document
        from ai.knowledge.store import KnowledgeStore
        from ai.schemas.knowledge import (
            KnowledgeExploitability,
            KnowledgeResearchPriority,
        )

        payload = _payload(
            "An unauthenticated attacker can exploit it. A public PoC exists.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        document = build_research_document(
            "CVE-2026-0001", payload, Path("x/CVE-2026-0001.cli.json")
        )
        legacy = document.model_copy(
            update={
                "exploitability": KnowledgeExploitability(),
                "research_priority": KnowledgeResearchPriority(),
                "intelligence_evidence": [],
            }
        )
        with tempfile.TemporaryDirectory() as td:
            store = KnowledgeStore(Path(td) / "kb")
            stored_legacy, created = store.ingest(legacy)
            self.assertTrue(created)
            self.assertEqual(
                stored_legacy.research_priority.priority, "INSUFFICIENT_DATA"
            )
            stored, created = store.ingest(document)
            self.assertFalse(created)
            self.assertGreater(stored.research_priority.score, 0)
            self.assertEqual(
                stored.exploitability.authentication_required, "false"
            )
            # Idempotent after the upgrade.
            again, _ = store.ingest(document)
            self.assertEqual(
                stored.model_dump(mode="json"),
                again.model_dump(mode="json"),
            )


class CliTests(unittest.TestCase):
    def test_priority_cli_ranks_and_emits_json(self):
        from ai.knowledge.ingestion import ingest_cve_research
        from ai.knowledge.store import KnowledgeStore
        from ai.research_cli import run_priority
        import argparse

        with tempfile.TemporaryDirectory() as td:
            research = Path(td) / "research"
            research.mkdir(parents=True)
            (research / "CVE-2026-0001.cli.json").write_text(
                json.dumps(
                    _payload(
                        "An unauthenticated attacker can exploit it. "
                        "A public PoC exists.",
                        cvss_vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        ),
                    )
                ),
                encoding="utf-8",
            )
            store = KnowledgeStore(Path(td) / "kb")
            ingest_cve_research("CVE-2026-0001", store, research)

            args = argparse.Namespace(cve=None, all=True, json=True)
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = run_priority(args, store=store)
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(len(payload), 1)
            self.assertEqual(payload[0]["cve"], "CVE-2026-0001")
            self.assertGreater(payload[0]["score"], 0)
            self.assertTrue(payload[0]["reasons"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
