"""Focused tests for the local watchlist evidence-gap intelligence layer.

No MongoDB, no network, no VPS, no production, no real Dell watchlist
execution. The analyzer operates on supplied structured data only; the
Dell-shaped fixture below is static test data, not production logic.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import unittest
from contextlib import redirect_stdout

from ai.research_agent.watchlist_evidence_gaps import (
    COMPONENT_IDENTITY,
    COMPONENT_PROVENANCE,
    CVE_WATCH_SIGNAL,
    DIMENSIONS,
    INSUFFICIENT_EVIDENCE,
    MATCH_STATE,
    MISSING,
    NOT_APPLICABLE,
    PARTIAL,
    PRESENT,
    READINESS_PARTIAL,
    READINESS_READY,
    SOURCE_CONTEXT,
    TECHNOLOGY_IDENTITY,
    VERSION_ASSOCIATION,
    VERSION_IDENTITY,
    analyze_candidate,
    analyze_snapshot,
)


def make_entry(**overrides):
    entry = {
        "cve_id": "CVE-2020-11022",
        "program": "dell",
        "match_state": "SUPPORTED",
        "confidence": "MEDIUM",
        "strongest_match_type": "COMPONENT",
        "strongest_confidence": "MEDIUM",
        "matched_component": "jquery",
        "matched_version": "1.12.4",
        "matched_parameter": "",
        "match_summary": "Component and version observed in inventory.",
        "research_status": "NOT YET SUFFICIENT",
        "version_state": "MATCH",
        "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
        "version_association_reason": "",
        "resolved_blockers": [],
        "remaining_blockers": [],
        "missing": [],
        "match_row_count": 3,
        "match_rows": [
            {
                "match_id": "am-" + "1" * 16,
                "match_type": "TECHNOLOGY",
                "matched_value": "JavaScript",
                "confidence": "MEDIUM",
            },
            {
                "match_id": "am-" + "2" * 16,
                "match_type": "COMPONENT",
                "matched_value": "jquery",
                "confidence": "MEDIUM",
            },
            {
                "match_id": "am-" + "3" * 16,
                "match_type": "VERSION",
                "matched_value": "1.12.4",
                "confidence": "MEDIUM",
            },
        ],
        "queue": {
            "present": True,
            "queue_id": "rq-" + "a" * 16,
            "relevance": "MEDIUM",
            "relevance_score": 40,
            "priority_class": "MEDIUM_RESEARCH",
            "priority_score": 50,
            "queue_score": 45,
            "blockers": [],
            "reasons": ["technology match"],
            "unknown_factors": [],
        },
        "fingerprint": "wf-" + "0" * 16,
        "delta": "UNCHANGED",
    }
    entry.update(overrides)
    return entry


def state_of(result, evidence_type):
    for dimension in result["dimensions"]:
        if dimension["evidence_type"] == evidence_type:
            return dimension["state"]
    raise AssertionError(f"unknown dimension: {evidence_type}")


def dell_shaped_entry():
    """Static Dell-shaped fixture mirroring local snapshot content.

    Technology (WordPress) observed via a generic-only match, no component
    binding, no version identity, CVE watch signal present. Mirrors the
    structure of ``ai_data/research/watchlist/dell/`` entries without
    reading production data or running watchlist logic.
    """
    return make_entry(
        cve_id="CVE-2026-1557",
        match_state="WEAK",
        confidence="MEDIUM",
        strongest_match_type="TECHNOLOGY",
        strongest_confidence="MEDIUM",
        matched_component="",
        matched_version="",
        matched_parameter="src",
        match_summary=(
            "Technology match exists, but affected component is not observed."
        ),
        version_state="UNKNOWN",
        version_association_state="FAMILY_MISMATCH",
        version_association_reason="observed version family mismatch",
        remaining_blockers=[
            "generic_technology_only",
            "plugin_not_observed",
            "component_not_observed",
            "version_unknown",
        ],
        missing=["PRODUCT", "COMPONENT", "PLUGIN", "VERSION", "PATH"],
        match_row_count=2,
        match_rows=[
            {
                "match_id": "am-6801b0d58e95c2d0",
                "match_type": "PARAMETER",
                "matched_value": "src",
                "confidence": "MEDIUM",
            },
            {
                "match_id": "am-2cf8fb279dde4632",
                "match_type": "TECHNOLOGY",
                "matched_value": "WordPress",
                "confidence": "MEDIUM",
            },
        ],
        queue={
            "present": True,
            "queue_id": "rq-075e9ef25c8f94a7",
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "CRITICAL_RESEARCH",
            "priority_score": 80,
            "queue_score": 56,
            "blockers": ["only generic technology match"],
            "reasons": ["critical research priority"],
            "unknown_factors": ["asset component/path not observed"],
        },
    )


class TestEvidenceGaps(unittest.TestCase):
    def test_01_fully_sufficient_evidence(self):
        result = analyze_candidate(make_entry())
        self.assertEqual(result["finding_readiness"], READINESS_READY)
        self.assertEqual(result["evidence_state"], "COMPLETE")
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["partial"], [])
        self.assertEqual(len(result["present"]), len(DIMENSIONS))
        self.assertEqual(result["acquisition_plan"], [])

    def test_02_technology_present_but_component_missing(self):
        result = analyze_candidate(
            make_entry(
                matched_component="",
                match_rows=[
                    {
                        "match_id": "am-" + "1" * 16,
                        "match_type": "TECHNOLOGY",
                        "matched_value": "WordPress",
                        "confidence": "MEDIUM",
                    }
                ],
            )
        )
        # WordPress technology evidence is preserved ...
        self.assertEqual(state_of(result, TECHNOLOGY_IDENTITY), PRESENT)
        # ... but the missing component binding is NOT converted into a match.
        self.assertEqual(state_of(result, COMPONENT_IDENTITY), MISSING)
        self.assertEqual(state_of(result, COMPONENT_PROVENANCE), NOT_APPLICABLE)
        self.assertEqual(result["finding_readiness"], INSUFFICIENT_EVIDENCE)
        self.assertIn(COMPONENT_IDENTITY, result["missing"])
        plan_types = [item["evidence_type"] for item in result["acquisition_plan"]]
        self.assertIn(COMPONENT_IDENTITY, plan_types)

    def test_03_component_present_but_version_missing(self):
        result = analyze_candidate(
            make_entry(
                matched_version="",
                version_state="UNKNOWN",
                version_association_state="",
                match_rows=[
                    {
                        "match_id": "am-" + "2" * 16,
                        "match_type": "COMPONENT",
                        "matched_value": "jquery",
                        "confidence": "MEDIUM",
                    }
                ],
            )
        )
        self.assertEqual(state_of(result, COMPONENT_IDENTITY), PRESENT)
        self.assertEqual(state_of(result, VERSION_IDENTITY), MISSING)
        self.assertEqual(result["finding_readiness"], INSUFFICIENT_EVIDENCE)
        self.assertIn(VERSION_IDENTITY, result["missing"])

    def test_04_version_association_without_component_ownership(self):
        result = analyze_candidate(
            make_entry(
                matched_component="",
                matched_version="",
                version_state="UNKNOWN",
                version_association_state="VERSION_MATCH_WITHIN_SAME_FAMILY",
                match_rows=[
                    {
                        "match_id": "am-" + "1" * 16,
                        "match_type": "TECHNOLOGY",
                        "matched_value": "WordPress",
                        "confidence": "MEDIUM",
                    }
                ],
            )
        )
        # Association signal exists ...
        self.assertEqual(state_of(result, VERSION_ASSOCIATION), PRESENT)
        # ... but it must NOT become component-specific evidence.
        self.assertEqual(state_of(result, COMPONENT_IDENTITY), MISSING)
        self.assertEqual(state_of(result, COMPONENT_PROVENANCE), NOT_APPLICABLE)
        self.assertEqual(result["finding_readiness"], INSUFFICIENT_EVIDENCE)

    def test_05_multiple_simultaneous_gaps(self):
        result = analyze_candidate(
            make_entry(
                matched_component="",
                matched_version="",
                match_state="UNKNOWN",
                version_state="UNKNOWN",
                version_association_state="",
                match_rows=[],
                queue={"present": True},
            )
        )
        self.assertGreaterEqual(len(result["missing"]), 3)
        self.assertIn(COMPONENT_IDENTITY, result["missing"])
        self.assertIn(VERSION_IDENTITY, result["missing"])
        self.assertIn(MATCH_STATE, result["missing"])
        self.assertEqual(
            len(result["acquisition_plan"]),
            len(result["missing"]) + len(result["partial"]),
        )
        for item in result["acquisition_plan"]:
            self.assertTrue(item["acquisition_strategy"])

    def test_06_no_evidence(self):
        result = analyze_candidate(
            make_entry(
                cve_id="",
                match_state="UNKNOWN",
                matched_component="",
                matched_version="",
                version_state="UNKNOWN",
                version_association_state="",
                match_rows=[],
                queue={"present": False},
            )
        )
        self.assertEqual(result["finding_readiness"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(result["evidence_state"], "ABSENT")
        self.assertEqual(result["present"], [])
        for dimension in result["dimensions"]:
            if dimension["evidence_type"] == COMPONENT_PROVENANCE:
                self.assertEqual(dimension["state"], NOT_APPLICABLE)
            else:
                self.assertEqual(dimension["state"], MISSING)

    def test_07_not_applicable_dimensions(self):
        result = analyze_candidate(
            make_entry(
                matched_component="",
                match_rows=[
                    {
                        "match_id": "am-" + "1" * 16,
                        "match_type": "TECHNOLOGY",
                        "matched_value": "WordPress",
                        "confidence": "MEDIUM",
                    }
                ],
            )
        )
        self.assertEqual(state_of(result, COMPONENT_PROVENANCE), NOT_APPLICABLE)
        self.assertIn(COMPONENT_PROVENANCE, result["not_applicable"])
        plan_types = [item["evidence_type"] for item in result["acquisition_plan"]]
        self.assertNotIn(COMPONENT_PROVENANCE, plan_types)
        for dimension in result["dimensions"]:
            if dimension["evidence_type"] == COMPONENT_PROVENANCE:
                self.assertIsNone(dimension["acquisition_strategy"])

    def test_08_deterministic_ordering(self):
        first = analyze_candidate(dell_shaped_entry())
        second = analyze_candidate(dell_shaped_entry())
        self.assertEqual(first, second)
        self.assertEqual(
            [item["evidence_type"] for item in first["dimensions"]],
            list(DIMENSIONS),
        )
        plan_types = [item["evidence_type"] for item in first["acquisition_plan"]]
        self.assertEqual(plan_types, sorted(plan_types, key=list(DIMENSIONS).index))

    def test_09_unknown_fields_never_become_evidence(self):
        entry = dell_shaped_entry()
        entry["exploitable"] = True
        entry["confirmed"] = True
        entry["component_proof"] = "jquery"
        entry["mystery_evidence"] = {"COMPONENT_IDENTITY": "PRESENT"}
        result = analyze_candidate(entry)
        for dimension in result["dimensions"]:
            self.assertNotIn("exploit", dimension["reason"].lower())
            self.assertNotIn("confirm", dimension["reason"].lower())
        blob = json.dumps(result, sort_keys=True).lower()
        self.assertNotIn("exploitable", blob)
        self.assertNotIn('"confirmed"', blob)
        self.assertEqual(state_of(result, COMPONENT_IDENTITY), MISSING)
        self.assertEqual(result["finding_readiness"], INSUFFICIENT_EVIDENCE)

    def test_10_real_dell_shaped_data(self):
        result = analyze_candidate(dell_shaped_entry())
        # WordPress technology preserved as partial (generic-only match).
        self.assertEqual(state_of(result, TECHNOLOGY_IDENTITY), PARTIAL)
        # Missing component binding and version evidence preserved.
        self.assertEqual(state_of(result, COMPONENT_IDENTITY), MISSING)
        self.assertEqual(state_of(result, VERSION_IDENTITY), MISSING)
        # CVE watch signal preserved.
        self.assertEqual(state_of(result, CVE_WATCH_SIGNAL), PRESENT)
        # No component conclusion drawn from technology evidence.
        self.assertFalse(
            any(
                "jquery" in str(dimension.get("reason", "")).lower()
                for dimension in result["dimensions"]
            )
        )
        self.assertEqual(result["finding_readiness"], INSUFFICIENT_EVIDENCE)

    def test_11_no_mutation_of_input(self):
        entry = dell_shaped_entry()
        before = copy.deepcopy(entry)
        analyze_candidate(entry)
        self.assertEqual(entry, before)

    def test_12_snapshot_analysis_is_deterministic_and_sorted(self):
        snapshot = {
            "snapshot_id": "watch-20260918T144218Z",
            "program": "dell",
            "entries": [dell_shaped_entry(), make_entry()],
        }
        first = analyze_snapshot(snapshot)
        second = analyze_snapshot(snapshot)
        self.assertEqual(first, second)
        self.assertEqual(
            [item["cve_id"] for item in first["candidates"]],
            sorted(item["cve_id"] for item in first["candidates"]),
        )
        self.assertEqual(first["cve_count"], 2)
        total = sum(first["readiness_counts"].values())
        self.assertEqual(total, 2)


class TestEvidenceGapsCli(unittest.TestCase):
    def test_cli_parses_evidence_gaps(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            ["agent", "evidence-gaps", "--program", "dell", "--json"]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "evidence-gaps")
        self.assertEqual(args.program, "dell")
        self.assertTrue(args.json)

    def test_cli_is_read_only(self):
        import tempfile
        from pathlib import Path

        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "watchlist"
            program_dir = root / "dell"
            program_dir.mkdir(parents=True)
            snapshot = {
                "snapshot_id": "watch-20260918T144218Z",
                "program": "dell",
                "entries": [dell_shaped_entry()],
            }
            (program_dir / "watch-20260918T144218Z.json").write_text(
                json.dumps(snapshot), encoding="utf-8"
            )
            before = sorted(path.name for path in program_dir.iterdir())
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_evidence_gaps(
                    argparse.Namespace(
                        program="dell",
                        snapshot_root=str(root),
                        snapshot_id="",
                        cve="",
                        json=True,
                    )
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["cve_count"], 1)
            self.assertEqual(
                payload["candidates"][0]["finding_readiness"],
                INSUFFICIENT_EVIDENCE,
            )
            after = sorted(path.name for path in program_dir.iterdir())
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
