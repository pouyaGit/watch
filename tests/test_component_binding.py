"""Focused tests for deterministic component binding evidence.

No network, no MongoDB, no acquisition, no production watchlist execution.
The evaluator consumes supplied structured evidence records only; the local
Dell snapshot is read-only test data.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ai.research_agent.watchlist_component_binding import (
    BOUND,
    CONFLICTING_EVIDENCE,
    INSUFFICIENT_EVIDENCE,
    RULE_ASSET_COMPONENT_MATCH,
    RULE_ASSET_COMPONENT_PROVENANCE,
    UNBOUND,
    apply_binding_to_candidate,
    evaluate_component_binding,
    reevaluate_with_binding,
)
from ai.research_agent.watchlist_evidence_gaps import (
    COMPONENT_IDENTITY,
    COMPONENT_PROVENANCE,
    MISSING,
    PRESENT,
    TECHNOLOGY_IDENTITY,
    VERSION_IDENTITY,
    analyze_candidate,
)

ASSET_ID = "asset-" + "a" * 16
OTHER_ASSET_ID = "asset-" + "b" * 16
SCOPE = "/wp-content/plugins/"
ASSET = {"asset_identifier": ASSET_ID, "scope_paths": [SCOPE]}
DELL_SNAPSHOT = Path(
    "ai_data/research/watchlist/dell/watch-20260918T144218Z.json"
)


def provenance_record(
    value="wp-smushit",
    *,
    category="PLUGIN",
    evidence_type="INFERRED_PLUGIN",
    evidence_path=None,
    scope_path=None,
    source="COMPONENT_INVENTORY",
    rule_id="r31-2-wp-plugin",
):
    path = (
        evidence_path
        if evidence_path is not None
        else f"/wp-content/plugins/{value}/readme.txt"
    )
    return {
        "kind": "COMPONENT_PROVENANCE",
        "category": category,
        "value": value,
        "evidence_type": evidence_type,
        "evidence_path": path,
        "scope_path": scope_path if scope_path is not None else f"/wp-content/plugins/{value}/",
        "source": source,
        "rule_id": rule_id,
    }


def match_row(
    value="wp-smushit",
    *,
    match_type="PLUGIN",
    source="COMPONENT_INVENTORY",
    asset_id=ASSET_ID,
    evidence=("component_inventory",),
    match_id=None,
):
    row = {
        "kind": "ASSET_MATCH",
        "match_type": match_type,
        "matched_value": value,
        "source": source,
        "asset_identifier": asset_id,
        "confidence": "MEDIUM",
        "evidence": list(evidence),
    }
    if match_id:
        row["match_id"] = match_id
    return row


def dell_shaped_entry():
    return {
        "cve_id": "CVE-2026-1557",
        "program": "dell",
        "match_state": "WEAK",
        "confidence": "MEDIUM",
        "strongest_match_type": "TECHNOLOGY",
        "strongest_confidence": "MEDIUM",
        "matched_component": "",
        "matched_version": "",
        "matched_parameter": "src",
        "match_summary": (
            "Technology match exists, but affected component is not observed."
        ),
        "research_status": "NOT YET SUFFICIENT",
        "version_state": "UNKNOWN",
        "version_association_state": "FAMILY_MISMATCH",
        "version_association_reason": "observed version family mismatch",
        "resolved_blockers": [],
        "remaining_blockers": ["generic_technology_only"],
        "missing": ["PRODUCT", "COMPONENT", "PLUGIN", "VERSION", "PATH"],
        "match_row_count": 2,
        "match_rows": [
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
        "queue": {
            "present": True,
            "queue_id": "rq-" + "a" * 16,
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "CRITICAL_RESEARCH",
            "priority_score": 80,
            "queue_score": 56,
            "blockers": ["only generic technology match"],
            "reasons": ["critical research priority"],
            "unknown_factors": ["asset component/path not observed"],
        },
    }


class TestBindingEvaluation(unittest.TestCase):
    def test_01_explicit_provenance_bound(self):
        result = evaluate_component_binding(
            cve_id="CVE-2026-1557",
            program="dell",
            asset=ASSET,
            evidence=[provenance_record()],
        )
        self.assertEqual(result["state"], BOUND)
        self.assertEqual(result["component"], "wp-smushit")
        self.assertEqual(result["component_category"], "PLUGIN")
        self.assertEqual(result["rule_id"], RULE_ASSET_COMPONENT_PROVENANCE)
        self.assertEqual(result["evidence_ref_count"], 1)
        self.assertTrue(result["evidence_refs"][0]["evidence_ref"].startswith("bref-"))
        self.assertEqual(result["rejected"], [])
        self.assertIn("bound", result["explanation"].lower())

    def test_02_deterministic_fingerprint_bound(self):
        result = evaluate_component_binding(
            asset={"asset_identifier": ASSET_ID, "scope_paths": ["/"]},
            evidence=[
                provenance_record(
                    "ckeditor",
                    category="COMPONENT",
                    evidence_type="INFERRED_COMPONENT",
                    evidence_path="/ckeditor/ckeditor.js",
                    scope_path="/ckeditor/",
                    rule_id="r31-2-editor-bundle",
                )
            ],
        )
        self.assertEqual(result["state"], BOUND)
        self.assertEqual(result["component"], "ckeditor")

        row_result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                match_row(
                    "jquery",
                    match_type="COMPONENT",
                    evidence=("component_inventory", "inventory:jquery"),
                )
            ],
        )
        self.assertEqual(row_result["state"], BOUND)
        self.assertEqual(row_result["rule_id"], RULE_ASSET_COMPONENT_MATCH)
        self.assertEqual(row_result["evidence_ref_count"], 1)

    def test_03_component_elsewhere_not_bound(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[provenance_record(scope_path="/other-surface/")],
        )
        self.assertEqual(result["state"], UNBOUND)
        self.assertEqual(result["component"], "")
        self.assertEqual(result["rejected"][0]["reason"], "SCOPE_MISMATCH")

        other = evaluate_component_binding(
            asset=ASSET,
            evidence=[match_row(asset_id=OTHER_ASSET_ID)],
        )
        self.assertEqual(other["state"], UNBOUND)
        self.assertEqual(other["component"], "")
        self.assertEqual(
            other["rejected"][0]["reason"], "ASSET_IDENTITY_MISMATCH"
        )

    def test_04_wordpress_plus_wp_smushit_elsewhere_no_bind(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                match_row("WordPress", match_type="TECHNOLOGY"),
                provenance_record(scope_path="/other/"),
            ],
        )
        self.assertNotEqual(result["state"], BOUND)
        self.assertEqual(result["component"], "")
        reasons = {item["reason"] for item in result["rejected"]}
        self.assertIn("TECHNOLOGY_IS_NOT_COMPONENT_EVIDENCE", reasons)
        # A technology row carrying a component-looking value never binds.
        sneaky = evaluate_component_binding(
            asset=ASSET,
            evidence=[match_row("wp-smushit", match_type="TECHNOLOGY")],
        )
        self.assertNotEqual(sneaky["state"], BOUND)
        self.assertEqual(sneaky["component"], "")

    def test_05_component_name_in_url_path_no_bind(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                match_row(
                    "/wp-content/plugins/wp-smushit/",
                    match_type="PATH",
                    source="ENDPOINT_INVENTORY",
                ),
                provenance_record(value="", evidence_path="/wp-content/plugins/wp-smushit/readme.txt"),
            ],
        )
        self.assertEqual(result["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(result["component"], "")
        reasons = {item["reason"] for item in result["rejected"]}
        self.assertIn("UNSUPPORTED_MATCH_TYPE", reasons)
        self.assertIn("MISSING_COMPONENT_VALUE", reasons)

    def test_06_component_name_in_hostname_no_bind(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                match_row("wp-smushit.example.com", match_type="TECHNOLOGY"),
                {"host": "wp-smushit.example.com", "component": "wp-smushit"},
                {"component_hint": "wp-smushit", "confidence": "HIGH"},
            ],
        )
        self.assertEqual(result["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(result["component"], "")
        blob = json.dumps(result, sort_keys=True).lower()
        self.assertNotIn("wp-smushit.example.com", blob)
        reasons = {item["reason"] for item in result["rejected"]}
        self.assertIn("UNKNOWN_EVIDENCE_KIND", reasons)

    def test_07_version_association_without_ownership_no_bind(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                {
                    "version": "6.8.3",
                    "technology_family": "WordPress",
                    "component": "",
                    "source": "TECHNOLOGY_INVENTORY",
                    "evidence_type": "STRUCTURED_TECHNOLOGY",
                },
                {
                    "version": "6.8.3",
                    "technology_family": "WordPress",
                    "component": "wp-smushit",
                    "source": "COMPONENT_INVENTORY",
                },
            ],
        )
        self.assertEqual(result["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(result["component"], "")
        reasons = {item["reason"] for item in result["rejected"]}
        self.assertEqual(
            reasons, {"VERSION_ASSOCIATION_IS_NOT_ASSET_BOUND"}
        )

    def test_08_cve_affected_product_text_no_bind(self):
        result = evaluate_component_binding(
            cve_id="CVE-2026-1557",
            asset=ASSET,
            evidence=[
                match_row(
                    "wp-smushit",
                    source="CVE_METADATA",
                    evidence=("nvd_cpe",),
                )
            ],
        )
        self.assertEqual(result["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(result["component"], "")
        self.assertEqual(
            result["rejected"][0]["reason"],
            "CVE_METADATA_IS_NOT_COMPONENT_EVIDENCE",
        )

    def test_09_conflicting_components_not_resolved(self):
        result = evaluate_component_binding(
            asset={"asset_identifier": ASSET_ID, "scope_paths": ["/"]},
            evidence=[
                provenance_record("wp-smushit", scope_path="/wp-smushit/"),
                provenance_record(
                    "ckeditor",
                    category="COMPONENT",
                    evidence_type="INFERRED_COMPONENT",
                    scope_path="/ckeditor/",
                ),
            ],
        )
        self.assertEqual(result["state"], CONFLICTING_EVIDENCE)
        self.assertEqual(result["component"], "")
        self.assertEqual(result["rule_id"], "")
        self.assertEqual(result["evidence_refs"], [])
        components = {item["component"] for item in result["candidate_components"]}
        self.assertEqual(components, {"wp-smushit", "ckeditor"})
        for candidate in result["candidate_components"]:
            self.assertTrue(candidate["evidence_refs"])

    def test_10_missing_provenance_never_bound(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                match_row(evidence=()),
                provenance_record(evidence_path="", scope_path=""),
            ],
        )
        self.assertEqual(result["state"], INSUFFICIENT_EVIDENCE)
        reasons = {item["reason"] for item in result["rejected"]}
        self.assertEqual(reasons, {"MISSING_PROVENANCE"})

    def test_11_empty_evidence_unresolved(self):
        empty = evaluate_component_binding(asset=ASSET, evidence=[])
        self.assertEqual(empty["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(empty["component"], "")
        self.assertIn("no component-binding evidence", empty["explanation"])
        none = evaluate_component_binding(asset=ASSET, evidence=None)
        self.assertEqual(none["state"], INSUFFICIENT_EVIDENCE)

    def test_12_deterministic_repeated_execution(self):
        evidence = [provenance_record(), match_row()]
        first = evaluate_component_binding(
            cve_id="CVE-2026-1557", program="dell", asset=ASSET, evidence=evidence
        )
        second = evaluate_component_binding(
            cve_id="CVE-2026-1557", program="dell", asset=ASSET, evidence=evidence
        )
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    def test_13_stable_evidence_reference_ordering(self):
        first_row = match_row(
            "jquery", match_type="COMPONENT", match_id="am-" + "1" * 16
        )
        second_row = match_row(
            "jquery", match_type="COMPONENT", match_id="am-" + "2" * 16
        )
        forward = evaluate_component_binding(
            asset=ASSET, evidence=[first_row, second_row]
        )
        reverse = evaluate_component_binding(
            asset=ASSET, evidence=[second_row, first_row]
        )
        self.assertEqual(forward, reverse)
        refs = [item["evidence_ref"] for item in forward["evidence_refs"]]
        self.assertEqual(refs, sorted(refs))
        self.assertEqual(len(refs), 2)

        conflict_forward = evaluate_component_binding(
            asset={"asset_identifier": ASSET_ID, "scope_paths": ["/"]},
            evidence=[
                provenance_record("zeta", scope_path="/zeta/"),
                provenance_record("alpha", scope_path="/alpha/"),
            ],
        )
        conflict_reverse = evaluate_component_binding(
            asset={"asset_identifier": ASSET_ID, "scope_paths": ["/"]},
            evidence=[
                provenance_record("alpha", scope_path="/alpha/"),
                provenance_record("zeta", scope_path="/zeta/"),
            ],
        )
        self.assertEqual(conflict_forward, conflict_reverse)

    def test_14_junk_fields_cannot_bind(self):
        result = evaluate_component_binding(
            asset=ASSET,
            evidence=[
                {
                    "kind": "MADE_UP",
                    "component": "wp-smushit",
                    "asset_identifier": ASSET_ID,
                    "evidence": ["x"],
                },
                {"guessed_component": "wp-smushit"},
                {"component_hint": "wp-smushit", "confidence": "HIGH"},
                {"kind": "ASSET_MATCH", "match_type": "COMPONENT"},
            ],
        )
        self.assertEqual(result["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(result["component"], "")
        self.assertNotIn("guessed_component", json.dumps(result, sort_keys=True))

    def test_15_real_local_dell_snapshot_unresolved(self):
        self.assertTrue(DELL_SNAPSHOT.exists(), "local snapshot missing")
        snapshot = json.loads(DELL_SNAPSHOT.read_text(encoding="utf-8"))
        entry = snapshot["entries"][0]
        before = copy.deepcopy(entry)
        records = [
            {"kind": "ASSET_MATCH", **row} for row in entry["match_rows"]
        ]
        binding = evaluate_component_binding(
            cve_id=entry["cve_id"],
            program=snapshot["program"],
            asset={"asset_identifier": "", "scope_paths": []},
            evidence=records,
        )
        self.assertEqual(binding["state"], INSUFFICIENT_EVIDENCE)
        self.assertEqual(binding["component"], "")
        blob = json.dumps(binding, sort_keys=True).lower()
        self.assertNotIn("wp-smushit", blob)
        self.assertNotIn("tinymce", blob)
        reasons = {item["reason"] for item in binding["rejected"]}
        self.assertIn("UNSUPPORTED_MATCH_TYPE", reasons)
        self.assertIn("TECHNOLOGY_IS_NOT_COMPONENT_EVIDENCE", reasons)

        reevaluation = reevaluate_with_binding(entry, binding)
        updated = {
            dim["evidence_type"]: dim["state"]
            for dim in reevaluation["updated_gap"]["dimensions"]
        }
        self.assertEqual(updated[COMPONENT_IDENTITY], MISSING)
        self.assertEqual(updated[VERSION_IDENTITY], MISSING)
        self.assertFalse(reevaluation["changed"])
        self.assertEqual(entry, before)


class TestGapIntegration(unittest.TestCase):
    def test_16_bound_binding_consumed_as_component_evidence(self):
        candidate = dell_shaped_entry()
        before = copy.deepcopy(candidate)
        binding = evaluate_component_binding(
            cve_id="CVE-2026-1557",
            program="dell",
            asset=ASSET,
            evidence=[provenance_record()],
        )
        self.assertEqual(binding["state"], BOUND)
        reevaluation = reevaluate_with_binding(candidate, binding)
        updated = {
            dim["evidence_type"]: dim["state"]
            for dim in reevaluation["updated_gap"]["dimensions"]
        }
        self.assertEqual(updated[COMPONENT_IDENTITY], PRESENT)
        self.assertEqual(updated[COMPONENT_PROVENANCE], PRESENT)
        # Component binding never implies version identity.
        self.assertEqual(updated[VERSION_IDENTITY], MISSING)
        self.assertEqual(updated[TECHNOLOGY_IDENTITY], "PARTIAL")
        self.assertTrue(reevaluation["changed"])
        self.assertEqual(candidate, before)

    def test_17_unresolved_binding_leaves_gap_unchanged(self):
        candidate = dell_shaped_entry()
        binding = evaluate_component_binding(
            asset=ASSET,
            evidence=[provenance_record(scope_path="/other/")],
        )
        self.assertEqual(binding["state"], UNBOUND)
        reevaluation = reevaluate_with_binding(candidate, binding)
        updated = {
            dim["evidence_type"]: dim["state"]
            for dim in reevaluation["updated_gap"]["dimensions"]
        }
        self.assertEqual(updated[COMPONENT_IDENTITY], MISSING)
        self.assertFalse(reevaluation["changed"])

    def test_18_existing_component_conflict_not_overwritten(self):
        candidate = dell_shaped_entry()
        candidate["matched_component"] = "jquery"
        binding = evaluate_component_binding(
            asset=ASSET, evidence=[provenance_record()]
        )
        applied = apply_binding_to_candidate(candidate, binding)
        self.assertEqual(applied["matched_component"], "jquery")
        self.assertFalse(applied["component_binding"]["applied"])
        self.assertEqual(
            applied["component_binding"]["apply_reason"],
            "EXISTING_COMPONENT_CONFLICT",
        )


def _cli_args(root, **overrides):
    values = {
        "program": "dell",
        "cve": "",
        "snapshot_root": str(root),
        "snapshot_id": "",
        "asset_id": "",
        "asset_scope": None,
        "evidence_file": "",
        "json": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class TestComponentBindingCli(unittest.TestCase):
    def test_cli_parses_component_binding(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            [
                "agent",
                "component-binding",
                "--program",
                "dell",
                "--cve",
                "CVE-2026-1557",
                "--json",
            ]
        )
        self.assertEqual(args.agent_command, "component-binding")
        self.assertEqual(args.program, "dell")
        self.assertEqual(args.cve, "CVE-2026-1557")
        self.assertTrue(args.json)

    def test_cli_read_only_evaluation(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program_dir = root / "dell"
            program_dir.mkdir(parents=True)
            snapshot = {
                "snapshot_id": "watch-20260918T144218Z",
                "program": "dell",
                "entries": [dell_shaped_entry()],
            }
            snapshot_path = program_dir / "watch-20260918T144218Z.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            before = snapshot_path.read_bytes()

            # Default: projections only -> unresolved, nothing written.
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_component_binding(_cli_args(root))
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["cve_count"], 1)
            self.assertEqual(
                payload["candidates"][0]["binding"]["state"],
                INSUFFICIENT_EVIDENCE,
            )
            self.assertEqual(sorted(p.name for p in program_dir.iterdir()), ["watch-20260918T144218Z.json"])
            self.assertEqual(snapshot_path.read_bytes(), before)

            # Explicit provenance evidence file + asset scope -> BOUND.
            evidence_path = root / "binding-evidence.json"
            evidence_path.write_text(
                json.dumps([provenance_record()]), encoding="utf-8"
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_component_binding(
                    _cli_args(
                        root,
                        asset_scope=[SCOPE],
                        evidence_file=str(evidence_path),
                    )
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            binding = payload["candidates"][0]["binding"]
            self.assertEqual(binding["state"], BOUND)
            self.assertEqual(binding["component"], "wp-smushit")
            self.assertEqual(
                payload["candidates"][0]["reevaluation"]["updated_gap"][
                    "finding_readiness"
                ],
                "INSUFFICIENT_EVIDENCE",
            )
            self.assertEqual(snapshot_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
