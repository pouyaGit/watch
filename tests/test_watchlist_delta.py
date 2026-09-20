"""Local tests for the watchlist delta intelligence layer.

No MongoDB, no network, no VPS, no production, no real Dell watchlist
execution. Pure structural ``compare_snapshots`` tests plus local CLI
read/``--apply`` behavior against a temporary snapshot root.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ai.research_agent.watchlist_delta import (
    BLOCKERS_CHANGED,
    EVIDENCE_CHANGED,
    MATCH_CHANGED,
    NEW_CVE,
    REMOVED_CVE,
    STATE_CHANGED,
    UNCHANGED,
    compare_snapshots,
)


def make_entry(cve_id, **overrides):
    entry = {
        "cve_id": cve_id,
        "program": "dell",
        "match_state": "WEAK",
        "confidence": "LOW",
        "strongest_match_type": "VERSION",
        "strongest_confidence": "LOW",
        "matched_component": "",
        "matched_version": "1.12.4",
        "matched_parameter": "",
        "match_summary": "Observed version satisfies the affected range.",
        "research_status": "NOT YET SUFFICIENT",
        "version_state": "MATCH",
        "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
        "version_association_reason": "",
        "resolved_blockers": [],
        "remaining_blockers": ["plugin_not_observed"],
        "missing": ["PRODUCT"],
        "match_row_count": 1,
        "match_rows": [
            {
                "match_id": "am-" + "1" * 16,
                "match_type": "VERSION",
                "matched_value": "1.12.4",
                "confidence": "LOW",
            }
        ],
        "queue": {
            "present": True,
            "queue_id": "rq-" + "a" * 16,
            "relevance": "MEDIUM",
            "relevance_score": 40,
            "priority_class": "MEDIUM_RESEARCH",
            "priority_score": 50,
            "queue_score": 45,
            "blockers": ["asset version unknown"],
            "reasons": ["technology match"],
            "unknown_factors": [],
        },
        "fingerprint": "wf-" + "0" * 16,
        "delta": "UNCHANGED",
    }
    entry.update(overrides)
    return entry


def make_snapshot(snapshot_id, entries, created_utc="2026-09-18T12:00:00Z"):
    return {
        "watchlist_version": "watchlist-1",
        "snapshot_id": snapshot_id,
        "created_utc": created_utc,
        "program": "dell",
        "cve_count": len(entries),
        "entries": entries,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def change_types_for(result, cve_id):
    return sorted(
        item["change_type"] for item in result["changes"] if item["cve_id"] == cve_id
    )


class TestCompareSnapshots(unittest.TestCase):
    def test_01_identical_snapshots(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z", [make_entry("CVE-2020-11022")]
        )
        result = compare_snapshots(previous, current)
        self.assertEqual(result["summary"][UNCHANGED], 1)
        self.assertEqual(result["summary"][NEW_CVE], 0)
        self.assertEqual(
            change_types_for(result, "CVE-2020-11022"), [UNCHANGED]
        )

    def test_02_new_cve(self):
        previous = make_snapshot("watch-20260918T120000Z", [])
        current = make_snapshot(
            "watch-20260918T120100Z", [make_entry("CVE-2020-11022")]
        )
        result = compare_snapshots(previous, current)
        self.assertEqual(result["summary"][NEW_CVE], 1)
        self.assertEqual(
            change_types_for(result, "CVE-2020-11022"), [NEW_CVE]
        )

    def test_03_removed_cve(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot("watch-20260918T120100Z", [])
        result = compare_snapshots(previous, current)
        self.assertEqual(result["summary"][REMOVED_CVE], 1)
        self.assertEqual(
            change_types_for(result, "CVE-2020-11022"), [REMOVED_CVE]
        )

    def test_04_match_state_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", match_state="SUPPORTED")],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(STATE_CHANGED, change_types_for(result, "CVE-2020-11022"))
        self.assertEqual(result["summary"][STATE_CHANGED], 1)

    def test_05_match_row_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [
                make_entry(
                    "CVE-2020-11022",
                    matched_parameter="src",
                    match_rows=[
                        {
                            "match_id": "am-" + "9" * 16,
                            "match_type": "PARAMETER",
                            "matched_value": "src",
                            "confidence": "LOW",
                        }
                    ],
                )
            ],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(MATCH_CHANGED, change_types_for(result, "CVE-2020-11022"))

    def test_06_version_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", matched_version="3.3.1")],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(MATCH_CHANGED, change_types_for(result, "CVE-2020-11022"))

    def test_07_component_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", matched_component="jquery")],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(MATCH_CHANGED, change_types_for(result, "CVE-2020-11022"))

    def test_08_confidence_evidence_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", confidence="HIGH")],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(
            EVIDENCE_CHANGED, change_types_for(result, "CVE-2020-11022")
        )

    def test_09_blocker_added(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [
                make_entry(
                    "CVE-2020-11022",
                    remaining_blockers=["plugin_not_observed", "version_unknown"],
                )
            ],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(
            BLOCKERS_CHANGED, change_types_for(result, "CVE-2020-11022")
        )

    def test_10_blocker_removed(self):
        previous = make_snapshot(
            "watch-20260918T120000Z",
            [
                make_entry(
                    "CVE-2020-11022",
                    remaining_blockers=["plugin_not_observed", "version_unknown"],
                )
            ],
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", remaining_blockers=[])],
        )
        result = compare_snapshots(previous, current)
        self.assertIn(
            BLOCKERS_CHANGED, change_types_for(result, "CVE-2020-11022")
        )

    def test_11_multiple_categories_for_one_cve(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [
                make_entry(
                    "CVE-2020-11022",
                    match_state="SUPPORTED",
                    matched_version="3.3.1",
                    confidence="HIGH",
                    remaining_blockers=["plugin_not_observed", "version_unknown"],
                )
            ],
        )
        types = change_types_for(result := compare_snapshots(previous, current), "CVE-2020-11022")
        self.assertIn(STATE_CHANGED, types)
        self.assertIn(MATCH_CHANGED, types)
        self.assertIn(EVIDENCE_CHANGED, types)
        self.assertIn(BLOCKERS_CHANGED, types)
        self.assertGreaterEqual(len(types), 4)

    def test_12_timestamp_only_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z",
            [make_entry("CVE-2020-11022")],
            created_utc="2026-09-18T12:00:00Z",
        )
        current = make_snapshot(
            "watch-20260918T120000Z",
            [make_entry("CVE-2020-11022")],
            created_utc="2026-09-18T12:05:00Z",
        )
        result = compare_snapshots(previous, current)
        self.assertEqual(
            change_types_for(result, "CVE-2020-11022"), [UNCHANGED]
        )

    def test_13_snapshot_id_only_change(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z", [make_entry("CVE-2020-11022")]
        )
        result = compare_snapshots(previous, current)
        self.assertEqual(result["previous_snapshot_id"], "watch-20260918T120000Z")
        self.assertEqual(result["current_snapshot_id"], "watch-20260918T120100Z")
        self.assertEqual(
            change_types_for(result, "CVE-2020-11022"), [UNCHANGED]
        )

    def test_14_json_ordering_only_change(self):
        base = make_entry("CVE-2020-11022")
        # Same semantic content, different key insertion order and list order.
        reordered = {
            "missing": list(reversed(base["missing"])),
            "remaining_blockers": list(base["remaining_blockers"]),
            "match_rows": list(base["match_rows"]),
            "cve_id": base["cve_id"],
            "program": base["program"],
            "match_state": base["match_state"],
            "confidence": base["confidence"],
            "strongest_match_type": base["strongest_match_type"],
            "strongest_confidence": base["strongest_confidence"],
            "matched_component": base["matched_component"],
            "matched_version": base["matched_version"],
            "matched_parameter": base["matched_parameter"],
            "match_summary": base["match_summary"],
            "research_status": base["research_status"],
            "version_state": base["version_state"],
            "version_association_state": base["version_association_state"],
            "version_association_reason": base["version_association_reason"],
            "resolved_blockers": base["resolved_blockers"],
            "match_row_count": base["match_row_count"],
            "queue": base["queue"],
            "fingerprint": "wf-" + "f" * 16,
            "delta": "NEW",
        }
        # Round-trip through JSON with different key order.
        previous = json.loads(
            json.dumps(make_snapshot("watch-20260918T120000Z", [base]))
        )
        current = json.loads(
            json.dumps(make_snapshot("watch-20260918T120100Z", [reordered]))
        )
        result = compare_snapshots(previous, current)
        self.assertEqual(
            change_types_for(result, "CVE-2020-11022"), [UNCHANGED]
        )

    def test_15_deterministic_ordering(self):
        previous = make_snapshot(
            "watch-20260918T120000Z",
            [make_entry("CVE-2020-11022"), make_entry("CVE-2024-29881")],
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [
                make_entry("CVE-2024-29881", confidence="HIGH"),
                make_entry("CVE-2020-11022", match_state="SUPPORTED"),
            ],
        )
        first = compare_snapshots(previous, current)
        second = compare_snapshots(previous, current)
        self.assertEqual(first, second)
        keys = [(item["cve_id"], item["change_type"]) for item in first["changes"]]
        self.assertEqual(keys, sorted(keys))

    def test_16_empty_previous_snapshot(self):
        result = compare_snapshots(
            {}, make_snapshot("watch-20260918T120100Z", [make_entry("CVE-2020-11022")])
        )
        self.assertEqual(result["summary"][NEW_CVE], 1)
        self.assertEqual(result["previous_snapshot_id"], "")

    def test_17_empty_current_snapshot(self):
        result = compare_snapshots(
            make_snapshot("watch-20260918T120000Z", [make_entry("CVE-2020-11022")]),
            {},
        )
        self.assertEqual(result["summary"][REMOVED_CVE], 1)
        self.assertEqual(result["current_snapshot_id"], "")

    def test_18_history_with_multiple_snapshots(self):
        first = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        second = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", matched_version="3.3.1")],
        )
        third = make_snapshot(
            "watch-20260918T120200Z",
            [make_entry("CVE-2020-11022", matched_version="3.3.1")],
        )
        first_delta = compare_snapshots(first, second)
        second_delta = compare_snapshots(second, third)
        self.assertIn(
            MATCH_CHANGED,
            change_types_for(first_delta, "CVE-2020-11022"),
        )
        self.assertEqual(
            change_types_for(second_delta, "CVE-2020-11022"), [UNCHANGED]
        )

    def test_19_no_mutation_of_inputs(self):
        previous = make_snapshot(
            "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
        )
        current = make_snapshot(
            "watch-20260918T120100Z",
            [make_entry("CVE-2020-11022", matched_version="3.3.1")],
        )
        before_previous = copy.deepcopy(previous)
        before_current = copy.deepcopy(current)
        compare_snapshots(previous, current)
        self.assertEqual(previous, before_previous)
        self.assertEqual(current, before_current)


def _write_local_snapshot(root: Path, snapshot: dict) -> Path:
    directory = root / "dell"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{snapshot['snapshot_id']}.json"
    path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def _delta_args(root: Path, **overrides):
    values = {
        "program": "dell",
        "snapshot_root": str(root),
        "apply": False,
        "json": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class TestWatchlistDeltaCli(unittest.TestCase):
    def test_20_apply_is_atomic_and_never_overwrites(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_local_snapshot(
                root,
                make_snapshot(
                    "watch-20260918T120000Z", [make_entry("CVE-2020-11022")]
                ),
            )
            _write_local_snapshot(
                root,
                make_snapshot(
                    "watch-20260918T120100Z",
                    [make_entry("CVE-2020-11022", matched_version="3.3.1")],
                ),
            )

            # Read-only by default: no delta artifact is written.
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_watchlist_delta(
                    _delta_args(root)
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(
                payload["previous_snapshot_id"], "watch-20260918T120000Z"
            )
            self.assertEqual(
                payload["current_snapshot_id"], "watch-20260918T120100Z"
            )
            self.assertEqual(
                sorted((root / "dell").glob("delta-*.json")), []
            )

            # --apply writes exactly one delta artifact.
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_watchlist_delta(
                    _delta_args(root, apply=True)
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertTrue(payload["written"])
            delta_files = sorted((root / "dell").glob("delta-*.json"))
            self.assertEqual(len(delta_files), 1)
            first_bytes = delta_files[0].read_bytes()

            # Second --apply with identical inputs replays without overwrite.
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_watchlist_delta(
                    _delta_args(root, apply=True)
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertFalse(payload["written"])
            self.assertEqual(sorted((root / "dell").glob("delta-*.json")), delta_files)
            self.assertEqual(delta_files[0].read_bytes(), first_bytes)

            # Original snapshots are untouched.
            self.assertEqual(len(sorted((root / "dell").glob("watch-*.json"))), 2)

    def test_cli_parses_watchlist_delta(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            ["agent", "watchlist-delta", "--program", "dell", "--json"]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "watchlist-delta")
        self.assertEqual(args.program, "dell")
        self.assertTrue(args.json)
        self.assertFalse(args.apply)


if __name__ == "__main__":
    unittest.main()
