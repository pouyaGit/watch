"""Focused tests for the standing CVE watchlist (local; no Mongo, no network).

Covers exactly the new behavior:

- CVE discovery for one program from the existing R18 queue rows, with no
  cross-program contamination;
- one unchanged per-CVE matcher call per discovered CVE;
- deterministic timestamped snapshot generation (byte-identical for identical
  inputs) and historical snapshot preservation;
- NEW / CHANGED / UNCHANGED delta classification against the previous
  persisted snapshot, with repeated identical runs creating no artificial
  changes;
- empty/no-match CVEs and outside-range association states;
- duplicate-run (same timestamp) replay without a write;
- dry-run writes nothing.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai import research_cli
from ai.research_agent.watchlist import (
    DELTA_CHANGED,
    DELTA_NEW,
    DELTA_UNCHANGED,
    REASON_INVALID_PROGRAM,
    STATUS_COMPLETED,
    STATUS_ERROR,
    STATUS_REPLAYED,
    build_entry,
    discover_cves,
    entry_fingerprint,
    list_snapshots,
    run_watchlist,
    snapshot_path,
    write_snapshot,
)

CVE_HTTP = "CVE-2020-11022"
CVE_SILENT = "CVE-2024-29881"
CVE_INDEED = "CVE-2026-1557"
NOW_1 = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)
NOW_2 = datetime(2026, 9, 18, 12, 1, 0, tzinfo=timezone.utc)


def queue_rows():
    return [
        {
            "cve": CVE_HTTP,
            "program": "dell",
            "queue_id": "rq-" + "a" * 16,
            "relevance": "MEDIUM",
            "relevance_score": 40,
            "priority_class": "MEDIUM_RESEARCH",
            "priority_score": 50,
            "queue_score": 45,
            "blockers": ["asset version unknown"],
            "reasons": ["Medium research priority", "technology match: jQuery"],
            "unknown_factors": [],
        },
        {
            "cve": CVE_HTTP,
            "program": "indeed",
            "queue_id": "rq-" + "b" * 16,
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "LOW_RESEARCH",
            "priority_score": 20,
            "queue_score": 20,
            "blockers": [],
            "reasons": [],
            "unknown_factors": [],
        },
        {
            "cve": CVE_INDEED,
            "program": "indeed",
            "queue_id": "rq-" + "c" * 16,
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "LOW_RESEARCH",
            "priority_score": 20,
            "queue_score": 20,
            "blockers": [],
            "reasons": [],
            "unknown_factors": [],
        },
        {
            "cve": CVE_SILENT,
            "program": "dell",
            "queue_id": "rq-" + "d" * 16,
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "LOW_RESEARCH",
            "priority_score": 20,
            "queue_score": 20,
            "blockers": [],
            "reasons": [],
            "unknown_factors": [],
        },
    ]


def match_item(**overrides):
    item = {
        "cve_id": CVE_HTTP,
        "program": "dell",
        "asset_match_state": "WEAK",
        "asset_match_confidence": "LOW",
        "strongest_match_type": "VERSION",
        "strongest_confidence": "LOW",
        "matched_component": "",
        "matched_version": "1.12.4",
        "matched_parameter": "",
        "match_summary": (
            "Observed version satisfies the affected range; component not "
            "confirmed."
        ),
        "research_status": "NOT YET SUFFICIENT",
        "version_state": "MATCH",
        "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
        "version_association_reason": "",
        "resolved_blockers": [],
        "remaining_blockers": ["plugin_not_observed"],
        "missing": ["PRODUCT"],
        "all_matches": [
            {
                "match_id": "am-" + "1" * 16,
                "match_type": "VERSION",
                "matched_value": "1.12.4",
                "confidence": "LOW",
            }
        ],
    }
    item.update(overrides)
    return item


def make_loader(mapping):
    calls: list[str] = []

    def load(cve):
        calls.append(cve)
        item = mapping.get(cve)
        items = [item] if item else []
        return {
            "cve": cve,
            "program": "dell",
            "total": len(items),
            "items": items,
            "rule_version": "r30.1-1",
            "research_only": True,
        }

    load.calls = calls
    return load


class WatchlistTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def run_case(
        self,
        mapping,
        *,
        now=NOW_1,
        write=True,
        rows=None,
        root=None,
        limit=100,
    ):
        loader = make_loader(mapping)
        outcome = run_watchlist(
            "dell",
            snapshot_root=root or self.root,
            queue_loader=lambda: rows if rows is not None else queue_rows(),
            match_loader=loader,
            now=now,
            write=write,
            limit=limit,
        )
        outcome["loader_calls"] = loader.calls
        return outcome

    def snapshot_files(self, root=None):
        directory = (root or self.root) / "dell"
        if not directory.is_dir():
            return []
        return sorted(directory.glob("watch-*.json"))


class TestDiscovery(WatchlistTestCase):
    def test_discovery_filters_program_and_dedupes(self):
        self.assertEqual(
            discover_cves(queue_rows(), "dell"), [CVE_HTTP, CVE_SILENT]
        )
        self.assertEqual(discover_cves(queue_rows(), "indeed"), [CVE_HTTP, CVE_INDEED])
        self.assertEqual(discover_cves(queue_rows(), "unknown"), [])

    def test_no_cross_program_cves_in_dell_snapshot(self):
        outcome = self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        self.assertEqual(outcome["cve_count"], 2)
        cves = [entry["cve_id"] for entry in outcome["snapshot"]["entries"]]
        self.assertEqual(cves, [CVE_HTTP, CVE_SILENT])
        self.assertNotIn(CVE_INDEED, cves)

    def test_program_item_from_another_program_is_not_bound(self):
        outcome = self.run_case(
            {CVE_HTTP: match_item(program="indeed")}, rows=queue_rows()
        )
        entry = outcome["snapshot"]["entries"][0]
        self.assertEqual(entry["program"], "dell")
        self.assertEqual(entry["match_state"], "UNKNOWN")
        self.assertEqual(entry["match_row_count"], 0)
        self.assertEqual(entry["match_rows"], [])

    def test_empty_and_unknown_program_errors_fail_closed(self):
        for program in ("", "   "):
            outcome = run_watchlist(
                program,
                snapshot_root=self.root,
                queue_loader=lambda: queue_rows(),
                match_loader=make_loader({}),
                now=NOW_1,
                write=True,
            )
            self.assertEqual(outcome["status"], STATUS_ERROR)
            self.assertEqual(outcome["reason"], REASON_INVALID_PROGRAM)
        self.assertEqual(self.snapshot_files(), [])


class TestMatcherInvocation(WatchlistTestCase):
    def test_one_call_per_discovered_cve(self):
        outcome = self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        self.assertEqual(outcome["loader_calls"], [CVE_HTTP, CVE_SILENT])

    def test_limit_caps_processed_cves(self):
        outcome = self.run_case({CVE_HTTP: match_item()}, limit=1)
        self.assertEqual(outcome["loader_calls"], [CVE_HTTP])
        self.assertEqual(outcome["cve_count"], 1)

    def test_matcher_failure_is_fail_soft(self):
        def broken(cve):
            raise RuntimeError("matcher unavailable")

        outcome = run_watchlist(
            "dell",
            snapshot_root=self.root,
            queue_loader=lambda: queue_rows(),
            match_loader=broken,
            now=NOW_1,
            write=True,
        )
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertEqual(outcome["cve_count"], 2)
        for entry in outcome["snapshot"]["entries"]:
            self.assertEqual(entry["match_state"], "UNKNOWN")
            self.assertEqual(entry["match_row_count"], 0)


class TestSnapshotDeterminism(WatchlistTestCase):
    def test_identical_inputs_produce_byte_identical_snapshots(self):
        with tempfile.TemporaryDirectory() as other:
            first = self.run_case({CVE_HTTP: match_item()})
            second = self.run_case(
                {CVE_HTTP: match_item()}, root=Path(other)
            )
            self.assertTrue(first["written"])
            self.assertTrue(second["written"])
            first_bytes = (self.root / "dell" / first["snapshot_path"]).read_bytes()
            second_bytes = (
                Path(other) / "dell" / second["snapshot_path"]
            ).read_bytes()
            self.assertEqual(first_bytes, second_bytes)

    def test_dry_run_writes_nothing(self):
        outcome = self.run_case({CVE_HTTP: match_item()}, write=False)
        self.assertEqual(outcome["status"], STATUS_COMPLETED)
        self.assertFalse(outcome["written"])
        self.assertEqual(self.snapshot_files(), [])
        self.assertIsNotNone(outcome["snapshot"])

    def test_fingerprint_is_timestamp_free_and_change_sensitive(self):
        entry_one = build_entry(CVE_HTTP, "dell", match_item(), None)
        entry_two = build_entry(CVE_HTTP, "dell", match_item(), None)
        self.assertEqual(entry_fingerprint(entry_one), entry_fingerprint(entry_two))
        changed = build_entry(
            CVE_HTTP, "dell", match_item(matched_version="3.3.1"), None
        )
        self.assertNotEqual(
            entry_fingerprint(entry_one), entry_fingerprint(changed)
        )

    def test_snapshot_path_rejects_malformed_ids(self):
        with self.assertRaises(ValueError):
            snapshot_path(self.root, "dell", "not-a-snapshot")

    def test_write_snapshot_never_overwrites(self):
        payload = {"snapshot_id": "watch-20260918T120000Z", "entries": []}
        first_path, first_written = write_snapshot(payload, self.root, "dell")
        second_path, second_written = write_snapshot(payload, self.root, "dell")
        self.assertTrue(first_written)
        self.assertFalse(second_written)
        self.assertEqual(first_path, second_path)


class TestDelta(WatchlistTestCase):
    def test_first_run_is_new(self):
        outcome = self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        self.assertEqual(
            outcome["delta_counts"],
            {DELTA_NEW: 2, DELTA_CHANGED: 0, DELTA_UNCHANGED: 0},
        )
        for entry in outcome["snapshot"]["entries"]:
            self.assertEqual(entry["delta"], DELTA_NEW)

    def test_identical_rerun_is_unchanged(self):
        self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        outcome = self.run_case(
            {CVE_HTTP: match_item(), CVE_SILENT: None}, now=NOW_2
        )
        self.assertEqual(
            outcome["delta_counts"],
            {DELTA_NEW: 0, DELTA_CHANGED: 0, DELTA_UNCHANGED: 2},
        )
        self.assertEqual(outcome["previous_snapshot_id"], "watch-20260918T120000Z")

    def test_changed_match_is_changed_and_others_unchanged(self):
        self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        outcome = self.run_case(
            {
                CVE_HTTP: match_item(
                    matched_version="3.3.1",
                    all_matches=[
                        {
                            "match_id": "am-" + "2" * 16,
                            "match_type": "VERSION",
                            "matched_value": "3.3.1",
                            "confidence": "LOW",
                        }
                    ],
                ),
                CVE_SILENT: None,
            },
            now=NOW_2,
        )
        self.assertEqual(outcome["delta_counts"][DELTA_CHANGED], 1)
        self.assertEqual(outcome["delta_counts"][DELTA_UNCHANGED], 1)
        by_cve = {
            entry["cve_id"]: entry for entry in outcome["snapshot"]["entries"]
        }
        self.assertEqual(by_cve[CVE_HTTP]["delta"], DELTA_CHANGED)
        self.assertEqual(by_cve[CVE_SILENT]["delta"], DELTA_UNCHANGED)

    def test_duplicate_run_same_timestamp_is_replayed(self):
        first = self.run_case({CVE_HTTP: match_item()})
        first_bytes = (
            self.root / "dell" / first["snapshot_path"]
        ).read_bytes()
        second = self.run_case({CVE_HTTP: match_item()})
        self.assertEqual(second["status"], STATUS_REPLAYED)
        self.assertFalse(second["written"])
        self.assertEqual(len(self.snapshot_files()), 1)
        self.assertEqual(
            (self.root / "dell" / second["snapshot_path"]).read_bytes(),
            first_bytes,
        )
        self.assertEqual(second["delta_counts"][DELTA_UNCHANGED], 2)

    def test_historical_snapshots_are_preserved(self):
        first = self.run_case({CVE_HTTP: match_item()})
        first_bytes = (
            self.root / "dell" / first["snapshot_path"]
        ).read_bytes()
        self.run_case(
            {CVE_HTTP: match_item(matched_version="3.3.1")}, now=NOW_2
        )
        files = self.snapshot_files()
        self.assertEqual(len(files), 2)
        self.assertEqual(files[0].read_bytes(), first_bytes)
        snapshots = list_snapshots(self.root, "dell")
        self.assertEqual(
            [item["snapshot_id"] for item in snapshots],
            ["watch-20260918T120000Z", "watch-20260918T120100Z"],
        )


class TestEntryStates(WatchlistTestCase):
    def test_empty_no_match_cve_entry(self):
        outcome = self.run_case({CVE_SILENT: None})
        entry = next(
            item
            for item in outcome["snapshot"]["entries"]
            if item["cve_id"] == CVE_SILENT
        )
        self.assertEqual(entry["cve_id"], CVE_SILENT)
        self.assertEqual(entry["match_state"], "UNKNOWN")
        self.assertEqual(entry["confidence"], "NONE")
        self.assertEqual(entry["match_row_count"], 0)
        self.assertEqual(entry["match_summary"], "No deterministic asset match.")
        self.assertEqual(entry["research_status"], "NOT YET SUFFICIENT")

    def test_outside_range_association_state_is_captured(self):
        item = match_item(
            asset_match_state="UNKNOWN",
            asset_match_confidence="NONE",
            strongest_match_type="",
            strongest_confidence="",
            matched_version="",
            match_summary="No deterministic asset match.",
            version_state="UNKNOWN",
            version_association_state="VERSION_OBSERVED_NO_MATCH",
            version_association_reason=(
                "observed version 28.4 does not satisfy <=28.0"
            ),
            remaining_blockers=["plugin_not_observed", "version_unknown"],
            all_matches=[],
        )
        outcome = self.run_case({CVE_SILENT: item})
        entry = next(
            candidate
            for candidate in outcome["snapshot"]["entries"]
            if candidate["cve_id"] == CVE_SILENT
        )
        self.assertEqual(
            entry["version_association_state"], "VERSION_OBSERVED_NO_MATCH"
        )
        self.assertEqual(
            entry["version_association_reason"],
            "observed version 28.4 does not satisfy <=28.0",
        )
        self.assertEqual(entry["match_row_count"], 0)

        changed = self.run_case(
            {
                CVE_SILENT: dict(
                    item,
                    version_association_reason=(
                        "observed version 28.4 does not satisfy <28.1"
                    ),
                )
            },
            now=NOW_2,
        )
        self.assertEqual(changed["delta_counts"][DELTA_CHANGED], 1)

    def test_queue_state_is_part_of_entry_identity(self):
        outcome = self.run_case({CVE_HTTP: match_item()})
        entry = outcome["snapshot"]["entries"][0]
        self.assertTrue(entry["queue"]["present"])
        self.assertEqual(entry["queue"]["relevance"], "MEDIUM")
        self.assertEqual(entry["queue"]["queue_id"], "rq-" + "a" * 16)

        rows = queue_rows()
        rows[0]["relevance"] = "HIGH"
        rows[0]["relevance_score"] = 60
        changed = self.run_case(
            {CVE_HTTP: match_item()}, rows=rows, now=NOW_2
        )
        self.assertEqual(changed["delta_counts"][DELTA_CHANGED], 1)


class TestSnapshotShape(WatchlistTestCase):
    def test_snapshot_carries_safety_and_counts(self):
        outcome = self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        snapshot = outcome["snapshot"]
        self.assertEqual(snapshot["watchlist_version"], "watchlist-1")
        self.assertEqual(snapshot["program"], "dell")
        self.assertTrue(snapshot["advisory"])
        self.assertTrue(snapshot["research_only"])
        self.assertEqual(snapshot["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(snapshot["match_state_counts"], {"UNKNOWN": 1, "WEAK": 1})

    def test_missing_from_current_is_recorded(self):
        self.run_case({CVE_HTTP: match_item(), CVE_SILENT: None})
        rows = [row for row in queue_rows() if row["cve"] != CVE_SILENT]
        outcome = self.run_case(
            {CVE_HTTP: match_item()}, rows=rows, now=NOW_2
        )
        self.assertEqual(outcome["snapshot"]["missing_from_current"], [CVE_SILENT])

    def test_snapshot_file_is_readable_json(self):
        outcome = self.run_case({CVE_HTTP: match_item()})
        path = self.root / "dell" / outcome["snapshot_path"]
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["snapshot_id"], outcome["snapshot_id"])
        self.assertEqual(payload["entries"][0]["cve_id"], CVE_HTTP)


class TestCli(WatchlistTestCase):
    def test_agent_watchlist_subcommand_parses(self):
        parser = research_cli.build_parser()
        args = parser.parse_args(
            ["agent", "watchlist", "--program", "dell", "--json"]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "watchlist")
        self.assertEqual(args.program, "dell")
        self.assertFalse(args.apply)
        self.assertEqual(args.timeout, 1800)

    def _args(self, **overrides):
        import argparse

        values = {
            "program": "dell",
            "snapshot_root": str(self.root),
            "limit": None,
            "timeout": 30,
            "apply": False,
            "json": True,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_cli_dry_run_writes_nothing(self):
        import contextlib
        import io
        from unittest import mock

        from ai.research_agent import watchlist as watchlist_module

        buffer = io.StringIO()
        with mock.patch.object(
            watchlist_module, "default_queue_loader", lambda: queue_rows()
        ), mock.patch.object(
            watchlist_module,
            "default_match_loader",
            lambda program: make_loader({CVE_HTTP: match_item()}),
        ), contextlib.redirect_stdout(buffer):
            code = research_cli.run_agent_watchlist(self._args())
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["cve_count"], 2)
        self.assertFalse(payload["written"])
        self.assertEqual(self.snapshot_files(), [])

    def test_cli_apply_writes_one_snapshot(self):
        import contextlib
        import io
        from unittest import mock

        from ai.research_agent import watchlist as watchlist_module

        buffer = io.StringIO()
        with mock.patch.object(
            watchlist_module, "default_queue_loader", lambda: queue_rows()
        ), mock.patch.object(
            watchlist_module,
            "default_match_loader",
            lambda program: make_loader({CVE_HTTP: match_item()}),
        ), contextlib.redirect_stdout(buffer):
            code = research_cli.run_agent_watchlist(self._args(apply=True))
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["written"])
        self.assertEqual(len(self.snapshot_files()), 1)


if __name__ == "__main__":
    unittest.main()
