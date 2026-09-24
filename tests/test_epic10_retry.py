#!/usr/bin/env python3
"""EPIC10 SS6/SS12 -- retry policy and attempt-state persistence.

Failed/unresolved names must be retried deterministically (never suppressed,
never retried at high frequency), the state must survive runs, corruption must
fail closed, and a chunk failure must not erase previous successful records.
"""

import json
import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.epic10_fixtures import (  # noqa: E402
    NOW,
    IncrementalTestCase,
    static_provider,
)
from utils import dns_incremental  # noqa: E402
from utils.dns_incremental import (  # noqa: E402
    MAX_STATE_ENTRIES,
    STATE_PRUNE_DAYS,
    AttemptState,
    DnsAttemptStore,
    DnsCategory,
    DnsSelectionError,
)


class RetryTestCase(IncrementalTestCase):
    def setUp(self):
        self.setUpIncremental()

    def tearDown(self):
        self.tearDownIncremental()

    def write_state(self, entries, version=1):
        payload = {"version": version, "updated_at": NOW.isoformat(),
                   "attempts": entries}
        with open(self.state_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    def read_state(self):
        with open(self.state_file, "r", encoding="utf-8") as handle:
            return json.load(handle)


class TestAttemptBookkeeping(RetryTestCase, unittest.TestCase):
    def test_unanswered_attempt_increments_streak(self):
        updated = self.store.apply_outcomes(
            ["a.example.com"], answered=[], previous={}, now=NOW)
        state = updated["a.example.com"]
        self.assertEqual(1, state.attempts)
        self.assertEqual(1, state.streak)
        self.assertEqual(NOW, state.last_attempt)
        self.assertIsNone(state.last_answer)

    def test_answered_attempt_resets_streak(self):
        previous = {"a.example.com": AttemptState(attempts=4, streak=4,
                                                  last_attempt=NOW)}
        updated = self.store.apply_outcomes(
            ["a.example.com"], answered=["a.example.com"], previous=previous,
            now=NOW)
        state = updated["a.example.com"]
        self.assertEqual(5, state.attempts)
        self.assertEqual(0, state.streak)
        self.assertEqual(NOW, state.last_answer)

    def test_repeated_failures_accumulate(self):
        previous = {}
        for _ in range(3):
            previous = self.store.apply_outcomes(
                ["a.example.com"], answered=[], previous=previous, now=NOW)
        self.assertEqual(3, previous["a.example.com"].streak)

    def test_name_not_queried_keeps_its_state(self):
        previous = {"a.example.com": AttemptState(attempts=2, streak=2,
                                                  last_attempt=NOW)}
        updated = self.store.apply_outcomes(
            ["b.example.com"], answered=[], previous=previous, now=NOW)
        self.assertEqual(2, updated["a.example.com"].streak)
        self.assertEqual(1, updated["b.example.com"].streak)

    def test_skipping_is_never_recorded_as_a_failure(self):
        result = self.select(["fresh.example.com"],
                             provider=static_provider({
                                 "fresh.example.com": self.resolve(
                                     "fresh.example.com", hours_ago=1)}))
        self.assertEqual([], result.selected)
        self.assertEqual({}, self.store.load())

    def test_outcome_is_persisted_across_runs(self):
        selection = self.select(["a.example.com"])
        dns_incremental.record_run_outcome(selection, [], reporter=lambda _l: None,
                                           now=NOW)
        state = self.store.load()
        self.assertEqual(1, state["a.example.com"].streak)

    def test_resolved_outcome_clears_the_streak(self):
        selection = self.select(["a.example.com"])
        line = json.dumps({"host": "a.example.com", "a": ["1.2.3.4"]})
        dns_incremental.record_run_outcome(selection, [line],
                                           reporter=lambda _l: None, now=NOW)
        self.assertEqual(0, self.store.load()["a.example.com"].streak)

    def test_non_json_lines_do_not_break_outcome_recording(self):
        selection = self.select(["a.example.com"])
        dns_incremental.record_run_outcome(
            selection, ["not json", "", json.dumps({"host": None})],
            reporter=lambda _l: None, now=NOW)
        self.assertEqual(1, self.store.load()["a.example.com"].streak)

    def test_answered_hosts_accepts_hostname_key(self):
        line = json.dumps({"hostname": "a.example.com", "a": ["1.2.3.4"]})
        self.assertEqual({"a.example.com"}, dns_incremental.answered_hosts([line]))

    def test_answered_hosts_ignores_unparseable_lines(self):
        self.assertEqual(set(), dns_incremental.answered_hosts(["", "{}", "nope"]))


class TestRetryEligibility(RetryTestCase, unittest.TestCase):
    def test_failed_name_is_retried_after_the_first_rung(self):
        self.write_state({"a.example.com": {
            "attempts": 1, "streak": 1,
            "last_attempt": (NOW - timedelta(hours=13)).isoformat(),
            "last_answer": None}})
        result = self.select(["a.example.com"],
                             policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(["a.example.com"], result.selected)
        self.assertEqual(1, result.counts[DnsCategory.RETRY_ELIGIBLE])

    def test_failed_name_is_deferred_inside_the_backoff_window(self):
        self.write_state({"a.example.com": {
            "attempts": 1, "streak": 1,
            "last_attempt": (NOW - timedelta(hours=1)).isoformat(),
            "last_answer": None}})
        result = self.select(["a.example.com"],
                             policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual([], result.selected)
        self.assertEqual(1, result.counts[DnsCategory.RETRY_BACKOFF])

    def test_deferred_name_is_not_lost(self):
        self.write_state({"a.example.com": {
            "attempts": 1, "streak": 1,
            "last_attempt": (NOW - timedelta(hours=1)).isoformat(),
            "last_answer": None}})
        result = self.select(["a.example.com"],
                             policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(1, len(result.decisions))
        self.assertIsNotNone(result.decisions[0].next_retry_at)

    def test_backoff_ladder_escalates_then_caps(self):
        ladder = (12.0, 72.0, 168.0)
        expectations = {1: 12.0, 2: 72.0, 3: 168.0, 4: 168.0, 99: 168.0}
        for streak, wait in expectations.items():
            self.write_state({"a.example.com": {
                "attempts": streak, "streak": streak,
                "last_attempt": (NOW - timedelta(hours=wait - 1)).isoformat(),
                "last_answer": None}})
            result = self.select(["a.example.com"],
                                 policy=self.policy(retry_backoff_hours=ladder))
            self.assertEqual([], result.selected,
                             f"streak={streak} must still be inside {wait}h")

    def test_no_high_frequency_retries_with_a_long_ladder(self):
        """A name failing every run is queried at most once per final rung."""
        self.write_state({"a.example.com": {
            "attempts": 20, "streak": 20,
            "last_attempt": (NOW - timedelta(hours=100)).isoformat(),
            "last_answer": None}})
        result = self.select(["a.example.com"],
                             policy=self.policy(retry_backoff_hours=(12.0, 72.0,
                                                                    168.0)))
        self.assertEqual([], result.selected)

    def test_unresolved_names_are_never_permanently_suppressed(self):
        self.write_state({"a.example.com": {
            "attempts": 999, "streak": 999,
            "last_attempt": (NOW - timedelta(days=365)).isoformat(),
            "last_answer": None}})
        result = self.select(["a.example.com"],
                             policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(["a.example.com"], result.selected)

    def test_zero_ladder_retries_every_run(self):
        self.write_state({"a.example.com": {
            "attempts": 5, "streak": 5,
            "last_attempt": NOW.isoformat(), "last_answer": None}})
        result = self.select(["a.example.com"],
                             policy=self.policy(retry_backoff_hours=(0.0,)))
        self.assertEqual(["a.example.com"], result.selected)


class TestStateStoreFailClosed(RetryTestCase, unittest.TestCase):
    def test_missing_state_file_is_empty_not_an_error(self):
        self.assertFalse(os.path.exists(self.state_file))
        self.assertEqual({}, self.store.load())

    def test_corrupt_json_fails_closed(self):
        with open(self.state_file, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_wrong_schema_version_fails_closed(self):
        self.write_state({}, version=99)
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_missing_attempts_mapping_fails_closed(self):
        with open(self.state_file, "w", encoding="utf-8") as handle:
            json.dump({"version": 1}, handle)
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_malformed_entry_fails_closed(self):
        self.write_state({"a.example.com": {"attempts": "many"}})
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_entry_not_a_mapping_fails_closed(self):
        self.write_state({"a.example.com": 5})
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_bad_timestamp_fails_closed(self):
        self.write_state({"a.example.com": {"attempts": 1, "streak": 1,
                                            "last_attempt": "yesterday"}})
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_unreadable_state_file_fails_closed(self):
        os.mkdir(self.state_file)
        with self.assertRaises(DnsSelectionError):
            self.select(["a.example.com"])

    def test_store_error_is_not_treated_as_all_eligible(self):
        with open(self.state_file, "w", encoding="utf-8") as handle:
            handle.write("{")
        with self.assertRaises(DnsSelectionError) as caught:
            self.select([f"h{i}.example.com" for i in range(10)])
        self.assertIn("state", str(caught.exception))


class TestStateStoreHygiene(RetryTestCase, unittest.TestCase):
    def test_state_is_written_atomically(self):
        self.store.save({"a.example.com": AttemptState(1, 1, NOW)}, now=NOW)
        leftovers = [n for n in os.listdir(self._tmpdir.name) if ".tmp." in n]
        self.assertEqual([], leftovers)
        self.assertTrue(os.path.exists(self.state_file))

    def test_state_file_records_version_and_timestamp(self):
        self.store.save({"a.example.com": AttemptState(1, 1, NOW)}, now=NOW)
        payload = self.read_state()
        self.assertEqual(1, payload["version"])
        self.assertEqual(NOW.isoformat(), payload["updated_at"])

    def test_zero_attempt_entries_are_not_persisted(self):
        self.store.save({"a.example.com": AttemptState(0, 0, None)}, now=NOW)
        self.assertEqual({}, self.read_state()["attempts"])

    def test_stale_entries_for_unknown_names_are_pruned(self):
        old = NOW - timedelta(days=STATE_PRUNE_DAYS + 1)
        self.store.save(
            {"gone.example.com": AttemptState(3, 3, old)},
            known_names=["kept.example.com"], now=NOW)
        self.assertEqual({}, self.read_state()["attempts"])

    def test_unknown_name_inside_the_retention_window_is_kept(self):
        recent = NOW - timedelta(days=1)
        self.store.save({"gone.example.com": AttemptState(3, 3, recent)},
                        known_names=["kept.example.com"], now=NOW)
        self.assertIn("gone.example.com", self.read_state()["attempts"])

    def test_known_names_are_always_kept(self):
        old = NOW - timedelta(days=STATE_PRUNE_DAYS + 30)
        self.store.save({"kept.example.com": AttemptState(3, 3, old)},
                        known_names=["kept.example.com"], now=NOW)
        self.assertIn("kept.example.com", self.read_state()["attempts"])

    def test_entry_cap_is_enforced(self):
        entries = {f"h{i}.example.com": AttemptState(1, 1, NOW - timedelta(minutes=i))
                   for i in range(10)}
        original = dns_incremental.MAX_STATE_ENTRIES
        try:
            dns_incremental.MAX_STATE_ENTRIES = 4
            store = DnsAttemptStore(self.state_file)
            store.save(entries, now=NOW)
        finally:
            dns_incremental.MAX_STATE_ENTRIES = original
        self.assertEqual(4, len(self.read_state()["attempts"]))

    def test_eviction_keeps_the_most_recent_entries(self):
        entries = {f"h{i}.example.com": AttemptState(1, 1, NOW - timedelta(minutes=i))
                   for i in range(5)}
        original = dns_incremental.MAX_STATE_ENTRIES
        try:
            dns_incremental.MAX_STATE_ENTRIES = 2
            DnsAttemptStore(self.state_file).save(entries, now=NOW)
        finally:
            dns_incremental.MAX_STATE_ENTRIES = original
        kept = set(self.read_state()["attempts"])
        self.assertEqual({"h0.example.com", "h1.example.com"}, kept)

    def test_state_round_trips_through_disk(self):
        state = {"a.example.com": AttemptState(2, 1, NOW, NOW)}
        self.store.save(state, now=NOW)
        loaded = self.store.load()
        self.assertEqual(state["a.example.com"], loaded["a.example.com"])

    def test_save_creates_missing_parent_directory(self):
        nested = os.path.join(self._tmpdir.name, "a", "b", "state.json")
        DnsAttemptStore(nested).save({"a.example.com": AttemptState(1, 1, NOW)},
                                     now=NOW)
        self.assertTrue(os.path.exists(nested))

    def test_state_file_stores_hostnames_only(self):
        """No credentials, no IPs, no payloads -- names and counters only."""
        self.store.save({"a.example.com": AttemptState(1, 1, NOW)}, now=NOW)
        entry = self.read_state()["attempts"]["a.example.com"]
        self.assertEqual({"attempts", "streak", "last_attempt", "last_answer"},
                         set(entry))


class TestPreviousDataIsPreserved(RetryTestCase, unittest.TestCase):
    def test_chunk_failure_does_not_erase_prior_state(self):
        """A failed chunk must not clear the attempt state of other names."""
        self.store.save({"a.example.com": AttemptState(2, 2, NOW - timedelta(hours=1))},
                        now=NOW)
        selection = self.select(["a.example.com"],
                                policy=self.policy(retry_backoff_hours=(0.0,)))
        dns_incremental.record_run_outcome(
            selection, [], error=RuntimeError("chunk 2 failed"),
            reporter=lambda _l: None, now=NOW)
        loaded = self.store.load()
        self.assertEqual(3, loaded["a.example.com"].attempts)
        self.assertEqual(3, loaded["a.example.com"].streak)

    def test_bookkeeping_failure_does_not_raise(self):
        selection = self.select(["a.example.com"])
        # make the store unwritable
        os.makedirs(self.state_file + ".tmp", exist_ok=True)
        selection.store = DnsAttemptStore(os.path.join(self._tmpdir.name, "nope",
                                                       "x", "state.json"))
        os.chmod(self._tmpdir.name, 0o500)
        try:
            dns_incremental.record_run_outcome(selection, [],
                                               reporter=lambda _l: None, now=NOW)
        finally:
            os.chmod(self._tmpdir.name, 0o700)

    def test_resolved_name_state_is_independent_of_unresolved_names(self):
        self.store.save({"ok.example.com": AttemptState(1, 0, NOW, NOW),
                         "bad.example.com": AttemptState(1, 1, NOW)}, now=NOW)
        loaded = self.store.load()
        self.assertEqual(0, loaded["ok.example.com"].streak)
        self.assertEqual(1, loaded["bad.example.com"].streak)


if __name__ == "__main__":
    unittest.main(verbosity=2)
