#!/usr/bin/env python3
"""EPIC10 SS4/SS5 -- discovery guarantees: new names are never lost.

The single most important correctness property: a hostname discovered after a
previous run must be selected even when every other name in the scope is FRESH,
and a name whose source metadata changed must be re-resolved. Also: duplicate
discoveries are de-duplicated (one DNS query per name, not per row), and no
candidate may vanish from both the selected and the skipped set.
"""

import sys
import unittest
from datetime import timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.epic10_fixtures import (  # noqa: E402
    NOW,
    IncrementalTestCase,
    static_provider,
    static_provider_with_scope,
)
from utils.dns_incremental import (  # noqa: E402
    DnsCategory,
    PriorResolution,
)


class DiscoveryTestCase(IncrementalTestCase):
    def setUp(self):
        self.setUpIncremental()

    def tearDown(self):
        self.tearDownIncremental()


class TestNewDiscoveriesAreNeverLost(DiscoveryTestCase, unittest.TestCase):
    def test_new_name_is_selected_while_fresh_names_are_skipped(self):
        """The mission's canonical example (EPIC10 SS4)."""
        fresh = {
            "a.example.com": self.resolve("a.example.com", hours_ago=1),
            "b.example.com": self.resolve("b.example.com", hours_ago=2),
        }
        result = self.select(
            ["a.example.com", "b.example.com", "c.example.com"],
            provider=static_provider(fresh))
        self.assertEqual(["c.example.com"], result.selected)
        self.assertEqual(1, result.counts[DnsCategory.NEW])
        self.assertEqual(2, result.counts[DnsCategory.FRESH])

    def test_new_name_selected_even_if_every_other_name_is_fresh(self):
        names = [f"h{i}.example.com" for i in range(50)]
        prior = {n: self.resolve(n, hours_ago=0.1) for n in names}
        candidates = names + ["brand-new.example.com"]
        result = self.select(candidates, provider=static_provider(prior))
        self.assertEqual(["brand-new.example.com"], result.selected)

    def test_many_new_names_are_all_selected(self):
        names = [f"h{i}.example.com" for i in range(1000)]
        prior = {n: self.resolve(n, hours_ago=1) for n in names[:500]}
        result = self.select(names, provider=static_provider(prior))
        self.assertEqual(500, len(result.selected))
        self.assertEqual(names[500:], result.selected)

    def test_new_name_that_is_malformed_is_reported_not_selected(self):
        result = self.select(["good.example.com", "bad_name"])
        self.assertEqual(["good.example.com"], result.selected)
        self.assertEqual(1, result.invalid)
        self.assertEqual(1, result.counts[DnsCategory.INVALID])

    def test_a_new_name_is_selected_on_every_run_until_it_resolves(self):
        """A name that never resolves must not be dropped by the selector."""
        names = ["flaky.example.com"]
        first = self.select(names)
        self.assertEqual(names, first.selected)
        # nothing resolved -> no prior state was created -> still NEW next run
        second = self.select(names)
        self.assertEqual(names, second.selected)

    def test_discovery_after_a_run_is_selected_on_the_next_run(self):
        # run 1: only a and b exist
        first = self.select(["a.example.com", "b.example.com"],
                            provider=static_provider({}))
        self.assertEqual(["a.example.com", "b.example.com"], first.selected)
        # both resolved in that run
        prior = {
            "a.example.com": self.resolve("a.example.com", hours_ago=0.5),
            "b.example.com": self.resolve("b.example.com", hours_ago=0.5),
        }
        # run 2: c was discovered in between
        second = self.select(["a.example.com", "b.example.com", "c.example.com"],
                             provider=static_provider(prior))
        self.assertEqual(["c.example.com"], second.selected)


class TestChangeDetection(DiscoveryTestCase, unittest.TestCase):
    def test_changed_source_is_selected_despite_fresh_result(self):
        prior = {"a.example.com": PriorResolution(
            last_resolved=NOW - timedelta(minutes=5), source_changed=True)}
        result = self.select(["a.example.com"], provider=static_provider(prior))
        self.assertEqual(["a.example.com"], result.selected)
        self.assertEqual(1, result.counts[DnsCategory.CHANGED])

    def test_unchanged_source_fresh_result_is_skipped(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=1)}
        result = self.select(["a.example.com"], provider=static_provider(prior))
        self.assertEqual([], result.selected)
        self.assertEqual(1, result.counts[DnsCategory.FRESH])

    def test_changed_and_unchanged_mix(self):
        prior = {
            "changed.example.com": PriorResolution(
                last_resolved=NOW - timedelta(hours=1), source_changed=True),
            "stable.example.com": self.resolve("stable.example.com", hours_ago=1),
        }
        result = self.select(["changed.example.com", "stable.example.com"],
                             provider=static_provider(prior))
        self.assertEqual(["changed.example.com"], result.selected)

    def test_change_detection_is_not_inferred_from_age_alone(self):
        """An old result is STALE, not CHANGED (no false change detection)."""
        prior = {"a.example.com": PriorResolution(
            last_resolved=NOW - timedelta(days=30), source_changed=False)}
        result = self.select(["a.example.com"], provider=static_provider(prior))
        self.assertEqual(1, result.counts[DnsCategory.STALE])
        self.assertEqual(0, result.counts.get(DnsCategory.CHANGED, 0))


class TestDuplicates(DiscoveryTestCase, unittest.TestCase):
    def test_duplicate_name_is_queried_once(self):
        result = self.select(["a.example.com", "a.example.com"])
        self.assertEqual(["a.example.com"], result.selected)
        self.assertEqual(1, result.duplicates)

    def test_duplicate_rows_across_programs_collapse(self):
        # Subdomains' unique index is (program_name, subdomain): the same name
        # can legitimately appear twice for one scope.
        names = ["a.example.com", "b.example.com", "a.example.com",
                 "b.example.com", "a.example.com"]
        result = self.select(names)
        self.assertEqual(["a.example.com", "b.example.com"], result.selected)
        self.assertEqual(3, result.duplicates)

    def test_duplicate_detection_preserves_first_seen_order(self):
        result = self.select(["b.example.com", "a.example.com", "b.example.com"])
        self.assertEqual(["b.example.com", "a.example.com"], result.selected)

    def test_duplicates_do_not_inflate_category_counts(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=1)}
        result = self.select(["a.example.com", "a.example.com"],
                             provider=static_provider(prior))
        self.assertEqual(1, result.counts[DnsCategory.FRESH])

    def test_whitespace_padded_duplicate_collapses(self):
        # the caller strips lines when it writes the list file; the selector
        # strips again so a stray CR/padding cannot produce a second query
        result = self.select(["a.example.com", " a.example.com "])
        self.assertEqual(["a.example.com"], result.selected)


class TestNoCandidateIsLost(DiscoveryTestCase, unittest.TestCase):
    def test_selected_and_skipped_partition_all_valid_candidates(self):
        names = [f"h{i}.example.com" for i in range(20)] + ["bad_name"]
        prior = {f"h{i}.example.com": self.resolve(f"h{i}.example.com", hours_ago=1)
                 for i in range(0, 20, 2)}
        result = self.select(names, provider=static_provider(prior))
        valid = [n for n in names if n != "bad_name"]
        accounted = set(result.selected) | {
            d.name for d in result.decisions if not d.eligible and d.category
            != DnsCategory.INVALID}
        self.assertEqual(set(valid), accounted)
        self.assertEqual(len(valid), len(result.selected) + result.deferred)
        self.assertEqual(len(valid) + result.invalid, len(result.selected)
                         + result.skipped)
        self.assertEqual(1, result.invalid)

    def test_candidates_count_is_the_input_size(self):
        names = [f"h{i}.example.com" for i in range(37)]
        result = self.select(names)
        self.assertEqual(37, result.candidates)

    def test_every_decision_is_recorded_for_every_unique_candidate(self):
        names = [f"h{i}.example.com" for i in range(11)] + ["h0.example.com"]
        result = self.select(names)
        self.assertEqual(11, len(result.decisions))
        self.assertEqual(set(names), {d.name for d in result.decisions})

    def test_empty_input_selects_nothing(self):
        result = self.select([])
        self.assertEqual([], result.selected)
        self.assertEqual(0, result.candidates)
        self.assertEqual(0, result.skipped)

    def test_single_candidate_new_is_selected(self):
        result = self.select(["only.example.com"])
        self.assertEqual(["only.example.com"], result.selected)


class TestScopeReporting(DiscoveryTestCase, unittest.TestCase):
    def test_scope_is_reported_from_prior_state(self):
        result = self.select(["a.example.com"],
                             provider=static_provider_with_scope("example.com"))
        self.assertEqual("example.com", result.scope)

    def test_scope_is_absent_when_no_prior_state(self):
        result = self.select(["a.example.com"])
        self.assertIsNone(result.scope)

    def test_scope_does_not_change_eligibility(self):
        with_scope = self.select(["a.example.com"],
                                 provider=static_provider_with_scope("x.com"))
        without = self.select(["a.example.com"])
        self.assertEqual(with_scope.selected, without.selected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
