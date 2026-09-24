#!/usr/bin/env python3
"""EPIC10 SS7/SS17 -- freshness policy, configuration parsing and the run report.

The freshness window decides which already-resolved names are skipped. These
tests pin the boundary (before/at/after), the documented default, the
environment parsing (a malformed policy must fail closed, never be guessed), and
the operator-facing report block that answers "why these names and not those?".
"""

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.epic10_fixtures import (  # noqa: E402
    NOW,
    IncrementalTestCase,
    static_provider,
)
from utils.dns_incremental import (  # noqa: E402
    DEFAULT_FRESHNESS_HOURS,
    DEFAULT_RETRY_BACKOFF_HOURS,
    DEFAULT_STATE_FILE,
    ENV_ENABLED,
    ENV_FORCE,
    ENV_FRESHNESS,
    ENV_RETRY,
    ENV_STATE_FILE,
    DnsCategory,
    DnsResolutionPolicy,
    DnsSelectionError,
    env_bool,
    parse_hours,
    parse_hours_ladder,
)


class FreshnessTestCase(IncrementalTestCase):
    def setUp(self):
        self.setUpIncremental()

    def tearDown(self):
        self.tearDownIncremental()


class TestFreshnessBoundary(FreshnessTestCase, unittest.TestCase):
    def _categories(self, hours_ago, freshness):
        prior = {"a.example.com": self.resolve("a.example.com",
                                               hours_ago=hours_ago)}
        result = self.select(["a.example.com"],
                             provider=static_provider(prior),
                             policy=self.policy(freshness_hours=freshness))
        return result.counts

    def test_before_threshold_is_fresh(self):
        counts = self._categories(6, 12.0)
        self.assertEqual(1, counts[DnsCategory.FRESH])

    def test_exactly_at_threshold_is_stale(self):
        counts = self._categories(12, 12.0)
        self.assertEqual(1, counts[DnsCategory.STALE])

    def test_after_threshold_is_stale(self):
        counts = self._categories(12.5, 12.0)
        self.assertEqual(1, counts[DnsCategory.STALE])

    def test_one_second_before_threshold_is_fresh(self):
        prior = {"a.example.com": self.resolve("a.example.com",
                                               hours_ago=11.9997)}
        result = self.select(["a.example.com"], provider=static_provider(prior),
                             policy=self.policy(freshness_hours=12.0))
        self.assertEqual(1, result.counts[DnsCategory.FRESH])

    def test_24h_window_keeps_tonights_result_stale(self):
        """The documented nightly-cadence property (freshness=12h default)."""
        # a name resolved in last night's run (~23.5h ago at tonight's run)
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=23.5)}
        result = self.select(["a.example.com"], provider=static_provider(prior),
                             policy=self.policy(freshness_hours=12.0))
        self.assertEqual(["a.example.com"], result.selected)

    def test_duplicate_run_inside_the_window_is_skipped(self):
        """What the 12h default buys: a re-run hours later does no DNS work."""
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=2)}
        result = self.select(["a.example.com"], provider=static_provider(prior),
                             policy=self.policy(freshness_hours=12.0))
        self.assertEqual([], result.selected)

    def test_freshness_zero_never_skips(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=0)}
        result = self.select(["a.example.com"], provider=static_provider(prior),
                             policy=self.policy(freshness_hours=0.0))
        self.assertEqual(["a.example.com"], result.selected)

    def test_fresh_names_are_reported_as_fresh(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=1)}
        result = self.select(["a.example.com"], provider=static_provider(prior))
        self.assertEqual(1, result.skipped_reasons[DnsCategory.FRESH])
        self.assertEqual("fresh_result", result.decisions[0].reason)

    def test_stale_names_report_their_age(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=30)}
        result = self.select(["a.example.com"], provider=static_provider(prior))
        self.assertAlmostEqual(30.0, result.decisions[0].age_hours, places=2)


class TestPolicyDefaults(FreshnessTestCase, unittest.TestCase):
    def test_default_freshness_is_documented_value(self):
        self.assertEqual(12.0, DEFAULT_FRESHNESS_HOURS)

    def test_default_retry_ladder_is_documented_value(self):
        self.assertEqual((12.0,), DEFAULT_RETRY_BACKOFF_HOURS)

    def test_default_state_file_is_under_ai_data(self):
        self.assertEqual(os.path.join("ai_data", "dns", "incremental_state.json"),
                         DEFAULT_STATE_FILE)

    def test_default_policy_is_enabled_and_not_forced(self):
        policy = DnsResolutionPolicy()
        self.assertTrue(policy.enabled)
        self.assertFalse(policy.force)

    def test_default_policy_preserves_nightly_coverage(self):
        """Every name resolved ~a day ago stays eligible under the defaults."""
        names = [f"h{i}.example.com" for i in range(10)]
        prior = {n: self.resolve(n, hours_ago=23.9) for n in names}
        result = self.select(names, provider=static_provider(prior))
        self.assertEqual(names, result.selected)

    def test_describe_mentions_the_effective_policy(self):
        text = self.policy().describe()
        for token in ("freshness=12h", "retry_backoff=12h", "force=False",
                      "enabled=True"):
            self.assertIn(token, text)


class TestEnvironmentConfiguration(unittest.TestCase):
    def test_from_env_uses_defaults_when_unset(self):
        policy = DnsResolutionPolicy.from_env({})
        self.assertTrue(policy.enabled)
        self.assertEqual(DEFAULT_FRESHNESS_HOURS, policy.freshness_hours)
        self.assertEqual(DEFAULT_RETRY_BACKOFF_HOURS, policy.retry_backoff_hours)
        self.assertFalse(policy.force)
        self.assertEqual(DEFAULT_STATE_FILE, policy.state_file)

    def test_from_env_reads_every_knob(self):
        policy = DnsResolutionPolicy.from_env({
            ENV_ENABLED: "true",
            ENV_FRESHNESS: "48",
            ENV_RETRY: "12,72,168",
            ENV_FORCE: "yes",
            ENV_STATE_FILE: "/tmp/state.json",
        })
        self.assertEqual(48.0, policy.freshness_hours)
        self.assertEqual((12.0, 72.0, 168.0), policy.retry_backoff_hours)
        self.assertTrue(policy.force)
        self.assertEqual("/tmp/state.json", policy.state_file)

    def test_disabled_selection_is_expressible(self):
        self.assertFalse(DnsResolutionPolicy.from_env({ENV_ENABLED: "false"}).enabled)

    def test_force_is_expressible(self):
        self.assertTrue(DnsResolutionPolicy.from_env({ENV_FORCE: "true"}).force)

    def test_invalid_boolean_fails_closed(self):
        with self.assertRaises(DnsSelectionError):
            DnsResolutionPolicy.from_env({ENV_ENABLED: "maybe"})

    def test_invalid_freshness_fails_closed(self):
        with self.assertRaises(DnsSelectionError):
            DnsResolutionPolicy.from_env({ENV_FRESHNESS: "soon"})

    def test_negative_freshness_fails_closed(self):
        with self.assertRaises(DnsSelectionError):
            DnsResolutionPolicy.from_env({ENV_FRESHNESS: "-1"})

    def test_invalid_retry_ladder_fails_closed(self):
        with self.assertRaises(DnsSelectionError):
            DnsResolutionPolicy.from_env({ENV_RETRY: "12,soon"})

    def test_negative_retry_rung_fails_closed(self):
        with self.assertRaises(DnsSelectionError):
            DnsResolutionPolicy.from_env({ENV_RETRY: "12,-5"})

    def test_empty_retry_ladder_falls_back_to_default(self):
        self.assertEqual(DEFAULT_RETRY_BACKOFF_HOURS,
                         parse_hours_ladder(""))

    def test_empty_freshness_falls_back_to_default(self):
        self.assertEqual(DEFAULT_FRESHNESS_HOURS,
                         parse_hours("", DEFAULT_FRESHNESS_HOURS, ENV_FRESHNESS))

    def test_env_bool_accepts_documented_forms(self):
        for raw in ("1", "true", "TRUE", "yes", "on"):
            self.assertTrue(env_bool(ENV_FORCE, False, {ENV_FORCE: raw}))
        for raw in ("0", "false", "no", "off"):
            self.assertFalse(env_bool(ENV_FORCE, True, {ENV_FORCE: raw}))

    def test_env_bool_uses_default_when_absent(self):
        self.assertTrue(env_bool("NOPE_NOT_SET", True, {}))

    def test_parse_hours_ladder_ignores_blank_items(self):
        self.assertEqual((12.0, 72.0), parse_hours_ladder("12,,72,"))

    def test_parse_hours_ladder_single_zero(self):
        self.assertEqual((0.0,), parse_hours_ladder("0"))


class TestRunReport(FreshnessTestCase, unittest.TestCase):
    def _report(self, names, prior):
        lines = []
        self.select(names, provider=static_provider(prior), reporter=lines.append)
        return "\n".join(lines)

    def test_report_lists_every_required_field(self):
        prior = {
            "new.example.com": None,
            "fresh.example.com": self.resolve("fresh.example.com", hours_ago=1),
            "stale.example.com": self.resolve("stale.example.com", hours_ago=100),
        }
        prior = {k: v for k, v in prior.items() if v}
        text = self._report(["new.example.com", "fresh.example.com",
                             "stale.example.com", "bad_name"], prior)
        for token in ("Candidates:", "Fresh", "New", "Stale", "Selected:",
                      "Skipped:", "Invalid", "Policy:", "Selection time:"):
            self.assertIn(token, text)

    def test_report_counts_match_the_selection(self):
        prior = {"fresh.example.com": self.resolve("fresh.example.com",
                                                   hours_ago=1)}
        result = self.select(["fresh.example.com", "new.example.com"],
                             provider=static_provider(prior))
        text = "\n".join(result.report_lines())
        self.assertIn("Candidates:               2", text)
        self.assertIn("Selected:                 1", text)

    def test_report_does_not_print_hostname_lists(self):
        names = [f"secret-name-{i}.example.com" for i in range(50)]
        text = self._report(names, {})
        for name in names:
            self.assertNotIn(name, text)

    def test_report_is_printed_through_the_reporter(self):
        lines = []
        self.select(["a.example.com"], reporter=lines.append)
        self.assertTrue(any("Candidates" in line for line in lines))

    def test_report_omits_zero_count_optional_categories(self):
        text = self._report(["a.example.com"], {})
        self.assertNotIn("Changed", text)
        self.assertNotIn("Force", text)

    def test_report_shows_skip_reasons(self):
        prior = {"a.example.com": self.resolve("a.example.com", hours_ago=1)}
        text = self._report(["a.example.com"], prior)
        self.assertIn("Skip reasons:", text)

    def test_report_never_reports_invalid_as_resolved(self):
        text = self._report(["bad_name"], {})
        self.assertIn("Invalid", text)
        self.assertNotIn("Resolved:", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
