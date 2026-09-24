#!/usr/bin/env python3
"""EPIC10 SS2/SS3 -- eligibility classification (offline, no DB, no DNS).

Every candidate must fall into exactly one explicit category, with a documented
precedence and a deterministic reason. These tests pin the classification matrix:
one generated test per (case) so a regression names the exact state it broke.
"""

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.epic10_fixtures import (  # noqa: E402
    NOW,
    IncrementalTestCase,
    passthrough_provider,
    static_provider,
)
from utils import dns_incremental  # noqa: E402
from utils.dns_incremental import (  # noqa: E402
    CATEGORY_ORDER,
    ELIGIBLE_CATEGORIES,
    SKIPPED_CATEGORIES,
    AttemptState,
    DnsCategory,
    DnsResolutionPolicy,
    PriorResolution,
    classify_dns_candidate,
    validate_dns_name,
)


class EligibilityTestCase(IncrementalTestCase):
    """Plain mixin (NOT a TestCase): concrete suites below subclass it.

    If this were a TestCase, every generated invalid-name test would be
    inherited by every other suite and the reported test count would multiply
    without adding coverage.
    """

    def setUp(self):
        self.setUpIncremental()

    def tearDown(self):
        self.tearDownIncremental()

    def classify(self, name, *, prior=None, attempts=None, policy=None, now=NOW):
        return classify_dns_candidate(
            name,
            prior=prior,
            attempts=attempts,
            policy=policy or self.policy(),
            now=now,
        )


# --------------------------------------------------------------------------
# INVALID -- malformed input is never queried and never counted as resolved
# --------------------------------------------------------------------------

INVALID_CASES = [
    ("empty_string", "", "empty"),
    ("whitespace_only", "   ", "surrounding_whitespace"),
    ("leading_space", " a.example.com", "surrounding_whitespace"),
    ("trailing_space", "a.example.com ", "surrounding_whitespace"),
    ("wildcard_label", "*.example.com", "wildcard"),
    ("wildcard_inside", "a.*.example.com", "wildcard"),
    ("no_dot", "localhost", "no_dot"),
    ("uppercase", "A.example.com", "not_lowercase"),
    ("too_long", ("a" * 60 + ".") * 5 + "example.com", "too_long"),
    ("leading_hyphen_label", "-a.example.com", "invalid_label"),
    ("trailing_hyphen_label", "a-.example.com", "invalid_label"),
    ("underscore_label", "a_b.example.com", "invalid_label"),
    ("empty_label", "a..example.com", "invalid_label"),
    ("space_inside", "a b.example.com", "invalid_label"),
    ("colon_port", "a.example.com:443", "invalid_label"),
    ("slash", "a.example.com/path", "invalid_label"),
    ("trailing_dot", "a.example.com.", "invalid_label"),
    ("label_too_long", "a" * 64 + ".example.com", "invalid_label"),
]


class TestInvalidNames(EligibilityTestCase, unittest.TestCase):
    """Malformed candidates: never queried, never counted as resolved."""


def _make_invalid_case(name, value, reason):
    def test(self):
        valid, got = validate_dns_name(value)
        self.assertFalse(valid, f"{value!r} must be invalid")
        self.assertEqual(reason, got)
        decision = self.classify(value)
        self.assertEqual(DnsCategory.INVALID, decision.category)
        self.assertFalse(decision.eligible)
        self.assertEqual(f"invalid_{reason}", decision.reason)
    return test


for _name, _value, _reason in INVALID_CASES:
    setattr(TestInvalidNames, f"test_invalid_{_name}",
            _make_invalid_case(_name, _value, _reason))


def _make_invalid_type_case(label, value):
    def test(self):
        valid, reason = validate_dns_name(value)
        self.assertFalse(valid)
        self.assertEqual("not_a_string", reason)
        decision = self.classify(value)
        self.assertEqual(DnsCategory.INVALID, decision.category)
        self.assertFalse(decision.eligible)
    return test


for _label, _value in [("none", None), ("int", 7), ("list", ["a.example.com"]),
                       ("bytes", b"a.example.com")]:
    setattr(TestInvalidNames, f"test_invalid_not_a_string_{_label}",
            _make_invalid_type_case(_label, _value))


class TestInvalidNeverResolvedOrSuppressed(EligibilityTestCase, unittest.TestCase):
    def test_invalid_is_never_eligible_even_when_forced(self):
        decision = self.classify("bad_name", policy=self.policy(force=True))
        self.assertEqual(DnsCategory.INVALID, decision.category)
        self.assertFalse(decision.eligible)

    def test_invalid_is_reported_not_dropped(self):
        result = self.select(["good.example.com", "bad_name"])
        self.assertEqual(1, result.invalid)
        self.assertEqual(2, result.candidates)
        self.assertIn("bad_name", [d.name for d in result.decisions])
        self.assertEqual(1, result.counts[DnsCategory.INVALID])

    def test_invalid_name_is_not_marked_resolved(self):
        # INVALID must never appear in the selected set (nothing to resolve)
        result = self.select(["bad_name", "also_bad"])
        self.assertEqual([], result.selected)


# --------------------------------------------------------------------------
# NEW
# --------------------------------------------------------------------------

class TestNewCategory(EligibilityTestCase, unittest.TestCase):
    def test_new_when_no_prior_and_no_attempts(self):
        decision = self.classify("new.example.com")
        self.assertEqual(DnsCategory.NEW, decision.category)
        self.assertTrue(decision.eligible)
        self.assertEqual("never_resolved", decision.reason)

    def test_new_when_prior_is_absent_object(self):
        decision = self.classify("new.example.com", prior=PriorResolution())
        self.assertEqual(DnsCategory.NEW, decision.category)

    def test_new_when_attempt_state_is_zero(self):
        decision = self.classify(
            "new.example.com", attempts=AttemptState(attempts=0, streak=0))
        self.assertEqual(DnsCategory.NEW, decision.category)
        self.assertTrue(decision.eligible)

    def test_new_when_attempts_but_no_last_attempt_timestamp(self):
        # attempts recorded without a timestamp cannot be backoff-scheduled:
        # the safe reading is "retry now", never "suppress"
        decision = self.classify(
            "new.example.com", attempts=AttemptState(attempts=3, streak=3))
        self.assertEqual(DnsCategory.RETRY_ELIGIBLE, decision.category)
        self.assertTrue(decision.eligible)

    def test_new_is_in_eligible_categories(self):
        self.assertIn(DnsCategory.NEW, ELIGIBLE_CATEGORIES)


# --------------------------------------------------------------------------
# FORCE
# --------------------------------------------------------------------------

class TestForceCategory(EligibilityTestCase, unittest.TestCase):
    def test_force_selects_new(self):
        decision = self.classify("a.example.com", policy=self.policy(force=True))
        self.assertEqual(DnsCategory.FORCE, decision.category)
        self.assertTrue(decision.eligible)
        self.assertEqual("forced", decision.reason)

    def test_force_overrides_fresh(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=1),
            policy=self.policy(force=True))
        self.assertEqual(DnsCategory.FORCE, decision.category)
        self.assertTrue(decision.eligible)

    def test_force_overrides_stale(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=500),
            policy=self.policy(force=True))
        self.assertEqual(DnsCategory.FORCE, decision.category)

    def test_force_overrides_retry_backoff(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=4, streak=4, last_hours_ago=1),
            policy=self.policy(force=True, retry_backoff_hours=(168.0,)))
        self.assertEqual(DnsCategory.FORCE, decision.category)
        self.assertTrue(decision.eligible)

    def test_force_does_not_override_invalid(self):
        decision = self.classify("a_b", policy=self.policy(force=True))
        self.assertEqual(DnsCategory.INVALID, decision.category)
        self.assertFalse(decision.eligible)

    def test_force_selects_every_valid_candidate(self):
        names = [f"h{i}.example.com" for i in range(5)]
        prior = {n: self.resolve(n, hours_ago=1) for n in names}
        result = self.select(names, policy=self.policy(force=True),
                             provider=static_provider(prior))
        self.assertEqual(names, result.selected)
        self.assertEqual(0, result.skipped)


# --------------------------------------------------------------------------
# CHANGED
# --------------------------------------------------------------------------

class TestChangedCategory(EligibilityTestCase, unittest.TestCase):
    def test_changed_overrides_fresh(self):
        decision = self.classify(
            "a.example.com",
            prior=self.resolve("a.example.com", hours_ago=0.5, changed=True))
        self.assertEqual(DnsCategory.CHANGED, decision.category)
        self.assertTrue(decision.eligible)
        self.assertEqual("source_changed", decision.reason)

    def test_changed_overrides_stale(self):
        decision = self.classify(
            "a.example.com",
            prior=self.resolve("a.example.com", hours_ago=900, changed=True))
        self.assertEqual(DnsCategory.CHANGED, decision.category)

    def test_changed_reports_age(self):
        decision = self.classify(
            "a.example.com",
            prior=self.resolve("a.example.com", hours_ago=30, changed=True))
        self.assertAlmostEqual(30.0, decision.age_hours, places=3)

    def test_unchanged_source_with_fresh_result_is_fresh(self):
        decision = self.classify(
            "a.example.com",
            prior=self.resolve("a.example.com", hours_ago=1, changed=False))
        self.assertEqual(DnsCategory.FRESH, decision.category)

    def test_changed_is_in_eligible_categories(self):
        self.assertIn(DnsCategory.CHANGED, ELIGIBLE_CATEGORIES)


# --------------------------------------------------------------------------
# STALE / FRESH
# --------------------------------------------------------------------------

class TestStaleAndFresh(EligibilityTestCase, unittest.TestCase):
    def test_stale_when_older_than_freshness(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=13),
            policy=self.policy(freshness_hours=12.0))
        self.assertEqual(DnsCategory.STALE, decision.category)
        self.assertTrue(decision.eligible)
        self.assertEqual("stale_result", decision.reason)

    def test_stale_exactly_at_threshold(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=12),
            policy=self.policy(freshness_hours=12.0))
        self.assertEqual(DnsCategory.STALE, decision.category)
        self.assertTrue(decision.eligible)

    def test_fresh_just_inside_threshold(self):
        decision = self.classify(
            "a.example.com",
            prior=self.resolve("a.example.com", hours_ago=11.99),
            policy=self.policy(freshness_hours=12.0))
        self.assertEqual(DnsCategory.FRESH, decision.category)
        self.assertFalse(decision.eligible)
        self.assertEqual("fresh_result", decision.reason)

    def test_fresh_when_just_resolved(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=0))
        self.assertEqual(DnsCategory.FRESH, decision.category)

    def test_freshness_zero_disables_fresh(self):
        # 0h = "no freshness skipping": a resolved name is always revalidated,
        # which is the pre-EPIC10 behavior and a supported configuration.
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=0),
            policy=self.policy(freshness_hours=0.0))
        self.assertEqual(DnsCategory.STALE, decision.category)
        self.assertTrue(decision.eligible)

    def test_fresh_is_skipped_category(self):
        self.assertIn(DnsCategory.FRESH, SKIPPED_CATEGORIES)

    def test_stale_after_72h(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=73),
            policy=self.policy(freshness_hours=72.0))
        self.assertEqual(DnsCategory.STALE, decision.category)

    def test_fresh_inside_72h(self):
        decision = self.classify(
            "a.example.com", prior=self.resolve("a.example.com", hours_ago=71),
            policy=self.policy(freshness_hours=72.0))
        self.assertEqual(DnsCategory.FRESH, decision.category)


# --------------------------------------------------------------------------
# RETRY_ELIGIBLE / RETRY_BACKOFF
# --------------------------------------------------------------------------

class TestRetryCategories(EligibilityTestCase, unittest.TestCase):
    def test_retry_eligible_after_backoff_elapsed(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=1, streak=1, last_hours_ago=13),
            policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(DnsCategory.RETRY_ELIGIBLE, decision.category)
        self.assertTrue(decision.eligible)
        self.assertEqual("retry_due_streak_1", decision.reason)

    def test_retry_eligible_exactly_at_backoff_boundary(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=1, streak=1, last_hours_ago=12),
            policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(DnsCategory.RETRY_ELIGIBLE, decision.category)

    def test_retry_backoff_inside_window(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=1, streak=1, last_hours_ago=1),
            policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(DnsCategory.RETRY_BACKOFF, decision.category)
        self.assertFalse(decision.eligible)
        self.assertEqual("retry_backoff_streak_1", decision.reason)
        self.assertIsNotNone(decision.next_retry_at)

    def test_retry_backoff_next_retry_at_is_last_attempt_plus_rung(self):
        last = NOW - timedelta(hours=1)
        decision = self.classify(
            "a.example.com",
            attempts=AttemptState(attempts=1, streak=1, last_attempt=last),
            policy=self.policy(retry_backoff_hours=(12.0,)))
        self.assertEqual(last + timedelta(hours=12), decision.next_retry_at)

    def test_second_rung_used_after_second_failure(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=2, streak=2, last_hours_ago=24),
            policy=self.policy(retry_backoff_hours=(12.0, 72.0, 168.0)))
        self.assertEqual(DnsCategory.RETRY_BACKOFF, decision.category)
        self.assertEqual(NOW - timedelta(hours=24) + timedelta(hours=72),
                         decision.next_retry_at)

    def test_third_rung_used_after_third_failure(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=3, streak=3, last_hours_ago=100),
            policy=self.policy(retry_backoff_hours=(12.0, 72.0, 168.0)))
        self.assertEqual(DnsCategory.RETRY_BACKOFF, decision.category)

    def test_ladder_is_capped_at_last_rung(self):
        # a name failing forever must not escalate past the final rung
        for streak in (3, 10, 100):
            wait = self.policy(retry_backoff_hours=(12.0, 72.0, 168.0)) \
                .backoff_for_streak(streak)
            self.assertEqual(168.0, wait)

    def test_zero_ladder_means_retry_every_run(self):
        decision = self.classify(
            "a.example.com",
            attempts=self.attempts(attempts=9, streak=9, last_hours_ago=0),
            policy=self.policy(retry_backoff_hours=(0.0,)))
        self.assertEqual(DnsCategory.RETRY_ELIGIBLE, decision.category)
        self.assertTrue(decision.eligible)

    def test_backoff_for_streak_zero_is_zero(self):
        self.assertEqual(0.0, self.policy().backoff_for_streak(0))

    def test_scalar_ladder_is_normalised_to_one_rung(self):
        policy = self.policy(retry_backoff_hours=12.0)
        self.assertEqual((12.0,), policy.retry_backoff_hours)
        self.assertEqual(12.0, policy.backoff_for_streak(5))

    def test_retry_eligible_is_in_eligible_categories(self):
        self.assertIn(DnsCategory.RETRY_ELIGIBLE, ELIGIBLE_CATEGORIES)

    def test_retry_backoff_is_skipped_category(self):
        self.assertIn(DnsCategory.RETRY_BACKOFF, SKIPPED_CATEGORIES)


# --------------------------------------------------------------------------
# Precedence, determinism, vocabulary
# --------------------------------------------------------------------------

class TestPrecedence(EligibilityTestCase, unittest.TestCase):
    def test_invalid_beats_force(self):
        self.assertEqual(
            DnsCategory.INVALID,
            self.classify("a..b", policy=self.policy(force=True)).category)

    def test_force_beats_changed(self):
        self.assertEqual(
            DnsCategory.FORCE,
            self.classify("a.example.com",
                          prior=self.resolve("a.example.com", hours_ago=1,
                                             changed=True),
                          policy=self.policy(force=True)).category)

    def test_changed_beats_fresh(self):
        self.assertEqual(
            DnsCategory.CHANGED,
            self.classify("a.example.com",
                          prior=self.resolve("a.example.com", hours_ago=0.1,
                                             changed=True)).category)

    def test_new_beats_retry_when_no_attempts(self):
        self.assertEqual(
            DnsCategory.NEW,
            self.classify("a.example.com", attempts=AttemptState()).category)

    def test_resolved_name_is_never_classified_as_retry(self):
        decision = self.classify(
            "a.example.com",
            prior=self.resolve("a.example.com", hours_ago=1),
            attempts=self.attempts(attempts=5, streak=5, last_hours_ago=1))
        self.assertIn(decision.category, (DnsCategory.FRESH, DnsCategory.STALE))

    def test_every_category_is_reachable(self):
        seen = set()
        cases = [
            ("bad_name", None, None, DnsResolutionPolicy()),
            ("a.example.com", None, None, DnsResolutionPolicy(force=True)),
            ("a.example.com", None, None, DnsResolutionPolicy()),
            ("a.example.com", PriorResolution(NOW - timedelta(hours=1), True),
             None, DnsResolutionPolicy()),
            ("a.example.com", PriorResolution(NOW - timedelta(hours=30), False),
             None, DnsResolutionPolicy()),
            ("a.example.com", PriorResolution(NOW - timedelta(hours=1), False),
             None, DnsResolutionPolicy()),
            ("a.example.com", None,
             AttemptState(1, 1, NOW - timedelta(hours=13)), DnsResolutionPolicy()),
            ("a.example.com", None,
             AttemptState(1, 1, NOW - timedelta(hours=1)), DnsResolutionPolicy()),
        ]
        for name, prior, attempts, policy in cases:
            seen.add(classify_dns_candidate(
                name, prior=prior, attempts=attempts, policy=policy, now=NOW).category)
        self.assertEqual(set(CATEGORY_ORDER), seen)

    def test_eligible_and_skipped_partition_the_vocabulary(self):
        self.assertEqual(set(CATEGORY_ORDER),
                         set(ELIGIBLE_CATEGORIES) | set(SKIPPED_CATEGORIES))
        self.assertEqual(set(), set(ELIGIBLE_CATEGORIES) & set(SKIPPED_CATEGORIES))


class TestDeterminism(EligibilityTestCase, unittest.TestCase):
    def test_same_inputs_same_verdict(self):
        kwargs = dict(prior=self.resolve("a.example.com", hours_ago=13),
                      attempts=self.attempts(last_hours_ago=1),
                      policy=self.policy(), now=NOW)
        first = self.classify("a.example.com", **kwargs)
        second = self.classify("a.example.com", **kwargs)
        self.assertEqual(first, second)

    def test_classification_does_not_mutate_inputs(self):
        prior = self.resolve("a.example.com", hours_ago=13)
        attempts = self.attempts(last_hours_ago=1)
        self.classify("a.example.com", prior=prior, attempts=attempts)
        self.assertEqual(13.0, (NOW - prior.last_resolved).total_seconds() / 3600)
        self.assertEqual(1, attempts.streak)

    def test_decision_is_hashable_and_comparable(self):
        decision = self.classify("a.example.com")
        self.assertEqual(decision, self.classify("a.example.com"))

    def test_now_defaults_to_current_time(self):
        decision = classify_dns_candidate(
            "a.example.com", prior=PriorResolution(),
            attempts=AttemptState(), policy=self.policy())
        self.assertEqual(DnsCategory.NEW, decision.category)


if __name__ == "__main__":
    unittest.main(verbosity=2)
