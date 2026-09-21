"""EPIC6 Part 7+17: real-vs-fixture isolation, production-claim guard."""

from __future__ import annotations

import unittest

from aec.research.guard import (
    ensure_no_production_claim, is_production_claim, promotable_to_production,
    same_source_mode)


class TestProductionClaimGuard(unittest.TestCase):
    def test_claim_markers_detected(self):
        for marker in ("confirmed", "vulnerable", "exploitable",
                       "finding", "verdict"):
            self.assertTrue(is_production_claim({"outcome": marker}))

    def test_case_insensitive(self):
        self.assertTrue(is_production_claim({"outcome": "CONFIRMED"}))
        self.assertTrue(is_production_claim({"status": "Vulnerable"}))

    def test_clean_document_allowed(self):
        self.assertFalse(is_production_claim({
            "outcome": "POTENTIAL", "confidence": "low"}))

    def test_empty_document_allowed(self):
        self.assertFalse(is_production_claim({}))

    def test_non_string_values_ignored(self):
        self.assertFalse(is_production_claim({"count": 5, "flag": True}))

    def test_ensure_raises_on_claim(self):
        with self.assertRaises(ValueError):
            ensure_no_production_claim({"outcome": "confirmed"}, "report")

    def test_ensure_passes_clean(self):
        ensure_no_production_claim({"outcome": "POTENTIAL"}, "report")

    def test_ensure_context_in_message(self):
        with self.assertRaises(ValueError) as ctx:
            ensure_no_production_claim({"outcome": "finding"}, "ctx-name")
        self.assertIn("ctx-name", str(ctx.exception))


class TestPromotionBoundary(unittest.TestCase):
    def test_nothing_promotable(self):
        self.assertFalse(promotable_to_production({"outcome": "POTENTIAL"}))
        self.assertFalse(promotable_to_production({"outcome": "CONFIRMED"}))
        self.assertFalse(promotable_to_production({}))

    def test_fixture_never_promotable(self):
        self.assertFalse(promotable_to_production({
            "source_mode": "OFFLINE_FIXTURE",
            "outcome": "POTENTIAL"}))

    def test_real_data_also_not_auto_promotable(self):
        self.assertFalse(promotable_to_production({
            "source_mode": "REAL_WATCH_DATA",
            "outcome": "POTENTIAL"}))


class TestSourceModeEquality(unittest.TestCase):
    def test_same_mode_true(self):
        self.assertTrue(same_source_mode("REAL_WATCH_DATA", "REAL_WATCH_DATA"))
        self.assertTrue(same_source_mode("OFFLINE_FIXTURE", "OFFLINE_FIXTURE"))

    def test_cross_mode_false(self):
        self.assertFalse(
            same_source_mode("REAL_WATCH_DATA", "OFFLINE_FIXTURE"))
        self.assertFalse(
            same_source_mode("OFFLINE_FIXTURE", "REAL_WATCH_DATA"))


if __name__ == "__main__":
    unittest.main()