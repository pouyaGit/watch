"""EPIC13 §5 — marker generation tests."""
from __future__ import annotations

import unittest

from tests.epic13_fixtures import (  # noqa: E402
    CANDIDATE_ID, OBJECTIVE_ID, PARAMETER, marker_for_action as marker_for)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification.acquisition import markers as mk  # noqa: E402


class TestMarkerShape(unittest.TestCase):
    def test_marker_has_the_documented_prefix(self):
        marker = marker_for()
        self.assertTrue(marker.startswith(mk.MARKER_PREFIX))

    def test_marker_matches_the_documented_pattern(self):
        self.assertRegex(marker_for(), r"^HERMES_REFLECT_[0-9A-F]{12}$")

    def test_marker_length_is_bounded(self):
        self.assertLessEqual(len(marker_for()), mk.MAX_MARKER_LENGTH)

    def test_marker_uses_only_the_inert_alphabet(self):
        marker = marker_for()
        for char in marker:
            self.assertIn(char, mk.MARKER_ALPHABET)

    def test_marker_carries_no_html_metacharacters(self):
        marker = marker_for()
        for char in ("<", ">", '"', "'", "&", "(", ")", "/", "\\", ";", ":"):
            self.assertNotIn(char, marker)

    def test_marker_carries_no_url_metacharacters(self):
        marker = marker_for()
        for char in ("?", "#", "=", "&", "%", " "):
            self.assertNotIn(char, marker)

    def test_marker_is_not_a_payload(self):
        """§15: a marker is never an exploit payload."""
        marker = marker_for()
        lowered = marker.lower()
        for token in ("script", "onerror", "onload", "javascript", "alert",
                      "svg", "img", "eval"):
            self.assertNotIn(token, lowered)

    def test_marker_is_ascii(self):
        self.assertTrue(marker_for().isascii())


class TestMarkerDeterminism(unittest.TestCase):
    def test_same_action_yields_the_same_marker(self):
        self.assertEqual(marker_for(), marker_for())

    def test_different_actions_yield_different_markers(self):
        first = marker_for(parameter="q")
        second = marker_for(parameter="redirect")
        self.assertNotEqual(first, second)

    def test_different_attempts_yield_different_markers(self):
        self.assertNotEqual(marker_for(attempt=1), marker_for(attempt=2))

    def test_different_action_types_yield_different_markers(self):
        first = marker_for(action_type=ac.SEND_MARKER)
        second = marker_for(action_type=ac.CLASSIFY_REFLECTION_CONTEXT)
        self.assertNotEqual(first, second)

    def test_different_candidates_yield_different_markers(self):
        first = marker_for(candidate_id=CANDIDATE_ID)
        second = marker_for(candidate_id="cand-other")
        self.assertNotEqual(first, second)

    def test_marker_body_is_stable_for_a_fixed_action(self):
        action_id = ac.action_id_for(candidate_id=CANDIDATE_ID,
                                     objective_id=OBJECTIVE_ID,
                                     action_type=ac.SEND_MARKER, attempt=1,
                                     salt=PARAMETER)
        self.assertEqual(mk.marker_body(action_id, PARAMETER, 1),
                         mk.marker_body(action_id, PARAMETER, 1))

    def test_no_static_marker_across_two_hundred_actions(self):
        """§5: the marker is never a fixed string."""
        seen = {marker_for(parameter=f"p{i}") for i in range(200)}
        self.assertEqual(len(seen), 200)

    def test_markers_are_unique_across_attempts_and_parameters(self):
        seen = set()
        for parameter in ("q", "redirect", "next"):
            for attempt in (1, 2, 3):
                seen.add(marker_for(parameter=parameter, attempt=attempt))
        self.assertEqual(len(seen), 9)


class TestMarkerValidation(unittest.TestCase):
    def test_validate_accepts_a_generated_marker(self):
        self.assertEqual(mk.validate(marker_for()), marker_for())

    def test_validate_rejects_an_empty_marker(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("")

    def test_validate_rejects_a_marker_with_a_payload(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("HERMES_REFLECT_AB12CD34EF56<script>")

    def test_validate_rejects_a_quoted_marker(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate('HERMES_REFLECT_AB12CD34EF56"')

    def test_validate_rejects_an_over_long_marker(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("HERMES_REFLECT_" + "A" * (mk.MAX_MARKER_LENGTH + 5))

    def test_validate_rejects_a_non_string(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate(None)  # type: ignore[arg-type]

    def test_validate_rejects_a_marker_with_whitespace(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("HERMES_REFLECT_AB12CD34EF56 ")

    def test_is_marker_true_for_a_generated_marker(self):
        self.assertTrue(mk.is_marker(marker_for()))

    def test_is_marker_false_for_random_text(self):
        self.assertFalse(mk.is_marker("HERMES_REFLECT_not-hex"))

    def test_is_marker_false_for_a_substring(self):
        self.assertFalse(mk.is_marker("prefix" + marker_for()))


class TestMarkerTraceability(unittest.TestCase):
    def test_occurrences_finds_every_offset(self):
        marker = marker_for()
        text = f"{marker} and {marker}"
        self.assertEqual(mk.occurrences(text, marker), [0, len(marker) + 5])

    def test_occurrences_is_empty_when_absent(self):
        self.assertEqual(mk.occurrences("nothing here", marker_for()), [])

    def test_lineage_records_the_action_id(self):
        marker = marker_for()
        action_id = ac.action_id_for(candidate_id=CANDIDATE_ID,
                                     objective_id=OBJECTIVE_ID,
                                     action_type=ac.SEND_MARKER, attempt=1,
                                     salt=PARAMETER)
        lineage = mk.marker_lineage(marker, action_id, PARAMETER, 1)
        self.assertEqual(lineage["action_id"], action_id)
        self.assertEqual(lineage["marker"], marker)

    def test_lineage_records_the_parameter(self):
        marker = marker_for()
        lineage = mk.marker_lineage(marker, "act-x", "redirect", 2)
        self.assertEqual(lineage["parameter"], "redirect")
        self.assertEqual(lineage["attempt"], 2)

    def test_marker_document_declares_the_rule_version(self):
        self.assertEqual(mk.marker_document()["rule_version"],
                         mk.MARKER_RULE_VERSION)

    def test_marker_document_declares_the_inert_property(self):
        document = mk.marker_document()
        self.assertIn("inert", document["properties"])

    def test_marker_document_declares_uniqueness_per_action(self):
        document = mk.marker_document()
        self.assertIn("unique-per-action", document["properties"])

    def test_marker_document_publishes_the_derivation(self):
        document = mk.marker_document()
        self.assertIn("sha256", document["derivation"])


if __name__ == "__main__":
    unittest.main()
