"""EPIC13 §7/§10 — deterministic reflection detection tests."""
from __future__ import annotations

import base64
import unittest
from urllib.parse import quote

from tests.epic13_fixtures import marker_for_action  # noqa: E402

from backend.research_agents.verification.acquisition import detector as dt  # noqa: E402

MARKER = marker_for_action()
OTHER = "HERMES_REFLECT_999999999999"


def detect(body, marker: str = MARKER, **kwargs):
    return dt.detect(body, marker, **kwargs)


class TestRequiredDistinctions(unittest.TestCase):
    """The eleven distinctions §7 requires, one test each."""

    def test_1_marker_absent(self):
        self.assertEqual(detect("<p>nothing</p>").status, dt.ABSENT)

    def test_2_marker_present(self):
        self.assertEqual(detect(f"<p>{MARKER}</p>").status, dt.PRESENT)

    def test_3_marker_present_multiple_times(self):
        result = detect(f"<p>{MARKER}</p><p>{MARKER}</p>")
        self.assertEqual(result.status, dt.MULTIPLE)
        self.assertEqual(result.occurrence_count, 2)

    def test_4_marker_transformed(self):
        result = detect(f"<p>{MARKER.lower()}</p>")
        self.assertEqual(result.status, dt.TRANSFORMED)
        self.assertEqual(result.transformation, dt.TRANSFORMATION_LOWERCASED)

    def test_5_marker_encoded(self):
        encoded = base64.b64encode(MARKER.encode()).decode()
        result = detect(f"<p>{encoded}</p>")
        self.assertEqual(result.status, dt.ENCODED)
        self.assertEqual(result.encoding, dt.ENCODING_BASE64)

    def test_5b_marker_unicode_escaped(self):
        escaped = "".join(f"\\u{ord(c):04X}" for c in MARKER)
        result = detect(f"<script>var a=\"{escaped}\";</script>")
        self.assertEqual(result.status, dt.ENCODED)
        self.assertEqual(result.encoding, dt.ENCODING_UNICODE_ESCAPED)

    def test_5c_marker_numeric_entity_encoded(self):
        entity = "".join(f"&#{ord(c)};" for c in MARKER)
        result = detect(f"<p>{entity}</p>")
        self.assertEqual(result.status, dt.ENCODED)
        self.assertEqual(result.encoding, dt.ENCODING_HTML_NUMERIC_ENTITY)

    def test_6_marker_decoded_from_an_encoded_body(self):
        percent = "".join(f"%{ord(c):02X}" for c in MARKER)
        result = detect(f"<p>{percent}</p>")
        self.assertEqual(result.status, dt.DECODED)
        self.assertEqual(result.body_encoding, dt.BODY_ENCODING_PERCENT)

    def test_6b_marker_decoded_from_a_partly_entity_encoded_body(self):
        mixed = "&#72;&#69;" + MARKER[2:]
        result = detect(f"<p>{mixed}</p>")
        self.assertEqual(result.status, dt.DECODED)
        self.assertEqual(result.body_encoding, dt.BODY_ENCODING_HTML_ENTITY)

    def test_7_marker_in_html_text(self):
        result = detect(f"<p>{MARKER}</p>")
        self.assertEqual(result.context, "HTML_TEXT")

    def test_8_marker_in_an_html_attribute(self):
        result = detect(f'<div data-q="{MARKER}">x</div>')
        self.assertEqual(result.context, "HTML_ATTRIBUTE")

    def test_9_marker_inside_script(self):
        result = detect(f'<script>var q="{MARKER}";</script>')
        self.assertEqual(result.context, "SCRIPT")

    def test_10_marker_in_a_url_context(self):
        result = detect(f'<a href="/next?q={MARKER}">n</a>')
        self.assertEqual(result.context, "URL")

    def test_11_response_body_unavailable(self):
        result = detect(None)
        self.assertEqual(result.status, dt.BODY_UNAVAILABLE)
        self.assertFalse(result.conclusive)


class TestAbsenceAndAvailability(unittest.TestCase):
    def test_absent_is_conclusive_for_a_complete_body(self):
        result = detect("<p>nothing</p>")
        self.assertTrue(result.conclusive)

    def test_absent_is_not_conclusive_for_a_truncated_body(self):
        result = detect("<p>nothing</p>", truncated=True)
        self.assertEqual(result.status, dt.ABSENT)
        self.assertFalse(result.conclusive)

    def test_absent_truncated_reason_mentions_truncation(self):
        self.assertIn("truncated", detect("<p>x</p>", truncated=True).reason)

    def test_present_is_conclusive_even_when_truncated(self):
        result = detect(f"<p>{MARKER}</p>", truncated=True)
        self.assertTrue(result.conclusive)
        self.assertTrue(result.reflected)

    def test_empty_body_is_absent_and_conclusive(self):
        result = detect("")
        self.assertEqual(result.status, dt.ABSENT)
        self.assertTrue(result.conclusive)

    def test_empty_body_is_not_a_negative_for_a_truncated_read(self):
        self.assertFalse(detect("", truncated=True).conclusive)

    def test_missing_marker_is_absent_and_never_conclusive(self):
        result = detect("<p>x</p>", "")
        self.assertEqual(result.status, dt.ABSENT)
        self.assertFalse(result.conclusive)

    def test_non_text_body_is_body_unavailable(self):
        """Fail closed: a non-text body is never reported as an absence."""
        for body in (12345, {"a": 1}, ["x"]):
            self.assertEqual(detect(body).status, dt.BODY_UNAVAILABLE)

    def test_bytes_body_is_decoded_and_searched(self):
        self.assertEqual(detect(b"<p>nothing</p>").status, dt.ABSENT)

    def test_bytes_body_reflecting_the_marker_is_found(self):
        result = detect(f"<p>{MARKER}</p>".encode())
        self.assertEqual(result.status, dt.PRESENT)
        self.assertEqual(result.context, "HTML_TEXT")


class TestReflectionFlag(unittest.TestCase):
    def test_present_is_reflected(self):
        self.assertTrue(detect(f"<p>{MARKER}</p>").reflected)

    def test_multiple_is_reflected(self):
        self.assertTrue(detect(f"{MARKER}{MARKER}").reflected)

    def test_encoded_is_reflected(self):
        encoded = base64.b64encode(MARKER.encode()).decode()
        self.assertTrue(detect(encoded).reflected)

    def test_transformed_is_reflected(self):
        self.assertTrue(detect(MARKER.lower()).reflected)

    def test_decoded_is_reflected(self):
        percent = "".join(f"%{ord(c):02X}" for c in MARKER)
        self.assertTrue(detect(percent).reflected)

    def test_absent_is_not_reflected(self):
        self.assertFalse(detect("<p>x</p>").reflected)

    def test_body_unavailable_is_not_reflected(self):
        self.assertFalse(detect(None).reflected)

    def test_raw_flag_is_true_only_for_a_verbatim_occurrence(self):
        self.assertTrue(detect(f"<p>{MARKER}</p>").to_dict()["raw"])
        self.assertFalse(detect(MARKER.lower()).to_dict()["raw"])


class TestOffsetsAndCounts(unittest.TestCase):
    def test_offsets_are_reported(self):
        body = f"<p>{MARKER}</p>"
        self.assertEqual(detect(body).offsets, [body.find(MARKER)])

    def test_offsets_lists_every_occurrence(self):
        body = f"{MARKER} x {MARKER} y {MARKER}"
        self.assertEqual(len(detect(body).offsets), 3)

    def test_occurrence_count_matches_the_offsets(self):
        body = f"{MARKER}{MARKER}"
        result = detect(body)
        self.assertEqual(result.occurrence_count, len(result.offsets))

    def test_occurrence_count_is_bounded(self):
        body = MARKER * 40
        result = detect(body, limits={"max_occurrences_recorded": 3})
        self.assertLessEqual(len(result.offsets), 3)

    def test_offsets_are_empty_when_absent(self):
        self.assertEqual(detect("<p>x</p>").offsets, [])

    def test_bytes_checked_is_reported(self):
        body = "<p>hello</p>"
        self.assertEqual(detect(body).bytes_checked, len(body))

    def test_bytes_checked_is_bounded_by_the_limits(self):
        body = "<p>" + ("x" * 20000) + "</p>"
        result = detect(body, limits={"max_response_bytes": 512})
        self.assertLessEqual(result.bytes_checked, 512)

    def test_a_window_limited_absence_is_not_conclusive(self):
        body = "<p>" + ("x" * 20000) + "</p>"
        result = detect(body, limits={"max_response_bytes": 512})
        self.assertEqual(result.status, dt.ABSENT)
        self.assertFalse(result.conclusive)
        self.assertTrue(result.truncated)

    def test_the_window_is_the_documented_default(self):
        body = "<p>" + ("x" * 20000) + "</p>"
        self.assertTrue(detect(body).truncated)

    def test_marker_inside_the_window_is_found(self):
        body = f"<p>{MARKER}</p>" + ("x" * 20000)
        result = detect(body, limits={"max_response_bytes": 512})
        self.assertEqual(result.status, dt.PRESENT)
        self.assertTrue(result.conclusive)

    def test_bytes_checked_never_exceeds_the_body_length(self):
        body = "<p>hello</p>"
        self.assertLessEqual(detect(body).bytes_checked, len(body))


class TestEvidenceLocation(unittest.TestCase):
    def test_location_names_the_context_and_offset(self):
        body = f"<p>{MARKER}</p>"
        self.assertEqual(detect(body).evidence_location,
                         f"html_text@offset:{body.find(MARKER)}")

    def test_location_for_a_script_context(self):
        body = f'<script>var q="{MARKER}";</script>'
        self.assertTrue(detect(body).evidence_location.startswith("script@"))

    def test_location_is_empty_when_absent(self):
        self.assertEqual(detect("<p>x</p>").evidence_location, "")

    def test_location_is_empty_when_the_body_is_unavailable(self):
        self.assertEqual(detect(None).evidence_location, "")


class TestOtherMarkers(unittest.TestCase):
    def test_a_different_marker_is_absent(self):
        self.assertEqual(detect(f"<p>{OTHER}</p>").status, dt.ABSENT)

    def test_a_partial_marker_is_absent(self):
        self.assertEqual(detect(f"<p>{MARKER[:10]}</p>").status, dt.ABSENT)

    def test_a_marker_with_a_suffix_is_still_found(self):
        result = detect(f"<p>{MARKER}extra</p>")
        self.assertEqual(result.status, dt.PRESENT)

    def test_a_marker_with_a_prefix_is_still_found(self):
        result = detect(f"<p>prefix{MARKER}</p>")
        self.assertEqual(result.status, dt.PRESENT)

    def test_an_html_escaped_marker_quote_is_absent(self):
        self.assertEqual(detect(f"<p>{MARKER}&#x27;</p>").status, dt.PRESENT)


class TestDetectionContract(unittest.TestCase):
    def test_rule_version_is_declared(self):
        self.assertEqual(detect(f"<p>{MARKER}</p>").detector_version,
                         dt.DETECTOR_RULE_VERSION)

    def test_to_dict_carries_the_required_fields(self):
        payload = detect(f"<p>{MARKER}</p>").to_dict()
        for key in ("status", "marker", "occurrence_count", "offsets",
                    "context", "encoding", "transformation",
                    "evidence_location", "detector_version", "conclusive"):
            self.assertIn(key, payload)

    def test_to_dict_never_carries_the_body(self):
        body = f"<p>SECRET-BODY-TEXT-{MARKER}</p>"
        self.assertNotIn("SECRET-BODY-TEXT", str(detect(body).to_dict()))

    def test_detector_document_declares_every_status(self):
        document = dt.detector_document()
        for status in (dt.ABSENT, dt.PRESENT, dt.MULTIPLE, dt.TRANSFORMED,
                       dt.ENCODED, dt.DECODED, dt.BODY_UNAVAILABLE):
            self.assertIn(status, str(document))

    def test_detector_document_never_claims_xss(self):
        document = dt.detector_document()
        self.assertIn("not", str(document).lower())

    def test_detector_document_declares_the_closed_encodings(self):
        document = dt.detector_document()
        self.assertIn("encodings", str(document).lower())

    def test_detector_is_deterministic(self):
        body = f"<p>{MARKER}</p>"
        self.assertEqual(detect(body).to_dict(), detect(body).to_dict())

    def test_detector_is_pure(self):
        body = f"<p>{MARKER}</p>"
        before = str(body)
        detect(body)
        self.assertEqual(str(body), before)


class TestEncodingOrderIsDeterministic(unittest.TestCase):
    def test_verbatim_beats_every_encoding(self):
        body = f"{MARKER} and {base64.b64encode(MARKER.encode()).decode()}"
        self.assertEqual(detect(body).status, dt.PRESENT)
        self.assertTrue(detect(body).to_dict()["raw"])

    def test_verbatim_wins_over_an_encoded_occurrence(self):
        body = f"{base64.b64encode(MARKER.encode()).decode()} and {MARKER}"
        self.assertEqual(detect(body).status, dt.PRESENT)

    def test_base64_beats_percent_of_the_body(self):
        encoded = base64.b64encode(MARKER.encode()).decode()
        body = f"{quote(encoded)}"
        self.assertEqual(detect(body).status, dt.ENCODED)

    def test_lowercased_beats_decoding(self):
        self.assertEqual(detect(MARKER.lower()).status, dt.TRANSFORMED)

    def test_uppercase_transformation_is_not_reported_as_transformed(self):
        """The marker is already uppercase; uppercase is the raw form."""
        self.assertEqual(detect(MARKER.upper()).status, dt.PRESENT)


if __name__ == "__main__":
    unittest.main()
