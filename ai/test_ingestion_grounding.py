import unittest

from ai.ingestion.grounding import (
    FORBIDDEN_PAYLOAD_PATTERNS,
    claim_fingerprint,
    contains_forbidden,
    normalize_for_grounding,
    value_grounded,
)


class NormalizeForGroundingTests(unittest.TestCase):
    def test_lowercases_ascii(self):
        self.assertEqual(
            normalize_for_grounding("Strict WAF"),
            "strict waf",
        )

    def test_collapses_whitespace(self):
        self.assertEqual(
            normalize_for_grounding(
                "  strict\t\n waf   is\nfront  "
            ),
            "strict waf is front",
        )

    def test_preserves_underscore_punctuation(self):
        self.assertEqual(
            normalize_for_grounding("html_attribute"),
            "html_attribute",
        )

    def test_preserves_unicode_letters(self):
        self.assertEqual(
            normalize_for_grounding("Café résumé"),
            "café résumé",
        )

    def test_preserves_non_latin_scripts(self):
        self.assertEqual(
            normalize_for_grounding("テスト データ"),
            "テスト データ",
        )

    def test_does_not_transliterate_to_ascii(self):
        self.assertNotEqual(
            normalize_for_grounding("é"),
            "e",
        )

    def test_does_not_strip_punctuation(self):
        self.assertEqual(
            normalize_for_grounding("a.b-c_d:e/f"),
            "a.b-c_d:e/f",
        )

    def test_html_attribute_not_collapsed(self):
        self.assertEqual(
            normalize_for_grounding("html_attribute"),
            "html_attribute",
        )

    def test_empty_string_returns_empty(self):
        self.assertEqual(normalize_for_grounding(""), "")

    def test_whitespace_only_returns_empty(self):
        self.assertEqual(
            normalize_for_grounding("   \t\n  "), ""
        )

    def test_deterministic(self):
        first = normalize_for_grounding("Hello, World!  Foo")
        second = normalize_for_grounding("Hello, World!  Foo")
        self.assertEqual(first, second)

    def test_unicode_case_folding(self):
        self.assertEqual(
            normalize_for_grounding("CAFÉ"),
            normalize_for_grounding("café"),
        )


class ValueGroundedTests(unittest.TestCase):
    def test_case_insensitive_match(self):
        self.assertTrue(
            value_grounded(
                "strict waf",
                "Strict WAF is in front of the endpoint",
            )
        )

    def test_whitespace_insensitive_match(self):
        self.assertTrue(
            value_grounded(
                "strict  waf",
                "Strict   WAF",
            )
        )

    def test_unicode_value_grounds_against_unicode_content(
        self,
    ):
        self.assertTrue(
            value_grounded(
                "Café",
                "The endpoint serves Café pages.",
            )
        )

    def test_preserves_underscore_value_grounding(self):
        self.assertTrue(
            value_grounded(
                "html_attribute",
                "context.type=html_attribute is observed",
            )
        )

    def test_empty_value_returns_false(self):
        self.assertFalse(value_grounded("", "anything"))

    def test_whitespace_only_value_returns_false(self):
        self.assertFalse(value_grounded("   \t  ", "anything"))

    def test_empty_content_returns_false(self):
        self.assertFalse(value_grounded("Strict WAF", ""))

    def test_none_inputs_return_false(self):
        self.assertFalse(value_grounded(None, "x"))
        self.assertFalse(value_grounded("x", None))

    def test_value_not_in_content_returns_false(self):
        self.assertFalse(
            value_grounded("imaginary waf", "Strict WAF")
        )


class ClaimFingerprintTests(unittest.TestCase):
    def test_independent_of_list_ordering(self):
        first = claim_fingerprint(
            {
                "xss_types": ["reflected", "dom"],
                "contexts": ["html_attribute"],
            }
        )
        second = claim_fingerprint(
            {
                "xss_types": ["dom", "reflected"],
                "contexts": ["html_attribute"],
            }
        )
        self.assertEqual(first, second)

    def test_materially_different_claims_differ(self):
        first = claim_fingerprint(
            {"xss_types": ["reflected"]}
        )
        second = claim_fingerprint(
            {"xss_types": ["stored"]}
        )
        self.assertNotEqual(first, second)

    def test_field_set_difference_changes_fingerprint(self):
        first = claim_fingerprint(
            {"xss_types": ["reflected"]}
        )
        second = claim_fingerprint(
            {
                "xss_types": ["reflected"],
                "contexts": ["html_attribute"],
            }
        )
        self.assertNotEqual(first, second)

    def test_deterministic_across_repeated_calls(self):
        claim = {
            "xss_types": ["reflected"],
            "contexts": ["html_attribute"],
            "wafs": ["Strict WAF"],
        }
        first = claim_fingerprint(claim)
        second = claim_fingerprint(claim)
        self.assertEqual(first, second)

    def test_value_change_changes_fingerprint(self):
        first = claim_fingerprint(
            {"confidence": 0.9, "xss_types": ["reflected"]}
        )
        second = claim_fingerprint(
            {"confidence": 0.5, "xss_types": ["reflected"]}
        )
        self.assertNotEqual(first, second)

    def test_unicode_values_produce_deterministic_fingerprint(
        self,
    ):
        first = claim_fingerprint({"title": "Café résumé"})
        second = claim_fingerprint({"title": "Café résumé"})
        self.assertEqual(first, second)

    def test_unicode_values_are_hashed_as_bytes(self):
        # The fingerprint is a deterministic hash of the
        # bytes the caller hands in. It does not apply any
        # Unicode normalization of its own. Two visually
        # different but NFKC-equivalent strings therefore
        # produce different fingerprints here (any
        # normalization must happen at the call site, in
        # normalize_for_grounding).
        first = claim_fingerprint({"title": "Café"})
        second = claim_fingerprint(
            {"title": "Cafe\u0301"}  # "Café" with combining acute
        )
        self.assertNotEqual(first, second)

    def test_fingerprint_is_hex_sha256(self):
        fingerprint = claim_fingerprint({"xss_types": ["reflected"]})
        self.assertEqual(len(fingerprint), 64)
        self.assertTrue(
            all(character in "0123456789abcdef" for character in fingerprint)
        )


class ContainsForbiddenTests(unittest.TestCase):
    def test_script_tag_detected(self):
        self.assertTrue(contains_forbidden("<script>alert(1)</script>"))
        self.assertTrue(contains_forbidden("<SCRIPT >alert(1)</SCRIPT>"))
        self.assertTrue(contains_forbidden("<\n  script  >x"))

    def test_javascript_url_detected(self):
        self.assertTrue(
            contains_forbidden("href=\"javascript:alert(1)\"")
        )
        self.assertTrue(
            contains_forbidden("JAVASCRIPT:alert(1)")
        )

    def test_event_handler_attribute_detected(self):
        self.assertTrue(contains_forbidden('x onerror="alert(1)"'))
        self.assertTrue(contains_forbidden("x onload=y"))
        self.assertTrue(contains_forbidden("x ONCLICK = y"))
        self.assertTrue(contains_forbidden("x onmouseover=alert(1)"))
        self.assertTrue(contains_forbidden("x onfocus=alert(1)"))

    def test_data_url_html_detected(self):
        self.assertTrue(
            contains_forbidden("iframe src=\"data:text/html,foo\"")
        )

    def test_eval_and_document_write_detected(self):
        self.assertTrue(contains_forbidden("eval(atob('...'))"))
        self.assertTrue(contains_forbidden("document.write('<x>')"))
        self.assertTrue(contains_forbidden("document.writeln('<x>')"))

    def test_normal_research_terminology_not_rejected(self):
        self.assertFalse(contains_forbidden("onerror bypass technique"))
        self.assertFalse(contains_forbidden("script context"))
        self.assertFalse(contains_forbidden("JavaScript context"))
        self.assertFalse(contains_forbidden("strict WAF"))
        self.assertFalse(contains_forbidden("attribute breakout"))
        self.assertFalse(contains_forbidden("reflected XSS"))
        self.assertFalse(contains_forbidden("DOM-based sink analysis"))

    def test_short_base64_like_blob_not_rejected(self):
        # Short base64-looking tokens (well under the threshold)
        # are not blobs and must not be rejected.
        self.assertFalse(contains_forbidden("aGVsbG8="))
        self.assertFalse(contains_forbidden("dGVzdA=="))

    def test_normal_short_strings_not_rejected(self):
        self.assertFalse(contains_forbidden("attribute breakout marker"))
        self.assertFalse(contains_forbidden("html_attribute"))
        self.assertFalse(contains_forbidden("Strict WAF"))

    def test_long_base64_like_blob_detected(self):
        long_blob = "A" * 250
        self.assertTrue(contains_forbidden(long_blob))
        # A single contiguous 250-char run of base64 alphabet
        # characters. The detector requires the blob to be
        # bounded by word boundaries; flanking spaces guarantee
        # the regex anchors fire.
        long_blob_mixed = " " + ("AbCdEfGh" * 32) + " "
        self.assertGreaterEqual(len(long_blob_mixed.strip()), 256)
        self.assertTrue(contains_forbidden(long_blob_mixed))

    def test_empty_value_returns_false(self):
        self.assertFalse(contains_forbidden(""))

    def test_deterministic(self):
        value = "<script>alert(1)</script>"
        self.assertEqual(
            contains_forbidden(value),
            contains_forbidden(value),
        )


class PublicSurfaceTests(unittest.TestCase):
    def test_forbidden_payload_patterns_is_public_tuple(self):
        self.assertIsInstance(FORBIDDEN_PAYLOAD_PATTERNS, tuple)
        self.assertGreater(len(FORBIDDEN_PAYLOAD_PATTERNS), 0)

    def test_every_pattern_is_a_compiled_regex(self):
        import re

        for pattern in FORBIDDEN_PAYLOAD_PATTERNS:
            self.assertIsInstance(pattern, re.Pattern)


if __name__ == "__main__":
    unittest.main()
