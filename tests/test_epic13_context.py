"""EPIC13 §8 — deterministic context classification tests."""
from __future__ import annotations

import unittest

from tests.epic13_fixtures import body_with, marker_for_action  # noqa: E402

from backend.research_agents.verification.acquisition import context as cx  # noqa: E402

MARKER = marker_for_action()
OTHER = "HERMES_REFLECT_999999999999"


def classify(sample: str, marker: str = MARKER) -> str:
    return cx.classify(sample, marker)


class TestRequiredContexts(unittest.TestCase):
    """The eight classes §8 requires, each from a real document shape."""

    def test_html_text(self):
        self.assertEqual(classify(f"<p>{MARKER}</p>"), cx.HTML_TEXT)

    def test_html_attribute(self):
        self.assertEqual(classify(f'<div data-q="{MARKER}">x</div>'),
                         cx.HTML_ATTRIBUTE)

    def test_script(self):
        self.assertEqual(classify(f'<script>var q="{MARKER}";</script>'),
                         cx.SCRIPT)

    def test_style(self):
        self.assertEqual(classify(f"<style>/* {MARKER} */</style>"),
                         cx.STYLE)

    def test_url(self):
        self.assertEqual(classify(f'<a href="/next?q={MARKER}">n</a>'),
                         cx.URL)

    def test_json(self):
        self.assertEqual(classify(f'<script type="application/json">'
                                  f'{{"q":"{MARKER}"}}</script>'),
                         cx.JSON_CONTEXT)

    def test_comment(self):
        self.assertEqual(classify(f"<!-- {MARKER} -->"), cx.COMMENT)

    def test_unknown(self):
        self.assertEqual(classify(f"<div {MARKER}>"), cx.UNKNOWN)

    def test_absent_marker_classifies_to_nothing(self):
        self.assertEqual(classify("<p>nothing</p>"), "")

    def test_every_class_is_in_the_declared_vocabulary(self):
        for klass in (cx.HTML_TEXT, cx.HTML_ATTRIBUTE, cx.SCRIPT, cx.STYLE,
                      cx.URL, cx.JSON_CONTEXT, cx.COMMENT, cx.UNKNOWN):
            self.assertIn(klass, cx.CONTEXT_CLASSES)


class TestContextDetails(unittest.TestCase):
    def test_attribute_value_in_a_url_attribute_is_url(self):
        self.assertEqual(classify(f'<form action="/go?q={MARKER}">'),
                         cx.URL)

    def test_src_attribute_is_url(self):
        self.assertEqual(classify(f'<img src="/i?q={MARKER}">'), cx.URL)

    def test_event_handler_attribute_is_an_attribute(self):
        self.assertEqual(classify(f'<div onclick="f(\'{MARKER}\')">'),
                         cx.HTML_ATTRIBUTE)

    def test_json_script_block_is_not_script(self):
        """A data block is not executable code (§8 distinction)."""
        self.assertEqual(classify(f'<script type="application/json">'
                                  f'["{MARKER}"]</script>'),
                         cx.JSON_CONTEXT)

    def test_bare_json_document_is_json(self):
        self.assertEqual(classify(f'{{"q":"{MARKER}"}}'), cx.JSON_CONTEXT)

    def test_style_block_wins_over_text(self):
        self.assertEqual(classify(f"<style>a{{content:'{MARKER}'}}</style>"),
                         cx.STYLE)

    def test_comment_wins_over_text(self):
        self.assertEqual(classify(f"<p>x</p><!-- {MARKER} -->"), cx.COMMENT)

    def test_text_between_tags_is_html_text(self):
        self.assertEqual(classify(f"<div><span>{MARKER}</span></div>"),
                         cx.HTML_TEXT)

    def test_multi_context_body_reports_the_script_context(self):
        """The most security-relevant occurrence decides the class."""
        sample = f"<p>{MARKER}</p><script>var a='{MARKER}';</script>"
        self.assertEqual(classify(sample), cx.SCRIPT)

    def test_classify_with_offset_reports_a_consistent_location(self):
        """The reported offset is one where ``classify`` yields that class."""
        sample = f"<p>{MARKER}</p><script>var a='{MARKER}';</script>"
        klass, index = cx.classify_with_offset(sample, MARKER)
        self.assertEqual(klass, cx.SCRIPT)
        self.assertEqual(cx.classify(sample, MARKER, offset=index), klass)

    def test_classify_with_offset_is_the_first_occurrence_for_one_context(self):
        sample = f"<p>{MARKER}</p>"
        klass, index = cx.classify_with_offset(sample, MARKER)
        self.assertEqual((klass, index), (cx.HTML_TEXT, sample.find(MARKER)))

    def test_classify_with_offset_is_empty_when_absent(self):
        self.assertEqual(cx.classify_with_offset("<p>x</p>", MARKER), ("", -1))

    def test_other_marker_is_ignored(self):
        self.assertEqual(classify(f"<p>{OTHER}</p>"), "")

    def test_empty_sample(self):
        self.assertEqual(classify(""), "")

    def test_whitespace_only_sample(self):
        self.assertEqual(classify("   \n\t"), "")


class TestContextHonesty(unittest.TestCase):
    def test_dom_analysis_is_declared_unavailable(self):
        self.assertEqual(cx.DOM_ANALYSIS_UNAVAILABLE, "DOM_ANALYSIS_UNAVAILABLE")

    def test_classification_document_separates_reflection_from_sink(self):
        document = cx.classification_document()
        self.assertIn("SERVER_REFLECTION != DOM_SINK", document["distinctions"])

    def test_classification_document_separates_sink_from_execution(self):
        document = cx.classification_document()
        self.assertIn("DOM_SINK != EXECUTION", document["distinctions"])

    def test_classification_document_reuses_the_platform_classifier(self):
        document = cx.classification_document()
        self.assertIn("classify_reflection_location", document["delegates_to"])

    def test_classification_document_declares_dom_unavailable(self):
        document = cx.classification_document()
        self.assertEqual(document.get("dom_analysis"),
                         cx.DOM_ANALYSIS_UNAVAILABLE)

    def test_classification_document_lists_the_classes(self):
        document = cx.classification_document()
        self.assertEqual(set(document.get("classes") or []),
                         set(cx.CONTEXT_CLASSES))

    def test_review_contexts_are_the_executable_ones(self):
        self.assertIn(cx.SCRIPT, cx.CONTEXTS_REQUIRING_REVIEW)
        self.assertIn(cx.HTML_ATTRIBUTE, cx.CONTEXTS_REQUIRING_REVIEW)

    def test_inert_contexts_are_not_flagged_for_review(self):
        self.assertNotIn(cx.COMMENT, cx.CONTEXTS_REQUIRING_REVIEW)

    def test_rule_version_is_declared(self):
        self.assertEqual(cx.CONTEXT_RULE_VERSION, "epic13-context-1")

    def test_classification_never_claims_execution(self):
        """§8: a context class is not exploitability."""
        document = cx.classification_document()
        self.assertTrue(any("exploitability" in str(v).lower()
                            for v in document["distinctions"]))


class TestContextFromBodies(unittest.TestCase):
    """The same decision, driven from whole response bodies."""

    def test_body_text(self):
        self.assertEqual(classify(body_with(MARKER, context="text")),
                         cx.HTML_TEXT)

    def test_body_attribute(self):
        self.assertEqual(classify(body_with(MARKER, context="attribute")),
                         cx.HTML_ATTRIBUTE)

    def test_body_url(self):
        self.assertEqual(classify(body_with(MARKER, context="url")), cx.URL)

    def test_body_script(self):
        self.assertEqual(classify(body_with(MARKER, context="script")),
                         cx.SCRIPT)

    def test_body_style(self):
        self.assertEqual(classify(body_with(MARKER, context="style")),
                         cx.STYLE)

    def test_body_comment(self):
        self.assertEqual(classify(body_with(MARKER, context="comment")),
                         cx.COMMENT)

    def test_body_json(self):
        self.assertEqual(classify(body_with(MARKER, context="json")),
                         cx.JSON_CONTEXT)


if __name__ == "__main__":
    unittest.main()
