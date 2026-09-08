"""Focused regression tests for ResearchResult.affected_products robustness.

Covers the real 3-CVE batch failure where CVE-2026-1557 LLM output
contained::

    {"name": "WP Responsive Images", "type": "WordPress Plugin"}

inside ``affected_products``, which must canonically stay ``list[str]``.

All tests are offline. No LLM calls, no Mongo writes, no Nuclei execution.
"""

from __future__ import annotations

import unittest

from pydantic import ValidationError

from ai.schemas.research import ResearchResult, stringify_affected_product


def _base_payload(**overrides):
    payload = {
        "title": "CVE-2026-1557",
        "summary": "Test summary.",
    }
    payload.update(overrides)
    return payload


class StringifyAffectedProductTests(unittest.TestCase):
    def test_string_unchanged(self) -> None:
        self.assertEqual(
            stringify_affected_product("WP Responsive Images"),
            "WP Responsive Images",
        )

    def test_dict_with_name(self) -> None:
        self.assertEqual(
            stringify_affected_product({"name": "WP Responsive Images"}),
            "WP Responsive Images",
        )

    def test_dict_with_name_and_type(self) -> None:
        self.assertEqual(
            stringify_affected_product(
                {"name": "WP Responsive Images", "type": "WordPress Plugin"}
            ),
            "WP Responsive Images (WordPress Plugin)",
        )

    def test_malformed_dict_returns_none(self) -> None:
        self.assertIsNone(stringify_affected_product({}))
        self.assertIsNone(stringify_affected_product({"type": "WordPress Plugin"}))
        self.assertIsNone(stringify_affected_product({"name": "   "}))

    def test_none_returns_none(self) -> None:
        self.assertIsNone(stringify_affected_product(None))


class AffectedProductsNormalizationTests(unittest.TestCase):
    def test_normal_list_of_strings_preserved(self) -> None:
        result = ResearchResult.model_validate(
            _base_payload(affected_products=["Plugin A", "Theme B"])
        )
        self.assertEqual(result.affected_products, ["Plugin A", "Theme B"])

    def test_dict_name_normalized(self) -> None:
        result = ResearchResult.model_validate(
            _base_payload(affected_products=[{"name": "WP Responsive Images"}])
        )
        self.assertEqual(result.affected_products, ["WP Responsive Images"])

    def test_dict_name_and_type_normalized(self) -> None:
        # Exact payload shape from the CVE-2026-1557 batch failure.
        result = ResearchResult.model_validate(
            _base_payload(
                affected_products=[
                    {"name": "WP Responsive Images", "type": "WordPress Plugin"}
                ]
            )
        )
        self.assertEqual(
            result.affected_products, ["WP Responsive Images (WordPress Plugin)"]
        )

    def test_mixed_strings_and_objects(self) -> None:
        result = ResearchResult.model_validate(
            _base_payload(
                affected_products=[
                    "Plain Product",
                    {"name": "WP Responsive Images", "type": "WordPress Plugin"},
                    {"name": "Other Plugin"},
                ]
            )
        )
        self.assertEqual(
            result.affected_products,
            [
                "Plain Product",
                "WP Responsive Images (WordPress Plugin)",
                "Other Plugin",
            ],
        )

    def test_malformed_object_dropped_conservatively(self) -> None:
        result = ResearchResult.model_validate(
            _base_payload(affected_products=[{}, {"foo": "bar"}])
        )
        # No product invented from malformed objects.
        self.assertEqual(result.affected_products, [])

    def test_canonical_type_stays_list_of_str(self) -> None:
        field = ResearchResult.model_fields["affected_products"]
        # The annotation must remain strictly list[str]; normalization
        # happens at the boundary, not via a widened schema.
        self.assertEqual(str(field.annotation), "list[str]")

    def test_existing_validation_still_rejects_bad_scalars(self) -> None:
        # Strings pass; nested containers must not become products.
        result = ResearchResult.model_validate(
            _base_payload(affected_products=[["nested"], "Fine"])
        )
        self.assertEqual(result.affected_products, ["Fine"])

    def test_no_regression_for_missing_field(self) -> None:
        result = ResearchResult.model_validate(_base_payload())
        self.assertEqual(result.affected_products, [])

    def test_unrelated_fields_not_silently_normalized(self) -> None:
        # An object inside an unrelated list[str] field must still fail:
        # normalization applies ONLY to affected_products.
        with self.assertRaises(ValidationError):
            ResearchResult.model_validate(
                _base_payload(impact=[{"name": "XSS", "type": "impact"}])
            )


class ResearchPromptRenderingTests(unittest.TestCase):
    """Regression test for the f-string prompt crash.

    The affected_products instruction added to the research prompt
    contains a literal JSON example with ``{}`` braces. Inside the
    f-string in ``SecurityResearcher.research`` those braces must be
    escaped (``{{``/``}}``); otherwise prompt construction raises::

        ValueError: Invalid format specifier ...
    """

    def test_prompt_renders_with_affected_products_json_example(self) -> None:
        from ai.researcher.researcher import SecurityResearcher
        from ai.schemas.source import ResearchDocument

        captured = {}

        class FakeLLM:
            def generate(self, prompt: str) -> str:
                captured["prompt"] = prompt
                return '{"title": "CVE-2026-1557", "summary": "ok"}'

        researcher = SecurityResearcher(llm=FakeLLM())
        document = ResearchDocument(
            source_type="nvd",
            title="CVE-2026-1557",
            content="Test content.",
        )

        # Must not raise ValueError from unescaped f-string braces.
        result = researcher.research(
            document=document,
            programs=[],
            assets=[],
            technologies=[],
        )

        self.assertEqual(result.title, "CVE-2026-1557")

        prompt = captured["prompt"]
        # The rendered prompt must contain the intended literal JSON
        # shape with single braces (i.e. the escape resolved correctly).
        self.assertIn("affected_products MUST be an array of strings", prompt)
        self.assertIn(
            'NEVER like [{"name": "WP Responsive Images", '
            '"type": "WordPress Plugin"}]',
            prompt,
        )
        # No raw double-brace escape residue may leak into the prompt.
        self.assertNotIn("{{", prompt)
        self.assertNotIn("}}", prompt)


if __name__ == "__main__":
    unittest.main()
