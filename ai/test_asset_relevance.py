"""Stage R17 tests: deterministic asset/program relevance.

Pure, offline tests. No LLM, no network, no subprocess, no active validation,
no Nuclei, no production authority chain. Uses synthetic asset records only;
the real-corpus evaluation lives in the report and the CLI.
"""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.knowledge.relevance import (
    ASSET_RELEVANCE_RULE_VERSION,
    AssetRecord,
    asset_relevance_projection,
    assess_asset_relevance,
    assets_from_research_metadata,
    derive_technology_hints,
    load_program_definitions,
)


def _assess(**kwargs):
    return assess_asset_relevance(**kwargs)


class StrongSignalTests(unittest.TestCase):
    def test_exact_product_match(self):
        result = _assess(
            products=["nginx"],
            assets=[{"program": "p", "asset": "a.com", "technologies": ["nginx"]}],
        )
        self.assertGreaterEqual(result.score, 50)
        self.assertIn("exact product match: nginx", result.reasons)
        self.assertEqual(result.matched_assets, ["a.com"])

    def test_exact_plugin_match(self):
        result = _assess(
            components=["wp-responsive-images"],
            assets=[
                {
                    "program": "p",
                    "asset": "a.com",
                    "components": ["wp-responsive-images"],
                }
            ],
        )
        self.assertIn(
            "exact plugin/component match: wp responsive images", result.reasons
        )
        self.assertGreaterEqual(result.score, 35)

    def test_exact_component_path_match(self):
        result = _assess(
            components=["wp-content/plugins/wp-responsive-images/image_handler.php"],
            assets=[
                {
                    "program": "p",
                    "asset": "a.com",
                    "paths": [
                        "/wp-content/plugins/wp-responsive-images/image_handler.php"
                    ],
                }
            ],
        )
        self.assertIn("component/path match:", "".join(result.reasons))
        self.assertGreater(result.score, 0)

    def test_normalized_name_match(self):
        result = _assess(
            products=["WP Responsive Images 1.0"],
            assets=[
                {"program": "p", "asset": "a.com", "components": ["wp-responsive-images"]}
            ],
        )
        self.assertIn("exact product match: wp responsive images", result.reasons)


class GenericAndWeakTests(unittest.TestCase):
    def test_technology_only_is_weak(self):
        result = _assess(
            technologies=["wordpress"],
            assets=[{"program": "p", "asset": "a.com", "technologies": ["WordPress"]}],
        )
        self.assertEqual(result.relevance, "LOW")
        self.assertLess(result.score, 70)

    def test_generic_php_does_not_create_high(self):
        result = _assess(
            technologies=["php"],
            assets=[{"program": "p", "asset": "a.com", "technologies": ["PHP"]}],
        )
        self.assertNotEqual(result.relevance, "HIGH")
        self.assertLess(result.score, 70)

    def test_generic_wordpress_alone_does_not_create_high(self):
        result = _assess(
            technologies=["wordpress"],
            assets=[{"program": "p", "asset": "a.com", "technologies": ["wordpress"]}],
        )
        self.assertNotEqual(result.relevance, "HIGH")
        self.assertLess(result.score, 70)

    def test_no_substring_explosion(self):
        # "image" must not match "images" / "image_handler".
        result = _assess(
            products=["image"],
            assets=[{"program": "p", "asset": "a.com", "components": ["images"]}],
        )
        self.assertEqual(result.relevance, "NONE")
        result2 = _assess(
            products=["image"],
            assets=[
                {"program": "p", "asset": "a.com", "components": ["image_handler"]}
            ],
        )
        self.assertEqual(result2.relevance, "NONE")

    def test_unrelated_product_is_none(self):
        result = _assess(
            products=["Zabbix"],
            assets=[{"program": "p", "asset": "dell.com"}],
        )
        self.assertEqual(result.relevance, "NONE")
        self.assertEqual(result.score, 0)


class UnknownAndBoundsTests(unittest.TestCase):
    def test_no_assets_is_unknown(self):
        result = _assess(products=["nginx"])
        self.assertEqual(result.relevance, "UNKNOWN")
        self.assertIn("asset intelligence unavailable", result.unknown_factors)

    def test_unknown_asset_technology_is_unknown(self):
        result = _assess(
            technologies=["wordpress"],
            assets=[{"program": "p", "asset": "a.com"}],
        )
        self.assertEqual(result.relevance, "UNKNOWN")
        self.assertIn("asset technology not observed", result.unknown_factors)

    def test_score_bounded(self):
        result = _assess(
            products=["wordpress responsive images"],
            technologies=["wordpress"],
            components=["wp-content/plugins/wp-responsive-images/image_handler.php"],
            vulnerability_types=["path_traversal"],
            assets=[
                {
                    "program": "p",
                    "asset": "a.com",
                    "technologies": ["WordPress"],
                    "components": ["wp-responsive-images"],
                    "paths": [
                        "/wp-content/plugins/wp-responsive-images/image_handler.php"
                    ],
                }
            ],
        )
        self.assertLessEqual(result.score, 100)
        self.assertGreaterEqual(result.score, 0)

    def test_every_positive_score_has_reasons(self):
        result = _assess(
            products=["nginx"],
            assets=[{"program": "p", "asset": "a.com", "technologies": ["nginx"]}],
        )
        self.assertGreater(result.score, 0)
        self.assertTrue(result.reasons)

    def test_adversarial_names_are_bounded(self):
        result = _assess(
            products=["A" * 5000, "", "   "],
            components=["b" * 5000],
            assets=[
                {"program": "p", "asset": "a" * 5000, "technologies": ["x" * 5000]}
            ],
        )
        self.assertLessEqual(result.score, 100)
        self.assertIn(
            result.relevance, ("HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
        )


class IsolationTests(unittest.TestCase):
    def test_program_isolation(self):
        result = _assess(
            products=["nginx"],
            assets=[
                {"program": "p1", "asset": "a.com", "technologies": ["nginx"]},
                {"program": "p2", "asset": "b.com", "technologies": ["apache"]},
            ],
        )
        self.assertEqual(result.matched_programs, ["p1"])
        self.assertNotIn("p2", result.matched_programs)

    def test_cross_cve_isolation(self):
        assets = [
            {"program": "p", "asset": "a.com", "technologies": ["nginx", "zabbix"]}
        ]
        first = _assess(products=["nginx"], assets=assets)
        second = _assess(products=["zabbix"], assets=assets)
        self.assertIn("exact product match: nginx", first.reasons)
        self.assertIn("exact product match: zabbix", second.reasons)
        self.assertNotIn("zabbix", " ".join(first.reasons))
        self.assertNotIn("nginx", " ".join(second.reasons))


class DeterminismTests(unittest.TestCase):
    def test_repeated_projection_is_identical(self):
        kwargs = dict(
            products=["nginx"],
            technologies=["nginx"],
            assets=[
                {"program": "p", "asset": "a.com", "technologies": ["nginx"]}
            ],
        )
        self.assertEqual(
            asset_relevance_projection(**kwargs),
            asset_relevance_projection(**kwargs),
        )

    def test_order_independent(self):
        assets = [
            {"program": "p", "asset": "a.com", "technologies": ["nginx"]},
            {"program": "q", "asset": "b.com", "technologies": ["nginx"]},
        ]
        forward = _assess(products=["nginx"], assets=assets)
        reverse = _assess(products=["nginx"], assets=list(reversed(assets)))
        self.assertEqual(forward.score, reverse.score)
        self.assertEqual(forward.matched_assets, reverse.matched_assets)
        self.assertEqual(forward.matched_programs, reverse.matched_programs)

    def test_evidence_is_bounded(self):
        result = _assess(
            products=["nginx"],
            assets=[
                {"program": "p", "asset": "a.com", "technologies": ["nginx"]}
            ],
        )
        for item in result.evidence:
            self.assertLessEqual(len(item.evidence), 240)
            self.assertTrue(item.rule_id)
            self.assertEqual(item.rule_version, ASSET_RELEVANCE_RULE_VERSION)


class LoaderTests(unittest.TestCase):
    def test_load_program_definitions_and_infer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "dell.json").write_text(
                json.dumps(
                    {
                        "program_name": "dell",
                        "scopes": ["dell.com", "delltechnologies.com"],
                        "ooscopes": [],
                    }
                ),
                encoding="utf-8",
            )
            programs = load_program_definitions(root)
            self.assertEqual(len(programs), 1)
            metadata = {
                "metadata": {
                    "assets": ["dellnetworkingvr.dell.com"],
                    "technologies": ["WordPress"],
                }
            }
            records = assets_from_research_metadata(metadata, programs)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].program, "dell")
            self.assertEqual(records[0].technologies, ("WordPress",))

    def test_derive_technology_hints(self):
        self.assertEqual(
            derive_technology_hints(
                ["WP Responsive Images (WordPress plugin)"]
            ),
            ["wordpress"],
        )
        self.assertEqual(derive_technology_hints(["Zabbix"]), [])


class SchemaCompatibilityTests(unittest.TestCase):
    def test_legacy_document_defaults(self):
        from ai.schemas.knowledge import KnowledgeDocument

        document = KnowledgeDocument.model_validate(
            {
                "knowledge_id": "kb-legacy",
                "title": "legacy",
                "source_url": "https://legacy.test/x",
                "source_type": "reference",
                "content": "legacy content",
            }
        )
        self.assertEqual(document.asset_relevance.relevance, "UNKNOWN")
        self.assertEqual(document.asset_relevance.score, 0)
        self.assertEqual(document.asset_relevance.rule_version, "r17-1")

    def test_projection_validates_against_schema(self):
        from ai.schemas.knowledge import KnowledgeAssetRelevance

        projection = asset_relevance_projection(
            products=["nginx"],
            assets=[{"program": "p", "asset": "a.com", "technologies": ["nginx"]}],
        )
        model = KnowledgeAssetRelevance.model_validate(projection)
        self.assertEqual(model.relevance, "MEDIUM")
        self.assertTrue(model.evidence)


class SafetyBoundaryTests(unittest.TestCase):
    def test_no_network_or_subprocess(self):
        with mock.patch.object(
            socket, "socket", side_effect=AssertionError("network used")
        ):
            with mock.patch.object(
                subprocess, "Popen", side_effect=AssertionError("subprocess used")
            ):
                result = _assess(
                    products=["nginx"],
                    assets=[
                        {
                            "program": "p",
                            "asset": "a.com",
                            "technologies": ["nginx"],
                        }
                    ],
                )
        self.assertGreater(result.score, 0)

    def test_rule_versions(self):
        self.assertEqual(ASSET_RELEVANCE_RULE_VERSION, "r17-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
