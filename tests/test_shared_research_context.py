"""tests/test_shared_research_context.py — Stage R43.2 tests.

Deterministic, offline tests for the shared research context:

- bounded block normalization and secret redaction
- closed source-layer vocabulary and canonical ordering
- deterministic merge semantics and input immutability
- context summary and fact counting
- schema validation, JSON serialization, determinism

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import copy
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.shared_research_context import (
    build_shared_research_context,
    merge_shared_research_context,
    shared_context_fact_count,
    shared_context_summary,
)
from ai.schemas import shared_research_context as schema


class TestSharedResearchContext(unittest.TestCase):
    def test_normalization(self):
        context = build_shared_research_context(
            {
                "asset_reference": "example-app",
                "application_context": {
                    "framework": "django",
                    "debug": True,
                    "version": 4,
                    "tags": ["a", "b", "a"],
                    "nested": {"x": 1},
                },
                "technology_context": {"token": "secret=ABC123"},
                "source_layers": ["REASONING", "NOPE", "MEMORY"],
            }
        )
        self.assertEqual(context["rule_version"], "r43-2")
        self.assertEqual(context["asset_reference"], "example-app")
        block = context["application_context"]
        self.assertEqual(block["framework"], "django")
        self.assertIs(block["debug"], True)
        self.assertEqual(block["version"], 4)
        self.assertEqual(block["tags"], ["a", "b", "a"])
        self.assertNotIn("nested", block)
        self.assertEqual(context["source_layers"], ["REASONING", "MEMORY"])
        self.assertNotIn("ABC123", json.dumps(context))
        self.assertIs(context["research_only"], True)

    def test_invalid_keys_dropped(self):
        context = build_shared_research_context(
            {
                "application_context": {
                    "Valid": "x",
                    "UPPER": "y",
                    "1bad": "z",
                    "ok_key": "v",
                }
            }
        )
        self.assertEqual(
            context["application_context"], {"ok_key": "v"}
        )

    def test_blocks_are_bounded(self):
        block = {f"k{index:03d}": index for index in range(40)}
        context = build_shared_research_context(
            {"application_context": block}
        )
        self.assertLessEqual(
            len(context["application_context"]), schema.MAX_BLOCK_KEYS
        )

    def test_merge_first_value_wins(self):
        merged = merge_shared_research_context(
            [
                {"application_context": {"framework": "django"}},
                {"application_context": {"framework": "flask",
                                         "runtime": "python"}},
            ]
        )
        self.assertEqual(
            merged["application_context"]["framework"], "django"
        )
        self.assertEqual(
            merged["application_context"]["runtime"], "python"
        )

    def test_merge_list_union(self):
        merged = merge_shared_research_context(
            [
                {"input_surface_context": {"params": ["a", "b"]}},
                {"input_surface_context": {"params": ["b", "c"]}},
            ]
        )
        self.assertEqual(
            merged["input_surface_context"]["params"], ["a", "b", "c"]
        )

    def test_merge_source_layers_canonical(self):
        merged = merge_shared_research_context(
            [
                {"source_layers": ["GOVERNANCE", "REASONING"]},
                {"source_layers": ["MEMORY"]},
            ]
        )
        self.assertEqual(
            merged["source_layers"],
            ["REASONING", "MEMORY", "GOVERNANCE"],
        )

    def test_merge_asset_reference(self):
        merged = merge_shared_research_context(
            [
                {"asset_reference": ""},
                {"asset_reference": "asset-1"},
            ]
        )
        self.assertEqual(merged["asset_reference"], "asset-1")

    def test_inputs_not_mutated(self):
        first = {"application_context": {"framework": "django"}}
        second = {"input_surface_context": {"params": ["a"]}}
        first_before = copy.deepcopy(first)
        second_before = copy.deepcopy(second)
        merge_shared_research_context([first, second])
        self.assertEqual(first, first_before)
        self.assertEqual(second, second_before)

    def test_fact_count_and_summary(self):
        self.assertEqual(shared_context_fact_count(None), 0)
        context = build_shared_research_context(
            {
                "asset_reference": "x",
                "application_context": {"framework": "django"},
                "source_layers": ["REASONING"],
            }
        )
        self.assertEqual(shared_context_fact_count(context), 2)
        summary = shared_context_summary(context)
        self.assertIs(summary["asset_reference_present"], True)
        self.assertEqual(summary["blocks_present"],
                         ["application_context"])
        self.assertEqual(summary["block_count"], 1)
        self.assertEqual(summary["fact_count"], 2)
        self.assertEqual(summary["source_layers"], ["REASONING"])

    def test_deterministic_output(self):
        value = {
            "application_context": {"framework": "django"},
            "source_layers": ["REASONING"],
        }
        first = build_shared_research_context(value)
        second = build_shared_research_context(value)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertEqual(
            json.dumps(
                merge_shared_research_context([value]),
                sort_keys=True,
            ),
            json.dumps(first, sort_keys=True),
        )

    def test_json_serializable(self):
        context = build_shared_research_context(
            {"asset_reference": "x"}
        )
        self.assertIsInstance(json.loads(json.dumps(context)), dict)

    def test_malformed_inputs(self):
        for bad in (None, "", 42, [], "NOPE"):
            context = build_shared_research_context(bad)
            self.assertEqual(context["asset_reference"], "")
            self.assertEqual(context["source_layers"], [])
            self.assertIs(context["research_only"], True)

    def test_schema_rejects_extra_and_research_only(self):
        with self.assertRaises(ValidationError):
            schema.SharedResearchContextPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.SharedResearchContextPlan(research_only=False)
        plan = schema.SharedResearchContextPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r43-2")

    def test_exact_rule_version(self):
        self.assertEqual(
            build_shared_research_context({})["rule_version"], "r43-2"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
