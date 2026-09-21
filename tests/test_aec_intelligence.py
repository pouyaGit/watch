"""Tests for aec/intelligence (EPIC 4 Part 2: Candidate Intelligence Engine).

Research prioritization — explicit effort-allocation rubric over surface,
context, history, and gap signals. Bands LOW/MEDIUM/HIGH name *research
priority* only: they are never severity claims, never exposure
statements, never conclusions about any target.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

INTEL_DIR = Path(__file__).resolve().parents[1] / "aec" / "intelligence"
MODULES = ("models.py", "scoring.py")
BANDS = ("LOW", "MEDIUM", "HIGH")
DIMENSIONS = (
    "endpoint_importance",
    "parameter_relevance",
    "technology_context",
    "research_history",
    "evidence_gap",
)

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "VULNERABILITY",
    "EXPLOIT", "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})


def candidate(**overrides):
    draft = {
        "candidate_id": "rc-abc123",
        "asset": "example.com",
        "endpoint": "/api/user",
        "parameters": ("id",),
        "technology": ("php",),
        "research_category": "idor",
        "evidence_gap": {"required": ["a", "b"], "missing": ["a", "b"]},
    }
    draft.update(overrides)
    return draft


def history(**overrides):
    summary = {"researched": False, "related_patterns": 0}
    summary.update(overrides)
    return summary


class TestPrioritize(unittest.TestCase):
    def test_plain_candidate_scores_deterministically(self):
        from aec.intelligence import scoring

        first = scoring.prioritize(candidate(), history())
        second = scoring.prioritize(candidate(), history())
        self.assertEqual(first, second)
        self.assertIn(first.band, BANDS)

    def test_dimensions_sum_to_total(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        parts = priority.dimensions
        self.assertEqual(
            priority.score,
            parts["endpoint_importance"] + parts["parameter_relevance"]
            + parts["technology_context"] + parts["research_history"]
            + parts["evidence_gap"],
        )

    def test_band_thresholds(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.band_for(60).band, "HIGH")
        self.assertEqual(scoring.band_for(100).band, "HIGH")
        self.assertEqual(scoring.band_for(59).band, "MEDIUM")
        self.assertEqual(scoring.band_for(30).band, "MEDIUM")
        self.assertEqual(scoring.band_for(29).band, "LOW")
        self.assertEqual(scoring.band_for(0).band, "LOW")

    def test_empty_candidate_scores_zero(self):
        from aec.intelligence import scoring

        draft = candidate(
            endpoint="/", parameters=(), technology=(),
            evidence_gap={"required": [], "missing": []},
        )
        priority = scoring.prioritize(draft, history(researched=True))
        self.assertEqual(priority.score, 0)
        self.assertEqual(priority.band, "LOW")

    def test_reasons_name_contributing_dimensions(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        self.assertTrue(priority.reasons)
        for reason in priority.reasons:
            self.assertTrue(
                any(reason.startswith(dim) for dim in DIMENSIONS), reason
            )


class TestEndpointImportance(unittest.TestCase):
    def test_sensitive_path_scores_above_plain(self):
        from aec.intelligence import scoring

        plain = scoring.endpoint_importance("/")
        admin = scoring.endpoint_importance("/admin/users")
        self.assertGreater(admin, plain)

    def test_capped_at_twenty(self):
        from aec.intelligence import scoring

        self.assertLessEqual(
            scoring.endpoint_importance("/admin/login/account/api/billing"), 20
        )

    def test_case_insensitive(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.endpoint_importance("/ADMIN"),
            scoring.endpoint_importance("/admin"),
        )


class TestParameterRelevance(unittest.TestCase):
    def test_reference_like_names_score_above_plain(self):
        from aec.intelligence import scoring

        self.assertGreater(
            scoring.parameter_relevance(("id",)),
            scoring.parameter_relevance(("theme",)),
        )

    def test_empty_parameters_score_zero(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.parameter_relevance(()), 0)

    def test_best_parameter_wins(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.parameter_relevance(("theme", "id")),
            scoring.parameter_relevance(("id",)),
        )


class TestTechnologyContext(unittest.TestCase):
    def test_recognized_stack_scores(self):
        from aec.intelligence import scoring

        self.assertGreater(scoring.technology_context(("php",)), 0)

    def test_unknown_stack_scores_zero(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.technology_context(("novastack9",)), 0)

    def test_capped_at_twenty(self):
        from aec.intelligence import scoring

        tech = ("php", "wordpress", "laravel", "django", "rails", "node")
        self.assertLessEqual(scoring.technology_context(tech), 20)


class TestResearchHistory(unittest.TestCase):
    def test_novel_candidate_scores_highest(self):
        from aec.intelligence import scoring

        novel = scoring.research_history(history())
        related = scoring.research_history(history(related_patterns=2))
        dup = scoring.research_history(history(researched=True))
        self.assertGreater(novel, related)
        self.assertGreater(related, dup)
        self.assertEqual(dup, 0)

    def test_duplicate_candidate_deprioritized(self):
        from aec.intelligence import scoring

        fresh = scoring.prioritize(candidate(), history())
        dup = scoring.prioritize(candidate(), history(researched=True))
        self.assertLess(dup.score, fresh.score)


class TestEvidenceGap(unittest.TestCase):
    def test_larger_gap_scores_higher(self):
        from aec.intelligence import scoring

        small = scoring.evidence_gap_weight({"required": ["a"], "missing": ["a"]})
        large = scoring.evidence_gap_weight(
            {"required": ["a", "b", "c"], "missing": ["a", "b", "c"]}
        )
        self.assertGreater(large, small)

    def test_no_gap_scores_zero(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.evidence_gap_weight({"required": ["a"], "missing": []}), 0
        )


class TestOrdering(unittest.TestCase):
    def test_richer_candidate_orders_first(self):
        from aec.intelligence import scoring

        rich = scoring.prioritize(
            candidate(endpoint="/admin/account", parameters=("user_id",)),
            history(),
        )
        thin = scoring.prioritize(
            candidate(endpoint="/", parameters=(), technology=()),
            history(researched=True),
        )
        ordered = scoring.order_priorities([thin, rich])
        self.assertEqual([p.candidate_id for p in ordered], [thin.candidate_id]
                         if thin.score > rich.score else [rich.candidate_id, thin.candidate_id])
        self.assertGreaterEqual(ordered[0].score, ordered[1].score)

    def test_ties_break_by_candidate_id(self):
        from aec.intelligence import scoring

        first = scoring.prioritize(candidate(candidate_id="rc-aaa"), history())
        second = scoring.prioritize(candidate(candidate_id="rc-zzz"), history())
        self.assertEqual(
            [p.candidate_id for p in scoring.order_priorities([second, first])],
            ["rc-aaa", "rc-zzz"],
        )


class TestSerialization(unittest.TestCase):
    def test_priority_round_trip_stable(self):
        import json
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        text = scoring.serialize_priority(priority)
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")),
            text,
        )

    def test_priorities_are_frozen(self):
        import dataclasses
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            priority.band = "HIGH"


class TestSafetyGuards(unittest.TestCase):
    def test_no_severity_vocabulary_in_source(self):
        for name in MODULES:
            source = (INTEL_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((INTEL_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)

    def test_band_values_are_not_severity_claims(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        self.assertNotIn("severity", priority.to_dict())


class TestRubricTables(unittest.TestCase):
    def test_weight_table_pinned(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.endpoint_importance("/admin/login/account/api/billing"), 20
        )
        self.assertEqual(scoring.endpoint_importance("/"), 0)
        self.assertEqual(scoring.parameter_relevance(("id",)), 12)
        self.assertEqual(scoring.parameter_relevance(("theme",)), 0)
        self.assertEqual(scoring.technology_context(("php",)), 7)
        self.assertEqual(scoring.research_history({"researched": False,
                                                   "related_patterns": 0}), 20)
        self.assertEqual(scoring.research_history({"researched": True,
                                                   "related_patterns": 0}), 0)
        self.assertEqual(
            scoring.evidence_gap_weight({"required": ["a"], "missing": ["a"]}), 7
        )

    def test_partial_name_match_scores_eight(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.parameter_relevance(("user_id",)), 8)
        self.assertEqual(scoring.parameter_relevance(("userid",)), 8)

    def test_exact_name_match_scores_twelve(self):
        from aec.intelligence import scoring

        for name in ("id", "url", "file", "role"):
            self.assertEqual(scoring.parameter_relevance((name,)), 12, name)

    def test_multiple_parameters_best_wins(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.parameter_relevance(("theme", "color", "url")), 12
        )

    def test_non_string_parameters_skipped(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.parameter_relevance((42, None)), 0)

    def test_invalid_inputs_score_zero(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.endpoint_importance(None), 0)
        self.assertEqual(scoring.parameter_relevance("id"), 0)
        self.assertEqual(scoring.technology_context(None), 0)
        self.assertEqual(scoring.research_history(None), 0)
        self.assertEqual(scoring.evidence_gap_weight(None), 0)

    def test_non_string_endpoint_scores_zero(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.endpoint_importance(42), 0)

    def test_gap_counts_map(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.evidence_gap_weight(
                {"required": ["a", "b", "c", "d"],
                 "missing": ["a", "b", "c", "d"]}), 20)
        self.assertEqual(
            scoring.evidence_gap_weight(
                {"required": ["a", "b"], "missing": ["a", "b"]}), 13)

    def test_non_list_missing_scores_zero(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.evidence_gap_weight({"required": ["a"], "missing": "a"}), 0
        )

    def test_band_edges(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.band_for(101).band, "HIGH")
        self.assertEqual(scoring.band_for(-1).band, "LOW")

    def test_band_for_shape(self):
        from aec.intelligence import scoring

        priority = scoring.band_for(75)
        self.assertEqual(priority.score, 75)
        self.assertEqual(priority.candidate_id, "")

    def test_prioritize_accepts_draft_objects(self):
        from aec.intelligence import scoring
        from aec.surface import adapter

        record = {
            "program": "pilot", "subdomain": "example.com", "url": "/x?a=",
            "endpoint": "/x", "parameter": "a", "method": "GET",
            "location": "query", "technology": [], "source": "watch",
            "last_update": None,
        }
        draft = adapter.adapt_record(record, default_category="xss").draft
        priority = scoring.prioritize(draft, {"researched": False,
                                              "related_patterns": 0})
        self.assertEqual(priority.candidate_id, draft.candidate_id)

    def test_prioritize_rejects_garbage(self):
        from aec.intelligence import scoring

        with self.assertRaises(ValueError):
            scoring.prioritize(42, {})

    def test_missing_candidate_id_defaults_empty(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize({"endpoint": "/"}, {})
        self.assertEqual(priority.candidate_id, "")

    def test_reasons_format(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        for reason in priority.reasons:
            name, _, value = reason.partition(":")
            self.assertIn(name, DIMENSIONS)
            self.assertTrue(value.isdigit())

    def test_zero_score_has_no_reasons(self):
        from aec.intelligence import scoring

        draft = candidate(
            endpoint="/", parameters=(), technology=(),
            evidence_gap={"required": [], "missing": []},
        )
        priority = scoring.prioritize(draft, history(researched=True))
        self.assertEqual(priority.reasons, ())

    def test_order_many_stable(self):
        from aec.intelligence import scoring

        ids = [f"rc-{letter}" for letter in "dcba"]
        priorities = [
            scoring.prioritize(candidate(candidate_id=cid), history())
            for cid in ids
        ]
        ordered = scoring.order_priorities(priorities)
        scores = [item.score for item in ordered]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_serialize_has_expected_keys(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        self.assertEqual(
            sorted(priority.to_dict()),
            ["band", "candidate_id", "dimensions", "reasons", "score"],
        )

    def test_dimensions_cover_all_five(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        self.assertEqual(set(priority.dimensions), set(DIMENSIONS))
        for value in priority.dimensions.values():
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 20)

    def test_score_bounded(self):
        from aec.intelligence import scoring

        draft = candidate(
            endpoint="/admin/login/account/api/billing/user/profile",
            parameters=("id",),
            technology=("php", "django", "rails", "node"),
            evidence_gap={"required": ["a", "b", "c"], "missing": ["a", "b", "c"]},
        )
        priority = scoring.prioritize(draft, history())
        self.assertLessEqual(priority.score, 100)


    def test_two_recognized_stacks_sum(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.technology_context(("php", "django")), 14)

    def test_unrecognized_entries_ignored(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.technology_context(("php", None, 42)), 7)

    def test_non_int_related_patterns_treated_novel(self):
        from aec.intelligence import scoring

        self.assertEqual(
            scoring.research_history(
                {"researched": False, "related_patterns": "many"}), 20
        )

    def test_list_parameters_accepted(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.parameter_relevance(["id"]), 12)

    def test_endpoint_each_token_scores(self):
        from aec.intelligence import scoring

        for token in ("login", "billing", "settings"):
            self.assertEqual(
                scoring.endpoint_importance(f"/{token}"), 4, token
            )

    def test_priority_score_is_int(self):
        from aec.intelligence import scoring

        priority = scoring.prioritize(candidate(), history())
        self.assertIsInstance(priority.score, int)

    def test_order_does_not_mutate_input(self):
        from aec.intelligence import scoring

        priorities = [
            scoring.prioritize(candidate(candidate_id="rc-b"), history()),
            scoring.prioritize(candidate(candidate_id="rc-a"), history()),
        ]
        scoring.order_priorities(priorities)
        self.assertEqual(
            [item.candidate_id for item in priorities], ["rc-b", "rc-a"]
        )

    def test_band_for_zeroed_dimensions(self):
        from aec.intelligence import scoring

        priority = scoring.band_for(45)
        self.assertEqual(priority.band, "MEDIUM")
        self.assertEqual(sum(priority.dimensions.values()), 0)

    def test_order_empty_list(self):
        from aec.intelligence import scoring

        self.assertEqual(scoring.order_priorities([]), [])

    def test_public_constants(self):
        from aec.intelligence import models

        self.assertEqual(models.BANDS, ("LOW", "MEDIUM", "HIGH"))
        self.assertEqual(len(models.DIMENSIONS), 5)


if __name__ == "__main__":
    unittest.main()
