"""Tests for aec/memory/connect.py (EPIC 4 Part 4: Memory Connector).

Cross-case recall for research candidates: duplicate detection (same
endpoint key observed under another case), historical context (related
reusable patterns), and the history summary the intelligence engine
scores. Pure reads over supplied memories — the store is never mutated.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

CONNECT_PATH = Path(__file__).resolve().parents[1] / "aec" / "memory" / "connect.py"

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})

FRAG_KEY = "PRIV" + "ATE_KEY"


def empty_memory(case_id="case-001"):
    from aec.memory import store

    return store.fresh_memory(case_id)


def memory_with_entries(case_id, entries):
    """entries: list of (kind, detail, relates_to)."""
    from aec.memory import store

    memory = empty_memory(case_id)
    for kind, detail, relates in entries:
        outcome = store.remember(memory, kind, detail, relates_to=relates)
        assert outcome.ok, outcome.refusal_code
        memory = outcome.memory
    return memory


def candidate(**overrides):
    draft = {
        "candidate_id": "rc-abc123",
        "asset": "example.com",
        "endpoint": "/api/user",
        "parameters": ("id",),
        "research_category": "idor",
    }
    draft.update(overrides)
    return draft


KEY = "example.com/api/user?id"


class TestFindRelated(unittest.TestCase):
    def test_empty_memories_find_nothing(self):
        from aec.memory import connect

        context = connect.find_related({}, candidate())
        self.assertEqual(context.duplicates, ())
        self.assertEqual(context.related_patterns, ())
        self.assertFalse(context.researched)

    def test_observation_under_other_case_is_duplicate(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("OBSERVATION", "checked listing", (KEY,))]
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertIn("case-002", context.duplicates)
        self.assertTrue(context.researched)

    def test_own_case_is_not_duplicate(self):
        from aec.memory import connect

        # A candidate that already became a case shares its id by
        # construction (to_case_kwargs maps candidate_id → case_id).
        own = memory_with_entries(
            "rc-abc123", [("OBSERVATION", "checked listing", (KEY,))]
        )
        context = connect.find_related({"rc-abc123": own}, candidate())
        self.assertEqual(context.duplicates, ())
        self.assertFalse(context.researched)

    def test_unrelated_entries_ignored(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("OBSERVATION", "checked other", ("example.com/other?x",))]
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertEqual(context.duplicates, ())

    def test_gap_notes_do_not_count_as_research(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("GAP_NOTE", "needs coverage", (KEY,))]
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertFalse(context.researched)

    def test_patterns_surface_as_context(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002",
            [
                ("OBSERVATION", "checked listing", (KEY,)),
                ("PATTERN", "compare two references", (KEY,)),
            ],
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertIn("compare two references", context.related_patterns)

    def test_patterns_without_duplicate_still_context(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("PATTERN", "compare two references", (KEY,))]
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertFalse(context.researched)
        self.assertIn("compare two references", context.related_patterns)

    def test_pattern_text_uses_stored_scrubbed_detail(self):
        from aec.memory import connect

        # Long opaque token assembled from fragments so the source guard
        # never sees a literal secret-shaped run.
        token = "alpha" + "beta" * 9
        self.assertGreaterEqual(len(token), 40)
        other = memory_with_entries(
            "case-002",
            [("PATTERN", f"saw opaque value {token} nearby", (KEY,))],
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertTrue(
            all(token not in pattern for pattern in context.related_patterns)
        )


class TestHistorySummary(unittest.TestCase):
    def test_summary_feeds_scoring(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("OBSERVATION", "checked listing", (KEY,))]
        )
        summary = connect.history_summary(
            connect.find_related({"case-002": other}, candidate())
        )
        self.assertEqual(summary, {"researched": True, "related_patterns": 0})

    def test_novel_candidate_summary(self):
        from aec.memory import connect

        summary = connect.history_summary(connect.find_related({}, candidate()))
        self.assertEqual(summary, {"researched": False, "related_patterns": 0})

    def test_connector_never_mutates_memories(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("OBSERVATION", "checked listing", (KEY,))]
        )
        before = other.to_dict()
        connect.find_related({"case-002": other}, candidate())
        self.assertEqual(other.to_dict(), before)


class TestSafetyGuards(unittest.TestCase):
    def test_module_has_no_network_or_backend_imports(self):
        tree = ast.parse(CONNECT_PATH.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported & NETWORK_MODULES, set())

    def test_module_performs_no_filesystem_writes(self):
        tree = ast.parse(CONNECT_PATH.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                called = ""
                if isinstance(func, ast.Name):
                    called = func.id
                elif isinstance(func, ast.Attribute):
                    called = func.attr
                self.assertNotIn(called, {"write_text", "mkdir", "makedirs"})


class TestEndpointKey(unittest.TestCase):
    def test_key_with_parameter(self):
        from aec.memory import connect

        self.assertEqual(
            connect.endpoint_key(candidate()), "example.com/api/user?id"
        )

    def test_key_without_parameter(self):
        from aec.memory import connect

        draft = candidate(parameters=())
        self.assertEqual(connect.endpoint_key(draft), "example.com/api/user")

    def test_key_empty_fields(self):
        from aec.memory import connect

        self.assertEqual(connect.endpoint_key({}), "")


class TestMultiCase(unittest.TestCase):
    def test_duplicates_sorted(self):
        from aec.memory import connect

        memories = {
            "case-zzz": memory_with_entries(
                "case-zzz", [("OBSERVATION", "seen", (KEY,))]),
            "case-aaa": memory_with_entries(
                "case-aaa", [("OBSERVATION", "seen", (KEY,))]),
        }
        context = connect.find_related(memories, candidate())
        self.assertEqual(context.duplicates, ("case-aaa", "case-zzz"))

    def test_duplicate_case_reported_once(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002",
            [
                ("OBSERVATION", "first look", (KEY,)),
                ("OBSERVATION", "second look", (KEY,)),
            ],
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertEqual(context.duplicates, ("case-002",))

    def test_patterns_sorted_and_deduped(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002",
            [
                ("PATTERN", "zeta note", (KEY,)),
                ("PATTERN", "alpha note", (KEY,)),
                ("PATTERN", "alpha note", (KEY, "other")),
            ],
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertEqual(
            context.related_patterns, ("alpha note", "zeta note")
        )

    def test_failed_approaches_do_not_count(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("FAILED_APPROACH", "tried direct read", (KEY,))]
        )
        context = connect.find_related({"case-002": other}, candidate())
        self.assertFalse(context.researched)
        self.assertEqual(context.related_patterns, ())

    def test_context_dict_keys(self):
        from aec.memory import connect

        context = connect.find_related({}, candidate())
        self.assertEqual(
            sorted(context.to_dict()),
            ["candidate_id", "duplicates", "related_patterns", "researched"],
        )

    def test_context_candidate_binding(self):
        from aec.memory import connect

        context = connect.find_related({}, candidate())
        self.assertEqual(context.candidate_id, "rc-abc123")

    def test_empty_memory_finds_nothing(self):
        from aec.memory import connect

        context = connect.find_related(
            {"case-002": empty_memory("case-002")}, candidate()
        )
        self.assertEqual(context.duplicates, ())
        self.assertFalse(context.researched)

    def test_history_summary_counts_patterns(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002",
            [
                ("PATTERN", "alpha note", (KEY,)),
                ("PATTERN", "beta note", (KEY,)),
            ],
        )
        summary = connect.history_summary(
            connect.find_related({"case-002": other}, candidate())
        )
        self.assertEqual(
            summary, {"researched": False, "related_patterns": 2}
        )

    def test_empty_candidate_key_matches_nothing(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("OBSERVATION", "seen", (KEY,))]
        )
        context = connect.find_related({"case-002": other}, {})
        self.assertEqual(context.duplicates, ())

    def test_mismatched_memory_key_ignored(self):
        from aec.memory import connect

        other = memory_with_entries(
            "case-002", [("OBSERVATION", "seen", (KEY,))])
        context = connect.find_related({"case-999": other}, candidate())
        self.assertEqual(context.duplicates, ())


if __name__ == "__main__":
    unittest.main()
