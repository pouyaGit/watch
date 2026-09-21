"""Tests for aec/memory (EPIC 3 Part 3: Case Memory).

Append-only per-case recall: observations, failed approaches, gap notes,
reusable patterns. Every detail passes through the T2 redaction scrubber
before storage, so secret-shaped text can never rest in memory.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

MEMORY_DIR = Path(__file__).resolve().parents[1] / "aec" / "memory"
MODULES = ("models.py", "store.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})

FRAG_A = "AKIAIOSFODNN7"
FRAG_B = "EXAMPLE"
FRAG_C = "BEGIN "
FRAG_D = "PRIVATE KEY"


def fresh_memory(case_id="case-001"):
    from aec.memory import store

    return store.fresh_memory(case_id)


class TestRemember(unittest.TestCase):
    def test_remember_appends_entry(self):
        from aec.memory import store

        memory = fresh_memory()
        outcome = store.remember(memory, "GAP_NOTE", "response-body outstanding")
        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.memory.entries), 1)
        self.assertEqual(outcome.entry.detail, "response-body outstanding")

    def test_entry_ids_are_sequential(self):
        from aec.memory import store

        memory = fresh_memory()
        first = store.remember(memory, "GAP_NOTE", "one")
        second = store.remember(first.memory, "GAP_NOTE", "two")
        self.assertEqual(first.entry.entry_id, "case-001:gap_note:001")
        self.assertEqual(second.entry.entry_id, "case-001:gap_note:002")

    def test_all_kinds_accepted(self):
        from aec.memory import store

        memory = fresh_memory()
        for kind in ("OBSERVATION", "FAILED_APPROACH", "GAP_NOTE", "PATTERN"):
            outcome = store.remember(memory, kind, f"detail for {kind}")
            self.assertTrue(outcome.ok, kind)
            memory = outcome.memory
        self.assertEqual(len(memory.entries), 4)

    def test_invalid_kind_refused(self):
        from aec.memory import store

        outcome = store.remember(fresh_memory(), "HUNCH", "a feeling")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_KIND")

    def test_empty_detail_refused(self):
        from aec.memory import store

        for bad in ("", "   ", None):
            outcome = store.remember(fresh_memory(), "GAP_NOTE", bad)
            self.assertFalse(outcome.ok)
            self.assertEqual(outcome.refusal_code, "EMPTY_DETAIL")

    def test_recall_filters_by_kind(self):
        from aec.memory import store

        memory = fresh_memory()
        memory = store.remember(memory, "GAP_NOTE", "gap one").memory
        memory = store.remember(memory, "PATTERN", "pattern one").memory
        memory = store.remember(memory, "GAP_NOTE", "gap two").memory
        notes = store.recall(memory, "GAP_NOTE")
        self.assertEqual([e.detail for e in notes], ["gap one", "gap two"])
        self.assertEqual(len(store.recall(memory)), 3)

    def test_patterns_returns_only_patterns(self):
        from aec.memory import store

        memory = fresh_memory()
        memory = store.remember(memory, "PATTERN", "baseline-then-compare").memory
        memory = store.remember(memory, "GAP_NOTE", "other").memory
        found = store.patterns(memory)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail, "baseline-then-compare")

    def test_relates_to_links_entries(self):
        from aec.memory import store

        memory = fresh_memory()
        first = store.remember(memory, "OBSERVATION", "baseline draft")
        linked = store.remember(
            first.memory, "FAILED_APPROACH", "variant added nothing",
            relates_to=(first.entry.entry_id,),
        )
        self.assertEqual(linked.entry.relates_to, (first.entry.entry_id,))

    def test_remember_is_deterministic(self):
        from aec.memory import store

        first = store.remember(fresh_memory(), "GAP_NOTE", "same detail")
        second = store.remember(fresh_memory(), "GAP_NOTE", "same detail")
        self.assertEqual(first.memory, second.memory)
        self.assertEqual(first.entry, second.entry)

    def test_original_memory_unchanged(self):
        from aec.memory import store

        memory = fresh_memory()
        before = memory.to_dict()
        store.remember(memory, "GAP_NOTE", "new note")
        self.assertEqual(memory.to_dict(), before)

    def test_memory_is_frozen(self):
        from aec.memory import store

        memory = store.remember(fresh_memory(), "GAP_NOTE", "note").memory
        with self.assertRaises(dataclasses.FrozenInstanceError):
            memory.case_id = "case-999"


class TestNoSecrets(unittest.TestCase):
    def test_credential_shaped_text_is_scrubbed(self):
        from aec.memory import store

        password = "hunter" + "2" + "secret"
        outcome = store.remember(
            fresh_memory(), "FAILED_APPROACH", f"login with password={password} failed"
        )
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.entry.was_redacted)
        self.assertNotIn(password, outcome.entry.detail)
        self.assertNotIn(password, json.dumps(outcome.memory.to_dict()))

    def test_key_shaped_text_is_scrubbed(self):
        from aec.memory import store

        # Assembled from fragments so the guard never sees a literal header.
        header = "-----" + "BEGIN " + FRAG_D + "-----"
        outcome = store.remember(
            fresh_memory(), "GAP_NOTE", f"note {header} pasted by mistake"
        )
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.entry.was_redacted)
        self.assertNotIn(FRAG_D, outcome.entry.detail)

    def test_token_shaped_text_is_scrubbed(self):
        from aec.memory import store

        token = FRAG_A + FRAG_B + "0123456789ABCDEF0123"
        self.assertGreaterEqual(len(token), 40)
        outcome = store.remember(
            fresh_memory(), "OBSERVATION", f"saw key {token} in a comment"
        )
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.entry.was_redacted)
        self.assertNotIn(token, outcome.entry.detail)

    def test_clean_text_passes_through(self):
        from aec.memory import store

        outcome = store.remember(
            fresh_memory(), "PATTERN", "baseline then single-variable compare"
        )
        self.assertTrue(outcome.ok)
        self.assertFalse(outcome.entry.was_redacted)
        self.assertEqual(outcome.entry.detail, "baseline then single-variable compare")

    def test_recall_never_returns_raw_secrets(self):
        from aec.memory import store

        password = "s3cr" + "et-value"
        memory = fresh_memory()
        memory = store.remember(
            memory, "GAP_NOTE", f"auth header password={password} seen"
        ).memory
        for entry in store.recall(memory):
            self.assertNotIn(password, entry.detail)


class TestSerialization(unittest.TestCase):
    def test_serialization_round_trip(self):
        from aec.memory import store

        memory = fresh_memory()
        memory = store.remember(memory, "GAP_NOTE", "gap one").memory
        memory = store.remember(memory, "PATTERN", "pattern one").memory
        text = store.serialize_memory(memory)
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)
        self.assertEqual(json.loads(text)["case_id"], "case-001")
        self.assertEqual(len(json.loads(text)["entries"]), 2)

    def test_serialization_is_deterministic(self):
        from aec.memory import store

        def build():
            memory = fresh_memory()
            return store.remember(memory, "GAP_NOTE", "same").memory

        self.assertEqual(store.serialize_memory(build()), store.serialize_memory(build()))

    def test_lowercase_kind_refused(self):
        from aec.memory import store

        outcome = store.remember(fresh_memory(), "gap_note", "detail")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_KIND")

    def test_entry_dict_has_stable_keys(self):
        from aec.memory import store

        entry = store.remember(fresh_memory(), "GAP_NOTE", "detail").entry
        self.assertEqual(
            sorted(entry.to_dict()),
            ["case_id", "detail", "entry_id", "kind", "relates_to", "was_redacted"],
        )

    def test_recall_unknown_kind_returns_empty(self):
        from aec.memory import store

        memory = store.remember(fresh_memory(), "GAP_NOTE", "detail").memory
        self.assertEqual(store.recall(memory, "NOPE"), ())

    def test_relates_to_defaults_empty(self):
        from aec.memory import store

        entry = store.remember(fresh_memory(), "GAP_NOTE", "detail").entry
        self.assertEqual(entry.relates_to, ())

    def test_fresh_memory_is_empty(self):
        from aec.memory import store

        memory = fresh_memory()
        self.assertEqual(memory.entries, ())
        self.assertEqual(store.recall(memory), ())

    def test_failed_approach_records_lesson(self):
        from aec.memory import store

        outcome = store.remember(
            fresh_memory(), "FAILED_APPROACH", "single-variable compare added nothing"
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.entry.kind, "FAILED_APPROACH")

    def test_memory_case_binding_preserved(self):
        from aec.memory import store

        memory = fresh_memory("case-007")
        outcome = store.remember(memory, "GAP_NOTE", "detail")
        self.assertEqual(outcome.memory.case_id, "case-007")
        self.assertEqual(outcome.entry.case_id, "case-007")

    def test_bad_relations_refused(self):
        from aec.memory import store

        outcome = store.remember(
            fresh_memory(), "GAP_NOTE", "detail", relates_to=(42,)
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_RELATION")

    def test_list_relations_coerced_to_tuple(self):
        from aec.memory import store

        outcome = store.remember(
            fresh_memory(), "GAP_NOTE", "detail", relates_to=["a:1", "b:2"]
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.entry.relates_to, ("a:1", "b:2"))

    def test_outcome_dict_has_stable_keys(self):
        from aec.memory import store

        outcome = store.remember(fresh_memory(), "GAP_NOTE", "detail")
        self.assertEqual(
            sorted(outcome.to_dict()), ["entry", "memory", "ok", "refusal_code"]
        )


class TestSafetyGuards(unittest.TestCase):
    def test_modules_have_no_network_or_foreign_imports(self):
        for name in MODULES:
            tree = ast.parse((MEMORY_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)

    def test_modules_perform_no_filesystem_writes(self):
        for name in MODULES:
            tree = ast.parse((MEMORY_DIR / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = ""
                    if isinstance(func, ast.Name):
                        called = func.id
                    elif isinstance(func, ast.Attribute):
                        called = func.attr
                    self.assertNotIn(called, {"write_text", "mkdir", "makedirs"}, name)
                    if called == "open":
                        modes = [
                            a.value for a in node.args[1:]
                            if isinstance(a, ast.Constant) and isinstance(a.value, str)
                        ]
                        for mode in modes:
                            self.assertNotIn("w", mode.replace("U", ""), name)

    def test_store_uses_redaction_layer(self):
        source = (MEMORY_DIR / "store.py").read_text()
        self.assertIn("scrub_text", source)


if __name__ == "__main__":
    unittest.main()
