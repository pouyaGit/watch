"""Tests for aec/review (EPIC 5 Part 7: Human Review Queue).

Review items are the offline review surface: every case that reaches a
terminal offline state gets one, with a closed reason, the current and
evidence states, outstanding evidence, research history, and a
recommended next action. Items are never converted into conclusions.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REVIEW_DIR = Path(__file__).resolve().parents[1] / "aec" / "review"
MODULES = ("models.py", "queue.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "EXPLOITABLE", "EXPLOIT",
    "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)

REASONS = frozenset({
    "DRAFT_INVALID",
    "PLAN_INVALID",
    "AUTHORIZATION_REFUSED",
    "EVIDENCE_INCOMPLETE",
    "DUPLICATE_OBSERVED",
})

ACTIONS = frozenset({
    "COLLECT_FIRST_OBSERVATION",
    "RESOLVE_REFUSAL",
    "HUMAN_TRIAGE",
    "DEDUPE_CONFIRM",
    "REPLAN_OBSERVATION",
})


def item(**overrides):
    entry = {
        "case_id": "case-001",
        "reason": "EVIDENCE_INCOMPLETE",
        "current_state": "WAITING_EVIDENCE",
        "evidence_state": "WAITING_EVIDENCE",
        "missing_evidence": ("initial-observation",),
        "research_history": {"duplicates": [], "related_patterns": 0},
        "recommended_next_action": "COLLECT_FIRST_OBSERVATION",
    }
    entry.update(overrides)
    return entry


class TestRecommendFor(unittest.TestCase):
    def test_recommendation_table(self):
        from aec.review import queue

        expected = {
            "EVIDENCE_INCOMPLETE": "COLLECT_FIRST_OBSERVATION",
            "AUTHORIZATION_REFUSED": "RESOLVE_REFUSAL",
            "DRAFT_INVALID": "HUMAN_TRIAGE",
            "PLAN_INVALID": "REPLAN_OBSERVATION",
            "DUPLICATE_OBSERVED": "DEDUPE_CONFIRM",
        }
        for reason, action in expected.items():
            self.assertEqual(queue.recommend_for(reason), action, reason)

    def test_unknown_reason_triages(self):
        from aec.review import queue

        self.assertEqual(queue.recommend_for("SOMETHING_ELSE"), "HUMAN_TRIAGE")


class TestBuildReviewItem(unittest.TestCase):
    def test_valid_item_builds(self):
        from aec.review import queue

        built = queue.build_review_item(item())
        self.assertEqual(built.case_id, "case-001")
        self.assertEqual(
            built.recommended_next_action, "COLLECT_FIRST_OBSERVATION"
        )

    def test_action_derived_when_missing(self):
        from aec.review import queue

        fields = item(recommended_next_action="")
        built = queue.build_review_item(fields)
        self.assertEqual(
            built.recommended_next_action, "COLLECT_FIRST_OBSERVATION"
        )

    def test_explicit_action_kept_when_valid(self):
        from aec.review import queue

        built = queue.build_review_item(item(recommended_next_action="HUMAN_TRIAGE"))
        self.assertEqual(built.recommended_next_action, "HUMAN_TRIAGE")

    def test_invalid_action_replaced(self):
        from aec.review import queue

        built = queue.build_review_item(item(recommended_next_action="SHIP_IT"))
        self.assertEqual(
            built.recommended_next_action, "COLLECT_FIRST_OBSERVATION"
        )

    def test_missing_case_refused(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item(item(case_id=""))

    def test_unknown_reason_refused(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item(item(reason="NOPE"))

    def test_non_mapping_refused(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item("nope")

    def test_missing_sorted_unique(self):
        from aec.review import queue

        built = queue.build_review_item(
            item(missing_evidence=("b", "a", "b")))
        self.assertEqual(built.missing_evidence, ("a", "b"))

    def test_item_dict_keys(self):
        from aec.review import queue

        self.assertEqual(
            sorted(queue.build_review_item(item()).to_dict()),
            ["case_id", "current_state", "evidence_state", "missing_evidence",
             "reason", "recommended_next_action", "research_history"],
        )

    def test_items_are_frozen(self):
        import dataclasses
        from aec.review import queue

        with self.assertRaises(dataclasses.FrozenInstanceError):
            queue.build_review_item(item()).reason = "OTHER"


class TestBuildReviewQueue(unittest.TestCase):
    def test_queue_orders_by_case_id(self):
        from aec.review import queue

        built = queue.build_review_queue([
            item(case_id="case-zzz"),
            item(case_id="case-aaa"),
        ])
        self.assertEqual(
            [entry.case_id for entry in built.items], ["case-aaa", "case-zzz"]
        )

    def test_queue_id_is_content_hash(self):
        import hashlib
        import json
        from aec.review import queue

        built = queue.build_review_queue([item()])
        canonical = json.dumps(
            [queue.build_review_item(item()).to_dict()],
            sort_keys=True, separators=(",", ":"),
        )
        expected = "review:" + hashlib.sha256(canonical.encode()).hexdigest()[:12]
        self.assertEqual(built.queue_id, expected)

    def test_empty_queue(self):
        from aec.review import queue

        built = queue.build_review_queue([])
        self.assertEqual(built.items, ())
        self.assertEqual(built.total, 0)

    def test_total_matches(self):
        from aec.review import queue

        built = queue.build_review_queue([item(), item(case_id="case-002")])
        self.assertEqual(built.total, 2)

    def test_serialize_stable(self):
        import json
        from aec.review import queue

        text = queue.serialize_queue(queue.build_review_queue([item()]))
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")),
            text,
        )

    def test_reasons_are_closed(self):
        from aec.review import models

        self.assertEqual(set(models.REVIEW_REASONS), REASONS)

    def test_actions_are_closed(self):
        from aec.review import models

        self.assertEqual(set(models.REVIEW_ACTIONS), ACTIONS)


class TestSafetyGuards(unittest.TestCase):
    def test_no_forbidden_vocabulary_in_source(self):
        for name in MODULES:
            source = (REVIEW_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((REVIEW_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)


class TestReviewDetails(unittest.TestCase):
    def test_history_passed_through(self):
        from aec.review import queue

        history = {"duplicates": ["case-9"], "related_patterns": 3}
        built = queue.build_review_item(item(research_history=history))
        self.assertEqual(built.research_history, history)

    def test_history_defaults_empty(self):
        from aec.review import queue

        fields = item()
        del fields["research_history"]
        built = queue.build_review_item(fields)
        self.assertEqual(built.research_history, {})

    def test_non_mapping_history_defaults(self):
        from aec.review import queue

        built = queue.build_review_item(item(research_history="nope"))
        self.assertEqual(built.research_history, {})

    def test_states_default_empty(self):
        from aec.review import queue

        fields = item()
        del fields["current_state"]
        del fields["evidence_state"]
        built = queue.build_review_item(fields)
        self.assertEqual(built.current_state, "")
        self.assertEqual(built.evidence_state, "")

    def test_missing_defaults_empty(self):
        from aec.review import queue

        fields = item()
        del fields["missing_evidence"]
        built = queue.build_review_item(fields)
        self.assertEqual(built.missing_evidence, ())

    def test_non_list_missing_defaults(self):
        from aec.review import queue

        built = queue.build_review_item(item(missing_evidence="a"))
        self.assertEqual(built.missing_evidence, ())

    def test_reason_case_sensitive(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item(item(reason="evidence_incomplete"))

    def test_case_id_stripped(self):
        from aec.review import queue

        built = queue.build_review_item(item(case_id="  case-001  "))
        self.assertEqual(built.case_id, "case-001")

    def test_whitespace_case_refused(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item(item(case_id="   "))

    def test_queue_id_changes_with_content(self):
        from aec.review import queue

        first = queue.build_review_queue([item()])
        second = queue.build_review_queue([item(case_id="case-002")])
        self.assertNotEqual(first.queue_id, second.queue_id)

    def test_queue_same_input_same_id(self):
        from aec.review import queue

        first = queue.build_review_queue([item(), item(case_id="case-002")])
        second = queue.build_review_queue([item(case_id="case-002"), item()])
        self.assertEqual(first.queue_id, second.queue_id)

    def test_queue_dict_keys(self):
        from aec.review import queue

        self.assertEqual(
            sorted(queue.build_review_queue([item()]).to_dict()),
            ["items", "queue_id", "total"],
        )

    def test_coordinator_review_dicts_validate(self):
        from aec.coordinator import pipeline
        from aec.review import queue

        run = pipeline.run_research([
            {
                "program": "pilot", "subdomain": "shop.example.com",
                "url": "/orders?order_id=", "endpoint": "/orders",
                "parameter": "order_id", "method": "GET",
                "location": "query", "technology": [],
                "source": "watch", "last_update": None,
                "category": "IDOR_CANDIDATE",
            }
        ])
        for fields in run.review_items:
            built = queue.build_review_item(fields)
            self.assertEqual(built.case_id, run.cases_created[0])

    def test_all_reasons_have_actions(self):
        from aec.review import models, queue

        for reason in models.REVIEW_REASONS:
            self.assertIn(queue.recommend_for(reason), models.REVIEW_ACTIONS)

    def test_duplicate_case_ids_allowed(self):
        from aec.review import queue

        built = queue.build_review_queue([item(), item(reason="PLAN_INVALID")])
        self.assertEqual(built.total, 2)

    def test_serialize_item_stable(self):
        import json
        from aec.review import queue

        built = queue.build_review_item(item())
        text = json.dumps(built.to_dict(), sort_keys=True,
                          separators=(",", ":"))
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True,
                       separators=(",", ":")),
            text,
        )

    def test_each_action_reachable(self):
        from aec.review import queue

        pairs = [
            ("EVIDENCE_INCOMPLETE", "COLLECT_FIRST_OBSERVATION"),
            ("AUTHORIZATION_REFUSED", "RESOLVE_REFUSAL"),
            ("DRAFT_INVALID", "HUMAN_TRIAGE"),
            ("PLAN_INVALID", "REPLAN_OBSERVATION"),
            ("DUPLICATE_OBSERVED", "DEDUPE_CONFIRM"),
        ]
        for reason, action in pairs:
            built = queue.build_review_item(
                item(reason=reason, recommended_next_action="")
            )
            self.assertEqual(built.recommended_next_action, action, reason)

    def test_none_reason_triages(self):
        from aec.review import queue

        self.assertEqual(queue.recommend_for(None), "HUMAN_TRIAGE")

    def test_empty_missing_list_ok(self):
        from aec.review import queue

        built = queue.build_review_item(item(missing_evidence=[]))
        self.assertEqual(built.missing_evidence, ())

    def test_research_history_not_mutated(self):
        import copy
        from aec.review import queue

        history = {"duplicates": ["case-9"], "related_patterns": 3}
        before = copy.deepcopy(history)
        queue.build_review_item(item(research_history=history))
        self.assertEqual(history, before)


    def test_extra_keys_ignored(self):
        from aec.review import queue

        fields = item(extra="dropped", score=99)
        built = queue.build_review_item(fields)
        self.assertNotIn("extra", built.to_dict())

    def test_evidence_state_passthrough(self):
        from aec.review import queue

        built = queue.build_review_item(item(evidence_state="EVIDENCE_PARTIAL"))
        self.assertEqual(built.evidence_state, "EVIDENCE_PARTIAL")

    def test_current_state_passthrough(self):
        from aec.review import queue

        built = queue.build_review_item(item(current_state="SELECTED"))
        self.assertEqual(built.current_state, "SELECTED")

    def test_queue_preserves_item_order_for_display(self):
        from aec.review import queue

        built = queue.build_review_queue([
            item(case_id="case-mid"),
            item(case_id="case-aaa", reason="PLAN_INVALID"),
            item(case_id="case-zzz", reason="DUPLICATE_OBSERVED"),
        ])
        self.assertEqual(
            [entry.case_id for entry in built.items],
            ["case-aaa", "case-mid", "case-zzz"],
        )

    def test_queue_total_zero_empty(self):
        from aec.review import queue

        built = queue.build_review_queue([])
        self.assertTrue(built.queue_id.startswith("review:"))

    def test_item_requires_mapping_case(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item(item(case_id=42))

    def test_missing_items_filtered_not_dropped(self):
        from aec.review import queue

        built = queue.build_review_item(item(missing_evidence=["x", "", "x"]))
        self.assertEqual(built.missing_evidence, ("x",))

    def test_review_models_frozen(self):
        import dataclasses
        from aec.review import queue

        built = queue.build_review_queue([item()])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            built.items[0].case_id = "other"

    def test_queue_is_frozen(self):
        import dataclasses
        from aec.review import queue

        with self.assertRaises(dataclasses.FrozenInstanceError):
            queue.build_review_queue([item()]).total = 99

    def test_recommend_mapping_complete(self):
        from aec.review import models, queue

        derived = {queue.recommend_for(reason) for reason in models.REVIEW_REASONS}
        self.assertEqual(
            derived,
            {"COLLECT_FIRST_OBSERVATION", "RESOLVE_REFUSAL", "HUMAN_TRIAGE",
             "REPLAN_OBSERVATION", "DEDUPE_CONFIRM"},
        )


    def test_all_reasons_build(self):
        from aec.review import models, queue

        for reason in models.REVIEW_REASONS:
            built = queue.build_review_item(item(reason=reason))
            self.assertEqual(built.reason, reason)

    def test_queue_items_are_tuple(self):
        from aec.review import queue

        built = queue.build_review_queue([item()])
        self.assertIsInstance(built.items, tuple)

    def test_history_duplicates_preserved(self):
        from aec.review import queue

        history = {"duplicates": ["case-1", "case-2"], "related_patterns": 0}
        built = queue.build_review_item(item(research_history=history))
        self.assertEqual(
            built.research_history["duplicates"], ["case-1", "case-2"]
        )

    def test_int_missing_defaults(self):
        from aec.review import queue

        built = queue.build_review_item(item(missing_evidence=42))
        self.assertEqual(built.missing_evidence, ())

    def test_queue_id_prefix_length(self):
        from aec.review import queue

        built = queue.build_review_queue([item()])
        self.assertTrue(built.queue_id.startswith("review:"))
        self.assertEqual(len(built.queue_id), len("review:") + 12)

    def test_to_dict_items_are_list(self):
        from aec.review import queue

        document = queue.build_review_queue([item()]).to_dict()
        self.assertIsInstance(document["items"], list)
        self.assertEqual(len(document["items"]), 1)

    def test_non_string_reason_refused(self):
        from aec.review import queue

        with self.assertRaises(ValueError):
            queue.build_review_item(item(reason=42))


if __name__ == "__main__":
    unittest.main()
