"""Tests for aec/queue (EPIC 3 Part 2: Research Queue).

Deterministic priority scheduling over case metadata, evidence state,
and budget state: explicit triage rubric, content-hash snapshots, and
bounded retry tracking. No clocks, no network, no writes.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

QUEUE_DIR = Path(__file__).resolve().parents[1] / "aec" / "queue"
MODULES = ("models.py", "priority.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})


def item(case_id="case-001", risk="R1_OBJECT_REFERENCE",
         evidence="WAITING_EVIDENCE", cost=3, order=1):
    return {
        "case_id": case_id,
        "risk_category": risk,
        "evidence_state": evidence,
        "planned_cost": cost,
        "selection_order": order,
    }


class TestScoring(unittest.TestCase):
    def test_score_is_deterministic(self):
        from aec.queue import priority

        self.assertEqual(priority.score_item(item()), priority.score_item(item()))

    def test_higher_risk_sorts_first(self):
        from aec.queue import priority

        low = priority.score_item(item(case_id="a", risk="R0_UNCLASSIFIED"))
        high = priority.score_item(item(case_id="b", risk="R5_ACCESS_CONTROL"))
        self.assertGreater(high, low)

    def test_partial_evidence_outranks_waiting(self):
        from aec.queue import priority

        waiting = priority.score_item(item(case_id="a", evidence="WAITING_EVIDENCE"))
        partial = priority.score_item(item(case_id="b", evidence="EVIDENCE_PARTIAL"))
        self.assertGreater(partial, waiting)

    def test_cheaper_cost_outranks_expensive(self):
        from aec.queue import priority

        cheap = priority.score_item(item(case_id="a", cost=1))
        dear = priority.score_item(item(case_id="b", cost=4))
        self.assertGreater(cheap, dear)

    def test_rubric_weights_are_pinned(self):
        from aec.queue import priority

        self.assertEqual(
            priority.RISK_WEIGHTS,
            {
                "R5_ACCESS_CONTROL": 50,
                "R1_OBJECT_REFERENCE": 40,
                "R2_SERVER_FETCH": 30,
                "R3_REFLECTION": 20,
                "R4_CONTENT_HANDLING": 10,
                "R0_UNCLASSIFIED": 0,
            },
        )
        self.assertEqual(
            priority.STATE_WEIGHTS,
            {
                "EVIDENCE_PARTIAL": 30,
                "WAITING_EVIDENCE": 20,
                "EVIDENCE_READY": 10,
                "REVIEW_REQUIRED": 0,
            },
        )

    def test_unknown_risk_scores_zero_weight(self):
        from aec.queue import priority

        known = priority.score_item(item(risk="R1_OBJECT_REFERENCE"))
        unknown = priority.score_item(item(risk="R9_UNKNOWN"))
        self.assertEqual(known - unknown, 40)

    def test_score_breakdown_explains_total(self):
        from aec.queue import priority

        parts = priority.score_breakdown(item())
        self.assertEqual(
            parts["total"], parts["risk"] + parts["state"] - parts["cost"]
        )


class TestQueueBuild(unittest.TestCase):
    def test_build_orders_by_score_then_order_then_id(self):
        from aec.queue import priority

        snapshot = priority.build_queue([
            item("case-003", order=3),
            item("case-001", order=1, risk="R0_UNCLASSIFIED"),
            item("case-002", order=2, evidence="EVIDENCE_PARTIAL"),
        ])
        ranked = [e.case_id for e in snapshot.entries]
        self.assertEqual(ranked[0], "case-002")
        self.assertEqual(ranked[1], "case-003")
        self.assertEqual(ranked[2], "case-001")

    def test_tie_breaks_are_deterministic(self):
        from aec.queue import priority

        items = [item(f"case-{i:03d}", order=1) for i in (9, 3, 7)]
        first = [e.case_id for e in priority.build_queue(items).entries]
        second = [e.case_id for e in priority.build_queue(list(reversed(items))).entries]
        self.assertEqual(first, second)
        self.assertEqual(first, ["case-003", "case-007", "case-009"])

    def test_ranks_are_dense_and_ordered(self):
        from aec.queue import priority

        snapshot = priority.build_queue([item(f"case-{i:03d}") for i in range(5)])
        self.assertEqual([e.rank for e in snapshot.entries], [1, 2, 3, 4, 5])
        scores = [e.score for e in snapshot.entries]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_queue_builds(self):
        from aec.queue import priority

        snapshot = priority.build_queue([])
        self.assertEqual(snapshot.entries, ())
        self.assertEqual(snapshot.total, 0)

    def test_snapshot_id_is_content_hash(self):
        import hashlib
        from aec.queue import priority

        snapshot = priority.build_queue([item()])
        expected = "queue:" + hashlib.sha256(
            json.dumps(snapshot.to_dict()["entries"], sort_keys=True).encode()
        ).hexdigest()[:12]
        self.assertEqual(snapshot.snapshot_id, expected)
        again = priority.build_queue([item()])
        self.assertEqual(snapshot.snapshot_id, again.snapshot_id)

    def test_snapshot_lists_source_cases(self):
        from aec.queue import priority

        snapshot = priority.build_queue([item("case-002"), item("case-001")])
        self.assertEqual(list(snapshot.generated_from), ["case-001", "case-002"])

    def test_invalid_items_rejected(self):
        from aec.queue import priority

        for bad in (None, "x", [{"case_id": ""}], [{"case_id": "a"}]):
            with self.assertRaises(ValueError, msg=f"{bad!r}"):
                priority.build_queue(bad)

    def test_duplicate_case_ids_rejected(self):
        from aec.queue import priority

        with self.assertRaises(ValueError):
            priority.build_queue([item("case-001"), item("case-001")])

    def test_negative_cost_rejected(self):
        from aec.queue import priority

        with self.assertRaises(ValueError):
            priority.build_queue([item(cost=-1)])

    def test_snapshot_is_frozen(self):
        from aec.queue import priority

        snapshot = priority.build_queue([item()])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snapshot.total = 99

    def test_serialization_round_trip(self):
        from aec.queue import priority

        snapshot = priority.build_queue([item("case-002"), item("case-001")])
        text = priority.serialize_snapshot(snapshot)
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)
        self.assertEqual(json.loads(text)["total"], 2)


class TestRetries(unittest.TestCase):
    def test_fresh_case_has_full_retries(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        self.assertEqual(priority.retries_left(tracker, "case-001"), 3)

    def test_attempts_consume_retries(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        tracker = priority.record_attempt(tracker, "case-001")
        tracker = priority.record_attempt(tracker, "case-001")
        self.assertEqual(priority.retries_left(tracker, "case-001"), 1)
        self.assertEqual(priority.attempt_count(tracker, "case-001"), 2)

    def test_exhausted_case_has_none_left(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        for _ in range(4):
            tracker = priority.record_attempt(tracker, "case-001")
        self.assertEqual(priority.retries_left(tracker, "case-001"), 0)

    def test_refusal_reason_recorded(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        tracker = priority.record_refusal(tracker, "case-001", "MISSING_ENDPOINT")
        self.assertEqual(priority.last_reason(tracker, "case-001"), "MISSING_ENDPOINT")

    def test_refusal_implies_attempt(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        tracker = priority.record_refusal(tracker, "case-001", "INVALID_BUDGET")
        self.assertEqual(priority.attempt_count(tracker, "case-001"), 1)

    def test_trackers_are_independent_per_case(self):
        from aec.queue import priority

        tracker = priority.record_attempt(priority.empty_tracker(), "case-001")
        self.assertEqual(priority.attempt_count(tracker, "case-002"), 0)
        self.assertEqual(priority.retries_left(tracker, "case-002"), 3)

    def test_empty_reason_rejected(self):
        from aec.queue import priority

        with self.assertRaises(ValueError):
            priority.record_refusal(priority.empty_tracker(), "case-001", "")

    def test_tracker_is_frozen_and_serializable(self):
        from aec.queue import priority

        tracker = priority.record_refusal(
            priority.empty_tracker(), "case-001", "MISSING_ENDPOINT"
        )
        text = priority.serialize_tracker(tracker)
        self.assertEqual(json.dumps(json.loads(text), sort_keys=True), text)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            tracker.cases = ()

    def test_exact_score_math(self):
        from aec.queue import priority

        # R1 (40) + WAITING (20) - cost 3 = 57.
        self.assertEqual(priority.score_item(item()), 57)

    def test_review_required_sorts_last(self):
        from aec.queue import priority

        snapshot = priority.build_queue([
            item("case-001", evidence="REVIEW_REQUIRED"),
            item("case-002", evidence="WAITING_EVIDENCE"),
        ])
        self.assertEqual(snapshot.entries[0].case_id, "case-002")

    def test_zero_cost_is_cheapest(self):
        from aec.queue import priority

        snapshot = priority.build_queue([item("case-001", cost=0), item("case-002", cost=1)])
        self.assertEqual(snapshot.entries[0].case_id, "case-001")

    def test_breakdown_keys_are_stable(self):
        from aec.queue import priority

        self.assertEqual(
            sorted(priority.score_breakdown(item())), ["cost", "risk", "state", "total"]
        )

    def test_tracker_dict_has_stable_keys(self):
        from aec.queue import priority

        tracker = priority.record_attempt(priority.empty_tracker(), "case-001")
        self.assertEqual(sorted(tracker.to_dict()), ["cases"])
        self.assertEqual(
            sorted(tracker.to_dict()["cases"][0]),
            ["attempts", "case_id", "last_reason"],
        )

    def test_unknown_case_has_zero_attempts(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        self.assertEqual(priority.attempt_count(tracker, "nope"), 0)
        self.assertIsNone(priority.last_reason(tracker, "nope"))

    def test_retries_never_go_negative(self):
        from aec.queue import priority

        tracker = priority.empty_tracker()
        for _ in range(10):
            tracker = priority.record_attempt(tracker, "case-001")
        self.assertEqual(priority.retries_left(tracker, "case-001"), 0)

    def test_max_retries_constant(self):
        from aec.queue import priority

        self.assertEqual(priority.MAX_RETRIES, 3)

    def test_queue_entry_dict_keys(self):
        from aec.queue import priority

        entry = priority.build_queue([item()]).entries[0]
        self.assertEqual(sorted(entry.to_dict()), ["case_id", "rank", "score"])

    def test_build_rejects_non_mapping_items(self):
        from aec.queue import priority

        with self.assertRaises(ValueError):
            priority.build_queue(["not-a-mapping"])

    def test_snapshot_to_dict_keys(self):
        from aec.queue import priority

        snapshot = priority.build_queue([item()])
        self.assertEqual(
            sorted(snapshot.to_dict()), ["entries", "generated_from", "snapshot_id", "total"]
        )

    def test_build_accepts_tuples(self):
        from aec.queue import priority

        snapshot = priority.build_queue((item("case-001"), item("case-002")))
        self.assertEqual(snapshot.total, 2)

    def test_tracker_round_trip_content(self):
        import json as json_lib
        from aec.queue import priority

        tracker = priority.record_refusal(
            priority.empty_tracker(), "case-001", "MISSING_ENDPOINT"
        )
        doc = json_lib.loads(priority.serialize_tracker(tracker))
        self.assertEqual(doc["cases"][0]["attempts"], 1)
        self.assertEqual(doc["cases"][0]["last_reason"], "MISSING_ENDPOINT")

    def test_scores_order_with_negative_values(self):
        from aec.queue import priority

        snapshot = priority.build_queue([
            item("case-001", cost=200),
            item("case-002", cost=1),
        ])
        self.assertEqual(snapshot.entries[0].case_id, "case-002")

    def test_state_weight_zero_for_review(self):
        from aec.queue import priority

        self.assertEqual(
            priority.score_item(item(evidence="REVIEW_REQUIRED")),
            priority.score_item(item(evidence="WAITING_EVIDENCE")) - 20,
        )


class TestSafetyGuards(unittest.TestCase):
    def test_modules_have_no_network_or_foreign_imports(self):
        for name in MODULES:
            tree = ast.parse((QUEUE_DIR / name).read_text())
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
            tree = ast.parse((QUEUE_DIR / name).read_text())
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


if __name__ == "__main__":
    unittest.main()
