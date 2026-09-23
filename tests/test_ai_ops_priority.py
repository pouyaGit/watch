"""EPIC9 §7/§8: deterministic prioritization + bounded fairness."""

from __future__ import annotations

import unittest

from backend.ai_ops.config import DispatcherConfig
from backend.ai_ops.discovery import (
    CLASS_CAMPAIGN, CLASS_FINDING, CLASS_JOB, WorkItem,
)
from backend.ai_ops.priority import (
    CLASS_RANK, order_key, prioritize, select_bounded,
)


def mk(work_id: str, work_class: str = CLASS_JOB, priority: int = 50,
       created_at: str = "2026-09-23T09:00:00+00:00",
       scope_ref: str = "watch:scope:www.example.com",
       target: str = "", campaign_id: str = "",
       executable: bool = True) -> WorkItem:
    return WorkItem(
        work_id=work_id, work_class=work_class, source="test",
        source_id=work_id, scope_ref=scope_ref,
        target=target or scope_ref, priority=priority,
        created_at=created_at, state="QUEUED", executable=executable,
        reason="EXECUTABLE" if executable else "INVALID_STATE",
        detail="fixture", campaign_id=campaign_id,
    )


def cfg(**kw) -> DispatcherConfig:
    env = {f"WATCH_AI_OPS_{k.upper()}": str(v) for k, v in kw.items()}
    return DispatcherConfig.from_env(env)


class OrderTests(unittest.TestCase):

    def test_deterministic_repeated_ordering(self):
        items = [mk("a"), mk("b", priority=90), mk("c", priority=10)]
        self.assertEqual([i.work_id for i in prioritize(items)],
                         [i.work_id for i in prioritize(list(reversed(items)))])

    def test_class_rank_job_before_finding_before_campaign(self):
        items = [mk("c1", CLASS_CAMPAIGN), mk("f1", CLASS_FINDING),
                 mk("j1", CLASS_JOB)]
        self.assertEqual([i.work_id for i in prioritize(items)],
                         ["j1", "f1", "c1"])

    def test_priority_descending_within_class(self):
        items = [mk("low", priority=10), mk("high", priority=90),
                 mid := mk("mid", priority=50)]
        del mid
        self.assertEqual([i.work_id for i in prioritize(items)],
                         ["high", "mid", "low"])

    def test_older_first_at_equal_priority(self):
        items = [mk("newer", created_at="2026-09-23T10:00:00+00:00"),
                 mk("older", created_at="2026-09-23T08:00:00+00:00")]
        self.assertEqual([i.work_id for i in prioritize(items)],
                         ["older", "newer"])

    def test_ageless_sorts_last(self):
        items = [mk("aged", created_at="2026-09-23T10:00:00+00:00"),
                 mk("ageless", created_at="")]
        self.assertEqual([i.work_id for i in prioritize(items)],
                         ["aged", "ageless"])

    def test_scope_tiebreak(self):
        items = [mk("z", scope_ref="watch:scope:zzz.example.com"),
                 mk("a", scope_ref="watch:scope:aaa.example.com")]
        self.assertEqual([i.work_id for i in prioritize(items)],
                         ["a", "z"])

    def test_work_id_final_tiebreak(self):
        items = [mk("same2"), mk("same1")]
        self.assertEqual([i.work_id for i in prioritize(items)],
                         ["same1", "same2"])

    def test_order_key_total_and_hashable(self):
        k1, k2 = order_key(mk("x")), order_key(mk("x"))
        self.assertEqual(k1, k2)
        self.assertIsInstance(k1, tuple)

    def test_class_rank_covers_all_executable_classes(self):
        for cls in (CLASS_JOB, CLASS_FINDING, CLASS_CAMPAIGN):
            self.assertIn(cls, CLASS_RANK)

    def test_no_opaque_score_component(self):
        # The ordering key is exactly the five documented fields.
        key = order_key(mk("x"))
        self.assertEqual(len(key), 5)


class SelectBoundedTests(unittest.TestCase):

    def test_empty_input(self):
        self.assertEqual(select_bounded([], cfg()), ([], []))

    def test_non_executable_never_selected(self):
        items = [mk("bad", executable=False)]
        selected, deferred = select_bounded(items, cfg())
        # filtered before the budget walk: neither bucket gets it
        self.assertEqual(selected, [])
        self.assertEqual(deferred, [])

    def test_max_work_cap(self):
        items = [mk(f"j{i}", created_at=f"2026-09-23T09:00:{i:02d}+00:00")
                 for i in range(4)]
        selected, deferred = select_bounded(items, cfg(max_work=2))
        self.assertEqual(len(selected), 2)
        self.assertEqual(len(deferred), 2)
        self.assertTrue(all(d.meta.get("deferred_by") == "work budget"
                            for d in deferred))

    def test_per_target_cap(self):
        scope = "watch:scope:www.example.com"
        items = [mk(f"j{i}", scope_ref=scope, target=scope,
                    created_at=f"2026-09-23T09:00:{i:02d}+00:00")
                 for i in range(3)]
        selected, deferred = select_bounded(
            items, cfg(max_work=10, max_per_target=2))
        self.assertEqual(len(selected), 2)
        self.assertEqual(len(deferred), 1)
        self.assertEqual(deferred[0].meta.get("deferred_by"),
                         "target budget")

    def test_per_campaign_cap(self):
        items = [mk(f"j{i}", campaign_id="camp-1") for i in range(3)]
        selected, deferred = select_bounded(
            items, cfg(max_work=10, max_per_target=10))
        self.assertEqual(len(selected), 1)
        self.assertEqual(deferred[0].meta.get("deferred_by"),
                         "campaign budget")

    def test_jobs_without_campaign_ignore_campaign_cap(self):
        items = [mk(f"j{i}") for i in range(4)]
        selected, _ = select_bounded(items, cfg(max_work=4,
                                                max_per_target=10))
        self.assertEqual(len(selected), 4)

    def test_fairness_rotation_across_targets(self):
        # Target A dominates priority; per-target cap forces the other
        # targets' items through — no starvation.
        a_scope = "watch:scope:aaa.example.com"
        b_scope = "watch:scope:bbb.example.com"
        c_scope = "watch:scope:ccc.example.com"
        items = [mk(f"a{i}", scope_ref=a_scope, target=a_scope,
                    priority=90, created_at=f"2026-09-23T09:00:{i:02d}+00:00")
                 for i in range(5)]
        items.append(mk("b0", scope_ref=b_scope, target=b_scope,
                        priority=10))
        items.append(mk("c0", scope_ref=c_scope, target=c_scope,
                        priority=10))
        selected, deferred = select_bounded(
            items, cfg(max_work=3, max_per_target=1))
        ids = [i.work_id for i in selected]
        self.assertEqual(len(ids), 3)
        self.assertIn("b0", ids)          # starvation prevented
        self.assertIn("c0", ids)
        self.assertEqual(len([i for i in selected
                              if i.scope_ref == a_scope]), 1)
        self.assertEqual(len(deferred), 4)

    def test_work_budget_defers_across_targets(self):
        items = [mk("a", scope_ref="watch:scope:aaa.example.com"),
                 mk("b", scope_ref="watch:scope:bbb.example.com"),
                 mk("c", scope_ref="watch:scope:ccc.example.com")]
        selected, deferred = select_bounded(
            items, cfg(max_work=1, max_per_target=5))
        self.assertEqual([i.work_id for i in selected], ["a"])
        self.assertEqual({d.work_id for d in deferred}, {"b", "c"})
        self.assertTrue(all(d.meta.get("deferred_by") == "work budget"
                            for d in deferred))

    def test_selected_respects_full_key_order(self):
        other = "watch:scope:other.example.com"
        items = [mk("j2", CLASS_JOB), mk("j1", CLASS_JOB),
                 mk("f1", CLASS_FINDING, scope_ref=other, target=other)]
        selected, _ = select_bounded(items, cfg(max_work=3))
        self.assertEqual([i.work_id for i in selected],
                         ["j1", "j2", "f1"])

    def test_repeated_selection_is_stable(self):
        items = [mk(f"j{i}") for i in range(3)]
        first, _ = select_bounded(items, cfg(max_work=2))
        second, _ = select_bounded(items, cfg(max_work=2))
        self.assertEqual([i.work_id for i in first],
                         [i.work_id for i in second])

    def test_deferred_items_remain_executable_for_next_tick(self):
        items = [mk(f"j{i}") for i in range(3)]
        _, deferred = select_bounded(items, cfg(max_work=1))
        for d in deferred:
            self.assertTrue(d.executable)
            self.assertEqual(d.reason, "EXECUTABLE")


if __name__ == "__main__":
    unittest.main()
