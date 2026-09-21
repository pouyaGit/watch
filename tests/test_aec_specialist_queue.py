"""EPIC6 Part 9: deterministic specialist queues (NEW module -> RED)."""

from __future__ import annotations

import json
import unittest

JOB_FIELDS = {
    "host": "shop.example.com",
    "family": "example.com",
    "category": "XSS_CANDIDATE",
    "band": "MEDIUM",
    "attempts": 0,
    "refused": "",
    "duplicate_of": "",
    "case_id": "case-",
}


def job_entry(**overrides):
    fields = dict(JOB_FIELDS)
    fields.update(overrides)
    return fields


class TestQueueBuild(unittest.TestCase):
    def test_queue_total_and_id(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(), job_entry(category="SSRF_CANDIDATE")],
            registry=queue.default_registry())
        self.assertEqual(built.total, 2)
        self.assertTrue(built.queue_id.startswith("specq:"))
        self.assertEqual(len(built.queue_id), len("specq:") + 12)

    def test_stable_ordering_by_band_then_case(self):
        from aec.specialists import queue

        entries = [
            job_entry(band="HIGH", case_id="case-b"),
            job_entry(band="LOW", case_id="case-c"),
            job_entry(band="MEDIUM", case_id="case-a"),
        ]
        built = queue.build_specialist_queue(entries, queue.default_registry())
        order = [item["case_id"] for item in built.entries]
        self.assertEqual(order, ["case-b", "case-a", "case-c"])

    def test_band_priority_explicit(self):
        from aec.specialists import queue

        self.assertEqual(queue.band_priority("HIGH"), 0)
        self.assertEqual(queue.band_priority("MEDIUM"), 1)
        self.assertEqual(queue.band_priority("LOW"), 2)

    def test_attempts_penalize(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(band="HIGH", attempts=1),
             job_entry(band="MEDIUM", attempts=0, case_id="case-z")],
            queue.default_registry())
        order = [item["case_id"] for item in built.entries]
        self.assertEqual(order, ["case-z", "case-"])

    def test_specialist_matched_by_category(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(category="IDOR_CANDIDATE")],
            queue.default_registry())
        entry = built.entries[0]
        self.assertEqual(entry["specialist"], "authorization-researcher")
        self.assertIn("authz-surface-review", entry["capabilities"])

    def test_unknown_category_gets_generalist(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(category="MYSTERY_CATEGORY", case_id="case-9")],
            queue.default_registry())
        self.assertEqual(built.entries[0]["specialist"], "general-researcher")

    def test_duplicate_suppression(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(case_id="case-1"), job_entry(case_id="case-1")],
            queue.default_registry())
        self.assertEqual(built.total, 2)
        dupes = [item for item in built.entries if item["duplicate_of"]]
        self.assertEqual(len(dupes), 1)
        self.assertEqual(dupes[0]["duplicate_of"], "case-1")

    def test_queued_excludes_duplicates(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(case_id="case-1"), job_entry(case_id="case-1")],
            queue.default_registry())
        self.assertEqual(built.queued_count, 1)

    def test_refusal_recorded(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(refused="BELOW_EVIDENCE_LEVEL", case_id="case-1")],
            queue.default_registry())
        entry = built.entries[0]
        self.assertEqual(entry["refused"], "BELOW_EVIDENCE_LEVEL")
        self.assertIn("BELOW_EVIDENCE_LEVEL", built.refusals)

    def test_retry_classification(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(attempts=0, case_id="case-1"),
             job_entry(attempts=2, case_id="case-2")],
            queue.default_registry())
        by_case = {item["case_id"]: item for item in built.entries}
        self.assertEqual(by_case["case-1"]["retry_class"], "FIRST_ATTEMPT")
        self.assertEqual(by_case["case-2"]["retry_class"], "RETRY")

    def test_starvation_detected(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(case_id="case-1", waiting_ticks=10)],
            queue.default_registry(),
            starvation_threshold=5)
        self.assertEqual(built.entries[0]["starvation"], "STARVED")

    def test_no_starvation_below_threshold(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(case_id="case-1", waiting_ticks=3)],
            queue.default_registry(),
            starvation_threshold=5)
        self.assertEqual(built.entries[0]["starvation"], "NORMAL")

    def test_host_budget_compatibility(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(host="a.example.com", case_id="case-1"),
             job_entry(host="a.example.com", case_id="case-2"),
             job_entry(host="a.example.com", case_id="case-3")],
            queue.default_registry(),
            host_budget=2)
        over = [item for item in built.entries if item["budget"] == "OVER"]
        self.assertEqual(len(over), 1)
        self.assertEqual(over[0]["case_id"], "case-3")

    def test_family_budget_compatibility(self):
        from aec.specialists import queue

        jobs = [
            job_entry(family="example.com", host="a.example.com",
                      case_id=f"case-{index}")
            for index in range(3)
        ]
        built = queue.build_specialist_queue(
            jobs, queue.default_registry(), family_budget=2)
        over = [item for item in built.entries if item["budget"] == "OVER"]
        self.assertEqual(len(over), 1)

    def test_metrics(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry(case_id="case-1"), job_entry(case_id="case-1"),
             job_entry(case_id="case-2", refused="UNSUPPORTED_INPUT")],
            queue.default_registry())
        metrics = built.metrics
        self.assertEqual(metrics["total"], 3)
        self.assertEqual(metrics["queued"], 1)
        self.assertEqual(metrics["duplicates"], 1)
        self.assertEqual(metrics["refusals"], 1)


class TestQueueSerialization(unittest.TestCase):
    def test_to_dict_shape(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry()], queue.default_registry())
        document = built.to_dict()
        self.assertEqual(
            sorted(document),
            ["entries", "metrics", "queue_id", "total"])

    def test_json_stable(self):
        from aec.specialists import queue

        def snapshot():
            built = queue.build_specialist_queue(
                [job_entry(case_id="case-1"),
                 job_entry(case_id="case-2", category="IDOR_CANDIDATE")],
                queue.default_registry())
            return json.dumps(built.to_dict(), sort_keys=True)

        self.assertEqual(snapshot(), snapshot())

    def test_entries_have_required_fields(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue(
            [job_entry()], queue.default_registry())
        entry = built.entries[0]
        self.assertEqual(sorted(entry), [
            "attempts", "band", "budget", "capabilities", "case_id",
            "category", "duplicate_of", "family", "host", "refused",
            "retry_class", "specialist", "starvation"])

    def test_empty_queue(self):
        from aec.specialists import queue

        built = queue.build_specialist_queue([], queue.default_registry())
        self.assertEqual(built.total, 0)
        self.assertEqual(built.entries, ())


if __name__ == "__main__":
    unittest.main()