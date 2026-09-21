"""Tests for aec/runtime job model (EPIC 6 Part 2: ResearchJob lifecycle).

13 durable states with explicit transition records. Invalid moves fail
closed. Timestamps are logical ticks (replay-stable), never wall clock.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

RUNTIME_DIR = Path(__file__).resolve().parents[1] / "aec" / "runtime"

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend", "requests", "httpx", "aiohttp",
})

FORBIDDEN = (
    "SEVERITY", "CVSS", "CRITICAL", "VULNERABLE", "EXPLOITABLE", "EXPLOIT",
    "PAYLOAD", "CONFIRMED", "FINDING", "VERDICT",
)

STATES = (
    "DISCOVERED", "QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
    "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING", "EVIDENCE_PENDING",
    "ANALYSIS_PENDING", "REVIEW_REQUIRED", "COMPLETED", "BLOCKED",
    "FAILED", "EXPIRED",
)

LEGAL = {
    "DISCOVERED": ("QUEUED", "BLOCKED"),
    "QUEUED": ("ASSIGNED", "BLOCKED", "EXPIRED"),
    "ASSIGNED": ("WAITING_AUTHORIZATION", "BLOCKED", "EXPIRED"),
    "WAITING_AUTHORIZATION": (
        "READY_FOR_OBSERVATION", "BLOCKED", "EXPIRED"),
    "READY_FOR_OBSERVATION": ("OBSERVATION_RUNNING", "BLOCKED", "EXPIRED"),
    "OBSERVATION_RUNNING": ("EVIDENCE_PENDING", "FAILED", "BLOCKED"),
    "EVIDENCE_PENDING": ("ANALYSIS_PENDING", "FAILED"),
    "ANALYSIS_PENDING": ("REVIEW_REQUIRED", "COMPLETED", "FAILED"),
    "REVIEW_REQUIRED": ("COMPLETED", "BLOCKED", "FAILED"),
    "FAILED": ("QUEUED", "BLOCKED"),
    "BLOCKED": ("QUEUED",),
    "EXPIRED": ("QUEUED",),
    "COMPLETED": (),
}


def make_job(**overrides):
    from aec.runtime import jobs

    fields = {
        "job_id": "job-001",
        "case_id": "case-001",
        "candidate_id": "rc-001",
        "source_mode": "OFFLINE_FIXTURE",
    }
    fields.update(overrides)
    return jobs.create_job(**fields)


def hop(job, target, reason="test hop", actor="test", tick=1):
    from aec.runtime import jobs

    return jobs.transition(
        job, target, reason=reason, actor=actor, tick=tick)


class TestJobStates(unittest.TestCase):
    def test_thirteen_states(self):
        from aec.runtime import jobs

        self.assertEqual(len(jobs.STATES), 13)
        self.assertEqual(set(jobs.STATES), set(STATES))

    def test_create_starts_discovered(self):
        self.assertEqual(make_job().state, "DISCOVERED")

    def test_create_requires_ids(self):
        from aec.runtime import jobs

        with self.assertRaises(ValueError):
            jobs.create_job(job_id="", case_id="c", candidate_id="r",
                            source_mode="OFFLINE_FIXTURE")

    def test_create_requires_source_mode(self):
        from aec.runtime import jobs

        with self.assertRaises(ValueError):
            jobs.create_job(job_id="j", case_id="c", candidate_id="r",
                            source_mode="LIVE")

    def test_job_dict_keys(self):
        self.assertEqual(
            sorted(make_job().to_dict()),
            ["actor_history", "attempts", "candidate_id", "case_id",
             "job_id", "max_attempts", "source_mode", "specialist",
             "state", "transitions"],
        )

    def test_jobs_frozen(self):
        import dataclasses

        with self.assertRaises(dataclasses.FrozenInstanceError):
            make_job().state = "QUEUED"

    def test_initial_attempts_zero(self):
        self.assertEqual(make_job().attempts, 0)


class TestLegalTransitions(unittest.TestCase):
    def test_full_table_matches(self):
        from aec.runtime import jobs

        for state, targets in LEGAL.items():
            for target in targets:
                job = make_job()
                object_path = [state]
                # Drive there via shortest legal prefix.
                order = list(jobs.STATES)
                current = make_job()
                path = _path_to(jobs, state)
                for step in path:
                    current = hop(current, step)
                moved = hop(current, target)
                self.assertEqual(moved.state, target, f"{state}->{target}")
                _ = object_path

    def test_happy_path_to_completed(self):
        job = make_job()
        for target in ("QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING",
                       "EVIDENCE_PENDING", "ANALYSIS_PENDING",
                       "REVIEW_REQUIRED", "COMPLETED"):
            job = hop(job, target)
        self.assertEqual(job.state, "COMPLETED")

    def test_transition_record_fields(self):
        job = hop(make_job(), "QUEUED", reason="r", actor="a", tick=7)
        record = job.transitions[0]
        self.assertEqual(
            sorted(record),
            ["actor", "next_state", "previous_state", "reason", "tick"],
        )
        self.assertEqual(record["previous_state"], "DISCOVERED")
        self.assertEqual(record["next_state"], "QUEUED")
        self.assertEqual(record["tick"], 7)

    def test_history_appends_in_order(self):
        job = make_job()
        job = hop(job, "QUEUED", tick=1)
        job = hop(job, "ASSIGNED", tick=2)
        self.assertEqual(len(job.transitions), 2)
        self.assertEqual(job.transitions[1]["previous_state"], "QUEUED")

    def test_failed_retry_returns_to_queued(self):
        job = make_job()
        for target in ("QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING"):
            job = hop(job, target)
        job = hop(job, "FAILED", reason="timeout")
        self.assertEqual(job.attempts, 1)
        job = hop(job, "QUEUED", reason="retry")
        self.assertEqual(job.state, "QUEUED")

    def test_attempts_bounded(self):
        from aec.runtime import jobs

        job = make_job(max_attempts=1)
        for target in ("QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING"):
            job = hop(job, target)
        job = hop(job, "FAILED", reason="timeout")
        with self.assertRaises(jobs.TransitionRefusal):
            hop(job, "QUEUED", reason="retry over budget")

    def test_blocked_recovery_to_queued(self):
        job = hop(make_job(), "BLOCKED", reason="denied")
        job = hop(job, "QUEUED", reason="operator requeue", actor="operator")
        self.assertEqual(job.state, "QUEUED")

    def test_expired_recovery_to_queued(self):
        job = hop(make_job(), "QUEUED")
        job = hop(job, "EXPIRED", reason="authz lapsed")
        job = hop(job, "QUEUED", reason="fresh authz")
        self.assertEqual(job.state, "QUEUED")

    def test_direct_analysis_completion(self):
        job = make_job()
        for target in ("QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING",
                       "EVIDENCE_PENDING", "ANALYSIS_PENDING"):
            job = hop(job, target)
        job = hop(job, "COMPLETED", reason="no signal")
        self.assertEqual(job.state, "COMPLETED")


class TestIllegalTransitions(unittest.TestCase):
    def test_skip_refused(self):
        from aec.runtime import jobs

        with self.assertRaises(jobs.TransitionRefusal):
            hop(make_job(), "ASSIGNED")

    def test_backward_refused(self):
        from aec.runtime import jobs

        job = hop(make_job(), "QUEUED")
        job = hop(job, "ASSIGNED")
        with self.assertRaises(jobs.TransitionRefusal):
            hop(job, "QUEUED")

    def test_self_transition_refused(self):
        from aec.runtime import jobs

        with self.assertRaises(jobs.TransitionRefusal):
            hop(hop(make_job(), "QUEUED"), "QUEUED")

    def test_completed_terminal(self):
        from aec.runtime import jobs

        job = make_job()
        for target in ("QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING",
                       "EVIDENCE_PENDING", "ANALYSIS_PENDING", "COMPLETED"):
            job = hop(job, target)
        with self.assertRaises(jobs.TransitionRefusal):
            hop(job, "QUEUED")

    def test_unknown_target_refused(self):
        from aec.runtime import jobs

        with self.assertRaises(jobs.TransitionRefusal):
            hop(make_job(), "SCANNING")

    def test_empty_reason_refused(self):
        from aec.runtime import jobs

        with self.assertRaises(jobs.TransitionRefusal):
            hop(make_job(), "QUEUED", reason="")

    def test_empty_actor_refused(self):
        from aec.runtime import jobs

        with self.assertRaises(jobs.TransitionRefusal):
            hop(make_job(), "QUEUED", actor="")

    def test_refusal_carries_codes(self):
        from aec.runtime import jobs

        try:
            hop(make_job(), "ASSIGNED")
            self.fail("expected refusal")
        except jobs.TransitionRefusal as refusal:
            self.assertEqual(refusal.code, "INVALID_TRANSITION")
            self.assertEqual(refusal.previous, "DISCOVERED")
            self.assertEqual(refusal.proposed, "ASSIGNED")

    def test_failed_job_keeps_history(self):
        from aec.runtime import jobs

        job = make_job()
        try:
            hop(job, "COMPLETED")
        except jobs.TransitionRefusal:
            pass
        self.assertEqual(job.state, "DISCOVERED")
        self.assertEqual(job.transitions, ())


class TestSafetyGuards(unittest.TestCase):
    def test_no_forbidden_vocabulary_in_source(self):
        for name in ("models.py", "jobs.py"):
            source = (RUNTIME_DIR / name).read_text()
            for word in FORBIDDEN:
                self.assertNotIn(word, source, f"{name}:{word}")

    def test_no_network_or_backend_imports(self):
        for name in ("models.py", "jobs.py"):
            tree = ast.parse((RUNTIME_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)


def _path_to(jobs_module, state):
    prefix = {
        "DISCOVERED": [],
        "QUEUED": ["QUEUED"],
        "ASSIGNED": ["QUEUED", "ASSIGNED"],
        "WAITING_AUTHORIZATION": ["QUEUED", "ASSIGNED",
                                  "WAITING_AUTHORIZATION"],
        "READY_FOR_OBSERVATION": ["QUEUED", "ASSIGNED",
                                  "WAITING_AUTHORIZATION",
                                  "READY_FOR_OBSERVATION"],
        "OBSERVATION_RUNNING": ["QUEUED", "ASSIGNED",
                                "WAITING_AUTHORIZATION",
                                "READY_FOR_OBSERVATION",
                                "OBSERVATION_RUNNING"],
        "EVIDENCE_PENDING": ["QUEUED", "ASSIGNED",
                             "WAITING_AUTHORIZATION",
                             "READY_FOR_OBSERVATION",
                             "OBSERVATION_RUNNING", "EVIDENCE_PENDING"],
        "ANALYSIS_PENDING": ["QUEUED", "ASSIGNED",
                             "WAITING_AUTHORIZATION",
                             "READY_FOR_OBSERVATION",
                             "OBSERVATION_RUNNING", "EVIDENCE_PENDING",
                             "ANALYSIS_PENDING"],
        "REVIEW_REQUIRED": ["QUEUED", "ASSIGNED",
                            "WAITING_AUTHORIZATION",
                            "READY_FOR_OBSERVATION",
                            "OBSERVATION_RUNNING", "EVIDENCE_PENDING",
                            "ANALYSIS_PENDING", "REVIEW_REQUIRED"],
        "COMPLETED": ["QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                      "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING",
                      "EVIDENCE_PENDING", "ANALYSIS_PENDING", "COMPLETED"],
        "BLOCKED": ["BLOCKED"],
        "FAILED": ["QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                   "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING",
                   "FAILED"],
        "EXPIRED": ["QUEUED", "EXPIRED"],
    }
    return prefix[state]


if __name__ == "__main__":
    unittest.main()
