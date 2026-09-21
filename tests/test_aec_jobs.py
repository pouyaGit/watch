"""EPIC6 Part 2: ResearchJob lifecycle — 13 states, fail-closed transitions."""

from __future__ import annotations

import unittest
from dataclasses import replace

from aec.runtime.models import ResearchJob, TransitionRefusal
from aec.runtime.jobs import (
    STATES, TRANSITIONS, allowed_targets, create_job, transition)


def job(**overrides):
    fields = {
        "job_id": "job-1",
        "case_id": "case-1",
        "candidate_id": "rc-1",
        "source_mode": "OFFLINE_FIXTURE",
    }
    fields.update(overrides)
    state = fields.pop("state", None)
    created = create_job(**fields)
    if state is not None:
        created = replace(created, state=state)
    return created


class TestStates(unittest.TestCase):
    def test_thirteen_states_exact(self):
        self.assertEqual(STATES, (
            "DISCOVERED", "QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
            "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING", "EVIDENCE_PENDING",
            "ANALYSIS_PENDING", "REVIEW_REQUIRED", "COMPLETED", "BLOCKED",
            "FAILED", "EXPIRED",
        ))

    def test_initial_state_discovered(self):
        self.assertEqual(job().state, "DISCOVERED")

    def test_source_modes_validated(self):
        for mode in ("REAL_WATCH_DATA", "OFFLINE_FIXTURE"):
            self.assertEqual(create_job(
                "job-1", "case-1", "rc-1", mode).source_mode, mode)
        with self.assertRaises(ValueError):
            create_job("job-1", "case-1", "rc-1", "LIVE_DATA")

    def test_blank_ids_refused(self):
        with self.assertRaises(ValueError):
            create_job("", "case-1", "rc-1", "OFFLINE_FIXTURE")
        with self.assertRaises(ValueError):
            create_job("job-1", "", "rc-1", "OFFLINE_FIXTURE")
        with self.assertRaises(ValueError):
            create_job("job-1", "case-1", "", "OFFLINE_FIXTURE")

    def test_max_attempts_positive(self):
        with self.assertRaises(ValueError):
            create_job("j", "c", "r", "OFFLINE_FIXTURE", max_attempts=0)


class TestAllowedTargets(unittest.TestCase):
    def test_every_state_has_table_entry(self):
        for state in STATES:
            self.assertIn(state, TRANSITIONS)

    def test_completed_is_terminal(self):
        self.assertEqual(allowed_targets("COMPLETED"), ())

    def test_unknown_state_empty(self):
        self.assertEqual(allowed_targets("NOPE"), ())

    def test_failed_requeues(self):
        self.assertIn("QUEUED", allowed_targets("FAILED"))
        self.assertIn("BLOCKED", allowed_targets("FAILED"))

    def test_blocked_current_requeues(self):
        self.assertEqual(allowed_targets("BLOCKED"), ("QUEUED",))

    def test_expired_current_requeues(self):
        self.assertEqual(allowed_targets("EXPIRED"), ("QUEUED",))


class TestValidTransitions(unittest.TestCase):
    def test_happy_path_to_completed(self):
        current = job()
        path = [
            ("QUEUED", "queued"),
            ("ASSIGNED", "staffed"),
            ("WAITING_AUTHORIZATION", "authz missing"),
            ("READY_FOR_OBSERVATION", "granted"),
            ("OBSERVATION_RUNNING", "submitted"),
            ("EVIDENCE_PENDING", "result accepted"),
            ("ANALYSIS_PENDING", "analyzing"),
            ("REVIEW_REQUIRED", "threshold reached"),
            ("COMPLETED", "reviewed"),
        ]
        for target, reason in path:
            current = transition(current, target, reason, "pipeline", 1)
        self.assertEqual(current.state, "COMPLETED")
        self.assertEqual(current.attempts, 0)
        self.assertTrue(current.transitions)

    def test_blocked_then_requeued(self):
        current = transition(job(), "BLOCKED", "no authz", "gate", 1)
        self.assertEqual(current.state, "BLOCKED")
        current = transition(current, "QUEUED", "retry", "pipeline", 2)
        self.assertEqual(current.state, "QUEUED")

    def test_failed_records_attempt(self):
        current = job()
        for target, reason in (("QUEUED", "q"), ("ASSIGNED", "a"),
                               ("WAITING_AUTHORIZATION", "w"),
                               ("READY_FOR_OBSERVATION", "r"),
                               ("OBSERVATION_RUNNING", "o")):
            current = transition(current, target, reason, "pipeline", 1)
        current = transition(current, "FAILED", "timeout", "observer", 2)
        self.assertEqual(current.attempts, 1)
        self.assertEqual(current.state, "FAILED")

    def test_failed_then_requeued_once(self):
        current = job()
        for target in ("QUEUED", "ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING"):
            current = transition(current, target, "advance", "pipeline", 1)
        current = transition(current, "FAILED", "timeout", "observer", 2)
        current = transition(current, "QUEUED", "retry", "pipeline", 3)
        self.assertEqual(current.state, "QUEUED")
        self.assertEqual(current.attempts, 1)

    def test_expired_then_requeued(self):
        current = transition(job(), "QUEUED", "enqueued", "pipeline", 1)
        current = transition(current, "EXPIRED", "authz expired", "gate", 2)
        current = transition(current, "QUEUED", "re-authorize", "pipeline", 3)
        self.assertEqual(current.state, "QUEUED")

    def test_transition_record_shape(self):
        current = transition(job(), "QUEUED", "enqueued", "pipeline", 7)
        record = current.transitions[-1]
        self.assertEqual(record["previous_state"], "DISCOVERED")
        self.assertEqual(record["next_state"], "QUEUED")
        self.assertEqual(record["reason"], "enqueued")
        self.assertEqual(record["actor"], "pipeline")
        self.assertEqual(record["tick"], 7)

    def test_audit_history_appends(self):
        current = transition(job(), "QUEUED", "q", "pipeline", 1)
        current = transition(current, "ASSIGNED", "a", "pipeline", 2)
        self.assertEqual(len(current.transitions), 2)
        self.assertEqual(
            [item["next_state"] for item in current.transitions],
            ["QUEUED", "ASSIGNED"])

    def test_actor_history_dedupes_consecutive(self):
        current = transition(job(), "QUEUED", "q", "pipeline", 1)
        current = transition(current, "ASSIGNED", "a", "pipeline", 2)
        self.assertEqual(current.actor_history, ("pipeline",))

    def test_actor_history_records_distinct(self):
        current = transition(job(), "QUEUED", "q", "pipeline", 1)
        current = transition(current, "ASSIGNED", "a", "operator", 2)
        self.assertEqual(current.actor_history, ("pipeline", "operator"))


class TestFailClosed(unittest.TestCase):
    def assert_refusal(self, code, current, target, tick=1,
                       reason="reason", actor="actor"):
        with self.assertRaises(TransitionRefusal) as ctx:
            transition(job(state=current), target, reason, actor, tick)
        self.assertEqual(ctx.exception.code, code)

    def test_unknown_target_refused(self):
        self.assert_refusal("INVALID_TRANSITION", "DISCOVERED", "COMPLETED")

    def test_state_skip_refused(self):
        self.assert_refusal("INVALID_TRANSITION", "DISCOVERED", "ASSIGNED")

    def test_self_transition_refused(self):
        self.assert_refusal("INVALID_TRANSITION", "QUEUED", "QUEUED")

    def test_backward_transition_refused(self):
        self.assert_refusal("INVALID_TRANSITION", "ASSIGNED", "DISCOVERED")

    def test_completed_is_immutable(self):
        done = transition(job(), "QUEUED", "q", "pipeline", 1)
        for target in ("BLOCKED", "FAILED", "EXPIRED", "QUEUED"):
            self.assert_refusal("INVALID_TRANSITION", "COMPLETED", target)

    def test_empty_reason_refused(self):
        self.assert_refusal("EMPTY_REASON", "DISCOVERED", "QUEUED",
                            reason="")

    def test_blank_reason_refused(self):
        self.assert_refusal("EMPTY_REASON", "DISCOVERED", "QUEUED",
                            reason="   ")

    def test_empty_actor_refused(self):
        self.assert_refusal("EMPTY_ACTOR", "DISCOVERED", "QUEUED",
                            actor="")

    def test_bad_tick_refused(self):
        self.assert_refusal("BAD_TICK", "DISCOVERED", "QUEUED",
                            tick="one")

    def test_negative_tick_refused(self):
        self.assert_refusal("BAD_TICK", "DISCOVERED", "QUEUED",
                            tick=-1)

    def test_failures_bounded_by_max_attempts(self):
        current = transition(job(max_attempts=2), "QUEUED", "enqueued",
                             "pipeline", 1)
        # fail #1 -> requeue allowed (attempts 1 < max 2)
        for target in ("ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING"):
            current = transition(current, target, "advance", "pipeline", 1)
        current = transition(current, "FAILED", "timeout", "observer", 2)
        current = transition(current, "QUEUED", "retry", "pipeline", 3)
        self.assertEqual(current.state, "QUEUED")
        self.assertEqual(current.attempts, 1)
        # fail #2 -> requeue refused (attempts 2 >= max 2)
        for target in ("ASSIGNED", "WAITING_AUTHORIZATION",
                       "READY_FOR_OBSERVATION", "OBSERVATION_RUNNING"):
            current = transition(current, target, "advance", "pipeline", 1)
        current = transition(current, "FAILED", "timeout", "observer", 2)
        self.assertEqual(current.attempts, 2)
        with self.assertRaises(TransitionRefusal) as ctx:
            transition(current, "QUEUED", "retry", "pipeline", 3)
        self.assertEqual(ctx.exception.code, "RETRY_BUDGET_EXHAUSTED")

    def test_blocked_requeue_not_budget_limited(self):
        current = job(max_attempts=1)
        for _ in range(5):
            current = transition(current, "BLOCKED", "no authz", "gate", 1)
            current = transition(current, "QUEUED", "recheck", "pipeline", 2)
        self.assertEqual(current.state, "QUEUED")

    def test_refusal_error_message_carries_codes(self):
        with self.assertRaises(TransitionRefusal) as ctx:
            transition(job(), "COMPLETED", "r", "a", 1)
        message = str(ctx.exception)
        self.assertIn("INVALID_TRANSITION", message)
        self.assertIn("DISCOVERED", message)
        self.assertIn("COMPLETED", message)


class TestSerialization(unittest.TestCase):
    def test_to_dict_exact_keys(self):
        current = transition(job(), "QUEUED", "q", "pipeline", 1)
        document = current.to_dict()
        self.assertEqual(sorted(document), [
            "actor_history", "attempts", "candidate_id", "case_id", "job_id",
            "max_attempts", "source_mode", "specialist", "state",
            "transitions"])

    def test_to_dict_json_stable(self):
        import json

        def snapshot():
            current = transition(job(), "QUEUED", "q", "pipeline", 1)
            return json.dumps(current.to_dict(), sort_keys=True)

        # fresh job, same path -> identical document
        self.assertEqual(snapshot(), snapshot())

    def test_specialist_field_preserved(self):
        current = job(specialist="input-researcher")
        document = current.to_dict()
        self.assertEqual(document["specialist"], "input-researcher")

    def test_frozen_job_rejects_mutation(self):
        current = job()
        with self.assertRaises(Exception):
            current.state = "QUEUED"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()