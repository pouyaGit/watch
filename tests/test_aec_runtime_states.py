"""EPIC7 Part 1: ObservationRuntime 11-state machine — fail-closed."""

from __future__ import annotations

import unittest

from aec.runtime.models import TransitionRefusal


def build_state():
    from aec.runtime.execution.states import (
        create_observation_state, STATES)

    return create_observation_state(
        request_id="obsreq-abc123",
        research_job_id="job-123",
        case_id="case-123",
        policy_version="v1",
        authorization_reference="authz-123",
    ), STATES


class TestStatesClosedSet(unittest.TestCase):
    def test_exactly_eleven_states(self):
        _, states = build_state()
        self.assertEqual(len(states), 11)
        self.assertEqual(
            sorted(states),
            ["AUTHORIZED", "BLOCKED", "COLLECTING", "COMPLETED", "DISPATCHED",
             "FAILED", "OBSERVING", "RECEIVED", "REFUSED", "TIMED_OUT",
             "VALIDATING"])


class TestCreateState(unittest.TestCase):
    def test_initial_state_received(self):
        state, _ = build_state()
        self.assertEqual(state.state, "RECEIVED")

    def test_records_request_id(self):
        state, _ = build_state()
        self.assertEqual(state.request_id, "obsreq-abc123")

    def test_records_job_and_case(self):
        state, _ = build_state()
        self.assertEqual(state.research_job_id, "job-123")
        self.assertEqual(state.case_id, "case-123")

    def test_records_policy_version(self):
        state, _ = build_state()
        self.assertEqual(state.policy_version, "v1")

    def test_records_authorization_reference(self):
        state, _ = build_state()
        self.assertEqual(state.authorization_reference, "authz-123")

    def test_empty_request_id_refused(self):
        from aec.runtime.execution.states import create_observation_state

        with self.assertRaises(ValueError):
            create_observation_state(
                request_id="", research_job_id="job", case_id="case",
                policy_version="v1", authorization_reference="authz")

    def test_empty_policy_version_refused(self):
        from aec.runtime.execution.states import create_observation_state

        with self.assertRaises(ValueError):
            create_observation_state(
                request_id="req", research_job_id="job", case_id="case",
                policy_version="", authorization_reference="authz")


class TestTransitionRecords(unittest.TestCase):
    def test_transition_records_all_fields(self):
        state, _ = build_state()
        moved = state.transition("VALIDATING", "validation started", "gate",
                                 1)
        record = moved.transitions[-1]
        self.assertEqual(record["request_id"], "obsreq-abc123")
        self.assertEqual(record["research_job_id"], "job-123")
        self.assertEqual(record["case_id"], "case-123")
        self.assertEqual(record["previous_state"], "RECEIVED")
        self.assertEqual(record["next_state"], "VALIDATING")
        self.assertEqual(record["reason"], "validation started")
        self.assertEqual(record["timestamp"], 1)
        self.assertEqual(record["policy_version"], "v1")
        self.assertEqual(record["authorization_reference"], "authz-123")

    def test_actor_recorded(self):
        state, _ = build_state()
        moved = state.transition("VALIDATING", "started", "validator", 1)
        self.assertEqual(moved.actor_history[-1], "validator")

    def test_chain_appends(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "started", "validator", 1)
                 .transition("AUTHORIZED", "valid", "validator", 2))
        self.assertEqual(len(moved.transitions), 2)


class TestTransitionTable(unittest.TestCase):
    def test_invalid_transition_fails_closed(self):
        state, _ = build_state()
        with self.assertRaises(TransitionRefusal):
            state.transition("COMPLETED", "never", "actor", 1)

    def test_valid_path_received_to_validating(self):
        state, _ = build_state()
        moved = state.transition("VALIDATING", "started", "validator", 1)
        self.assertEqual(moved.state, "VALIDATING")

    def test_validating_to_authorized(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "started", "validator", 1)
                 .transition("AUTHORIZED", "valid", "validator", 2))
        self.assertEqual(moved.state, "AUTHORIZED")

    def test_authorized_to_dispatched(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3))
        self.assertEqual(moved.state, "DISPATCHED")

    def test_dispatched_to_observing(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3)
                 .transition("OBSERVING", "o", "adapter", 4))
        self.assertEqual(moved.state, "OBSERVING")

    def test_observing_to_collecting(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3)
                 .transition("OBSERVING", "o", "adapter", 4)
                 .transition("COLLECTING", "c", "adapter", 5))
        self.assertEqual(moved.state, "COLLECTING")

    def test_collecting_to_completed(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3)
                 .transition("OBSERVING", "o", "adapter", 4)
                 .transition("COLLECTING", "c", "adapter", 5)
                 .transition("COMPLETED", "done", "adapter", 6))
        self.assertEqual(moved.state, "COMPLETED")

    def test_validating_to_refused(self):
        state, _ = build_state()
        moved = state.transition("VALIDATING", "bad", "validator", 1) \
                     .transition("REFUSED", "out of scope", "validator", 2)
        self.assertEqual(moved.state, "REFUSED")

    def test_validating_to_blocked(self):
        state, _ = build_state()
        moved = state.transition("VALIDATING", "bad", "validator", 1) \
                     .transition("BLOCKED", "authz expired", "validator", 2)
        self.assertEqual(moved.state, "BLOCKED")

    def test_observing_to_timed_out(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3)
                 .transition("OBSERVING", "o", "adapter", 4)
                 .transition("TIMED_OUT", "timeout", "adapter", 5))
        self.assertEqual(moved.state, "TIMED_OUT")

    def test_observing_to_failed(self):
        state, _ = build_state()
        moved = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3)
                 .transition("OBSERVING", "o", "adapter", 4)
                 .transition("FAILED", "dns", "adapter", 5))
        self.assertEqual(moved.state, "FAILED")


class TestTerminalStates(unittest.TestCase):
    def test_completed_is_terminal(self):
        state, _ = build_state()
        completed = (state
                     .transition("VALIDATING", "s", "validator", 1)
                     .transition("AUTHORIZED", "v", "validator", 2)
                     .transition("DISPATCHED", "d", "adapter", 3)
                     .transition("OBSERVING", "o", "adapter", 4)
                     .transition("COLLECTING", "c", "adapter", 5)
                     .transition("COMPLETED", "done", "adapter", 6))
        with self.assertRaises(TransitionRefusal):
            completed.transition("FAILED", "after", "adapter", 7)

    def test_refused_is_terminal(self):
        state, _ = build_state()
        refused = (state
                   .transition("VALIDATING", "s", "validator", 1)
                   .transition("REFUSED", "scope", "validator", 2))
        with self.assertRaises(TransitionRefusal):
            refused.transition("COMPLETED", "escape", "validator", 3)


class TestEmptyReason(unittest.TestCase):
    def test_empty_reason_refused(self):
        state, _ = build_state()
        with self.assertRaises(TransitionRefusal):
            state.transition("VALIDATING", "   ", "validator", 1)

    def test_empty_actor_refused(self):
        state, _ = build_state()
        with self.assertRaises(TransitionRefusal):
            state.transition("VALIDATING", "started", "", 1)

    def test_bad_tick_refused(self):
        state, _ = build_state()
        with self.assertRaises(TransitionRefusal):
            state.transition("VALIDATING", "started", "validator", -1)


class TestStateDict(unittest.TestCase):
    def test_to_dict_snapshot(self):
        state, _ = build_state()
        data = state.to_dict()
        self.assertEqual(data["state"], "RECEIVED")
        self.assertEqual(data["request_id"], "obsreq-abc123")
        self.assertEqual(data["transition_count"], 0)

    def test_to_dict_after_transition(self):
        state, _ = build_state()
        moved = state.transition("VALIDATING", "started", "validator", 1)
        data = moved.to_dict()
        self.assertEqual(data["transition_count"], 1)
        self.assertEqual(data["state"], "VALIDATING")


class TestRetryPath(unittest.TestCase):
    def test_timed_out_retry_explicit_only(self):
        state, _ = build_state()
        timed = (state
                 .transition("VALIDATING", "s", "validator", 1)
                 .transition("AUTHORIZED", "v", "validator", 2)
                 .transition("DISPATCHED", "d", "adapter", 3)
                 .transition("OBSERVING", "o", "adapter", 4)
                 .transition("TIMED_OUT", "timeout", "adapter", 5))
        retried = timed.transition("RECEIVED", "retry classified safe",
                                   "runtime", 6)
        self.assertEqual(retried.state, "RECEIVED")

    def test_failed_retry_explicit_only(self):
        state, _ = build_state()
        failed = (state
                  .transition("VALIDATING", "s", "validator", 1)
                  .transition("AUTHORIZED", "v", "validator", 2)
                  .transition("DISPATCHED", "d", "adapter", 3)
                  .transition("OBSERVING", "o", "adapter", 4)
                  .transition("FAILED", "dns", "adapter", 5))
        retried = failed.transition("RECEIVED", "retry classified safe",
                                    "runtime", 6)
        self.assertEqual(retried.state, "RECEIVED")

    def test_blocked_never_retry(self):
        state, _ = build_state()
        blocked = state.transition(
            "VALIDATING", "s", "validator", 1) \
                       .transition("BLOCKED", "authz", "validator", 2)
        with self.assertRaises(TransitionRefusal):
            blocked.transition("RECEIVED", "retry", "runtime", 3)

    def test_refused_never_retry(self):
        state, _ = build_state()
        refused = state.transition(
            "VALIDATING", "s", "validator", 1) \
                       .transition("REFUSED", "scope", "validator", 2)
        with self.assertRaises(TransitionRefusal):
            refused.transition("RECEIVED", "retry", "runtime", 3)


if __name__ == "__main__":
    unittest.main()