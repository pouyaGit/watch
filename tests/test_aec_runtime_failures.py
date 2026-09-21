"""EPIC7 Part 13: failure classification — explicit states, no silence."""

from __future__ import annotations

import unittest


class TestFailureKindsMapped(unittest.TestCase):
    def test_dns_failure_failed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("DNS_FAILURE"), "FAILED")

    def test_connection_timeout_timed_out(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("CONNECTION_TIMEOUT"), "TIMED_OUT")

    def test_tls_failure_failed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("TLS_FAILURE"), "FAILED")

    def test_http_timeout_timed_out(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("HTTP_TIMEOUT"), "TIMED_OUT")

    def test_response_too_large_blocked(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("RESPONSE_TOO_LARGE"), "BLOCKED")

    def test_redirect_out_of_scope_refused(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("REDIRECT_OUT_OF_SCOPE"),
                         "REFUSED")

    def test_authorization_expiry_blocked(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("AUTHORIZATION_EXPIRY"),
                         "BLOCKED")

    def test_scope_mismatch_refused(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("SCOPE_MISMATCH"), "REFUSED")

    def test_policy_mismatch_refused(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("POLICY_MISMATCH"), "REFUSED")

    def test_duplicate_request_blocked(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("DUPLICATE_REQUEST"), "BLOCKED")

    def test_runtime_shutdown_failed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("RUNTIME_SHUTDOWN"), "FAILED")

    def test_partial_evidence_failed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("PARTIAL_EVIDENCE"), "FAILED")

    def test_redaction_failure_failed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("REDACTION_FAILURE"), "FAILED")

    def test_invalid_transition_failed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("INVALID_TRANSITION"), "FAILED")


class TestFailureClassificationClosed(unittest.TestCase):
    def test_exactly_fourteen_kinds(self):
        from aec.runtime.execution.failures import (
            FAILURE_KIND_TO_STATE)

        self.assertEqual(len(FAILURE_KIND_TO_STATE), 14)

    def test_unknown_kind_fails_closed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("SOMETHING_ELSE"), "FAILED")

    def test_empty_kind_fails_closed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state(""), "FAILED")

    def test_none_kind_fails_closed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state(None), "FAILED")

    def test_all_failure_states_terminal(self):
        from aec.runtime.execution.failures import (
            FAILURE_KIND_TO_STATE, FAILURE_STATES)

        self.assertLessEqual(
            set(FAILURE_KIND_TO_STATE.values()), FAILURE_STATES)

    def test_no_silent_pass_state(self):
        from aec.runtime.execution.failures import (
            FAILURE_KIND_TO_STATE)

        for kind, state in FAILURE_KIND_TO_STATE.items():
            self.assertNotEqual(state, "COMPLETED", kind)
            self.assertNotEqual(state, "AUTHORIZED", kind)

    def test_retryable_kinds_positional(self):
        from aec.runtime.execution.failures import (
            FAILURE_KIND_TO_STATE)

        retryable = {"CONNECTION_TIMEOUT", "HTTP_TIMEOUT",
                     "DNS_FAILURE", "TLS_FAILURE", "PARTIAL_EVIDENCE"}
        for kind in retryable:
            self.assertIn(kind, FAILURE_KIND_TO_STATE)

    def test_failure_states_match_lifecycle(self):
        from aec.runtime.execution.failures import FAILURE_STATES
        from aec.runtime.execution.states import STATES

        self.assertLessEqual(FAILURE_STATES, set(STATES))

    def test_failure_kinds_are_upper_snake(self):
        from aec.runtime.execution.failures import (
            FAILURE_KIND_TO_STATE)

        for kind in FAILURE_KIND_TO_STATE:
            self.assertRegex(kind, r"^[A-Z][A-Z0-9_]*$")


if __name__ == "__main__":
    unittest.main()