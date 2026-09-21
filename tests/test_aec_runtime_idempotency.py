"""EPIC7 Part 12: idempotency, retry classification, duplicate suppression."""

from __future__ import annotations

import unittest


def valid_request(**overrides):
    request = {
        "request_id": "obsreq-abc123",
        "research_job_id": "job-123",
        "case_id": "case-123",
        "target_id": "tgt-000000000001",
        "observation_type": "HTTP_METADATA",
        "method": "GET",
        "required_evidence_level": "PARTIAL",
        "authorization_reference": "authz-123",
        "policy_version": "v1",
    }
    request.update(overrides)
    return request


class TestExecutionKey(unittest.TestCase):
    def test_key_deterministic(self):
        from aec.runtime.execution.idempotency import execution_key

        first = execution_key(valid_request())
        second = execution_key(valid_request())
        self.assertEqual(first, second)

    def test_key_changes_with_request_id(self):
        from aec.runtime.execution.idempotency import execution_key

        first = execution_key(valid_request())
        second = execution_key(valid_request(request_id="obsreq-other"))
        self.assertNotEqual(first, second)

    def test_key_changes_with_target(self):
        from aec.runtime.execution.idempotency import execution_key

        first = execution_key(valid_request())
        second = execution_key(valid_request(target_id="tgt-other"))
        self.assertNotEqual(first, second)

    def test_key_changes_with_type(self):
        from aec.runtime.execution.idempotency import execution_key

        first = execution_key(valid_request())
        second = execution_key(
            valid_request(observation_type="HTTP_HEADERS"))
        self.assertNotEqual(first, second)


class TestIdempotencyGuard(unittest.TestCase):
    def test_first_execution_allowed(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        self.assertFalse(guard.is_duplicate(valid_request()))

    def test_second_execution_blocked(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        guard.record(valid_request())
        self.assertTrue(guard.is_duplicate(valid_request()))

    def test_record_returns_key(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        key = guard.record(valid_request())
        self.assertTrue(key.startswith("exec-"))

    def test_different_request_passes(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        guard.record(valid_request())
        self.assertFalse(
            guard.is_duplicate(valid_request(request_id="obsreq-other")))

    def test_guard_snapshot(self):
        from aec.runtime.execution.idempotency import IdempotencyGuard

        guard = IdempotencyGuard()
        guard.record(valid_request())
        self.assertEqual(guard.snapshot()["count"], 1)


class TestRetryClassification(unittest.TestCase):
    def test_timeout_retryable(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("TIMEOUT"), "RETRYABLE")

    def test_connection_timeout_retryable(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("CONNECTION_TIMEOUT"), "RETRYABLE")

    def test_dns_failure_retryable(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("DNS_FAILURE"), "RETRYABLE")

    def test_scope_mismatch_terminal(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("SCOPE_MISMATCH"), "TERMINAL")

    def test_authz_denied_terminal(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("AUTHORIZATION_DENIED"), "TERMINAL")

    def test_unknown_kind_terminal(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("MYSTERY"), "TERMINAL")

    def test_retryable_kinds_closed(self):
        from aec.runtime.execution.idempotency import (
            RETRYABLE_KINDS, classify_retry)

        for kind in RETRYABLE_KINDS:
            self.assertEqual(classify_retry(kind), "RETRYABLE")

    def test_redaction_failure_terminal(self):
        from aec.runtime.execution.idempotency import classify_retry

        self.assertEqual(classify_retry("REDACTION_FAILURE"), "TERMINAL")


class TestNoAutoRetry(unittest.TestCase):
    def test_retry_never_automatic(self):
        from aec.runtime.execution.idempotency import (
            IdempotencyGuard, retry_allowed)

        guard = IdempotencyGuard()
        # A retry is an explicit, classified act — never implicit.
        self.assertTrue(retry_allowed(guard, "TIMEOUT", 1, 2))
        self.assertFalse(retry_allowed(guard, "REDACTION_FAILURE", 1, 2))
        self.assertFalse(retry_allowed(guard, "TIMEOUT", 2, 2))

    def test_retry_budget_used(self):
        from aec.runtime.execution.idempotency import (
            IdempotencyGuard, retry_allowed)

        guard = IdempotencyGuard()
        self.assertTrue(retry_allowed(guard, "TIMEOUT", 0, 2))
        self.assertTrue(retry_allowed(guard, "TIMEOUT", 1, 2))
        self.assertFalse(retry_allowed(guard, "TIMEOUT", 2, 2))


if __name__ == "__main__":
    unittest.main()