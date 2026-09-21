"""EPIC7 Part 2: request validation — the 12 explicit checks, fail-closed."""

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


def valid_authorization(**overrides):
    authz = {
        "status": "GRANTED",
        "expires_tick": 100,
        "authorization_reference": "authz-123",
        "target_id": "tgt-000000000001",
        "case_id": "case-123",
    }
    authz.update(overrides)
    return authz


def valid_policy(**overrides):
    from aec.runtime.policy.models import default_policy

    return overrides.pop("policy", default_policy())


class TestAuthorizationChecks(unittest.TestCase):
    def test_authorization_missing(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), None, valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_MISSING", result.reasons)

    def test_authorization_not_mapping(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), "junk", valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_MISSING", result.reasons)

    def test_authorization_denied(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), {"status": "DENIED"}, valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_DENIED", result.reasons)

    def test_authorization_expired_status(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(),
            valid_authorization(status="EXPIRED"), valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_EXPIRED", result.reasons)

    def test_authorization_expired_by_tick(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(expires_tick=5),
            valid_policy(), tick=6)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_EXPIRED", result.reasons)

    def test_authorization_missing_reference(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(authorization_reference=""),
            valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_REFERENCE_MISSING", result.reasons)

    def test_authorization_unknown_status(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(status="PENDING"),
            valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("AUTHORIZATION_UNKNOWN_STATUS", result.reasons)

    def test_expired_authz_never_enters_observation(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(expires_tick=0),
            valid_policy(), tick=0)
        self.assertNotEqual(result.decision, "AUTHORIZED")


class TestIdentityChecks(unittest.TestCase):
    def test_request_reference_matches_authz(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(),
            valid_authorization(authorization_reference="other-authz"),
            valid_policy(), tick=5)
        self.assertIn("AUTHORIZATION_REFERENCE_MISMATCH", result.reasons)

    def test_case_identity_matches(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(case_id="case-other"),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("CASE_IDENTITY_MISMATCH", result.reasons)

    def test_target_identity_matches_authz(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(target_id="tgt-999999999999"),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("TARGET_IDENTITY_MISMATCH", result.reasons)

    def test_target_missing_from_authz(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(),
            valid_authorization(target_id=""), valid_policy(), tick=5)
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("TARGET_IDENTITY_MISSING", result.reasons)


class TestPolicyChecks(unittest.TestCase):
    def test_observation_type_not_permitted(self):
        from aec.runtime.execution.validation import validate_request
        from aec.runtime.policy.models import ObservationPolicy

        narrow = ObservationPolicy(
            observation_types=("HTTP_STATUS",))
        result = validate_request(
            valid_request(observation_type="HTTP_HEADERS"),
            valid_authorization(), narrow, tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("TYPE_NOT_PERMITTED", result.reasons)

    def test_unknown_observation_type(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(observation_type="SCAN_ALL"),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("TYPE_UNKNOWN", result.reasons)

    def test_method_not_permitted(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(method="POST"),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("METHOD_NOT_PERMITTED", result.reasons)

    def test_empty_method_refused(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(method=""),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("METHOD_NOT_PERMITTED", result.reasons)

    def test_evidence_level_incompatible(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(required_evidence_level="READY"),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("EVIDENCE_LEVEL_INCOMPATIBLE", result.reasons)

    def test_evidence_level_missing(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(required_evidence_level=""),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("EVIDENCE_LEVEL_MISSING", result.reasons)

    def test_policy_version_unsupported(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(policy_version="v99"),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("POLICY_VERSION_UNSUPPORTED", result.reasons)

    def test_policy_version_missing(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(policy_version=""),
            valid_authorization(), valid_policy(), tick=5)
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("POLICY_VERSION_UNSUPPORTED", result.reasons)


class TestExecutedCheck(unittest.TestCase):
    def test_request_already_executed(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(),
            tick=5, executed_request_ids={"obsreq-abc123"})
        self.assertEqual(result.decision, "BLOCKED")
        self.assertIn("REQUEST_ALREADY_EXECUTED", result.reasons)

    def test_unexecuted_request_passes(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(),
            tick=5, executed_request_ids={"obsreq-other"})
        self.assertEqual(result.decision, "AUTHORIZED")


class TestTargetScopeChecks(unittest.TestCase):
    def test_target_not_in_scope(self):
        from aec.runtime.execution.validation import validate_request

        target = {"host": "evil.example.com", "scheme": "https",
                  "port": None, "target_id": "tgt-000000000001"}
        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(),
            tick=5, target=target,
            scope_hosts=frozenset({"good.example.com"}))
        self.assertEqual(result.decision, "REFUSED")
        self.assertIn("TARGET_HOST_OUT_OF_SCOPE", result.reasons)

    def test_target_in_scope(self):
        from aec.runtime.execution.validation import validate_request

        target = {"host": "good.example.com", "scheme": "https",
                  "port": None, "target_id": "tgt-000000000001"}
        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(),
            tick=5, target=target,
            scope_hosts=frozenset({"good.example.com"}))
        self.assertEqual(result.decision, "AUTHORIZED")

    def test_userinfo_host_refused(self):
        from aec.runtime.execution.validation import validate_request

        target = {"host": "user:pass@good.example.com", "scheme": "https",
                  "port": None, "target_id": "tgt-000000000001"}
        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(),
            tick=5, target=target,
            scope_hosts=frozenset({"good.example.com"}))
        self.assertIn("TARGET_USERINFO", result.reasons)

    def test_localhost_refused_unless_authorized(self):
        from aec.runtime.execution.validation import validate_request

        target = {"host": "localhost", "scheme": "https", "port": None,
                  "target_id": "tgt-000000000001"}
        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(),
            tick=5, target=target, scope_hosts=frozenset({"localhost"}))
        self.assertNotEqual(result.decision, "AUTHORIZED")


class TestValidationResult(unittest.TestCase):
    def test_authorized_decision(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(), tick=1,
            scope_hosts=frozenset())
        self.assertEqual(result.decision, "AUTHORIZED")
        self.assertEqual(result.reasons, ())

    def test_reasons_are_tuple(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(method="POST"), valid_authorization(),
            valid_policy(), tick=5)
        self.assertIsInstance(result.reasons, tuple)

    def test_policy_version_recorded(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(), tick=1)
        self.assertEqual(result.policy_version, "v1")

    def test_authorization_reference_recorded(self):
        from aec.runtime.execution.validation import validate_request

        result = validate_request(
            valid_request(), valid_authorization(), valid_policy(), tick=1)
        self.assertEqual(result.authorization_reference, "authz-123")


if __name__ == "__main__":
    unittest.main()