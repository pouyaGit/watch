"""EPIC7 Part 2+7: runtime policy — observation types, methods, limits."""

from __future__ import annotations

import unittest


class TestObservationTypes(unittest.TestCase):
    def test_allowlist_exact(self):
        from aec.runtime.policy.models import OBSERVATION_TYPES

        self.assertEqual(
            sorted(OBSERVATION_TYPES),
            ["HTTP_BODY_METADATA", "HTTP_HEADERS", "HTTP_METADATA",
             "HTTP_STATUS"])

    def test_unknown_type_refused(self):
        from aec.runtime.policy.models import is_observation_type

        self.assertFalse(is_observation_type("HTTP_POST"))

    def test_known_type_accepted(self):
        from aec.runtime.policy.models import is_observation_type

        self.assertTrue(is_observation_type("HTTP_METADATA"))

    def test_case_sensitive(self):
        from aec.runtime.policy.models import is_observation_type

        self.assertFalse(is_observation_type("http_metadata"))

    def test_policy_rejects_unlisted_type(self):
        from aec.runtime.policy.models import (
            ObservationPolicy, policy_refuses_type)

        policy = ObservationPolicy(observation_types=("HTTP_METADATA",))
        self.assertFalse(policy_refuses_type(policy, "HTTP_METADATA"))
        self.assertTrue(policy_refuses_type(policy, "HTTP_STATUS"))


class TestTypeEvidenceLevels(unittest.TestCase):
    def test_each_type_has_level(self):
        from aec.runtime.policy.models import TYPE_EVIDENCE_LEVELS

        for kind in ("HTTP_METADATA", "HTTP_HEADERS", "HTTP_STATUS",
                     "HTTP_BODY_METADATA"):
            self.assertIn(kind, TYPE_EVIDENCE_LEVELS)

    def test_metadata_never_ready(self):
        from aec.runtime.policy.models import TYPE_EVIDENCE_LEVELS

        for level in TYPE_EVIDENCE_LEVELS.values():
            self.assertNotIn(level, ("READY",))

    def test_required_level_compatible(self):
        from aec.runtime.policy.models import evidence_level_compatible

        self.assertTrue(
            evidence_level_compatible("NONE", "HTTP_METADATA"))
        self.assertTrue(
            evidence_level_compatible("PARTIAL", "HTTP_METADATA"))
        self.assertFalse(
            evidence_level_compatible("READY", "HTTP_METADATA"))

    def test_unknown_required_level_incompatible(self):
        from aec.runtime.policy.models import evidence_level_compatible

        self.assertFalse(
            evidence_level_compatible("DEFINITIVE", "HTTP_METADATA"))


class TestMethods(unittest.TestCase):
    def test_get_only_permitted(self):
        from aec.runtime.policy.models import PERMITTED_METHODS

        self.assertEqual(PERMITTED_METHODS, ("GET",))

    def test_post_refused(self):
        from aec.runtime.policy.models import method_permitted

        self.assertFalse(method_permitted("POST"))

    def test_get_permitted(self):
        from aec.runtime.policy.models import method_permitted

        self.assertTrue(method_permitted("GET"))

    def test_delete_refused(self):
        from aec.runtime.policy.models import method_permitted

        self.assertFalse(method_permitted("DELETE"))


class TestPolicyModel(unittest.TestCase):
    def test_default_policy_version_supported(self):
        from aec.runtime.policy.models import (
            SUPPORTED_POLICY_VERSIONS, default_policy)

        self.assertIn(default_policy().policy_version,
                      SUPPORTED_POLICY_VERSIONS)

    def test_unsupported_version_refused(self):
        from aec.runtime.policy.models import policy_version_supported

        self.assertFalse(policy_version_supported("v99"))

    def test_supported_version_accepted(self):
        from aec.runtime.policy.models import policy_version_supported

        self.assertTrue(policy_version_supported("v1"))

    def test_policy_default_contains_all_types(self):
        from aec.runtime.policy.models import default_policy

        self.assertEqual(
            sorted(default_policy().observation_types),
            ["HTTP_BODY_METADATA", "HTTP_HEADERS", "HTTP_METADATA",
             "HTTP_STATUS"])

    def test_policy_rejects_empty_types(self):
        from aec.runtime.policy.models import ObservationPolicy

        with self.assertRaises(ValueError):
            ObservationPolicy(observation_types=())

    def test_policy_rejects_unknown_type_at_build(self):
        from aec.runtime.policy.models import ObservationPolicy

        with self.assertRaises(ValueError):
            ObservationPolicy(observation_types=("HTTP_POST",))

    def test_policy_to_dict(self):
        from aec.runtime.policy.models import default_policy

        data = default_policy().to_dict()
        self.assertEqual(data["policy_version"], "v1")
        self.assertIn("limits", data)

    def test_policy_refusal_reason_closed(self):
        from aec.runtime.policy.models import (
            ObservationPolicy, validate_policy_for_request)

        policy = ObservationPolicy(observation_types=("HTTP_STATUS",))
        reason = validate_policy_for_request(
            {"observation_type": "HTTP_METADATA"}, policy)
        self.assertTrue(reason.startswith("TYPE_NOT_PERMITTED"))


class TestResourceLimits(unittest.TestCase):
    def test_defaults_present(self):
        from aec.runtime.policy.limits import default_limits

        limits = default_limits()
        self.assertGreater(limits.request_timeout_seconds, 0)
        self.assertGreater(limits.max_response_bytes, 0)
        self.assertGreater(limits.max_redirects, 0)
        self.assertGreater(limits.max_concurrent_observations, 0)
        self.assertGreater(limits.max_observations_per_host, 0)
        self.assertGreater(limits.max_total_runtime_seconds, 0)
        self.assertGreater(limits.retry_limit, 0)

    def test_invalid_zero_rejected(self):
        from aec.runtime.policy.limits import ResourceLimits

        with self.assertRaises(ValueError):
            ResourceLimits(
                request_timeout_seconds=0, max_response_bytes=10,
                max_redirects=1, max_concurrent_observations=1,
                max_observations_per_host=1,
                max_total_runtime_seconds=1, retry_limit=1)

    def test_negative_bytes_rejected(self):
        from aec.runtime.policy.limits import ResourceLimits

        with self.assertRaises(ValueError):
            ResourceLimits(
                request_timeout_seconds=1, max_response_bytes=-1,
                max_redirects=1, max_concurrent_observations=1,
                max_observations_per_host=1,
                max_total_runtime_seconds=1, retry_limit=1)

    def test_limits_to_dict(self):
        from aec.runtime.policy.limits import default_limits

        data = default_limits().to_dict()
        self.assertIn("request_timeout_seconds", data)
        self.assertIn("max_response_bytes", data)


class TestLimitsEnforcer(unittest.TestCase):
    def test_concurrency_cap(self):
        from aec.runtime.policy.limits import LimitsEnforcer, default_limits

        limits = default_limits()
        enforcer = LimitsEnforcer(limits)
        for _ in range(limits.max_concurrent_observations):
            self.assertTrue(enforcer.acquire("a.example"))
        self.assertFalse(enforcer.acquire("a.example"))

    def test_release_frees_concurrency(self):
        from aec.runtime.policy.limits import LimitsEnforcer, default_limits

        enforcer = LimitsEnforcer(default_limits())
        enforcer.acquire("a.example")
        enforcer.release("a.example")
        self.assertTrue(enforcer.acquire("a.example"))

    def test_per_host_cap(self):
        from aec.runtime.policy.limits import ResourceLimits, LimitsEnforcer

        enforcer = LimitsEnforcer(ResourceLimits(
            request_timeout_seconds=1, max_response_bytes=100,
            max_redirects=1, max_concurrent_observations=100,
            max_observations_per_host=2,
            max_total_runtime_seconds=100, retry_limit=1))
        self.assertTrue(enforcer.observe_host("a.example"))
        self.assertTrue(enforcer.observe_host("a.example"))
        self.assertFalse(enforcer.observe_host("a.example"))

    def test_different_hosts_independent(self):
        from aec.runtime.policy.limits import ResourceLimits, LimitsEnforcer

        enforcer = LimitsEnforcer(ResourceLimits(
            request_timeout_seconds=1, max_response_bytes=100,
            max_redirects=1, max_concurrent_observations=100,
            max_observations_per_host=2,
            max_total_runtime_seconds=100, retry_limit=1))
        self.assertTrue(enforcer.observe_host("a.example"))
        self.assertTrue(enforcer.observe_host("b.example"))

    def test_total_runtime_exceeded(self):
        from aec.runtime.policy.limits import ResourceLimits, LimitsEnforcer

        enforcer = LimitsEnforcer(ResourceLimits(
            request_timeout_seconds=1, max_response_bytes=100,
            max_redirects=1, max_concurrent_observations=100,
            max_observations_per_host=100,
            max_total_runtime_seconds=5, retry_limit=1))
        self.assertFalse(enforcer.runtime_exceeded(5, 5))
        self.assertTrue(enforcer.runtime_exceeded(5, 6))

    def test_retry_budget(self):
        from aec.runtime.policy.limits import LimitsEnforcer, default_limits

        limits = default_limits()
        enforcer = LimitsEnforcer(limits)
        for _ in range(limits.retry_limit):
            self.assertTrue(enforcer.retry_budget_available())
            enforcer.consume_retry()
        self.assertFalse(enforcer.retry_budget_available())

    def test_per_host_never_negative(self):
        from aec.runtime.policy.limits import LimitsEnforcer, default_limits

        enforcer = LimitsEnforcer(default_limits())
        counts = enforcer.host_counts()
        self.assertGreaterEqual(counts.get("a.example", 0), 0)


if __name__ == "__main__":
    unittest.main()