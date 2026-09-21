"""EPIC7 Part 7: policy-driven resource limits and the enforcer."""

from __future__ import annotations

import unittest


class TestDefaultLimitsPositive(unittest.TestCase):
    def test_all_finite_positive(self):
        from aec.runtime.policy.limits import default_limits

        for name, value in default_limits().to_dict().items():
            self.assertGreater(value, 0, name)

    def test_request_timeout_bounded(self):
        from aec.runtime.policy.limits import default_limits

        self.assertLessEqual(default_limits().request_timeout_seconds, 60)

    def test_max_response_bytes_bounded(self):
        from aec.runtime.policy.limits import default_limits

        self.assertLessEqual(default_limits().max_response_bytes,
                             16 * 1024 * 1024)

    def test_max_redirects_bounded(self):
        from aec.runtime.policy.limits import default_limits

        self.assertLessEqual(default_limits().max_redirects, 10)

    def test_max_concurrent_bounded(self):
        from aec.runtime.policy.limits import default_limits

        self.assertLessEqual(default_limits().max_concurrent_observations,
                             32)

    def test_retry_limit_small(self):
        from aec.runtime.policy.limits import default_limits

        self.assertLessEqual(default_limits().retry_limit, 5)


class TestResourceLimitsValidation(unittest.TestCase):
    def test_zero_rejected(self):
        from aec.runtime.policy.limits import ResourceLimits

        with self.assertRaises(ValueError):
            ResourceLimits(0, 1, 1, 1, 1, 1, 1)

    def test_negative_rejected(self):
        from aec.runtime.policy.limits import ResourceLimits

        with self.assertRaises(ValueError):
            ResourceLimits(10, -5, 1, 1, 1, 1, 1)

    def test_non_int_rejected(self):
        from aec.runtime.policy.limits import ResourceLimits

        with self.assertRaises(ValueError):
            ResourceLimits(10, 1, "3", 1, 1, 1, 1)

    def test_frozen_dataclass(self):
        from dataclasses import FrozenInstanceError
        from aec.runtime.policy.limits import ResourceLimits

        limits = ResourceLimits(10, 1, 1, 1, 1, 1, 1)
        with self.assertRaises(FrozenInstanceError):
            limits.retry_limit = 99  # type: ignore[misc]

    def test_to_dict_keys(self):
        from aec.runtime.policy.limits import default_limits

        keys = set(default_limits().to_dict())
        self.assertEqual(
            keys,
            {"request_timeout_seconds", "max_response_bytes",
             "max_redirects", "max_concurrent_observations",
             "max_observations_per_host", "max_total_runtime_seconds",
             "retry_limit"})


class TestLimitsEnforcerConcurrency(unittest.TestCase):
    def test_acquire_release_cycle(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, default_limits)

        enforcer = LimitsEnforcer(default_limits())
        self.assertTrue(enforcer.acquire("h1"))
        enforcer.release("h1")
        self.assertTrue(enforcer.acquire("h1"))

    def test_concurrency_cap_enforced(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, ResourceLimits)

        enforcer = LimitsEnforcer(ResourceLimits(1, 1, 1, 2, 10, 1, 1))
        self.assertTrue(enforcer.acquire("h1"))
        self.assertTrue(enforcer.acquire("h1"))
        self.assertFalse(enforcer.acquire("h1"))

    def test_per_host_cap_enforced(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, ResourceLimits)

        enforcer = LimitsEnforcer(
            ResourceLimits(1, 1, 1, 10, 2, 1, 1))
        self.assertTrue(enforcer.observe_host("h1"))
        self.assertTrue(enforcer.observe_host("h1"))
        self.assertFalse(enforcer.observe_host("h1"))
        self.assertTrue(enforcer.observe_host("h2"))

    def test_retry_budget_cap(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, ResourceLimits)

        enforcer = LimitsEnforcer(ResourceLimits(1, 1, 1, 1, 1, 1, 2))
        self.assertTrue(enforcer.retry_budget_available())
        enforcer.consume_retry()
        self.assertTrue(enforcer.retry_budget_available())
        enforcer.consume_retry()
        self.assertFalse(enforcer.retry_budget_available())

    def test_no_infinite_retry(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, default_limits)

        enforcer = LimitsEnforcer(default_limits())
        attempts = 0
        while enforcer.retry_budget_available():
            enforcer.consume_retry()
            attempts += 1
        self.assertEqual(attempts, default_limits().retry_limit)

    def test_runtime_budget_check(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, default_limits)

        enforcer = LimitsEnforcer(default_limits())
        self.assertFalse(enforcer.runtime_exceeded(3600, 100))
        self.assertTrue(enforcer.runtime_exceeded(3600, 3601))

    def test_snapshot_invariants(self):
        from aec.runtime.policy.limits import (
            LimitsEnforcer, default_limits)

        enforcer = LimitsEnforcer(default_limits())
        enforcer.acquire("h1")
        snap = enforcer.snapshot()
        self.assertEqual(snap["active"], 1)
        self.assertIn("limits", snap)
        self.assertGreater(snap["limits"]["request_timeout_seconds"], 0)


class TestFailClosedLimits(unittest.TestCase):
    def test_limits_are_policy_driven_not_hardcoded_in_adapter(self):
        import ast
        from pathlib import Path

        adapter = Path(
            "aec/runtime/adapters/http_observation.py")
        tree = ast.parse(adapter.read_text())
        # The adapter must consume a limits object; no magic numbers
        # that bypass policy.
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(
                    node.value, int) and node.value > 10000:
                self.fail(f"magic number {node.value} in adapter")

    def test_limits_module_not_imported_by_network(self):
        import ast
        from pathlib import Path

        for path in Path("aec/runtime").rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotEqual(
                        node.module, "socket",
                        f"{path} imports socket")


if __name__ == "__main__":
    unittest.main()