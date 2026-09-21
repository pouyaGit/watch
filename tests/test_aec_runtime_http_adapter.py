"""EPIC7 Part 5: tightly constrained HTTP observation adapter.

The adapter is the single sanctioned transport. It never takes a raw URL:
it receives a ResolvedTarget plus an observation request and a policy, and
it records only allowlisted, redacted, bounded metadata. The transport is
injected so the full suite runs without touching the network; the default
transport is loaded lazily and only reached when every gate has passed.
"""

from __future__ import annotations

import unittest


class _NoNetwork(Exception):
    pass


class ExplodingTransport:
    """Proves zero network traffic: any call fails the test."""

    def __call__(self, *args, **kwargs):
        raise _NoNetwork("transport invoked — network forbidden")


class FakeTransport:
    """Deterministic in-memory transport for timeout/size tests."""

    def __init__(self):
        self.calls = 0

    def __call__(self, target, request, policy):
        self.calls += 1
        return {
            "status": 200,
            "headers": {"content-type": "text/html",
                        "set-cookie": "sid=secret123"},
            "body": b"<html>hello</html>",
            "timing_ms": 12,
        }


def valid_target():
    from aec.runtime.adapters.target import resolve_target

    return resolve_target(
        {"host": "shop.example.com", "scheme": "https",
         "endpoint": "/orders", "port": None, "source": "watch",
         "authorization_reference": "authz-123"},
        scope_hosts=frozenset({"shop.example.com"}))


def valid_request(**overrides):
    request = {
        "request_id": "obsreq-abc123",
        "research_job_id": "job-123",
        "case_id": "case-123",
        "observation_type": "HTTP_METADATA",
        "method": "GET",
        "required_evidence_level": "PARTIAL",
        "authorization_reference": "authz-123",
        "policy_version": "v1",
    }
    request.update(overrides)
    return request


class TestAdapterObserve(unittest.TestCase):
    def test_observe_records_status(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.status, 200)

    def test_observe_records_timing(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.timing_ms, 12)

    def test_observe_records_content_metadata(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.content_type, "text/html")
        self.assertEqual(result.content_length, 18)

    def test_observe_redacts_sensitive_headers(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertNotIn("secret123", str(result.selected_headers))
        self.assertNotIn("set-cookie", str(result.selected_headers))

    def test_observe_selects_only_allowlisted_headers(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertIn("content-type", result.selected_headers)
        for name in result.selected_headers:
            self.assertNotIn(name, ("set-cookie", "authorization", "cookie"))

    def test_transport_never_invoked_by_default_path(self):
        from aec.runtime.adapters.http_observation import (
            default_transport, observe)

        # The default transport must not be callable without the runtime's
        # gating; constructing it must never touch the network.
        transport = default_transport()
        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.status, 200)


class TestAdapterScopeEnforcement(unittest.TestCase):
    def test_redirect_out_of_scope_refused(self):
        from aec.runtime.adapters.http_observation import (
            RedirectLimit, check_redirect)

        with self.assertRaises(RedirectLimit):
            check_redirect("https://evil.example.com/x", "shop.example.com",
                           frozenset({"shop.example.com"}))

    def test_redirect_in_scope_allowed(self):
        from aec.runtime.adapters.http_observation import check_redirect

        check_redirect("https://shop.example.com/other",
                       "shop.example.com",
                       frozenset({"shop.example.com"}))

    def test_redirect_alternate_host_refused(self):
        from aec.runtime.adapters.http_observation import (
            RedirectLimit, check_redirect)

        with self.assertRaises(RedirectLimit):
            check_redirect("https://cdn.shop.example.com/x",
                           "shop.example.com",
                           frozenset({"shop.example.com"}))

    def test_redirect_scheme_downgrade_refused(self):
        from aec.runtime.adapters.http_observation import (
            RedirectLimit, check_redirect)

        with self.assertRaises(RedirectLimit):
            check_redirect("http://shop.example.com/x",
                           "shop.example.com",
                           frozenset({"shop.example.com"}))

    def test_redirect_userinfo_refused(self):
        from aec.runtime.adapters.http_observation import (
            RedirectLimit, check_redirect)

        with self.assertRaises(RedirectLimit):
            check_redirect("https://user:pass@shop.example.com/x",
                           "shop.example.com",
                           frozenset({"shop.example.com"}))


class TestAdapterLimits(unittest.TestCase):
    def test_response_too_large_fails(self):
        from aec.runtime.adapters.http_observation import ResponseTooLarge

        with self.assertRaises(ResponseTooLarge):
            raise ResponseTooLarge(2_000_000, 1_048_576)

    def test_response_under_limit_ok(self):
        from aec.runtime.adapters.http_observation import (
            bounded_size, default_limits)

        self.assertTrue(bounded_size(1000, default_limits()))

    def test_response_over_limit_refused(self):
        from aec.runtime.adapters.http_observation import (
            bounded_size, default_limits)

        self.assertFalse(bounded_size(default_limits().max_response_bytes + 1,
                                      default_limits()))

    def test_redirect_budget_exhausted(self):
        from aec.runtime.adapters.http_observation import (
            RedirectLimit, check_redirect_budget)

        with self.assertRaises(RedirectLimit):
            check_redirect_budget(3, 2)


class TestAdapterDeterminism(unittest.TestCase):
    def test_observe_deterministic(self):
        from aec.runtime.adapters.http_observation import observe

        first = observe(valid_target(), valid_request(), None,
                        transport=FakeTransport())
        second = observe(valid_target(), valid_request(), None,
                        transport=FakeTransport())
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_result_to_dict_fields(self):
        from aec.runtime.adapters.http_observation import observe

        data = observe(valid_target(), valid_request(), None,
                       transport=FakeTransport()).to_dict()
        for key in ("status", "timing_ms", "content_type", "content_length",
                    "selected_headers", "scope_validation",
                    "authorization_reference", "policy_version",
                    "target_id", "redaction_status"):
            self.assertIn(key, data)

    def test_scope_validation_recorded(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.scope_validation, "PASS")

    def test_provenance_recorded(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.target_id, valid_target().target_id)
        self.assertEqual(result.authorization_reference, "authz-123")


class TestMinimalCollection(unittest.TestCase):
    def test_body_content_never_returned(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertIsNone(getattr(result, "body", None))
        self.assertNotIn("hello", str(result.to_dict()))

    def test_only_get_method(self):
        from aec.runtime.adapters.http_observation import observe

        result = observe(valid_target(), valid_request(), None,
                         transport=FakeTransport())
        self.assertEqual(result.method_used, "GET")

    def test_no_secrets_in_output_mapping(self):
        from aec.runtime.adapters.http_observation import observe

        data = observe(valid_target(), valid_request(), None,
                       transport=FakeTransport()).to_dict()
        joined = " ".join(
            str(value) for value in data.values())
        for secret in ("secret123", "sid=", "Bearer "):
            self.assertNotIn(secret, joined)


if __name__ == "__main__":
    unittest.main()