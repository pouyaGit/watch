"""EPIC7 Part 6+19: scope enforcement and failure-state mapping."""

from __future__ import annotations

import unittest


def valid_target():
    from aec.runtime.adapters.target import resolve_target

    return resolve_target(
        {"host": "shop.example.com", "scheme": "https",
         "endpoint": "/orders", "port": None, "source": "watch",
         "authorization_reference": "authz-123"},
        scope_hosts=frozenset({"shop.example.com"}))


class TestScopeChecks(unittest.TestCase):
    def test_host_in_scope(self):
        from aec.runtime.execution.scope import target_in_scope

        self.assertTrue(
            target_in_scope("shop.example.com",
                            frozenset({"shop.example.com"})))

    def test_host_out_of_scope(self):
        from aec.runtime.execution.scope import target_in_scope

        self.assertFalse(
            target_in_scope("evil.example.com",
                            frozenset({"shop.example.com"})))

    def test_scheme_permitted(self):
        from aec.runtime.execution.scope import scheme_permitted

        self.assertTrue(scheme_permitted("https", frozenset({"https"})))

    def test_scheme_not_permitted(self):
        from aec.runtime.execution.scope import scheme_permitted

        self.assertFalse(
            scheme_permitted("http", frozenset({"https"})))

    def test_port_permitted(self):
        from aec.runtime.execution.scope import port_permitted

        self.assertTrue(port_permitted(443, None, "https"))

    def test_unexpected_port_refused(self):
        from aec.runtime.execution.scope import port_permitted

        self.assertFalse(port_permitted(8080, None, "https"))

    def test_explicit_authorized_port(self):
        from aec.runtime.execution.scope import port_permitted

        self.assertTrue(port_permitted(8443, 8443, "https"))

    def test_path_in_scope(self):
        from aec.runtime.execution.scope import path_in_scope

        self.assertTrue(path_in_scope("/orders", "/orders"))

    def test_path_not_in_scope(self):
        from aec.runtime.execution.scope import path_in_scope

        self.assertFalse(path_in_scope("/admin", "/orders"))

    def test_path_prefix_allow(self):
        from aec.runtime.execution.scope import path_allowed_by_prefix

        self.assertTrue(path_allowed_by_prefix("/orders/123", "/orders"))

    def test_path_prefix_deny(self):
        from aec.runtime.execution.scope import path_allowed_by_prefix

        self.assertFalse(path_allowed_by_prefix("/admin/panel", "/orders"))

    def test_observation_type_allowed(self):
        from aec.runtime.execution.scope import observation_type_allowed

        self.assertTrue(
            observation_type_allowed("HTTP_METADATA",
                                     frozenset({"HTTP_METADATA"})))

    def test_observation_type_denied(self):
        from aec.runtime.execution.scope import observation_type_allowed

        self.assertFalse(
            observation_type_allowed("HTTP_POST",
                                     frozenset({"HTTP_METADATA"})))


class TestScopeDocument(unittest.TestCase):
    def test_scope_to_dict(self):
        from aec.runtime.execution.scope import build_scope

        scope = build_scope(
            hosts=frozenset({"shop.example.com"}),
            schemes=frozenset({"https"}))
        data = scope.to_dict()
        self.assertIn("hosts", data)
        self.assertIn("schemes", data)

    def test_scope_empty_refused(self):
        from aec.runtime.execution.scope import ScopeRefusal, build_scope

        with self.assertRaises(ScopeRefusal):
            build_scope(hosts=frozenset())

    def test_scope_host_list(self):
        from aec.runtime.execution.scope import build_scope

        scope = build_scope(
            hosts=frozenset({"a.example.com"}),
            schemes=frozenset({"https"}))
        self.assertIn("a.example.com", scope.hosts)

    def test_scope_immutable(self):
        from aec.runtime.execution.scope import build_scope

        scope = build_scope(
            hosts=frozenset({"a.example.com"}),
            schemes=frozenset({"https"}))
        with self.assertRaises(AttributeError):
            scope.hosts = frozenset()

    def test_userinfo_url_refused(self):
        from aec.runtime.execution.scope import ScopeRefusal, userinfo_present

        self.assertTrue(userinfo_present("https://user:pass@host/x"))
        self.assertFalse(userinfo_present("https://host/x"))


class TestFailureMapping(unittest.TestCase):
    def test_every_failure_kind_maps_to_state(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(len(FAILURE_KIND_TO_STATE), 14)
        for kind, state in FAILURE_KIND_TO_STATE.items():
            self.assertIn(state, (
                "REFUSED", "BLOCKED", "TIMED_OUT", "FAILED"))

    def test_dns_failure(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(FAILURE_KIND_TO_STATE["DNS_FAILURE"], "FAILED")

    def test_connection_timeout(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["CONNECTION_TIMEOUT"], "TIMED_OUT")

    def test_tls_failure(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(FAILURE_KIND_TO_STATE["TLS_FAILURE"], "FAILED")

    def test_http_timeout(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(FAILURE_KIND_TO_STATE["HTTP_TIMEOUT"], "TIMED_OUT")

    def test_response_too_large(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["RESPONSE_TOO_LARGE"], "BLOCKED")

    def test_redirect_out_of_scope(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["REDIRECT_OUT_OF_SCOPE"], "REFUSED")

    def test_authorization_expiry(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["AUTHORIZATION_EXPIRY"], "BLOCKED")

    def test_scope_mismatch(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(FAILURE_KIND_TO_STATE["SCOPE_MISMATCH"], "REFUSED")

    def test_policy_mismatch(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(FAILURE_KIND_TO_STATE["POLICY_MISMATCH"], "REFUSED")

    def test_duplicate_request(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["DUPLICATE_REQUEST"], "BLOCKED")

    def test_runtime_shutdown(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["RUNTIME_SHUTDOWN"], "FAILED")

    def test_partial_evidence(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["PARTIAL_EVIDENCE"], "FAILED")

    def test_redaction_failure(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        self.assertEqual(
            FAILURE_KIND_TO_STATE["REDACTION_FAILURE"], "FAILED")

    def test_unknown_failure_kind_fails_closed(self):
        from aec.runtime.execution.failures import failure_state

        self.assertEqual(failure_state("MYSTERY_BREAKAGE"), "FAILED")

    def test_failure_kinds_closed_set(self):
        from aec.runtime.execution.failures import FAILURE_KIND_TO_STATE

        for kind in FAILURE_KIND_TO_STATE:
            self.assertEqual(kind, kind.upper())


class TestScopeValidationFlow(unittest.TestCase):
    def test_full_scope_validation_passes(self):
        from aec.runtime.execution.scope import (
            build_scope, validate_target_against_scope)

        scope = build_scope(
            hosts=frozenset({"shop.example.com"}),
            schemes=frozenset({"https"}))
        result = validate_target_against_scope(
            valid_target(), scope, "HTTP_METADATA")
        self.assertEqual(result, "PASS")

    def test_scope_validation_catches_host(self):
        from aec.runtime.adapters.target import resolve_target
        from aec.runtime.execution.scope import (
            build_scope, validate_target_against_scope)

        target = resolve_target(
            {"host": "evil.example.com", "scheme": "https",
             "endpoint": "/x", "port": None, "source": "watch",
             "authorization_reference": "authz-1"},
            scope_hosts=frozenset({"evil.example.com"}))
        scope = build_scope(
            hosts=frozenset({"shop.example.com"}),
            schemes=frozenset({"https"}))
        self.assertEqual(
            validate_target_against_scope(target, scope, "HTTP_METADATA"),
            "SCOPE_MISMATCH")

    def test_scope_validation_catches_type(self):
        from aec.runtime.execution.scope import (
            build_scope, validate_target_against_scope)

        scope = build_scope(
            hosts=frozenset({"shop.example.com"}),
            schemes=frozenset({"https"}))
        self.assertEqual(
            validate_target_against_scope(
                valid_target(), scope, "HTTP_POST"),
            "TYPE_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main()