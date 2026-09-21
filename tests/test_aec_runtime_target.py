"""EPIC7 Part 4: target adapter — normalized identities only, never raw URLs."""

from __future__ import annotations

import unittest


def valid_target_input(**overrides):
    target = {
        "target_id": "tgt-000000000001",
        "host": "shop.example.com",
        "scheme": "https",
        "endpoint": "/orders",
        "port": None,
        "source": "watch",
        "authorization_reference": "authz-123",
    }
    target.update(overrides)
    return target


class TestTargetAdapterAccepts(unittest.TestCase):
    def test_normalized_target_accepted(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(valid_target_input(),
                                scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.host, "shop.example.com")
        self.assertEqual(target.scheme, "https")
        self.assertTrue(target.target_id.startswith("tgt-"))
        self.assertEqual(len(target.target_id), 16)

    def test_source_recorded(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(valid_target_input(),
                                scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.source, "watch")

    def test_authorization_reference_recorded(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(valid_target_input(),
                                scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.authorization_reference, "authz-123")

    def test_explicit_https_port(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(
            valid_target_input(port=443),
            scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.port, 443)

    def test_endpoint_preserved(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(
            valid_target_input(endpoint="/orders?id=1"),
            scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.endpoint, "/orders?id=1")


class TestRawUrlRefusal(unittest.TestCase):
    def test_raw_url_string_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target("https://shop.example.com/orders",
                           scope_hosts=frozenset({"shop.example.com"}))

    def test_url_in_host_field_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(host="https://shop.example.com"),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_full_url_in_endpoint_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(
                    endpoint="https://shop.example.com/orders"),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_userinfo_host_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(host="user:pass@shop.example.com"),
                scope_hosts=frozenset({"shop.example.com"}))


class TestTargetMismatch(unittest.TestCase):
    def test_out_of_scope_host_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(host="evil.example.com"),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_wrong_scheme_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(scheme="ftp"),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_unexpected_port_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(port=8080),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_empty_host_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(valid_target_input(host=""),
                           scope_hosts=frozenset())

    def test_ip_substitution_refused_unless_authorized(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(host="93.184.216.34"),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_localhost_refused_unless_authorized(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(host="127.0.0.1"),
                scope_hosts=frozenset({"127.0.0.1"}))


class TestNoImplicitDefaults(unittest.TestCase):
    def test_missing_host_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(valid_target_input(host=None),
                           scope_hosts=frozenset({"shop.example.com"}))

    def test_missing_scheme_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(valid_target_input(scheme=""),
                           scope_hosts=frozenset({"shop.example.com"}))

    def test_missing_authorization_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(authorization_reference=""),
                scope_hosts=frozenset({"shop.example.com"}))

    def test_scheme_defaults_never_inferred(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(valid_target_input(scheme=None),
                           scope_hosts=frozenset({"shop.example.com"}))


class TestWildcardRefusal(unittest.TestCase):
    def test_wildcard_host_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(host="*.example.com"),
                scope_hosts=frozenset({"*.example.com"}))

    def test_wildcard_endpoint_refused(self):
        from aec.runtime.adapters.target import TargetRefusal, resolve_target

        with self.assertRaises(TargetRefusal):
            resolve_target(
                valid_target_input(endpoint="/*"),
                scope_hosts=frozenset({"shop.example.com"}))


class TestTargetIdentity(unittest.TestCase):
    def test_identity_digest_deterministic(self):
        from aec.runtime.adapters.target import target_identity

        first = target_identity(valid_target_input())
        second = target_identity(valid_target_input())
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("tgt-"))

    def test_identity_changes_with_host(self):
        from aec.runtime.adapters.target import target_identity

        first = target_identity(valid_target_input())
        second = target_identity(
            valid_target_input(host="other.example.com"))
        self.assertNotEqual(first, second)

    def test_record_target_identity(self):
        from aec.runtime.adapters.target import resolve_target, target_identity

        raw = valid_target_input()
        target = resolve_target(raw,
                                scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.target_id, target_identity(raw))

    def test_adapter_refuses_http_only_when_authorized(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(
            valid_target_input(scheme="http", port=80),
            scope_hosts=frozenset({"shop.example.com"}),
            permitted_schemes=frozenset({"https", "http"}))
        self.assertEqual(target.scheme, "http")


class TestScopeMetadata(unittest.TestCase):
    def test_scope_validation_recorded(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(valid_target_input(),
                                scope_hosts=frozenset({"shop.example.com"}))
        self.assertEqual(target.scope_validation, "PASS")

    def test_resolution_never_expands(self):
        from aec.runtime.adapters.target import resolve_target

        target = resolve_target(valid_target_input(),
                                scope_hosts=frozenset({"shop.example.com"}))
        resolved = target.to_dict()
        self.assertEqual(resolved["host"], "shop.example.com")


if __name__ == "__main__":
    unittest.main()