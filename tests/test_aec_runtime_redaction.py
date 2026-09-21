"""EPIC7 Part 9: deterministic redaction policy."""

from __future__ import annotations

import unittest

SECRET_HEADERS = {"authorization": "Bearer abc123secret",
                  "cookie": "session=super-secret-value",
                  "set-cookie": "sid=secret123"}


class TestRedactionPolicy(unittest.TestCase):
    def test_authorization_header_redacted(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers(SECRET_HEADERS)
        self.assertNotIn("abc123secret", str(out))
        self.assertEqual(out.get("authorization", ""), "")

    def test_cookie_header_redacted(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers(SECRET_HEADERS)
        self.assertNotIn("super-secret-value", str(out))

    def test_set_cookie_redacted(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers(SECRET_HEADERS)
        self.assertNotIn("secret123", str(out))

    def test_allowlisted_header_kept(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers({"content-type": "text/html"})
        self.assertEqual(out.get("content-type"), "text/html")

    def test_host_kept(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers({"host": "shop.example.com"})
        self.assertEqual(out.get("host"), "shop.example.com")

    def test_token_value_scrubbed_by_content(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers({"x-custom": "token=eyJhbGciOiJIUzI1NiJ9"})
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", str(out))

    def test_password_like_value_scrubbed(self):
        from aec.runtime.results.redaction import redact_headers

        out = redact_headers({"x-extra": "password=hunter2"})
        self.assertNotIn("hunter2", str(out))

    def test_known_secret_header_names(self):
        from aec.runtime.results.redaction import REDACTED_HEADER_NAMES

        self.assertIn("authorization", REDACTED_HEADER_NAMES)
        self.assertIn("cookie", REDACTED_HEADER_NAMES)
        self.assertIn("set-cookie", REDACTED_HEADER_NAMES)
        self.assertIn("x-api-key", REDACTED_HEADER_NAMES)

    def test_empty_headers_ok(self):
        from aec.runtime.results.redaction import redact_headers

        self.assertEqual(redact_headers({}), {})

    def test_deterministic_same_input(self):
        from aec.runtime.results.redaction import redact_headers

        first = redact_headers(SECRET_HEADERS)
        second = redact_headers(SECRET_HEADERS)
        self.assertEqual(first, second)


class TestBodyRedaction(unittest.TestCase):
    def test_body_never_retained(self):
        from aec.runtime.results.redaction import project_body

        digest, size = project_body(b"<html>secret body</html>")
        self.assertNotIn("secret", digest)
        self.assertEqual(size, 24)

    def test_body_projection_deterministic(self):
        from aec.runtime.results.redaction import project_body

        first = project_body(b"payload")
        second = project_body(b"payload")
        self.assertEqual(first, second)

    def test_empty_body(self):
        from aec.runtime.results.redaction import project_body

        digest, size = project_body(b"")
        self.assertEqual(size, 0)
        self.assertTrue(digest.startswith("sha256:"))


class TestTraceRedaction(unittest.TestCase):
    def test_secrets_absent_from_failure_trace(self):
        from aec.runtime.results.redaction import redact_trace

        trace = redact_trace(
            "failed with Authorization: Bearer abc123secret")
        self.assertNotIn("abc123secret", trace)

    def test_trace_keeps_reason(self):
        from aec.runtime.results.redaction import redact_trace

        trace = redact_trace("connection refused on host shop.example.com")
        self.assertIn("connection refused", trace)

    def test_trace_deterministic(self):
        from aec.runtime.results.redaction import redact_trace

        first = redact_trace("token=abc123 payload")
        second = redact_trace("token=abc123 payload")
        self.assertEqual(first, second)


class TestLogRedaction(unittest.TestCase):
    def test_log_line_redacted(self):
        from aec.runtime.results.redaction import redact_log

        line = redact_log("observed Cookie: session=super-secret-value")
        self.assertNotIn("super-secret-value", line)

    def test_log_deterministic(self):
        from aec.runtime.results.redaction import redact_log

        first = redact_log("Authorization: Bearer abc123secret")
        second = redact_log("Authorization: Bearer abc123secret")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()