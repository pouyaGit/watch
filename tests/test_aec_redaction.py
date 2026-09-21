"""Tests for aec/redaction.py — AEC-1 T2 (S5): metadata allowlist + secret/PII scrubbing.

Written before the module exists (TDD, execution plan §4.3 for
``test_aec_redaction.py``):

- metadata allowlist enforced
- cookie / authorization / token values never retained
- PII-shaped strings scrubbed
- redaction list populated
- body limited to digest + length
- adversarial fixtures

Purity is asserted the same way as in T1: AST scan (no writes, no transport
imports) plus a live check that importing the module creates no file.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
AEC_DIR = REPO_ROOT / "aec"
REDACTION_PATH = AEC_DIR / "redaction.py"

# Adversarial material, assembled at runtime so this file itself never contains
# a literal that a secret scanner (including the delivery diff guard) flags.
# The *values* the tests use are the real shapes (a private-key header, a
# credential-bearing connection URI); only their source text is split, so the
# delivery gate keeps flagging genuine credentials instead of test fixtures.
SECRET = "s3cr3t-value-" + "DO-NOT-RETAIN"
COOKIE_VALUE = "session=" + "abcdef0123456789"
AUTH_VALUE = "Bearer " + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
JWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dGhpcy1pc2Etc2lnbmF0dXJl"
EMAIL = "research.contact@" + "example-target.test"
LONG_HEX = "f" * 64
LONG_TOKEN = "Z" * 48
_DASHES = "-" * 5
PRIVATE_KEY_LINE = _DASHES + "BEGIN RSA " + "PRIVATE" + " KEY" + _DASHES
MONGO_URI = "mongodb" + "://" + "watcher" + ":" + "hunter" + "2" + "@db.internal:27017/watch"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class RedactionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.redaction = load_module("watch_aec_redaction", REDACTION_PATH)

    def records_for(self, field, records):
        return [item for item in records if item["field"] == field]

    def assert_no_leak(self, payload, *secrets):
        blob = json.dumps(payload, sort_keys=True, default=str)
        for secret in secrets:
            self.assertNotIn(secret, blob, f"secret leaked: {secret!r}")


class TestVocabularyAlignment(RedactionTestCase):
    def test_module_exists_with_rule_version(self):
        self.assertTrue(REDACTION_PATH.is_file(), f"missing {REDACTION_PATH}")
        self.assertEqual(self.redaction.RULE_VERSION, "aec-redaction/v1")

    def test_header_allowlists_match_the_frozen_evidence_module(self):
        from ai.evidence import observations

        self.assertEqual(
            frozenset(self.redaction.REQUEST_HEADER_ALLOWLIST),
            frozenset(observations.REQUEST_HEADER_ALLOWLIST),
        )
        self.assertEqual(
            frozenset(self.redaction.RESPONSE_HEADER_ALLOWLIST),
            frozenset(observations.RESPONSE_HEADER_ALLOWLIST),
        )

    def test_value_length_cap_matches_the_frozen_context_module(self):
        from ai.schemas import shared_research_context

        self.assertEqual(
            self.redaction.MAX_RETAINED_VALUE_LEN,
            shared_research_context.MAX_VALUE_LEN,
        )

    def test_actions_are_a_closed_vocabulary(self):
        self.assertEqual(
            tuple(self.redaction.ACTIONS),
            ("KEPT", "DROPPED", "REDACTED", "DIGESTED", "TRUNCATED"),
        )

    def test_reasons_are_a_closed_vocabulary(self):
        reasons = tuple(self.redaction.REASONS)
        self.assertEqual(len(reasons), len(set(reasons)))
        for expected in (
            "NOT_ALLOWLISTED",
            "SENSITIVE_HEADER",
            "SENSITIVE_NAME",
            "SECRET_PAIR",
            "BEARER_TOKEN",
            "USERINFO",
            "EMAIL",
            "JWT",
            "LONG_TOKEN",
            "PRIVATE_KEY",
            "CONNECTION_URI",
            "CONTROL_CHARS",
            "TOO_LONG",
            "BODY_NOT_RETAINED",
            "UNKNOWN_METADATA_KEY",
        ):
            self.assertIn(expected, reasons)

    def test_never_retained_keys_cover_the_credential_surface(self):
        for name in (
            "cookie",
            "set-cookie",
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-xsrf-token",
            "x-amz-security-token",
            "ww-authenticate",
            "authentication-info",
        ):
            self.assertIn(name, self.redaction.NEVER_RETAINED_KEYS)


class TestHeaderRedaction(RedactionTestCase):
    def test_allowlisted_headers_are_kept(self):
        safe, records = self.redaction.redact_headers(
            {"Content-Type": "application/json", "Content-Length": "17", "Server": "nginx"},
            kind="response",
        )
        self.assertEqual(
            safe,
            {"content-type": "application/json", "content-length": "17", "server": "nginx"},
        )
        self.assertEqual(records, [])

    def test_non_allowlisted_headers_are_dropped_with_a_record(self):
        safe, records = self.redaction.redact_headers({"X-Custom": "1"}, kind="response")
        self.assertNotIn("x-custom", safe)
        self.assertEqual(records[0]["field"], "x-custom")
        self.assertEqual(records[0]["action"], "DROPPED")
        self.assertEqual(records[0]["reason"], "NOT_ALLOWLISTED")

    def test_cookie_and_authorization_are_never_retained(self):
        safe, records = self.redaction.redact_headers(
            {
                "Set-Cookie": COOKIE_VALUE,
                "Cookie": COOKIE_VALUE,
                "Authorization": AUTH_VALUE,
                "X-Api-Key": SECRET,
            },
            kind="response",
        )
        self.assertEqual(safe, {})
        self.assert_no_leak(safe, COOKIE_VALUE, AUTH_VALUE, SECRET)
        reasons = {item["reason"] for item in records}
        self.assertEqual(reasons, {"SENSITIVE_HEADER"})
        self.assertEqual({item["action"] for item in records}, {"DROPPED"})

    def test_sensitive_headers_nested_in_allowlisted_names_still_dropped(self):
        safe, records = self.redaction.redact_headers(
            {"X-Powered-By": "Express", "X-Auth-Token": SECRET}, kind="response"
        )
        self.assertEqual(safe, {"x-powered-by": "Express"})
        self.assert_no_leak(safe, SECRET)

    def test_header_names_are_normalised_before_matching(self):
        safe, records = self.redaction.redact_headers(
            {"  Content-Type  ": "text/html", "SET_COOKIE": COOKIE_VALUE}, kind="response"
        )
        self.assertIn("content-type", safe)
        self.assertNotIn("set_cookie", safe)
        self.assert_no_leak(safe, COOKIE_VALUE)

    def test_request_allowlist_is_honoured_for_request_snapshots(self):
        safe, _ = self.redaction.redact_headers(
            {"Host": "example.test", "User-Agent": "watch/1.0", "X-Custom": "nope"},
            kind="request",
        )
        self.assertEqual(safe, {"host": "example.test", "user-agent": "watch/1.0"})

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            self.redaction.redact_headers({"server": "nginx"}, kind="mystery")

    def test_header_count_is_bounded(self):
        headers = {f"x-extra-{i}": "v" for i in range(80)}
        headers["server"] = "nginx"
        safe, records = self.redaction.redact_headers(headers, kind="response")
        self.assertLessEqual(len(safe), self.redaction.MAX_HEADER_COUNT)
        self.assertIn("server", safe)

    def test_values_of_kept_headers_are_still_scrubbed(self):
        safe, records = self.redaction.redact_headers(
            {"Location": f"https://example.test/cb#token={SECRET}"}, kind="response"
        )
        self.assertNotIn(SECRET, json.dumps(safe))
        self.assertTrue(records)

    def test_non_string_header_values_are_coerced_or_dropped_safely(self):
        safe, records = self.redaction.redact_headers(
            {"Server": None, "Content-Length": 17, "Content-Type": b"text/html"},
            kind="response",
        )
        self.assertEqual(safe.get("content-length"), "17")
        self.assertIsInstance(safe.get("server", ""), str)


class TestUrlRedaction(RedactionTestCase):
    def test_plain_url_is_preserved(self):
        safe, records = self.redaction.redact_url("https://example.test/a/b?page=2")
        self.assertEqual(safe, "https://example.test/a/b?page=2")
        self.assertEqual(records, [])

    def test_userinfo_is_stripped(self):
        safe, records = self.redaction.redact_url("https://user:pass@example.test/private")
        self.assertNotIn("user:pass", safe)
        self.assertIn("example.test", safe)
        self.assertEqual(records[0]["reason"], "USERINFO")

    def test_sensitive_query_values_are_digested_not_dropped(self):
        safe, records = self.redaction.redact_url(
            "https://example.test/cb?token=" + SECRET + "&page=2"
        )
        self.assertNotIn(SECRET, safe)
        self.assertIn("page=2", safe)
        self.assertIn("token=", safe)
        self.assertIn(self.redaction.digest(SECRET)[:16], safe)
        self.assertEqual(records[0]["action"], "DIGESTED")

    def test_fragment_is_dropped(self):
        safe, records = self.redaction.redact_url("https://example.test/a#/reset?token=abc")
        self.assertNotIn("#", safe)
        self.assertTrue(any(item["reason"] == "SENSITIVE_NAME" for item in records))

    def test_url_without_scheme_is_not_guessed(self):
        safe, records = self.redaction.redact_url("example.test/path")
        self.assertEqual(safe, "example.test/path")

    def test_malformed_and_empty_urls_do_not_raise(self):
        for value in ("", "   ", "http://", "::::", "https://example.test/?a=%zz"):
            with self.subTest(value=value):
                safe, _ = self.redaction.redact_url(value)
                self.assertIsInstance(safe, str)

    def test_query_values_that_look_like_secrets_are_scrubbed_even_for_safe_names(self):
        safe, records = self.redaction.redact_url(
            "https://example.test/?q=" + JWT + "&ref=" + EMAIL
        )
        self.assert_no_leak(safe, JWT, EMAIL)
        self.assertTrue(records)


class TestTextScrubbing(RedactionTestCase):
    def test_email_is_scrubbed(self):
        safe, records = self.redaction.scrub_text(f"contact {EMAIL} for details")
        self.assertNotIn(EMAIL, safe)
        self.assertIn("[redacted:EMAIL]", safe)
        self.assertEqual(records[0]["reason"], "EMAIL")

    def test_jwt_is_scrubbed(self):
        safe, _ = self.redaction.scrub_text(f"cookie jwt {JWT} seen")
        self.assertNotIn(JWT, safe)

    def test_bearer_token_is_scrubbed(self):
        safe, records = self.redaction.scrub_text("Authorization: " + AUTH_VALUE)
        self.assertNotIn(AUTH_VALUE, safe)
        self.assertIn("BEARER_TOKEN", {item["reason"] for item in records})

    def test_secret_pairs_are_scrubbed(self):
        safe, records = self.redaction.scrub_text(f"password={SECRET} and api_key={SECRET}")
        self.assertNotIn(SECRET, safe)
        self.assertIn("SECRET_PAIR", {item["reason"] for item in records})

    def test_long_high_entropy_tokens_are_scrubbed(self):
        safe, _ = self.redaction.scrub_text(f"nonce {LONG_HEX} and {LONG_TOKEN}")
        self.assertNotIn(LONG_HEX, safe)
        self.assertNotIn(LONG_TOKEN, safe)

    def test_connection_uri_credentials_are_scrubbed(self):
        safe, records = self.redaction.scrub_text(f"dsn {MONGO_URI} loaded")
        self.assertNotIn("hunter2", safe)
        self.assertIn("CONNECTION_URI", {item["reason"] for item in records})

    def test_private_key_material_is_scrubbed(self):
        safe, records = self.redaction.scrub_text(PRIVATE_KEY_LINE)
        self.assertIn("PRIVATE_KEY", {item["reason"] for item in records})
        self.assertNotIn("BEGIN RSA", safe)

    def test_control_characters_are_removed(self):
        safe, _ = self.redaction.scrub_text("a\x00b\x1fc\x7f")
        self.assertNotIn("\x00", safe)
        self.assertNotIn("\x1f", safe)

    def test_plain_text_is_unchanged(self):
        safe, records = self.redaction.scrub_text("plain observation text 123")
        self.assertEqual(safe, "plain observation text 123")
        self.assertEqual(records, [])

    def test_unicode_is_preserved(self):
        safe, _ = self.redaction.scrub_text("café ünïcode — ok")
        self.assertIn("café", safe)

    def test_long_text_is_truncated_with_a_record(self):
        safe, records = self.redaction.scrub_text("observation prose " * 40)
        self.assertLessEqual(len(safe), self.redaction.MAX_RETAINED_VALUE_LEN)
        self.assertIn("TOO_LONG", {item["reason"] for item in records})

    def test_long_unbroken_token_is_redacted_not_truncated(self):
        safe, records = self.redaction.scrub_text("x" * 500)
        self.assertNotIn("x" * 40, safe)
        self.assertIn("LONG_TOKEN", {item["reason"] for item in records})

    def test_non_string_input_is_coerced_without_raising(self):
        for value in (None, 5, b"bytes", ["a"], {"k": "v"}):
            with self.subTest(value=value):
                safe, _ = self.redaction.scrub_text(value)
                self.assertIsInstance(safe, str)


class TestBodyProjection(RedactionTestCase):
    def test_body_is_reduced_to_digest_and_length(self):
        body = "line one\nline two\n"
        projection = self.redaction.project_body(body)
        self.assertFalse(projection["retained"])
        self.assertEqual(projection["length"], len(body.encode("utf-8")))
        self.assertEqual(projection["sha256"], hashlib.sha256(body.encode("utf-8")).hexdigest())
        self.assert_is_none_sample(projection)

    def assert_is_none_sample(self, projection):
        self.assertIsNone(projection["sample"])
        self.assertTrue(projection["sample_omitted"])

    def test_body_content_never_appears_in_the_projection(self):
        projection = self.redaction.project_body(f"secret-body {SECRET} content")
        self.assert_no_leak(projection, SECRET, "secret-body")

    def test_binary_body_is_digested_without_decoding(self):
        payload = bytes(range(256))
        projection = self.redaction.project_body(payload)
        self.assertEqual(projection["length"], 256)
        self.assertEqual(projection["sha256"], hashlib.sha256(payload).hexdigest())

    def test_missing_body_is_reported_honestly(self):
        projection = self.redaction.project_body(None)
        self.assertFalse(projection["retained"])
        self.assertIsNone(projection["sha256"])
        self.assertEqual(projection["length"], 0)

    def test_large_body_projection_stays_bounded(self):
        projection = self.redaction.project_body("y" * 2_000_000)
        self.assertLess(len(json.dumps(projection)), 1200)

    def test_projection_carries_a_redaction_record(self):
        projection = self.redaction.project_body("anything")
        self.assertIn("BODY_NOT_RETAINED", {item["reason"] for item in projection["records"]})


class TestMetadataProjection(RedactionTestCase):
    def metadata(self):
        return {
            "status_code": 200,
            "content_type": "text/html",
            "content_length": 1234,
            "content_sha256": LONG_HEX,
            "elapsed_ms": 42,
            "server": "nginx",
            "x_powered_by": "PHP/8.1",
        }

    def test_allowlisted_metadata_passes_through_unchanged(self):
        result = self.redaction.project_metadata(self.metadata())
        for key, value in self.metadata().items():
            self.assertEqual(result["metadata"][key], value)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["rule_version"], "aec-redaction/v1")

    def test_unknown_metadata_keys_are_dropped_with_a_record(self):
        payload = self.metadata()
        payload["raw_response_body"] = SECRET
        payload["cookie_header"] = COOKIE_VALUE
        result = self.redaction.project_metadata(payload)
        self.assertNotIn("raw_response_body", result["metadata"])
        self.assertNotIn("cookie_header", result["metadata"])
        self.assert_no_leak(result, SECRET, COOKIE_VALUE)
        reasons = {item["reason"] for item in result["records"]}
        self.assertIn("UNKNOWN_METADATA_KEY", reasons)
        self.assertIn("SENSITIVE_NAME", reasons)

    def test_metadata_values_are_scrubbed(self):
        payload = self.metadata()
        payload["content_type"] = f"text/html; note={SECRET}"
        result = self.redaction.project_metadata(payload)
        self.assert_no_leak(result, SECRET)

    def test_nested_values_are_collapsed_to_a_digest(self):
        payload = self.metadata()
        payload["content_length"] = {"nested": "dict with " + SECRET}
        result = self.redaction.project_metadata(payload)
        self.assert_no_leak(result, SECRET)
        self.assertTrue(result["records"])

    def test_summary_counts_are_present_and_sorted(self):
        payload = self.metadata()
        payload["unexpected_key"] = "x"
        result = self.redaction.project_metadata(payload)
        summary = result["summary"]
        self.assertEqual(summary["total"], len(result["records"]))
        self.assertEqual(list(summary["by_action"]), sorted(summary["by_action"]))
        self.assertEqual(list(summary["by_reason"]), sorted(summary["by_reason"]))

    def test_projection_is_idempotent(self):
        first = self.redaction.project_metadata(self.metadata())["metadata"]
        second = self.redaction.project_metadata(first)["metadata"]
        self.assertEqual(first, second)


class TestDeterminismAndPurity(RedactionTestCase):
    def test_repeated_runs_are_byte_identical(self):
        payload = {"status_code": 200, "server": "nginx", "weird": SECRET}
        headers = {"Set-Cookie": COOKIE_VALUE, "Server": "nginx"}
        first = json.dumps(
            [
                self.redaction.project_metadata(payload),
                self.redaction.redact_headers(headers, kind="response"),
                self.redaction.redact_url("https://a.test/x?token=" + SECRET),
            ],
            sort_keys=True,
        )
        second = json.dumps(
            [
                self.redaction.project_metadata(payload),
                self.redaction.redact_headers(headers, kind="response"),
                self.redaction.redact_url("https://a.test/x?token=" + SECRET),
            ],
            sort_keys=True,
        )
        self.assertEqual(first, second)

    def test_records_are_deterministically_ordered(self):
        headers = {"X-B": "1", "X-A": "2", "Set-Cookie": COOKIE_VALUE}
        _, records = self.redaction.redact_headers(headers, kind="response")
        self.assertEqual([item["field"] for item in records], sorted(item["field"] for item in records))

    def test_digest_is_stable_and_hex(self):
        self.assertEqual(self.redaction.digest("abc"), hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(self.redaction.digest("abc"), self.redaction.digest("abc"))

    def test_module_writes_nothing_and_imports_nothing_dangerous(self):
        source = REDACTION_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(
            imported
            & {
                "socket",
                "ssl",
                "http",
                "urllib",
                "subprocess",
                "shutil",
                "os",
                "pathlib",
                "tempfile",
                "requests",
                "ai",
                "backend",
            },
            set(),
        )
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)
        self.assertEqual(
            called & {"open", "write_text", "mkdir", "remove", "unlink", "system", "popen", "run"},
            set(),
        )

    def test_importing_the_module_creates_no_file(self):
        before = sorted(path.name for path in AEC_DIR.iterdir())
        load_module("watch_aec_redaction_probe", REDACTION_PATH)
        after = sorted(path.name for path in AEC_DIR.iterdir())
        self.assertEqual(before, after)

    def test_no_verdict_vocabulary_in_the_module(self):
        source = REDACTION_PATH.read_text(encoding="utf-8").upper()
        for forbidden in ("CONFIRMED", "EXPLOITABLE", "VULNERABLE", "SEVERITY"):
            self.assertNotIn(forbidden, source.replace("AEC-REDACTION", ""))


class TestAdversarialFixtures(RedactionTestCase):
    def test_kitchen_sink_never_leaks(self):
        headers = {
            "Set-Cookie": COOKIE_VALUE,
            "SET-COOKIE": COOKIE_VALUE,
            "set_cookie": COOKIE_VALUE,
            "Authorization": AUTH_VALUE,
            "  X-Api-Key  ": SECRET,
            "Server": "nginx",
            "X-Powered-By": f"PHP note={SECRET}",
            "Location": f"https://a.test/r?token={SECRET}",
        }
        payload = {
            "status_code": 302,
            "server": "nginx",
            "note": f"see {MONGO_URI} and {EMAIL}",
            "nested": {"deep": {"authorization": AUTH_VALUE}},
            "listy": ["a", SECRET, {"k": JWT}],
            "bytes": b"raw",
            "huge": "z" * 10000,
        }
        safe_headers, header_records = self.redaction.redact_headers(headers, kind="response")
        result = self.redaction.project_metadata(payload)
        url, url_records = self.redaction.redact_url(f"https://u:p@a.test/x?token={SECRET}#f")
        body = self.redaction.project_body(f"raw body {SECRET}")
        self.assert_no_leak(
            [safe_headers, result, url, body],
            SECRET,
            COOKIE_VALUE,
            AUTH_VALUE,
            JWT,
            EMAIL,
            "hunter2",
            "u:p@",
        )
        self.assertTrue(header_records and result["records"] and url_records)
        # Keys are canonicalised (lower-case) on purpose: matching must not depend
        # on header casings the transport happens to produce.
        self.assertIn("server", json.dumps(safe_headers, sort_keys=True))

    def test_repeated_projection_never_reintroduces_secrets(self):
        payload = {"server": f"nginx note={SECRET}"}
        once = self.redaction.project_metadata(payload)
        twice = self.redaction.project_metadata(once["metadata"])
        self.assert_no_leak(twice, SECRET)

    def test_records_contain_no_secret_values(self):
        payload = {"weird_key": SECRET, "server": f"n={SECRET}"}
        result = self.redaction.project_metadata(payload)
        self.assert_no_leak(result["records"], SECRET)

    def test_summary_helper_is_total(self):
        summary = self.redaction.redaction_summary([])
        self.assertEqual(summary["total"], 0)
        summary = self.redaction.redaction_summary(
            [{"field": "a", "action": "DROPPED", "reason": "NOT_ALLOWLISTED"}]
        )
        self.assertEqual(summary["by_action"], {"DROPPED": 1})


if __name__ == "__main__":
    unittest.main()
