"""EPIC13 §6/§11 — controlled request construction tests."""
from __future__ import annotations

import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, SCOPE_REF, TARGET_URL, marker_for_action)

from backend.research_agents.verification.acquisition import (  # noqa: E402
    markers as mk, requests as rq, transport as tr)

MARKER = marker_for_action()


def ref(url: str = TARGET_URL, parameter: str = "q", method: str = "GET",
        location: str = "query") -> rq.ParameterRef:
    return rq.ParameterRef(url=url, parameter=parameter, method=method,
                           location=location)


def build(**overrides):
    kwargs = {"action_id": "act-epic13-1", "parameter_ref": ref(),
              "marker": MARKER, "scope_ref": SCOPE_REF,
              "authorization_id": AUTH_ID}
    kwargs.update(overrides)
    return rq.build_request(**kwargs)


class TestQueryRewrite(unittest.TestCase):
    def test_target_parameter_is_replaced(self):
        out = rq.rewrite_query(TARGET_URL, "q", MARKER)
        self.assertIn(f"q={MARKER}", out)

    def test_unrelated_parameter_is_preserved_verbatim(self):
        out = rq.rewrite_query(TARGET_URL, "q", MARKER)
        self.assertIn("page=2", out)

    def test_original_value_is_gone(self):
        out = rq.rewrite_query(TARGET_URL, "q", MARKER)
        self.assertNotIn("q=test", out)

    def test_scheme_host_and_path_are_preserved(self):
        out = rq.rewrite_query(TARGET_URL, "q", MARKER)
        self.assertTrue(out.startswith("https://www.dell.com/support/search?"))

    def test_port_is_preserved(self):
        out = rq.rewrite_query("https://www.dell.com:8443/a?q=1", "q", MARKER)
        self.assertIn(":8443", out)

    def test_fragment_is_preserved(self):
        out = rq.rewrite_query("https://www.dell.com/a?q=1#frag", "q", MARKER)
        self.assertTrue(out.endswith("#frag"))

    def test_duplicate_parameter_names_are_all_replaced(self):
        out = rq.rewrite_query("https://www.dell.com/a?q=1&q=2", "q", MARKER)
        self.assertEqual(out.count(MARKER), 2)

    def test_blank_parameter_value_is_replaced(self):
        out = rq.rewrite_query("https://www.dell.com/a?q=", "q", MARKER)
        self.assertIn(f"q={MARKER}", out)

    def test_other_parameters_keep_their_encoding(self):
        url = "https://www.dell.com/a?q=1&next=a%2Fb+c&page=2"
        out = rq.rewrite_query(url, "q", MARKER)
        self.assertIn("next=a%2Fb+c", out)

    def test_parameter_without_separator_is_handled(self):
        out = rq.rewrite_query("https://www.dell.com/a?q&page=2", "q", MARKER)
        self.assertIn(MARKER, out)
        self.assertIn("page=2", out)

    def test_missing_parameter_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            rq.rewrite_query("https://www.dell.com/a?other=1", "q", MARKER)
        self.assertEqual(caught.exception.reason,
                         rq.REASON_PARAMETER_MISSING)

    def test_empty_query_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.rewrite_query("https://www.dell.com/a", "q", MARKER)

    def test_no_parameter_is_added_when_absent(self):
        with self.assertRaises(rq.RequestError):
            rq.rewrite_query("https://www.dell.com/a?x=1", "q", MARKER)


class TestRequestConstruction(unittest.TestCase):
    def test_built_request_uses_get(self):
        self.assertEqual(build().method, "GET")

    def test_built_request_carries_the_marker(self):
        self.assertEqual(build().marker, MARKER)

    def test_built_request_carries_the_action_id(self):
        self.assertEqual(build().action_id, "act-epic13-1")

    def test_built_request_carries_the_authorization_id(self):
        self.assertEqual(build().authorization_id, AUTH_ID)

    def test_built_request_carries_the_scope_ref(self):
        self.assertEqual(build().scope_ref, SCOPE_REF)

    def test_built_request_carries_the_parameter(self):
        self.assertEqual(build().parameter, "q")

    def test_built_request_timeout_is_bounded(self):
        self.assertLessEqual(build().timeout_seconds, 10)

    def test_built_request_byte_limit_is_bounded(self):
        self.assertLessEqual(build().max_bytes, 8192)

    def test_built_request_follows_no_redirect_by_default(self):
        self.assertEqual(build().max_redirects, 0)

    def test_built_request_sends_no_headers(self):
        self.assertFalse(dict(build().headers or {}))

    def test_built_url_preserves_unrelated_parameters(self):
        self.assertIn("page=2", build().url)


class TestRequestRefusals(unittest.TestCase):
    def test_out_of_scope_target_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref("https://evil.test/a?q=1"))
        self.assertEqual(caught.exception.reason, rq.REASON_OUT_OF_SCOPE)

    def test_sibling_host_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref("https://www.dell.com.evil.test/a?q=1"))
        self.assertEqual(caught.exception.reason, rq.REASON_OUT_OF_SCOPE)

    def test_plain_http_scheme_is_accepted_only_in_scope(self):
        with self.assertRaises(rq.RequestError):
            build(parameter_ref=ref("ftp://www.dell.com/a?q=1"))

    def test_file_scheme_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref("file:///etc/passwd?q=1"))
        self.assertEqual(caught.exception.reason, rq.REASON_BAD_SCHEME)

    def test_url_credentials_are_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref("https://u:p@www.dell.com/a?q=1"))
        self.assertEqual(caught.exception.reason, rq.REASON_USERINFO)

    def test_method_escalation_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref(method="GET"), method="POST")
        self.assertEqual(caught.exception.reason, rq.REASON_METHOD)

    def test_arbitrary_method_is_refused(self):
        with self.assertRaises(rq.RequestError):
            build(parameter_ref=ref(method="DELETE"), method="DELETE")

    def test_trace_method_is_refused(self):
        with self.assertRaises(rq.RequestError):
            build(parameter_ref=ref(method="TRACE"), method="TRACE")

    def test_non_query_parameter_location_is_refused(self):
        with self.assertRaises(rq.RequestError):
            build(parameter_ref=ref(location="body"))

    def test_missing_url_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref(url=""))
        self.assertEqual(caught.exception.reason, rq.REASON_NO_URL)

    def test_non_inert_marker_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            build(marker="HERMES_REFLECT_AB12CD34EF56<script>")

    def test_empty_marker_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            build(marker="")

    def test_secret_shaped_query_is_refused(self):
        url = ("https://www.dell.com/a?q=1&access_token="
               "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N")
        with self.assertRaises(rq.RequestError) as caught:
            build(parameter_ref=ref(url))
        self.assertEqual(caught.exception.reason, rq.REASON_SECRET_SHAPE)


class TestRequestAuditSafety(unittest.TestCase):
    def test_request_line_has_no_credentials(self):
        request = build(parameter_ref=ref("https://www.dell.com/a?q=1"))
        line = rq.request_line(request)
        self.assertNotIn("@", line)
        self.assertIn("marker=", line)

    def test_request_line_is_bounded(self):
        line = rq.request_line(build())
        self.assertLessEqual(len(line), 400)

    def test_request_document_declares_the_rule_version(self):
        self.assertEqual(rq.request_document()["rule_version"],
                         rq.REQUEST_RULE_VERSION)

    def test_request_document_declares_no_credentials(self):
        document = rq.request_document()
        self.assertIn("add credentials", document["never"])

    def test_request_document_declares_no_method_change(self):
        document = rq.request_document()
        self.assertIn("change the method", document["never"])

    def test_request_document_declares_no_added_parameters(self):
        document = rq.request_document()
        self.assertIn("add parameters", document["never"])

    def test_request_document_publishes_every_refusal(self):
        document = rq.request_document()
        for reason in (rq.REASON_OUT_OF_SCOPE, rq.REASON_USERINFO,
                       rq.REASON_SECRET_SHAPE, rq.REASON_METHOD):
            self.assertIn(reason, document["refusals"])

    def test_request_document_states_what_is_preserved(self):
        document = rq.request_document()
        self.assertIn("path", document["preserved"])
        self.assertIn("port", document["preserved"])

    def test_allowed_methods_are_a_small_closed_set(self):
        self.assertLessEqual(len(tr.ALLOWED_METHODS), 3)
        self.assertIn("GET", tr.ALLOWED_METHODS)

    def test_post_is_not_an_allowed_method(self):
        self.assertNotIn("POST", tr.ALLOWED_METHODS)


if __name__ == "__main__":
    unittest.main()
