import inspect
import json
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

import requests.exceptions

from ai.schemas.xss_verification import (
    AttemptStatus,
    VerificationMode,
    build_verification_attempt,
)
from ai.verification import http_executor as http_executor_module
from ai.verification.http_executor import HTTPEvidenceExecutor
from ai.verification.verifier import XSSVerifier
from ai.researcher.xss_orchestrator import (
    XSSAnalysisAudit,
    XSSAnalysisResult,
)
from ai.schemas.xss import (
    XSSAttributedValue,
    XSSCase,
    XSSContext,
    XSSResearchContext,
    XSSResearchLLMResult,
    XSSSuggestedPayload,
)

KNOWLEDGE_ID = "kb-1234567890abcde"
SOURCE_ID = "src-1234567890abcde"
ENDPOINT = "https://target.example.test/search"
PAYLOAD = "<img src=x onerror=alert(1)>"


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        body="",
        headers=None,
        encoding="utf-8",
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self.encoding = encoding
        self._body = body.encode(encoding)

    def iter_content(self, chunk_size=65536):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start : start + chunk_size]

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses, default_headers=None):
        self._responses = list(responses)
        self.headers = dict(default_headers or {})
        self.calls = []

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        timeout=None,
        allow_redirects=True,
        stream=False,
    ):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": dict(headers or {}),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
                "stream": stream,
            }
        )
        if not self._responses:
            raise AssertionError("unexpected extra HTTP call")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _attempt(**overrides):
    kwargs = dict(
        case_id="case-1",
        endpoint=ENDPOINT,
        method="GET",
        parameter="q",
        parameter_location="query",
        payload=PAYLOAD,
        payload_origin="knowledge",
        knowledge_ids=[KNOWLEDGE_ID],
        source_ids=[SOURCE_ID],
        based_on_pattern="marker",
        mode=VerificationMode.HTTP_REFLECTION,
        phase="http",
    )
    kwargs.update(overrides)
    return build_verification_attempt(**kwargs)


def _executor(responses, default_headers=None, **executor_kwargs):
    session = FakeSession(responses, default_headers=default_headers)
    return HTTPEvidenceExecutor(session=session, **executor_kwargs), session


def _bound_value(attempt):
    return f"{attempt.payload}~~{attempt.correlation_token}"


class HTTPEvidenceExecutorRequestTests(unittest.TestCase):
    def test_query_parameter_injection(self):
        attempt = _attempt()
        executor, session = _executor([FakeResponse(200, body="ok")])
        executor.execute(attempt)

        self.assertEqual(len(session.calls), 1)
        call = session.calls[0]
        self.assertEqual(call["method"], "GET")
        query = parse_qs(urlsplit(call["url"]).query)
        self.assertEqual(query["q"], [_bound_value(attempt)])

    def test_body_form_parameter_injection(self):
        attempt = _attempt(
            method="POST", parameter_location="body"
        )
        executor, session = _executor([FakeResponse(200, body="ok")])
        executor.execute(attempt)

        call = session.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(
            call["data"], {"q": _bound_value(attempt)}
        )
        self.assertEqual(
            call["headers"]["Content-Type"],
            "application/x-www-form-urlencoded",
        )

    def test_body_parameter_on_get_is_unsupported(self):
        attempt = _attempt(method="GET", parameter_location="body")
        executor, session = _executor([FakeResponse(200, body="ok")])
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertEqual(session.calls, [])

    def test_unsupported_parameter_locations_fail_explicitly(self):
        for location in ("header", "path", "cookie"):
            attempt = _attempt(parameter_location=location)
            executor, session = _executor(
                [FakeResponse(200, body="ok")]
            )
            evidence = executor.execute(attempt)
            self.assertEqual(
                evidence.attempt_status, AttemptStatus.ERROR
            )
            self.assertIn(
                "unsupported_parameter_location", evidence.error_reason
            )
            self.assertEqual(session.calls, [])

    def test_endpoint_without_http_scheme_is_unsupported(self):
        attempt = _attempt(endpoint="ftp://target.example.test/search")
        executor, _session = _executor([FakeResponse(200, body="ok")])
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("unsupported_endpoint_scheme", evidence.error_reason)

    def test_token_is_bound_into_same_input_value(self):
        attempt = _attempt()
        executor = HTTPEvidenceExecutor(
            session=FakeSession([FakeResponse(200, body="ok")])
        )
        self.assertEqual(
            executor.bound_input_value(attempt),
            f"{attempt.payload}~~{attempt.correlation_token}",
        )
        self.assertNotIn("~~", attempt.correlation_token)


class HTTPEvidenceExecutorReflectionTests(unittest.TestCase):
    @staticmethod
    def _reflect(attempt, body):
        executor, _session = _executor([FakeResponse(200, body=body)])
        return executor.execute(attempt)

    def test_exact_observed_token_match(self):
        attempt = _attempt()
        body = f"<p>hello {_bound_value(attempt)} world</p>"
        evidence = self._reflect(attempt, body)

        self.assertTrue(evidence.reflection.reflected)
        self.assertEqual(
            evidence.reflection.observed_correlation_token,
            attempt.correlation_token,
        )
        self.assertNotEqual(
            evidence.reflection.observed_correlation_token,
            attempt.correlation_token + "x",
        )
        self.assertLessEqual(len(evidence.reflection.context_before), 80)
        self.assertLessEqual(len(evidence.reflection.context_after), 80)

    def test_html_body_reflection(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt, f"<p>hello {_bound_value(attempt)} world</p>"
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_body"
        )
        self.assertEqual(evidence.waf_observations, [])

    def test_html_attribute_reflection(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt, f'<div class="{_bound_value(attempt)}">hi</div>'
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )

    def test_script_block_reflection(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt, f"<script>var s = {_bound_value(attempt)};</script>"
        )
        self.assertEqual(
            evidence.reflection.location.value, "script_block"
        )

    def test_javascript_string_reflection(self):
        attempt = _attempt()
        body = (
            "<script>var s = "
            f'"~~{attempt.correlation_token}"; '
            f'var p = "{PAYLOAD}";</script>'
        )
        executor, _session = _executor([FakeResponse(200, body=body)])
        evidence = executor.execute(attempt)
        self.assertEqual(
            evidence.reflection.location.value, "javascript_string"
        )

    def test_url_reflection(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            f'<a href="https://x.test/r?to={_bound_value(attempt)}">x</a>',
        )
        self.assertEqual(evidence.reflection.location.value, "url")

    def test_no_reflection(self):
        attempt = _attempt()
        evidence = self._reflect(attempt, "<p>nothing here</p>")
        self.assertFalse(evidence.reflection.reflected)
        self.assertEqual(evidence.reflection.location.value, "none")
        self.assertIsNone(
            evidence.reflection.observed_correlation_token
        )
        self.assertEqual(evidence.attempt_status, AttemptStatus.SUCCEEDED)

    def test_token_absent_but_payload_present_is_info_only(self):
        attempt = _attempt()
        body = f"<p>{PAYLOAD}</p>"
        executor, _session = _executor([FakeResponse(200, body=body)])
        evidence = executor.execute(attempt)

        self.assertFalse(evidence.reflection.reflected)
        self.assertEqual(
            [o.kind.value for o in evidence.waf_observations],
            ["info"],
        )
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )


class HTTPEvidenceExecutorTagContextTests(unittest.TestCase):
    """
    Regression tests for the tag-value state machine: while a
    quoted attribute value is open, '>', '=', and whitespace
    are literal value characters and must never terminate
    tag-context analysis.
    """

    @staticmethod
    def _reflect(attempt, body):
        executor, _session = _executor([FakeResponse(200, body=body)])
        return executor.execute(attempt)

    def test_quoted_attribute_containing_gt(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            "<div title=\"hello > world "
            f"{attempt.payload}~~{attempt.correlation_token}"
            '">x</div>',
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )

    def test_quoted_attribute_containing_equals(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            "<div title=\"a=b "
            f"{attempt.payload}~~{attempt.correlation_token}"
            '">x</div>',
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )

    def test_quoted_attribute_containing_whitespace(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            "<div title=\"a b c "
            f"{attempt.payload}~~{attempt.correlation_token}"
            '">x</div>',
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )

    def test_normal_quoted_attribute_reflection(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            f'<div class="{_bound_value(attempt)}">x</div>',
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )

    def test_unquoted_attribute_reflection(self):
        attempt = _attempt(payload="x")
        evidence = self._reflect(
            attempt,
            f"<div class=x~~{attempt.correlation_token}>y</div>",
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )
        self.assertEqual(
            evidence.reflection.observed_correlation_token,
            attempt.correlation_token,
        )

    def test_quoted_value_then_second_attribute_then_token(self):
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            "<div title=\"a > b\" class=\""
            f"{attempt.payload}~~{attempt.correlation_token}"
            '">x</div>',
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_attribute"
        )

    def test_token_after_tag_close_is_html_body(self):
        # The '>' after the closed quoted value ends the tag;
        # a token in the element text is HTML_BODY, not an
        # attribute reflection.
        attempt = _attempt()
        evidence = self._reflect(
            attempt,
            '<div title="hello > world">'
            f"~~{attempt.correlation_token}</div>",
        )
        self.assertEqual(
            evidence.reflection.location.value, "html_body"
        )


class HTTPEvidenceExecutorWAFTests(unittest.TestCase):
    def test_waf_block_on_403(self):
        attempt = _attempt()
        executor, _session = _executor(
            [FakeResponse(403, body="forbidden")]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(
            evidence.attempt_status, AttemptStatus.WAF_BLOCKED
        )
        self.assertEqual(len(evidence.waf_observations), 1)
        self.assertEqual(
            evidence.waf_observations[0].kind.value, "block"
        )
        self.assertEqual(
            evidence.waf_observations[0].note, "http_status_403"
        )
        self.assertFalse(evidence.reflection.reflected)

    def test_waf_block_on_406(self):
        attempt = _attempt()
        executor, _session = _executor([FakeResponse(406, body="")])
        evidence = executor.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.WAF_BLOCKED
        )

    def test_waf_transform_when_payload_absent_token_present(self):
        attempt = _attempt()
        body = f"<p>echo: ~~{attempt.correlation_token}</p>"
        executor, _session = _executor([FakeResponse(200, body=body)])
        evidence = executor.execute(attempt)

        self.assertEqual(
            evidence.attempt_status, AttemptStatus.WAF_TRANSFORMED
        )
        self.assertEqual(
            [o.kind.value for o in evidence.waf_observations],
            ["transform"],
        )
        self.assertIn(
            "payload_bytes_absent_token_present",
            evidence.waf_observations[0].note,
        )

    def test_amp_preserving_url_encoded_escaped_form_is_intact(self):
        # A server that echoes a reconstructed query string
        # percent-encodes the value while leaving the '&'
        # separator intact, then HTML-escapes the echo. This
        # echo form must count as intact transit, not as a WAF
        # transformation.
        attempt = _attempt(payload="a&b<c>d")
        echo = f"a&amp;b%3Cc%3Ed~~{attempt.correlation_token}"
        executor, _session = _executor(
            [FakeResponse(200, body=f"<p>{echo}</p>")]
        )
        evidence = executor.execute(attempt)

        self.assertTrue(evidence.reflection.reflected)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertEqual(evidence.waf_observations, [])

    def test_waf_info_for_csp_header(self):
        attempt = _attempt()
        body = f"<p>{_bound_value(attempt)}</p>"
        executor, _session = _executor(
            [
                FakeResponse(
                    200,
                    body=body,
                    headers={"Content-Security-Policy": "default-src 'self'"},
                )
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertEqual(
            [o.kind.value for o in evidence.waf_observations],
            ["info"],
        )
        self.assertEqual(
            evidence.waf_observations[0].note, "csp_header_present"
        )

    def test_suspicious_looking_200_without_signals_is_not_blocked(self):
        attempt = _attempt()
        executor, _session = _executor(
            [FakeResponse(200, body="denied blocked suspicious")]
        )
        evidence = executor.execute(attempt)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )
        self.assertEqual(evidence.waf_observations, [])


class HTTPEvidenceExecutorFailureTests(unittest.TestCase):
    def test_timeout_returns_timeout_evidence(self):
        attempt = _attempt()
        executor, _session = _executor(
            [requests.exceptions.Timeout("read timed out")]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.TIMEOUT)
        self.assertEqual(evidence.response_status, None)

    def test_connection_failure_returns_error_evidence(self):
        attempt = _attempt()
        executor, _session = _executor(
            [requests.exceptions.ConnectionError("connection refused")]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("ConnectionError", evidence.error_reason)
        self.assertIn("connection refused", evidence.error_reason)

    def test_http_error_returns_failed_evidence(self):
        attempt = _attempt()
        executor, _session = _executor([FakeResponse(500, body="boom")])
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.FAILED)
        self.assertEqual(evidence.response_status, 500)
        self.assertEqual(evidence.error_reason, "http_status_500")

    def test_unexpected_crash_never_yields_succeeded(self):
        attempt = _attempt()

        class ExplodingSession(FakeSession):
            def request(self, *args, **kwargs):
                raise ValueError("unexpected internal state")

        executor = HTTPEvidenceExecutor(session=ExplodingSession([]))
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)


class HTTPEvidenceExecutorRedactionTests(unittest.TestCase):
    def test_request_and_response_header_redaction(self):
        attempt = _attempt()
        executor, _session = _executor(
            [
                FakeResponse(
                    200,
                    body="ok",
                    headers={
                        "Set-Cookie": "session=resp-secret",
                        "X-Custom": "1",
                    },
                )
            ],
            default_headers={
                "Cookie": "sid=req-secret",
                "Authorization": "Bearer req-secret-2",
                "Accept": "*/*",
            },
        )
        evidence = executor.execute(attempt)

        self.assertEqual(
            evidence.request_headers_redacted["Cookie"],
            "[REDACTED]",
        )
        self.assertEqual(
            evidence.request_headers_redacted["Authorization"],
            "[REDACTED]",
        )
        self.assertEqual(
            evidence.request_headers_redacted["Accept"], "*/*"
        )
        self.assertEqual(
            evidence.response_headers_redacted["Set-Cookie"],
            "[REDACTED]",
        )
        self.assertEqual(
            evidence.response_headers_redacted["X-Custom"], "1"
        )
        dumped = json.dumps(evidence.model_dump())
        self.assertNotIn("req-secret", dumped)
        self.assertNotIn("resp-secret", dumped)

    def test_error_reason_scrubs_sensitive_header_values(self):
        attempt = _attempt()

        class AuthedFailingSession(FakeSession):
            def request(self, *args, **kwargs):
                raise ValueError(
                    "header trace: sid=req-secret Bearer req-secret-2"
                )

        executor = HTTPEvidenceExecutor(
            session=AuthedFailingSession(
                [],
                default_headers={
                    "Cookie": "sid=req-secret",
                    "Authorization": "Bearer req-secret-2",
                },
            )
        )
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertNotIn("req-secret", evidence.error_reason)
        self.assertIn("[REDACTED]", evidence.error_reason)


class HTTPEvidenceExecutorRedirectTests(unittest.TestCase):
    def test_same_host_redirect_is_followed(self):
        attempt = _attempt()
        executor, session = _executor(
            [
                FakeResponse(
                    302,
                    body=f"intermediate ~~{attempt.correlation_token}",
                    headers={"Location": "/final"},
                ),
                FakeResponse(200, body="<p>final clean page</p>"),
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(len(session.calls), 2)
        self.assertTrue(session.calls[1]["url"].endswith("/final"))
        self.assertFalse(evidence.reflection.reflected)
        self.assertEqual(
            evidence.attempt_status, AttemptStatus.SUCCEEDED
        )

    def test_reflection_only_from_final_response(self):
        attempt = _attempt()
        executor, _session = _executor(
            [
                FakeResponse(
                    302,
                    body="hop",
                    headers={"Location": "/final"},
                ),
                FakeResponse(200, body=f"<p>{_bound_value(attempt)}</p>"),
            ]
        )
        evidence = executor.execute(attempt)
        self.assertTrue(evidence.reflection.reflected)
        self.assertEqual(
            evidence.reflection.observed_correlation_token,
            attempt.correlation_token,
        )

    def test_cross_host_redirect_rejected(self):
        attempt = _attempt()
        executor, session = _executor(
            [
                FakeResponse(
                    302,
                    body="hop",
                    headers={"Location": "https://evil.example.test/x"},
                ),
                FakeResponse(200, body="should not be reached"),
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("cross_host_redirect_rejected", evidence.error_reason)
        self.assertEqual(len(session.calls), 1)

    def test_https_to_http_downgrade_rejected(self):
        attempt = _attempt()
        executor, _session = _executor(
            [
                FakeResponse(
                    302,
                    body="hop",
                    headers={"Location": "http://target.example.test/final"},
                ),
            ]
        )
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("scheme_downgrade", evidence.error_reason)

    def test_same_host_redirect_cycle_rejected(self):
        attempt = _attempt()
        executor, session = _executor(
            [
                FakeResponse(302, body="hop", headers={"Location": "/a"}),
                FakeResponse(302, body="hop", headers={"Location": "/b"}),
                FakeResponse(302, body="hop", headers={"Location": "/a"}),
                FakeResponse(200, body="cycle escaped"),
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("redirect_cycle_detected", evidence.error_reason)
        # The third request (back to /a) must never be issued.
        self.assertEqual(len(session.calls), 3)

    def test_self_redirect_rejected(self):
        attempt = _attempt()
        value = _bound_value(attempt)
        location = "/search?" + urlencode({"q": value})
        executor, session = _executor(
            [
                FakeResponse(302, body="hop", headers={"Location": location}),
                FakeResponse(200, body="should not be reached"),
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("redirect_cycle_detected", evidence.error_reason)
        self.assertEqual(len(session.calls), 1)

    def test_max_redirects_enforced_for_non_cyclic_chain(self):
        attempt = _attempt()
        executor, session = _executor(
            [
                FakeResponse(
                    302,
                    body="hop",
                    headers={"Location": f"/hop{index}"},
                )
                for index in range(10)
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("redirect_limit_exceeded", evidence.error_reason)
        self.assertEqual(len(session.calls), 6)

    def test_redirect_without_location_rejected(self):
        attempt = _attempt()
        executor, _session = _executor(
            [FakeResponse(302, body="hop", headers={})]
        )
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("redirect_without_location", evidence.error_reason)

    def test_repeated_location_is_detected_as_cycle(self):
        # A redirect chain that repeats the same Location is a
        # cycle: rejected before the repeated request is
        # re-issued, independently of max_redirects.
        attempt = _attempt()
        executor, session = _executor(
            [
                FakeResponse(302, body="hop", headers={"Location": "/next"})
                for _ in range(10)
            ]
        )
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("redirect_cycle_detected", evidence.error_reason)
        self.assertEqual(len(session.calls), 2)
class HTTPEvidenceExecutorBoundsTests(unittest.TestCase):
    def test_response_body_size_bounded(self):
        attempt = _attempt()
        body = "A" * 10 + attempt.correlation_token + "B" * 2000
        executor, _session = _executor(
            [FakeResponse(200, body=body)], max_body_bytes=50
        )
        evidence = executor.execute(attempt)

        self.assertLessEqual(
            len(evidence.response_body_truncated), 50
        )
        self.assertTrue(evidence.reflection.reflected)

    def test_token_beyond_capture_bound_is_not_observed(self):
        attempt = _attempt()
        body = "A" * 500 + attempt.correlation_token
        executor, _session = _executor(
            [FakeResponse(200, body=body)], max_body_bytes=100
        )
        evidence = executor.execute(attempt)
        self.assertFalse(evidence.reflection.reflected)


class HTTPEvidenceExecutorBindingTests(unittest.TestCase):
    def test_success_evidence_binds_to_attempt(self):
        attempt = _attempt()
        executor, _session = _executor([FakeResponse(200, body="ok")])
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_id, attempt.attempt_id)
        self.assertEqual(evidence.request_url, attempt.endpoint)
        self.assertEqual(evidence.request_method, attempt.method)

    def test_error_evidence_binds_to_attempt(self):
        attempt = _attempt()
        executor, _session = _executor(
            [
                FakeResponse(
                    302,
                    body="hop",
                    headers={"Location": "https://evil.example.test/x"},
                ),
            ]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_id, attempt.attempt_id)
        self.assertEqual(evidence.request_url, attempt.endpoint)
        self.assertEqual(evidence.request_method, attempt.method)

    def test_identifiers_are_never_rewritten(self):
        attempt = _attempt()
        executor, _session = _executor(
            [FakeResponse(200, body=f"<p>{_bound_value(attempt)}</p>")]
        )
        evidence = executor.execute(attempt)
        self.assertEqual(evidence.attempt_id, attempt.attempt_id)
        self.assertEqual(
            evidence.reflection.observed_correlation_token,
            attempt.correlation_token,
        )


class HTTPEvidenceExecutorRoleTests(unittest.TestCase):
    def test_executor_module_never_names_security_verdicts(self):
        source = inspect.getsource(http_executor_module)
        for banned in ("CONFIRMED", "POTENTIAL", "NOT_VULNERABLE"):
            self.assertNotIn(banned, source)

    def test_evidence_schema_has_no_verdict_field(self):
        from ai.schemas.xss_verification import VerificationEvidence

        fields = VerificationEvidence.model_fields
        self.assertFalse(
            [name for name in fields if "verdict" in name]
        )

    def test_browser_mode_never_touches_network(self):
        attempt = _attempt(mode=VerificationMode.BROWSER_EXECUTION)
        executor, session = _executor(
            [FakeResponse(200, body="should not be fetched")]
        )
        evidence = executor.execute(attempt)

        self.assertEqual(evidence.attempt_status, AttemptStatus.ERROR)
        self.assertIn("mode_not_supported", evidence.error_reason)
        self.assertEqual(session.calls, [])

    def test_all_emitted_statuses_are_transport_statuses(self):
        allowed = {status.value for status in AttemptStatus}
        scenarios = [
            [FakeResponse(200, body="ok")],
            [FakeResponse(403, body="no")],
            [FakeResponse(500, body="no")],
            [requests.exceptions.Timeout("t")],
            [requests.exceptions.ConnectionError("c")],
        ]
        for responses in scenarios:
            attempt = _attempt()
            executor, _session = _executor(responses)
            evidence = executor.execute(attempt)
            self.assertIn(evidence.attempt_status.value, allowed)


class HTTPEvidenceExecutorDeterminismTests(unittest.TestCase):
    def test_identical_mocked_responses_yield_identical_evidence(self):
        attempt = _attempt()
        body = f'<div class="{_bound_value(attempt)}">hi</div>'

        def run():
            executor, _session = _executor(
                [
                    FakeResponse(
                        200,
                        body=body,
                        headers={"Content-Security-Policy": "x"},
                    )
                ]
            )
            return executor.execute(attempt)

        first = run().model_dump(exclude={"started_at", "finished_at"})
        second = run().model_dump(exclude={"started_at", "finished_at"})
        self.assertEqual(first, second)


class HTTPEvidenceExecutorVerifierIntegrationTests(unittest.TestCase):
    def _analysis(self):
        case = XSSCase(
            case_id="case-1",
            target="https://target.example.test",
            endpoint=ENDPOINT,
            method="GET",
            parameter="q",
            parameter_location="query",
            xss_type="reflected",
            context=XSSContext(
                type="html_attribute",
                attribute_name="class",
                attribute_quoted=True,
            ),
            source_type="endpoint",
        )
        llm = XSSResearchLLMResult(
            case_id="case-1",
            case_status_suggestion="ANALYZED",
            suggested_payloads=[
                XSSSuggestedPayload(
                    pattern=PAYLOAD,
                    origin="knowledge",
                    knowledge_ids=[KNOWLEDGE_ID],
                    source_ids=[SOURCE_ID],
                    based_on_pattern="marker",
                    rationale="kb adapted",
                )
            ],
            verification_ideas=[],
            context_observations=[],
            next_research_questions=[],
            evidence=["SECONDARY: stub"],
        )
        context = XSSResearchContext(
            case_id="case-1",
            retrieved_knowledge_ids=[KNOWLEDGE_ID],
            documents=[],
            payload_patterns=[
                XSSAttributedValue(
                    value="marker", source_ids=[SOURCE_ID]
                )
            ],
        )
        return XSSAnalysisResult(
            case=case,
            context=context,
            llm_result=llm,
            stage="ANALYZED",
            audit=XSSAnalysisAudit(
                retrieval_call_count=1,
                llm_call_count=1,
                retrieved_knowledge_ids=[KNOWLEDGE_ID],
                retrieval_had_results=True,
                had_payload_suggestions=True,
                had_verification_ideas=False,
                had_any_knowledge_derived_suggestion=True,
                had_any_model_generated_suggestion=False,
                llm_case_status_suggestion="ANALYZED",
                notes=[],
            ),
        )

    def test_http_reflection_alone_can_only_be_potential(self):
        analysis = self._analysis()
        attempt_like = build_verification_attempt(
            case_id=analysis.case.case_id,
            endpoint=analysis.case.endpoint,
            method=analysis.case.method,
            parameter=analysis.case.parameter,
            parameter_location=analysis.case.parameter_location,
            payload=PAYLOAD,
            payload_origin="knowledge",
            knowledge_ids=[KNOWLEDGE_ID],
            source_ids=[SOURCE_ID],
            based_on_pattern="marker",
            mode=VerificationMode.HTTP_REFLECTION,
            phase="http",
        )
        body = f'<div class="{_bound_value(attempt_like)}">hi</div>'
        session = FakeSession([FakeResponse(200, body=body)])
        result = XSSVerifier(
            HTTPEvidenceExecutor(session=session)
        ).verify(analysis)

        statuses = sorted(f.status for f in result.findings)
        self.assertEqual(statuses, ["POTENTIAL"])
        self.assertNotIn("CONFIRMED", statuses)


if __name__ == "__main__":
    unittest.main()
