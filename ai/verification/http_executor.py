from __future__ import annotations

import html as _html
import re
from typing import Mapping
from urllib.parse import (
    parse_qsl,
    quote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from ai.schemas.xss_verification import (
    AttemptStatus,
    ReflectionLocation,
    ReflectionObservation,
    VerificationAttempt,
    VerificationEvidence,
    VerificationMode,
    WAFObservation,
    WAFObservationKind,
)

try:
    import requests
    import requests.exceptions
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]


_TOKEN_SEPARATOR = "~~"

_REQUEST_SENSITIVE_HEADERS = frozenset(
    {"cookie", "authorization", "proxy-authorization"}
)
_RESPONSE_SENSITIVE_HEADERS = frozenset(
    {"set-cookie", "www-authenticate", "proxy-authenticate"}
)
_REDACTED_PLACEHOLDER = "[REDACTED]"

_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

_CHUNK_SIZE = 65536
_ERROR_REASON_LIMIT = 200
_CONTEXT_LIMIT = 80

_URL_ATTRIBUTE_NAMES = frozenset(
    {
        "href",
        "src",
        "action",
        "formaction",
        "data",
        "poster",
        "cite",
        "background",
        "longdesc",
        "usemap",
        "manifest",
        "codebase",
        "archive",
        "profile",
        "classid",
        "xlink:href",
        "xml:base",
    }
)

_WAF_VENDOR_HEADER_HINTS = (
    "cloudflare",
    "akamai",
    "sucuri",
    "incapsula",
    "imperva",
)

_SCRIPT_OPEN_RE = re.compile(r"<script\b", re.IGNORECASE)
_SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)
_TAG_OPEN_RE = re.compile(r"<")
_ATTR_NAME_BEFORE_EQ_RE = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_.:-]*)\s*$"
)


class _UnsupportedRequest(Exception):
    """The attempt cannot be turned into a safe deterministic request."""


class _VerificationError(Exception):
    """The transport interaction violated the executor's safety policy."""


class _TransportTimeout(Exception):
    """The HTTP interaction timed out."""


class _TransportError(Exception):
    """The HTTP interaction failed at the transport layer."""


def _sanitize_reason(
    exc: BaseException,
    sensitive_values: tuple[str, ...] = (),
) -> str:
    text = f"{type(exc).__name__}: {exc}"
    for value in sensitive_values:
        if value:
            text = text.replace(value, _REDACTED_PLACEHOLDER)
    return text[:_ERROR_REASON_LIMIT]


def _redact(
    headers: Mapping[str, str],
    sensitive_names: frozenset[str],
) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in sensitive_names:
            redacted[name] = _REDACTED_PLACEHOLDER
        else:
            redacted[name] = value
    return redacted


def _session_default_headers(session) -> dict[str, str]:
    headers = getattr(session, "headers", None)
    if not headers:
        return {}
    return {str(name): str(value) for name, value in headers.items()}


class HTTPEvidenceExecutor:
    """
    The real network-facing :class:`VerificationExecutor`.

    Security contract: this executor is an EVIDENCE PROVIDER,
    never a verdict authority. It issues the HTTP request a
    :class:`VerificationAttempt` describes, observes the raw
    response, and reports structured evidence. It never
    emits security verdict labels (the verifier's status
    vocabulary is absent from this module by test-enforced
    invariant), never interprets LLM output, never fabricates
    browser or stored-phase evidence, and never rewrites
    identifiers to make evidence bind. ``XSSVerifier`` remains
    the sole classification authority and treats this
    executor's output as untrusted input.

    Correlation-token binding: the token is concatenated into
    the SAME input value that carries the payload
    (``payload + TOKEN_SEPARATOR + token``). The token is
    derived deterministically from the attempt and uses only
    URL-safe characters, so it survives query/form transport
    byte-identically. Reflection of the token therefore
    evidences that the tested input containing the payload
    reached the reflection surface. The token is never
    altered, and ``observed_correlation_token`` is recorded
    only as the literal response substring; it is never
    normalised, decoded, or transformed to force a match.

    Verifier binding note: ``XSSVerifier._enforce_evidence_binding``
    compares ``evidence.request_url`` to ``attempt.endpoint``
    exactly, so ``request_url`` echoes the endpoint verbatim.
    The fully constructed request URL (with the injected
    parameter) is used only for the transport call.
    """

    DEFAULT_TIMEOUT_SECONDS = 10.0
    DEFAULT_MAX_REDIRECTS = 5
    DEFAULT_MAX_BODY_BYTES = 512 * 1024
    WAF_BLOCK_STATUS_CODES = frozenset({403, 406})

    def __init__(
        self,
        *,
        session=None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        if requests is None:  # pragma: no cover
            raise RuntimeError(
                "HTTPEvidenceExecutor requires the 'requests' library"
            )
        if session is None:
            session = requests.Session()
        self.session = session
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes

    # ------------------------------------------------------------------
    # Protocol entry point
    # ------------------------------------------------------------------

    def execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        """
        Execute one attempt and return structured evidence.

        Every failure path returns structured evidence bound
        to the attempt. An exception can never become
        SUCCEEDED evidence.
        """

        try:
            return self._execute(attempt)
        except Exception as exc:  # noqa: BLE001
            return self._error_evidence(
                attempt,
                _sanitize_reason(exc),
                AttemptStatus.ERROR,
            )

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------

    def bound_input_value(
        self, attempt: VerificationAttempt
    ) -> str:
        """
        The single input value sent for the attempt: the
        payload and the correlation token concatenated so
        they travel as one verification input.
        """

        return (
            f"{attempt.payload}"
            f"{_TOKEN_SEPARATOR}"
            f"{attempt.correlation_token}"
        )

    def _build_request(
        self, attempt: VerificationAttempt
    ) -> tuple[str, str, dict[str, str] | None, dict[str, str]]:
        parts = urlsplit(attempt.endpoint)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise _UnsupportedRequest(
                f"unsupported_endpoint_scheme:{parts.scheme!r}"
            )

        method = attempt.method.upper()
        value = self.bound_input_value(attempt)
        location = (attempt.parameter_location or "").strip().lower()

        if location in ("body", "form"):
            if method in ("GET", "HEAD"):
                raise _UnsupportedRequest(
                    "body_parameter_location_requires_body_method"
                )
            if not attempt.parameter:
                raise _UnsupportedRequest(
                    "body_parameter_requires_parameter_name"
                )
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            return (
                method,
                attempt.endpoint,
                {attempt.parameter: value},
                headers,
            )

        if location == "query":
            if not attempt.parameter:
                raise _UnsupportedRequest(
                    "query_parameter_requires_parameter_name"
                )
            return (
                method,
                self._build_query_url(
                    attempt.endpoint, attempt.parameter, value
                ),
                None,
                {},
            )

        raise _UnsupportedRequest(
            f"unsupported_parameter_location:{location!r}"
        )

    @staticmethod
    def _build_query_url(
        endpoint: str, parameter: str, value: str
    ) -> str:
        parts = urlsplit(endpoint)
        pairs = [
            (name, existing)
            for name, existing in parse_qsl(
                parts.query, keep_blank_values=True
            )
            if name != parameter
        ]
        pairs.append((parameter, value))
        return urlunsplit(parts._replace(query=urlencode(pairs)))

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _send_following_redirects(
        self,
        method: str,
        url: str,
        data: dict[str, str] | None,
        headers: dict[str, str],
        sensitive_values: tuple[str, ...],
    ) -> tuple[object, str]:
        current_method = method
        current_url = url
        current_data = data
        # Every issued request URL, including the initial one.
        # A redirect back to any visited URL is a cycle and is
        # rejected before another request is issued;
        # max_redirects remains an independent upper bound for
        # non-cyclic chains of distinct URLs.
        visited = {current_url}

        for _hop in range(self.max_redirects + 1):
            try:
                response = self.session.request(
                    current_method,
                    current_url,
                    data=current_data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.exceptions.Timeout as exc:
                raise _TransportTimeout(
                    _sanitize_reason(exc, sensitive_values)
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise _TransportError(
                    _sanitize_reason(exc, sensitive_values)
                ) from exc
            except Exception as exc:  # noqa: BLE001
                raise _TransportError(
                    _sanitize_reason(exc, sensitive_values)
                ) from exc

            if response.status_code not in _REDIRECT_STATUS_CODES:
                return response, current_url

            location = response.headers.get("Location")
            self._close(response)
            if not location:
                raise _VerificationError(
                    "redirect_without_location:"
                    f"http_status_{response.status_code}"
                )
            next_url = urljoin(current_url, location)
            if next_url in visited:
                raise _VerificationError("redirect_cycle_detected")
            self._check_redirect_safety(current_url, next_url)
            visited.add(next_url)
            current_method, current_data = self._redirect_method(
                current_method, response.status_code, current_data
            )
            current_url = next_url

        raise _VerificationError("redirect_limit_exceeded")

    @staticmethod
    def _redirect_method(
        method: str,
        status_code: int,
        data: dict[str, str] | None,
    ) -> tuple[str, dict[str, str] | None]:
        if status_code == 303:
            return "GET", None
        if status_code in (301, 302) and method in (
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ):
            return "GET", None
        return method, data

    @staticmethod
    def _check_redirect_safety(current_url: str, next_url: str) -> None:
        current = urlsplit(current_url)
        target = urlsplit(next_url)
        if (current.hostname or "").lower() != (
            target.hostname or ""
        ).lower():
            raise _VerificationError(
                "cross_host_redirect_rejected:"
                f"{(target.hostname or '').lower()}"
            )
        if (current.port or "") != (target.port or ""):
            raise _VerificationError("cross_port_redirect_rejected")
        if current.scheme == "https" and target.scheme != "https":
            raise _VerificationError("scheme_downgrade_redirect_rejected")
        if target.scheme not in ("http", "https"):
            raise _VerificationError(
                f"unsupported_redirect_scheme:{target.scheme!r}"
            )

    def _read_bounded_body(self, response) -> str:
        buffer = bytearray()
        for chunk in response.iter_content(chunk_size=_CHUNK_SIZE):
            buffer.extend(chunk)
            if len(buffer) >= self.max_body_bytes:
                del buffer[self.max_body_bytes :]
                break
        self._close(response)
        encoding = getattr(response, "encoding", None) or "utf-8"
        return bytes(buffer).decode(encoding, errors="replace")

    @staticmethod
    def _close(response) -> None:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Evidence assembly
    # ------------------------------------------------------------------

    def _execute(
        self, attempt: VerificationAttempt
    ) -> VerificationEvidence:
        if attempt.mode != VerificationMode.HTTP_REFLECTION:
            raise _UnsupportedRequest(
                "mode_not_supported_by_http_executor:"
                f"{attempt.mode.value}"
            )

        method, url, data, extra_headers = self._build_request(attempt)
        merged_headers = {
            **_session_default_headers(self.session),
            **extra_headers,
        }
        sensitive_values = tuple(
            value
            for name, value in merged_headers.items()
            if name.lower() in _REQUEST_SENSITIVE_HEADERS
        )

        try:
            response, _final_url = self._send_following_redirects(
                method, url, data, merged_headers, sensitive_values
            )
        except _TransportTimeout as exc:
            return self._error_evidence(
                attempt, str(exc), AttemptStatus.TIMEOUT
            )
        except (_TransportError, _VerificationError, _UnsupportedRequest) as exc:
            return self._error_evidence(
                attempt, str(exc), AttemptStatus.ERROR
            )

        body_text = self._read_bounded_body(response)
        status_code = response.status_code

        redacted_request = _redact(
            merged_headers, _REQUEST_SENSITIVE_HEADERS
        )
        redacted_response = _redact(
            dict(response.headers), _RESPONSE_SENSITIVE_HEADERS
        )

        waf_observations: list[WAFObservation] = []
        error_reason: str | None = None

        if status_code in self.WAF_BLOCK_STATUS_CODES:
            attempt_status = AttemptStatus.WAF_BLOCKED
            waf_observations.append(
                WAFObservation(
                    kind=WAFObservationKind.BLOCK,
                    note=f"http_status_{status_code}",
                )
            )
            reflection = _no_reflection()
        elif 200 <= status_code < 300:
            attempt_status = AttemptStatus.SUCCEEDED
            reflection, transform_obs, info_obs = (
                self._analyse_success_body(body_text, attempt)
            )
            if transform_obs is not None:
                attempt_status = AttemptStatus.WAF_TRANSFORMED
                waf_observations.append(transform_obs)
            waf_observations.extend(info_obs)
            waf_observations.extend(self._info_observations(response))
        else:
            attempt_status = AttemptStatus.FAILED
            error_reason = f"http_status_{status_code}"
            reflection = _no_reflection()

        return VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=attempt_status,
            request_url=attempt.endpoint,
            request_method=attempt.method,
            request_headers_redacted=redacted_request,
            response_status=status_code,
            response_headers_redacted=redacted_response,
            response_body_truncated=body_text or None,
            reflection=reflection,
            waf_observations=waf_observations,
            error_reason=error_reason,
        )

    def _analyse_success_body(
        self, body: str, attempt: VerificationAttempt
    ) -> tuple[
        ReflectionObservation,
        WAFObservation | None,
        list[WAFObservation],
    ]:
        token = attempt.correlation_token
        idx = body.find(token)

        if idx == -1:
            info: list[WAFObservation] = []
            if attempt.payload in body:
                info.append(
                    WAFObservation(
                        kind=WAFObservationKind.INFO,
                        note="payload_without_correlation_token",
                    )
                )
            return _no_reflection(), None, info

        token_literal = body[idx : idx + len(token)]
        reflection = ReflectionObservation(
            reflected=True,
            location=self._classify_location(body, idx, len(token)),
            context_before=body[max(0, idx - _CONTEXT_LIMIT) : idx],
            context_after=body[
                idx + len(token) : idx + len(token) + _CONTEXT_LIMIT
            ],
            matched_correlation_token=(
                token_literal == attempt.correlation_token
            ),
            observed_correlation_token=token_literal,
        )

        transform_obs: WAFObservation | None = None
        if not self._payload_reached_intact(body, attempt.payload):
            transform_obs = WAFObservation(
                kind=WAFObservationKind.TRANSFORM,
                note="payload_bytes_absent_token_present",
            )
        return reflection, transform_obs, []

    @staticmethod
    def _payload_transit_forms(payload: str) -> tuple[str, ...]:
        """
        Mechanical byte forms the payload is known to take in
        transit. Used only for WAF TRANSFORM detection; the
        correlation token is never normalised. The set is
        bounded and deterministic: raw, fully percent-encoded,
        HTML-escaped, URL-encoded-after-HTML-escape, and
        HTML-escape applied after URL-encoding that preserves
        the ``&`` query separator (the form produced by
        servers that echo a reconstructed query string).
        """

        return (
            payload,
            quote(payload, safe=""),
            _html.escape(payload, quote=True),
            quote(_html.escape(payload, quote=True), safe=""),
            _html.escape(quote(payload, safe="&"), quote=True),
        )

    def _payload_reached_intact(
        self, body: str, payload: str
    ) -> bool:
        return any(
            form and form in body
            for form in self._payload_transit_forms(payload)
        )

    @staticmethod
    def _scan_open_quote(text: str) -> str | None:
        """
        The quote character whose string region is still open
        at the end of ``text``, or None. Bounded, linear scan;
        escape sequences are deliberately not interpreted.
        """

        quote = None
        for ch in text:
            if quote is not None:
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch
        return quote

    @classmethod
    def _tag_value_context(
        cls, body: str, tag_start: int, token_index: int
    ) -> tuple[str, bool] | None:
        """
        Scan the tag starting at ``tag_start`` up to
        ``token_index``. Returns None when the tag closes
        before the token; otherwise returns the attribute
        name whose value region contains the token (possibly
        empty) and whether the tag is still open at the
        token. Quote-aware: angle brackets and quotes inside
        quoted values do not close the tag, so payloads that
        themselves contain ``<``/``>`` are handled.
        """

        quote = None
        attribute = ""
        in_unquoted_value = False
        i = tag_start + 1
        while i < token_index:
            ch = body[i]
            if quote is not None:
                # Inside a quoted attribute value: only the
                # matching quote character can close it. '>',
                # '=', and whitespace are literal value
                # characters here and must never fall through
                # to the tag-closing or unquoted-value branches.
                if ch == quote:
                    quote = None
                    attribute = ""
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
            elif ch == ">":
                return None
            elif ch == "=":
                match = _ATTR_NAME_BEFORE_EQ_RE.search(
                    body[tag_start + 1 : i]
                )
                attribute = (
                    match.group(1).lower() if match else ""
                )
                in_unquoted_value = True
            elif ch.isspace():
                in_unquoted_value = False
            i += 1
        if quote is not None:
            return attribute, True
        if in_unquoted_value and attribute:
            return attribute, True
        return "", True

    @classmethod
    def _classify_location(
        cls,
        body: str,
        token_index: int,
        token_length: int,
    ) -> ReflectionLocation:
        """
        Deterministic, bounded-context classification of where
        the token was observed. This is a structural heuristic
        over raw bytes, not an HTML/JS parser; the verifier
        relies on the exact token match, the location only
        gates meaningfulness of the reflection.

        Tag candidates are tried nearest-first: a payload that
        itself contains tags sits inside an enclosing tag's
        quoted attribute value, and the enclosing tag is the
        correct structural context.
        """

        open_positions = [
            match.start()
            for match in _SCRIPT_OPEN_RE.finditer(body)
            if match.start() < token_index
        ]
        if open_positions:
            last_open = open_positions[-1]
            close_after_open = [
                match.start()
                for match in _SCRIPT_CLOSE_RE.finditer(body)
                if match.start() > last_open
            ]
            if not close_after_open or close_after_open[0] > token_index:
                if cls._scan_open_quote(
                    body[last_open:token_index]
                ):
                    return ReflectionLocation.JAVASCRIPT_STRING
                return ReflectionLocation.SCRIPT_BLOCK

        tag_positions = [
            match.start()
            for match in _TAG_OPEN_RE.finditer(
                body[:token_index]
            )
        ]
        for tag_start in reversed(tag_positions):
            context = cls._tag_value_context(
                body, tag_start, token_index
            )
            if context is None:
                continue
            attribute, _tag_open = context
            if attribute:
                if attribute in _URL_ATTRIBUTE_NAMES:
                    return ReflectionLocation.URL
                return ReflectionLocation.HTML_ATTRIBUTE

        prefix = body[max(0, token_index - 8) : token_index].lower()
        if prefix.endswith(("http://", "https://")):
            return ReflectionLocation.URL
        return ReflectionLocation.HTML_BODY

    @staticmethod
    def _info_observations(response) -> list[WAFObservation]:
        observations: list[WAFObservation] = []
        headers = response.headers
        if headers.get("Content-Security-Policy"):
            observations.append(
                WAFObservation(
                    kind=WAFObservationKind.INFO,
                    note="csp_header_present",
                )
            )
        server = (headers.get("Server") or "").lower()
        for vendor in _WAF_VENDOR_HEADER_HINTS:
            if vendor in server:
                observations.append(
                    WAFObservation(
                        kind=WAFObservationKind.INFO,
                        note=f"waf_vendor_header:{vendor}",
                    )
                )
        return observations

    @staticmethod
    def _error_evidence(
        attempt: VerificationAttempt,
        reason: str,
        status: AttemptStatus,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            attempt_id=attempt.attempt_id,
            attempt_status=status,
            request_url=attempt.endpoint,
            request_method=attempt.method,
            request_headers_redacted={},
            response_status=None,
            response_headers_redacted={},
            response_body_truncated=None,
            error_reason=reason,
        )


def _no_reflection() -> ReflectionObservation:
    return ReflectionObservation(
        reflected=False,
        location=ReflectionLocation.NONE,
        matched_correlation_token=False,
        observed_correlation_token=None,
    )


__all__ = [
    "HTTPEvidenceExecutor",
]
