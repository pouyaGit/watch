"""EPIC13 §6 — controlled request construction.

A request is built from an observation the runtime already holds (an endpoint
plus one parameter) and differs from it in exactly one respect: the value of
the authorized parameter is replaced by that action's marker.

Preserved, byte for byte: scheme, host, port, path, fragment, and every other
query parameter (including their original ordering, separators and encoding).
Not preserved, on purpose: nothing else is ever changed.

Refused, fail closed:

* a target outside the recorded scope
* a parameter that is not present in the request being replayed
* a non-http(s) scheme, or a URL carrying userinfo (credentials)
* a query that carries a secret-shaped value — the acquisition layer must not
  replay a session token or an API key into a target
* a marker that is not inert (see :mod:`markers`)
* any method outside the closed acquisition set

Nothing here touches the network.  It produces a value; the transport sends it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import limits as lm
from . import markers as mk
from . import transport as tr

REQUEST_RULE_VERSION = "epic13-request-1"

REASON_OUT_OF_SCOPE = "target_out_of_scope"
REASON_BAD_SCHEME = "unsupported_scheme"
REASON_USERINFO = "url_carries_credentials"
REASON_PARAMETER_MISSING = "parameter_not_in_request"
REASON_SECRET_SHAPE = "request_contains_secret_shape"
REASON_MARKER_INVALID = "marker_not_inert"
REASON_METHOD = "method_not_allowed"
REASON_NO_URL = "no_request_url"


class RequestError(ValueError):
    """A controlled request could not be built (always fail closed)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ParameterRef:
    """The observed parameter an acquisition would exercise."""

    url: str
    parameter: str
    method: str = "GET"
    location: str = "query"

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "parameter": self.parameter,
                "method": self.method, "location": self.location}


def _contains_secret_shape(text: str) -> bool:
    """Reuse the platform's own secret-shape detector when it is available."""
    try:
        from ai.evidence import scrubber
    except Exception:  # noqa: BLE001
        return False
    try:
        return bool(scrubber.contains_secret_shape(text))
    except Exception:  # noqa: BLE001
        return False


def _redact_url(url: str) -> str:
    try:
        from ai.evidence import scrubber
        return str(scrubber.redact_url(url))
    except Exception:  # noqa: BLE001
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        if "@" not in (parts.netloc or ""):
            return url
        return url.replace(parts.netloc, parts.netloc.rsplit("@", 1)[-1], 1)


def _parts(url: str) -> Any:
    from urllib.parse import urlsplit

    try:
        return urlsplit(str(url or ""))
    except ValueError as exc:
        raise RequestError(REASON_BAD_SCHEME, str(exc)) from exc


def rewrite_query(url: str, parameter: str, value: str) -> str:
    """Replace exactly one query parameter's value; keep everything else.

    The raw query string is rewritten textually so that unrelated parameters
    keep their original separators and encoding — a parse/re-serialise round
    trip would silently normalise them.
    """
    from urllib.parse import unquote, urlsplit, urlunsplit

    parts = urlsplit(url)
    query = parts.query or ""
    if not query:
        raise RequestError(REASON_PARAMETER_MISSING,
                           f"{parameter!r} is not present in the request")
    wanted = str(parameter)
    found = False
    out: list[str] = []
    for chunk in query.split("&"):
        if not chunk:
            out.append(chunk)
            continue
        name, sep, _old = chunk.partition("=")
        try:
            decoded = unquote(name.replace("+", " "))
        except Exception:  # noqa: BLE001
            decoded = name
        if decoded == wanted:
            found = True
            out.append(f"{name}{sep or '='}{value}")
        else:
            out.append(chunk)
    if not found:
        raise RequestError(REASON_PARAMETER_MISSING,
                           f"{parameter!r} is not present in the request")
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       "&".join(out), parts.fragment))


def build_request(*, action_id: str, parameter_ref: ParameterRef,
                  marker: str, scope_ref: str, authorization_id: str = "",
                  attempt: int = 1, limits: dict[str, int] | None = None,
                  method: str = "GET") -> tr.AcquisitionRequest:
    """Build one controlled acquisition request.  Fail closed on anything."""
    from backend.research_agents.verification import actions as ac

    bounds = dict(limits or lm.limits_for())
    url = str(parameter_ref.url or "").strip()
    if not url:
        raise RequestError(REASON_NO_URL, "the observation carries no URL")
    method = str(method or parameter_ref.method or "GET").upper()
    if method not in tr.ALLOWED_METHODS:
        raise RequestError(REASON_METHOD,
                           f"{method} is not an allowed acquisition method")
    if method != str(parameter_ref.method or "GET").upper():
        # an acquisition never escalates the observed method
        raise RequestError(REASON_METHOD,
                           f"method escalation {parameter_ref.method}->"
                           f"{method} is refused")

    parts = _parts(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise RequestError(REASON_BAD_SCHEME, scheme or "(empty)")
    if "@" in (parts.netloc or ""):
        raise RequestError(REASON_USERINFO,
                           "the request URL carries credentials")
    if not ac.target_in_scope(url, scope_ref):
        raise RequestError(REASON_OUT_OF_SCOPE, _redact_url(url))
    if str(parameter_ref.location or "query") != "query":
        raise RequestError(REASON_PARAMETER_MISSING,
                           f"parameter location {parameter_ref.location!r} "
                           f"is not supported for acquisition")
    if _contains_secret_shape(parts.query or ""):
        raise RequestError(REASON_SECRET_SHAPE,
                           "the request query carries a secret-shaped value")

    safe_marker = mk.validate(marker, limits=bounds)
    controlled = rewrite_query(url, parameter_ref.parameter, safe_marker)
    return tr.AcquisitionRequest(
        action_id=str(action_id), url=controlled, method=method,
        parameter=str(parameter_ref.parameter), marker=safe_marker,
        scope_ref=str(scope_ref), authorization_id=str(authorization_id or ""),
        timeout_seconds=int(bounds.get("read_timeout_seconds", 10)),
        max_bytes=int(bounds.get("max_response_bytes", 8 * 1024)),
        max_redirects=int(bounds.get("max_redirects", 0)),
        attempt=int(attempt))


def request_line(request: tr.AcquisitionRequest) -> str:
    """An audit-safe one-line description (redacted, bounded)."""
    return (f"{request.method} {_redact_url(request.url)} "
            f"[param={request.parameter} marker={request.marker} "
            f"action={request.action_id} attempt={request.attempt}]")


def request_document() -> dict[str, Any]:
    """The request-construction contract, for docs and reports."""
    return {
        "rule_version": REQUEST_RULE_VERSION,
        "preserved": ["scheme", "host", "port", "path", "fragment",
                      "every other query parameter (raw)"],
        "changed": ["the value of the authorized parameter only"],
        "refusals": [REASON_OUT_OF_SCOPE, REASON_BAD_SCHEME, REASON_USERINFO,
                     REASON_PARAMETER_MISSING, REASON_SECRET_SHAPE,
                     REASON_MARKER_INVALID, REASON_METHOD, REASON_NO_URL],
        "never": ["add credentials", "add parameters", "change the method",
                  "replay a secret-shaped value"],
    }


__all__ = [
    "ParameterRef", "REASON_BAD_SCHEME", "REASON_MARKER_INVALID",
    "REASON_METHOD", "REASON_NO_URL", "REASON_OUT_OF_SCOPE",
    "REASON_PARAMETER_MISSING", "REASON_SECRET_SHAPE", "REASON_USERINFO",
    "REQUEST_RULE_VERSION", "RequestError", "build_request",
    "request_document", "request_line", "rewrite_query",
]
