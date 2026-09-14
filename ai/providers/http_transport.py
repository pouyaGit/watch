"""Stage R51 HTTP transport (the only network-capable R51 module).

Defines the bounded HTTP transport interface used by the real provider
adapters and the stdlib-backed default transport:

    provider adapter -> HttpTransport -> configured provider endpoint

Hard boundaries encoded here:

- Network isolation: this module is the only R51 source that imports
  network primitives (``urllib``/``ssl``). The rest of the provider layer
  operates on request/response specs, so specialists never gain network
  access and tests inject a fake transport.
- Explicit bounds: every call carries an explicit timeout and a maximum
  response size; oversized responses fail instead of being read.
- No redirect following: redirect responses are surfaced as bounded HTTP
  responses, never followed.
- No secrets in metadata: the transport never records headers, prompts or
  bodies; failures carry only a bounded transport kind.
- No LLM, no database, no browser, no subprocess, no execution.

The request/response specs and the abstract interface are pure; only the
default :class:`UrllibHttpTransport` performs network I/O.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

HTTP_TRANSPORT_RULE_VERSION = "r51-http-transport"
RULE_VERSION = HTTP_TRANSPORT_RULE_VERSION

DEFAULT_USER_AGENT = "watch-r51-advisory/1.0"

FAILURE_TIMEOUT = "TIMEOUT"
FAILURE_NETWORK = "NETWORK"
FAILURE_TLS = "TLS"
FAILURE_RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"

TRANSPORT_FAILURE_KINDS: tuple[str, ...] = (
    FAILURE_TIMEOUT,
    FAILURE_NETWORK,
    FAILURE_TLS,
    FAILURE_RESPONSE_TOO_LARGE,
)

MAX_TRANSPORT_DETAIL_LEN = 120


@dataclass(frozen=True)
class HttpRequestSpec:
    """Bounded HTTP request specification (headers may include auth)."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    timeout_seconds: float
    max_response_bytes: int


@dataclass(frozen=True)
class HttpResponseSpec:
    """Bounded HTTP response (status and body text only)."""

    status_code: int
    body_text: str
    content_type: str = ""


class TransportFailure(RuntimeError):
    """Bounded transport-level failure (no response available)."""

    def __init__(self, kind: str, detail: str = ""):
        resolved = kind if kind in TRANSPORT_FAILURE_KINDS else FAILURE_NETWORK
        self.kind = resolved
        self.detail = " ".join(
            str(detail or "").split()
        )[:MAX_TRANSPORT_DETAIL_LEN]
        super().__init__(resolved)


class HttpTransport(ABC):
    """Provider-agnostic bounded HTTP transport interface."""

    transport_kind: str = "ABSTRACT"

    @abstractmethod
    def send(self, spec: HttpRequestSpec) -> HttpResponseSpec:
        """Perform one bounded HTTP exchange."""

        raise NotImplementedError

    def describe(self) -> dict:
        """Return the deterministic transport boundary description."""

        return {
            "rule_version": HTTP_TRANSPORT_RULE_VERSION,
            "transport_kind": self.transport_kind,
            "network_access": True,
            "redirects_followed": False,
            "credentials_recorded": False,
            "research_only": True,
        }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: surface them instead of silently following."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibHttpTransport(HttpTransport):
    """Bounded stdlib HTTP transport (the only real network client).

    The transport uses an explicit timeout, refuses redirects, reads at
    most ``max_response_bytes`` bytes and surfaces HTTP error statuses as
    bounded responses for deterministic adapter error mapping.
    """

    transport_kind = "URLLIB"

    def __init__(self, ssl_context: object = None):
        self._context = (
            ssl_context
            if ssl_context is not None
            else ssl.create_default_context()
        )

    def _opener(self):
        return urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=self._context),
        )

    def send(self, spec: HttpRequestSpec) -> HttpResponseSpec:
        if not isinstance(spec, HttpRequestSpec):
            raise TransportFailure(FAILURE_NETWORK, "invalid request spec")
        method = str(spec.method or "POST").strip().upper()
        body = spec.body if method != "GET" else None
        request = urllib.request.Request(
            url=spec.url,
            data=body,
            headers=dict(spec.headers),
            method=method,
        )
        limit = max(1, int(spec.max_response_bytes))
        opener = self._opener()
        try:
            with opener.open(
                request, timeout=float(spec.timeout_seconds)
            ) as response:
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise TransportFailure(
                        FAILURE_RESPONSE_TOO_LARGE,
                        "provider response exceeds the configured limit",
                    )
                status = int(getattr(response, "status", 0) or 0)
                content_type = ""
                headers = getattr(response, "headers", None)
                if headers is not None:
                    content_type = str(
                        headers.get("Content-Type", "") or ""
                    )[:120]
                return HttpResponseSpec(
                    status_code=status,
                    body_text=raw.decode("utf-8", errors="replace"),
                    content_type=content_type,
                )
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read(limit + 1)
            except Exception:
                raw = b""
            if len(raw) > limit:
                raise TransportFailure(
                    FAILURE_RESPONSE_TOO_LARGE,
                    "provider error response exceeds the configured limit",
                ) from None
            return HttpResponseSpec(
                status_code=int(getattr(exc, "code", 0) or 0),
                body_text=raw.decode("utf-8", errors="replace"),
                content_type="",
            )
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", "") or "")
            if "timed out" in reason.lower():
                raise TransportFailure(FAILURE_TIMEOUT, "request timed out")
            if isinstance(getattr(exc, "reason", None), ssl.SSLError):
                raise TransportFailure(FAILURE_TLS, "TLS handshake failed")
            raise TransportFailure(FAILURE_NETWORK, "connection failed")
        except TimeoutError:
            raise TransportFailure(FAILURE_TIMEOUT, "request timed out")
        except ssl.SSLError:
            raise TransportFailure(FAILURE_TLS, "TLS handshake failed")
        except TransportFailure:
            raise
        except OSError as exc:
            if "timed out" in str(exc).lower():
                raise TransportFailure(FAILURE_TIMEOUT, "request timed out")
            raise TransportFailure(FAILURE_NETWORK, "connection failed")


__all__ = [
    "HTTP_TRANSPORT_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_USER_AGENT",
    "FAILURE_TIMEOUT",
    "FAILURE_NETWORK",
    "FAILURE_TLS",
    "FAILURE_RESPONSE_TOO_LARGE",
    "TRANSPORT_FAILURE_KINDS",
    "MAX_TRANSPORT_DETAIL_LEN",
    "HttpRequestSpec",
    "HttpResponseSpec",
    "TransportFailure",
    "HttpTransport",
    "UrllibHttpTransport",
]
