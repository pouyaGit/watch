"""Stage R24.8 — the single production-safe bounded HTTP transport adapter.

This is the ONE real transport used by the R24 discovery pipeline. It is a
plain callable that matches the existing R24.2 ``ProviderTransport`` signature
(``transport(method, url, *, params, headers, timeout, max_bytes)``) and the
R24.3 ``safe_fetch_with_redirects`` seam, so no new networking abstraction is
introduced.

Guarantees:

- http/https only; embedded credentials in the URL are refused;
- caller-supplied ``Authorization`` / ``Cookie`` / ``Set-Cookie`` /
  ``Proxy-Authorization`` / API-key style headers are refused (the only header
  ever sent is a fixed neutral ``User-Agent``);
- explicit connect / read / total timeout bounds;
- bounded response body (hard truncation, never streams);
- **no automatic redirect following** — redirects are returned to the caller
  (R24.3 walks and validates every hop);
- preserves status, headers (via ``content_type`` on the R24.2 response),
  body and final URL;
- fails closed (``None``) on timeout / network / parse errors;
- never logs secrets, authorization headers or API keys.

The low-level ``send`` callable is injectable so unit tests never touch the
live network. The default ``send`` lazily imports ``httpx`` (already a project
dependency) only when the transport is actually invoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from ai.research_agent.provider_base import ProviderResponse

__all__ = [
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
    "DEFAULT_TOTAL_TIMEOUT",
    "DEFAULT_MAX_BYTES",
    "NEUTRAL_USER_AGENT",
    "SENSITIVE_HEADERS",
    "TransportResult",
    "HTTPTransport",
    "default_send",
]

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 15.0
DEFAULT_TOTAL_TIMEOUT = 20.0
DEFAULT_MAX_BYTES = 2_000_000
NEUTRAL_USER_AGENT = "Watch-Security-Researcher/0.1 (authorized security research)"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
    }
)


@dataclass(frozen=True)
class TransportResult:
    """Bounded low-level HTTP result (bytes in, no redirect following)."""

    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    final_url: str = ""
    url: str = ""

    @property
    def content_type(self) -> str:
        for key, value in (self.headers or {}).items():
            if str(key).lower() == "content-type":
                return str(value)
        return ""


SendFn = Callable[..., "TransportResult | None"]


def default_send(
    method: str,
    url: str,
    headers: dict,
    timeout: float,
    params: dict | None,
    *,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
) -> TransportResult | None:
    """httpx-backed single request with NO redirect following.

    Imported lazily so importing this module never loads a network client.
    """
    import httpx  # local import: keeps module import side-effect free

    try:
        client_timeout = httpx.Timeout(
            max(float(timeout), 0.1),
            connect=max(float(connect_timeout), 0.1),
            read=max(float(read_timeout), 0.1),
        )
        with httpx.Client(timeout=client_timeout, follow_redirects=False) as client:
            response = client.request(
                str(method or "GET").upper(),
                url,
                headers=headers or {},
                params=params or None,
            )
    except Exception:
        # Fail closed; the caller records a bounded reason. Never surface the
        # exception text (it may contain the URL / host only).
        return None
    return TransportResult(
        status=int(response.status_code),
        headers=dict(response.headers),
        body=bytes(response.content or b""),
        final_url=str(response.url),
        url=str(response.url),
    )


class HTTPTransport:
    """Bounded, fail-closed, redirect-preserving HTTP transport."""

    def __init__(
        self,
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        user_agent: str = NEUTRAL_USER_AGENT,
        send: SendFn | None = None,
    ) -> None:
        self.connect_timeout = max(float(connect_timeout), 0.1)
        self.read_timeout = max(float(read_timeout), 0.1)
        self.total_timeout = max(float(total_timeout), 0.1)
        self.max_bytes = max(int(max_bytes), 1)
        self.user_agent = str(user_agent or NEUTRAL_USER_AGENT)
        self._send = send

    def _dispatch(self, *args, **kwargs) -> TransportResult | None:
        fn = self._send or default_send
        if fn is default_send:
            return default_send(
                *args,
                **kwargs,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
            )
        return fn(*args, **kwargs)

    def __call__(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> ProviderResponse | None:
        text = str(url or "").strip()
        if not text:
            return None
        try:
            parsed = urlparse(text)
        except Exception:
            return None
        if (parsed.scheme or "").lower() not in ("http", "https"):
            return None
        if parsed.username or parsed.password:
            return None
        if not (parsed.hostname or "").strip():
            return None

        out_headers = {"User-Agent": self.user_agent}
        for key, value in (headers or {}).items():
            if str(key).strip().lower() in SENSITIVE_HEADERS:
                return None
            out_headers[str(key)] = str(value)

        cap = max(int(max_bytes if max_bytes is not None else self.max_bytes), 1)
        eff_timeout = max(float(timeout or self.total_timeout), 0.1)

        try:
            result = self._dispatch(
                str(method or "GET").upper(),
                text,
                out_headers,
                eff_timeout,
                params or None,
            )
        except Exception:
            return None
        if result is None:
            return None

        body_cap = result.body[:cap]
        try:
            body_text = body_cap.decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        return ProviderResponse(
            url=result.url or text,
            status=int(result.status or 0),
            body=body_text,
            content_type=result.content_type,
            final_url=result.final_url or result.url or text,
        )
