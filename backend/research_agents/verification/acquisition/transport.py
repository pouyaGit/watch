"""EPIC13 §3 — the narrow, authorized acquisition transport.

**This module adds no network primitive.**  There is no ``requests``, no
``urllib.request``, no ``httpx``, no ``socket``, no ``subprocess``, no
``curl`` anywhere in this package (asserted by an AST guard in the tests).  A
transport is something the *platform* provides; this module defines the
contract, wires the platform's existing authorized executor when it is
available, and otherwise fails closed.

Three transports exist:

``PlatformAuthorizedTransport``
    Delegates to the platform's own authorized HTTP executor
    (``ai.execution.http_executor.execute_http``).  That executor is switched
    off in this runtime: ``LIVE_TRAFFIC_ENABLED`` is ``False``, its B1
    (production ``AddressSource``) and B2 (production authorization/ledger/
    audit/evidence adapters) prerequisites are deferred, and the module states
    there is no code path that turns it on.  This transport therefore reports
    ``TRANSPORT_UNAVAILABLE`` with the platform's own status strings.  It
    reads the gate; it never writes it, never imports a private symbol to get
    around it, and never constructs the artifacts the platform requires
    without them genuinely existing.

``InjectedTransport``
    A caller-supplied callable.  This is the seam the platform itself uses for
    offline execution ("offline execution proceeds only through injected
    fakes"), and it is how the acquisition machinery is exercised in tests and
    fixtures without any network access.

``UnavailableTransport``
    Always refuses.  The honest default.

Every request a transport receives has already been constructed, scoped,
marker-injected and budget-checked by this package, and every response it
returns is re-checked here (redirect scope, size bound, redaction) before
anything is persisted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from . import limits as lm

TRANSPORT_RULE_VERSION = "epic13-transport-1"

#: closed outcome vocabulary (§19).
OUTCOME_RESPONDED = "responded"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_REFUSED = "refused"
OUTCOME_TRANSPORT_UNAVAILABLE = "transport_unavailable"
OUTCOME_TRANSPORT_FAILED = "transport_failed"
OUTCOME_REDIRECT_OUT_OF_SCOPE = "redirect_out_of_scope"
OUTCOME_RESPONSE_LIMIT_EXCEEDED = "response_limit_exceeded"
OUTCOME_INCONCLUSIVE = "inconclusive"

TRANSPORT_OUTCOMES: tuple[str, ...] = (
    OUTCOME_RESPONDED, OUTCOME_TIMEOUT, OUTCOME_REFUSED,
    OUTCOME_TRANSPORT_UNAVAILABLE, OUTCOME_TRANSPORT_FAILED,
    OUTCOME_REDIRECT_OUT_OF_SCOPE, OUTCOME_RESPONSE_LIMIT_EXCEEDED,
    OUTCOME_INCONCLUSIVE,
)

#: the only methods an acquisition may use.  Reflection needs no more, and a
#: method the platform treats as non-idempotent is never escalated to.
ALLOWED_METHODS: tuple[str, ...] = ("GET", "HEAD")

#: headers an acquisition may send.  Empty by default: the platform's own
#: executor owns the identity headers, and this layer never invents one.
ALLOWED_REQUEST_HEADERS: tuple[str, ...] = ()


class TransportError(RuntimeError):
    """A transport was used incorrectly (never a security result by itself)."""


@dataclass
class AcquisitionRequest:
    """One constructed, scoped acquisition request."""

    action_id: str
    url: str
    method: str = "GET"
    parameter: str = ""
    marker: str = ""
    scope_ref: str = ""
    authorization_id: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 10
    max_bytes: int = 8 * 1024
    max_redirects: int = 0
    attempt: int = 1

    def __post_init__(self) -> None:
        self.method = str(self.method or "GET").upper()
        if self.method not in ALLOWED_METHODS:
            raise TransportError(f"method not allowed for acquisition: "
                                 f"{self.method}")
        extra = sorted(set(self.headers) - set(ALLOWED_REQUEST_HEADERS))
        if extra:
            raise TransportError(f"headers not allowed for acquisition: "
                                 f"{extra}")
        self.timeout_seconds = lm.check("read_timeout_seconds",
                                        int(self.timeout_seconds))
        self.max_bytes = lm.check("max_response_bytes", int(self.max_bytes))
        self.max_redirects = lm.check("max_redirects", int(self.max_redirects))

    def to_dict(self) -> dict[str, Any]:
        """Audit-safe view: no secret can appear here by construction."""
        return {
            "action_id": self.action_id, "method": self.method,
            "url": self.url, "parameter": self.parameter,
            "marker": self.marker, "scope_ref": self.scope_ref,
            "authorization_id": self.authorization_id,
            "headers": dict(self.headers), "attempt": self.attempt,
            "timeout_seconds": self.timeout_seconds,
            "max_bytes": self.max_bytes, "max_redirects": self.max_redirects,
        }


@dataclass
class AcquisitionResponse:
    """One transport response, already bounded and scrubbed."""

    outcome: str = OUTCOME_TRANSPORT_UNAVAILABLE
    status_code: int = 0
    body: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    truncated: bool = False
    final_url: str = ""
    redirects: list[dict[str, Any]] = field(default_factory=list)
    response_ref: str = ""
    reason: str = ""
    elapsed_seconds: float = 0.0
    bytes_received: int = 0
    transport: str = ""

    @property
    def responded(self) -> bool:
        return self.outcome == OUTCOME_RESPONDED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome, "status_code": self.status_code,
            "headers": dict(self.headers), "truncated": self.truncated,
            "final_url": self.final_url, "redirects": list(self.redirects),
            "response_ref": self.response_ref, "reason": self.reason,
            "elapsed_seconds": self.elapsed_seconds,
            "bytes_received": self.bytes_received, "transport": self.transport,
            "body_present": self.body is not None,
            "body_bytes": len(self.body or ""),
        }


class AcquisitionTransport(Protocol):
    """The transport contract.  Implementations are injected, never imported."""

    name: str

    @property
    def available(self) -> bool: ...

    def send(self, request: AcquisitionRequest) -> AcquisitionResponse: ...


def _platform_status() -> dict[str, Any]:
    """Read the platform's live-execution gate state (read-only)."""
    out: dict[str, Any] = {"live_traffic_enabled": False, "b1": "", "b2": "",
                           "available": False, "source": "absent"}
    try:
        from ai.execution import http_executor as ex
    except Exception:  # noqa: BLE001 - an absent module is not an open gate
        return out
    try:
        out["live_traffic_enabled"] = bool(
            getattr(ex, "LIVE_TRAFFIC_ENABLED", False))
        out["b1"] = str(getattr(ex, "B1_STATUS", "") or "")
        out["b2"] = str(getattr(ex, "B2_STATUS", "") or "")
        out["source"] = "ai.execution.http_executor"
    except Exception:  # noqa: BLE001
        return out
    out["available"] = bool(out["live_traffic_enabled"])
    return out


@dataclass
class PlatformAuthorizedTransport:
    """The platform's authorized executor, used only when it is open."""

    name: str = "platform_authorized_transport"
    executor: Callable[..., Any] | None = None

    @property
    def available(self) -> bool:
        return bool(_platform_status().get("available")) and \
            self.executor is not None

    def status(self) -> dict[str, Any]:
        return _platform_status()

    def send(self, request: AcquisitionRequest) -> AcquisitionResponse:
        status = _platform_status()
        if not status.get("available"):
            return AcquisitionResponse(
                outcome=OUTCOME_TRANSPORT_UNAVAILABLE,
                reason=("the platform's live execution gate is closed "
                        "(LIVE_TRAFFIC_ENABLED=false; "
                        f"{status.get('b1', '')}; {status.get('b2', '')})"),
                transport=self.name)
        if self.executor is None:
            return AcquisitionResponse(
                outcome=OUTCOME_TRANSPORT_UNAVAILABLE,
                reason=("the platform executor is open but no executor "
                        "callable was injected; acquisition never builds the "
                        "authorization/scope artifacts itself"),
                transport=self.name)
        try:
            result = self.executor(request)
        except Exception as exc:  # noqa: BLE001 - a failure is never evidence
            return AcquisitionResponse(
                outcome=OUTCOME_TRANSPORT_FAILED,
                reason=f"platform executor raised {type(exc).__name__}",
                transport=self.name)
        if isinstance(result, AcquisitionResponse):
            result.transport = self.name
            return result
        return AcquisitionResponse(
            outcome=OUTCOME_TRANSPORT_FAILED,
            reason="platform executor returned an unusable result",
            transport=self.name)


@dataclass
class InjectedTransport:
    """A caller-supplied transport callable (the platform's own offline seam)."""

    callable_: Callable[[AcquisitionRequest], AcquisitionResponse] | None = None
    name: str = "injected_transport"

    def __post_init__(self) -> None:
        # a transport that was handed something it cannot call is a
        # configuration error, not "no transport": fail loudly.
        if self.callable_ is not None and not callable(self.callable_):
            raise TransportError(
                f"an injected transport must be callable, got "
                f"{type(self.callable_).__name__}")

    @property
    def available(self) -> bool:
        return self.callable_ is not None

    def send(self, request: AcquisitionRequest) -> AcquisitionResponse:
        if self.callable_ is None:
            return AcquisitionResponse(
                outcome=OUTCOME_TRANSPORT_UNAVAILABLE,
                reason="no transport callable was injected",
                transport=self.name)
        try:
            result = self.callable_(request)
        except TimeoutError:
            return AcquisitionResponse(outcome=OUTCOME_TIMEOUT,
                                       reason="the transport timed out",
                                       transport=self.name)
        except Exception as exc:  # noqa: BLE001 - never evidence
            return AcquisitionResponse(
                outcome=OUTCOME_TRANSPORT_FAILED,
                reason=f"the injected transport raised {type(exc).__name__}",
                transport=self.name)
        if isinstance(result, AcquisitionResponse):
            result.transport = self.name
            return result
        return AcquisitionResponse(
            outcome=OUTCOME_TRANSPORT_FAILED,
            reason="the injected transport returned an unusable result",
            transport=self.name)


@dataclass
class UnavailableTransport:
    """Always refuses.  The honest default when nothing was provided."""

    name: str = "unavailable_transport"
    reason: str = "no authorized transport was provided for acquisition"

    @property
    def available(self) -> bool:
        return False

    def send(self, request: AcquisitionRequest) -> AcquisitionResponse:
        return AcquisitionResponse(
            outcome=OUTCOME_TRANSPORT_UNAVAILABLE, reason=self.reason,
            transport=self.name)


def transport_for(candidate: Any) -> AcquisitionTransport:
    """Resolve a transport from a caller-supplied object, fail closed.

    Accepts an object exposing ``send`` (an :class:`AcquisitionTransport`), a
    bare callable, or ``None``.  Anything else is refused rather than
    interpreted.
    """
    if candidate is None:
        return UnavailableTransport()
    if hasattr(candidate, "send") and callable(getattr(candidate, "send")):
        return candidate  # type: ignore[return-value]
    if callable(candidate):
        return InjectedTransport(callable_=candidate)
    return UnavailableTransport(
        reason=f"unsupported transport object: {type(candidate).__name__}")


def transport_document() -> dict[str, Any]:
    """The transport architecture and its honest state, for docs/reports."""
    status = _platform_status()
    return {
        "rule_version": TRANSPORT_RULE_VERSION,
        "new_network_primitive_added": False,
        "allowed_methods": list(ALLOWED_METHODS),
        "allowed_request_headers": list(ALLOWED_REQUEST_HEADERS),
        "outcomes": list(TRANSPORT_OUTCOMES),
        "platform_gate": status,
        "platform_transport_available": bool(status.get("available")),
        "seam": "injected transport (the platform's own offline seam)",
        "fail_closed": True,
        "redaction": ("response headers are scrubbed and no body is "
                      "persisted by the transport layer"),
        "notes": [
            "no requests/urllib.request/httpx/socket/subprocess/curl in this "
            "package",
            "the platform's live gate is read, never written",
            "a transport failure is never negative vulnerability evidence",
        ],
    }


__all__ = [
    "ALLOWED_METHODS", "ALLOWED_REQUEST_HEADERS", "AcquisitionRequest",
    "AcquisitionResponse", "AcquisitionTransport", "InjectedTransport",
    "OUTCOME_INCONCLUSIVE", "OUTCOME_REDIRECT_OUT_OF_SCOPE",
    "OUTCOME_REFUSED", "OUTCOME_RESPONDED", "OUTCOME_RESPONSE_LIMIT_EXCEEDED",
    "OUTCOME_TIMEOUT", "OUTCOME_TRANSPORT_FAILED",
    "OUTCOME_TRANSPORT_UNAVAILABLE", "PlatformAuthorizedTransport",
    "TRANSPORT_OUTCOMES", "TRANSPORT_RULE_VERSION", "TransportError",
    "UnavailableTransport", "transport_document", "transport_for",
]
