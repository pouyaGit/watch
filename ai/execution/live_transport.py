"""B1 live transport adapters (Phase B1).

The ONLY B1-new module permitted to import ``socket``/``ssl``. Every
other B1 module (address source, hop resolver, dial proof, egress
guard) is statically banned from those imports (AST-tested).

Contents:

- :class:`LiveSocketFactory`: implements the frozen 5E
  ``SocketFactory`` protocol against real sockets. Accepts IP
  literals only (hostname-shaped input is unrepresentable and
  rejected); derives the address family from the literal (never
  ``getaddrinfo``, never implicit DNS); bounded connect timeout;
  connects only to the provided literal.
- :class:`LiveTlsWrapper`: implements the frozen 5E ``TlsWrapper``
  protocol against the system CA store (``CERT_REQUIRED``,
  ``check_hostname=True``, TLS >= 1.2, SNI = canonical hostname,
  never an IP, no custom CA, no insecure mode).
- :func:`verify_socket_peer`: ``getpeername()`` equality against the
  selected authorized IP (mismatch fails closed; unavailable peer
  fails closed).
- :func:`dns_tcp_exchange`: length-prefixed TCP DNS exchange used by
  the production address source (single attempt, bounded timeout).
- Connection-identity tracking: every issued socket carries a unique
  ``connection_id``; a socket is never wrapped twice and never
  served from any pool (pooling/keep-alive/reuse are structurally
  absent — one fresh socket per hop, closed by the caller).

No proxy: this module reads no proxy environment, takes no proxy
parameter, emits no ``CONNECT``, and honors no PAC/WPAD/system
discovery. No high-level HTTP client exists here (raw ``socket`` +
``ssl`` only; no HTTP/2, HTTP/3, QUIC, or Happy Eyeballs).

Production live traffic remains disabled (``LIVE_TRAFFIC_ENABLED``
is ``False``); these adapters are admitted by the executor live
gate only under a separately authorized activation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import socket
import ssl
import struct
import weakref

__all__ = [
    "LIVE_TRANSPORT_VERSION",
    "CONNECT_TIMEOUT_SECONDS",
    "LIVE_TRANSPORT_ERROR_CODES",
    "LiveTransportError",
    "require_ip_literal",
    "LiveSocketFactory",
    "LiveTlsWrapper",
    "verify_socket_peer",
    "tls_version_of",
    "peer_cert_hash_of",
    "close_quietly",
    "dns_tcp_exchange",
]

#: Reviewed adapter identity (bound into dial proof / audit).
LIVE_TRANSPORT_VERSION = "b1-live-transport/v1"

#: Bounded connect timeout family (mirrors frozen ceilings).
CONNECT_TIMEOUT_SECONDS = 10.0

#: Closed error vocabulary for live-transport failures.
LIVE_TRANSPORT_ERROR_CODES = frozenset(
    {
        "DIAL_BINDING_MISMATCH",
        "TRANSPORT_FAILURE",
        "TRANSPORT_TIMEOUT",
        "TRANSPORT_BINDING_FAILURE",
        "UNEXPECTED_SOCKET_PEER",
        "TLS_FAILURE",
        "TLS_MISMATCH",
        "CONNECTION_REUSE_VIOLATION",
    }
)


class LiveTransportError(ValueError):
    """Bounded, secret-free live-transport failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in LIVE_TRANSPORT_ERROR_CODES:
            raise ValueError(f"unknown live transport code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("live transport detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


def require_ip_literal(value: object) -> str:
    """Fail-closed IP-literal gate (mirrors the frozen 5E gate).

    Local copy (no import of ``http_executor``) so this module stays
    acyclic: ``http_executor`` may import this module, never the
    reverse.
    """

    if not isinstance(value, str) or not value:
        raise LiveTransportError("DIAL_BINDING_MISMATCH", "dial target not a string")
    if "/" in value or "?" in value or "#" in value or "@" in value:
        raise LiveTransportError("DIAL_BINDING_MISMATCH", "dial target not literal")
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise LiveTransportError(
            "DIAL_BINDING_MISMATCH", "dial target not literal"
        ) from exc
    if value.strip() != str(parsed) and "%" in value:
        raise LiveTransportError("DIAL_BINDING_MISMATCH", "scoped address denied")
    return str(parsed)


def _family_for(literal: str) -> int:
    parsed = ipaddress.ip_address(literal)
    return socket.AF_INET6 if parsed.version == 6 else socket.AF_INET


def _new_connection_id() -> str:
    return "conn-" + secrets.token_hex(16)


class LiveSocketFactory:
    """Live IP-literal socket factory (frozen ``SocketFactory`` shape).

    ``connect(ip_literal, port, timeout)`` returns a fresh connected
    ``socket.socket``. No pooling, no keep-alive, no reuse: every
    call creates exactly one socket.
    """

    def __init__(self) -> None:
        self._issued: weakref.WeakSet = weakref.WeakSet()
        self._ids: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

    @property
    def transport_version(self) -> str:
        """Reviewed adapter identity."""
        return LIVE_TRANSPORT_VERSION

    def connection_id_for(self, sock: object) -> str | None:
        """Return the per-SYN connection id, or ``None`` if foreign."""
        try:
            return self._ids.get(sock)  # type: ignore[arg-type]
        except TypeError:
            return None

    def connect(self, ip_literal: str, port: int, timeout: float):  # noqa: ANN204
        """Dial one IP literal with a bounded timeout (single SYN)."""

        dial_ip = require_ip_literal(ip_literal)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise LiveTransportError("DIAL_BINDING_MISMATCH", "dial port out of range")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 60
        ):
            raise LiveTransportError("TRANSPORT_FAILURE", "timeout out of range")
        family = _family_for(dial_ip)
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            raise LiveTransportError("TRANSPORT_FAILURE", "socket create failed") from exc
        try:
            sock.settimeout(float(timeout))
            sock.connect((dial_ip, port))
        except TimeoutError as exc:
            close_quietly(sock)
            raise LiveTransportError("TRANSPORT_TIMEOUT", "connect timeout") from exc
        except (ConnectionError, OSError) as exc:
            close_quietly(sock)
            raise LiveTransportError("TRANSPORT_FAILURE", "connection error") from exc
        self._issued.add(sock)
        self._ids[sock] = _new_connection_id()
        return sock


class LiveTlsWrapper:
    """Live TLS wrapper (frozen ``TlsWrapper`` shape).

    System CA store, ``CERT_REQUIRED``, ``check_hostname=True``,
    TLS >= 1.2, SNI = caller's hostname (rejected when IP-shaped),
    no custom trust roots, no insecure mode. Each raw socket may be
    wrapped at most once; a second wrap is
    ``CONNECTION_REUSE_VIOLATION``.
    """

    def __init__(self) -> None:
        self._wrapped: weakref.WeakSet = weakref.WeakSet()
        self._sni_log: list[str] = []

    @property
    def transport_version(self) -> str:
        """Reviewed adapter identity."""
        return LIVE_TRANSPORT_VERSION

    @property
    def sni_log(self) -> tuple[str, ...]:
        """SNI hostnames presented (audit aid, hostnames only)."""
        return tuple(self._sni_log)

    def _context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def wrap(self, raw_sock: object, *, sni_host: str, timeout: float):  # noqa: ANN204
        """Wrap a connected IP socket with hostname-bound TLS."""

        if raw_sock in self._wrapped:
            raise LiveTransportError(
                "CONNECTION_REUSE_VIOLATION", "socket already wrapped"
            )
        if not isinstance(sni_host, str) or not sni_host:
            raise LiveTransportError("TLS_MISMATCH", "sni host not a string")
        try:
            ipaddress.ip_address(sni_host)
        except ValueError:
            pass
        else:
            raise LiveTransportError("TLS_MISMATCH", "sni must not be an ip")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 60
        ):
            raise LiveTransportError("TLS_FAILURE", "timeout out of range")
        # Consumed at entry: a socket that entered TLS never returns
        # to any usable pool, even when the handshake fails.
        try:
            self._wrapped.add(raw_sock)  # type: ignore[arg-type]
        except TypeError as exc:
            raise LiveTransportError("TLS_FAILURE", "unwrappable socket") from exc
        context = self._context()
        self._sni_log.append(sni_host)
        try:
            if hasattr(raw_sock, "settimeout"):
                raw_sock.settimeout(float(timeout))  # type: ignore[union-attr]
            tls_sock = context.wrap_socket(raw_sock, server_hostname=sni_host)  # type: ignore[arg-type]
        except LiveTransportError:
            raise
        except (ssl.SSLError, ssl.CertificateError) as exc:
            raise LiveTransportError("TLS_FAILURE", "tls handshake failed") from exc
        except (ConnectionError, OSError) as exc:
            raise LiveTransportError("TLS_FAILURE", "tls handshake failed") from exc
        except Exception as exc:
            raise LiveTransportError("TLS_FAILURE", "tls handshake failed") from exc
        return tls_sock


def verify_socket_peer(sock: object, expected_ip: str) -> str:
    """Check ``getpeername()`` against the selected authorized IP.

    Returns the normalized actual peer IP. Any mismatch, any
    unavailable/non-IP peer identity, fails closed.
    """

    dial_ip = require_ip_literal(expected_ip)
    try:
        peer = sock.getpeername()  # type: ignore[union-attr]
    except Exception as exc:
        raise LiveTransportError(
            "UNEXPECTED_SOCKET_PEER", "peer identity unavailable"
        ) from exc
    actual = peer[0] if isinstance(peer, (list, tuple)) and peer else None
    if not isinstance(actual, str) or not actual:
        raise LiveTransportError("UNEXPECTED_SOCKET_PEER", "peer identity not ip")
    try:
        normalized = require_ip_literal(actual)
    except LiveTransportError as exc:
        raise LiveTransportError(
            "UNEXPECTED_SOCKET_PEER", "peer identity not ip"
        ) from exc
    if normalized != dial_ip:
        raise LiveTransportError(
            "TRANSPORT_BINDING_FAILURE", "peer address mismatch"
        )
    return normalized


def tls_version_of(tls_sock: object) -> str:
    """Negotiated TLS version name (proof field; ``unknown`` never)."""

    try:
        version = tls_sock.version()  # type: ignore[union-attr]
    except Exception as exc:
        raise LiveTransportError("TLS_FAILURE", "tls version unknown") from exc
    if not isinstance(version, str) or not version:
        raise LiveTransportError("TLS_FAILURE", "tls version unknown")
    return version


def peer_cert_hash_of(tls_sock: object) -> str:
    """SHA-256 over the DER peer certificate (fingerprint, not content)."""

    try:
        der = tls_sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
    except Exception as exc:
        raise LiveTransportError("TLS_FAILURE", "peer cert unavailable") from exc
    if not isinstance(der, (bytes, bytearray)) or not der:
        raise LiveTransportError("TLS_FAILURE", "peer cert unavailable")
    return hashlib.sha256(bytes(der)).hexdigest()


def close_quietly(sock: object) -> None:
    """Best-effort close (never raises; never returns the socket)."""

    try:
        sock.close()  # type: ignore[union-attr]
    except Exception:
        pass


def dns_tcp_exchange(server_ip: str, query_bytes: bytes, timeout: float) -> bytes:
    """Single-attempt length-prefixed TCP DNS exchange (no retries).

    Used as the ``exchange`` callable for :class:`ProductionAddressSource`
    production wiring. Exactly one TCP connection, one query, one
    response; any failure maps to a fail-closed exception.
    """

    dial_ip = require_ip_literal(server_ip)
    if not isinstance(query_bytes, (bytes, bytearray)) or not query_bytes:
        raise LiveTransportError("TRANSPORT_FAILURE", "dns query empty")
    if len(query_bytes) > 65535 - 2:
        raise LiveTransportError("TRANSPORT_FAILURE", "dns query over cap")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0 < timeout <= 60
    ):
        raise LiveTransportError("TRANSPORT_FAILURE", "timeout out of range")
    family = _family_for(dial_ip)
    wire = struct.pack(">H", len(query_bytes)) + bytes(query_bytes)
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        raise LiveTransportError("TRANSPORT_FAILURE", "socket create failed") from exc
    try:
        sock.settimeout(float(timeout))
        sock.connect((dial_ip, 53))
        sock.sendall(wire)
        prefix = _recv_exact(sock, 2)
        (length,) = struct.unpack(">H", prefix)
        if length == 0 or length > 65535 - 2:
            raise LiveTransportError("TRANSPORT_FAILURE", "dns length invalid")
        return _recv_exact(sock, length)
    except TimeoutError as exc:
        raise LiveTransportError("TRANSPORT_TIMEOUT", "dns exchange timeout") from exc
    except LiveTransportError:
        raise
    except (ConnectionError, OSError) as exc:
        raise LiveTransportError("TRANSPORT_FAILURE", "dns exchange failed") from exc
    except Exception as exc:
        raise LiveTransportError("TRANSPORT_FAILURE", "dns exchange failed") from exc
    finally:
        close_quietly(sock)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        try:
            chunk = sock.recv(count - len(out))
        except TimeoutError as exc:
            raise LiveTransportError("TRANSPORT_TIMEOUT", "dns read timeout") from exc
        except (ConnectionError, OSError) as exc:
            raise LiveTransportError("TRANSPORT_FAILURE", "dns read failed") from exc
        if not chunk:
            raise LiveTransportError("TRANSPORT_FAILURE", "dns truncated")
        out += chunk
    return bytes(out)
