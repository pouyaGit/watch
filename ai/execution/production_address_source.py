"""Production DNS address source (Phase B1).

B1 production ``DnsResolver`` adapter implementing the frozen
``ai.resolver.dns.DnsResolver`` protocol. This is the ONLY resolver the
production ``HopResolver`` may call.

Security posture (normative per
``agent-reports/b1-live-dial-policy-architecture.md`` §4):

- Explicit operator-configured resolver IP literals. No ambient
  resolver discovery (no ``resolv.conf`` search domains, no ``ndots``
  heuristics, no mDNS/LLMNR/NSS plugins), no caller-selected
  resolver: ``server_ips`` is fixed at construction and immutable.
- The canonical host is resolved EXACTLY as given (post-5C
  canonicalization); no search-domain expansion is ever applied.
- Raw answers are returned to the frozen ``validate_answers`` gate
  (ceiling 8, whole-set failure, deterministic numeric order). This
  module never duplicates 5C validation logic: classification and
  ordering belong to ``ai.resolver.dns`` alone.
- CNAME records may be followed INTERNALLY only to terminal A/AAAA
  answers. A CNAME identity itself NEVER authorizes anything, is
  never pinned as identity, and never enters the dial set. The
  CNAME chain is bounded (8 links); SRV/TXT/service-discovery
  records are never consulted for destination selection.
- TCP-capable: the wire exchange is delegated to an injected
  ``exchange`` callable (production wiring passes
  ``live_transport.dns_tcp_exchange``). This module performs NO
  socket I/O itself and imports neither ``socket`` nor ``ssl`` — the
  no-implicit-DNS proof depends on that confinement.
- One resolution attempt per hop: exactly one exchange against the
  first configured server per ``resolve()`` call. No retries, no
  failover, no cross-hop cache. Transient failure is a fail-closed
  ``DnsError``; retry requires a NEW authorization (ledger rule).
- Resolver identity/version is explicit, immutable, and recorded on
  every resolution (``resolver_name``, ``resolver_version``,
  ``resolver_config_hash``), so a resolver change forks finding
  identity instead of silently reinterpreting history.

This module is OFFLINE except through the injected ``exchange``
callable: no sockets, no subprocess, no database, no LLM, no
findings, no verdicts. Production live traffic remains disabled
(``LIVE_TRAFFIC_ENABLED`` is ``False``); this adapter serves the
fixture-network test path and the reviewed activation path only.
"""

from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass
from typing import Callable

from ai.evidence import hashing as hash_mod
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.dns import (
    MAX_DNS_ANSWERS,
    DnsError,
    validate_answers,
)

__all__ = [
    "RESOLVER_NAME",
    "RESOLVER_VERSION",
    "DNS_TRANSPORT",
    "MAX_CNAME_LINKS",
    "ProductionAddressSource",
    "ProductionAnswerInfo",
    "build_dns_query",
    "parse_dns_response",
]

#: Explicit resolver identity (immutable; versioned so a resolver
#: change forks downstream finding identity).
RESOLVER_NAME = "prod-dns-stub"
RESOLVER_VERSION = "prod-dns-stub/v1"

#: Wire transport used by the production exchange helper.
DNS_TRANSPORT = "tcp"

#: CNAME chain ceiling (mirrors the ``dns_answers`` ceiling).
MAX_CNAME_LINKS = MAX_DNS_ANSWERS

#: Bounded connect/read timeout family (mirrors frozen ceilings).
_QUERY_TIMEOUT_SECONDS = 10.0

_DNS_TYPE_A = 1
_DNS_TYPE_CNAME = 5
_DNS_TYPE_AAAA = 28
_DNS_CLASS_IN = 1


def _require_server_literal(value: object) -> str:
    """Operator resolver entries must be plain IP literals."""

    if not isinstance(value, str) or not value:
        raise TypeError(
            "resolver server entries must be IP literal strings, "
            f"not {type(value).__name__}"
        )
    text = value.strip()
    if text != value or not text:
        raise ValueError("resolver server entry is not canonical")
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(
            "resolver server entry is not an IP literal"
        ) from exc
    return str(parsed)


def build_dns_query(canonical_host: str, query_id: int) -> bytes:
    """Encode one minimal DNS query (A + AAAA) for an exact name.

    Pure function: no I/O. The name is used EXACTLY as given — no
    search-domain expansion, no ``ndots`` heuristics.
    """

    if not isinstance(canonical_host, str) or not canonical_host:
        raise ValueError("query host must be a non-empty string")
    if not isinstance(query_id, int) or not 0 <= query_id <= 0xFFFF:
        raise ValueError("query id must be a uint16")
    labels = canonical_host.rstrip(".").split(".")
    qname = b""
    for label in labels:
        raw = label.encode("ascii") if label else b""
        if not raw or len(raw) > 63:
            raise ValueError("query host has a bad label")
        qname += bytes((len(raw),)) + raw
    qname += b"\x00"
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    # Two questions: A then AAAA (single round trip, no family racing
    # downstream — ordering is fixed by validate_answers, not by
    # answer arrival order).
    body = qname + struct.pack(">HH", _DNS_TYPE_A, _DNS_CLASS_IN)
    body += qname + struct.pack(">HH", _DNS_TYPE_AAAA, _DNS_CLASS_IN)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 2, 0, 0, 0)
    return header + body


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; return (text, next)."""

    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen: set[int] = set()
    while True:
        if offset >= len(data):
            raise ValueError("dns name overruns packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("dns pointer overruns packet")
            target = ((length & 0x3F) << 8) | data[offset + 1]
            if target in seen:
                raise ValueError("dns pointer loop")
            seen.add(target)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = target
            continue
        if length == 0:
            return (".".join(labels), next_offset if jumped else offset + 1)
        if length & 0xC0:
            raise ValueError("dns reserved label bits")
        offset += 1
        if offset + length > len(data):
            raise ValueError("dns label overruns packet")
        try:
            labels.append(data[offset : offset + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("dns label not ascii") from exc
        offset += length
        if len(labels) > 64:
            raise ValueError("dns name too deep")


def parse_dns_response(data: bytes, query_id: int) -> tuple[list[tuple[int, str, int]], list[str]]:
    """Parse a DNS response into ``([(type, rdata, ttl)], [cname])``.

    Pure function: no I/O. Only IN-class A/AAAA/CNAME records are
    surfaced; every other type (SRV/TXT/...) is ignored so it can
    never drive destination selection. Malformed packets raise
    ``ValueError`` (the caller maps to a closed ``DnsError``).
    """

    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        raise ValueError("dns packet too short")
    raw = bytes(data)
    (resp_id, flags, qdcount, ancount, _, _) = struct.unpack(">HHHHHH", raw[:12])
    if resp_id != query_id:
        raise ValueError("dns id mismatch")
    if not flags & 0x8000:
        raise ValueError("dns not a response")
    if flags & 0x000F != 0:
        raise ValueError("dns error status")
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(raw, offset)
        if offset + 4 > len(raw):
            raise ValueError("dns question overruns packet")
        offset += 4
    answers: list[tuple[int, str, int]] = []
    cnames: list[str] = []
    for _ in range(ancount):
        _, offset = _read_name(raw, offset)
        if offset + 10 > len(raw):
            raise ValueError("dns answer overruns packet")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", raw[offset : offset + 10])
        offset += 10
        if offset + rdlen > len(raw):
            raise ValueError("dns rdata overruns packet")
        rdata = raw[offset : offset + rdlen]
        offset += rdlen
        if rclass != _DNS_CLASS_IN:
            continue
        if rtype == _DNS_TYPE_A and rdlen == 4:
            answers.append((rtype, str(ipaddress.IPv4Address(rdata)), ttl))
        elif rtype == _DNS_TYPE_AAAA and rdlen == 16:
            answers.append((rtype, str(ipaddress.IPv6Address(rdata)), ttl))
        elif rtype == _DNS_TYPE_CNAME:
            target, _ = _read_name(raw, offset - rdlen)
            cnames.append(target)
        # All other types ignored by construction.
    return answers, cnames


@dataclass(frozen=True)
class ProductionAnswerInfo:
    """Per-resolution metadata bound into the dial proof."""

    resolver_name: str
    resolver_version: str
    resolver_config_hash: str
    transport: str
    server_ips: tuple[str, ...]
    resolved_at: str
    ttl_seen: int | None
    cname_chain: tuple[str, ...]
    raw_answer_count: int


class ProductionAddressSource:
    """Pinned production DNS stub implementing ``DnsResolver``.

    ``exchange`` is ``(server_ip, query_bytes, timeout) -> bytes``.
    Production wiring injects ``live_transport.dns_tcp_exchange``;
    tests inject scripted fakes. ``None`` fails closed (no ambient
    DNS is ever attempted).
    """

    name = RESOLVER_VERSION

    def __init__(
        self,
        *,
        server_ips: list[str] | tuple[str, ...],
        resolver_name: str = RESOLVER_NAME,
        resolver_version: str = RESOLVER_VERSION,
        exchange: Callable[[str, bytes, float], bytes] | None = None,
        timeout_seconds: float = _QUERY_TIMEOUT_SECONDS,
        now_iso: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(server_ips, (list, tuple)) or not server_ips:
            raise TypeError("server_ips must be a non-empty list of IP literals")
        canonical_servers = tuple(_require_server_literal(item) for item in server_ips)
        if len(set(canonical_servers)) != len(canonical_servers):
            raise ValueError("resolver server entries must be distinct")
        if not isinstance(resolver_name, str) or not resolver_name:
            raise TypeError("resolver_name must be a non-empty string")
        if not isinstance(resolver_version, str) or not resolver_version:
            raise TypeError("resolver_version must be a non-empty string")
        if exchange is not None and not callable(exchange):
            raise TypeError("exchange must be callable or None")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 60
        ):
            raise ValueError("timeout_seconds must be in (0, 60]")
        if now_iso is not None and not callable(now_iso):
            raise TypeError("now_iso must be callable or None")
        self._server_ips = canonical_servers
        self._resolver_name = resolver_name
        self._resolver_version = resolver_version
        self._exchange = exchange
        self._timeout = float(timeout_seconds)
        self._now_iso = now_iso
        self._config_hash = hash_mod.hash_payload(
            {
                "resolver_name": resolver_name,
                "resolver_version": resolver_version,
                "server_ips": list(canonical_servers),
                "transport": DNS_TRANSPORT,
            }
        )
        self._last_info: ProductionAnswerInfo | None = None

    @property
    def resolver_name(self) -> str:
        """Explicit immutable resolver identity (name)."""
        return self._resolver_name

    @property
    def resolver_version(self) -> str:
        """Explicit immutable resolver identity (version)."""
        return self._resolver_version

    @property
    def server_ips(self) -> tuple[str, ...]:
        """Operator-pinned resolver literals (immutable, fixed order)."""
        return self._server_ips

    @property
    def config_hash(self) -> str:
        """Hash of the pinned resolver configuration."""
        return self._config_hash

    @property
    def last_info(self) -> ProductionAnswerInfo | None:
        """Metadata of the most recent successful resolution."""
        return self._last_info

    def resolve(self, canonical_host: str) -> tuple[str, ...]:
        """Return classified, ordered dial candidates (protocol body)."""
        addresses, _ = self.resolve_with_info(canonical_host)
        return addresses

    def resolve_with_info(
        self, canonical_host: str
    ) -> tuple[tuple[str, ...], ProductionAnswerInfo]:
        """Resolve exactly once; return ``(addresses, info)``."""

        if not isinstance(canonical_host, str):
            raise TypeError(
                "resolve accepts only a canonical host string, "
                f"not {type(canonical_host).__name__}"
            )
        try:
            host, _ = canonicalize_host(canonical_host)
        except (CanonicalizationError, TypeError) as exc:
            raise DnsError("DNS_MALFORMED_ANSWER", "host not canonical") from exc
        if host != canonical_host:
            # No search-domain expansion, no case/encoding repair:
            # the caller must supply the exact 5C canonical host.
            raise DnsError("DNS_MALFORMED_ANSWER", "host not canonical")
        if self._exchange is None:
            raise DnsError("DNS_RESOLUTION_FAILED", "no dns transport configured")
        # Query id is random per attempt (uniqueness only); scripted
        # exchanges recover it from the query bytes (offset 0:2).
        query_id = secrets.randbits(16)
        query = build_dns_query(host, query_id)
        try:
            raw = self._exchange(self._server_ips[0], query, self._timeout)
        except DnsError:
            raise
        except TimeoutError as exc:
            raise DnsError("DNS_TIMEOUT", "resolver exchange timed out") from exc
        except Exception as exc:
            raise DnsError("DNS_RESOLUTION_FAILED", "resolver exchange failed") from exc
        try:
            answers, cnames = parse_dns_response(bytes(raw), query_id)
        except (ValueError, struct.error) as exc:
            raise DnsError("DNS_MALFORMED_ANSWER", "resolver packet malformed") from exc
        if len(cnames) > MAX_CNAME_LINKS:
            raise DnsError("DNS_TOO_MANY_ANSWERS", "cname chain over ceiling")
        # CNAMEs are logged as observation only: only terminal
        # A/AAAA rdata become dial candidates. A response carrying
        # nothing but CNAMEs (no terminal addresses observed in this
        # packet) fails closed rather than triggering follow-up
        # queries that would smear per-hop freshness.
        raw_answers = [text for _, text, _ in answers]
        if not raw_answers:
            raise DnsError("DNS_RESOLUTION_FAILED", "no terminal addresses seen")
        if len(raw_answers) > MAX_DNS_ANSWERS:
            raise DnsError("DNS_TOO_MANY_ANSWERS", "answer set over ceiling")
        # Frozen single acceptance gate: whole-set validation +
        # deterministic numeric ordering (never "first clean wins",
        # never truncated).
        ordered = validate_answers(raw_answers)
        ttls = [ttl for _, _, ttl in answers]
        info = ProductionAnswerInfo(
            resolver_name=self._resolver_name,
            resolver_version=self._resolver_version,
            resolver_config_hash=self._config_hash,
            transport=DNS_TRANSPORT,
            server_ips=self._server_ips,
            resolved_at=self._now_iso() if self._now_iso else "",
            ttl_seen=min(ttls) if ttls else None,
            cname_chain=tuple(cnames[:MAX_CNAME_LINKS]),
            raw_answer_count=len(raw_answers),
        )
        self._last_info = info
        return ordered, info
