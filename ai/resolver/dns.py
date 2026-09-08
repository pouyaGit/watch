"""DNS resolution abstraction for TargetResolver (Phase 5C).

The architecture's normative enforcement point is the actual
connection (pinned resolver + dial-by-IP, owned by future 5E/5F/5G
transport). This module provides the 5C observation half:

- :class:`DnsResolver`: dependency-injected resolution interface. No
  live adapter exists in 5C — only this boundary plus the
  deterministic :class:`FakeDnsResolver` used by tests. Introducing a
  live adapter later must preserve the pinned-answer contract
  (resolve once per execution; transport dials the pinned addresses
  with SNI/Host preserved; any re-resolution mismatch aborts).
- :func:`classify_address`: pure IP-safety classification implementing
  the architecture's deny policy (loopback, unspecified, private,
  link-local, multicast, reserved, metadata-service ranges,
  IPv4-mapped IPv6 unfolding, unique-local IPv6). Only globally
  routable unicast addresses pass; everything else — and anything
  unparseable — fails closed.
- :func:`validate_answers`: answer-count ceiling (frozen
  ``dns_answers``) + per-address classification + deterministic
  ordering. Oversized sets are never truncated; mixed safe/unsafe
  sets are never filtered to "first clean wins".

This module is DETERMINISTIC and OFFLINE:

- NO live DNS, NO sockets, NO subprocess, NO database, NO LLM.
  ``ipaddress`` performs local computation only.
"""

from __future__ import annotations

import ipaddress
from typing import Protocol

from ai.evidence.scrubber import contains_secret_shape
from ai.limits.ceilings import CEILINGS

__all__ = [
    "MAX_DNS_ANSWERS",
    "DNS_ERROR_CODES",
    "DnsError",
    "DnsResolver",
    "FakeDnsResolver",
    "FakeDnsFailure",
    "classify_address",
    "validate_answers",
]

#: Frozen ceiling: maximum DNS answers processed per resolution.
#: Oversized answer sets fail closed (never truncated).
MAX_DNS_ANSWERS = CEILINGS["dns_answers"]

#: Closed error vocabulary for DNS observation failures. Details are
#: static templates: raw resolver exceptions, answer contents, and
#: credentials never enter error strings.
DNS_ERROR_CODES = frozenset(
    {
        "DNS_NXDOMAIN",
        "DNS_SERVFAIL",
        "DNS_TIMEOUT",
        "DNS_UNSAFE_ADDRESS",
        "DNS_TOO_MANY_ANSWERS",
        "DNS_RESOLUTION_FAILED",
        "DNS_MALFORMED_ANSWER",
    }
)

#: Hostnames that are denied even before resolution answers arrive.
#: ``localhost`` and its common aliases can never become dial targets;
#: the fake resolver maps them to loopback so the standard unsafe path
#: exercises, and defense-in-depth rejects the token itself.
_DENIED_HOST_TOKENS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "localdomain",
        "metadata.google",
        "metadata.google.internal",
        "instance-data",
        "instance-data.compute.internal",
    }
)


class DnsError(ValueError):
    """Closed DNS observation failure (secret-free, bounded)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in DNS_ERROR_CODES:
            raise ValueError(f"unknown DNS error code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("DNS error detail must be single-line")
        if contains_secret_shape(safe_detail):
            raise ValueError(
                "DNS error detail carries suspected secret material"
            )
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


class DnsResolver(Protocol):
    """Injected resolution interface (observation only, never dial)."""

    name: str

    def resolve(self, canonical_host: str) -> tuple[str, ...]:
        """Return raw answer address strings for a canonical host.

        Raises :class:`DnsError` with a closed code on any failure.
        Implementations must not retry unboundedly, follow chains
        beyond the returned answer set, or perform any connection.
        """
        ...  # pragma: no cover


class FakeDnsFailure(DnsError):
    """Pre-programmed fake failure (test fixture signal)."""


class FakeDnsResolver:
    """Deterministic offline fixture implementing :class:`DnsResolver`.

    ``mapping`` binds canonical host -> answer list (raw address
    strings, which may include hostile/malformed entries by design) or
    a :class:`FakeDnsFailure` to raise. Unknown hosts raise
    ``DNS_NXDOMAIN`` (closed world = deterministic). Denied tokens
    (``localhost``, metadata aliases) always raise
    ``DNS_UNSAFE_ADDRESS`` without consulting the mapping.
    """

    name = "fake-dns/v1"

    def __init__(
        self, mapping: dict[str, list[str] | FakeDnsFailure] | None = None
    ) -> None:
        if mapping is not None and not isinstance(mapping, dict):
            raise TypeError(
                "FakeDnsResolver mapping must be a dict, "
                f"not {type(mapping).__name__}"
            )
        self._mapping: dict[str, list[str] | FakeDnsFailure] = dict(
            mapping or {}
        )

    def resolve(self, canonical_host: str) -> tuple[str, ...]:
        if not isinstance(canonical_host, str):
            raise TypeError(
                "resolve accepts only a canonical host string, "
                f"not {type(canonical_host).__name__}"
            )
        if canonical_host in _DENIED_HOST_TOKENS:
            raise DnsError(
                "DNS_UNSAFE_ADDRESS", "host token is never resolvable"
            )
        entry = self._mapping.get(canonical_host)
        if entry is None:
            raise DnsError("DNS_NXDOMAIN", "no fixture answer for host")
        if isinstance(entry, DnsError):
            raise DnsError(entry.code, entry.detail)
        if not isinstance(entry, (list, tuple)):
            raise TypeError("fixture answers must be a list of strings")
        return tuple(entry)


def classify_address(value: object) -> str:
    """Classify one answer string; return canonical IP text or fail.

    Unwraps IPv4-mapped IPv6 and polices the inner address. Only
    globally routable unicast addresses pass. Raises ``DnsError`` with
    ``DNS_MALFORMED_ANSWER`` for unparseable input and
    ``DNS_UNSAFE_ADDRESS`` for any denied class. The input value is
    never reflected into the error (secret-free by construction).
    """

    if not isinstance(value, str) or not value:
        raise DnsError("DNS_MALFORMED_ANSWER", "answer is not a string")
    text = value.strip()
    if not text or text != value:
        raise DnsError("DNS_MALFORMED_ANSWER", "answer has bad padding")
    if "%" in text:
        # Zone-scoped literals are link-local by definition: deny.
        raise DnsError("DNS_UNSAFE_ADDRESS", "scoped address denied")
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise DnsError(
            "DNS_MALFORMED_ANSWER", "answer is not an IP literal"
        ) from exc
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        # IPv4-mapped IPv6 is policed as its inner IPv4 address.
        parsed = parsed.ipv4_mapped
    if (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
        or not parsed.is_global
    ):
        raise DnsError("DNS_UNSAFE_ADDRESS", "non-global address denied")
    return str(parsed)


def validate_answers(answers: object) -> tuple[str, ...]:
    """Enforce ceiling + safety + deterministic order on one answer set.

    - Empty sets raise ``DNS_RESOLUTION_FAILED`` (fail closed: 5D must
      never evaluate an address-less target as safe).
    - Oversized sets raise ``DNS_TOO_MANY_ANSWERS`` (never truncated:
      truncation would turn an attacker-inflated set into an
      apparently safe target).
    - Any unsafe/malformed entry fails the whole set (no silent
      discard, no "first clean wins"): an ambiguous resolution never
      becomes an apparently safe target.
    - Success returns the deduplicated canonical addresses sorted by
      numeric value, so input order never affects identity.
    """

    if not isinstance(answers, (list, tuple)):
        raise TypeError(
            "validate_answers accepts only a list/tuple, "
            f"not {type(answers).__name__}"
        )
    if len(answers) == 0:
        raise DnsError("DNS_RESOLUTION_FAILED", "empty answer set")
    if len(answers) > MAX_DNS_ANSWERS:
        raise DnsError("DNS_TOO_MANY_ANSWERS", "answer set over ceiling")
    canonical = [classify_address(item) for item in answers]
    ordered = sorted(
        set(canonical),
        key=lambda text: (
            ipaddress.ip_address(text).version,
            int(ipaddress.ip_address(text)),
        ),
    )
    return tuple(ordered)
