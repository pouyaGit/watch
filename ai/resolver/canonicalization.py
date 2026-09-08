"""Deterministic fail-closed target canonicalization (Phase 5C).

Single shared canonicalizer implementing the architecture's URL
canonicalization rules (``execution-authorization-architecture.md``
§18) for the resolver stage: scheme allowlist, hostname lowercase +
trailing-dot strip + IDNA, userinfo rejection, IPv6 bracket handling,
IPv4-mapped awareness, non-decimal IP-literal parsing, and effective
ports (explicit-default equivalence).

Fail-closed contract: any ambiguity — whitespace, control characters,
wildcards, credentials, malformed labels, empty labels, invalid IDNA,
unparseable numerics, unknown schemes, out-of-range ports — raises
:class:`CanonicalizationError` with a static, caller-value-free
message. There is no "best effort" normalization path.

This module is PURE and DETERMINISTIC:

- NO network, NO DNS, NO subprocess, NO database, NO LLM, NO scope
  evaluation, NO execution. Only ``re`` + ``ipaddress`` from the
  standard library (both perform local computation, never I/O).
"""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple

__all__ = [
    "SCHEMES",
    "DEFAULT_PORTS",
    "MAX_HOSTNAME_LENGTH",
    "MAX_LABEL_LENGTH",
    "CanonicalizationError",
    "CanonicalAuthority",
    "canonicalize_host",
    "canonicalize_scheme",
    "canonicalize_port",
    "canonicalize_target",
]

#: Schemes the resolver stage admits. Anything else (ftp, file,
#: javascript, data, gopher, ...) fails closed here; 5D re-checks.
SCHEMES = ("http", "https")

DEFAULT_PORTS = {"http": 80, "https": 443}

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

#: Numeric-ish tokens that must be interpreted as IP literals in
#: decimal/octal/hex notation (never as DNS names), per the
#: architecture's non-decimal-literal rule.
_NUMERIC_TOKEN_RE = re.compile(r"^[0-9a-fA-FxX.]+$")
_NUMERIC_PART_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-9]+|[0-9]+)$")

_IPV6_BRACKETED_RE = re.compile(r"^\[([^\[\]]+)\]$")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CanonicalizationError(ValueError):
    """Deterministic fail-closed canonicalization failure.

    Messages are static templates without caller-supplied values, so
    credentials or control characters in hostile input can never be
    reflected into logs, errors, or audit records.
    """

    _CODES = frozenset(
        {
            "INVALID_HOST",
            "INVALID_SCHEME",
            "INVALID_PORT",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            raise ValueError(f"unknown canonicalization code: {code!r}")
        super().__init__(code)
        self.code = code


class CanonicalAuthority(NamedTuple):
    """Canonical target authority (identity, not reachability)."""

    scheme: str
    canonical_host: str
    host_kind: str
    effective_port: int
    port_explicit: bool


def _has_control_or_whitespace(value: str) -> bool:
    for char in value:
        if ord(char) < 32 or ord(char) == 127 or char.isspace():
            return True
    return False


def _parse_numeric_part(part: str) -> int | None:
    """Parse one dotted-numeric component (decimal/octal/hex)."""

    if not _NUMERIC_PART_RE.match(part):
        return None
    try:
        if part.lower().startswith("0x"):
            return int(part, 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part, 8)
        return int(part, 10)
    except ValueError:
        return None


def _inet_aton_canonical(value: str) -> str | None:
    """Classic dotted-numeric -> dotted-decimal, or None if unparseable.

    Accepts 1–4 components (``127.1``, ``0x7f.0.0.1``,
    ``2130706433``) exactly like historical ``inet_aton``. Returns the
    canonical dotted-decimal string; returns None when the token is
    not a well-formed numeric address (the caller then fails closed
    instead of guessing).
    """

    parts = value.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    numbers: list[int] = []
    for part in parts:
        if not part:
            return None
        number = _parse_numeric_part(part)
        if number is None:
            return None
        numbers.append(number)
    if len(numbers) == 1:
        if not 0 <= numbers[0] <= 0xFFFFFFFF:
            return None
        address = numbers[0]
    elif len(numbers) == 2:
        first, last = numbers
        if not (0 <= first <= 255 and 0 <= last <= 0xFFFFFF):
            return None
        address = (first << 24) | last
    elif len(numbers) == 3:
        first, second, last = numbers
        if not (0 <= first <= 255 and 0 <= second <= 255 and 0 <= last <= 0xFFFF):
            return None
        address = (first << 24) | (second << 16) | last
    else:
        if any(not 0 <= number <= 255 for number in numbers):
            return None
        address = (
            (numbers[0] << 24)
            | (numbers[1] << 16)
            | (numbers[2] << 8)
            | numbers[3]
        )
    return ".".join(
        str((address >> shift) & 0xFF) for shift in (24, 16, 8, 0)
    )


def _unfold_mapped(parsed: object) -> tuple[str, str] | None:
    """Unfold IPv4-mapped IPv6 to its inner IPv4 literal (or None)."""

    if isinstance(parsed, ipaddress.IPv6Address):
        inner = parsed.ipv4_mapped
        if inner is not None:
            return (str(inner), "ipv4")
    return None


def canonicalize_host(host: object) -> tuple[str, str]:
    """Canonicalize a hostname to ``(canonical_host, host_kind)``.

    ``host_kind`` is one of ``"dns"``, ``"ipv4"``, ``"ipv6"``. IPv4
    literals (decimal/octal/hex/dotted-numeric) and IPv6 literals
    (bracketed or bare) are recognized and returned in canonical text
    form; everything else must survive IDNA + label validation as a
    DNS name. Raises :class:`CanonicalizationError` on any ambiguity.
    """

    if not isinstance(host, str):
        raise TypeError(
            "canonicalize_host accepts only str, "
            f"not {type(host).__name__}"
        )
    if not host:
        raise CanonicalizationError("INVALID_HOST")
    if _has_control_or_whitespace(host):
        raise CanonicalizationError("INVALID_HOST")
    if "@" in host:
        # Embedded credentials/userinfo never travel in resolver input.
        raise CanonicalizationError("INVALID_HOST")
    if "*" in host:
        # Wildcard syntax is scope-list vocabulary, never an identity.
        raise CanonicalizationError("INVALID_HOST")
    if "/" in host or "?" in host or "#" in host or ":" in host and host.count(
        ":"
    ) >= 1 and "[" not in host and _looks_like_url_or_port(host):
        raise CanonicalizationError("INVALID_HOST")

    token = host
    if token.endswith("."):
        # Exactly one trailing root dot is stripped (architecture §18);
        # anything left over (empty labels, double dots) fails below.
        token = token[:-1]
    if not token:
        raise CanonicalizationError("INVALID_HOST")
    lowered = token.lower()

    bracketed = _IPV6_BRACKETED_RE.match(lowered)
    if bracketed:
        inner = bracketed.group(1)
        if "%" in inner:
            # Zone identifiers are link-scoped and never canonical.
            raise CanonicalizationError("INVALID_HOST")
        try:
            parsed = ipaddress.ip_address(inner)
        except ValueError as exc:
            raise CanonicalizationError("INVALID_HOST") from exc
        if not isinstance(parsed, ipaddress.IPv6Address):
            raise CanonicalizationError("INVALID_HOST")
        unfolded = _unfold_mapped(parsed)
        if unfolded is not None:
            return unfolded
        return (str(parsed), "ipv6")

    # Bare IP literals (v4 dotted-decimal, v6 text) parse directly.
    try:
        parsed = ipaddress.ip_address(lowered)
    except ValueError:
        parsed = None
    if parsed is not None:
        if "%" in lowered:
            raise CanonicalizationError("INVALID_HOST")
        if isinstance(parsed, ipaddress.IPv4Address):
            return (str(parsed), "ipv4")
        unfolded = _unfold_mapped(parsed)
        if unfolded is not None:
            return unfolded
        return (str(parsed), "ipv6")

    # Non-decimal / dotted-numeric IP obfuscations are policed as IPs
    # (architecture §17): parseable numerics become IPv4 literals;
    # numeric-looking tokens that fail to parse are ambiguous and die.
    if _NUMERIC_TOKEN_RE.match(lowered) and (
        "." in lowered or lowered.startswith("0x") or lowered.isdigit()
    ):
        dotted = _inet_aton_canonical(lowered)
        if dotted is None:
            raise CanonicalizationError("INVALID_HOST")
        return (dotted, "ipv4")

    if "%" in lowered:
        raise CanonicalizationError("INVALID_HOST")
    try:
        ascii_host = lowered.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise CanonicalizationError("INVALID_HOST") from exc
    if len(ascii_host) > MAX_HOSTNAME_LENGTH:
        raise CanonicalizationError("INVALID_HOST")
    labels = ascii_host.split(".")
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH:
            raise CanonicalizationError("INVALID_HOST")
        if not _LABEL_RE.match(label):
            raise CanonicalizationError("INVALID_HOST")
    return (ascii_host, "dns")


def _looks_like_url_or_port(token: str) -> bool:
    """True when ``:`` more likely means URL/port syntax than IPv6."""

    if "://" in token:
        return True
    # A single colon followed by digits is port syntax, not an address
    # (bare IPv6 without brackets carries 2+ colons).
    if token.count(":") == 1:
        _, _, suffix = token.partition(":")
        if suffix.isdigit():
            return True
    return False


def canonicalize_scheme(scheme: object) -> str:
    """Lowercase + allowlist ``http``/``https`` (fail closed)."""

    if not isinstance(scheme, str):
        raise TypeError(
            "canonicalize_scheme accepts only str, "
            f"not {type(scheme).__name__}"
        )
    lowered = scheme.lower()
    if lowered not in SCHEMES:
        raise CanonicalizationError("INVALID_SCHEME")
    return lowered


def canonicalize_port(scheme: str, port: object) -> tuple[int, bool]:
    """Effective port + explicitness flag (fail closed).

    ``None`` maps to the scheme default (explicit=False). Any integer
    1–65535 is accepted with explicit=True — including an explicitly
    stated default (``:443`` on https), which is canonically identical
    to the omitted form. Booleans, strings, floats, zero, negatives,
    and values above 65535 are rejected (never coerced).
    """

    if port is None:
        return (DEFAULT_PORTS[scheme], False)
    if isinstance(port, bool) or not isinstance(port, int):
        raise CanonicalizationError("INVALID_PORT")
    if not 1 <= port <= 65535:
        raise CanonicalizationError("INVALID_PORT")
    return (port, True)


def canonicalize_target(
    host: object, scheme: object, port: object = None
) -> CanonicalAuthority:
    """Canonicalize one target authority tuple (pure, deterministic)."""

    canonical_scheme = canonicalize_scheme(scheme)
    canonical_host, host_kind = canonicalize_host(host)
    effective_port, explicit = canonicalize_port(canonical_scheme, port)
    return CanonicalAuthority(
        scheme=canonical_scheme,
        canonical_host=canonical_host,
        host_kind=host_kind,
        effective_port=effective_port,
        port_explicit=explicit,
    )
