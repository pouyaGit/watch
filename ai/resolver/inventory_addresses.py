"""B1 inventory address source (Stage 2 production read path).

A ``DnsResolver`` implementation that serves EXPLICITLY REVIEWED,
already-known address facts (e.g. derived from Watch
``Http.ips`` / ``LiveSubdomains.ips`` inventory observations) instead
of performing DNS.

Position in the pipeline::

    Watch inventory rows (Http/LiveSubdomains, read-only)
        |
        v  (operator/curator review — explicit, per program+host)
    AddressReview (facts with provenance, never authorization)
        |
        v
    InventoryAddressSource (this module, ``DnsResolver`` protocol)
        |
        v  (existing frozen gate, never duplicated)
    ai.resolver.dns.validate_answers (ceiling + whole-set safety)
        |
        v
    TargetResolver (unchanged 5C; exact-pair inventory gate still applies)

Security posture (all test-enforced):

- No DNS, no sockets, no subprocess, no network, no database driver,
  no LLM. This module imports ``ipaddress``-backed pure helpers only
  (via ``ai.resolver.dns``) and performs local computation alone.
- Facts, never authorization: a review can never grant scope or
  execution permission. Cross-program confusion stays impossible
  because 5C still resolves through the exact
  ``(program_name, canonical_host)`` inventory pair and 5D still
  evaluates scope independently.
- Closed world per source instance: one instance serves exactly one
  program. Unknown hosts raise ``DNS_NXDOMAIN`` (same closed-world
  rule as ``FakeDnsResolver``) — there is deliberately no implicit
  DNS/network fallback.
- No silent choice: two reviews for the same host with different
  address sets poison the slot — every ``resolve()`` for it raises
  ``DNS_RESOLUTION_FAILED`` (conflict), never first-wins.
- Whole-set safety is inherited, not reimplemented: every answer set
  passes through the frozen ``validate_answers`` (ceiling, any-unsafe
  fails all, deterministic numeric order).
- Staleness is explicit: a review carries ``reviewed_at``; when the
  source is constructed with ``max_age_seconds``, expired facts raise
  ``DNS_RESOLUTION_FAILED`` instead of serving stale addresses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.dns import DnsError, validate_answers

__all__ = [
    "SOURCE_NAME",
    "SOURCE_VERSION",
    "AddressReview",
    "InventoryAddressSource",
]

#: Explicit source identity (recorded by callers, versioned so a
#: source change forks downstream finding identity).
SOURCE_NAME = "inventory-address-source/v1"
SOURCE_VERSION = "inventory-address-source/v1"


def _parse_instant(value: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"malformed instant: {value!r}") from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


@dataclass(frozen=True)
class AddressReview:
    """One explicitly reviewed address-fact set (observation, not permit).

    ``addresses`` are raw answer strings as observed in Watch
    inventory (they may include hostile/malformed entries by design —
    the frozen ``validate_answers`` gate polices them at resolve
    time). ``source`` names the inventory origin
    (e.g. ``"watch-inventory:Http.ips"``); ``reviewer`` names the
    curator; ``reviewed_at`` is the review instant (ISO-8601).
    """

    program_name: str
    canonical_host: str
    addresses: tuple[str, ...] = field(default_factory=tuple)
    source: str = "watch-inventory:Http.ips"
    reviewer: str = "security-operator"
    reviewed_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.program_name, str) or not self.program_name.strip():
            raise ValueError("review requires a non-empty program_name")
        if "\n" in self.program_name or "\r" in self.program_name:
            raise ValueError("program_name must be single-line")
        try:
            canonical, kind = canonicalize_host(self.canonical_host)
        except (CanonicalizationError, TypeError) as exc:
            raise ValueError("review host is not canonical") from exc
        if kind != "dns" or canonical != self.canonical_host:
            raise ValueError("review host is not a canonical dns host")
        if not isinstance(self.addresses, (list, tuple)) or not self.addresses:
            # An approved EMPTY set is meaningless: absence of facts
            # must be explicit absence of a review (closed world),
            # never an approved empty answer set.
            raise ValueError("review requires a non-empty address list")
        for entry in self.addresses:
            if not isinstance(entry, str) or not entry:
                raise ValueError("review addresses must be non-empty strings")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("review requires a source label")
        if not isinstance(self.reviewer, str) or not self.reviewer.strip():
            raise ValueError("review requires a reviewer label")
        _parse_instant(self.reviewed_at)
        object.__setattr__(self, "addresses", tuple(self.addresses))


class InventoryAddressSource:
    """Reviewed-facts ``DnsResolver`` for exactly one program.

    ``reviews`` is the complete explicit review set for the program;
    two reviews for the same host with different address sets poison
    that slot (conflict → fail closed at resolve time). The source
    performs no I/O of any kind.
    """

    name = SOURCE_VERSION

    def __init__(
        self,
        *,
        program_name: str,
        reviews: list[AddressReview] | tuple[AddressReview, ...],
        max_age_seconds: int | None = None,
        now_iso: str | None = None,
    ) -> None:
        if not isinstance(program_name, str) or not program_name.strip():
            raise TypeError("InventoryAddressSource requires a program_name")
        if not isinstance(reviews, (list, tuple)):
            raise TypeError("reviews must be a list or tuple of AddressReview")
        for item in reviews:
            if not isinstance(item, AddressReview):
                raise TypeError(
                    "reviews must be AddressReview, "
                    f"not {type(item).__name__}"
                )
            if item.program_name != program_name:
                raise ValueError(
                    "review program does not match source program"
                )
        if max_age_seconds is not None and (
            not isinstance(max_age_seconds, int)
            or isinstance(max_age_seconds, bool)
            or max_age_seconds < 0
        ):
            raise ValueError("max_age_seconds must be a non-negative int or None")
        if now_iso is not None and not isinstance(now_iso, str):
            raise TypeError("now_iso must be an ISO-8601 string or None")
        if now_iso is not None:
            _parse_instant(now_iso)
        self._program = program_name
        self._max_age = max_age_seconds
        self._now = now_iso
        # Slot map: host -> review, plus the poisoned (conflicted) set.
        self._slots: dict[str, AddressReview] = {}
        self._poisoned: set[str] = set()
        for item in sorted(reviews, key=lambda r: r.canonical_host):
            host = item.canonical_host
            if host in self._poisoned:
                continue
            existing = self._slots.get(host)
            if existing is None:
                self._slots[host] = item
            elif set(existing.addresses) != set(item.addresses):
                # Conflicting facts for one slot: poison it. Neither
                # set is served; resolve() fails closed.
                del self._slots[host]
                self._poisoned.add(host)
            # Identical re-review: idempotent, first wins (same facts).

    @property
    def program_name(self) -> str:
        return self._program

    def resolve(self, canonical_host: str) -> tuple[str, ...]:
        """Serve reviewed facts for one canonical host (no I/O).

        Unknown hosts → ``DNS_NXDOMAIN`` (closed world, no fallback).
        Poisoned (conflicted) slots and stale reviews →
        ``DNS_RESOLUTION_FAILED``. Surviving sets pass through the
        frozen ``validate_answers`` gate (whole-set safety + ceiling +
        deterministic order).
        """
        if not isinstance(canonical_host, str):
            raise TypeError(
                "resolve accepts only a canonical host string, "
                f"not {type(canonical_host).__name__}"
            )
        if canonical_host in self._poisoned:
            raise DnsError(
                "DNS_RESOLUTION_FAILED", "conflicting address facts for host"
            )
        review = self._slots.get(canonical_host)
        if review is None:
            raise DnsError("DNS_NXDOMAIN", "no reviewed facts for host")
        if self._max_age is not None and self._now is not None:
            age = (
                _parse_instant(self._now) - _parse_instant(review.reviewed_at)
            ).total_seconds()
            if age < 0 or age > self._max_age:
                raise DnsError(
                    "DNS_RESOLUTION_FAILED", "reviewed address facts are stale"
                )
        return validate_answers(list(review.addresses))
