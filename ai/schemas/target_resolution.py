"""TargetResolution data contract (Phase 5C).

Position in the pipeline::

    IssuedExecutionAuthorization (5B authority, LIVE only)
        |
        v
    TargetResolver (this phase: canonicalize + inventory + DNS observe)
        |
        v
    TargetResolution (immutable facts, this module)
        |
        v
    5D ScopeEvaluator (verdicts live there, never here)

Trust semantics (normative per
``agent-reports/executor-architecture.md`` §6 and
``agent-reports/execution-authorization-architecture.md`` §§13-18):

- A ``TargetResolution`` is observation, never permission. ``RESOLVED``
  means "the authorized target was canonically identified, found in
  current inventory without drift, and its resolution-time addresses
  were observed and classified safe" — NOT "in scope", NOT "allowed
  to execute", NOT a verdict of any kind.
- No verdict-shaped field may exist on any model in this module
  (``extra="forbid"`` enforces it structurally; tests enumerate the
  forbidden names).
- The canonical target identity is the exact tuple
  ``(program_name, canonical_host, scheme, effective_port)``.
  ``(program_name, canonical_host)`` is the cross-program isolation
  key: the same hostname under two programs never shares identity.
- ``resolved_addresses`` are RESOLUTION-TIME observations pinned for
  future dial-time enforcement. This module does not dial, connect,
  fetch, or verify reachability; it preserves the binding so future
  transport (5E/5F/5G) cannot silently re-resolve to a different
  address.
- Inventory ``ips`` observations and the historical
  ``TargetIntelligence`` snapshot are advisory context only and never
  authority. Fresh DNS observation (via the injected resolver) is the
  only address source recorded here.

This module is PURE and DETERMINISTIC:

- NO network, NO subprocess, NO database, NO LLM, NO scope
  evaluation, NO execution, NO verification, NO findings.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.evidence.hashing import hash_payload
from ai.evidence.scrubber import contains_secret_shape

SCHEMA_VERSION = "target_resolution/v1"

RESOLVER_VERSION = "target-resolver/v1"

ResolutionStatus = Literal[
    "RESOLVED",
    "TARGET_GONE",
    "TARGET_PROGRAM_GONE",
    "TARGET_REASSIGNED",
    "SCOPE_DRIFT",
    "RESOLUTION_FAILED",
]

TERMINAL_FAILURE_STATUSES = frozenset(
    {
        "TARGET_GONE",
        "TARGET_PROGRAM_GONE",
        "TARGET_REASSIGNED",
        "SCOPE_DRIFT",
        "RESOLUTION_FAILED",
    }
)

#: Closed failure vocabulary for ``TargetResolution.failure_code``.
#: ``None`` on every status except ``RESOLUTION_FAILED`` (the remaining
#: terminal statuses are self-describing by design).
ResolutionFailureCode = Literal[
    "TARGET_MALFORMED",
    "INVENTORY_ERROR",
    "DNS_NXDOMAIN",
    "DNS_SERVFAIL",
    "DNS_TIMEOUT",
    "DNS_UNSAFE_ADDRESS",
    "DNS_TOO_MANY_ANSWERS",
    "DNS_RESOLUTION_FAILED",
    "DNS_MALFORMED_ANSWER",
]

HostKind = Literal["dns", "ipv4", "ipv6"]

_RESOLUTION_ID_RE = re.compile(r"^res-[0-9a-f]{16}$")
_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: Field names that must never appear on resolution models. Defense in
#: depth behind ``extra="forbid"``: any future field addition with one
#: of these names fails closed at review time via tests.
FORBIDDEN_RESOLUTION_FIELDS = frozenset(
    {
        "scope_allowed",
        "execution_allowed",
        "verdict",
        "finding",
        "matched",
        "vulnerable",
        "confirmed",
        "not_vulnerable",
        "severity",
        "exploited",
        "scope_verdict",
        "allow",
        "deny",
    }
)


class ResolutionError(ValueError):
    """Bounded, non-secret 5C failure with an explicit code.

    Details are closed-code style: short, caller-value-free, screened
    against secret markers. Raw exceptions, resolver messages, and
    credentials must never flow through here.
    """

    _CODES = frozenset(
        {
            "TARGET_MALFORMED",
            "INVALID_REQUEST",
            "INVENTORY_ERROR",
            "DNS_NXDOMAIN",
            "DNS_SERVFAIL",
            "DNS_TIMEOUT",
            "DNS_UNSAFE_ADDRESS",
            "DNS_TOO_MANY_ANSWERS",
            "DNS_RESOLUTION_FAILED",
            "DNS_MALFORMED_ANSWER",
        }
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self._CODES:
            raise ValueError(f"unknown resolution error code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("resolution error detail must be single-line")
        if contains_secret_shape(safe_detail):
            raise ValueError(
                "resolution error detail carries suspected secret material"
            )
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


def canonical_target_hash_for(
    *,
    program_name: str,
    canonical_host: str,
    scheme: str,
    effective_port: int,
) -> str:
    """Content identity of the canonical target tuple.

    Uses the effective port only, so ``https://host`` and
    ``https://host:443`` share one identity by construction. Address
    lists, timestamps, and snapshots never enter this hash: identity
    is WHO the target is, not what it resolved to.
    """

    return hash_payload(
        {
            "canonical_host": canonical_host,
            "effective_port": effective_port,
            "program_name": program_name,
            "scheme": scheme,
        }
    )


def resolution_id_for(
    *,
    authorization_id: str,
    execution_id: str,
    canonical_target_hash: str,
    resolved_addresses: tuple[str, ...],
    scope_lists_hash_current: str | None,
    snapshot_current: str | None,
) -> str:
    """Deterministic resolution identity (dedupe alias, never proof).

    Same inputs always yield the same id; any binding change (new
    execution, new addresses, new scope lists, new snapshot) yields a
    new resolution. Resolutions are never mutated or rebound: a new
    target requires a new resolution.
    """

    basis = hash_payload(
        {
            "authorization_id": authorization_id,
            "canonical_target_hash": canonical_target_hash,
            "execution_id": execution_id,
            "resolved_addresses": sorted(resolved_addresses),
            "resolver_version": RESOLVER_VERSION,
            "scope_lists_hash_current": scope_lists_hash_current,
            "snapshot_current": snapshot_current,
        }
    )
    return "res-" + basis[:16]


def base_authority_for(
    *, scheme: str, canonical_host: str, effective_port: int, host_kind: str
) -> str:
    """Base authority string (scheme + host + non-default port only).

    Request paths and query strings are never part of resolver
    authority and are never constructed here.
    """

    host_part = f"[{canonical_host}]" if host_kind == "ipv6" else canonical_host
    default = {"http": 80, "https": 443}.get(scheme)
    if default is not None and effective_port == default:
        return f"{scheme}://{host_part}"
    return f"{scheme}://{host_part}:{effective_port}"


class DialBinding(BaseModel):
    """Future-transport dial contract (binding, not enforcement).

    The downstream transport MUST dial one of ``addresses`` with
    ``sni_host`` preserved (TLS verified against the hostname) and
    MUST abort when re-resolution disagrees with this pin. The actual
    enforcement belongs to 5E/5F/5G or the approved egress layer;
    this record only preserves the invariant::

        RESOLVED ADDRESS == AUTHORIZED/DISPATCHED DIAL ADDRESS

    ``TargetResolver`` alone does not solve DNS rebinding; it makes
    silent re-resolution structurally representable as a violation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    addresses: tuple[str, ...]
    effective_port: int
    sni_host: str
    pin_required: Literal[True] = True

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("dial addresses must be non-empty")
        for item in value:
            if not isinstance(item, str) or not item:
                raise ValueError("dial addresses must be non-empty strings")
            try:
                ipaddress.ip_address(item)
            except ValueError as exc:
                raise ValueError(f"dial address is not an IP: {item!r}") from exc
        return value

    @field_validator("effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("effective_port must be an integer")
        if not 1 <= value <= 65535:
            raise ValueError("effective_port out of range")
        return value


class TargetResolution(BaseModel):
    """Immutable facts of one target-resolution attempt.

    Successful (``RESOLVED``) records carry the canonical identity,
    the pinned resolution-time addresses, the inventory binding, and
    the advisory snapshot observations a 5D ScopeEvaluator needs.
    Terminal records carry a self-describing ``status`` (plus a closed
    ``failure_code`` for ``RESOLUTION_FAILED``) and must equally never
    be interpreted as permission.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    resolution_id: str
    authorization_id: str
    execution_id: str
    program_name: str
    host_as_authorized: str
    canonical_host: str
    host_kind: HostKind = "dns"
    scheme: Literal["http", "https"] = "https"
    effective_port: int = 443
    port_explicit: bool = False
    base_authority: str = ""
    path_scope_ref: str = ""
    resolved_addresses: tuple[str, ...] = ()
    dns_answer_count: int = 0
    dns_source: str = ""
    dial: DialBinding | None = None
    scope_lists_hash_authorized: str = ""
    scope_lists_hash_current: str | None = None
    scope_drift: bool | None = None
    inventory_endpoint_base: str | None = None
    reassigned: bool = False
    snapshot_ref: str | None = None
    snapshot_observed: str | None = None
    snapshot_current: str | None = None
    snapshot_match: bool | None = None
    snapshot_stale: bool | None = None
    status: ResolutionStatus = "RESOLUTION_FAILED"
    failure_code: ResolutionFailureCode | None = None
    canonical_target_hash: str = ""
    resolved_at: str = ""
    resolver_version: Literal["target-resolver/v1"] = "target-resolver/v1"
    schema_version: Literal["target_resolution/v1"] = "target_resolution/v1"

    @field_validator("resolution_id")
    @classmethod
    def _resolution_id(cls, value: str) -> str:
        if not _RESOLUTION_ID_RE.match(value or ""):
            raise ValueError(f"invalid resolution_id: {value!r}")
        return value

    @field_validator("authorization_id")
    @classmethod
    def _authorization_id(cls, value: str) -> str:
        if not _AUTHZ_ID_RE.match(value or ""):
            raise ValueError(f"invalid authorization_id: {value!r}")
        return value

    @field_validator("execution_id")
    @classmethod
    def _execution_id(cls, value: str) -> str:
        if not _EXECUTION_ID_RE.match(value or ""):
            raise ValueError(f"invalid execution_id: {value!r}")
        return value

    @field_validator("canonical_target_hash")
    @classmethod
    def _target_hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError("invalid canonical_target_hash")
        return value

    @field_validator("scope_lists_hash_authorized")
    @classmethod
    def _authorized_hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError("invalid scope_lists_hash_authorized")
        return value

    @field_validator("scope_lists_hash_current")
    @classmethod
    def _current_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError("invalid scope_lists_hash_current")
        return value

    @field_validator("snapshot_ref", "snapshot_observed", "snapshot_current")
    @classmethod
    def _snapshot(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError("invalid snapshot hash")
        return value

    @field_validator("effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("effective_port must be an integer")
        if not 1 <= value <= 65535:
            raise ValueError("effective_port out of range")
        return value

    @field_validator("path_scope_ref")
    @classmethod
    def _path(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("path_scope_ref must be single-line")
        if value and not value.startswith("/"):
            raise ValueError("path_scope_ref must start with '/'")
        return value

    @field_validator("resolved_addresses")
    @classmethod
    def _resolved(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not isinstance(item, str) or not item:
                raise ValueError("resolved addresses must be non-empty strings")
            try:
                ipaddress.ip_address(item)
            except ValueError as exc:
                raise ValueError(
                    f"resolved address is not an IP: {item!r}"
                ) from exc
        return value

    def scope_view(self) -> dict:
        """Read-only 5D handoff projection (facts only, no verdict).

        Returns a frozen snapshot mapping with exactly the fields a
        ScopeEvaluator needs: canonical identity, pinned addresses,
        program binding, and DNS/inventory facts. Mutating the
        returned mapping is impossible (keys map to tuples/strings);
        the resolution itself stays immutable regardless.
        """

        return {
            "authorization_id": self.authorization_id,
            "canonical_host": self.canonical_host,
            "dns_answer_count": self.dns_answer_count,
            "effective_port": self.effective_port,
            "execution_id": self.execution_id,
            "program_name": self.program_name,
            "resolution_id": self.resolution_id,
            "resolved_addresses": self.resolved_addresses,
            "scheme": self.scheme,
            "scope_lists_hash_current": self.scope_lists_hash_current,
            "snapshot_current": self.snapshot_current,
            "status": self.status,
        }


@dataclass(frozen=True)
class ResolutionRequest:
    """Typed authorized execution context for one resolution.

    ``authorization`` must be a genuine ``IssuedExecutionAuthorization``
    record (never a dict, JSON blob, LLM output, hypothesis, plan, or
    intelligence object — the resolver type-checks this). ``now`` is
    the caller-supplied clock instant (ISO-8601) so resolution stays
    deterministic under test. ``snapshot_observed`` is an optional
    descriptive TargetIntelligence snapshot hash; it is recorded as
    context and can never grant authority.
    """

    authorization: object
    execution_id: str
    now: str
    snapshot_observed: object = None


__all__ = [
    "SCHEMA_VERSION",
    "RESOLVER_VERSION",
    "ResolutionStatus",
    "TERMINAL_FAILURE_STATUSES",
    "ResolutionFailureCode",
    "HostKind",
    "FORBIDDEN_RESOLUTION_FIELDS",
    "ResolutionError",
    "DialBinding",
    "TargetResolution",
    "ResolutionRequest",
    "canonical_target_hash_for",
    "resolution_id_for",
    "base_authority_for",
]
