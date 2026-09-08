"""TargetResolver runtime (Phase 5C).

Fresh canonical target representation for exactly one authorized
execution::

    IssuedExecutionAuthorization (5B, LIVE-for-execution only)
        |
        v
    TargetResolver.resolve() (this module)
        |
        v
    TargetResolution (immutable facts)
        |
        v
    5D ScopeEvaluator (verdicts live there, never here)

Resolution order (every call, in order):

1. Typed-context gate: ``authorization`` must be a genuine
   ``IssuedExecutionAuthorization`` (dicts/JSON/LLM output/plans/
   intelligence objects are rejected by type — they are never
   authority). ``execution_id`` and ``now`` are shape-validated.
2. Liveness gate: ``require_live_for_execution`` (the 5H-core
   ``AUTHZ_LIVE_FOR_EXECUTION`` check). ``CONSUMED``/``REVOKED``/
   expired records raise ``AUTHZ_NOT_LIVE`` — a consumed
   authorization never permits another resolution, and
   ``AUTHZ_VALID_FOR_PROVENANCE`` is never accepted as execution
   permission here.
3. Canonicalization: the authorized host/scheme/port become the exact
   ``(program_name, canonical_host, scheme, effective_port)`` tuple
   (fail-closed; ``RESOLUTION_FAILED``/``TARGET_MALFORMED``).
4. Inventory: program row -> asset row, both keyed by the exact pair
   (missing program -> ``TARGET_PROGRAM_GONE``; missing asset ->
   ``TARGET_GONE``). Current scope-lists hash vs the authorized hash
   (mismatch -> ``SCOPE_DRIFT``). Current endpoint base vs the
   authorized base (change -> ``TARGET_REASSIGNED``: 5D must
   scope-check the NEW base; the old URL is never silently reused).
5. DNS observation: injected resolver answers are ceiling-checked,
   safety-classified (any-denied fails the whole set), and pinned as
   ``resolved_addresses`` + :class:`DialBinding` for future
   dial-time enforcement (failures -> ``RESOLUTION_FAILED`` with the
   closed DNS code).
6. Snapshot binding: the observed vs authorized vs current snapshot
   hashes are recorded as advisory staleness facts. A historical
   snapshot can never authorize a current target by construction —
   snapshot fields play no role in the ``RESOLVED`` decision.

What this module NEVER does: scope verdicts, execution verdicts,
vulnerability classification, redirect authorization, URL building
beyond the base authority, LLM calls, network I/O, subprocess,
browser use, database access, or authorization lifecycle mutation
(no consume/revoke here — that authority belongs to the 5B store at
executor start).

DNS-rebinding boundary (mandatory): the ``RESOLVED`` record pins
``RESOLUTION-TIME ADDRESSES`` and exposes them as the ``APPROVED
ADDRESS BINDING`` (``dial``). Future transport MUST dial a pinned
address with SNI/Host preserved and abort on re-resolution
mismatch. This module preserves the binding; enforcement belongs to
5E/5F/5G or the approved egress layer and is explicitly NOT claimed
here.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ai.evidence.handoff import require_live_for_execution
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_target,
)
from ai.resolver.dns import DnsError, DnsResolver, validate_answers
from ai.resolver.inventory import InventoryRepository, scope_lists_hash_for
from ai.schemas.execution_authorization import IssuedExecutionAuthorization
from ai.schemas.target_resolution import (
    RESOLVER_VERSION,
    DialBinding,
    ResolutionError,
    ResolutionRequest,
    TargetResolution,
    base_authority_for,
    canonical_target_hash_for,
    resolution_id_for,
)

__all__ = [
    "TargetResolver",
]

_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_SNAPSHOT_RE = re.compile(r"^[0-9a-f]{64}$")
_HOST_ECHO_LIMIT = 253


def _safe_host_echo(raw: object) -> str:
    """Secret-free, single-line echo of the authorized host string.

    Successful canonicalization implies the raw host carries no
    userinfo (``@`` is rejected), so the echo is verbatim. On
    canonicalization failure the raw text is hostile by definition:
    credentials (through the last ``@``) are dropped, control
    characters and newlines are folded away, and length is bounded.
    """

    if not isinstance(raw, str) or not raw:
        return ""
    text = raw
    if "@" in text:
        text = "[redacted]@" + text.rsplit("@", 1)[1]
    cleaned = "".join(
        char if 32 <= ord(char) < 127 else "?" for char in text
    )
    return cleaned[:_HOST_ECHO_LIMIT]


def _parse_instant(value: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ResolutionError(
            "INVALID_REQUEST", "malformed clock instant"
        ) from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


class TargetResolver:
    """Deterministic read-only target resolution (injected deps only)."""

    def __init__(
        self, *, inventory: InventoryRepository, dns: DnsResolver
    ) -> None:
        if not (
            hasattr(inventory, "get_program")
            and hasattr(inventory, "get_asset")
        ):
            raise TypeError(
                "inventory must implement InventoryRepository, "
                f"not {type(inventory).__name__}"
            )
        if not hasattr(dns, "resolve") or not isinstance(
            getattr(dns, "name", ""), str
        ):
            raise TypeError(
                "dns must implement DnsResolver, "
                f"not {type(dns).__name__}"
            )
        self._inventory = inventory
        self._dns = dns

    @property
    def version(self) -> str:
        """Frozen resolver version stamped on every resolution."""
        return RESOLVER_VERSION

    def resolve(self, request: object) -> TargetResolution:
        """Resolve one authorized execution context to a resolution."""

        if not isinstance(request, ResolutionRequest):
            raise TypeError(
                "resolve accepts only ResolutionRequest, "
                f"not {type(request).__name__}; raw dicts never coerce"
            )
        authorization = request.authorization
        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "resolution accepts only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}; dicts, JSON, LLM "
                "output, plans, and intelligence are never authority"
            )
        if not isinstance(request.execution_id, str):
            raise TypeError("execution_id must be a string")
        if not _EXECUTION_ID_RE.match(request.execution_id):
            raise ResolutionError(
                "INVALID_REQUEST", "malformed execution id"
            )
        if not isinstance(request.now, str):
            raise TypeError("clock instant must be a string")
        _parse_instant(request.now)
        if request.snapshot_observed is not None:
            if not isinstance(request.snapshot_observed, str):
                raise TypeError("snapshot_observed must be a string or None")
            if not _SNAPSHOT_RE.match(request.snapshot_observed):
                raise ResolutionError(
                    "INVALID_REQUEST", "malformed snapshot ref"
                )

        # Liveness BEFORE any resolution work: provenance is not
        # permission, consumed is never re-executable.
        require_live_for_execution(authorization, now=request.now)

        bound = authorization.target
        program_name = bound.program_name

        # Canonical target tuple (fail-closed; never trust raw text).
        try:
            authority = canonicalize_target(
                bound.host, bound.scheme, bound.effective_port
            )
        except CanonicalizationError as exc:
            return self._failure(
                authorization,
                request,
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                failure_code="TARGET_MALFORMED",
            )

        canonical_host = authority.canonical_host
        target_hash = canonical_target_hash_for(
            program_name=program_name,
            canonical_host=canonical_host,
            scheme=authority.scheme,
            effective_port=authority.effective_port,
        )
        base_authority = base_authority_for(
            scheme=authority.scheme,
            canonical_host=canonical_host,
            effective_port=authority.effective_port,
            host_kind=authority.host_kind,
        )

        # Inventory (exact pair only; adapter failures stay secret).
        try:
            program = self._inventory.get_program(program_name)
        except Exception:
            return self._failure(
                authorization,
                request,
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                failure_code="INVENTORY_ERROR",
            )
        if program is None:
            return self._terminal(
                authorization,
                request,
                status="TARGET_PROGRAM_GONE",
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
            )
        try:
            asset = self._inventory.get_asset(program_name, canonical_host)
        except Exception:
            return self._failure(
                authorization,
                request,
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                failure_code="INVENTORY_ERROR",
            )
        if asset is None:
            return self._terminal(
                authorization,
                request,
                status="TARGET_GONE",
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                scope_current=None,
            )

        scope_current = scope_lists_hash_for(program.scopes, program.ooscopes)
        scope_drift = scope_current != bound.scope_lists_hash

        snapshot = self._snapshot_facts(
            authorization, request, asset.snapshot_current
        )

        if scope_drift:
            return self._terminal(
                authorization,
                request,
                status="SCOPE_DRIFT",
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                scope_current=scope_current,
                scope_drift=True,
                inventory_base=asset.endpoint_base,
                snapshot=snapshot,
            )

        reassigned = (
            asset.scheme != authority.scheme
            or asset.effective_port != authority.effective_port
        )
        if reassigned:
            return self._terminal(
                authorization,
                request,
                status="TARGET_REASSIGNED",
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                scope_current=scope_current,
                scope_drift=False,
                inventory_base=asset.endpoint_base,
                reassigned=True,
                snapshot=snapshot,
            )

        # DNS observation (injected; raw adapter exceptions collapse
        # to the closed code without message text).
        try:
            raw_answers = self._dns.resolve(canonical_host)
        except DnsError as exc:
            return self._failure(
                authorization,
                request,
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                scope_current=scope_current,
                scope_drift=False,
                inventory_base=asset.endpoint_base,
                snapshot=snapshot,
                failure_code=exc.code,  # type: ignore[arg-type]
            )
        except Exception:
            return self._failure(
                authorization,
                request,
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                scope_current=scope_current,
                scope_drift=False,
                inventory_base=asset.endpoint_base,
                snapshot=snapshot,
                failure_code="DNS_RESOLUTION_FAILED",
            )
        try:
            addresses = validate_answers(raw_answers)
        except DnsError as exc:
            return self._failure(
                authorization,
                request,
                program_name=program_name,
                host_as_authorized=_safe_host_echo(bound.host),
                canonical_host=canonical_host,
                host_kind=authority.host_kind,
                scheme=authority.scheme,
                effective_port=authority.effective_port,
                base_authority=base_authority,
                target_hash=target_hash,
                scope_current=scope_current,
                scope_drift=False,
                inventory_base=asset.endpoint_base,
                snapshot=snapshot,
                failure_code=exc.code,  # type: ignore[arg-type]
            )

        dial = DialBinding(
            addresses=addresses,
            effective_port=authority.effective_port,
            sni_host=canonical_host,
        )
        return TargetResolution(
            resolution_id=resolution_id_for(
                authorization_id=authorization.authorization_id,
                execution_id=request.execution_id,
                canonical_target_hash=target_hash,
                resolved_addresses=addresses,
                scope_lists_hash_current=scope_current,
                snapshot_current=asset.snapshot_current,
            ),
            authorization_id=authorization.authorization_id,
            execution_id=request.execution_id,
            program_name=program_name,
            host_as_authorized=_safe_host_echo(bound.host),
            canonical_host=canonical_host,
            host_kind=authority.host_kind,  # type: ignore[arg-type]
            scheme=authority.scheme,  # type: ignore[arg-type]
            effective_port=authority.effective_port,
            port_explicit=False,
            base_authority=base_authority,
            path_scope_ref=bound.path_scope,
            resolved_addresses=addresses,
            dns_answer_count=len(addresses),
            dns_source=self._dns.name,
            dial=dial,
            scope_lists_hash_authorized=bound.scope_lists_hash,
            scope_lists_hash_current=scope_current,
            scope_drift=False,
            inventory_endpoint_base=asset.endpoint_base,
            reassigned=False,
            snapshot_ref=bound.snapshot_ref,
            snapshot_observed=(
                request.snapshot_observed
                if isinstance(request.snapshot_observed, str)
                else None
            ),
            snapshot_current=asset.snapshot_current,
            snapshot_match=snapshot["match"],
            snapshot_stale=snapshot["stale"],
            status="RESOLVED",
            failure_code=None,
            canonical_target_hash=target_hash,
            resolved_at=request.now,
            resolver_version=RESOLVER_VERSION,  # type: ignore[arg-type]
        )

    def _snapshot_facts(
        self,
        authorization: IssuedExecutionAuthorization,
        request: ResolutionRequest,
        snapshot_current: str | None,
    ) -> dict:
        """Advisory staleness facts (never permission inputs)."""

        ref = authorization.target.snapshot_ref
        observed = request.snapshot_observed
        assert observed is None or isinstance(observed, str)
        match: bool | None = None
        if ref is not None and observed is not None:
            match = observed == ref
        stale: bool | None = None
        if ref is not None and snapshot_current is not None:
            stale = ref != snapshot_current
        return {"match": match, "stale": stale}

    def _failure(
        self,
        authorization: IssuedExecutionAuthorization,
        request: ResolutionRequest,
        *,
        program_name: str,
        host_as_authorized: str,
        canonical_host: str = "",
        host_kind: str = "dns",
        scheme: str = "https",
        effective_port: int = 443,
        base_authority: str = "",
        target_hash: str | None = None,
        scope_current: str | None = None,
        scope_drift: bool | None = None,
        inventory_base: str | None = None,
        snapshot: dict | None = None,
        failure_code: str,
    ) -> TargetResolution:
        """Deterministic closed failure record (never raises)."""

        computed_hash = target_hash or canonical_target_hash_for(
            program_name=program_name,
            canonical_host=canonical_host,
            scheme=scheme,
            effective_port=effective_port,
        )
        snapshot = snapshot or {"match": None, "stale": None}
        observed = (
            request.snapshot_observed
            if isinstance(request.snapshot_observed, str)
            else None
        )
        return TargetResolution(
            resolution_id=resolution_id_for(
                authorization_id=authorization.authorization_id,
                execution_id=request.execution_id,
                canonical_target_hash=computed_hash,
                resolved_addresses=(),
                scope_lists_hash_current=scope_current,
                snapshot_current=None,
            ),
            authorization_id=authorization.authorization_id,
            execution_id=request.execution_id,
            program_name=program_name,
            host_as_authorized=host_as_authorized,
            canonical_host=canonical_host,
            host_kind=host_kind,  # type: ignore[arg-type]
            scheme=scheme,  # type: ignore[arg-type]
            effective_port=effective_port,
            port_explicit=False,
            base_authority=base_authority,
            path_scope_ref=authorization.target.path_scope,
            resolved_addresses=(),
            dns_answer_count=0,
            dns_source=self._dns.name,
            dial=None,
            scope_lists_hash_authorized=(
                authorization.target.scope_lists_hash
            ),
            scope_lists_hash_current=scope_current,
            scope_drift=scope_drift,
            inventory_endpoint_base=inventory_base,
            reassigned=False,
            snapshot_ref=authorization.target.snapshot_ref,
            snapshot_observed=observed,
            snapshot_current=None,
            snapshot_match=snapshot["match"],
            snapshot_stale=snapshot["stale"],
            status="RESOLUTION_FAILED",
            failure_code=failure_code,  # type: ignore[arg-type]
            canonical_target_hash=computed_hash,
            resolved_at=request.now,
            resolver_version=RESOLVER_VERSION,  # type: ignore[arg-type]
        )

    def _terminal(
        self,
        authorization: IssuedExecutionAuthorization,
        request: ResolutionRequest,
        *,
        status: str,
        program_name: str,
        host_as_authorized: str,
        canonical_host: str = "",
        host_kind: str = "dns",
        scheme: str = "https",
        effective_port: int = 443,
        base_authority: str = "",
        target_hash: str | None = None,
        scope_current: str | None = None,
        scope_drift: bool | None = None,
        inventory_base: str | None = None,
        reassigned: bool = False,
        snapshot: dict | None = None,
    ) -> TargetResolution:
        """Terminal non-error record (gone/drift/reassigned)."""

        computed_hash = target_hash or canonical_target_hash_for(
            program_name=program_name,
            canonical_host=canonical_host,
            scheme=scheme,
            effective_port=effective_port,
        )
        snapshot = snapshot or {"match": None, "stale": None}
        observed = (
            request.snapshot_observed
            if isinstance(request.snapshot_observed, str)
            else None
        )
        current_for_id = (
            scope_current if status not in ("TARGET_PROGRAM_GONE",) else None
        )
        return TargetResolution(
            resolution_id=resolution_id_for(
                authorization_id=authorization.authorization_id,
                execution_id=request.execution_id,
                canonical_target_hash=computed_hash,
                resolved_addresses=(),
                scope_lists_hash_current=current_for_id,
                snapshot_current=None,
            ),
            authorization_id=authorization.authorization_id,
            execution_id=request.execution_id,
            program_name=program_name,
            host_as_authorized=host_as_authorized,
            canonical_host=canonical_host,
            host_kind=host_kind,  # type: ignore[arg-type]
            scheme=scheme,  # type: ignore[arg-type]
            effective_port=effective_port,
            port_explicit=False,
            base_authority=base_authority,
            path_scope_ref=authorization.target.path_scope,
            resolved_addresses=(),
            dns_answer_count=0,
            dns_source=self._dns.name,
            dial=None,
            scope_lists_hash_authorized=(
                authorization.target.scope_lists_hash
            ),
            scope_lists_hash_current=scope_current,
            scope_drift=scope_drift,
            inventory_endpoint_base=inventory_base,
            reassigned=reassigned,
            snapshot_ref=authorization.target.snapshot_ref,
            snapshot_observed=observed,
            snapshot_current=None,
            snapshot_match=snapshot["match"],
            snapshot_stale=snapshot["stale"],
            status=status,  # type: ignore[arg-type]
            failure_code=None,
            canonical_target_hash=computed_hash,
            resolved_at=request.now,
            resolver_version=RESOLVER_VERSION,  # type: ignore[arg-type]
        )
