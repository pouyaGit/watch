"""Production HopResolver wiring (Phase B1).

Production implementation of the frozen 5E ``HopResolver`` protocol
around the frozen ``TargetResolver`` + ``ScopeEvaluator`` contracts.
No frozen shape is changed; no logic is duplicated.

Required flow for EVERY hop (authorization → ledger claim happens in
the executor; everything below runs post-claim, pre-SYN):

    fresh resolution → fresh scope evaluation → DialBinding
    → binding coherence checks → return pair for transport dial

- Hop 0 (:meth:`resolve_initial`) resolves through the real
  ``TargetResolver`` (canonicalize + inventory + drift + pinned DNS
  via the production address source) and evaluates through the real
  ``ScopeEvaluator``. The authorization-time ``TargetResolution`` is
  provenance only: when the caller supplies its pin
  (``authz_time_addresses``), any disagreement with the post-claim
  fresh pin is ``STALE_RESOLUTION`` — abort before SYN, retry only
  under a NEW authorization. The executor must call this post-claim
  (wiring is an activation-gate item; until activation no live dial
  occurs at all).
- Redirect hops (:meth:`resolve_hop` for a new host/scheme/port)
  repeat the full chain: canonicalize → scheme gate → fresh DNS via
  the production source → fresh ``TargetResolution`` → append
  ``HopObservation`` → fresh ``evaluate_chain`` over the WHOLE chain
  → fresh per-hop ``ScopeEvaluation``. No previous-hop inheritance:
  policy is re-read per hop, addresses re-resolved per hop, bindings
  re-issued per hop. Frozen redirect limits (5 edges) and scheme
  rules (never downgrade; upgrade http→https only for
  ``http_probe``) are enforced here as well as in the executor.

The caller supplies NO address-typed input anywhere: no IP
parameter, no resolver override, no SNI/Host/port/scheme override.
IP-literal hop destinations are ``REDIRECT_NOT_IN_SCOPE`` (no-IP
scope policy). Unsafe/malformed DNS answers fail the whole hop
(never subset dialing).

This module is OFFLINE except through injected deps: no sockets, no
``ssl``, no subprocess, no database driver, no LLM.
"""

from __future__ import annotations

import re
from typing import Any

from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.dns import MAX_DNS_ANSWERS, DnsError
from ai.resolver.resolver import TargetResolver
from ai.schemas.execution_authorization import IssuedExecutionAuthorization
from ai.schemas.scope_evaluation import ScopeEvaluation, evaluation_id_for
from ai.schemas.target_resolution import (
    DialBinding,
    TargetResolution,
    ResolutionRequest,
    base_authority_for,
    canonical_target_hash_for,
    resolution_id_for,
)
from ai.scope.evaluator import HopObservation, ScopeEvaluator

__all__ = [
    "PRODUCTION_HOP_VERSION",
    "PRODUCTION_HOP_ERROR_CODES",
    "ProductionHopError",
    "ProductionHopResolver",
]

#: Production wiring identity.
PRODUCTION_HOP_VERSION = "b1-production-hop/v1"

#: Closed failure vocabulary (B1-new + shared frozen DNS/redirect codes).
PRODUCTION_HOP_ERROR_CODES = frozenset(
    {
        "STALE_RESOLUTION",
        "DIAL_BINDING_MISMATCH",
        "SCOPE_DRIFT",
        "SCOPE_POLICY_MISSING",
        "REDIRECT_NOT_IN_SCOPE",
        "REDIRECT_INVALID",
        "REDIRECT_LIMIT",
        "AUTHZ_NOT_LIVE",
        "AUTHZ_BINDING_MISMATCH",
        "RESOLUTION_BINDING_MISMATCH",
        "TARGET_BINDING_MISMATCH",
        "INITIAL_HOP_REQUIRED",
        "INVALID_REQUEST",
        "TARGET_MALFORMED",
        "TARGET_GONE",
        "TARGET_PROGRAM_GONE",
        "TARGET_REASSIGNED",
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

_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class ProductionHopError(ValueError):
    """Bounded, secret-free production-hop failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in PRODUCTION_HOP_ERROR_CODES:
            raise ValueError(f"unknown production hop code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("production hop detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


class ProductionHopResolver:
    """Post-claim fresh resolution + evaluation per hop (B1 wiring).

    ``address_source`` is the production ``DnsResolver`` (pinned
    stub); ``inventory`` the read-only repository; ``policy_store``
    the fresh scope-policy source. State is keyed per
    ``(authorization_id, execution_id)`` so parallel executions never
    share pins, history, or initial bindings.
    """

    def __init__(
        self,
        *,
        address_source: Any,
        inventory: Any,
        policy_store: Any,
    ) -> None:
        if not hasattr(address_source, "resolve") or not isinstance(
            getattr(address_source, "name", ""), str
        ):
            raise TypeError(
                "address_source must implement DnsResolver, "
                f"not {type(address_source).__name__}"
            )
        if not (
            hasattr(inventory, "get_program") and hasattr(inventory, "get_asset")
        ):
            raise TypeError(
                "inventory must implement InventoryRepository, "
                f"not {type(inventory).__name__}"
            )
        if not hasattr(policy_store, "get_policy"):
            raise TypeError(
                "policy_store must implement PolicyStore, "
                f"not {type(policy_store).__name__}"
            )
        self._source = address_source
        self._inventory = inventory
        self._policies = policy_store
        self._target_resolver = TargetResolver(
            inventory=inventory, dns=address_source
        )
        self._evaluator = ScopeEvaluator(policy_store=policy_store)
        self._initial: dict[tuple[str, str], TargetResolution] = {}
        self._history: dict[tuple[str, str], list[HopObservation]] = {}

    @property
    def version(self) -> str:
        """Production wiring identity."""
        return PRODUCTION_HOP_VERSION

    # -- shared guards -------------------------------------------------

    def _check_request(
        self,
        *,
        authorization: object,
        execution_id: str,
        now: str,
    ) -> IssuedExecutionAuthorization:
        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "hop resolution accepts only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}"
            )
        if not isinstance(execution_id, str) or not _EXECUTION_ID_RE.match(
            execution_id
        ):
            raise ProductionHopError("INVALID_REQUEST", "malformed execution id")
        if not isinstance(now, str) or not now:
            raise ProductionHopError("INVALID_REQUEST", "malformed clock instant")
        return authorization

    def _check_coherence(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        resolution: TargetResolution,
        evaluation: ScopeEvaluation,
        execution_id: str,
    ) -> None:
        """Dial-coherence equality (first mismatch wins, fail closed)."""

        if not isinstance(resolution, TargetResolution) or not isinstance(
            evaluation, ScopeEvaluation
        ):
            raise ProductionHopError(
                "RESOLUTION_BINDING_MISMATCH", "hop binding not typed"
            )
        if resolution.authorization_id != authorization.authorization_id:
            raise ProductionHopError(
                "RESOLUTION_BINDING_MISMATCH", "hop authorization mismatch"
            )
        if resolution.execution_id != execution_id:
            raise ProductionHopError(
                "AUTHZ_BINDING_MISMATCH", "hop execution mismatch"
            )
        if evaluation.authorization_id != authorization.authorization_id:
            raise ProductionHopError(
                "AUTHZ_BINDING_MISMATCH", "hop evaluation mismatch"
            )
        if evaluation.execution_id != execution_id:
            raise ProductionHopError(
                "AUTHZ_BINDING_MISMATCH", "hop evaluation mismatch"
            )
        if evaluation.resolution_id != resolution.resolution_id:
            raise ProductionHopError(
                "RESOLUTION_BINDING_MISMATCH", "evaluation resolution mismatch"
            )
        if resolution.status != "RESOLVED":
            raise ProductionHopError(
                "RESOLUTION_BINDING_MISMATCH", "hop not resolved"
            )
        if resolution.program_name != authorization.target.program_name:
            raise ProductionHopError("TARGET_BINDING_MISMATCH", "hop program mismatch")
        recomputed = canonical_target_hash_for(
            program_name=resolution.program_name,
            canonical_host=resolution.canonical_host,
            scheme=resolution.scheme,
            effective_port=resolution.effective_port,
        )
        if recomputed != resolution.canonical_target_hash:
            raise ProductionHopError(
                "RESOLUTION_BINDING_MISMATCH", "hop target hash mismatch"
            )
        dial = resolution.dial
        if (
            dial is None
            or tuple(dial.addresses) != tuple(resolution.resolved_addresses)
            or dial.effective_port != resolution.effective_port
            or dial.sni_host != resolution.canonical_host
            or dial.pin_required is not True
        ):
            raise ProductionHopError("DIAL_BINDING_MISMATCH", "hop dial incoherent")
        if not resolution.resolved_addresses:
            raise ProductionHopError("DNS_RESOLUTION_FAILED", "hop address set empty")
        if len(resolution.resolved_addresses) > MAX_DNS_ANSWERS:
            raise ProductionHopError("DNS_TOO_MANY_ANSWERS", "hop answers over ceiling")
        if resolution.scope_lists_hash_current != authorization.target.scope_lists_hash:
            raise ProductionHopError("SCOPE_DRIFT", "hop policy drift")

    def _check_pin_freshness(
        self,
        fresh: tuple[str, ...],
        authz_time_addresses: tuple[str, ...] | list[str] | None,
    ) -> None:
        """Authorization-time pin is provenance: disagreement is stale."""

        if authz_time_addresses is None:
            return
        if tuple(authz_time_addresses) != tuple(fresh):
            raise ProductionHopError(
                "STALE_RESOLUTION", "post-claim pin differs from authz pin"
            )

    # -- hop 0: post-claim fresh resolution ------------------------------

    def resolve_initial(
        self,
        *,
        authorization: object,
        execution_id: str,
        now: str,
        authz_time_addresses: tuple[str, ...] | list[str] | None = None,
    ) -> tuple[TargetResolution, ScopeEvaluation]:
        """Fresh hop-0 pair, post-ledger-claim (never the authz pin)."""

        authz = self._check_request(
            authorization=authorization, execution_id=execution_id, now=now
        )
        try:
            resolution = self._target_resolver.resolve(
                ResolutionRequest(
                    authorization=authz, execution_id=execution_id, now=now
                )
            )
        except TypeError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code in PRODUCTION_HOP_ERROR_CODES:
                raise ProductionHopError(code, "initial resolution failed") from exc
            raise ProductionHopError(
                "DNS_RESOLUTION_FAILED", "initial resolution failed"
            ) from exc
        if resolution.status != "RESOLVED":
            code = resolution.failure_code or "DNS_RESOLUTION_FAILED"
            if code == "SCOPE_DRIFT":
                raise ProductionHopError("SCOPE_DRIFT", "scope drift at hop zero")
            if code in ("TARGET_GONE", "TARGET_PROGRAM_GONE", "TARGET_REASSIGNED"):
                raise ProductionHopError(code, "inventory terminal at hop zero")  # type: ignore[arg-type]
            if code in PRODUCTION_HOP_ERROR_CODES:
                raise ProductionHopError(code, "initial resolution failed")  # type: ignore[arg-type]
            raise ProductionHopError("DNS_RESOLUTION_FAILED", "initial hop failed")
        self._check_pin_freshness(
            tuple(resolution.resolved_addresses), authz_time_addresses
        )
        evaluation = self._evaluator.evaluate(
            authz, resolution, execution_id=execution_id, now=now
        )
        if evaluation.decision != "ALLOWED":
            code = evaluation.failure_code
            if code == "SCOPE_DRIFT":
                raise ProductionHopError("SCOPE_DRIFT", "scope drift at hop zero")
            if code == "AUTHZ_NOT_LIVE":
                raise ProductionHopError("AUTHZ_NOT_LIVE", "authorization not live")
            raise ProductionHopError(
                "REDIRECT_NOT_IN_SCOPE", "initial hop not in scope"
            )
        self._check_coherence(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            execution_id=execution_id,
        )
        key = (authz.authorization_id, execution_id)
        self._initial[key] = resolution
        self._history.setdefault(key, [])
        return resolution, evaluation

    # -- redirect hops: fresh resolve + evaluate, no inheritance ---------

    def resolve_hop(
        self,
        *,
        authorization: object,
        execution_id: str,
        canonical_host: str,
        scheme: str,
        effective_port: int,
        path: str = "/",
        query: str = "",
        now: str,
        authz_time_addresses: tuple[str, ...] | list[str] | None = None,
    ) -> tuple[TargetResolution, ScopeEvaluation]:
        """Per-hop fresh pair (frozen ``HopResolver`` protocol body)."""

        authz = self._check_request(
            authorization=authorization, execution_id=execution_id, now=now
        )
        key = (authz.authorization_id, execution_id)
        if not isinstance(canonical_host, str) or not canonical_host:
            raise ProductionHopError("INVALID_REQUEST", "hop host not a string")
        if scheme not in ("http", "https"):
            raise ProductionHopError("REDIRECT_INVALID", "hop scheme rejected")
        if (
            not isinstance(effective_port, int)
            or isinstance(effective_port, bool)
            or not 1 <= effective_port <= 65535
        ):
            raise ProductionHopError("REDIRECT_INVALID", "hop port rejected")
        if not isinstance(path, str) or not isinstance(query, str):
            raise ProductionHopError("INVALID_REQUEST", "hop path not strings")

        try:
            authz_host, _ = canonicalize_host(authz.target.host)
        except (CanonicalizationError, TypeError) as exc:
            raise ProductionHopError("TARGET_MALFORMED", "authz host rejected") from exc
        is_initial_hop = (
            canonical_host == authz_host
            and scheme == authz.target.scheme
            and effective_port == authz.target.effective_port
            and key not in self._initial
        )
        if is_initial_hop:
            # Hop 0 takes the post-claim fresh path (never substituted).
            return self.resolve_initial(
                authorization=authz,
                execution_id=execution_id,
                now=now,
                authz_time_addresses=authz_time_addresses,
            )
        initial = self._initial.get(key)
        if initial is None:
            raise ProductionHopError(
                "INITIAL_HOP_REQUIRED", "resolve the initial hop first"
            )
        history = self._history.setdefault(key, [])
        if len(history) >= 5:
            raise ProductionHopError("REDIRECT_LIMIT", "redirect budget spent")

        try:
            hop_host, kind = canonicalize_host(canonical_host)
        except (CanonicalizationError, TypeError) as exc:
            raise ProductionHopError("REDIRECT_INVALID", "hop host rejected") from exc
        if hop_host != canonical_host:
            raise ProductionHopError("REDIRECT_INVALID", "hop host not canonical")
        if kind != "dns":
            # No-IP scope policy: IP-literal redirect destinations can
            # never be authorized.
            raise ProductionHopError(
                "REDIRECT_NOT_IN_SCOPE", "ip redirect not in scope"
            )
        current_scheme = initial.scheme
        if current_scheme == "https" and scheme == "http":
            raise ProductionHopError("REDIRECT_INVALID", "https downgrade denied")
        if current_scheme == "http" and scheme == "https":
            if authz.execution_class != "http_probe":
                raise ProductionHopError("REDIRECT_INVALID", "http upgrade denied")
        allowed_ports = {80, 443, initial.effective_port}
        if effective_port not in allowed_ports:
            raise ProductionHopError("REDIRECT_NOT_IN_SCOPE", "hop port not allowed")

        try:
            raw_answers = self._source.resolve(hop_host)
        except DnsError as exc:
            code = exc.code
            if code not in PRODUCTION_HOP_ERROR_CODES:
                raise ProductionHopError(
                    "DNS_RESOLUTION_FAILED", "hop dns failed"
                ) from exc
            raise ProductionHopError(code, "hop dns failed") from exc  # type: ignore[arg-type]
        except ProductionHopError:
            raise
        except Exception as exc:
            raise ProductionHopError("DNS_RESOLUTION_FAILED", "hop dns failed") from exc
        # validate_answers already ran inside the production source;
        # re-assert here so a substituted source cannot smuggle an
        # unvalidated set past this layer.
        from ai.resolver.dns import validate_answers as _validate

        try:
            addresses = _validate(raw_answers)
        except DnsError as exc:
            code = exc.code
            if code not in PRODUCTION_HOP_ERROR_CODES:
                raise ProductionHopError(
                    "DNS_UNSAFE_ADDRESS", "hop answers unsafe"
                ) from exc
            raise ProductionHopError(code, "hop answers unsafe") from exc  # type: ignore[arg-type]

        program = authz.target.program_name
        target_hash = canonical_target_hash_for(
            program_name=program,
            canonical_host=hop_host,
            scheme=scheme,
            effective_port=effective_port,
        )
        policy = self._policies.get_policy(program)
        if policy is None:
            raise ProductionHopError("SCOPE_POLICY_MISSING", "program policy missing")
        policy_hash = policy.scope_lists_hash
        resolution = TargetResolution(
            resolution_id=resolution_id_for(
                authorization_id=authz.authorization_id,
                execution_id=execution_id,
                canonical_target_hash=target_hash,
                resolved_addresses=tuple(addresses),
                scope_lists_hash_current=policy_hash,
                snapshot_current=None,
            ),
            authorization_id=authz.authorization_id,
            execution_id=execution_id,
            program_name=program,
            host_as_authorized=hop_host,
            canonical_host=hop_host,
            host_kind="dns",
            scheme=scheme,  # type: ignore[arg-type]
            effective_port=effective_port,
            base_authority=base_authority_for(
                scheme=scheme,
                canonical_host=hop_host,
                effective_port=effective_port,
                host_kind="dns",
            ),
            resolved_addresses=tuple(addresses),
            dns_answer_count=len(addresses),
            dns_source=self._source.name,
            dial=DialBinding(
                addresses=tuple(addresses),
                effective_port=effective_port,
                sni_host=hop_host,
            ),
            scope_lists_hash_authorized=authz.target.scope_lists_hash,
            scope_lists_hash_current=policy_hash,
            scope_drift=(policy_hash != authz.target.scope_lists_hash),
            status="RESOLVED",
            canonical_target_hash=target_hash,
            resolved_at=now,
        )
        default = _DEFAULT_PORTS[scheme]
        location = (
            f"{scheme}://{hop_host}"
            + ("" if effective_port == default else f":{effective_port}")
            + (path if path.startswith("/") else "/" + path)
            + (f"?{query}" if query else "")
        )
        history.append(HopObservation(location=location, addresses=tuple(addresses)))
        chained = self._evaluator.evaluate_chain(
            authz,
            initial,
            execution_id=execution_id,
            now=now,
            hops=tuple(history),
        )
        if chained.decision != "ALLOWED":
            history.pop()
            code = chained.failure_code or "REDIRECT_NOT_IN_SCOPE"
            if code == "SCOPE_DRIFT":
                raise ProductionHopError("SCOPE_DRIFT", "hop policy drift")
            if code == "AUTHZ_NOT_LIVE":
                raise ProductionHopError("AUTHZ_NOT_LIVE", "authorization not live")
            if code in ("TARGET_EXCLUDED", "TARGET_NOT_IN_SCOPE"):
                raise ProductionHopError("REDIRECT_NOT_IN_SCOPE", "hop not in scope")
            raise ProductionHopError("REDIRECT_NOT_IN_SCOPE", "hop not allowed")
        evaluation = ScopeEvaluation(
            evaluation_id=evaluation_id_for(
                authorization_id=authz.authorization_id,
                execution_id=execution_id,
                resolution_id=resolution.resolution_id,
                canonical_target_hash=target_hash,
                scope_lists_hash_current=policy_hash,
                chain_digest=location,
            ),
            authorization_id=authz.authorization_id,
            execution_id=execution_id,
            resolution_id=resolution.resolution_id,
            program_name=program,
            canonical_target_hash=target_hash,
            scope_lists_hash_current=policy_hash,
            decision="ALLOWED",
            evaluated_at=now,
        )
        self._check_coherence(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            execution_id=execution_id,
        )
        return resolution, evaluation
