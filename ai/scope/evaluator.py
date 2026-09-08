"""Deterministic ScopeEvaluator (Phase 5D).

Centralized scope authority for all future executors (5E/5F/5G)::

    live IssuedExecutionAuthorization (5B, typed)
      + immutable TargetResolution (5C, RESOLVED only)
      + fresh CompiledScopePolicy (program-keyed, hash-bound)
          |
          v
    ScopeEvaluator.evaluate() -> ScopeEvaluation (initial target)
    ScopeEvaluator.evaluate_chain() -> ScopeEvaluation (with hops)

Rules (normative per ``agent-reports/scope-evaluator-architecture.md``):

- Exact-host matching over canonical labels; eTLD+1 never authorizes.
- Label-aware single-level wildcards; absolute exclusion.
- Host-only policy + explicit scheme/port defaults (no silent
  upgrade/downgrade; upgrade http→https only for ``http_probe``,
  recorded; downgrade always DENY).
- Dual address gate: every pinned address re-classified safe (5C
  safety re-asserted locally — a hand-built resolution with unsafe
  addresses cannot pass) AND scope-evaluated (host-only policy:
  safe ⇒ pass, recorded per address).
- ALL pinned addresses must pass; any unsafe ⇒ total DENY.
- Every redirect hop independently evaluated (no inheritance);
  canonical-URL visited set; max 5 edges; per-hop policy re-read
  (mid-chain change ⇒ SCOPE_DRIFT stop).
- 5D performs ZERO DNS (``classify_address`` is pure local
  computation over supplied strings, not resolution).

This module is PURE and DETERMINISTIC (caller-supplied ``now`` is
the only time source): no network, no sockets, no subprocess, no
database driver, no LLM, no evidence authority, no store writes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from ai.evidence.handoff import require_live_for_execution
from ai.evidence.scrubber import REDACTED, contains_secret_shape
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.dns import DnsError, classify_address
from ai.schemas.evidence import EvidenceError
from ai.schemas.execution_authorization import IssuedExecutionAuthorization
from ai.schemas.scope_evaluation import (
    EVALUATOR_VERSION,
    AddressDecision,
    HopDecision,
    ScopeError,
    ScopeEvaluation,
    evaluation_id_for,
)
from ai.schemas.target_resolution import (
    TargetResolution,
    canonical_target_hash_for,
)
from ai.scope.matcher import match_exclusions, match_inclusions
from ai.scope.policy import CompiledScopePolicy, PolicyError, PolicyStore

__all__ = [
    "MAX_REDIRECT_EDGES",
    "MAX_LOCATION_LENGTH",
    "HopObservation",
    "ScopeEvaluator",
    "require_allowed",
]

#: Frozen redirect budget: hop 0 is the initial target, up to 5
#: redirect edges. The 6th edge is REDIRECT_LIMIT (mirrors the
#: 5H-core ``redirect_hops`` ceiling without importing transport
#: semantics).
MAX_REDIRECT_EDGES = 5

#: Frozen bound on one raw Location value (reject, never truncate).
MAX_LOCATION_LENGTH = 2048

_ALLOWED_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class HopObservation:
    """One observed redirect hop (transport-supplied facts only).

    ``location`` is the raw ``Location`` header value. ``addresses``
    are the dial addresses the transport observed for the hop
    destination (empty ⇒ the hop cannot be decided ⇒ INCONCLUSIVE,
    never assumed safe).
    """

    location: str
    addresses: tuple[str, ...] = ()


def _parse_instant(value: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ScopeError("INVALID_REQUEST", "malformed clock instant") from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


def _canonical_hop_url(
    scheme: str, host: str, port: int, path: str, query: str
) -> str:
    default = _DEFAULT_PORTS[scheme]
    authority = host if port == default else f"{host}:{port}"
    suffix = ""
    if path:
        suffix += path if path.startswith("/") else "/" + path
    if query:
        suffix += "?" + query
    return f"{scheme}://{authority}{suffix}"


class ScopeEvaluator:
    """Centralized deterministic scope authority (injected policy only)."""

    def __init__(self, *, policy_store: PolicyStore) -> None:
        if not hasattr(policy_store, "get_policy"):
            raise TypeError(
                "policy_store must implement PolicyStore, "
                f"not {type(policy_store).__name__}"
            )
        self._policies = policy_store

    @property
    def version(self) -> str:
        """Frozen evaluator version stamped on every decision."""
        return EVALUATOR_VERSION

    # ------------------------------------------------------------------
    # Initial evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        authorization: object,
        resolution: object,
        *,
        execution_id: str,
        now: str,
    ) -> ScopeEvaluation:
        """Evaluate the 5C-resolved initial target against fresh policy."""

        ctx = self._base_context(authorization, resolution, execution_id, now)
        if isinstance(ctx, ScopeEvaluation):
            return ctx
        (
            authz,
            res,
            program,
            canonical_host,
            policy,
        ) = ctx

        include = match_inclusions(policy.inclusions, canonical_host)
        exclude = match_exclusions(policy.exclusions, canonical_host)
        if exclude is not None:
            return self._deny(
                authz, res, execution_id, now, policy,
                "TARGET_EXCLUDED",
                include_rule=include.text if include else None,
                exclude_rule=exclude.text,
            )
        if include is None:
            return self._deny(
                authz, res, execution_id, now, policy,
                "TARGET_NOT_IN_SCOPE",
            )
        addresses = self._address_gate(
            authz, res, execution_id, now, policy, res.resolved_addresses
        )
        if isinstance(addresses, ScopeEvaluation):
            return addresses
        return ScopeEvaluation(
            evaluation_id=evaluation_id_for(
                authorization_id=authz.authorization_id,
                execution_id=execution_id,
                resolution_id=res.resolution_id,
                canonical_target_hash=res.canonical_target_hash,
                scope_lists_hash_current=policy.scope_lists_hash,
            ),
            authorization_id=authz.authorization_id,
            execution_id=execution_id,
            resolution_id=res.resolution_id,
            program_name=program,
            canonical_target_hash=res.canonical_target_hash,
            scope_lists_hash_current=policy.scope_lists_hash,
            decision="ALLOWED",
            include_rule=include.text,
            exclude_rule=None,
            address_decisions=addresses,
            hop_decisions=(),
            failure_code=None,
            evaluated_at=now,
            evaluator_version=EVALUATOR_VERSION,  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------
    # Redirect-chain evaluation (pure; observations supplied by caller)
    # ------------------------------------------------------------------

    def evaluate_chain(
        self,
        authorization: object,
        resolution: object,
        *,
        execution_id: str,
        now: str,
        hops: tuple[HopObservation, ...] = (),
    ) -> ScopeEvaluation:
        """Evaluate initial target + each redirect hop independently."""

        if not isinstance(hops, (list, tuple)):
            raise TypeError("hops must be a list/tuple of HopObservation")
        for hop in hops:
            if not isinstance(hop, HopObservation):
                raise TypeError(
                    "hops must be HopObservation, "
                    f"not {type(hop).__name__}"
                )
        hops = tuple(hops)
        initial = self.evaluate(authorization, resolution, execution_id=execution_id, now=now)
        if initial.decision != "ALLOWED" or not hops:
            return initial
        assert isinstance(authorization, IssuedExecutionAuthorization)
        assert isinstance(resolution, TargetResolution)
        res = resolution
        pinned_hash = initial.scope_lists_hash_current
        current_url = (res.base_authority or "") + "/"
        visited = {current_url}
        hop_decisions: list[HopDecision] = []
        for index, hop in enumerate(hops, start=1):
            if index > MAX_REDIRECT_EDGES:
                return self._chain_deny(
                    initial, hop_decisions, "REDIRECT_LIMIT"
                )
            try:
                policy = self._policies.get_policy(res.program_name)
            except PolicyError:
                return self._chain_deny(
                    initial, hop_decisions, "SCOPE_POLICY_INVALID"
                )
            if policy is None:
                return self._chain_deny(
                    initial, hop_decisions, "PROGRAM_NOT_FOUND"
                )
            if policy.scope_lists_hash != pinned_hash:
                return self._chain_deny(
                    initial, hop_decisions, "SCOPE_DRIFT"
                )
            outcome = self._evaluate_hop(
                authorization, res, execution_id, now, policy,
                current_url, visited, index, hop,
            )
            if isinstance(outcome, ScopeEvaluation):
                # INCONCLUSIVE stop (missing observations): chain ends
                # non-authorizing with hops recorded so far.
                prior = list(outcome.hop_decisions)
                return outcome.model_copy(
                    update={
                        "hop_decisions": tuple(hop_decisions + prior),
                        "evaluation_id": evaluation_id_for(
                            authorization_id=outcome.authorization_id,
                            execution_id=outcome.execution_id,
                            resolution_id=outcome.resolution_id,
                            canonical_target_hash=outcome.canonical_target_hash,
                            scope_lists_hash_current=outcome.scope_lists_hash_current,
                            chain_digest=self._chain_digest(
                                hop_decisions + prior
                            ),
                        ),
                    }
                )
            hop_decision, next_url = outcome
            hop_decisions.append(hop_decision)
            if hop_decision.decision != "ALLOWED":
                return self._chain_deny(
                    initial, hop_decisions,
                    hop_decision.failure_code or "REDIRECT_NOT_IN_SCOPE",
                )
            visited.add(next_url)
            current_url = next_url
        return initial.model_copy(
            update={
                "hop_decisions": tuple(hop_decisions),
                "evaluation_id": evaluation_id_for(
                    authorization_id=initial.authorization_id,
                    execution_id=initial.execution_id,
                    resolution_id=initial.resolution_id,
                    canonical_target_hash=initial.canonical_target_hash,
                    scope_lists_hash_current=initial.scope_lists_hash_current,
                    chain_digest=self._chain_digest(hop_decisions),
                ),
            }
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _base_context(
        self,
        authorization: object,
        resolution: object,
        execution_id: str,
        now: str,
    ) -> tuple | ScopeEvaluation:
        """Type gates + liveness + cross-binding checks.

        Returns the verified context tuple, or a DENIED record when a
        semantic (non-programmer-error) check fails.
        """

        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "evaluation accepts only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}; dicts, JSON, LLM "
                "output, plans, and intelligence are never authority"
            )
        if not isinstance(resolution, TargetResolution):
            raise TypeError(
                "evaluation accepts only TargetResolution, "
                f"not {type(resolution).__name__}; raw URLs, hosts, IPs, "
                "dicts, and JSON are never evaluation targets"
            )
        authz = authorization
        res = resolution
        if not isinstance(execution_id, str):
            raise TypeError("execution_id must be a string")
        if not isinstance(now, str):
            raise TypeError("clock instant must be a string")
        _parse_instant(now)

        def deny(code: str, policy: CompiledScopePolicy | None) -> ScopeEvaluation:
            # Malformed execution ids raise before any deny() call, so
            # execution_id is schema-valid everywhere below.
            return ScopeEvaluation(
                evaluation_id=evaluation_id_for(
                    authorization_id=authz.authorization_id,
                    execution_id=execution_id,
                    resolution_id=res.resolution_id,
                    canonical_target_hash=res.canonical_target_hash,
                    scope_lists_hash_current=(
                        policy.scope_lists_hash if policy else None
                    ),
                ),
                authorization_id=authz.authorization_id,
                execution_id=execution_id,
                resolution_id=res.resolution_id,
                program_name=authz.target.program_name,
                canonical_target_hash=res.canonical_target_hash,
                scope_lists_hash_current=(
                    policy.scope_lists_hash if policy else None
                ),
                decision="DENIED",
                include_rule=None,
                exclude_rule=None,
                address_decisions=(),
                hop_decisions=(),
                failure_code=code,  # type: ignore[arg-type]
                evaluated_at=now,
                evaluator_version=EVALUATOR_VERSION,  # type: ignore[arg-type]
            )

        if not re.match(r"^ex-[0-9a-f]{32}$", execution_id):
            raise ScopeError("INVALID_REQUEST", "malformed execution id")
        try:
            require_live_for_execution(authz, now=now)
        except EvidenceError:
            return deny("AUTHZ_NOT_LIVE", None)
        if execution_id != res.execution_id:
            return deny("AUTHZ_BINDING_MISMATCH", None)
        if res.authorization_id != authz.authorization_id:
            return deny("RESOLUTION_BINDING_MISMATCH", None)
        if res.status != "RESOLVED":
            return deny("RESOLUTION_BINDING_MISMATCH", None)
        bound = authz.target
        if res.program_name != bound.program_name:
            return deny("TARGET_BINDING_MISMATCH", None)
        try:
            authz_host, _ = canonicalize_host(bound.host)
        except (CanonicalizationError, TypeError):
            return deny("TARGET_BINDING_MISMATCH", None)
        if authz_host != res.canonical_host:
            return deny("RESOLUTION_BINDING_MISMATCH", None)
        try:
            re_host, _ = canonicalize_host(res.canonical_host)
        except (CanonicalizationError, TypeError):
            return deny("TARGET_NOT_CANONICAL", None)
        if re_host != res.canonical_host:
            return deny("TARGET_NOT_CANONICAL", None)
        if res.scheme != bound.scheme or (
            res.effective_port != bound.effective_port
        ):
            return deny("RESOLUTION_BINDING_MISMATCH", None)
        recomputed = canonical_target_hash_for(
            program_name=res.program_name,
            canonical_host=res.canonical_host,
            scheme=res.scheme,
            effective_port=res.effective_port,
        )
        if recomputed != res.canonical_target_hash:
            return deny("RESOLUTION_BINDING_MISMATCH", None)
        dial = res.dial
        if (
            dial is None
            or tuple(dial.addresses) != tuple(res.resolved_addresses)
            or dial.effective_port != res.effective_port
            or dial.sni_host != res.canonical_host
            or dial.pin_required is not True
        ):
            return deny("DIAL_BINDING_MISMATCH", None)
        program = bound.program_name
        try:
            policy = self._policies.get_policy(program)
        except PolicyError:
            return deny("SCOPE_POLICY_INVALID", None)
        if policy is None:
            return deny("PROGRAM_NOT_FOUND", None)
        if policy.program_name != program:
            return deny("AUTHZ_BINDING_MISMATCH", policy)
        if policy.scope_lists_hash != bound.scope_lists_hash:
            return deny("SCOPE_DRIFT", policy)
        if not policy.inclusions:
            return deny("SCOPE_POLICY_MISSING", policy)
        return (authz, res, program, res.canonical_host, policy)

    def _address_gate(
        self,
        authz: IssuedExecutionAuthorization,
        res: TargetResolution,
        execution_id: str,
        now: str,
        policy: CompiledScopePolicy,
        addresses: tuple[str, ...],
    ) -> tuple[AddressDecision, ...] | ScopeEvaluation:
        """Dual safety/scope gate over every address (ALL must pass).

        Safety is re-classified locally (never trusted from the
        input record alone); scope under the host-only policy is
        satisfied by safety (recorded per address for audit).
        """

        if not addresses:
            return self._deny(
                authz, res, execution_id, now, policy, "UNSAFE_ADDRESS"
            )
        decisions: list[AddressDecision] = []
        for address in addresses:
            try:
                canonical = classify_address(address)
            except DnsError:
                return self._deny(
                    authz, res, execution_id, now, policy, "UNSAFE_ADDRESS"
                )
            decisions.append(
                AddressDecision(
                    address=canonical,
                    outcome="ALLOW",
                    reason="pinned-safe",
                )
            )
        return tuple(decisions)

    def _deny(
        self,
        authz: IssuedExecutionAuthorization,
        res: TargetResolution,
        execution_id: str,
        now: str,
        policy: CompiledScopePolicy,
        code: str,
        *,
        include_rule: str | None = None,
        exclude_rule: str | None = None,
    ) -> ScopeEvaluation:
        return ScopeEvaluation(
            evaluation_id=evaluation_id_for(
                authorization_id=authz.authorization_id,
                execution_id=execution_id,
                resolution_id=res.resolution_id,
                canonical_target_hash=res.canonical_target_hash,
                scope_lists_hash_current=policy.scope_lists_hash,
            ),
            authorization_id=authz.authorization_id,
            execution_id=execution_id,
            resolution_id=res.resolution_id,
            program_name=authz.target.program_name,
            canonical_target_hash=res.canonical_target_hash,
            scope_lists_hash_current=policy.scope_lists_hash,
            decision="DENIED",
            include_rule=include_rule,
            exclude_rule=exclude_rule,
            address_decisions=(),
            hop_decisions=(),
            failure_code=code,  # type: ignore[arg-type]
            evaluated_at=now,
            evaluator_version=EVALUATOR_VERSION,  # type: ignore[arg-type]
        )

    def _chain_digest(self, hop_decisions: list[HopDecision]) -> str:
        from ai.evidence.hashing import hash_payload

        return hash_payload(
            {"hops": [hop.canonical_url for hop in hop_decisions]}
        )

    def _chain_deny(
        self,
        initial: ScopeEvaluation,
        hop_decisions: list[HopDecision],
        code: str,
    ) -> ScopeEvaluation:
        return initial.model_copy(
            update={
                "decision": "DENIED",
                "failure_code": code,
                "hop_decisions": tuple(hop_decisions),
                "evaluation_id": evaluation_id_for(
                    authorization_id=initial.authorization_id,
                    execution_id=initial.execution_id,
                    resolution_id=initial.resolution_id,
                    canonical_target_hash=initial.canonical_target_hash,
                    scope_lists_hash_current=initial.scope_lists_hash_current,
                    chain_digest=self._chain_digest(hop_decisions),
                ),
            }
        )

    def _evaluate_hop(
        self,
        authorization: IssuedExecutionAuthorization,
        res: TargetResolution,
        execution_id: str,
        now: str,
        policy: CompiledScopePolicy,
        current_url: str,
        visited: set[str],
        index: int,
        hop: HopObservation,
    ) -> tuple[HopDecision, str] | ScopeEvaluation:
        """One hop: join → canonicalize → gates → HopDecision.

        Returns ``(hop_decision, next_canonical_url)`` for decided
        hops, or an INCONCLUSIVE ``ScopeEvaluation`` stop when the hop
        lacks the observations needed to decide.
        """

        location = hop.location
        if not isinstance(location, str) or not location:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        if len(location) > MAX_LOCATION_LENGTH:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        if any(ord(c) < 32 or ord(c) == 127 for c in location):
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        try:
            joined = urljoin(current_url, location)
            parts = urlsplit(joined)
        except ValueError:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        scheme = (parts.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        netloc = parts.netloc or ""
        if "@" in netloc or parts.username is not None:
            # Userinfo never travels in evaluated URLs.
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        raw_host = parts.hostname or ""
        if not raw_host:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        try:
            host, kind = canonicalize_host(raw_host)
        except (CanonicalizationError, TypeError):
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        if kind != "dns":
            # Redirects to IP literals are new destinations outside
            # host policy: deny (no IP scope in this phase).
            return self._hop_deny(index, "REDIRECT_NOT_IN_SCOPE"), ""
        try:
            port = parts.port
        except ValueError:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        if port is None:
            port = _DEFAULT_PORTS[scheme]
        if not 1 <= port <= 65535:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        if "\\" in (parts.path or "") or "\\" in joined:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        current_parts = urlsplit(current_url)
        current_scheme = (current_parts.scheme or "").lower()
        if current_scheme == "https" and scheme == "http":
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        upgraded = False
        if current_scheme == "http" and scheme == "https":
            if authorization.execution_class != "http_probe":
                return self._hop_deny(index, "REDIRECT_INVALID"), ""
            upgraded = True
        canonical_url = _canonical_hop_url(
            scheme, host, port, parts.path or "", parts.query or ""
        )
        if canonical_url in visited:
            return self._hop_deny(index, "REDIRECT_INVALID"), ""
        exclude = match_exclusions(policy.exclusions, host)
        include = match_inclusions(policy.inclusions, host)
        if exclude is not None:
            return self._hop_deny(
                index, "REDIRECT_NOT_IN_SCOPE",
                include_rule=include.text if include else None,
                exclude_rule=exclude.text,
            ), canonical_url
        if include is None:
            return self._hop_deny(
                index, "REDIRECT_NOT_IN_SCOPE"
            ), canonical_url
        if port not in (80, 443, res.effective_port):
            # Cross-port destinations get no inheritance: the port
            # allowlist decides, exactly like the initial target.
            return self._hop_deny(
                index, "REDIRECT_NOT_IN_SCOPE",
                include_rule=include.text,
            ), canonical_url
        if not hop.addresses:
            # Missing address observations: cannot decide this hop.
            # INCONCLUSIVE stop (non-authorizing), never assumed safe.
            location_echo = (
                REDACTED
                if contains_secret_shape(location)
                else location[:200]
            )
            inconclusive = ScopeEvaluation(
                evaluation_id=evaluation_id_for(
                    authorization_id=authorization.authorization_id,
                    execution_id=execution_id,
                    resolution_id=res.resolution_id,
                    canonical_target_hash=res.canonical_target_hash,
                    scope_lists_hash_current=policy.scope_lists_hash,
                    chain_digest="pending",
                ),
                authorization_id=authorization.authorization_id,
                execution_id=execution_id,
                resolution_id=res.resolution_id,
                program_name=res.program_name,
                canonical_target_hash=res.canonical_target_hash,
                scope_lists_hash_current=policy.scope_lists_hash,
                decision="INCONCLUSIVE",
                include_rule=None,
                exclude_rule=None,
                address_decisions=(),
                hop_decisions=(
                    HopDecision(
                        hop_index=index,
                        location_raw_scrubbed=location_echo,
                        canonical_url=canonical_url,
                        canonical_host=host,
                        scheme=scheme,
                        effective_port=port,
                        decision="INCONCLUSIVE",
                        failure_code=None,
                        include_rule=include.text,
                        exclude_rule=None,
                        upgraded=upgraded,
                    ),
                ),
                failure_code=None,
                evaluated_at=now,
                evaluator_version=EVALUATOR_VERSION,  # type: ignore[arg-type]
            )
            return inconclusive
        for address in hop.addresses:
            try:
                classify_address(address)
            except DnsError:
                return self._hop_deny(
                    index, "UNSAFE_ADDRESS",
                    include_rule=include.text,
                ), canonical_url
        return (
            HopDecision(
                hop_index=index,
                location_raw_scrubbed=location[:200],
                canonical_url=canonical_url,
                canonical_host=host,
                scheme=scheme,
                effective_port=port,
                decision="ALLOWED",
                failure_code=None,
                include_rule=include.text,
                exclude_rule=None,
                upgraded=upgraded,
            ),
            canonical_url,
        )

    def _hop_deny(
        self,
        index: int,
        code: str,
        *,
        include_rule: str | None = None,
        exclude_rule: str | None = None,
    ) -> HopDecision:
        return HopDecision(
            hop_index=index,
            location_raw_scrubbed="",
            canonical_url="",
            canonical_host="",
            scheme="",
            effective_port=0,
            decision="DENIED",
            failure_code=code,  # type: ignore[arg-type]
            include_rule=include_rule,
            exclude_rule=exclude_rule,
            upgraded=False,
        )


def require_allowed(
    evaluation: object,
    *,
    authorization_id: str,
    execution_id: str,
    resolution_id: str,
) -> ScopeEvaluation:
    """Future-transport entry gate (5E/5F/5G call this, never bypass).

    Returns the evaluation only when ``decision == ALLOWED`` and the
    ``(authorization_id, execution_id, resolution_id)`` triple
    matches the execution context. Anything else raises closed
    ``ScopeError``. There is deliberately no generic
    ``execute(url)``-shaped API anywhere in 5D.
    """

    if not isinstance(evaluation, ScopeEvaluation):
        raise TypeError(
            "transport gate accepts only ScopeEvaluation, "
            f"not {type(evaluation).__name__}"
        )
    if evaluation.decision != "ALLOWED":
        raise ScopeError("TARGET_NOT_IN_SCOPE", "evaluation not allowing")
    if evaluation.authorization_id != authorization_id:
        raise ScopeError("AUTHZ_BINDING_MISMATCH", "authorization mismatch")
    if evaluation.execution_id != execution_id:
        raise ScopeError("AUTHZ_BINDING_MISMATCH", "execution mismatch")
    if evaluation.resolution_id != resolution_id:
        raise ScopeError(
            "RESOLUTION_BINDING_MISMATCH", "resolution mismatch"
        )
    return evaluation
