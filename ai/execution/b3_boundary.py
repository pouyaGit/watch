"""B3 execution safety boundary (Stage 3).

The smallest possible production execution boundary in which a future
authorized ``http_probe`` can run ONLY when the full 5B-5J authority,
resolution, scope, evidence, and verification chain permits it.

This module is OFFLINE and DETERMINISTIC: no sockets, no ``ssl``, no
subprocess, no database driver, no DNS, no LLM, no browser, no Nuclei,
no findings, no verdicts. It introduces no live traffic path:
``HTTP_PROBE_PILOT_ENABLED`` is ``False`` and no code path in this
module (or anywhere else in Stage 3) sets it to ``True``. The existing
``LIVE_TRAFFIC_ENABLED`` / ``LIVE_NUCLEI`` / ``LIVE_BROWSER`` switches
are untouched and remain ``False``.

Contents (all fail-closed, all with a closed error vocabulary):

- :class:`EgressPolicy`: explicit per-execution egress allowlist bound
  to ``authorization_id + execution_id + program + canonical host +
  approved address + effective port + scheme + scope_lists_hash +
  resolution_id + evaluation_id`` (policy version
  ``B3_POLICY_VERSION`` for ``http_probe``;
  ``NUCLEI_EGRESS_POLICY_VERSION`` for the controlled ``nuclei_scan``
  class, which additionally binds ``canonical_target_hash`` + the
  artifact identity/hash + the full validated address set). Built only
  by :func:`build_egress_policy` from genuine 5B/5C/5D records; the
  executor may dial ONLY the exact bound ``(address, port, scheme)``
  triple via :func:`check_egress_dial`. No wildcard, no proxy, no
  host-header authorization, no destination override, no redirect
  reuse.
- Network-isolation abstraction (:func:`acquire_sandbox` /
  :func:`release_sandbox`): documents the namespace/interface/route/
  DNS/egress/teardown contract. A real Linux network namespace cannot
  be created safely in this environment (requires root /
  ``CAP_SYS_ADMIN``; ``unshare -n`` fails here), so
  :func:`acquire_sandbox` records the intended boundary parameters and
  release accounting proves bounded lifetime + cleanup on normal
  completion, timeout, and failure. The ``nuclei_scan`` policy shape
  requests the ``production-netns`` mode (``SandboxSpec`` accounting
  only); the actual namespace/filter materialization is performed by
  the separately reviewed ``ai.execution.netns_sandbox`` machinery,
  which fails closed — ``SANDBOX_UNAVAILABLE`` — wherever privileges
  or tools are missing. No code path here creates a namespace, a veth
  pair, an iptables rule, or a child process in order to "make tests
  pass".
- Resource limits (:func:`check_request_bounds`,
  :func:`check_response_budget`, :class:`SandboxSpec` budgets): frozen
  ``CEILINGS`` values reused (never redefined, never loosened);
  outbound request bounds are conservative explicit caps documented
  below.
- Redirect safety (:func:`check_redirect_target`,
  :func:`require_fresh_scope_for_redirect`): every redirect hop
  requires a FRESH ``TargetResolution`` + ``ScopeEvaluation`` pair
  through the approved B1 seam; the previous hop's policy never
  authorizes the next dial.
- Dial-proof integration (:func:`assert_dial_matches_egress`): reuses
  the EXISTING ``ai.execution.dial_proof`` proof format (no second
  format) and additionally binds the proven peer to the egress policy.
- Live pilot gate (:func:`evaluate_pilot_gate` /
  :func:`check_pilot_gate`): 15-condition conjunctive gate, CLOSED BY
  DEFAULT. Even a fully passing evaluation does not perform I/O: it
  only reports structural admissibility. Live transport additionally
  requires the frozen ``LIVE_TRAFFIC_ENABLED`` switch, which Stage 3
  does not touch.

Frozen contracts reused (never duplicated): 5B
``IssuedExecutionAuthorization`` (+ ``ALLOWED_METHODS``), 5C
``TargetResolution`` / ``DialBinding`` (+ ``classify_address`` /
``validate_answers`` deny policy), 5D ``ScopeEvaluation``
(``ALLOWED`` only), B1 ``DialProof`` / ``verify_dial_proof``,
``CEILINGS``, evidence hashing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from ai.evidence import hashing as hash_mod
from ai.limits.ceilings import CEILINGS
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.resolver.dns import DnsError, classify_address
from ai.schemas.execution_authorization import (
    ALLOWED_METHODS,
    IssuedExecutionAuthorization,
)
from ai.schemas.scope_evaluation import ScopeEvaluation
from ai.schemas.target_resolution import TargetResolution

__all__ = [
    "B3_POLICY_VERSION",
    "NUCLEI_EGRESS_POLICY_VERSION",
    "B3_BOUNDARY_VERSION",
    "B3_RESOURCE_VERSION",
    "PILOT_GATE_VERSION",
    "HTTP_PROBE_PILOT_ENABLED",
    "PILOT_GATE_CHECKS",
    "B3_ERROR_CODES",
    "B3BoundaryError",
    "SANDBOX_MODES",
    "SANDBOX_PRODUCTION_BLOCKER",
    "ADMITTED_EXECUTION_CLASSES",
    "B3_MAX_URL_LENGTH",
    "B3_MAX_REQUEST_HEADERS",
    "B3_MAX_HEADER_VALUE",
    "EgressPolicy",
    "SandboxSpec",
    "SandboxRelease",
    "PilotGateConfig",
    "check_authorization_freshness",
    "build_egress_policy",
    "check_egress_dial",
    "egress_policy_hash",
    "is_forbidden_destination",
    "check_destination_allowed",
    "check_redirect_target",
    "require_fresh_scope_for_redirect",
    "check_request_bounds",
    "check_response_budget",
    "acquire_sandbox",
    "release_sandbox",
    "assert_dial_matches_egress",
    "evaluate_pilot_gate",
    "check_pilot_gate",
    "assert_nuclei_browser_blocked",
]

#: Egress-policy shape version (bumped only additively).
B3_POLICY_VERSION = "b3-egress-policy/v1"

#: Explicit egress-policy version/identity for the controlled
#: ``nuclei_scan`` execution class (Phase 5K-live B7-A). Evidence can
#: later prove WHICH reviewed policy shape authorized an execution by
#: carrying ``policy_version`` alongside ``egress_policy_hash``. Never
#: equal to ``B3_POLICY_VERSION``: a nuclei policy is never mistaken
#: for an http-probe policy (and vice versa) at dial/sandbox time.
NUCLEI_EGRESS_POLICY_VERSION = "b7-nuclei-egress/v1"

#: Execution classes admitted to ``build_egress_policy``. Each class
#: gets an explicit, narrowly scoped policy; anything outside this
#: closed set fails ``FORBIDDEN_EXECUTION_CLASS``.
ADMITTED_EXECUTION_CLASSES = frozenset({"http_probe", "nuclei_scan"})

#: Sandbox-boundary abstraction version.
B3_BOUNDARY_VERSION = "b3-sandbox-boundary/v1"

#: Resource-limit profile version.
B3_RESOURCE_VERSION = "b3-resource-limits/v1"

#: Pilot-gate shape version.
PILOT_GATE_VERSION = "b3-http-probe-pilot-gate/v1"

#: Master pilot switch. Frozen ``False`` for Stage 3. No code path in
#: this module sets it to ``True``: enabling requires an explicit
#: trusted-configuration change OUTSIDE this module plus the separately
#: authorized activation review. Flipping this constant in place is NOT
#: an authorized activation (see ``SANDBOX_PRODUCTION_BLOCKER``).
HTTP_PROBE_PILOT_ENABLED = False

#: Conjunctive pilot-gate conditions (all must hold; see
#: :func:`evaluate_pilot_gate`).
PILOT_GATE_CHECKS: tuple[str, ...] = (
    "issued_authorization_live",
    "resolved_target",
    "scope_allowed",
    "scope_fresh",
    "b1_address_review",
    "egress_policy_valid",
    "dial_proof_valid",
    "request_bounded",
    "ledger_admitted",
    "resource_limits_applied",
    "evidence_path_ready",
    "verifier_path_ready",
    "destination_permitted",
    "authorization_fresh",
    "no_scope_drift",
)

#: Closed B3 failure vocabulary (secret-free, single-line details).
B3_ERROR_CODES = frozenset(
    {
        "EGRESS_DENIED",
        "STALE_EGRESS_POLICY",
        "MISSING_EGRESS_POLICY",
        "FORBIDDEN_DESTINATION",
        "STALE_AUTHORIZATION",
        "SCOPE_DRIFT",
        "DIAL_BINDING_MISMATCH",
        "DIAL_PROOF_MISMATCH",
        "REQUEST_BOUND_REJECTED",
        "RESPONSE_BOUND_EXCEEDED",
        "REDIRECT_REQUIRES_FRESH_SCOPE",
        "REDIRECT_INVALID",
        "REDIRECT_NOT_IN_SCOPE",
        "REDIRECT_LIMIT",
        "RESOURCE_LIMIT",
        "SANDBOX_UNAVAILABLE",
        "PILOT_GATE_CLOSED",
        "FORBIDDEN_EXECUTION_CLASS",
    }
)


class B3BoundaryError(ValueError):
    """Bounded, secret-free B3 boundary failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in B3_ERROR_CODES:
            raise ValueError(f"unknown B3 boundary code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("B3 boundary detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


# ------------------------------------------------------------------
# Sandbox modes.
# ------------------------------------------------------------------

#: Sandbox modes :func:`acquire_sandbox` can record. ``dry-run-blocked``
#: means the boundary is specified, budgeted, and accounted for, but NO
#: isolated execution context is actually materialized. For a
#: ``nuclei_scan`` EgressPolicy the recorded intent is
#: ``production-netns`` (isolated namespace + default-deny egress
#: allowlist); materializing that namespace is performed by
#: ``ai.execution.netns_sandbox`` and fails closed with
#: ``SANDBOX_UNAVAILABLE`` on this host (see
#: ``SANDBOX_PRODUCTION_BLOCKER``). Recording ``production-netns`` here
#: is accounting, never proof of provisioned containment.
SANDBOX_MODES = ("dry-run-blocked", "production-netns")

#: Why no production network namespace is materialized in this module.
#: Recorded as data (not a comment) so tests and the pilot gate can
#: assert on it instead of trusting prose. The materialization layer
#: (``ai.execution.netns_sandbox.SystemNetnsBackend``) probes these
#: capabilities before any command and ALWAYS fails closed — never a
#: fallback to host networking.
SANDBOX_PRODUCTION_BLOCKER = (
    "isolated namespace materialization requires root/CAP_SYS_ADMIN "
    "plus the ip/nftables tooling; unshare -n fails in this "
    "environment, so live egress stays structurally refused "
    "(SANDBOX_UNAVAILABLE) with no host-network fallback"
)

# ------------------------------------------------------------------
# Request/response bounds (conservative, explicit, documented).
# ------------------------------------------------------------------

#: Outbound URL cap = translator caps summed, no weaker: path (2048) +
#: query worst case (16 params x (128 name + 1024 value + 2)) + 256
#: scheme/authority margin. Anything longer never passed translation.
B3_MAX_URL_LENGTH = 2048 + 16 * (128 + 1024 + 2) + 256

#: Outbound header count cap. Translation admits at most the 4 safe
#: artifact headers plus the injected User-Agent; 16 leaves headroom
#: for transport-generated framing without admitting smuggling width.
B3_MAX_REQUEST_HEADERS = 16

#: Outbound per-header value cap (mirrors the 5E translator cap of
#: 1024; never looser).
B3_MAX_HEADER_VALUE = 1024

#: Header-name cap (mirrors the transport framing cap).
B3_MAX_HEADER_NAME = 128

_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_SCHEMES = ("http", "https")

# Explicit IPv4 metadata-service range (defense in depth: the frozen
# ``classify_address`` deny policy already rejects link-local, but the
# metadata address is named here so the pilot gate asserts on it by
# value, never by prose).
_METADATA_IPV4 = ipaddress.ip_address("169.254.169.254")


# ------------------------------------------------------------------
# Forbidden destinations.
# ------------------------------------------------------------------


def is_forbidden_destination(address: object) -> bool:
    """True when an address must never be dialed.

    Authority is the frozen 5C ``classify_address`` deny policy
    (loopback, unspecified, private, link-local, multicast, reserved,
    mapped/odd families fail closed there); the cloud metadata address
    is additionally named explicitly. Anything unparseable is
    forbidden. This function never authorizes: ``False`` means "not
    forbidden by B3", not "authorized" (authorization still requires a
    full egress policy).
    """

    if not isinstance(address, str) or not address:
        return True
    try:
        parsed = ipaddress.ip_address(address.strip())
    except ValueError:
        return True
    if parsed == _METADATA_IPV4:
        return True
    try:
        classify_address(str(parsed))
    except (DnsError, ValueError, TypeError):
        return True
    except Exception:
        return True
    return False


def check_destination_allowed(address: object) -> str:
    """Return the canonical literal, or raise ``FORBIDDEN_DESTINATION``."""

    if is_forbidden_destination(address):
        raise B3BoundaryError(
            "FORBIDDEN_DESTINATION", "destination not globally routable"
        )
    assert isinstance(address, str)
    return str(ipaddress.ip_address(address.strip()))


# ------------------------------------------------------------------
# Egress allowlist policy.
# ------------------------------------------------------------------


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable per-execution egress allowlist (one dial target).

    Exactly one ``(approved_address, effective_port, scheme)`` triple
    is authorized, bound to the full 5B/5C/5D lineage. The transport
    must dial this triple and nothing else; any other destination is
    ``EGRESS_DENIED``. A redirect hop needs a NEW policy built from a
    FRESH resolution/evaluation pair (never this object reused).

    ``http_probe`` policies carry ``policy_version ==
    B3_POLICY_VERSION`` and a single ``approved_address``. The
    controlled ``nuclei_scan`` class (Phase 5K-live B7-A) carries
    ``policy_version == NUCLEI_EGRESS_POLICY_VERSION`` plus the full
    validated ``allowed_addresses`` set (every entry re-checked
    globally routable at build time), the ``canonical_target_hash``,
    and the artifact identity/hash — so the reviewed lineage survives
    through the policy and any mismatch fails closed. Caller input
    cannot select an approved address independently: every allowed
    address MUST already be in the reviewed resolution's validated
    set.
    """

    authorization_id: str
    execution_id: str
    program_name: str
    canonical_host: str
    approved_address: str
    effective_port: int
    scheme: str
    scope_lists_hash: str
    resolution_id: str
    evaluation_id: str
    policy_version: str = B3_POLICY_VERSION
    # B7-A: explicit class/transport identity (evidence-provable).
    execution_class: str = "http_probe"
    transport: str = "tcp"
    # B7-A: nuclei lineage bound through the policy (http_probe leaves
    # these empty; nuclei_scan REQUIRES them).
    canonical_target_hash: str = ""
    artifact_id: str = ""
    artifact_hash: str = ""
    # B7-A: full validated address set (http_probe: the single
    # approved address). Never user-supplied; always derived from the
    # reviewed resolution.
    allowed_addresses: tuple[str, ...] = ()


def _require_typed_records(
    *, authorization: object, resolution: object, evaluation: object
) -> None:
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "egress policy accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if not isinstance(resolution, TargetResolution):
        raise TypeError(
            "egress policy accepts only TargetResolution, "
            f"not {type(resolution).__name__}"
        )
    if not isinstance(evaluation, ScopeEvaluation):
        raise TypeError(
            "egress policy accepts only ScopeEvaluation, "
            f"not {type(evaluation).__name__}"
        )


def _parse_instant(value: object) -> Any:
    """Parse one ISO-8601 instant with the single frozen rule.

    Identical to the 5B issuance rule (``ai.authorizer.service``):
    ``datetime.fromisoformat``; naive timestamps are read as UTC (never
    rejected, never reinterpreted — the rule is documented here so no
    timestamp is ever ambiguous). Unparseable input raises
    ``STALE_AUTHORIZATION`` (fail closed).
    """

    from datetime import datetime, timezone

    if not isinstance(value, str) or not value:
        raise B3BoundaryError(
            "STALE_AUTHORIZATION", "authorization instant malformed"
        )
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise B3BoundaryError(
            "STALE_AUTHORIZATION", "authorization instant malformed"
        ) from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


def check_authorization_freshness(
    *, authorization: object, now: str
) -> None:
    """Enforce the deterministic authorization validity window (Part E).

    An authorization is fresh exactly when ``issued_at <= now <
    expires_at`` — the same boundary the 5B ``_is_live`` rule enforces
    (expiry instant is exclusive: at ``expires_at`` the authorization
    is already expired; before ``issued_at`` it is not yet valid).
    Anything else — expired, not-yet-valid, or malformed instants —
    is ``STALE_AUTHORIZATION``. No wall clock is read: ``now`` is the
    caller-supplied deterministic instant.
    """

    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "freshness accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    current = _parse_instant(now)
    issued = _parse_instant(authorization.issued_at)
    expires = _parse_instant(authorization.expires_at)
    if expires <= issued:
        raise B3BoundaryError(
            "STALE_AUTHORIZATION", "authorization window inverted"
        )
    if current < issued:
        raise B3BoundaryError(
            "STALE_AUTHORIZATION", "authorization not yet valid"
        )
    if expires <= current:
        raise B3BoundaryError("STALE_AUTHORIZATION", "authorization expired")
    return None


def build_egress_policy(
    *,
    authorization: object,
    resolution: object,
    evaluation: object,
    selected_address: str,
    now: str,
) -> EgressPolicy:
    """Bind one approved dial target to the 5B/5C/5D lineage.

    Both ``http_probe`` and the controlled ``nuclei_scan`` class are
    admitted with explicit, narrowly scoped policy shapes (see
    ``ADMITTED_EXECUTION_CLASSES``); any other class fails closed.
    ``nuclei_scan`` additionally binds ``canonical_target_hash`` +
    artifact identity/hash + the full validated address set under
    ``NUCLEI_EGRESS_POLICY_VERSION``.

    Fail-closed rejections: wrong record types (``TypeError``); stale,
    non-live, or time-invalid authorization (``STALE_AUTHORIZATION`` —
    lifecycle AND the deterministic ``issued_at <= now < expires_at``
    window); unresolved target, binding mismatch, dial incoherence, or
    a caller-supplied address outside the reviewed resolution
    (``DIAL_BINDING_MISMATCH``); scope drift (``SCOPE_DRIFT``);
    non-``ALLOWED`` evaluation (``EGRESS_DENIED``); forbidden
    destination (``FORBIDDEN_DESTINATION``); non-admitted execution
    class (``FORBIDDEN_EXECUTION_CLASS``).
    """

    _require_typed_records(
        authorization=authorization,
        resolution=resolution,
        evaluation=evaluation,
    )
    assert isinstance(authorization, IssuedExecutionAuthorization)
    assert isinstance(resolution, TargetResolution)
    assert isinstance(evaluation, ScopeEvaluation)

    if authorization.lifecycle not in ("ISSUED", "CONSUMED"):
        raise B3BoundaryError(
            "STALE_AUTHORIZATION", "authorization not live"
        )
    check_authorization_freshness(authorization=authorization, now=now)
    execution_class = authorization.execution_class
    if execution_class not in ADMITTED_EXECUTION_CLASSES:
        raise B3BoundaryError(
            "FORBIDDEN_EXECUTION_CLASS", "execution class not in scope"
        )
    if resolution.status != "RESOLVED":
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "resolution not resolved"
        )
    if (
        resolution.authorization_id != authorization.authorization_id
        or evaluation.authorization_id != authorization.authorization_id
        or evaluation.resolution_id != resolution.resolution_id
    ):
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "lineage binding mismatch"
        )
    if resolution.program_name != authorization.target.program_name:
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "program binding mismatch"
        )
    if resolution.scope_lists_hash_current != authorization.target.scope_lists_hash:
        raise B3BoundaryError("SCOPE_DRIFT", "policy hash drift at build")
    if (
        evaluation.scope_lists_hash_current is not None
        and evaluation.scope_lists_hash_current
        != authorization.target.scope_lists_hash
    ):
        raise B3BoundaryError("SCOPE_DRIFT", "evaluation hash drift at build")
    if bool(getattr(resolution, "scope_drift", False)):
        raise B3BoundaryError("SCOPE_DRIFT", "resolution drift flag set")
    if evaluation.decision != "ALLOWED":
        raise B3BoundaryError("EGRESS_DENIED", "scope not allowed")
    if evaluation.execution_id != resolution.execution_id:
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "execution binding mismatch"
        )
    if not isinstance(selected_address, str) or not selected_address:
        raise B3BoundaryError("MISSING_EGRESS_POLICY", "selected address absent")
    if selected_address not in tuple(resolution.resolved_addresses):
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "selected address not in pin list"
        )
    dial = resolution.dial
    if (
        dial is None
        or tuple(dial.addresses) != tuple(resolution.resolved_addresses)
        or dial.sni_host != resolution.canonical_host
    ):
        raise B3BoundaryError("DIAL_BINDING_MISMATCH", "dial binding incoherent")
    if resolution.scheme not in _SCHEMES:
        raise B3BoundaryError("DIAL_BINDING_MISMATCH", "scheme not probeable")
    if (
        not isinstance(resolution.effective_port, int)
        or isinstance(resolution.effective_port, bool)
        or not 1 <= resolution.effective_port <= 65535
        or dial.effective_port != resolution.effective_port
    ):
        raise B3BoundaryError("DIAL_BINDING_MISMATCH", "port incoherent")
    approved = check_destination_allowed(selected_address)
    if approved != selected_address:
        # Non-canonical text (padding, zones, aliases) is not a literal
        # the transport may dial: exact binding only.
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "selected address not canonical"
        )
    if execution_class == "nuclei_scan":
        # B7-A narrowly scoped nuclei policy: the full validated set is
        # bound (each entry re-checked globally routable), plus the
        # reviewed lineage (canonical_target_hash + artifact identity).
        # The caller cannot supply an approved address independently:
        # every allowed address MUST already be inside the resolution.
        cth = getattr(resolution, "canonical_target_hash", None)
        artifact = getattr(authorization, "artifact", None)
        artifact_id = getattr(artifact, "artifact_id", None)
        artifact_hash = getattr(artifact, "content_hash", None)
        if (
            not isinstance(cth, str)
            or not cth
            or not isinstance(artifact_id, str)
            or not artifact_id
            or not isinstance(artifact_hash, str)
            or not artifact_hash
        ):
            raise B3BoundaryError(
                "DIAL_BINDING_MISMATCH", "nuclei lineage fields absent"
            )
        resolved = tuple(resolution.resolved_addresses)
        if not resolved:
            raise B3BoundaryError(
                "DIAL_BINDING_MISMATCH", "nuclei address set empty"
            )
        allowed_addresses = tuple(
            check_destination_allowed(addr) for addr in resolved
        )
        if approved not in allowed_addresses:
            raise B3BoundaryError(
                "DIAL_BINDING_MISMATCH", "selected not in nuclei allowlist"
            )
        policy_version = NUCLEI_EGRESS_POLICY_VERSION
        transport = "tcp"
    else:
        cth = ""
        artifact_id = ""
        artifact_hash = ""
        allowed_addresses = (approved,)
        policy_version = B3_POLICY_VERSION
        transport = "tcp"
    return EgressPolicy(
        authorization_id=authorization.authorization_id,
        execution_id=resolution.execution_id,
        program_name=resolution.program_name,
        canonical_host=resolution.canonical_host,
        approved_address=approved,
        effective_port=resolution.effective_port,
        scheme=resolution.scheme,
        scope_lists_hash=authorization.target.scope_lists_hash,
        resolution_id=resolution.resolution_id,
        evaluation_id=evaluation.evaluation_id,
        policy_version=policy_version,
        execution_class=execution_class,
        transport=transport,
        canonical_target_hash=cth,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        allowed_addresses=allowed_addresses,
    )


def egress_policy_hash(policy: EgressPolicy) -> str:
    """Deterministic identity of one egress policy (audit binding)."""

    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "egress hash accepts only EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    return hash_mod.hash_payload(
        {
            "allowed_addresses": tuple(policy.allowed_addresses),
            "approved_address": policy.approved_address,
            "artifact_hash": policy.artifact_hash,
            "artifact_id": policy.artifact_id,
            "authorization_id": policy.authorization_id,
            "canonical_host": policy.canonical_host,
            "canonical_target_hash": policy.canonical_target_hash,
            "effective_port": policy.effective_port,
            "evaluation_id": policy.evaluation_id,
            "execution_class": policy.execution_class,
            "execution_id": policy.execution_id,
            "policy_version": policy.policy_version,
            "program_name": policy.program_name,
            "resolution_id": policy.resolution_id,
            "scheme": policy.scheme,
            "scope_lists_hash": policy.scope_lists_hash,
            "transport": policy.transport,
        }
    )


def check_egress_dial(
    *,
    policy: object,
    dial_ip: str,
    dial_port: int,
    dial_scheme: str,
    authorization_id: str,
    resolution_id: str,
) -> EgressPolicy:
    """Authorize exactly one SYN against the egress policy (fail closed).

    Every field must match exactly: stale policy versions
    (``STALE_EGRESS_POLICY``), missing policy (``MISSING_EGRESS_POLICY``),
    and any address/port/scheme/authorization/resolution deviation
    (``EGRESS_DENIED``) refuse the dial. There is no wildcard, no
    prefix match, no port-range match.
    """

    if policy is None:
        raise B3BoundaryError("MISSING_EGRESS_POLICY", "no egress policy bound")
    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "egress check accepts only EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    if policy.policy_version not in (B3_POLICY_VERSION, NUCLEI_EGRESS_POLICY_VERSION):
        raise B3BoundaryError("STALE_EGRESS_POLICY", "policy version skew")
    if (
        not isinstance(dial_ip, str)
        or not isinstance(authorization_id, str)
        or not isinstance(resolution_id, str)
        or not isinstance(dial_scheme, str)
    ):
        raise B3BoundaryError("EGRESS_DENIED", "dial descriptors untyped")
    if (
        dial_ip != policy.approved_address
        or dial_port != policy.effective_port
        or dial_scheme != policy.scheme
        or authorization_id != policy.authorization_id
        or resolution_id != policy.resolution_id
    ):
        raise B3BoundaryError("EGRESS_DENIED", "dial not in egress policy")
    return policy


# ------------------------------------------------------------------
# Redirect safety.
# ------------------------------------------------------------------


def check_redirect_target(
    *,
    location_host: str,
    location_scheme: str,
    location_port: int,
    current_scheme: str,
    execution_class: str,
) -> str:
    """Structural redirect-target gate (pre-resolution, fail closed).

    Returns the canonical host. Rejects: non-canonical hosts,
    IP-literal destinations (``REDIRECT_NOT_IN_SCOPE`` — the no-IP
    scope policy), forbidden host tokens are left to resolution/scope
    but IP-shaped input never passes, unsafe ports, https-downgrade,
    and non-``http_probe`` http-upgrade (``REDIRECT_INVALID``).
    A returned host is NOT authorized: the caller must still resolve
    it through the B1 seam, re-evaluate scope, and build a fresh
    egress policy before any dial.
    """

    if execution_class != "http_probe":
        raise B3BoundaryError(
            "FORBIDDEN_EXECUTION_CLASS", "only http_probe is in scope"
        )
    if location_scheme not in _SCHEMES or current_scheme not in _SCHEMES:
        raise B3BoundaryError("REDIRECT_INVALID", "redirect scheme rejected")
    if current_scheme == "https" and location_scheme == "http":
        raise B3BoundaryError("REDIRECT_INVALID", "https downgrade denied")
    if not isinstance(location_host, str) or not location_host:
        raise B3BoundaryError("REDIRECT_INVALID", "redirect host missing")
    try:
        host, kind = canonicalize_host(location_host)
    except (CanonicalizationError, TypeError) as exc:
        raise B3BoundaryError("REDIRECT_INVALID", "redirect host rejected") from exc
    if host != location_host:
        raise B3BoundaryError("REDIRECT_INVALID", "redirect host not canonical")
    if kind != "dns":
        raise B3BoundaryError(
            "REDIRECT_NOT_IN_SCOPE", "ip redirect not in scope"
        )
    if (
        not isinstance(location_port, int)
        or isinstance(location_port, bool)
        or not 1 <= location_port <= 65535
    ):
        raise B3BoundaryError("REDIRECT_INVALID", "redirect port rejected")
    return host


def require_fresh_scope_for_redirect(
    *,
    policy: object,
    authorization: object,
    new_resolution: object,
    new_evaluation: object,
    redirect_hop_index: int,
    selected_address: str,
    now: str,
) -> EgressPolicy:
    """Build the next hop's egress policy from FRESH bindings.

    Requires: the current policy (typed); the live 5B authorization
    record re-presented (typed, still live, same id and scope hash as
    the policy, AND still inside its deterministic validity window at
    ``now`` — a redirect never extends a revoked/expired/drifted
    authorization); a fresh ``TargetResolution`` + ``ScopeEvaluation``
    pair for the redirect target (typed, ``ALLOWED``, lineage-bound to
    the SAME authorization/execution); a hop index within the frozen
    redirect budget; and a selected address drawn from the fresh pin.
    Reusing the previous hop's resolution/evaluation ids is
    ``REDIRECT_REQUIRES_FRESH_SCOPE`` — the old policy never
    authorizes the next dial (exact-match :func:`check_egress_dial`
    would refuse it anyway).
    """

    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "redirect scope requires EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "redirect scope requires IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if not isinstance(new_resolution, TargetResolution) or not isinstance(
        new_evaluation, ScopeEvaluation
    ):
        raise TypeError("redirect scope requires fresh typed bindings")
    if not isinstance(redirect_hop_index, int) or not 1 <= redirect_hop_index <= CEILINGS[
        "redirect_hops"
    ]:
        raise B3BoundaryError("REDIRECT_LIMIT", "redirect budget spent")
    if authorization.authorization_id != policy.authorization_id:
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "redirect authorization mismatch"
        )
    if authorization.target.scope_lists_hash != policy.scope_lists_hash:
        raise B3BoundaryError("SCOPE_DRIFT", "redirect authorization drifted")
    if new_resolution.resolution_id == policy.resolution_id:
        raise B3BoundaryError(
            "REDIRECT_REQUIRES_FRESH_SCOPE", "resolution not refreshed"
        )
    if new_evaluation.evaluation_id == policy.evaluation_id:
        raise B3BoundaryError(
            "REDIRECT_REQUIRES_FRESH_SCOPE", "evaluation not refreshed"
        )
    if (
        new_resolution.authorization_id != policy.authorization_id
        or new_evaluation.authorization_id != policy.authorization_id
        or new_resolution.execution_id != policy.execution_id
        or new_evaluation.execution_id != policy.execution_id
        or new_evaluation.resolution_id != new_resolution.resolution_id
    ):
        raise B3BoundaryError(
            "DIAL_BINDING_MISMATCH", "redirect lineage mismatch"
        )
    if new_evaluation.decision != "ALLOWED":
        raise B3BoundaryError(
            "REDIRECT_NOT_IN_SCOPE", "redirect hop not allowed"
        )
    # Reuse the single build gate so redirect hops face the identical
    # binding/drift/destination/freshness discipline as hop zero
    # (liveness AND validity window of the re-presented authorization
    # are re-checked inside the build gate at the redirect instant).
    return build_egress_policy(
        authorization=authorization,
        resolution=new_resolution,
        evaluation=new_evaluation,
        selected_address=selected_address,
        now=now,
    )


# ------------------------------------------------------------------
# Request/response bounds.
# ------------------------------------------------------------------


def check_request_bounds(*, request: object) -> str:
    """Admit one bounded ``BoundedHttpRequest`` for B3 transport.

    Accepts only the genuine 5E ``BoundedHttpRequest`` type (never a
    dict/URL string: an arbitrary URL can never enter the transport).
    Enforces: allowed method, URL length, header count, header
    name/value sizes, body size (frozen ``request_body_bytes``
    ceiling), and lineage-id presence. Returns the canonical URL.
    """

    if type(request).__name__ != "BoundedHttpRequest" or not hasattr(
        request, "canonical_url"
    ):
        raise TypeError(
            "B3 transport accepts only BoundedHttpRequest, "
            f"not {type(request).__name__}"
        )
    method = getattr(request, "method", None)
    if method not in ALLOWED_METHODS:
        raise B3BoundaryError("REQUEST_BOUND_REJECTED", "method not allowed")
    canonical_url = getattr(request, "canonical_url", None)
    if not isinstance(canonical_url, str) or not canonical_url:
        raise B3BoundaryError("REQUEST_BOUND_REJECTED", "url missing")
    if len(canonical_url) > B3_MAX_URL_LENGTH:
        raise B3BoundaryError("REQUEST_BOUND_REJECTED", "url over cap")
    headers = getattr(request, "headers", None)
    if not isinstance(headers, (tuple, list)):
        raise B3BoundaryError("REQUEST_BOUND_REJECTED", "headers untyped")
    if len(headers) > B3_MAX_REQUEST_HEADERS:
        raise B3BoundaryError("REQUEST_BOUND_REJECTED", "too many headers")
    seen: set[str] = set()
    for item in headers:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", "header untyped")
        name = item[0].strip().casefold()
        if not name or name in seen:
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", "header rejected")
        seen.add(name)
        if len(item[0]) > B3_MAX_HEADER_NAME or len(item[1]) > B3_MAX_HEADER_VALUE:
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", "header over cap")
        if name in ("host", "content-length", "transfer-encoding", "connection"):
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", "framing header denied")
    body = getattr(request, "body", None)
    if body is not None:
        if not isinstance(body, (bytes, bytearray)):
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", "body untyped")
        if len(body) > CEILINGS["request_body_bytes"]:
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", "body over ceiling")
    for field in (
        "authorization_id",
        "execution_id",
        "resolution_id",
        "evaluation_id",
        "artifact_id",
        "artifact_content_hash",
    ):
        if not isinstance(getattr(request, field, None), str) or not getattr(
            request, field
        ):
            raise B3BoundaryError("REQUEST_BOUND_REJECTED", f"{field} absent")
    return canonical_url


def check_response_budget(
    *, bytes_received: int, decompressed_bytes: int = 0
) -> None:
    """Enforce transport/response budgets (frozen ceilings, fail closed)."""

    for label, value in (
        ("received", bytes_received),
        ("decompressed", decompressed_bytes),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise B3BoundaryError("RESPONSE_BOUND_EXCEEDED", f"{label} uncounted")
    if bytes_received > CEILINGS["response_transport_bytes"]:
        raise B3BoundaryError("RESPONSE_BOUND_EXCEEDED", "transport cap exceeded")
    if decompressed_bytes > CEILINGS["decompressed_bytes"]:
        raise B3BoundaryError("RESPONSE_BOUND_EXCEEDED", "decompression cap exceeded")


# ------------------------------------------------------------------
# Sandbox (isolation abstraction, dry-run-blocked production gate).
# ------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxSpec:
    """Intended execution boundary parameters (accounting, not handles).

    The ``nuclei_scan`` policy shape records
    ``mode == "production-netns"`` plus the exact egress tuple set
    (``egress_rules``); the http-probe shape records
    ``dry-run-blocked``. Neither mode creates anything here — actual
    namespace/filter materialization belongs to
    ``ai.execution.netns_sandbox`` and fails closed whenever it cannot
    provision (see ``SANDBOX_PRODUCTION_BLOCKER``). The spec records
    WHAT the production launcher must provision — dedicated netns,
    default-deny egress allowlist of exactly the approved
    ``(ip, effective_port, tcp)`` tuples, no DNS service, no default
    route, teardown on completion/timeout/failure — plus the budgets
    actually enforced by the B3 checks, so a reviewer can diff intent
    vs. mechanism.
    """

    mode: str
    execution_id: str
    authorization_id: str
    egress_policy_hash: str
    wall_seconds: int
    connect_timeout_seconds: int
    response_transport_cap: int
    decompressed_cap: int
    max_redirect_hops: int
    max_requests: int
    boundary_version: str = B3_BOUNDARY_VERSION
    resource_version: str = B3_RESOURCE_VERSION
    production_blocker: str = SANDBOX_PRODUCTION_BLOCKER
    policy_version: str = B3_POLICY_VERSION
    egress_rules: tuple[tuple[str, int, str], ...] = ()


@dataclass(frozen=True)
class SandboxRelease:
    """Cleanup accounting: every acquisition must end in one release."""

    execution_id: str
    egress_policy_hash: str
    reason: str
    released_at: str
    boundary_version: str = B3_BOUNDARY_VERSION


_RELEASE_REASONS = frozenset({"completed", "timeout", "failed"})


def acquire_sandbox(
    *,
    policy: object,
    execution_id: str,
    now: str,
) -> SandboxSpec:
    """Record the intended isolated boundary for one execution.

    The ``now`` instant is caller-supplied (deterministic clocks only).
    A ``nuclei_scan`` EgressPolicy records the ``production-netns``
    intent (``egress_rules`` = the exact approved
    ``(ip, effective_port, tcp)`` tuple set); every other policy
    records ``dry-run-blocked``. Acquisition performs no I/O and
    creates no namespace/process/filter — materialization is the
    netns backend's job and is always fail-closed here.
    """

    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "sandbox requires EgressPolicy, " f"not {type(policy).__name__}"
        )
    if policy.policy_version not in (B3_POLICY_VERSION, NUCLEI_EGRESS_POLICY_VERSION):
        raise B3BoundaryError("STALE_EGRESS_POLICY", "policy version skew")
    if not isinstance(execution_id, str) or not _EXECUTION_ID_RE.match(
        execution_id
    ):
        raise B3BoundaryError("RESOURCE_LIMIT", "malformed execution id")
    if execution_id != policy.execution_id:
        raise B3BoundaryError("EGRESS_DENIED", "sandbox execution mismatch")
    if not isinstance(now, str) or not now:
        raise B3BoundaryError("RESOURCE_LIMIT", "malformed clock instant")
    _ = now  # recorded by the caller (audit owns timestamps, not B3)
    if (
        policy.execution_class == "nuclei_scan"
        and policy.transport == "tcp"
        and policy.policy_version == NUCLEI_EGRESS_POLICY_VERSION
        and policy.allowed_addresses
    ):
        mode = "production-netns"
        egress_rules = tuple(
            (addr, policy.effective_port, "tcp")
            for addr in policy.allowed_addresses
        )
        policy_version = NUCLEI_EGRESS_POLICY_VERSION
    else:
        mode = "dry-run-blocked"
        egress_rules = ()
        policy_version = B3_POLICY_VERSION
    return SandboxSpec(
        mode=mode,
        execution_id=execution_id,
        authorization_id=policy.authorization_id,
        egress_policy_hash=egress_policy_hash(policy),
        wall_seconds=CEILINGS["http_wall_seconds"],
        connect_timeout_seconds=CEILINGS["connect_timeout_seconds"],
        response_transport_cap=CEILINGS["response_transport_bytes"],
        decompressed_cap=CEILINGS["decompressed_bytes"],
        max_redirect_hops=CEILINGS["redirect_hops"],
        max_requests=CEILINGS["requests_per_execution"],
        policy_version=policy_version,
        egress_rules=egress_rules,
    )


def release_sandbox(
    *,
    spec: object,
    reason: str,
    released_at: str,
) -> SandboxRelease:
    """Account for teardown (normal, timeout, and failure alike).

    No orphan boundary may survive the execution lifetime: the caller
    must produce exactly one release per acquisition. Unknown reasons
    fail closed (a leaked boundary must never be relabeled "done").
    """

    if not isinstance(spec, SandboxSpec):
        raise TypeError(
            "release accepts only SandboxSpec, " f"not {type(spec).__name__}"
        )
    if reason not in _RELEASE_REASONS:
        raise B3BoundaryError("RESOURCE_LIMIT", "unknown release reason")
    if not isinstance(released_at, str) or not released_at:
        raise B3BoundaryError("RESOURCE_LIMIT", "malformed clock instant")
    return SandboxRelease(
        execution_id=spec.execution_id,
        egress_policy_hash=spec.egress_policy_hash,
        reason=reason,
        released_at=released_at,
    )


# ------------------------------------------------------------------
# Dial-proof integration (existing format only).
# ------------------------------------------------------------------


def assert_dial_matches_egress(
    *,
    proof: object,
    policy: object,
    resolution: object,
    evaluation: object,
    authorization_id: str,
) -> Any:
    """Prove the actual dial stayed inside the egress policy.

    Re-verifies the EXISTING B1 ``DialProof`` against the live 5C/5D
    bindings (``verify_dial_proof`` — no second proof format exists),
    then binds the proven peer to the egress policy: ``actual_peer_ip``
    and ``selected_address`` must equal the policy's approved address.
    Any deviation is ``DIAL_PROOF_MISMATCH``. Returns the verified
    proof.
    """

    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "dial/egress proof requires EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    if not isinstance(authorization_id, str) or not authorization_id:
        raise B3BoundaryError("DIAL_PROOF_MISMATCH", "authorization id absent")
    if authorization_id != policy.authorization_id:
        raise B3BoundaryError(
            "DIAL_PROOF_MISMATCH", "authorization differs from policy"
        )
    try:
        from ai.execution import dial_proof as _dp

        verified = _dp.verify_dial_proof(
            proof,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authorization_id,
        )
    except B3BoundaryError:
        raise
    except Exception as exc:
        code = getattr(exc, "code", "")
        if code in ("MISSING_PROOF", "DIAL_MISMATCH", "PROOF_BINDING_MISMATCH"):
            raise B3BoundaryError("DIAL_PROOF_MISMATCH", "dial proof rejected") from exc
        raise B3BoundaryError("DIAL_PROOF_MISMATCH", "dial proof untyped") from exc
    if (
        getattr(verified, "actual_peer_ip", None) != policy.approved_address
        or getattr(verified, "selected_address", None) != policy.approved_address
    ):
        raise B3BoundaryError(
            "DIAL_PROOF_MISMATCH", "proven peer outside egress policy"
        )
    return verified


# ------------------------------------------------------------------
# Live pilot gate (CLOSED BY DEFAULT).
# ------------------------------------------------------------------


@dataclass(frozen=True)
class PilotGateConfig:
    """Trusted-configuration surface for the future pilot.

    ``pilot_enabled`` defaults to ``False`` and Stage 3 provides no
    code path that constructs a ``True`` instance: enabling requires
    an explicit trusted-configuration change plus the separately
    authorized activation review. Unknown/truthy-non-bool values are
    rejected at construction (fail closed — ``"false"`` the string
    must never enable anything).
    """

    pilot_enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.pilot_enabled) is not bool:
            raise TypeError("pilot_enabled must be exactly bool")


def evaluate_pilot_gate(
    *,
    config: object,
    authorization: object,
    resolution: object,
    evaluation: object,
    policy: object,
    proof: object,
    request: object,
    sandbox: object,
    ledger_admitted: bool,
    evidence_path_ready: bool,
    verifier_path_ready: bool,
    now: str,
) -> tuple[bool, tuple[str, ...]]:
    """Evaluate the 15-condition pilot gate (no I/O, decision only).

    Returns ``(allowed, denials)``. ``allowed`` is ``True`` only when
    every one of ``PILOT_GATE_CHECKS`` holds AND ``config`` explicitly
    enables the pilot. A passing evaluation still performs no dial:
    live transport additionally requires the frozen
    ``LIVE_TRAFFIC_ENABLED`` switch, which Stage 3 leaves ``False``.
    """

    denials: list[str] = []
    if not isinstance(config, PilotGateConfig):
        return False, ("pilot configuration untrusted",)
    if config.pilot_enabled is not True:
        return False, ("pilot gate closed by default",)
    if HTTP_PROBE_PILOT_ENABLED is not False:
        return False, ("master pilot switch tampered",)

    if not isinstance(authorization, IssuedExecutionAuthorization):
        denials.append("issued_authorization_live: untyped authorization")
    else:
        if authorization.lifecycle not in ("ISSUED", "CONSUMED"):
            denials.append("issued_authorization_live: authorization not live")
        if authorization.execution_class != "http_probe":
            denials.append(
                "issued_authorization_live: execution class not http_probe"
            )
        try:
            from ai.execution import nuclei_executor as _nx

            from ai.execution import browser_executor as _bx

            if _nx.LIVE_NUCLEI is not False or _bx.LIVE_BROWSER is not False:
                denials.append(
                    "issued_authorization_live: nuclei/browser gates open"
                )
        except Exception:
            denials.append("issued_authorization_live: gate unreadable")

    if not isinstance(resolution, TargetResolution):
        denials.append("resolved_target: untyped resolution")
    else:
        if resolution.status != "RESOLVED":
            denials.append("resolved_target: target not resolved")
        if not resolution.resolved_addresses or not getattr(
            resolution, "dns_source", ""
        ):
            denials.append("b1_address_review: address review absent")
        if isinstance(authorization, IssuedExecutionAuthorization):
            if (
                resolution.authorization_id != authorization.authorization_id
                or resolution.program_name != authorization.target.program_name
            ):
                denials.append("resolved_target: resolution binding mismatch")

    if not isinstance(evaluation, ScopeEvaluation):
        denials.append("scope_allowed: untyped evaluation")
    else:
        if evaluation.decision != "ALLOWED":
            denials.append("scope_allowed: scope not allowed")
        if not isinstance(now, str) or not now or evaluation.evaluated_at != now:
            denials.append("scope_fresh: evaluation not fresh")
        if isinstance(resolution, TargetResolution):
            if evaluation.resolution_id != resolution.resolution_id:
                denials.append("scope_allowed: evaluation resolution mismatch")

    if not isinstance(policy, EgressPolicy):
        denials.append("egress_policy_valid: egress policy absent")
    else:
        if policy.policy_version != B3_POLICY_VERSION:
            denials.append("egress_policy_valid: policy version skew")
        if isinstance(resolution, TargetResolution) and isinstance(
            evaluation, ScopeEvaluation
        ):
            if (
                policy.resolution_id != resolution.resolution_id
                or policy.evaluation_id != evaluation.evaluation_id
            ):
                denials.append("egress_policy_valid: policy lineage mismatch")
        if isinstance(authorization, IssuedExecutionAuthorization):
            if (
                policy.authorization_id != authorization.authorization_id
                or policy.scope_lists_hash != authorization.target.scope_lists_hash
            ):
                denials.append("egress_policy_valid: policy authorization drift")
        if is_forbidden_destination(policy.approved_address):
            denials.append("destination_permitted: forbidden destination")

    if (
        isinstance(policy, EgressPolicy)
        and isinstance(resolution, TargetResolution)
        and isinstance(evaluation, ScopeEvaluation)
        and isinstance(authorization, IssuedExecutionAuthorization)
    ):
        try:
            assert_dial_matches_egress(
                proof=proof,
                policy=policy,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authorization.authorization_id,
            )
        except Exception:
            denials.append("dial_proof_valid: dial proof rejected")
    else:
        denials.append("dial_proof_valid: bindings absent")

    try:
        check_request_bounds(request=request)
    except Exception:
        denials.append("request_bounded: request rejected")

    if ledger_admitted is not True:
        denials.append("ledger_admitted: execution not admitted")
    if not isinstance(sandbox, SandboxSpec):
        denials.append("resource_limits_applied: sandbox absent")
    else:
        if (
            sandbox.mode not in SANDBOX_MODES
            or sandbox.egress_policy_hash
            != (
                egress_policy_hash(policy)
                if isinstance(policy, EgressPolicy)
                else ""
            )
        ):
            denials.append("resource_limits_applied: sandbox incoherent")
    if evidence_path_ready is not True:
        denials.append("evidence_path_ready: evidence path not ready")
    if verifier_path_ready is not True:
        denials.append("verifier_path_ready: verifier path not ready")

    if isinstance(authorization, IssuedExecutionAuthorization) and isinstance(
        resolution, TargetResolution
    ):
        if (
            resolution.scope_lists_hash_current
            != authorization.target.scope_lists_hash
        ):
            denials.append("authorization_fresh: authorization stale")
        if bool(getattr(resolution, "scope_drift", False)):
            denials.append("no_scope_drift: scope drift detected")
        try:
            check_authorization_freshness(
                authorization=authorization, now=now
            )
        except Exception:
            denials.append("authorization_fresh: authorization not fresh")
    else:
        denials.append("authorization_fresh: bindings absent")

    if denials:
        return False, tuple(denials)
    return True, ()


def check_pilot_gate(**kwargs: Any) -> None:
    """Enforce the pilot gate (fail closed; never dials)."""

    allowed, denials = evaluate_pilot_gate(**kwargs)  # type: ignore[arg-type]
    if not allowed:
        first = denials[0] if denials else "pilot gate closed"
        raise B3BoundaryError("PILOT_GATE_CLOSED", first[:200])
    return None


def assert_nuclei_browser_blocked() -> None:
    """Prove Nuclei/browser live execution stays blocked (Stage 3)."""

    from ai.execution import browser_executor as _bx
    from ai.execution import nuclei_executor as _nx

    if _nx.LIVE_NUCLEI is not False:
        raise B3BoundaryError("FORBIDDEN_EXECUTION_CLASS", "nuclei gate open")
    if _bx.LIVE_BROWSER is not False:
        raise B3BoundaryError("FORBIDDEN_EXECUTION_CLASS", "browser gate open")
    return None
