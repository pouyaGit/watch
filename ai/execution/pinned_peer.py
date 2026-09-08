"""Pinned-peer transport proof for Nuclei live egress (Phase 5K-live B6-D).

The critical invariant: the authorized hostname MUST NOT resolve again
independently at socket-connect time. The actual connection is bound to
the previously authorized IP.

This module is the minimum reviewed transport adapter enforcing that
invariant for the *reviewed transport* (raw socket + TLS). It reuses
— never duplicates — the existing reviewed abstractions:

- ``LiveSocketFactory`` (IP-literal-only dial, no ``getaddrinfo``,
  no implicit DNS, no proxy) from ``ai.execution.live_transport``.
- ``LiveTlsWrapper`` (system CA store, ``CERT_REQUIRED``,
  ``check_hostname``, SNI = canonical hostname, never an IP).
- ``verify_socket_peer`` (``getpeername()`` equality vs the selected
  authorized IP).
- ``build_egress_policy`` / ``check_egress_dial`` (exact-match dial
  authorization) from ``ai.execution.b3_boundary``.
- ``assemble_dial_proof`` / ``assert_dial_matches_egress`` (dial-proof
  binding) from ``ai.execution.dial_proof`` / ``b3_boundary``.

Flow (every step fail-closed, socket closed on every path):

1. ``check_egress_dial`` authorizes exactly one
   ``(approved_address, effective_port, scheme)`` SYN.
2. ``factory.connect(selected_address, port, timeout)`` dials the IP
   literal. A hostname can never reach the wire here:
   ``require_ip_literal`` rejects it before any socket exists, so a
   re-resolution bypass is unrepresentable (there is no resolver call
   anywhere in this module — no ``socket``, ``getaddrinfo``, DNS, or
   proxy input exists on this path).
3. ``verify_socket_peer`` proves the kernel peer is the selected IP.
4. For ``https``: ``tls_wrapper.wrap(sock, sni_host=canonical_host)``
   preserves the canonical hostname for SNI and verifies the peer
   certificate against it (``check_hostname=True``); the negotiated
   version and peer-cert hash enter the proof. For ``http``: no TLS
   is performed and the proof records the plaintext marker (the SNI
   that *would* be presented is still pinned to the canonical host).
5. ``assemble_dial_proof`` + ``assert_dial_matches_egress`` bind the
   proven peer to the egress policy, resolution, evaluation, and
   authorization lineage.

Factory admission: only genuine ``LiveSocketFactory`` /
``LiveTlsWrapper`` instances (``isinstance`` — subclasses overriding
``connect``/``wrap`` for offline tests are admitted; foreign
duck-typed impostors are not). The adapters carry the reviewed
``LIVE_TRANSPORT_VERSION`` identity; anything else is refused before
any socket exists.

ARCHITECTURAL LIMITS (reported, not hidden):

1. This adapter proves the peer for connections *it* makes. The
   Nuclei child process invoked with ``-u <hostname>`` performs its
   own independent resolution through its internal resolver at dial
   time and offers no file-descriptor-passing / dial-hook interface
   in the pinned release (v3.11.1 ``-h`` shows resolver selection
   only via ``-r``/``-sr``, SNI defaulting to the input domain). The
   child therefore cannot be forced through this socket. Subprocess
   containment additionally requires the network-namespace egress
   allowlist (``(approved_address, effective_port, tcp)`` only),
   which B6-F leaves gated (``SANDBOX_UNAVAILABLE``).
2. ``build_egress_policy`` admits only the ``http_probe`` execution
   class (``FORBIDDEN_EXECUTION_CLASS`` otherwise), so no
   ``EgressPolicy`` — and therefore no peer proof — can exist for
   ``nuclei_scan`` lineage until B3 admits the class under its own
   review. This module refuses to work around that gate.
Live egress stays DISABLED.
"""

from __future__ import annotations

from typing import Any

from ai.execution.b3_boundary import (
    assert_dial_matches_egress,
    check_egress_dial,
)
from ai.execution.dial_proof import DialProof, assemble_dial_proof
from ai.execution.live_transport import (
    LiveSocketFactory,
    LiveTlsWrapper,
    LiveTransportError,
    close_quietly,
    peer_cert_hash_of,
    tls_version_of,
    verify_socket_peer,
)

__all__ = [
    "PINNED_PEER_VERSION",
    "PLAINTEXT_TLS_MARKER",
    "PEER_ERROR_CODES",
    "PinnedPeerError",
    "prove_pinned_peer",
]

#: Adapter identity (bound into audit alongside the dial proof).
PINNED_PEER_VERSION = "b6-pinned-peer/v1"

#: Plaintext marker recorded when no TLS is performed (http only).
PLAINTEXT_TLS_MARKER = "plaintext-none"

#: Closed failure vocabulary for pinned-peer proof.
PEER_ERROR_CODES = frozenset(
    {
        "PEER_PROOF_FAILED",
        "PEER_MISMATCH",
        "FOREIGN_TRANSPORT_ADAPTER",
    }
)


class PinnedPeerError(ValueError):
    """Bounded, secret-free pinned-peer failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in PEER_ERROR_CODES:
            raise ValueError(f"unknown pinned peer code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("pinned peer detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


def _require_live_factory(factory: object) -> LiveSocketFactory:
    if not isinstance(factory, LiveSocketFactory):
        raise PinnedPeerError(
            "FOREIGN_TRANSPORT_ADAPTER", "socket factory not reviewed"
        )
    return factory


def _require_live_tls_wrapper(wrapper: object) -> LiveTlsWrapper:
    if not isinstance(wrapper, LiveTlsWrapper):
        raise PinnedPeerError(
            "FOREIGN_TRANSPORT_ADAPTER", "tls wrapper not reviewed"
        )
    return wrapper


def prove_pinned_peer(
    *,
    policy: object,
    resolution: object,
    evaluation: object,
    authorization_id: str,
    socket_factory: object,
    tls_wrapper: object,
    timeout_seconds: float = 10.0,
) -> DialProof:
    """Dial the policy-approved IP and prove the peer (fail closed).

    ``policy`` is the genuine ``EgressPolicy`` (single approved
    ``(address, port, scheme)`` triple); ``resolution``/``evaluation``
    are the genuine 5C/5D records the policy was built from. The
    dial target is ``policy.approved_address`` ONLY — the canonical
    hostname is used for SNI/Host identity and never for routing.
    Returns the verified ``DialProof``; raises ``PinnedPeerError``
    (peer mismatch, proof failure) or the underlying closed errors
    on any deviation. The socket is closed on every path.
    """

    factory = _require_live_factory(socket_factory)
    wrapper = _require_live_tls_wrapper(tls_wrapper)
    if not isinstance(authorization_id, str) or not authorization_id:
        raise PinnedPeerError("PEER_PROOF_FAILED", "authorization id absent")
    scheme = getattr(policy, "scheme", None)
    approved_address = getattr(policy, "approved_address", None)
    effective_port = getattr(policy, "effective_port", None)
    canonical_host = getattr(policy, "canonical_host", None)
    if scheme not in ("http", "https"):
        raise PinnedPeerError("PEER_PROOF_FAILED", "policy scheme rejected")
    if not isinstance(canonical_host, str) or not canonical_host:
        raise PinnedPeerError("PEER_PROOF_FAILED", "policy host absent")
    # Exact-match dial authorization FIRST: no approved policy triple,
    # no SYN. kwargs are typed inside check_egress_dial (fail closed).
    try:
        checked = check_egress_dial(
            policy=policy,
            dial_ip=approved_address,
            dial_port=effective_port,
            dial_scheme=scheme,
            authorization_id=authorization_id,
            resolution_id=getattr(policy, "resolution_id", None),
        )
    except Exception as exc:
        raise PinnedPeerError(
            "PEER_PROOF_FAILED", "dial not in egress policy"
        ) from exc
    _ = checked
    try:
        sock = factory.connect(
            approved_address, effective_port, timeout_seconds
        )
    except Exception as exc:
        raise PinnedPeerError(
            "PEER_PROOF_FAILED", "pinned dial failed"
        ) from exc
    try:
        # Kernel-level peer proof: the connected peer MUST be the
        # selected authorized IP (a hostname can never arrive here —
        # require_ip_literal inside connect/verify rejects it).
        try:
            peer_ip = verify_socket_peer(sock, approved_address)
        except Exception as exc:
            raise PinnedPeerError(
                "PEER_MISMATCH", "socket peer outside pin"
            ) from exc
        try:
            local_sockaddr = str(sock.getsockname())
        except Exception as exc:
            raise PinnedPeerError(
                "PEER_PROOF_FAILED", "local sockaddr unavailable"
            ) from exc
        if not local_sockaddr:
            raise PinnedPeerError(
                "PEER_PROOF_FAILED", "local sockaddr unavailable"
            )
        connection_id = factory.connection_id_for(sock)
        if not isinstance(connection_id, str) or not connection_id:
            raise PinnedPeerError(
                "PEER_PROOF_FAILED", "connection identity absent"
            )
        if scheme == "https":
            try:
                tls_sock = wrapper.wrap(
                    sock, sni_host=canonical_host, timeout=timeout_seconds
                )
            except Exception as exc:
                raise PinnedPeerError(
                    "PEER_PROOF_FAILED", "tls bind failed"
                ) from exc
            # Re-prove the peer AFTER the TLS handshake: the handshake
            # must not have migrated the connection elsewhere.
            try:
                peer_after = verify_socket_peer(tls_sock, approved_address)
            except Exception as exc:
                close_quietly(tls_sock)
                raise PinnedPeerError(
                    "PEER_MISMATCH", "post-tls peer outside pin"
                ) from exc
            if peer_after != peer_ip:
                close_quietly(tls_sock)
                raise PinnedPeerError(
                    "PEER_MISMATCH", "post-tls peer outside pin"
                )
            try:
                tls_version = tls_version_of(tls_sock)
                cert_hash = peer_cert_hash_of(tls_sock)
            except Exception as exc:
                close_quietly(tls_sock)
                raise PinnedPeerError(
                    "PEER_PROOF_FAILED", "tls proof unavailable"
                ) from exc
            close_quietly(tls_sock)
            tls_peer_cert_hash: str | None = cert_hash
        else:
            tls_version = PLAINTEXT_TLS_MARKER
            tls_peer_cert_hash = None
        dns_source = getattr(resolution, "dns_source", "")
        if not isinstance(dns_source, str) or not dns_source:
            raise PinnedPeerError(
                "PEER_PROOF_FAILED", "resolution provenance absent"
            )
        dial_addresses = tuple(getattr(resolution, "resolved_addresses", ()))
        try:
            proof = assemble_dial_proof(
                actual_peer_ip=peer_ip,
                local_sockaddr=local_sockaddr,
                selected_address=approved_address,
                resolved_addresses=tuple(
                    getattr(resolution, "resolved_addresses", ())
                ),
                resolver_name=dns_source,
                resolver_version=dns_source,
                dial_addresses=dial_addresses,
                dial_port=effective_port,
                dial_sni=canonical_host,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authorization_id,
                tls_sni=canonical_host,
                tls_version_negotiated=tls_version,
                tls_peer_cert_hash=tls_peer_cert_hash,
                redirect_hop_index=0,
                connection_id=connection_id,
            )
        except Exception as exc:
            raise PinnedPeerError(
                "PEER_PROOF_FAILED", "dial proof rejected"
            ) from exc
        try:
            return assert_dial_matches_egress(
                proof=proof,
                policy=policy,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authorization_id,
            )
        except Exception as exc:
            raise PinnedPeerError(
                "PEER_MISMATCH", "proven peer outside egress"
            ) from exc
    finally:
        close_quietly(sock)
