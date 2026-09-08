"""Actual-dial proof model (Phase B1).

Pure deterministic helpers establishing, for every live hop::

    actual_peer_ip == selected_address
    selected_address ∈ pinned resolved_addresses
    DialBinding matches TargetResolution
    DialBinding matches ScopeEvaluation
    authorization_id matches execution lineage
    resolution_id matches evidence
    evaluation_id matches evidence

The proof is typed data (:class:`DialProof`), never logs. Missing
proof maps to ``MISSING_PROOF``; any mismatch fails closed
(``DIAL_MISMATCH`` / ``PROOF_BINDING_MISMATCH``).

5H integration (narrow seam, no 5H change): :func:`assert_proof_for_seal`
verifies the per-hop proofs BEFORE the caller seals; :func:`seal_with_dial_proof`
takes the caller's seal callable, asserts first, seals second, and
returns ``(sealed_record, proof_digest)``. The existing observation
schema is NOT extended in v1 (``HttpObservation`` keeps
``extra="forbid"``): the proof digest is returned for audit
metadata, while the proof's ``resolution_id`` / ``evaluation_id`` /
``dialed_ip`` triple is already carried inside the frozen sealed
bindings (``dial_ips`` + binding ids), so any dial-fact change forks
evidence identity through the frozen hash discipline. No second
evidence store is created; nothing here classifies or finds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from ai.evidence import hashing as hash_mod

__all__ = [
    "DIAL_PROOF_VERSION",
    "DIAL_PROOF_ERROR_CODES",
    "DialProofError",
    "DialProof",
    "hash_pin_list",
    "hash_dial_binding",
    "assemble_dial_proof",
    "verify_dial_proof",
    "assert_proof_for_seal",
    "seal_with_dial_proof",
    "proof_digest_for",
]

#: Proof shape version (bumped additively if fields are ever added).
DIAL_PROOF_VERSION = "b1-dial-proof/v1"

#: Closed proof-failure vocabulary.
DIAL_PROOF_ERROR_CODES = frozenset(
    {
        "MISSING_PROOF",
        "DIAL_MISMATCH",
        "PROOF_BINDING_MISMATCH",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONN_ID_RE = re.compile(r"^conn-[0-9a-f]{32}$")


class DialProofError(ValueError):
    """Bounded, secret-free dial-proof failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in DIAL_PROOF_ERROR_CODES:
            raise ValueError(f"unknown dial proof code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("dial proof detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


@dataclass(frozen=True)
class DialProof:
    """Immutable per-hop actual-dial proof (all fields required)."""

    actual_peer_ip: str
    local_sockaddr: str
    selected_address: str
    pin_list_hash: str
    resolver_name: str
    resolver_version: str
    dial_binding_hash: str
    target_resolution_hash: str
    scope_evaluation_hash: str
    tls_sni: str
    tls_version_negotiated: str
    tls_peer_cert_hash: str
    redirect_hop_index: int
    connection_id: str
    proof_version: str = DIAL_PROOF_VERSION


def hash_pin_list(resolved_addresses: tuple[str, ...] | list[str]) -> str:
    """Hash of the ordered pinned ``resolved_addresses`` actually used."""

    if not isinstance(resolved_addresses, (list, tuple)) or not resolved_addresses:
        raise DialProofError("MISSING_PROOF", "pin list absent")
    for item in resolved_addresses:
        if not isinstance(item, str) or not item:
            raise DialProofError("MISSING_PROOF", "pin entry absent")
    return hash_mod.hash_payload({"pinned_addresses": list(resolved_addresses)})


def hash_dial_binding(
    *,
    addresses: tuple[str, ...] | list[str],
    effective_port: int,
    sni_host: str,
) -> str:
    """Hash of the ``DialBinding`` triple consumed at SYN time."""

    if not addresses or not isinstance(effective_port, int) or not sni_host:
        raise DialProofError("MISSING_PROOF", "dial binding absent")
    return hash_mod.hash_payload(
        {
            "addresses": list(addresses),
            "effective_port": effective_port,
            "sni_host": sni_host,
        }
    )


def _require_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value or ""):
        raise DialProofError("MISSING_PROOF", f"{field} absent")
    return value


def assemble_dial_proof(
    *,
    actual_peer_ip: str,
    local_sockaddr: str,
    selected_address: str,
    resolved_addresses: tuple[str, ...] | list[str],
    resolver_name: str,
    resolver_version: str,
    dial_addresses: tuple[str, ...] | list[str],
    dial_port: int,
    dial_sni: str,
    resolution: Any,
    evaluation: Any,
    authorization_id: str,
    tls_sni: str,
    tls_version_negotiated: str,
    tls_peer_cert_hash: str | None = None,
    redirect_hop_index: int = 0,
    connection_id: str = "",
) -> DialProof:
    """Assemble and coherence-check one hop's proof (fail closed).

    ``resolution``/``evaluation`` are genuine ``TargetResolution`` /
    ``ScopeEvaluation`` records (type-checked by module + class name
    so dicts/LLM output can never pose as bindings). Every equality
    below is checked; the first mismatch raises.
    """

    for label, value in (
        ("actual peer ip", actual_peer_ip),
        ("local sockaddr", local_sockaddr),
        ("selected address", selected_address),
        ("resolver name", resolver_name),
        ("resolver version", resolver_version),
        ("tls sni", tls_sni),
        ("tls version", tls_version_negotiated),
        ("connection id", connection_id),
    ):
        if not isinstance(value, str) or not value:
            raise DialProofError("MISSING_PROOF", f"{label} absent")
    if type(resolution).__name__ != "TargetResolution" or not hasattr(
        resolution, "resolution_id"
    ):
        raise DialProofError("MISSING_PROOF", "resolution binding absent")
    if type(evaluation).__name__ != "ScopeEvaluation" or not hasattr(
        evaluation, "evaluation_id"
    ):
        raise DialProofError("MISSING_PROOF", "evaluation binding absent")
    if not isinstance(redirect_hop_index, int) or redirect_hop_index < 0:
        raise DialProofError("MISSING_PROOF", "hop index absent")
    if not _CONN_ID_RE.match(connection_id or ""):
        raise DialProofError("MISSING_PROOF", "connection id malformed")
    if actual_peer_ip != selected_address:
        raise DialProofError("DIAL_MISMATCH", "peer differs from selected")
    if selected_address not in tuple(resolved_addresses):
        raise DialProofError("DIAL_MISMATCH", "selected not in pin list")
    dial = getattr(resolution, "dial", None)
    if dial is None:
        raise DialProofError("MISSING_PROOF", "dial binding absent")
    if (
        tuple(getattr(dial, "addresses", ())) != tuple(dial_addresses)
        or tuple(getattr(dial, "addresses", ())) != tuple(resolved_addresses)
        or getattr(dial, "effective_port", None) != dial_port
        or getattr(dial, "sni_host", None) != dial_sni
    ):
        raise DialProofError("DIAL_MISMATCH", "dial binding incoherent")
    if getattr(resolution, "canonical_host", None) != dial_sni:
        raise DialProofError("PROOF_BINDING_MISMATCH", "binding host mismatch")
    if tls_sni != getattr(resolution, "canonical_host", None):
        raise DialProofError("DIAL_MISMATCH", "tls sni mismatch")
    if getattr(resolution, "authorization_id", None) != authorization_id:
        raise DialProofError("PROOF_BINDING_MISMATCH", "authorization mismatch")
    if getattr(evaluation, "authorization_id", None) != authorization_id:
        raise DialProofError("PROOF_BINDING_MISMATCH", "authorization mismatch")
    if getattr(evaluation, "resolution_id", None) != getattr(
        resolution, "resolution_id", None
    ):
        raise DialProofError("PROOF_BINDING_MISMATCH", "resolution mismatch")
    _require_hash(getattr(resolution, "canonical_target_hash", None), "target hash")
    scheme = getattr(resolution, "scheme", "https")
    if scheme == "http" and tls_peer_cert_hash is not None:
        raise DialProofError("PROOF_BINDING_MISMATCH", "tls proof on plaintext")
    if scheme == "https" and tls_peer_cert_hash is None:
        raise DialProofError("MISSING_PROOF", "peer cert hash absent")
    return DialProof(
        actual_peer_ip=actual_peer_ip,
        local_sockaddr=local_sockaddr,
        selected_address=selected_address,
        pin_list_hash=hash_pin_list(tuple(resolved_addresses)),
        resolver_name=resolver_name,
        resolver_version=resolver_version,
        dial_binding_hash=hash_dial_binding(
            addresses=tuple(dial_addresses),
            effective_port=dial_port,
            sni_host=dial_sni,
        ),
        target_resolution_hash=_require_hash(
            getattr(resolution, "resolution_id", None) and hash_mod.hash_payload(
                {
                    "canonical_target_hash": resolution.canonical_target_hash,
                    "resolution_id": resolution.resolution_id,
                }
            ),
            "target hash",
        ),
        scope_evaluation_hash=_require_hash(
            getattr(evaluation, "evaluation_id", None) and hash_mod.hash_payload(
                {"evaluation_id": evaluation.evaluation_id}
            ),
            "evaluation hash",
        ),
        tls_sni=tls_sni,
        tls_version_negotiated=tls_version_negotiated,
        tls_peer_cert_hash=tls_peer_cert_hash or "",
        redirect_hop_index=redirect_hop_index,
        connection_id=connection_id,
    )


def verify_dial_proof(
    proof: object,
    *,
    resolution: Any,
    evaluation: Any,
    authorization_id: str,
) -> DialProof:
    """Re-verify a proof against live bindings (seal-time assertion).

    Recomputes every hash and re-checks every equality. ``None`` /
    wrong-typed / tampered proofs raise ``MISSING_PROOF`` /
    ``DIAL_MISMATCH`` / ``PROOF_BINDING_MISMATCH`` — never seal.
    """

    if not isinstance(proof, DialProof):
        raise DialProofError("MISSING_PROOF", "proof absent or untyped")
    if proof.proof_version != DIAL_PROOF_VERSION:
        raise DialProofError("MISSING_PROOF", "proof version skew")
    for field in (
        "actual_peer_ip",
        "local_sockaddr",
        "selected_address",
        "resolver_name",
        "resolver_version",
        "tls_sni",
        "tls_version_negotiated",
        "connection_id",
    ):
        if not isinstance(getattr(proof, field, None), str) or not getattr(proof, field):
            raise DialProofError("MISSING_PROOF", f"{field} absent")
    _require_hash(proof.pin_list_hash, "pin hash")
    _require_hash(proof.dial_binding_hash, "dial hash")
    _require_hash(proof.target_resolution_hash, "target hash")
    _require_hash(proof.scope_evaluation_hash, "evaluation hash")
    if type(resolution).__name__ != "TargetResolution" or type(
        evaluation
    ).__name__ != "ScopeEvaluation":
        raise DialProofError("MISSING_PROOF", "bindings absent")
    if proof.actual_peer_ip != proof.selected_address:
        raise DialProofError("DIAL_MISMATCH", "peer differs from selected")
    expected_pins = tuple(getattr(resolution, "resolved_addresses", ()))
    if hash_pin_list(expected_pins) != proof.pin_list_hash:
        raise DialProofError("DIAL_MISMATCH", "pin list changed")
    if proof.selected_address not in expected_pins:
        raise DialProofError("DIAL_MISMATCH", "selected not in pin list")
    dial = getattr(resolution, "dial", None)
    if dial is None:
        raise DialProofError("MISSING_PROOF", "dial binding absent")
    if hash_dial_binding(
        addresses=tuple(dial.addresses),
        effective_port=dial.effective_port,
        sni_host=dial.sni_host,
    ) != proof.dial_binding_hash:
        raise DialProofError("DIAL_MISMATCH", "dial binding changed")
    if proof.tls_sni != getattr(resolution, "canonical_host", None):
        raise DialProofError("DIAL_MISMATCH", "tls sni mismatch")
    if getattr(resolution, "scheme", "https") == "https":
        _require_hash(proof.tls_peer_cert_hash, "peer cert hash")
    elif proof.tls_peer_cert_hash:
        raise DialProofError("PROOF_BINDING_MISMATCH", "tls proof on plaintext")
    if getattr(resolution, "authorization_id", None) != authorization_id:
        raise DialProofError("PROOF_BINDING_MISMATCH", "authorization mismatch")
    if getattr(evaluation, "authorization_id", None) != authorization_id:
        raise DialProofError("PROOF_BINDING_MISMATCH", "authorization mismatch")
    if getattr(evaluation, "resolution_id", None) != getattr(
        resolution, "resolution_id", None
    ):
        raise DialProofError("PROOF_BINDING_MISMATCH", "resolution mismatch")
    if getattr(evaluation, "execution_id", None) != getattr(
        resolution, "execution_id", None
    ):
        raise DialProofError("PROOF_BINDING_MISMATCH", "execution mismatch")
    return proof


def proof_digest_for(proofs: tuple[DialProof, ...] | list[DialProof]) -> str:
    """Deterministic digest over one execution's per-hop proofs."""

    if not isinstance(proofs, (list, tuple)) or not proofs:
        raise DialProofError("MISSING_PROOF", "proof chain absent")
    for item in proofs:
        if not isinstance(item, DialProof):
            raise DialProofError("MISSING_PROOF", "proof chain untyped")
    return hash_mod.hash_payload(
        {
            "proof_version": DIAL_PROOF_VERSION,
            "proofs": [
                {
                    "actual_peer_ip": item.actual_peer_ip,
                    "connection_id": item.connection_id,
                    "dial_binding_hash": item.dial_binding_hash,
                    "pin_list_hash": item.pin_list_hash,
                    "redirect_hop_index": item.redirect_hop_index,
                    "resolver_name": item.resolver_name,
                    "resolver_version": item.resolver_version,
                    "scope_evaluation_hash": item.scope_evaluation_hash,
                    "target_resolution_hash": item.target_resolution_hash,
                    "tls_peer_cert_hash": item.tls_peer_cert_hash,
                    "tls_sni": item.tls_sni,
                    "tls_version_negotiated": item.tls_version_negotiated,
                }
                for item in proofs
            ],
        }
    )


def assert_proof_for_seal(
    *,
    proofs: tuple[DialProof, ...] | list[DialProof],
    resolutions: tuple[Any, ...] | list[Any],
    evaluations: tuple[Any, ...] | list[Any],
    authorization_id: str,
) -> str:
    """Seal-time assertion: every hop proven, else ``MISSING_PROOF``.

    Returns the proof digest for audit metadata. Never seals itself —
    the caller seals through the frozen 5H path only after this
    returns.
    """

    if (
        not isinstance(proofs, (list, tuple))
        or not isinstance(resolutions, (list, tuple))
        or not isinstance(evaluations, (list, tuple))
    ):
        raise DialProofError("MISSING_PROOF", "seal inputs untyped")
    if not proofs or len(proofs) != len(resolutions) or len(proofs) != len(evaluations):
        raise DialProofError("MISSING_PROOF", "seal chain length mismatch")
    seen_hops: set[int] = set()
    seen_conns: set[str] = set()
    for proof, resolution, evaluation in zip(proofs, resolutions, evaluations):
        verified = verify_dial_proof(
            proof,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authorization_id,
        )
        if verified.redirect_hop_index in seen_hops:
            raise DialProofError("DIAL_MISMATCH", "hop index reused")
        seen_hops.add(verified.redirect_hop_index)
        if verified.connection_id in seen_conns:
            # One fresh socket per hop: connection ids must be unique
            # across the chain (no pooling, no reuse).
            raise DialProofError("DIAL_MISMATCH", "connection reused")
        seen_conns.add(verified.connection_id)
    if seen_hops != set(range(len(proofs))):
        raise DialProofError("MISSING_PROOF", "hop coverage gap")
    return proof_digest_for(tuple(proofs))


def seal_with_dial_proof(
    *,
    proofs: tuple[DialProof, ...] | list[DialProof],
    resolutions: tuple[Any, ...] | list[Any],
    evaluations: tuple[Any, ...] | list[Any],
    authorization_id: str,
    seal: Callable[[], Any],
) -> tuple[Any, str]:
    """Narrow 5H seam: assert proof, then seal via the frozen path.

    ``seal`` is the caller's zero-argument seal callable (e.g. the
    5H ``EvidenceBuilder.seal``/``seal_partial`` invocation). It is
    NEVER invoked when the proof assertion fails: missing or
    inconsistent proof means no sealed record. Returns
    ``(sealed_record, proof_digest)``.
    """

    if not callable(seal):
        raise DialProofError("MISSING_PROOF", "seal callable absent")
    digest = assert_proof_for_seal(
        proofs=proofs,
        resolutions=resolutions,
        evaluations=evaluations,
        authorization_id=authorization_id,
    )
    return seal(), digest
