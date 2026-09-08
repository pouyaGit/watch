"""Verifier EvidenceHandoff contract (Phase 5H-core).

One-way, verdict-free handoff: references + hashes only. The handoff
service assembles; the verifier revalidates; results never flow back
into execution.

CRITICAL SEMANTIC DISTINCTION (explicit in code, tests, report):

- ``AUTHZ_LIVE_FOR_EXECUTION``: the authorization is currently
  executable (``ISSUED`` + unexpired). Required BEFORE execution
  starts. Checked by :func:`require_live_for_execution`.
- ``AUTHZ_VALID_FOR_PROVENANCE``: the historically issued record
  exists and matches this execution. Required AT HANDOFF.
  A legitimate ``CONSUMED`` authorization REMAINS valid provenance
  for its own sealed evidence — consumption is the expected
  post-execution state, not invalidation.

``AUTHZ_CONSUMED`` therefore does NOT imply ``HANDOFF_REJECTED``.
Revoked, expired-at-start, forged, or binding-mismatched
provenance DOES imply ``HANDOFF_REJECTED``. Consumed must never be
reinterpreted as permission to execute again (the ledger's replay
guard owns that invariant, not this module).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.evidence import builder as seal
from ai.schemas import evidence as ev

__all__ = [
    "AUTHZ_VALID_FOR_PROVENANCE",
    "HandoffProvenance",
    "EvidenceHandoff",
    "assemble_handoff",
    "bind_provenance",
    "require_live_for_execution",
    "verify_provenance_for_handoff",
]

#: Success marker for provenance verification (not an error code).
AUTHZ_VALID_FOR_PROVENANCE = "AUTHZ_VALID_FOR_PROVENANCE"


class HandoffProvenance(BaseModel):
    """Historical issuance facts pinned at handoff (no liveness claim)."""

    model_config = ConfigDict(extra="forbid")

    authorization_id: str
    issuance_nonce: str
    issued_at: str
    expires_at: str
    lifecycle_at_seal: Literal["ISSUED", "CONSUMED"] = "CONSUMED"


class EvidenceHandoff(BaseModel):
    """Immutable verifier-handoff reference (no verdict, ever)."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    execution_id: str
    authorization_id: str
    execution_stage: str = "single"
    execution_class: str = "http_probe"
    artifact_id: str
    artifact_content_hash: str
    program_name: str
    target_host: str
    target_scheme: str = "https"
    target_effective_port: int = 443
    target_path_scope: str = ""
    test_plan_id: str
    hypothesis_id: str | None = None
    match_id: str | None = None
    scope_lists_hash: str | None = None
    derivation_contract_hash: str | None = None
    executed_payload_hash: str | None = None
    template_hash: str | None = None
    bindings_hash: str
    observations_hash: str
    content_hash: str
    sealed_at: str = ""
    provenance: HandoffProvenance
    handoff_schema_version: Literal["evidence-handoff/v1"] = (
        "evidence-handoff/v1"
    )

    @field_validator("target_effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("target_effective_port must be an integer")
        if not 1 <= value <= 65535:
            raise ValueError("target_effective_port out of range")
        return value


def assemble_handoff(record: ev.EvidenceRecord) -> EvidenceHandoff:
    """Assemble a handoff for sealed + complete + hash-valid evidence.

    Raises ``HANDOFF_REJECTED`` for INCOMPLETE records (never a
    negative or positive finding — handoff refusal is data-state,
    not classification) and ``EVIDENCE_HASH_MISMATCH`` for altered
    content. Performs no authorization check (provenance is verified
    separately by :func:`verify_provenance_for_handoff`).
    """
    if not isinstance(record, ev.EvidenceRecord):
        raise TypeError(
            "assemble_handoff accepts only EvidenceRecord, "
            f"not {type(record).__name__}"
        )
    if record.lifecycle != "SEALED" or not record.complete:
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "only sealed complete evidence may hand off"
        )
    seal.verify_record(record)
    if (
        record.bindings_hash is None
        or record.observations_hash is None
        or record.content_hash is None
    ):
        raise ev.EvidenceError("HANDOFF_REJECTED", "seal hashes absent")
    derivation = record.derivation_binding
    template = record.template_binding
    scope_hash = (
        record.snapshot_binding.scope_lists_hash
        if record.snapshot_binding is not None
        else None
    )
    return EvidenceHandoff(
        evidence_id=record.evidence_id,
        execution_id=record.execution_id,
        authorization_id=record.authorization_id,
        execution_stage=record.execution_stage,
        execution_class=record.execution_class,
        artifact_id=record.artifact_id,
        artifact_content_hash=record.artifact_content_hash,
        program_name=record.program_name,
        target_host=record.target.host,
        target_scheme=record.target.scheme,
        target_effective_port=record.target.effective_port,
        target_path_scope=record.target.path_scope,
        test_plan_id=record.test_plan_id,
        hypothesis_id=record.hypothesis_id,
        match_id=record.match_id,
        scope_lists_hash=scope_hash,
        derivation_contract_hash=(
            derivation.contract_hash if derivation is not None else None
        ),
        executed_payload_hash=(
            derivation.executed_payload_hash
            if derivation is not None
            else None
        ),
        template_hash=template.template_hash if template is not None else None,
        bindings_hash=record.bindings_hash,
        observations_hash=record.observations_hash,
        content_hash=record.content_hash,
        sealed_at=record.sealed_at,
        provenance=HandoffProvenance(
            authorization_id=record.authorization_id,
            issuance_nonce="",
            issued_at="",
            expires_at="",
            lifecycle_at_seal="CONSUMED",
        ),
    )


def bind_provenance(
    handoff: EvidenceHandoff, authorization: object
) -> EvidenceHandoff:
    """Pin historical issuance facts onto an assembled handoff.

    Copies ``issuance_nonce``/``issued_at``/``expires_at`` from the
    genuine issuance record so :func:`verify_provenance_for_handoff`
    can detect forgery. Accepts only genuine issuance records.
    Never consults liveness (provenance, not permission).
    """
    from ai.schemas.execution_authorization import IssuedExecutionAuthorization

    if not isinstance(handoff, EvidenceHandoff):
        raise TypeError(
            "bind_provenance accepts only EvidenceHandoff, "
            f"not {type(handoff).__name__}"
        )
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "bind_provenance accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if authorization.authorization_id != handoff.authorization_id:
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "authorization identity mismatch"
        )
    return handoff.model_copy(
        update={
            "provenance": HandoffProvenance(
                authorization_id=handoff.authorization_id,
                issuance_nonce=authorization.issuance_nonce,
                issued_at=authorization.issued_at,
                expires_at=authorization.expires_at,
                lifecycle_at_seal=(
                    "CONSUMED"
                    if authorization.lifecycle == "CONSUMED"
                    else "ISSUED"
                ),
            )
        }
    )


def _parse_instant(value: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", "malformed instant"
        ) from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


def require_live_for_execution(
    authorization: object, *, now: str
) -> None:
    """Execution-permission gate: authorization must be LIVE now.

    Only ``ISSUED`` + unexpired records pass. ``CONSUMED``,
    ``REVOKED``, and ``EXPIRED`` all raise ``AUTHZ_NOT_LIVE`` — a
    consumed authorization is never permission to execute again.
    Accepts only genuine issuance records (``TypeError`` otherwise).
    """
    from ai.schemas.execution_authorization import IssuedExecutionAuthorization

    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "liveness accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if authorization.lifecycle != "ISSUED":
        raise ev.EvidenceError(
            "AUTHZ_NOT_LIVE", "authorization is not executable"
        )
    if _parse_instant(authorization.expires_at) <= _parse_instant(now):
        raise ev.EvidenceError("AUTHZ_NOT_LIVE", "authorization expired")


def verify_provenance_for_handoff(
    handoff: EvidenceHandoff,
    authorization: object | None,
    *,
    execution_started_at: str,
) -> str:
    """Historical-provenance gate: issuance must match this execution.

    Verifies: record exists (``None`` → ``HANDOFF_REJECTED``);
    identity match; issuance-nonce match (forgery detection);
    lifecycle is ``ISSUED`` or ``CONSUMED`` (``REVOKED``/``EXPIRED``
    → ``HANDOFF_REJECTED``); issuance window covers execution start
    (valid when execution began); all bound axes equal
    (artifact/target/plan/derivation).

    A legitimate ``CONSUMED`` record returns
    ``AUTHZ_VALID_FOR_PROVENANCE``. This grants NO execution
    permission — provenance only.
    """
    from ai.schemas.execution_authorization import IssuedExecutionAuthorization

    if not isinstance(handoff, EvidenceHandoff):
        raise TypeError(
            "provenance accepts only EvidenceHandoff, "
            f"not {type(handoff).__name__}"
        )
    if authorization is None:
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "no issuance record for authorization"
        )
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "provenance accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if authorization.authorization_id != handoff.authorization_id:
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "authorization identity mismatch"
        )
    if not handoff.provenance.issuance_nonce or (
        authorization.issuance_nonce != handoff.provenance.issuance_nonce
    ):
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "issuance provenance mismatch"
        )
    if authorization.lifecycle not in ("ISSUED", "CONSUMED"):
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "authorization revoked or expired"
        )
    started = _parse_instant(execution_started_at)
    if _parse_instant(authorization.issued_at) > started:
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "authorization issued after execution start"
        )
    if _parse_instant(authorization.expires_at) <= started:
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "authorization expired at execution start"
        )
    if (
        authorization.artifact.artifact_id != handoff.artifact_id
        or authorization.artifact.content_hash
        != handoff.artifact_content_hash
    ):
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "artifact binding mismatch"
        )
    target = authorization.target
    if (
        target.program_name != handoff.program_name
        or target.host != handoff.target_host
        or target.scheme != handoff.target_scheme
        or target.effective_port != handoff.target_effective_port
        or target.path_scope != handoff.target_path_scope
    ):
        raise ev.EvidenceError(
            "HANDOFF_REJECTED", "target binding mismatch"
        )
    if (
        authorization.test_plan_id != handoff.test_plan_id
        or (authorization.hypothesis_id or None)
        != (handoff.hypothesis_id or None)
        or (authorization.match_id or None) != (handoff.match_id or None)
    ):
        raise ev.EvidenceError("HANDOFF_REJECTED", "plan binding mismatch")
    return AUTHZ_VALID_FOR_PROVENANCE
