"""Immutable sealed finding contract (Phase 5J, ``sealed-finding/v1``).

Security record ONLY: every field is either hashed into finding
identity or derived from it. There are NO timestamps, NO caller
metadata, NO raw content fields anywhere on this model — audit
envelope data (``materialized_at``, backend, event refs) lives in the
store entry and audit events, never here.

Content discipline: hashes, IDs, version pins, and closed-vocabulary
summaries (channels, states). No secrets, auth headers, cookies,
bearer tokens, raw oracle S/D values, OOB material, unrestricted
bodies, console/DOM text, Nuclei stdout/stderr, LLM text, or raw
payloads have a field to inhabit (``extra="forbid"`` rejects them at
construction).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.evidence import hashing
from ai.schemas import evidence as ev

__all__ = [
    "FINDING_SCHEMA_VERSION",
    "SealedFinding",
    "finding_identity_payload",
    "finding_id_for",
    "canonical_finding_bytes",
]

#: Sealed finding schema version (the ONLY version this build emits).
FINDING_SCHEMA_VERSION = "sealed-finding/v1"

_EVIDENCE_ID_RE = ev._EVIDENCE_ID_RE
_EXECUTION_ID_RE = ev._EXECUTION_ID_RE
_AUTHZ_ID_RE = ev._AUTHZ_ID_RE
_ART_ID_RE = ev._ART_ID_RE
_TP_ID_RE = ev._TP_ID_RE
_SHA256_RE = ev._SHA256_RE
_ROUND_ID_RE = ev._ROUND_ID_RE


class SealedFinding(BaseModel):
    """Immutable deterministic finding (one per classification)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_schema_version: Literal["sealed-finding/v1"] = (
        FINDING_SCHEMA_VERSION
    )
    finding_id: str
    classification_result_hash: str
    evidence_id: str
    execution_id: str
    authorization_id: str
    program_name: str
    canonical_host: str
    scheme: Literal["http", "https"] = "https"
    effective_port: int = 443
    path_scope: str = ""
    target_resolution_identity: str | None = None
    scope_evaluation_identity: str
    artifact_id: str
    artifact_content_hash: str
    evidence_content_hash: str
    evidence_bindings_hash: str
    evidence_observations_hash: str
    verifier_version: str
    rule_id: str
    observation_schema_version: str
    artifact_schema_version: str
    policy_version: str
    eligibility_policy_version: str
    classification: Literal["CONFIRMED"] = "CONFIRMED"
    confirmation_state: (
        Literal[
            "REFLECTION",
            "SINK_REACHED",
            "JAVASCRIPT_EXECUTION",
            "OBSERVABLE_EFFECT",
            "STORAGE_ATTRIBUTED",
        ]
        | None
    ) = None
    oracle_channels: tuple[str, ...] = ()
    severity: Literal[
        "UNSET", "critical", "high", "medium", "low", "info"
    ] = "UNSET"
    severity_unset_reason: str | None = None
    severity_policy_version: str
    executed_payload_hash: str | None = None
    derivation_contract_hash: str | None = None
    round_id: str | None = None
    submit_evidence_ref: str | None = None
    submit_content_hash: str | None = None
    reason_code: str

    @field_validator("finding_id")
    @classmethod
    def _finding_id(cls, value: str) -> str:
        import re as _re

        if not _re.match(r"^xf-[0-9a-f]{32}$", value or ""):
            raise ValueError(f"invalid finding_id: {value!r}")
        return value

    @field_validator("oracle_channels")
    @classmethod
    def _channels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"E1", "E2", "E3"}
        for item in value:
            if item not in allowed:
                raise ValueError(f"unknown oracle channel: {item!r}")
        return tuple(sorted(value))

    @field_validator("evidence_id")
    @classmethod
    def _evidence_id(cls, value: str) -> str:
        if not _EVIDENCE_ID_RE.match(value or ""):
            raise ValueError(f"invalid evidence_id: {value!r}")
        return value

    @field_validator("execution_id")
    @classmethod
    def _execution_id(cls, value: str) -> str:
        if not _EXECUTION_ID_RE.match(value or ""):
            raise ValueError(f"invalid execution_id: {value!r}")
        return value

    @field_validator("authorization_id")
    @classmethod
    def _authz_id(cls, value: str) -> str:
        if not _AUTHZ_ID_RE.match(value or ""):
            raise ValueError(f"invalid authorization_id: {value!r}")
        return value

    @field_validator("artifact_id")
    @classmethod
    def _artifact_id(cls, value: str) -> str:
        if not _ART_ID_RE.match(value or ""):
            raise ValueError(f"invalid artifact_id: {value!r}")
        return value

    @field_validator(
        "classification_result_hash",
        "artifact_content_hash",
        "evidence_content_hash",
        "evidence_bindings_hash",
        "evidence_observations_hash",
        "scope_evaluation_identity",
    )
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid hash field: {value!r}")
        return value

    @field_validator(
        "target_resolution_identity",
        "executed_payload_hash",
        "derivation_contract_hash",
        "submit_evidence_ref",
        "submit_content_hash",
    )
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid hash field: {value!r}")
        return value

    @field_validator("round_id")
    @classmethod
    def _round_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ROUND_ID_RE.match(value):
            raise ValueError(f"invalid round_id: {value!r}")
        return value

    @field_validator("effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("effective_port must be an integer")
        if not 1 <= value <= 65535:
            raise ValueError("effective_port out of range")
        return value

    @field_validator("reason_code", "severity_unset_reason")
    @classmethod
    def _bounded_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or len(value) > 120:
            raise ValueError("reason field must be 1..120 chars")
        if "\n" in value or "\r" in value:
            raise ValueError("reason fields must be single-line")
        return value

    @field_validator("program_name", "canonical_host")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if "\n" in value or "\r" in value:
            raise ValueError("must not contain newlines")
        return value


def finding_identity_payload(
    *,
    classification_result_hash: str,
    evidence_bindings_hash: str,
    evidence_observations_hash: str,
    evidence_content_hash: str,
    verifier_version: str,
    rule_id: str,
    policy_version: str,
    eligibility_policy_version: str,
) -> dict:
    """Fixed canonical payload for finding identity (no extras).

    Timestamps and audit-envelope leaves MUST NEVER enter this
    payload: identity is security material only.
    """
    return {
        "classification_result_hash": classification_result_hash,
        "eligibility_policy_version": eligibility_policy_version,
        "evidence_bindings_hash": evidence_bindings_hash,
        "evidence_content_hash": evidence_content_hash,
        "evidence_observations_hash": evidence_observations_hash,
        "policy_version": policy_version,
        "rule_id": rule_id,
        "verifier_version": verifier_version,
    }


def finding_id_for(
    *,
    classification_result_hash: str,
    evidence_bindings_hash: str,
    evidence_observations_hash: str,
    evidence_content_hash: str,
    verifier_version: str,
    rule_id: str,
    policy_version: str,
    eligibility_policy_version: str,
) -> str:
    """Deterministic finding identity (5H canonical hashing discipline).

    Same security inputs → same ``finding_id``. Any change to
    evidence, classification, or any version pin → a distinct id.
    The caller MUST NOT select this value (it is recomputed, never
    accepted).
    """
    payload = finding_identity_payload(
        classification_result_hash=classification_result_hash,
        evidence_bindings_hash=evidence_bindings_hash,
        evidence_observations_hash=evidence_observations_hash,
        evidence_content_hash=evidence_content_hash,
        verifier_version=verifier_version,
        rule_id=rule_id,
        policy_version=policy_version,
        eligibility_policy_version=eligibility_policy_version,
    )
    return "xf-" + hashing.hash_payload(payload)[:32]


def canonical_finding_bytes(finding: SealedFinding) -> bytes:
    """Byte-identical canonical encoding (store compare + replay)."""
    return hashing.canonical_json(
        hashing.normalize_for_hash(finding.model_dump(mode="json"))
    ).encode("utf-8")
