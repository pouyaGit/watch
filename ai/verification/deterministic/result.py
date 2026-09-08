"""Immutable classification result (Phase 5I).

The result is frozen, carries exactly the deterministic replay
fields (no arbitrary extras), and is hashed with the SAME canonical
hashing discipline as 5H (``ai.evidence.hashing.hash_payload``).
Same input + same versions => byte-identical result and hash.

``NOT_VULNERABLE`` is DECLARED (architecture state machine) but
UNREACHABLE: the ``_target`` constructor raises
``VerifierInvariantError`` unless the future two-control
negative-evidence schema is pinned (it is not), and no rule can
produce it. "No evidence" can never become "NOT_VULNERABLE".
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.evidence.hashing import hash_payload

OUTCOME_CONFIRMED = "CONFIRMED"
OUTCOME_POTENTIAL = "POTENTIAL"
OUTCOME_UNKNOWN = "UNKNOWN"
OUTCOME_NOT_VULNERABLE = "NOT_VULNERABLE"

CONFIRMED = OUTCOME_CONFIRMED
POTENTIAL = OUTCOME_POTENTIAL
UNKNOWN = OUTCOME_UNKNOWN
NOT_VULNERABLE = OUTCOME_NOT_VULNERABLE

Outcome = Literal[
    "CONFIRMED",
    "POTENTIAL",
    "UNKNOWN",
    "NOT_VULNERABLE",
]

#: The classification states that may carry a finding (policy: the
#: finding-eligible set; UNKNOWN and gate blocks never materialize).
FINDING_ELIGIBLE_OUTCOMES = frozenset(
    {OUTCOME_CONFIRMED, OUTCOME_POTENTIAL}
)

OutcomeDetail = Literal[
    "oracle_execution_proof",
    "stored_round_execution_proof",
    "meaningful_http_reflection",
    "sink_reached_advisory",
    "storage_attributed",
    "nuclei_advisory_weak",
    "insufficient_evidence",
    "gate_blocked",
    "negative_schema_absent",
]

ConfirmationState = Literal[
    "REFLECTION",
    "SINK_REACHED",
    "JAVASCRIPT_EXECUTION",
    "OBSERVABLE_EFFECT",
    "STORAGE_ATTRIBUTED",
]

RESULT_SCHEMA_VERSION = "classification-result/v1"


class ClassificationResult(BaseModel):
    """Immutable deterministic classification (one per gate pass)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result_schema_version: Literal["classification-result/v1"] = (
        RESULT_SCHEMA_VERSION
    )
    evidence_id: str
    execution_id: str
    authorization_id: str
    program_name: str
    target_host: str
    target_scheme: str
    target_effective_port: int
    target_path_scope: str
    artifact_id: str
    artifact_content_hash: str
    test_plan_id: str
    hypothesis_id: str | None = None
    match_id: str | None = None
    evidence_bindings_hash: str
    evidence_observations_hash: str
    evidence_content_hash: str
    verifier_version: str
    rule_id: str
    observation_schema_version: str
    artifact_schema_version: str
    policy_version: str
    outcome: Outcome
    outcome_detail: OutcomeDetail
    severity: Literal[
        "UNSET", "critical", "high", "medium", "low", "info"
    ] = "UNSET"
    severity_unset_reason: str | None = None
    finding_eligible: bool = False
    confirmation_state: ConfirmationState | None = None
    oracle_channels: tuple[str, ...] = ()
    reason_code: str

    @field_validator("oracle_channels")
    @classmethod
    def _channels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"E1", "E2", "E3"}
        for item in value:
            if item not in allowed:
                raise ValueError(f"unknown oracle channel: {item!r}")
        return tuple(sorted(value))

    @field_validator("severity_unset_reason")
    @classmethod
    def _unset_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) > 120:
            raise ValueError("severity_unset_reason over 120 chars")
        if "\n" in value or "\r" in value:
            raise ValueError("severity_unset_reason must be single-line")
        return value


def result_payload(result: ClassificationResult) -> dict:
    """Fixed canonical payload for result hashing (no extras)."""
    return {
        "artifact_content_hash": result.artifact_content_hash,
        "artifact_id": result.artifact_id,
        "artifact_schema_version": result.artifact_schema_version,
        "authorization_id": result.authorization_id,
        "confirmation_state": result.confirmation_state,
        "evidence_bindings_hash": result.evidence_bindings_hash,
        "evidence_content_hash": result.evidence_content_hash,
        "evidence_id": result.evidence_id,
        "evidence_observations_hash": result.evidence_observations_hash,
        "execution_id": result.execution_id,
        "finding_eligible": result.finding_eligible,
        "hypothesis_id": result.hypothesis_id,
        "match_id": result.match_id,
        "observation_schema_version": result.observation_schema_version,
        "oracle_channels": list(result.oracle_channels),
        "outcome": result.outcome,
        "outcome_detail": result.outcome_detail,
        "policy_version": result.policy_version,
        "program_name": result.program_name,
        "reason_code": result.reason_code,
        "result_schema_version": result.result_schema_version,
        "rule_id": result.rule_id,
        "severity": result.severity,
        "severity_unset_reason": result.severity_unset_reason,
        "target_effective_port": result.target_effective_port,
        "target_host": result.target_host,
        "target_path_scope": result.target_path_scope,
        "target_scheme": result.target_scheme,
        "test_plan_id": result.test_plan_id,
        "verifier_version": result.verifier_version,
    }


def compute_result_hash(result: ClassificationResult) -> str:
    """Deterministic result hash (5H canonical hashing discipline)."""
    return hash_payload(result_payload(result))


def deterministic_finding_id(
    *,
    result_hash: str,
    evidence_bindings_hash: str,
    evidence_observations_hash: str,
    evidence_content_hash: str,
    verifier_version: str,
    rule_id: str,
    policy_version: str,
) -> str:
    """Deterministic finding identity (xf- discipline, version-pinned)."""
    from ai.evidence.hashing import sha256_hex

    basis = "\x00".join(
        (
            result_hash,
            evidence_bindings_hash,
            evidence_observations_hash,
            evidence_content_hash,
            verifier_version,
            rule_id,
            policy_version,
        )
    )
    return "xf-" + sha256_hex(basis.encode("utf-8"))[:32]


__all__ = [
    "CONFIRMED",
    "FINDING_ELIGIBLE_OUTCOMES",
    "NOT_VULNERABLE",
    "OUTCOME_CONFIRMED",
    "OUTCOME_NOT_VULNERABLE",
    "OUTCOME_POTENTIAL",
    "OUTCOME_UNKNOWN",
    "POTENTIAL",
    "RESULT_SCHEMA_VERSION",
    "UNKNOWN",
    "ClassificationResult",
    "compute_result_hash",
    "deterministic_finding_id",
    "result_payload",
]
