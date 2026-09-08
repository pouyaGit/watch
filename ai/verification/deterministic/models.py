"""5I typed input boundary + closed vocabularies (Phase 5I).

The classifier accepts ONLY a ``VerifierInput``:

    VerifierInput {
        handoff: EvidenceHandoff
        envelope: bytes
        verifier_version
        rule_version
        policy_version
    }

Strict validation (``extra="forbid"``) means no verdict, finding,
severity, vulnerable, confirmed, confidence, LLM text, executor
object, browser object, network object, or subprocess object can
enter the classifier as authority — any such field fails validation
instead of being ignored.

Nothing in this module performs I/O of any kind.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.evidence.handoff import EvidenceHandoff
from ai.evidence.store import canonical_envelope_bytes, parse_envelope
from ai.schemas import evidence as ev
from ai.schemas.execution_authorization import (
    IssuedExecutionAuthorization,
)

# ------------------------------------------------------------------
# Pinned versions (the ONLY versions this build implements)
# ------------------------------------------------------------------

VERIFIER_VERSION = "deterministic-verifier/5I-v1"
RULES_VERSION = "5i-rules/v1"
POLICY_VERSION = "5i-severity-policy/v1"
OBSERVATION_SCHEMA_VERSION = "evidence/v1"
ARTIFACT_SCHEMA_VERSION = "artifact/v1"

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")

# ------------------------------------------------------------------
# Forbidden authority fields (structural, defence in depth)
# ------------------------------------------------------------------

#: Field names that must NEVER exist on any 5I input or result model.
#: ``extra="forbid"`` rejects them at construction; this set is the
#: review-time double lock (mirrors ``FORBIDDEN_EVIDENCE_FIELDS``).
FORBIDDEN_AUTHORITY_FIELDS = frozenset(
    {
        "verdict",
        "finding",
        "matched",
        "vulnerable",
        "confirmed",
        "not_vulnerable",
        "severity",
        "exploited",
        "confidence",
        "expected_behavior",
        "llm_prose",
        "browser",
        "executor",
        "network",
        "subprocess",
        "executed_script",
        "correlation_token_in_runtime",
    }
)

# ------------------------------------------------------------------
# Gate rejection reasons (closed, deterministic, first-failure-wins)
# ------------------------------------------------------------------

RejectReason = Literal[
    "HANDOFF_SCHEMA_UNSUPPORTED",
    "HANDOFF_MALFORMED",
    "ENVELOPE_MALFORMED",
    "SEAL_HASH_ABSENT",
    "TRIPLE_HASH_MISMATCH",
    "INDEX_CLAIM_MISMATCH",
    "INDEX_KEY_MISMATCH",
    "LIFECYCLE_NOT_SEALED",
    "LIFECYCLE_FORBIDDEN_STATE",
    "INCOMPLETE_EVIDENCE",
    "OBSERVATION_CHANNEL_MISSING",
    "PROGRAM_BINDING_MISMATCH",
    "PROVENANCE_MISSING",
    "PROVENANCE_INVALID",
    "TARGET_BINDING_MISMATCH",
    "ARTIFACT_BINDING_MISMATCH",
    "EXECUTION_IDENTITY_MISMATCH",
    "STAGE_PAIRING_INVALID",
    "SCHEMA_VERSION_UNSUPPORTED",
    "OBSERVATION_CLASS_UNSUPPORTED",
    "VERIFIER_VERSION_UNKNOWN",
    "RULE_VERSION_UNKNOWN",
    "POLICY_VERSION_UNKNOWN",
    "VERIFIER_INPUT_MALFORMED",
]

_REJECT_REASONS = frozenset(RejectReason.__args__)  # type: ignore[attr-defined]

# Event names for the append-only verifier audit contract.
VerifierAuditEventName = Literal[
    "HANDOFF_ACCEPTED",
    "HANDOFF_REJECTED",
    "INTEGRITY_REJECTED",
    "CLASSIFICATION_COMPLETED",
    "CLASSIFICATION_BLOCKED_UNKNOWN",
]

_INTEGRITY_REASONS = frozenset(
    {
        "TRIPLE_HASH_MISMATCH",
        "INDEX_CLAIM_MISMATCH",
        "INDEX_KEY_MISMATCH",
    }
)

# ------------------------------------------------------------------
# Closed classification outcomes (single source: result.py)
# ------------------------------------------------------------------

from ai.verification.deterministic.result import (  # noqa: E402
    OUTCOME_CONFIRMED,
    OUTCOME_NOT_VULNERABLE,
    OUTCOME_POTENTIAL,
    OUTCOME_UNKNOWN,
)


class VerifierInvariantError(RuntimeError):
    """Raised when code targets a state the architecture forbids.

    The canonical case: emitting ``NOT_VULNERABLE`` without the
    future two-control negative-evidence schema. This is an
    implementation invariant violation, never a security result.
    """


class IncompleteEvidence(Exception):
    """A stored-round SUBMIT leg reference could not be resolved.

    Raised (not returned) because the primary record is intact; the
    classifier turns this into ``UNKNOWN`` — missing a referenced leg
    is never negative evidence.
    """


# ------------------------------------------------------------------
# Typed verifier input boundary
# ------------------------------------------------------------------


class VerifierInput(BaseModel):
    """The ONLY classifier input shape (strict, authority-free).

    ``handoff`` must be a genuine ``EvidenceHandoff`` (references +
    hashes, provenance-bound). ``envelope`` must be the exact sealed
    envelope bytes obtained by a verified read. Versions must be the
    pinned strings this build implements — anything else fails closed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    handoff: EvidenceHandoff
    envelope: bytes
    verifier_version: str
    rule_version: str
    policy_version: str

    @field_validator("envelope")
    @classmethod
    def _envelope(cls, value: bytes) -> bytes:
        if not isinstance(value, (bytes, bytearray)) or not value:
            raise ValueError("envelope must be non-empty bytes")
        return bytes(value)

    @field_validator("verifier_version", "rule_version", "policy_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not isinstance(value, str) or not _VERSION_RE.match(value):
            raise ValueError(f"invalid version: {value!r}")
        return value

    def model_post_init(self, __context: object) -> None:
        # Defence in depth: a handoff bound for a different build, an
        # unknown rule generation, or an unknown policy generation is
        # a downgrade attempt — rejected before any gate runs.
        for name, expected in (
            ("verifier_version", VERIFIER_VERSION),
            ("rule_version", RULES_VERSION),
            ("policy_version", POLICY_VERSION),
        ):
            if getattr(self, name) != expected:
                raise ValueError(
                    f"pinned {name} not implemented by this build"
                )


# ------------------------------------------------------------------
# Verifier audit events (append-only, hashes + codes, no secrets)
# ------------------------------------------------------------------

_SECRET_MARKERS = (
    "mongodb://",
    "postgres://",
    "mysql://",
    "redis://",
    "amqp://",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "secret",
    "bearer ",
    "basic ",
    "-----begin",
    "private_key",
)


class VerifierAuditEvent(BaseModel):
    """Append-only verifier audit record (5I vocabulary).

    Same discipline as the frozen 5H ``AuditRecord``: hashes +
    decisions + codes only, bounded single-line, secret-screened,
    ``extra="forbid"``. Never carries payloads, bodies, stdout,
    browser text, or LLM text. The verifier audit sink is an injected
    appendable; audit failure never mutates evidence (the verifier
    holds no evidence-write capability at all).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event: VerifierAuditEventName
    evidence_id: str
    execution_id: str
    authorization_id: str
    program_name: str = ""
    host: str = ""
    reason_code: str = ""
    result_hash: str | None = None
    outcome: str | None = None
    verifier_version: str = VERIFIER_VERSION
    actor: Literal["deterministic-verifier/5I"] = (
        "deterministic-verifier/5I"
    )

    @field_validator("evidence_id")
    @classmethod
    def _evidence_id(cls, value: str) -> str:
        if not ev._EVIDENCE_ID_RE.match(value or ""):
            raise ValueError(f"invalid evidence_id: {value!r}")
        return value

    @field_validator("execution_id")
    @classmethod
    def _execution_id(cls, value: str) -> str:
        if not ev._EXECUTION_ID_RE.match(value or ""):
            raise ValueError(f"invalid execution_id: {value!r}")
        return value

    @field_validator("authorization_id")
    @classmethod
    def _authz_id(cls, value: str) -> str:
        if not ev._AUTHZ_ID_RE.match(value or ""):
            raise ValueError(f"invalid authorization_id: {value!r}")
        return value

    @field_validator("reason_code", "outcome", "program_name", "host")
    @classmethod
    def _bounded_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) > 120:
            raise ValueError("verifier audit field exceeds 120 chars")
        if "\n" in value or "\r" in value:
            raise ValueError("verifier audit fields must be single-line")
        lowered = value.casefold()
        for marker in _SECRET_MARKERS:
            if marker in lowered:
                raise ValueError(
                    "verifier audit field carries suspected secret material"
                )
        return value

    @field_validator("result_hash")
    @classmethod
    def _hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not ev._SHA256_RE.match(value):
            raise ValueError(f"invalid result_hash: {value!r}")
        return value


def emit_audit(sink: object, event: VerifierAuditEvent) -> None:
    """Append one event to an injected audit sink (never mutates evidence).

    Audit is accounting only: a failure here is swallowed (the caller
    may record an audit gap); it can never alter classification or
    evidence bytes.
    """
    if sink is None:
        return
    append = getattr(sink, "append", None)
    if not callable(append) and isinstance(sink, list):
        raise TypeError("audit sink is not appendable")
    if not callable(append):
        raise TypeError("audit sink is not appendable")
    try:
        append(event)
    except Exception:
        # Audit failure must not mutate evidence or classification.
        return


def audit_event_for_rejection(
    *,
    reason: str,
    record: ev.EvidenceRecord,
) -> VerifierAuditEvent:
    """Map a gate rejection to its audit event (closed mapping)."""
    if reason in _INTEGRITY_REASONS:
        name: VerifierAuditEventName = "INTEGRITY_REJECTED"
    else:
        name = "HANDOFF_REJECTED"
    return VerifierAuditEvent(
        event=name,
        evidence_id=record.evidence_id,
        execution_id=record.execution_id,
        authorization_id=record.authorization_id,
        program_name=record.program_name,
        host=record.target.host,
        reason_code=reason,
    )


__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "FORBIDDEN_AUTHORITY_FIELDS",
    "IncompleteEvidence",
    "OBSERVATION_SCHEMA_VERSION",
    "OUTCOME_CONFIRMED",
    "OUTCOME_NOT_VULNERABLE",
    "OUTCOME_POTENTIAL",
    "OUTCOME_UNKNOWN",
    "POLICY_VERSION",
    "RejectReason",
    "RULES_VERSION",
    "VERIFIER_VERSION",
    "VerifierAuditEvent",
    "VerifierAuditEventName",
    "VerifierInput",
    "VerifierInvariantError",
    "audit_event_for_rejection",
    "canonical_envelope_bytes",
    "emit_audit",
    "parse_envelope",
    "IssuedExecutionAuthorization",
]
