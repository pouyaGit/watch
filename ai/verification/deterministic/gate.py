"""5I integrity/provenance gate (Phase 5I, exact architecture order).

Gate order is FROZEN (architecture §4 / phase order — first failure
wins, fail-closed, no reinterpretation):

 1. structural handoff validation
 2. EvidenceStore verified read / equivalent injected verified-read seam
 3. triple-hash verification
 4. index binding verification
 5. SEALED lifecycle check
 6. complete observation requirement
 7. program binding
 8. authorization provenance
 9. target binding
10. artifact binding
11. execution identity / stage pairing
12. observation schema/version
13. forbidden lifecycle checks

Every gate failure carries a deterministic closed reason. Failure is
NEVER reinterpreted as a negative security result: it is a blocked /
rejected state (HANDOFF_REJECTED / INTEGRITY_REJECTED audit events),
never CONFIRMED/POTENTIAL, and never NOT_VULNERABLE.

Provenance vs permission: gate 8 consumes the 5B issuance record as
PROVENANCE only (``AUTHZ_VALID_FOR_PROVENANCE``; CONSUMED is the
expected post-execution state). The verifier never asks an
authorization to be live-for-execution and never enables any
execution path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai.evidence.builder import REQUIRED_OBSERVATIONS, verify_record
from ai.evidence.handoff import (
    AUTHZ_VALID_FOR_PROVENANCE,
    EvidenceHandoff,
    verify_provenance_for_handoff,
)
from ai.evidence.store import canonical_envelope_bytes, parse_envelope
from ai.schemas import evidence as ev
from ai.schemas.execution_authorization import (
    IssuedExecutionAuthorization,
)

from ai.verification.deterministic.models import (
    ARTIFACT_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    OUTCOME_UNKNOWN,
    RejectReason,
    VerifierAuditEvent,
    VerifierInput,
    audit_event_for_rejection,
    emit_audit,
)

VERIFIED = "VERIFIED"

_EVIDENCE_ID_RE = ev._EVIDENCE_ID_RE
_EXECUTION_ID_RE = ev._EXECUTION_ID_RE
_AUTHZ_ID_RE = ev._AUTHZ_ID_RE
_ART_ID_RE = ev._ART_ID_RE
_TP_ID_RE = ev._TP_ID_RE
_SHA256_RE = ev._SHA256_RE

#: Execution classes this verifier build understands (gate 12).
SUPPORTED_EXECUTION_CLASSES = frozenset(
    {"http_probe", "http_verification", "nuclei_scan", "browser_verification"}
)

#: Lifecycle states that are never consumable by the verifier.
FORBIDDEN_LIFECYCLE_STATES = frozenset({"BUILDING", "INCOMPLETE"})


@dataclass(frozen=True)
class GateOutcome:
    """Deterministic gate result (sealed context or closed rejection)."""

    status: str
    reason: RejectReason | None = None
    record: ev.EvidenceRecord | None = None
    handoff: EvidenceHandoff | None = None
    authorization: IssuedExecutionAuthorization | None = None
    index_claims: Any = None

    @property
    def accepted(self) -> bool:
        return self.status == VERIFIED

    @property
    def blocked(self) -> bool:
        return not self.accepted


def _reject(
    reason: RejectReason, *, record: ev.EvidenceRecord | None = None
) -> GateOutcome:
    return GateOutcome(status="REJECTED", reason=reason, record=record)


def _reject_with_audit(
    reason: RejectReason, *, record: ev.EvidenceRecord | None, audit: object
) -> GateOutcome:
    outcome = _reject(reason, record=record)
    if record is not None:
        emit_audit(audit, audit_event_for_rejection(reason=reason, record=record))
    return outcome


def _handoff_structurally_valid(handoff: EvidenceHandoff) -> RejectReason | None:
    """Gate 1: schema version, ID formats, seal hashes, provenance pin."""
    if getattr(handoff, "handoff_schema_version", None) != (
        "evidence-handoff/v1"
    ):
        return "HANDOFF_SCHEMA_UNSUPPORTED"
    checks = (
        ("evidence_id", _EVIDENCE_ID_RE),
        ("execution_id", _EXECUTION_ID_RE),
        ("authorization_id", _AUTHZ_ID_RE),
        ("artifact_id", _ART_ID_RE),
        ("test_plan_id", _TP_ID_RE),
    )
    for name, pattern in checks:
        value = getattr(handoff, name, None)
        if not isinstance(value, str) or not pattern.match(value):
            return "HANDOFF_MALFORMED"
    for name in ("bindings_hash", "observations_hash", "content_hash"):
        value = getattr(handoff, name, None)
        if not isinstance(value, str) or not _SHA256_RE.match(value):
            return "HANDOFF_MALFORMED"
    provenance = getattr(handoff, "provenance", None)
    if provenance is None:
        return "HANDOFF_MALFORMED"
    if not provenance.issuance_nonce:
        return "HANDOFF_MALFORMED"
    if provenance.authorization_id != handoff.authorization_id:
        return "HANDOFF_MALFORMED"
    if not isinstance(handoff.target_host, str) or not handoff.target_host:
        return "HANDOFF_MALFORMED"
    return None


def _record_binding_checks(
    record: ev.EvidenceRecord, handoff: EvidenceHandoff
) -> RejectReason | None:
    """Shared binding comparisons (gates 7, 9, 11 identity half)."""
    if (
        record.program_name != handoff.program_name
        or record.target.program_name != handoff.program_name
    ):
        return "PROGRAM_BINDING_MISMATCH"
    if (
        record.target.host != handoff.target_host
        or record.target.scheme != handoff.target_scheme
        or record.target.effective_port != handoff.target_effective_port
        or record.target.path_scope != handoff.target_path_scope
    ):
        return "TARGET_BINDING_MISMATCH"
    if (
        record.artifact_id != handoff.artifact_id
        or record.artifact_content_hash != handoff.artifact_content_hash
    ):
        return "ARTIFACT_BINDING_MISMATCH"
    if record.evidence_id != handoff.evidence_id:
        return "EXECUTION_IDENTITY_MISMATCH"
    if record.execution_id != handoff.execution_id:
        return "EXECUTION_IDENTITY_MISMATCH"
    return None


def _artifact_class_consistency(record: ev.EvidenceRecord) -> RejectReason | None:
    """Gate 10 second half: derivation/template binding vs class."""
    if record.execution_class in ("http_probe", "http_verification"):
        return None
    if record.execution_class == "nuclei_scan":
        template = record.template_binding
        if (
            template is None
            or not template.template_id
            or not template.template_hash
        ):
            return "ARTIFACT_BINDING_MISMATCH"
        return None
    # browser_verification: derivation contract required for oracle/stored.
    derivation = record.derivation_binding
    if record.execution_stage == "oracle" and (
        derivation is None or not derivation.contract_hash
    ):
        return "ARTIFACT_BINDING_MISMATCH"
    if derivation is not None and derivation.execution_phase is not None:
        if derivation.execution_phase not in (
            "oracle",
            "stored_submit",
            "stored_read",
        ):
            return "ARTIFACT_BINDING_MISMATCH"
    return None


def _stage_pairing_valid(record: ev.EvidenceRecord) -> RejectReason | None:
    """Gate 11 second half: stage pairing (stored READ needs SUBMIT leg)."""
    stage = record.execution_stage
    cls = record.execution_class
    if stage == "submit" and cls not in (
        "http_verification",
        "browser_verification",
    ):
        return "STAGE_PAIRING_INVALID"
    if stage == "read":
        if cls != "browser_verification":
            return "STAGE_PAIRING_INVALID"
        browser = record.browser
        if browser is None or not browser.round_id:
            return "STAGE_PAIRING_INVALID"
        if not browser.submit_evidence_ref:
            return "STAGE_PAIRING_INVALID"
    if stage == "oracle" and cls != "browser_verification":
        return "STAGE_PAIRING_INVALID"
    return None


def verify_handoff_evidence(
    verifier_input: VerifierInput,
    seam: Any,
    *,
    audit: object = None,
) -> GateOutcome:
    """Run the 13-gate integrity/provenance order (first failure wins).

    ``seam`` is the injected verified read (never trusted blindly:
    everything it returns is re-verified from the handed envelope
    bytes). ``audit`` is an optional append-only sink for verifier
    audit events; audit failure never mutates evidence.
    """
    # -- Gate 1: structural handoff validation --------------------------
    handoff = verifier_input.handoff
    if not isinstance(handoff, EvidenceHandoff):
        return _reject("HANDOFF_MALFORMED")
    reason = _handoff_structurally_valid(handoff)
    if reason is not None:
        return _reject(reason)

    # -- Gate 2: verified read via injected seam ------------------------
    if not (
        callable(getattr(seam, "read_verified", None))
        and callable(getattr(seam, "read_authorization", None))
    ):
        return _reject("HANDOFF_MALFORMED")
    try:
        verified = seam.read_verified(handoff.evidence_id)
        store_record = verified.record
        claims = verified.index
        parsed = parse_envelope(verifier_input.envelope)
    except ev.EvidenceError as exc:
        code = getattr(exc, "code", "")
        if "tombstoned" in str(exc) or "quarantined" in str(exc):
            return _reject("LIFECYCLE_FORBIDDEN_STATE")
        if code == "EVIDENCE_HASH_MISMATCH":
            return _reject("TRIPLE_HASH_MISMATCH")
        return _reject("ENVELOPE_MALFORMED")
    except Exception:
        return _reject("ENVELOPE_MALFORMED")

    if not isinstance(parsed, ev.EvidenceRecord) or not isinstance(
        store_record, ev.EvidenceRecord
    ):
        return _reject("ENVELOPE_MALFORMED")

    # -- Gate 3: triple-hash verification --------------------------------
    try:
        verify_record(parsed)
    except ev.EvidenceError:
        return _reject("TRIPLE_HASH_MISMATCH")
    if (
        parsed.bindings_hash is None
        or parsed.observations_hash is None
        or parsed.content_hash is None
    ):
        return _reject("SEAL_HASH_ABSENT")
    if (
        parsed.bindings_hash != handoff.bindings_hash
        or parsed.observations_hash != handoff.observations_hash
        or parsed.content_hash != handoff.content_hash
    ):
        return _reject("TRIPLE_HASH_MISMATCH")
    if canonical_envelope_bytes(parsed) != bytes(verifier_input.envelope):
        return _reject("TRIPLE_HASH_MISMATCH")
    if canonical_envelope_bytes(store_record) != bytes(verifier_input.envelope):
        return _reject("TRIPLE_HASH_MISMATCH")

    # -- Gate 4: index binding verification ------------------------------
    if claims is not None:
        if (
            claims.content_hash != parsed.content_hash
            or claims.bindings_hash != parsed.bindings_hash
            or claims.observations_hash != parsed.observations_hash
        ):
            return _reject_with_audit(
                "INDEX_CLAIM_MISMATCH", record=parsed, audit=audit
            )
        if (
            claims.evidence_id != parsed.evidence_id
            or claims.execution_id != parsed.execution_id
            or claims.authorization_id != parsed.authorization_id
        ):
            return _reject_with_audit(
                "INDEX_KEY_MISMATCH", record=parsed, audit=audit
            )

    # -- Gate 5: SEALED lifecycle check -----------------------------------
    if parsed.lifecycle != "SEALED":
        if parsed.lifecycle == "INCOMPLETE":
            return _reject_with_audit(
                "INCOMPLETE_EVIDENCE", record=parsed, audit=audit
            )
        return _reject_with_audit(
            "LIFECYCLE_NOT_SEALED", record=parsed, audit=audit
        )
    if not parsed.complete:
        return _reject_with_audit(
            "INCOMPLETE_EVIDENCE", record=parsed, audit=audit
        )

    # -- Gate 6: complete observation requirement ------------------------
    required = REQUIRED_OBSERVATIONS.get(parsed.execution_class, ())
    for channel in required:
        if getattr(parsed, channel, None) is None:
            return _reject_with_audit(
                "OBSERVATION_CHANNEL_MISSING", record=parsed, audit=audit
            )

    # -- Gates 7 / 9 / 11(identity): program, target, execution ids ------
    reason = _record_binding_checks(parsed, handoff)
    if reason is not None:
        return _reject_with_audit(reason, record=parsed, audit=audit)

    # -- Gate 8: authorization provenance (PROVENANCE, never permission) --
    try:
        authorization = seam.read_authorization(parsed.authorization_id)
    except Exception:
        authorization = None
    if authorization is None:
        return _reject_with_audit(
            "PROVENANCE_MISSING", record=parsed, audit=audit
        )
    if not isinstance(authorization, IssuedExecutionAuthorization):
        return _reject_with_audit(
            "PROVENANCE_INVALID", record=parsed, audit=audit
        )
    try:
        marker = verify_provenance_for_handoff(
            handoff,
            authorization,
            execution_started_at=parsed.started_at or handoff.sealed_at,
        )
    except ev.EvidenceError:
        return _reject_with_audit(
            "PROVENANCE_INVALID", record=parsed, audit=audit
        )
    except TypeError:
        return _reject_with_audit(
            "PROVENANCE_INVALID", record=parsed, audit=audit
        )
    if marker != AUTHZ_VALID_FOR_PROVENANCE:
        return _reject_with_audit(
            "PROVENANCE_INVALID", record=parsed, audit=audit
        )

    # -- Gate 10: artifact binding (consistency with execution class) -----
    reason = _artifact_class_consistency(parsed)
    if reason is not None:
        return _reject_with_audit(reason, record=parsed, audit=audit)
    if parsed.template_binding is not None and parsed.execution_class in (
        "http_probe",
        "http_verification",
        "browser_verification",
    ):
        # Template hashes must not ride on non-nuclei evidence.
        if handoff.template_hash not in (None, parsed.template_binding.template_hash):
            return _reject_with_audit(
                "ARTIFACT_BINDING_MISMATCH", record=parsed, audit=audit
            )

    # -- Gate 11: stage pairing -------------------------------------------
    reason = _stage_pairing_valid(parsed)
    if reason is not None:
        return _reject_with_audit(reason, record=parsed, audit=audit)

    # -- Gate 12: observation schema/version ------------------------------
    if parsed.evidence_schema_version != OBSERVATION_SCHEMA_VERSION:
        return _reject_with_audit(
            "SCHEMA_VERSION_UNSUPPORTED", record=parsed, audit=audit
        )
    if parsed.execution_class not in SUPPORTED_EXECUTION_CLASSES:
        return _reject_with_audit(
            "OBSERVATION_CLASS_UNSUPPORTED", record=parsed, audit=audit
        )

    # -- Gate 13: forbidden lifecycle checks ------------------------------
    if parsed.lifecycle in FORBIDDEN_LIFECYCLE_STATES:
        return _reject_with_audit(
            "LIFECYCLE_FORBIDDEN_STATE", record=parsed, audit=audit
        )
    if claims is not None and (claims.tombstoned or claims.quarantined):
        return _reject_with_audit(
            "LIFECYCLE_FORBIDDEN_STATE", record=parsed, audit=audit
        )
    if parsed.incomplete_reasons:
        return _reject_with_audit(
            "LIFECYCLE_FORBIDDEN_STATE", record=parsed, audit=audit
        )

    outcome = GateOutcome(
        status=VERIFIED,
        record=parsed,
        handoff=handoff,
        authorization=authorization,
        index_claims=claims,
    )
    emit_audit(
        audit,
        VerifierAuditEvent(
            event="HANDOFF_ACCEPTED",
            evidence_id=parsed.evidence_id,
            execution_id=parsed.execution_id,
            authorization_id=parsed.authorization_id,
            program_name=parsed.program_name,
            host=parsed.target.host,
            reason_code="GATES_PASSED",
        ),
    )
    return outcome


__all__ = [
    "VERIFIED",
    "FORBIDDEN_LIFECYCLE_STATES",
    "GateOutcome",
    "SUPPORTED_EXECUTION_CLASSES",
    "verify_handoff_evidence",
    "OUTCOME_UNKNOWN",
]
