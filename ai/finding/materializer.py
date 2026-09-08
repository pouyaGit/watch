"""5J materialization orchestrator (Phase 5J, offline, deterministic).

Exactly one pipeline (first failure wins, fail closed)::

    ClassificationResult (+ trusted infra bundle)
      -> 5I authority structure gate
      -> 5J eligibility gate (CONFIRMED-only, pinned policy)
      -> FRESH verified read (never the classification-time read)
      -> index-claim + liveness checks
      -> 5I authority binding gate (record equality, registry,
         severity-triple recomputation)
      -> stored-round linkage pinning (stored XSS only)
      -> immutable SealedFinding (severity verbatim, no content)
      -> deterministic finding id
      -> put-if-absent persistence (dedup / corrupt-collision)
      -> workflow record init + single alert claim + audit

This orchestrator NEVER classifies: it performs equality, registry,
and policy-table lookups only. Zero observation inspection beyond
hash/binding comparison. No severity computation (verbatim copy).
No POTENTIAL/UNKNOWN promotion (no code path exists for it).

Dependency-injection rule: ``evidence_reader``, ``finding_store``,
``workflow_store``, ``notification_sink``, and ``alert_ledger`` are
trusted infrastructure, type-checked at the boundary (ABC /
callable-seam checks). A faulty or hostile seam can only force
fail-closed (NO FINDING): every returned byte is re-verified
(triple recomputation, index comparison, full axis equality) and
never trusted for a security decision. The caller supplies ONLY the
``ClassificationResult`` — never infra authority, never bindings,
never severity.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.evidence.builder import verify_record
from ai.schemas import evidence as ev
from ai.verification.deterministic.result import (
    ClassificationResult,
    compute_result_hash,
)
from ai.verification.deterministic.verified_read import VerifiedEvidence

from ai.finding.audit import FindingAuditEvent, emit_finding_audit
from ai.finding.authority import (
    _parse_rule_display,
    verify_authority_binding,
    verify_authority_structure,
)
from ai.finding.eligibility import (
    ELIGIBILITY_POLICY_VERSION,
    check_eligibility,
)
from ai.finding.notify import (
    AlertLedgerMemory,
    FindingAlert,
    NotificationSink,
    alert_id_for,
)
from ai.finding.sealed import (
    SealedFinding,
    canonical_finding_bytes,
    finding_id_for,
)
from ai.finding.store_memory import (
    CORRUPT_COLLISION,
    DEDUPLICATED,
    PERSISTED,
    FindingStore,
    WorkflowStore,
)

__all__ = [
    "MATERIALIZER_VERSION",
    "FindingInfrastructure",
    "MaterializationOutcome",
    "materialize",
    "finding_availability",
]

#: Materializer build version (audit + envelope only, never identity).
MATERIALIZER_VERSION = "finding-pipeline/5J-v1"

_PERSISTED_AVAILABILITY = "PERSISTED"
_UNVERIFIABLE_AVAILABILITY = "PERSISTED_UNVERIFIABLE"
_GONE_AVAILABILITY = "EVIDENCE_GONE"


@dataclass(frozen=True)
class FindingInfrastructure:
    """Trusted infrastructure bundle (typed, never caller authority).

    Constructed by the application (production wiring) or by tests
    (fakes). The untrusted caller to ``materialize`` supplies ONLY
    the classification; these handles are never read from caller
    input — they are function arguments owned by the wiring layer.
    """

    evidence_reader: object
    finding_store: FindingStore
    workflow_store: WorkflowStore
    audit_sink: object
    notification_sink: NotificationSink
    alert_ledger: AlertLedgerMemory


@dataclass(frozen=True)
class MaterializationOutcome:
    """Deterministic materialization outcome (result or refusal)."""

    accepted: bool
    reason: str
    finding: SealedFinding | None = None
    finding_id: str | None = None
    notified: bool = False
    alert_id: str | None = None
    deduplicated: bool = False


def _check_infra(infra: FindingInfrastructure) -> None:
    """Boundary type checks (programming errors fail loudly)."""
    if not isinstance(infra, FindingInfrastructure):
        raise TypeError(
            "materialize requires FindingInfrastructure, "
            f"not {type(infra).__name__}"
        )
    reader = infra.evidence_reader
    if not (
        callable(getattr(reader, "read_verified", None))
        and callable(getattr(reader, "read_by_content_hash", None))
    ):
        raise TypeError(
            "evidence_reader must expose read_verified + "
            f"read_by_content_hash, got {type(reader).__name__}"
        )
    if not isinstance(infra.finding_store, FindingStore):
        raise TypeError(
            "finding_store must be a FindingStore, "
            f"not {type(infra.finding_store).__name__}"
        )
    if not isinstance(infra.workflow_store, WorkflowStore):
        raise TypeError(
            "workflow_store must be a WorkflowStore, "
            f"not {type(infra.workflow_store).__name__}"
        )
    if not isinstance(infra.notification_sink, NotificationSink):
        raise TypeError(
            "notification_sink must be a NotificationSink, "
            f"not {type(infra.notification_sink).__name__}"
        )
    if not isinstance(infra.alert_ledger, AlertLedgerMemory):
        raise TypeError(
            "alert_ledger must be an AlertLedgerMemory, "
            f"not {type(infra.alert_ledger).__name__}"
        )
    sink = infra.audit_sink
    if sink is not None and not (
        callable(getattr(sink, "append", None))
        or isinstance(sink, list)
    ):
        raise TypeError("audit_sink is not appendable")


def _audit_ids(classification: object) -> dict:
    """Best-effort audit identity (never raises, never secrets)."""
    ids = {
        "finding_id": None,
        "classification_hash": None,
        "evidence_id": None,
        "execution_id": None,
        "authorization_id": None,
        "program_name": "",
        "host": "",
    }
    if isinstance(classification, ClassificationResult):
        try:
            ids["classification_hash"] = compute_result_hash(
                classification
            )
        except Exception:
            ids["classification_hash"] = None
        for key in (
            "evidence_id",
            "execution_id",
            "authorization_id",
            "program_name",
        ):
            value = getattr(classification, key, None)
            ids[key] = value if isinstance(value, str) else None
        host = getattr(classification, "target_host", None)
        ids["host"] = host if isinstance(host, str) else ""
        if ids["program_name"] is None:
            ids["program_name"] = ""
    return ids


def _emit(
    infra: FindingInfrastructure,
    *,
    event: str,
    classification: object,
    reason: str,
    finding_id: str | None = None,
    alert_id: str | None = None,
) -> None:
    ids = _audit_ids(classification)
    try:
        emit_finding_audit(
            infra.audit_sink,
            FindingAuditEvent(
                event=event,  # type: ignore[arg-type]
                finding_id=finding_id,
                classification_hash=ids["classification_hash"],
                evidence_id=ids["evidence_id"],
                execution_id=ids["execution_id"],
                authorization_id=ids["authorization_id"],
                program_name=ids["program_name"] or "",
                host=ids["host"] or "",
                reason_code=reason,
                alert_id=alert_id,
            ),
        )
    except Exception:
        return


def _claims_ok(claims: object, record: ev.EvidenceRecord) -> bool:
    """Index-claim equality + liveness (attribute-read, fail closed)."""
    try:
        if claims is None:
            return False
        if (
            getattr(claims, "content_hash", None) != record.content_hash
            or getattr(claims, "bindings_hash", None)
            != record.bindings_hash
            or getattr(claims, "observations_hash", None)
            != record.observations_hash
        ):
            return False
        if (
            getattr(claims, "evidence_id", None) != record.evidence_id
            or getattr(claims, "execution_id", None)
            != record.execution_id
            or getattr(claims, "authorization_id", None)
            != record.authorization_id
        ):
            return False
        if getattr(claims, "tombstoned", False) or getattr(
            claims, "quarantined", False
        ):
            return False
        return getattr(claims, "lifecycle", None) in (
            "SEALED",
            "INDEXED",
        )
    except Exception:
        return False


def _resolve_submit_linkage(
    infra: FindingInfrastructure,
    record: ev.EvidenceRecord,
) -> tuple[str | None, str | None]:
    """Pin stored-round SUBMIT linkage (content hash, verified).

    Returns ``(submit_evidence_ref, submit_content_hash)`` or
    ``(None, None)`` when the linkage cannot be pinned fail-safe.
    The SUBMIT leg is resolved through the sealed ref, re-verified
    from scratch, and leg-consistency checked (stage, program,
    target, artifact, plan) — a READ is NEVER rebound to another
    SUBMIT: the ref is sealed on the READ record itself.
    """
    browser = record.browser
    if browser is None:
        return None, None
    ref = browser.submit_evidence_ref
    if not ref:
        return None, None
    try:
        legs = infra.evidence_reader.read_by_content_hash(ref)  # type: ignore[union-attr]
    except Exception:
        return None, None
    if not isinstance(legs, tuple) or len(legs) != 1:
        return None, None
    submit = legs[0]
    if not isinstance(submit, ev.EvidenceRecord):
        return None, None
    try:
        verify_record(submit)
    except Exception:
        return None, None
    if submit.lifecycle != "SEALED" or not submit.complete:
        return None, None
    if submit.execution_stage != "submit":
        return None, None
    if (
        submit.program_name != record.program_name
        or submit.target.host != record.target.host
        or submit.target.scheme != record.target.scheme
        or submit.target.effective_port != record.target.effective_port
        or submit.target.path_scope != record.target.path_scope
        or submit.artifact_id != record.artifact_id
        or submit.artifact_content_hash != record.artifact_content_hash
        or submit.test_plan_id != record.test_plan_id
    ):
        return None, None
    return ref, submit.content_hash


def materialize(
    classification: object,
    infra: FindingInfrastructure,
    *,
    materialized_at: str = "",
) -> MaterializationOutcome:
    """Run the full 5J pipeline for one 5I classification.

    ``materialized_at`` is audit-envelope metadata ONLY: it is
    validated as a string and never enters finding identity (same
    inputs + different timestamps → identical ``finding_id``).
    Idempotent: the same classification through the same infra
    yields a byte-identical finding; the second persist is a
    deduplicated no-op with no re-notification.
    """
    _check_infra(infra)
    if not isinstance(materialized_at, str) or len(materialized_at) > 120:
        raise TypeError("materialized_at must be a bounded string")

    authority = verify_authority_structure(classification)
    if not authority.authorized:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason=authority.reason,
        )
        return MaterializationOutcome(False, authority.reason)

    assert isinstance(classification, ClassificationResult)
    eligibility = check_eligibility(classification)
    if not eligibility.eligible:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason=eligibility.reason,
        )
        return MaterializationOutcome(False, eligibility.reason)
    _emit(
        infra,
        event="FINDING_ELIGIBILITY_ACCEPTED",
        classification=classification,
        reason=eligibility.reason,
    )

    try:
        verified = infra.evidence_reader.read_verified(  # type: ignore[union-attr]
            classification.evidence_id
        )
    except Exception:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason="FRESH_READ_UNAVAILABLE",
        )
        return MaterializationOutcome(False, "FRESH_READ_UNAVAILABLE")
    if not isinstance(verified, VerifiedEvidence) or not isinstance(
        verified.record, ev.EvidenceRecord
    ):
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason="FRESH_READ_MALFORMED",
        )
        return MaterializationOutcome(False, "FRESH_READ_MALFORMED")
    record = verified.record
    try:
        verify_record(record)
    except Exception:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason="FRESH_EVIDENCE_UNVERIFIABLE",
        )
        return MaterializationOutcome(False, "FRESH_EVIDENCE_UNVERIFIABLE")
    if record.lifecycle != "SEALED" or not record.complete:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason="FRESH_EVIDENCE_LIFECYCLE",
        )
        return MaterializationOutcome(False, "FRESH_EVIDENCE_LIFECYCLE")
    if not _claims_ok(verified.index, record):
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason="FRESH_INDEX_MISMATCH",
        )
        return MaterializationOutcome(False, "FRESH_INDEX_MISMATCH")

    binding = verify_authority_binding(classification, record)
    if not binding.authorized:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason=binding.reason,
        )
        return MaterializationOutcome(False, binding.reason)

    parsed = _parse_rule_display(classification.rule_id)
    base = parsed[0] if parsed is not None else ""
    round_id: str | None = None
    submit_ref: str | None = None
    submit_hash: str | None = None
    if base == "xss-stored-round":
        if record.execution_stage != "read":
            _emit(
                infra,
                event="FINDING_ELIGIBILITY_REJECTED",
                classification=classification,
                reason="ROUND_LINKAGE_MISSING",
            )
            return MaterializationOutcome(False, "ROUND_LINKAGE_MISSING")
        browser = record.browser
        round_id = browser.round_id if browser is not None else None
        submit_ref, submit_hash = _resolve_submit_linkage(infra, record)
        if not round_id or not submit_ref or not submit_hash:
            _emit(
                infra,
                event="FINDING_ELIGIBILITY_REJECTED",
                classification=classification,
                reason="ROUND_SUBMIT_UNRESOLVED",
            )
            return MaterializationOutcome(False, "ROUND_SUBMIT_UNRESOLVED")

    snapshot = record.snapshot_binding
    derivation = record.derivation_binding
    browser = record.browser
    result_hash = compute_result_hash(classification)
    finding_id = finding_id_for(
        classification_result_hash=result_hash,
        evidence_bindings_hash=classification.evidence_bindings_hash,
        evidence_observations_hash=(
            classification.evidence_observations_hash
        ),
        evidence_content_hash=classification.evidence_content_hash,
        verifier_version=classification.verifier_version,
        rule_id=classification.rule_id,
        policy_version=classification.policy_version,
        eligibility_policy_version=ELIGIBILITY_POLICY_VERSION,
    )
    try:
        finding = SealedFinding(
            finding_id=finding_id,
            classification_result_hash=result_hash,
            evidence_id=record.evidence_id,
            execution_id=record.execution_id,
            authorization_id=record.authorization_id,
            program_name=record.program_name,
            canonical_host=record.target.host,
            scheme=record.target.scheme,
            effective_port=record.target.effective_port,
            path_scope=record.target.path_scope,
            target_resolution_identity=(
                snapshot.snapshot_ref if snapshot is not None else None
            ),
            scope_evaluation_identity=(
                snapshot.scope_lists_hash if snapshot is not None else ""
            ),
            artifact_id=record.artifact_id,
            artifact_content_hash=record.artifact_content_hash,
            evidence_content_hash=record.content_hash or "",
            evidence_bindings_hash=record.bindings_hash or "",
            evidence_observations_hash=record.observations_hash or "",
            verifier_version=classification.verifier_version,
            rule_id=classification.rule_id,
            observation_schema_version=(
                classification.observation_schema_version
            ),
            artifact_schema_version=(
                classification.artifact_schema_version
            ),
            policy_version=classification.policy_version,
            eligibility_policy_version=ELIGIBILITY_POLICY_VERSION,
            classification="CONFIRMED",
            confirmation_state=classification.confirmation_state,
            oracle_channels=tuple(classification.oracle_channels),
            severity=classification.severity,  # type: ignore[arg-type]
            severity_unset_reason=classification.severity_unset_reason,
            severity_policy_version=classification.policy_version,
            executed_payload_hash=(
                derivation.executed_payload_hash
                if derivation is not None
                else None
            )
            or (
                browser.executed_payload_hash
                if browser is not None
                else None
            ),
            derivation_contract_hash=(
                derivation.contract_hash if derivation is not None else None
            ),
            round_id=round_id,
            submit_evidence_ref=submit_ref,
            submit_content_hash=submit_hash,
            reason_code=classification.reason_code,
        )
    except Exception:
        _emit(
            infra,
            event="FINDING_ELIGIBILITY_REJECTED",
            classification=classification,
            reason="FINDING_CONSTRUCTION_INVALID",
        )
        return MaterializationOutcome(False, "FINDING_CONSTRUCTION_INVALID")

    payload = canonical_finding_bytes(finding)
    stored = infra.finding_store.put(
        finding.program_name, finding.finding_id, payload
    )
    if stored == CORRUPT_COLLISION:
        _emit(
            infra,
            event="FINDING_STORE_REFUSED",
            classification=classification,
            reason="STORE_CORRUPT_COLLISION",
            finding_id=finding.finding_id,
        )
        return MaterializationOutcome(
            False,
            "STORE_CORRUPT_COLLISION",
            finding_id=finding.finding_id,
        )
    if stored == DEDUPLICATED:
        infra.workflow_store.get_or_create(
            finding.finding_id, finding.program_name
        )
        _emit(
            infra,
            event="FINDING_DEDUPLICATED",
            classification=classification,
            reason="FINDING_DEDUPLICATED",
            finding_id=finding.finding_id,
        )
        return MaterializationOutcome(
            True,
            "FINDING_DEDUPLICATED",
            finding=finding,
            finding_id=finding.finding_id,
            notified=False,
            deduplicated=True,
        )
    _emit(
        infra,
        event="FINDING_MATERIALIZED",
        classification=classification,
        reason="FINDING_MATERIALIZED",
        finding_id=finding.finding_id,
    )
    infra.workflow_store.get_or_create(
        finding.finding_id, finding.program_name
    )
    _emit(
        infra,
        event="FINDING_PERSISTED",
        classification=classification,
        reason="FINDING_PERSISTED",
        finding_id=finding.finding_id,
    )
    alert_id = alert_id_for(finding.finding_id)
    notified = False
    if infra.alert_ledger.claim(alert_id):
        try:
            infra.notification_sink.publish(
                FindingAlert(
                    alert_id=alert_id,
                    finding_id=finding.finding_id,
                    program_name=finding.program_name,
                    severity=finding.severity,
                    severity_pending=(finding.severity == "UNSET"),
                    classification_hash=result_hash,
                )
            )
            notified = True
        except Exception:
            notified = False
    _emit(
        infra,
        event="FINDING_PERSISTED",
        classification=classification,
        reason=(
            "FINDING_NOTIFICATION_SENT"
            if notified
            else "FINDING_NOTIFICATION_SKIPPED"
        ),
        finding_id=finding.finding_id,
        alert_id=alert_id,
    )
    return MaterializationOutcome(
        True,
        PERSISTED,
        finding=finding,
        finding_id=finding.finding_id,
        notified=notified,
        alert_id=alert_id,
    )


def finding_availability(
    finding: SealedFinding,
    evidence_reader: object,
) -> str:
    """Read-side availability flag (never a verdict).

    ``PERSISTED``: evidence present, SEALED, triple reproduces the
    finding's pinned hashes. ``PERSISTED_UNVERIFIABLE``: evidence
    present but lifecycle/triple diverged (availability event, NOT
    "not vulnerable" — history stands). ``EVIDENCE_GONE``: no
    readable evidence row at all.
    """
    if not isinstance(finding, SealedFinding):
        raise TypeError(
            "availability accepts only SealedFinding, "
            f"not {type(finding).__name__}"
        )
    read = getattr(evidence_reader, "read_verified", None)
    if not callable(read):
        raise TypeError("evidence_reader must expose read_verified")
    try:
        verified = read(finding.evidence_id)
    except Exception:
        return _GONE_AVAILABILITY
    record = getattr(verified, "record", None)
    if not isinstance(record, ev.EvidenceRecord):
        return _GONE_AVAILABILITY
    try:
        verify_record(record)
    except Exception:
        return _UNVERIFIABLE_AVAILABILITY
    if record.lifecycle != "SEALED" or not record.complete:
        return _UNVERIFIABLE_AVAILABILITY
    if (
        record.bindings_hash != finding.evidence_bindings_hash
        or record.observations_hash != finding.evidence_observations_hash
        or record.content_hash != finding.evidence_content_hash
    ):
        return _UNVERIFIABLE_AVAILABILITY
    return _PERSISTED_AVAILABILITY
