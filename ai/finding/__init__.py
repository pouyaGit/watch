"""Phase 5J — Finding Pipeline / Production Materialization (offline).

ONLY transition owned here::

    5I ClassificationResult
        -> 5I authority/provenance gate
        -> 5J eligibility gate (CONFIRMED-only, pinned policy)
        -> fresh evidence revalidation (new verified read, full axis set)
        -> immutable sealed finding (deterministic id)
        -> in-memory persistence seam (put-if-absent dedup)
        -> append-only audit + offline notification seam

Hard boundaries (all test-enforced):

- 5J MUST NOT classify evidence, inspect raw browser/Nuclei/HTTP
  observations for vulnerability decisions, calculate severity, or
  promote POTENTIAL / UNKNOWN / INCONCLUSIVE.
- Severity is copied verbatim from the 5I-authorized triple; no
  severity literal may appear in 5J code outside prose.
- Persistence store, evidence reader, audit sink, and notification
  sink are trusted infrastructure dependencies injected as typed
  objects. A malicious or faulty seam can only force fail-closed
  (NO FINDING) — never a forged finding — because every security
  field is re-derived or equality-checked, never trusted.
- No network, DNS, browser, Nuclei, subprocess, LLM, MongoDB, or
  live execution. ``LIVE_BROWSER`` / ``LIVE_NUCLEI`` /
  ``LIVE_TRAFFIC_ENABLED`` remain False; production persistence is
  NOT enabled (in-memory backend only; the Mongo adapter is a
  B2-blocked stub that fails closed on any use).
"""

from __future__ import annotations

from ai.finding.audit import (
    FindingAuditEvent,
    emit_finding_audit,
)
from ai.finding.authority import (
    verify_authority_binding,
    verify_authority_structure,
)
from ai.finding.eligibility import (
    ELIGIBILITY_POLICY_VERSION,
    check_eligibility,
)
from ai.finding.legacy_block import (
    BANNED_TOKENS,
    HARD_BLOCKED_PATHS,
)
from ai.finding.materializer import (
    MATERIALIZER_VERSION,
    FindingInfrastructure,
    MaterializationOutcome,
    finding_availability,
    materialize,
)
from ai.finding.notify import (
    ALERT_POLICY_VERSION,
    AlertLedgerMemory,
    FindingAlert,
    NotificationSink,
    RecordingNotificationSink,
    alert_id_for,
)
from ai.finding.sealed import (
    FINDING_SCHEMA_VERSION,
    SealedFinding,
    canonical_finding_bytes,
    finding_id_for,
)
from ai.finding.store_memory import (
    B2_BLOCKED,
    FindingStore,
    FindingStoreMemory,
    MongoFindingStoreAdapter,
    StoredFinding,
    WorkflowRecord,
    WorkflowStore,
    WorkflowStoreMemory,
    WorkflowVersionConflict,
)

__all__ = [
    "ALERT_POLICY_VERSION",
    "B2_BLOCKED",
    "BANNED_TOKENS",
    "ELIGIBILITY_POLICY_VERSION",
    "FINDING_SCHEMA_VERSION",
    "HARD_BLOCKED_PATHS",
    "MATERIALIZER_VERSION",
    "AlertLedgerMemory",
    "FindingAlert",
    "FindingAuditEvent",
    "FindingInfrastructure",
    "FindingStore",
    "FindingStoreMemory",
    "MaterializationOutcome",
    "MongoFindingStoreAdapter",
    "NotificationSink",
    "RecordingNotificationSink",
    "SealedFinding",
    "StoredFinding",
    "WorkflowRecord",
    "WorkflowStore",
    "WorkflowStoreMemory",
    "WorkflowVersionConflict",
    "alert_id_for",
    "canonical_finding_bytes",
    "check_eligibility",
    "emit_finding_audit",
    "finding_availability",
    "finding_id_for",
    "materialize",
    "verify_authority_binding",
    "verify_authority_structure",
]
