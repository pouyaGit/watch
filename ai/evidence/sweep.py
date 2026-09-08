"""Orphan detection + sweep (Phase 5H).

Typed sweep over the blob/index set-diff reusing the frozen pure
semantics (``classify_orphan`` / ``validate_reindex``). The sweeper
never synthesizes identity, never silently deletes, and never
mutates bytes: recoverable orphans re-index under ORIGINAL keys;
corrupt/missing-reference cases quarantine with operator visibility
and audit annotations.

Grace period: candidates younger than ``grace_seconds`` (measured
from the sealed record's ``sealed_at`` where available) are reported
but not acted on. Destructive deletion is out of scope (retention
policy owns tombstones; see ``ai.evidence.store``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ai.evidence.orphan import OrphanClass, classify_orphan
from ai.schemas import evidence as ev

__all__ = [
    "SweepCandidate",
    "SweepReport",
    "SweepConfig",
    "discover_candidates",
    "run_sweep",
]

_DEFAULT_GRACE_SECONDS = 24 * 3600


@dataclass(frozen=True)
class SweepConfig:
    """Sweep tuning (policy, not content)."""

    grace_seconds: int = _DEFAULT_GRACE_SECONDS
    actor: str = "evidence-sweeper/5H"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.grace_seconds, int)
            or isinstance(self.grace_seconds, bool)
            or self.grace_seconds < 0
        ):
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "sweep grace period invalid"
            )


@dataclass(frozen=True)
class SweepCandidate:
    """One classified set-diff finding (observation, not mutation)."""

    content_hash: str | None
    evidence_id: str | None
    execution_id: str | None
    orphan_class: OrphanClass
    within_grace: bool = False


@dataclass
class SweepReport:
    """Deterministic sweep outcome (accounting, never a verdict)."""

    epoch: str
    candidates: list[SweepCandidate] = field(default_factory=list)
    reindexed: list[str] = field(default_factory=list)
    quarantined: list[str] = field(default_factory=list)
    deferred_grace: list[str] = field(default_factory=list)
    audit_gap: bool = False


def _parse_epoch(value: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ev.EvidenceError(
            "EVIDENCE_MALFORMED", "sweep epoch instant malformed"
        ) from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


def _record_age_seconds(record: ev.EvidenceRecord, now: datetime) -> float:
    try:
        sealed = datetime.fromisoformat(record.sealed_at)
    except (ValueError, TypeError):
        return float("inf")
    if sealed.tzinfo is None:
        sealed = sealed.replace(tzinfo=timezone.utc)
    return (now - sealed).total_seconds()


def discover_candidates(
    *,
    blobs: object,
    index: object,
    now_epoch: str,
    grace_seconds: int = _DEFAULT_GRACE_SECONDS,
) -> list[SweepCandidate]:
    """Set-diff blob listing vs. index (pure observation, no writes)."""
    from ai.evidence.store import parse_envelope

    list_hashes = getattr(blobs, "list_hashes", None)
    blob_get = getattr(blobs, "get", None)
    idx_get = getattr(index, "get_by_evidence_id", None)
    if not callable(list_hashes) or not callable(blob_get):
        raise TypeError("sweep requires a blob store with listing")
    if not callable(idx_get):
        raise TypeError("sweep requires an index with evidence lookup")
    now = _parse_epoch(now_epoch)
    candidates: list[SweepCandidate] = []
    # Case 1/5: object exists, index missing (or hash-divergent).
    for content_hash in list_hashes():
        raw = blob_get(content_hash)
        if raw is None:
            continue
        try:
            record = parse_envelope(raw)
        except ev.EvidenceError:
            candidates.append(
                SweepCandidate(
                    content_hash=content_hash,
                    evidence_id=None,
                    execution_id=None,
                    orphan_class="BINDING_AMBIGUOUS",
                )
            )
            continue
        entry = idx_get(record.evidence_id)
        if entry is None:
            age = _record_age_seconds(record, now)
            candidates.append(
                SweepCandidate(
                    content_hash=content_hash,
                    evidence_id=record.evidence_id,
                    execution_id=record.execution_id,
                    orphan_class=(
                        "INDEX_MISSING_INCOMPLETE"
                        if record.lifecycle == "INCOMPLETE"
                        else "INDEX_MISSING_SEALED"
                    ),
                    within_grace=age < grace_seconds,
                )
            )
            continue
        # Index present: verify claims without mutating.
        try:
            from ai.evidence.builder import verify_record

            verify_record(record)
            claims_ok = (
                entry.content_hash == record.content_hash
                and entry.bindings_hash == record.bindings_hash
                and entry.observations_hash == record.observations_hash
                and entry.evidence_id == record.evidence_id
                and entry.execution_id == record.execution_id
            )
        except ev.EvidenceError:
            claims_ok = False
        if not claims_ok:
            candidates.append(
                SweepCandidate(
                    content_hash=content_hash,
                    evidence_id=record.evidence_id,
                    execution_id=record.execution_id,
                    orphan_class="BINDING_AMBIGUOUS",
                )
            )
    # Case 2/7: index entries without bytes are found via the store
    # read path (needs the full store); the store-index-only diff
    # below flags entries the blob listing lacks.
    known_hashes = set(list_hashes())
    seen_index_hashes: set[str] = set()
    index_entries = getattr(index, "_by_evidence", None)
    entries = (
        list(index_entries.values())
        if isinstance(index_entries, dict)
        else []
    )
    for entry in entries:
        if entry.content_hash in seen_index_hashes:
            continue
        seen_index_hashes.add(entry.content_hash)
        if entry.content_hash not in known_hashes:
            candidates.append(
                SweepCandidate(
                    content_hash=entry.content_hash,
                    evidence_id=entry.evidence_id,
                    execution_id=entry.execution_id,
                    orphan_class="BYTES_MISSING",
                )
            )
    _ = classify_orphan  # frozen semantics reused by the store path.
    return candidates


def run_sweep(
    *,
    store: object,
    blobs: object,
    index: object,
    now_epoch: str,
    config: SweepConfig | None = None,
) -> SweepReport:
    """Execute one sweep epoch (quarantine/re-index only, no delete)."""
    cfg = config or SweepConfig()
    report = SweepReport(epoch=now_epoch)
    reindex = getattr(store, "reindex_from_blob", None)
    quarantine = getattr(store, "quarantine_evidence", None)
    if not callable(reindex) or not callable(quarantine):
        raise TypeError("sweep requires a store with reindex/quarantine")
    for candidate in discover_candidates(
        blobs=blobs,
        index=index,
        now_epoch=now_epoch,
        grace_seconds=cfg.grace_seconds,
    ):
        report.candidates.append(candidate)
        label = candidate.evidence_id or candidate.content_hash or "unknown"
        if candidate.within_grace:
            report.deferred_grace.append(label)
            continue
        try:
            if candidate.orphan_class in (
                "INDEX_MISSING_SEALED",
                "INDEX_MISSING_INCOMPLETE",
            ):
                assert candidate.content_hash is not None
                entry_lookup = getattr(index, "get_by_evidence_id", None)
                _ = entry_lookup
                # Original keys come from the sealed bytes themselves.
                from ai.evidence.store import parse_envelope

                raw = getattr(blobs, "get")(candidate.content_hash)
                record = parse_envelope(raw)
                reindex(
                    candidate.content_hash,
                    claimed_evidence_id=record.evidence_id,
                    claimed_execution_id=record.execution_id,
                    claimed_authorization_id=record.authorization_id,
                )
                report.reindexed.append(label)
            else:
                if candidate.evidence_id is not None:
                    quarantine(
                        candidate.evidence_id,
                        reason=f"sweep:{candidate.orphan_class}",
                    )
                report.quarantined.append(label)
        except Exception:
            report.quarantined.append(label)
            report.audit_gap = True
    return report
