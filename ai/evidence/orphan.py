"""Orphan classification + re-index validation (Phase 5H-core).

Orphans are an INDEX state, never an evidence-byte state. This module
is pure and local: it classifies sweep findings and validates
recovery preconditions. It performs no I/O, owns no store, and —
critically — exposes no API that writes bytes, mints identities, or
changes bindings.

Recoverable: ``INDEX_MISSING_SEALED``, ``INDEX_MISSING_INCOMPLETE``.
Corrupt/quarantine: ``BYTES_MISSING``, ``BINDING_AMBIGUOUS``.

Recovery (:func:`validate_reindex`) restores the ORIGINAL index entry
only: same ``evidence_id``/``execution_id``/``authorization_id``,
same bindings, same hashes. Anything else raises.
"""

from __future__ import annotations

from typing import Literal

from ai.evidence import builder as seal
from ai.schemas import evidence as ev

__all__ = [
    "OrphanClass",
    "classify_orphan",
    "validate_reindex",
]

OrphanClass = Literal[
    "INDEX_MISSING_SEALED",
    "INDEX_MISSING_INCOMPLETE",
    "BYTES_MISSING",
    "BINDING_AMBIGUOUS",
]


def classify_orphan(
    *,
    bytes_present: bool,
    index_present: bool,
    binding_ambiguous: bool = False,
    lifecycle: str = "SEALED",
) -> OrphanClass | None:
    """Classify a sweep finding (pure decision table).

    Returns ``None`` when there is nothing to recover (healthy indexed
    record, or no bytes and no index — nothing exists).
    """
    if not isinstance(bytes_present, bool) or not isinstance(
        index_present, bool
    ):
        raise TypeError("orphan classification flags must be booleans")
    if binding_ambiguous and bytes_present:
        return "BINDING_AMBIGUOUS"
    if bytes_present and not index_present:
        if lifecycle == "INCOMPLETE":
            return "INDEX_MISSING_INCOMPLETE"
        return "INDEX_MISSING_SEALED"
    if index_present and not bytes_present:
        return "BYTES_MISSING"
    return None


def validate_reindex(
    record: ev.EvidenceRecord,
    *,
    claimed_evidence_id: str,
    claimed_execution_id: str,
    claimed_authorization_id: str,
) -> OrphanClass:
    """Validate that an orphan may be re-indexed under its original key.

    Checks (ALL required): record parses (typed input), all three
    hashes recompute-equal, claimed keys equal the sealed embedded
    bindings byte-identically, lifecycle is a sealed terminal
    (SEALED or INCOMPLETE — never BUILDING).

    Returns the orphan class the record recovers from
    (``INDEX_MISSING_SEALED`` / ``INDEX_MISSING_INCOMPLETE``).
    Raises ``EVIDENCE_*`` on any violation. Never mints a new
    identity, never changes a binding, never writes bytes.
    """
    if not isinstance(record, ev.EvidenceRecord):
        raise TypeError(
            "validate_reindex accepts only EvidenceRecord, "
            f"not {type(record).__name__}"
        )
    if record.lifecycle not in ("SEALED", "INCOMPLETE"):
        raise ev.EvidenceError(
            "ORPHAN_EVIDENCE", "only sealed terminals may be re-indexed"
        )
    seal.verify_record(record)
    if (
        claimed_evidence_id != record.evidence_id
        or claimed_execution_id != record.execution_id
        or claimed_authorization_id != record.authorization_id
    ):
        raise ev.EvidenceError(
            "EVIDENCE_BINDING_MISMATCH",
            "re-index key differs from sealed bindings",
        )
    if record.lifecycle == "INCOMPLETE":
        return "INDEX_MISSING_INCOMPLETE"
    return "INDEX_MISSING_SEALED"
