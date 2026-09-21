"""Observation -> evidence ingestion (EPIC 6 Part 5).

ingest() normalizes a caller-supplied observation result into an
EvidenceRecord with a content-hash id, an integrity digest, and a
redaction verdict. apply_to_gap() converts records into evidence-layer
artifact drafts and advances the real EvidenceGapState — the same
contracts the offline pipeline uses. No observation ever becomes a
finding here: the strongest state is EVIDENCE_READY (coverage), which
still requires human review before any conclusion.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from aec.evidence.models import EvidenceArtifactDraft
from aec.evidence.state_machine import EvidenceGapState, advance
from aec.evidence_bridge.models import EvidenceRecord
from aec.redaction import scrub_text

SOURCE_MODES = frozenset({"REAL_WATCH_DATA", "OFFLINE_FIXTURE"})

_SENSITIVE_HINTS = frozenset({"token", "secret", "password", "cookie",
                              "session", "auth"})


class IngestionFailure(Exception):
    """Refused or failed evidence ingestion."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def ingest(case_id: str, job_id: str, result: Mapping[str, Any],
           source_mode: str, tick: int) -> EvidenceRecord:
    """Normalize one observation result into an evidence record."""
    if not isinstance(case_id, str) or not case_id:
        raise IngestionFailure("case_id required")
    if not isinstance(job_id, str) or not job_id:
        raise IngestionFailure("job_id required")
    if source_mode not in SOURCE_MODES:
        raise IngestionFailure(f"unknown source mode: {source_mode!r}")
    if not isinstance(result, Mapping):
        raise IngestionFailure("result must be a mapping")
    observation_id = result.get("observation_id")
    observed = result.get("observed_fields")
    missing = result.get("missing_fields", [])
    if not isinstance(observation_id, str) or not observation_id:
        raise IngestionFailure("result missing observation_id")
    if not isinstance(observed, Sequence) \
            or isinstance(observed, (str, bytes)) or not observed:
        raise IngestionFailure("result carries no observed fields")
    if not isinstance(missing, Sequence) \
            or isinstance(missing, (str, bytes)):
        raise IngestionFailure("result has malformed missing fields")
    observed_fields = [str(item) for item in observed]
    missing_fields = [str(item) for item in missing]
    digest = hashlib.sha256(
        f"{case_id}|{job_id}|{observation_id}|{_canonical(result)}"
        .encode("utf-8")).hexdigest()
    integrity = hashlib.sha256(
        _canonical({"case": case_id, "job": job_id,
                    "result": result}).encode("utf-8")).hexdigest()
    joined = " ".join(observed_fields + missing_fields).lower()
    scrubbed, _ = scrub_text(joined)
    sensitive = any(hint in joined for hint in _SENSITIVE_HINTS)
    redaction = "scrubbed" if (sensitive or scrubbed != joined) else "clean"
    level = "COMPLETE" if not missing_fields else "PARTIAL"
    source = result.get("source") if isinstance(
        result.get("source"), str) and result.get("source") else "unknown"
    return EvidenceRecord(
        evidence_id=f"ev-{digest[:12]}",
        case_id=case_id,
        job_id=job_id,
        evidence_level=level,
        source=source,
        source_mode=source_mode,
        artifact_reference=f"{observation_id}:{digest[:8]}",
        observation=tuple(observed_fields),
        missing_fields=tuple(missing_fields),
        tick=tick if isinstance(tick, int) and tick >= 0 else 0,
        integrity=integrity,
        confidence="unstated",
        redaction_status=redaction,
    )


def apply_to_gap(state: EvidenceGapState,
                 records: Sequence[EvidenceRecord],
                 case_id: str, plan_id: str,
                 ) -> tuple[EvidenceGapState, list[EvidenceArtifactDraft]]:
    """Convert records to artifact drafts and advance the gap state."""
    items = list(records)
    for record in items:
        if record.case_id != case_id:
            raise IngestionFailure(
                f"record {record.evidence_id} belongs to "
                f"{record.case_id}, not {case_id}")
    drafts = [
        EvidenceArtifactDraft(
            artifact_id=record.evidence_id,
            plan_id=plan_id,
            case_id=record.case_id,
            observation_ref=record.artifact_reference,
            artifact_kind="observation",
            artifact_type="bridge-ingest",
            collected_fields=tuple(record.observation),
            missing_fields=tuple(record.missing_fields),
            provenance=(("source", record.source),
                        ("mode", record.source_mode)),
        )
        for record in items
    ]
    # Missing fields must still count: carry the union of still-missing
    # fields so advance() computes coverage against the full universe.
    # The bridge does not know the case's original missing set, so it
    # reconstructs drafts per record: collected = observed. Coverage is
    # therefore relative to observed records — documented, no inference.
    advanced = advance(state, drafts if drafts else None)
    return advanced, drafts


__all__ = ["IngestionFailure", "apply_to_gap", "ingest"]
