"""Append-only audit contract (Phase 5H-core).

One record per transition, sequence-ordered per execution. Audit is
ACCOUNTING, not authority: no executor reads audit to decide
permission, and no verifier trusts audit over recomputed hashes.
Audit carries hashes + decisions + codes only — never secrets, raw
bodies, raw pages, raw stdout/stderr, raw DB exceptions, or LLM text.

Failure rule (frozen): audit failure BEFORE execution blocks
execution (fail closed); audit failure AFTER execution begins is
recorded as a separate ``AUDIT_GAP`` entry — sealed evidence is
never mutated to repair audit.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas import evidence as ev

__all__ = [
    "AuditTransition",
    "AuditRecord",
    "gap_record",
    "check_ordering",
    "ORDERED_TRANSITIONS",
]

AuditTransition = Literal[
    "AUTHORIZATION",
    "EXECUTION_STARTED",
    "EXECUTION_STAGE",
    "EVIDENCE_SEALED",
    "EXECUTION_TERMINAL",
    "VERIFIER_HANDOFF",
    "AUDIT_GAP",
    "ORPHAN_REINDEXED",
]

#: Legal per-execution transition order. ``AUDIT_GAP`` and
#: ``ORPHAN_REINDEXED`` are sibling annotations that may attach after
#: any post-start transition without breaking the main chain.
ORDERED_TRANSITIONS: tuple[str, ...] = (
    "AUTHORIZATION",
    "EXECUTION_STARTED",
    "EXECUTION_STAGE",
    "EVIDENCE_SEALED",
    "EXECUTION_TERMINAL",
    "VERIFIER_HANDOFF",
)

_AUTHZ_ID_RE_TMPL = r"^authz-[0-9a-f]{16}$"
_EVIDENCE_ID_RE_TMPL = r"^ev-[0-9a-f]{32}$"
_EXECUTION_ID_RE_TMPL = r"^ex-[0-9a-f]{32}$"

import re as _re

_AUTHZ_ID_RE = _re.compile(_AUTHZ_ID_RE_TMPL)
_EVIDENCE_ID_RE = _re.compile(_EVIDENCE_ID_RE_TMPL)
_EXECUTION_ID_RE = _re.compile(_EXECUTION_ID_RE_TMPL)
_SHA256_RE = _re.compile(r"^[0-9a-f]{64}$")


class AuditRecord(BaseModel):
    """One append-only transition record (hashes + codes, no secrets)."""

    model_config = ConfigDict(extra="forbid")

    seq: int
    execution_id: str
    authorization_id: str
    evidence_id: str | None = None
    stage: str | None = None
    transition: AuditTransition
    at: str = ""
    actor: str = ""
    program_name: str = ""
    host: str = ""
    scope_decision: str | None = None
    artifact_id: str | None = None
    artifact_content_hash: str | None = None
    evidence_hashes: dict[str, str] = {}
    error_code: str | None = None

    @field_validator("seq")
    @classmethod
    def _seq(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("seq must be a non-negative integer")
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

    @field_validator("evidence_id")
    @classmethod
    def _evidence_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _EVIDENCE_ID_RE.match(value):
            raise ValueError(f"invalid evidence_id: {value!r}")
        return value

    @field_validator("actor", "program_name", "host", "scope_decision",
                     "error_code")
    @classmethod
    def _bounded_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("audit text fields must be strings")
        if len(value) > 200:
            raise ValueError("audit text field exceeds 200 chars")
        if "\n" in value or "\r" in value:
            raise ValueError("audit text fields must be single-line")
        lowered = value.casefold()
        for marker in (
            "mongodb://",
            "password",
            "api_key",
            "secret",
            "bearer ",
            "-----begin",
        ):
            if marker in lowered:
                raise ValueError(
                    "audit record carries suspected secret material"
                )
        return value

    @field_validator("evidence_hashes")
    @classmethod
    def _hashes(cls, value: dict[str, str]) -> dict[str, str]:
        if not isinstance(value, dict):
            raise ValueError("evidence_hashes must be a mapping")
        allowed = {"bindings_hash", "observations_hash", "content_hash"}
        for key, item in value.items():
            if key not in allowed:
                raise ValueError(f"unexpected evidence hash key: {key!r}")
            if not _SHA256_RE.match(item or ""):
                raise ValueError(f"invalid evidence hash: {item!r}")
        return value


def gap_record(
    *,
    seq: int,
    execution_id: str,
    authorization_id: str,
    missing_from: str,
    error_code: str = "AUDIT_GAP",
    at: str = "",
    actor: str = "",
) -> AuditRecord:
    """Build a separate AUDIT_GAP entry (never an evidence mutation)."""
    return AuditRecord(
        seq=seq,
        execution_id=execution_id,
        authorization_id=authorization_id,
        transition="AUDIT_GAP",
        at=at,
        actor=actor,
        scope_decision=f"gap-after:{missing_from}"[:200],
        error_code=error_code,
    )


def check_ordering(records: list[AuditRecord]) -> None:
    """Validate append-only ordering for one execution's audit chain.

    Requires contiguous ``seq`` values and non-decreasing positions
    in ``ORDERED_TRANSITIONS`` (gap/orphan annotations are
    order-exempt siblings). Raises ``EVIDENCE_MALFORMED`` on any
    violation. Pure; performs no I/O.
    """
    if not isinstance(records, list):
        raise TypeError(
            "check_ordering accepts only a list, "
            f"not {type(records).__name__}"
        )
    if not records:
        return
    for record in records:
        if not isinstance(record, AuditRecord):
            raise TypeError(
                "check_ordering accepts only AuditRecord items, "
                f"not {type(record).__name__}"
            )
    base_seq = records[0].seq
    position = -1
    for offset, record in enumerate(records):
        if record.seq != base_seq + offset:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "audit seq is not contiguous"
            )
        if record.transition in ("AUDIT_GAP", "ORPHAN_REINDEXED"):
            continue
        try:
            slot = ORDERED_TRANSITIONS.index(record.transition)
        except ValueError:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED",
                f"unknown audit transition: {record.transition!r}",
            ) from None
        if slot < position:
            raise ev.EvidenceError(
                "EVIDENCE_MALFORMED", "audit transition out of order"
            )
        position = slot
