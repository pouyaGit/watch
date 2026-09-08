"""Append-only 5J audit contract (Phase 5J).

Same discipline as the frozen 5H trail and the 5I verifier audit:
hashes + IDs + closed codes only — never secrets, payloads, bodies,
stdout/stderr, browser text, or LLM text. Audit is ACCOUNTING, never
authority: nothing reads audit to grant permission, and audit never
overrides recomputed hashes. Audit-sink failure is swallowed (the
caller may record a gap); it can never mutate findings or evidence.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas import evidence as ev

__all__ = [
    "FindingAuditEventName",
    "FindingAuditEvent",
    "emit_finding_audit",
]

FindingAuditEventName = Literal[
    "FINDING_ELIGIBILITY_ACCEPTED",
    "FINDING_ELIGIBILITY_REJECTED",
    "FINDING_MATERIALIZED",
    "FINDING_PERSISTED",
    "FINDING_DEDUPLICATED",
    "FINDING_TOMBSTONED",
    "FINDING_WORKFLOW_CHANGED",
    "FINDING_STORE_REFUSED",
]

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


class FindingAuditEvent(BaseModel):
    """One append-only finding-pipeline record (hashes + codes)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event: FindingAuditEventName
    finding_id: str | None = None
    classification_hash: str | None = None
    evidence_id: str | None = None
    execution_id: str | None = None
    authorization_id: str | None = None
    program_name: str = ""
    host: str = ""
    reason_code: str = ""
    alert_id: str | None = None
    actor: Literal["finding-pipeline/5J"] = "finding-pipeline/5J"

    @field_validator("finding_id")
    @classmethod
    def _finding_id(cls, value: str | None) -> str | None:
        import re as _re

        if value is None:
            return None
        if not _re.match(r"^xf-[0-9a-f]{32}$", value):
            raise ValueError(f"invalid finding_id: {value!r}")
        return value

    @field_validator("evidence_id")
    @classmethod
    def _evidence_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not ev._EVIDENCE_ID_RE.match(value):
            raise ValueError(f"invalid evidence_id: {value!r}")
        return value

    @field_validator("execution_id")
    @classmethod
    def _execution_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not ev._EXECUTION_ID_RE.match(value):
            raise ValueError(f"invalid execution_id: {value!r}")
        return value

    @field_validator("authorization_id")
    @classmethod
    def _authz_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not ev._AUTHZ_ID_RE.match(value):
            raise ValueError(f"invalid authorization_id: {value!r}")
        return value

    @field_validator("classification_hash")
    @classmethod
    def _hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not ev._SHA256_RE.match(value):
            raise ValueError(f"invalid classification_hash: {value!r}")
        return value

    @field_validator(
        "reason_code", "program_name", "host", "alert_id"
    )
    @classmethod
    def _bounded_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) > 120:
            raise ValueError("finding audit field exceeds 120 chars")
        if "\n" in value or "\r" in value:
            raise ValueError("finding audit fields must be single-line")
        lowered = value.casefold()
        for marker in _SECRET_MARKERS:
            if marker in lowered:
                raise ValueError(
                    "finding audit field carries suspected secret material"
                )
        return value


def emit_finding_audit(sink: object, event: FindingAuditEvent) -> None:
    """Append one event to an injected audit sink (never authoritative).

    A failing sink is swallowed: audit failure must not mutate
    findings, evidence, or classification.
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
        return
