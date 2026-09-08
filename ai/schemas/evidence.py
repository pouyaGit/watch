"""Evidence/v1 contract schemas (Phase 5H-core).

Position in the pipeline::

    sealed transport facts (future 5E-5G)
        |
        v
    EvidenceRecord (immutable after seal, this module)
        |
        v  (handoff service, 5I)
    EvidenceHandoff (verdict-free reference)

Trust semantics (normative per
``agent-reports/evidence-core-architecture.md``):

- An ``EvidenceRecord`` is raw observation. It is NEVER authority,
  NEVER a verdict, and NEVER executable. ``complete=true`` means
  "required observations present and hashes verify" — NOT
  "vulnerable", NOT "not vulnerable".
- ``evidence_id`` / ``execution_id`` are random handles, NOT content
  identity. Content identity is the frozen triple
  (``bindings_hash``, ``observations_hash``, ``content_hash``).
- Timestamps are audit/metadata only and NEVER enter any hash.
- ``ORPHANED`` is an index/recovery classification, not an evidence
  byte state: only ``BUILDING``, ``SEALED``, ``INCOMPLETE`` exist here.
- No verdict-shaped field may exist on any model in this module
  (``extra="forbid"`` enforces it structurally).

This module is PURE and DETERMINISTIC (aside from random ID
generation, which uses ``secrets`` and is format-tested, never
value-tested):

- NO network, NO subprocess, NO database, NO LLM, NO scope
  evaluation, NO DNS, NO execution, NO verification, NO findings.
"""

from __future__ import annotations

import re
import secrets
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "evidence/v1"

ExecutionStage = Literal[
    "single",
    "submit",
    "read",
    "oracle",
]

EvidenceLifecycle = Literal[
    "BUILDING",
    "SEALED",
    "INCOMPLETE",
]

EvidenceExecutionClass = Literal[
    "http_probe",
    "nuclei_scan",
    "http_verification",
    "browser_verification",
]

TransportOutcome = Literal[
    "responded",
    "timeout",
    "connection_error",
    "killed",
    "process_died",
    "aborted_limit",
]

# Closed audit-reason vocabulary for INCOMPLETE records: names the
# missing element without free prose.
IncompleteReason = Literal[
    "response_missing",
    "body_over_cap",
    "chain_over_cap",
    "process_killed",
    "channels_partial",
    "binding_unverifiable",
]

_EVIDENCE_ID_RE = re.compile(r"^ev-[0-9a-f]{32}$")
_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_ART_ID_RE = re.compile(r"^art-[0-9a-f]{16}$")
_TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")
_HYP_ID_RE = re.compile(r"^hyp-[0-9a-f]{16}$")
_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ROUND_ID_RE = re.compile(r"^sr-[0-9a-f]{32}$")

#: Field names that must never appear on evidence models. Defense in
#: depth behind ``extra="forbid"``: any future field addition with one
#: of these names fails closed at import-review time via tests.
FORBIDDEN_EVIDENCE_FIELDS = frozenset(
    {
        "verdict",
        "finding",
        "matched",
        "vulnerable",
        "confirmed",
        "not_vulnerable",
        "severity",
        "exploited",
    }
)


def generate_evidence_id() -> str:
    """Random 128-bit evidence handle (uniqueness only, no meaning)."""
    return "ev-" + secrets.token_hex(16)


def generate_execution_id() -> str:
    """Random 128-bit execution handle (uniqueness only, no meaning)."""
    return "ex-" + secrets.token_hex(16)


class EvidenceError(ValueError):
    """Bounded, non-secret 5H-core failure with an explicit code.

    Details are closed-code style: short, caller-value-free, screened
    against secret markers. Raw exceptions, connection strings, and
    credentials must never flow through here.
    """

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

    _CODES = frozenset(
        {
            "EVIDENCE_NOT_FOUND",
            "EVIDENCE_IMMUTABLE",
            "EVIDENCE_BINDING_MISMATCH",
            "EVIDENCE_HASH_MISMATCH",
            "EVIDENCE_INCOMPLETE",
            "EVIDENCE_MALFORMED",
            "OUTCOME_UNKNOWN",
            "EXECUTION_DUPLICATE",
            "EXECUTION_IN_PROGRESS",
            "EXECUTION_REPLAY",
            "ORPHAN_EVIDENCE",
            "ORPHAN_REINDEXED",
            "AUDIT_GAP",
            "LIMIT_EXCEEDED",
            "LIMIT_UNKNOWN",
            "HANDOFF_REJECTED",
            "STALE_EVIDENCE",
            "AUTHZ_NOT_LIVE",
        }
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self._CODES:
            raise ValueError(f"unknown evidence error code: {code!r}")
        safe_detail = (detail or "")[:200]
        lowered = safe_detail.casefold()
        for marker in self._SECRET_MARKERS:
            if marker in lowered:
                raise ValueError(
                    "evidence error detail carries suspected secret material"
                )
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("evidence error detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


class TargetIdentity(BaseModel):
    """Canonical target identity tuple (copied from authorization)."""

    model_config = ConfigDict(extra="forbid")

    program_name: str
    host: str
    scheme: Literal["http", "https"] = "https"
    effective_port: int = 443
    path_scope: str = ""

    @field_validator("program_name", "host")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if "\n" in value or "\r" in value:
            raise ValueError("must not contain newlines")
        return value

    @field_validator("effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("effective_port must be an integer")
        if not 1 <= value <= 65535:
            raise ValueError("effective_port out of range")
        return value

    @field_validator("path_scope")
    @classmethod
    def _path(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("path_scope must not contain newlines")
        if value and not value.startswith("/"):
            raise ValueError("path_scope must start with '/'")
        return value


class SnapshotBinding(BaseModel):
    """Descriptive pin values copied from authorization (never permission)."""

    model_config = ConfigDict(extra="forbid")

    snapshot_ref: str | None = None
    scope_policy_version: str = "scope-policy/v1"
    scope_lists_hash: str
    fixture_set_id: str | None = None
    fixture_version: str | None = None
    cdn_mapping_version: str | None = None
    cdn_mapping_hash: str | None = None

    @field_validator(
        "snapshot_ref", "scope_lists_hash", "cdn_mapping_hash"
    )
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid hash value: {value!r}")
        return value


class DerivationBinding(BaseModel):
    """XSS derivation binding: contract hash copied, executed hash computed."""

    model_config = ConfigDict(extra="forbid")

    contract_hash: str | None = None
    executed_payload_hash: str | None = None
    execution_phase: Literal["oracle", "stored_submit", "stored_read"] | None = (
        None
    )

    @field_validator("contract_hash", "executed_payload_hash")
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid payload/contract hash: {value!r}")
        return value


class TemplateBinding(BaseModel):
    """Nuclei template binding: recomputed from projected bytes at seal."""

    model_config = ConfigDict(extra="forbid")

    template_id: str | None = None
    template_hash: str | None = None

    @field_validator("template_id")
    @classmethod
    def _template_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.strip() or len(value) > 256:
            raise ValueError("invalid template_id")
        if "\n" in value or "\r" in value:
            raise ValueError("template_id must be single-line")
        return value

    @field_validator("template_hash")
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid template_hash: {value!r}")
        return value


class RedactedUrl(BaseModel):
    """Observation-only URL: redacted canonical form + hashes only."""

    model_config = ConfigDict(extra="forbid")

    redacted_url: str
    canonical_hash: str
    redacted_query_hash: str | None = None

    @field_validator("redacted_url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("redacted_url must be non-empty")
        if len(value) > 2048:
            raise ValueError("redacted_url exceeds 2048 chars")
        if "\n" in value or "\r" in value:
            raise ValueError("redacted_url must be single-line")
        if "@" in value.split("?", 1)[0].split("/", 3)[-1].rsplit("/", 1)[-1]:
            # Netloc userinfo must never persist: caught structurally.
            raise ValueError("redacted_url must not contain userinfo")
        return value

    @field_validator("canonical_hash", "redacted_query_hash")
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid url hash: {value!r}")
        return value


class HeaderSnapshot(BaseModel):
    """Allowlisted, bounded, redacted header snapshot."""

    model_config = ConfigDict(extra="forbid")

    headers: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False


class HttpObservation(BaseModel):
    """Bounded HTTP transport facts (hashes always, samples sometimes)."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"] = "GET"
    request_url: RedactedUrl
    request_headers: HeaderSnapshot = Field(default_factory=HeaderSnapshot)
    request_body_hash: str
    request_body_sample: str | None = None
    response_status: int | None = None
    response_headers: HeaderSnapshot = Field(default_factory=HeaderSnapshot)
    response_body_hash: str | None = None
    response_body_sample: str | None = None
    sample_omitted: str | None = None
    redirect_chain: list[RedactedUrl] = Field(default_factory=list)
    chain_truncated: bool = False
    dial_ips: tuple[str, ...] = ()
    transport_outcome: TransportOutcome = "responded"

    @field_validator("request_body_hash", "response_body_hash")
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid body hash: {value!r}")
        return value

    @field_validator("response_status")
    @classmethod
    def _status(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("response_status must be an integer")
        if not 100 <= value <= 599:
            raise ValueError("response_status out of range")
        return value


class NucleiObservation(BaseModel):
    """Untrusted Nuclei process facts. Advisory only — never a verdict."""

    model_config = ConfigDict(extra="forbid")

    template_id: str
    template_hash: str
    argv_digest: str
    exit_code: int | None = None
    timed_out: bool = False
    killed: bool = False
    stdout_hash: str
    stderr_hash: str
    stdout_sample: str | None = None
    stderr_sample: str | None = None
    finding_like_text_present: bool = False

    @field_validator("template_hash", "argv_digest", "stdout_hash",
                     "stderr_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid nuclei hash: {value!r}")
        return value

    @field_validator("exit_code")
    @classmethod
    def _exit(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("exit_code must be an integer")
        return value


class BrowserObservation(BaseModel):
    """Bounded browser/XSS channel facts. Predicates are advisory."""

    model_config = ConfigDict(extra="forbid")

    dialog_marker_hashes: tuple[str, ...] = ()
    oracle_event_hashes: tuple[str, ...] = ()
    eval_marker_hashes: tuple[str, ...] = ()
    e1_observed: bool = False
    e2_observed: bool = False
    e3_observed: bool = False
    executed_payload_hash: str | None = None
    page_url: RedactedUrl | None = None
    storage_keys_hash: str | None = None
    channels_truncated: bool = False
    round_id: str | None = None
    submit_evidence_ref: str | None = None

    @field_validator(
        "dialog_marker_hashes", "oracle_event_hashes", "eval_marker_hashes"
    )
    @classmethod
    def _marker_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not _SHA256_RE.match(item or ""):
                raise ValueError(f"invalid marker hash: {item!r}")
        if len(value) > 16:
            raise ValueError("marker list exceeds 16 entries")
        return value

    @field_validator("executed_payload_hash", "storage_keys_hash")
    @classmethod
    def _hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid browser hash: {value!r}")
        return value

    @field_validator("round_id")
    @classmethod
    def _round_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ROUND_ID_RE.match(value):
            raise ValueError(f"invalid round_id: {value!r}")
        return value

    @field_validator("submit_evidence_ref")
    @classmethod
    def _submit_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid submit_evidence_ref: {value!r}")
        return value


class EvidenceRecord(BaseModel):
    """One sealed (or sealing) evidence record. Observations only."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    execution_id: str
    authorization_id: str
    execution_stage: ExecutionStage = "single"
    execution_class: EvidenceExecutionClass = "http_probe"
    artifact_id: str
    artifact_content_hash: str
    target: TargetIdentity
    program_name: str
    hypothesis_id: str | None = None
    test_plan_id: str
    match_id: str | None = None
    snapshot_binding: SnapshotBinding | None = None
    derivation_binding: DerivationBinding | None = None
    template_binding: TemplateBinding | None = None
    complete: bool = False
    lifecycle: EvidenceLifecycle = "BUILDING"
    bindings_hash: str | None = None
    observations_hash: str | None = None
    content_hash: str | None = None
    http: HttpObservation | None = None
    nuclei: NucleiObservation | None = None
    browser: BrowserObservation | None = None
    incomplete_reasons: tuple[str, ...] = ()
    started_at: str = ""
    finished_at: str = ""
    sealed_at: str = ""
    evidence_schema_version: Literal["evidence/v1"] = "evidence/v1"

    @field_validator("evidence_id")
    @classmethod
    def _evidence_id(cls, value: str) -> str:
        if not _EVIDENCE_ID_RE.match(value or ""):
            raise ValueError(f"invalid evidence_id: {value!r}")
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

    @field_validator("artifact_id")
    @classmethod
    def _art_id(cls, value: str) -> str:
        if not _ART_ID_RE.match(value or ""):
            raise ValueError(f"invalid artifact_id: {value!r}")
        return value

    @field_validator("artifact_content_hash")
    @classmethod
    def _content_hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid artifact_content_hash: {value!r}")
        return value

    @field_validator("test_plan_id")
    @classmethod
    def _tp_id(cls, value: str) -> str:
        if not _TP_ID_RE.match(value or ""):
            raise ValueError(f"invalid test_plan_id: {value!r}")
        return value

    @field_validator("hypothesis_id")
    @classmethod
    def _hyp_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HYP_ID_RE.match(value):
            raise ValueError(f"invalid hypothesis_id: {value!r}")
        return value

    @field_validator("match_id")
    @classmethod
    def _match_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _TM_ID_RE.match(value):
            raise ValueError(f"invalid match_id: {value!r}")
        return value

    @field_validator("bindings_hash", "observations_hash", "content_hash")
    @classmethod
    def _seal_hash_or_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid seal hash: {value!r}")
        return value


__all__ = [
    "SCHEMA_VERSION",
    "ExecutionStage",
    "EvidenceLifecycle",
    "EvidenceExecutionClass",
    "TransportOutcome",
    "IncompleteReason",
    "FORBIDDEN_EVIDENCE_FIELDS",
    "generate_evidence_id",
    "generate_execution_id",
    "EvidenceError",
    "TargetIdentity",
    "SnapshotBinding",
    "DerivationBinding",
    "TemplateBinding",
    "RedactedUrl",
    "HeaderSnapshot",
    "HttpObservation",
    "NucleiObservation",
    "BrowserObservation",
    "EvidenceRecord",
]
