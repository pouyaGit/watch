"""Artifact Reference + Safety Contract (Phase 4C).

Position in the pipeline::

    TestPlan
        +
    artifact bytes
        |
        v
    validated, hash-bound ArtifactReference

This module defines the DETERMINISTIC contract a future artifact
generator (LLM or deterministic) must satisfy. It does NOT generate
artifacts, store artifacts, execute artifacts, verify targets, or
create findings.

Trust semantics:

- An ``ArtifactReference`` is metadata. It is NEVER executable
  content and NEVER proof of safety by possession.
- ``validation_state == VALID`` means ONLY: "the artifact bytes
  passed deterministic contract/safety validation". It does NOT
  mean the target is vulnerable, the scope is authorized, or the
  artifact is approved for execution.
- Artifact content is separate from the reference. The reference
  binds content via SHA-256 over exact bytes; one changed byte
  yields a different hash and a different identity.
- Identity (``artifact_id``) binds artifact type + TestPlan +
  content hash + schema version. Hostile metadata (model names,
  prompt versions, timestamps, labels) is audit-only and NEVER
  enters identity.

Closed vocabularies (fail closed, no "other" escape hatch):

- ``ArtifactType``: ``nuclei_template`` | ``xss_payload`` |
  ``http_request_spec``.
- ``ValidationState``: ``UNVALIDATED`` | ``VALID`` | ``REJECTED``.

There are deliberately NO verdict-valued states (``CONFIRMED``,
``EXPLOITED``, ``VULNERABLE``) and NO authorization fields
(``scope_allowed``, ``execution_allowed``); unknown extras are
rejected by ``extra="forbid"``.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "artifact/v1"

ArtifactType = Literal[
    "nuclei_template",
    "xss_payload",
    "http_request_spec",
]

ValidationState = Literal[
    "UNVALIDATED",
    "VALID",
    "REJECTED",
]

# Conservative deterministic size limits (raw artifact bytes).
# Chosen against existing Watch contracts (single-line labels are
# <=512 chars, prose <=2048, explanations <=4096): a Nuclei template
# carrying a raw request plus matchers fits comfortably under 32KiB,
# an XSS payload under 4KiB, and an HTTP request spec under 16KiB.
# Anything larger is rejected fail-closed.
MAX_NUCLEI_TEMPLATE_BYTES = 32768
MAX_XSS_PAYLOAD_BYTES = 4096
MAX_HTTP_ARTIFACT_BYTES = 16384

MAX_ARTIFACT_BYTES_BY_TYPE: dict[str, int] = {
    "nuclei_template": MAX_NUCLEI_TEMPLATE_BYTES,
    "xss_payload": MAX_XSS_PAYLOAD_BYTES,
    "http_request_spec": MAX_HTTP_ARTIFACT_BYTES,
}

_ART_ID_RE = re.compile(r"^art-[0-9a-f]{16}$")
_TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")
_HYP_ID_RE = re.compile(r"^hyp-[0-9a-f]{16}$")
_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash_for_bytes(content: bytes) -> str:
    """SHA-256 over the exact artifact bytes.

    ``content_hash = SHA256(canonical artifact bytes)``. Raw
    control inputs (timestamps, paths, model metadata, prompts,
    environment) are NEVER hashed: only the artifact bytes enter
    the digest. The same bytes always yield the same hash; a
    one-byte change yields a different hash.
    """

    if not isinstance(content, (bytes, bytearray)):
        raise TypeError(
            "content_hash_for_bytes accepts only bytes, not "
            f"{type(content).__name__}"
        )
    return _sha256_hex(bytes(content))


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def content_hash_for_mapping(payload: dict) -> str:
    """SHA-256 over the canonical JSON of a mapping.

    Canonical form is ``json.dumps(sort_keys=True,
    separators=(",", ":"), ensure_ascii=False)`` encoded as UTF-8.
    Key order and nesting order therefore never affect the digest:
    validation is independent of dictionary/input order.
    """

    if not isinstance(payload, dict):
        raise TypeError(
            "content_hash_for_mapping accepts only dict, not "
            f"{type(payload).__name__}"
        )
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def artifact_id_for(
    *,
    artifact_type: str,
    test_plan_id: str,
    content_hash: str,
    schema_version: str = SCHEMA_VERSION,
) -> str:
    """Deterministic artifact identity.

    ``artifact_id = "art-" + SHA256(artifact_type + test_plan_id +
    content_hash + schema_version)[:16]``. No UUIDs, no randomness,
    no filesystem names, no timestamps, no model metadata. The same
    (type, plan, content, version) tuple always yields the same id;
    a different TestPlan yields a different identity even for
    identical bytes (plan binding is structural).
    """

    basis = _canonical_json(
        {
            "artifact_type": artifact_type,
            "content_hash": content_hash,
            "schema_version": schema_version,
            "test_plan_id": test_plan_id,
        }
    )
    return "art-" + _sha256_hex(basis.encode("utf-8"))[:16]


def max_bytes_for(artifact_type: str) -> int:
    """Size limit for one closed artifact type (fail closed)."""

    try:
        return MAX_ARTIFACT_BYTES_BY_TYPE[artifact_type]
    except KeyError:
        raise ValueError(f"unknown artifact_type: {artifact_type!r}") from None


class ArtifactReference(BaseModel):
    """Hash-bound, TestPlan-bound pointer to future artifact bytes.

    In-memory metadata only. The artifact bytes themselves are NOT
    embedded and are NEVER executed. ``validation_state`` records
    the outcome of deterministic contract/safety validation:

    - ``UNVALIDATED``: no validation has been performed.
    - ``VALID``: the bytes passed deterministic contract/safety
      validation (NOT a vulnerability verdict, NOT scope
      authorization, NOT execution authorization).
    - ``REJECTED``: the bytes failed validation fail-closed.

    Provenance (``hypothesis_id`` / ``match_id`` /
    ``snapshot_hash``) is descriptive audit data copied from the
    bound TestPlan, never manufactured, and never authority.
    """

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    artifact_type: ArtifactType
    content_hash: str
    test_plan_id: str
    hypothesis_id: str | None = None
    match_id: str | None = None
    snapshot_hash: str | None = None
    artifact_schema_version: Literal["artifact/v1"] = "artifact/v1"
    validation_state: ValidationState = "UNVALIDATED"
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("artifact_id")
    @classmethod
    def _art_id(cls, value: str) -> str:
        if not _ART_ID_RE.match(value or ""):
            raise ValueError(f"invalid artifact_id: {value!r}")
        return value

    @field_validator("content_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid content_hash: {value!r}")
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

    @field_validator("snapshot_hash")
    @classmethod
    def _snapshot(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid snapshot_hash: {value!r}")
        return value

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if not isinstance(value, dict):
            raise ValueError("metadata must be a string map")
        for key, item in value.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise ValueError("metadata keys and values must be strings")
            if len(key) > 128 or len(item) > 512:
                raise ValueError("metadata entry exceeds size limit")
            if "\n" in key or "\r" in key or "\n" in item or "\r" in item:
                raise ValueError("metadata must be single-line")
        # Hostile metadata must never become authority: verdict or
        # authorization keys are rejected fail-closed.
        forbidden = {
            "verdict", "confirmed", "vulnerable", "exploited",
            "scope_allowed", "execution_allowed", "authorized",
            "finding", "evidence",
        }
        for key in value:
            if key.casefold() in forbidden:
                raise ValueError(
                    f"metadata key is not permitted: {key!r}"
                )
        return value

    @model_validator(mode="after")
    def _identity_consistency(self) -> "ArtifactReference":
        expected = artifact_id_for(
            artifact_type=self.artifact_type,
            test_plan_id=self.test_plan_id,
            content_hash=self.content_hash,
            schema_version=self.artifact_schema_version,
        )
        if self.artifact_id != expected:
            raise ValueError(
                "artifact_id must be the deterministic alias of "
                "(artifact_type, test_plan_id, content_hash, "
                "schema_version)"
            )
        return self


def build_artifact_reference(
    *,
    artifact_type: str,
    content: bytes,
    test_plan_id: str,
    hypothesis_id: str | None = None,
    match_id: str | None = None,
    snapshot_hash: str | None = None,
    validation_state: str = "UNVALIDATED",
    metadata: dict[str, str] | None = None,
) -> ArtifactReference:
    """Deterministic factory: same (type, bytes, plan) → same id.

    ``metadata`` is audit-only and excluded from identity: hostile
    or reordered metadata cannot change ``artifact_id``. Size is
    enforced here fail-closed (oversized bytes raise ``ValueError``).
    """

    if not isinstance(content, (bytes, bytearray)):
        raise TypeError(
            "build_artifact_reference accepts only bytes content, "
            f"not {type(content).__name__}"
        )
    limit = max_bytes_for(artifact_type)  # fail closed on unknown type
    if len(content) > limit:
        raise ValueError(
            f"artifact content exceeds {limit} bytes for "
            f"{artifact_type!r} ({len(content)} bytes)"
        )
    digest = content_hash_for_bytes(bytes(content))
    return ArtifactReference(
        artifact_id=artifact_id_for(
            artifact_type=artifact_type,
            test_plan_id=test_plan_id,
            content_hash=digest,
        ),
        artifact_type=artifact_type,  # type: ignore[arg-type]
        content_hash=digest,
        test_plan_id=test_plan_id,
        hypothesis_id=hypothesis_id,
        match_id=match_id,
        snapshot_hash=snapshot_hash,
        validation_state=validation_state,  # type: ignore[arg-type]
        metadata=dict(metadata or {}),
    )


__all__ = [
    "SCHEMA_VERSION",
    "MAX_ARTIFACT_BYTES_BY_TYPE",
    "MAX_HTTP_ARTIFACT_BYTES",
    "MAX_NUCLEI_TEMPLATE_BYTES",
    "MAX_XSS_PAYLOAD_BYTES",
    "ArtifactReference",
    "ArtifactType",
    "ValidationState",
    "artifact_id_for",
    "build_artifact_reference",
    "content_hash_for_bytes",
    "content_hash_for_mapping",
    "max_bytes_for",
]
