"""Hypothesis data contract (Phase 1).

A Hypothesis is UNTRUSTED pre-verification intent:

- It NEVER owns scope, execution, evidence, or verdicts.
- It NEVER contains CONFIRMED / NOT_VULNERABLE / VERIFIED semantics.
- It is a proposal generated from research-derived patterns against a
  specific Watch target, validated deterministically by this schema.

Identity follows the KnowledgeStore convention (see AGENTS.md): the
deterministic idempotency key is the full SHA-256 over the canonical
hypothesis basis, and ``hypothesis_id`` is its short human-readable
alias (``hyp-`` + first 16 hex chars). LLM metadata is audit metadata
only and is EXCLUDED from identity so the same logical hypothesis from
any provider/model deduplicates to one key.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


SCHEMA_VERSION = "hypothesis/v1"

HypothesisStatus = Literal["PROPOSED", "SUPERSEDED", "CANCELLED"]

HypothesisType = Literal[
    "vulnerability_relevance",
    "technique_relevance",
    "technology_relevance",
    "attack_surface",
]

PatternKind = Literal[
    "cve",
    "ghsa",
    "technique",
    "knowledge_claim",
    "writeup",
]

_KB_ID_RE = re.compile(r"^kb-[0-9a-f]{16}$")
_SRC_ID_RE = re.compile(r"^src-[0-9a-f]{16}$")
_CLM_ID_RE = re.compile(r"^clm-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HYP_ID_RE = re.compile(r"^hyp-[0-9a-f]{16}$")
_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_text(value: str) -> str:
    """Deterministic basis normalization (NFKC + casefold + collapse).

    Mirrors the semantics of ``ai.ingestion.grounding`` matching for
    identity purposes without creating a schema→ingestion layer
    dependency. Equal logical statements MUST normalize equally so
    idempotency holds across providers, whitespace, and casing.
    """

    folded = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(folded.split())


def hypothesis_idempotency_key(
    *,
    program_name: str,
    subdomain: str,
    endpoint: str,
    hypothesis_type: str,
    statement: str,
    pattern_kind: str,
    pattern_id: str,
    knowledge_ids: list[str],
    source_ids: list[str],
    claim_ids: list[str],
    research_hashes: list[str],
    match_id: str = "",
    snapshot_hash: str = "",
) -> str:
    """Full SHA-256 idempotency key over the canonical hypothesis basis.

    The basis binds target + type + normalized statement + pattern +
    sorted provenance. LLM metadata, priority, timestamps, and status
    are deliberately EXCLUDED so retries, re-runs, and cross-provider
    duplicates resolve to one key.

    Phase 4A addition: ``match_id`` (a ``tm-…`` deterministic match
    alias) and ``snapshot_hash`` (the bound target-observation state)
    join the basis WHEN PROVIDED, so the same pattern against the
    same target at two different snapshots yields two distinct
    identities. Both default to ``""`` and are OMITTED from the
    canonical basis when empty, so every key computed by
    pre-existing callers reproduces byte-for-byte.
    """

    canonical = {
        "endpoint": endpoint,
        "hypothesis_type": hypothesis_type,
        "pattern_id": pattern_id,
        "pattern_kind": pattern_kind,
        "program_name": program_name,
        "statement": _normalize_text(statement),
        "subdomain": subdomain,
        "claim_ids": sorted(claim_ids),
        "knowledge_ids": sorted(knowledge_ids),
        "research_hashes": sorted(research_hashes),
        "source_ids": sorted(source_ids),
    }
    if match_id:
        canonical["match_id"] = match_id
    if snapshot_hash:
        canonical["snapshot_hash"] = snapshot_hash
    return _sha256_hex(_canonical_json(canonical))


def hypothesis_id_from_key(key: str) -> str:
    """Short human-readable alias for a full idempotency key."""

    return "hyp-" + key[:16]


class TargetRef(BaseModel):
    """Canonical Watch target reference (descriptive, non-authoritative).

    Mirrors ``ai.schemas.http.HTTPAsset`` identity fields without
    importing recon schemas. The eventual matcher supplies the
    authoritative target; an LLM-provided target here is advisory only.
    ``technology_snapshot`` records the immutable recon observation the
    hypothesis was built against so it stays auditable after the target
    changes.
    """

    model_config = ConfigDict(extra="forbid")

    program_name: str
    subdomain: str
    scope: str = ""
    endpoint: str = ""
    technology_snapshot: list[str] = Field(default_factory=list)
    observed_at: str | None = None

    @field_validator("program_name", "subdomain")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value


class ResearchProvenance(BaseModel):
    """Stable provenance back to research items and claims.

    Uses the KnowledgeStore identity formats (``kb-…``, ``src-…``,
    ``clm-…`` full content hashes for raw items) so no second
    incompatible provenance system is invented. Free-form URLs alone
    are NOT accepted: every entry must be a stable ID or hash.
    At least one reference is required.
    """

    model_config = ConfigDict(extra="forbid")

    knowledge_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    claim_ids: list[str] = Field(default_factory=list)
    research_hashes: list[str] = Field(default_factory=list)

    @field_validator("knowledge_ids")
    @classmethod
    def _kb_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _KB_ID_RE.match(value or ""):
                raise ValueError(
                    f"invalid knowledge_id: {value!r}"
                )
        return values

    @field_validator("source_ids")
    @classmethod
    def _src_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _SRC_ID_RE.match(value or ""):
                raise ValueError(f"invalid source_id: {value!r}")
        return values

    @field_validator("claim_ids")
    @classmethod
    def _clm_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _CLM_ID_RE.match(value or ""):
                raise ValueError(f"invalid claim_id: {value!r}")
        return values

    @field_validator("research_hashes")
    @classmethod
    def _hashes(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _SHA256_RE.match(value or ""):
                raise ValueError(
                    f"invalid research_hash: {value!r}"
                )
        return values

    @model_validator(mode="after")
    def _at_least_one(self) -> "ResearchProvenance":
        if not (
            self.knowledge_ids
            or self.source_ids
            or self.claim_ids
            or self.research_hashes
        ):
            raise ValueError(
                "provenance requires at least one stable reference"
            )
        return self


class LLMMetadata(BaseModel):
    """Audit metadata for AI-generated content. Non-authoritative.

    These fields MUST NEVER influence verification authority,
    idempotency, scope, or verdicts. They exist so a future finding
    can answer "which model and prompt produced this hypothesis".
    """

    model_config = ConfigDict(extra="forbid")

    provider: str = ""
    model: str = ""
    prompt_version: str = ""
    generated_at: str | None = None
    request_id: str | None = None


class Hypothesis(BaseModel):
    """A pre-verification security hypothesis. Untrusted intent only.

    Lifecycle is pre-verification: PROPOSED → SUPERSEDED / CANCELLED.
    There is deliberately NO verdict-valued state; APPROVED-like and
    CONFIRMED-like values are rejected by the ``HypothesisStatus``
    literal. A Hypothesis can describe what evidence WOULD support it
    but can never assert that evidence exists.
    """

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    idempotency_key: str
    target: TargetRef
    hypothesis_type: HypothesisType
    statement: str
    pattern_kind: PatternKind
    pattern_id: str
    # Phase 4A match binding (optional, additive). When set, these
    # identify the exact deterministic TargetPatternMatch
    # (``tm-…``) and target-observation snapshot (full SHA-256)
    # this hypothesis was derived from. They are descriptive audit
    # pointers, NOT authority: scope and execution still require
    # independent re-resolution. ``None`` preserves the pre-4A
    # shape for hypotheses built without a bound match.
    match_id: str | None = None
    snapshot_hash: str | None = None
    provenance: ResearchProvenance
    priority: float = Field(default=0.0, ge=0.0, le=1.0)
    priority_basis: str = ""
    status: HypothesisStatus = "PROPOSED"
    supersedes: str | None = None
    cancel_reason: str | None = None
    llm: LLMMetadata = Field(default_factory=LLMMetadata)
    schema_version: Literal["hypothesis/v1"] = "hypothesis/v1"
    created_at: str = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    @field_validator("hypothesis_id")
    @classmethod
    def _hyp_id(cls, value: str) -> str:
        if not _HYP_ID_RE.match(value or ""):
            raise ValueError(
                f"invalid hypothesis_id: {value!r}"
            )
        return value

    @field_validator("idempotency_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(
                f"invalid idempotency_key: {value!r}"
            )
        return value

    @field_validator("statement", "pattern_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
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
    def _snapshot_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid snapshot_hash: {value!r}")
        return value

    @field_validator("supersedes")
    @classmethod
    def _supersedes_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HYP_ID_RE.match(value):
            raise ValueError(f"invalid supersedes: {value!r}")
        return value

    @model_validator(mode="after")
    def _lifecycle_consistency(self) -> "Hypothesis":
        if self.status == "SUPERSEDED" and not self.supersedes:
            raise ValueError(
                "SUPERSEDED requires supersedes hypothesis_id"
            )
        if self.status == "CANCELLED" and not (
            self.cancel_reason and self.cancel_reason.strip()
        ):
            raise ValueError(
                "CANCELLED requires cancel_reason"
            )
        if self.hypothesis_id != hypothesis_id_from_key(
            self.idempotency_key
        ):
            raise ValueError(
                "hypothesis_id must be the alias of idempotency_key"
            )
        return self


def build_hypothesis(
    *,
    target: TargetRef,
    hypothesis_type: str,
    statement: str,
    pattern_kind: str,
    pattern_id: str,
    provenance: ResearchProvenance,
    priority: float = 0.0,
    priority_basis: str = "",
    llm: LLMMetadata | None = None,
    created_at: str | None = None,
    match_id: str | None = None,
    snapshot_hash: str | None = None,
) -> Hypothesis:
    """Deterministic factory: same logical basis → same identity.

    The idempotency key binds target + type + normalized statement +
    pattern + sorted provenance. LLM metadata and priority are
    recorded but excluded from identity. When ``match_id`` /
    ``snapshot_hash`` are provided they join the key basis, so the
    same pattern against different target snapshots cannot collide;
    when omitted the key reproduces the pre-4A basis exactly.
    """

    key = hypothesis_idempotency_key(
        program_name=target.program_name,
        subdomain=target.subdomain,
        endpoint=target.endpoint,
        hypothesis_type=hypothesis_type,
        statement=statement,
        pattern_kind=pattern_kind,
        pattern_id=pattern_id,
        knowledge_ids=list(provenance.knowledge_ids),
        source_ids=list(provenance.source_ids),
        claim_ids=list(provenance.claim_ids),
        research_hashes=list(provenance.research_hashes),
        match_id=match_id or "",
        snapshot_hash=snapshot_hash or "",
    )
    return Hypothesis(
        hypothesis_id=hypothesis_id_from_key(key),
        idempotency_key=key,
        target=target,
        hypothesis_type=hypothesis_type,  # type: ignore[arg-type]
        statement=statement,
        pattern_kind=pattern_kind,  # type: ignore[arg-type]
        pattern_id=pattern_id,
        match_id=match_id,
        snapshot_hash=snapshot_hash,
        provenance=provenance,
        priority=priority,
        priority_basis=priority_basis,
        llm=llm or LLMMetadata(),
        **(
            {"created_at": created_at}
            if created_at is not None
            else {}
        ),
    )


__all__ = [
    "SCHEMA_VERSION",
    "Hypothesis",
    "HypothesisStatus",
    "HypothesisType",
    "LLMMetadata",
    "PatternKind",
    "ResearchProvenance",
    "TargetRef",
    "build_hypothesis",
    "hypothesis_id_from_key",
    "hypothesis_idempotency_key",
]
