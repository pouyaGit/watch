from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class KnowledgeSourceClaims(BaseModel):
    """Security-relevant claims made by one source about this content."""

    claim_id: str | None = None
    title: str | None = None
    summary: str | None = None
    technologies: list[str] = Field(default_factory=list)
    xss_types: list[str] = Field(default_factory=list)
    contexts: list[str] = Field(default_factory=list)
    wafs: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    payload_patterns: list[str] = Field(default_factory=list)
    verification_patterns: list[str] = Field(default_factory=list)
    evidence_quality: str = "UNKNOWN"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)


class KnowledgeProvenance(BaseModel):
    """One source identity and its independently attributable claims."""

    source_id: str | None = None
    source_url: str
    source_type: str
    published_at: str | None = None
    ingested_at: str | None = None

    # Retained to parse the first KnowledgeDocument schema. For new data,
    # title belongs to claims and this field is legacy source metadata only.
    title: str | None = None

    claims: list[KnowledgeSourceClaims] = Field(default_factory=list)


class KnowledgeAttributedValue(BaseModel):
    """A retrieval value and every source that contributed it."""

    value: str
    source_ids: list[str] = Field(default_factory=list)


class KnowledgeConfidenceAttribution(BaseModel):
    """A confidence/evidence pair without a synthesized global verdict."""

    source_id: str
    claim_id: str
    evidence_quality: str
    confidence: float = Field(ge=0.0, le=1.0)


class KnowledgeAggregate(BaseModel):
    """Derived deterministic retrieval projection; never authoritative."""

    titles: list[KnowledgeAttributedValue] = Field(default_factory=list)
    summaries: list[KnowledgeAttributedValue] = Field(default_factory=list)
    technologies: list[KnowledgeAttributedValue] = Field(default_factory=list)
    xss_types: list[KnowledgeAttributedValue] = Field(default_factory=list)
    contexts: list[KnowledgeAttributedValue] = Field(default_factory=list)
    wafs: list[KnowledgeAttributedValue] = Field(default_factory=list)
    techniques: list[KnowledgeAttributedValue] = Field(default_factory=list)
    payload_patterns: list[KnowledgeAttributedValue] = Field(default_factory=list)
    verification_patterns: list[KnowledgeAttributedValue] = Field(
        default_factory=list
    )
    tags: list[KnowledgeAttributedValue] = Field(default_factory=list)
    source_confidence: list[KnowledgeConfidenceAttribution] = Field(
        default_factory=list
    )


class KnowledgeDocument(BaseModel):
    """
    One trusted knowledge-base document.

    The document can originate from a public research source,
    write-up, advisory, GitHub research, lab or other source.
    """

    # Missing from legacy JSON. The store migrates version 1 on ingestion.
    schema_version: int = 1

    knowledge_id: str

    title: str
    source_url: str

    source_type: str

    published_at: str | None = None

    # Legacy compatibility projection. New readers use provenance/aggregate;
    # these fields are not global security truth.
    technologies: list[str] = Field(default_factory=list)
    xss_types: list[str] = Field(default_factory=list)
    contexts: list[str] = Field(default_factory=list)
    wafs: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    payload_patterns: list[str] = Field(default_factory=list)
    verification_patterns: list[str] = Field(default_factory=list)

    content: str

    summary: str | None = None

    evidence_quality: str = "UNKNOWN"
    # PRIMARY
    # HIGH_CONFIDENCE
    # SECONDARY
    # UNVERIFIED

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    tags: list[str] = Field(default_factory=list)

    content_hash: str | None = None

    provenance: list[KnowledgeProvenance] = Field(default_factory=list)
    aggregate: KnowledgeAggregate = Field(default_factory=KnowledgeAggregate)

    indexed_at: str = Field(
        default_factory=lambda:
        datetime.now(
            timezone.utc
        ).isoformat()
    )
