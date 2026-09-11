from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


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
    # Stage R12: deterministic vulnerability-intelligence dimensions.
    # Optional additive metadata; empty by default; never a verdict.
    vulnerability_types: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    # Stage R14: vulnerable component/file/endpoint evidence.
    components: list[str] = Field(default_factory=list)
    evidence_quality: str = "UNKNOWN"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)


class KnowledgeIntelligenceEvidence(BaseModel):
    """Provenance trace for one extracted intelligence value."""

    field: str
    value: str
    source_artifact: str
    source_url: str | None = None
    source_type: str
    evidence: str
    rule_id: str
    rule_version: str


class KnowledgeCvssExploitability(BaseModel):
    """Structured CVSS-derived exploitability metrics (never a score).

    Values are the raw CVSS metric letters, or ``"unknown"`` when no
    structured/prose vector supplied them. No score is ever computed.
    """

    attack_vector: str = "unknown"
    attack_complexity: str = "unknown"
    attack_requirements: str = "unknown"
    privileges_required: str = "unknown"
    user_interaction: str = "unknown"
    # Which provenance class produced the structured fields.
    source: str = "unknown"


class KnowledgeExploitability(BaseModel):
    """Stage R15: additive, evidence-backed exploitability projection.

    Every value is a deterministic tri-state (``"true"``/``"false"``/
    ``"unknown"``) or ``"unknown"``; exploit_complexity additionally allows
    ``"low"``/``"high"``. ``conflicts`` records claim fields with genuinely
    conflicting evidence (aggregate value then resolves to ``"unknown"``
    unless a structured source wins). Never a verdict, never a finding.
    """

    authentication_required: str = "unknown"
    privilege_required: str = "unknown"
    user_interaction_required: str = "unknown"
    exploit_available: str = "unknown"
    public_poc: str = "unknown"
    active_exploitation: str = "unknown"
    exploit_complexity: str = "unknown"

    cvss: KnowledgeCvssExploitability = Field(
        default_factory=KnowledgeCvssExploitability
    )
    conflicts: list[str] = Field(default_factory=list)
    exploitability_evidence: list[KnowledgeIntelligenceEvidence] = Field(
        default_factory=list
    )


class KnowledgeResearchPriority(BaseModel):
    """Stage R16: additive, explainable research-priority projection.

    ``priority`` is a research-attention class
    (CRITICAL_RESEARCH/HIGH_RESEARCH/MEDIUM_RESEARCH/LOW_RESEARCH/
    INSUFFICIENT_DATA) — never "exploitable"/"verified"/"confirmed".
    ``score`` is a bounded 0-100 sum of explicit rules. Deterministic and
    backward compatible: every field has a safe default.
    """

    priority: str = "INSUFFICIENT_DATA"
    score: int = 0
    reasons: list[str] = Field(default_factory=list)
    negative_factors: list[str] = Field(default_factory=list)
    unknown_factors: list[str] = Field(default_factory=list)
    evidence: list[KnowledgeIntelligenceEvidence] = Field(default_factory=list)
    rule_version: str = "r16-1"


class KnowledgeAssetRelevance(BaseModel):
    """Stage R17: additive, explainable asset/program relevance projection.

    ``relevance`` is a research-relevance class
    (HIGH/MEDIUM/LOW/NONE/UNKNOWN) — never "vulnerable"/"exploitable"/
    "verified"/"confirmed". ``score`` is a bounded 0-100 sum of explicit
    deterministic match rules. Defaults to UNKNOWN so pre-R17 documents stay
    readable.
    """

    relevance: str = "UNKNOWN"
    score: int = 0
    reasons: list[str] = Field(default_factory=list)
    matched_assets: list[str] = Field(default_factory=list)
    matched_programs: list[str] = Field(default_factory=list)
    unknown_factors: list[str] = Field(default_factory=list)
    evidence: list[KnowledgeIntelligenceEvidence] = Field(default_factory=list)
    rule_version: str = "r17-1"


class KnowledgeResearchQueueItem(BaseModel):
    """Stage R18: additive deterministic research-queue item (CVE x program).

    RESEARCH ATTENTION ONLY — never a target-vulnerability statement. Combines
    the R16 research-priority score and the R17 asset-relevance score into a
    bounded 0-100 ``queue_score`` with explicit reasons, blockers, and unknown
    factors. Standalone (not attached to a document): one item per
    deterministic CVE/program candidate.
    """

    queue_id: str
    cve: str
    program: str
    priority_class: str = "INSUFFICIENT_DATA"
    priority_score: int = 0
    relevance: str = "UNKNOWN"
    relevance_score: int = 0
    queue_score: int = 0
    rank: int = 0
    reasons: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    unknown_factors: list[str] = Field(default_factory=list)
    evidence: list[KnowledgeIntelligenceEvidence] = Field(default_factory=list)
    rule_version: str = "r18-1"


class KnowledgeEconomicValue(BaseModel):
    """Stage R25.2 additive deterministic economic research-prioritization.

    Research-attention only — never a vulnerability verdict, never a payout
    prediction, never a finding. Composes existing R15-R24 outputs into a
    bounded 0-100 Money Score with VALUE/CONFIDENCE/EFFORT/RISK subscores.
    Standalone (not attached to a document): one item per lead. ``research_only``
    is forced True; ``rule_version`` is fixed ``r25-1``.
    """

    cve_id: str = ""
    program: str = ""
    lead_id: str = ""
    plan_id: str = ""
    queue_id: str = ""
    task_id: str = ""
    money_score: int = Field(default=0, ge=0, le=100)
    priority: str = "P5_DEFER"
    confidence: str = "LOW"
    confidence_basis: list[str] = Field(default_factory=list)
    effort: int = Field(default=0, ge=0, le=100)
    effort_estimate: str = ""
    asset_match: str = "NONE"
    why_valuable: list[str] = Field(default_factory=list)
    main_blockers: list[str] = Field(default_factory=list)
    recommended_action: str = "DEFER"
    subscores: dict = Field(default_factory=dict)
    evidence_summary: dict = Field(default_factory=dict)
    caps_applied: list[str] = Field(default_factory=list)
    rule_version: str = "r25-1"
    research_only: bool = Field(default=True, frozen=False)

    @field_validator("research_only")
    @classmethod
    def _force_research_only(cls, value: bool) -> bool:
        # Money Score is research prioritization only; never a verdict.
        return True


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
    # Stage R12: deterministic vulnerability-intelligence dimensions.
    vulnerability_types: list[KnowledgeAttributedValue] = Field(default_factory=list)
    cwes: list[KnowledgeAttributedValue] = Field(default_factory=list)
    parameters: list[KnowledgeAttributedValue] = Field(default_factory=list)
    # Stage R14: vulnerable component/file/endpoint evidence.
    components: list[KnowledgeAttributedValue] = Field(default_factory=list)
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

    # Stage R12: deterministic vulnerability-intelligence dimensions.
    # Optional additive metadata surfaced from evidence-backed
    # extraction; empty by default; never a verdict.
    vulnerability_types: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    # Stage R14: vulnerable component/file/endpoint evidence.
    components: list[str] = Field(default_factory=list)

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

    # Stage R12: bounded, verbatim provenance trace for extracted
    # intelligence values above. Additive metadata only; never consumed
    # as a verdict by any agent.
    intelligence_evidence: list[KnowledgeIntelligenceEvidence] = Field(
        default_factory=list
    )

    # Stage R15: additive deterministic exploitability projection. Defaults
    # to all-unknown + empty evidence, so pre-R15 documents stay readable.
    exploitability: KnowledgeExploitability = Field(
        default_factory=KnowledgeExploitability
    )

    # Stage R16: additive deterministic research-priority projection.
    # Defaults to INSUFFICIENT_DATA, so pre-R16 documents stay readable.
    research_priority: KnowledgeResearchPriority = Field(
        default_factory=KnowledgeResearchPriority
    )

    # Stage R17: additive deterministic asset/program relevance projection.
    # Defaults to UNKNOWN, so pre-R17 documents stay readable.
    asset_relevance: KnowledgeAssetRelevance = Field(
        default_factory=KnowledgeAssetRelevance
    )

    provenance: list[KnowledgeProvenance] = Field(default_factory=list)
    aggregate: KnowledgeAggregate = Field(default_factory=KnowledgeAggregate)

    indexed_at: str = Field(
        default_factory=lambda:
        datetime.now(
            timezone.utc
        ).isoformat()
    )
