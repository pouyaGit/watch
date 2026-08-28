from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ai.ingestion.grounding import contains_forbidden
from ai.schemas.knowledge import KnowledgeSourceClaims

EvidenceClass = Literal[
    "EXPLICIT",
    "STRONGLY_IMPLIED",
    "MODEL_INFERENCE",
]


class IngestionError(Exception):
    """Raised on schema-level ingestion failures."""


class SourceDocument(BaseModel):
    """
    An already-acquired research source handed to the ingestion
    layer.

    The ingestion layer does not perform web requests, crawling,
    or downloading. ``content`` is the full fetched text
    supplied by the caller; the agent is responsible for
    grounding every extracted claim against this text.
    """

    title: str
    source_url: str
    source_type: str
    published_at: str | None = None
    content: str

    tags: list[str] = Field(default_factory=list)


class EvidenceSnippet(BaseModel):
    """
    A short verbatim excerpt from the source document that
    supports a claim.

    The snippet is intentionally coarse: it is the textual
    fragment the LLM relied on, with a coarse section label
    rather than a brittle character offset. The agent layer
    verifies that every snippet is present in the source
    content via :func:`ai.ingestion.grounding.value_grounded`.
    """

    text: str
    section: str | None = None

    @field_validator("text")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "EvidenceSnippet.text must be non-empty"
            )
        return value


class ExtractedClaim(BaseModel):
    """
    One security claim extracted from a :class:`SourceDocument`.

    The shape deliberately mirrors :class:`KnowledgeSourceClaims`
    so a future agent layer can project one onto the other
    without inventing a second competing representation.
    """

    evidence_class: EvidenceClass
    rationale: str = ""

    evidence_snippets: list[EvidenceSnippet] = Field(
        default_factory=list
    )

    title: str | None = None
    summary: str | None = None

    technologies: list[str] = Field(default_factory=list)
    xss_types: list[str] = Field(default_factory=list)
    contexts: list[str] = Field(default_factory=list)
    wafs: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    payload_patterns: list[str] = Field(default_factory=list)
    verification_patterns: list[str] = Field(
        default_factory=list
    )
    tags: list[str] = Field(default_factory=list)

    evidence_quality: str = "UNVERIFIED"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    forbidden_values: list[str] = Field(
        default_factory=list,
        description=(
            "Values that were rejected by the agent's "
            "forbidden-payload scan. Surfaced for audit; "
            "never silently dropped."
        ),
    )

    strict_payloads: bool = Field(
        default=True,
        description=(
            "If True (the default), executable payload "
            "constructs in payload_patterns / "
            "verification_patterns / evidence_snippets raise "
            "IngestionError instead of being accepted."
        ),
    )

    @model_validator(mode="after")
    def _reject_empty_claim(self) -> "ExtractedClaim":
        has_payload = (
            self.title
            or self.summary
            or self.technologies
            or self.xss_types
            or self.contexts
            or self.wafs
            or self.techniques
            or self.payload_patterns
            or self.verification_patterns
            or self.tags
            or self.evidence_snippets
        )
        if not has_payload:
            raise IngestionError(
                "ExtractedClaim must carry at least one "
                "non-empty field (title, summary, list, or "
                "evidence_snippets); empty claims are not "
                "accepted."
            )
        return self

    @model_validator(mode="after")
    def _enforce_confidence_band(self) -> "ExtractedClaim":
        band = _CONFIDENCE_BANDS.get(self.evidence_class)
        if band is None:
            return self
        low, high = band
        if not (low <= self.confidence <= high):
            raise IngestionError(
                f"ExtractedClaim.confidence={self.confidence} "
                f"is outside the band for evidence_class="
                f"{self.evidence_class!r} "
                f"(expected {low}..{high})"
            )
        return self

    @model_validator(mode="after")
    def _reject_executable_payloads(self) -> "ExtractedClaim":
        offenders: list[str] = []

        for value in self.payload_patterns:
            if contains_forbidden(value):
                offenders.append(value)
        for value in self.verification_patterns:
            if contains_forbidden(value):
                offenders.append(value)
        for snippet in self.evidence_snippets:
            if contains_forbidden(snippet.text):
                offenders.append(snippet.text)

        if not offenders:
            return self

        if self.strict_payloads:
            raise IngestionError(
                "ExtractedClaim contains forbidden executable "
                f"payload construct(s): {offenders!r}"
            )

        # Non-strict path: surface the offenders for audit so
        # the agent layer can quarantine them. We merge with
        # any forbidden_values the caller pre-populated.
        merged = list(self.forbidden_values)
        for offender in offenders:
            if offender not in merged:
                merged.append(offender)
        object.__setattr__(self, "forbidden_values", merged)
        return self

    def projected_evidence_quality(self) -> str:
        """
        Map the agent-side ``evidence_class`` to a
        KnowledgeStore-compatible ``evidence_quality`` value.

        This is a *projection*: it must be applied by the
        agent layer when building a :class:`KnowledgeSourceClaims`
        so the LLM cannot pick a higher-quality label than
        its evidence class warrants.
        """

        return _EVIDENCE_QUALITY_BY_CLASS[self.evidence_class]

    def to_knowledge_source_claims(self) -> KnowledgeSourceClaims:
        """
        Project this claim onto the existing
        :class:`KnowledgeSourceClaims` shape used by
        :class:`KnowledgeStore`.

        The agent layer should call this only after grounding
        validation has passed.
        """

        return KnowledgeSourceClaims(
            title=self.title,
            summary=self.summary,
            technologies=list(self.technologies),
            xss_types=list(self.xss_types),
            contexts=list(self.contexts),
            wafs=list(self.wafs),
            techniques=list(self.techniques),
            payload_patterns=list(self.payload_patterns),
            verification_patterns=list(
                self.verification_patterns
            ),
            evidence_quality=self.projected_evidence_quality(),
            confidence=self.confidence,
            tags=list(self.tags),
        )


_CONFIDENCE_BANDS: dict[
    EvidenceClass, tuple[float, float]
] = {
    "EXPLICIT": (0.80, 1.00),
    "STRONGLY_IMPLIED": (0.55, 0.79),
    "MODEL_INFERENCE": (0.00, 0.54),
}


_EVIDENCE_QUALITY_BY_CLASS: dict[EvidenceClass, str] = {
    "EXPLICIT": "HIGH_CONFIDENCE",
    "STRONGLY_IMPLIED": "SECONDARY",
    "MODEL_INFERENCE": "UNVERIFIED",
}


class ExtractionResult(BaseModel):
    """
    The output of one extraction pass over a :class:`SourceDocument`.

    The result carries the source identity (so the agent layer
    can re-verify the source_url / source_type pair) and the
    list of extracted claims. No LLM provider fields are
    exposed here; provider metadata belongs in the
    LLM-research layer, not in the ingestion layer.
    """

    source: SourceDocument
    claims: list[ExtractedClaim] = Field(
        default_factory=list
    )

    extraction_notes: list[str] = Field(
        default_factory=list,
        description=(
            "Non-fatal observations made during extraction, "
            "e.g. 'one claim rejected for missing snippet', "
            "'one MODEL_INFERENCE claim quarantined'."
        ),
    )

    @model_validator(mode="after")
    def _at_least_one_claim(
        cls, value: "ExtractionResult"
    ) -> "ExtractionResult":
        if not value.claims:
            raise IngestionError(
                "ExtractionResult must contain at least one "
                "ExtractedClaim; an empty result is not a "
                "valid extraction."
            )
        return value


__all__ = [
    "EvidenceClass",
    "EvidenceSnippet",
    "ExtractedClaim",
    "ExtractionResult",
    "IngestionError",
    "SourceDocument",
]
