from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class XSSContext(BaseModel):
    """
    Describes where attacker-controlled input appears.
    """

    type: str = "unknown"
    raw_reflection: str | None = None

    surrounding_text: str | None = None

    attribute_name: str | None = None
    attribute_quoted: bool | None = None

    tag_name: str | None = None

    script_context: bool = False
    javascript_context: bool = False

    html_encoded: bool = False
    url_encoded: bool = False
    js_encoded: bool = False

    notes: list[str] = Field(
        default_factory=list
    )


class XSSCase(BaseModel):
    """
    One XSS investigation case.

    A case is a hypothesis/investigation object.
    It is not a confirmed vulnerability by itself.
    """

    case_id: str

    target: str
    endpoint: str

    method: str = "GET"

    parameter: str | None = None

    parameter_location: str = "query"

    input_value: str | None = None

    xss_type: str = "unknown"
    # reflected / stored / dom / mutation / unknown

    context: XSSContext = Field(
        default_factory=XSSContext
    )

    framework: str | None = None
    technology: list[str] = Field(
        default_factory=list
    )

    waf: str | None = None

    source_type: str = "endpoint"
    # endpoint / js / html / user_supplied

    discovery_evidence: list[str] = Field(
        default_factory=list
    )

    retrieved_knowledge_ids: list[str] = Field(
        default_factory=list
    )

    status: str = "NEW"
    # NEW / ANALYZED / VERIFYING / CONFIRMED /
    # NOT_VULNERABLE / INCONCLUSIVE

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    created_at: str = Field(
        default_factory=lambda:
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    updated_at: str = Field(
        default_factory=lambda:
        datetime.now(
            timezone.utc
        ).isoformat()
    )


class XSSAttributedValue(BaseModel):
    """A retrieval value and the source_ids that contributed it."""

    value: str
    source_ids: list[str] = Field(
        default_factory=list
    )


class XSSResearchContext(BaseModel):
    """
    Deterministic XSS research projection derived from the
    local KnowledgeStore.

    No LLM inference, no network access, and no global verdict
    are represented here. Every list preserves per-value
    source attribution. Ordering is stable; timestamps are
    not used for ordering.
    """

    case_id: str

    retrieved_knowledge_ids: list[str] = Field(
        default_factory=list
    )

    documents: list["KnowledgeDocument"] = Field(
        default_factory=list
    )

    payload_patterns: list[XSSAttributedValue] = Field(
        default_factory=list
    )
    verification_patterns: list[XSSAttributedValue] = Field(
        default_factory=list
    )
    contexts: list[XSSAttributedValue] = Field(
        default_factory=list
    )
    technologies: list[XSSAttributedValue] = Field(
        default_factory=list
    )
    waf_observations: list[XSSAttributedValue] = Field(
        default_factory=list
    )


from ai.schemas.knowledge import KnowledgeDocument  # noqa: E402

XSSResearchContext.model_rebuild()


class XSSAttributedSuggestion(BaseModel):
    """
    Shared attribution structure for LLM-generated suggestions.

    The LLM must populate ``origin`` explicitly. Cross-validation
    against the supplied :class:`XSSResearchContext` enforces the
    non-empty attribution requirements for ``knowledge`` items
    and the empty-attribution invariant for ``model_generated``
    items.
    """

    origin: Literal["knowledge", "model_generated"]

    knowledge_ids: list[str] = Field(
        default_factory=list
    )
    source_ids: list[str] = Field(
        default_factory=list
    )

    based_on_pattern: str | None = None

    rationale: str = ""


class XSSSuggestedPayload(XSSAttributedSuggestion):
    """One payload pattern suggested by the LLM layer."""

    pattern: str


class XSSVerificationIdea(XSSAttributedSuggestion):
    """One verification approach suggested by the LLM layer."""

    pattern: str


class XSSContextObservation(XSSAttributedSuggestion):
    """One context-attribute observation suggested by the LLM layer."""

    observation: str


class XSSResearchLLMResult(BaseModel):
    """
    Structured result of the LLM layer over an
    :class:`XSSResearchContext`.

    The result carries no global confidence value. Every list
    item carries explicit attribution, and ``case_status_suggestion``
    is restricted to pre-confirmation states only.
    """

    case_id: str

    case_status_suggestion: Literal[
        "NEW",
        "ANALYZED",
        "VERIFYING",
        "INCONCLUSIVE",
    ]

    suggested_payloads: list[XSSSuggestedPayload] = Field(
        default_factory=list
    )
    verification_ideas: list[XSSVerificationIdea] = Field(
        default_factory=list
    )
    context_observations: list[XSSContextObservation] = Field(
        default_factory=list
    )

    next_research_questions: list[str] = Field(
        default_factory=list
    )

    evidence: list[str] = Field(
        default_factory=list
    )

    model: str | None = None
    raw_response_id: str | None = None


class XSSCandidateSourceEvidence(BaseModel):
    """One matched KB document and why it matched (Stage R3 agent)."""

    knowledge_id: str
    title: str
    score: int
    reasons: list[str] = Field(
        default_factory=list
    )


class XSSAttributedSink(BaseModel):
    """A sink/source value with the KB documents that state it."""

    value: str
    knowledge_ids: list[str] = Field(
        default_factory=list
    )


class XSSResearchCandidate(BaseModel):
    """
    Structured XSS research candidate (Stage R3 agent MVP).

    A candidate is a research hypothesis, never a confirmed
    vulnerability. ``status`` is one of ``RESEARCH_CANDIDATE``,
    ``INSUFFICIENT_EVIDENCE`` or ``REJECTED``. Pattern matches must
    never be read as exploitability claims; see ``disclaimer``.
    """

    candidate_id: str
    agent_version: str

    status: str

    query: str
    xss_type: str | None = None
    context: str | None = None
    technologies: list[str] = Field(
        default_factory=list
    )
    techniques: list[str] = Field(
        default_factory=list
    )

    source_evidence: list[XSSCandidateSourceEvidence] = Field(
        default_factory=list
    )
    vulnerability_pattern: str | None = None
    injection_context: str | None = None
    sinks: list[XSSAttributedSink] = Field(
        default_factory=list
    )
    sources: list[XSSAttributedSink] = Field(
        default_factory=list
    )
    preconditions: list[str] = Field(
        default_factory=list
    )
    test_idea: str | None = None

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    unknowns: list[str] = Field(
        default_factory=list
    )
    references: list[str] = Field(
        default_factory=list
    )

    disclaimer: str = (
        "Pattern match is NOT exploitability. "
        "No live testing was performed and no target was contacted."
    )


class XSSLLMResearchEvidence(BaseModel):
    """One evidence/inference/unknown line from the LLM research assistant.

    ``kind`` separates facts directly present in supplied Watch
    artifacts (EVIDENCE), model interpretation (INFERENCE), and facts
    that cannot be established from the supplied evidence (UNKNOWN).

    The LLM never converts inference into evidence. EVIDENCE items MUST
    carry ``knowledge_ids`` drawn from the supplied KB evidence;
    INFERENCE/UNKNOWN items MUST NOT carry attribution (they are model
    reasoning, not sourced facts).
    """

    kind: Literal["EVIDENCE", "INFERENCE", "UNKNOWN"]
    text: str
    knowledge_ids: list[str] = Field(default_factory=list)


class XSSLLMResearchAssistantResult(BaseModel):
    """Structured research explanation from the LLM research assistant.

    Consumed AFTER the deterministic :class:`XSSResearchCandidate`,
    which remains authoritative for status and confidence. ``status``
    and ``confidence`` here MUST mirror the deterministic candidate
    exactly; the LLM cannot upgrade or downgrade them. ``references_used``
    must be a subset of the supplied KB evidence ids; ``content_hash`` is
    the SHA-256 of the deterministic candidate the research is based on,
    so a later re-read can confirm it was not regenerated against a
    different candidate.

    All free-text fields are model reasoning. The only sourced facts are
    the EVIDENCE items (with attribution) and the references_used list.
    """

    candidate_id: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0)
    content_hash: str

    explanation: str
    likely_attack_surface: str | None = None
    relevant_context: str | None = None
    supporting_reasoning: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    suggested_test_idea: str | None = None

    references_used: list[str] = Field(default_factory=list)
    evidence: list[XSSLLMResearchEvidence] = Field(default_factory=list)

    model: str | None = None
    raw_response_id: str | None = None
