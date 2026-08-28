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
