"""Autonomous research-agent result schema (Stage R23).

The Research Agent turns an R22 Research Execution Plan into a bounded,
research-only result: which public sources were consulted, which claims are
grounded evidence (with a deterministically computed content hash), which are
model/researcher inferences, and which facts remain unknown.

Hard safety invariants encoded here:

- status is never VULNERABLE / VERIFIED / EXPLOITED / FINDING.
- an evidence item must carry a real source URL and a trusted content hash
  (the hash is assigned by the source layer, never by the LLM).
- a Nuclei "candidate" is a research proposal only: ``executed`` is forced
  False and ``target_url`` is forced None.

This schema never represents a production finding and never authorizes any
target interaction or active validation.
"""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, Field, field_validator

RESEARCH_AGENT_RULE_VERSION = "r23-1"
RESULT_ID_PREFIX = "ra-"

# ---------------------------------------------------------------------------
# status vocabulary (research-workflow only)
# ---------------------------------------------------------------------------
STATUS_COMPLETED = "RESEARCH_COMPLETED"
STATUS_PARTIAL = "RESEARCH_PARTIAL"
STATUS_BLOCKED = "RESEARCH_BLOCKED"
STATUS_FAILED = "RESEARCH_FAILED"

AGENT_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_BLOCKED,
    STATUS_FAILED,
)

# Never permitted as a status or a positive verdict.
FORBIDDEN_STATUS_TERMS = ("VULNERABLE", "VERIFIED", "EXPLOITED", "FINDING")

EVIDENCE_CONFIDENCE = ("HIGH", "MEDIUM", "LOW")

SOURCE_AVAILABLE = "AVAILABLE"
SOURCE_STORED_ONLY = "STORED_ONLY"
SOURCE_EMPTY = "EMPTY"
SOURCE_FAILED = "FAILED"
SOURCE_REJECTED = "REJECTED"
SOURCE_STATES: tuple[str, ...] = (
    SOURCE_AVAILABLE,
    SOURCE_STORED_ONLY,
    SOURCE_EMPTY,
    SOURCE_FAILED,
    SOURCE_REJECTED,
)

# Bounded sizes (single source of truth for the agent + prompt).
MAX_SOURCES = 12
MAX_DOC_CHARS = 6000
MAX_CLAIMS = 40
MAX_UNKNOWNS = 40
MAX_INFERENCES = 40
MAX_NUCLEI_CANDIDATES = 10

_FORBIDDEN_RE = re.compile(
    r"\b(" + "|".join(FORBIDDEN_STATUS_TERMS) + r")\b",
    re.IGNORECASE,
)


def result_id_for(plan_id: str, rule_version: str = RESEARCH_AGENT_RULE_VERSION) -> str:
    """Deterministic result id for one (plan_id, rule_version)."""
    basis = f"{rule_version}\n{plan_id}"
    return RESULT_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def find_forbidden_terms(text: str) -> list[str]:
    """Return forbidden verdict terms literally present in ``text``.

    Used to redact unsupported model verdict language. Case-insensitive,
    word-bounded so e.g. "verified_by" is not matched, but "is VERIFIED" is.
    """
    if not text:
        return []
    return sorted({m.group(1).upper() for m in _FORBIDDEN_RE.finditer(str(text))})


class ResearchAgentSource(BaseModel):
    """One bounded public research source consulted by the agent."""

    source_id: str
    url: str
    source_type: str = "other"
    title: str | None = None
    status: str = SOURCE_STORED_ONLY
    content_hash: str | None = None
    char_count: int = 0
    note: str = ""

    @field_validator("status")
    @classmethod
    def _valid_state(cls, value: str) -> str:
        if value not in SOURCE_STATES:
            raise ValueError(f"invalid source status: {value!r}")
        return value


class ResearchAgentEvidence(BaseModel):
    """One claim grounded in a supplied, hash-verified research source."""

    evidence_id: str
    source_url: str
    source_type: str = "other"
    claim: str
    confidence: str = "LOW"
    knowledge_ids: list[str] = Field(default_factory=list)
    quote: str = ""
    content_hash: str

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: str) -> str:
        value = str(value or "LOW").upper()
        if value not in EVIDENCE_CONFIDENCE:
            raise ValueError(f"invalid confidence: {value!r}")
        return value

    @field_validator("content_hash")
    @classmethod
    def _hash_required(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("evidence requires a trusted content_hash")
        return text

    @field_validator("source_url")
    @classmethod
    def _url_required(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("evidence requires a source_url")
        return text


class ResearchAgentInference(BaseModel):
    """A researcher/model reasoning step — explicitly not evidence."""

    statement: str
    basis: str = ""
    confidence: str = "LOW"
    model_generated: bool = False


class ResearchAgentNucleiCandidate(BaseModel):
    """A RESEARCH-ONLY Nuclei template proposal (never executed)."""

    product: str = ""
    template_source: str | None = None
    request_shape: str | None = None
    matcher_logic: str | None = None
    status: str = "RESEARCH_CANDIDATE"
    # Safety invariants, forced regardless of input.
    executed: bool = False
    target_url: str | None = None
    note: str = "research artifact only — never executed against any target"

    @field_validator("executed")
    @classmethod
    def _never_executed(cls, value: bool) -> bool:
        if value:
            raise ValueError("nuclei candidates are never executed")
        return False

    @field_validator("target_url")
    @classmethod
    def _no_target(cls, value: str | None) -> None:
        if value:
            raise ValueError("nuclei candidates never carry a target URL")
        return None


class ResearchAgentResult(BaseModel):
    """One deterministic autonomous-research result for an R22 plan."""

    result_id: str
    run_id: str
    plan_id: str
    lead_id: str = ""
    cve_id: str
    program: str
    started_at: str = ""
    completed_at: str = ""
    status: str = STATUS_PARTIAL
    sources: list[ResearchAgentSource] = Field(default_factory=list)
    evidence: list[ResearchAgentEvidence] = Field(default_factory=list)
    inferences: list[ResearchAgentInference] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    affected_parameters: list[str] = Field(default_factory=list)
    exploitability_summary: str = ""
    nuclei_candidates: list[ResearchAgentNucleiCandidate] = Field(
        default_factory=list
    )
    recommended_next_step: str = ""
    report_path: str | None = None
    rule_version: str = RESEARCH_AGENT_RULE_VERSION
    # Always False: this result is research-only, never a production finding.
    production_finding: bool = False

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        value = str(value or "").strip().upper()
        if value in FORBIDDEN_STATUS_TERMS:
            raise ValueError(f"forbidden research status: {value!r}")
        if value not in AGENT_STATUSES:
            raise ValueError(f"invalid research status: {value!r}")
        return value

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("research agent results are never production findings")
        return False
