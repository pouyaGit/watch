"""Stage R24.6 — sanitized LLM research context, prompt, and output contract.

This is the first R24 module that permits an LLM into the research pipeline.
It is deliberately split from the loop orchestration (``llm_loop.py``) so the
LLM boundary is small, auditable and independently testable.

Hard guarantees:

- The LLM context is built from **public research artifacts only**: CVE
  metadata, public source metadata/content, trusted hashes, source
  category/tier/quality, grounded evidence, and deterministic discovery
  metadata. It structurally cannot carry a target URL/host/IP, program/asset
  inventory, target response, endpoint, credential, cookie, or header.
- Program/asset tokens are used **only** as an exclusion filter: any candidate
  source/evidence whose text contains a forbidden token is excluded from the
  context (never placed in a prompt).
- LLM output never becomes evidence and can never upgrade a source's
  deterministic trust tier/category. Unattributed, ungrounded, invented or
  verdict-bearing items are dropped (downgraded to UNKNOWN), never silently
  promoted.
- ``production_finding`` is forced ``False`` and the result is explicitly
  ``public_research_only``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from pydantic import BaseModel, Field, field_validator

from ai.collectors.body_extraction import normalize_text
from ai.research_agent.discovery_contract import (
    DiscoveryQuery,
    SourceCategory,
    TrustTier,
    assert_no_forbidden_input,
    contains_forbidden_token,
)
from ai.research_agent.evidence import DiscoveryBlock
from ai.research_agent.queries import (
    TEMPLATE_CVE_ADVISORY,
    TEMPLATE_CVE_CWE,
    TEMPLATE_CVE_DETECTION,
    TEMPLATE_CVE_ID,
    TEMPLATE_CVE_POC,
    TEMPLATE_COMPONENT_CVE,
    TEMPLATE_PRODUCT_CVE,
    CVEResearchMetadata,
    QueryBuilder,
    sanitize_query,
)
from ai.schemas.research_agent import MAX_DOC_CHARS, find_forbidden_terms

__all__ = [
    "PROMPT_RULE_VERSION",
    "LLM_ANALYSIS_RULE_VERSION",
    "MAX_CONTEXT_SOURCES",
    "MAX_CONTEXT_EVIDENCE",
    "MAX_CONTEXT_CHARS",
    "MAX_PROMPT_CHARS",
    "MAX_SUGGESTED_QUERIES",
    "MAX_CLAIMS",
    "MAX_UNKNOWNS",
    "FORBIDDEN_CONTEXT_FIELDS",
    "ResearchContextSource",
    "ResearchContextEvidence",
    "ResearchLLMContext",
    "build_llm_context",
    "assert_context_safe",
    "LLMSupportedClaim",
    "LLMInference",
    "LLMContradiction",
    "LLMAnalysis",
    "AnalysisValidation",
    "parse_llm_analysis",
    "validate_and_sanitize_analysis",
    "is_safe_suggested_query",
    "map_suggestion_to_discovery_query",
    "build_research_analysis_prompt",
]

PROMPT_RULE_VERSION = "r24-llm-1"
LLM_ANALYSIS_RULE_VERSION = "r24-analysis-1"

MAX_CONTEXT_SOURCES = 12
MAX_CONTEXT_EVIDENCE = 40
MAX_CONTEXT_CHARS = MAX_DOC_CHARS
MAX_PROMPT_CHARS = 60_000
MAX_SUGGESTED_QUERIES = 6
MAX_CLAIMS = 40
MAX_UNKNOWNS = 40

FORBIDDEN_CONTEXT_FIELDS = frozenset(
    {
        "program",
        "target",
        "asset",
        "target_url",
        "target_host",
        "target_ip",
        "endpoint",
        "response",
        "credentials",
        "cookies",
        "headers",
        "authorization",
        "cookie",
        "credential",
    }
)

# Words that must never be supplied as an LLM "query direction".
_FORBIDDEN_QUERY_WORDS = frozenset(
    {
        "target",
        "program",
        "asset",
        "endpoint",
        "response",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "header",
        "headers",
        "authorization",
        "authorisation",
    }
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HOSTLIKE_RE = re.compile(r"(?<![a-z0-9-])([a-z0-9-]+\.)+[a-z]{2,}(?![a-z0-9-])", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


# ---------------------------------------------------------------------------
# Sanitized LLM context (public research only)
# ---------------------------------------------------------------------------
class ResearchContextSource(BaseModel):
    """Public source metadata/content supplied to the LLM (no target data)."""

    source_id: str
    canonical_url: str
    title: str | None = None
    category: SourceCategory
    tier: TrustTier
    source_quality: float = 0.0
    content_hash: str | None = None
    discovery_provider: str = ""
    discovery_query: str = ""
    discovery_template_id: str = ""
    content: str = ""


class ResearchContextEvidence(BaseModel):
    """Grounded R24.5 evidence supplied to the LLM (no target data)."""

    evidence_id: str
    source_id: str
    source_url: str
    claim: str
    content_hash: str


class ResearchLLMContext(BaseModel):
    """The ONLY research context an R24 LLM call may receive.

    CVE research metadata + public sources + grounded evidence + deterministic
    discovery metadata. It structurally has no target/program/asset fields.
    """

    cve_id: str = ""
    product: str = ""
    component: str = ""
    parameter: str = ""
    version: str = ""
    cwe: str = ""
    vulnerability_type: str = ""
    existing_references: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    sources: list[ResearchContextSource] = Field(default_factory=list)
    evidence: list[ResearchContextEvidence] = Field(default_factory=list)
    excluded_forbidden: int = 0
    public_research_only: bool = True
    production_finding: bool = False

    @field_validator("public_research_only")
    @classmethod
    def _public_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("R24 LLM context must remain public-research-only")
        return True

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("R24 LLM context is never a production finding")
        return False


def _iter_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def assert_context_safe(
    context: ResearchLLMContext,
    forbidden_tokens: Iterable[str] = (),
) -> None:
    """Raise ``ValueError`` if a context carries a forbidden field or token.

    Deterministic structural + token check. Program/asset tokens must never
    appear anywhere in the context.
    """
    payload = context.model_dump(mode="json")
    fields = set(payload.keys())
    leaked = fields & FORBIDDEN_CONTEXT_FIELDS
    if leaked:
        raise ValueError(f"forbidden context fields present: {sorted(leaked)}")
    for text in _iter_strings(payload):
        if forbidden_tokens and contains_forbidden_token(text, forbidden_tokens):
            raise ValueError("LLM context contains a forbidden program/asset token")


def build_llm_context(
    block: DiscoveryBlock,
    metadata: CVEResearchMetadata,
    *,
    content_by_source_id: Mapping[str, str] | None = None,
    forbidden_tokens: Iterable[str] = (),
    max_sources: int = MAX_CONTEXT_SOURCES,
    max_evidence: int = MAX_CONTEXT_EVIDENCE,
    max_content_chars: int = MAX_CONTEXT_CHARS,
) -> ResearchLLMContext:
    """Build the sanitized LLM context from a discovery block + metadata.

    Sources/evidence whose text contains a forbidden program/asset token are
    excluded (deterministic, counted in ``excluded_forbidden``). Content is
    bounded. Never fetches; uses only supplied materialized content.
    """
    content_map = dict(content_by_source_id or {})
    forbidden = tuple(forbidden_tokens or ())

    included_ids: set[str] = set()
    sources: list[ResearchContextSource] = []
    excluded = 0
    for record in sorted(block.sources, key=lambda r: (str(r.source_id), r.canonical_url)):
        if len(sources) >= max(1, max_sources):
            break
        blobs = [record.canonical_url, record.title or "", record.discovery_query or "",
                 record.discovery_provider or ""]
        if any(contains_forbidden_token(blob, forbidden) for blob in blobs if blob):
            excluded += 1
            continue
        content = normalize_text(str(content_map.get(record.source_id, "")))[:max_content_chars]
        included_ids.add(record.source_id)
        sources.append(
            ResearchContextSource(
                source_id=record.source_id,
                canonical_url=record.canonical_url,
                title=record.title,
                category=record.category,
                tier=record.tier,
                source_quality=record.source_quality,
                content_hash=record.content_hash,
                discovery_provider=record.discovery_provider,
                discovery_query=record.discovery_query,
                discovery_template_id=record.discovery_template_id,
                content=content,
            )
        )

    evidence: list[ResearchContextEvidence] = []
    for item in sorted(block.evidence, key=lambda e: str(e.evidence_id)):
        if len(evidence) >= max(1, max_evidence):
            break
        if item.source_id not in included_ids:
            continue
        if forbidden and (
            contains_forbidden_token(item.claim, forbidden)
            or contains_forbidden_token(item.source_url, forbidden)
        ):
            excluded += 1
            continue
        evidence.append(
            ResearchContextEvidence(
                evidence_id=item.evidence_id,
                source_id=item.source_id,
                source_url=item.source_url,
                claim=item.claim[:max_content_chars],
                content_hash=item.content_hash,
            )
        )

    unknowns = [str(u) for u in (block.unknowns or [])][:MAX_UNKNOWNS]
    if forbidden:
        unknowns = [u for u in unknowns if not contains_forbidden_token(u, forbidden)]

    context = ResearchLLMContext(
        cve_id=metadata.cve_id,
        product=metadata.product,
        component=metadata.component,
        parameter=metadata.parameter,
        version=metadata.version,
        cwe=metadata.cwe,
        vulnerability_type=metadata.vulnerability_type,
        existing_references=list(metadata.existing_references or [])[:50],
        unknowns=unknowns,
        sources=sources,
        evidence=evidence,
        excluded_forbidden=excluded,
    )
    assert_context_safe(context, forbidden)
    return context


# ---------------------------------------------------------------------------
# LLM output contract (strict)
# ---------------------------------------------------------------------------
class LLMSupportedClaim(BaseModel):
    claim: str
    evidence_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    confidence: str = "LOW"
    quote: str = ""

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: str) -> str:
        text = str(value or "LOW").upper()
        if text not in ("HIGH", "MEDIUM", "LOW"):
            raise ValueError(f"invalid confidence: {value!r}")
        return text


class LLMInference(BaseModel):
    statement: str
    basis: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)


class LLMContradiction(BaseModel):
    statement: str
    source_ids: list[str] = Field(default_factory=list)


class LLMAnalysis(BaseModel):
    """Strict, non-authoritative LLM analysis output.

    Every field is advisory; none of it is evidence and none of it can change
    source trust. Defaults handle absent fields.
    """

    summary: str = ""
    supported_claims: list[LLMSupportedClaim] = Field(default_factory=list)
    inferences: list[LLMInference] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    contradictions: list[LLMContradiction] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    suggested_queries: list[str] = Field(default_factory=list)
    public_research_only: bool = True
    production_finding: bool = False

    @field_validator("public_research_only")
    @classmethod
    def _public_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("LLM analysis must remain public-research-only")
        return True

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("LLM analysis is never a production finding")
        return False


@dataclass(frozen=True)
class AnalysisValidation:
    """Result of validating/sanitizing raw LLM output against the context."""

    analysis: LLMAnalysis
    dropped: tuple[str, ...] = ()
    downgraded_unknowns: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.analysis is not None


def parse_llm_analysis(raw: object) -> LLMAnalysis:
    """Parse raw LLM output into an :class:`LLMAnalysis`.

    Accepts a JSON string or an already-decoded dict. Raises ``ValueError`` on
    malformed/non-object output (never treated as success).
    """
    from ai.researcher.researcher import parse_llm_json

    if isinstance(raw, str):
        data = parse_llm_json(raw)
    elif isinstance(raw, dict):
        data = raw
    else:
        raise ValueError("LLM analysis must be a JSON object or string")
    if not isinstance(data, dict):
        raise ValueError("LLM analysis root must be an object")
    return LLMAnalysis.model_validate(data)


def _significant_tokens(text: str) -> set[str]:
    return {tok for tok in re.findall(r"[a-z0-9]{4,}", str(text or "").lower())}


def _is_grounded(claim: str, texts: list[str]) -> bool:
    normalized_claim = normalize_text(claim)
    if not normalized_claim:
        return False
    claim_tokens = _significant_tokens(claim)
    for text in texts:
        if normalized_claim in normalize_text(text):
            return True
    if not claim_tokens:
        return False
    for text in texts:
        if claim_tokens & _significant_tokens(text):
            return True
    return False


def _allowed_urls(context: ResearchLLMContext) -> set[str]:
    urls: set[str] = set()
    for source in context.sources:
        urls.add(source.canonical_url)
    for item in context.evidence:
        urls.add(item.source_url)
    return urls


def _introduces_url(text: str, allowed_urls: set[str]) -> bool:
    for match in _URL_RE.findall(str(text or "")):
        candidate = match.rstrip(").,;")
        if candidate not in allowed_urls:
            return True
    return False


def validate_and_sanitize_analysis(
    analysis: LLMAnalysis,
    context: ResearchLLMContext,
    *,
    forbidden_tokens: Iterable[str] = (),
) -> AnalysisValidation:
    """Attribution + grounding + verdict validation of LLM output.

    - Any claim/inference with an unknown evidence/source id, no attribution,
      an invented URL, a forbidden verdict term, or no grounding in the
      referenced supplied text is dropped (claims) or downgraded to UNKNOWN.
    - Contradictions with unknown source ids are dropped (both sides preserved
      when valid).
    - Suggested queries are retained only if they pass
      :func:`is_safe_suggested_query`.
    - ``summary`` carrying a forbidden verdict term is cleared.
    LLM output never becomes evidence; source trust is never modified here.
    """
    forbidden = tuple(forbidden_tokens or ())
    known_source_ids = {s.source_id for s in context.sources}
    known_evidence_ids = {e.evidence_id for e in context.evidence}
    evidence_by_id = {e.evidence_id: e for e in context.evidence}
    source_by_id = {s.source_id: s for s in context.sources}
    allowed_urls = _allowed_urls(context)

    dropped: list[str] = []
    downgraded: list[str] = []

    clean_claims: list[LLMSupportedClaim] = []
    seen_claims: set[str] = set()
    for claim in analysis.supported_claims:
        text = str(claim.claim or "").strip()
        if not text:
            continue
        if find_forbidden_terms(text):
            dropped.append(f"claim rejected (forbidden verdict language): {text[:120]}")
            continue
        if forbidden and contains_forbidden_token(text, forbidden):
            dropped.append("claim rejected (forbidden program/asset token)")
            continue
        if (
            any(eid not in known_evidence_ids for eid in claim.evidence_ids)
            or any(sid not in known_source_ids for sid in claim.source_ids)
        ):
            dropped.append(f"claim rejected (unknown attribution): {text[:120]}")
            continue
        if not claim.evidence_ids and not claim.source_ids:
            downgraded.append(text)
            continue
        if _introduces_url(text, allowed_urls):
            dropped.append(f"claim rejected (invented URL): {text[:120]}")
            continue
        refs: list[str] = []
        for eid in claim.evidence_ids:
            refs.append(evidence_by_id[eid].claim)
        for sid in claim.source_ids:
            source = source_by_id[sid]
            refs.append(source.content)
            refs.append(source.title or "")
        if not _is_grounded(text, refs):
            downgraded.append(text)
            continue
        key = normalize_text(text)
        if key in seen_claims:
            continue
        seen_claims.add(key)
        clean_claims.append(claim)

    clean_inferences: list[LLMInference] = []
    for inference in analysis.inferences:
        statement = str(inference.statement or "").strip()
        if not statement:
            continue
        if find_forbidden_terms(statement) or (
            forbidden and contains_forbidden_token(statement, forbidden)
        ):
            dropped.append(f"inference rejected (forbidden language): {statement[:120]}")
            continue
        if (
            any(eid not in known_evidence_ids for eid in inference.evidence_ids)
            or any(sid not in known_source_ids for sid in inference.source_ids)
        ):
            dropped.append(f"inference rejected (unknown attribution): {statement[:120]}")
            continue
        refs = [evidence_by_id[eid].claim for eid in inference.evidence_ids]
        refs += [source_by_id[sid].content for sid in inference.source_ids]
        if refs and not _is_grounded(statement, refs):
            downgraded.append(statement)
            continue
        clean_inferences.append(inference)

    clean_contradictions: list[LLMContradiction] = []
    for contradiction in analysis.contradictions:
        statement = str(contradiction.statement or "").strip()
        if not statement:
            continue
        if any(sid not in known_source_ids for sid in contradiction.source_ids):
            dropped.append("contradiction rejected (unknown source id)")
            continue
        if find_forbidden_terms(statement):
            dropped.append("contradiction rejected (forbidden verdict language)")
            continue
        clean_contradictions.append(contradiction)

    clean_unknowns: list[str] = []
    for item in list(analysis.unknowns) + downgraded:
        text = str(item or "").strip()
        if not text:
            continue
        if find_forbidden_terms(text):
            continue
        if forbidden and contains_forbidden_token(text, forbidden):
            continue
        if text not in clean_unknowns:
            clean_unknowns.append(text)
        if len(clean_unknowns) >= MAX_UNKNOWNS:
            break

    clean_gaps: list[str] = []
    for item in analysis.gaps:
        text = str(item or "").strip()
        if not text or find_forbidden_terms(text):
            continue
        if forbidden and contains_forbidden_token(text, forbidden):
            continue
        if text not in clean_gaps:
            clean_gaps.append(text)

    clean_queries = [
        str(q).strip()
        for q in analysis.suggested_queries
        if is_safe_suggested_query(q, forbidden)
    ][:MAX_SUGGESTED_QUERIES]

    summary = str(analysis.summary or "")
    if find_forbidden_terms(summary) or (
        forbidden and contains_forbidden_token(summary, forbidden)
    ):
        dropped.append("summary cleared (forbidden verdict/program language)")
        summary = ""

    clean = LLMAnalysis(
        summary=summary,
        supported_claims=clean_claims,
        inferences=clean_inferences,
        unknowns=clean_unknowns,
        contradictions=clean_contradictions,
        gaps=clean_gaps,
        suggested_queries=clean_queries,
    )
    return AnalysisValidation(
        analysis=clean,
        dropped=tuple(dropped),
        downgraded_unknowns=tuple(downgraded),
    )


def is_safe_suggested_query(
    suggestion: object,
    forbidden_tokens: Iterable[str] = (),
) -> bool:
    """Structural safety check for a model-suggested query direction.

    Rejects (never silently sanitizes) any suggestion containing a forbidden
    program/asset token, a URL, a hostname, an IP literal, an endpoint/path,
    credentials markers, or a forbidden field word. Deterministic, no network.
    """
    text = sanitize_query(suggestion)
    if not text or len(text) > 200:
        return False
    forbidden = tuple(forbidden_tokens or ())
    if forbidden and contains_forbidden_token(text, forbidden):
        return False
    lowered = text.lower()
    if "://" in lowered or "@" in lowered or "/" in lowered or "?" in lowered:
        return False
    if ":" in lowered:
        return False
    if _HOSTLIKE_RE.search(lowered) or _IPV4_RE.search(lowered):
        return False
    words = set(re.findall(r"[a-z0-9_]+", lowered))
    if words & _FORBIDDEN_QUERY_WORDS:
        return False
    try:
        assert_no_forbidden_input(text, forbidden)
    except Exception:
        return False
    return True


# Deterministic keyword -> approved R24.1 template mapping.
_TEMPLATE_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("advisory", "vendor", "bulletin"), TEMPLATE_CVE_ADVISORY),
    (("poc", "exploit", "proof"), TEMPLATE_CVE_POC),
    (("detection", "rule", "signature", "yara", "sigma"), TEMPLATE_CVE_DETECTION),
    (("cwe", "weakness"), TEMPLATE_CVE_CWE),
    (("product", "software"), TEMPLATE_PRODUCT_CVE),
    (("component", "plugin", "module", "file"), TEMPLATE_COMPONENT_CVE),
)


def map_suggestion_to_discovery_query(
    suggestion: object,
    metadata: CVEResearchMetadata,
    *,
    forbidden_tokens: Iterable[str] = (),
) -> DiscoveryQuery | None:
    """Map a *safe* model suggestion to an approved deterministic query.

    The model never supplies provider/URL/query execution. An accepted
    suggestion only selects among the fixed R24.1 templates; the concrete query
    text is rendered deterministically by :class:`QueryBuilder`. Unsafe
    suggestions return ``None`` (rejected, not sanitized).
    """
    if not is_safe_suggested_query(suggestion, forbidden_tokens):
        return None
    words = str(suggestion or "").lower()
    template_id = TEMPLATE_CVE_ID
    for keywords, candidate in _TEMPLATE_KEYWORDS:
        if any(word in words for word in keywords):
            template_id = candidate
            break
    builder = QueryBuilder(forbidden_tokens=forbidden_tokens)
    for query in builder.build_queries(metadata):
        if query.template_id == template_id:
            return query
    return None


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------
_SYSTEM_RULES = """You are a PUBLIC SECURITY RESEARCH analyst assisting an authorized bug-bounty research process.

PUBLIC RESEARCH ONLY. You are NOT testing, validating, or interacting with any target.
Do NOT claim a target/program is vulnerable, exploitable, exposed, present, or affected.
Do NOT use the words VULNERABLE, VERIFIED, EXPLOITED, or FINDING as a verdict.
Do NOT invent evidence, URLs, source ids, evidence ids, CVE ids, versions, components, or parameters.
Do NOT request credentials, cookies, headers, endpoints, or responses.
Do NOT execute or recommend exploiting a target.

Rules:
- Base every supported_claim ONLY on the supplied public sources/evidence.
- Every supported_claim MUST reference at least one supplied evidence_id or source_id.
- Preserve source attribution; when evidence is insufficient, put the item under unknowns.
- Distinguish EVIDENCE (grounded in supplied sources) from INFERENCE (reasoning) and UNKNOWN.
- If public sources disagree, record the contradiction with all source ids involved.
- Suggested query directions must be generic public-research terms only (no URLs, hosts, IPs, or target terms).

Return ONLY a single JSON object matching:
{
  "summary": "string",
  "supported_claims": [
    {"claim": "string", "evidence_ids": ["..."], "source_ids": ["..."],
     "confidence": "HIGH|MEDIUM|LOW", "quote": "string"}
  ],
  "inferences": [
    {"statement": "string", "basis": "string", "evidence_ids": ["..."], "source_ids": ["..."]}
  ],
  "unknowns": ["string"],
  "contradictions": [{"statement": "string", "source_ids": ["..."]}],
  "gaps": ["string"],
  "suggested_queries": ["string"]
}
"""


def build_research_analysis_prompt(
    context: ResearchLLMContext,
    *,
    max_chars: int = MAX_PROMPT_CHARS,
) -> str:
    """Render a bounded prompt from the sanitized context (no target data)."""
    import json

    payload = context.model_dump(mode="json")
    prompt = (
        _SYSTEM_RULES
        + "\nRESEARCH CONTEXT (public only):\n"
        + json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    )
    return prompt[:max_chars]
