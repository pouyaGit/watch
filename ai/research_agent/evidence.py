"""Stage R24.5 — evidence integration for discovered public sources.

This module is the additive bridge between the R24 discovery pipeline
(R24.1 contract → R24.2 providers → R24.3 hardening → R24.4 ranking/dedup) and
the existing R23 research result. It turns already-materialized
:class:`~ai.research_agent.discovery_contract.DiscoveredSource` records into
grounded :class:`DiscoveryEvidence` plus a deterministic, serializable
:class:`DiscoveryBlock`.

Safety properties (R24 scope §8/§11/§12):

- **Offline / network-free.** No HTTP, no DNS, no sockets, no provider call,
  no LLM call, no re-fetch, no re-hash of a URL. Evidence is a pure grounded
  transformation of already-supplied materialized content.
- **Grounded.** A claim is either a deterministic bounded excerpt of the
  supplied content, or a caller-supplied claim that must appear verbatim
  (normalized) in the supplied content. Otherwise no evidence is produced and
  the item is recorded as UNKNOWN.
- **Eligibility is reused, not duplicated.** The R24.4
  :func:`ai.research_agent.ranking.is_evidence_eligible` predicate is the sole
  gate; this module never re-implements it.
- **Public research only.** Evidence describes public research sources; it never
  asserts target vulnerability, exploitability, exposure, version, presence or
  behavior. ``production_finding`` is forced ``False`` everywhere.
- **Traceable.** Every evidence object references exactly one known source and
  carries its source id, canonical URL, final URL, trusted content hash,
  category, tier, quality, extraction method and discovery provenance. No
  fabricated URLs, hashes or claims.

R23 models are **not** modified and R23 result files remain deserializable; the
discovery block is a separate additive structure.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Mapping, Sequence

from pydantic import BaseModel, Field, field_validator

from ai.collectors.body_extraction import normalize_text
from ai.research_agent.dedup import canonical_url
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    Lifecycle,
    SourceCategory,
    TrustTier,
)
from ai.research_agent.ranking import EVIDENCE_FLOOR, is_evidence_eligible
from ai.schemas.research_agent import (
    MAX_DOC_CHARS,
    SOURCE_STORED_ONLY,
)

__all__ = [
    "DISCOVERY_RULE_VERSION",
    "EVIDENCE_ID_PREFIX",
    "MAX_EXCERPT_CHARS",
    "EVIDENCE_CONFIDENCE",
    "LifecycleError",
    "LIFECYCLE_ORDER",
    "TERMINAL_LIFECYCLES",
    "is_valid_lifecycle_transition",
    "transition_lifecycle",
    "with_lifecycle",
    "next_lifecycle_for",
    "evidence_id_for",
    "inference_id_for",
    "DiscoveryEvidence",
    "DiscoveryInference",
    "DiscoverySourceRecord",
    "DiscoveryBlock",
    "build_evidence",
    "content_has_required_token",
    "integrate_discovery",
    "attach_discovery_block",
]

DISCOVERY_RULE_VERSION = "r24-1"
EVIDENCE_ID_PREFIX = "de-"
INFERENCE_ID_PREFIX = "di-"
MAX_EXCERPT_CHARS = 500

EVIDENCE_CONFIDENCE = ("HIGH", "MEDIUM", "LOW")

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
LIFECYCLE_ORDER: dict[Lifecycle, int] = {
    Lifecycle.DISCOVERED_SOURCE: 0,
    Lifecycle.FETCHED_SOURCE: 1,
    Lifecycle.RELEVANT_SOURCE: 2,
    Lifecycle.EVIDENCE: 3,
}

# UNKNOWN / INFERENCE are terminal (no further source-lifecycle progression).
TERMINAL_LIFECYCLES: frozenset[Lifecycle] = frozenset(
    {Lifecycle.UNKNOWN, Lifecycle.INFERENCE}
)


class LifecycleError(ValueError):
    """Raised for an invalid lifecycle transition."""


def is_valid_lifecycle_transition(current: object, target: object) -> bool:
    """True when ``current → target`` is an allowed deterministic transition.

    Allowed: identity; one-step forward progression along
    ``DISCOVERED_SOURCE → FETCHED_SOURCE → RELEVANT_SOURCE → EVIDENCE``; and a
    jump from any non-terminal state to the terminal ``UNKNOWN``/``INFERENCE``.
    Backward, skipped-forward, and out-of-terminal transitions are rejected.
    """
    try:
        current_l = Lifecycle(current)
        target_l = Lifecycle(target)
    except ValueError:
        return False
    if current_l == target_l:
        return True
    if current_l in TERMINAL_LIFECYCLES:
        return False
    if target_l in TERMINAL_LIFECYCLES:
        return True
    if current_l not in LIFECYCLE_ORDER or target_l not in LIFECYCLE_ORDER:
        return False
    return LIFECYCLE_ORDER[target_l] == LIFECYCLE_ORDER[current_l] + 1


def transition_lifecycle(current: object, target: object) -> Lifecycle:
    """Validate and return the target lifecycle; raise on an illegal move."""
    if not is_valid_lifecycle_transition(current, target):
        raise LifecycleError(f"invalid lifecycle transition: {current!r} -> {target!r}")
    return Lifecycle(target)


def with_lifecycle(source: DiscoveredSource, target: object) -> DiscoveredSource:
    """Return a copy of ``source`` advanced to ``target`` (validated)."""
    if source is None:
        raise LifecycleError("cannot transition a missing source")
    state = transition_lifecycle(source.lifecycle, target)
    return source.model_copy(update={"lifecycle": state})


def next_lifecycle_for(
    source: DiscoveredSource,
    *,
    content_present: bool,
    eligible: bool,
) -> Lifecycle:
    """Deterministically derive the lifecycle a source reaches.

    - no trusted hash and no materialized content → ``DISCOVERED_SOURCE``
    - content and/or trusted hash present but not evidence-eligible →
      ``FETCHED_SOURCE`` (no content) or ``RELEVANT_SOURCE`` (content + hash)
    - eligible with materialized content → ``EVIDENCE``
    """
    has_hash = bool(getattr(source, "content_hash", None))
    if content_present and has_hash:
        return Lifecycle.EVIDENCE if eligible else Lifecycle.RELEVANT_SOURCE
    if content_present or has_hash:
        return Lifecycle.FETCHED_SOURCE
    return Lifecycle.DISCOVERED_SOURCE


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class DiscoveryEvidence(BaseModel):
    """One grounded claim backed by exactly one known public source.

    This is public-research evidence only. It never asserts anything about a
    target/program and is never a production finding.
    """

    evidence_id: str
    source_id: str
    source_url: str
    canonical_url: str
    final_url: str | None = None
    content_hash: str
    source_category: SourceCategory
    trust_tier: TrustTier
    source_quality: float = 0.0
    lifecycle: Lifecycle = Lifecycle.EVIDENCE
    claim: str
    quote: str = ""
    confidence: str = "LOW"
    extraction_method: str = "content_excerpt"
    discovery_provider: str = ""
    discovery_query: str = ""
    discovery_template_id: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    # research-only safety invariant (never a production finding).
    production_finding: bool = False

    @field_validator("evidence_id", "source_id", "source_url", "content_hash", "claim")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("evidence requires a non-empty identity/grounding field")
        return text

    @field_validator("lifecycle")
    @classmethod
    def _evidence_state(cls, value: object) -> Lifecycle:
        state = Lifecycle(value)
        if state != Lifecycle.EVIDENCE:
            raise ValueError("a DiscoveryEvidence object must be in EVIDENCE state")
        return state

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: str) -> str:
        text = str(value or "LOW").upper()
        if text not in EVIDENCE_CONFIDENCE:
            raise ValueError(f"invalid evidence confidence: {value!r}")
        return text

    @field_validator("source_quality")
    @classmethod
    def _bounded_quality(cls, value: float) -> float:
        value = float(value or 0.0)
        if not (0.0 <= value <= 1.0):
            raise ValueError("source_quality must be within [0.0, 1.0]")
        return value

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("research evidence is never a production finding")
        return False


class DiscoveryInference(BaseModel):
    """A deterministic claim explicitly derived from available evidence.

    Never a target assertion and never a production finding.
    """

    inference_id: str
    statement: str
    basis: str = ""
    source_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    model_generated: bool = False
    production_finding: bool = False

    @field_validator("inference_id", "statement")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("inference requires a non-empty id/statement")
        return text

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("research inferences are never production findings")
        return False


class DiscoverySourceRecord(BaseModel):
    """Deterministic per-source lifecycle + provenance summary."""

    source_id: str
    canonical_url: str
    discovered_url: str = ""
    final_url: str | None = None
    status: str = SOURCE_STORED_ONLY
    lifecycle: Lifecycle
    category: SourceCategory
    tier: TrustTier
    source_quality: float = 0.0
    content_hash: str | None = None
    char_count: int = 0
    title: str | None = None
    discovery_provider: str = ""
    discovery_query: str = ""
    discovery_template_id: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    eligible: bool = False
    ineligible_reason: str = ""
    evidence_id: str | None = None
    # research-only safety invariant (never a production finding).
    production_finding: bool = False

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("source records are never production findings")
        return False


class DiscoveryBlock(BaseModel):
    """Additive, deterministic R24 discovery result block.

    Carries counts, per-source lifecycle/provenance, grounded evidence,
    unknowns and (deterministic) inferences. Contains no target/program/asset
    information and never represents a production finding.
    """

    rule_version: str = DISCOVERY_RULE_VERSION
    discovery_enabled: bool = False
    plan_id: str = ""
    result_id: str = ""
    discovered_sources: int = 0
    fetched_sources: int = 0
    relevant_sources: int = 0
    evidence_count: int = 0
    unknown_count: int = 0
    inference_count: int = 0
    ineligible_count: int = 0
    providers: list[str] = Field(default_factory=list)
    evidence: list[DiscoveryEvidence] = Field(default_factory=list)
    sources: list[DiscoverySourceRecord] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    inferences: list[DiscoveryInference] = Field(default_factory=list)
    # research-only safety invariant (never a production finding).
    production_finding: bool = False

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("discovery blocks are never production findings")
        return False


# ---------------------------------------------------------------------------
# Deterministic ids
# ---------------------------------------------------------------------------
def evidence_id_for(
    source_id: str, canonical: str, content_hash: str, claim: str
) -> str:
    """Deterministic evidence id from its full grounding tuple."""
    basis = "\n".join(
        [
            str(source_id or ""),
            str(canonical or ""),
            str(content_hash or ""),
            str(claim or ""),
        ]
    )
    return EVIDENCE_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def inference_id_for(statement: str, basis: str) -> str:
    """Deterministic inference id from (statement, basis)."""
    joined = "\n".join([str(statement or ""), str(basis or "")])
    return INFERENCE_ID_PREFIX + hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Grounded evidence construction (no fetch, no LLM)
# ---------------------------------------------------------------------------
def content_has_required_token(
    content: object, required_tokens: Iterable[str] | None
) -> bool:
    """True when ``content`` contains at least one required advisory token.

    Used by R24.8 to stop generic vendor search pages (which carry no
    CVE-specific text) from becoming TRUSTED evidence. When no tokens are
    supplied the gate is open (backward compatible).
    """
    tokens = [str(t).strip().lower() for t in (required_tokens or ()) if str(t or "").strip()]
    if not tokens:
        return True
    normalized = normalize_text(str(content or "")).lower()
    if not normalized:
        return False
    return any(token in normalized for token in tokens)


def build_evidence(
    source: DiscoveredSource,
    content: object,
    *,
    claim: str | None = None,
    extraction_method: str | None = None,
    advisory_reference: str | None = None,
    required_content_tokens: Iterable[str] | None = None,
    confidence: str = "LOW",
) -> DiscoveryEvidence | None:
    """Build grounded evidence for one source, or ``None`` when not possible.

    The source must be evidence-eligible (R24.4 predicate) AND have supplied,
    non-empty materialized content. When ``required_content_tokens`` is given
    (R24.8) the content must contain at least one of them (e.g. the exact CVE
    id) so generic landing pages cannot become evidence. When ``claim`` is
    provided it must appear in the normalized content; otherwise a deterministic
    bounded excerpt is used. Never fetches, never invents a URL/hash/claim.
    """
    if source is None:
        return None
    if not is_evidence_eligible(source, advisory_reference=advisory_reference):
        return None

    normalized = normalize_text(str(content or ""))[:MAX_DOC_CHARS]
    if not normalized:
        return None
    if not content_has_required_token(normalized, required_content_tokens):
        return None

    if claim is not None:
        normalized_claim = normalize_text(str(claim))
        if not normalized_claim or normalized_claim not in normalized:
            return None
        method = str(extraction_method or "grounded_claim")
    else:
        normalized_claim = normalized[:MAX_EXCERPT_CHARS]
        method = str(extraction_method or "content_excerpt")

    canonical = canonical_url(source)
    source_url = str(source.final_url or source.url or canonical)
    return DiscoveryEvidence(
        evidence_id=evidence_id_for(
            str(source.source_id), canonical, str(source.content_hash), normalized_claim
        ),
        source_id=str(source.source_id),
        source_url=source_url,
        canonical_url=canonical,
        final_url=source.final_url,
        content_hash=str(source.content_hash),
        source_category=source.category,
        trust_tier=source.tier,
        source_quality=float(source.source_quality or 0.0),
        lifecycle=Lifecycle.EVIDENCE,
        claim=normalized_claim,
        quote=normalized_claim,
        confidence=confidence,
        extraction_method=method,
        discovery_provider=str(source.discovery_provider or ""),
        discovery_query=str(source.discovery_query or ""),
        discovery_template_id=str(source.discovery_template_id or ""),
        redirect_chain=list(source.redirect_chain or []),
        aliases=list(source.aliases or []),
    )


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------
def _ineligible_reason(
    source: DiscoveredSource,
    content_present: bool,
    *,
    content_gate_ok: bool = True,
) -> str:
    if not source.content_hash:
        return "no trusted content_hash"
    if float(getattr(source, "source_quality", 0.0) or 0.0) < EVIDENCE_FLOOR:
        return "source_quality below evidence floor"
    if source.tier == TrustTier.GENERIC:
        return "generic tier cannot back evidence"
    if not content_gate_ok:
        return "content lacks CVE/advisory-specific signal"
    if not content_present:
        return "no materialized content supplied"
    return "not evidence-eligible"


def integrate_discovery(
    sources: Iterable[DiscoveredSource],
    content_by_source_id: Mapping[str, str] | None = None,
    *,
    discovery_enabled: bool = False,
    advisory_reference_by_source_id: Mapping[str, str] | None = None,
    inferences: Sequence[DiscoveryInference] | None = None,
    plan_id: str = "",
    result_id: str = "",
    required_content_tokens: Iterable[str] | None = None,
) -> DiscoveryBlock:
    """Transform ranked/deduplicated sources into a discovery block.

    Input ``sources`` is expected to be the R24.4 output (ranked + deduplicated);
    this function does not re-rank or re-canonicalize. ``content_by_source_id``
    supplies already-materialized content keyed by ``source_id`` (or canonical
    URL); it is never fetched. No network, no provider, no LLM.
    """
    content_map = dict(content_by_source_id or {})
    advisory_map = dict(advisory_reference_by_source_id or {})

    records: list[DiscoverySourceRecord] = []
    evidence: list[DiscoveryEvidence] = []
    unknowns: list[str] = []
    seen_sources: set[str] = set()
    seen_evidence: set[str] = set()

    for source in sources or ():
        if source is None:
            continue
        source_id = str(source.source_id or "")
        canonical = canonical_url(source)
        dedup_key = source_id or canonical
        if dedup_key in seen_sources:
            # Duplicate source cannot create duplicate evidence.
            continue
        seen_sources.add(dedup_key)

        content = content_map.get(source_id, "")
        if not content and canonical:
            content = content_map.get(canonical, "")
        content_present = bool(normalize_text(str(content or "")))
        advisory = advisory_map.get(source_id) or advisory_map.get(canonical) or None

        content_gate_ok = content_has_required_token(content, required_content_tokens)
        eligible = is_evidence_eligible(
            source, advisory_reference=advisory
        ) and content_gate_ok
        item = None
        if eligible and content_present:
            item = build_evidence(
                source,
                content,
                advisory_reference=advisory,
                required_content_tokens=required_content_tokens,
            )
        lifecycle = next_lifecycle_for(
            source, content_present=content_present, eligible=eligible
        )

        if item is not None:
            if item.evidence_id not in seen_evidence:
                seen_evidence.add(item.evidence_id)
                evidence.append(item)
        else:
            if source.content_hash or content_present:
                reason = _ineligible_reason(
                    source, content_present, content_gate_ok=content_gate_ok
                )
                note = f"source {source_id or canonical}: not evidence ({reason})"
                if note not in unknowns:
                    unknowns.append(note)

        records.append(
            DiscoverySourceRecord(
                source_id=source_id,
                canonical_url=canonical,
                discovered_url=str(source.discovered_url or ""),
                final_url=source.final_url,
                status=str(source.status or SOURCE_STORED_ONLY),
                lifecycle=lifecycle,
                category=source.category,
                tier=source.tier,
                source_quality=float(source.source_quality or 0.0),
                content_hash=source.content_hash,
                char_count=int(source.char_count or 0),
                title=source.title,
                discovery_provider=str(source.discovery_provider or ""),
                discovery_query=str(source.discovery_query or ""),
                discovery_template_id=str(source.discovery_template_id or ""),
                redirect_chain=list(source.redirect_chain or []),
                aliases=list(source.aliases or []),
                eligible=bool(eligible),
                ineligible_reason=(
                    ""
                    if eligible
                    else _ineligible_reason(
                        source, content_present, content_gate_ok=content_gate_ok
                    )
                ),
                evidence_id=item.evidence_id if item is not None else None,
            )
        )

    valid_inferences: list[DiscoveryInference] = []
    known_source_ids = {record.source_id for record in records}
    known_evidence_ids = {item.evidence_id for item in evidence}
    for inference in inferences or ():
        if not isinstance(inference, DiscoveryInference):
            continue
        if any(
            sid not in known_source_ids for sid in (inference.source_ids or [])
        ) or any(
            eid not in known_evidence_ids for eid in (inference.evidence_ids or [])
        ):
            note = (
                f"inference {inference.inference_id}: references an unknown "
                "source/evidence; dropped"
            )
            if note not in unknowns:
                unknowns.append(note)
            continue
        valid_inferences.append(inference)

    fetched = sum(
        1
        for record in records
        if record.lifecycle
        in (Lifecycle.FETCHED_SOURCE, Lifecycle.RELEVANT_SOURCE, Lifecycle.EVIDENCE)
    )
    relevant = sum(
        1
        for record in records
        if record.lifecycle in (Lifecycle.RELEVANT_SOURCE, Lifecycle.EVIDENCE)
    )
    ineligible = sum(1 for record in records if not record.eligible)
    providers = sorted(
        {record.discovery_provider for record in records if record.discovery_provider}
    )

    return DiscoveryBlock(
        rule_version=DISCOVERY_RULE_VERSION,
        discovery_enabled=bool(discovery_enabled),
        plan_id=str(plan_id or ""),
        result_id=str(result_id or ""),
        discovered_sources=len(records),
        fetched_sources=fetched,
        relevant_sources=relevant,
        evidence_count=len(evidence),
        unknown_count=len(unknowns),
        inference_count=len(valid_inferences),
        ineligible_count=ineligible,
        providers=providers,
        evidence=evidence,
        sources=records,
        unknowns=unknowns,
        inferences=valid_inferences,
    )


def attach_discovery_block(result: object, block: DiscoveryBlock) -> dict:
    """Return a NEW result dict with the additive ``discovery`` block attached.

    - accepts an R23 result dict or any object with ``model_dump``.
    - never mutates the input and never changes the R23 result itself.
    - old R23 results without a discovery block remain valid (the key is simply
      absent there).
    """
    if hasattr(result, "model_dump"):
        payload = result.model_dump(mode="json")
    elif isinstance(result, dict):
        payload = dict(result)
    else:
        raise TypeError("result must be a dict or an object with model_dump()")
    payload = dict(payload)
    if hasattr(block, "model_dump"):
        payload["discovery"] = block.model_dump(mode="json")
    else:
        payload["discovery"] = dict(block)
    return payload
