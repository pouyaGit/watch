from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import ValidationError

from ai.ingestion.grounding import (
    contains_forbidden,
    value_grounded,
)
from ai.knowledge.store import (
    KnowledgeStore,
    canonicalize_source_url,
    content_hash,
    source_id,
)
from ai.llm.base import LLMProvider
from ai.schemas.ingestion import (
    ExtractedClaim,
    ExtractionResult,
    IngestionError,
    SourceDocument,
)
from ai.schemas.knowledge import (
    KnowledgeAggregate,
    KnowledgeDocument,
    KnowledgeProvenance,
    KnowledgeSourceClaims,
)


class IngestionReport:
    """
    Provider-agnostic, audit-friendly outcome of one ingestion
    pass.

    The report deliberately does NOT expose LLM provider
    metadata. ``persisted_knowledge_id`` and ``created`` are the
    only fields tied to the knowledge store; everything else is
    bookkeeping for the caller and for the audit log.
    """

    __slots__ = (
        "persisted_knowledge_id",
        "created",
        "accepted_claim_count",
        "rejected_claim_count",
        "quarantined_claim_count",
        "notes",
    )

    def __init__(
        self,
        persisted_knowledge_id: str | None,
        *,
        created: bool,
        accepted_claim_count: int,
        rejected_claim_count: int,
        quarantined_claim_count: int = 0,
        notes: list[str] | None = None,
    ) -> None:
        self.persisted_knowledge_id = persisted_knowledge_id
        self.created = created
        self.accepted_claim_count = accepted_claim_count
        self.rejected_claim_count = rejected_claim_count
        self.quarantined_claim_count = quarantined_claim_count
        self.notes: list[str] = list(notes or [])

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return (
            "IngestionReport("
            f"persisted_knowledge_id={self.persisted_knowledge_id!r}, "
            f"created={self.created!r}, "
            f"accepted={self.accepted_claim_count}, "
            f"rejected={self.rejected_claim_count}, "
            f"quarantined={self.quarantined_claim_count})"
        )


def _parse_llm_json(raw: str) -> dict:
    """
    Extract the first valid JSON object from an LLM response.

    Handles ```` ```json ... ``` ``` fences, valid JSON followed
    by extra prose, and surrounding whitespace. Raises
    :class:`IngestionError` on failure.
    """

    text = raw.strip()
    if text.startswith("```"):
        text = text.replace("```json", "", 1)
        text = text.replace("```", "", 1).strip()

    decoder = json.JSONDecoder()
    start = text.find("{")
    if start == -1:
        raise IngestionError(
            "LLM response does not contain a JSON object."
        )

    try:
        data, _ = decoder.raw_decode(text[start:])
    except json.JSONDecodeError as exc:
        raise IngestionError(
            f"LLM returned invalid JSON: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise IngestionError(
            "LLM JSON root must be an object."
        )
    return data


def _build_prompt(source: SourceDocument) -> str:
    """
    Build a deterministic extraction prompt. The full source
    content is included; the prompt makes the source identity
    and the extraction rules explicit.
    """

    metadata: dict[str, object] = {
        "title": source.title,
        "source_url": source.source_url,
        "source_type": source.source_type,
        "published_at": source.published_at,
        "tags": sorted(source.tags),
    }
    metadata_block = json.dumps(
        metadata, ensure_ascii=False, sort_keys=True, indent=2
    )

    return f"""
You are an expert security research analyst performing evidence
extraction from a single research source handed to you by the
ingestion layer.

SOURCE METADATA
---------------

{metadata_block}

RULES
-----

1. Extract ONLY information explicitly supported by the
   supplied source content below. Do NOT invent technologies,
   XSS types, contexts, WAFs, techniques, payload patterns,
   or verification patterns.
2. Every claim MUST carry at least one evidence_snippet whose
   ``text`` is a verbatim excerpt from the source content.
3. For each claim, set ``evidence_class`` to EXACTLY one of:
   - "EXPLICIT"        (the source literally states it)
   - "STRONGLY_IMPLIED" (the source strongly implies it)
   - "MODEL_INFERENCE"  (you are inferring it; the source
                         does not directly state it)
4. MODEL_INFERENCE claims are quarantined and NEVER become
   trusted knowledge. Prefer EXPLICIT or STRONGLY_IMPLIED.
5. Do NOT return executable payload fragments, ``<script>``
   tags, ``javascript:`` URLs, event-handler attributes, or
   very long base64-style blobs. Use short pattern LABELS
   instead (for example
   "attribute breakout marker",
   "dom-sink execution", "hash-based marker").
6. Do NOT include any system- or provider-specific fields.

CONFIDENCE BAND
---------------

EXPLICIT        -> 0.80 .. 1.00
STRONGLY_IMPLIED -> 0.55 .. 0.79
MODEL_INFERENCE  -> 0.00 .. 0.54

The confidence value MUST fall within the band for the
chosen evidence_class.

OUTPUT SCHEMA
-------------

Return ONLY valid JSON matching this schema:

{{
  "source": {{
    "title": "string",
    "source_url": "string",
    "source_type": "string",
    "published_at": "string or null",
    "content": "string (echo back unchanged)",
    "tags": ["string"]
  }},
  "claims": [
    {{
      "evidence_class": "EXPLICIT" | "STRONGLY_IMPLIED" | "MODEL_INFERENCE",
      "rationale": "string",
      "evidence_snippets": [
        {{"text": "verbatim source excerpt", "section": "label or null"}}
      ],
      "title": "string or null",
      "summary": "string or null",
      "technologies": ["string"],
      "xss_types": ["string"],
      "contexts": ["string"],
      "wafs": ["string"],
      "techniques": ["string"],
      "payload_patterns": ["string"],
      "verification_patterns": ["string"],
      "tags": ["string"],
      "evidence_quality": "string",
      "confidence": 0.0,
      "forbidden_values": [],
      "strict_payloads": true
    }}
  ],
  "extraction_notes": ["string"]
}}

SOURCE CONTENT
--------------

<<<
{source.content}
>>>
"""


def _snippet_grounded(
    snippet_text: str, content: str
) -> bool:
    return value_grounded(snippet_text, content)


def _claim_value_grounded(
    claim: ExtractedClaim, content: str
) -> tuple[bool, str | None]:
    """
    Return ``(supported, reason)`` for a single claim.

    A claim is "supported" if at least one of its
    ``evidence_snippets`` is grounded in the source content.
    The list-valued fields themselves are not required to
    appear verbatim; the spec permits permissive support
    "when the source clearly supports it through an evidence
    snippet". The list values are not promoted to
    trusted knowledge on their own; they ride on the
    snippet grounding.
    """

    if not claim.evidence_snippets:
        return False, "no evidence snippets"

    for snippet in claim.evidence_snippets:
        if _snippet_grounded(snippet.text, content):
            return True, None
    return False, "no grounded evidence snippet"


def _claim_passes_payload_safety(
    claim: ExtractedClaim,
) -> tuple[bool, list[str]]:
    """
    Defence-in-depth payload check.

    ``ExtractedClaim``'s own validators normally raise
    ``IngestionError`` on a forbidden construct, but the LLM
    can produce a non-strict claim that lists offenders in
    ``forbidden_values``. We re-run the scan here so the
    agent has a single, auditable view of the outcome
    regardless of the LLM-side ``strict_payloads`` flag.
    """

    offenders: list[str] = []
    for value in claim.payload_patterns:
        if contains_forbidden(value):
            offenders.append(value)
    for value in claim.verification_patterns:
        if contains_forbidden(value):
            offenders.append(value)
    for snippet in claim.evidence_snippets:
        if contains_forbidden(snippet.text):
            offenders.append(snippet.text)
    return (not offenders), offenders


def _build_knowledge_provenance(
    source: SourceDocument,
    claims: list[ExtractedClaim],
) -> KnowledgeProvenance:
    return KnowledgeProvenance(
        source_id=source_id(source.source_type, source.source_url),
        source_url=canonicalize_source_url(source.source_url),
        source_type=source.source_type.strip().lower(),
        published_at=source.published_at,
        ingested_at=datetime.now(timezone.utc).isoformat(),
        title=source.title,
        claims=[
            claim.to_knowledge_source_claims() for claim in claims
        ],
    )


def _build_knowledge_id(document_hash: str) -> str:
    """
    Mirror of :func:`ai.knowledge.store._knowledge_id`.

    The store's helper is module-private by convention; the
    ingestion agent reproduces the exact rule so its
    pre-construction ``knowledge_id`` matches the value the
    store will compute on the way in.
    """

    return f"kb-{document_hash[:16]}"


def _build_knowledge_document(
    source: SourceDocument,
    accepted_claims: list[ExtractedClaim],
) -> KnowledgeDocument:
    document_hash = content_hash(source.content)
    knowledge_id = _build_knowledge_id(document_hash)
    provenance = _build_knowledge_provenance(
        source, accepted_claims
    )

    return KnowledgeDocument(
        schema_version=2,
        knowledge_id=knowledge_id,
        title=source.title,
        source_url=source.source_url,
        source_type=source.source_type,
        published_at=source.published_at,
        content=source.content,
        summary=None,
        technologies=[],
        xss_types=[],
        contexts=[],
        wafs=[],
        techniques=[],
        payload_patterns=[],
        verification_patterns=[],
        tags=sorted(source.tags),
        evidence_quality=provenance.claims[0].evidence_quality
        if provenance.claims
        else "UNVERIFIED",
        confidence=provenance.claims[0].confidence
        if provenance.claims
        else 0.0,
        content_hash=document_hash,
        provenance=[provenance],
        aggregate=KnowledgeAggregate(),
    )


class KnowledgeIngestionAgent:
    """
    Provider-agnostic ingestion layer.

    The agent:
      1. builds a deterministic prompt from a
         :class:`SourceDocument`,
      2. calls the injected :class:`LLMProvider`,
      3. parses the JSON response into an
         :class:`ExtractionResult`,
      4. validates every claim (grounding, payload safety,
         evidence class), and
      5. persists the surviving claims through the injected
         :class:`KnowledgeStore`.

    The agent never performs web requests, never instantiates
    an LLM provider, and never writes JSON files directly to
    disk. ``MODEL_INFERENCE`` claims are quarantined and never
    reach the knowledge store.
    """

    def __init__(
        self,
        llm: LLMProvider,
        store: KnowledgeStore,
    ) -> None:
        self.llm = llm
        self.store = store

    def ingest(self, source: SourceDocument) -> IngestionReport:
        notes: list[str] = []

        prompt = _build_prompt(source)
        provider_result = self.llm.complete(prompt)
        raw = provider_result.content

        try:
            data = _parse_llm_json(raw)
        except IngestionError as exc:
            notes.append(f"malformed_json: {exc}")
            return IngestionReport(
                None,
                created=False,
                accepted_claim_count=0,
                rejected_claim_count=0,
                quarantined_claim_count=0,
                notes=notes,
            )

        try:
            result = ExtractionResult.model_validate(data)
        except (ValidationError, IngestionError) as exc:
            notes.append(f"schema_invalid: {exc}")
            return IngestionReport(
                None,
                created=False,
                accepted_claim_count=0,
                rejected_claim_count=0,
                quarantined_claim_count=0,
                notes=notes,
            )

        accepted: list[ExtractedClaim] = []
        rejected = 0
        quarantined = 0
        for index, claim in enumerate(result.claims):
            supported, reason = _claim_value_grounded(
                claim, source.content
            )
            if not supported:
                rejected += 1
                notes.append(
                    f"claim[{index}].evidence: rejected ({reason})"
                )
                continue

            payload_ok, offenders = _claim_passes_payload_safety(
                claim
            )
            if not payload_ok:
                rejected += 1
                notes.append(
                    f"claim[{index}].payload: rejected "
                    f"(forbidden constructs: {offenders!r})"
                )
                continue

            if claim.evidence_class == "MODEL_INFERENCE":
                quarantined += 1
                notes.append(
                    f"claim[{index}]: quarantined "
                    "(MODEL_INFERENCE never trusted)"
                )
                continue

            accepted.append(claim)

        if not accepted:
            notes.append("no accepted claims; nothing persisted")
            return IngestionReport(
                None,
                created=False,
                accepted_claim_count=0,
                rejected_claim_count=rejected,
                quarantined_claim_count=quarantined,
                notes=notes,
            )

        document = _build_knowledge_document(source, accepted)
        stored, created = self.store.ingest(document)

        return IngestionReport(
            stored.knowledge_id,
            created=created,
            accepted_claim_count=len(accepted),
            rejected_claim_count=rejected,
            quarantined_claim_count=quarantined,
            notes=notes,
        )
