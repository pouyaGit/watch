"""Stage R7 — LLM-assisted XSS research assistant.

Sits ABOVE the deterministic :class:`XSSResearchCandidate` (Stage R3).
The deterministic agent remains the authority for candidate scoring,
status, evidence references and research classification. The LLM is
ONLY a research/synthesis assistant that turns a candidate + its
matched KB evidence into a structured, bounded research explanation.

Data flow:

    KnowledgeStore
        ↓
    Deterministic XSS Agent → candidate + evidence
        ↓
    LLM Research Assistant (this module)
        ↓
    Structured research explanation
        ↓
    ai_data/research/xss/llm/<candidate_id>.json  (read-only dashboard/report)

The LLM MUST NOT execute anything, generate/send HTTP requests, run
Nuclei, invoke subprocesses, access Mongo, create production findings
or alerts, modify scope, upgrade candidate status, override
deterministic confidence, invent evidence, invent URLs, or claim
exploitation was verified.

This module has NO network code itself: it calls the injected
:class:`LLMProvider` (the existing OpenRouter wrapper). Input to the
LLM is minimized and deterministically bounded. Output is validated
structurally and the authority invariants (status, confidence,
references, evidence attribution, URL allow-list) are enforced; any
violation rejects the response with no partial persistence.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ai.llm.base import LLMProvider
from ai.researcher.xss_llm_researcher import _parse_llm_json
from ai.schemas.xss import XSSLLMResearchAssistantResult, XSSResearchCandidate

LLM_RESEARCH_DIR = Path("ai_data/research/xss/llm")

# Deterministic bounding knobs (input minimization).
MAX_EVIDENCE_DOCS = 10
MAX_DOC_CONTENT_CHARS = 1200
MAX_SOURCE_EVIDENCE = 10
MAX_PROMPT_CHARS = 20000

_URL_TOKEN_RE = re.compile(r"https?://[^\s\"'<>]+")


class XSSLLMResearchError(ValueError):
    """Raised for any LLM-research boundary violation or input problem."""


# ---------------------------------------------------------------------------
# Candidate / evidence projection (input minimization)
# ---------------------------------------------------------------------------


def _bounded(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    text = str(text).strip()
    if not text:
        return None
    if len(text) > limit:
        text = text[:limit] + "…[truncated]"
    return text


def _candidate_projection(candidate: dict) -> dict:
    """Project the deterministic candidate to the fields the LLM may see.

    Unrelated corpus, filesystem paths (beyond the candidate id) and
    any secrets are excluded. Only the fields needed to reason about
    THIS candidate are sent.
    """
    evidence = []
    for item in (candidate.get("source_evidence") or [])[:MAX_SOURCE_EVIDENCE]:
        evidence.append(
            {
                "knowledge_id": item.get("knowledge_id"),
                "title": item.get("title"),
                "score": item.get("score"),
                "reasons": item.get("reasons") or [],
            }
        )
    return {
        "candidate_id": candidate.get("candidate_id"),
        "status": candidate.get("status"),
        "query": _bounded(candidate.get("query"), 400),
        "xss_type": candidate.get("xss_type"),
        "context": candidate.get("context"),
        "injection_context": candidate.get("injection_context"),
        "confidence": candidate.get("confidence"),
        "vulnerability_pattern": _bounded(
            candidate.get("vulnerability_pattern"), 500
        ),
        "sinks": [s.get("value") for s in (candidate.get("sinks") or [])],
        "sources": [s.get("value") for s in (candidate.get("sources") or [])],
        "preconditions": [
            _bounded(p, 300) for p in (candidate.get("preconditions") or [])
        ],
        "unknowns": [_bounded(u, 300) for u in (candidate.get("unknowns") or [])],
        "source_evidence": evidence,
        "references": candidate.get("references") or [],
    }


def _evidence_projection(documents: list[Any]) -> list[dict]:
    """Bounded, deterministic projection of matched KB documents."""
    projected = []
    for doc in documents[:MAX_EVIDENCE_DOCS]:
        aggregate = getattr(doc, "aggregate", None)

        def _values(field: str) -> list[str]:
            vals: list[str] = []
            if aggregate is not None:
                for item in getattr(aggregate, field, []) or []:
                    vals.append(str(getattr(item, "value", item)))
            vals.extend(str(v) for v in (getattr(doc, field, None) or []))
            return sorted({v for v in vals if v.strip()})

        projected.append(
            {
                "knowledge_id": getattr(doc, "knowledge_id", None),
                "title": _bounded(getattr(doc, "title", None), 300),
                "source_url": getattr(doc, "source_url", None),
                "source_type": getattr(doc, "source_type", None),
                "evidence_quality": getattr(doc, "evidence_quality", None),
                "confidence": getattr(doc, "confidence", None),
                "xss_types": _values("xss_types"),
                "contexts": _values("contexts"),
                "technologies": _values("technologies"),
                "summary": _bounded(getattr(doc, "summary", None), 600),
                "content": _bounded(getattr(doc, "content", None), MAX_DOC_CONTENT_CHARS),
            }
        )
    return projected


# ---------------------------------------------------------------------------
# Prompt (bounded, minimized)
# ---------------------------------------------------------------------------


def _build_prompt(candidate: dict, evidence: list[dict]) -> str:
    projection = _candidate_projection(candidate)
    prompt = f"""
You are an XSS research assistant. You are given ONE deterministic
research candidate and the knowledge-base evidence the deterministic
agent matched to it. You produce a structured research explanation.

THE DETERMINISTIC CANDIDATE IS AUTHORITATIVE. You MUST:
- keep status and confidence exactly as given; never upgrade REJECTED or
  INSUFFICIENT_EVIDENCE to RESEARCH_CANDIDATE, never change confidence;
- only reason about what the supplied evidence supports;
- never claim exploitation was verified, never invent URLs, never invent
  knowledge_ids, never invent evidence.

DETERMINISTIC CANDIDATE (authoritative)
--------------------------------------
{json.dumps(projection, ensure_ascii=False, indent=2)}

SUPPLIED KB EVIDENCE (matched by the deterministic agent)
----------------------------------------------------------
{json.dumps(evidence, ensure_ascii=False, indent=2)}

EVIDENCE / INFERENCE / UNKNOWN RULES
------------------------------------
For the "evidence" array, each item MUST have kind one of:
  EVIDENCE   = a fact directly present in the supplied KB evidence.
              You MUST set knowledge_ids to the exact knowledge_id(s)
              from the supplied evidence that support it.
  INFERENCE  = your model interpretation/reasoning.
              knowledge_ids MUST be an empty list.
  UNKNOWN    = a fact that cannot be established from the supplied
              evidence. knowledge_ids MUST be an empty list.
Never convert inference into evidence. If the supplied evidence does not
establish something (e.g. cookie theft, actual reflection), mark it
UNKNOWN. Prefer the phrasing "The supplied evidence indicates X. Y is
not established by the supplied evidence."

REFERENCES / URLS
-----------------
"references_used" MUST contain ONLY knowledge_ids present in the
supplied KB evidence. Do NOT include any other identifiers or URLs.
Do NOT introduce any URL that is not exactly one of the supplied
evidence source_urls.

RETURN ONLY VALID JSON MATCHING THIS SCHEMA
-------------------------------------------
{{
  "candidate_id": "string (exactly as given)",
  "status": "string (exactly as given)",
  "confidence": 0.0,
  "explanation": "string",
  "likely_attack_surface": "string or null",
  "relevant_context": "string or null",
  "supporting_reasoning": ["string"],
  "missing_evidence": ["string"],
  "suggested_test_idea": "string or null",
  "references_used": ["kb-..."],
  "evidence": [
    {{"kind": "EVIDENCE|INFERENCE|UNKNOWN", "text": "string", "knowledge_ids": ["kb-..."]}}
  ]
}}
"""
    if len(prompt) > MAX_PROMPT_CHARS:
        prompt = prompt[:MAX_PROMPT_CHARS] + "\n[truncated]\n"
    return prompt


# ---------------------------------------------------------------------------
# Validation (structural determinism + authority enforcement)
# ---------------------------------------------------------------------------


def _supplied_urls(evidence: list[dict]) -> set[str]:
    urls: set[str] = set()
    for doc in evidence:
        url = doc.get("source_url")
        if url:
            urls.add(str(url))
    return urls


def _check_authority(
    result: XSSLLMResearchAssistantResult, candidate: dict
) -> None:
    if result.candidate_id != candidate.get("candidate_id"):
        raise XSSLLMResearchError(
            f"LLM returned candidate_id {result.candidate_id!r} but "
            f"deterministic candidate is {candidate.get('candidate_id')!r}"
        )
    det_status = candidate.get("status")
    if result.status != det_status:
        raise XSSLLMResearchError(
            f"LLM attempted to change status: {result.status!r} != "
            f"deterministic {det_status!r}"
        )
    det_conf = candidate.get("confidence")
    if det_conf is None or abs(float(result.confidence) - float(det_conf)) > 1e-9:
        raise XSSLLMResearchError(
            f"LLM attempted to override confidence: {result.confidence!r} "
            f"!= deterministic {det_conf!r}"
        )
    det_hash = candidate.get("content_hash")
    if not det_hash:
        raise XSSLLMResearchError("deterministic content_hash is unavailable")
    # content_hash is a verifier-derived binding, not model output: the
    # model never supplies it and can never change it. This asserts that
    # the verifier-stamped binding is intact.
    if result.content_hash != det_hash:
        raise XSSLLMResearchError(
            "content_hash binding mismatch (verifier-stamped value only)"
        )


def _check_references(
    result: XSSLLMResearchAssistantResult, supplied_ids: set[str]
) -> None:
    for kid in result.references_used:
        if kid not in supplied_ids:
            raise XSSLLMResearchError(
                f"LLM introduced a knowledge_id not in supplied evidence: {kid!r}"
            )


def _check_evidence_attribution(
    result: XSSLLMResearchAssistantResult, supplied_ids: set[str]
) -> None:
    for item in result.evidence:
        kids = set(item.knowledge_ids)
        if item.kind == "EVIDENCE":
            if not kids:
                raise XSSLLMResearchError(
                    "EVIDENCE item lacks knowledge_ids: " f"{item.text!r}"
                )
            if not kids.issubset(supplied_ids):
                unknown = kids - supplied_ids
                raise XSSLLMResearchError(
                    f"EVIDENCE item cites unknown knowledge_ids: {sorted(unknown)!r}"
                )
        else:  # INFERENCE / UNKNOWN
            if kids:
                raise XSSLLMResearchError(
                    f"{item.kind} item must not carry knowledge_ids: {item.text!r}"
                )


def _check_urls(
    result: XSSLLMResearchAssistantResult, supplied_urls: set[str]
) -> None:
    fields = [
        result.explanation,
        result.likely_attack_surface,
        result.relevant_context,
        result.suggested_test_idea,
        *(result.supporting_reasoning or []),
        *(result.missing_evidence or []),
        *(item.text for item in result.evidence),
    ]
    for field in fields:
        for token in _URL_TOKEN_RE.findall(field or ""):
            if not any(token.startswith(url) for url in supplied_urls):
                raise XSSLLMResearchError(
                    f"LLM introduced an arbitrary URL not in supplied evidence: {token!r}"
                )


def _load_evidence(
    candidate: dict, store: Any
) -> list[Any]:
    """Load the referenced KB documents (deterministic order, bounded)."""
    ids = sorted(set(candidate.get("references") or []))
    documents = []
    for kid in ids:
        if len(documents) >= MAX_EVIDENCE_DOCS:
            break
        try:
            doc = store.get_by_id(kid)
        except ValueError as exc:
            raise XSSLLMResearchError(f"knowledge-store readback failed: {exc}") from exc
        if doc is not None:
            documents.append(doc)
    return documents


def build_research_assistant_result(
    candidate: dict,
    evidence: list[dict],
    llm_data: dict,
    model: str | None = None,
    raw_response_id: str | None = None,
) -> XSSLLMResearchAssistantResult:
    """Validate a fully-resolved LLM research assistant response.

    Rejects malformed/authority-violating responses; never coerces
    malformed evidence into valid evidence.
    """
    supplied_ids = {doc["knowledge_id"] for doc in evidence if doc.get("knowledge_id")}
    # content_hash is a verifier-derived binding. The model is never asked
    # to produce it, so any model-supplied value is discarded (never
    # trusted, never compared). The deterministic value is stamped from
    # trusted local state after validation.
    llm_data = dict(llm_data)
    llm_data.pop("content_hash", None)
    payload = {
        "candidate_id": candidate.get("candidate_id"),
        "status": candidate.get("status"),
        "confidence": candidate.get("confidence"),
        "content_hash": candidate.get("content_hash"),
    }
    payload.update(llm_data)
    result = XSSLLMResearchAssistantResult.model_validate(payload)
    _check_authority(result, candidate)
    _check_references(result, supplied_ids)
    _check_evidence_attribution(result, supplied_ids)
    _check_urls(result, _supplied_urls(evidence))
    return result.model_copy(update={"model": model, "raw_response_id": raw_response_id})


class XSSLLMResearchAssistant:
    """LLM research assistant over a deterministic XSS candidate."""

    def __init__(self, llm: LLMProvider) -> None:
        self.llm = llm

    def research(
        self,
        candidate: dict,
        store: Any,
        *,
        content_hash: str | None = None,
    ) -> XSSLLMResearchAssistantResult:
        documents = _load_evidence(candidate, store)
        if not documents:
            raise XSSLLMResearchError(
                "no KB evidence available for this candidate; "
                "failing closed (no LLM call)"
            )
        evidence = _evidence_projection(documents)
        if content_hash is None:
            content_hash = _candidate_content_hash(candidate)
        candidate = dict(candidate)
        candidate["content_hash"] = content_hash

        prompt = _build_prompt(candidate, evidence)
        provider_result = self.llm.complete(prompt)

        try:
            data = _parse_llm_json(provider_result.content)
        except ValueError as exc:
            raise XSSLLMResearchError(f"LLM returned malformed JSON: {exc}") from exc

        try:
            result = build_research_assistant_result(
                candidate,
                evidence,
                data,
                model=provider_result.model,
                raw_response_id=provider_result.request_id,
            )
        except ValidationError as exc:
            raise XSSLLMResearchError(
                f"LLM response failed schema validation: {exc}"
            ) from exc
        return result


def _candidate_content_hash(candidate: dict) -> str:
    """Deterministic content hash of the deterministic candidate payload.

    The ``content_hash`` field itself (if present) is excluded so the
    hash is stable regardless of when it was attached.
    """
    payload = {k: v for k, v in candidate.items() if k != "content_hash"}
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _result_to_json(result: XSSLLMResearchAssistantResult) -> str:
    return (
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def persist_research(
    result: XSSLLMResearchAssistantResult,
    output_path: str | Path | None = None,
    research_dir: str | Path = LLM_RESEARCH_DIR,
) -> Path:
    """Persist the LLM research output atomically, keyed by candidate_id.

    One record per candidate_id; re-running overwrites the same file
    (idempotent, no duplicates). The deterministic candidate JSON is
    never overwritten.
    """
    dest = (
        Path(output_path)
        if output_path is not None
        else Path(research_dir) / f"{result.candidate_id}.json"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(_result_to_json(result), encoding="utf-8")
    tmp.replace(dest)
    return dest
