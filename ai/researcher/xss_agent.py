"""Deterministic XSS research agent MVP (Stage R3).

Consumes ONLY persisted/local knowledge:

- bundled deterministic seed documents (``ai/researcher/xss_seed/``),
- any additional documents in a :class:`KnowledgeStore`,
- optionally persisted research JSON supplied by the caller.

Produces a structured :class:`XSSResearchCandidate` persisted under
``ai_data/research/xss/<candidate_id>.json``.

This is NOT a generic autonomous agent: matching is a fixed,
explainable, deterministic scoring function over the seeded XSS KB.
No vector database, no embeddings, no LLM, no network, no subprocess,
no browser, no Nuclei, no production verifier, no finding
materialization, no alerting.

A candidate NEVER claims exploitability from a pattern match. Status
is one of ``RESEARCH_CANDIDATE``, ``INSUFFICIENT_EVIDENCE`` or
``REJECTED``.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ai.schemas.xss import (
    XSSAttributedSink,
    XSSCandidateSourceEvidence,
    XSSResearchCandidate,
)

AGENT_VERSION = "xss-mvp-1"

SEED_DIR = Path(__file__).parent / "xss_seed"
XSS_RESEARCH_DIR = Path("ai_data/research/xss")

# Supported (xss_type, context) categories. The bundled seed covers at
# least these three; additional store documents may extend coverage.
SUPPORTED_CATEGORIES = (
    ("reflected", "html_attribute"),
    ("reflected", "script"),
    ("dom", "javascript"),
)

# Deterministic scoring weights (documented for explainability).
W_TYPE_EXACT = 4
W_CONTEXT_EXACT = 4
W_TECHNOLOGY_OVERLAP = 2
W_TECHNIQUE_OVERLAP = 1
W_KEYWORD = 1
MAX_KEYWORD_POINTS = 3

# Query signal keywords. Fixed tables, evaluated in sorted order for
# deterministic signal extraction.
TYPE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "reflected": ("reflect",),
    "stored": ("stored", "persist",),
    "dom": ("dom",),
}
CONTEXT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "html_attribute": ("attribute", "attr", "event handler", "onfocus", "onerror", "quoted"),
    "script": ("script", "script block"),
    "javascript": ("javascript", "sink", "hash", "innerhtml", "eval", "fragment"),
}
GENERIC_XSS_KEYWORDS = ("xss", "cross-site scripting", "cross site scripting")

# Sink/source vocabulary extracted ONLY when literally present in a
# matched document's persisted text (never invented).
SINK_VOCABULARY = (
    "innerhtml",
    "outerhtml",
    "document.write",
    "eval",
    "insertadjacenthtml",
    "inline script",
)
SOURCE_VOCABULARY = (
    "location.hash",
    "location.search",
    "document.referrer",
    "postmessage",
    "query parameter",
    "fragment",
)


class XSSAgentError(ValueError):
    """Raised for malformed input or unreadable persisted artifacts."""


def _normalize(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _norm_set(values: Any) -> set[str]:
    items = values if isinstance(values, list) else [values]
    return {_normalize(str(v)) for v in items if str(v or "").strip()}


def _doc_values(document: Any, field: str) -> list[str]:
    aggregate = getattr(document, "aggregate", None)
    values: list[str] = []
    if aggregate is not None:
        for item in getattr(aggregate, field, []) or []:
            values.append(str(getattr(item, "value", item)))
    for item in getattr(document, field, []) or []:
        values.append(str(item))
    # Deterministic: sorted unique, drop empties.
    return sorted({v for v in values if v.strip()})


def _doc_text(document: Any) -> str:
    return "\n".join(
        [
            str(getattr(document, "title", "") or ""),
            str(getattr(document, "summary", "") or ""),
            str(getattr(document, "content", "") or ""),
            " ".join(_doc_values(document, "techniques")),
            " ".join(_doc_values(document, "payload_patterns")),
        ]
    ).lower()


def load_seed_documents() -> list[Any]:
    """Load bundled seed documents as validated KnowledgeDocuments."""
    from ai.knowledge.store import content_hash
    from ai.schemas.knowledge import KnowledgeDocument

    documents = []
    for path in sorted(SEED_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise XSSAgentError(f"invalid seed document: {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise XSSAgentError(f"invalid seed document (not an object): {path}")
        payload.setdefault("knowledge_id", "seed-placeholder")
        document = KnowledgeDocument.model_validate(payload)
        digest = content_hash(document.content)
        document = document.model_copy(
            update={"content_hash": digest, "knowledge_id": f"kb-{digest[:16]}"}
        )
        documents.append(document)
    documents.sort(key=lambda d: str(d.knowledge_id))
    return documents


def _pool_documents(store: Any | None) -> list[Any]:
    """Seed documents union store documents, deduped by knowledge_id."""
    pooled: dict[str, Any] = {}
    for document in load_seed_documents():
        pooled[str(document.knowledge_id)] = document
    if store is not None:
        try:
            stored = store.retrieve()
        except ValueError as exc:
            raise XSSAgentError(f"knowledge-store readback failed: {exc}") from exc
        for document in stored or []:
            pooled.setdefault(str(document.knowledge_id), document)
    return [pooled[key] for key in sorted(pooled)]


def parse_query_signals(query: str) -> dict[str, list[str]]:
    """Extract deterministic (type, context, keyword) signals from text."""
    lowered = (query or "").lower()
    types = sorted(
        {t for t, words in TYPE_KEYWORDS.items() if any(w in lowered for w in words)}
    )
    contexts = sorted(
        {c for c, words in CONTEXT_KEYWORDS.items() if any(w in lowered for w in words)}
    )
    generic = any(w in lowered for w in GENERIC_XSS_KEYWORDS)
    keywords = sorted(
        {w for w in re.findall(r"[a-z0-9]{4,}", lowered) if w not in {"http", "https"}}
    )
    return {
        "types": types,
        "contexts": contexts,
        "generic": [generic and "xss" or ""],
        "keywords": keywords,
    }


def _score_document(
    document: Any,
    types: list[str],
    contexts: list[str],
    technologies: list[str],
    techniques: list[str],
    keywords: list[str],
) -> tuple[int, list[str]]:
    """Score one document; return (score, human-readable reasons)."""
    score = 0
    reasons: list[str] = []

    doc_types = _norm_set(_doc_values(document, "xss_types"))
    for wanted in sorted(set(types)):
        if _normalize(wanted) in doc_types:
            score += W_TYPE_EXACT
            reasons.append(f"xss_type exact match: {wanted}")

    doc_contexts = _norm_set(_doc_values(document, "contexts"))
    for wanted in sorted(set(contexts)):
        if _normalize(wanted) in doc_contexts:
            score += W_CONTEXT_EXACT
            reasons.append(f"context exact match: {wanted}")

    doc_techs = _norm_set(_doc_values(document, "technologies"))
    for wanted in sorted(set(technologies)):
        if wanted and _normalize(wanted) in doc_techs:
            score += W_TECHNOLOGY_OVERLAP
            reasons.append(f"technology overlap: {wanted}")

    doc_techniques = _norm_set(_doc_values(document, "techniques"))
    for wanted in sorted(set(techniques)):
        if wanted and _normalize(wanted) in doc_techniques:
            score += W_TECHNIQUE_OVERLAP
            reasons.append(f"technique overlap: {wanted}")

    haystack = _doc_text(document)
    keyword_points = 0
    for word in sorted(set(keywords)):
        if len(word) >= 4 and word in haystack and keyword_points < MAX_KEYWORD_POINTS:
            score += W_KEYWORD
            keyword_points += 1
            reasons.append(f"keyword '{word}' in document text")

    return score, reasons


def rank_documents(
    query: str,
    store: Any | None = None,
    xss_type: str | None = None,
    context: str | None = None,
    technologies: list[str] | None = None,
    techniques: list[str] | None = None,
) -> tuple[list[dict], dict]:
    """Rank pooled KB documents for a query (deterministic, explainable).

    Returns (ranked_matches, signals). Each match carries
    ``knowledge_id``, ``title``, ``score`` and ``reasons``. Ordering is
    stable: score descending, then knowledge_id ascending.
    """
    signals = parse_query_signals(query)
    types = sorted(set(signals["types"] + ([xss_type] if xss_type else [])))
    contexts = sorted(set(signals["contexts"] + ([context] if context else []))
    )
    techs = sorted(set(signals["keywords"][:0] + list(technologies or [])))
    techns = sorted(set(list(techniques or [])))

    ranked = []
    for document in _pool_documents(store):
        score, reasons = _score_document(
            document, types, contexts, techs, techns, signals["keywords"]
        )
        if score > 0:
            ranked.append(
                {
                    "knowledge_id": str(document.knowledge_id),
                    "title": str(document.title),
                    "score": score,
                    "reasons": sorted(reasons),
                    "document": document,
                }
            )
    ranked.sort(key=lambda m: (-m["score"], m["knowledge_id"]))
    return ranked, {
        "types": types,
        "contexts": contexts,
        "technologies": techs,
        "techniques": techns,
        "generic_xss": bool(
            any(w in (query or "").lower() for w in GENERIC_XSS_KEYWORDS)
        ),
    }


def _extract_vocab(
    documents: list[Any], vocabulary: tuple[str, ...]
) -> list[XSSAttributedSink]:
    found: dict[str, set[str]] = {}
    for document in documents:
        haystack = _doc_text(document)
        for term in vocabulary:
            if term in haystack:
                found.setdefault(term, set()).add(str(document.knowledge_id))
    return [
        XSSAttributedSink(
            value=term, knowledge_ids=sorted(found[term])
        )
        for term in sorted(found)
    ]


def _candidate_id(
    query: str, signals: dict, matches: list[dict]
) -> str:
    fingerprint = "|".join(
        [
            AGENT_VERSION,
            _normalize(query),
            ",".join(signals["types"]),
            ",".join(signals["contexts"]),
            ",".join(f"{m['knowledge_id']}:{m['score']}" for m in matches),
        ]
    )
    return "xss-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]


def _confidence(status: str, top_score: int, num_matches: int) -> float:
    if status == "REJECTED":
        return 0.0
    if status == "INSUFFICIENT_EVIDENCE":
        return round(min(0.35, 0.1 + 0.05 * top_score), 2)
    return round(min(0.9, 0.3 + 0.1 * top_score + 0.05 * num_matches), 2)


def build_candidate(
    query: str,
    store: Any | None = None,
    xss_type: str | None = None,
    context: str | None = None,
    technologies: list[str] | None = None,
    techniques: list[str] | None = None,
) -> XSSResearchCandidate:
    """Build a deterministic XSS research candidate for a query."""
    if not (query or "").strip():
        raise XSSAgentError("empty query: describe the suspected XSS scenario")

    ranked, signals = rank_documents(
        query,
        store=store,
        xss_type=xss_type,
        context=context,
        technologies=technologies,
        techniques=techniques,
    )
    matches = [
        {
            "knowledge_id": m["knowledge_id"],
            "title": m["title"],
            "score": m["score"],
            "reasons": m["reasons"],
        }
        for m in ranked
    ]
    knowledge_ids = sorted({m["knowledge_id"] for m in matches})
    has_xss_signal = bool(signals["types"] or signals["contexts"] or signals["generic_xss"] or xss_type or context)

    if not matches or not has_xss_signal:
        status = "REJECTED"
        reason = (
            "no KB document matched the query signals"
            if has_xss_signal
            else "no XSS-relevant signals in query and no KB match"
        )
        return XSSResearchCandidate(
            candidate_id=_candidate_id(query, signals, []),
            agent_version=AGENT_VERSION,
            status=status,
            query=query.strip(),
            xss_type=xss_type,
            context=context,
            technologies=sorted(technologies or []),
            techniques=sorted(techniques or []),
            source_evidence=[],
            unknowns=[reason, "no source evidence available"],
            references=[],
            confidence=0.0,
        )

    top = ranked[0]
    top_doc = top["document"]
    top_reasons = set(top["reasons"])
    has_type = any(r.startswith("xss_type exact match") for r in top_reasons)
    has_context = any(r.startswith("context exact match") for r in top_reasons)

    if has_type and has_context:
        status = "RESEARCH_CANDIDATE"
    else:
        status = "INSUFFICIENT_EVIDENCE"

    top_docs = [m["document"] for m in ranked[:3]]
    sinks = _extract_vocab(top_docs, SINK_VOCABULARY)
    sources = _extract_vocab(top_docs, SOURCE_VOCABULARY)

    primary_type = signals["types"][0] if signals["types"] else xss_type
    primary_context = signals["contexts"][0] if signals["contexts"] else context

    pattern = None
    test_idea = None
    preconditions: list[str] = []
    unknowns: list[str] = []
    if status == "RESEARCH_CANDIDATE":
        pattern = (
            f"{top['title']} "
            f"(xss_type={primary_type}, context={primary_context}; "
            f"per {top['knowledge_id']})"
        )
        verification = _doc_values(top_doc, "verification_patterns")
        test_idea = (
            f"Untested idea only — never executed: "
            f"{verification[0] if verification else 'observe whether attacker-controlled input reaches the documented context'} "
            f"(per {top['knowledge_id']}). NOT a confirmation of exploitability."
        )
        preconditions = sorted(
            {
                f"attacker-controlled input reaches a {primary_context} context"
                f" (per {top['knowledge_id']})",
                f"output handling matches the documented {primary_type} pattern"
                f" (per {top['knowledge_id']})",
            }
        )
    if not has_type:
        unknowns.append("xss_type: no exact KB type match for the query signals")
    if not has_context:
        unknowns.append("injection context: no exact KB context match")
    if not sinks:
        unknowns.append("sinks: none explicitly stated in matched documents")
    if not sources:
        unknowns.append("sources: none explicitly stated in matched documents")
    unknowns.append("live reflection: not observed (no target contacted)")
    unknowns.append("exploitability: unconfirmed by design (pattern match only)")

    evidence = [
        XSSCandidateSourceEvidence(
            knowledge_id=m["knowledge_id"],
            title=m["title"],
            score=m["score"],
            reasons=m["reasons"],
        )
        for m in matches
    ]

    return XSSResearchCandidate(
        candidate_id=_candidate_id(query, signals, matches),
        agent_version=AGENT_VERSION,
        status=status,
        query=query.strip(),
        xss_type=primary_type,
        context=primary_context,
        technologies=sorted(technologies or []),
        techniques=sorted(techniques or []),
        source_evidence=evidence,
        vulnerability_pattern=pattern,
        injection_context=primary_context,
        sinks=sinks,
        sources=sources,
        preconditions=preconditions,
        test_idea=test_idea,
        confidence=_confidence(
            status, ranked[0]["score"] if ranked else 0, len(ranked)
        ),
        unknowns=sorted(set(unknowns)),
        references=knowledge_ids,
    )


def candidate_to_json(candidate: XSSResearchCandidate) -> str:
    """Stable serialization: sorted keys, fixed indent, trailing newline."""
    return (
        json.dumps(
            candidate.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def persist_candidate(
    candidate: XSSResearchCandidate,
    output_path: str | Path | None = None,
    research_dir: str | Path = XSS_RESEARCH_DIR,
) -> Path:
    """Persist a candidate atomically; return the destination path."""
    dest = Path(output_path) if output_path is not None else (
        Path(research_dir) / f"{candidate.candidate_id}.json"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(candidate_to_json(candidate), encoding="utf-8")
    tmp.replace(dest)
    return dest


def research_and_persist(
    query: str,
    store: Any | None = None,
    xss_type: str | None = None,
    context: str | None = None,
    technologies: list[str] | None = None,
    techniques: list[str] | None = None,
    output_path: str | Path | None = None,
    research_dir: str | Path = XSS_RESEARCH_DIR,
) -> tuple[XSSResearchCandidate, Path]:
    """Build a candidate for a query and persist it (no network, no LLM)."""
    candidate = build_candidate(
        query,
        store=store,
        xss_type=xss_type,
        context=context,
        technologies=technologies,
        techniques=techniques,
    )
    return candidate, persist_candidate(
        candidate, output_path=output_path, research_dir=research_dir
    )


def list_candidates(
    research_dir: str | Path = XSS_RESEARCH_DIR,
) -> list[dict]:
    """List persisted candidates (id, status, query) in stable order."""
    root = Path(research_dir)
    if not root.exists():
        return []
    items = []
    for path in sorted(root.glob("xss-*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        items.append(
            {
                "candidate_id": payload.get("candidate_id", path.stem),
                "status": payload.get("status", "UNKNOWN"),
                "query": payload.get("query", ""),
                "path": path.as_posix(),
            }
        )
    items.sort(key=lambda i: str(i["candidate_id"]))
    return items


def load_candidate(
    candidate_id: str, research_dir: str | Path = XSS_RESEARCH_DIR
) -> dict:
    """Load one persisted candidate by id (deterministic failure)."""
    candidate_id = (candidate_id or "").strip()
    if not re.match(r"^xss-[0-9a-f]{16}$", candidate_id):
        raise XSSAgentError(f"invalid candidate id: {candidate_id!r}")
    path = Path(research_dir) / f"{candidate_id}.json"
    if not path.exists():
        raise XSSAgentError(f"unknown candidate id: {candidate_id} ({path} not found)")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise XSSAgentError(f"invalid candidate artifact: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise XSSAgentError(f"invalid candidate artifact (not an object): {path}")
    return payload
