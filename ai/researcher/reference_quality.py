"""Deterministic reference-context quality gate (research-only).

Validates the per-CVE ``ReferenceContext`` material produced by the
EXISTING ``build_research_contexts`` / ``ReferenceRanker.build``
pipeline before it reaches ``SecurityResearcher``. This is NOT a new
ranking system, NOT an LLM judge, NOT a provider change, and NOT a
persistent cache.

Existing abstractions reused (never replaced, never modified):

- ``ai.researcher.research_context.build_research_contexts`` (context
  construction; ranking algorithm untouched).
- ``ai.collectors.reference_ranker.ReferenceRanker.CVE_PATTERN`` (the
  existing CVE identifier pattern, reused for identity scoping).
- ``ai.researcher.reference_cache.canonicalize_reference_url`` (the
  frozen cache-key canonicalization, reused for dedup keys only;
  the actual source URL is never altered).
- ``ai.schemas.reference.ReferenceDocument`` / ``ReferenceContext``
  (value types; the gate never invents new fields).

Contract (pure, deterministic, offline — no LLM, no network, no
subprocess):

- Input: the ``contexts_raw`` list of dicts produced by
  ``build_research_contexts`` for ONE CVE, plus that CVE's id and
  the set of source URLs the discovery/fetch layer actually
  produced for it (``known_urls``).
- Output: ``(kept, rejected)`` where ``kept`` is a filtered list
  containing the SAME dict objects in the SAME order (never
  reordered, never mutated, never replaced), and ``rejected`` is
  True when a non-empty input lost at least one entry.
- Per-entry keep rules (an entry is dropped when any rule fails):
  1. Entry is a dict with a non-empty string ``url``; when
     ``known_urls`` is provided the URL must be a member (source
     integrity: no synthetic references).
  2. ``exact_record``, when present (not None), must be a
     non-empty string containing the current CVE id
     (case-insensitive); an exact record scoped to another CVE
     is dropped (CVE identity).
  3. The entry's scoped text (``exact_record`` plus all
     ``context_chunks``) must not mention only foreign CVE ids:
     when CVE ids are found anywhere in the entry and the
     current CVE id is not among them, the entry is dropped.
     Entries mentioning no CVE id at all are kept (fallback
     tolerance for keyword-scoped vendor material produced by
     the existing ranker).
  4. An entry with no ``exact_record`` and no non-empty chunk
     is dropped (empty reference content).
  5. Duplicate source URLs within the one CVE (compared by the
     frozen canonical key) keep only the first occurrence
     (dedup); the surviving entry keeps its ORIGINAL source URL.
- Missing/empty ``cve_id``: identity cannot be established, so a
  non-empty input is dropped entirely (fail closed, ``rejected``
  True); an empty input stays empty (``rejected`` False).
- Content-hash note: the existing ``ReferenceContext`` schema
  carries no hash and no raw content, so hash validation is NOT
  supported by the existing schema. The gate therefore performs
  no hash check and invents no new hash algorithm; existing
  content hashes upstream are preserved untouched (nothing here
  mutates source content).

Failure behavior (all-invalid input):

- The gate returns an empty list. It never fabricates a
  replacement context, never adds exploit/severity/impact/
  payload claims, and never marks anything authoritative.
- The existing pipeline then proceeds with zero reference
  contexts, letting ``SecurityResearcher`` (and the unchanged
  Nuclei candidate lane) make a conservative decision on CVE
  metadata alone. Provider fail-soft/degraded semantics are
  untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class QualityGateResult:
    """Outcome of gating one CVE's reference contexts."""

    contexts: list[dict] = field(default_factory=list)
    rejected: bool = False


def empty_reference_quality_histogram() -> dict[str, int]:
    """Return a zeroed reference-quality histogram (stable schema)."""
    return {"checked": 0, "rejected": 0}


def gate_reference_contexts(contexts, *, cve_id, known_urls=None) -> QualityGateResult:
    """Filter one CVE's raw reference contexts deterministically.

    See the module docstring for the full contract. Never raises
    on malformed input; never mutates entries; never reorders.
    """
    from ai.collectors.reference_ranker import ReferenceRanker
    from ai.researcher.reference_cache import canonicalize_reference_url

    cve_norm = (cve_id or "").strip()
    if not isinstance(contexts, list):
        return QualityGateResult(
            contexts=[],
            rejected=bool(contexts),
        )
    if not cve_norm:
        # No identity to scope against: fail closed.
        return QualityGateResult(
            contexts=[],
            rejected=len(contexts) > 0,
        )

    cve_upper = cve_norm.upper()
    pattern = ReferenceRanker.CVE_PATTERN
    known = set(known_urls) if known_urls is not None else None

    kept: list[dict] = []
    seen_keys: set[str] = set()
    for entry in contexts:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        if known is not None and url not in known:
            continue

        exact = entry.get("exact_record")
        if exact is not None:
            if not isinstance(exact, str) or not exact.strip():
                continue
            if not re.search(re.escape(cve_norm), exact, re.IGNORECASE):
                continue

        raw_chunks = entry.get("context_chunks")
        if raw_chunks is None:
            raw_chunks = []
        if not isinstance(raw_chunks, list):
            continue
        non_empty = [
            chunk
            for chunk in raw_chunks
            if isinstance(chunk, str) and chunk.strip()
        ]
        scoped_texts: list[str] = []
        if isinstance(exact, str):
            scoped_texts.append(exact)
        scoped_texts.extend(non_empty)
        found: set[str] = set()
        for text in scoped_texts:
            for match in pattern.finditer(text):
                found.add(match.group(0).upper())
        if found and cve_upper not in found:
            continue

        if exact is None and not non_empty:
            continue

        key = canonicalize_reference_url(url)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        kept.append(entry)

    return QualityGateResult(
        contexts=kept,
        rejected=len(kept) < len(contexts),
    )
