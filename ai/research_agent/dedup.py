"""Stage R24.4 — deterministic URL canonicalization and two-level dedup.

Pure, deterministic and **network-free**. This module never performs DNS
resolution, never opens an HTTP client, never fetches a URL and never re-fetches
content. It operates only on already-materialized :class:`DiscoveredSource`
records and already-fetched bodies passed in by the caller.

Two dedup levels (R24 scope §6):

- **Level 1 — URL dedup before fetch**: canonicalize each source URL with
  :func:`canonicalize_url` and merge sources that canonicalize to the same URL,
  preserving aliases and discovery provenance.
- **Level 2 — content-hash dedup after fetch**: when a trusted
  ``content_hash`` is already present, group by hash and collapse identical
  normalized content into one source, keeping the highest-tier /
  highest-quality / lowest-canonical-url / lowest-source-id source as canonical
  and recording the others as aliases.

Determinism guarantees:

- no clock, no randomness, no dictionary/set iteration order leaking into output
  (all aggregates are ``sorted``);
- canonical source selection is a pure total order over
  (tier rank, source_quality desc, canonical_url asc, source_id asc).

Import boundary: standard library + the neutral body-extraction helpers + the
R24.1 contract. No ``ai.execution`` / ``ai.verification`` / ``ai.finding`` /
``ai.resolver`` / ``ai.authorizer`` / ``ai.persistence`` / ``nuclei_runner`` /
browser automation / ``subprocess`` / HTTP client / ``socket`` imports.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

from ai.collectors.body_extraction import normalize_text, sha256_text
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    TrustTier,
)
from ai.schemas.research_agent import MAX_DOC_CHARS

__all__ = [
    "TIER_ORDER",
    "DEFAULT_PORTS",
    "TRACKING_PARAMS",
    "canonicalize_url",
    "canonical_url",
    "github_raw_url",
    "content_hash_for",
    "with_content_hash",
    "provenance_ledger",
    "choose_canonical",
    "merge_group",
    "dedup_by_url",
    "dedup_by_content_hash",
    "dedup_discovered_sources",
]

# Deterministic trust-tier ordering (higher trust = lower rank number). A source
# never promotes its own tier; this table only orders already-assigned tiers.
TIER_ORDER: dict[TrustTier, int] = {
    TrustTier.TRUSTED: 0,
    TrustTier.SEMI_TRUSTED: 1,
    TrustTier.DISCOVERY_ONLY: 2,
    TrustTier.GENERIC: 3,
}

DEFAULT_PORTS: dict[str, str] = {"http": "80", "https": "443"}

# Only clearly non-semantic tracking parameters are removed from the canonical
# key. Every other parameter (including ``id``, ``token``, ``q``, ``page`` ...)
# is preserved byte-for-byte and only re-ordered deterministically.
TRACKING_PARAMS: frozenset[str] = frozenset({"gclid", "fbclid"})

_TRACKING_PREFIXES = ("utm_",)

_GITHUB_BLOB_HOSTS = frozenset({"github.com", "www.github.com"})
_RAW_GITHUB_HOST = "raw.githubusercontent.com"


def _is_tracking_param(name: str) -> bool:
    """True only for clearly non-semantic tracking parameters."""
    return name in TRACKING_PARAMS or any(
        name.startswith(prefix) for prefix in _TRACKING_PREFIXES
    )


def github_raw_url(url: str) -> str | None:
    """Deterministic ``github.com`` blob/raw → ``raw.githubusercontent.com`` map.

    Only exact ``/<owner>/<repo>/blob/<ref>/<path>`` and
    ``/<owner>/<repo>/raw/<ref>/<path>`` paths are rewritten; the remaining path
    is preserved verbatim. Anything else returns ``None``. No repository content
    is fetched or inspected.
    """
    text = str(url or "").strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
    except Exception:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in _GITHUB_BLOB_HOSTS:
        return None
    segments = [seg for seg in parts.path.lstrip("/").split("/")]
    if len(segments) < 4 or segments[2] not in ("blob", "raw"):
        return None
    owner, repo = segments[0], segments[1]
    if not owner or not repo:
        return None
    remainder = "/".join(segments[3:])
    if not remainder:
        return None
    return f"https://{_RAW_GITHUB_HOST}/{owner}/{repo}/{remainder}"


def _canonical_query(query: str) -> str:
    """Drop tracking params and sort the remaining params deterministically.

    Non-tracking parameters are preserved byte-for-byte (name and value,
    including their original percent-encoding); only their order is normalized.
    Empty chunks are dropped so a redundant ``&`` never changes the key.
    """
    if not query:
        return ""
    kept: list[str] = []
    for chunk in query.split("&"):
        if not chunk:
            continue
        name = chunk.split("=", 1)[0]
        if _is_tracking_param(name):
            continue
        kept.append(chunk)
    return "&".join(sorted(kept))


def canonicalize_url(url: object) -> str:
    """Deterministic canonical form of a URL for the R24.4 dedup key.

    Rules (R24 scope §5/§6):

    - trim surrounding whitespace;
    - deterministic GitHub blob/raw → ``raw.githubusercontent.com`` mapping;
    - lowercase scheme and hostname (path case is preserved — it is
      resource-significant);
    - drop the URL fragment;
    - strip default ports (``:80`` for http, ``:443`` for https);
    - drop credentials from the netloc;
    - remove only ``utm_*`` / ``gclid`` / ``fbclid`` query parameters and order
      the remaining parameters deterministically;
    - never resolves DNS, never fetches, never follows redirects.

    Malformed input never raises: it falls back to the whitespace-stripped
    original. Non-string input yields ``""``.
    """
    if url is None:
        return ""
    text = str(url).strip()
    if not text:
        return ""

    mapped = github_raw_url(text)
    if mapped:
        text = mapped

    try:
        parts = urlsplit(text)
    except Exception:
        return text

    scheme = (parts.scheme or "").lower()
    try:
        host = (parts.hostname or "").lower().rstrip(".")
    except Exception:
        host = ""
    if not scheme or not host:
        # Not an absolute URL; return the trimmed original unchanged.
        return text

    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host
    if port is not None and str(port) != DEFAULT_PORTS.get(scheme, ""):
        netloc = f"{host}:{port}"

    path = parts.path
    query = _canonical_query(parts.query)
    try:
        return urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return text


def canonical_url(source: DiscoveredSource | None) -> str:
    """Canonical dedup key for a discovered source.

    Uses ``final_url`` when a fetch/redirect resolution already supplied one
    (R24.3), otherwise ``url`` then ``discovered_url``. Never performs network
    activity.
    """
    if source is None:
        return ""
    candidate = (
        getattr(source, "final_url", None)
        or getattr(source, "url", None)
        or getattr(source, "discovered_url", None)
        or ""
    )
    return canonicalize_url(candidate)


# ---------------------------------------------------------------------------
# Content hashing (reuse the existing trusted normalization + hash)
# ---------------------------------------------------------------------------
def content_hash_for(body: object) -> str | None:
    """Trusted content hash of an already-fetched body.

    ``sha256(normalize_text(body)[:MAX_DOC_CHARS])`` using the existing project
    normalization and hash helpers (no competing algorithm). Returns ``None``
    for empty/normalized-empty bodies. Never fetches anything.
    """
    normalized = normalize_text(str(body or ""))[:MAX_DOC_CHARS]
    if not normalized:
        return None
    return sha256_text(normalized)


def with_content_hash(
    source: DiscoveredSource, body: object
) -> DiscoveredSource:
    """Return ``source`` with a content hash computed from ``body``.

    If ``source.content_hash`` already exists it is treated as trusted and is
    **not** recomputed. No fetch, no network.
    """
    if source is None:
        return source
    if source.content_hash:
        return source
    digest = content_hash_for(body)
    if not digest:
        return source
    normalized = normalize_text(str(body or ""))[:MAX_DOC_CHARS]
    return source.model_copy(
        update={"content_hash": digest, "char_count": len(normalized)}
    )


# ---------------------------------------------------------------------------
# Canonical source selection + provenance
# ---------------------------------------------------------------------------
def _tier_rank(tier: object) -> int:
    return TIER_ORDER.get(tier, len(TIER_ORDER))


def _canonical_key(source: DiscoveredSource) -> tuple:
    """Deterministic total order for canonical-source selection.

    (tier rank asc, source_quality desc, canonical_url asc, source_id asc).
    Timestamps and discovery order are deliberately excluded.
    """
    return (
        _tier_rank(getattr(source, "tier", TrustTier.GENERIC)),
        -float(getattr(source, "source_quality", 0.0) or 0.0),
        canonical_url(source),
        str(getattr(source, "source_id", "") or ""),
    )


def choose_canonical(
    sources: Sequence[DiscoveredSource],
) -> DiscoveredSource | None:
    """Deterministically choose the canonical source from a duplicate group.

    Highest trust tier, then highest ``source_quality``, then lowest canonical
    URL, then lowest ``source_id``. Returns ``None`` for an empty sequence.
    """
    candidates = [s for s in sources or () if s is not None]
    if not candidates:
        return None
    return min(candidates, key=_canonical_key)


def provenance_ledger(sources: Sequence[DiscoveredSource]) -> list[str]:
    """Deterministic, deduplicated discovery provenance entries for a group.

    Each entry records provider/template/query/canonical URL. Sorted, so the
    output never depends on iteration order.
    """
    entries: set[str] = set()
    for source in sources or ():
        if source is None:
            continue
        entries.add(
            "provider={p};template={t};query={q};url={u}".format(
                p=str(getattr(source, "discovery_provider", "") or ""),
                t=str(getattr(source, "discovery_template_id", "") or ""),
                q=str(getattr(source, "discovery_query", "") or ""),
                u=canonical_url(source),
            )
        )
    return sorted(entries)


def _merge_aliases(group: Sequence[DiscoveredSource], canonical: DiscoveredSource) -> list[str]:
    """All alternate URLs / aliases from a group, deterministically sorted."""
    canonical_key = canonical_url(canonical)
    aliases: set[str] = set()
    for source in group:
        if source is None:
            continue
        for value in (
            source.url,
            source.final_url,
            source.discovered_url,
        ):
            key = canonicalize_url(value) if value else ""
            if key and key != canonical_key:
                aliases.add(key)
        for existing in source.aliases or ():
            key = canonicalize_url(existing)
            if key and key != canonical_key:
                aliases.add(key)
    return sorted(aliases)


def _merge_redirect_chain(group: Sequence[DiscoveredSource], canonical: DiscoveredSource) -> list[str]:
    """Canonical source's redirect chain, with any other unique hops appended.

    Order is meaningful (hop order); the canonical chain is preserved first and
    only unique extra hops are appended in deterministic sorted order.
    """
    chain: list[str] = []
    for hop in canonical.redirect_chain or ():
        text = str(hop or "").strip()
        if text and text not in chain:
            chain.append(text)
    extra: set[str] = set()
    for source in group:
        if source is None:
            continue
        for hop in source.redirect_chain or ():
            text = str(hop or "").strip()
            if text and text not in chain:
                extra.add(text)
    chain.extend(sorted(extra))
    return chain


def merge_group(group: Sequence[DiscoveredSource]) -> DiscoveredSource:
    """Merge a duplicate group into one source, preserving provenance.

    Deterministic: canonical chosen by :func:`choose_canonical`; aliases sorted;
    redirect chain order preserved; the provenance ledger appended to ``note``
    only once (idempotent across both dedup levels).
    """
    members = [s for s in group or () if s is not None]
    if not members:
        raise ValueError("merge_group requires at least one source")
    if len(members) == 1:
        return members[0]

    canonical = choose_canonical(members)
    assert canonical is not None  # non-empty by construction

    aliases = _merge_aliases(members, canonical)
    redirect_chain = _merge_redirect_chain(members, canonical)

    content_hash = canonical.content_hash
    if not content_hash:
        for source in members:
            if source.content_hash:
                content_hash = source.content_hash
                break

    note = str(canonical.note or "")
    ledger = provenance_ledger(members)
    if ledger and "discovered_via=" not in note:
        summary = "discovered_via=" + "|".join(ledger)
        note = f"{note} | {summary}" if note else summary

    return canonical.model_copy(
        update={
            "aliases": aliases,
            "redirect_chain": redirect_chain,
            "content_hash": content_hash,
            "note": note,
        }
    )


# ---------------------------------------------------------------------------
# Two-level dedup
# ---------------------------------------------------------------------------
def dedup_by_url(
    sources: Iterable[DiscoveredSource],
) -> list[DiscoveredSource]:
    """Level 1: collapse sources sharing a canonical URL (no network).

    Output is sorted by canonical URL ascending so the result is independent of
    input order.
    """
    groups: dict[str, list[DiscoveredSource]] = {}
    for source in sources or ():
        if source is None:
            continue
        groups.setdefault(canonical_url(source), []).append(source)
    merged = [merge_group(groups[key]) for key in sorted(groups.keys())]
    return merged


def dedup_by_content_hash(
    sources: Iterable[DiscoveredSource],
) -> list[DiscoveredSource]:
    """Level 2: collapse sources sharing an already-known trusted content hash.

    Sources without a ``content_hash`` cannot be content-deduplicated and are
    passed through unchanged. No body is fetched or read from disk. Output is
    sorted deterministically.
    """
    hashed: dict[str, list[DiscoveredSource]] = {}
    unhashed: list[DiscoveredSource] = []
    for source in sources or ():
        if source is None:
            continue
        if source.content_hash:
            hashed.setdefault(str(source.content_hash), []).append(source)
        else:
            unhashed.append(source)
    merged = [merge_group(hashed[key]) for key in sorted(hashed.keys())]
    merged.extend(unhashed)
    merged.sort(key=lambda s: (canonical_url(s), str(s.source_id or "")))
    return merged


def dedup_discovered_sources(
    sources: Iterable[DiscoveredSource],
) -> list[DiscoveredSource]:
    """Full deterministic two-level dedup (URL then content hash).

    No network, no DNS, no re-fetch. The caller is responsible for supplying any
    already-fetched ``content_hash`` values.
    """
    url_merged = dedup_by_url(sources)
    content_merged = dedup_by_content_hash(url_merged)
    return content_merged
