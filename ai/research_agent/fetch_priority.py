"""Stage R24.10 — deterministic fetch priority under a tiny fetch budget.

The R24.4 ranking scores sources by *quality*; this module adds a separate,
deterministic **fetch priority** so the small fetch budget is spent on
CVE-specific / structured sources before generic search/landing pages.

It does not change R24.4 scoring, tiers, categories or signals — it only
re-orders (and can select) already-ranked :class:`DiscoveredSource` records
before fetching. A generic vendor search page still may be discovered, and it
still may be fetched when budget permits; it simply must not consume a slot
while a higher-quality CVE-specific source fits the budget. The R24.8 evidence
gate (``required_content_tokens``) is untouched.

Priority levels (lower = fetched first), derived only from the existing
R24.1/R24.4 vocabulary plus a deterministic URL-shape rule:

    0  TRUSTED + advisory category + exact CVE token
    1  TRUSTED + advisory / structured (NVD/CVE) source
    2  TRUSTED + other non-generic
    3  SEMI_TRUSTED + advisory
    4  SEMI_TRUSTED + other
    5  DISCOVERY_ONLY detection / exploit / writeup / blog
    6  other non-generic
    40 generic search / landing page (any tier)

Import boundary: standard library + the R24.1 contract + R24.4 dedup helper. No
network, no LLM, no target data.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence
from urllib.parse import parse_qs, urlsplit

from ai.research_agent.dedup import TIER_ORDER, canonical_url
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    SourceCategory,
    TrustTier,
)
from ai.research_agent.queries import CVEResearchMetadata

__all__ = [
    "ADVISORY_CATEGORIES",
    "STRUCTURED_CATEGORIES",
    "QUALIFYING_CATEGORIES",
    "GENERIC_LEVEL",
    "is_generic_search_source",
    "fetch_level",
    "fetch_priority_key",
    "order_for_fetch",
    "select_for_fetch",
    "reserved_trusted_source",
]

ADVISORY_CATEGORIES = frozenset(
    {
        SourceCategory.NVD_CVE,
        SourceCategory.VENDOR_ADVISORY,
        SourceCategory.GITHUB_ADVISORY,
        SourceCategory.WORDFENCE,
        SourceCategory.WPSCAN,
    }
)
STRUCTURED_CATEGORIES = frozenset({SourceCategory.NVD_CVE})
QUALIFYING_CATEGORIES = frozenset(
    {
        SourceCategory.DETECTION_RULE,
        SourceCategory.EXPLOIT_REFERENCE,
        SourceCategory.WRITEUP,
        SourceCategory.SECURITY_BLOG,
    }
)

GENERIC_LEVEL = 40

# Deterministic URL-shape markers for a vendor/generic search or landing page.
_SEARCH_PATH_MARKERS = (
    "/search",
    "search/",
    "search.php",
    "searchresults",
    "/search.",
)
_SEARCH_QUERY_PARAMS = frozenset({"q", "query", "pattern", "search"})

_CVE_ANY_RE = re.compile(r"CVE-\d{4,}-\d+", re.IGNORECASE)


def _source_text(source: DiscoveredSource) -> str:
    return " ".join(
        str(v)
        for v in (
            getattr(source, "url", "") or "",
            getattr(source, "final_url", "") or "",
            getattr(source, "title", "") or "",
            getattr(source, "discovery_query", "") or "",
        )
        if v
    )


def _source_has_cve(source: DiscoveredSource, cve_id: str) -> bool:
    token = str(cve_id or "").strip()
    if not token:
        return False
    text = _source_text(source)
    return (
        re.search(
            r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])",
            text,
            re.IGNORECASE,
        )
        is not None
    )


def is_generic_search_source(source: DiscoveredSource) -> bool:
    """True for a generic search / landing page (deterministic URL shape).

    A GENERIC-tier source is always generic. Otherwise the check is purely
    structural (path contains a ``search`` segment, or the query string carries
    a search parameter such as ``q``/``query``/``pattern``); it is not
    provider-specific.
    """
    if source is None:
        return True
    if getattr(source, "tier", None) == TrustTier.GENERIC:
        return True
    key = canonical_url(source) or str(getattr(source, "url", "") or "")
    if not key:
        return True
    try:
        parts = urlsplit(key)
    except Exception:
        return False
    path = (parts.path or "").lower()
    if any(marker in path for marker in _SEARCH_PATH_MARKERS):
        return True
    params = {name.lower() for name in parse_qs(parts.query, keep_blank_values=True)}
    return bool(params & _SEARCH_QUERY_PARAMS)


def fetch_level(
    source: DiscoveredSource,
    metadata: CVEResearchMetadata | None = None,
) -> int:
    """Deterministic fetch-priority level (lower = higher priority)."""
    if source is None:
        return 99
    if is_generic_search_source(source):
        return GENERIC_LEVEL
    tier = getattr(source, "tier", TrustTier.GENERIC)
    category = getattr(source, "category", SourceCategory.GENERIC_SEARCH)
    cve_id = getattr(metadata, "cve_id", "") if metadata is not None else ""
    advisory = category in ADVISORY_CATEGORIES
    cve_specific = _source_has_cve(source, cve_id)
    if tier == TrustTier.TRUSTED:
        if advisory and cve_specific:
            return 0
        if advisory or category in STRUCTURED_CATEGORIES:
            return 1
        return 2
    if tier == TrustTier.SEMI_TRUSTED:
        return 3 if advisory else 4
    if category in QUALIFYING_CATEGORIES:
        return 5
    return 6


def fetch_priority_key(
    source: DiscoveredSource,
    metadata: CVEResearchMetadata | None = None,
) -> tuple:
    """Deterministic total order for fetch selection.

    (level asc, CVE-specific desc, source_quality desc, tier rank asc,
    canonical_url asc, source_id asc). No clock, no randomness, no set/dict
    iteration order.
    """
    cve_id = getattr(metadata, "cve_id", "") if metadata is not None else ""
    return (
        fetch_level(source, metadata),
        0 if _source_has_cve(source, cve_id) else 1,
        -float(getattr(source, "source_quality", 0.0) or 0.0),
        TIER_ORDER.get(getattr(source, "tier", TrustTier.GENERIC), len(TIER_ORDER)),
        canonical_url(source),
        str(getattr(source, "source_id", "") or ""),
    )


def order_for_fetch(
    sources: Iterable[DiscoveredSource],
    metadata: CVEResearchMetadata | None = None,
) -> list[DiscoveredSource]:
    """Return ALL sources re-ordered for fetching (generic pages last)."""
    items = [s for s in (sources or ()) if s is not None]
    return sorted(items, key=lambda s: fetch_priority_key(s, metadata))


def reserved_trusted_source(
    sources: Sequence[DiscoveredSource],
    metadata: CVEResearchMetadata | None = None,
) -> DiscoveredSource | None:
    """Highest-priority high-value TRUSTED source (non-generic), or ``None``."""
    for source in order_for_fetch(sources, metadata):
        if getattr(source, "tier", None) == TrustTier.TRUSTED and not is_generic_search_source(
            source
        ):
            return source
    return None


def select_for_fetch(
    sources: Iterable[DiscoveredSource],
    max_fetched: int,
    metadata: CVEResearchMetadata | None = None,
) -> list[DiscoveredSource]:
    """Select at most ``max_fetched`` sources, reserving a high-value slot.

    When a non-generic TRUSTED source exists it is guaranteed to be inside the
    selected set (the "reserved high-value slot"), so generic search/landing
    pages cannot starve it even when ``max_fetched == 1``.
    """
    ordered = order_for_fetch(sources, metadata)
    cap = max(int(max_fetched or 0), 0)
    if cap == 0:
        return []
    if len(ordered) <= cap:
        return ordered
    selected = ordered[:cap]
    reserved = reserved_trusted_source(ordered, metadata)
    if reserved is not None and not any(s is reserved for s in selected):
        selected = [reserved] + selected[: cap - 1]
    return selected
