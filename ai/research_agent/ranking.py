"""Stage R24.4 — deterministic source ranking and evidence eligibility.

Pure, offline, network-free, LLM-free. This module scores already-discovered
public sources by *source quality* and orders them deterministically. It does
**not** assess target/program relevance and never consumes any target, program,
asset, endpoint, response, credential, cookie or header material.

Scoring (R24 scope §5) is an integer sum, clamped to ``[0, 200]``::

    TIER_BASE(TRUSTED=100, SEMI_TRUSTED=70, DISCOVERY_ONLY=40, GENERIC=10)
    + category_bonus
    + signal_bonus
    + penalties

``source_quality = round(score / 200, 2)``.

Deterministic ordering (R24 scope §4): score desc, tier rank asc, canonical URL
asc, source_id asc. No clock, no randomness, no set/dict iteration order.

Import boundary: standard library + R24.1 contract + the neutral R24.4 dedup
helpers + the R24.1 metadata structure. No ``ai.execution`` / ``ai.verification``
/ ``ai.finding`` / ``ai.resolver`` / ``ai.authorizer`` / ``ai.persistence`` /
``nuclei_runner`` / browser automation / ``subprocess`` / HTTP client / socket
imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ai.research_agent.dedup import TIER_ORDER, canonical_url
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    SourceCategory,
    TrustTier,
)
from ai.research_agent.queries import CVEResearchMetadata

__all__ = [
    "TIER_BASE",
    "CATEGORY_BONUS",
    "SIGNAL_EXACT_CVE",
    "SIGNAL_PRODUCT",
    "SIGNAL_COMPONENT",
    "SIGNAL_CWE",
    "SIGNAL_VERSION",
    "SIGNAL_CANONICAL_ADVISORY",
    "PENALTY_AGGREGATOR",
    "PENALTY_GENERIC_NO_CORROBORATION",
    "MAX_SCORE",
    "EVIDENCE_FLOOR",
    "AGGREGATOR_HOSTS",
    "tier_rank",
    "ScoreBreakdown",
    "score_breakdown",
    "score_source",
    "rank_sources",
    "authoritative_advisory_reference",
    "is_evidence_eligible",
]

# ---------------------------------------------------------------------------
# Scoring tables (exactly per the R24 scope)
# ---------------------------------------------------------------------------
TIER_BASE: dict[TrustTier, int] = {
    TrustTier.TRUSTED: 100,
    TrustTier.SEMI_TRUSTED: 70,
    TrustTier.DISCOVERY_ONLY: 40,
    TrustTier.GENERIC: 10,
}

CATEGORY_BONUS: dict[SourceCategory, int] = {
    SourceCategory.NVD_CVE: 30,
    SourceCategory.VENDOR_ADVISORY: 30,
    SourceCategory.GITHUB_ADVISORY: 25,
    SourceCategory.WORDFENCE: 15,
    SourceCategory.WPSCAN: 15,
    SourceCategory.DETECTION_RULE: 10,
    SourceCategory.EXPLOIT_REFERENCE: 5,
    SourceCategory.WRITEUP: 0,
    SourceCategory.SECURITY_BLOG: 0,
    SourceCategory.GITHUB_REPO: 0,
    SourceCategory.GENERIC_SEARCH: 0,
}

SIGNAL_EXACT_CVE = 25
SIGNAL_PRODUCT = 15
SIGNAL_COMPONENT = 10
SIGNAL_CWE = 10
SIGNAL_VERSION = 5
SIGNAL_CANONICAL_ADVISORY = 10

PENALTY_AGGREGATOR = -15
PENALTY_GENERIC_NO_CORROBORATION = -20

MAX_SCORE = 200
EVIDENCE_FLOOR = 0.45

# Fixed, documented aggregator/mirror hosts (a deterministic penalty table; not
# a target/program list). Hosts are matched exactly or as a parent suffix.
AGGREGATOR_HOSTS: frozenset[str] = frozenset(
    {
        "cvedetails.com",
        "vulmon.com",
        "cvefeed.io",
        "cvedb.io",
        "sploitus.com",
        "cve.report",
        "opencve.io",
        "cve.circl.lu",
    }
)

_EXACT_CVE_RE = re.compile(r"^CVE-\d{4,}-\d+$", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
_CVE_ANY_RE = re.compile(r"CVE-\d{4,}-\d+", re.IGNORECASE)
_ADVISORY_URL_MARKERS = ("/advisories/", "/vuln/detail/", "ghsa-")
_ADVISORY_CATEGORIES = frozenset(
    {
        SourceCategory.NVD_CVE,
        SourceCategory.VENDOR_ADVISORY,
        SourceCategory.GITHUB_ADVISORY,
    }
)


def tier_rank(tier: object) -> int:
    """Deterministic tier rank (lower = more trusted)."""
    return TIER_ORDER.get(tier, len(TIER_ORDER))


@dataclass(frozen=True)
class ScoreBreakdown:
    """Transparent, testable decomposition of one source's score."""

    tier_base: int = 0
    category_bonus: int = 0
    signal_bonus: int = 0
    penalty: int = 0
    raw_score: int = 0
    score: int = 0
    source_quality: float = 0.0
    signals: tuple[str, ...] = ()
    penalties: tuple[str, ...] = ()
    components: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Deterministic signal extraction (offline, text-only)
# ---------------------------------------------------------------------------
def _haystack(source: DiscoveredSource) -> str:
    parts = [
        str(getattr(source, "url", "") or ""),
        str(getattr(source, "final_url", "") or ""),
        str(getattr(source, "title", "") or ""),
        str(getattr(source, "source_type", "") or ""),
        str(getattr(source, "discovery_query", "") or ""),
    ]
    return " ".join(p for p in parts if p)


def _has_token(haystack_lower: str, value: object, *, min_len: int = 3) -> bool:
    token = str(value or "").strip().lower()
    if len(token) < min_len:
        return False
    return (
        re.search(
            r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])",
            haystack_lower,
        )
        is not None
    )


def _has_cve(haystack: str, value: object) -> bool:
    cve = str(value or "").strip()
    if not _EXACT_CVE_RE.match(cve):
        return False
    return (
        re.search(
            r"(?<![a-z0-9])" + re.escape(cve) + r"(?![a-z0-9])",
            haystack,
            re.IGNORECASE,
        )
        is not None
    )


def _is_aggregator(source: DiscoveredSource) -> bool:
    key = canonical_url(source) or str(getattr(source, "url", "") or "").strip()
    if not key:
        return False
    try:
        from urllib.parse import urlsplit

        host = (urlsplit(key).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    if host in AGGREGATOR_HOSTS:
        return True
    return any(host.endswith("." + agg) for agg in sorted(AGGREGATOR_HOSTS))


def _has_canonical_advisory_signal(source: DiscoveredSource) -> bool:
    if getattr(source, "category", None) in _ADVISORY_CATEGORIES:
        return True
    text = _haystack(source).lower()
    key = canonical_url(source).lower()
    return any(marker in text or marker in key for marker in _ADVISORY_URL_MARKERS)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def score_breakdown(
    source: DiscoveredSource,
    metadata: CVEResearchMetadata | None = None,
    *,
    corroborated: bool = False,
) -> ScoreBreakdown:
    """Deterministically score one source; return a transparent breakdown.

    ``metadata`` carries only CVE research metadata (no target/program/asset
    fields exist on :class:`CVEResearchMetadata`). ``corroborated`` records that
    an independent higher-tier source confirmed the same item; it only affects
    the Tier-4 penalty.
    """
    if source is None:
        return ScoreBreakdown()

    tier_base = TIER_BASE.get(getattr(source, "tier", TrustTier.GENERIC), 10)
    category_bonus = CATEGORY_BONUS.get(
        getattr(source, "category", SourceCategory.GENERIC_SEARCH), 0
    )

    components: dict[str, int] = {
        "tier_base": tier_base,
        "category_bonus": category_bonus,
    }
    signals: list[str] = []

    meta = metadata if metadata is not None else CVEResearchMetadata()
    haystack = _haystack(source)
    lowered = haystack.lower()

    if _has_cve(haystack, meta.cve_id):
        components["exact_cve_id"] = SIGNAL_EXACT_CVE
        signals.append("exact_cve_id")
    if _has_token(lowered, meta.product, min_len=3):
        components["product_match"] = SIGNAL_PRODUCT
        signals.append("product_match")
    if _has_token(lowered, meta.component, min_len=3):
        components["component_match"] = SIGNAL_COMPONENT
        signals.append("component_match")
    if _has_token(lowered, meta.cwe, min_len=3):
        components["cwe_match"] = SIGNAL_CWE
        signals.append("cwe_match")
    version = str(meta.version or "").strip()
    if len(version) >= 2 and version.lower() in lowered:
        components["version_match"] = SIGNAL_VERSION
        signals.append("version_match")
    if _has_canonical_advisory_signal(source):
        components["canonical_advisory"] = SIGNAL_CANONICAL_ADVISORY
        signals.append("canonical_advisory")

    penalties: list[str] = []
    if _is_aggregator(source):
        components["aggregator"] = PENALTY_AGGREGATOR
        penalties.append("aggregator")
    if getattr(source, "tier", None) == TrustTier.GENERIC and not corroborated:
        components["generic_uncorroborated"] = PENALTY_GENERIC_NO_CORROBORATION
        penalties.append("generic_uncorroborated")

    signal_bonus = (
        components.get("exact_cve_id", 0)
        + components.get("product_match", 0)
        + components.get("component_match", 0)
        + components.get("cwe_match", 0)
        + components.get("version_match", 0)
        + components.get("canonical_advisory", 0)
    )
    penalty = sum(
        v for k, v in components.items() if k in ("aggregator", "generic_uncorroborated")
    )

    raw_score = tier_base + category_bonus + signal_bonus + penalty
    score = max(0, min(MAX_SCORE, raw_score))
    quality = round(score / MAX_SCORE, 2)

    return ScoreBreakdown(
        tier_base=tier_base,
        category_bonus=category_bonus,
        signal_bonus=signal_bonus,
        penalty=penalty,
        raw_score=raw_score,
        score=score,
        source_quality=quality,
        signals=tuple(sorted(signals)),
        penalties=tuple(sorted(penalties)),
        components=components,
    )


def score_source(
    source: DiscoveredSource,
    metadata: CVEResearchMetadata | None = None,
    *,
    corroborated: bool = False,
) -> int:
    """Deterministic clamped score (0..200) for one source."""
    return score_breakdown(source, metadata, corroborated=corroborated).score


def rank_sources(
    sources: Iterable[DiscoveredSource],
    metadata: CVEResearchMetadata | None = None,
    *,
    corroborated: bool = False,
    assign_quality: bool = True,
) -> list[DiscoveredSource]:
    """Rank sources deterministically and (optionally) assign ``source_quality``.

    Ordering: score desc, tier rank asc, canonical URL asc, source_id asc. The
    computation is a total function of the inputs; shuffled input yields an
    identical result. No clock, no randomness, no network.
    """
    scored: list[tuple[tuple, DiscoveredSource]] = []
    for source in sources or ():
        if source is None:
            continue
        breakdown = score_breakdown(source, metadata, corroborated=corroborated)
        if assign_quality:
            source = source.model_copy(
                update={"source_quality": breakdown.source_quality}
            )
        key = (
            -breakdown.score,
            tier_rank(getattr(source, "tier", TrustTier.GENERIC)),
            canonical_url(source),
            str(getattr(source, "source_id", "") or ""),
        )
        scored.append((key, source))
    scored.sort(key=lambda pair: pair[0])
    return [source for _, source in scored]


# ---------------------------------------------------------------------------
# Evidence eligibility (pure predicate; never creates or persists evidence)
# ---------------------------------------------------------------------------
def authoritative_advisory_reference(source: DiscoveredSource) -> str | None:
    """Return an explicit CVE/GHSA/advisory marker found in the source, or None.

    Deterministic text scan only (URL/title/note/aliases). No fetch, no
    fabrication.
    """
    if source is None:
        return None
    text = " ".join(
        str(v or "")
        for v in (
            getattr(source, "url", ""),
            getattr(source, "final_url", ""),
            getattr(source, "title", ""),
            getattr(source, "note", ""),
        )
    )
    text = text + " " + " ".join(str(a) for a in (source.aliases or ()))
    cve = _CVE_ANY_RE.search(text)
    if cve:
        return cve.group(0).upper()
    ghsa = _GHSA_RE.search(text)
    if ghsa:
        return ghsa.group(0).upper()
    lowered = text.lower()
    for marker in _ADVISORY_URL_MARKERS:
        if marker in lowered:
            return marker
    return None


def is_evidence_eligible(
    source: DiscoveredSource,
    *,
    advisory_reference: str | None = None,
) -> bool:
    """Pure predicate: may this source back an evidence claim?

    Requirements:

    - a trusted, non-empty ``content_hash``;
    - ``source_quality >= EVIDENCE_FLOOR`` (0.45);
    - tier ``TRUSTED`` or ``SEMI_TRUSTED``.

    Exception: a ``DISCOVERY_ONLY`` ``detection_rule`` qualifies only when it
    carries an explicit authoritative advisory reference (supplied via
    ``advisory_reference`` or deterministically present in the source text).
    ``GENERIC`` can never qualify by itself. Does not create or persist
    evidence.
    """
    if source is None:
        return False
    if not source.content_hash:
        return False
    if float(getattr(source, "source_quality", 0.0) or 0.0) < EVIDENCE_FLOOR:
        return False

    tier = getattr(source, "tier", TrustTier.GENERIC)
    if tier in (TrustTier.TRUSTED, TrustTier.SEMI_TRUSTED):
        return True

    if tier == TrustTier.DISCOVERY_ONLY and getattr(
        source, "category", None
    ) == SourceCategory.DETECTION_RULE:
        if advisory_reference is not None and str(advisory_reference).strip():
            return True
        return authoritative_advisory_reference(source) is not None

    return False
