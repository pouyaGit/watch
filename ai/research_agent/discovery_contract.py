"""Stage R24.1 — deterministic source-discovery contract (data model only).

This module defines the *contract* for public research source discovery. It is
purely structural and deterministic: it holds no HTTP client, no DNS resolver,
no redirect engine, no provider implementation and no ranking score. Those are
later R24 stages (R24.2+).

Everything here is a deterministic, total function of its inputs:

- :class:`SourceCategory`, :class:`TrustTier`, :class:`Lifecycle` and
  :class:`SearchProvider` fix the closed vocabularies used across discovery.
- :class:`DiscoveryQuery` carries deterministic provenance
  (``query_id`` / ``template_id`` / ``provider`` / ``query`` / ``inputs_used``)
  and deliberately has **no** target/program/asset input fields.
- :class:`DiscoveredSource` is the additive per-source record. It preserves the
  minimum identity/status fields required by the existing R23
  ``ResearchAgentSource`` serialization (``url``, ``source_type``, ``status``,
  ``title``, ``content_hash``, ``char_count``, ``note``) so later stages can map
  R24 lifecycle onto the R23 ``sources[]`` list without changing R23 behavior.
- the forbidden-input invariant rejects any query/value that contains a
  supplied program/asset host/token.

Safety invariants enforced here:

- ``production_finding`` is forced ``False``.
- The research status vocabulary never uses VULNERABLE / VERIFIED / EXPLOITED /
  FINDING as affirmative result states.

Import boundary: this module imports only the standard library, pydantic, the
neutral R23 schema constants and the deterministic canonicalization/hash
helpers. It never imports ``ai.execution``, ``ai.verification``,
``ai.finding``, ``ai.resolver``, ``ai.authorizer``, ``ai.persistence``,
``nuclei_runner``, browser automation, ``subprocess`` or any target-validation
package, and it never performs network I/O.
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Iterable

from pydantic import BaseModel, Field, field_validator

from ai.collectors.body_extraction import sha256_text
from ai.researcher.reference_cache import canonicalize_reference_url
from ai.schemas.research_agent import (
    FORBIDDEN_STATUS_TERMS,
    SOURCE_STORED_ONLY,
    SOURCE_STATES,
)

__all__ = [
    "SourceCategory",
    "TrustTier",
    "Lifecycle",
    "SearchProvider",
    "ForbiddenInputError",
    "contains_forbidden_token",
    "assert_no_forbidden_input",
    "query_id_for",
    "discovered_source_id",
    "DiscoveryQuery",
    "DiscoveredSource",
    "SOURCE_ID_PREFIX",
    "QUERY_ID_PREFIX",
]

# Deterministic id prefixes (kept distinct from the R23 ``src-`` ids so a
# re-serialized discovery source can never collide with an R23 stored source).
SOURCE_ID_PREFIX = "ds-"
QUERY_ID_PREFIX = "q-"


class SourceCategory(str, Enum):
    """Deterministic public research source category (closed vocabulary)."""

    NVD_CVE = "nvd_cve"
    VENDOR_ADVISORY = "vendor_advisory"
    WORDFENCE = "wordfence"
    WPSCAN = "wpscan"
    GITHUB_ADVISORY = "github_advisory"
    GITHUB_REPO = "github_repo"
    DETECTION_RULE = "detection_rule"
    EXPLOIT_REFERENCE = "exploit_reference"
    WRITEUP = "writeup"
    SECURITY_BLOG = "security_blog"
    GENERIC_SEARCH = "generic_search"


class TrustTier(str, Enum):
    """Deterministic trust tier. A source never promotes its own tier."""

    TRUSTED = "TRUSTED"
    SEMI_TRUSTED = "SEMI_TRUSTED"
    DISCOVERY_ONLY = "DISCOVERY_ONLY"
    GENERIC = "GENERIC"


class Lifecycle(str, Enum):
    """Deterministic per-source lifecycle state (R24.1 value set)."""

    DISCOVERED_SOURCE = "DISCOVERED_SOURCE"
    FETCHED_SOURCE = "FETCHED_SOURCE"
    RELEVANT_SOURCE = "RELEVANT_SOURCE"
    EVIDENCE = "EVIDENCE"
    UNKNOWN = "UNKNOWN"
    INFERENCE = "INFERENCE"


class SearchProvider(str, Enum):
    """Deterministic discovery provider identifiers (protocol stub).

    Providers themselves are implemented in R24.2; here the enum only fixes the
    closed set of identifiers a :class:`DiscoveryQuery` may carry.
    """

    NVD = "nvd"
    GITHUB_SEARCH = "github_search"
    VENDOR_ADVISORY = "vendor_advisory"
    WORDFENCE = "wordfence"
    WPSCAN = "wpscan"
    DETECTION_RULE = "detection_rule"
    # Added in R24.2 to complete the closed set required by the R24
    # scope (generic open-web search, opt-in, Tier 4).
    GENERIC_SEARCH = "generic_search"
# ---------------------------------------------------------------------------
# Forbidden-input invariant
# ---------------------------------------------------------------------------
# Generic public TLDs are never treated as a forbidden token (they are not
# attributable to a program/asset and would cause excessive false rejections).
_GENERIC_TLDS = frozenset(
    {
        "com",
        "net",
        "org",
        "io",
        "co",
        "info",
        "dev",
        "cloud",
        "ai",
        "me",
        "app",
        "site",
        "online",
        "tech",
    }
)


class ForbiddenInputError(ValueError):
    """Raised when a discovery query/value contains a program/asset token."""


def _expand_forbidden(tokens: Iterable[str]) -> frozenset[str]:
    """Normalize forbidden tokens into a whole-token match set.

    The full token is always included. For host-like tokens (contain a dot) the
    DNS labels are also included so a program ``www.dell.com`` rejects a query
    containing the bare label ``dell``. To avoid false positives on benign
    inputs (e.g. a version ``1.2.3``) only individual **labels that contain a
    letter** and are not a generic TLD are added — all-numeric labels (IP
    octets) are matched only as the exact full token, and generic TLDs are never
    treated as forbidden.
    """
    out: set[str] = set()
    for raw in tokens:
        token = str(raw or "").strip().lower().rstrip(".")
        if not token:
            continue
        out.add(token)
        if "." in token:
            for label in token.split("."):
                label = label.strip()
                if (
                    label
                    and label not in _GENERIC_TLDS
                    and any(ch.isalpha() for ch in label)
                ):
                    out.add(label)
    return frozenset(out)


def contains_forbidden_token(text: str, forbidden_tokens: Iterable[str]) -> bool:
    """Return True when ``text`` contains any forbidden program/asset token.

    Matching is whole-token (word-boundary) and case-insensitive, so e.g. the
    program label ``dell`` does not match ``medellin`` but does match
    ``dell.com``, ``dell-advisory`` and ``www.dell.com``.
    """
    haystack = str(text or "")
    if not haystack:
        return False
    lowered = haystack.lower()
    for token in _expand_forbidden(forbidden_tokens):
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered):
            return True
    return False


def assert_no_forbidden_input(text: str, forbidden_tokens: Iterable[str]) -> None:
    """Raise :class:`ForbiddenInputError` when ``text`` leaks a forbidden token."""
    if contains_forbidden_token(text, forbidden_tokens):
        raise ForbiddenInputError(
            "discovery input contains a forbidden program/asset token"
        )


# ---------------------------------------------------------------------------
# Deterministic query id
# ---------------------------------------------------------------------------
def query_id_for(
    template_id: str,
    provider: str,
    query: str,
    inputs_used: Iterable[str],
) -> str:
    """Deterministic query id from the full rendered provenance.

    Total function of (template_id, provider, query, inputs_used): no clock, no
    randomness, no model. Inputs are deduplicated and sorted.
    """
    basis = "\n".join(
        [str(template_id or ""), str(provider or ""), str(query or "")]
        + sorted({str(i or "") for i in inputs_used})
    )
    return QUERY_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def discovered_source_id(url: str) -> str:
    """Deterministic source id from the canonicalized discovery URL."""
    return SOURCE_ID_PREFIX + sha256_text(canonicalize_reference_url(url or ""))[:16]
# ---------------------------------------------------------------------------
# DiscoveryQuery
# ---------------------------------------------------------------------------
class DiscoveryQuery(BaseModel):
    """One deterministic discovery query and its provenance.

    Explicitly carries **no** target/program/asset input fields.
    """

    query_id: str
    template_id: str
    provider: str
    query: str = ""
    inputs_used: list[str] = Field(default_factory=list)
    # research-only safety invariant (never a production finding).
    production_finding: bool = False

    @field_validator("query_id", "template_id", "provider")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("query id/template/provider must be non-empty")
        return text

    @field_validator("query")
    @classmethod
    def _query_no_quotes(cls, value: str) -> str:
        text = str(value or "").strip()
        if '"' in text or "\\" in text or "'" in text:
            raise ValueError("query must not contain provider-syntax-altering quotes")
        return text

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("discovery queries never represent production findings")
        return False


# ---------------------------------------------------------------------------
# DiscoveredSource
# ---------------------------------------------------------------------------
class DiscoveredSource(BaseModel):
    """One discovered public source and its deterministic provenance.

    Additive R24 fields (lifecycle/category/tier/source_quality/provenance ...)
    are combined with the minimum identity/status fields required by the
    existing R23 ``ResearchAgentSource`` serialization (``url``, ``source_type``,
    ``status``, ``title``, ``content_hash``, ``char_count``, ``note``) so later
    R24 stages can map onto R23 without changing R23 behavior.
    """

    # -- R23-compatible identity/status ------------------------------------
    source_id: str
    url: str
    source_type: str = "other"
    title: str | None = None
    status: str = SOURCE_STORED_ONLY
    content_hash: str | None = None
    char_count: int = 0
    note: str = ""

    # -- R24 additive fields ----------------------------------------------
    lifecycle: Lifecycle = Lifecycle.DISCOVERED_SOURCE
    category: SourceCategory = SourceCategory.GENERIC_SEARCH
    tier: TrustTier = TrustTier.GENERIC
    source_quality: float = 0.0
    discovery_provider: str = ""
    discovery_query: str = ""
    discovery_template_id: str = ""
    discovered_url: str = ""
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    extraction_method: str = ""

    # research-only safety invariant (never a production finding).
    production_finding: bool = False

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        value = str(value or "").strip().upper()
        if value in FORBIDDEN_STATUS_TERMS:
            raise ValueError(f"forbidden research status term: {value!r}")
        if value not in SOURCE_STATES:
            raise ValueError(f"invalid R23 source status: {value!r}")
        return value

    @field_validator("production_finding")
    @classmethod
    def _never_finding(cls, value: bool) -> bool:
        if value:
            raise ValueError("discovered sources never represent production findings")
        return False

    @field_validator("source_quality")
    @classmethod
    def _quality_bounded(cls, value: float) -> float:
        value = float(value or 0.0)
        if not (0.0 <= value <= 1.0):
            raise ValueError("source_quality must be within [0.0, 1.0]")
        return value

    def to_r23(self) -> "ResearchAgentSource":
        """Map onto the existing R23 source schema (identity/status preserved).

        Only the R23-compatible subset is carried across; R24 additive fields
        stay within the discovery layer. Behavior of the R23 schema is
        unchanged.
        """
        from ai.schemas.research_agent import ResearchAgentSource

        return ResearchAgentSource(
            source_id=self.source_id,
            url=self.final_url or self.url,
            source_type=self.source_type,
            title=self.title,
            status=self.status,
            content_hash=self.content_hash,
            char_count=self.char_count,
            note=self.note,
        )


# Keep a forward reference for the type annotation in to_r23().
if False:  # pragma: no cover - typing aid only (never executed)
    from ai.schemas.research_agent import ResearchAgentSource  # noqa: F401