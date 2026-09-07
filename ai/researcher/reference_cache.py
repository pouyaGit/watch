"""Per-batch reference context cache (research-only).

Wraps the existing reference discovery/fetch primitives so two CVEs
in the same ``run_cve_batch`` invocation that point at the same URL
share one fetch. NOT a persistent cache. NOT a cross-batch cache.
NOT a second provider. NOT a new retry mechanism.

Existing abstraction reused:

- ``ai.collectors.reference.ReferenceCollector.fetch`` (the
  per-URL HTTP fetch primitive).
- ``ai.collectors.discovery_fetch.fetch_discovered_sources`` (the
  discovery-result -> document loop that calls the primitive).
- ``ai.collectors.discovery.ReferenceDiscovery`` (CVE -> source list).
- ``ai.schemas.reference.ReferenceDocument`` (the cached value type).

Cache key:

- The canonicalized reference URL. The cache applies
  ``(raw or "").strip()``, drops the URL fragment (``#...``),
  and drops only clearly non-semantic tracking query
  parameters (``utm_*``, ``gclid``, ``fbclid``). Everything
  else is preserved byte-for-byte: scheme, host case, path
  (including trailing slash), the order of the remaining
  query parameters, and their percent-encoding. The existing
  ``ReferenceCollector.fetch`` follows redirects and stores the
  final URL on the returned ``ReferenceDocument`` (under
  ``document.url``). The canonical form used here is derived
  from the ``DiscoveredSource.url`` that the discovery layer
  produced — the input the real fetcher would have received.
  Only the cache key is canonicalized: the fetcher always
  receives the original (whitespace-stripped) discovered URL,
  and the stored ``ReferenceDocument`` is never rewritten.
  No host lowercasing, no path lowercasing, no trailing-slash
  normalization, no query reordering, no percent
  decode/re-encode, no scheme normalization, and no redirect
  resolution are performed. Parsing reuses the standard
  library ``urllib.parse`` (``urlsplit``/``urlunsplit``) —
  the same library already used by
  ``ai.collectors.reference.ReferenceCollector`` — and never
  a custom full URL parser. The target canonicalizer under
  ``ai.resolver.canonicalization`` is deliberately NOT reused
  here because it lowercases hosts and otherwise normalizes
  in ways this cache must not apply.

Failure policy:

- Only successful ``ReferenceDocument`` results are cached.
  When the wrapped ``ReferenceCollector.fetch`` returns
  ``None`` (the existing "hard miss" sentinel for HTTP failure,
  non-text content, or empty text), the cache records nothing
  and a later CVE that needs the same URL will perform its own
  fetch. This avoids poisoning a batch with a transient
  failure that another CVE might succeed in fetching (e.g.
  after a redirect settles) and matches the spec's "Prefer
  caching successful deterministic reference material only"
  guidance.

Provenance:

- The cached value is a ``ReferenceDocument`` (a verbatim copy
  of the HTTP-fetched source material: URL, source type,
  title, content, content hash, status code). It is NOT a
  ``ReferenceContext`` (which is the CVE-specific ranked
  slice). Ranking into ``ReferenceContext`` is still performed
  per CVE by the existing ``build_research_contexts`` /
  ``ReferenceRanker.build`` pipeline, so CVE B does not
  inherit CVE A's CVE-specific LLM claims. The cache
  guarantees only the deterministic source material is
  shared; CVE-specific conclusions are never shared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

# Query parameters that are clearly non-semantic tracking markers.
# Only these (plus the ``utm_`` prefix family) are removed from the
# cache key. Every other parameter — including ``id``, ``token``,
# ``key``, ``page``, ``q``, ``query``, ``search``, ``lang``,
# ``locale``, ``version``, and any unknown parameter — is preserved
# exactly. Matching is case-sensitive on purpose: only the canonical
# lowercase tracking names are stripped.
_TRACKING_PARAMS_EXACT = frozenset({"gclid", "fbclid"})


def _is_tracking_param(name: str) -> bool:
    """Return True only for clearly non-semantic tracking parameters."""
    return name in _TRACKING_PARAMS_EXACT or name.startswith("utm_")


def canonicalize_reference_url(url) -> str:
    """Conservative canonicalization for the reference cache key only.

    Rules (cache key only; the fetcher always receives the
    original discovered URL):

    - Strip surrounding whitespace (backward compatible).
    - Drop the URL fragment (``#...``).
    - Drop only ``utm_*``, ``gclid``, and ``fbclid`` query
      parameters; preserve every other parameter byte-for-byte,
      in its original order, with its original percent-encoding.
    - Never lowercase/upper-case anything, never touch the
      trailing slash, never reorder parameters, never
      decode/re-encode components, never resolve redirects.

    Malformed input never raises: unparseable URLs fall back to
    the whitespace-stripped original. Non-string input (``None``,
    etc.) yields ``""``.
    """
    if not isinstance(url, str):
        return ""
    stripped = url.strip()
    if not stripped:
        return ""
    try:
        parts = urlsplit(stripped)
    except Exception:
        return stripped
    query = parts.query
    if query:
        try:
            kept: list[str] = []
            for chunk in query.split("&"):
                if chunk == "":
                    # Preserve empty chunks verbatim so non-tracking
                    # URLs are never rewritten by the join below.
                    kept.append(chunk)
                    continue
                name = chunk.split("=", 1)[0]
                if _is_tracking_param(name):
                    continue
                kept.append(chunk)
            query = "&".join(kept)
        except Exception:
            return stripped
    try:
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    except Exception:
        return stripped


@dataclass
class BatchReferenceCache:
    """Per-batch in-memory URL -> ReferenceDocument cache.

    Created and dropped by ``run_cve_batch``. The ``hits`` counter
    tracks the number of times a later CVE reused a
    previously-fetched reference document (vs. the first
    occurrence that actually invoked the fetcher). The first
    fetch for a URL is a miss and never increments ``hits``.
    """

    fetch_fn: object = None
    _store: dict[str, object] = field(default_factory=dict)
    hits: int = 0

    def fetch(self, url):
        """Fetch ``url`` through the cache, falling back to ``fetch_fn``.

        Returns the cached ``ReferenceDocument`` if the canonical
        cache key has been seen before in this batch, or invokes
        ``fetch_fn`` for the first occurrence. ``None`` (hard miss
        from ``ReferenceCollector.fetch``) is never cached.

        Cache-key-only canonicalization: the lookup/store key is
        ``canonicalize_reference_url(url)`` (fragment and tracking
        parameters removed), but ``fetch_fn`` always receives the
        original discovered URL (whitespace-stripped, fragment and
        full query intact) and the returned ``ReferenceDocument``
        is stored verbatim.
        """
        raw = url if isinstance(url, str) else ""
        original = raw.strip()
        if not original:
            return None
        key = canonicalize_reference_url(original)
        if not key:
            return None
        cached = self._store.get(key)
        if cached is not None:
            self.hits += 1
            return cached
        document = self.fetch_fn(original)
        if document is not None:
            self._store[key] = document
        return document

    def state(self) -> dict:
        """Snapshot the cache contents (for tests / inspection).

        Returns a shallow copy of the URL->document mapping
        plus the running hit count. Documents are returned
        as-is; callers must not mutate the cached entries.
        """
        return {
            "store": dict(self._store),
            "hits": self.hits,
        }


def empty_reference_cache_histogram() -> dict[str, int]:
    """Return a zeroed reference-cache histogram (stable schema)."""
    return {"hits": 0}
