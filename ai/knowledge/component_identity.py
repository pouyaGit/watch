"""Stage R31.6 deterministic CVE-side component/plugin identity resolution.

R30.1 currently matches CVE-side component/plugin values against observed
inventory values using only ``ai.knowledge.asset_cve_matching``'s
``normalize_product`` / ``normalize_plugin`` / ``normalize_component``. That
normalization is conservative by design (lowercase, parenthetical stripping,
``PRODUCT_ALIASES``). Real CVE-side identities appear in several distinct
forms that the conservative normalization does not collapse:

* ``wordpress_automatic_plugin``           (CVE-2024-27956)
* ``Automatic``                             (CVE-2024-27956 alt product)
* ``OttoKit: All-in-One Automation Platform`` (CVE-2025-3102)
* ``wp-ottokit``                            (observed plugin slug)
* ``WP Responsive Images (WordPress plugin)`` (CVE-2026-1557)
* ``wp-responsive-images``                  (observed plugin slug)

This module adds a small, auditable identity-resolution layer that runs *only*
on CVE-side identifiers before they are passed to the unchanged R30.1 engine.
The resolver never mutates observed inventory values and never invents
identities from prose. Every transformation is:

* deterministic (same input -> byte-identical output, ordered independent),
* conservative (no edit distance, no token intersection, no substring match),
* versioned (``RULE_VERSION``),
* bounded (``MAX_ALIAS_HITS``, ``MAX_SCAN_ROWS``, ``MAX_VALUE_LEN``),
* privacy-safe (no credentials, headers, hostnames, paths-with-host),
* documented in evidence rows with raw / normalized / canonical / observed
  identities and a ``resolution_method`` so a downstream reader can audit why
  two strings were treated as equivalent.

The resolver distinguishes:

* ``raw_identity``        - the exact CVE-side string as captured.
* ``normalized_identity`` - lowercase, parenthetical-stripped,
                             separator-normalized, trailing-language stripped.
* ``canonical_identity``  - the canonical slug (e.g. ``wp-responsive-images``)
                             when the resolver can build one deterministically.
* ``alias_set``           - the explicit, versioned alias variants for a
                             canonical identity (``wordpress-automatic``,
                             ``automatic``, ``wp-ottokit``).
* ``category``            - ``COMPONENT`` / ``PLUGIN`` / ``PRODUCT`` /
                             ``TECHNOLOGY`` / ``UNKNOWN`` (closed vocabulary).
* ``resolution_method``   - one of ``EXACT_NORMALIZED``, ``CANONICAL_SLUG``,
                             ``EXPLICIT_ALIAS``, ``NO_RESOLUTION``.
* ``evidence``            - bounded list of human-readable resolution lines.

The resolved identities are produced through :func:`resolve_cve_identities`
(CVE-side -> structured resolutions) and :func:`match_observed_identities`
(resolved CVE identities vs. observed inventory identities -> resolved
evidence rows). The R30.1 engine still receives compatible string values; the
adapter simply passes the resolved values in addition to the originals.

Hard boundaries encoded here:

* No I/O, no network, no DNS, no LLM, no subprocess, no Nuclei, no browser,
  no target interaction, no persistence.
* No fuzzy / Levenshtein / token-intersection / substring matching.
* No inference from URLs, hostnames, parameter names, keywords, or CVE text.
* Aliases are explicit and versioned; every entry is justified by current
  corpus evidence (see ``ALIAS_TABLE`` docstrings).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field as dataclass_field

# Stage R31.6 identity-resolution rule version (additive; the R30.1 engine
# rule_version is unchanged).
RULE_VERSION = "r31-6"

# Closed category vocabulary. Mirrors R30.1 ``PRODUCT`` / ``COMPONENT`` /
# ``PLUGIN`` categories plus ``TECHNOLOGY`` for cases where the resolver
# cannot classify and ``UNKNOWN`` when input is unparseable.
CATEGORY_PRODUCT = "PRODUCT"
CATEGORY_COMPONENT = "COMPONENT"
CATEGORY_PLUGIN = "PLUGIN"
CATEGORY_TECHNOLOGY = "TECHNOLOGY"
CATEGORY_UNKNOWN = "UNKNOWN"

CATEGORIES: tuple[str, ...] = (
    CATEGORY_PRODUCT,
    CATEGORY_COMPONENT,
    CATEGORY_PLUGIN,
    CATEGORY_TECHNOLOGY,
    CATEGORY_UNKNOWN,
)

# Closed resolution-method vocabulary.
METHOD_EXACT_NORMALIZED = "EXACT_NORMALIZED"
METHOD_CANONICAL_SLUG = "CANONICAL_SLUG"
METHOD_EXPLICIT_ALIAS = "EXPLICIT_ALIAS"
METHOD_NO_RESOLUTION = "NO_RESOLUTION"

METHODS: tuple[str, ...] = (
    METHOD_EXACT_NORMALIZED,
    METHOD_CANONICAL_SLUG,
    METHOD_EXPLICIT_ALIAS,
    METHOD_NO_RESOLUTION,
)

# Bounded lengths to keep resolver output deterministic and fail-soft.
MAX_VALUE_LEN = 512
MAX_RAW_VALUES = 256
MAX_EVIDENCE_PER_RESOLUTION = 4
MAX_RESOLUTIONS = 256
MAX_ALIAS_HITS = 32
MAX_SCAN_ROWS = 4096

# ---------------------------------------------------------------------------
# Conservative normalization (text-level only; no semantic / fuzzy logic)
# ---------------------------------------------------------------------------

_PARENTHETICAL_RE = re.compile(r"\([^)]*\)")
_MULTI_WS_RE = re.compile(r"\s+")
_SEPARATOR_RE = re.compile(r"[\s_\-]+")
_TRAILING_DASH_RE = re.compile(r"-+$")
_LEADING_DASH_RE = re.compile(r"^-+")

# Marketing / framing trailers that frequently follow a product identity in
# CVE ``products`` fields. Each trailer is intentionally narrow: it is only
# stripped when it appears *after* a colon-space or a punctuation break, or as
# the entire tail of the string after a single name token. We never strip
# arbitrary adjectives ("Pro", "Enterprise") from inside a name.
_MARKETING_TRAILERS: tuple[str, ...] = (
    "All-in-One Automation Platform",
    "All-in-One Automation",
    "Automation Platform",
    "WordPress Plugin",
    "Wordpress Plugin",
    "WP Plugin",
    "WordPress plugin",
    "Wordpress plugin",
    "WP plugin",
    "Plugin",
    "plugin",
)

# Suffixes that only carry type information, never identity, and which the
# resolver removes only at the end of a normalized string.
_TRAILING_TYPE_SUFFIXES: tuple[str, ...] = (
    "_plugin",
    "-plugin",
    "_component",
    "-component",
)

# Words that should never appear as a normalized identity by themselves; they
# are dropped from CVE-side strings when they form the entire token, but
# preserved inside multi-token names.
_STOPWORD_ALONE: frozenset[str] = frozenset({
    "the",
    "a",
    "an",
})


def _strip_diacritics(value: str) -> str:
    """Remove diacritics deterministically (NFKD -> ASCII)."""

    normalized = unicodedata.normalize("NFKD", value or "")
    return "".join(
        char for char in normalized
        if not unicodedata.combining(char)
    )


def _collapse_separators(value: str) -> str:
    return _SEPARATOR_RE.sub("-", value or "")


def _clean_text(value: object) -> str:
    """Lowercase, parenthetical-strip, diacritic-strip, separator-collapse.

    Mirrors the conservative ``_clean_text`` in ``asset_cve_matching`` for the
    subset the resolver operates on. Query strings, fragments and trailing
    URL-shaped tokens are stripped so the resolver never carries credentials,
    authorization headers, or sensitive request data into its output.
    """

    text = str(value if value is not None else "")
    text = text.split("?", 1)[0].split("#", 1)[0]
    text = _PARENTHETICAL_RE.sub(" ", text)
    text = _strip_diacritics(text).lower()
    text = text.replace(":", " ")
    text = text.replace(",", " ")
    text = _MULTI_WS_RE.sub(" ", text).strip()
    if not text:
        return ""
    text = _collapse_separators(text)
    return _TRAILING_DASH_RE.sub("", _LEADING_DASH_RE.sub("", text))


# Pre-normalized marketing trailers (deterministic, computed once at module
# load). ``_strip_marketing_trailer`` reads from this tuple instead of
# re-invoking ``_clean_text`` on every iteration.
_NORMALIZED_MARKETING_TRAILERS: tuple[str, ...] = tuple(
    _clean_text(trailer) for trailer in _MARKETING_TRAILERS
)


def _strip_marketing_trailer(value: str) -> str:
    """Strip a single recognized marketing trailer from the tail of ``value``."""

    text = value or ""
    while True:
        changed = False
        for tail in _NORMALIZED_MARKETING_TRAILERS:
            if text.endswith(tail) and text != tail:
                text = text[: -len(tail)].rstrip("- ")
                changed = True
                break
        if not changed:
            break
    return text


def _strip_type_suffix(value: str) -> str:
    """Drop a single trailing type-only suffix (e.g. ``_plugin``)."""

    text = value or ""
    for suffix in _TRAILING_TYPE_SUFFIXES:
        if text.endswith(suffix) and text != suffix:
            text = text[: -len(suffix)]
            text = text.rstrip("-_ ")
            return text
    return text


def _leading_wp(value: str) -> str:
    """Drop a leading ``wp-`` token (e.g. ``wp-ottokit`` -> ``ottokit``).

    Conservative: the ``wp-`` is the standard WordPress plugin-slug prefix
    used in observed plugin directories and CVE product slugs alike. The
    strip is only applied when the remainder still carries a *single-token*
    identity (e.g. ``wp-ottokit`` -> ``ottokit``). Multi-token remainders
    (``wp-responsive-images`` -> ``responsive-images``) are preserved because
    dropping the prefix would destroy identity (the observed plugin slug is
    ``wp-responsive-images`` itself).
    """

    text = value or ""
    if text.startswith("wp-"):
        remainder = text[3:]
        if remainder and remainder not in _STOPWORD_ALONE:
            if "-" not in remainder:
                return remainder
    return text


def normalize_identity(value: object) -> str:
    """Conservative CVE-side identity normalization (one input -> one key).

    Steps (deterministic, ordered):

    1. parenthetical-strip + diacritic-strip + lowercase,
    2. marketing-trailer-strip (e.g. ``All-in-One Automation Platform``),
    3. trailing-type-suffix-strip (e.g. ``_plugin``, ``-plugin``),
    4. leading ``wp-`` strip when the remainder carries identity,
    5. separator-collapse to ``-`` and stopword-only drop.

    The function never invents aliases and never collapses two distinct
    strings; it only removes structural language and clearly-redundant
    WordPress plugin-slug decoration. When in doubt, the input is preserved
    unchanged (fail-soft).
    """

    cleaned = _clean_text(value)
    if not cleaned:
        return ""
    cleaned = _strip_marketing_trailer(cleaned)
    cleaned = _strip_type_suffix(cleaned)
    cleaned = _leading_wp(cleaned)
    cleaned = _collapse_separators(cleaned)
    cleaned = _TRAILING_DASH_RE.sub("", _LEADING_DASH_RE.sub("", cleaned))
    if not cleaned or cleaned in _STOPWORD_ALONE:
        return ""
    return cleaned[:MAX_VALUE_LEN]


# ---------------------------------------------------------------------------
# Canonical slug generation (only when the resolver can derive one safely)
# ---------------------------------------------------------------------------

_VALID_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,63}$")


def canonical_slug(
    *, raw: str, normalized: str, category: str
) -> str:
    """Build a conservative canonical slug from raw + normalized inputs.

    Only emits a slug when the normalized value already matches the slug
    shape. Never invents a slug from arbitrary prose and never concatenates
    fragments. Returns ``""`` when a safe slug cannot be derived (the resolver
    must then fall back to ``EXACT_NORMALIZED`` or ``EXPLICIT_ALIAS``).
    """

    if not normalized:
        return ""
    if category not in (CATEGORY_PLUGIN, CATEGORY_COMPONENT, CATEGORY_PRODUCT):
        return ""
    candidate = normalized
    candidate = _collapse_separators(candidate)
    candidate = _TRAILING_DASH_RE.sub("", _LEADING_DASH_RE.sub("", candidate))
    candidate = candidate[:64]
    if not _VALID_SLUG_RE.match(candidate):
        return ""
    if not candidate or candidate in _STOPWORD_ALONE:
        return ""
    return candidate


# ---------------------------------------------------------------------------
# Explicit alias table (versioned, deterministic, documented)
# ---------------------------------------------------------------------------

# Each canonical identity maps to a finite, ordered tuple of variants. The
# resolver is the *only* consumer of this table and never invents aliases
# beyond it. Every entry is justified by current local corpus evidence (see
# the stage report for the per-entry audit).
#
# Do NOT add entries here without examining the current corpus; the alias table
# is the single most sensitive source of false positives in this module.

@dataclass(frozen=True)
class AliasEntry:
    """One canonical identity and its bounded, ordered alias variants."""

    canonical: str
    category: str
    aliases: tuple[str, ...]
    # Short human justification; not used in matching, only for evidence.
    rationale: str = ""

    def alias_set(self) -> frozenset[str]:
        out: set[str] = {self.canonical}
        out.update(self.aliases)
        return frozenset(out)


# Aliases are evaluated in declaration order; earlier entries win ties so the
# deterministic ordering of ``resolve_cve_identities`` stays stable.
ALIAS_TABLE: tuple[AliasEntry, ...] = (
    AliasEntry(
        canonical="wp-responsive-images",
        category=CATEGORY_PLUGIN,
        aliases=(
            "wp-responsive-images",
            "wp responsive images",
            "wp responsive image",
            "wpresponsiveimages",
        ),
        rationale=(
            "CVE-2026-1557 affected_products includes "
            "'WP Responsive Images (WordPress plugin)'; the observed slug "
            "'wp-responsive-images' is the WordPress plugin directory "
            "convention. The current R30.1 alias table already covers this "
            "case for the plugin matcher; R31.6 carries it forward at the "
            "resolver layer so the same identities resolve identically "
            "when they appear as products or components."
        ),
    ),
    AliasEntry(
        canonical="wordpress-automatic",
        category=CATEGORY_PLUGIN,
        aliases=(
            "wordpress-automatic",
            "wordpress_automatic_plugin",
            "wordpress automatic",
            "automatic",
        ),
        rationale=(
            "CVE-2024-27956 lists both 'Automatic' and "
            "'wordpress_automatic_plugin' as products; the WordPress plugin "
            "directory slug is 'wordpress-automatic'. The CVE-side product "
            "'Automatic' is the post-strip form of 'wordpress_automatic_plugin' "
            "and the plugin directory slug 'wordpress-automatic' is the "
            "observed form. All three resolve to the same canonical "
            "WordPress plugin identity."
        ),
    ),
    AliasEntry(
        canonical="ottokit",
        category=CATEGORY_PLUGIN,
        aliases=(
            "ottokit",
            "wp-ottokit",
            "otto kit",
        ),
        rationale=(
            "CVE-2025-3102 lists 'OttoKit: All-in-One Automation Platform' "
            "as product. The marketing trailer is stripped by "
            "normalize_identity. The observed WordPress plugin directory "
            "slug in CVE references is 'wp-ottokit' which the resolver maps "
            "to 'ottokit' via the leading 'wp-' strip. The marketing name "
            "'OttoKit' and the slug 'wp-ottokit' therefore both resolve to "
            "the canonical plugin identity 'ottokit'."
        ),
    ),
)


# Aliases that the resolver MUST NOT collapse even when the strings share
# tokens. Used by the negative tests to guard against accidental relaxation
# of the alias table.
_NEGATIVE_ALIASES: tuple[tuple[str, str], ...] = (
    ("automatic", "automatic-login"),
    ("ottokit", "otto"),
    ("ckeditor", "ckfinder"),
    ("wp-smushit", "smush"),
    ("wordpress", "wordpress-automatic"),
    ("jquery", "jquery-ui"),
)


def _alias_lookup(value: str) -> AliasEntry | None:
    if not value:
        return None
    for entry in ALIAS_TABLE:
        if value in entry.alias_set():
            return entry
    return None


# ---------------------------------------------------------------------------
# Classification (PLUGIN vs. COMPONENT vs. PRODUCT vs. TECHNOLOGY vs. UNKNOWN)
# ---------------------------------------------------------------------------

_PLUGIN_TOKENS: tuple[str, ...] = (
    # The trailing ``plugin`` substring is the conservative single-token
    # signal that a CVE-side value names a plugin. Other tokens are
    # redundant because they all contain ``plugin``.
    "plugin",
)


def classify(raw: str, normalized: str) -> str:
    """Classify one CVE-side identity into a closed R31.6 category."""

    raw_lower = str(raw or "").strip().lower()
    if not normalized:
        return CATEGORY_UNKNOWN
    if any(token in raw_lower for token in _PLUGIN_TOKENS):
        return CATEGORY_PLUGIN
    entry = _alias_lookup(normalized)
    if entry is not None and normalized in entry.alias_set():
        # The alias table records the canonical category explicitly.
        return entry.category
    return CATEGORY_PRODUCT


# ---------------------------------------------------------------------------
# Resolution data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityResolution:
    """One resolved CVE-side identity (input -> output)."""

    raw: str
    normalized: str
    canonical: str
    category: str
    resolution_method: str
    alias_variants: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "raw_identity": self.raw,
            "normalized_identity": self.normalized,
            "canonical_identity": self.canonical,
            "category": self.category,
            "resolution_method": self.resolution_method,
            "alias_variants": list(self.alias_variants),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class IdentityEvidence:
    """One resolved match between a CVE identity and an observed identity."""

    raw_cve_identity: str
    canonical_cve_identity: str
    category: str
    resolution_method: str
    observed_identity: str
    observed_normalized: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "raw_cve_identity": self.raw_cve_identity,
            "canonical_cve_identity": self.canonical_cve_identity,
            "category": self.category,
            "resolution_method": self.resolution_method,
            "observed_identity": self.observed_identity,
            "observed_normalized": self.observed_normalized,
            "evidence": list(self.evidence),
        }


@dataclass
class IdentityResolutionResult:
    """Aggregate resolution output for one CVE context."""

    resolutions: list[IdentityResolution] = dataclass_field(
        default_factory=list
    )
    matches: list[IdentityEvidence] = dataclass_field(default_factory=list)

    def resolved_values(self, category: str | None = None) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for resolution in self.resolutions:
            if category and resolution.category != category:
                continue
            for value in (resolution.canonical, resolution.normalized):
                if value and value not in seen:
                    seen.add(value)
                    out.append(value)
        return out


# ---------------------------------------------------------------------------
# CVE-side resolution
# ---------------------------------------------------------------------------


def _resolve_one(raw: str) -> IdentityResolution | None:
    text = str(raw or "").strip()
    if not text:
        return None
    normalized = normalize_identity(text)
    if not normalized:
        return IdentityResolution(
            raw=text,
            normalized="",
            canonical="",
            category=CATEGORY_UNKNOWN,
            resolution_method=METHOD_NO_RESOLUTION,
            evidence=(f"raw {text!r} normalized to empty",),
        )
    entry = _alias_lookup(normalized)
    if entry is not None:
        slug = canonical_slug(
            raw=text,
            normalized=entry.canonical,
            category=entry.category,
        )
        canonical = slug or entry.canonical
        return IdentityResolution(
            raw=text,
            normalized=normalized,
            canonical=canonical,
            category=entry.category,
            resolution_method=METHOD_EXPLICIT_ALIAS,
            alias_variants=tuple(sorted(entry.alias_set())),
            evidence=(
                f"alias {entry.canonical!r} matched normalized "
                f"{normalized!r} via {entry.rationale[:64]!r}",
            ),
        )
    category = classify(text, normalized)
    slug = canonical_slug(
        raw=text, normalized=normalized, category=category
    )
    if slug:
        return IdentityResolution(
            raw=text,
            normalized=normalized,
            canonical=slug,
            category=category,
            resolution_method=METHOD_CANONICAL_SLUG,
            evidence=(
                f"canonical slug {slug!r} derived from normalized "
                f"{normalized!r}",
            ),
        )
    return IdentityResolution(
        raw=text,
        normalized=normalized,
        canonical=normalized,
        category=category,
        resolution_method=METHOD_EXACT_NORMALIZED,
        evidence=(
            f"normalized {normalized!r} used as canonical for raw {text!r}",
        ),
    )


def resolve_cve_identities(
    cve_products: object = (),
    cve_plugins: object = (),
    cve_components: object = (),
    *,
    max_inputs: int = MAX_RAW_VALUES,
) -> IdentityResolutionResult:
    """Resolve every CVE-side identity to a structured ``IdentityResolution``.

    The function is pure, deterministic, order-preserving and bounded: the
    first ``max_inputs`` unique raw strings per category are processed.
    """

    result = IdentityResolutionResult()
    seen: set[tuple[str, str]] = set()
    for category, values in (
        (CATEGORY_PRODUCT, cve_products),
        (CATEGORY_PLUGIN, cve_plugins),
        (CATEGORY_COMPONENT, cve_components),
    ):
        emitted = 0
        for raw in values or ():
            text = str(raw or "").strip()
            if not text:
                continue
            key = (category, text)
            if key in seen:
                continue
            seen.add(key)
            resolution = _resolve_one(text)
            if resolution is None:
                continue
            # CVE-side category hint may override the resolver classification
            # when the resolver produced UNKNOWN; never override an explicit
            # alias table classification.
            if (
                resolution.category == CATEGORY_UNKNOWN
                or (
                    resolution.resolution_method == METHOD_EXACT_NORMALIZED
                    and category != CATEGORY_PRODUCT
                    and resolution.category == CATEGORY_PRODUCT
                )
            ):
                resolution = IdentityResolution(
                    raw=resolution.raw,
                    normalized=resolution.normalized,
                    canonical=resolution.canonical,
                    category=category,
                    resolution_method=resolution.resolution_method,
                    alias_variants=resolution.alias_variants,
                    evidence=resolution.evidence + (
                        f"category hint from caller: {category}",
                    ),
                )
            result.resolutions.append(resolution)
            emitted += 1
            if len(result.resolutions) >= MAX_RESOLUTIONS:
                return result
            if emitted >= max_inputs:
                break
    return result


# ---------------------------------------------------------------------------
# Observed-inventory matching against resolved CVE identities
# ---------------------------------------------------------------------------


def _observed_normalize(value: object) -> str:
    text = str(value if value is not None else "").strip()
    if not text:
        return ""
    return _clean_text(text)


def match_observed_identities(
    *,
    resolutions: object,
    observed_components: object = (),
    observed_plugins: object = (),
    observed_products: object = (),
    max_observed: int = MAX_SCAN_ROWS,
) -> list[IdentityEvidence]:
    """Compare resolved CVE identities against observed inventory identities.

    Returns a bounded list of :class:`IdentityEvidence` rows that record the
    raw/canonical/observed identities and the resolution method. The R30.1
    engine still receives the canonical CVE-side values; this function exists
    so the backend adapter can record *why* two identities were treated as
    equivalent without changing matching semantics.
    """

    out: list[IdentityEvidence] = []
    seen: set[tuple[str, str, str]] = set()

    def _emit(evidence: IdentityEvidence) -> None:
        key = (
            evidence.raw_cve_identity,
            evidence.canonical_cve_identity,
            evidence.observed_identity,
        )
        if key in seen:
            return
        seen.add(key)
        out.append(evidence)

    for category, observed_values in (
        (CATEGORY_COMPONENT, observed_components),
        (CATEGORY_PLUGIN, observed_plugins),
        (CATEGORY_PRODUCT, observed_products),
    ):
        seen_observed: set[str] = set()
        for raw in observed_values or ():
            text = str(raw or "").strip()
            if not text or text in seen_observed:
                continue
            seen_observed.add(text)
            observed_normalized = _observed_normalize(text)
            if not observed_normalized:
                continue
            emitted = 0
            for resolution in resolutions or ():
                if emitted >= MAX_ALIAS_HITS:
                    break
                if resolution.category not in (
                    category,
                    CATEGORY_PRODUCT,
                ):
                    continue
                if not resolution.canonical:
                    continue
                resolution_alias_set = set(resolution.alias_variants)
                resolution_alias_set.add(resolution.normalized)
                resolution_alias_set.add(resolution.canonical)
                # Direct alias-set intersection (set-equality only; never
                # substring or token intersection).
                observed_alias_set = {observed_normalized}
                if not (observed_alias_set & resolution_alias_set):
                    continue
                evidence = IdentityEvidence(
                    raw_cve_identity=resolution.raw,
                    canonical_cve_identity=resolution.canonical,
                    category=resolution.category,
                    resolution_method=resolution.resolution_method,
                    observed_identity=text,
                    observed_normalized=observed_normalized,
                    evidence=(
                        f"observed {text!r} aliases overlap with "
                        f"resolved {resolution.canonical!r}",
                    ),
                )
                _emit(evidence)
                emitted += 1
            if len(out) >= max_observed:
                return out[:MAX_SCAN_ROWS]
    return out[:MAX_SCAN_ROWS]


# ---------------------------------------------------------------------------
# Resolver input builders for the backend adapter
# ---------------------------------------------------------------------------


def expanded_cve_values(resolution: IdentityResolution) -> list[str]:
    """CVE-side value list for the unchanged R30.1 matcher.

    The adapter passes the canonical identity first (so the engine sees the
    preferred form) and then the normalized and alias variants so any existing
    R30.1 alias set can still match. Order is stable; duplicates are removed.
    """

    out: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        text = str(value or "").strip()
        if not text or text in seen:
            return
        seen.add(text)
        out.append(text)

    _add(resolution.canonical)
    _add(resolution.normalized)
    for variant in resolution.alias_variants:
        _add(variant)
    return out


def expanded_cve_value_set(
    resolutions: object, category: str | None = None
) -> list[str]:
    """Aggregate ``expanded_cve_values`` over a list of resolutions."""

    out: list[str] = []
    seen: set[str] = set()
    for resolution in resolutions or ():
        if category and resolution.category != category:
            continue
        for value in expanded_cve_values(resolution):
            if value not in seen:
                seen.add(value)
                out.append(value)
    return out


# ---------------------------------------------------------------------------
# Internal helpers exposed for tests
# ---------------------------------------------------------------------------


def negative_alias_pairs() -> tuple[tuple[str, str], ...]:
    """The current corpus-derived negative-collision set (read-only)."""

    return _NEGATIVE_ALIASES


__all__ = [
    "RULE_VERSION",
    "CATEGORIES",
    "METHODS",
    "CATEGORY_PRODUCT",
    "CATEGORY_COMPONENT",
    "CATEGORY_PLUGIN",
    "CATEGORY_TECHNOLOGY",
    "CATEGORY_UNKNOWN",
    "METHOD_EXACT_NORMALIZED",
    "METHOD_CANONICAL_SLUG",
    "METHOD_EXPLICIT_ALIAS",
    "METHOD_NO_RESOLUTION",
    "ALIAS_TABLE",
    "MAX_VALUE_LEN",
    "MAX_RAW_VALUES",
    "MAX_EVIDENCE_PER_RESOLUTION",
    "MAX_RESOLUTIONS",
    "MAX_ALIAS_HITS",
    "MAX_SCAN_ROWS",
    "AliasEntry",
    "IdentityResolution",
    "IdentityEvidence",
    "IdentityResolutionResult",
    "normalize_identity",
    "canonical_slug",
    "classify",
    "resolve_cve_identities",
    "match_observed_identities",
    "expanded_cve_values",
    "expanded_cve_value_set",
    "negative_alias_pairs",
]
