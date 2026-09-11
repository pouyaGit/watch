"""Stage R30.1 asset <-> CVE matching intelligence (pure engine).

Answers the owner's personal-research question *"Does Watch have enough
evidence that this CVE applies to something I actually monitor?"* using only
already-persisted CVE metadata and observed asset/recon inventory.

This module is **pure and offline**: no I/O, no network, no DNS, no LLM, no
subprocess, no Nuclei, no browser, no target interaction, no persistence and no
execution. It never emits "vulnerable"/"exploitable"/"confirmed": a match is
RESEARCH RELEVANCE only.

Design principles
-----------------
- Deterministic, token/boundary-aware matching (never arbitrary substring
  matching). ``press`` never matches ``wordpress``.
- Only claim a VERSION match when real observed version evidence exists and the
  CVE range parses safely; otherwise the state is ``VERSION_UNKNOWN``.
- PARAMETER / PATH / VULNERABILITY_TYPE are supporting signals only and never
  independently make a target-specific match HIGH.
- A single generic technology match can never be HIGH.
- Every match carries traceable evidence (source + matched value + reason).

R30.1 is additive: it does not change R17 relevance formulas, R25.2 Money
Score, R26 opportunity classification, R26.2 action precedence or R29.1 hunt
priority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from ai.correlator.technology import (
    GENERIC_TECHNOLOGIES,
    INVALID_VALUES,
    TECHNOLOGY_ALIASES,
    normalize,
)
from ai.schemas.asset_cve_match import (
    ASSET_CVE_MATCH_RULE_VERSION,
    ASSET_ID_RE,
    AssetCVEMatch,
    confidence_score_for,
    match_id_for,
    match_projection,
)

RULE_VERSION = ASSET_CVE_MATCH_RULE_VERSION

# Evidence sources (closed vocabulary, mirrored by the schema).
SOURCE_ASSET = "ASSET_INVENTORY"
SOURCE_TECHNOLOGY = "TECHNOLOGY_INVENTORY"
SOURCE_COMPONENT = "COMPONENT_INVENTORY"
SOURCE_PARAMETER = "PARAMETER_INVENTORY"
SOURCE_ENDPOINT = "ENDPOINT_INVENTORY"
SOURCE_CVE = "CVE_METADATA"

# Closed asset-match-state vocabulary (R30.1; NOT a new hunt tier).
ASSET_MATCH_STATES: tuple[str, ...] = (
    "CONFIRMED",
    "SUPPORTED",
    "WEAK",
    "UNKNOWN",
)

# Closed blocker-code vocabulary (canonical codes; R18 text is mapped to these).
BLOCKER_CODES: tuple[str, ...] = (
    "generic_technology_only",
    "plugin_not_observed",
    "component_not_observed",
    "version_unknown",
    "parameter_unknown",
)

# R18 emits human blocker text; map it onto stable R30.1 codes. Unknown codes
# are preserved verbatim (never invented, never silently dropped).
_BLOCKER_CODE_MAP: dict[str, str] = {
    "only generic technology match": "generic_technology_only",
    "generic_technology_only": "generic_technology_only",
    "affected plugin not observed": "plugin_not_observed",
    "plugin_not_observed": "plugin_not_observed",
    "asset component not observed": "component_not_observed",
    "component_not_observed": "component_not_observed",
    "asset version unknown": "version_unknown",
    "version_unknown": "version_unknown",
    "parameter unknown": "parameter_unknown",
    "parameter_unknown": "parameter_unknown",
}

# ---------------------------------------------------------------------------
# Normalization (deterministic only; no broad fuzzy matching)
# ---------------------------------------------------------------------------

_PARENTHETICAL_RE = re.compile(r"\([^)]*\)")

# Small, versioned, testable alias mechanism. Only aliases justified by
# existing project data are present. Each canonical key maps to the set of
# normalized variants that denote the same product/plugin.
PRODUCT_ALIASES: dict[str, frozenset[str]] = {
    "wordpress": frozenset({"wordpress"}),
    "wp responsive images": frozenset(
        {
            "wp responsive images",
            "wp responsive image",
            "wpresponsiveimages",
        }
    ),
}

PLUGIN_ALIASES: dict[str, frozenset[str]] = {
    "wp responsive images": frozenset(
        {
            "wp responsive images",
            "wp responsive image",
            "wpresponsiveimages",
        }
    ),
}

COMPONENT_ALIASES: dict[str, frozenset[str]] = {}


def _clean_text(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    # Parenthetical qualifiers like "(WordPress plugin)" are descriptive, not
    # part of the identity; drop them deterministically.
    text = _PARENTHETICAL_RE.sub(" ", text)
    return text


def _canonical(value: str, table: dict[str, frozenset[str]]) -> str:
    if not value:
        return ""
    for canonical, variants in table.items():
        if value == canonical or value in variants:
            return canonical
    return value


def normalize_product(value: object) -> str:
    """Normalize a CVE/asset product name (alias-aware, boundary-safe)."""

    return _canonical(normalize(_clean_text(value)), PRODUCT_ALIASES)


def normalize_plugin(value: object) -> str:
    """Normalize a plugin name (path/parenthetical stripped, alias-aware)."""

    return _canonical(
        normalize(_clean_text(_basename(value))), PLUGIN_ALIASES
    )


def normalize_component(value: object) -> str:
    """Normalize a component/file reference (basename, alias-aware)."""

    base = _basename(value)
    normalized = normalize(_clean_text(base))
    if not normalized:
        normalized = normalize(_clean_text(value))
    return _canonical(normalized, COMPONENT_ALIASES)


def normalize_version(value: object) -> str:
    """Normalize a version string without inventing digits."""

    return str(value or "").strip().lower()


def normalize_parameter(value: object) -> str:
    """Normalize a parameter name (single-token, boundary-safe)."""

    text = str(value or "").strip().lstrip("?&")
    if "=" in text:
        text = text.split("=", 1)[0]
    return normalize(_clean_text(_basename(text)))


def _basename(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace("\\", "/")
    text = text.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    if "/" in text:
        return text.rsplit("/", 1)[-1]
    return text


def _valid(value: str) -> bool:
    return bool(value) and value not in INVALID_VALUES


def _alias_set(
    value: str, table: dict[str, frozenset[str]]
) -> frozenset[str]:
    variants = set(table.get(value, frozenset()))
    variants.add(value)
    return frozenset(variants)


# ---------------------------------------------------------------------------
# Match result model (internal; the persisted/public shape is AssetCVEMatch)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchResult:
    """One deterministic per-type match (research relevance only)."""

    match_type: str
    confidence: str
    matched_value: str
    normalized_value: str
    source: str
    evidence: tuple[str, ...] = ()
    reason: str = ""
    supporting: bool = False
    version_state: str = ""


@dataclass
class MatchEvaluation:
    """Internal bundle returned by :func:`evaluate_inventory`."""

    matches: list[MatchResult] = dataclass_field(default_factory=list)
    resolved_blockers: list[str] = dataclass_field(default_factory=list)
    remaining_blockers: list[str] = dataclass_field(default_factory=list)


# ---------------------------------------------------------------------------
# Per-type matchers
# ---------------------------------------------------------------------------


def _exact_pair(
    cve_values: object,
    observed_values: object,
    normalize_fn,
    alias_table: dict[str, frozenset[str]],
) -> tuple[str, str] | None:
    """Boundary-aware match: normalized/aliased equality only (no substring)."""

    observed: list[tuple[str, str]] = []
    for item in observed_values or ():
        normalized = normalize_fn(item)
        if _valid(normalized):
            observed.append((normalized, str(item).strip()))
    for item in cve_values or ():
        cve_norm = normalize_fn(item)
        if not _valid(cve_norm):
            continue
        cve_set = _alias_set(cve_norm, alias_table)
        for obs_norm, obs_original in observed:
            obs_set = _alias_set(obs_norm, alias_table)
            if cve_norm == obs_norm or (cve_set & obs_set):
                return cve_norm, obs_original
    return None


def match_product(cve_products: object, observed_products: object) -> MatchResult | None:
    """CVE affected product <-> known asset product (exact/alias)."""

    hit = _exact_pair(cve_products, observed_products,
                      normalize_product, PRODUCT_ALIASES)
    if hit is None:
        return None
    cve_norm, observed = hit
    return MatchResult(
        match_type="PRODUCT",
        confidence="MEDIUM",
        matched_value=observed,
        normalized_value=cve_norm,
        source=SOURCE_ASSET,
        evidence=(f"observed product: {observed}", f"cve product: {cve_norm}"),
        reason=f"product match: {observed}",
    )


def match_component(
    cve_components: object, observed_components: object
) -> MatchResult | None:
    """CVE affected component <-> observed component (basename exact/alias)."""

    hit = _exact_pair(cve_components, observed_components,
                      normalize_component, COMPONENT_ALIASES)
    if hit is None:
        return None
    cve_norm, observed = hit
    return MatchResult(
        match_type="COMPONENT",
        confidence="MEDIUM",
        matched_value=observed,
        normalized_value=cve_norm,
        source=SOURCE_COMPONENT,
        evidence=(
            f"observed component: {observed}",
            f"cve component: {cve_norm}",
        ),
        reason=f"component match: {observed}",
    )


def match_plugin(cve_plugins: object, observed_plugins: object) -> MatchResult | None:
    """CVE plugin <-> observed plugin (exact/alias)."""

    hit = _exact_pair(cve_plugins, observed_plugins,
                      normalize_plugin, PLUGIN_ALIASES)
    if hit is None:
        return None
    cve_norm, observed = hit
    return MatchResult(
        match_type="PLUGIN",
        confidence="MEDIUM",
        matched_value=observed,
        normalized_value=cve_norm,
        source=SOURCE_COMPONENT,
        evidence=(f"observed plugin: {observed}", f"cve plugin: {cve_norm}"),
        reason=f"plugin match: {observed}",
    )


def match_technology(
    cve_technologies: object, observed_technologies: object
) -> MatchResult | None:
    """CVE technology <-> observed technology (alias-aware, generic-aware)."""

    observed: list[tuple[str, str]] = []
    for item in observed_technologies or ():
        normalized = normalize(str(item))
        if _valid(normalized):
            observed.append((normalized, str(item).strip()))
    for item in cve_technologies or ():
        cve_norm = normalize(str(item))
        if not _valid(cve_norm):
            continue
        cve_set = _alias_set(cve_norm, TECHNOLOGY_ALIASES)
        for obs_norm, obs_original in observed:
            obs_set = _alias_set(obs_norm, TECHNOLOGY_ALIASES)
            if cve_norm == obs_norm or (cve_set & obs_set):
                generic = cve_norm in GENERIC_TECHNOLOGIES
                return MatchResult(
                    match_type="TECHNOLOGY",
                    confidence="LOW" if generic else "MEDIUM",
                    matched_value=obs_original,
                    normalized_value=cve_norm,
                    source=SOURCE_TECHNOLOGY,
                    evidence=(
                        f"observed technology: {obs_original}",
                        f"cve technology: {cve_norm}",
                    ),
                    reason=f"technology match: {obs_original}",
                )
    return None


# -- Version matching -------------------------------------------------------


_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*")


def _parse_version(value: object) -> tuple[int, ...] | None:
    match = _VERSION_TOKEN_RE.search(str(value or ""))
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(0).split("."))
    except ValueError:  # pragma: no cover - defensive
        return None


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    length = max(len(left), len(right))
    left = left + (0,) * (length - len(left))
    right = right + (0,) * (length - len(right))
    return (left > right) - (left < right)


def _satisfies(observed: tuple[int, ...], spec: str) -> bool | None:
    """Return True/False when ``spec`` parses, else None (unknown)."""

    text = str(spec or "").strip().lower()
    if not text:
        return None
    if text in ("*", "any", "all", "all versions"):
        return True

    range_match = re.match(r"^(.+?)\s+(?:-|to|through)\s+(.+)$", text)
    if range_match:
        low = _parse_version(range_match.group(1))
        high = _parse_version(range_match.group(2))
        if low is None or high is None:
            return None
        return _compare(observed, low) >= 0 and _compare(observed, high) <= 0

    if "," in text:
        results = [_satisfies(observed, part) for part in text.split(",")]
        if any(result is True for result in results):
            return True
        if any(result is False for result in results):
            return False
        return None

    comparator = re.match(r"^(<=|>=|==|=|<|>)\s*(.+)$", text)
    if comparator:
        operator = comparator.group(1)
        right = _parse_version(comparator.group(2))
        if right is None:
            return None
        comparison = _compare(observed, right)
        if operator == "<":
            return comparison < 0
        if operator == "<=":
            return comparison <= 0
        if operator == ">":
            return comparison > 0
        if operator == ">=":
            return comparison >= 0
        return comparison == 0

    right = _parse_version(text)
    if right is None:
        return None
    return _compare(observed, right) == 0


def evaluate_version(
    cve_versions: object, observed_versions: object
) -> dict:
    """Safe deterministic version evaluation.

    Returns ``{"state": MATCH|NO_MATCH|UNKNOWN, "observed_version", "spec"}``.
    Never assumes latest/oldest/current; unparseable ranges -> UNKNOWN.
    """

    observed: list[tuple[str, tuple[int, ...]]] = []
    for item in observed_versions or ():
        parsed = _parse_version(item)
        if parsed is not None:
            observed.append((str(item).strip(), parsed))
    specs = [str(item).strip() for item in (cve_versions or ()) if str(item).strip()]

    if not observed or not specs:
        return {"state": "UNKNOWN", "observed_version": "", "spec": ""}

    saw_parsable = False
    for spec in specs:
        for original, parsed in observed:
            result = _satisfies(parsed, spec)
            if result is None:
                continue
            saw_parsable = True
            if result:
                return {
                    "state": "MATCH",
                    "observed_version": original,
                    "spec": spec,
                }
    if not saw_parsable:
        return {"state": "UNKNOWN", "observed_version": "", "spec": ""}
    return {
        "state": "NO_MATCH",
        "observed_version": observed[0][0],
        "spec": specs[0],
    }


def match_version(
    cve_versions: object, observed_versions: object
) -> MatchResult | None:
    """CVE affected version/range <-> known asset version (only on MATCH)."""

    evaluation = evaluate_version(cve_versions, observed_versions)
    if evaluation["state"] != "MATCH":
        return None
    observed = evaluation["observed_version"]
    spec = evaluation["spec"]
    return MatchResult(
        match_type="VERSION",
        confidence="MEDIUM",
        matched_value=observed,
        normalized_value=normalize_version(observed),
        source=SOURCE_ASSET,
        evidence=(
            f"observed version: {observed}",
            f"cve affected range: {spec}",
        ),
        reason=f"version match: {observed} satisfies {spec}",
        version_state="MATCH",
    )


# -- Supporting matchers ----------------------------------------------------


def match_parameter(
    cve_parameters: object, observed_parameters: object
) -> MatchResult | None:
    """CVE affected parameter <-> observed parameter (exact, no inference)."""

    hit = _exact_pair(cve_parameters, observed_parameters,
                      normalize_parameter, {})
    if hit is None:
        return None
    cve_norm, observed = hit
    return MatchResult(
        match_type="PARAMETER",
        confidence="LOW",
        matched_value=observed,
        normalized_value=cve_norm,
        source=SOURCE_PARAMETER,
        evidence=(
            f"observed parameter: {observed}",
            f"cve parameter: {cve_norm}",
        ),
        reason=f"parameter match: {observed}",
        supporting=True,
    )


def match_path(cve_paths: object, observed_paths: object) -> MatchResult | None:
    """CVE component/path <-> observed endpoint/path (supporting only)."""

    observed: list[tuple[str, str]] = []
    for item in observed_paths or ():
        normalized = normalize(_clean_text(item))
        if normalized:
            observed.append((normalized, str(item).strip()))
    for item in cve_paths or ():
        cve_norm = normalize(_clean_text(item))
        if not cve_norm:
            continue
        cve_tokens = set(cve_norm.split())
        for obs_norm, obs_original in observed:
            if cve_norm == obs_norm:
                return MatchResult(
                    match_type="PATH",
                    confidence="LOW",
                    matched_value=obs_original,
                    normalized_value=cve_norm,
                    source=SOURCE_ENDPOINT,
                    evidence=(
                        f"observed path: {obs_original}",
                        f"cve path: {cve_norm}",
                    ),
                    reason=f"path match: {obs_original}",
                    supporting=True,
                )
            if len(cve_tokens) >= 2 and cve_tokens.issubset(
                set(obs_norm.split())
            ):
                return MatchResult(
                    match_type="PATH",
                    confidence="LOW",
                    matched_value=obs_original,
                    normalized_value=cve_norm,
                    source=SOURCE_ENDPOINT,
                    evidence=(
                        f"observed path contains: {obs_original}",
                        f"cve path: {cve_norm}",
                    ),
                    reason=f"path match: {obs_original}",
                    supporting=True,
                )
    return None


def match_vulnerability_type(
    cve_types: object, observed_categories: object
) -> MatchResult | None:
    """CVE vulnerability type <-> observed relevant behavior (supporting only).

    Never independently makes a target-specific match HIGH.
    """

    hit = _exact_pair(cve_types, observed_categories, normalize, {})
    if hit is None:
        return None
    cve_norm, observed = hit
    return MatchResult(
        match_type="VULNERABILITY_TYPE",
        confidence="LOW",
        matched_value=observed,
        normalized_value=cve_norm,
        source=SOURCE_CVE,
        evidence=(
            f"observed category: {observed}",
            f"cve vulnerability type: {cve_norm}",
        ),
        reason=f"vulnerability type compatibility: {cve_norm}",
        supporting=True,
    )


# ---------------------------------------------------------------------------
# Confidence + blockers + aggregation
# ---------------------------------------------------------------------------


_CONFIDENCE_SUPPORT: frozenset[str] = frozenset(
    {"PARAMETER", "PATH", "VULNERABILITY_TYPE"}
)


def calculate_match_confidence(matches: object) -> str:
    """Deterministic confidence class for a set of matches (documented).

    Precedence (first match wins):

    1. PRODUCT + (COMPONENT or PLUGIN)                         -> HIGH
    2. VERSION match + (COMPONENT or PLUGIN)                   -> HIGH
    3. (COMPONENT or PLUGIN) + supporting PARAMETER/PATH       -> HIGH
    4. PRODUCT only                                            -> MEDIUM
    5. COMPONENT or PLUGIN only                                -> MEDIUM
    6. VERSION + PRODUCT                                       -> MEDIUM
    7. specific TECHNOLOGY                                     -> MEDIUM
    8. generic TECHNOLOGY                                      -> LOW
    9. supporting-only / VERSION-only / nothing                -> LOW
    """

    results = list(matches or ())
    types = {result.match_type for result in results}
    support = types & _CONFIDENCE_SUPPORT
    has_product = "PRODUCT" in types
    has_component = "COMPONENT" in types
    has_plugin = "PLUGIN" in types
    has_version = any(
        result.match_type == "VERSION" and result.version_state == "MATCH"
        for result in results
    )
    has_technology = "TECHNOLOGY" in types
    technology_generic = any(
        result.match_type == "TECHNOLOGY"
        and result.normalized_value in GENERIC_TECHNOLOGIES
        for result in results
    )

    if has_product and (has_component or has_plugin):
        return "HIGH"
    if has_version and (has_component or has_plugin):
        return "HIGH"
    if (has_component or has_plugin) and support:
        return "HIGH"

    if has_product:
        return "MEDIUM"
    if has_component or has_plugin:
        return "MEDIUM"
    if has_version and has_product:
        return "MEDIUM"
    if has_technology:
        return "LOW" if technology_generic else "MEDIUM"
    return "LOW"


def normalize_blocker_code(value: object) -> str:
    """Map R18 human blocker text onto a stable R30.1 code."""

    text = str(value or "").strip()
    return _BLOCKER_CODE_MAP.get(
        text, _BLOCKER_CODE_MAP.get(text.lower(), text)
    )


def resolve_blockers(
    blocker_codes: object, matches: object
) -> dict:
    """Resolve R18 blockers from real match evidence only.

    Never resolves a blocker because a CVE has a public PoC.
    """

    results = list(matches or ())
    types = {result.match_type for result in results}
    version_matched = any(
        result.match_type == "VERSION" and result.version_state == "MATCH"
        for result in results
    )
    resolved: list[str] = []
    remaining: list[str] = []
    seen: set[str] = set()
    for raw in blocker_codes or ():
        code = normalize_blocker_code(raw)
        if not code or code in seen:
            continue
        seen.add(code)
        if code == "generic_technology_only" and (
            types & {"PRODUCT", "COMPONENT", "PLUGIN"}
        ):
            resolved.append(code)
        elif code == "plugin_not_observed" and "PLUGIN" in types:
            resolved.append(code)
        elif code == "component_not_observed" and "COMPONENT" in types:
            resolved.append(code)
        elif code == "version_unknown" and version_matched:
            resolved.append(code)
        elif code == "parameter_unknown" and "PARAMETER" in types:
            resolved.append(code)
        else:
            remaining.append(code)
    return {"resolved": resolved, "remaining": remaining}


_STRONGEST_ORDER: tuple[str, ...] = (
    "COMPONENT",
    "PLUGIN",
    "PRODUCT",
    "VERSION",
    "TECHNOLOGY",
    "PARAMETER",
    "PATH",
    "VULNERABILITY_TYPE",
)

_EXPECTED_TYPES: tuple[tuple[str, str], ...] = (
    ("PRODUCT", "cve_products"),
    ("COMPONENT", "cve_components"),
    ("PLUGIN", "cve_plugins"),
    ("VERSION", "cve_versions"),
    ("PARAMETER", "cve_parameters"),
    ("PATH", "cve_paths"),
    ("TECHNOLOGY", "cve_technologies"),
)


def _asset_state(confidence: str, types: set[str]) -> str:
    target_specific = {"PRODUCT", "COMPONENT", "PLUGIN", "VERSION"}
    if confidence == "HIGH" and (types & target_specific):
        return "CONFIRMED"
    if confidence == "MEDIUM" and (types & target_specific):
        return "SUPPORTED"
    if types:
        return "WEAK"
    return "UNKNOWN"


def _match_summary_text(types: set[str], state: str) -> str:
    if not types:
        return "No deterministic asset match."
    if state == "CONFIRMED":
        if "VERSION" in types and ({"COMPONENT", "PLUGIN"} & types):
            return "Exact component observed; version evidence available."
        return "Exact affected product/component observed."
    if {"COMPONENT", "PLUGIN"} & types:
        if "VERSION" in types:
            return "Exact component observed; version evidence available."
        return "Affected component observed, but asset version is unknown."
    if "PRODUCT" in types:
        return "Affected product observed; component not confirmed."
    if "VERSION" in types:
        return "Observed version satisfies the affected range; component not confirmed."
    if "TECHNOLOGY" in types:
        return "Technology match exists, but affected component is not observed."
    return "Only supporting evidence observed; no target-specific component."


def _research_status(state: str) -> str:
    if state == "CONFIRMED":
        return "SUFFICIENT FOR RESEARCH"
    if state == "SUPPORTED":
        return "PARTIALLY SUPPORTED"
    return "NOT YET SUFFICIENT"


def build_asset_cve_match(
    *,
    cve_id: str,
    program: str,
    match: MatchResult,
    confidence: str,
    asset_identifier: str = "",
    blocker_resolution: object = (),
    rule_version: str = RULE_VERSION,
) -> AssetCVEMatch:
    """Build one schema :class:`AssetCVEMatch` from a per-type result."""

    asset = str(asset_identifier or "").strip()
    if asset and not ASSET_ID_RE.match(asset):
        asset = ""
    return AssetCVEMatch(
        match_id=match_id_for(
            cve_id,
            program,
            match.match_type,
            match.normalized_value,
            asset,
            rule_version,
        ),
        cve_id=cve_id,
        program=program,
        asset_identifier=asset,
        match_type=match.match_type,
        confidence=confidence,
        confidence_score=confidence_score_for(confidence),
        matched_value=match.matched_value,
        source=match.source,
        evidence=list(match.evidence),
        reason=match.reason,
        blocker_resolution=list(blocker_resolution or ()),
        rule_version=rule_version,
        research_only=True,
    )


def build_match_summary(
    *,
    cve_id: str,
    program: str,
    matches: object,
    asset_identifier: str = "",
    blocker_codes: object = (),
    expected_types: object = (),
    version_state: str = "UNKNOWN",
    extra_evidence: object = (),
    rule_version: str = RULE_VERSION,
) -> dict:
    """Aggregate matches into the deterministic R30.1 summary projection.

    Returns ``strongest_match``, ``all_matches``, ``strongest_confidence``,
    ``resolved_blockers``, ``remaining_blockers`` and ``match_summary`` plus the
    additive section-13 fields. It never overwrites R17 records.
    """

    results = list(matches or ())
    confidence = calculate_match_confidence(results) if results else "NONE"
    blocker_result = resolve_blockers(blocker_codes, results)
    resolved_blockers = list(blocker_result["resolved"])
    remaining_blockers = list(blocker_result["remaining"])

    # Each row carries the aggregate confidence for this CVE<->program
    # relationship (deterministic); blocker_resolution only on rows that
    # actually contribute to resolving a blocker.
    schema_matches: list[AssetCVEMatch] = []
    for result in results:
        contributes = _contributes_to(result.match_type)
        row_resolution = [
            code for code in resolved_blockers if code in contributes
        ]
        schema_matches.append(
            build_asset_cve_match(
                cve_id=cve_id,
                program=program,
                match=result,
                confidence=confidence,
                asset_identifier=asset_identifier,
                blocker_resolution=row_resolution,
                rule_version=rule_version,
            )
        )

    types = {result.match_type for result in results}
    asset_match_state = _asset_state(confidence, types)
    strongest = next(
        (row for kind in _STRONGEST_ORDER
         for row in schema_matches if row.match_type == kind),
        None,
    )

    observed = [
        f"{row.match_type}: {row.matched_value}" for row in schema_matches
    ]
    missing = [
        kind for kind, key in _EXPECTED_TYPES
        if kind not in types and _has_values(expected_types, key)
    ]
    evidence: list[str] = []
    for item in extra_evidence or ():
        text = str(item or "").strip()
        if text and text not in evidence:
            evidence.append(text)
    for row in schema_matches:
        for item in row.evidence:
            if item not in evidence:
                evidence.append(item)

    matched_component = next(
        (row.matched_value for row in schema_matches
         if row.match_type in ("COMPONENT", "PLUGIN")),
        "",
    )
    matched_version = next(
        (row.matched_value for row in schema_matches
         if row.match_type == "VERSION"),
        "",
    )
    matched_parameter = next(
        (row.matched_value for row in schema_matches
         if row.match_type == "PARAMETER"),
        "",
    )

    return {
        "cve_id": cve_id,
        "program": program,
        "asset_identifier": asset_identifier,
        "strongest_match": strongest,
        "all_matches": schema_matches,
        "strongest_confidence": confidence,
        "asset_match_state": asset_match_state,
        "asset_match_confidence": (
            confidence if strongest is not None else "NONE"
        ),
        "strongest_match_type": (
            strongest.match_type if strongest is not None else ""
        ),
        "matched_component": matched_component,
        "matched_version": matched_version,
        "matched_parameter": matched_parameter,
        "resolved_blockers": resolved_blockers,
        "remaining_blockers": remaining_blockers,
        "observed": observed,
        "missing": missing,
        "evidence": evidence,
        "version_state": version_state,
        "match_summary": _match_summary_text(types, asset_match_state),
        "research_status": _research_status(asset_match_state),
        "rule_version": rule_version,
        "research_only": True,
    }


_STRONGEST_ORDER_INDEX = {
    kind: index for index, kind in enumerate(_STRONGEST_ORDER)
}


def _contributes_to(match_type: str) -> tuple[str, ...]:
    if match_type == "PRODUCT":
        return ("generic_technology_only",)
    if match_type == "COMPONENT":
        return ("generic_technology_only", "component_not_observed")
    if match_type == "PLUGIN":
        return ("plugin_not_observed",)
    if match_type == "VERSION":
        return ("version_unknown",)
    if match_type == "PARAMETER":
        return ("parameter_unknown",)
    return ()


def _has_values(expected_types: object, key: str) -> bool:
    if isinstance(expected_types, dict):
        values = expected_types.get(key) or ()
    else:
        values = ()
    if isinstance(values, (str, bytes)):
        values = [values]
    return any(str(item or "").strip() for item in values)


def _serialized_summary(summary: dict) -> dict:
    """Return the summary with match models serialized to plain dicts."""

    summary["all_matches"] = [
        match_projection(row) for row in summary.get("all_matches") or ()
    ]
    strongest = summary.get("strongest_match")
    if strongest is not None:
        summary["strongest_match"] = match_projection(strongest)
    return summary


def evaluate_inventory(
    *,
    cve_id: str,
    program: str,
    asset_identifier: str = "",
    cve_products: object = (),
    cve_components: object = (),
    cve_plugins: object = (),
    cve_technologies: object = (),
    cve_versions: object = (),
    cve_parameters: object = (),
    cve_paths: object = (),
    cve_vulnerability_types: object = (),
    observed_products: object = (),
    observed_components: object = (),
    observed_plugins: object = (),
    observed_technologies: object = (),
    observed_versions: object = (),
    observed_parameters: object = (),
    observed_paths: object = (),
    observed_categories: object = (),
    blocker_codes: object = (),
) -> dict:
    """Full deterministic CVE <-> program evaluation (one program)."""

    matches: list[MatchResult] = []
    for result in (
        match_product(cve_products, observed_products),
        match_component(cve_components, observed_components),
        match_plugin(cve_plugins, observed_plugins),
        match_technology(cve_technologies, observed_technologies),
        match_version(cve_versions, observed_versions),
        match_parameter(cve_parameters, observed_parameters),
        match_path(cve_paths, observed_paths),
        match_vulnerability_type(cve_vulnerability_types, observed_categories),
    ):
        if result is not None:
            matches.append(result)
    matches.sort(key=lambda item: (_STRONGEST_ORDER_INDEX.get(
        item.match_type, len(_STRONGEST_ORDER)), item.normalized_value))

    version_eval = evaluate_version(cve_versions, observed_versions)
    expected = {
        "cve_products": cve_products,
        "cve_components": cve_components,
        "cve_plugins": cve_plugins,
        "cve_versions": cve_versions,
        "cve_parameters": cve_parameters,
        "cve_paths": cve_paths,
        "cve_technologies": cve_technologies,
    }
    return _serialized_summary(
        build_match_summary(
            cve_id=cve_id,
            program=program,
            matches=matches,
            asset_identifier=asset_identifier,
            blocker_codes=blocker_codes,
            expected_types=expected,
            version_state=version_eval["state"],
        )
    )


__all__ = [
    "RULE_VERSION",
    "ASSET_MATCH_STATES",
    "BLOCKER_CODES",
    "PRODUCT_ALIASES",
    "PLUGIN_ALIASES",
    "COMPONENT_ALIASES",
    "MatchResult",
    "MatchEvaluation",
    "normalize_product",
    "normalize_component",
    "normalize_plugin",
    "normalize_version",
    "normalize_parameter",
    "match_product",
    "match_component",
    "match_plugin",
    "match_technology",
    "match_version",
    "match_parameter",
    "match_path",
    "match_vulnerability_type",
    "evaluate_version",
    "calculate_match_confidence",
    "normalize_blocker_code",
    "resolve_blockers",
    "build_asset_cve_match",
    "build_match_summary",
    "evaluate_inventory",
]
