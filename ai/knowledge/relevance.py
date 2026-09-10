"""Deterministic asset/program relevance engine (Stage R17).

Answers, for a researched CVE, "does it appear relevant to assets/programs
Watch already knows, and why?" — using only persisted/local intelligence
(R12-R16 vulnerability intelligence plus read-only asset inventory snapshots).

This module is pure and offline: no HTTP, DNS, Nuclei, browser, subprocess,
active validation, exploit execution, production mutation, alerts, LLM, or
external network. It never emits "vulnerable"/"exploitable"/"verified"/
"confirmed": the result is RESEARCH RELEVANCE only.

Matching is deterministic and token-based (never arbitrary substring
matching), reusing the existing ``ai/correlator/technology.py`` normalizer so
there is no competing vocabulary. Asset inputs are plain records (dicts or
``AssetRecord``); the loader reads local program definitions and persisted
research metadata JSON, never the production database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path

from ai.correlator.technology import (
    GENERIC_TECHNOLOGIES,
    INVALID_VALUES,
    TECHNOLOGY_ALIASES,
    normalize,
)
from ai.knowledge.intelligence import IntelligenceEvidence

ASSET_RELEVANCE_RULE_VERSION = "r17-1"

# Explicit, transparent points (each signal awarded at most once per asset).
ASSET_RELEVANCE_WEIGHTS: dict[str, int] = {
    "product": 50,
    "plugin": 35,
    "technology": 20,
    "path": 20,
    "vulnerability_type": 10,
    "keyword": 5,
}
# (class, minimum score) evaluated highest-first; score > 0 and below the
# lowest threshold is LOW.
ASSET_RELEVANCE_THRESHOLDS: tuple[tuple[str, int], ...] = (
    ("HIGH", 70),
    ("MEDIUM", 40),
)
ASSET_RELEVANCE_MAX_SCORE = 100
ASSET_RELEVANCE_MIN_SCORE = 0

_MAX_TERM_CHARS = 200
_MAX_ITEMS = 256
_MAX_EVIDENCE = 25

# Tokens too generic to support a weak-overlap signal on their own (e.g.
# "image" must not match every image-related product). Stronger signals
# (product/plugin/technology/path) are unaffected by this list.
_WEAK_STOPWORDS = frozenset(
    {
        "www", "com", "net", "org", "http", "https", "html", "htm",
        "index", "the", "and", "for", "with", "from", "app", "web", "api",
        "plugin", "plugins", "module", "modules", "system", "systems",
        "server", "service", "services", "component", "components",
        "wordpress",  # generic as a weak keyword; handled by the tech signal
        "image", "images", "file", "files", "data", "user", "users",
        "page", "pages", "list", "view", "core", "main", "test", "tests",
        "default", "public", "private", "static", "asset", "assets",
        "upload", "uploads", "media", "content", "version", "update",
        "admin", "login", "search",
    }
)
_GENERIC_TOKENS = frozenset(
    token for value in GENERIC_TECHNOLOGIES for token in value.split()
)


def _is_generic(value: str) -> bool:
    return value in GENERIC_TECHNOLOGIES


def _valid(value: str | None) -> bool:
    return bool(value) and value not in INVALID_VALUES


def _normalize_term(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return normalize(text[:_MAX_TERM_CHARS])


def _bounded_list(values: object) -> list[str]:
    if values is None:
        return []
    items = values if isinstance(values, (list, tuple, set)) else [values]
    out: list[str] = []
    for item in items:
        text = _normalize_term(item)
        if text and _valid(text) and text not in out:
            out.append(text)
        if len(out) >= _MAX_ITEMS:
            break
    return out


def _tokens(values: list[str]) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        tokens.update(value.split())
    return tokens


def _weak_tokens(values: list[str]) -> set[str]:
    return {
        token
        for value in values
        for token in value.split()
        if len(token) >= 4
        and token not in _WEAK_STOPWORDS
        and token not in _GENERIC_TOKENS
    }


@dataclass(frozen=True)
class AssetRecord:
    """One read-only known asset (program + asset + observed inventory)."""

    program: str = ""
    asset: str = ""
    technologies: tuple[str, ...] = ()
    components: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    products: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict) -> "AssetRecord":
        return cls(
            program=str(value.get("program") or value.get("program_name") or ""),
            asset=str(value.get("asset") or value.get("subdomain") or ""),
            technologies=tuple(value.get("technologies") or ()),
            components=tuple(value.get("components") or ()),
            paths=tuple(value.get("paths") or ()),
            products=tuple(value.get("products") or ()),
            scopes=tuple(value.get("scopes") or ()),
        )


@dataclass
class AssetRelevance:
    """Deterministic, explainable research-relevance projection."""

    relevance: str = "UNKNOWN"
    score: int = 0
    reasons: list[str] = dataclass_field(default_factory=list)
    matched_assets: list[str] = dataclass_field(default_factory=list)
    matched_programs: list[str] = dataclass_field(default_factory=list)
    unknown_factors: list[str] = dataclass_field(default_factory=list)
    evidence: list[IntelligenceEvidence] = dataclass_field(default_factory=list)
    rule_version: str = ASSET_RELEVANCE_RULE_VERSION


@dataclass(frozen=True)
class _AssetMatch:
    asset: str
    program: str
    score: int
    reasons: tuple[str, ...]
    raw: AssetRecord


def _technology_aliases(value: str) -> set[str]:
    return set(TECHNOLOGY_ALIASES.get(value, {value}))


def _match_asset(
    asset: AssetRecord,
    *,
    v_products: list[str],
    v_components: list[str],
    v_technologies: list[str],
    v_types: list[str],
) -> _AssetMatch:
    a_technologies = _bounded_list(asset.technologies)
    a_components = _bounded_list(asset.components)
    a_products = _bounded_list(asset.products)
    a_paths = _bounded_list(asset.paths)
    a_identity = a_products + a_technologies + a_components

    reasons: list[str] = []
    score = 0

    # --- exact product match (+50) ---
    product_hit = next(
        (value for value in v_products if value in a_identity), None
    )
    if product_hit:
        score += ASSET_RELEVANCE_WEIGHTS["product"]
        reasons.append(f"exact product match: {product_hit}")

    # --- exact plugin/package/module or component match (+35) ---
    plugin_hit = None
    if not product_hit:
        for component in v_components:
            if component and component in a_components:
                plugin_hit = component
                break
        if not plugin_hit:
            for product in v_products:
                if product in a_components:
                    plugin_hit = product
                    break
    if plugin_hit:
        score += ASSET_RELEVANCE_WEIGHTS["plugin"]
        reasons.append(f"exact plugin/component match: {plugin_hit}")

    # --- technology/framework match (+20, generic excluded) ---
    tech_hit = None
    a_tech_set = set(a_technologies)
    for technology in v_technologies:
        if _is_generic(technology):
            continue
        if _technology_aliases(technology) & a_tech_set:
            tech_hit = technology
            break
    if tech_hit:
        score += ASSET_RELEVANCE_WEIGHTS["technology"]
        reasons.append(f"technology match: {tech_hit}")

    # --- component/path relationship (+20, token-subset only) ---
    path_hit = None
    a_path_tokens = [set(path.split()) for path in a_paths]
    for component in v_components:
        tokens = set(component.split())
        if len(tokens) < 2:
            continue
        if any(tokens.issubset(path_tokens) for path_tokens in a_path_tokens):
            path_hit = component
            break
    if path_hit:
        score += ASSET_RELEVANCE_WEIGHTS["path"]
        reasons.append(f"component/path match: {path_hit}")

    # --- vulnerability-type compatibility (+10 only on an existing match) ---
    if v_types and score > 0 and (a_paths or a_components):
        score += ASSET_RELEVANCE_WEIGHTS["vulnerability_type"]
        reasons.append(
            "vulnerability type: " + ", ".join(sorted(v_types))
        )

    # --- weak keyword overlap (+5, token equality, generic excluded) ---
    if not (product_hit or plugin_hit or tech_hit or path_hit):
        overlap = _weak_tokens(v_products + v_components) & _weak_tokens(
            a_technologies + a_components + a_products
        )
        if overlap:
            score += ASSET_RELEVANCE_WEIGHTS["keyword"]
            reasons.append(
                "keyword overlap: " + ", ".join(sorted(overlap)[:8])
            )

    score = max(
        ASSET_RELEVANCE_MIN_SCORE,
        min(ASSET_RELEVANCE_MAX_SCORE, score),
    )
    return _AssetMatch(
        asset=asset.asset.strip(),
        program=asset.program.strip(),
        score=score,
        reasons=tuple(reasons),
        raw=asset,
    )


def _asset_evidence(match: _AssetMatch) -> IntelligenceEvidence:
    return IntelligenceEvidence(
        field="asset.match",
        value=match.asset or match.program,
        source_artifact="local-asset-snapshot",
        source_url=None,
        source_type="asset",
        evidence=(
            (f"program={match.program} " if match.program else "")
            + "; ".join(match.reasons)
        )[:208],
        rule_id="asset-relevance-match",
        rule_version=ASSET_RELEVANCE_RULE_VERSION,
    )


def _relevance_evidence(
    evidence: object, matched: list[_AssetMatch]
) -> list[IntelligenceEvidence]:
    """Bounded references: matched assets + the vuln evidence behind them."""

    kept: list[IntelligenceEvidence] = []
    for match in matched[:_MAX_EVIDENCE]:
        kept.append(_asset_evidence(match))
    wanted = {"component", "vulnerability_type", "parameter", "cwe"}
    vuln_records = sorted(
        (
            item
            for item in (evidence or [])
            if getattr(item, "field", "") in wanted
        ),
        key=lambda item: (
            getattr(item, "field", ""),
            getattr(item, "value", ""),
            getattr(item, "source_url", "") or "",
            getattr(item, "evidence", ""),
            getattr(item, "rule_id", ""),
        ),
    )
    for item in vuln_records[: _MAX_EVIDENCE]:
        kept.append(item)
    return kept


def assess_asset_relevance(
    *,
    products: object = (),
    technologies: object = (),
    components: object = (),
    parameters: object = (),
    vulnerability_types: object = (),
    cwes: object = (),
    assets: object = (),
    evidence: object = (),
) -> AssetRelevance:
    """Deterministically score a vulnerability profile against known assets.

    Pure, order-independent, idempotent. Unknown stays unknown; no signal
    means UNKNOWN when no asset intelligence exists and NONE when assets exist
    but nothing matched. Generic-only technology overlap never yields HIGH.
    """

    v_products = [
        value
        for value in _bounded_list(products)
        if not _is_generic(value)
    ]
    v_components = _bounded_list(components)
    v_technologies = _bounded_list(technologies)
    # Path-like components are also usable for path matching.
    v_types = sorted(
        {
            _normalize_term(value)
            for value in _bounded_list(vulnerability_types)
            if value
        }
    )

    records = [
        record
        if isinstance(record, AssetRecord)
        else AssetRecord.from_dict(record)
        for record in (assets or [])
        if isinstance(record, (AssetRecord, dict))
    ]
    records = [record for record in records if record.asset or record.program]
    records = records[:_MAX_ITEMS]

    if not records:
        return AssetRelevance(
            relevance="UNKNOWN",
            score=0,
            unknown_factors=["asset intelligence unavailable"],
        )

    if not (v_products or v_components or v_technologies or v_types):
        return AssetRelevance(
            relevance="UNKNOWN",
            score=0,
            unknown_factors=["vulnerability intelligence unavailable"],
        )

    matches = [
        _match_asset(
            record,
            v_products=v_products,
            v_components=v_components,
            v_technologies=v_technologies,
            v_types=v_types,
        )
        for record in records
    ]
    scored = [match for match in matches if match.score > 0]
    scored.sort(key=lambda item: (-item.score, item.asset, item.program))

    unknown_factors: list[str] = []
    if all(not record.technologies for record in records):
        unknown_factors.append("asset technology not observed")
    if all(
        not record.components and not record.paths for record in records
    ):
        unknown_factors.append("asset component/path not observed")
    if scored and not any(record.components for record in records):
        unknown_factors.append("asset plugin/component not observed")

    if not scored:
        only_technology_profile = (
            bool(v_technologies) and not v_products and not v_components
        )
        if only_technology_profile and all(
            not record.technologies for record in records
        ):
            # The one signal that could match (technology) was never observed
            # on any asset, so relevance is genuinely undetermined.
            return AssetRelevance(
                relevance="UNKNOWN",
                score=0,
                unknown_factors=["asset technology not observed"],
            )
        return AssetRelevance(
            relevance="NONE",
            score=0,
            reasons=[],
            matched_assets=[],
            matched_programs=[],
            unknown_factors=unknown_factors,
            evidence=[],
        )

    best = scored[0]
    relevance = "LOW"
    for name, threshold in ASSET_RELEVANCE_THRESHOLDS:
        if best.score >= threshold:
            relevance = name
            break

    matched_assets = sorted({match.asset for match in scored if match.asset})
    matched_programs = sorted(
        {match.program for match in scored if match.program}
    )
    return AssetRelevance(
        relevance=relevance,
        score=best.score,
        reasons=list(best.reasons),
        matched_assets=matched_assets,
        matched_programs=matched_programs,
        unknown_factors=unknown_factors,
        evidence=_relevance_evidence(evidence, scored),
    )


def asset_relevance_projection(**kwargs) -> dict[str, object]:
    """Serialize the asset-relevance projection for the knowledge schema."""

    summary = assess_asset_relevance(**kwargs)
    return {
        "relevance": summary.relevance,
        "score": summary.score,
        "reasons": list(summary.reasons),
        "matched_assets": list(summary.matched_assets),
        "matched_programs": list(summary.matched_programs),
        "unknown_factors": list(summary.unknown_factors),
        "evidence": [
            {
                "field": item.field,
                "value": item.value,
                "source_artifact": item.source_artifact,
                "source_url": item.source_url,
                "source_type": item.source_type,
                "evidence": item.evidence,
                "rule_id": item.rule_id,
                "rule_version": item.rule_version,
            }
            for item in summary.evidence
        ],
        "rule_version": summary.rule_version,
    }


# ===========================================================================
# Read-only local asset snapshot loaders (no database, no network).
# ===========================================================================


def load_program_definitions(programs_dir: str | Path) -> list[dict]:
    """Read local program scope definitions (``programs/*.json``)."""

    root = Path(programs_dir)
    if not root.is_dir():
        return []
    programs: list[dict] = []
    for path in sorted(root.glob("*.json")) + sorted(root.glob("*.json.*")):
        if path.suffix not in (".json",) and not path.name.endswith("._json"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        program = str(payload.get("program_name") or "").strip()
        scopes = [
            str(scope).strip()
            for scope in (payload.get("scopes") or [])
            if str(scope).strip()
        ]
        ooscopes = [
            str(scope).strip()
            for scope in (payload.get("ooscopes") or [])
            if str(scope).strip()
        ]
        if program or scopes:
            programs.append(
                {
                    "program": program,
                    "scopes": scopes,
                    "ooscopes": ooscopes,
                }
            )
    return programs


def _infer_program(asset: str, programs: list[dict]) -> str:
    best = ""
    best_len = -1
    lowered = asset.lower()
    for entry in programs:
        for scope in entry.get("scopes", []):
            scope_l = scope.lower()
            if lowered == scope_l or lowered.endswith("." + scope_l):
                if len(scope_l) > best_len:
                    best_len = len(scope_l)
                    best = entry.get("program", "")
    return best


def assets_from_programs(programs: list[dict]) -> list[AssetRecord]:
    """One asset record per declared scope (no technology invented)."""

    records: list[AssetRecord] = []
    for entry in programs:
        program = entry.get("program", "")
        scopes = tuple(entry.get("scopes", []))
        for scope in scopes:
            records.append(
                AssetRecord(program=program, asset=scope, scopes=scopes)
            )
    return records


def assets_from_research_metadata(
    payload: dict, programs: list[dict]
) -> list[AssetRecord]:
    """Assets + technologies already correlated in persisted research metadata.

    The technologies are the metadata's own recorded list (not invented here);
    ``source`` remains the research artifact.
    """

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return []
    technologies = tuple(
        str(item).strip()
        for item in (metadata.get("technologies") or [])
        if str(item).strip()
    )
    records: list[AssetRecord] = []
    for asset in metadata.get("assets") or []:
        asset_text = str(asset).strip()
        if not asset_text:
            continue
        records.append(
            AssetRecord(
                program=_infer_program(asset_text, programs),
                asset=asset_text,
                technologies=technologies,
            )
        )
    return records


def load_asset_snapshot(path: str | Path) -> list[AssetRecord]:
    """Read an explicit local asset snapshot JSON (documented shape)."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        raw = payload.get("assets") or []
    elif isinstance(payload, list):
        raw = payload
    else:
        return []
    return [
        AssetRecord.from_dict(item)
        for item in raw
        if isinstance(item, dict)
    ]


def derive_technology_hints(product_strings: object = ()) -> list[str]:
    """Deterministic technology hints from explicit product wording.

    Only known technology alias keys whose tokens are all present in a product
    string are returned (e.g. "WP Responsive Images (WordPress plugin)" ->
    "wordpress"). No inference beyond literal token containment.
    """

    hints: list[str] = []
    for value in _bounded_list(product_strings):
        tokens = set(value.split())
        for alias_key in TECHNOLOGY_ALIASES:
            if (
                alias_key not in hints
                and set(alias_key.split()).issubset(tokens)
            ):
                hints.append(alias_key)
    return hints
