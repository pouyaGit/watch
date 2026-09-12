"""Stage R31.9 deterministic evidence quality and confidence gate (pure).

Evaluates how strong, complete, scoped and internally consistent the evidence
supporting one Asset <-> CVE research candidate is. It is **additive audit
metadata only**: R30.1 remains authoritative for match/confidence semantics,
R31.5 for provenance/scope, R31.6 for identity, R31.7 for versions and R31.8
for path/parameter relevance. Nothing here is overwritten or reinterpreted.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no persistence, no execution.
- Deterministic: closed vocabularies, documented first-match rules, bounded
  output; repeated evaluation yields byte-identical results.
- No probability: strength is a closed classification, never a numeric
  "probability of vulnerability".
- Supporting evidence can never override authoritative negative evidence
  (version NO_MATCH, component conflicts, scope restrictions).
- Privacy: the engine emits only classifications, counts, blocker codes and
  static reason strings; it never copies raw paths, parameters or query
  values from the evidence it consumes.
"""

from __future__ import annotations

# Stage R31.9 evidence-quality rule version (additive; all previous stage
# rule versions are unchanged).
EVIDENCE_QUALITY_RULE_VERSION = "r31-9"
RULE_VERSION = EVIDENCE_QUALITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

LEVEL_HIGH = "HIGH"
LEVEL_MEDIUM = "MEDIUM"
LEVEL_LOW = "LOW"
LEVEL_INSUFFICIENT = "INSUFFICIENT"

EVIDENCE_QUALITY_LEVELS: tuple[str, ...] = (
    LEVEL_HIGH,
    LEVEL_MEDIUM,
    LEVEL_LOW,
    LEVEL_INSUFFICIENT,
)

STATE_STRONG = "STRONG"
STATE_SUPPORTING = "SUPPORTING"
STATE_WEAK = "WEAK"
STATE_UNKNOWN = "UNKNOWN"
STATE_CONFLICTING = "CONFLICTING"

EVIDENCE_STATES: tuple[str, ...] = (
    STATE_STRONG,
    STATE_SUPPORTING,
    STATE_WEAK,
    STATE_UNKNOWN,
    STATE_CONFLICTING,
)

STRENGTH_STRONG = "STRONG"
STRENGTH_SUPPORTING = "SUPPORTING"
STRENGTH_WEAK = "WEAK"
STRENGTH_NONE = "NONE"

EVIDENCE_STRENGTHS: tuple[str, ...] = (
    STRENGTH_STRONG,
    STRENGTH_SUPPORTING,
    STRENGTH_WEAK,
    STRENGTH_NONE,
)

CONSISTENCY_CONSISTENT = "CONSISTENT"
CONSISTENCY_CONFLICTING = "CONFLICTING"
CONSISTENCY_UNKNOWN = "UNKNOWN"

EVIDENCE_CONSISTENCIES: tuple[str, ...] = (
    CONSISTENCY_CONSISTENT,
    CONSISTENCY_CONFLICTING,
    CONSISTENCY_UNKNOWN,
)

COMPLETENESS_EVALUATED = "EVALUATED"
COMPLETENESS_NOT_AVAILABLE = "NOT_AVAILABLE"
COMPLETENESS_NOT_APPLICABLE = "NOT_APPLICABLE"
COMPLETENESS_UNKNOWN = "UNKNOWN"

EVIDENCE_COMPLETENESS: tuple[str, ...] = (
    COMPLETENESS_EVALUATED,
    COMPLETENESS_NOT_AVAILABLE,
    COMPLETENESS_NOT_APPLICABLE,
    COMPLETENESS_UNKNOWN,
)

# Dimension names (closed, ordered).
DIM_ASSET_IDENTITY = "ASSET_IDENTITY"
DIM_COMPONENT_IDENTITY = "COMPONENT_IDENTITY"
DIM_COMPONENT_PROVENANCE = "COMPONENT_PROVENANCE"
DIM_VERSION_COMPATIBILITY = "VERSION_COMPATIBILITY"
DIM_VERSION_EVIDENCE = "VERSION_EVIDENCE"
DIM_PATH_RELEVANCE = "PATH_RELEVANCE"
DIM_PARAMETER_RELEVANCE = "PARAMETER_RELEVANCE"
DIM_METHOD_RELEVANCE = "METHOD_RELEVANCE"
DIM_SCOPE = "SCOPE"
DIM_PROVENANCE = "PROVENANCE"
DIM_AMBIGUITY = "AMBIGUITY"
DIM_CONFLICTS = "CONFLICTS"

DIMENSION_ORDER: tuple[str, ...] = (
    DIM_ASSET_IDENTITY,
    DIM_COMPONENT_IDENTITY,
    DIM_COMPONENT_PROVENANCE,
    DIM_VERSION_COMPATIBILITY,
    DIM_VERSION_EVIDENCE,
    DIM_PATH_RELEVANCE,
    DIM_PARAMETER_RELEVANCE,
    DIM_METHOD_RELEVANCE,
    DIM_SCOPE,
    DIM_PROVENANCE,
    DIM_AMBIGUITY,
    DIM_CONFLICTS,
)

# Dimensions whose completeness contributes to the aggregate completeness
# representation (meta dimensions such as provenance/scope/conflicts are
# classifications, not missing-information signals).
COMPLETENESS_DIMENSIONS: tuple[str, ...] = (
    DIM_ASSET_IDENTITY,
    DIM_COMPONENT_IDENTITY,
    DIM_VERSION_COMPATIBILITY,
    DIM_VERSION_EVIDENCE,
    DIM_PATH_RELEVANCE,
    DIM_PARAMETER_RELEVANCE,
    DIM_METHOD_RELEVANCE,
)

# Deterministic bounds.
MAX_GAPS = 16
MAX_REASONS = 16
MAX_CONFLICTS = 8
MAX_VALUE_LEN = 256

_TARGET_TYPES: frozenset[str] = frozenset(
    {"PRODUCT", "COMPONENT", "PLUGIN"}
)
_SUPPORTING_TYPES: frozenset[str] = frozenset(
    {"TECHNOLOGY", "PARAMETER", "PATH", "VULNERABILITY_TYPE"}
)
_AMBIGUOUS_TYPES: frozenset[str] = frozenset({"AMBIGUOUS", "UNKNOWN"})


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _version_rows(version_normalization: object) -> list:
    if not isinstance(version_normalization, dict):
        return []
    rows = version_normalization.get("rows")
    return rows if isinstance(rows, list) else []


def _path_parameter_rows(path_parameter_relevance: object) -> list:
    if not isinstance(path_parameter_relevance, dict):
        return []
    rows = path_parameter_relevance.get("evidence")
    return rows if isinstance(rows, list) else []


def _path_parameter_summary(path_parameter_relevance: object) -> dict:
    if not isinstance(path_parameter_relevance, dict):
        return {}
    summary = path_parameter_relevance.get("summary")
    return summary if isinstance(summary, dict) else {}


def _dimension(
    name: str,
    state: str,
    reason: str,
    *,
    completeness: str = COMPLETENESS_NOT_APPLICABLE,
    supporting: bool = False,
) -> dict:
    return {
        "name": name,
        "state": state,
        "reason": reason[:MAX_VALUE_LEN],
        "source": f"r31-9:{name}",
        "authoritative": not supporting,
        "supporting": supporting,
        "completeness": completeness,
    }


# ---------------------------------------------------------------------------
# Dimension evaluation
# ---------------------------------------------------------------------------


def _asset_identity(
    strongest_match_type: str,
    strongest_confidence: str,
) -> dict:
    kind = _upper(strongest_match_type)
    confidence = _upper(strongest_confidence or "NONE")
    if kind in _TARGET_TYPES:
        return _dimension(
            DIM_ASSET_IDENTITY,
            STATE_STRONG,
            "asset identity is an explicit product/component/plugin match",
            completeness=COMPLETENESS_EVALUATED,
        )
    if kind == "TECHNOLOGY":
        if confidence in ("HIGH", "MEDIUM"):
            return _dimension(
                DIM_ASSET_IDENTITY,
                STATE_SUPPORTING,
                "technology identity is present but not component-specific",
                completeness=COMPLETENESS_EVALUATED,
                supporting=True,
            )
        return _dimension(
            DIM_ASSET_IDENTITY,
            STATE_WEAK,
            "only generic technology identity is present",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if kind in _SUPPORTING_TYPES:
        return _dimension(
            DIM_ASSET_IDENTITY,
            STATE_WEAK,
            "only supporting (path/parameter/type) evidence is present",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    return _dimension(
        DIM_ASSET_IDENTITY,
        STATE_UNKNOWN,
        "no asset identity evidence is available",
        completeness=COMPLETENESS_NOT_AVAILABLE,
    )


def _component_identity(
    strongest_match_type: str,
    matched_component: str,
    provenance: str,
) -> dict:
    kind = _upper(strongest_match_type)
    component = _text(matched_component)
    if not component and kind not in ("COMPONENT", "PLUGIN", "PRODUCT"):
        return _dimension(
            DIM_COMPONENT_IDENTITY,
            STATE_UNKNOWN,
            "no observed component/plugin identity is available",
            completeness=COMPLETENESS_NOT_AVAILABLE,
        )
    if provenance == "EXPLICIT":
        return _dimension(
            DIM_COMPONENT_IDENTITY,
            STATE_STRONG,
            "component/plugin identity comes from explicit evidence",
            completeness=COMPLETENESS_EVALUATED,
        )
    if provenance == "MIXED":
        return _dimension(
            DIM_COMPONENT_IDENTITY,
            STATE_SUPPORTING,
            "component/plugin identity is backed by explicit and inferred"
            " evidence",
            completeness=COMPLETENESS_EVALUATED,
        )
    return _dimension(
        DIM_COMPONENT_IDENTITY,
        STATE_SUPPORTING,
        "component/plugin identity is inferred from anchored path rules",
        completeness=COMPLETENESS_EVALUATED,
    )


def _component_provenance(provenance: str) -> dict:
    if provenance == "EXPLICIT":
        return _dimension(
            DIM_COMPONENT_PROVENANCE,
            STATE_STRONG,
            "component evidence is explicit",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if provenance == "MIXED":
        return _dimension(
            DIM_COMPONENT_PROVENANCE,
            STATE_SUPPORTING,
            "component evidence is explicit and inferred (mixed)",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if provenance == "INFERRED":
        return _dimension(
            DIM_COMPONENT_PROVENANCE,
            STATE_WEAK,
            "component evidence is inferred only",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    return _dimension(
        DIM_COMPONENT_PROVENANCE,
        STATE_UNKNOWN,
        "component provenance is unavailable",
        completeness=COMPLETENESS_UNKNOWN,
        supporting=True,
    )


def _version_compatibility(
    version_state: str,
    association_state: str,
    rows: list,
    cve_versions: list,
    observed_versions: list,
) -> tuple[dict, bool]:
    """Return (dimension, authoritative_negative).

    Consumes R30.1 ``version_state`` and the R30.3 association state. R30.3
    deliberately withholds non-matching observed versions from the engine, so
    ``VERSION_OBSERVED_NO_MATCH`` is the authoritative negative signal when
    the engine state itself is UNKNOWN.
    """

    state = _upper(version_state or "UNKNOWN")
    association = _upper(association_state or "")
    evaluated = any(
        _upper(row.get("comparison")) in ("MATCH", "NO_MATCH")
        for row in rows
        if isinstance(row, dict)
    )
    if (
        state == "NO_MATCH"
        or association == "VERSION_OBSERVED_NO_MATCH"
    ):
        return _dimension(
            DIM_VERSION_COMPATIBILITY,
            STATE_CONFLICTING,
            "observed version does not satisfy the affected range",
            completeness=COMPLETENESS_EVALUATED,
        ), True
    if (
        state == "MATCH"
        or association == "VERSION_MATCH_WITHIN_SAME_FAMILY"
    ):
        return _dimension(
            DIM_VERSION_COMPATIBILITY,
            STATE_STRONG,
            "observed version satisfies the affected range",
            completeness=COMPLETENESS_EVALUATED,
        ), False
    if association == "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION":
        return _dimension(
            DIM_VERSION_COMPATIBILITY,
            STATE_SUPPORTING,
            "observed version satisfies the range at family level only",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        ), False
    if not cve_versions and not rows and not association:
        return _dimension(
            DIM_VERSION_COMPATIBILITY,
            STATE_UNKNOWN,
            "research has no affected-version information",
            completeness=COMPLETENESS_NOT_AVAILABLE,
        ), False
    if not observed_versions and association in (
        "",
        "NO_VERSION_OBSERVATION",
        "COMPONENT_ASSOCIATED_VERSION_UNKNOWN",
        "VERSION_ASSOCIATION_UNKNOWN",
    ):
        return _dimension(
            DIM_VERSION_COMPATIBILITY,
            STATE_UNKNOWN,
            "no comparable observed version is available",
            completeness=COMPLETENESS_NOT_AVAILABLE,
        ), False
    if evaluated:
        return _dimension(
            DIM_VERSION_COMPATIBILITY,
            STATE_WEAK,
            "version comparison is inconclusive",
            completeness=COMPLETENESS_EVALUATED,
        ), False
    return _dimension(
        DIM_VERSION_COMPATIBILITY,
        STATE_UNKNOWN,
        "version comparison is indeterminate",
        completeness=COMPLETENESS_UNKNOWN,
    ), False


def _version_evidence(
    rows: list,
    cve_versions: list,
    observed: list,
    association_state: str,
) -> dict:
    association = _upper(association_state or "")
    if association == "VERSION_OBSERVED_NO_MATCH":
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_WEAK,
            "observed version was evaluated and does not match",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if association == "VERSION_MATCH_WITHOUT_COMPONENT_ASSOCIATION":
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_SUPPORTING,
            "family-level version evidence matches without component"
            " association",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if association == "VERSION_MATCH_WITHIN_SAME_FAMILY":
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_STRONG,
            "component-associated version evidence matches",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if not cve_versions:
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_UNKNOWN,
            "research has no structured version evidence",
            completeness=COMPLETENESS_NOT_AVAILABLE,
            supporting=True,
        )
    if not observed:
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_UNKNOWN,
            "no observed version evidence is available",
            completeness=COMPLETENESS_NOT_AVAILABLE,
            supporting=True,
        )
    matches = [
        row for row in rows
        if isinstance(row, dict)
        and _upper(row.get("comparison")) == "MATCH"
    ]
    if matches:
        exact = any(
            _upper(row.get("cve_kind")) == "EXACT"
            and _upper(row.get("cve_evidence_class")) == "EXACT_OBSERVED"
            for row in matches
        )
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_STRONG if exact else STATE_SUPPORTING,
            "observed version matches an affected version"
            + (" (exact)" if exact else " (normalized/range)"),
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    no_match = any(
        _upper(row.get("comparison")) == "NO_MATCH" for row in rows
        if isinstance(row, dict)
    )
    if no_match:
        return _dimension(
            DIM_VERSION_EVIDENCE,
            STATE_WEAK,
            "observed version was evaluated and does not match",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    return _dimension(
        DIM_VERSION_EVIDENCE,
        STATE_UNKNOWN,
        "version evidence could not be evaluated",
        completeness=COMPLETENESS_UNKNOWN,
        supporting=True,
    )


def _support_dimension(
    name: str,
    rows: list,
    matching_type_names: tuple[str, ...],
    available_label: str,
) -> dict:
    typed = [
        row for row in rows
        if isinstance(row, dict)
        and _upper(row.get("evidence_type")) in matching_type_names
    ]
    if not typed:
        return _dimension(
            name,
            STATE_UNKNOWN,
            f"research has no structured {available_label} evidence",
            completeness=COMPLETENESS_NOT_AVAILABLE,
            supporting=True,
        )
    matches = [
        row for row in typed if _upper(row.get("result")) == "MATCH"
    ]
    if matches and all(row.get("component_scoped") for row in matches):
        return _dimension(
            name,
            STATE_SUPPORTING,
            f"component-scoped {available_label} evidence matches",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if matches:
        return _dimension(
            name,
            STATE_WEAK,
            f"{available_label} evidence matches globally, not"
            " component-scoped",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    evaluated = any(
        _upper(row.get("result")) in ("NO_MATCH", "INDETERMINATE")
        for row in typed
    )
    return _dimension(
        name,
        STATE_WEAK if evaluated else STATE_UNKNOWN,
        f"{available_label} evidence was evaluated without a match",
        completeness=(
            COMPLETENESS_EVALUATED if evaluated
            else COMPLETENESS_UNKNOWN
        ),
        supporting=True,
    )


def _method_relevance(path_parameter_relevance: object) -> dict:
    summary = _path_parameter_summary(path_parameter_relevance)
    method = summary.get("method")
    method = method if isinstance(method, dict) else {}
    evidence_type = _upper(method.get("evidence_type"))
    result = _upper(method.get("result"))
    if not method or evidence_type == "NO_EVIDENCE":
        return _dimension(
            DIM_METHOD_RELEVANCE,
            STATE_UNKNOWN,
            "research has no structured HTTP method evidence",
            completeness=COMPLETENESS_NOT_AVAILABLE,
            supporting=True,
        )
    if result == "MATCH":
        return _dimension(
            DIM_METHOD_RELEVANCE,
            STATE_SUPPORTING,
            "research HTTP method was observed",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if result == "NO_MATCH":
        return _dimension(
            DIM_METHOD_RELEVANCE,
            STATE_WEAK,
            "research HTTP method was not observed",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    return _dimension(
        DIM_METHOD_RELEVANCE,
        STATE_UNKNOWN,
        "HTTP method evidence is indeterminate",
        completeness=COMPLETENESS_UNKNOWN,
        supporting=True,
    )


def _scope_dimension(support_scope: str) -> dict:
    scope = _upper(support_scope or "NONE")
    if scope == "COMPONENT_SCOPED":
        state, reason = (
            STATE_STRONG,
            "inferred component evidence has component-scoped support",
        )
    elif scope == "GLOBAL":
        state, reason = (
            STATE_SUPPORTING,
            "support evidence is global to the asset",
        )
    else:
        state, reason = (
            STATE_WEAK,
            "no component-scoped support is available",
        )
    return _dimension(
        DIM_SCOPE,
        state,
        reason,
        completeness=COMPLETENESS_EVALUATED,
        supporting=True,
    )


def _provenance_dimension(provenance: str) -> dict:
    if provenance == "EXPLICIT":
        return _dimension(
            DIM_PROVENANCE,
            STATE_STRONG,
            "component evidence is explicit",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if provenance == "MIXED":
        return _dimension(
            DIM_PROVENANCE,
            STATE_SUPPORTING,
            "component evidence is mixed (explicit wins)",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    if provenance == "INFERRED":
        return _dimension(
            DIM_PROVENANCE,
            STATE_WEAK,
            "component evidence is inferred only",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        )
    return _dimension(
        DIM_PROVENANCE,
        STATE_UNKNOWN,
        "component evidence provenance is unavailable",
        completeness=COMPLETENESS_UNKNOWN,
        supporting=True,
    )


def _ambiguity_dimension(rows: list, version_rows: list) -> tuple[dict, int]:
    count = sum(
        1 for row in rows
        if isinstance(row, dict)
        and _upper(row.get("evidence_type")) in _AMBIGUOUS_TYPES
    )
    count += sum(
        1 for row in version_rows
        if isinstance(row, dict)
        and _upper(row.get("cve_kind")) == "UNKNOWN"
    )
    if count == 0:
        return _dimension(
            DIM_AMBIGUITY,
            STATE_STRONG,
            "no ambiguous evidence was encountered",
            completeness=COMPLETENESS_EVALUATED,
            supporting=True,
        ), 0
    return _dimension(
        DIM_AMBIGUITY,
        STATE_WEAK,
        f"{count} ambiguous or unsupported evidence row(s) preserved",
        completeness=COMPLETENESS_EVALUATED,
        supporting=True,
    ), count


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------


def _conflicts(
    *,
    component_conflict: bool,
    version_state: str,
    version_rows: list,
    provenance: str,
    support_scope: str,
    path_match: bool,
    parameter_match: bool,
) -> list[dict]:
    records: list[dict] = []
    if component_conflict:
        records.append(
            {
                "kind": "component",
                "severity": "authoritative",
                "reason": "explicit and inferred component evidence match"
                " different identities",
            }
        )
    state = _upper(version_state)
    rows_match = any(
        _upper(row.get("comparison")) == "MATCH" for row in version_rows
        if isinstance(row, dict)
    )
    rows_no_match = any(
        _upper(row.get("comparison")) == "NO_MATCH"
        for row in version_rows
        if isinstance(row, dict)
    )
    if state == "NO_MATCH" and rows_match:
        records.append(
            {
                "kind": "version",
                "severity": "authoritative",
                "reason": "engine version state says NO_MATCH while"
                " normalized evidence contains a MATCH",
            }
        )
    elif (
        state == "MATCH"
        and version_rows
        and not rows_match
        and rows_no_match
    ):
        records.append(
            {
                "kind": "version",
                "severity": "authoritative",
                "reason": "engine version state says MATCH while"
                " normalized evidence contains only NO_MATCH",
            }
        )
    if (
        provenance == "INFERRED"
        and _upper(support_scope or "NONE") != "COMPONENT_SCOPED"
        and (path_match or parameter_match)
    ):
        records.append(
            {
                "kind": "scope",
                "severity": "supporting",
                "reason": "inferred component identity has only global"
                " supporting evidence",
            }
        )
    return records[:MAX_CONFLICTS]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_evidence_quality(
    *,
    strongest_match_type: object = "",
    strongest_confidence: object = "",
    asset_match_state: object = "",
    matched_component: object = "",
    matched_version: object = "",
    matched_parameter: object = "",
    version_state: object = "UNKNOWN",
    version_association_state: object = "",
    remaining_blockers: object = (),
    resolved_blockers: object = (),
    evidence_provenance: object = "EXPLICIT",
    support_scope: object = "GLOBAL",
    withheld_support: object = (),
    version_normalization: object = None,
    path_parameter_relevance: object = None,
    identity_resolution: object = (),
    component_conflict: bool = False,
) -> dict:
    """Deterministic additive evidence-quality classification.

    The result never overwrites R30.1/R31.x fields and never exposes a
    numeric probability.
    """

    match_type = _upper(strongest_match_type)
    confidence = _upper(strongest_confidence or "NONE")
    state = _upper(asset_match_state or "UNKNOWN")
    provenance = _upper(evidence_provenance or "EXPLICIT")
    scope = _upper(support_scope or "NONE")
    version = _upper(version_state or "UNKNOWN")
    association = _upper(version_association_state or "")
    component = _text(matched_component)
    version_data = (
        version_normalization
        if isinstance(version_normalization, dict)
        else {}
    )
    version_rows = _version_rows(version_normalization)
    cve_versions = list(version_data.get("cve_versions") or ())
    observed_versions = list(version_data.get("observed_versions") or ())
    pp_rows = _path_parameter_rows(path_parameter_relevance)
    pp_summary = _path_parameter_summary(path_parameter_relevance)
    path_match = bool(pp_summary.get("path_match"))
    parameter_match = bool(pp_summary.get("parameter_match"))
    identity_rows = [
        row for row in (identity_resolution or ()) if isinstance(row, dict)
    ]

    version_dim, authoritative_negative = _version_compatibility(
        version, association, version_rows, cve_versions, observed_versions
    )
    ambiguity_dim, ambiguity_count = _ambiguity_dimension(
        pp_rows, version_rows
    )
    conflicts = _conflicts(
        component_conflict=bool(component_conflict),
        version_state=version,
        version_rows=version_rows,
        provenance=provenance,
        support_scope=scope,
        path_match=path_match,
        parameter_match=parameter_match,
    )
    has_authoritative_conflict = any(
        record["severity"] == "authoritative" for record in conflicts
    )
    has_scope_conflict = any(
        record["kind"] == "scope" for record in conflicts
    )

    dimensions = {
        DIM_ASSET_IDENTITY: _asset_identity(match_type, confidence),
        DIM_COMPONENT_IDENTITY: _component_identity(
            match_type, component, provenance
        ),
        DIM_COMPONENT_PROVENANCE: _component_provenance(provenance),
        DIM_VERSION_COMPATIBILITY: version_dim,
        DIM_VERSION_EVIDENCE: _version_evidence(
            version_rows, cve_versions, observed_versions, association
        ),
        DIM_PATH_RELEVANCE: _support_dimension(
            DIM_PATH_RELEVANCE,
            pp_rows,
            ("EXACT_PATH", "PATH_PREFIX", "PATH_PATTERN"),
            "path",
        ),
        DIM_PARAMETER_RELEVANCE: _support_dimension(
            DIM_PARAMETER_RELEVANCE,
            pp_rows,
            ("EXACT_PARAMETER", "PARAMETER_SET"),
            "parameter",
        ),
        DIM_METHOD_RELEVANCE: _method_relevance(
            path_parameter_relevance
        ),
        DIM_SCOPE: _scope_dimension(scope),
        DIM_PROVENANCE: _provenance_dimension(provenance),
        DIM_AMBIGUITY: ambiguity_dim,
        DIM_CONFLICTS: _dimension(
            DIM_CONFLICTS,
            STATE_CONFLICTING if conflicts else STATE_STRONG,
            (
                f"{len(conflicts)} conflict(s) detected"
                if conflicts
                else "no conflicting evidence detected"
            ),
            completeness=COMPLETENESS_EVALUATED,
        ),
    }

    # -- quality rules (first match wins) -----------------------------------
    scope_ok = provenance in ("EXPLICIT", "MIXED") or (
        scope == "COMPONENT_SCOPED"
    )
    has_target_identity = match_type in _TARGET_TYPES or bool(component)
    reasons: list[str] = []
    gaps: list[str] = []

    if authoritative_negative:
        level = LEVEL_INSUFFICIENT
        reasons.append(
            "authoritative version NO_MATCH blocks this candidate"
        )
    elif has_authoritative_conflict:
        level = LEVEL_INSUFFICIENT
        reasons.append(
            "authoritative evidence conflict blocks this candidate"
        )
    elif state == "UNKNOWN" and not has_target_identity:
        level = LEVEL_INSUFFICIENT
        reasons.append(
            "no meaningful asset/component relationship was established"
        )
    elif state == "CONFIRMED":
        if scope_ok and not conflicts:
            level = LEVEL_HIGH
            reasons.append(
                "explicit/scoped component identity with compatible"
                " version or supporting evidence"
            )
        else:
            level = LEVEL_MEDIUM
            reasons.append(
                "confirmed engine state but evidence is inferred without"
                " component-scoped support"
            )
    elif state == "SUPPORTED":
        if scope_ok:
            level = LEVEL_MEDIUM
            reasons.append(
                "component/plugin identity observed without version match"
            )
        else:
            level = LEVEL_LOW
            reasons.append(
                "component/plugin identity is inferred and only global"
                " support exists"
            )
    elif state == "WEAK":
        if has_target_identity:
            level = LEVEL_LOW
            reasons.append(
                "weak identity evidence; supporting evidence only"
            )
        else:
            level = LEVEL_INSUFFICIENT
            reasons.append(
                "only supporting (path/parameter/technology) evidence exists"
            )
    else:
        level = LEVEL_INSUFFICIENT
        reasons.append("asset match state is unknown or unavailable")

    if has_scope_conflict and level in (LEVEL_HIGH, LEVEL_MEDIUM):
        level = LEVEL_LOW
        reasons.append(
            "confidence capped because inferred identity lacks"
            " component-scoped support"
        )
    if ambiguity_count and level == LEVEL_HIGH:
        level = LEVEL_MEDIUM
        reasons.append(
            "confidence capped because ambiguous evidence rows remain"
        )

    # -- completeness --------------------------------------------------------
    completeness_dimensions = {
        name: dimensions[name]["completeness"]
        for name in COMPLETENESS_DIMENSIONS
    }
    evaluated = sorted(
        name for name, value in completeness_dimensions.items()
        if value == COMPLETENESS_EVALUATED
    )
    not_available = sorted(
        name for name, value in completeness_dimensions.items()
        if value == COMPLETENESS_NOT_AVAILABLE
    )
    overall_completeness = (
        COMPLETENESS_EVALUATED if evaluated
        else COMPLETENESS_NOT_AVAILABLE
    )

    # -- gaps ----------------------------------------------------------------
    if version == "NO_MATCH" or association == "VERSION_OBSERVED_NO_MATCH":
        gaps.append("version: authoritative NO_MATCH")
    elif not cve_versions:
        gaps.append("version: research has no affected version")
    elif not observed_versions:
        gaps.append("version: no observed version available")
    elif version_dim["state"] in (STATE_WEAK, STATE_UNKNOWN):
        gaps.append("version: comparison inconclusive")
    if not component:
        gaps.append("component: no observed component/plugin identity")
    if provenance == "INFERRED":
        gaps.append("provenance: component evidence is inferred only")
    if scope == "NONE":
        gaps.append("scope: no component-scoped support available")
    if not path_match:
        if dimensions[DIM_PATH_RELEVANCE]["state"] == STATE_UNKNOWN:
            gaps.append("path: no structured research path evidence")
        else:
            gaps.append("path: no matching observed path evidence")
    if not parameter_match:
        if dimensions[DIM_PARAMETER_RELEVANCE]["state"] == STATE_UNKNOWN:
            gaps.append("parameter: no structured research parameter"
                        " evidence")
        else:
            gaps.append("parameter: no matching observed parameter evidence")
    if dimensions[DIM_METHOD_RELEVANCE]["state"] == STATE_UNKNOWN:
        gaps.append("method: no structured method evidence")
    if ambiguity_count:
        gaps.append(f"ambiguity: {ambiguity_count} ambiguous row(s)")
    if not identity_rows and not component:
        gaps.append("identity: no resolved CVE component identity")
    for code in sorted(
        {_text(item) for item in remaining_blockers or () if _text(item)}
    ):
        gaps.append(f"blocker: {code}")
    if withheld_support:
        gaps.append(
            f"support: {len(list(withheld_support))} withheld global"
            " evidence item(s)"
        )

    # -- state / consistency / strength -------------------------------------
    if conflicts and level == LEVEL_INSUFFICIENT:
        evidence_state = STATE_CONFLICTING
    elif level == LEVEL_HIGH:
        evidence_state = STATE_STRONG
    elif level == LEVEL_MEDIUM:
        evidence_state = STATE_SUPPORTING
    elif level == LEVEL_LOW:
        evidence_state = STATE_WEAK
    else:
        evidence_state = STATE_UNKNOWN

    if conflicts:
        consistency = CONSISTENCY_CONFLICTING
    elif ambiguity_count:
        consistency = CONSISTENCY_UNKNOWN
    else:
        consistency = CONSISTENCY_CONSISTENT

    strength = {
        LEVEL_HIGH: STRENGTH_STRONG,
        LEVEL_MEDIUM: STRENGTH_SUPPORTING,
        LEVEL_LOW: STRENGTH_WEAK,
        LEVEL_INSUFFICIENT: STRENGTH_NONE,
    }.get(level, STRENGTH_NONE)

    return {
        "rule_version": EVIDENCE_QUALITY_RULE_VERSION,
        "evidence_quality": level,
        "evidence_state": evidence_state,
        "evidence_strength": strength,
        "evidence_consistency": consistency,
        "evidence_completeness": {
            "overall": overall_completeness,
            "dimensions": completeness_dimensions,
            "evaluated_dimensions": evaluated,
            "not_available_dimensions": not_available,
        },
        "dimensions": dimensions,
        "dimension_order": list(DIMENSION_ORDER),
        "evidence_gaps": gaps[:MAX_GAPS],
        "evidence_reasons": reasons[:MAX_REASONS],
        "conflicts": conflicts[:MAX_CONFLICTS],
        "counts": {
            "gaps": len(gaps[:MAX_GAPS]),
            "reasons": len(reasons[:MAX_REASONS]),
            "conflicts": len(conflicts[:MAX_CONFLICTS]),
            "ambiguous": ambiguity_count,
            "evaluated_dimensions": len(evaluated),
            "not_available_dimensions": len(not_available),
        },
    }


__all__ = [
    "EVIDENCE_QUALITY_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_QUALITY_LEVELS",
    "EVIDENCE_STATES",
    "EVIDENCE_STRENGTHS",
    "EVIDENCE_CONSISTENCIES",
    "EVIDENCE_COMPLETENESS",
    "DIMENSION_ORDER",
    "LEVEL_HIGH",
    "LEVEL_MEDIUM",
    "LEVEL_LOW",
    "LEVEL_INSUFFICIENT",
    "STATE_STRONG",
    "STATE_SUPPORTING",
    "STATE_WEAK",
    "STATE_UNKNOWN",
    "STATE_CONFLICTING",
    "STRENGTH_STRONG",
    "STRENGTH_SUPPORTING",
    "STRENGTH_WEAK",
    "STRENGTH_NONE",
    "CONSISTENCY_CONSISTENT",
    "CONSISTENCY_CONFLICTING",
    "CONSISTENCY_UNKNOWN",
    "COMPLETENESS_EVALUATED",
    "COMPLETENESS_NOT_AVAILABLE",
    "COMPLETENESS_NOT_APPLICABLE",
    "COMPLETENESS_UNKNOWN",
    "DIM_ASSET_IDENTITY",
    "DIM_COMPONENT_IDENTITY",
    "DIM_COMPONENT_PROVENANCE",
    "DIM_VERSION_COMPATIBILITY",
    "DIM_VERSION_EVIDENCE",
    "DIM_PATH_RELEVANCE",
    "DIM_PARAMETER_RELEVANCE",
    "DIM_METHOD_RELEVANCE",
    "DIM_SCOPE",
    "DIM_PROVENANCE",
    "DIM_AMBIGUITY",
    "DIM_CONFLICTS",
    "evaluate_evidence_quality",
]
