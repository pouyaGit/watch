"""Stage R31.10 evidence-aware hunt candidate prioritisation (pure engine).

Consumes the read-only evidence already produced by R30.1/R31.5/R31.6/R31.7/
R31.8/R31.9 for one Asset<->CVE research candidate and produces a
deterministic, explainable hunt-ordering signal:

    "Given the evidence currently available, which candidate deserves my
     limited bug-bounty verification time first?"

This is a **hunt prioritisation signal only**. It is not exploitability,
not CVSS, not a payout prediction, not a probability of vulnerability and
never a 5J finding. The existing Money Score, R25.2/R26/R29 rankings and the
R30.1 confidence remain authoritative and are not replaced or modified.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no persistence, no execution.
- Deterministic: fixed bounded constants, documented reason codes, stable
  tie-break keys; two identical candidates always sort identically.
- Ordered decision model: authoritative negatives are terminal; everything
  else is a bounded additive score with explicit adjustments.
- No probability semantics: ``hunt_score`` is a bounded 0..100 ordering key
  with documented components, never a probability.
- Privacy: only closed reason codes, bounded counts and sanitised gap text
  are retained; raw URLs, query values, headers, cookies, tokens and secrets
  are never copied.
- R31.9 evidence-quality rules, R31.5 scope authority, R30.1 confidence and
  R29 hunt queue logic are consumed read-only and never reimplemented.
"""

from __future__ import annotations

import re

HUNT_PRIORITY_RULE_VERSION = "r31-10"
RULE_VERSION = HUNT_PRIORITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

P0 = "P0"
P1 = "P1"
P2 = "P2"
P3 = "P3"
DEFER = "DEFER"

HUNT_PRIORITIES: tuple[str, ...] = (P0, P1, P2, P3, DEFER)
PRIORITY_RANKS: dict[str, int] = {
    P0: 0,
    P1: 1,
    P2: 2,
    P3: 3,
    DEFER: 4,
}

# Terminal blocking reason codes.
BLOCK_VERSION_NO_MATCH = "VERSION_NO_MATCH"
BLOCK_AUTHORITATIVE_CONFLICT = "AUTHORITATIVE_CONFLICT"
BLOCK_EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
BLOCK_NO_ASSET_IDENTITY = "NO_ASSET_IDENTITY"

BLOCKING_CODES: tuple[str, ...] = (
    BLOCK_VERSION_NO_MATCH,
    BLOCK_AUTHORITATIVE_CONFLICT,
    BLOCK_EVIDENCE_INSUFFICIENT,
    BLOCK_NO_ASSET_IDENTITY,
)

# Positive / negative adjustment reason codes.
REASON_EVIDENCE_HIGH = "EVIDENCE_HIGH"
REASON_EVIDENCE_MEDIUM = "EVIDENCE_MEDIUM"
REASON_EVIDENCE_LOW = "EVIDENCE_LOW"
REASON_COMPONENT_IDENTITY = "COMPONENT_IDENTITY"
REASON_EXACT_VERSION_MATCH = "EXACT_VERSION_MATCH"
REASON_FAMILY_VERSION_MATCH = "FAMILY_VERSION_MATCH"
REASON_RANGE_VERSION_MATCH = "RANGE_VERSION_MATCH"
REASON_EXPLICIT_PROVENANCE = "EXPLICIT_PROVENANCE"
REASON_MIXED_PROVENANCE = "MIXED_PROVENANCE"
REASON_COMPONENT_SCOPED_SUPPORT = "COMPONENT_SCOPED_SUPPORT"
REASON_EXACT_PATH_MATCH = "EXACT_PATH_MATCH"
REASON_PREFIX_PATH_MATCH = "PREFIX_PATH_MATCH"
REASON_EXACT_PARAMETER_MATCH = "EXACT_PARAMETER_MATCH"
REASON_METHOD_MATCH = "METHOD_MATCH"
REASON_NO_REMAINING_BLOCKERS = "NO_REMAINING_BLOCKERS"
REASON_INFERRED_UNSCOPED = "INFERRED_UNSCOPED_IDENTITY"
REASON_VERSION_UNRESOLVED = "VERSION_UNRESOLVED"
REASON_EVIDENCE_GAPS = "EVIDENCE_GAPS"
REASON_SUPPORTING_CONFLICT = "SUPPORTING_CONFLICT"
REASON_REMAINING_BLOCKER = "REMAINING_BLOCKER"

REASON_CODES: tuple[str, ...] = (
    REASON_EVIDENCE_HIGH,
    REASON_EVIDENCE_MEDIUM,
    REASON_EVIDENCE_LOW,
    REASON_COMPONENT_IDENTITY,
    REASON_EXACT_VERSION_MATCH,
    REASON_FAMILY_VERSION_MATCH,
    REASON_RANGE_VERSION_MATCH,
    REASON_EXPLICIT_PROVENANCE,
    REASON_MIXED_PROVENANCE,
    REASON_COMPONENT_SCOPED_SUPPORT,
    REASON_EXACT_PATH_MATCH,
    REASON_PREFIX_PATH_MATCH,
    REASON_EXACT_PARAMETER_MATCH,
    REASON_METHOD_MATCH,
    REASON_NO_REMAINING_BLOCKERS,
    REASON_INFERRED_UNSCOPED,
    REASON_VERSION_UNRESOLVED,
    REASON_EVIDENCE_GAPS,
    REASON_SUPPORTING_CONFLICT,
    REASON_REMAINING_BLOCKER,
)

# ---------------------------------------------------------------------------
# Bounded scoring constants (documented, fixed, reproducible)
# ---------------------------------------------------------------------------

SCORE_MIN = 0
SCORE_MAX = 100

BASE_EVIDENCE_HIGH = 60
BASE_EVIDENCE_MEDIUM = 40
BASE_EVIDENCE_LOW = 20
BASE_EVIDENCE_INSUFFICIENT = 0

DELTA_COMPONENT_IDENTITY = 10
DELTA_EXACT_VERSION_MATCH = 15
DELTA_FAMILY_VERSION_MATCH = 12
DELTA_RANGE_VERSION_MATCH = 8
DELTA_EXPLICIT_PROVENANCE = 6
DELTA_MIXED_PROVENANCE = 4
DELTA_COMPONENT_SCOPED_SUPPORT = 6
DELTA_EXACT_PATH_MATCH = 4
DELTA_PREFIX_PATH_MATCH = 2
DELTA_EXACT_PARAMETER_MATCH = 3
DELTA_METHOD_MATCH = 2
DELTA_NO_REMAINING_BLOCKERS = 4

PENALTY_INFERRED_UNSCOPED = -6
PENALTY_VERSION_UNRESOLVED = -4
PENALTY_EVIDENCE_GAPS = -4
PENALTY_SUPPORTING_CONFLICT = -10
PENALTY_REMAINING_BLOCKER = -2

# Priority thresholds over the bounded score (inclusive lower bound).
THRESHOLD_P0 = 80
THRESHOLD_P1 = 60
THRESHOLD_P2 = 40
THRESHOLD_P3 = 20

MAX_BLOCKING_REASONS = 8
MAX_POSITIVE_REASONS = 16
MAX_GAPS = 16
MAX_VALUE_LEN = 160

_EVIDENCE_QUALITY_RANK = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
    "INSUFFICIENT": 3,
}
_CONFIDENCE_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
_MATCH_TYPE_RANK = {
    "COMPONENT": 0,
    "PLUGIN": 1,
    "PRODUCT": 2,
    "VERSION": 3,
    "TECHNOLOGY": 4,
    "PARAMETER": 5,
    "PATH": 6,
    "VULNERABILITY_TYPE": 7,
    "": 8,
}

_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _safe_text(value: object) -> str:
    """Bound and redact credential-like text before it enters evidence."""

    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:MAX_VALUE_LEN]


def _bounded_strings(values: object, limit: int) -> list[str]:
    out: list[str] = []
    for value in values or ():
        text = _safe_text(value)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _evidence_quality_block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _conflicts(value: object) -> list[dict]:
    block = _evidence_quality_block(value)
    conflicts = block.get("conflicts")
    return [
        item for item in (conflicts or ()) if isinstance(item, dict)
    ]


def _adjust(
    adjustments: list[dict],
    code: str,
    delta: int,
) -> None:
    if delta == 0:
        return
    adjustments.append({"code": code, "delta": int(delta)})


def _reason_lines(
    adjustments: list[dict], *, positive: bool
) -> list[str]:
    out: list[str] = []
    for item in adjustments:
        delta = int(item.get("delta") or 0)
        if positive and delta <= 0:
            continue
        if not positive and delta >= 0:
            continue
        text = f"{item['code']}({'+' if delta > 0 else ''}{delta})"
        if text not in out:
            out.append(text)
    return out[:MAX_POSITIVE_REASONS]


def _priority_for(score: int) -> str:
    if score >= THRESHOLD_P0:
        return P0
    if score >= THRESHOLD_P1:
        return P1
    if score >= THRESHOLD_P2:
        return P2
    if score >= THRESHOLD_P3:
        return P3
    return DEFER


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_hunt_priority(
    *,
    evidence_quality: object = None,
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
    version_normalization: object = None,
    path_parameter_relevance: object = None,
    cve_id: object = "",
    max_gaps: int = MAX_GAPS,
) -> dict:
    """Deterministic bounded hunt priority for one candidate summary.

    Read-only: consumes R30.1/R31.5/R31.7/R31.8/R31.9 outputs. Never mutates
    them and never scans corpus data.
    """

    quality = _evidence_quality_block(evidence_quality)
    level = _upper(quality.get("evidence_quality") or "INSUFFICIENT")
    strength = _upper(quality.get("evidence_strength") or "NONE")
    consistency = _upper(
        quality.get("evidence_consistency") or "UNKNOWN"
    )
    conflicts = _conflicts(evidence_quality)
    match_type = _upper(strongest_match_type)
    confidence = _upper(strongest_confidence or "NONE")
    state = _upper(asset_match_state or "UNKNOWN")
    association = _upper(version_association_state or "")
    engine_version_state = _upper(version_state or "UNKNOWN")
    provenance = _upper(evidence_provenance or "EXPLICIT")
    scope = _upper(support_scope or "NONE")
    component = _text(matched_component)
    version = _text(matched_version)
    parameter = _text(matched_parameter)

    version_normalization = (
        version_normalization
        if isinstance(version_normalization, dict)
        else {}
    )
    version_rows = [
        row for row in (version_normalization.get("rows") or ())
        if isinstance(row, dict)
    ]
    path_parameter_relevance = (
        path_parameter_relevance
        if isinstance(path_parameter_relevance, dict)
        else {}
    )
    pp_summary = path_parameter_relevance.get("summary")
    pp_summary = pp_summary if isinstance(pp_summary, dict) else {}
    pp_rows = [
        row for row in (path_parameter_relevance.get("evidence") or ())
        if isinstance(row, dict)
    ]

    blocking_reasons: list[str] = []
    adjustments: list[dict] = []

    # -- terminal authoritative blockers -----------------------------------
    version_mismatch = (
        engine_version_state == "NO_MATCH"
        or association == "VERSION_OBSERVED_NO_MATCH"
    )
    authoritative_conflict = any(
        _upper(conflict.get("severity")) == "AUTHORITATIVE"
        for conflict in conflicts
    )
    has_identity = match_type in (
        "COMPONENT", "PLUGIN", "PRODUCT"
    ) or bool(component)

    if version_mismatch:
        blocking_reasons.append(BLOCK_VERSION_NO_MATCH)
    if authoritative_conflict:
        blocking_reasons.append(BLOCK_AUTHORITATIVE_CONFLICT)
    if level == "INSUFFICIENT":
        blocking_reasons.append(BLOCK_EVIDENCE_INSUFFICIENT)
    if not has_identity and not version_mismatch:
        blocking_reasons.append(BLOCK_NO_ASSET_IDENTITY)

    gaps = _bounded_strings(
        quality.get("evidence_gaps"), max(1, int(max_gaps))
    )
    blocker_codes = _bounded_strings(
        remaining_blockers, MAX_BLOCKING_REASONS
    )

    if blocking_reasons:
        priority = DEFER
        return {
            "rule_version": HUNT_PRIORITY_RULE_VERSION,
            "priority": priority,
            "priority_rank": PRIORITY_RANKS[priority],
            "hunt_score": SCORE_MIN,
            "blocked": True,
            "evidence_quality": level,
            "evidence_strength": strength,
            "evidence_consistency": consistency,
            "blocking_reasons": blocking_reasons[
                :MAX_BLOCKING_REASONS
            ],
            "positive_reasons": _reason_lines(
                adjustments, positive=True
            ),
            "negative_reasons": _reason_lines(
                adjustments, positive=False
            ),
            "evidence_gaps": gaps,
            "remaining_blocker_codes": blocker_codes,
            "adjustments": adjustments,
            "tie_break_key": [
                PRIORITY_RANKS[priority],
                -SCORE_MIN,
                _EVIDENCE_QUALITY_RANK.get(level, 3),
                -_CONFIDENCE_RANK.get(confidence, 0),
                _MATCH_TYPE_RANK.get(match_type, 8),
                0,
                0,
                _safe_text(cve_id),
            ],
            "reason": "authoritative evidence blocks this candidate",
        }

    # -- bounded additive score --------------------------------------------
    base = {
        "HIGH": BASE_EVIDENCE_HIGH,
        "MEDIUM": BASE_EVIDENCE_MEDIUM,
        "LOW": BASE_EVIDENCE_LOW,
    }.get(level, BASE_EVIDENCE_INSUFFICIENT)
    if base:
        _adjust(
            adjustments,
            {
                "HIGH": REASON_EVIDENCE_HIGH,
                "MEDIUM": REASON_EVIDENCE_MEDIUM,
                "LOW": REASON_EVIDENCE_LOW,
            }.get(level, REASON_EVIDENCE_LOW),
            base,
        )

    if match_type in ("COMPONENT", "PLUGIN") or component:
        _adjust(
            adjustments,
            REASON_COMPONENT_IDENTITY,
            DELTA_COMPONENT_IDENTITY,
        )

    # Version evidence (R31.7 rows + R30.3 association state).
    exact_version_match = False
    family_version_match = association == "VERSION_MATCH_WITHIN_SAME_FAMILY"
    range_version_match = any(
        _upper(row.get("comparison")) == "MATCH"
        and _upper(row.get("cve_kind")) in ("RANGE", "WILDCARD", "PREFIX")
        for row in version_rows
    )
    for row in version_rows:
        if _upper(row.get("comparison")) != "MATCH":
            continue
        if (
            _upper(row.get("cve_kind")) == "EXACT"
            and _upper(row.get("cve_evidence_class"))
            == "EXACT_OBSERVED"
        ):
            exact_version_match = True
    if engine_version_state == "MATCH" or family_version_match:
        if exact_version_match:
            _adjust(
                adjustments,
                    REASON_EXACT_VERSION_MATCH,
                DELTA_EXACT_VERSION_MATCH,
            )
        else:
            _adjust(
                adjustments,
                    REASON_FAMILY_VERSION_MATCH,
                DELTA_FAMILY_VERSION_MATCH,
            )
    elif range_version_match:
        _adjust(
            adjustments,
            REASON_RANGE_VERSION_MATCH,
            DELTA_RANGE_VERSION_MATCH,
        )

    # Provenance / scope (R31.5; authority untouched).
    if provenance == "EXPLICIT":
        _adjust(
            adjustments,
            REASON_EXPLICIT_PROVENANCE,
            DELTA_EXPLICIT_PROVENANCE,
        )
    elif provenance == "MIXED":
        _adjust(
            adjustments,
            REASON_MIXED_PROVENANCE,
            DELTA_MIXED_PROVENANCE,
        )
    if scope == "COMPONENT_SCOPED":
        _adjust(
            adjustments,
            REASON_COMPONENT_SCOPED_SUPPORT,
            DELTA_COMPONENT_SCOPED_SUPPORT,
        )
    elif provenance == "INFERRED":
        _adjust(
            adjustments,
            REASON_INFERRED_UNSCOPED,
            PENALTY_INFERRED_UNSCOPED,
        )

    # Path / parameter / method relevance (R31.8 summary only).
    path_match = bool(pp_summary.get("path_match"))
    parameter_match = bool(pp_summary.get("parameter_match"))
    method = pp_summary.get("method")
    method = method if isinstance(method, dict) else {}
    method_match = _upper(method.get("result")) == "MATCH"
    exact_path = any(
        _upper(row.get("evidence_type")) == "EXACT_PATH"
        and _upper(row.get("result")) == "MATCH"
        for row in pp_rows
    )
    prefix_path = any(
        _upper(row.get("evidence_type"))
        in ("PATH_PREFIX", "PATH_PATTERN")
        and _upper(row.get("result")) == "MATCH"
        for row in pp_rows
    )
    exact_parameter = any(
        _upper(row.get("evidence_type")) == "EXACT_PARAMETER"
        and _upper(row.get("result")) == "MATCH"
        for row in pp_rows
    )
    if path_match and exact_path:
        _adjust(
            adjustments,
            REASON_EXACT_PATH_MATCH,
            DELTA_EXACT_PATH_MATCH,
        )
    elif path_match and prefix_path:
        _adjust(
            adjustments,
            REASON_PREFIX_PATH_MATCH,
            DELTA_PREFIX_PATH_MATCH,
        )
    if parameter_match or exact_parameter:
        _adjust(
            adjustments,
            REASON_EXACT_PARAMETER_MATCH,
            DELTA_EXACT_PARAMETER_MATCH,
        )
    if method_match:
        _adjust(
            adjustments,
            REASON_METHOD_MATCH,
            DELTA_METHOD_MATCH,
        )

    # Version unresolved penalty (research versions exist but no comparison).
    observed_versions = list(
        version_normalization.get("observed_versions") or ()
    )
    if (
        engine_version_state != "MATCH"
        and not family_version_match
        and observed_versions
    ):
        _adjust(
            adjustments,
            REASON_VERSION_UNRESOLVED,
            PENALTY_VERSION_UNRESOLVED,
        )

    # Blockers and gaps.
    if not blocker_codes:
        _adjust(
            adjustments,
            REASON_NO_REMAINING_BLOCKERS,
            DELTA_NO_REMAINING_BLOCKERS,
        )
    else:
        _adjust(
            adjustments,
            REASON_REMAINING_BLOCKER,
            PENALTY_REMAINING_BLOCKER * len(blocker_codes),
        )
    if len(gaps) >= 3:
        _adjust(
            adjustments,
            REASON_EVIDENCE_GAPS,
            PENALTY_EVIDENCE_GAPS,
        )
    if any(
        _upper(conflict.get("severity")) != "AUTHORITATIVE"
        for conflict in conflicts
    ):
        _adjust(
            adjustments,
            REASON_SUPPORTING_CONFLICT,
            PENALTY_SUPPORTING_CONFLICT,
        )

    score = sum(item["delta"] for item in adjustments)
    score = max(SCORE_MIN, min(SCORE_MAX, score))
    priority = _priority_for(score)
    if priority == DEFER:
        blocking_reasons.append(BLOCK_EVIDENCE_INSUFFICIENT)

    scoped_flag = 1 if scope == "COMPONENT_SCOPED" else 0
    tie_break_key = [
        PRIORITY_RANKS[priority],
        -score,
        _EVIDENCE_QUALITY_RANK.get(level, 3),
        -_CONFIDENCE_RANK.get(confidence, 0),
        _MATCH_TYPE_RANK.get(match_type, 8),
        1 if exact_version_match else 0,
        scoped_flag,
        _safe_text(cve_id),
    ]
    return {
        "rule_version": HUNT_PRIORITY_RULE_VERSION,
        "priority": priority,
        "priority_rank": PRIORITY_RANKS[priority],
        "hunt_score": score,
        "blocked": False,
        "evidence_quality": level,
        "evidence_strength": strength,
        "evidence_consistency": consistency,
        "blocking_reasons": blocking_reasons[:MAX_BLOCKING_REASONS],
        "positive_reasons": _reason_lines(adjustments, positive=True),
        "negative_reasons": _reason_lines(adjustments, positive=False),
        "evidence_gaps": gaps,
        "remaining_blocker_codes": blocker_codes,
        "adjustments": adjustments,
        "tie_break_key": tie_break_key,
        "reason": "ranked from evidence quality, identity, version and"
        " supporting relevance",
    }


__all__ = [
    "HUNT_PRIORITY_RULE_VERSION",
    "RULE_VERSION",
    "HUNT_PRIORITIES",
    "PRIORITY_RANKS",
    "BLOCKING_CODES",
    "REASON_CODES",
    "P0",
    "P1",
    "P2",
    "P3",
    "DEFER",
    "BLOCK_VERSION_NO_MATCH",
    "BLOCK_AUTHORITATIVE_CONFLICT",
    "BLOCK_EVIDENCE_INSUFFICIENT",
    "BLOCK_NO_ASSET_IDENTITY",
    "evaluate_hunt_priority",
]
