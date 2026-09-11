"""Stage R25.2 deterministic economic research-prioritization engine.

Pure, offline, bounded: no network, DNS, LLM, subprocess, target interaction,
Nuclei, browser, PoC execution, 5B-5J, findings, alerts, Mongo writes.

Composes the existing R15-R24 outputs into a single deterministic Money Score
with four axes (VALUE / CONFIDENCE / EFFORT / RISK), a priority band, and a
researcher decision. Nothing here re-derives R15-R24 intelligence: every
signal is read verbatim from the inputs (lead, plan, intel, payload, task,
r23, r24). Unknown contributes zero; false and unknown are never conflated.

Money Score is research-attention prioritization only. It never implies a
vulnerability is confirmed, a target is vulnerable, or a payout is likely.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field as dataclass_field
from typing import Any

RULE_VERSION = "r25-1"

# ---------------------------------------------------------------------------
# VALUE weights
# ---------------------------------------------------------------------------
W_PRIORITY = 0.30
W_RELEVANCE = 0.35
W_SEVERITY = 0.20
W_EXPLOIT_MATURITY = 0.15

# Severity text -> score (substring match, evaluated critical-first)
SEVERITY_TEXT = (("critical", 90), ("high", 75), ("medium", 55), ("low", 30))

# Exploit maturity tri-state contributions
EX_PUBLIC_POC = 55
EX_EXPLOIT_AVAILABLE = 30
EX_ACTIVE_EXPLOITATION = 15

# ---------------------------------------------------------------------------
# CONFIDENCE adjustments
# ---------------------------------------------------------------------------
CONF_BASE = 50
CONF_STRUCTURED_CVSS = 15
CONF_R23_CONF = {"HIGH": 20, "MEDIUM": 12, "LOW": 5}
CONF_R24_TIER = {"TRUSTED": 20, "SEMI_TRUSTED": 12, "DISCOVERY_ONLY": 6}
CONF_RELEVANCE_CLASS = {"HIGH": 10, "MEDIUM": 5}
CONF_CONFLICT_PENALTY = -15
CONF_CONFLICT_CAP = -30
CONF_GENERIC_BLOCKER = -12
CONF_ASSET_BLOCKER = -6
CONF_ASSET_BLOCKER_CAP = -20
CONF_UNKNOWN_PENALTY = -2
CONF_UNKNOWN_CAP = -20
CONF_NO_KNOWLEDGE_CAP = 35

# Confidence classes
CONF_HIGH_MIN = 70
CONF_MEDIUM_MIN = 45

# ---------------------------------------------------------------------------
# EFFORT adjustments
# ---------------------------------------------------------------------------
EFFORT_BASE = 50
EFFORT_PUBLIC_POC = -20
EFFORT_EXPLOIT_AVAILABLE = -10
EFFORT_EXPLOIT_CAP = -25
EFFORT_UNAUTH = -8
EFFORT_NO_UI = -7
EFFORT_SPECIFIC_MATCH = -12
EFFORT_PARAMETER = -5
EFFORT_VERSION = -5
EFFORT_VERSION_UNKNOWN = 12
EFFORT_PLUGIN_NOT_OBSERVED = 10
EFFORT_COMPONENT_NOT_OBSERVED = 10
EFFORT_GENERIC_MATCH = 15
EFFORT_NO_RESULT = 8
EFFORT_NO_COMPONENT = 8
EFFORT_MIN = 10
EFFORT_MAX = 100

# ---------------------------------------------------------------------------
# RISK (DUP / FP) weights
# ---------------------------------------------------------------------------
DUP_PUBLIC_POC = 20
DUP_ACTIVE_EXPLOITATION = 15
DUP_NUCLEI = 10
DUP_REPORT = 10
DUP_PRIOR_RESULT = 5
DUP_TASK_IN_PROGRESS = 8
DUP_TASK_BLOCKED = 5
DUP_CAP = 60

FP_GENERIC_MATCH = 12
FP_VERSION_UNKNOWN = 8
FP_PLUGIN_NOT_OBSERVED = 8
FP_COMPONENT_NOT_OBSERVED = 8
FP_CONFLICTS = 8
FP_RELEVANCE_LOW = 6
FP_CAP = 40

# ---------------------------------------------------------------------------
# MONEY weights + caps
# ---------------------------------------------------------------------------
MONEY_W_VALUE = 0.55
MONEY_W_CONFIDENCE = 0.15
MONEY_W_EFFORT_EFF = 0.15
MONEY_W_RISK_AVOID = 0.15

# (condition, cap, label) — applied in this exact order
MONEY_CAPS = (
    ("confidence_low", 60, "confidence below 45"),
    ("risk_high", 55, "risk 70 or above"),
    ("effort_high", 60, "effort 85 or above"),
    ("value_low", 45, "value below 30"),
    ("no_value_signal", 40, "no positive value signal"),
)

# Priority bands (money high -> low)
PRIORITY_BANDS = (
    ("P1_START_NOW", 85),
    ("P2_HIGH", 65),
    ("P3_MEDIUM", 45),
    ("P4_LOW", 30),
    ("P5_DEFER", 0),
)

# Effort score -> human estimate
EFFORT_ESTIMATES = (
    (25, "15\u201330 min"),
    (45, "30\u201360 min"),
    (65, "1\u20132 h"),
    (85, "2\u20136 h"),
    (100, "1\u20133 days"),
)

# Asset match classification (R17 reason substrings)
ASSET_MATCH_PRODUCT = "exact product match"
ASSET_MATCH_COMPONENT = "exact plugin/component match"
ASSET_MATCH_PATH = "component/path match"
ASSET_MATCH_TECHNOLOGY = "technology match"

# Blockers considered "asset-specific" for action selection
ASSET_SPECIFIC_BLOCKERS = frozenset(
    {
        "affected plugin not observed",
        "asset component not observed",
        "asset version unknown",
    }
)

# R23 confidence ordering
_R23_CONF_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
# R24 tier ordering
_R24_TIER_ORDER = {"TRUSTED": 3, "SEMI_TRUSTED": 2, "DISCOVERY_ONLY": 1}


def half_up(x: float) -> int:
    """Half-up rounding: floor(x + 0.5). Matches the R18 convention."""
    return int(math.floor(x + 0.5))


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read key from dict or attribute from object; default when missing."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ---------------------------------------------------------------------------
# Signal extraction (all fail-soft: missing/None -> safe default)
# ---------------------------------------------------------------------------


def _exploitability(intel: Any) -> dict:
    return _get(intel, "exploitability") or {}


def _relevance_row(intel: Any, program: str) -> dict:
    for row in _get(intel, "relevance", []) or []:
        if _get(row, "program") == program:
            return row or {}
    return {}


def _priority_score(lead: Any, intel: Any, program: str) -> int:
    score = _get(lead, "priority_score")
    if isinstance(score, (int, float)):
        return int(score)
    row = _get(intel, "priority") or {}
    if isinstance(row, dict) and isinstance(row.get("score"), (int, float)):
        return int(row["score"])
    return 0


def _relevance_score(lead: Any, intel: Any, program: str) -> int:
    score = _get(lead, "relevance_score")
    if isinstance(score, (int, float)):
        return int(score)
    return int(_relevance_row(intel, program).get("score") or 0)


def _relevance_class(lead: Any, intel: Any, program: str) -> str:
    level = _get(lead, "relevance_level")
    if level:
        return str(level).upper()
    return str(_relevance_row(intel, program).get("relevance") or "UNKNOWN").upper()


def _tri_state(field: str) -> str:
    """Normalize an R15 tri-state field; only true/false/unknown allowed."""
    v = str(field or "unknown").strip().lower()
    if v in ("true", "false", "unknown"):
        return v
    return "unknown"


def _blockers(lead: Any) -> list[str]:
    b = _get(lead, "blockers") or []
    return [str(x) for x in b]


def _has_blocker(blockers: list[str], marker: str) -> bool:
    return any(marker in x for x in blockers)


def _severity_score(payload: Any) -> int:
    cve_block = _get(payload, "cve") or {}
    cvss = cve_block.get("cvss_score") if isinstance(cve_block, dict) else None
    if isinstance(cvss, (int, float)):
        return _clamp(round(float(cvss) * 10), 0, 100)
    research = _get(payload, "research")
    text = str(_get(research, "severity") or "").lower() if isinstance(research, dict) else ""
    for token, score in SEVERITY_TEXT:
        if token in text:
            return score
    return 0


def _cvss_structured(intel: Any) -> bool:
    expl = _exploitability(intel)
    cvss = _get(expl, "cvss") or {}
    return (_get(cvss, "source") or "").lower() == "structured"


def _conflicts(intel: Any) -> list[str]:
    return list(_exploitability(intel).get("conflicts") or [])


def _r23_best_confidence(r23: Any) -> str | None:
    evidence = _get(r23, "evidence") or []
    best = 0
    for item in evidence:
        conf = str(_get(item, "confidence") or "LOW").upper()
        best = max(best, _R23_CONF_ORDER.get(conf, 0))
    if best == 0:
        return None
    for name, rank in _R23_CONF_ORDER.items():
        if rank == best:
            return name
    return None


def _r24_best_tier(r24: Any) -> str | None:
    best = 0
    rounds = _get(r24, "rounds") or []
    for rnd in rounds:
        discovery = _get(rnd, "discovery") or {}
        for src in _get(discovery, "sources") or []:
            tier = str(_get(src, "tier") or "").upper()
            best = max(best, _R24_TIER_ORDER.get(tier, 0))
    if best == 0:
        return None
    for name, rank in _R24_TIER_ORDER.items():
        if rank == best:
            return name
    return None


def _r23_source_count(r23: Any) -> int:
    return len(_get(r23, "sources") or [])


def _r23_evidence_count(r23: Any) -> int:
    return len(_get(r23, "evidence") or [])


def _r23_affected_components(r23: Any) -> list[str]:
    return list(_get(r23, "affected_components") or [])


def _r23_affected_parameters(r23: Any) -> list[str]:
    return list(_get(r23, "affected_parameters") or [])


def _r23_affected_versions(r23: Any) -> list[str]:
    return list(_get(r23, "affected_versions") or [])


def _plan_has_evidence_target(plan: Any, code: str) -> bool:
    for t in _get(plan, "evidence_targets") or []:
        if _get(t, "code") == code:
            return True
    return False


def _payload_versions(payload: Any) -> list[str]:
    research = _get(payload, "research")
    if isinstance(research, dict):
        return list(research.get("affected_versions") or [])
    return []


def _payload_parameters(payload: Any) -> list[str]:
    research = _get(payload, "research")
    if isinstance(research, dict):
        return list(research.get("parameters") or [])
    return []


def _payload_nuclei_candidate(payload: Any) -> bool:
    research = _get(payload, "research")
    if isinstance(research, dict):
        return bool(research.get("nuclei_candidate"))
    return False


def _task_status(task: Any) -> str | None:
    s = _get(task, "status")
    return str(s).upper() if s else None


def _report_exists(r23: Any) -> bool:
    return bool(_get(r23, "report_path"))


def _prior_result_exists(r23: Any) -> bool:
    # A prior R23 result exists for this plan when r23 carries evidence or
    # sources (the platform already invested research time).
    return bool(_get(r23, "evidence") or _get(r23, "sources"))


def _unique_unknowns(lead: Any, intel: Any, plan: Any, program: str) -> set[str]:
    out: set[str] = set()
    for u in _get(_get(intel, "priority") or {}, "unknown_factors") or []:
        out.add(str(u).strip().lower())
    for u in _relevance_row(intel, program).get("unknown_factors") or []:
        out.add(str(u).strip().lower())
    for u in _get(plan, "unknowns") or []:
        out.add(str(u).strip().lower())
    out.discard("")
    return out


# ---------------------------------------------------------------------------
# Component formulas
# ---------------------------------------------------------------------------


def compute_value(lead: Any, intel: Any, payload: Any, program: str) -> tuple[int, int, int, int]:
    """Return (V, P, R, SEV, EX) — V is the rounded composite."""
    P = _priority_score(lead, intel, program)
    R = _relevance_score(lead, intel, program)
    SEV = _severity_score(payload)
    expl = _exploitability(intel)
    EX = 0
    if _tri_state(expl.get("public_poc")) == "true":
        EX += EX_PUBLIC_POC
    if _tri_state(expl.get("exploit_available")) == "true":
        EX += EX_EXPLOIT_AVAILABLE
    if _tri_state(expl.get("active_exploitation")) == "true":
        EX += EX_ACTIVE_EXPLOITATION
    EX = _clamp(EX, 0, 100)
    V = half_up(W_PRIORITY * P + W_RELEVANCE * R + W_SEVERITY * SEV + W_EXPLOIT_MATURITY * EX)
    V = _clamp(V, 0, 100)
    return V, P, R, SEV, EX


def compute_confidence(
    lead: Any, intel: Any, r23: Any, r24: Any, program: str
) -> tuple[int, list[str]]:
    """Return (C, confidence_basis) per R25.1 5."""
    basis: list[str] = []
    expl = _exploitability(intel)
    C = CONF_BASE
    basis.append(f"base {CONF_BASE}")

    if _cvss_structured(intel):
        C += CONF_STRUCTURED_CVSS
        basis.append(f"structured cvss +{CONF_STRUCTURED_CVSS}")

    r23_conf = _r23_best_confidence(r23)
    if r23_conf and r23_conf in CONF_R23_CONF:
        delta = CONF_R23_CONF[r23_conf]
        C += delta
        basis.append(f"r23 {r23_conf.lower()} confidence +{delta}")

    r24_tier = _r24_best_tier(r24)
    if r24_tier and r24_tier in CONF_R24_TIER:
        delta = CONF_R24_TIER[r24_tier]
        C += delta
        basis.append(f"r24 {r24_tier.lower()} tier +{delta}")

    rel_cls = _relevance_class(lead, intel, program)
    if rel_cls in CONF_RELEVANCE_CLASS:
        delta = CONF_RELEVANCE_CLASS[rel_cls]
        C += delta
        basis.append(f"relevance {rel_cls.lower()} +{delta}")

    # Conflicts penalty (capped)
    conflict_count = len(_conflicts(intel))
    if conflict_count:
        penalty = max(CONF_CONFLICT_CAP, CONF_CONFLICT_PENALTY * conflict_count)
        C += penalty
        basis.append(f"conflicts({conflict_count}) {penalty}")

    # Asset-specific blocker penalties
    blk = _blockers(lead)
    if _has_blocker(blk, "only generic technology match"):
        C += CONF_GENERIC_BLOCKER
        basis.append(f"generic-only match {CONF_GENERIC_BLOCKER}")
    asset_blockers = 0
    for marker in ASSET_SPECIFIC_BLOCKERS:
        if _has_blocker(blk, marker):
            asset_blockers += 1
    if asset_blockers:
        penalty = max(CONF_ASSET_BLOCKER_CAP, CONF_ASSET_BLOCKER * asset_blockers)
        C += penalty
        basis.append(f"asset blockers({asset_blockers}) {penalty}")

    # Unknowns penalty (capped)
    unknown_count = len(_unique_unknowns(lead, intel, lead, program))
    if unknown_count:
        penalty = max(CONF_UNKNOWN_CAP, CONF_UNKNOWN_PENALTY * unknown_count)
        C += penalty
        basis.append(f"unknowns({unknown_count}) {penalty}")

    C = _clamp(C, 0, 100)

    # No R15/R16 knowledge document -> hard cap
    if not _get(intel, "available"):
        if C > CONF_NO_KNOWLEDGE_CAP:
            C = CONF_NO_KNOWLEDGE_CAP
            basis.append(f"no knowledge document cap {CONF_NO_KNOWLEDGE_CAP}")

    return C, basis


def compute_effort(lead: Any, intel: Any, plan: Any, payload: Any, r23: Any, r24: Any) -> int:
    """Return E per R25.1 6."""
    E = EFFORT_BASE
    expl = _exploitability(intel)

    # Exploit discount (capped)
    exploit_discount = 0
    if _tri_state(expl.get("public_poc")) == "true":
        exploit_discount += EFFORT_PUBLIC_POC
    if _tri_state(expl.get("exploit_available")) == "true":
        exploit_discount += EFFORT_EXPLOIT_AVAILABLE
    exploit_discount = max(EFFORT_EXPLOIT_CAP, exploit_discount)
    E += exploit_discount

    if _tri_state(expl.get("authentication_required")) == "false":
        E += EFFORT_UNAUTH
    if _tri_state(expl.get("user_interaction_required")) == "false":
        E += EFFORT_NO_UI

    # R17 exact product/plugin/component/path match
    blk = _blockers(lead)
    rel_row = None  # relevance reasons come from lead reasons / relevance row
    reasons = list(_relevance_row(intel, _get(lead, "program")).get("reasons") or [])
    if not reasons:
        for r in _get(lead, "reasons") or []:
            t = str(_get(r, "text") or "")
            if "match" in t:
                reasons.append(t)
    specific = False
    for reason in reasons:
        if (ASSET_MATCH_PRODUCT in reason or ASSET_MATCH_COMPONENT in reason
                or ASSET_MATCH_PATH in reason):
            specific = True
            break
    if specific:
        E += EFFORT_SPECIFIC_MATCH

    # Affected parameter / version known
    params = _r23_affected_parameters(r23) or _payload_parameters(payload)
    if params:
        E += EFFORT_PARAMETER
    versions = _r23_affected_versions(r23) or _payload_versions(payload)
    if versions:
        E += EFFORT_VERSION

    # Blocker penalties
    if _has_blocker(blk, "asset version unknown"):
        E += EFFORT_VERSION_UNKNOWN
    if _has_blocker(blk, "affected plugin not observed"):
        E += EFFORT_PLUGIN_NOT_OBSERVED
    if _has_blocker(blk, "asset component not observed"):
        E += EFFORT_COMPONENT_NOT_OBSERVED
    if _has_blocker(blk, "only generic technology match"):
        E += EFFORT_GENERIC_MATCH

    # No R23 and no R24 result
    if not _prior_result_exists(r23) and not _r24_best_tier(r24) and not _get(r24, "rounds"):
        E += EFFORT_NO_RESULT

    # No affected component identified
    comps = _r23_affected_components(r23)
    if not comps and not _plan_has_evidence_target(plan, "AFFECTED_COMPONENT"):
        E += EFFORT_NO_COMPONENT

    return _clamp(E, EFFORT_MIN, EFFORT_MAX)


def compute_risk(
    lead: Any, intel: Any, payload: Any, task: Any, r23: Any
) -> tuple[int, int, int]:
    """Return (K, DUP, FP) per R25.1 3.2."""
    expl = _exploitability(intel)
    blk = _blockers(lead)

    DUP = 0
    if _tri_state(expl.get("public_poc")) == "true":
        DUP += DUP_PUBLIC_POC
    if _tri_state(expl.get("active_exploitation")) == "true":
        DUP += DUP_ACTIVE_EXPLOITATION
    if _payload_nuclei_candidate(payload):
        DUP += DUP_NUCLEI
    if _report_exists(r23):
        DUP += DUP_REPORT
    if _prior_result_exists(r23):
        DUP += DUP_PRIOR_RESULT
    task_st = _task_status(task)
    if task_st == "IN_PROGRESS":
        DUP += DUP_TASK_IN_PROGRESS
    elif task_st == "BLOCKED":
        DUP += DUP_TASK_BLOCKED
    DUP = _clamp(DUP, 0, DUP_CAP)

    program = _get(lead, "program")
    FP = 0
    if _has_blocker(blk, "only generic technology match"):
        FP += FP_GENERIC_MATCH
    if _has_blocker(blk, "asset version unknown"):
        FP += FP_VERSION_UNKNOWN
    if _has_blocker(blk, "affected plugin not observed"):
        FP += FP_PLUGIN_NOT_OBSERVED
    if _has_blocker(blk, "asset component not observed"):
        FP += FP_COMPONENT_NOT_OBSERVED
    if _conflicts(intel):
        FP += FP_CONFLICTS
    if _relevance_class(lead, intel, program) == "LOW":
        FP += FP_RELEVANCE_LOW
    FP = _clamp(FP, 0, FP_CAP)

    K = _clamp(DUP + FP, 0, 100)
    return K, DUP, FP


def _priority_band(money: int) -> str:
    for name, minimum in PRIORITY_BANDS:
        if money >= minimum:
            return name
    return PRIORITY_BANDS[-1][0]


def _effort_estimate(effort: int) -> str:
    for ceiling, label in EFFORT_ESTIMATES:
        if effort <= ceiling:
            return label
    return EFFORT_ESTIMATES[-1][1]


def _confidence_class(C: int) -> str:
    if C >= CONF_HIGH_MIN:
        return "HIGH"
    if C >= CONF_MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


def _asset_match(lead: Any, intel: Any, program: str) -> str:
    reasons = list(_relevance_row(intel, program).get("reasons") or [])
    if not reasons:
        for r in _get(lead, "reasons") or []:
            t = str(_get(r, "text") or "")
            if "match" in t:
                reasons.append(t)
    has_product = any(ASSET_MATCH_PRODUCT in r for r in reasons)
    has_component = any(ASSET_MATCH_COMPONENT in r for r in reasons)
    has_path = any(ASSET_MATCH_PATH in r for r in reasons)
    has_tech = any(ASSET_MATCH_TECHNOLOGY in r for r in reasons)
    if has_product:
        return "PRODUCT"
    if has_component:
        return "COMPONENT"
    if has_path:
        return "PATH"
    if has_tech:
        return "TECHNOLOGY_ONLY"
    return "NONE"


def _recommended_action(money: int, lead: Any, task: Any) -> str:
    """Deterministic first-match action per R25.1 7."""
    task_st = _task_status(task)
    blk = _blockers(lead)
    has_asset_blocker = any(_has_blocker(blk, m) for m in ASSET_SPECIFIC_BLOCKERS)

    if task_st == "DONE":
        return "COMPLETED"
    if task_st == "IN_PROGRESS":
        return "CONTINUE"
    if task_st == "BLOCKED":
        return "UNBLOCK_OR_SKIP"

    band = _priority_band(money)
    if band == "P1_START_NOW":
        return "START_NOW"
    if band == "P2_HIGH":
        return "START_TIME_BOXED"
    if band == "P3_MEDIUM":
        if has_asset_blocker:
            return "VERIFY_ASSET_MATCH_FIRST"
        return "MONITOR"
    if band == "P4_LOW":
        return "MONITOR"
    return "DEFER"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class EconomicValue:
    """Deterministic economic projection for one lead (research-only)."""

    cve_id: str = ""
    program: str = ""
    lead_id: str = ""
    plan_id: str = ""
    queue_id: str = ""
    task_id: str = ""
    money_score: int = 0
    priority: str = "P5_DEFER"
    confidence: str = "LOW"
    confidence_basis: list[str] = dataclass_field(default_factory=list)
    effort: int = 0
    effort_estimate: str = ""
    asset_match: str = "NONE"
    why_valuable: list[str] = dataclass_field(default_factory=list)
    main_blockers: list[str] = dataclass_field(default_factory=list)
    recommended_action: str = "DEFER"
    subscores: dict = dataclass_field(default_factory=dict)
    evidence_summary: dict = dataclass_field(default_factory=dict)
    caps_applied: list[str] = dataclass_field(default_factory=list)
    rule_version: str = RULE_VERSION
    research_only: bool = True


def assess_economic_value(
    lead: Any,
    plan: Any,
    intel: Any,
    payload: Any,
    task: Any,
    r23: Any,
    r24: Any,
) -> EconomicValue:
    """Pure deterministic Money Score for one lead.

    Every signal is read verbatim from the R15-R24 inputs; nothing is
    re-derived. Unknown contributes zero. Safe to call with None inputs.
    """
    program = _get(lead, "program") or _get(plan, "program") or ""

    V, P, R, SEV, EX = compute_value(lead, intel, payload, program)
    C, conf_basis = compute_confidence(lead, intel, r23, r24, program)
    E = compute_effort(lead, intel, plan, payload, r23, r24)
    K, DUP, FP = compute_risk(lead, intel, payload, task, r23)

    raw = (MONEY_W_VALUE * V + MONEY_W_CONFIDENCE * C
           + MONEY_W_EFFORT_EFF * (100 - E) + MONEY_W_RISK_AVOID * (100 - K))

    caps_applied: list[str] = []
    M = raw
    if C < 45:
        M = min(M, 60)
        caps_applied.append(MONEY_CAPS[0][2])
    if K >= 70:
        M = min(M, 55)
        caps_applied.append(MONEY_CAPS[1][2])
    if E >= 85:
        M = min(M, 60)
        caps_applied.append(MONEY_CAPS[2][2])
    if V < 30:
        M = min(M, 45)
        caps_applied.append(MONEY_CAPS[3][2])
    if P == 0 and R == 0 and EX == 0:
        M = min(M, 40)
        caps_applied.append(MONEY_CAPS[4][2])

    money = _clamp(half_up(M), 0, 100)
    band = _priority_band(money)

    # why_valuable: fired VALUE/EX/SEV signals (deterministic order)
    why: list[str] = []
    if P > 0:
        why.append(f"research priority score {P}")
    if R > 0:
        why.append(f"asset relevance score {R}")
    if SEV > 0:
        why.append(f"severity score {SEV}")
    expl = _exploitability(intel)
    if _tri_state(expl.get("public_poc")) == "true":
        why.append("public proof-of-concept available")
    if _tri_state(expl.get("exploit_available")) == "true":
        why.append("exploit available")
    if _tri_state(expl.get("active_exploitation")) == "true":
        why.append("active exploitation reported")

    blk = _blockers(lead)

    return EconomicValue(
        cve_id=_get(lead, "cve_id") or "",
        program=program,
        lead_id=_get(lead, "lead_id") or "",
        plan_id=_get(plan, "plan_id") or "",
        queue_id=_get(lead, "queue_id") or _get(plan, "queue_id") or "",
        task_id=_get(lead, "task_id") or _get(plan, "task_id") or "",
        money_score=money,
        priority=band,
        confidence=_confidence_class(C),
        confidence_basis=conf_basis,
        effort=E,
        effort_estimate=_effort_estimate(E),
        asset_match=_asset_match(lead, intel, program),
        why_valuable=why,
        main_blockers=list(blk),
        recommended_action=_recommended_action(money, lead, task),
        subscores={"value": V, "confidence": C, "effort": E, "risk": K,
                   "dup": DUP, "fp": FP},
        evidence_summary={
            "r23_confidence": _r23_best_confidence(r23),
            "r24_tier": _r24_best_tier(r24),
            "sources": _r23_source_count(r23),
            "evidence": _r23_evidence_count(r23),
        },
        caps_applied=caps_applied,
        rule_version=RULE_VERSION,
        research_only=True,
    )


def economic_projection(value: EconomicValue) -> dict:
    """Serialize one EconomicValue to a deterministic dict (r25-1 schema)."""
    return {
        "cve_id": value.cve_id,
        "program": value.program,
        "lead_id": value.lead_id,
        "plan_id": value.plan_id,
        "queue_id": value.queue_id,
        "task_id": value.task_id,
        "money_score": value.money_score,
        "priority": value.priority,
        "confidence": value.confidence,
        "confidence_basis": list(value.confidence_basis),
        "effort": value.effort,
        "effort_estimate": value.effort_estimate,
        "asset_match": value.asset_match,
        "why_valuable": list(value.why_valuable),
        "main_blockers": list(value.main_blockers),
        "recommended_action": value.recommended_action,
        "subscores": dict(value.subscores),
        "evidence_summary": dict(value.evidence_summary),
        "caps_applied": list(value.caps_applied),
        "rule_version": value.rule_version,
        "research_only": True,
    }
