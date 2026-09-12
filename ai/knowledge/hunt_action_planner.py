"""Stage R31.12 deterministic hunt action planner (pure engine).

Consumes the read-only R31.10 hunt priority and R31.11 hunt actionability
projections for one Asset<->CVE research candidate and produces the smallest
useful next investigation step for a human bug-bounty hunter:

    "Given the evidence already available, what is the single next thing I
     should do about this candidate?"

This is a **planning signal only**. It never performs the action, never
creates a 5J finding, never contacts a target, never scans, never executes,
never calls an LLM and never renders a probability, exploitability, severity,
CVSS, payout or bounty-value judgement. The recommended action is an
advisory research step, not a confirmed vulnerability.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Additive and read-only: the R31.10/R31.11 input dicts are never mutated;
  the result is a new dict with rule version ``r31-12``.
- No recomputation: R31.10 priority/score and the R31.11 state are consumed
  verbatim. The planner never rescoring and never re-derives R31.10/R31.11
  rules.
- Downgrade-only: ``BLOCKED`` is terminal; ``LOW_VALUE_DEFERRED`` can only
  defer; ``SUPPORTING_CONTEXT`` can never become immediate verification;
  inferred/mixed/unknown provenance can never select
  ``VERIFY_EXISTING_EVIDENCE``.
- Evidence-driven gaps only: an evidence gap is selected only when the
  existing R31.10/R31.11 projection (or an explicit R30.1
  ``strongest_match_type`` hint) carries an explicit signal for it. Absent
  fields never become invented gaps.
- Deterministic: closed action/gap/effort/confidence vocabularies, documented
  precedence and a stable ``action_order_key`` that preserves the R31.11 key
  as its secondary ordering.
- Privacy: only closed codes, bounded counts and sanitised rule-version text
  are retained; raw URLs, credentials, tokens, headers, query values and
  arbitrary source text are never copied.
"""

from __future__ import annotations

import re

from ai.knowledge.hunt_actionability import (
    BLOCKED as ACTIONABILITY_BLOCKED,
    IMMEDIATE_VERIFICATION as ACTIONABILITY_IMMEDIATE,
    LOW_VALUE_DEFERRED as ACTIONABILITY_LOW_VALUE,
    STRONG_MANUAL_REVIEW as ACTIONABILITY_STRONG,
    SUPPORTING_CONTEXT as ACTIONABILITY_SUPPORTING,
)

HUNT_ACTION_PLANNER_RULE_VERSION = "r31-12"
RULE_VERSION = HUNT_ACTION_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed action vocabulary
# ---------------------------------------------------------------------------

VERIFY_EXISTING_EVIDENCE = "VERIFY_EXISTING_EVIDENCE"
VERIFY_VERSION = "VERIFY_VERSION"
VERIFY_COMPONENT_IDENTITY = "VERIFY_COMPONENT_IDENTITY"
VERIFY_SCOPE = "VERIFY_SCOPE"
VERIFY_PATH = "VERIFY_PATH"
VERIFY_PARAMETER = "VERIFY_PARAMETER"
COLLECT_HTTP_EVIDENCE = "COLLECT_HTTP_EVIDENCE"
COLLECT_TECHNOLOGY_EVIDENCE = "COLLECT_TECHNOLOGY_EVIDENCE"
MANUAL_REVIEW = "MANUAL_REVIEW"
DEFER = "DEFER"
RESOLVE_BLOCKERS = "RESOLVE_BLOCKERS"

HUNT_ACTIONS: tuple[str, ...] = (
    VERIFY_EXISTING_EVIDENCE,
    VERIFY_VERSION,
    VERIFY_COMPONENT_IDENTITY,
    VERIFY_SCOPE,
    VERIFY_PATH,
    VERIFY_PARAMETER,
    COLLECT_HTTP_EVIDENCE,
    COLLECT_TECHNOLOGY_EVIDENCE,
    MANUAL_REVIEW,
    DEFER,
    RESOLVE_BLOCKERS,
)

# Ascending action order (most actionable first, terminal last).
ACTION_RANKS: dict[str, int] = {
    VERIFY_EXISTING_EVIDENCE: 0,
    VERIFY_VERSION: 1,
    VERIFY_COMPONENT_IDENTITY: 2,
    VERIFY_SCOPE: 3,
    VERIFY_PATH: 4,
    VERIFY_PARAMETER: 5,
    COLLECT_HTTP_EVIDENCE: 6,
    COLLECT_TECHNOLOGY_EVIDENCE: 7,
    MANUAL_REVIEW: 8,
    DEFER: 9,
    RESOLVE_BLOCKERS: 10,
}

_ACTION_REASON: dict[str, str] = {
    VERIFY_EXISTING_EVIDENCE: (
        "verify the candidate using the evidence already available"
    ),
    VERIFY_VERSION: "version compatibility is the explicit remaining gap",
    VERIFY_COMPONENT_IDENTITY: (
        "component/plugin identity is the explicit remaining gap"
    ),
    VERIFY_SCOPE: (
        "program/component scope is the explicit remaining gap"
    ),
    VERIFY_PATH: "path relevance is the explicit remaining gap",
    VERIFY_PARAMETER: "parameter usage is the explicit remaining gap",
    COLLECT_HTTP_EVIDENCE: (
        "HTTP behavior evidence is the explicit remaining gap"
    ),
    COLLECT_TECHNOLOGY_EVIDENCE: (
        "technology-level evidence is the explicit remaining gap"
    ),
    MANUAL_REVIEW: (
        "actionable for manual review; no narrower explicit evidence gap"
        " was selected"
    ),
    DEFER: "R31.11 classified the candidate as low-value/deferred",
    RESOLVE_BLOCKERS: (
        "terminal blockers must be resolved before any verification"
    ),
}

# ---------------------------------------------------------------------------
# Closed evidence-gap vocabulary
# ---------------------------------------------------------------------------

GAP_VERSION = "GAP_VERSION"
GAP_COMPONENT_IDENTITY = "GAP_COMPONENT_IDENTITY"
GAP_SCOPE = "GAP_SCOPE"
GAP_PATH = "GAP_PATH"
GAP_PARAMETER = "GAP_PARAMETER"
GAP_HTTP = "GAP_HTTP"
GAP_TECHNOLOGY = "GAP_TECHNOLOGY"
GAP_NONE = "GAP_NONE"

EVIDENCE_GAPS: tuple[str, ...] = (
    GAP_VERSION,
    GAP_COMPONENT_IDENTITY,
    GAP_SCOPE,
    GAP_PATH,
    GAP_PARAMETER,
    GAP_HTTP,
    GAP_TECHNOLOGY,
    GAP_NONE,
)

# Conservative precedence: first explicit gap wins.
_GAP_PRECEDENCE: tuple[str, ...] = (
    GAP_VERSION,
    GAP_COMPONENT_IDENTITY,
    GAP_SCOPE,
    GAP_PATH,
    GAP_PARAMETER,
    GAP_HTTP,
    GAP_TECHNOLOGY,
)

_GAP_ACTION: dict[str, str] = {
    GAP_VERSION: VERIFY_VERSION,
    GAP_COMPONENT_IDENTITY: VERIFY_COMPONENT_IDENTITY,
    GAP_SCOPE: VERIFY_SCOPE,
    GAP_PATH: VERIFY_PATH,
    GAP_PARAMETER: VERIFY_PARAMETER,
    GAP_HTTP: COLLECT_HTTP_EVIDENCE,
    GAP_TECHNOLOGY: COLLECT_TECHNOLOGY_EVIDENCE,
}

# ---------------------------------------------------------------------------
# Closed reason-code vocabulary
# ---------------------------------------------------------------------------

REASON_SOURCE_BLOCKED = "SOURCE_BLOCKED"
REASON_SOURCE_IMMEDIATE = "SOURCE_IMMEDIATE_VERIFICATION"
REASON_SOURCE_STRONG = "SOURCE_STRONG_MANUAL_REVIEW"
REASON_SOURCE_SUPPORTING = "SOURCE_SUPPORTING_CONTEXT"
REASON_SOURCE_LOW_VALUE = "SOURCE_LOW_VALUE_DEFERRED"
REASON_MISSING_ACTIONABILITY = "MISSING_ACTIONABILITY"
REASON_UNRECOGNIZED_ACTIONABILITY = "UNRECOGNIZED_ACTIONABILITY"
REASON_MULTIPLE_GAPS = "MULTIPLE_GAPS_PRESENT"
REASON_NO_EXPLICIT_GAP = "NO_EXPLICIT_GAP"
REASON_INFERRED_PROVENANCE = "INFERRED_PROVENANCE_OBSERVED"
REASON_NON_EXPLICIT_PROVENANCE = "NON_EXPLICIT_PROVENANCE_OBSERVED"

REASON_CODES: tuple[str, ...] = (
    REASON_SOURCE_BLOCKED,
    REASON_SOURCE_IMMEDIATE,
    REASON_SOURCE_STRONG,
    REASON_SOURCE_SUPPORTING,
    REASON_SOURCE_LOW_VALUE,
    REASON_MISSING_ACTIONABILITY,
    REASON_UNRECOGNIZED_ACTIONABILITY,
    REASON_MULTIPLE_GAPS,
    REASON_NO_EXPLICIT_GAP,
    REASON_INFERRED_PROVENANCE,
    REASON_NON_EXPLICIT_PROVENANCE,
) + EVIDENCE_GAPS

_STATE_REASON_CODES: dict[str, str] = {
    ACTIONABILITY_BLOCKED: REASON_SOURCE_BLOCKED,
    ACTIONABILITY_IMMEDIATE: REASON_SOURCE_IMMEDIATE,
    ACTIONABILITY_STRONG: REASON_SOURCE_STRONG,
    ACTIONABILITY_SUPPORTING: REASON_SOURCE_SUPPORTING,
    ACTIONABILITY_LOW_VALUE: REASON_SOURCE_LOW_VALUE,
}

# ---------------------------------------------------------------------------
# Closed effort / confidence vocabularies
# ---------------------------------------------------------------------------

EFFORT_LOW = "LOW"
EFFORT_MEDIUM = "MEDIUM"
EFFORT_HIGH = "HIGH"
EFFORT_UNKNOWN = "UNKNOWN"

ESTIMATED_EFFORTS: tuple[str, ...] = (
    EFFORT_LOW,
    EFFORT_MEDIUM,
    EFFORT_HIGH,
    EFFORT_UNKNOWN,
)

_EFFORT_BY_ACTION: dict[str, str] = {
    VERIFY_EXISTING_EVIDENCE: EFFORT_LOW,
    VERIFY_VERSION: EFFORT_MEDIUM,
    VERIFY_COMPONENT_IDENTITY: EFFORT_MEDIUM,
    VERIFY_SCOPE: EFFORT_MEDIUM,
    VERIFY_PATH: EFFORT_LOW,
    VERIFY_PARAMETER: EFFORT_LOW,
    COLLECT_HTTP_EVIDENCE: EFFORT_MEDIUM,
    COLLECT_TECHNOLOGY_EVIDENCE: EFFORT_MEDIUM,
    MANUAL_REVIEW: EFFORT_HIGH,
    DEFER: EFFORT_UNKNOWN,
    RESOLVE_BLOCKERS: EFFORT_UNKNOWN,
}

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"

PLAN_CONFIDENCES: tuple[str, ...] = (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
)

# ---------------------------------------------------------------------------
# Explicit source signals consumed read-only
# ---------------------------------------------------------------------------

# R30.1 canonical blocker codes (flow through R31.10 remaining_blocker_codes).
_BLOCKER_VERSION = "version_unknown"
_BLOCKER_COMPONENT = "component_not_observed"
_BLOCKER_PLUGIN = "plugin_not_observed"
_BLOCKER_PARAMETER = "parameter_unknown"
_BLOCKER_TECHNOLOGY = "generic_technology_only"

# R31.10 negative adjustment codes.
_SOURCE_VERSION_UNRESOLVED = "VERSION_UNRESOLVED"
_SOURCE_INFERRED_UNSCOPED = "INFERRED_UNSCOPED_IDENTITY"
_SOURCE_EXPLICIT_PROVENANCE = "EXPLICIT_PROVENANCE"
_SOURCE_MIXED_PROVENANCE = "MIXED_PROVENANCE"

# R31.9 explicit gap-line prefixes (stable, generated by evidence_quality).
_GAP_PREFIXES: tuple[tuple[str, str], ...] = (
    ("version:", GAP_VERSION),
    ("component:", GAP_COMPONENT_IDENTITY),
    ("identity:", GAP_COMPONENT_IDENTITY),
    ("provenance:", GAP_SCOPE),
    ("scope:", GAP_SCOPE),
    ("path:", GAP_PATH),
    ("parameter:", GAP_PARAMETER),
    ("method:", GAP_HTTP),
    ("technology:", GAP_TECHNOLOGY),
)

MAX_REASON_CODES = 8
MAX_ORDER_KEY = 16
MAX_GAP_LINES = 64
MAX_VALUE_LEN = 160

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


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _signal_codes(block: dict) -> tuple[set[str], set[str]]:
    """Read R31.10 adjustment/reason codes as positive/negative sets."""

    positive: set[str] = set()
    negative: set[str] = set()
    adjustments = block.get("adjustments")
    if isinstance(adjustments, (list, tuple)):
        for item in adjustments:
            if not isinstance(item, dict):
                continue
            code = _upper(item.get("code"))
            if not code:
                continue
            try:
                delta = int(item.get("delta") or 0)
            except (TypeError, ValueError):
                delta = 0
            if delta < 0:
                negative.add(code)
            elif delta > 0:
                positive.add(code)
    for key, target in (
        ("positive_reasons", positive),
        ("negative_reasons", negative),
    ):
        lines = block.get(key)
        if not isinstance(lines, (list, tuple)):
            continue
        for line in lines:
            code = _upper(_text(line).split("(", 1)[0])
            if code:
                target.add(code)
    return positive, negative


def _resolve_provenance(
    block: dict,
    hint: object,
    positive: set[str],
    negative: set[str],
) -> str:
    """Resolve the observed-vs-inferred provenance signal (read-only)."""

    if _text(hint):
        return _upper(hint)
    if _SOURCE_INFERRED_UNSCOPED in negative:
        return "INFERRED"
    if _SOURCE_EXPLICIT_PROVENANCE in positive:
        return "EXPLICIT"
    if _SOURCE_MIXED_PROVENANCE in positive:
        return "MIXED"
    return "UNKNOWN"


def _detect_gaps(
    block: dict,
    negative: set[str],
    *,
    provenance: str,
    scope: str,
    strongest_match_type: object,
) -> tuple[list[str], str]:
    """Collect only explicitly signalled evidence gaps, then select one.

    Sources (all read-only):
    - R30.1 canonical blocker codes in ``remaining_blocker_codes``;
    - R31.10 negative adjustment codes;
    - R31.9 gap lines in ``evidence_gaps`` (stable prefixes);
    - an explicit inferred+unscoped provenance/scope state;
    - an explicit R30.1 ``strongest_match_type == TECHNOLOGY`` hint.
    """

    detected: list[str] = []

    def mark(gap: str) -> None:
        if gap not in detected:
            detected.append(gap)

    for raw in block.get("remaining_blocker_codes") or ():
        code = _text(raw).lower()
        if code == _BLOCKER_VERSION:
            mark(GAP_VERSION)
        elif code in (_BLOCKER_COMPONENT, _BLOCKER_PLUGIN):
            mark(GAP_COMPONENT_IDENTITY)
        elif code == _BLOCKER_PARAMETER:
            mark(GAP_PARAMETER)
        elif code == _BLOCKER_TECHNOLOGY:
            mark(GAP_TECHNOLOGY)

    if _SOURCE_VERSION_UNRESOLVED in negative:
        mark(GAP_VERSION)
    if _SOURCE_INFERRED_UNSCOPED in negative:
        mark(GAP_SCOPE)
    if provenance == "INFERRED" and scope in ("GLOBAL", "NONE"):
        mark(GAP_SCOPE)

    source_gaps = block.get("evidence_gaps")
    if isinstance(source_gaps, (list, tuple)):
        for line in list(source_gaps)[:MAX_GAP_LINES]:
            text = _text(line).lower()
            if not text:
                continue
            for prefix, gap in _GAP_PREFIXES:
                if text.startswith(prefix):
                    mark(gap)
                    break

    if _upper(strongest_match_type) == "TECHNOLOGY":
        mark(GAP_TECHNOLOGY)

    selected = GAP_NONE
    for gap in _GAP_PRECEDENCE:
        if gap in detected:
            selected = gap
            break
    return detected, selected


def _sanitized_order_key(value: object) -> list:
    if not isinstance(value, (list, tuple)):
        return []
    out: list = []
    for item in value:
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            out.append(item)
        else:
            out.append(_safe_text(item))
        if len(out) >= MAX_ORDER_KEY:
            break
    return out


def _result(
    action: str,
    *,
    hunt_priority: dict,
    hunt_actionability: dict,
    reason_codes: list[str],
    evidence_gap: str,
    effort: str,
    confidence: str,
) -> dict:
    """Compose the bounded, deterministic action-plan projection."""

    codes: list[str] = []
    for code in reason_codes:
        if code and code not in codes:
            codes.append(code)
    secondary = _sanitized_order_key(
        hunt_actionability.get("action_order_key")
    )
    if not secondary:
        secondary = _sanitized_order_key(
            hunt_priority.get("tie_break_key")
        )
    rank = ACTION_RANKS[action]
    return {
        "rule_version": HUNT_ACTION_PLANNER_RULE_VERSION,
        "action": action,
        "action_rank": rank,
        "reason_codes": codes[:MAX_REASON_CODES],
        "reason": _ACTION_REASON[action],
        "source_actionability": _upper(
            hunt_actionability.get("actionability")
        ),
        "source_priority": _upper(hunt_priority.get("priority")),
        "source_hunt_score": _coerce_int(
            hunt_priority.get("hunt_score"), 0
        ),
        "source_rule_versions": {
            "hunt_priority": _safe_text(
                hunt_priority.get("rule_version")
            ),
            "hunt_actionability": _safe_text(
                hunt_actionability.get("rule_version")
            ),
        },
        "evidence_gap": evidence_gap,
        "estimated_effort": effort,
        "confidence": confidence,
        "action_order_key": [rank] + secondary,
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_hunt_action(
    hunt_priority: object = None,
    hunt_actionability: object = None,
    *,
    evidence_provenance: object = None,
    support_scope: object = None,
    strongest_match_type: object = None,
) -> dict:
    """Select the smallest useful next research action for one candidate.

    ``hunt_priority`` is the R31.10 result dict and ``hunt_actionability`` the
    R31.11 result dict; both are consumed read-only. ``evidence_provenance``,
    ``support_scope`` and ``strongest_match_type`` are optional explicit
    R31.5/R30.1 hints already available in the research pipeline. Absent
    hints never create a gap.
    """

    hp_block = _block(hunt_priority)
    ha_block = _block(hunt_actionability)
    state = _upper(ha_block.get("actionability"))

    # 1. Terminal blockers (either projection) are never overridden.
    if state == ACTIONABILITY_BLOCKED or bool(hp_block.get("blocked")):
        return _result(
            RESOLVE_BLOCKERS,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            reason_codes=[REASON_SOURCE_BLOCKED],
            evidence_gap=GAP_NONE,
            effort=EFFORT_UNKNOWN,
            confidence=CONFIDENCE_HIGH,
        )

    if not state:
        return _result(
            DEFER,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            reason_codes=[REASON_MISSING_ACTIONABILITY],
            evidence_gap=GAP_NONE,
            effort=EFFORT_UNKNOWN,
            confidence=CONFIDENCE_LOW,
        )

    # 2. Low value is terminal for planning.
    if state == ACTIONABILITY_LOW_VALUE:
        return _result(
            DEFER,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            reason_codes=[REASON_SOURCE_LOW_VALUE],
            evidence_gap=GAP_NONE,
            effort=EFFORT_UNKNOWN,
            confidence=CONFIDENCE_HIGH,
        )

    positive, negative = _signal_codes(hp_block)
    provenance = _resolve_provenance(
        hp_block, evidence_provenance, positive, negative
    )
    scope = _upper(support_scope)
    detected, selected = _detect_gaps(
        hp_block,
        negative,
        provenance=provenance,
        scope=scope,
        strongest_match_type=strongest_match_type,
    )

    # 3. Immediate verification: verify with the existing evidence.
    if state == ACTIONABILITY_IMMEDIATE:
        if provenance == "EXPLICIT":
            return _result(
                VERIFY_EXISTING_EVIDENCE,
                hunt_priority=hp_block,
                hunt_actionability=ha_block,
                reason_codes=[REASON_SOURCE_IMMEDIATE],
                evidence_gap=GAP_NONE,
                effort=EFFORT_LOW,
                confidence=CONFIDENCE_HIGH,
            )
        # Defensive downgrade: non-explicit provenance can never become
        # explicit verification. Prefer an explicit gap, else target the
        # inferred identity or its missing scope.
        code = (
            REASON_INFERRED_PROVENANCE
            if provenance == "INFERRED"
            else REASON_NON_EXPLICIT_PROVENANCE
        )
        if selected == GAP_NONE:
            if provenance == "INFERRED" and scope in ("GLOBAL", "NONE"):
                selected = GAP_SCOPE
            else:
                selected = GAP_COMPONENT_IDENTITY
        return _result(
            _GAP_ACTION[selected],
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            reason_codes=[
                REASON_SOURCE_IMMEDIATE, code, selected,
            ],
            evidence_gap=selected,
            effort=EFFORT_MEDIUM,
            confidence=CONFIDENCE_MEDIUM,
        )

    # 4./5. Strong manual review / supporting context: select the strongest
    # explicit gap, else generic manual review.
    if state in (ACTIONABILITY_STRONG, ACTIONABILITY_SUPPORTING):
        source_code = _STATE_REASON_CODES[state]
        if selected == GAP_NONE:
            return _result(
                MANUAL_REVIEW,
                hunt_priority=hp_block,
                hunt_actionability=ha_block,
                reason_codes=[source_code, REASON_NO_EXPLICIT_GAP],
                evidence_gap=GAP_NONE,
                effort=EFFORT_HIGH,
                confidence=CONFIDENCE_LOW,
            )
        codes = [source_code, selected]
        if len(detected) > 1:
            codes.append(REASON_MULTIPLE_GAPS)
        return _result(
            _GAP_ACTION[selected],
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            reason_codes=codes,
            evidence_gap=selected,
            effort=_EFFORT_BY_ACTION[_GAP_ACTION[selected]],
            confidence=(
                CONFIDENCE_HIGH
                if len(detected) == 1
                else CONFIDENCE_MEDIUM
            ),
        )

    # Defensive: an unrecognised actionability state can only defer.
    return _result(
        DEFER,
        hunt_priority=hp_block,
        hunt_actionability=ha_block,
        reason_codes=[REASON_UNRECOGNIZED_ACTIONABILITY],
        evidence_gap=GAP_NONE,
        effort=EFFORT_UNKNOWN,
        confidence=CONFIDENCE_LOW,
    )


__all__ = [
    "HUNT_ACTION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "HUNT_ACTIONS",
    "ACTION_RANKS",
    "EVIDENCE_GAPS",
    "REASON_CODES",
    "ESTIMATED_EFFORTS",
    "PLAN_CONFIDENCES",
    "VERIFY_EXISTING_EVIDENCE",
    "VERIFY_VERSION",
    "VERIFY_COMPONENT_IDENTITY",
    "VERIFY_SCOPE",
    "VERIFY_PATH",
    "VERIFY_PARAMETER",
    "COLLECT_HTTP_EVIDENCE",
    "COLLECT_TECHNOLOGY_EVIDENCE",
    "MANUAL_REVIEW",
    "DEFER",
    "RESOLVE_BLOCKERS",
    "GAP_VERSION",
    "GAP_COMPONENT_IDENTITY",
    "GAP_SCOPE",
    "GAP_PATH",
    "GAP_PARAMETER",
    "GAP_HTTP",
    "GAP_TECHNOLOGY",
    "GAP_NONE",
    "EFFORT_LOW",
    "EFFORT_MEDIUM",
    "EFFORT_HIGH",
    "EFFORT_UNKNOWN",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_LOW",
    "MAX_REASON_CODES",
    "plan_hunt_action",
]
