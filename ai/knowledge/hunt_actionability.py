"""Stage R31.11 deterministic hunt actionability classification (pure engine).

Consumes the read-only R31.10 evidence-aware hunt priority output for one
Asset<->CVE research candidate and projects a stable, bounded action-ordering
signal for a human bug-bounty researcher:

    "Of the candidates R31.10 already ranked, which are immediately
     verification-ready, which need strong manual review, which are only
     supporting context, which are low value, and which are terminally
     blocked?"

This is an **ordering/actionability refinement only**. It never rescoring,
never replaces the R31.10 priority/score, never replaces the R29 personal
hunt queue, the R25.2 Money Score, the R26 opportunity class or the R30.1
confidence, and never creates a 5J finding.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no persistence, no execution.
- Additive and read-only: the R31.10 input dict is never mutated; the result
  is a new dict with a new rule version (``r31-11``).
- Downgrade-only: R31.10 priority is consumed as the authoritative ordering
  signal and can only be narrowed (never raised). Weak/inferred evidence can
  never become a confirmation or an immediate-verification candidate.
- Terminal blockers preserved: any R31.10 ``blocked`` candidate is
  classified ``BLOCKED`` before any refinement; blocker codes are copied
  read-only and never overridden.
- Deterministic: fixed closed vocabularies, documented reason codes and a
  stable ``action_order_key`` (R31.10 tie-break key preserved as the
  secondary key); identical evidence always classifies and sorts identically.
- Privacy: only closed reason codes, bounded counts and sanitised text are
  retained; raw URLs, query values, headers, cookies, tokens and secrets are
  never copied.
"""

from __future__ import annotations

import re

ACTIONABILITY_RULE_VERSION = "r31-11"
HUNT_ACTIONABILITY_RULE_VERSION = ACTIONABILITY_RULE_VERSION
RULE_VERSION = ACTIONABILITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

IMMEDIATE_VERIFICATION = "IMMEDIATE_VERIFICATION"
STRONG_MANUAL_REVIEW = "STRONG_MANUAL_REVIEW"
SUPPORTING_CONTEXT = "SUPPORTING_CONTEXT"
LOW_VALUE_DEFERRED = "LOW_VALUE_DEFERRED"
BLOCKED = "BLOCKED"

HUNT_ACTIONABILITY_STATES: tuple[str, ...] = (
    IMMEDIATE_VERIFICATION,
    STRONG_MANUAL_REVIEW,
    SUPPORTING_CONTEXT,
    LOW_VALUE_DEFERRED,
    BLOCKED,
)

# Ascending action order: strongest actionable first, terminal last.
ACTIONABILITY_RANKS: dict[str, int] = {
    IMMEDIATE_VERIFICATION: 0,
    STRONG_MANUAL_REVIEW: 1,
    SUPPORTING_CONTEXT: 2,
    LOW_VALUE_DEFERRED: 3,
    BLOCKED: 4,
}

# Closed next-action vocabulary (advisory labels only; nothing is executed).
NEXT_ACTIONS: dict[str, str] = {
    IMMEDIATE_VERIFICATION: "VERIFY_WITH_EXISTING_EVIDENCE",
    STRONG_MANUAL_REVIEW: "MANUAL_REVIEW",
    SUPPORTING_CONTEXT: "COLLECT_MORE_EVIDENCE",
    LOW_VALUE_DEFERRED: "DEFER",
    BLOCKED: "RESOLVE_BLOCKERS_FIRST",
}

# Reason codes (closed, machine-readable explanation vocabulary).
REASON_SOURCE_BLOCKED = "SOURCE_BLOCKED"
REASON_PRIORITY_P0 = "PRIORITY_P0"
REASON_PRIORITY_P1 = "PRIORITY_P1"
REASON_PRIORITY_P2 = "PRIORITY_P2"
REASON_PRIORITY_P3 = "PRIORITY_P3"
REASON_PRIORITY_DEFER = "PRIORITY_DEFER"
REASON_MISSING_SIGNAL = "MISSING_PRIORITY_SIGNAL"
REASON_UNRECOGNIZED_PRIORITY = "UNRECOGNIZED_PRIORITY"
REASON_VERIFICATION_READY = "VERIFICATION_READY"
REASON_MANUAL_REVIEW = "MANUAL_REVIEW_REQUIRED"
REASON_CONTEXT_ONLY = "CONTEXT_ONLY"
REASON_LOW_VALUE = "LOW_VALUE"
REASON_QUALITY_NOT_HIGH = "EVIDENCE_QUALITY_NOT_HIGH"
REASON_EVIDENCE_INCONSISTENT = "EVIDENCE_INCONSISTENT"
REASON_REMAINING_BLOCKERS = "REMAINING_BLOCKERS_PRESENT"
REASON_INFERRED_PROVENANCE = "INFERRED_PROVENANCE"
REASON_MIXED_PROVENANCE = "MIXED_PROVENANCE"
REASON_PROVENANCE_UNCONFIRMED = "PROVENANCE_UNCONFIRMED"
REASON_NO_STRONG_ANCHOR = "NO_STRONG_ANCHOR"

REASON_CODES: tuple[str, ...] = (
    REASON_SOURCE_BLOCKED,
    REASON_PRIORITY_P0,
    REASON_PRIORITY_P1,
    REASON_PRIORITY_P2,
    REASON_PRIORITY_P3,
    REASON_PRIORITY_DEFER,
    REASON_MISSING_SIGNAL,
    REASON_UNRECOGNIZED_PRIORITY,
    REASON_VERIFICATION_READY,
    REASON_MANUAL_REVIEW,
    REASON_CONTEXT_ONLY,
    REASON_LOW_VALUE,
    REASON_QUALITY_NOT_HIGH,
    REASON_EVIDENCE_INCONSISTENT,
    REASON_REMAINING_BLOCKERS,
    REASON_INFERRED_PROVENANCE,
    REASON_MIXED_PROVENANCE,
    REASON_PROVENANCE_UNCONFIRMED,
    REASON_NO_STRONG_ANCHOR,
)

# R31.10 reason codes consumed read-only for provenance/anchor refinement.
_SOURCE_INFERRED_UNSCOPED = "INFERRED_UNSCOPED_IDENTITY"
_SOURCE_EXPLICIT_PROVENANCE = "EXPLICIT_PROVENANCE"
_SOURCE_MIXED_PROVENANCE = "MIXED_PROVENANCE"
_SOURCE_COMPONENT_SCOPED = "COMPONENT_SCOPED_SUPPORT"
_SOURCE_EXACT_VERSION = "EXACT_VERSION_MATCH"
_SOURCE_EXACT_PATH = "EXACT_PATH_MATCH"

_PRIORITY_CODES: dict[str, str] = {
    "P0": REASON_PRIORITY_P0,
    "P1": REASON_PRIORITY_P1,
    "P2": REASON_PRIORITY_P2,
    "P3": REASON_PRIORITY_P3,
    "DEFER": REASON_PRIORITY_DEFER,
}

_BASE_STATE_BY_PRIORITY: dict[str, str] = {
    "P0": IMMEDIATE_VERIFICATION,
    "P1": STRONG_MANUAL_REVIEW,
    "P2": SUPPORTING_CONTEXT,
    "P3": LOW_VALUE_DEFERRED,
    "DEFER": LOW_VALUE_DEFERRED,
}

_STATE_CODES: dict[str, str] = {
    IMMEDIATE_VERIFICATION: REASON_VERIFICATION_READY,
    STRONG_MANUAL_REVIEW: REASON_MANUAL_REVIEW,
    SUPPORTING_CONTEXT: REASON_CONTEXT_ONLY,
    LOW_VALUE_DEFERRED: REASON_LOW_VALUE,
    BLOCKED: REASON_SOURCE_BLOCKED,
}

_REASON_TEXT: dict[str, str] = {
    IMMEDIATE_VERIFICATION: (
        "highest-confidence actionable candidate; verification-ready under"
        " the existing evidence"
    ),
    STRONG_MANUAL_REVIEW: (
        "strong candidate that requires manual review before verification"
    ),
    SUPPORTING_CONTEXT: (
        "supporting/manual-context candidate; not yet a verification target"
    ),
    LOW_VALUE_DEFERRED: (
        "low-value or insufficiently anchored candidate; deferred"
    ),
    BLOCKED: "terminal blocker present; not actionable until resolved",
}

MAX_REASON_CODES = 8
MAX_SOURCE_CODES = 8
MAX_ORDER_KEY = 16
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


def _bounded_strings(values: object, limit: int) -> list[str]:
    out: list[str] = []
    for value in values or ():
        text = _safe_text(value)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _signal_codes(block: dict) -> tuple[set[str], set[str]]:
    """Read R31.10 adjustment/reason codes as positive/negative sets.

    ``adjustments`` is authoritative when present; the rendered
    positive/negative reason strings are a read-only fallback so a trimmed
    R31.10 projection still classifies deterministically.
    """

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


def _provenance_signal(
    block: dict,
    explicit: object,
    positive: set[str],
    negative: set[str],
) -> str:
    """Resolve the observed-vs-inferred provenance signal (read-only)."""

    if _text(explicit):
        return _upper(explicit)
    if _SOURCE_INFERRED_UNSCOPED in negative:
        return "INFERRED"
    if _SOURCE_EXPLICIT_PROVENANCE in positive:
        return "EXPLICIT"
    if _SOURCE_MIXED_PROVENANCE in positive:
        return "MIXED"
    return "UNKNOWN"


def _has_strong_anchor(
    positive: set[str], scope: str
) -> bool:
    """A strong anchor is component-scoped support, an exact observed version
    match or an exact observed path match; family/range version matches alone
    are not enough for immediate verification."""

    if scope == "COMPONENT_SCOPED":
        return True
    return any(
        code in positive
        for code in (
            _SOURCE_COMPONENT_SCOPED,
            _SOURCE_EXACT_VERSION,
            _SOURCE_EXACT_PATH,
        )
    )


def _immediate_downgrades(
    block: dict,
    positive: set[str],
    provenance: str,
    scope: str,
) -> list[str]:
    """Deterministic guards that block IMMEDIATE_VERIFICATION (downgrade)."""

    codes: list[str] = []
    if _upper(block.get("evidence_quality")) != "HIGH":
        codes.append(REASON_QUALITY_NOT_HIGH)
    if _upper(block.get("evidence_consistency")) != "CONSISTENT":
        codes.append(REASON_EVIDENCE_INCONSISTENT)
    remaining = block.get("remaining_blocker_codes")
    if isinstance(remaining, (list, tuple)) and remaining:
        codes.append(REASON_REMAINING_BLOCKERS)
    if provenance == "INFERRED":
        codes.append(REASON_INFERRED_PROVENANCE)
    elif provenance == "MIXED":
        codes.append(REASON_MIXED_PROVENANCE)
    elif provenance != "EXPLICIT":
        codes.append(REASON_PROVENANCE_UNCONFIRMED)
    if not _has_strong_anchor(positive, scope):
        codes.append(REASON_NO_STRONG_ANCHOR)
    return codes


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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
    state: str,
    block: dict,
    reason_codes: list[str],
) -> dict:
    """Compose the bounded, deterministic actionability projection."""

    priority = _upper(block.get("priority"))
    codes: list[str] = []
    for code in reason_codes:
        if code and code not in codes:
            codes.append(code)
    rank = ACTIONABILITY_RANKS[state]
    source_remaining = block.get("remaining_blocker_codes")
    return {
        "rule_version": ACTIONABILITY_RULE_VERSION,
        "actionability": state,
        "actionability_rank": rank,
        "next_action": NEXT_ACTIONS[state],
        "blocked": bool(block.get("blocked")),
        "source_priority": priority,
        "source_priority_rank": _coerce_int(
            block.get("priority_rank"), -1
        ),
        "source_hunt_score": _coerce_int(block.get("hunt_score"), 0),
        "source_evidence_quality": _upper(
            block.get("evidence_quality")
        ),
        "source_evidence_consistency": _upper(
            block.get("evidence_consistency")
        ),
        "source_rule_version": _safe_text(block.get("rule_version")),
        "source_reason": _safe_text(block.get("reason")),
        "source_blocking_reasons": _bounded_strings(
            block.get("blocking_reasons"), MAX_SOURCE_CODES
        ),
        "source_remaining_blockers": _bounded_strings(
            source_remaining if isinstance(source_remaining, (list, tuple))
            else (),
            MAX_SOURCE_CODES,
        ),
        "reason_codes": codes[:MAX_REASON_CODES],
        "reason": _REASON_TEXT[state],
        "action_order_key": [rank]
        + _sanitized_order_key(block.get("tie_break_key")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_hunt_actionability(
    hunt_priority: object = None,
    *,
    evidence_provenance: object = None,
    support_scope: object = None,
) -> dict:
    """Classify one R31.10 hunt-priority projection (read-only, additive).

    ``hunt_priority`` is the R31.10 result dict. ``evidence_provenance`` and
    ``support_scope`` are optional read-only R31.5 signals already consumed by
    R31.10; when omitted, provenance is resolved from the R31.10 reason codes
    and unknown provenance can never reach IMMEDIATE_VERIFICATION.
    """

    block = _block(hunt_priority)
    if not block or not _text(block.get("priority")):
        return _result(
            LOW_VALUE_DEFERRED,
            block,
            [REASON_MISSING_SIGNAL, REASON_LOW_VALUE],
        )

    priority = _upper(block.get("priority"))
    positive, negative = _signal_codes(block)
    provenance = _provenance_signal(
        block, evidence_provenance, positive, negative
    )
    scope = _upper(support_scope)

    # Terminal blockers are consumed first and never overridden.
    if bool(block.get("blocked")):
        return _result(BLOCKED, block, [REASON_SOURCE_BLOCKED])

    base_state = _BASE_STATE_BY_PRIORITY.get(priority)
    if base_state is None:
        return _result(
            LOW_VALUE_DEFERRED,
            block,
            [REASON_UNRECOGNIZED_PRIORITY, REASON_LOW_VALUE],
        )

    priority_code = _PRIORITY_CODES[priority]
    if base_state == IMMEDIATE_VERIFICATION:
        downgrades = _immediate_downgrades(
            block, positive, provenance, scope
        )
        if downgrades:
            return _result(
                STRONG_MANUAL_REVIEW,
                block,
                [priority_code] + downgrades + [REASON_MANUAL_REVIEW],
            )
        return _result(
            IMMEDIATE_VERIFICATION,
            block,
            [priority_code, REASON_VERIFICATION_READY],
        )

    if base_state == STRONG_MANUAL_REVIEW:
        return _result(
            STRONG_MANUAL_REVIEW,
            block,
            [priority_code, REASON_MANUAL_REVIEW],
        )
    if base_state == SUPPORTING_CONTEXT:
        return _result(
            SUPPORTING_CONTEXT,
            block,
            [priority_code, REASON_CONTEXT_ONLY],
        )
    return _result(
        LOW_VALUE_DEFERRED,
        block,
        [priority_code, REASON_LOW_VALUE],
    )


__all__ = [
    "ACTIONABILITY_RULE_VERSION",
    "HUNT_ACTIONABILITY_RULE_VERSION",
    "RULE_VERSION",
    "HUNT_ACTIONABILITY_STATES",
    "ACTIONABILITY_RANKS",
    "NEXT_ACTIONS",
    "REASON_CODES",
    "IMMEDIATE_VERIFICATION",
    "STRONG_MANUAL_REVIEW",
    "SUPPORTING_CONTEXT",
    "LOW_VALUE_DEFERRED",
    "BLOCKED",
    "MAX_REASON_CODES",
    "REASON_SOURCE_BLOCKED",
    "REASON_PRIORITY_P0",
    "REASON_PRIORITY_P1",
    "REASON_PRIORITY_P2",
    "REASON_PRIORITY_P3",
    "REASON_PRIORITY_DEFER",
    "REASON_MISSING_SIGNAL",
    "REASON_UNRECOGNIZED_PRIORITY",
    "REASON_VERIFICATION_READY",
    "REASON_MANUAL_REVIEW",
    "REASON_CONTEXT_ONLY",
    "REASON_LOW_VALUE",
    "REASON_QUALITY_NOT_HIGH",
    "REASON_EVIDENCE_INCONSISTENT",
    "REASON_REMAINING_BLOCKERS",
    "REASON_INFERRED_PROVENANCE",
    "REASON_MIXED_PROVENANCE",
    "REASON_PROVENANCE_UNCONFIRMED",
    "REASON_NO_STRONG_ANCHOR",
    "evaluate_hunt_actionability",
]
