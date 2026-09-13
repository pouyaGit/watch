"""Stage R31.13 deterministic evidence acquisition planner (pure engine).

Consumes the read-only R31.10 hunt priority, R31.11 hunt actionability and
R31.12 hunt action plan projections for one Asset<->CVE research candidate and
projects the smallest safe *evidence acquisition* step that would close the
gap R31.12 already selected:

    "What evidence is missing, what minimum evidence type would close the
     selected gap, what safe research method could acquire it, and what
     completion condition would mean the gap is addressed?"

This is a **planning signal only, and it is plan-only**. It never executes the
acquisition method, never contacts a target, never scans, never runs Nuclei,
never crawls, never fuzzes, never exploits, never calls an LLM and never
renders a probability, exploitability, severity, CVSS or payout judgement.
It contains no payloads, exploit strings, fuzzing dictionaries, scanner
commands, Nuclei templates, request bodies, bypass techniques or
exploitation sequences. It describes *what evidence is needed*, never *how to
attack*.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no Mongo, no persistence, no
  execution.
- Additive and read-only: the R31.10/R31.11/R31.12 input dicts are never
  mutated; the result is a new dict with rule version ``r31-13``.
- No recomputation: R31.10 priority/score, the R31.11 state and the R31.12
  selected action/gap are consumed verbatim. The planner never re-derives a
  priority, an actionability state, an action or an evidence gap. R31.12
  remains the only source of truth for the selected gap.
- Terminal-first: ``BLOCKED`` (either projection) and ``LOW_VALUE_DEFERRED``
  are terminal; a terminal R31.12 action (``RESOLVE_BLOCKERS``/``DEFER``) is
  terminal for acquisition planning.
- Defensive conflict handling: a known R31.12 action whose ``evidence_gap``
  does not match the gap that action selects yields a deterministic ``NONE``
  plan with ``ACTION_PLAN_CONFLICT``; malformed upstream data is never
  silently reinterpreted.
- Deterministic: closed method/target/gap/completion/effort/confidence/reason
  vocabularies, documented first-match rules and a stable
  ``acquisition_order_key`` that preserves the R31.12 key as its secondary
  ordering. No randomness, timestamps, hashes or external state.
- Privacy: only closed codes, bounded counts and sanitised text are retained;
  raw URLs, credentials, tokens, headers, query values and arbitrary source
  text are never copied.
"""

from __future__ import annotations

import re

from ai.knowledge.hunt_action_planner import (
    COLLECT_HTTP_EVIDENCE,
    COLLECT_TECHNOLOGY_EVIDENCE,
    DEFER,
    GAP_COMPONENT_IDENTITY,
    GAP_HTTP,
    GAP_NONE,
    GAP_PARAMETER,
    GAP_PATH,
    GAP_SCOPE,
    GAP_TECHNOLOGY,
    GAP_VERSION,
    HUNT_ACTIONS,
    MANUAL_REVIEW,
    RESOLVE_BLOCKERS,
    VERIFY_COMPONENT_IDENTITY,
    VERIFY_EXISTING_EVIDENCE,
    VERIFY_PARAMETER,
    VERIFY_PATH,
    VERIFY_SCOPE,
    VERIFY_VERSION,
)
from ai.knowledge.hunt_actionability import (
    BLOCKED as ACTIONABILITY_BLOCKED,
    IMMEDIATE_VERIFICATION as ACTIONABILITY_IMMEDIATE,
    LOW_VALUE_DEFERRED as ACTIONABILITY_LOW_VALUE,
)

EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION = "r31-13"
RULE_VERSION = EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed acquisition-method vocabulary
# ---------------------------------------------------------------------------

EXISTING_EVIDENCE_REVIEW = "EXISTING_EVIDENCE_REVIEW"
VERSION_LOOKUP = "VERSION_LOOKUP"
COMPONENT_IDENTITY_LOOKUP = "COMPONENT_IDENTITY_LOOKUP"
SCOPE_EVIDENCE_REVIEW = "SCOPE_EVIDENCE_REVIEW"
PATH_EVIDENCE_REVIEW = "PATH_EVIDENCE_REVIEW"
PARAMETER_EVIDENCE_REVIEW = "PARAMETER_EVIDENCE_REVIEW"
HTTP_BEHAVIOR_REVIEW = "HTTP_BEHAVIOR_REVIEW"
TECHNOLOGY_EVIDENCE_REVIEW = "TECHNOLOGY_EVIDENCE_REVIEW"
MANUAL_RESEARCH = "MANUAL_RESEARCH"
NO_ACQUISITION = "NONE"

ACQUISITION_METHODS: tuple[str, ...] = (
    EXISTING_EVIDENCE_REVIEW,
    VERSION_LOOKUP,
    COMPONENT_IDENTITY_LOOKUP,
    SCOPE_EVIDENCE_REVIEW,
    PATH_EVIDENCE_REVIEW,
    PARAMETER_EVIDENCE_REVIEW,
    HTTP_BEHAVIOR_REVIEW,
    TECHNOLOGY_EVIDENCE_REVIEW,
    MANUAL_RESEARCH,
    NO_ACQUISITION,
)

# Ascending acquisition order (review-only first, no-acquisition last).
ACQUISITION_RANKS: dict[str, int] = {
    EXISTING_EVIDENCE_REVIEW: 0,
    VERSION_LOOKUP: 1,
    COMPONENT_IDENTITY_LOOKUP: 2,
    SCOPE_EVIDENCE_REVIEW: 3,
    PATH_EVIDENCE_REVIEW: 4,
    PARAMETER_EVIDENCE_REVIEW: 5,
    HTTP_BEHAVIOR_REVIEW: 6,
    TECHNOLOGY_EVIDENCE_REVIEW: 7,
    MANUAL_RESEARCH: 8,
    NO_ACQUISITION: 9,
}

# ---------------------------------------------------------------------------
# Closed evidence-target vocabulary
# ---------------------------------------------------------------------------

TARGET_VERSION = "VERSION"
TARGET_COMPONENT_IDENTITY = "COMPONENT_IDENTITY"
TARGET_SCOPE = "SCOPE"
TARGET_PATH = "PATH"
TARGET_PARAMETER = "PARAMETER"
TARGET_HTTP_BEHAVIOR = "HTTP_BEHAVIOR"
TARGET_TECHNOLOGY = "TECHNOLOGY"
TARGET_EXISTING_EVIDENCE = "EXISTING_EVIDENCE"
TARGET_NONE = "NONE"

EVIDENCE_TARGETS: tuple[str, ...] = (
    TARGET_VERSION,
    TARGET_COMPONENT_IDENTITY,
    TARGET_SCOPE,
    TARGET_PATH,
    TARGET_PARAMETER,
    TARGET_HTTP_BEHAVIOR,
    TARGET_TECHNOLOGY,
    TARGET_EXISTING_EVIDENCE,
    TARGET_NONE,
)

# ---------------------------------------------------------------------------
# Closed completion-condition vocabulary (fixed deterministic labels)
# ---------------------------------------------------------------------------

CONDITION_BLOCKERS_RESOLVED = "BLOCKERS_RESOLVED_BEFORE_RESEARCH"
CONDITION_REACTIVATE = "REACTIVATE_ONLY_IF_PRIORITY_CHANGES"
CONDITION_EXISTING_REVIEWED = "EXISTING_EVIDENCE_REVIEWED"
CONDITION_VERSION_ESTABLISHED = (
    "VERSION_COMPATIBILITY_EXPLICITLY_ESTABLISHED"
)
CONDITION_IDENTITY_ESTABLISHED = (
    "COMPONENT_IDENTITY_EXPLICITLY_ESTABLISHED"
)
CONDITION_SCOPE_ESTABLISHED = "EVIDENCE_SCOPE_EXPLICITLY_ESTABLISHED"
CONDITION_PATH_ESTABLISHED = "PATH_RELEVANCE_EXPLICITLY_ESTABLISHED"
CONDITION_PARAMETER_ESTABLISHED = (
    "PARAMETER_RELEVANCE_EXPLICITLY_ESTABLISHED"
)
CONDITION_HTTP_ESTABLISHED = (
    "RELEVANT_HTTP_BEHAVIOR_EVIDENCE_ESTABLISHED"
)
CONDITION_TECHNOLOGY_ESTABLISHED = (
    "TECHNOLOGY_RELATIONSHIP_EXPLICITLY_ESTABLISHED"
)
CONDITION_MANUAL_COMPLETED = "HUMAN_RESEARCH_COMPLETED"
CONDITION_REQUIRES_ACTION_PLAN = "REQUIRES_VALID_ACTION_PLAN"

COMPLETION_CONDITIONS: tuple[str, ...] = (
    CONDITION_BLOCKERS_RESOLVED,
    CONDITION_REACTIVATE,
    CONDITION_EXISTING_REVIEWED,
    CONDITION_VERSION_ESTABLISHED,
    CONDITION_IDENTITY_ESTABLISHED,
    CONDITION_SCOPE_ESTABLISHED,
    CONDITION_PATH_ESTABLISHED,
    CONDITION_PARAMETER_ESTABLISHED,
    CONDITION_HTTP_ESTABLISHED,
    CONDITION_TECHNOLOGY_ESTABLISHED,
    CONDITION_MANUAL_COMPLETED,
    CONDITION_REQUIRES_ACTION_PLAN,
)

# ---------------------------------------------------------------------------
# Closed reason-code vocabulary
# ---------------------------------------------------------------------------

REASON_SOURCE_BLOCKED = "SOURCE_BLOCKED"
REASON_SOURCE_DEFERRED = "SOURCE_DEFERRED"
REASON_SOURCE_IMMEDIATE = "SOURCE_IMMEDIATE"
REASON_SOURCE_ACTION = "SOURCE_ACTION"
REASON_NO_ACQUISITION_REQUIRED = "NO_ACQUISITION_REQUIRED"
REASON_ACTION_PLAN_CONFLICT = "ACTION_PLAN_CONFLICT"
REASON_ACTION_PLAN_MISSING = "ACTION_PLAN_MISSING"
REASON_UNKNOWN_ACTION = "UNKNOWN_ACTION"

REASON_CODES: tuple[str, ...] = (
    REASON_SOURCE_BLOCKED,
    REASON_SOURCE_DEFERRED,
    REASON_SOURCE_IMMEDIATE,
    REASON_SOURCE_ACTION,
    REASON_NO_ACQUISITION_REQUIRED,
    REASON_ACTION_PLAN_CONFLICT,
    REASON_ACTION_PLAN_MISSING,
    REASON_UNKNOWN_ACTION,
) + (
    GAP_VERSION,
    GAP_COMPONENT_IDENTITY,
    GAP_SCOPE,
    GAP_PATH,
    GAP_PARAMETER,
    GAP_HTTP,
    GAP_TECHNOLOGY,
)

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

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"

ACQUISITION_CONFIDENCES: tuple[str, ...] = (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
)

# ---------------------------------------------------------------------------
# Deterministic action -> acquisition mapping (R31.12 remains authoritative)
# ---------------------------------------------------------------------------

_ACTION_METHOD: dict[str, str] = {
    VERIFY_EXISTING_EVIDENCE: EXISTING_EVIDENCE_REVIEW,
    VERIFY_VERSION: VERSION_LOOKUP,
    VERIFY_COMPONENT_IDENTITY: COMPONENT_IDENTITY_LOOKUP,
    VERIFY_SCOPE: SCOPE_EVIDENCE_REVIEW,
    VERIFY_PATH: PATH_EVIDENCE_REVIEW,
    VERIFY_PARAMETER: PARAMETER_EVIDENCE_REVIEW,
    COLLECT_HTTP_EVIDENCE: HTTP_BEHAVIOR_REVIEW,
    COLLECT_TECHNOLOGY_EVIDENCE: TECHNOLOGY_EVIDENCE_REVIEW,
    MANUAL_REVIEW: MANUAL_RESEARCH,
}

_ACTION_TARGET: dict[str, str] = {
    VERIFY_EXISTING_EVIDENCE: TARGET_EXISTING_EVIDENCE,
    VERIFY_VERSION: TARGET_VERSION,
    VERIFY_COMPONENT_IDENTITY: TARGET_COMPONENT_IDENTITY,
    VERIFY_SCOPE: TARGET_SCOPE,
    VERIFY_PATH: TARGET_PATH,
    VERIFY_PARAMETER: TARGET_PARAMETER,
    COLLECT_HTTP_EVIDENCE: TARGET_HTTP_BEHAVIOR,
    COLLECT_TECHNOLOGY_EVIDENCE: TARGET_TECHNOLOGY,
    MANUAL_REVIEW: TARGET_EXISTING_EVIDENCE,
}

# The single evidence gap each non-terminal R31.12 action must select. A
# mismatch is an upstream conflict and never silently reinterpreted.
_ACTION_GAP: dict[str, str] = {
    VERIFY_EXISTING_EVIDENCE: GAP_NONE,
    VERIFY_VERSION: GAP_VERSION,
    VERIFY_COMPONENT_IDENTITY: GAP_COMPONENT_IDENTITY,
    VERIFY_SCOPE: GAP_SCOPE,
    VERIFY_PATH: GAP_PATH,
    VERIFY_PARAMETER: GAP_PARAMETER,
    COLLECT_HTTP_EVIDENCE: GAP_HTTP,
    COLLECT_TECHNOLOGY_EVIDENCE: GAP_TECHNOLOGY,
    MANUAL_REVIEW: GAP_NONE,
}

_ACTION_CONDITION: dict[str, str] = {
    VERIFY_EXISTING_EVIDENCE: CONDITION_EXISTING_REVIEWED,
    VERIFY_VERSION: CONDITION_VERSION_ESTABLISHED,
    VERIFY_COMPONENT_IDENTITY: CONDITION_IDENTITY_ESTABLISHED,
    VERIFY_SCOPE: CONDITION_SCOPE_ESTABLISHED,
    VERIFY_PATH: CONDITION_PATH_ESTABLISHED,
    VERIFY_PARAMETER: CONDITION_PARAMETER_ESTABLISHED,
    COLLECT_HTTP_EVIDENCE: CONDITION_HTTP_ESTABLISHED,
    COLLECT_TECHNOLOGY_EVIDENCE: CONDITION_TECHNOLOGY_ESTABLISHED,
    MANUAL_REVIEW: CONDITION_MANUAL_COMPLETED,
}

_GAP_REASON: dict[str, str] = {
    GAP_VERSION: GAP_VERSION,
    GAP_COMPONENT_IDENTITY: GAP_COMPONENT_IDENTITY,
    GAP_SCOPE: GAP_SCOPE,
    GAP_PATH: GAP_PATH,
    GAP_PARAMETER: GAP_PARAMETER,
    GAP_HTTP: GAP_HTTP,
    GAP_TECHNOLOGY: GAP_TECHNOLOGY,
}

_METHOD_REASON: dict[str, str] = {
    EXISTING_EVIDENCE_REVIEW: (
        "review the evidence already collected; no new target interaction"
    ),
    VERSION_LOOKUP: (
        "acquire authoritative/public version information from an allowed"
        " research source"
    ),
    COMPONENT_IDENTITY_LOOKUP: (
        "acquire authoritative/public component/plugin/product identity"
        " information from an allowed research source"
    ),
    SCOPE_EVIDENCE_REVIEW: (
        "confirm the collected evidence belongs to the correct"
        " program/component scope"
    ),
    PATH_EVIDENCE_REVIEW: (
        "confirm the path/resource relationship using already collected"
        " evidence"
    ),
    PARAMETER_EVIDENCE_REVIEW: (
        "confirm parameter presence/relevance using already collected"
        " evidence"
    ),
    HTTP_BEHAVIOR_REVIEW: (
        "determine what HTTP behavior evidence would be needed for the gap"
    ),
    TECHNOLOGY_EVIDENCE_REVIEW: (
        "determine what technology evidence would establish the technology"
        " relationship"
    ),
    MANUAL_RESEARCH: (
        "no narrower acquisition method can be safely selected; human"
        " research is required"
    ),
    NO_ACQUISITION: (
        "no evidence acquisition is planned for this candidate"
    ),
}

# Static terminal/defensive reason labels (never copied from upstream text).
_NONE_REASON_BLOCKED = (
    "terminal blockers must be resolved before any evidence acquisition"
)
_NONE_REASON_DEFERRED = (
    "candidate is low-value/deferred; no evidence acquisition is planned"
)
_NONE_REASON_MISSING = (
    "a valid R31.12 action plan is required before acquisition planning"
)
_NONE_REASON_UNKNOWN = (
    "the R31.12 action is not recognized; no acquisition is planned"
)
_NONE_REASON_CONFLICT = (
    "the R31.12 action plan is inconsistent; no acquisition is planned"
)

# Deterministic fallbacks when the R31.12 confidence/effort is absent or
# outside the closed vocabulary (R31.12 values are consumed when valid).
_METHOD_CONFIDENCE: dict[str, str] = {
    EXISTING_EVIDENCE_REVIEW: CONFIDENCE_HIGH,
    VERSION_LOOKUP: CONFIDENCE_MEDIUM,
    COMPONENT_IDENTITY_LOOKUP: CONFIDENCE_MEDIUM,
    SCOPE_EVIDENCE_REVIEW: CONFIDENCE_MEDIUM,
    PATH_EVIDENCE_REVIEW: CONFIDENCE_MEDIUM,
    PARAMETER_EVIDENCE_REVIEW: CONFIDENCE_MEDIUM,
    HTTP_BEHAVIOR_REVIEW: CONFIDENCE_MEDIUM,
    TECHNOLOGY_EVIDENCE_REVIEW: CONFIDENCE_MEDIUM,
    MANUAL_RESEARCH: CONFIDENCE_LOW,
    NO_ACQUISITION: CONFIDENCE_LOW,
}

_METHOD_EFFORT: dict[str, str] = {
    EXISTING_EVIDENCE_REVIEW: EFFORT_LOW,
    VERSION_LOOKUP: EFFORT_MEDIUM,
    COMPONENT_IDENTITY_LOOKUP: EFFORT_MEDIUM,
    SCOPE_EVIDENCE_REVIEW: EFFORT_MEDIUM,
    PATH_EVIDENCE_REVIEW: EFFORT_LOW,
    PARAMETER_EVIDENCE_REVIEW: EFFORT_LOW,
    HTTP_BEHAVIOR_REVIEW: EFFORT_MEDIUM,
    TECHNOLOGY_EVIDENCE_REVIEW: EFFORT_MEDIUM,
    MANUAL_RESEARCH: EFFORT_HIGH,
    NO_ACQUISITION: EFFORT_UNKNOWN,
}

MAX_REASON_CODES = 8
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


def _block(value: object) -> dict:
    return value if isinstance(value, dict) else {}


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


def _codes(values: list[str]) -> list[str]:
    out: list[str] = []
    for code in values:
        if code and code not in out:
            out.append(code)
    return out[:MAX_REASON_CODES]


def _upstream_confidence(plan_block: dict, method: str) -> str:
    value = _upper(plan_block.get("confidence"))
    if value in ACQUISITION_CONFIDENCES:
        return value
    return _METHOD_CONFIDENCE[method]


def _upstream_effort(plan_block: dict, method: str) -> str:
    value = _upper(plan_block.get("estimated_effort"))
    if value in ESTIMATED_EFFORTS:
        return value
    return _METHOD_EFFORT[method]


# ---------------------------------------------------------------------------
# Result composition
# ---------------------------------------------------------------------------


def _result(
    method: str,
    *,
    hunt_priority: dict,
    hunt_actionability: dict,
    hunt_action_plan: dict,
    evidence_gap: str,
    evidence_target: str,
    completion_condition: str,
    reason_codes: list[str],
    reason: str,
    confidence: str,
    effort: str,
) -> dict:
    """Compose the bounded, deterministic acquisition-plan projection."""

    rank = ACQUISITION_RANKS[method]
    secondary = _sanitized_order_key(
        hunt_action_plan.get("action_order_key")
    )
    return {
        "rule_version": EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION,
        "acquisition_method": method,
        "acquisition_rank": rank,
        "evidence_target": evidence_target,
        "evidence_gap": evidence_gap,
        "completion_condition": completion_condition,
        "reason_codes": _codes(reason_codes),
        "reason": reason,
        "source_action": _upper(_safe_text(hunt_action_plan.get("action"))),
        "source_actionability": _upper(
            _safe_text(hunt_actionability.get("actionability"))
        ),
        "source_priority": _upper(
            _safe_text(hunt_priority.get("priority"))
        ),
        "source_hunt_score": _coerce_int(
            hunt_priority.get("hunt_score"), 0
        ),
        "confidence": confidence,
        "estimated_effort": effort,
        "acquisition_order_key": [rank] + secondary,
        "research_only": True,
    }


def _none_result(
    *,
    completion_condition: str,
    reason_codes: list[str],
    reason: str,
    confidence: str,
    effort: str,
    hunt_priority: dict,
    hunt_actionability: dict,
    hunt_action_plan: dict,
) -> dict:
    return _result(
        NO_ACQUISITION,
        hunt_priority=hunt_priority,
        hunt_actionability=hunt_actionability,
        hunt_action_plan=hunt_action_plan,
        evidence_gap=GAP_NONE,
        evidence_target=TARGET_NONE,
        completion_condition=completion_condition,
        reason_codes=reason_codes,
        reason=reason,
        confidence=confidence,
        effort=effort,
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def plan_evidence_acquisition(
    hunt_priority: object = None,
    hunt_actionability: object = None,
    hunt_action_plan: object = None,
    *,
    evidence_provenance: object = None,
    support_scope: object = None,
    strongest_match_type: object = None,
) -> dict:
    """Plan the smallest safe evidence acquisition for one candidate.

    ``hunt_priority`` is the R31.10 result dict, ``hunt_actionability`` the
    R31.11 result dict and ``hunt_action_plan`` the R31.12 result dict; all
    three are consumed read-only. R31.12's selected action is authoritative
    for the acquisition plan and its selected gap is never independently
    recomputed here.

    ``evidence_provenance``, ``support_scope`` and ``strongest_match_type``
    are optional read-only R31.5/R30.1 hints accepted for pipeline parity.
    Because R31.12 is the only gap selector in this pipeline, these hints can
    never change the acquisition plan or invent a gap.
    """

    hp_block = _block(hunt_priority)
    ha_block = _block(hunt_actionability)
    plan_block = _block(hunt_action_plan)

    state = _upper(ha_block.get("actionability"))

    # 1. Terminal blockers (either projection) are never overridden.
    if state == ACTIONABILITY_BLOCKED or bool(hp_block.get("blocked")):
        return _none_result(
            completion_condition=CONDITION_BLOCKERS_RESOLVED,
            reason_codes=[REASON_SOURCE_BLOCKED],
            reason=_NONE_REASON_BLOCKED,
            confidence=CONFIDENCE_HIGH,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )

    # 2. Low value is terminal for planning.
    if state == ACTIONABILITY_LOW_VALUE:
        return _none_result(
            completion_condition=CONDITION_REACTIVATE,
            reason_codes=[REASON_SOURCE_DEFERRED],
            reason=_NONE_REASON_DEFERRED,
            confidence=CONFIDENCE_HIGH,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )

    action = _upper(plan_block.get("action"))

    # 12. A valid R31.12 action plan is required for a narrower plan.
    if not action:
        return _none_result(
            completion_condition=CONDITION_REQUIRES_ACTION_PLAN,
            reason_codes=[REASON_ACTION_PLAN_MISSING],
            reason=_NONE_REASON_MISSING,
            confidence=CONFIDENCE_LOW,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )
    if action not in HUNT_ACTIONS:
        return _none_result(
            completion_condition=CONDITION_REQUIRES_ACTION_PLAN,
            reason_codes=[REASON_UNKNOWN_ACTION],
            reason=_NONE_REASON_UNKNOWN,
            confidence=CONFIDENCE_LOW,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )

    # 13. A terminal R31.12 action is terminal for acquisition planning.
    if action == RESOLVE_BLOCKERS:
        return _none_result(
            completion_condition=CONDITION_BLOCKERS_RESOLVED,
            reason_codes=[REASON_SOURCE_BLOCKED],
            reason=_NONE_REASON_BLOCKED,
            confidence=CONFIDENCE_HIGH,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )
    if action == DEFER:
        return _none_result(
            completion_condition=CONDITION_REACTIVATE,
            reason_codes=[REASON_SOURCE_DEFERRED],
            reason=_NONE_REASON_DEFERRED,
            confidence=CONFIDENCE_HIGH,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )

    # 14. The selected gap must match the action's gap. Never reinterpret.
    # An absent/empty gap field carries no contradicted upstream selection,
    # so the action's deterministic gap pair is used; a present-but-different
    # gap is an upstream conflict and yields a defensive NONE plan.
    expected_gap = _ACTION_GAP[action]
    raw_gap = plan_block.get("evidence_gap")
    upstream_gap = _upper(raw_gap)
    if not upstream_gap:
        upstream_gap = expected_gap
    elif upstream_gap != expected_gap:
        return _none_result(
            completion_condition=CONDITION_REQUIRES_ACTION_PLAN,
            reason_codes=[REASON_ACTION_PLAN_CONFLICT],
            reason=_NONE_REASON_CONFLICT,
            confidence=CONFIDENCE_LOW,
            effort=EFFORT_UNKNOWN,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
        )

    method = _ACTION_METHOD[action]
    target = _ACTION_TARGET[action]
    condition = _ACTION_CONDITION[action]

    # 3. Immediate verification: review what is already collected.
    if action == VERIFY_EXISTING_EVIDENCE:
        reason_codes = [REASON_SOURCE_ACTION, REASON_NO_ACQUISITION_REQUIRED]
        if state == ACTIONABILITY_IMMEDIATE:
            reason_codes.insert(0, REASON_SOURCE_IMMEDIATE)
        return _result(
            method,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
            evidence_gap=GAP_NONE,
            evidence_target=target,
            completion_condition=condition,
            reason_codes=reason_codes,
            reason=_METHOD_REASON[method],
            confidence=CONFIDENCE_HIGH,
            effort=EFFORT_LOW,
        )

    # 11. Manual review maps to human research with no narrow gap.
    if action == MANUAL_REVIEW:
        return _result(
            method,
            hunt_priority=hp_block,
            hunt_actionability=ha_block,
            hunt_action_plan=plan_block,
            evidence_gap=GAP_NONE,
            evidence_target=target,
            completion_condition=condition,
            reason_codes=[REASON_SOURCE_ACTION],
            reason=_METHOD_REASON[method],
            confidence=_upstream_confidence(plan_block, method),
            effort=_upstream_effort(plan_block, method),
        )

    # 4.-10. Evidence-targeted acquisition for the R31.12-selected gap.
    reason_codes = [REASON_SOURCE_ACTION, _GAP_REASON[upstream_gap]]
    if state == ACTIONABILITY_IMMEDIATE:
        reason_codes.insert(0, REASON_SOURCE_IMMEDIATE)
    return _result(
        method,
        hunt_priority=hp_block,
        hunt_actionability=ha_block,
        hunt_action_plan=plan_block,
        evidence_gap=upstream_gap,
        evidence_target=target,
        completion_condition=condition,
        reason_codes=reason_codes,
        reason=_METHOD_REASON[method],
        confidence=_upstream_confidence(plan_block, method),
        effort=_upstream_effort(plan_block, method),
    )


__all__ = [
    "EVIDENCE_ACQUISITION_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "ACQUISITION_METHODS",
    "ACQUISITION_RANKS",
    "EVIDENCE_TARGETS",
    "COMPLETION_CONDITIONS",
    "REASON_CODES",
    "ESTIMATED_EFFORTS",
    "ACQUISITION_CONFIDENCES",
    "EXISTING_EVIDENCE_REVIEW",
    "VERSION_LOOKUP",
    "COMPONENT_IDENTITY_LOOKUP",
    "SCOPE_EVIDENCE_REVIEW",
    "PATH_EVIDENCE_REVIEW",
    "PARAMETER_EVIDENCE_REVIEW",
    "HTTP_BEHAVIOR_REVIEW",
    "TECHNOLOGY_EVIDENCE_REVIEW",
    "MANUAL_RESEARCH",
    "NO_ACQUISITION",
    "TARGET_VERSION",
    "TARGET_COMPONENT_IDENTITY",
    "TARGET_SCOPE",
    "TARGET_PATH",
    "TARGET_PARAMETER",
    "TARGET_HTTP_BEHAVIOR",
    "TARGET_TECHNOLOGY",
    "TARGET_EXISTING_EVIDENCE",
    "TARGET_NONE",
    "CONDITION_BLOCKERS_RESOLVED",
    "CONDITION_REACTIVATE",
    "CONDITION_EXISTING_REVIEWED",
    "CONDITION_VERSION_ESTABLISHED",
    "CONDITION_IDENTITY_ESTABLISHED",
    "CONDITION_SCOPE_ESTABLISHED",
    "CONDITION_PATH_ESTABLISHED",
    "CONDITION_PARAMETER_ESTABLISHED",
    "CONDITION_HTTP_ESTABLISHED",
    "CONDITION_TECHNOLOGY_ESTABLISHED",
    "CONDITION_MANUAL_COMPLETED",
    "CONDITION_REQUIRES_ACTION_PLAN",
    "REASON_SOURCE_BLOCKED",
    "REASON_SOURCE_DEFERRED",
    "REASON_SOURCE_IMMEDIATE",
    "REASON_SOURCE_ACTION",
    "REASON_NO_ACQUISITION_REQUIRED",
    "REASON_ACTION_PLAN_CONFLICT",
    "REASON_ACTION_PLAN_MISSING",
    "REASON_UNKNOWN_ACTION",
    "EFFORT_LOW",
    "EFFORT_MEDIUM",
    "EFFORT_HIGH",
    "EFFORT_UNKNOWN",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_LOW",
    "MAX_REASON_CODES",
    "MAX_ORDER_KEY",
    "plan_evidence_acquisition",
]
