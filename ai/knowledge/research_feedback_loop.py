"""Stage R73 deterministic research feedback and iteration loop (pure engine).

R73 closes the bounded research loop. When new evidence becomes available, it
compares the previous R70/R71/R72 state against the explicit new evidence and
answers:

    "What changed in our understanding of this hypothesis: which requirements
     moved MISSING -> AVAILABLE (or were explicitly invalidated), is the
     hypothesis retained, refined, weakened or unresolved, and is another
     automated research iteration justified?"

    Evidence -> Hypothesis -> R70 action -> R71 acquisition plan
             -> R72 readiness -> NEW EVIDENCE -> R73 feedback
             -> continue / revise / stop

This is a **feedback signal only, and it is plan-only**. It never confirms a
vulnerability, never creates a finding, never executes, never contacts a
target, never authorizes anything, never calls an LLM and never touches
Mongo. It contains no payloads, exploit strings, scanner commands or request
bodies.

Architecture / composition decision (existing concepts inspected first):

- R43.3 ``hypothesis_correlator.py`` correlates hypotheses across agents
  (duplicate/related/independent/conflicting) and is not a feedback model.
- R31.15 ``evidence_confidence_aggregator.py`` measures confidence over the
  Asset<->CVE chain; R55.4 ``research_prioritization.py`` ranks finding
  intelligence. Neither consumes new evidence against a previous readiness
  state, and re-deriving either here would duplicate a framework.
- R73 does **not** create a second hypothesis model, a second confidence
  framework or a second acquisition planner. It composes the existing chain:
  it consumes the previous validated hypotheses, the R70 action plan, the R71
  acquisition plan and the R72 readiness records, and compares them with
  explicit new evidence. Requirement kinds, requirement classes, statuses and
  safety come from the previous stages; R73 only computes the *delta* and the
  bounded research-state transition.
- R69 skill references already carried by the R71 plan are propagated
  read-only; no skills are re-sent or invented.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no persistence, no execution.
- New evidence must be explicit and canonical: every observation carries a
  canonical ``kind:value`` reference from the closed R64/R68 reference
  vocabulary; item-level failures (unknown hypothesis, unknown requirement,
  unknown invalidated reference, malformed or sensitive data) fail closed and
  are reported as rejections, never silently used or dropped.
- No invented transitions: a MISSING requirement can only become AVAILABLE
  through an explicit PROVIDES item, and an AVAILABLE requirement can only
  become MISSING through an explicit INVALIDATES item whose reference is
  actually part of the previous R71 evidence. Nothing is silently
  invalidated.
- Sufficiency/readiness is never recomputed here; R72 remains the source of
  truth for readiness. R73 only reports what changed.
- Closed vocabularies: evidence effects, sources, feedback states, hypothesis
  states, next-iteration decisions, reason codes, causes and safety flags are
  closed sets. No ``CONFIRMED``/``VULNERABLE``/``EXPLOITABLE`` state exists.
- Additive and read-only: inputs are never mutated; every result is a new
  dict with rule version ``r73-1``.
- Every iteration forces ``confirmation_state = NOT_CONFIRMED``; ``STOP``
  means only that the automated loop should stop and hand the state to human
  review.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ai.knowledge.research_decision_readiness_planner import (
    CLASS_DECISION,
    DECISION_READY_FOR_HUMAN_REVIEW,
    RULE_VERSION as SOURCE_READINESS_RULE_VERSION,
    requirement_class_of,
)
from ai.knowledge.research_evidence_acquisition_planner import (
    RULE_VERSION as SOURCE_ACQUISITION_RULE_VERSION,
    STATUS_AVAILABLE,
    STATUS_MISSING,
)
from ai.knowledge.research_outcome_planner import (
    RULE_VERSION as SOURCE_ACTION_RULE_VERSION,
    SAFETY_BLOCK,
)

RULE_VERSION = "r73-1"

MAX_ITERATIONS = 8
MAX_HYPOTHESES = 8
MAX_REQUIREMENTS = 8
MAX_EVIDENCE_ITEMS = 16
MAX_DELTAS = 8
MAX_CHANGED_REFS = 8
MAX_REJECTIONS = 8
MAX_TEXT_CHARS = 320
MAX_REF_CHARS = 512

# ---------------------------------------------------------------------------
# Closed evidence-effect / source vocabularies
# ---------------------------------------------------------------------------

EFFECT_PROVIDES = "PROVIDES"
EFFECT_CONTRADICTS = "CONTRADICTS"
EFFECT_INVALIDATES = "INVALIDATES"

EVIDENCE_EFFECTS: tuple[str, ...] = (
    EFFECT_PROVIDES,
    EFFECT_CONTRADICTS,
    EFFECT_INVALIDATES,
)

SOURCE_EXISTING_CONTEXT = "EXISTING_CONTEXT"
SOURCE_STORED_RESPONSE = "STORED_RESPONSE"
SOURCE_HUMAN_REVIEW = "HUMAN_REVIEW"
SOURCE_WATCH_DERIVED = "WATCH_DERIVED"

EVIDENCE_SOURCES: tuple[str, ...] = (
    SOURCE_EXISTING_CONTEXT,
    SOURCE_STORED_RESPONSE,
    SOURCE_HUMAN_REVIEW,
    SOURCE_WATCH_DERIVED,
)

#: Closed canonical reference-kind vocabulary (R64/R68 evidence identity).
EVIDENCE_REF_KINDS: tuple[str, ...] = (
    "program",
    "snapshot",
    "path",
    "parameter",
    "technology",
    "version",
    "record",
    "url",
    "host",
    "endpoint",
    "response",
    "authorization",
    "redirect",
    "session",
    "token",
    "jwt",
    "algorithm",
    "header",
    "error",
    "status",
)

# ---------------------------------------------------------------------------
# Closed feedback / hypothesis-state / next-iteration vocabularies
# ---------------------------------------------------------------------------

FEEDBACK_NO_CHANGE = "NO_CHANGE"
FEEDBACK_NEW_SUPPORTING = "NEW_SUPPORTING_EVIDENCE"
FEEDBACK_NEW_CONTRADICTING = "NEW_CONTRADICTING_EVIDENCE"
FEEDBACK_GAP_REDUCED = "EVIDENCE_GAP_REDUCED"
FEEDBACK_GAP_REMAINS = "EVIDENCE_GAP_REMAINS"
FEEDBACK_INVALIDATED = "EVIDENCE_INVALIDATED"
FEEDBACK_REQUIRES_REVIEW = "HYPOTHESIS_REQUIRES_REVIEW"

FEEDBACK_STATES: tuple[str, ...] = (
    FEEDBACK_NO_CHANGE,
    FEEDBACK_NEW_SUPPORTING,
    FEEDBACK_NEW_CONTRADICTING,
    FEEDBACK_GAP_REDUCED,
    FEEDBACK_GAP_REMAINS,
    FEEDBACK_INVALIDATED,
    FEEDBACK_REQUIRES_REVIEW,
)

#: Consolidation precedence (first present wins at record level).
FEEDBACK_PRECEDENCE: tuple[str, ...] = (
    FEEDBACK_INVALIDATED,
    FEEDBACK_NEW_CONTRADICTING,
    FEEDBACK_REQUIRES_REVIEW,
    FEEDBACK_GAP_REDUCED,
    FEEDBACK_NEW_SUPPORTING,
    FEEDBACK_GAP_REMAINS,
    FEEDBACK_NO_CHANGE,
)

STATE_RETAIN = "RETAIN"
STATE_REFINE = "REFINE"
STATE_WEAKEN = "WEAKEN"
STATE_UNRESOLVED = "UNRESOLVED"
STATE_STOP = "STOP"

HYPOTHESIS_STATES: tuple[str, ...] = (
    STATE_RETAIN,
    STATE_REFINE,
    STATE_WEAKEN,
    STATE_UNRESOLVED,
    STATE_STOP,
)

STATE_SEVERITY: dict[str, int] = {
    STATE_RETAIN: 0,
    STATE_REFINE: 1,
    STATE_UNRESOLVED: 2,
    STATE_WEAKEN: 3,
    STATE_STOP: 4,
}

NEXT_CONTINUE = "CONTINUE"
NEXT_HUMAN_REVIEW = "HUMAN_REVIEW"
NEXT_STOP = "STOP"

NEXT_ITERATIONS: tuple[str, ...] = (NEXT_CONTINUE, NEXT_HUMAN_REVIEW, NEXT_STOP)

NEXT_SEVERITY: dict[str, int] = {
    NEXT_CONTINUE: 0,
    NEXT_HUMAN_REVIEW: 1,
    NEXT_STOP: 2,
}

# ---------------------------------------------------------------------------
# Closed reason codes (with fixed, bounded texts)
# ---------------------------------------------------------------------------

REASON_NO_RELEVANT_EVIDENCE = "NO_RELEVANT_EVIDENCE"
REASON_SUPPORTING_EVIDENCE_ADDED = "SUPPORTING_EVIDENCE_ADDED"
REASON_MISSING_EVIDENCE_ACQUIRED = "MISSING_EVIDENCE_ACQUIRED"
REASON_CONTRADICTING_EVIDENCE = "CONTRADICTING_EVIDENCE"
REASON_EVIDENCE_INVALIDATED = "EVIDENCE_INVALIDATED"
REASON_DECISION_EVIDENCE_COMPLETE = "DECISION_EVIDENCE_COMPLETE"
REASON_DECISION_EVIDENCE_NOT_COMPLETE = "DECISION_EVIDENCE_NOT_COMPLETE"
REASON_ACQUISITION_UNAVAILABLE = "ACQUISITION_UNAVAILABLE"

REASON_CODES: tuple[str, ...] = (
    REASON_NO_RELEVANT_EVIDENCE,
    REASON_SUPPORTING_EVIDENCE_ADDED,
    REASON_MISSING_EVIDENCE_ACQUIRED,
    REASON_CONTRADICTING_EVIDENCE,
    REASON_EVIDENCE_INVALIDATED,
    REASON_DECISION_EVIDENCE_COMPLETE,
    REASON_DECISION_EVIDENCE_NOT_COMPLETE,
    REASON_ACQUISITION_UNAVAILABLE,
)

REASON_TEXTS: dict[str, str] = {
    REASON_NO_RELEVANT_EVIDENCE: (
        "no new evidence related to this hypothesis was supplied"
    ),
    REASON_SUPPORTING_EVIDENCE_ADDED: (
        "new evidence supports a requirement that was already available"
    ),
    REASON_MISSING_EVIDENCE_ACQUIRED: (
        "new evidence satisfies previously missing required evidence"
    ),
    REASON_CONTRADICTING_EVIDENCE: (
        "new evidence contradicts a required evidence item"
    ),
    REASON_EVIDENCE_INVALIDATED: (
        "previously available evidence was explicitly invalidated"
    ),
    REASON_DECISION_EVIDENCE_COMPLETE: (
        "all decision-critical requirements are available"
    ),
    REASON_DECISION_EVIDENCE_NOT_COMPLETE: (
        "decision-critical requirements remain missing"
    ),
    REASON_ACQUISITION_UNAVAILABLE: (
        "no valid acquisition plan exists for the remaining evidence"
    ),
}

CAUSE_NEW_EVIDENCE = "NEW_EVIDENCE"
CAUSE_INVALIDATION = "INVALIDATION"

DELTA_CAUSES: tuple[str, ...] = (CAUSE_NEW_EVIDENCE, CAUSE_INVALIDATION)

# ---------------------------------------------------------------------------
# Closed rejection codes
# ---------------------------------------------------------------------------

REJECTION_MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
REJECTION_UNSUPPORTED_EFFECT = "UNSUPPORTED_EFFECT"
REJECTION_UNKNOWN_HYPOTHESIS = "UNKNOWN_HYPOTHESIS_REF"
REJECTION_UNKNOWN_REQUIREMENT = "UNKNOWN_REQUIREMENT_KIND"
REJECTION_UNKNOWN_INVALIDATED_REF = "UNKNOWN_INVALIDATED_REF"
REJECTION_AMBIGUOUS_EVIDENCE = "AMBIGUOUS_EVIDENCE_REF"
REJECTION_SENSITIVE_EVIDENCE = "SENSITIVE_EVIDENCE_REJECTED"
REJECTION_INVALID_SOURCE = "INVALID_EVIDENCE_SOURCE"

REJECTION_CODES: tuple[str, ...] = (
    REJECTION_MALFORMED_EVIDENCE,
    REJECTION_UNSUPPORTED_EFFECT,
    REJECTION_UNKNOWN_HYPOTHESIS,
    REJECTION_UNKNOWN_REQUIREMENT,
    REJECTION_UNKNOWN_INVALIDATED_REF,
    REJECTION_AMBIGUOUS_EVIDENCE,
    REJECTION_SENSITIVE_EVIDENCE,
    REJECTION_INVALID_SOURCE,
)

_URL_RE = re.compile(r"://")
_MONGO_ID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*\S+"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)


class ResearchFeedbackError(ValueError):
    """Deterministic, secret-free R73 feedback failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _safe_text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    """Bound and redact credential-like text before it enters a record."""

    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:limit]


def _untrusted(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    """Normalise a string for the sensitive-data gate (never persisted raw)."""

    text = _CONTROL_RE.sub(" ", _text(value))
    return " ".join(text.split())[:limit]


def _is_sensitive(text: str) -> bool:
    return bool(
        _URL_RE.search(text)
        or _MONGO_ID_RE.search(text)
        or _IPV4_RE.search(text)
        or _SECRET_RE.search(text)
        or _BEARER_RE.search(text)
    )


def _ref_is_sensitive(ref: str) -> bool:
    """Canonical refs are ``kind:value``; the kind is never a secret key."""

    _, _, value = _text(ref).partition(":")
    return _is_sensitive(value)


def _ref_safe_text(value: object, limit: int = MAX_REF_CHARS) -> str:
    """Sanitise a canonical reference without destroying its identity.

    The value part has already passed the sensitive-data gate, so the
    secret-key redaction is intentionally *not* applied here: the reference
    kind (for example ``authorization``) is not a credential key.
    """

    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    return text[:limit]


def _redact_like_r31(value: object, limit: int = MAX_REF_CHARS) -> str:
    """Apply the previous-stage redaction form used by R31/R71 ``_safe_text``.

    Needed only to *match* previously stored references: R71 redacts
    ``authorization:value`` to ``authorization=[redacted]``. R73 never treats
    a redacted form as an identity by itself; ambiguous groups are rejected.
    """

    text = _CONTROL_RE.sub(" ", _text(value))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    return text[:limit]


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_strings(value: object, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _safe_text(item, item_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_refs(value: object, limit: int) -> list[str]:
    """Bound canonical references while preserving their identity."""

    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _ref_safe_text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ref_kind(ref: object) -> str:
    return _text(ref).partition(":")[0].strip().lower()


# ---------------------------------------------------------------------------
# Previous-state projection (R70/R71/R72 consumed read-only)
# ---------------------------------------------------------------------------


def _records_by_id(readiness_plan: object) -> list[Mapping]:
    block = _block(readiness_plan)
    raw = block.get("records")
    if raw is not None:
        return _mapping_items(raw)
    return _mapping_items(readiness_plan)


def _plans_by_ref(acquisition_plan: object) -> dict[str, Mapping]:
    plans: dict[str, Mapping] = {}
    block = _block(acquisition_plan)
    raw = block.get("plans")
    items = _mapping_items(raw) if raw is not None else _mapping_items(
        acquisition_plan
    )
    for plan in items:
        ref = _safe_text(plan.get("plan_id"), 16)
        if ref:
            plans[ref] = plan
    return plans


def _requirements_by_plan(acquisition_plan: object) -> dict[str, dict]:
    """plan_ref -> {requirement_kind: (status, [evidence refs])}."""

    index: dict[str, dict] = {}
    for ref, plan in _plans_by_ref(acquisition_plan).items():
        entries: dict[str, tuple[str, list[str]]] = {}
        for entry in _mapping_items(plan.get("required_evidence")):
            kind = _upper(entry.get("requirement_kind"))
            if not kind:
                continue
            status = _upper(entry.get("status"))
            if status not in (STATUS_AVAILABLE, STATUS_MISSING):
                status = STATUS_MISSING
            refs: list[str] = []
            for evidence in _mapping_items(entry.get("evidence")):
                value = _safe_text(evidence.get("ref"), MAX_REF_CHARS)
                if value and value not in refs:
                    refs.append(value)
            entries[kind] = (status, refs)
        index[ref] = entries
    return index


def _previous_state_of(record: Mapping) -> str:
    decision = _upper(record.get("decision_state"))
    if decision == DECISION_READY_FOR_HUMAN_REVIEW:
        return STATE_STOP
    return STATE_UNRESOLVED


def _consolidate_state(states: Sequence[str]) -> str:
    present = [state for state in states if state in STATE_SEVERITY]
    if not present:
        return STATE_UNRESOLVED
    return max(present, key=lambda state: STATE_SEVERITY[state])


def _consolidate_next(decisions: Sequence[str]) -> str:
    present = [
        decision for decision in decisions if decision in NEXT_SEVERITY
    ]
    if not present:
        return NEXT_CONTINUE
    return max(present, key=lambda decision: NEXT_SEVERITY[decision])


def _consolidate_feedback(states: Sequence[str]) -> str:
    present = {state for state in states if state in FEEDBACK_STATES}
    for state in FEEDBACK_PRECEDENCE:
        if state in present:
            return state
    return FEEDBACK_NO_CHANGE


# ---------------------------------------------------------------------------
# New-evidence validation (explicit, canonical, fail closed per item)
# ---------------------------------------------------------------------------


def _raw_outcome_refs(action_plan: object) -> set[str]:
    """Raw canonical observation refs carried by the R70 outcomes."""

    refs: set[str] = set()
    for outcome in _mapping_items(_block(action_plan).get("outcomes")):
        evidence = outcome.get("current_evidence")
        if not isinstance(evidence, Mapping):
            continue
        for entry in _mapping_items(evidence.get("observations")):
            ref = _untrusted(entry.get("ref"), MAX_REF_CHARS)
            if ref:
                refs.add(ref)
    return refs


def _validate_observation(entry: object) -> dict | None:
    if not isinstance(entry, Mapping):
        return None
    ref = _untrusted(entry.get("ref"), MAX_REF_CHARS)
    fact = _untrusted(entry.get("fact"), MAX_TEXT_CHARS)
    if not ref or _ref_kind(ref) not in EVIDENCE_REF_KINDS:
        return None
    if _ref_is_sensitive(ref) or _is_sensitive(fact):
        raise ResearchFeedbackError(REJECTION_SENSITIVE_EVIDENCE, "ref")
    return {"ref": _ref_safe_text(ref), "fact": _safe_text(fact)}


def _validate_signal(entry: object) -> dict | None:
    if not isinstance(entry, Mapping):
        return None
    name = _untrusted(entry.get("signal"), 64)
    detail = _untrusted(entry.get("detail"), MAX_TEXT_CHARS)
    if not name:
        return None
    if _is_sensitive(name) or _is_sensitive(detail):
        raise ResearchFeedbackError(REJECTION_SENSITIVE_EVIDENCE, "signal")
    return {"signal": _safe_text(name, 64), "detail": _safe_text(detail)}


def _normalize_item(
    item: object,
    known_refs: set[str],
    ambiguous_refs: set[str],
    known_requirements: Mapping[str, set[str]],
) -> tuple[dict | None, str | None]:
    """Validate one new-evidence item; returns (item, rejection_code)."""

    if not isinstance(item, Mapping):
        return None, REJECTION_MALFORMED_EVIDENCE
    hypothesis_ref = _safe_text(item.get("hypothesis_ref"), 16)
    if not hypothesis_ref:
        return None, REJECTION_UNKNOWN_HYPOTHESIS
    effect = _upper(item.get("effect")) or EFFECT_PROVIDES
    if effect not in EVIDENCE_EFFECTS:
        return None, REJECTION_UNSUPPORTED_EFFECT
    source = _upper(item.get("source")) or SOURCE_EXISTING_CONTEXT
    if source not in EVIDENCE_SOURCES:
        return None, REJECTION_INVALID_SOURCE
    requirement_kind = _upper(item.get("requirement_kind"))
    try:
        observations = []
        for entry in _mapping_items(item.get("observations")):
            observation = _validate_observation(entry)
            if observation is None:
                return None, REJECTION_MALFORMED_EVIDENCE
            observations.append(observation)
        signals = []
        for entry in _mapping_items(item.get("derived_signals")):
            signal = _validate_signal(entry)
            if signal is None:
                return None, REJECTION_MALFORMED_EVIDENCE
            signals.append(signal)
    except ResearchFeedbackError as exc:
        return None, exc.code
    invalidates = _bounded_refs(
        item.get("invalidates_refs"), MAX_CHANGED_REFS
    )
    for ref in invalidates:
        kind = _ref_kind(ref)
        if kind not in EVIDENCE_REF_KINDS:
            return None, REJECTION_MALFORMED_EVIDENCE
        if _ref_is_sensitive(ref):
            return None, REJECTION_SENSITIVE_EVIDENCE
        if ref in ambiguous_refs:
            return None, REJECTION_AMBIGUOUS_EVIDENCE
        if ref not in known_refs:
            return None, REJECTION_UNKNOWN_INVALIDATED_REF
    if effect == EFFECT_INVALIDATES:
        if not invalidates:
            return None, REJECTION_MALFORMED_EVIDENCE
    else:
        if not observations and not signals:
            return None, REJECTION_MALFORMED_EVIDENCE
        if not requirement_kind:
            return None, REJECTION_UNKNOWN_REQUIREMENT
        if requirement_kind not in known_requirements.get(
            hypothesis_ref, set()
        ):
            return None, REJECTION_UNKNOWN_REQUIREMENT
    return (
        {
            "hypothesis_ref": hypothesis_ref,
            "effect": effect,
            "source": source,
            "requirement_kind": requirement_kind,
            "observations": observations[:MAX_EVIDENCE_ITEMS],
            "derived_signals": signals[:MAX_EVIDENCE_ITEMS],
            "invalidates_refs": invalidates,
        },
        None,
    )


def _normalize_evidence(
    new_evidence: object,
    known_hypotheses: set[str],
    known_refs: set[str],
    ambiguous_refs: set[str],
    known_requirements: Mapping[str, set[str]],
) -> tuple[list[dict], list[dict]]:
    items: list[dict] = []
    rejections: list[dict] = []
    block = _block(new_evidence)
    raw_items = block.get("items")
    if isinstance(raw_items, (list, tuple)):
        source_items = list(raw_items)
    elif isinstance(new_evidence, (list, tuple)):
        source_items = list(new_evidence)
    else:
        source_items = []
    for position, raw in enumerate(source_items, start=1):
        if isinstance(raw, Mapping):
            ref = _safe_text(raw.get("hypothesis_ref"), 16)
            if ref and ref not in known_hypotheses:
                rejections.append(
                    {"index": position, "code": REJECTION_UNKNOWN_HYPOTHESIS}
                )
                continue
        normalized, code = _normalize_item(
            raw, known_refs, ambiguous_refs, known_requirements
        )
        if normalized is None:
            rejections.append(
                {"index": position, "code": code or REJECTION_MALFORMED_EVIDENCE}
            )
            continue
        if normalized["hypothesis_ref"] not in known_hypotheses:
            rejections.append(
                {"index": position, "code": REJECTION_UNKNOWN_HYPOTHESIS}
            )
            continue
        items.append(normalized)
        if len(items) >= MAX_EVIDENCE_ITEMS:
            break
    return items, rejections[:MAX_REJECTIONS]


# ---------------------------------------------------------------------------
# Iteration evaluation
# ---------------------------------------------------------------------------


def _evaluate_record(
    record: Mapping,
    plan: Mapping | None,
    requirement_index: Mapping[str, tuple[str, list[str]]],
    items: Sequence[Mapping],
    position: int,
) -> tuple[dict, dict | None]:
    plan_ref = _safe_text(record.get("plan_ref"), 16) or f"P{position}"
    action_ref = _safe_text(record.get("action_ref"), 16) or f"A{position}"
    hypothesis_refs = _bounded_strings(
        record.get("hypothesis_refs"), MAX_HYPOTHESES, 16
    )
    hypothesis_count = len(hypothesis_refs)
    ref_set = set(hypothesis_refs)

    statuses: dict[str, str] = {}
    for entry in _mapping_items(record.get("required_evidence")):
        kind = _upper(entry.get("requirement_kind"))
        if not kind:
            continue
        status = _upper(entry.get("status"))
        if status not in (STATUS_AVAILABLE, STATUS_MISSING):
            status = STATUS_MISSING
        statuses[kind] = status
    decision_kinds = [
        kind for kind in statuses if requirement_class_of(kind) == CLASS_DECISION
    ][:MAX_REQUIREMENTS]

    relevant = [
        item for item in items if item["hypothesis_ref"] in ref_set
    ]

    deltas: list[dict] = []
    newly_available: list[str] = []
    newly_missing: list[str] = []
    invalidated: list[str] = []
    changed_refs: list[str] = []
    supporting_added = False
    contradicted: set[str] = set()
    evidence_items: list[dict] = []

    for item in relevant:
        kind = item["requirement_kind"]
        for observation in item["observations"]:
            ref = observation["ref"]
            if ref not in changed_refs:
                changed_refs.append(ref)
        if item["effect"] == EFFECT_PROVIDES:
            if kind and statuses.get(kind) == STATUS_MISSING:
                statuses[kind] = STATUS_AVAILABLE
                deltas.append(
                    {
                        "requirement_kind": kind,
                        "from_status": STATUS_MISSING,
                        "to_status": STATUS_AVAILABLE,
                        "cause": CAUSE_NEW_EVIDENCE,
                        "hypothesis_ref": item["hypothesis_ref"],
                    }
                )
                if kind not in newly_available:
                    newly_available.append(kind)
            else:
                supporting_added = True
        elif item["effect"] == EFFECT_CONTRADICTS:
            if kind:
                contradicted.add(kind)
        else:
            for ref in item["invalidates_refs"]:
                if ref not in changed_refs:
                    changed_refs.append(ref)
                for storage_ref in (ref, _redact_like_r31(ref)):
                    for target, (_, refs) in requirement_index.items():
                        if (
                            storage_ref not in refs
                            or statuses.get(target) != STATUS_AVAILABLE
                        ):
                            continue
                        statuses[target] = STATUS_MISSING
                        deltas.append(
                            {
                                "requirement_kind": target,
                                "from_status": STATUS_AVAILABLE,
                                "to_status": STATUS_MISSING,
                                "cause": CAUSE_INVALIDATION,
                                "hypothesis_ref": item["hypothesis_ref"],
                            }
                        )
                        if target not in newly_missing:
                            newly_missing.append(target)
                        if target not in invalidated:
                            invalidated.append(target)
        evidence_items.append(
            {
                "hypothesis_ref": item["hypothesis_ref"],
                "effect": item["effect"],
                "requirement_kind": kind,
                "observation_count": len(item["observations"]),
                "signal_count": len(item["derived_signals"]),
            }
        )
        if len(evidence_items) >= MAX_EVIDENCE_ITEMS:
            break

    remaining_decision = [
        kind for kind in decision_kinds if statuses.get(kind) == STATUS_MISSING
    ]
    available_decision = [
        kind for kind in decision_kinds if statuses.get(kind) == STATUS_AVAILABLE
    ]
    acquisition_status = _upper(record.get("acquisition_status"))

    feedback: str
    current_state: str
    next_iteration: str
    reason: str
    human_review_required: bool
    if not relevant:
        if not remaining_decision:
            feedback = FEEDBACK_NO_CHANGE
            current_state = STATE_RETAIN
            next_iteration = NEXT_HUMAN_REVIEW
            reason = REASON_DECISION_EVIDENCE_COMPLETE
        else:
            feedback = FEEDBACK_GAP_REMAINS
            current_state = STATE_UNRESOLVED
            if acquisition_status == "PLANNED":
                next_iteration = NEXT_CONTINUE
                reason = REASON_NO_RELEVANT_EVIDENCE
            else:
                next_iteration = NEXT_HUMAN_REVIEW
                reason = REASON_ACQUISITION_UNAVAILABLE
        human_review_required = next_iteration != NEXT_CONTINUE
    elif invalidated and not available_decision:
        feedback = FEEDBACK_INVALIDATED
        current_state = STATE_UNRESOLVED
        next_iteration = NEXT_STOP
        reason = REASON_EVIDENCE_INVALIDATED
        human_review_required = True
    elif invalidated:
        feedback = FEEDBACK_INVALIDATED
        current_state = STATE_REFINE
        next_iteration = NEXT_CONTINUE
        reason = REASON_EVIDENCE_INVALIDATED
        human_review_required = True
    elif contradicted and not available_decision:
        feedback = FEEDBACK_NEW_CONTRADICTING
        current_state = STATE_STOP
        next_iteration = NEXT_STOP
        reason = REASON_CONTRADICTING_EVIDENCE
        human_review_required = True
    elif contradicted:
        feedback = FEEDBACK_NEW_CONTRADICTING
        current_state = STATE_WEAKEN
        next_iteration = NEXT_CONTINUE
        reason = REASON_CONTRADICTING_EVIDENCE
        human_review_required = False
    elif not remaining_decision:
        feedback = FEEDBACK_REQUIRES_REVIEW
        current_state = STATE_STOP
        next_iteration = NEXT_HUMAN_REVIEW
        reason = REASON_DECISION_EVIDENCE_COMPLETE
        human_review_required = True
    elif newly_available:
        feedback = FEEDBACK_GAP_REDUCED
        current_state = STATE_REFINE
        next_iteration = NEXT_CONTINUE
        reason = REASON_MISSING_EVIDENCE_ACQUIRED
        human_review_required = False
    elif supporting_added:
        feedback = FEEDBACK_NEW_SUPPORTING
        current_state = STATE_RETAIN
        next_iteration = NEXT_CONTINUE
        reason = REASON_SUPPORTING_EVIDENCE_ADDED
        human_review_required = False
    else:
        feedback = FEEDBACK_GAP_REMAINS
        current_state = STATE_UNRESOLVED
        next_iteration = NEXT_CONTINUE
        reason = REASON_DECISION_EVIDENCE_NOT_COMPLETE
        human_review_required = False

    record_out = {
        "iteration_id": "",
        "order": 0,
        "plan_ref": plan_ref,
        "action_ref": action_ref,
        "hypothesis_refs": hypothesis_refs,
        "hypothesis_count": hypothesis_count,
        "category": _upper(record.get("category")),
        "gap_id": _upper(record.get("gap_id")),
        "previous_state": _previous_state_of(record),
        "current_state": current_state,
        "feedback_state": feedback,
        "evidence_delta": deltas[:MAX_DELTAS],
        "newly_available_requirements": newly_available[:MAX_REQUIREMENTS],
        "newly_missing_requirements": newly_missing[:MAX_REQUIREMENTS],
        "invalidated_requirements": invalidated[:MAX_REQUIREMENTS],
        "unchanged_requirements": [
            kind
            for kind in statuses
            if kind not in newly_available
            and kind not in newly_missing
        ][:MAX_REQUIREMENTS],
        "remaining_decision_requirements": remaining_decision[
            :MAX_REQUIREMENTS
        ],
        "changed_evidence_refs": changed_refs[:MAX_CHANGED_REFS],
        "evidence_items": evidence_items[:MAX_EVIDENCE_ITEMS],
        "reason": reason,
        "reason_text": REASON_TEXTS.get(reason, ""),
        "next_iteration": next_iteration,
        "human_review_required": human_review_required,
        "skill_refs": _bounded_strings(
            plan.get("skill_refs") if isinstance(plan, Mapping) else [],
            MAX_HYPOTHESES,
            64,
        ),
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }
    return record_out, None


def build_iteration_records(
    hypotheses: object = None,
    *,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    new_evidence: object = None,
) -> tuple[list[dict], list[dict]]:
    """One bounded iteration record per R72 readiness record (input order).

    ``hypotheses`` is the previous validated hypothesis list (used read-only
    for reference discovery); the previous action/acquisition/readiness plans
    are the authoritative state. New evidence is explicit; when it is absent
    or invalid the loop reports ``EVIDENCE_GAP_REMAINS``/``NO_CHANGE`` and
    never invents a transition.
    """

    records = _records_by_id(readiness_plan)
    known_hypotheses: set[str] = set()
    known_requirements: dict[str, set[str]] = {}
    for record in records:
        kinds = {
            _upper(entry.get("requirement_kind"))
            for entry in _mapping_items(record.get("required_evidence"))
            if entry.get("requirement_kind")
        }
        for ref in record.get("hypothesis_refs") or ():
            name = _safe_text(ref, 16)
            if not name:
                continue
            known_hypotheses.add(name)
            known_requirements.setdefault(name, set()).update(kinds)
    if not known_hypotheses:
        for position in range(1, len(_mapping_items(hypotheses)) + 1):
            known_hypotheses.add(f"H{position}")
    requirement_index = _requirements_by_plan(acquisition_plan)
    raw_refs = _raw_outcome_refs(action_plan)
    redaction_peers: dict[str, set[str]] = {}
    for ref in raw_refs:
        redaction_peers.setdefault(_redact_like_r31(ref), set()).add(ref)
    ambiguous_refs = {
        ref
        for group in redaction_peers.values()
        if len(group) > 1
        for ref in group
    }
    known_refs: set[str] = set(raw_refs)
    for ref in raw_refs:
        known_refs.add(_redact_like_r31(ref))
    for entries in requirement_index.values():
        for _, refs in entries.values():
            known_refs.update(refs)
    items, rejections = _normalize_evidence(
        new_evidence, known_hypotheses, known_refs, ambiguous_refs,
        known_requirements,
    )
    plans = _plans_by_ref(acquisition_plan)
    iterations: list[dict] = []
    for position, record in enumerate(records, start=1):
        plan_ref = _safe_text(record.get("plan_ref"), 16)
        iteration, _ = _evaluate_record(
            record,
            plans.get(plan_ref),
            requirement_index.get(plan_ref, {}),
            items,
            position,
        )
        iterations.append(iteration)
    return iterations, rejections


def summarize_iterations(iterations: object = None) -> dict:
    """Bounded iteration summary (counts, bands, top record)."""

    items = list(_mapping_items(iterations))
    feedback_bands = {state: 0 for state in FEEDBACK_STATES}
    state_bands = {state: 0 for state in HYPOTHESIS_STATES}
    next_bands = {decision: 0 for decision in NEXT_ITERATIONS}
    for iteration in items:
        feedback = _upper(iteration.get("feedback_state"))
        if feedback in feedback_bands:
            feedback_bands[feedback] += 1
        state = _upper(iteration.get("current_state"))
        if state in state_bands:
            state_bands[state] += 1
        decision = _upper(iteration.get("next_iteration"))
        if decision in next_bands:
            next_bands[decision] += 1
    top = items[0] if items else {}
    return {
        "rule_version": RULE_VERSION,
        "iteration_count": len(items),
        "covered_plans": len(
            {
                _safe_text(item.get("plan_ref"), 16)
                for item in items
                if item.get("plan_ref")
            }
        ),
        "covered_hypotheses": sum(
            int(item.get("hypothesis_count") or 0) for item in items
        ),
        "feedback_bands": feedback_bands,
        "hypothesis_state_bands": state_bands,
        "next_iteration_bands": next_bands,
        "human_review_required": any(
            bool(item.get("human_review_required")) for item in items
        ),
        "top_iteration_id": _safe_text(top.get("iteration_id"), 16),
        "top_feedback_state": _upper(top.get("feedback_state")),
        "top_current_state": _upper(top.get("current_state")),
        "top_next_iteration": _upper(top.get("next_iteration")),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def evaluate_research_iteration(
    hypotheses: object = None,
    *,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
    new_evidence: object = None,
    limit: int = MAX_ITERATIONS,
) -> dict:
    """Evaluate one bounded feedback iteration over the previous chain."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ResearchFeedbackError("limit must be an integer")
    if limit < 0:
        raise ResearchFeedbackError("limit must be >= 0")

    iterations, rejections = build_iteration_records(
        hypotheses,
        action_plan=action_plan,
        acquisition_plan=acquisition_plan,
        readiness_plan=readiness_plan,
        new_evidence=new_evidence,
    )
    limited = [dict(iteration) for iteration in iterations[:limit]]
    for position, iteration in enumerate(limited, start=1):
        iteration["iteration_id"] = f"I{position}"
        iteration["order"] = position
    return {
        "rule_version": RULE_VERSION,
        "source_action_rule_version": (
            _safe_text(_block(action_plan).get("rule_version"), 32)
            or SOURCE_ACTION_RULE_VERSION
        ),
        "source_acquisition_rule_version": (
            _safe_text(_block(acquisition_plan).get("rule_version"), 32)
            or SOURCE_ACQUISITION_RULE_VERSION
        ),
        "source_readiness_rule_version": (
            _safe_text(_block(readiness_plan).get("rule_version"), 32)
            or SOURCE_READINESS_RULE_VERSION
        ),
        "iterations": limited,
        "rejections": rejections[:MAX_REJECTIONS],
        "summary": summarize_iterations(limited),
        "safety": dict(SAFETY_BLOCK),
        "research_only": True,
    }


__all__ = [
    "RULE_VERSION",
    "SOURCE_ACTION_RULE_VERSION",
    "SOURCE_ACQUISITION_RULE_VERSION",
    "SOURCE_READINESS_RULE_VERSION",
    "MAX_ITERATIONS",
    "MAX_HYPOTHESES",
    "MAX_REQUIREMENTS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_DELTAS",
    "MAX_CHANGED_REFS",
    "MAX_REJECTIONS",
    "MAX_TEXT_CHARS",
    "MAX_REF_CHARS",
    "EFFECT_PROVIDES",
    "EFFECT_CONTRADICTS",
    "EFFECT_INVALIDATES",
    "EVIDENCE_EFFECTS",
    "SOURCE_EXISTING_CONTEXT",
    "SOURCE_STORED_RESPONSE",
    "SOURCE_HUMAN_REVIEW",
    "SOURCE_WATCH_DERIVED",
    "EVIDENCE_SOURCES",
    "EVIDENCE_REF_KINDS",
    "FEEDBACK_NO_CHANGE",
    "FEEDBACK_NEW_SUPPORTING",
    "FEEDBACK_NEW_CONTRADICTING",
    "FEEDBACK_GAP_REDUCED",
    "FEEDBACK_GAP_REMAINS",
    "FEEDBACK_INVALIDATED",
    "FEEDBACK_REQUIRES_REVIEW",
    "FEEDBACK_STATES",
    "FEEDBACK_PRECEDENCE",
    "STATE_RETAIN",
    "STATE_REFINE",
    "STATE_WEAKEN",
    "STATE_UNRESOLVED",
    "STATE_STOP",
    "HYPOTHESIS_STATES",
    "STATE_SEVERITY",
    "NEXT_CONTINUE",
    "NEXT_HUMAN_REVIEW",
    "NEXT_STOP",
    "NEXT_ITERATIONS",
    "REASON_CODES",
    "REASON_TEXTS",
    "REASON_NO_RELEVANT_EVIDENCE",
    "REASON_SUPPORTING_EVIDENCE_ADDED",
    "REASON_MISSING_EVIDENCE_ACQUIRED",
    "REASON_CONTRADICTING_EVIDENCE",
    "REASON_EVIDENCE_INVALIDATED",
    "REASON_DECISION_EVIDENCE_COMPLETE",
    "REASON_DECISION_EVIDENCE_NOT_COMPLETE",
    "REASON_ACQUISITION_UNAVAILABLE",
    "CAUSE_NEW_EVIDENCE",
    "CAUSE_INVALIDATION",
    "DELTA_CAUSES",
    "REJECTION_CODES",
    "REJECTION_MALFORMED_EVIDENCE",
    "REJECTION_UNSUPPORTED_EFFECT",
    "REJECTION_UNKNOWN_HYPOTHESIS",
    "REJECTION_UNKNOWN_REQUIREMENT",
    "REJECTION_UNKNOWN_INVALIDATED_REF",
    "REJECTION_AMBIGUOUS_EVIDENCE",
    "REJECTION_SENSITIVE_EVIDENCE",
    "REJECTION_INVALID_SOURCE",
    "ResearchFeedbackError",
    "build_iteration_records",
    "summarize_iterations",
    "evaluate_research_iteration",
]
