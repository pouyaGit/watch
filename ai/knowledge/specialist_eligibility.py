"""Stage R52.2 deterministic specialist eligibility and selection (pure engine).

Determines which existing specialists are relevant to a structured research
context and derives the deterministic orchestration selection:

    "Which specialists are relevant to this context, and which are selected?"

Hard boundaries encoded here:

- Orchestration/model only: eligibility reads structured data and performs no
  execution, no network, no database, no browser, no LLM call, no subprocess
  and no target interaction.
- Relevance only: eligibility means "this specialist is relevant to the
  supplied research context". It never means a vulnerability exists and it
  never confirms, ranks or scores a finding.
- No keyword-only inference: a specialist is eligible only when at least one
  of its declared discriminating structured context keys carries a known
  value. Generic shared keys (for example ``input_location``) never make a
  specialist eligible on their own.
- Deterministic: eligibility, selection and ordering are pure functions of
  the bounded context, registry and policy; the canonical order and the
  (priority, canonical order) sort never depend on dictionary or set
  iteration order.
- Explicit selection fails closed: unknown, disabled, ineligible or
  over-limit explicitly requested categories raise a structured selection
  error instead of being silently added or dropped.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.specialist_registry import (
    SPECIALIST_CONTEXT_KEYS,
    enabled_categories,
    registry_entry,
    static_registry_entries,
)
from ai.schemas.agent_orchestrator_context import (
    context_value_is_known,
    sanitize_orchestration_context,
)
from ai.schemas.agent_orchestrator_policy import (
    MODE_AUTOMATIC,
    MODE_EXPLICIT,
)
from ai.schemas.agent_orchestrator_registry import (
    CANONICAL_SPECIALIST_ORDER,
    SPECIALIST_CATEGORIES,
)
from ai.schemas.agent_orchestrator_result import (
    ERROR_SPECIALIST_SELECTION,
    ERROR_LIMIT_EXCEEDED,
    SKIP_DISABLED,
    SKIP_MAX_SPECIALISTS_EXCEEDED,
    SKIP_NOT_ELIGIBLE,
    SKIP_NOT_REQUESTED,
)

SPECIALIST_ELIGIBILITY_RULE_VERSION = "r52-2"
RULE_VERSION = SPECIALIST_ELIGIBILITY_RULE_VERSION

#: Context keys shared by more than one specialist. They are relevance
#: signals for the shared category family only and can never make a single
#: specialist eligible on their own.
SHARED_CONTEXT_KEYS: frozenset[str] = frozenset(
    {
        "input_location",
        "authentication_mechanism",
        "authorization_boundary",
        "issuer_validation",
        "token_exposure",
    }
)

#: Per-category discriminating structured context keys: keys that only that
#: specialist's analyzer consumes (shared keys removed).
SPECIALIST_SIGNAL_KEYS: dict[str, tuple[str, ...]] = {
    category: tuple(
        key
        for key in SPECIALIST_CONTEXT_KEYS.get(category, ())
        if key not in SHARED_CONTEXT_KEYS
    )
    for category in CANONICAL_SPECIALIST_ORDER
}


class SpecialistSelectionError(ValueError):
    """Structured, deterministic specialist selection failure."""

    def __init__(
        self,
        message: str,
        *,
        error_category: str = ERROR_SPECIALIST_SELECTION,
        category: str = "",
        reason: str = "",
    ):
        super().__init__(message)
        self.error_category = error_category
        self.category = category
        self.reason = reason


def matched_signal_keys(category: object, context: object = None) -> list[str]:
    """Discriminating context keys carrying a known value (bounded)."""

    resolved = str(category if category is not None else "").strip().upper()
    if resolved not in SPECIALIST_SIGNAL_KEYS:
        return []
    bounded = sanitize_orchestration_context(context)
    matched: list[str] = []
    for key in SPECIALIST_SIGNAL_KEYS[resolved]:
        if context_value_is_known(bounded.get(key)):
            matched.append(key)
    return matched


def specialist_is_eligible(category: object, context: object = None) -> bool:
    """True when the specialist is relevant to the structured context.

    Relevance only: eligibility is not a vulnerability claim, a confidence
    level or a finding.
    """

    return bool(matched_signal_keys(category, context))


def analyze_specialist_eligibility(
    context: object = None,
    registry: object = None,
) -> dict:
    """Analyze eligibility for every registered category (read-only).

    Returns the eligible categories in canonical order, the ineligible
    categories, the matched signal keys per eligible category and the number
    of known context values. Nothing is executed and no vulnerability state
    is produced.
    """

    bounded = sanitize_orchestration_context(context)
    enabled = (
        enabled_categories(registry)
        if isinstance(registry, dict)
        else enabled_categories(None)
    )
    entries = (
        registry.get("entries")
        if isinstance(registry, dict)
        else None
    )
    if entries is None:
        entries = static_registry_entries()
    eligible: list[str] = []
    ineligible: list[str] = []
    signals: dict[str, list[str]] = {}
    for category in CANONICAL_SPECIALIST_ORDER:
        entry = registry_entry(category, {"entries": entries})
        if entry.get("enabled") is not True:
            continue
        matched = matched_signal_keys(category, bounded)
        if matched:
            eligible.append(category)
            signals[category] = matched
        else:
            ineligible.append(category)
    return {
        "rule_version": SPECIALIST_ELIGIBILITY_RULE_VERSION,
        "context": bounded,
        "enabled_categories": enabled,
        "eligible_categories": eligible,
        "ineligible_categories": ineligible,
        "signal_keys": signals,
        "known_context_values": sum(
            1 for value in bounded.values() if context_value_is_known(value)
        ),
        "relevance_only": True,
        "research_only": True,
    }


def _skipped_for_automatic(
    selected: list[str],
    limit_exceeded: list[str],
    registry: object = None,
) -> list[dict]:
    skipped: list[dict] = []
    for category in CANONICAL_SPECIALIST_ORDER:
        if category in selected:
            continue
        entry = registry_entry(category, registry)
        if entry.get("enabled") is not True:
            reason = SKIP_DISABLED
        elif category in limit_exceeded:
            reason = SKIP_MAX_SPECIALISTS_EXCEEDED
        else:
            reason = SKIP_NOT_ELIGIBLE
        skipped.append({"category": category, "reason": reason})
    return skipped


def select_specialists(
    eligibility: object = None,
    policy: object = None,
    registry: object = None,
) -> dict:
    """Derive the deterministic selection from eligibility and policy.

    Automatic mode selects eligible specialists in canonical order up to the
    policy maximum. Explicit mode requires every requested category to be a
    known, enabled, eligible category within the policy maximum; otherwise a
    structured :class:`SpecialistSelectionError` is raised (fail closed).
    """

    if not isinstance(eligibility, dict):
        raise SpecialistSelectionError("missing eligibility analysis")
    if not isinstance(policy, dict):
        raise SpecialistSelectionError("missing orchestration policy")

    mode = str(policy.get("mode") or MODE_AUTOMATIC).strip().upper()
    eligible = [
        category
        for category in CANONICAL_SPECIALIST_ORDER
        if category in (eligibility.get("eligible_categories") or ())
    ]
    max_specialists = policy.get("max_specialists")
    if isinstance(max_specialists, bool) or not isinstance(
        max_specialists, int
    ):
        raise SpecialistSelectionError("invalid max_specialists")
    if max_specialists < 1:
        raise SpecialistSelectionError("invalid max_specialists")

    if mode == MODE_EXPLICIT:
        requested = [
            str(item).strip().upper()
            for item in (policy.get("allowed_categories") or ())
        ]
        if not requested:
            raise SpecialistSelectionError(
                "explicit selection requires at least one category"
            )
        for category in requested:
            if category not in SPECIALIST_CATEGORIES:
                raise SpecialistSelectionError(
                    f"unknown specialist category: {category}",
                    category=category,
                    reason="UNKNOWN_CATEGORY",
                )
            entry = registry_entry(category, registry)
            if entry.get("enabled") is not True:
                raise SpecialistSelectionError(
                    f"specialist category is disabled: {category}",
                    category=category,
                    reason="DISABLED",
                )
            if category not in eligible:
                raise SpecialistSelectionError(
                    f"specialist category is not relevant to the supplied "
                    f"context: {category}",
                    category=category,
                    reason="INELIGIBLE",
                )
        ordered = [
            category
            for category in CANONICAL_SPECIALIST_ORDER
            if category in requested
        ]
        if len(ordered) > max_specialists:
            raise SpecialistSelectionError(
                "explicit selection exceeds max_specialists",
                error_category=ERROR_LIMIT_EXCEEDED,
                reason="MAX_SPECIALISTS_EXCEEDED",
            )
        selected = ordered
        limit_exceeded: list[str] = []
        skipped = [
            {
                "category": category,
                "reason": (
                    SKIP_DISABLED
                    if registry_entry(category, registry).get("enabled")
                    is not True
                    else SKIP_NOT_REQUESTED
                ),
            }
            for category in CANONICAL_SPECIALIST_ORDER
            if category not in selected
        ]
    elif mode == MODE_AUTOMATIC:
        selected = eligible[:max_specialists]
        limit_exceeded = eligible[max_specialists:]
        skipped = _skipped_for_automatic(
            selected, limit_exceeded, registry
        )
    else:
        raise SpecialistSelectionError(f"invalid selection mode: {mode}")

    return {
        "rule_version": SPECIALIST_ELIGIBILITY_RULE_VERSION,
        "mode": mode,
        "selected_specialists": selected,
        "skipped_specialists": skipped,
        "limit_exceeded_specialists": list(limit_exceeded)
        if mode == MODE_AUTOMATIC
        else [],
        "research_only": True,
    }


__all__ = [
    "SPECIALIST_ELIGIBILITY_RULE_VERSION",
    "RULE_VERSION",
    "SHARED_CONTEXT_KEYS",
    "SPECIALIST_SIGNAL_KEYS",
    "SpecialistSelectionError",
    "matched_signal_keys",
    "specialist_is_eligible",
    "analyze_specialist_eligibility",
    "select_specialists",
]
