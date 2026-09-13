"""Stage R43.2 deterministic shared research context (pure engine).

Builds and deterministically merges bounded shared research context:

    "Which structured research context do the collaborating agents share?"

Hard boundaries encoded here:

- Collaboration only: context is normalized and referenced; it is never
  mutated in place, and no reasoning/memory/learning/strategy/
  orchestration/authorization/governance logic is duplicated.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.shared_research_context import (
    CONTEXT_BLOCK_KEYS,
    SHARED_RESEARCH_CONTEXT_RULE_VERSION,
    SOURCE_LAYERS,
    SharedResearchContextPlan,
    sanitize_shared_research_context,
    shared_research_context_plan_projection,
)

SHARED_RESEARCH_CONTEXT_BUILDER_RULE_VERSION = "r43-2"
RULE_VERSION = SHARED_RESEARCH_CONTEXT_BUILDER_RULE_VERSION

BLOCK_KEYS: tuple[str, ...] = CONTEXT_BLOCK_KEYS


def build_shared_research_context(value: object = None) -> dict:
    """Build a bounded shared research context (read-only)."""

    sanitized = sanitize_shared_research_context(value)
    sanitized["rule_version"] = SHARED_RESEARCH_CONTEXT_RULE_VERSION
    plan = SharedResearchContextPlan(**sanitized)
    return shared_research_context_plan_projection(plan)


def merge_shared_research_context(values: object = None) -> dict:
    """Merge shared contexts deterministically (read-only).

    Blocks are merged key-wise; the first non-empty value wins in input
    order, list values are unioned preserving first-seen order, and source
    layers are emitted in canonical layer order. Inputs are never mutated.
    """

    if isinstance(values, dict):
        raw_items = [values]
    elif isinstance(values, (list, tuple)):
        raw_items = list(values)
    else:
        raw_items = []

    contexts = [
        sanitize_shared_research_context(item) for item in raw_items
    ]

    merged = {
        "rule_version": SHARED_RESEARCH_CONTEXT_RULE_VERSION,
        "asset_reference": "",
        "application_context": {},
        "technology_context": {},
        "input_surface_context": {},
        "observed_behavior_context": {},
        "existing_research_context": {},
        "source_layers": [],
        "authorization_context": {},
        "governance_context": {},
        "research_only": True,
    }

    for context in contexts:
        if not merged["asset_reference"] and context["asset_reference"]:
            merged["asset_reference"] = context["asset_reference"]
        for block in BLOCK_KEYS:
            target = merged[block]
            for key, value in context[block].items():
                if key not in target:
                    target[key] = value
                elif isinstance(target[key], list) and isinstance(
                    value, list
                ):
                    for item in value:
                        if item not in target[key]:
                            target[key].append(item)

    layers: list[str] = []
    for layer in SOURCE_LAYERS:
        if any(layer in context["source_layers"] for context in contexts):
            layers.append(layer)
    merged["source_layers"] = layers

    plan = SharedResearchContextPlan(**merged)
    return shared_research_context_plan_projection(plan)


def shared_context_fact_count(value: object) -> int:
    """Count known shared-context facts (bounded, generic)."""

    context = sanitize_shared_research_context(value)
    count = 0
    if context["asset_reference"]:
        count += 1
    for block in BLOCK_KEYS:
        for entry in context[block].values():
            if isinstance(entry, list):
                if entry:
                    count += 1
            elif entry not in ("", None):
                count += 1
    return count


def shared_context_summary(value: object) -> dict:
    """Deterministic summary of a shared research context."""

    context = sanitize_shared_research_context(value)
    blocks_present = [
        block
        for block in BLOCK_KEYS
        if context[block]
    ]
    return {
        "asset_reference_present": bool(context["asset_reference"]),
        "blocks_present": blocks_present,
        "block_count": len(blocks_present),
        "fact_count": shared_context_fact_count(context),
        "source_layers": list(context["source_layers"]),
        "research_only": True,
    }


__all__ = [
    "SHARED_RESEARCH_CONTEXT_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "BLOCK_KEYS",
    "build_shared_research_context",
    "merge_shared_research_context",
    "shared_context_fact_count",
    "shared_context_summary",
]
