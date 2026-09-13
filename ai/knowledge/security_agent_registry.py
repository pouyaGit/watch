"""Stage R38.6 deterministic security agent registry builder (pure engine).

Builds the static conceptual registry of security specialist categories:

    "Which conceptual security specialists exist in the framework?"

Hard boundaries encoded here:

- Framework/model only: the registry is static data. No plugin system, no
  dynamic discovery, no dynamic imports, no runtime, no execution.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Closed categories only; caller-supplied entries are bounded, validated and
  never extended with arbitrary capabilities.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import (
    CATEGORY_CVE_RESEARCH,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_RECON,
    CATEGORY_SQLI,
    CATEGORY_SSRF,
    CATEGORY_XSS,
    MATURITY_EXPERIMENTAL,
    MATURITY_RESEARCH,
)
from ai.schemas.security_agent_registry import (
    MAX_ENTRIES,
    REGISTRY_PARTIAL,
    REGISTRY_UNKNOWN,
    REGISTRY_VALID,
    SECURITY_AGENT_REGISTRY_RULE_VERSION,
    SecurityAgentRegistryPlan,
    sanitize_registry_entry,
    security_agent_registry_plan_projection,
)
from ai.knowledge.security_agent_capability import (
    CATEGORY_CAPABILITIES,
)
from ai.knowledge.security_agent_identity import (
    compute_agent_id,
    default_agent_name,
)

SECURITY_AGENT_REGISTRY_BUILDER_RULE_VERSION = "r38-6"
RULE_VERSION = SECURITY_AGENT_REGISTRY_BUILDER_RULE_VERSION

# Static framework maturity per category (no runtime metadata).
STATIC_MATURITY: dict[str, str] = {
    CATEGORY_XSS: MATURITY_RESEARCH,
    CATEGORY_SSRF: MATURITY_EXPERIMENTAL,
    CATEGORY_SQLI: MATURITY_EXPERIMENTAL,
    CATEGORY_IDOR: MATURITY_EXPERIMENTAL,
    CATEGORY_JWT: MATURITY_EXPERIMENTAL,
    CATEGORY_OAUTH: MATURITY_EXPERIMENTAL,
    CATEGORY_CVE_RESEARCH: MATURITY_RESEARCH,
    CATEGORY_RECON: MATURITY_RESEARCH,
}

# Fixed static registration order.
STATIC_CATEGORIES: tuple[str, ...] = (
    CATEGORY_XSS,
    CATEGORY_SSRF,
    CATEGORY_SQLI,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_CVE_RESEARCH,
    CATEGORY_RECON,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def static_registry_entries() -> list[dict]:
    """Deterministic static framework entries (no discovery, no plugins)."""

    entries: list[dict] = []
    for category in STATIC_CATEGORIES:
        name = default_agent_name(category)
        maturity = STATIC_MATURITY[category]
        capabilities = [
            capability
            for capability in CATEGORY_CAPABILITIES.get(category, ())
            if capability in ALLOWED_CAPABILITIES
            and capability not in PROHIBITED_CAPABILITIES
        ]
        entries.append(
            {
                "agent_id": compute_agent_id(category, name, "UNKNOWN"),
                "category": category,
                "maturity": maturity,
                "capabilities": capabilities,
            }
        )
    return entries


def build_security_agent_registry(entries: object = None) -> dict:
    """Build the static registry, or validate bounded caller entries.

    When ``entries`` is None the deterministic static registry is built.
    Caller-supplied entries are bounded and filtered: invalid entries are
    skipped and downgrade the registry state to ``PARTIAL``; an empty result
    is ``UNKNOWN``.
    """

    if entries is None:
        resolved = static_registry_entries()[:MAX_ENTRIES]
        state = REGISTRY_VALID if resolved else REGISTRY_UNKNOWN
    else:
        raw = list(entries) if isinstance(entries, (list, tuple)) else []
        resolved = []
        skipped = 0
        for item in raw[:MAX_ENTRIES]:
            entry = sanitize_registry_entry(item)
            if not entry["agent_id"] or not entry["category"]:
                skipped += 1
                continue
            if entry not in resolved:
                resolved.append(entry)
        if not resolved:
            state = REGISTRY_UNKNOWN
        elif skipped:
            state = REGISTRY_PARTIAL
        else:
            state = REGISTRY_VALID

    plan = SecurityAgentRegistryPlan(
        rule_version=SECURITY_AGENT_REGISTRY_RULE_VERSION,
        registered_agents=resolved,
        registry_state=state,
        research_only=True,
    )
    return security_agent_registry_plan_projection(plan)


__all__ = [
    "SECURITY_AGENT_REGISTRY_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "STATIC_MATURITY",
    "STATIC_CATEGORIES",
    "static_registry_entries",
    "build_security_agent_registry",
]
