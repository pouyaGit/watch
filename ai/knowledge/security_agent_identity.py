"""Stage R38.1 deterministic security agent identity planner (pure engine).

Defines WHO a future security specialist agent is:

    "Which category of security specialist is this agent?"

Hard boundaries encoded here:

- Framework/model only: no agent runtime, vulnerability scanning, HTTP,
  crawling, fuzzing, Nuclei, payloads, exploits, browser automation,
  subprocess, shell, queues, schedulers, autonomous loops, tool execution,
  external APIs, LLM calls, embeddings, Mongo persistence, database writes,
  plugin loading or dynamic imports.
- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no target interaction, no Mongo, no wall-clock time, no
  randomness, no environment or filesystem state.
- Unknown categories must remain ``UNKNOWN`` and are never promoted.
- Deterministic: the agent id is a content token (SHA-256 over bounded
  identity fields); identical input always produces identical output.
- No runtime metadata, no execution capability, read-only inputs.
"""

from __future__ import annotations

import hashlib

from ai.schemas.security_agent_identity import (
    AGENT_CATEGORIES,
    AGENT_ID_PREFIX,
    AGENT_MATURITIES,
    CATEGORY_UNKNOWN,
    MATURITY_UNKNOWN,
    SECURITY_AGENT_IDENTITY_RULE_VERSION,
    SecurityAgentIdentityPlan,
    security_agent_identity_plan_projection,
)

SECURITY_AGENT_IDENTITY_PLANNER_RULE_VERSION = "r38-1"
RULE_VERSION = SECURITY_AGENT_IDENTITY_PLANNER_RULE_VERSION

DEFAULT_VERSION = "UNKNOWN"


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def default_agent_name(category: str) -> str:
    """Deterministic default agent name for a closed category."""

    if category in AGENT_CATEGORIES and category != CATEGORY_UNKNOWN:
        return f"{category.lower()}-agent"
    return "unknown-agent"


def compute_agent_id(
    category: object,
    agent_name: object,
    version: object = None,
) -> str:
    """Deterministic content id over bounded identity fields (no clock)."""

    basis = "\n".join(
        [
            SECURITY_AGENT_IDENTITY_RULE_VERSION,
            _upper(category),
            _text(agent_name),
            _text(version) or DEFAULT_VERSION,
        ]
    )
    return AGENT_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


def plan_security_agent_identity(
    category: object = None,
    agent_name: object = None,
    version: object = None,
    maturity: object = None,
    description: object = None,
) -> dict:
    """Build a deterministic security agent identity (read-only).

    Missing/malformed categories remain ``UNKNOWN``; missing/malformed
    maturity levels remain ``UNKNOWN``. The default agent name is derived
    deterministically from the closed category. No execution capability of
    any kind is represented.
    """

    resolved_category = _upper(category)
    if resolved_category not in AGENT_CATEGORIES:
        resolved_category = CATEGORY_UNKNOWN

    resolved_maturity = _upper(maturity)
    if resolved_maturity not in AGENT_MATURITIES:
        resolved_maturity = MATURITY_UNKNOWN

    resolved_name = _text(agent_name) or default_agent_name(
        resolved_category
    )
    resolved_version = _text(version) or DEFAULT_VERSION

    plan = SecurityAgentIdentityPlan(
        rule_version=SECURITY_AGENT_IDENTITY_RULE_VERSION,
        agent_id=compute_agent_id(
            resolved_category, resolved_name, resolved_version
        ),
        agent_name=resolved_name,
        category=resolved_category,
        version=resolved_version,
        maturity=resolved_maturity,
        description=_text(description),
        research_only=True,
    )
    return security_agent_identity_plan_projection(plan)


__all__ = [
    "SECURITY_AGENT_IDENTITY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_VERSION",
    "default_agent_name",
    "compute_agent_id",
    "plan_security_agent_identity",
]
