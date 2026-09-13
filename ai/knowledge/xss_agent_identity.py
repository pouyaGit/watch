"""Stage R39.1 deterministic XSS agent identity planner (pure engine).

Defines WHO the XSS specialist research agent is:

    "Which XSS research contexts does this agent cover?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP, payload execution, browser or
  JavaScript execution, DOM crawling, fuzzing, exploitation, auth bypass,
  subprocess, shell, external API, LLM call, persistence, worker or scheduler
  is created.
- Conforms to R38: the agent id uses the R38 content-token format and the
  identity projects onto a valid ``SecurityAgentIdentityPlan``.
- Pure and offline: no I/O, no network, no LLM, no browser, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.security_agent_identity import compute_agent_id
from ai.schemas.security_agent_identity import (
    CATEGORY_XSS,
    SecurityAgentIdentityPlan,
    security_agent_identity_plan_projection,
)
from ai.schemas.xss_agent_identity import (
    CONTEXT_DOM,
    CONTEXT_REFLECTED,
    CONTEXT_STORED,
    CONTEXT_UNKNOWN,
    LIMITATION_CONTEXT_UNKNOWN,
    LIMITATION_NO_EXECUTION_CAPABILITY,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    MATURITY_UNKNOWN,
    XSS_AGENT_IDENTITY_RULE_VERSION,
    XSS_KNOWN_MATURITIES,
    XSSAgentIdentityPlan,
    sanitize_xss_agent_identity_plan,
    xss_agent_identity_plan_projection,
)

XSS_AGENT_IDENTITY_PLANNER_RULE_VERSION = "r39-1"
RULE_VERSION = XSS_AGENT_IDENTITY_PLANNER_RULE_VERSION

DEFAULT_AGENT_NAME = "xss-agent"
DEFAULT_AGENT_VERSION = "2.0"

DEFAULT_SUPPORTED_CONTEXTS: tuple[str, ...] = (
    CONTEXT_REFLECTED,
    CONTEXT_STORED,
    CONTEXT_DOM,
)

KNOWN_CONTEXTS: tuple[str, ...] = (
    CONTEXT_REFLECTED,
    CONTEXT_STORED,
    CONTEXT_DOM,
)


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def default_supported_contexts() -> list[str]:
    """Deterministic default XSS research contexts."""

    return list(DEFAULT_SUPPORTED_CONTEXTS)


def resolve_supported_contexts(value: object = None) -> list[str]:
    """Bound caller contexts to the known set, preserving input order."""

    if value is None:
        return default_supported_contexts()
    if isinstance(value, (str, bytes)):
        raw = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = list(value)
    else:
        raw = []
    out: list[str] = []
    for item in raw:
        text = _upper(item)
        if text in KNOWN_CONTEXTS and text not in out:
            out.append(text)
    return out


def compute_xss_agent_id(
    agent_name: object = None,
    version: object = None,
) -> str:
    """Deterministic R38-conformant content id for the XSS agent."""

    return compute_agent_id(
        CATEGORY_XSS,
        _text(agent_name) or DEFAULT_AGENT_NAME,
        _text(version) or DEFAULT_AGENT_VERSION,
    )


def plan_xss_agent_identity(
    maturity: object = None,
    version: object = None,
    supported_contexts: object = None,
    agent_name: object = None,
) -> dict:
    """Build the deterministic XSS agent identity (read-only).

    Missing/malformed maturity remains ``UNKNOWN``. Contexts are bounded to
    the known set; when none survive, the plan declares ``UNKNOWN`` coverage
    and records the ``CONTEXT_UNKNOWN`` limitation.
    """

    resolved_maturity = _upper(maturity)
    if resolved_maturity not in XSS_KNOWN_MATURITIES:
        resolved_maturity = MATURITY_UNKNOWN

    contexts = resolve_supported_contexts(supported_contexts)
    limitations = [
        LIMITATION_NO_EXECUTION_CAPABILITY,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    ]
    if not contexts:
        contexts = [CONTEXT_UNKNOWN]
        limitations.append(LIMITATION_CONTEXT_UNKNOWN)

    resolved_name = _text(agent_name) or DEFAULT_AGENT_NAME
    resolved_version = _text(version) or DEFAULT_AGENT_VERSION

    plan = XSSAgentIdentityPlan(
        rule_version=XSS_AGENT_IDENTITY_RULE_VERSION,
        agent_id=compute_xss_agent_id(resolved_name, resolved_version),
        agent_name=resolved_name,
        category=CATEGORY_XSS,
        version=resolved_version,
        maturity=resolved_maturity,
        supported_contexts=contexts,
        limitations=limitations,
        research_only=True,
    )
    return xss_agent_identity_plan_projection(plan)


def xss_agent_identity_to_r38(identity_plan: object = None) -> dict:
    """Project the XSS identity onto a valid R38 identity plan.

    The R38 identity contract has no XSS-specific context field; the R39
    identity remains the carrier of that information while this projection
    proves R38 category/maturity/id conformance.
    """

    identity = sanitize_xss_agent_identity_plan(
        identity_plan
        if isinstance(identity_plan, dict)
        else plan_xss_agent_identity()
    )
    agent_id = identity["agent_id"] or compute_xss_agent_id(
        identity["agent_name"], identity["version"]
    )
    plan = SecurityAgentIdentityPlan(
        agent_id=agent_id,
        agent_name=identity["agent_name"] or DEFAULT_AGENT_NAME,
        category=CATEGORY_XSS,
        version=identity["version"] or DEFAULT_AGENT_VERSION,
        maturity=identity["maturity"],
        description="",
        research_only=True,
    )
    return security_agent_identity_plan_projection(plan)


__all__ = [
    "XSS_AGENT_IDENTITY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_AGENT_NAME",
    "DEFAULT_AGENT_VERSION",
    "DEFAULT_SUPPORTED_CONTEXTS",
    "KNOWN_CONTEXTS",
    "default_supported_contexts",
    "resolve_supported_contexts",
    "compute_xss_agent_id",
    "plan_xss_agent_identity",
    "xss_agent_identity_to_r38",
]
