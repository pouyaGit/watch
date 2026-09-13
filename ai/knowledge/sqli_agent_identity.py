"""Stage R41.1 deterministic SQLi agent identity planner (pure engine).

Defines WHO the SQL injection specialist research agent is:

    "Which SQL query contexts does this agent cover?"

Hard boundaries encoded here:

- Research intelligence only: no SQL execution, no database connection, no
  payload, no network request, no fuzzing, no sqlmap, no subprocess, no
  socket, no browser, no external API, no LLM call, no persistence, worker
  or scheduler is created.
- Conforms to R38: the agent id uses the R38 content-token format, the
  identity projects onto a valid ``SecurityAgentIdentityPlan``, declared
  capabilities are restricted to the R38 analysis-only vocabulary, and the
  lifecycle is restricted to identity states (CREATED/PLANNED).
- Pure and offline: no I/O, no SQL, no network, no LLM, no target
  interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.security_agent_identity import compute_agent_id
from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    PROHIBITED_CAPABILITIES,
)
from ai.schemas.security_agent_identity import (
    CATEGORY_SQLI,
    SecurityAgentIdentityPlan,
    security_agent_identity_plan_projection,
)
from ai.schemas.sqli_agent_identity import (
    LIFECYCLE_PLANNED,
    LIMITATION_NO_EXECUTION_CAPABILITY,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_NO_SQL_EXECUTION,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_SCOPE_UNKNOWN,
    MATURITY_UNKNOWN,
    SQLI_AGENT_IDENTITY_RULE_VERSION,
    SQLI_IDENTITY_LIFECYCLE_STATES,
    SQLI_KNOWN_MATURITIES,
    SQLIAgentIdentityPlan,
    sanitize_sqli_agent_identity_plan,
    sqli_agent_identity_plan_projection,
)
from ai.schemas.sqli_context_analysis import (
    QCTX_UNKNOWN,
    QUERY_CONTEXTS,
)

SQLI_AGENT_IDENTITY_PLANNER_RULE_VERSION = "r41-1"
RULE_VERSION = SQLI_AGENT_IDENTITY_PLANNER_RULE_VERSION

DEFAULT_AGENT_NAME = "sqli-agent"
DEFAULT_AGENT_VERSION = "1.0"

KNOWN_CONTEXTS: tuple[str, ...] = tuple(
    value for value in QUERY_CONTEXTS if value != QCTX_UNKNOWN
)

DEFAULT_SUPPORTED_CONTEXTS: tuple[str, ...] = KNOWN_CONTEXTS
DEFAULT_SUPPORTED_CAPABILITIES: tuple[str, ...] = ALLOWED_CAPABILITIES


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def default_supported_contexts() -> list[str]:
    """Deterministic default SQLi research scope."""

    return list(DEFAULT_SUPPORTED_CONTEXTS)


def default_supported_capabilities() -> list[str]:
    """Deterministic default (analysis-only) capabilities."""

    return list(DEFAULT_SUPPORTED_CAPABILITIES)


def resolve_supported_contexts(value: object = None) -> list[str]:
    """Bound caller contexts to the known query-context set."""

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


def resolve_supported_capabilities(value: object = None) -> list[str]:
    """Bound caller capabilities to the R38 allowed analysis-only set.

    Prohibited execution capabilities are always dropped; an explicit list
    that resolves to nothing yields an empty (honest) declaration instead of
    silently granting defaults.
    """

    if value is None:
        return default_supported_capabilities()
    if isinstance(value, (str, bytes)):
        raw = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = list(value)
    else:
        raw = []
    out: list[str] = []
    for item in raw:
        text = _upper(item)
        if (
            text in ALLOWED_CAPABILITIES
            and text not in PROHIBITED_CAPABILITIES
            and text not in out
        ):
            out.append(text)
    return out


def compute_sqli_agent_id(
    agent_name: object = None,
    version: object = None,
) -> str:
    """Deterministic R38-conformant content id for the SQLi agent."""

    return compute_agent_id(
        CATEGORY_SQLI,
        _text(agent_name) or DEFAULT_AGENT_NAME,
        _text(version) or DEFAULT_AGENT_VERSION,
    )


def plan_sqli_agent_identity(
    maturity: object = None,
    version: object = None,
    supported_contexts: object = None,
    supported_capabilities: object = None,
    lifecycle_state: object = None,
    agent_name: object = None,
) -> dict:
    """Build the deterministic SQLi agent identity (read-only).

    Missing/malformed maturity remains ``UNKNOWN``; malformed lifecycle
    resolves to the safe identity state ``PLANNED``. Contexts are bounded to
    the known query-context set; when none survive, the plan declares
    ``UNKNOWN`` scope and records the ``SCOPE_UNKNOWN`` limitation.
    """

    resolved_maturity = _upper(maturity)
    if resolved_maturity not in SQLI_KNOWN_MATURITIES:
        resolved_maturity = MATURITY_UNKNOWN

    resolved_lifecycle = _upper(lifecycle_state)
    if resolved_lifecycle not in SQLI_IDENTITY_LIFECYCLE_STATES:
        resolved_lifecycle = LIFECYCLE_PLANNED

    contexts = resolve_supported_contexts(supported_contexts)
    limitations = [
        LIMITATION_NO_EXECUTION_CAPABILITY,
        LIMITATION_NO_SQL_EXECUTION,
        LIMITATION_NO_NETWORK_REQUESTS,
        LIMITATION_NO_PAYLOAD_GENERATION,
        LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    ]
    if not contexts:
        contexts = [QCTX_UNKNOWN]
        limitations.append(LIMITATION_SCOPE_UNKNOWN)

    resolved_name = _text(agent_name) or DEFAULT_AGENT_NAME
    resolved_version = _text(version) or DEFAULT_AGENT_VERSION

    plan = SQLIAgentIdentityPlan(
        rule_version=SQLI_AGENT_IDENTITY_RULE_VERSION,
        agent_id=compute_sqli_agent_id(resolved_name, resolved_version),
        agent_name=resolved_name,
        category=CATEGORY_SQLI,
        version=resolved_version,
        maturity=resolved_maturity,
        supported_contexts=contexts,
        supported_capabilities=resolve_supported_capabilities(
            supported_capabilities
        ),
        lifecycle_state=resolved_lifecycle,
        limitations=limitations,
        research_only=True,
    )
    return sqli_agent_identity_plan_projection(plan)


def sqli_agent_identity_to_r38(identity_plan: object = None) -> dict:
    """Project the SQLi identity onto a valid R38 identity plan.

    The R38 identity contract has no SQLi-specific context or capability
    fields; the R41 identity remains the carrier of that information while
    this projection proves R38 category/maturity/id conformance.
    """

    identity = sanitize_sqli_agent_identity_plan(
        identity_plan
        if isinstance(identity_plan, dict)
        else plan_sqli_agent_identity()
    )
    agent_id = identity["agent_id"] or compute_sqli_agent_id(
        identity["agent_name"], identity["version"]
    )
    plan = SecurityAgentIdentityPlan(
        agent_id=agent_id,
        agent_name=identity["agent_name"] or DEFAULT_AGENT_NAME,
        category=CATEGORY_SQLI,
        version=identity["version"] or DEFAULT_AGENT_VERSION,
        maturity=identity["maturity"],
        description="",
        research_only=True,
    )
    return security_agent_identity_plan_projection(plan)


__all__ = [
    "SQLI_AGENT_IDENTITY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "DEFAULT_AGENT_NAME",
    "DEFAULT_AGENT_VERSION",
    "KNOWN_CONTEXTS",
    "DEFAULT_SUPPORTED_CONTEXTS",
    "DEFAULT_SUPPORTED_CAPABILITIES",
    "default_supported_contexts",
    "default_supported_capabilities",
    "resolve_supported_contexts",
    "resolve_supported_capabilities",
    "compute_sqli_agent_id",
    "plan_sqli_agent_identity",
    "sqli_agent_identity_to_r38",
]
