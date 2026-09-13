"""Stage R38.7 deterministic security agent framework exporter (pure engine).

Combines all R38 models into the final deterministic framework contract:

    "Is the security agent framework core complete and internally valid?"

Hard boundaries encoded here:

- Framework/model only: this is the Security Agent SDK foundation, not an
  execution engine. No agent runtime, vulnerability agent, autonomous loop,
  worker, tool execution, plugin loading or dynamic import is created.
- ``ready`` is true only when the identity, capability, lifecycle and
  registry contracts are valid; UNKNOWN critical states prevent readiness.
- Pure and offline: no I/O, no network, no LLM, no subprocess, no browser, no
  target interaction, no Mongo, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.security_agent_capability import (
    plan_security_agent_capabilities,
)
from ai.knowledge.security_agent_identity import (
    plan_security_agent_identity,
)
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.security_agent_lifecycle import (
    plan_security_agent_lifecycle,
)
from ai.knowledge.security_agent_registry import (
    STATIC_CATEGORIES,
    build_security_agent_registry,
)
from ai.knowledge.security_agent_result_validator import (
    validate_security_agent_result,
)
from ai.schemas.security_agent_capability import CAPABILITY_VALID
from ai.schemas.security_agent_framework_export import (
    LIMITATION_NO_REGISTERED_AGENTS,
    LIMITATION_PLACEHOLDER_TEMPLATES,
    LIMITATION_UNKNOWN_CAPABILITY,
    LIMITATION_UNKNOWN_IDENTITY,
    LIMITATION_UNKNOWN_LIFECYCLE,
    LIMITATION_UNKNOWN_REGISTRY,
    SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION,
    SecurityAgentFrameworkExportPlan,
    security_agent_framework_export_plan_projection,
)
from ai.schemas.security_agent_identity import AGENT_ID_RE, AGENT_CATEGORIES
from ai.schemas.security_agent_lifecycle import (
    LIFECYCLE_VALID,
    STATE_CREATED,
)
from ai.schemas.security_agent_registry import REGISTRY_VALID
from ai.schemas.security_agent_result import STATUS_CREATED

SECURITY_AGENT_FRAMEWORK_EXPORTER_RULE_VERSION = "r38-7"
RULE_VERSION = SECURITY_AGENT_FRAMEWORK_EXPORTER_RULE_VERSION


def export_security_agent_framework(
    identity_plans: object = None,
    capability_plans: object = None,
    input_plan: object = None,
    lifecycle_plan: object = None,
    result_plan: object = None,
    registry_plan: object = None,
) -> dict:
    """Package the R38 framework models into a deterministic export.

    When individual plans are omitted the static framework templates are
    built deterministically (no discovery, no plugins). ``ready`` requires
    valid identities, capabilities, lifecycle and registry contracts.
    """

    if identity_plans is None:
        identities = [
            plan_security_agent_identity(category)
            for category in STATIC_CATEGORIES
        ]
    else:
        identities = [
            plan_security_agent_identity(
                item.get("category") if isinstance(item, dict) else None,
                item.get("agent_name") if isinstance(item, dict) else None,
                item.get("version") if isinstance(item, dict) else None,
                item.get("maturity") if isinstance(item, dict) else None,
                item.get("description") if isinstance(item, dict) else None,
            )
            for item in (identity_plans or ())
            if isinstance(item, dict)
        ]

    if capability_plans is None:
        capabilities = [
            plan_security_agent_capabilities(category)
            for category in STATIC_CATEGORIES
        ]
    else:
        capabilities = [
            plan_security_agent_capabilities(
                item.get("agent_category")
                if isinstance(item, dict) else None
            )
            for item in (capability_plans or ())
            if isinstance(item, dict)
        ]

    if input_plan is None:
        primary = identities[0] if identities else {}
        input_contract = validate_security_agent_input(
            agent_identity=primary
        )
    else:
        input_contract = validate_security_agent_input(
            **_input_kwargs(input_plan)
        )

    if lifecycle_plan is None:
        lifecycle = plan_security_agent_lifecycle(STATE_CREATED)
    else:
        lifecycle = plan_security_agent_lifecycle(
            _field(lifecycle_plan, "current_state"),
            _field(lifecycle_plan, "previous_state"),
        )

    if result_plan is None:
        agent_name = identities[0].get("agent_name") if identities else ""
        result_contract = validate_security_agent_result(
            agent_name=agent_name, status=STATUS_CREATED
        )
    else:
        result_contract = validate_security_agent_result(
            agent_name=_field(result_plan, "agent_name"),
            status=_field(result_plan, "status"),
            confidence=_field(result_plan, "confidence"),
            findings_summary=_field(result_plan, "findings_summary"),
            evidence_summary=_field(result_plan, "evidence_summary"),
            limitations=_field(result_plan, "limitations"),
        )

    if registry_plan is None:
        registry = build_security_agent_registry()
    elif (
        isinstance(registry_plan, dict)
        and registry_plan.get("registered_agents") is not None
    ):
        registry = build_security_agent_registry(
            registry_plan.get("registered_agents")
        )
    else:
        registry = build_security_agent_registry([])

    identities_valid = bool(identities) and all(
        entry.get("category") in AGENT_CATEGORIES
        and AGENT_ID_RE.match(str(entry.get("agent_id") or ""))
        for entry in identities
    )
    capabilities_valid = bool(capabilities) and all(
        entry.get("capability_state") == CAPABILITY_VALID
        for entry in capabilities
    )
    lifecycle_valid = lifecycle.get("lifecycle_state") == LIFECYCLE_VALID
    registry_valid = registry.get("registry_state") == REGISTRY_VALID

    ready = (
        identities_valid and capabilities_valid
        and lifecycle_valid and registry_valid
    )

    limitations: list[str] = []
    if not identities_valid:
        limitations.append(LIMITATION_UNKNOWN_IDENTITY)
    if not capabilities_valid:
        limitations.append(LIMITATION_UNKNOWN_CAPABILITY)
    if not lifecycle_valid:
        limitations.append(LIMITATION_UNKNOWN_LIFECYCLE)
    if not registry_valid:
        limitations.append(LIMITATION_UNKNOWN_REGISTRY)
    if not registry.get("registered_agents"):
        limitations.append(LIMITATION_NO_REGISTERED_AGENTS)
    limitations.append(LIMITATION_PLACEHOLDER_TEMPLATES)

    plan = SecurityAgentFrameworkExportPlan(
        rule_version=SECURITY_AGENT_FRAMEWORK_EXPORT_RULE_VERSION,
        ready=ready,
        identities=identities,
        capabilities=capabilities,
        input_contract=input_contract,
        lifecycle=lifecycle,
        result_contract=result_contract,
        registry=registry,
        limitations=limitations,
        research_only=True,
    )
    return security_agent_framework_export_plan_projection(plan)


def _field(value: object, key: str) -> object:
    return value.get(key) if isinstance(value, dict) else None


def _input_kwargs(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    return {
        "agent_identity": value.get("agent_identity"),
        "research_context": value.get("research_context"),
        "memory_context": value.get("memory_context"),
        "strategy_context": value.get("strategy_context"),
        "orchestration_context": value.get("orchestration_context"),
        "authorization_context": value.get("authorization_context"),
        "governance_context": value.get("governance_context"),
    }


__all__ = [
    "SECURITY_AGENT_FRAMEWORK_EXPORTER_RULE_VERSION",
    "RULE_VERSION",
    "export_security_agent_framework",
]
