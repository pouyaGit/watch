"""Stage R52.1 deterministic specialist registry (pure engine).

Builds the closed registry of orchestration-supported security specialist
categories and their bounded metadata:

    "Which existing specialists may the orchestrator coordinate?"

Hard boundaries encoded here:

- Orchestration/model only: the registry is static data. No plugin system, no
  dynamic discovery, no dynamic imports, no runtime, no execution, no
  network, no LLM and no target interaction.
- Canonical categories only: every entry reuses the R38.1 canonical category
  vocabulary and the R38.2 allowed-capability vocabulary. R38 is not
  modified.
- No invented capability: the declared capabilities are the R38.2
  analysis/planning capabilities already assigned to the category, and the
  declared contexts are exactly the structured context keys the specialist's
  own analyzer consumes.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.api_security_agent_identity import (
    plan_api_security_agent_identity,
)
from ai.knowledge.cve_research_agent_identity import (
    plan_cve_research_agent_identity,
)
from ai.knowledge.idor_bola_agent_identity import (
    plan_idor_bola_agent_identity,
)
from ai.knowledge.jwt_authentication_agent_identity import (
    plan_jwt_authentication_agent_identity,
)
from ai.knowledge.oauth_agent_identity import plan_oauth_agent_identity
from ai.knowledge.security_agent_capability import CATEGORY_CAPABILITIES
from ai.knowledge.sqli_agent_identity import plan_sqli_agent_identity
from ai.knowledge.ssrf_agent_identity import plan_ssrf_agent_identity
from ai.knowledge.xss_agent_identity import plan_xss_agent_identity
from ai.schemas.agent_orchestrator_registry import (
    AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION,
    CANONICAL_SPECIALIST_ORDER,
    MAX_ENTRIES,
    REGISTRY_UNKNOWN,
    REGISTRY_VALID,
    AgentOrchestratorRegistryPlan,
    agent_orchestrator_registry_plan_projection,
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
)

SPECIALIST_REGISTRY_BUILDER_RULE_VERSION = "r52-1"
RULE_VERSION = SPECIALIST_REGISTRY_BUILDER_RULE_VERSION

#: Structured context keys each specialist analyzer actually consumes. This
#: is the exact analyzer parameter vocabulary; R52 declares no context the
#: specialist cannot process.
SPECIALIST_CONTEXT_KEYS: dict[str, tuple[str, ...]] = {
    CATEGORY_XSS: (
        "input_location",
        "output_context",
        "reflection_state",
        "encoding_state",
        "framework_context",
    ),
    CATEGORY_SSRF: (
        "input_location",
        "url_handling",
        "server_side_fetch",
        "protocol_context",
        "redirect_behavior",
        "hostname_validation",
        "ip_validation",
        "allowlist_behavior",
        "encoding_behavior",
    ),
    CATEGORY_SQLI: (
        "input_location",
        "parameter_type",
        "data_flow",
        "query_context",
        "database_context",
        "input_handling",
        "type_handling",
        "error_behavior",
        "behavioral_signal",
    ),
    CATEGORY_IDOR: (
        "object_reference",
        "resource_type",
        "identifier_type",
        "ownership_relationship",
        "tenant_boundary",
        "role_boundary",
        "authorization_control",
        "authorization_location",
        "object_lookup",
        "authorization_behavior",
        "route_context",
    ),
    CATEGORY_JWT: (
        "authentication_mechanism",
        "token_mechanism",
        "token_format",
        "signing_algorithm",
        "signing_method",
        "signature_verification",
        "algorithm_validation",
        "issuer_validation",
        "audience_validation",
        "expiration_validation",
        "not_before_validation",
        "claim_validation",
        "key_management",
        "key_rotation",
        "token_lifetime",
        "refresh_token",
        "refresh_control",
        "revocation_control",
        "session_lifecycle",
        "token_storage",
        "cookie_attributes",
        "token_exposure",
        "authorization_boundary",
        "authentication_flow",
        "authentication_control",
    ),
    CATEGORY_OAUTH: (
        "oauth_version",
        "flow",
        "client_type",
        "authorization_server_context",
        "resource_server_context",
        "authorization_endpoint",
        "token_endpoint",
        "redirect_uri",
        "client_id",
        "response_type",
        "grant_type",
        "scope_context",
        "state_parameter",
        "nonce_parameter",
        "pkce_challenge",
        "redirect_uri_validation",
        "exact_redirect_matching",
        "redirect_uri_registration",
        "state_validation",
        "state_binding",
        "nonce_validation",
        "pkce_enforcement",
        "pkce_verifier_validation",
        "authorization_code_binding",
        "authorization_code_lifetime",
        "code_reuse_control",
        "client_authentication",
        "token_endpoint_auth_method",
        "client_secret_usage",
        "scope_validation",
        "resource_audience_validation",
        "issuer_validation",
        "token_validation",
        "refresh_token_present",
        "refresh_token_rotation",
        "refresh_token_revocation",
        "consent_control",
        "csrf_protection",
        "login_csrf_protection",
        "redirect_handling",
        "authorization_boundary",
        "session_integration",
        "token_exposure",
    ),
    CATEGORY_RECON: (
        "api_type",
        "api_versioning",
        "content_type",
        "authentication_mechanism",
        "resource_exposure",
        "sensitive_field_exposure",
        "error_detail",
        "debug_information",
        "graphql_introspection",
        "object_authorization_context",
        "endpoint_metadata",
        "request_schema",
        "response_schema",
        "pagination_context",
        "batch_context",
        "file_upload_context",
        "file_download_context",
        "nested_resource_context",
        "graphql_batching",
        "webhook_context",
        "api_authentication",
        "endpoint_authorization",
        "function_role_authorization",
        "tenant_isolation",
        "schema_validation",
        "parameter_validation",
        "unknown_field_handling",
        "content_type_validation",
        "http_method_restrictions",
        "method_override_control",
        "rate_limit_control",
        "request_size_limit",
        "pagination_limit",
        "query_complexity_limit",
        "batch_limit",
        "upload_limit",
        "download_control",
        "error_detail_control",
        "debug_mode_control",
        "sensitive_field_control",
        "cors_origin_policy",
        "cors_credentials_policy",
        "graphql_field_authorization",
        "graphql_mutation_authorization",
        "graphql_depth_limit",
        "graphql_complexity_limit",
        "graphql_introspection_control",
        "api_key_rotation",
        "api_key_revocation",
        "webhook_signature_validation",
        "webhook_replay_protection",
        "webhook_source_validation",
    ),
    CATEGORY_CVE_RESEARCH: (
        "cve_metadata",
        "vulnerability_description",
        "affected_product",
        "affected_versions",
        "fixed_version",
        "vendor_advisory",
        "cwe_metadata",
        "cvss_metadata",
        "references",
        "patch_information",
        "observed_component",
        "observed_version",
        "technology_mapping",
        "version_match",
        "component_match",
        "advisory_match",
        "cwe_match",
        "cvss_severity",
        "attack_vector",
        "prerequisites",
        "exploit_maturity",
        "fixed_version_state",
        "patch_state",
        "reference_corroboration",
        "applicability_evidence",
        "historical_context",
        "target_exposure",
    ),
}

#: Fixed priority per specialist. Ordering is by (priority, canonical order);
#: the registry never reorders based on context or an LLM.
SPECIALIST_PRIORITY: dict[str, int] = {
    category: (index + 1) * 10
    for index, category in enumerate(CANONICAL_SPECIALIST_ORDER)
}

_IDENTITY_PLANNERS: dict[str, object] = {
    CATEGORY_XSS: plan_xss_agent_identity,
    CATEGORY_SSRF: plan_ssrf_agent_identity,
    CATEGORY_SQLI: plan_sqli_agent_identity,
    CATEGORY_IDOR: plan_idor_bola_agent_identity,
    CATEGORY_JWT: plan_jwt_authentication_agent_identity,
    CATEGORY_OAUTH: plan_oauth_agent_identity,
    CATEGORY_RECON: plan_api_security_agent_identity,
    CATEGORY_CVE_RESEARCH: plan_cve_research_agent_identity,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def specialist_identity(category: object) -> dict:
    """Return the specialist's deterministic identity projection.

    The identity is produced by the specialist's own R39-R50 planner; R52
    never invents an identity.
    """

    resolved = _text(category).upper()
    planner = _IDENTITY_PLANNERS.get(resolved)
    if planner is None:
        return {}
    return planner()


def specialist_name(category: object) -> str:
    """Return the canonical specialist name (empty for unknown categories)."""

    identity = specialist_identity(category)
    return _text(identity.get("agent_name"))


def specialist_agent_id(category: object) -> str:
    """Return the deterministic specialist agent id (empty when unknown)."""

    identity = specialist_identity(category)
    return _text(identity.get("agent_id"))


def static_registry_entries() -> list[dict]:
    """Deterministic static registry entries in canonical order."""

    entries: list[dict] = []
    for category in CANONICAL_SPECIALIST_ORDER:
        identity = specialist_identity(category)
        entries.append(
            {
                "category": category,
                "specialist_name": identity.get("agent_name") or "",
                "agent_id": identity.get("agent_id") or "",
                "capabilities": list(
                    CATEGORY_CAPABILITIES.get(category, ())
                ),
                "supported_contexts": list(
                    SPECIALIST_CONTEXT_KEYS.get(category, ())
                ),
                "priority": SPECIALIST_PRIORITY[category],
                "enabled": True,
            }
        )
    return entries


def build_specialist_registry(
    disabled_categories: object = None,
) -> dict:
    """Build the closed specialist registry (read-only).

    ``disabled_categories`` is a bounded caller-supplied list; unknown values
    are ignored and each valid category is marked disabled. The registry
    remains a static, deterministic structure.
    """

    disabled: list[str] = []
    for item in disabled_categories or ():
        text = _text(item).upper()
        if text in CANONICAL_SPECIALIST_ORDER and text not in disabled:
            disabled.append(text)

    entries = static_registry_entries()[:MAX_ENTRIES]
    for entry in entries:
        entry["enabled"] = entry["category"] not in disabled

    if entries:
        state = REGISTRY_VALID
    else:
        state = REGISTRY_UNKNOWN

    plan = AgentOrchestratorRegistryPlan(
        rule_version=AGENT_ORCHESTRATOR_REGISTRY_RULE_VERSION,
        entries=entries,
        registry_state=state,
        research_only=True,
    )
    return agent_orchestrator_registry_plan_projection(plan)


def registry_entry(category: object, registry: object = None) -> dict:
    """Return one bounded registry entry (empty when absent)."""

    resolved = _text(category).upper()
    source = (
        registry.get("entries")
        if isinstance(registry, dict)
        else None
    )
    if source is None:
        source = static_registry_entries()
    for entry in source:
        if isinstance(entry, dict) and entry.get("category") == resolved:
            return dict(entry)
    return {}


def enabled_categories(registry: object = None) -> list[str]:
    """Enabled categories in canonical order (read-only)."""

    source = (
        registry.get("entries")
        if isinstance(registry, dict)
        else None
    )
    if source is None:
        source = static_registry_entries()
    enabled: list[str] = []
    for entry in source:
        if not isinstance(entry, dict):
            continue
        if entry.get("category") in CANONICAL_SPECIALIST_ORDER and (
            entry.get("enabled") is True
        ):
            enabled.append(entry["category"])
    return [
        category
        for category in CANONICAL_SPECIALIST_ORDER
        if category in enabled
    ]


__all__ = [
    "SPECIALIST_REGISTRY_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "SPECIALIST_CONTEXT_KEYS",
    "SPECIALIST_PRIORITY",
    "specialist_identity",
    "specialist_name",
    "specialist_agent_id",
    "static_registry_entries",
    "build_specialist_registry",
    "registry_entry",
    "enabled_categories",
]
