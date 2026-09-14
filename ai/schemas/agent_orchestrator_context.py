"""Agent orchestration context schema (Stage R52.2).

An :class:`AgentOrchestrationContextPlan` is the bounded, read-only
normalization of the structured research context the orchestrator reasons
over. It answers the orchestration question:

    "Which structured context did the caller supply, and which context keys
     are known?"

Hard boundaries encoded here:

- Orchestration/model only: context normalization reads structured data and
  performs no execution, no network, no database, no browser, no LLM call and
  no target interaction.
- Closed context vocabulary: only the declared specialist context keys are
  retained. Unknown, malformed and non-deterministic keys are dropped and
  counted; nothing is inferred.
- Presence of a context key is relevance information only. It never means a
  vulnerability exists and it never promotes confidence.
- Bounded, privacy-safe, JSON serializable: scalars and bounded scalar lists
  only.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

AGENT_ORCHESTRATOR_CONTEXT_RULE_VERSION = "r52-2"
RULE_VERSION = AGENT_ORCHESTRATOR_CONTEXT_RULE_VERSION

#: Closed union of the structured context keys that the supported specialist
#: analyzers consume (R39-R50). This is a vocabulary, not a new contract:
#: values are re-validated by each specialist's own closed analyzer.
ORCHESTRATION_CONTEXT_KEYS: tuple[str, ...] = (
    # R39 XSS / R40 SSRF / R41 SQLi shared input location
    "input_location",
    # R39 XSS
    "output_context",
    "reflection_state",
    "encoding_state",
    "framework_context",
    # R40 SSRF
    "url_handling",
    "server_side_fetch",
    "protocol_context",
    "redirect_behavior",
    "hostname_validation",
    "ip_validation",
    "allowlist_behavior",
    "encoding_behavior",
    # R41 SQLi
    "parameter_type",
    "data_flow",
    "query_context",
    "database_context",
    "input_handling",
    "type_handling",
    "error_behavior",
    "behavioral_signal",
    # R46 IDOR/BOLA
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
    # R47 JWT/authentication
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
    # R48 OAuth
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
    "token_validation",
    "refresh_token_present",
    "refresh_token_rotation",
    "refresh_token_revocation",
    "consent_control",
    "csrf_protection",
    "login_csrf_protection",
    "redirect_handling",
    "session_integration",
    # R49 API security (canonical category RECON)
    "api_type",
    "api_versioning",
    "content_type",
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
    # R50 CVE research
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
)

#: Context values that explicitly mean "not observed / not known".
UNKNOWN_CONTEXT_VALUE = "UNKNOWN"
KNOWN_CONTEXT_VALUE = "KNOWN"

MAX_CONTEXT_KEYS = len(ORCHESTRATION_CONTEXT_KEYS)
MAX_LIST = 16
MAX_VALUE_LEN = 160

_CONTEXT_KEY_SET = frozenset(ORCHESTRATION_CONTEXT_KEYS)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

_NONDETERMINISTIC_KEY_TOKENS: tuple[str, ...] = (
    "timestamp",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "runtime_id",
    "nonce",
    "uuid",
    "random",
)


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_scalar_list(value: object) -> list:
    out: list = []
    for item in value or ():
        if isinstance(item, bool):
            out.append(item)
        elif isinstance(item, (int, float)):
            out.append(item)
        elif isinstance(item, str):
            text = _safe_text(item)
            if text:
                out.append(text)
        if len(out) >= MAX_LIST:
            break
    return out


def context_value_is_known(value: object) -> bool:
    """True when a bounded context value carries an observed fact.

    Only a non-empty, non-``UNKNOWN`` value counts. Presence of a key is
    relevance information; it is never a vulnerability claim.
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        text = value.strip().upper()
        return bool(text) and text != UNKNOWN_CONTEXT_VALUE
    if isinstance(value, (list, tuple)):
        return bool(value)
    return False


def sanitize_orchestration_context(value: object) -> dict:
    """Project a research context onto the closed bounded context keys."""

    if not isinstance(value, dict):
        return {}
    out: dict = {}
    for key in ORCHESTRATION_CONTEXT_KEYS:
        if key not in value:
            continue
        raw = value.get(key)
        if isinstance(raw, bool):
            out[key] = raw
        elif isinstance(raw, (int, float)):
            out[key] = raw
        elif isinstance(raw, str):
            text = _safe_text(raw)
            if text:
                out[key] = text
        elif isinstance(raw, (list, tuple)):
            items = _bounded_scalar_list(raw)
            if items:
                out[key] = items
    return out


def count_known_context_values(context: object) -> int:
    """Count known values in a sanitized context mapping."""

    if not isinstance(context, dict):
        return 0
    return sum(
        1 for value in context.values() if context_value_is_known(value)
    )


def count_dropped_context_keys(value: object) -> int:
    """Count context keys outside the closed vocabulary or non-deterministic."""

    if not isinstance(value, dict):
        return 0
    dropped = 0
    for key in value:
        name = str(key if key is not None else "")
        if name not in _CONTEXT_KEY_SET:
            dropped += 1
            continue
        if any(token in name.lower() for token in _NONDETERMINISTIC_KEY_TOKENS):
            dropped += 1
    return dropped


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentOrchestrationContextPlan(BaseModel):
    """Bounded, normalized orchestration context (R52.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_ORCHESTRATOR_CONTEXT_RULE_VERSION
    context: dict = Field(default_factory=dict)
    known_key_count: int = 0
    dropped_key_count: int = 0
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_ORCHESTRATOR_CONTEXT_RULE_VERSION

    @field_validator("context")
    @classmethod
    def _bounded_context(cls, value: object) -> dict:
        return sanitize_orchestration_context(value)

    @field_validator("known_key_count", "dropped_key_count")
    @classmethod
    def _bounded_count(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return max(0, min(MAX_CONTEXT_KEYS, value))

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("orchestration contexts are research-only")
        return True


def agent_orchestration_context_plan_projection(
    value: AgentOrchestrationContextPlan,
) -> dict:
    """Serialize an orchestration context to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_ORCHESTRATOR_CONTEXT_RULE_VERSION",
    "RULE_VERSION",
    "ORCHESTRATION_CONTEXT_KEYS",
    "UNKNOWN_CONTEXT_VALUE",
    "KNOWN_CONTEXT_VALUE",
    "MAX_CONTEXT_KEYS",
    "MAX_LIST",
    "MAX_VALUE_LEN",
    "context_value_is_known",
    "sanitize_orchestration_context",
    "count_known_context_values",
    "count_dropped_context_keys",
    "AgentOrchestrationContextPlan",
    "agent_orchestration_context_plan_projection",
]
