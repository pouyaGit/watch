"""IDOR/BOLA context analysis schema (Stage R46.2).

An :class:`IDORBOLAContextAnalysisPlan` is the deterministic, descriptive
analysis of possible insecure-direct-object-reference / broken-object-level-
authorization (IDOR/BOLA) context. It answers the research question:

    "Which object-reference, ownership, boundary and authorization signals
     were supplied?"

Hard boundaries encoded here:

- Research intelligence only: no HTTP request, no DNS resolution, no socket,
  no browser, no database, no scanning, no exploitation, no authorization
  bypass, no payload generation, no persistence.
- IDOR and BOLA are treated as related authorization research concepts, not
  automatically identical findings.
- Closed vocabularies: object reference, resource type, identifier type,
  ownership/tenant/role boundary, authorization control, authorization
  location, object lookup, observed behavior and route context are closed
  sets; unknown values remain ``UNKNOWN`` and are never promoted.
- Context confidence reuses the shared evidence-confidence vocabulary and is
  computed deterministically by the analyzer; it means "how complete is the
  supplied object-level authorization context?", never "is the target
  vulnerable?".
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION = "r46-2"
RULE_VERSION = IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Object reference location
# ---------------------------------------------------------------------------

OBJREF_NONE_OBSERVED = "NONE_OBSERVED"
OBJREF_PATH_PARAMETER = "PATH_PARAMETER"
OBJREF_QUERY_PARAMETER = "QUERY_PARAMETER"
OBJREF_BODY_FIELD = "BODY_FIELD"
OBJREF_HEADER_VALUE = "HEADER_VALUE"
OBJREF_COOKIE_VALUE = "COOKIE_VALUE"
OBJREF_UNKNOWN = "UNKNOWN"

OBJECT_REFERENCE_LOCATIONS: tuple[str, ...] = (
    OBJREF_NONE_OBSERVED,
    OBJREF_PATH_PARAMETER,
    OBJREF_QUERY_PARAMETER,
    OBJREF_BODY_FIELD,
    OBJREF_HEADER_VALUE,
    OBJREF_COOKIE_VALUE,
    OBJREF_UNKNOWN,
)

# Known (supplied) object references exclude the negative/unknown values.
KNOWN_OBJECT_REFERENCE_LOCATIONS: tuple[str, ...] = (
    OBJREF_PATH_PARAMETER,
    OBJREF_QUERY_PARAMETER,
    OBJREF_BODY_FIELD,
    OBJREF_HEADER_VALUE,
    OBJREF_COOKIE_VALUE,
)

# ---------------------------------------------------------------------------
# Resource type
# ---------------------------------------------------------------------------

RESOURCE_NONE_OBSERVED = "NONE_OBSERVED"
RESOURCE_DOCUMENT = "DOCUMENT"
RESOURCE_RECORD = "RECORD"
RESOURCE_PROFILE = "PROFILE"
RESOURCE_ORDER = "ORDER"
RESOURCE_FILE = "FILE"
RESOURCE_MESSAGE = "MESSAGE"
RESOURCE_TRANSACTION = "TRANSACTION"
RESOURCE_INVOICE = "INVOICE"
RESOURCE_UNKNOWN = "UNKNOWN"

RESOURCE_TYPES: tuple[str, ...] = (
    RESOURCE_NONE_OBSERVED,
    RESOURCE_DOCUMENT,
    RESOURCE_RECORD,
    RESOURCE_PROFILE,
    RESOURCE_ORDER,
    RESOURCE_FILE,
    RESOURCE_MESSAGE,
    RESOURCE_TRANSACTION,
    RESOURCE_INVOICE,
    RESOURCE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Identifier type
# ---------------------------------------------------------------------------

IDENT_NONE_OBSERVED = "NONE_OBSERVED"
IDENT_OPAQUE = "OPAQUE_ID"
IDENT_SEQUENTIAL_INTEGER = "SEQUENTIAL_INTEGER"
IDENT_UUID = "UUID"
IDENT_SLUG = "SLUG"
IDENT_COMPOSITE = "COMPOSITE_KEY"
IDENT_UNKNOWN = "UNKNOWN"

IDENTIFIER_TYPES: tuple[str, ...] = (
    IDENT_NONE_OBSERVED,
    IDENT_OPAQUE,
    IDENT_SEQUENTIAL_INTEGER,
    IDENT_UUID,
    IDENT_SLUG,
    IDENT_COMPOSITE,
    IDENT_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Ownership / tenant / role boundary evidence
# ---------------------------------------------------------------------------

OWNER_RECORDED = "OWNER_RECORDED"
OWNER_NOT_RECORDED = "OWNER_NOT_RECORDED"
OWNER_UNKNOWN = "UNKNOWN"

OWNERSHIP_STATES: tuple[str, ...] = (
    OWNER_RECORDED,
    OWNER_NOT_RECORDED,
    OWNER_UNKNOWN,
)

TENANT_RECORDED = "TENANT_RECORDED"
TENANT_NOT_RECORDED = "TENANT_NOT_RECORDED"
TENANT_UNKNOWN = "UNKNOWN"

TENANT_BOUNDARY_STATES: tuple[str, ...] = (
    TENANT_RECORDED,
    TENANT_NOT_RECORDED,
    TENANT_UNKNOWN,
)

ROLE_RECORDED = "ROLE_RECORDED"
ROLE_NOT_RECORDED = "ROLE_NOT_RECORDED"
ROLE_UNKNOWN = "UNKNOWN"

ROLE_BOUNDARY_STATES: tuple[str, ...] = (
    ROLE_RECORDED,
    ROLE_NOT_RECORDED,
    ROLE_UNKNOWN,
)

BOUNDARY_RECORDED_STATES: tuple[str, ...] = (
    OWNER_RECORDED,
    TENANT_RECORDED,
    ROLE_RECORDED,
)

BOUNDARY_NOT_RECORDED_STATES: tuple[str, ...] = (
    OWNER_NOT_RECORDED,
    TENANT_NOT_RECORDED,
    ROLE_NOT_RECORDED,
)

# ---------------------------------------------------------------------------
# Authorization control evidence
# ---------------------------------------------------------------------------

AUTH_CONTROL_POLICY_ENFORCEMENT = "POLICY_ENFORCEMENT_PRESENT"
AUTH_CONTROL_OWNERSHIP_CHECK = "OWNERSHIP_CHECK_PRESENT"
AUTH_CONTROL_TENANT_AUTHORIZATION = "TENANT_AUTHORIZATION_PRESENT"
AUTH_CONTROL_ROLE_AUTHORIZATION = "ROLE_AUTHORIZATION_PRESENT"
AUTH_CONTROL_MIDDLEWARE = "ACCESS_CONTROL_MIDDLEWARE_PRESENT"
AUTH_CONTROL_SERVER_SIDE = "SERVER_SIDE_AUTHORIZATION_PRESENT"
AUTH_CONTROL_ABSENT = "AUTHORIZATION_ABSENT"
AUTH_CONTROL_UNKNOWN = "UNKNOWN"

AUTHORIZATION_CONTROLS: tuple[str, ...] = (
    AUTH_CONTROL_POLICY_ENFORCEMENT,
    AUTH_CONTROL_OWNERSHIP_CHECK,
    AUTH_CONTROL_TENANT_AUTHORIZATION,
    AUTH_CONTROL_ROLE_AUTHORIZATION,
    AUTH_CONTROL_MIDDLEWARE,
    AUTH_CONTROL_SERVER_SIDE,
    AUTH_CONTROL_ABSENT,
    AUTH_CONTROL_UNKNOWN,
)

AUTHORIZATION_CONTROL_PRESENT_STATES: tuple[str, ...] = (
    AUTH_CONTROL_POLICY_ENFORCEMENT,
    AUTH_CONTROL_OWNERSHIP_CHECK,
    AUTH_CONTROL_TENANT_AUTHORIZATION,
    AUTH_CONTROL_ROLE_AUTHORIZATION,
    AUTH_CONTROL_MIDDLEWARE,
    AUTH_CONTROL_SERVER_SIDE,
)

# ---------------------------------------------------------------------------
# Authorization enforcement location
# ---------------------------------------------------------------------------

AUTH_LOCATION_SERVER_SIDE = "SERVER_SIDE"
AUTH_LOCATION_CLIENT_SIDE = "CLIENT_SIDE_ONLY"
AUTH_LOCATION_MIXED = "MIXED"
AUTH_LOCATION_NONE_OBSERVED = "NONE_OBSERVED"
AUTH_LOCATION_UNKNOWN = "UNKNOWN"

AUTHORIZATION_LOCATIONS: tuple[str, ...] = (
    AUTH_LOCATION_SERVER_SIDE,
    AUTH_LOCATION_CLIENT_SIDE,
    AUTH_LOCATION_MIXED,
    AUTH_LOCATION_NONE_OBSERVED,
    AUTH_LOCATION_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Object lookup pattern
# ---------------------------------------------------------------------------

LOOKUP_BY_IDENTIFIER = "LOOKUP_BY_IDENTIFIER"
LOOKUP_BY_OWNED_SCOPE = "LOOKUP_BY_OWNED_SCOPE"
LOOKUP_BY_TENANT_SCOPE = "LOOKUP_BY_TENANT_SCOPE"
LOOKUP_NONE_OBSERVED = "NONE_OBSERVED"
LOOKUP_UNKNOWN = "UNKNOWN"

OBJECT_LOOKUP_PATTERNS: tuple[str, ...] = (
    LOOKUP_BY_IDENTIFIER,
    LOOKUP_BY_OWNED_SCOPE,
    LOOKUP_BY_TENANT_SCOPE,
    LOOKUP_NONE_OBSERVED,
    LOOKUP_UNKNOWN,
)

DIRECT_LOOKUP_PATTERNS: tuple[str, ...] = (
    LOOKUP_BY_IDENTIFIER,
)

SCOPED_LOOKUP_PATTERNS: tuple[str, ...] = (
    LOOKUP_BY_OWNED_SCOPE,
    LOOKUP_BY_TENANT_SCOPE,
)

# ---------------------------------------------------------------------------
# Observed authorization behavior (preserved only when explicitly supplied)
# ---------------------------------------------------------------------------

BEHAVIOR_CROSS_USER_ACCESS_OBSERVED = "CROSS_USER_ACCESS_OBSERVED"
BEHAVIOR_CROSS_TENANT_ACCESS_OBSERVED = "CROSS_TENANT_ACCESS_OBSERVED"
BEHAVIOR_OWN_OBJECT_ONLY_OBSERVED = "OWN_OBJECT_ONLY_OBSERVED"
BEHAVIOR_ACCESS_DENIED_OBSERVED = "ACCESS_DENIED_OBSERVED"
BEHAVIOR_NO_BEHAVIOR_OBSERVED = "NO_BEHAVIOR_OBSERVED"
BEHAVIOR_UNKNOWN = "UNKNOWN"

AUTHORIZATION_BEHAVIORS: tuple[str, ...] = (
    BEHAVIOR_CROSS_USER_ACCESS_OBSERVED,
    BEHAVIOR_CROSS_TENANT_ACCESS_OBSERVED,
    BEHAVIOR_OWN_OBJECT_ONLY_OBSERVED,
    BEHAVIOR_ACCESS_DENIED_OBSERVED,
    BEHAVIOR_NO_BEHAVIOR_OBSERVED,
    BEHAVIOR_UNKNOWN,
)

CROSS_CONTEXT_BEHAVIORS: tuple[str, ...] = (
    BEHAVIOR_CROSS_USER_ACCESS_OBSERVED,
    BEHAVIOR_CROSS_TENANT_ACCESS_OBSERVED,
)

# ---------------------------------------------------------------------------
# Route / controller context
# ---------------------------------------------------------------------------

ROUTE_RESOURCE = "RESOURCE_ROUTE"
ROUTE_COLLECTION = "COLLECTION_ROUTE"
ROUTE_ADMIN = "ADMIN_ROUTE"
ROUTE_INTERNAL = "INTERNAL_ROUTE"
ROUTE_NONE_OBSERVED = "NONE_OBSERVED"
ROUTE_UNKNOWN = "UNKNOWN"

ROUTE_CONTEXTS: tuple[str, ...] = (
    ROUTE_RESOURCE,
    ROUTE_COLLECTION,
    ROUTE_ADMIN,
    ROUTE_INTERNAL,
    ROUTE_NONE_OBSERVED,
    ROUTE_UNKNOWN,
)

ROLE_SENSITIVE_ROUTES: tuple[str, ...] = (
    ROUTE_RESOURCE,
    ROUTE_ADMIN,
)

MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def sanitize_idor_bola_context_analysis_plan(value: object) -> dict:
    """Project an R46.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "object_reference": OBJREF_UNKNOWN,
            "resource_type": RESOURCE_UNKNOWN,
            "identifier_type": IDENT_UNKNOWN,
            "ownership_relationship": OWNER_UNKNOWN,
            "tenant_boundary": TENANT_UNKNOWN,
            "role_boundary": ROLE_UNKNOWN,
            "authorization_control": AUTH_CONTROL_UNKNOWN,
            "authorization_location": AUTH_LOCATION_UNKNOWN,
            "object_lookup": LOOKUP_UNKNOWN,
            "authorization_behavior": BEHAVIOR_UNKNOWN,
            "route_context": ROUTE_UNKNOWN,
            "context_confidence": "UNKNOWN",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "object_reference": _closed(
            value.get("object_reference"),
            OBJECT_REFERENCE_LOCATIONS,
            OBJREF_UNKNOWN,
        ),
        "resource_type": _closed(
            value.get("resource_type"), RESOURCE_TYPES, RESOURCE_UNKNOWN
        ),
        "identifier_type": _closed(
            value.get("identifier_type"),
            IDENTIFIER_TYPES,
            IDENT_UNKNOWN,
        ),
        "ownership_relationship": _closed(
            value.get("ownership_relationship"),
            OWNERSHIP_STATES,
            OWNER_UNKNOWN,
        ),
        "tenant_boundary": _closed(
            value.get("tenant_boundary"),
            TENANT_BOUNDARY_STATES,
            TENANT_UNKNOWN,
        ),
        "role_boundary": _closed(
            value.get("role_boundary"),
            ROLE_BOUNDARY_STATES,
            ROLE_UNKNOWN,
        ),
        "authorization_control": _closed(
            value.get("authorization_control"),
            AUTHORIZATION_CONTROLS,
            AUTH_CONTROL_UNKNOWN,
        ),
        "authorization_location": _closed(
            value.get("authorization_location"),
            AUTHORIZATION_LOCATIONS,
            AUTH_LOCATION_UNKNOWN,
        ),
        "object_lookup": _closed(
            value.get("object_lookup"),
            OBJECT_LOOKUP_PATTERNS,
            LOOKUP_UNKNOWN,
        ),
        "authorization_behavior": _closed(
            value.get("authorization_behavior"),
            AUTHORIZATION_BEHAVIORS,
            BEHAVIOR_UNKNOWN,
        ),
        "route_context": _closed(
            value.get("route_context"), ROUTE_CONTEXTS, ROUTE_UNKNOWN
        ),
        "context_confidence": _closed(
            value.get("context_confidence"),
            CONFIDENCE_LEVELS,
            "UNKNOWN",
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class IDORBOLAContextAnalysisPlan(BaseModel):
    """Deterministic descriptive IDOR/BOLA context analysis (R46.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION
    object_reference: str = OBJREF_UNKNOWN
    resource_type: str = RESOURCE_UNKNOWN
    identifier_type: str = IDENT_UNKNOWN
    ownership_relationship: str = OWNER_UNKNOWN
    tenant_boundary: str = TENANT_UNKNOWN
    role_boundary: str = ROLE_UNKNOWN
    authorization_control: str = AUTH_CONTROL_UNKNOWN
    authorization_location: str = AUTH_LOCATION_UNKNOWN
    object_lookup: str = LOOKUP_UNKNOWN
    authorization_behavior: str = BEHAVIOR_UNKNOWN
    route_context: str = ROUTE_UNKNOWN
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("object_reference")
    @classmethod
    def _valid_object_reference(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OBJECT_REFERENCE_LOCATIONS:
            raise ValueError(f"invalid object_reference: {value!r}")
        return text

    @field_validator("resource_type")
    @classmethod
    def _valid_resource_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RESOURCE_TYPES:
            raise ValueError(f"invalid resource_type: {value!r}")
        return text

    @field_validator("identifier_type")
    @classmethod
    def _valid_identifier_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IDENTIFIER_TYPES:
            raise ValueError(f"invalid identifier_type: {value!r}")
        return text

    @field_validator("ownership_relationship")
    @classmethod
    def _valid_ownership(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OWNERSHIP_STATES:
            raise ValueError(f"invalid ownership_relationship: {value!r}")
        return text

    @field_validator("tenant_boundary")
    @classmethod
    def _valid_tenant(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TENANT_BOUNDARY_STATES:
            raise ValueError(f"invalid tenant_boundary: {value!r}")
        return text

    @field_validator("role_boundary")
    @classmethod
    def _valid_role(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ROLE_BOUNDARY_STATES:
            raise ValueError(f"invalid role_boundary: {value!r}")
        return text

    @field_validator("authorization_control")
    @classmethod
    def _valid_control(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_CONTROLS:
            raise ValueError(f"invalid authorization_control: {value!r}")
        return text

    @field_validator("authorization_location")
    @classmethod
    def _valid_location(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_LOCATIONS:
            raise ValueError(f"invalid authorization_location: {value!r}")
        return text

    @field_validator("object_lookup")
    @classmethod
    def _valid_lookup(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in OBJECT_LOOKUP_PATTERNS:
            raise ValueError(f"invalid object_lookup: {value!r}")
        return text

    @field_validator("authorization_behavior")
    @classmethod
    def _valid_behavior(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_BEHAVIORS:
            raise ValueError(f"invalid authorization_behavior: {value!r}")
        return text

    @field_validator("route_context")
    @classmethod
    def _valid_route(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ROUTE_CONTEXTS:
            raise ValueError(f"invalid route_context: {value!r}")
        return text

    @field_validator("context_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid context_confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("idor/bola context analyses are research-only")
        return True


def idor_bola_context_analysis_plan_projection(
    value: IDORBOLAContextAnalysisPlan,
) -> dict:
    """Serialize an IDOR/BOLA context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "IDOR_BOLA_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "OBJREF_NONE_OBSERVED",
    "OBJREF_PATH_PARAMETER",
    "OBJREF_QUERY_PARAMETER",
    "OBJREF_BODY_FIELD",
    "OBJREF_HEADER_VALUE",
    "OBJREF_COOKIE_VALUE",
    "OBJREF_UNKNOWN",
    "OBJECT_REFERENCE_LOCATIONS",
    "KNOWN_OBJECT_REFERENCE_LOCATIONS",
    "RESOURCE_NONE_OBSERVED",
    "RESOURCE_DOCUMENT",
    "RESOURCE_RECORD",
    "RESOURCE_PROFILE",
    "RESOURCE_ORDER",
    "RESOURCE_FILE",
    "RESOURCE_MESSAGE",
    "RESOURCE_TRANSACTION",
    "RESOURCE_INVOICE",
    "RESOURCE_UNKNOWN",
    "RESOURCE_TYPES",
    "IDENT_NONE_OBSERVED",
    "IDENT_OPAQUE",
    "IDENT_SEQUENTIAL_INTEGER",
    "IDENT_UUID",
    "IDENT_SLUG",
    "IDENT_COMPOSITE",
    "IDENT_UNKNOWN",
    "IDENTIFIER_TYPES",
    "OWNER_RECORDED",
    "OWNER_NOT_RECORDED",
    "OWNER_UNKNOWN",
    "OWNERSHIP_STATES",
    "TENANT_RECORDED",
    "TENANT_NOT_RECORDED",
    "TENANT_UNKNOWN",
    "TENANT_BOUNDARY_STATES",
    "ROLE_RECORDED",
    "ROLE_NOT_RECORDED",
    "ROLE_UNKNOWN",
    "ROLE_BOUNDARY_STATES",
    "BOUNDARY_RECORDED_STATES",
    "BOUNDARY_NOT_RECORDED_STATES",
    "AUTH_CONTROL_POLICY_ENFORCEMENT",
    "AUTH_CONTROL_OWNERSHIP_CHECK",
    "AUTH_CONTROL_TENANT_AUTHORIZATION",
    "AUTH_CONTROL_ROLE_AUTHORIZATION",
    "AUTH_CONTROL_MIDDLEWARE",
    "AUTH_CONTROL_SERVER_SIDE",
    "AUTH_CONTROL_ABSENT",
    "AUTH_CONTROL_UNKNOWN",
    "AUTHORIZATION_CONTROLS",
    "AUTHORIZATION_CONTROL_PRESENT_STATES",
    "AUTH_LOCATION_SERVER_SIDE",
    "AUTH_LOCATION_CLIENT_SIDE",
    "AUTH_LOCATION_MIXED",
    "AUTH_LOCATION_NONE_OBSERVED",
    "AUTH_LOCATION_UNKNOWN",
    "AUTHORIZATION_LOCATIONS",
    "LOOKUP_BY_IDENTIFIER",
    "LOOKUP_BY_OWNED_SCOPE",
    "LOOKUP_BY_TENANT_SCOPE",
    "LOOKUP_NONE_OBSERVED",
    "LOOKUP_UNKNOWN",
    "OBJECT_LOOKUP_PATTERNS",
    "DIRECT_LOOKUP_PATTERNS",
    "SCOPED_LOOKUP_PATTERNS",
    "BEHAVIOR_CROSS_USER_ACCESS_OBSERVED",
    "BEHAVIOR_CROSS_TENANT_ACCESS_OBSERVED",
    "BEHAVIOR_OWN_OBJECT_ONLY_OBSERVED",
    "BEHAVIOR_ACCESS_DENIED_OBSERVED",
    "BEHAVIOR_NO_BEHAVIOR_OBSERVED",
    "BEHAVIOR_UNKNOWN",
    "AUTHORIZATION_BEHAVIORS",
    "CROSS_CONTEXT_BEHAVIORS",
    "ROUTE_RESOURCE",
    "ROUTE_COLLECTION",
    "ROUTE_ADMIN",
    "ROUTE_INTERNAL",
    "ROUTE_NONE_OBSERVED",
    "ROUTE_UNKNOWN",
    "ROUTE_CONTEXTS",
    "ROLE_SENSITIVE_ROUTES",
    "MAX_VALUE_LEN",
    "sanitize_idor_bola_context_analysis_plan",
    "IDORBOLAContextAnalysisPlan",
    "idor_bola_context_analysis_plan_projection",
]
