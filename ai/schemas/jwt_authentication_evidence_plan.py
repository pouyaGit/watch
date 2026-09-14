"""JWT/authentication evidence plan schema (Stage R47.4).

A :class:`JWTAuthenticationEvidencePlan` defines which research evidence
would be required to evaluate the JWT/authentication hypotheses. It answers
the research question:

    "Which bounded authentication/validation evidence categories would this
     research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/HTTPS request, no DNS
  resolution, no socket, no browser, no database, no scanner, no token
  decoding or manipulation, no token forgery, no signature bypass, no
  authentication bypass, no credential testing, no payload, no execution,
  no persistence. Nothing is queried, sent, forged, bypassed or executed.
- Evidence items describe what would be relevant; they are never collected
  here and never instruct an attack.
- Closed vocabularies: evidence items, evidence state and limitations are
  closed sets; confidence reuses the shared evidence-confidence vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION = "r47-4"
RULE_VERSION = JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed evidence vocabulary
# ---------------------------------------------------------------------------

EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION = (
    "SIGNATURE_VERIFICATION_CONFIGURATION"
)
EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR = (
    "SIGNATURE_VERIFICATION_BEHAVIOR"
)
EVIDENCE_ALGORITHM_ACCEPTANCE_RULES = "ALGORITHM_ACCEPTANCE_RULES"
EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR = (
    "ALGORITHM_VALIDATION_BEHAVIOR"
)
EVIDENCE_ISSUER_CONFIGURATION = "ISSUER_CONFIGURATION"
EVIDENCE_ISSUER_VALIDATION_RULES = "ISSUER_VALIDATION_RULES"
EVIDENCE_AUDIENCE_CONFIGURATION = "AUDIENCE_CONFIGURATION"
EVIDENCE_AUDIENCE_VALIDATION_RULES = "AUDIENCE_VALIDATION_RULES"
EVIDENCE_EXPIRATION_POLICY = "EXPIRATION_POLICY"
EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR = (
    "EXPIRATION_VALIDATION_BEHAVIOR"
)
EVIDENCE_NOT_BEFORE_POLICY = "NOT_BEFORE_POLICY"
EVIDENCE_NOT_BEFORE_VALIDATION_BEHAVIOR = (
    "NOT_BEFORE_VALIDATION_BEHAVIOR"
)
EVIDENCE_CLAIM_VALIDATION_RULES = "CLAIM_VALIDATION_RULES"
EVIDENCE_KEY_MANAGEMENT_CONFIGURATION = "KEY_MANAGEMENT_CONFIGURATION"
EVIDENCE_KEY_ROTATION_POLICY = "KEY_ROTATION_POLICY"
EVIDENCE_TOKEN_LIFETIME_POLICY = "TOKEN_LIFETIME_POLICY"
EVIDENCE_TOKEN_STORAGE_MECHANISM = "TOKEN_STORAGE_MECHANISM"
EVIDENCE_COOKIE_SECURITY_ATTRIBUTES = "COOKIE_SECURITY_ATTRIBUTES"
EVIDENCE_REFRESH_CONTROL_CONFIGURATION = "REFRESH_CONTROL_CONFIGURATION"
EVIDENCE_REVOCATION_CONFIGURATION = "REVOCATION_CONFIGURATION"
EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION = (
    "SESSION_LIFECYCLE_CONFIGURATION"
)
EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION = (
    "AUTHENTICATION_FLOW_CONFIGURATION"
)
EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE = (
    "AUTHENTICATION_CONTROL_EVIDENCE"
)
EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE = (
    "VALIDATION_IMPLEMENTATION_EVIDENCE"
)
EVIDENCE_UNKNOWN = "UNKNOWN"

JWT_AUTHENTICATION_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION,
    EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR,
    EVIDENCE_ALGORITHM_ACCEPTANCE_RULES,
    EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR,
    EVIDENCE_ISSUER_CONFIGURATION,
    EVIDENCE_ISSUER_VALIDATION_RULES,
    EVIDENCE_AUDIENCE_CONFIGURATION,
    EVIDENCE_AUDIENCE_VALIDATION_RULES,
    EVIDENCE_EXPIRATION_POLICY,
    EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR,
    EVIDENCE_NOT_BEFORE_POLICY,
    EVIDENCE_NOT_BEFORE_VALIDATION_BEHAVIOR,
    EVIDENCE_CLAIM_VALIDATION_RULES,
    EVIDENCE_KEY_MANAGEMENT_CONFIGURATION,
    EVIDENCE_KEY_ROTATION_POLICY,
    EVIDENCE_TOKEN_LIFETIME_POLICY,
    EVIDENCE_TOKEN_STORAGE_MECHANISM,
    EVIDENCE_COOKIE_SECURITY_ATTRIBUTES,
    EVIDENCE_REFRESH_CONTROL_CONFIGURATION,
    EVIDENCE_REVOCATION_CONFIGURATION,
    EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION,
    EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION,
    EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE,
    EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE,
    EVIDENCE_UNKNOWN,
)

STATE_COMPLETE = "COMPLETE"
STATE_PARTIAL = "PARTIAL"
STATE_UNKNOWN = "UNKNOWN"

EVIDENCE_STATES: tuple[str, ...] = (
    STATE_COMPLETE,
    STATE_PARTIAL,
    STATE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Closed limitations
# ---------------------------------------------------------------------------

LIMITATION_NO_COLLECTION_PERFORMED = "NO_COLLECTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_TOKEN_MANIPULATION = "NO_TOKEN_MANIPULATION"
LIMITATION_NO_SIGNATURE_BYPASS = "NO_SIGNATURE_BYPASS"
LIMITATION_NO_AUTHENTICATION_BYPASS = "NO_AUTHENTICATION_BYPASS"
LIMITATION_NO_CREDENTIAL_TESTING = "NO_CREDENTIAL_TESTING"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

JWT_AUTHENTICATION_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_TOKEN_MANIPULATION,
    LIMITATION_NO_SIGNATURE_BYPASS,
    LIMITATION_NO_AUTHENTICATION_BYPASS,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 25
MAX_LIMITATIONS = 9
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_jwt_authentication_evidence_plan(value: object) -> dict:
    """Project an R47.4 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "evidence_items": [],
            "evidence_state": STATE_UNKNOWN,
            "confidence": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    evidence_state = _safe_text(value.get("evidence_state")).strip().upper()
    if evidence_state not in EVIDENCE_STATES:
        evidence_state = STATE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "evidence_items": [
            item
            for item in (
                _safe_text(entry)
                for entry in value.get("evidence_items") or ()
            )
            if item in JWT_AUTHENTICATION_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in JWT_AUTHENTICATION_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class JWTAuthenticationEvidencePlan(BaseModel):
    """Deterministic research-only JWT/authentication evidence plan (R47.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(
            value, JWT_AUTHENTICATION_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS
        )

    @field_validator("evidence_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_STATES:
            raise ValueError(f"invalid evidence_state: {value!r}")
        return text

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, JWT_AUTHENTICATION_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "jwt/authentication evidence plans are research-only"
            )
        return True


def jwt_authentication_evidence_plan_projection(
    value: JWTAuthenticationEvidencePlan,
) -> dict:
    """Serialize an R47.4 evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "JWT_AUTHENTICATION_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_SIGNATURE_VERIFICATION_CONFIGURATION",
    "EVIDENCE_SIGNATURE_VERIFICATION_BEHAVIOR",
    "EVIDENCE_ALGORITHM_ACCEPTANCE_RULES",
    "EVIDENCE_ALGORITHM_VALIDATION_BEHAVIOR",
    "EVIDENCE_ISSUER_CONFIGURATION",
    "EVIDENCE_ISSUER_VALIDATION_RULES",
    "EVIDENCE_AUDIENCE_CONFIGURATION",
    "EVIDENCE_AUDIENCE_VALIDATION_RULES",
    "EVIDENCE_EXPIRATION_POLICY",
    "EVIDENCE_EXPIRATION_VALIDATION_BEHAVIOR",
    "EVIDENCE_NOT_BEFORE_POLICY",
    "EVIDENCE_NOT_BEFORE_VALIDATION_BEHAVIOR",
    "EVIDENCE_CLAIM_VALIDATION_RULES",
    "EVIDENCE_KEY_MANAGEMENT_CONFIGURATION",
    "EVIDENCE_KEY_ROTATION_POLICY",
    "EVIDENCE_TOKEN_LIFETIME_POLICY",
    "EVIDENCE_TOKEN_STORAGE_MECHANISM",
    "EVIDENCE_COOKIE_SECURITY_ATTRIBUTES",
    "EVIDENCE_REFRESH_CONTROL_CONFIGURATION",
    "EVIDENCE_REVOCATION_CONFIGURATION",
    "EVIDENCE_SESSION_LIFECYCLE_CONFIGURATION",
    "EVIDENCE_AUTHENTICATION_FLOW_CONFIGURATION",
    "EVIDENCE_AUTHENTICATION_CONTROL_EVIDENCE",
    "EVIDENCE_VALIDATION_IMPLEMENTATION_EVIDENCE",
    "EVIDENCE_UNKNOWN",
    "JWT_AUTHENTICATION_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_TOKEN_MANIPULATION",
    "LIMITATION_NO_SIGNATURE_BYPASS",
    "LIMITATION_NO_AUTHENTICATION_BYPASS",
    "LIMITATION_NO_CREDENTIAL_TESTING",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "JWT_AUTHENTICATION_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_jwt_authentication_evidence_plan",
    "JWTAuthenticationEvidencePlan",
    "jwt_authentication_evidence_plan_projection",
]
