"""OAuth evidence plan schema (Stage R48.4).

An :class:`OAuthEvidencePlan` defines which research evidence would be
required to evaluate the OAuth hypotheses. It answers the research
question:

    "Which bounded OAuth evidence categories would this research require?"

Hard boundaries encoded here:

- Evidence planning only: no collection, no HTTP/HTTPS request, no OAuth
  authorization/token/callback request, no redirect following, no DNS
  resolution, no socket, no browser, no database, no scanner, no token
  decoding or exchange, no state/nonce/PKCE manipulation, no credential
  testing, no payload, no execution, no persistence. Nothing is queried,
  sent, exchanged or executed.
- Evidence items describe what would be relevant; they are never collected
  here and never instruct an attack.
- Closed vocabularies: evidence items, evidence state and limitations are
  closed sets; confidence reuses the shared evidence-confidence
  vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

OAUTH_EVIDENCE_PLAN_RULE_VERSION = "r48-4"
RULE_VERSION = OAUTH_EVIDENCE_PLAN_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed evidence vocabulary
# ---------------------------------------------------------------------------

EVIDENCE_REDIRECT_URI_REGISTRATION = "REDIRECT_URI_REGISTRATION"
EVIDENCE_REDIRECT_URI_MATCHING_POLICY = "REDIRECT_URI_MATCHING_POLICY"
EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR = (
    "REDIRECT_URI_VALIDATION_BEHAVIOR"
)
EVIDENCE_STATE_GENERATION = "STATE_GENERATION"
EVIDENCE_STATE_SESSION_BINDING = "STATE_SESSION_BINDING"
EVIDENCE_STATE_VALIDATION_BEHAVIOR = "STATE_VALIDATION_BEHAVIOR"
EVIDENCE_NONCE_VALIDATION_BEHAVIOR = "NONCE_VALIDATION_BEHAVIOR"
EVIDENCE_PKCE_ENFORCEMENT_POLICY = "PKCE_ENFORCEMENT_POLICY"
EVIDENCE_PKCE_CHALLENGE_METHOD = "PKCE_CHALLENGE_METHOD"
EVIDENCE_PKCE_VERIFIER_VALIDATION = "PKCE_VERIFIER_VALIDATION"
EVIDENCE_AUTHORIZATION_CODE_LIFETIME = "AUTHORIZATION_CODE_LIFETIME"
EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE = "AUTHORIZATION_CODE_ONE_TIME_USE"
EVIDENCE_AUTHORIZATION_CODE_BINDING = "AUTHORIZATION_CODE_BINDING"
EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS = (
    "AUTHORIZATION_CODE_REPLAY_CONTROLS"
)
EVIDENCE_CLIENT_TYPE = "CLIENT_TYPE"
EVIDENCE_CLIENT_AUTHENTICATION_METHOD = "CLIENT_AUTHENTICATION_METHOD"
EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION = (
    "CLIENT_REGISTRATION_CONFIGURATION"
)
EVIDENCE_REQUESTED_SCOPES = "REQUESTED_SCOPES"
EVIDENCE_GRANTED_SCOPES = "GRANTED_SCOPES"
EVIDENCE_SCOPE_VALIDATION_POLICY = "SCOPE_VALIDATION_POLICY"
EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION = (
    "RESOURCE_INDICATOR_CONFIGURATION"
)
EVIDENCE_AUDIENCE_VALIDATION_POLICY = "AUDIENCE_VALIDATION_POLICY"
EVIDENCE_ISSUER_CONFIGURATION = "ISSUER_CONFIGURATION"
EVIDENCE_TOKEN_VALIDATION_CONFIGURATION = "TOKEN_VALIDATION_CONFIGURATION"
EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY = "REFRESH_TOKEN_ROTATION_POLICY"
EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY = (
    "REFRESH_TOKEN_REVOCATION_POLICY"
)
EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION = "REFRESH_TOKEN_REUSE_DETECTION"
EVIDENCE_CONSENT_CONFIGURATION = "CONSENT_CONFIGURATION"
EVIDENCE_CSRF_REQUEST_BINDING = "CSRF_REQUEST_BINDING"
EVIDENCE_LOGIN_CSRF_SESSION_BINDING = "LOGIN_CSRF_SESSION_BINDING"
EVIDENCE_REDIRECT_HANDLING_CONFIGURATION = (
    "REDIRECT_HANDLING_CONFIGURATION"
)
EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION = (
    "AUTHORIZATION_FLOW_CONFIGURATION"
)
EVIDENCE_TOKEN_STORAGE_MECHANISM = "TOKEN_STORAGE_MECHANISM"
EVIDENCE_TOKEN_EXPOSURE_CONTEXT = "TOKEN_EXPOSURE_CONTEXT"
EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION = (
    "AUTHORIZATION_SERVER_CONFIGURATION"
)
EVIDENCE_UNKNOWN = "UNKNOWN"

OAUTH_EVIDENCE_ITEMS: tuple[str, ...] = (
    EVIDENCE_REDIRECT_URI_REGISTRATION,
    EVIDENCE_REDIRECT_URI_MATCHING_POLICY,
    EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR,
    EVIDENCE_STATE_GENERATION,
    EVIDENCE_STATE_SESSION_BINDING,
    EVIDENCE_STATE_VALIDATION_BEHAVIOR,
    EVIDENCE_NONCE_VALIDATION_BEHAVIOR,
    EVIDENCE_PKCE_ENFORCEMENT_POLICY,
    EVIDENCE_PKCE_CHALLENGE_METHOD,
    EVIDENCE_PKCE_VERIFIER_VALIDATION,
    EVIDENCE_AUTHORIZATION_CODE_LIFETIME,
    EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE,
    EVIDENCE_AUTHORIZATION_CODE_BINDING,
    EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS,
    EVIDENCE_CLIENT_TYPE,
    EVIDENCE_CLIENT_AUTHENTICATION_METHOD,
    EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION,
    EVIDENCE_REQUESTED_SCOPES,
    EVIDENCE_GRANTED_SCOPES,
    EVIDENCE_SCOPE_VALIDATION_POLICY,
    EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION,
    EVIDENCE_AUDIENCE_VALIDATION_POLICY,
    EVIDENCE_ISSUER_CONFIGURATION,
    EVIDENCE_TOKEN_VALIDATION_CONFIGURATION,
    EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY,
    EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY,
    EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION,
    EVIDENCE_CONSENT_CONFIGURATION,
    EVIDENCE_CSRF_REQUEST_BINDING,
    EVIDENCE_LOGIN_CSRF_SESSION_BINDING,
    EVIDENCE_REDIRECT_HANDLING_CONFIGURATION,
    EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION,
    EVIDENCE_TOKEN_STORAGE_MECHANISM,
    EVIDENCE_TOKEN_EXPOSURE_CONTEXT,
    EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION,
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
LIMITATION_NO_OAUTH_FLOW_EXECUTION = "NO_OAUTH_FLOW_EXECUTION"
LIMITATION_NO_TOKEN_EXCHANGE = "NO_TOKEN_EXCHANGE"
LIMITATION_NO_REDIRECT_FOLLOWING = "NO_REDIRECT_FOLLOWING"
LIMITATION_NO_CREDENTIAL_TESTING = "NO_CREDENTIAL_TESTING"
LIMITATION_NO_PAYLOAD_GENERATION = "NO_PAYLOAD_GENERATION"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

OAUTH_EVIDENCE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_COLLECTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_OAUTH_FLOW_EXECUTION,
    LIMITATION_NO_TOKEN_EXCHANGE,
    LIMITATION_NO_REDIRECT_FOLLOWING,
    LIMITATION_NO_CREDENTIAL_TESTING,
    LIMITATION_NO_PAYLOAD_GENERATION,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_EVIDENCE_ITEMS = 36
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


def sanitize_oauth_evidence_plan(value: object) -> dict:
    """Project an R48.4 plan onto its fixed bounded key set."""

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
            if item in OAUTH_EVIDENCE_ITEMS
        ][:MAX_EVIDENCE_ITEMS],
        "evidence_state": evidence_state,
        "confidence": confidence,
        "limitations": [
            code
            for code in (
                _safe_text(entry)
                for entry in value.get("limitations") or ()
            )
            if code in OAUTH_EVIDENCE_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class OAuthEvidencePlan(BaseModel):
    """Deterministic research-only OAuth evidence plan (R48.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = OAUTH_EVIDENCE_PLAN_RULE_VERSION
    evidence_items: list[str] = Field(default_factory=list)
    evidence_state: str = STATE_UNKNOWN
    confidence: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return OAUTH_EVIDENCE_PLAN_RULE_VERSION

    @field_validator("evidence_items")
    @classmethod
    def _valid_items(cls, value: list) -> list[str]:
        return _require_codes(
            value, OAUTH_EVIDENCE_ITEMS, MAX_EVIDENCE_ITEMS
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
            value, OAUTH_EVIDENCE_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("oauth evidence plans are research-only")
        return True


def oauth_evidence_plan_projection(value: OAuthEvidencePlan) -> dict:
    """Serialize an R48.4 evidence plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "OAUTH_EVIDENCE_PLAN_RULE_VERSION",
    "RULE_VERSION",
    "EVIDENCE_REDIRECT_URI_REGISTRATION",
    "EVIDENCE_REDIRECT_URI_MATCHING_POLICY",
    "EVIDENCE_REDIRECT_URI_VALIDATION_BEHAVIOR",
    "EVIDENCE_STATE_GENERATION",
    "EVIDENCE_STATE_SESSION_BINDING",
    "EVIDENCE_STATE_VALIDATION_BEHAVIOR",
    "EVIDENCE_NONCE_VALIDATION_BEHAVIOR",
    "EVIDENCE_PKCE_ENFORCEMENT_POLICY",
    "EVIDENCE_PKCE_CHALLENGE_METHOD",
    "EVIDENCE_PKCE_VERIFIER_VALIDATION",
    "EVIDENCE_AUTHORIZATION_CODE_LIFETIME",
    "EVIDENCE_AUTHORIZATION_CODE_ONE_TIME_USE",
    "EVIDENCE_AUTHORIZATION_CODE_BINDING",
    "EVIDENCE_AUTHORIZATION_CODE_REPLAY_CONTROLS",
    "EVIDENCE_CLIENT_TYPE",
    "EVIDENCE_CLIENT_AUTHENTICATION_METHOD",
    "EVIDENCE_CLIENT_REGISTRATION_CONFIGURATION",
    "EVIDENCE_REQUESTED_SCOPES",
    "EVIDENCE_GRANTED_SCOPES",
    "EVIDENCE_SCOPE_VALIDATION_POLICY",
    "EVIDENCE_RESOURCE_INDICATOR_CONFIGURATION",
    "EVIDENCE_AUDIENCE_VALIDATION_POLICY",
    "EVIDENCE_ISSUER_CONFIGURATION",
    "EVIDENCE_TOKEN_VALIDATION_CONFIGURATION",
    "EVIDENCE_REFRESH_TOKEN_ROTATION_POLICY",
    "EVIDENCE_REFRESH_TOKEN_REVOCATION_POLICY",
    "EVIDENCE_REFRESH_TOKEN_REUSE_DETECTION",
    "EVIDENCE_CONSENT_CONFIGURATION",
    "EVIDENCE_CSRF_REQUEST_BINDING",
    "EVIDENCE_LOGIN_CSRF_SESSION_BINDING",
    "EVIDENCE_REDIRECT_HANDLING_CONFIGURATION",
    "EVIDENCE_AUTHORIZATION_FLOW_CONFIGURATION",
    "EVIDENCE_TOKEN_STORAGE_MECHANISM",
    "EVIDENCE_TOKEN_EXPOSURE_CONTEXT",
    "EVIDENCE_AUTHORIZATION_SERVER_CONFIGURATION",
    "EVIDENCE_UNKNOWN",
    "OAUTH_EVIDENCE_ITEMS",
    "STATE_COMPLETE",
    "STATE_PARTIAL",
    "STATE_UNKNOWN",
    "EVIDENCE_STATES",
    "LIMITATION_NO_COLLECTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_OAUTH_FLOW_EXECUTION",
    "LIMITATION_NO_TOKEN_EXCHANGE",
    "LIMITATION_NO_REDIRECT_FOLLOWING",
    "LIMITATION_NO_CREDENTIAL_TESTING",
    "LIMITATION_NO_PAYLOAD_GENERATION",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "OAUTH_EVIDENCE_LIMITATIONS",
    "MAX_EVIDENCE_ITEMS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_oauth_evidence_plan",
    "OAuthEvidencePlan",
    "oauth_evidence_plan_projection",
]
