"""ExecutionAuthorization data contract (Phase 5B).

Position in the pipeline::

    READY TestPlan + VALID ArtifactReference
        |
        v
    AuthorizationRequest (issuer intent, NOT authority)
        |
        v  (issuer service, server-side issuance record)
    IssuedExecutionAuthorization (authority, by reference only)
        |
        v  (typed retrieval: opaque id -> genuine record)
    future 5C-5J gates (resolution, scope, revalidation, execution)

Trust semantics (normative per
``agent-reports/execution-authorization-architecture.md``):

- An ``AuthorizationRequest`` is intent. It can never be consumed,
  executed, or treated as authority.
- An ``IssuerContext`` is an informational issuer view. It can never
  mint authority (it carries ``is_authority=False`` structurally).
- Only an ``IssuedExecutionAuthorization`` materialized through the
  typed issuance boundary (``ai.authorizer`` store API) is authority.
  A dict/JSON/text blob with identical public fields is data, never
  authority: no ``authorize_from_dict/json/blob`` constructor exists
  in this codebase by design.
- ``authorization_id`` / ``idempotency_key`` are deterministic dedupe
  keys, never proof. Authenticity comes from store provenance (the
  record was written by the issuance service under its ACL), not
  from recomputing a hash.
- Canonical artifact identity is ``ArtifactReference`` /
  ``artifact_id_for()`` (plan-bound). ``TestPlan.artifact_ref`` is
  advisory/legacy and is NEVER consulted here.
- ``max_executions`` is fixed to 1. Multi-artifact binding is
  exactly-one (Option A). HTTP methods exclude DELETE/CONNECT/TRACE
  with no coercion. XSS oracle paths bind the derivation contract
  and record P != O explicitly via dual hashes.

This module is PURE and DETERMINISTIC (aside from issuance-nonce
generation, which uses ``secrets`` and is format-tested, never
value-tested):

- NO network, NO subprocess, NO database, NO LLM, NO scope
  evaluation, NO DNS, NO execution, NO verification, NO findings.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai.schemas.artifact import (
    SCHEMA_VERSION as ARTIFACT_SCHEMA_VERSION,
    artifact_id_for,
)


SCHEMA_VERSION = "execution_authorization/v1"

PLANNER_ID = "oracle-planner"

SEED_RULE = "sha256-salt-attempt-phase-v1"

RUN_SALT_AUTHORITY = "executor-runtime"

# ------------------------------------------------------------------
# Closed vocabularies (fail closed, no "other" escape hatch)
# ------------------------------------------------------------------

ExecutionClass = Literal[
    "http_probe",
    "nuclei_scan",
    "http_verification",
    "browser_verification",
]

ExecutionPhase = Literal[
    "single",
    "submit",
    "read",
    "oracle",
]

LifecycleState = Literal[
    "ISSUED",
    "CONSUMED",
    "REVOKED",
    "EXPIRED",
]

StageLeaseState = Literal[
    "PENDING",
    "CONSUMED",
    "FAILED",
    "SKIPPED",
]

AllowedMethod = Literal[
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "HEAD",
    "OPTIONS",
]

ALLOWED_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"}
)

FORBIDDEN_METHODS = frozenset({"DELETE", "CONNECT", "TRACE"})

OracleContext = Literal[
    "html_body",
    "html_attribute",
    "script_block",
    "generic",
]

ORACLE_CONTEXTS = frozenset(
    {"html_body", "html_attribute", "script_block", "generic"}
)

SkeletonFamily = Literal[
    "attribute",
    "script",
]

IssuerIdentity = Literal[
    "human-review-board",
    "security-operator",
]

AUTHORIZED_ISSUERS = frozenset({"human-review-board", "security-operator"})

# Principals that must never hold issuance rights. Checked by the
# service layer; listed here so tests can enumerate the boundary.
NEVER_ISSUERS = frozenset(
    {"llm-researcher", "scheduler", "collector", "verifier", ""}
)

Scheme = Literal["http", "https"]

AuthzErrorCode = Literal[
    "AUTHZ_NOT_FOUND",
    "AUTHZ_NOT_LIVE",
    "AUTHZ_EXPIRED",
    "AUTHZ_REVOKED",
    "AUTHZ_ALREADY_CONSUMED",
    "AUTHZ_BINDING_MISMATCH",
    "ARTIFACT_BINDING_MISMATCH",
    "ARTIFACT_AMBIGUOUS",
    "NOT_READY",
    "METHOD_NOT_ALLOWED",
    "TRANSLATION_REJECTED",
    "TARGET_BINDING_MISMATCH",
    "DERIVATION_BINDING_MISMATCH",
    "LEASE_NOT_LIVE",
    "INVALID_AUTHORIZATION_REQUEST",
]

# ------------------------------------------------------------------
# Identifier shapes
# ------------------------------------------------------------------

_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")
_HYP_ID_RE = re.compile(r"^hyp-[0-9a-f]{16}$")
_TM_ID_RE = re.compile(r"^tm-[0-9a-f]{16}$")
_ART_ID_RE = re.compile(r"^art-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_ROUND_ID_RE = re.compile(r"^sr-[0-9a-f]{32}$")
_FIXTURE_SET_RE = re.compile(r"^fix-[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_LEGAL_LEASE_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"CONSUMED", "FAILED", "SKIPPED"}),
    "CONSUMED": frozenset(),
    "FAILED": frozenset(),
    "SKIPPED": frozenset(),
}

_LEGAL_LIFECYCLE_TRANSITIONS: dict[str, frozenset[str]] = {
    "ISSUED": frozenset({"CONSUMED", "REVOKED", "EXPIRED"}),
    "CONSUMED": frozenset(),
    "REVOKED": frozenset(),
    "EXPIRED": frozenset(),
}


# ------------------------------------------------------------------
# Pure helpers
# ------------------------------------------------------------------


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def utcnow_iso() -> str:
    """Current UTC time as ISO-8601. Only non-determinism source's peer."""
    return datetime.now(timezone.utc).isoformat()


def generate_issuance_nonce() -> str:
    """128-bit random issuance nonce, 32 lowercase hex chars."""
    return secrets.token_hex(16)


def authorization_id_for(
    *,
    test_plan_id: str,
    artifact_id: str,
    content_hash: str,
    program_name: str,
    host: str,
    execution_class: str,
    scope_lists_hash: str,
    issuance_nonce: str,
) -> str:
    """Deterministic dedupe alias (NOT proof) for an authorization basis.

    The nonce guarantees distinct issuances never collide even for
    identical logical bases; dedupe on the idempotency key instead.
    """

    basis = _canonical_json(
        {
            "artifact_id": artifact_id,
            "content_hash": content_hash,
            "execution_class": execution_class,
            "host": host,
            "issuance_nonce": issuance_nonce,
            "program_name": program_name,
            "scope_lists_hash": scope_lists_hash,
            "test_plan_id": test_plan_id,
        }
    )
    return "authz-" + _sha256_hex(basis)[:16]


def idempotency_key_for(
    *,
    test_plan_id: str,
    artifact_id: str,
    content_hash: str,
    program_name: str,
    host: str,
    execution_class: str,
    scope_lists_hash: str,
    caller_scope: str,
) -> str:
    """Full SHA-256 dedupe key over the idempotency basis.

    Caller scope comes from a fixed vocabulary (validated at the
    service layer); distinct keys are distinct intent by definition.
    """

    basis = _canonical_json(
        {
            "artifact_id": artifact_id,
            "caller_scope": caller_scope,
            "content_hash": content_hash,
            "execution_class": execution_class,
            "host": host,
            "program_name": program_name,
            "scope_lists_hash": scope_lists_hash,
            "test_plan_id": test_plan_id,
        }
    )
    return _sha256_hex(basis)


def effective_port_for(scheme: str, port: int | None) -> int:
    """Default ports to effective integers (fail closed on bad input)."""

    if port is not None:
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValueError(f"invalid port: {port!r}")
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port!r}")
        return port
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    raise ValueError(f"unknown scheme for default port: {scheme!r}")


def check_method_pair(plan_method: object, artifact_method: object) -> str:
    """Validate the 5B method contract (no coercion, ever).

    Returns "OK". Raises ``AuthzError`` with METHOD_NOT_ALLOWED when
    either side is forbidden/unknown, or TRANSLATION_REJECTED when
    both are allowed but unequal.
    """

    if plan_method not in ALLOWED_METHODS or artifact_method not in ALLOWED_METHODS:
        raise AuthzError(
            "METHOD_NOT_ALLOWED",
            f"forbidden or unknown method pair: {plan_method!r}/{artifact_method!r}",
        )
    if plan_method != artifact_method:
        raise AuthzError(
            "TRANSLATION_REJECTED",
            f"plan/artifact method mismatch: {plan_method!r} != {artifact_method!r}",
        )
    return "OK"


def canonical_artifact_id_for(
    *,
    artifact_type: str,
    test_plan_id: str,
    content_hash: str,
    schema_version: str = ARTIFACT_SCHEMA_VERSION,
) -> str:
    """Canonical execution artifact identity (single source of truth).

    Thin wrapper over ``ai.schemas.artifact.artifact_id_for`` so all
    5B code paths share one import. Legacy ``TestPlan.artifact_ref``
    identities (``"art-" + hash[:16]``) never pass through here.
    """

    return artifact_id_for(
        artifact_type=artifact_type,
        test_plan_id=test_plan_id,
        content_hash=content_hash,
        schema_version=schema_version,
    )


# ------------------------------------------------------------------
# Security error model
# ------------------------------------------------------------------


class AuthzError(ValueError):
    """Deterministic authorization failure with an explicit code.

    Messages are static, bounded, caller-supplied-value-free templates
    plus validated identifiers only. Raw exceptions, connection
    strings, credentials, and environment values must never flow
    through here (enforced by constructor sanitization + tests).
    """

    _SECRET_MARKERS = (
        "mongodb://",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "secret",
        "bearer ",
        "-----begin",
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in (
            "AUTHZ_NOT_FOUND",
            "AUTHZ_NOT_LIVE",
            "AUTHZ_EXPIRED",
            "AUTHZ_REVOKED",
            "AUTHZ_ALREADY_CONSUMED",
            "AUTHZ_BINDING_MISMATCH",
            "ARTIFACT_BINDING_MISMATCH",
            "ARTIFACT_AMBIGUOUS",
            "NOT_READY",
            "METHOD_NOT_ALLOWED",
            "TRANSLATION_REJECTED",
            "TARGET_BINDING_MISMATCH",
            "DERIVATION_BINDING_MISMATCH",
            "LEASE_NOT_LIVE",
            "INVALID_AUTHORIZATION_REQUEST",
        ):
            raise ValueError(f"unknown authz error code: {code!r}")
        safe_detail = (detail or "")[:300]
        lowered = safe_detail.casefold()
        for marker in self._SECRET_MARKERS:
            if marker in lowered:
                raise ValueError(
                    "authz error detail carries suspected secret material"
                )
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


# ------------------------------------------------------------------
# Binding models
# ------------------------------------------------------------------


class TargetBinding(BaseModel):
    """Canonical execution target identity (data, not resolution).

    Effective port is an integer (80/443 defaulted at issuance);
    ``None``-vs-explicit ambiguity is unrepresentable by construction.
    ``(program_name, host)`` is the cross-program isolation key.
    """

    model_config = ConfigDict(extra="forbid")

    program_name: str
    host: str
    scheme: Scheme = "https"
    effective_port: int = 443
    path_scope: str = ""
    snapshot_ref: str | None = None
    scope_policy_version: str = "scope-policy/v1"
    scope_lists_hash: str

    @field_validator("program_name", "host")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if "\n" in value or "\r" in value:
            raise ValueError("must not contain newlines")
        return value

    @field_validator("effective_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("effective_port must be an integer")
        if not 1 <= value <= 65535:
            raise ValueError("effective_port out of range")
        return value

    @field_validator("path_scope")
    @classmethod
    def _path(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("path_scope must not contain newlines")
        if value and not value.startswith("/"):
            raise ValueError("path_scope must start with '/'")
        return value

    @field_validator("snapshot_ref")
    @classmethod
    def _snapshot(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid snapshot_ref: {value!r}")
        return value

    @field_validator("scope_lists_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid scope_lists_hash: {value!r}")
        return value


class ArtifactBinding(BaseModel):
    """Exact authorized artifact triple (+ descriptive provenance).

    Identity rule: ``artifact_id`` MUST equal ``artifact_id_for()``
    over (type, plan, hash, version). Legacy content-keyed
    (``"art-" + hash[:16]``) identities fail this check structurally.
    """

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    artifact_type: Literal[
        "nuclei_template", "xss_payload", "http_request_spec"
    ]
    content_hash: str
    test_plan_id: str
    artifact_schema_version: Literal["artifact/v1"] = "artifact/v1"
    hypothesis_id: str | None = None
    match_id: str | None = None
    snapshot_hash: str | None = None

    @field_validator("artifact_id")
    @classmethod
    def _art_id(cls, value: str) -> str:
        if not _ART_ID_RE.match(value or ""):
            raise ValueError(f"invalid artifact_id: {value!r}")
        return value

    @field_validator("content_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid content_hash: {value!r}")
        return value

    @field_validator("test_plan_id")
    @classmethod
    def _tp_id(cls, value: str) -> str:
        if not _TP_ID_RE.match(value or ""):
            raise ValueError(f"invalid test_plan_id: {value!r}")
        return value

    @field_validator("hypothesis_id")
    @classmethod
    def _hyp_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HYP_ID_RE.match(value):
            raise ValueError(f"invalid hypothesis_id: {value!r}")
        return value

    @field_validator("match_id")
    @classmethod
    def _match_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _TM_ID_RE.match(value):
            raise ValueError(f"invalid match_id: {value!r}")
        return value

    @field_validator("snapshot_hash")
    @classmethod
    def _snapshot(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SHA256_RE.match(value):
            raise ValueError(f"invalid snapshot_hash: {value!r}")
        return value

    @model_validator(mode="after")
    def _identity_consistency(self) -> "ArtifactBinding":
        expected = artifact_id_for(
            artifact_type=self.artifact_type,
            test_plan_id=self.test_plan_id,
            content_hash=self.content_hash,
            schema_version=self.artifact_schema_version,
        )
        if self.artifact_id != expected:
            raise ValueError(
                "artifact_id must be the plan-bound canonical identity "
                "(legacy content-keyed identities are not authorized)"
            )
        return self


class XSSDerivationContract(BaseModel):
    """Authorization for planner-derived oracle execution (Model 1).

    Binds the source artifact P plus the derivation contract that
    produces the executed oracle payload O. P != O is expected and
    explicit; evidence must carry both hashes (§ dual-hash rule).
    """

    model_config = ConfigDict(extra="forbid")

    source_artifact_id: str
    source_content_hash: str
    planner_id: Literal["oracle-planner"] = "oracle-planner"
    planner_version: str = "oracle-planner/v1"
    oracle_version: int = 1
    allowed_context: OracleContext
    allowed_skeleton_family: SkeletonFamily
    execution_phase: Literal["oracle", "stored_submit", "stored_read"] = (
        "oracle"
    )
    seed_rule: Literal["sha256-salt-attempt-phase-v1"] = (
        "sha256-salt-attempt-phase-v1"
    )
    run_salt_authority: Literal["executor-runtime"] = "executor-runtime"

    @field_validator("source_artifact_id")
    @classmethod
    def _art_id(cls, value: str) -> str:
        if not _ART_ID_RE.match(value or ""):
            raise ValueError(f"invalid source_artifact_id: {value!r}")
        return value

    @field_validator("source_content_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid source_content_hash: {value!r}")
        return value

    @field_validator("oracle_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("oracle_version must be a positive integer")
        return value


class StoredStageLeases(BaseModel):
    """Two independent stage leases for one stored-XSS round.

    SUBMIT success never implies READ permission: the read lease has
    its own gate and transitions independently.
    """

    model_config = ConfigDict(extra="forbid")

    round_id: str
    submit_lease: StageLeaseState = "PENDING"
    read_lease: StageLeaseState = "PENDING"

    @field_validator("round_id")
    @classmethod
    def _round_id(cls, value: str) -> str:
        if not _ROUND_ID_RE.match(value or ""):
            raise ValueError(f"invalid round_id: {value!r}")
        return value

    def transition_submit(self, next_state: str) -> "StoredStageLeases":
        """Pure lease transition (returns a new instance)."""
        allowed = _LEGAL_LEASE_TRANSITIONS[self.submit_lease]
        if next_state not in allowed:
            raise AuthzError(
                "LEASE_NOT_LIVE",
                f"illegal submit lease transition: {self.submit_lease!r}",
            )
        return self.model_copy(update={"submit_lease": next_state})

    def transition_read(self, next_state: str) -> "StoredStageLeases":
        """Pure lease transition (returns a new instance)."""
        allowed = _LEGAL_LEASE_TRANSITIONS[self.read_lease]
        if next_state not in allowed:
            raise AuthzError(
                "LEASE_NOT_LIVE",
                f"illegal read lease transition: {self.read_lease!r}",
            )
        return self.model_copy(update={"read_lease": next_state})


class FixtureBinding(BaseModel):
    """Immutable pin of issuer-curated specificity fixtures."""

    model_config = ConfigDict(extra="forbid")

    fixture_set_id: str
    fixture_version: str
    fixture_hashes: tuple[str, ...]
    family_binding: str

    @field_validator("fixture_set_id")
    @classmethod
    def _set_id(cls, value: str) -> str:
        if not _FIXTURE_SET_RE.match(value or ""):
            raise ValueError(f"invalid fixture_set_id: {value!r}")
        return value

    @field_validator("fixture_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not _VERSION_RE.match(value or ""):
            raise ValueError(f"invalid fixture_version: {value!r}")
        return value

    @field_validator("fixture_hashes")
    @classmethod
    def _hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("fixture_hashes must be non-empty")
        for item in value:
            if not _SHA256_RE.match(item or ""):
                raise ValueError(f"invalid fixture_hash: {item!r}")
        return value

    @field_validator("family_binding")
    @classmethod
    def _family(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("family_binding must be non-empty")
        if "\n" in value or "\r" in value:
            raise ValueError("family_binding must be single-line")
        return value


class CdnMappingBinding(BaseModel):
    """Pin of the per-program CDN host-mapping version (if any)."""

    model_config = ConfigDict(extra="forbid")

    mapping_version: str
    mapping_hash: str

    @field_validator("mapping_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not _VERSION_RE.match(value or ""):
            raise ValueError(f"invalid mapping_version: {value!r}")
        return value

    @field_validator("mapping_hash")
    @classmethod
    def _hash(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid mapping_hash: {value!r}")
        return value


# ------------------------------------------------------------------
# Request (intent, NOT authority) and issued record (authority)
# ------------------------------------------------------------------


class AuthorizationRequest(BaseModel):
    """Issuer intent for a future authorization. NOT authority.

    This object can never be consumed, executed, or treated as
    permission. Only the issuance service can mint an
    ``IssuedExecutionAuthorization`` from it.
    """

    model_config = ConfigDict(extra="forbid")

    test_plan_id: str
    hypothesis_id: str | None = None
    match_id: str | None = None
    artifact: ArtifactBinding
    target: TargetBinding
    execution_class: ExecutionClass
    execution_phase: ExecutionPhase = "single"
    plan_method: AllowedMethod = "GET"
    artifact_method: AllowedMethod = "GET"
    expires_at: str
    caller_scope: str = "manual"
    issuer_identity: IssuerIdentity = "human-review-board"
    xss_derivation: XSSDerivationContract | None = None
    stored_round_id: str | None = None
    fixture_binding: FixtureBinding | None = None
    cdn_binding: CdnMappingBinding | None = None
    resource_profile_ref: str = "default"
    audit_metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("test_plan_id")
    @classmethod
    def _tp_id(cls, value: str) -> str:
        if not _TP_ID_RE.match(value or ""):
            raise ValueError(f"invalid test_plan_id: {value!r}")
        return value

    @field_validator("hypothesis_id")
    @classmethod
    def _hyp_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HYP_ID_RE.match(value):
            raise ValueError(f"invalid hypothesis_id: {value!r}")
        return value

    @field_validator("match_id")
    @classmethod
    def _match_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _TM_ID_RE.match(value):
            raise ValueError(f"invalid match_id: {value!r}")
        return value

    @field_validator("stored_round_id")
    @classmethod
    def _round_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ROUND_ID_RE.match(value):
            raise ValueError(f"invalid stored_round_id: {value!r}")
        return value

    @field_validator("audit_metadata")
    @classmethod
    def _audit(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise ValueError("audit metadata keys/values must be strings")
            if len(key) > 128 or len(item) > 512:
                raise ValueError("audit metadata entry exceeds size limit")
            if "\n" in key or "\r" in key or "\n" in item or "\r" in item:
                raise ValueError("audit metadata must be single-line")
        forbidden = {
            "verdict",
            "confirmed",
            "scope_allowed",
            "execution_allowed",
        }
        for key in value:
            if key.casefold() in forbidden:
                raise ValueError(
                    f"audit metadata key is not permitted: {key!r}"
                )
        return value


class IssuedExecutionAuthorization(BaseModel):
    """Authoritative issuance record. Authority by reference only.

    Instances are valid only when materialized through the typed
    issuance boundary (``ai.authorizer``). Structural equality with
    a forged dict proves nothing; store provenance is the authority.
    """

    model_config = ConfigDict(extra="forbid")

    authorization_id: str
    idempotency_key: str
    issuance_nonce: str
    issuer_identity: IssuerIdentity
    issued_at: str
    expires_at: str
    lifecycle: LifecycleState = "ISSUED"
    record_version: int = 1
    test_plan_id: str
    hypothesis_id: str | None = None
    match_id: str | None = None
    artifact: ArtifactBinding
    target: TargetBinding
    execution_class: ExecutionClass
    execution_phase: ExecutionPhase = "single"
    plan_method: AllowedMethod = "GET"
    artifact_method: AllowedMethod = "GET"
    max_executions: Literal[1] = 1
    caller_scope: str = "manual"
    xss_derivation: XSSDerivationContract | None = None
    stored_leases: StoredStageLeases | None = None
    fixture_binding: FixtureBinding | None = None
    cdn_binding: CdnMappingBinding | None = None
    resource_profile_ref: str = "default"
    audit_metadata: dict[str, str] = Field(default_factory=dict)
    schema_version: Literal["execution_authorization/v1"] = (
        "execution_authorization/v1"
    )

    @field_validator("authorization_id")
    @classmethod
    def _authz_id(cls, value: str) -> str:
        if not _AUTHZ_ID_RE.match(value or ""):
            raise ValueError(f"invalid authorization_id: {value!r}")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid idempotency_key: {value!r}")
        return value

    @field_validator("issuance_nonce")
    @classmethod
    def _nonce(cls, value: str) -> str:
        if not _NONCE_RE.match(value or ""):
            raise ValueError(f"invalid issuance_nonce: {value!r}")
        return value

    @field_validator("test_plan_id")
    @classmethod
    def _tp_id(cls, value: str) -> str:
        if not _TP_ID_RE.match(value or ""):
            raise ValueError(f"invalid test_plan_id: {value!r}")
        return value

    @field_validator("record_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("record_version must be a positive integer")
        return value


class IssuerContext(BaseModel):
    """Informational issuer view. Explicitly NOT authority.

    ``is_authority`` is structurally False so no consumer can mistake
    this view for permission. The issuance service reads it to mint
    records; the executor must never accept it.
    """

    model_config = ConfigDict(extra="forbid")

    is_authority: Literal[False] = False
    test_plan_id: str
    hypothesis_id: str | None = None
    artifact_id: str
    content_hash: str
    artifact_type: str = ""
    target_program: str = ""
    target_host: str = ""
    scope_policy_version: str = ""
    scope_lists_hash: str = ""
    readiness_outcome: str = ""
    artifact_validation_state: str = ""
    fixture_set_id: str = ""
    execution_class: str = ""
    resource_profile_ref: str = "default"
    requested_ttl_note: str = ""
    replay_note: str = ""


__all__ = [
    "SCHEMA_VERSION",
    "PLANNER_ID",
    "SEED_RULE",
    "RUN_SALT_AUTHORITY",
    "ExecutionClass",
    "ExecutionPhase",
    "LifecycleState",
    "StageLeaseState",
    "AllowedMethod",
    "ALLOWED_METHODS",
    "FORBIDDEN_METHODS",
    "OracleContext",
    "ORACLE_CONTEXTS",
    "SkeletonFamily",
    "IssuerIdentity",
    "AUTHORIZED_ISSUERS",
    "NEVER_ISSUERS",
    "Scheme",
    "AuthzErrorCode",
    "AuthzError",
    "TargetBinding",
    "ArtifactBinding",
    "XSSDerivationContract",
    "StoredStageLeases",
    "FixtureBinding",
    "CdnMappingBinding",
    "AuthorizationRequest",
    "IssuedExecutionAuthorization",
    "IssuerContext",
    "utcnow_iso",
    "generate_issuance_nonce",
    "authorization_id_for",
    "idempotency_key_for",
    "effective_port_for",
    "check_method_pair",
    "canonical_artifact_id_for",
]
