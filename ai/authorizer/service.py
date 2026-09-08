"""Typed issuance boundary + binding validation (Phase 5B).

The ONLY path from "data shaped like an authorization" to authority
runs through :func:`issue_authorization` (issuer service side). The
ONLY path from an opaque id to authority runs through
:func:`get_issued_authorization` (executor side). No
``authorize_from_dict/json/blob`` helper exists anywhere by design.

All functions are pure except store interactions, use no network /
subprocess / LLM / database beyond the injected store, and raise
sanitized :class:`AuthzError` (never raw exceptions) for security
decisions.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import ValidationError

from ai.authorizer.store import (
    AuthorizationStore,
    AuthorizationStoreError,
    DuplicateIdempotencyKeyError,
    RecordNotFoundError,
    VersionConflictError,
)
from ai.schemas.artifact import ArtifactReference
from ai.schemas.execution_authorization import (
    AUTHORIZED_ISSUERS,
    ArtifactBinding,
    AuthzError,
    AuthorizationRequest,
    FixtureBinding,
    IssuedExecutionAuthorization,
    TargetBinding,
    XSSDerivationContract,
    _LEGAL_LIFECYCLE_TRANSITIONS,
    authorization_id_for,
    check_method_pair,
    generate_issuance_nonce,
    idempotency_key_for,
    utcnow_iso,
)

_AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CALLER_SCOPES = frozenset({"manual", "scheduled", "retry-new-authz"})


# ------------------------------------------------------------------
# Internal validation helpers
# ------------------------------------------------------------------


def _parse_instant(value: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise AuthzError("INVALID_AUTHORIZATION_REQUEST", "malformed instant") from exc
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant


def _validate_request_shape(request: AuthorizationRequest, now: str) -> None:
    if not isinstance(request, AuthorizationRequest):
        raise TypeError(
            "issuance accepts only AuthorizationRequest, "
            f"not {type(request).__name__}; raw dicts are never coerced"
        )
    if request.issuer_identity not in AUTHORIZED_ISSUERS:
        raise AuthzError(
            "INVALID_AUTHORIZATION_REQUEST",
            f"issuer not authorized: {request.issuer_identity!r}",
        )
    if request.caller_scope not in CALLER_SCOPES:
        raise AuthzError(
            "INVALID_AUTHORIZATION_REQUEST",
            "unknown caller scope",
        )
    issued = _parse_instant(now)
    expires = _parse_instant(request.expires_at)
    if expires <= issued:
        raise AuthzError(
            "INVALID_AUTHORIZATION_REQUEST",
            "expiry must be after issuance",
        )
    # Method contract: both sides allowed AND equal (no coercion).
    check_method_pair(request.plan_method, request.artifact_method)
    # Derivation coherence: oracle-phase work requires a contract whose
    # source matches the bound artifact; non-oracle work must not carry one.
    if request.xss_derivation is not None:
        contract = request.xss_derivation
        if contract.source_artifact_id != request.artifact.artifact_id:
            raise AuthzError(
                "DERIVATION_BINDING_MISMATCH",
                "derivation source does not match bound artifact",
            )
        if contract.source_content_hash != request.artifact.content_hash:
            raise AuthzError(
                "DERIVATION_BINDING_MISMATCH",
                "derivation source hash does not match bound artifact",
            )
    if request.execution_phase in ("submit", "read") and request.stored_round_id is None:
        raise AuthzError(
            "INVALID_AUTHORIZATION_REQUEST",
            "stored phases require a round identity",
        )


def _is_live(record: IssuedExecutionAuthorization, now: str) -> str | None:
    """Return None when live, else the terminal error code."""
    if record.lifecycle == "CONSUMED":
        return "AUTHZ_ALREADY_CONSUMED"
    if record.lifecycle == "REVOKED":
        return "AUTHZ_REVOKED"
    if record.lifecycle == "EXPIRED":
        return "AUTHZ_EXPIRED"
    if record.lifecycle != "ISSUED":
        return "AUTHZ_NOT_LIVE"
    if _parse_instant(record.expires_at) <= _parse_instant(now):
        return "AUTHZ_EXPIRED"
    return None


# ------------------------------------------------------------------
# Issuance + typed retrieval boundary
# ------------------------------------------------------------------


def issue_authorization(
    store: object,
    request: object,
    *,
    now: str | None = None,
) -> IssuedExecutionAuthorization:
    """Mint an authoritative record from issuer intent (issuer side only).

    Idempotent on the idempotency key: re-issuing the same basis
    returns the existing record instead of minting a duplicate.
    """

    if not isinstance(store, AuthorizationStore):
        raise TypeError(
            "issuance operates only on an AuthorizationStore, "
            f"not {type(store).__name__}"
        )
    _validate_request_shape(request, now or utcnow_iso())
    assert isinstance(request, AuthorizationRequest)
    moment = now or utcnow_iso()

    key = idempotency_key_for(
        test_plan_id=request.test_plan_id,
        artifact_id=request.artifact.artifact_id,
        content_hash=request.artifact.content_hash,
        program_name=request.target.program_name,
        host=request.target.host,
        execution_class=request.execution_class,
        scope_lists_hash=request.target.scope_lists_hash,
        caller_scope=request.caller_scope,
    )
    existing = store.get_by_idempotency_key(key)
    if existing is not None:
        return existing

    nonce = generate_issuance_nonce()
    record = IssuedExecutionAuthorization(
        authorization_id=authorization_id_for(
            test_plan_id=request.test_plan_id,
            artifact_id=request.artifact.artifact_id,
            content_hash=request.artifact.content_hash,
            program_name=request.target.program_name,
            host=request.target.host,
            execution_class=request.execution_class,
            scope_lists_hash=request.target.scope_lists_hash,
            issuance_nonce=nonce,
        ),
        idempotency_key=key,
        issuance_nonce=nonce,
        issuer_identity=request.issuer_identity,
        issued_at=moment,
        expires_at=request.expires_at,
        lifecycle="ISSUED",
        record_version=1,
        test_plan_id=request.test_plan_id,
        hypothesis_id=request.hypothesis_id,
        match_id=request.match_id,
        artifact=request.artifact,
        target=request.target,
        execution_class=request.execution_class,
        execution_phase=request.execution_phase,
        plan_method=request.plan_method,
        artifact_method=request.artifact_method,
        caller_scope=request.caller_scope,
        xss_derivation=request.xss_derivation,
        stored_leases=(
            _initial_leases(request.stored_round_id)
            if request.stored_round_id is not None
            else None
        ),
        fixture_binding=request.fixture_binding,
        cdn_binding=request.cdn_binding,
        resource_profile_ref=request.resource_profile_ref,
        audit_metadata=dict(request.audit_metadata),
    )
    try:
        return store.put_new(record)
    except DuplicateIdempotencyKeyError:
        # Lost a race with an identical issuance: return the winner
        # deterministically instead of failing.
        winner = store.get_by_idempotency_key(key)
        if winner is None:  # pragma: no cover - defensive
            raise
        return winner


def _initial_leases(round_id: str):  # local import to avoid cycle at top
    from ai.schemas.execution_authorization import StoredStageLeases

    return StoredStageLeases(round_id=round_id)


def get_issued_authorization(
    store: object, authorization_id: object
) -> IssuedExecutionAuthorization | None:
    """Typed retrieval: opaque id -> genuine record, or None.

    Only genuine store instances are returned. Dicts, JSON, strings
    shaped like records, LLM output, and arbitrary objects are
    rejected by type (never coerced, never parsed).
    """

    if not isinstance(store, AuthorizationStore):
        raise TypeError(
            "retrieval operates only on an AuthorizationStore, "
            f"not {type(store).__name__}"
        )
    if not isinstance(authorization_id, str):
        raise TypeError(
            "retrieval accepts only an opaque string authorization_id, "
            f"not {type(authorization_id).__name__}"
        )
    if not _AUTHZ_ID_RE.match(authorization_id):
        return None
    record = store.get(authorization_id)
    if record is None:
        return None
    # Re-validate through the contract so a store holding a facsimile
    # cannot smuggle malformed authority past the boundary.
    try:
        return IssuedExecutionAuthorization.model_validate(
            record.model_dump(mode="json")
        )
    except ValidationError:
        return None


def consume_authorization(
    store: object, authorization_id: object, *, now: str | None = None
) -> IssuedExecutionAuthorization:
    """Atomic single-consume CAS: ISSUED -> CONSUMED (executor side)."""

    moment = now or utcnow_iso()
    record = get_issued_authorization(store, authorization_id)
    if record is None:
        raise AuthzError("AUTHZ_NOT_FOUND", "unknown authorization")
    blocked = _is_live(record, moment)
    if blocked is not None:
        raise AuthzError(blocked, "authorization is not live")
    assert isinstance(store, AuthorizationStore)
    progressed = record.model_copy(
        update={"lifecycle": "CONSUMED", "record_version": record.record_version + 1}
    )
    try:
        return store.compare_and_swap(
            record.authorization_id, record.record_version, progressed
        )
    except (VersionConflictError, RecordNotFoundError) as exc:
        raise AuthzError(
            "AUTHZ_ALREADY_CONSUMED", "concurrent consume lost; no retry"
        ) from exc


def revoke_authorization(
    store: object, authorization_id: object, *, reason: str = "operator-revoked"
) -> IssuedExecutionAuthorization:
    """Monotonic ISSUED -> REVOKED transition (issuer side)."""

    record = get_issued_authorization(store, authorization_id)
    if record is None:
        raise AuthzError("AUTHZ_NOT_FOUND", "unknown authorization")
    if record.lifecycle != "ISSUED":
        raise AuthzError("AUTHZ_NOT_LIVE", "only ISSUED records revoke")
    assert isinstance(store, AuthorizationStore)
    _ = reason  # audit hook for 5H; reason text never enters the record
    progressed = record.model_copy(
        update={"lifecycle": "REVOKED", "record_version": record.record_version + 1}
    )
    try:
        return store.compare_and_swap(
            record.authorization_id, record.record_version, progressed
        )
    except (VersionConflictError, RecordNotFoundError) as exc:
        raise AuthzError("AUTHZ_NOT_LIVE", "revocation race lost") from exc


# ------------------------------------------------------------------
# Binding validation (pure; operates on genuine records only)
# ------------------------------------------------------------------


def _require_issued(record: object) -> IssuedExecutionAuthorization:
    if not isinstance(record, IssuedExecutionAuthorization):
        raise TypeError(
            "binding validation accepts only IssuedExecutionAuthorization, "
            f"not {type(record).__name__}; dicts/JSON never coerce"
        )
    return record


def validate_target_binding(
    record: object,
    *,
    program_name: str,
    host: str,
    scheme: str,
    effective_port: int,
    path_scope: str = "",
    scope_lists_hash: str,
) -> str:
    """Exact target equality (cross-program confusion impossible)."""

    authz = _require_issued(record)
    bound = authz.target
    if (
        bound.program_name != program_name
        or bound.host != host
        or bound.scheme != scheme
        or bound.effective_port != effective_port
        or bound.scope_lists_hash != scope_lists_hash
    ):
        raise AuthzError(
            "TARGET_BINDING_MISMATCH", "target binding does not match"
        )
    if bound.path_scope and path_scope != bound.path_scope:
        raise AuthzError(
            "TARGET_BINDING_MISMATCH", "path binding does not match"
        )
    return "OK"


def validate_derivation_binding(
    record: object, contract: object
) -> str:
    """Exact XSS derivation-contract equality (P-side + contract)."""

    authz = _require_issued(record)
    if not isinstance(contract, XSSDerivationContract):
        raise TypeError(
            "derivation validation accepts only XSSDerivationContract, "
            f"not {type(contract).__name__}"
        )
    bound = authz.xss_derivation
    if bound is None or bound != contract:
        raise AuthzError(
            "DERIVATION_BINDING_MISMATCH",
            "derivation contract does not match",
        )
    if (
        bound.source_artifact_id != authz.artifact.artifact_id
        or bound.source_content_hash != authz.artifact.content_hash
    ):
        raise AuthzError(
            "DERIVATION_BINDING_MISMATCH",
            "derivation source diverges from bound artifact",
        )
    return "OK"


def validate_fixture_binding(record: object, binding: object) -> str:
    """Exact fixture-pin equality (attacker bytes can never qualify)."""

    authz = _require_issued(record)
    if not isinstance(binding, FixtureBinding):
        raise TypeError(
            "fixture validation accepts only FixtureBinding, "
            f"not {type(binding).__name__}"
        )
    if authz.fixture_binding is None or authz.fixture_binding != binding:
        raise AuthzError(
            "AUTHZ_BINDING_MISMATCH", "fixture binding does not match"
        )
    return "OK"


def resolve_authorized_artifact(
    record: object, candidates: object
) -> ArtifactReference:
    """Exactly-one artifact resolution (Option A).

    ``candidates`` are the stored VALID records for the plan. Zero ->
    NOT_READY; more than one -> ARTIFACT_AMBIGUOUS (never first/pick);
    one but unequal to the bound triple -> ARTIFACT_BINDING_MISMATCH.
    """

    authz = _require_issued(record)
    if not isinstance(candidates, (list, tuple)):
        raise TypeError(
            "artifact resolution accepts a list/tuple of ArtifactReference, "
            f"not {type(candidates).__name__}"
        )
    for item in candidates:
        if not isinstance(item, ArtifactReference):
            raise TypeError(
                "candidates must be ArtifactReference, "
                f"not {type(item).__name__}"
            )
    if len(candidates) == 0:
        raise AuthzError("NOT_READY", "no eligible artifact stored")
    if len(candidates) > 1:
        raise AuthzError(
            "ARTIFACT_AMBIGUOUS",
            "multiple eligible artifacts; new authorization required",
        )
    only = candidates[0]
    bound = authz.artifact
    if (
        only.artifact_id != bound.artifact_id
        or only.content_hash != bound.content_hash
        or only.artifact_type != bound.artifact_type
        or only.test_plan_id != bound.test_plan_id
        or only.artifact_schema_version != bound.artifact_schema_version
    ):
        raise AuthzError(
            "ARTIFACT_BINDING_MISMATCH",
            "stored artifact differs from authorized artifact",
        )
    if bound.hypothesis_id is not None and only.hypothesis_id != bound.hypothesis_id:
        raise AuthzError("ARTIFACT_BINDING_MISMATCH", "hypothesis binding mismatch")
    if bound.match_id is not None and only.match_id != bound.match_id:
        raise AuthzError("ARTIFACT_BINDING_MISMATCH", "match binding mismatch")
    if bound.snapshot_hash is not None and only.snapshot_hash != bound.snapshot_hash:
        raise AuthzError("ARTIFACT_BINDING_MISMATCH", "snapshot binding mismatch")
    return only


# ------------------------------------------------------------------
# Stored-XSS stage leases (separate gates; SUBMIT never implies READ)
# ------------------------------------------------------------------


def _live_record_for_lease(
    store: object, authorization_id: object, now: str
) -> IssuedExecutionAuthorization:
    record = get_issued_authorization(store, authorization_id)
    if record is None:
        raise AuthzError("AUTHZ_NOT_FOUND", "unknown authorization")
    blocked = _is_live(record, now)
    if blocked is not None:
        raise AuthzError(blocked, "authorization is not live")
    if record.stored_leases is None:
        raise AuthzError("LEASE_NOT_LIVE", "no stored round bound")
    return record


def consume_submit_lease(
    store: object, authorization_id: object, *, now: str | None = None
) -> IssuedExecutionAuthorization:
    """Consume the SUBMIT lease (READ lease untouched)."""

    moment = now or utcnow_iso()
    record = _live_record_for_lease(store, authorization_id, moment)
    assert isinstance(store, AuthorizationStore)
    assert record.stored_leases is not None
    leases = record.stored_leases.transition_submit("CONSUMED")
    progressed = record.model_copy(
        update={"stored_leases": leases, "record_version": record.record_version + 1}
    )
    try:
        return store.compare_and_swap(
            record.authorization_id, record.record_version, progressed
        )
    except (VersionConflictError, RecordNotFoundError) as exc:
        raise AuthzError("LEASE_NOT_LIVE", "submit lease race lost") from exc


def consume_read_lease(
    store: object, authorization_id: object, *, now: str | None = None
) -> IssuedExecutionAuthorization:
    """Consume the READ lease via its own gate (SUBMIT state irrelevant)."""

    moment = now or utcnow_iso()
    record = _live_record_for_lease(store, authorization_id, moment)
    assert isinstance(store, AuthorizationStore)
    assert record.stored_leases is not None
    leases = record.stored_leases.transition_read("CONSUMED")
    progressed = record.model_copy(
        update={"stored_leases": leases, "record_version": record.record_version + 1}
    )
    try:
        return store.compare_and_swap(
            record.authorization_id, record.record_version, progressed
        )
    except (VersionConflictError, RecordNotFoundError) as exc:
        raise AuthzError("LEASE_NOT_LIVE", "read lease race lost") from exc


__all__ = [
    "CALLER_SCOPES",
    "consume_authorization",
    "consume_read_lease",
    "consume_submit_lease",
    "get_issued_authorization",
    "issue_authorization",
    "resolve_authorized_artifact",
    "revoke_authorization",
    "validate_derivation_binding",
    "validate_fixture_binding",
    "validate_target_binding",
]
