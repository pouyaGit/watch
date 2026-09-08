"""Authoritative ExecutionAuthorization issuance boundary (Phase 5B).

Server-side authorization-by-reference: the executor accepts only an
opaque ``authorization_id`` and loads the genuine issuance record
through this package's typed API. Dicts, JSON blobs, LLM output, and
any other serialized shape are never coerced into authority.
"""

from ai.authorizer.service import (
    consume_authorization,
    consume_read_lease,
    consume_submit_lease,
    get_issued_authorization,
    issue_authorization,
    resolve_authorized_artifact,
    revoke_authorization,
    validate_derivation_binding,
    validate_fixture_binding,
    validate_target_binding,
)
from ai.authorizer.store import (
    AuthorizationStore,
    AuthorizationStoreError,
    DuplicateIdempotencyKeyError,
    InMemoryAuthorizationStore,
    RecordNotFoundError,
    VersionConflictError,
)

__all__ = [
    "AuthorizationStore",
    "AuthorizationStoreError",
    "DuplicateIdempotencyKeyError",
    "InMemoryAuthorizationStore",
    "RecordNotFoundError",
    "VersionConflictError",
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
