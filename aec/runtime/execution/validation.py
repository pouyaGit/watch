"""EPIC7 Part 2: request validation — the twelve explicit checks.

Every observation is validated afresh against its authorization, policy,
and scope. There are no implicit defaults: an authorization that is
missing, denied, expired, mismatched, or unknown is BLOCKED; a request
the policy does not permit is REFUSED. The single honest outcome is an
explicit AUTHORIZED decision with zero reasons.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aec.runtime.policy.models import (
    evidence_level_compatible, is_observation_type, method_permitted,
    policy_version_supported)

_PRIVATE_HOST_SUFFIXES = (
    ".localhost", ".internal", ".local", ".lan")
_PRIVATE_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0", "10.0.0.0",
    "169.254.169.254"})


@dataclass(frozen=True)
class ValidationResult:
    decision: str            # AUTHORIZED | BLOCKED | REFUSED
    reasons: tuple[str, ...]
    policy_version: str
    authorization_reference: str


def _host_is_private(host: str) -> bool:
    lowered = host.lower()
    if lowered in _PRIVATE_HOSTS:
        return True
    if lowered.startswith(("10.", "127.", "192.168.", "169.254.",
                           "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.",
                           "172.24.", "172.25.", "172.26.", "172.27.",
                           "172.28.", "172.29.", "172.30.", "172.31.")):
        return True
    return any(lowered.endswith(suffix) for suffix in _PRIVATE_HOST_SUFFIXES)


def _looks_like_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(
        part.isdigit() for part in parts)


def validate_request(
    request: Mapping[str, Any],
    authorization: Mapping[str, Any] | None,
    policy: Any,
    tick: int,
    executed_request_ids: set[str] | None = None,
    target: Mapping[str, Any] | None = None,
    scope_hosts: frozenset[str] = frozenset(),
) -> ValidationResult:
    """Run the twelve checks. BLOCKED for authorization failures, REFUSED
    for policy/scope failures, AUTHORIZED only when every check passes."""
    blocked: list[str] = []
    refused: list[str] = []
    request = dict(request) if isinstance(request, Mapping) else {}
    policy_version = str(request.get("policy_version") or "unspecified")
    authorization_reference = str(request.get(
        "authorization_reference") or "")

    # 1. Authorization exists and is well-formed.
    if authorization is None or not isinstance(authorization, Mapping):
        blocked.append("AUTHORIZATION_MISSING")
        return _result("BLOCKED", blocked, policy_version,
                       authorization_reference)
    authz = dict(authorization)

    # 2. Authorization is valid (status) and 3. not expired.
    status = authz.get("status")
    if status == "DENIED":
        blocked.append("AUTHORIZATION_DENIED")
    elif status == "EXPIRED":
        blocked.append("AUTHORIZATION_EXPIRED")
    elif status == "GRANTED":
        expires = authz.get("expires_tick")
        if isinstance(expires, int) and tick >= expires:
            blocked.append("AUTHORIZATION_EXPIRED")
    else:
        blocked.append(
            "AUTHORIZATION_UNKNOWN_STATUS" if status is not None
            else "AUTHORIZATION_REFERENCE_MISSING")

    # 4. Request identity matches authorization.
    authz_ref = str(authz.get("authorization_reference") or "")
    if not authz_ref:
        blocked.append("AUTHORIZATION_REFERENCE_MISSING")
    elif authorization_reference and authorization_reference != authz_ref:
        blocked.append("AUTHORIZATION_REFERENCE_MISMATCH")

    # 5. Case identity matches request.
    authz_case = str(authz.get("case_id") or "")
    request_case = str(request.get("case_id") or "")
    if authz_case and request_case and authz_case != request_case:
        blocked.append("CASE_IDENTITY_MISMATCH")
    elif not request_case:
        blocked.append("CASE_IDENTITY_MISSING")

    # 6. Target identity matches authorization.
    authz_target = str(authz.get("target_id") or "")
    request_target = str(request.get("target_id") or "")
    if not authz_target:
        blocked.append("TARGET_IDENTITY_MISSING")
    elif authz_target != request_target:
        blocked.append("TARGET_IDENTITY_MISMATCH")

    # 7. Request has not already executed.
    executed = executed_request_ids or set()
    request_id = str(request.get("request_id") or "")
    if request_id and request_id in executed:
        blocked.append("REQUEST_ALREADY_EXECUTED")

    # 8-12. Policy checks.
    obs_type = request.get("observation_type")
    if not isinstance(obs_type, str) or not is_observation_type(obs_type):
        refused.append("TYPE_UNKNOWN")
    else:
        allowed = getattr(policy, "observation_types", ()) or ()
        if obs_type not in allowed:
            refused.append("TYPE_NOT_PERMITTED")
    method = request.get("method")
    if not isinstance(method, str) or not method_permitted(method):
        refused.append("METHOD_NOT_PERMITTED")
    level = request.get("required_evidence_level")
    if not isinstance(level, str) or not level:
        refused.append("EVIDENCE_LEVEL_MISSING")
    elif isinstance(obs_type, str) \
            and not evidence_level_compatible(level, obs_type):
        refused.append("EVIDENCE_LEVEL_INCOMPATIBLE")
    if not policy_version_supported(
            request.get("policy_version")):
        refused.append("POLICY_VERSION_UNSUPPORTED")

    # Target scope checks (when a target is supplied).
    if isinstance(target, Mapping):
        host = str(target.get("host") or "")
        if isinstance(target.get("host"), str) and "@" in host:
            refused.append("TARGET_USERINFO")
        elif host and scope_hosts and host not in scope_hosts:
            refused.append("TARGET_HOST_OUT_OF_SCOPE")
        if host and (_host_is_private(host) or _looks_like_ip(host)):
            refused.append("TARGET_PRIVATE_NETWORK")

    if blocked:
        return _result("BLOCKED", blocked, policy_version,
                       authorization_reference)
    if refused:
        return _result("REFUSED", refused, policy_version,
                       authorization_reference)
    return _result("AUTHORIZED", (), policy_version,
                   authorization_reference)


def _result(decision: str, reasons: list[str] | tuple[str, ...],
            policy_version: str,
            authorization_reference: str) -> ValidationResult:
    return ValidationResult(
        decision=decision,
        reasons=tuple(reasons),
        policy_version=policy_version,
        authorization_reference=authorization_reference,
    )


__all__ = ["ValidationResult", "validate_request"]