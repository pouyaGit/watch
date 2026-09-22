"""Authorization bridge (Phase 8): Hunt Plan -> Authorization Request ->
Authorization Gate -> (executor) Observation Runtime.

The gate wraps the EXISTING fail-closed boundary — it never replaces it:

  1. plan.scope_ref must equal the job's authorization_ref (the
     authoritative ``watch:scope:`` reference);
  2. ``AuthorizationChecker.verify(job)`` (runtime scope boundary) must
     pass — the same check executed before every observation;
  3. every requested observation type must be in the registry AND in the
     capability's allowlist.

Fail closed: any exception or mismatch => DENIED. A denied plan becomes
BLOCKED (or REJECTED for registry violations), an audit event is
recorded by the caller, and no observation executes. Authorization
records are re-verified before EVERY observation (stale rejection).
"""

from __future__ import annotations

from typing import Any, Iterable

from backend.research_agents.hunt.models import (
    AuthorizationRecord,
    HuntPlan,
    new_id,
)
from backend.research_agents.hunt.registry import REGISTRY
from backend.research_agents.hunt.store import utcnow

GATE_NAME = "authorization_checker+observation_registry+capability_allowlist"


def _bounded(value: object, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def build_authorization_request(
    plan: HuntPlan,
    *,
    job: Any,
    capability: Any,
) -> dict[str, Any]:
    """Deterministic authorization request derived from the plan."""
    return {
        "authorization_id": new_id("authz"),
        "plan_id": plan.plan_id,
        "objective_id": plan.objective_id,
        "job_id": plan.job_id,
        "scope_ref": plan.scope_ref,
        "target": _bounded(
            f"{getattr(job, 'program', '')}/"
            f"{getattr(job, 'subdomain', '')}", 160),
        "observation_types": list(plan.observation_types),
        "capability": str(getattr(capability, "category", "") or ""),
        "specialist": str(getattr(capability, "agent_name", "") or ""),
        "purpose": "authorized_read_only_observation_for_research",
        "allowed_data": sorted({
            o for t in plan.observation_types
            for o in (REGISTRY[t].outputs if t in REGISTRY else ())}),
        "safety_class": "READ_ONLY",
        "requested_at": utcnow(),
    }


def authorization_gate(
    request: dict[str, Any],
    *,
    job: Any,
    capability: Any,
    auth_checker: Any,
    stale_check: bool = False,
) -> AuthorizationRecord:
    """Fail-closed gate evaluation. Never raises for expected denials —
    returns a DENIED record with explicit reasons. Unexpected internal
    errors also DENY (fail closed)."""
    reasons: list[str] = []
    now = utcnow()

    def denied(*why: str) -> AuthorizationRecord:
        return AuthorizationRecord(
            auth_id=str(request.get("authorization_id")
                        or new_id("authz")),
            plan_id=str(request.get("plan_id") or ""),
            objective_id=str(request.get("objective_id") or ""),
            job_id=str(request.get("job_id") or ""),
            scope_ref=str(request.get("scope_ref") or ""),
            target=str(request.get("target") or ""),
            observation_types=tuple(
                request.get("observation_types") or ()),
            capability=str(request.get("capability") or ""),
            specialist=str(request.get("specialist") or ""),
            purpose=str(request.get("purpose") or ""),
            allowed_data=tuple(request.get("allowed_data") or ()),
            safety_class="READ_ONLY",
            status="DENIED",
            reasons=tuple(why) or ("authorization_failed",),
            gate=GATE_NAME,
            requested_at=str(request.get("requested_at") or now),
            decided_at=now,
        )

    # 1. scope reference identity (planner cannot choose its own scope)
    job_scope = str(getattr(job, "authorization_ref", "") or "")
    if not job_scope:
        return denied("job_missing_authorization_ref")
    if str(request.get("scope_ref") or "") != job_scope:
        return denied("plan_scope_does_not_match_job_authorization")

    # 2. existing runtime authorization boundary (fail-closed itself)
    try:
        auth_checker.verify(job)
    except Exception as exc:  # noqa: BLE001 - denial is the expected path
        return denied(f"authorization_checker:"
                      f"{_bounded(str(exc) or exc.__class__.__name__, 80)}")

    # 3. observation types: registry ∩ capability allowlist
    allowed = {str(t) for t in
               (getattr(capability, "allowed_observation_types", ()) or ())}
    for otype in (request.get("observation_types") or ()):
        if otype not in REGISTRY:
            return denied(f"unknown_observation_type:{otype}")
        if otype not in allowed:
            return denied(f"type_not_allowed_for_capability:{otype}")
        if REGISTRY[otype].executes_http:
            return denied(f"type_requires_http_execution:{otype}")

    # 4. request must match its plan exactly (tamper guard)
    #    (types compared as ordered tuple)
    if not (request.get("observation_types") or []):
        return denied("request_has_no_observation_types")

    if reasons:
        return denied(*reasons)

    return AuthorizationRecord(
        auth_id=str(request.get("authorization_id") or new_id("authz")),
        plan_id=str(request.get("plan_id") or ""),
        objective_id=str(request.get("objective_id") or ""),
        job_id=str(request.get("job_id") or ""),
        scope_ref=str(request.get("scope_ref") or ""),
        target=str(request.get("target") or ""),
        observation_types=tuple(request.get("observation_types") or ()),
        capability=str(request.get("capability") or ""),
        specialist=str(request.get("specialist") or ""),
        purpose=str(request.get("purpose") or ""),
        allowed_data=tuple(request.get("allowed_data") or ()),
        safety_class="READ_ONLY",
        status="GRANTED",
        reasons=(),
        gate=GATE_NAME,
        requested_at=str(request.get("requested_at") or now),
        decided_at=now,
    )


def reverify_before_observation(
    record: AuthorizationRecord | None,
    *,
    plan: HuntPlan,
    job: Any,
    capability: Any,
    auth_checker: Any,
    observation_types: Iterable[str],
) -> tuple[bool, str]:
    """Stale-authorization guard executed before EVERY observation.

    Re-runs the full gate against the stored record plus record-integrity
    checks. Returns ``(allowed, reason)``; ``allowed`` is False for a
    missing/changed/denied/expired authorization (fail closed).
    """
    if record is None:
        return False, "authorization_absent"
    if record.status != "GRANTED":
        return False, f"authorization_not_granted:{record.status}"
    if record.plan_id != plan.plan_id:
        return False, "authorization_plan_mismatch"
    if record.scope_ref != str(getattr(job, "authorization_ref", "") or ""):
        return False, "authorization_scope_changed"
    want = tuple(observation_types)
    if want and tuple(record.observation_types) != want \
            and not set(want) <= set(record.observation_types):
        return False, "authorization_types_mismatch"
    request = {
        "authorization_id": record.auth_id,
        "plan_id": record.plan_id,
        "objective_id": record.objective_id,
        "job_id": record.job_id,
        "scope_ref": record.scope_ref,
        "target": record.target,
        "observation_types": list(record.observation_types),
        "capability": record.capability,
        "specialist": record.specialist,
        "purpose": record.purpose,
        "allowed_data": list(record.allowed_data),
        "safety_class": record.safety_class,
        "requested_at": record.requested_at,
    }
    fresh = authorization_gate(request, job=job, capability=capability,
                               auth_checker=auth_checker, stale_check=True)
    if fresh.status != "GRANTED":
        reason = fresh.reasons[0] if fresh.reasons else "reverification"
        return False, f"stale_authorization:{reason}"
    return True, "granted"


__all__ = [
    "GATE_NAME",
    "authorization_gate",
    "build_authorization_request",
    "reverify_before_observation",
]
