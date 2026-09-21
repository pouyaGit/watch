"""EPIC7 Part 10+11+17: ObservationRuntime — dry-run and live execution.

execute() is the whole runtime in one fail-closed pass:

- mode must be DRY_RUN or LIVE_OBSERVATION (no other modes exist).
- OFFline_FIXTURE never executes, in any mode.
- DRY_RUN performs every validation and policy check, produces an
  execution plan, and stops — the transport is never invoked.
- LIVE_OBSERVATION reaches the transport only when authorization is
  valid, target is in scope, observation type is allowed, the request
  has not already executed, and policy validation passes. There is no
  fallback from refusal to execution.
- The transport is injected (tests) or the lazy sanctioned default; a
  missing transport refuses rather than defaulting open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from aec.runtime.adapters.http_observation import (
    ObservationResult, observe)
from aec.runtime.adapters.target import ResolvedTarget
from aec.runtime.execution.failures import failure_state
from aec.runtime.execution.idempotency import (
    IdempotencyGuard, execution_key)
from aec.runtime.execution.states import (
    ObservationState, create_observation_state)
from aec.runtime.execution.validation import validate_request
from aec.runtime.policy.limits import default_limits
from aec.runtime.policy.models import default_policy
from aec.runtime.results.audit import AuditTrail
from aec.runtime.results.evidence import build_evidence

RUNTIME_MODES = ("DRY_RUN", "LIVE_OBSERVATION")
SOURCE_MODES = frozenset({"REAL_WATCH_DATA", "OFFLINE_FIXTURE"})


def is_supported_mode(mode: str) -> bool:
    return isinstance(mode, str) and mode in RUNTIME_MODES


def live_requires_real_source(source_mode: str) -> bool:
    """LIVE_OBSERVATION is only meaningful for real watch data."""
    return source_mode == "REAL_WATCH_DATA"


@dataclass(frozen=True)
class ObservationExecution:
    decision: str
    reasons: tuple[str, ...]
    state: str
    dry_run: bool
    executed: bool
    policy_version: str
    authorization_reference: str
    target_id: str
    plan: dict[str, Any] | None = None
    evidence: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "state": self.state,
            "dry_run": self.dry_run,
            "executed": self.executed,
            "policy_version": self.policy_version,
            "authorization_reference": self.authorization_reference,
            "target_id": self.target_id,
            "plan": self.plan,
            "evidence": self.evidence.to_dict()
            if self.evidence is not None else None,
        }


def build_plan(
    request: Mapping[str, Any],
    authorization: Mapping[str, Any] | None,
    target: ResolvedTarget | None,
    *,
    mode: str,
    policy_version: str,
    decision: str,
    reasons: tuple[str, ...],
) -> dict[str, Any]:
    """The DRY_RUN execution plan: what would happen and why."""
    limits = default_limits()
    return {
        "mode": mode,
        "dry_run": mode == "DRY_RUN",
        "authorization_result": decision,
        "target_validation": "PASS" if target is not None and
        decision == "AUTHORIZED" else "N/A",
        "observation_type": str(request.get("observation_type", "")),
        "limits": limits.to_dict(),
        "expected_evidence": [str(request.get("observation_type", ""))],
        "refusal_reason": reasons[0] if reasons else "",
        "policy_version": policy_version,
    }


def execute(
    request: Mapping[str, Any],
    authorization: Mapping[str, Any] | None,
    target: ResolvedTarget | None,
    *,
    mode: str,
    source_mode: str,
    policy_version: str = "v1",
    transport: Callable[..., Mapping[str, Any]] | None = ...,
    scope_hosts: frozenset[str] = frozenset(),
    guard: IdempotencyGuard | None = None,
    audit: AuditTrail | None = None,
    tick: int = 0,
) -> ObservationExecution:
    """Run one observation through all gates. Never raises for the
    request; every refusal is an explicit decision."""
    if not is_supported_mode(mode):
        return _refusal("REFUSED", ("UNSUPPORTED_MODE",), "REFUSED",
                        request, policy_version, mode=mode,
                        target_id=_tid(target))
    dry_run = mode == "DRY_RUN"
    guard = guard if guard is not None else IdempotencyGuard()
    audit = audit if audit is not None else AuditTrail()

    # Fixture isolation comes first: a fixture never executes, ever.
    if source_mode == "OFFLINE_FIXTURE" and not dry_run:
        return _refusal(
            "REFUSED", ("FIXTURE_CANNOT_EXECUTE",), "REFUSED",
            request, policy_version, mode=mode, target_id=_tid(target),
            audit=audit)

    policy = default_policy()
    resolved = validate_request(
        request, authorization, policy, tick,
        executed_request_ids=guard.executed_keys(),
        target=target.to_dict() if target is not None else None,
        scope_hosts=scope_hosts,
    )

    if resolved.decision != "AUTHORIZED":
        return _refusal(
            resolved.decision, resolved.reasons,
            resolved.decision, request, policy_version, mode=mode,
            target_id=_tid(target), audit=audit)

    if dry_run:
        plan = build_plan(
            request, authorization, target, mode=mode,
            policy_version=policy_version,
            decision="AUTHORIZED", reasons=())
        _audit(audit, request, "AUTHORIZED", "AUTHORIZED", tick,
               target_id=_tid(target))
        return ObservationExecution(
            decision="AUTHORIZED", reasons=(), state="AUTHORIZED",
            dry_run=True, executed=False,
            policy_version=policy_version,
            authorization_reference=str(
                request.get("authorization_reference", "")),
            target_id=_tid(target), plan=plan)

    # LIVE_OBSERVATION: every gate must pass; nothing defaults open.
    if guard.is_duplicate(request):
        return _refusal(
            "BLOCKED", ("DUPLICATE_REQUEST",), "BLOCKED",
            request, policy_version, mode=mode, target_id=_tid(target),
            audit=audit, tick=tick)
    if transport is ... or transport is None:
        return _refusal(
            "REFUSED", ("TRANSPORT_NOT_AVAILABLE",), "REFUSED",
            request, policy_version, mode=mode, target_id=_tid(target),
            audit=audit, tick=tick)
    if target is None:
        return _refusal(
            "REFUSED", ("TARGET_MISSING",), "REFUSED",
            request, policy_version, mode=mode, target_id=_tid(target),
            audit=audit, tick=tick)

    state = create_observation_state(
        request_id=str(request.get("request_id", "")),
        research_job_id=str(request.get("research_job_id", "")),
        case_id=str(request.get("case_id", "")),
        policy_version=policy_version,
        authorization_reference=str(
            request.get("authorization_reference", "")),
    )
    state = state.transition("VALIDATING", "validation passed", "runtime",
                             tick)
    state = state.transition("AUTHORIZED", "authorized", "runtime", tick)
    state = state.transition("DISPATCHED", "dispatched", "runtime", tick)
    state = state.transition("OBSERVING", "observing", "runtime", tick)

    try:
        result = observe(target, request, policy.limits,
                         transport=transport)
    except Exception as exc:  # noqa: BLE001 - mapped, never raised
        kind = getattr(exc, "kind", "OBSERVATION_ERROR")
        terminal = failure_state(kind)
        _audit(audit, request, terminal, terminal, tick,
               reason=str(exc)[:200], target_id=_tid(target))
        return _refusal(
            terminal, (kind,), terminal, request, policy_version,
            mode=mode, target_id=_tid(target), audit=audit, tick=tick)

    state = state.transition("COLLECTING", "collected", "runtime", tick)
    state = state.transition("COMPLETED", "completed", "runtime", tick)
    guard.record(request)
    evidence = build_evidence(
        request=request,
        tick=tick,
        status=result.status,
        selected_headers=result.selected_headers,
        content_metadata={"content_type": result.content_type,
                          "body_digest": result.body_digest},
        response_size=result.content_length,
        timing_ms=result.timing_ms,
        target_id=result.target_id,
        authorization_reference=result.authorization_reference,
        policy_version=result.policy_version,
        mode="LIVE_OBSERVATION",
        scope_validation=result.scope_validation,
    )
    _audit(audit, request, "COMPLETED", "COMPLETED", tick,
           evidence_reference=evidence.evidence_id,
           target_id=_tid(target))
    return ObservationExecution(
        decision="AUTHORIZED", reasons=(), state="COMPLETED",
        dry_run=False, executed=True,
        policy_version=policy_version,
        authorization_reference=str(
            request.get("authorization_reference", "")),
        target_id=_tid(target), evidence=evidence)


def _tid(target: ResolvedTarget | None) -> str:
    return target.target_id if target is not None else ""


def _refusal(decision: str, reasons: tuple[str, ...], state: str,
             request: Mapping[str, Any], policy_version: str, *,
             mode: str, target_id: str, audit: AuditTrail | None = None,
             tick: int = 0) -> ObservationExecution:
    if audit is not None:
        _audit(audit, request, decision, state, tick,
               reason=reasons[0] if reasons else "", target_id=target_id)
    return ObservationExecution(
        decision=decision, reasons=reasons, state=state,
        dry_run=mode == "DRY_RUN", executed=False,
        policy_version=policy_version,
        authorization_reference=str(
            request.get("authorization_reference", "")),
        target_id=target_id,
        plan=build_plan(request, None, None, mode=mode,
                        policy_version=policy_version,
                        decision=decision, reasons=reasons)
        if mode == "DRY_RUN" else None,
    )


def _audit(audit: AuditTrail, request: Mapping[str, Any],
           decision: str, state: str, tick: int,
           reason: str = "", evidence_reference: str = "",
           target_id: str = "") -> None:
    audit.append({
        "request_id": str(request.get("request_id", "")),
        "research_job_id": str(request.get("research_job_id", "")),
        "case_id": str(request.get("case_id", "")),
        "target_id": target_id,
        "authorization_reference": str(
            request.get("authorization_reference", "")),
        "policy_version": str(request.get("policy_version", "")),
        "decision": decision,
        "execution_state": state,
        "reason": reason,
        "evidence_reference": evidence_reference,
    })


__all__ = ["ObservationExecution", "RUNTIME_MODES", "SOURCE_MODES",
           "build_plan", "execute", "is_supported_mode",
           "live_requires_real_source"]