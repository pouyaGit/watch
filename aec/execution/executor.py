"""ResearchExecutor (EPIC 6 Part 4: execution bridge).

A data-only boundary. submit_plan() verifies the gate decision and an
explicit authorization state, then mints an AUTHORIZED_OBSERVATION_REQUEST
— a plain mapping describing what may be observed, never an executed
request. ingest_result() validates caller-supplied observation results
against the request they answer. No network calls exist in this module
by construction (asserted by AST tests).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from aec.execution.models import (
    ExecutionOutcome, IngestionRefusal, SubmissionRefusal)

REFUSAL_CODES = ("EMPTY_PLAN", "EMPTY_STEPS", "BAD_TICK", "EMPTY_JOB")

RETRYABLE = frozenset({"TIMEOUT", "INGESTION_ERROR", "OBSERVATION_ERROR"})

_GATE_ALLOW = "ALLOW"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def _request_id(job_id: str, plan_id: str, tick: int) -> str:
    digest = hashlib.sha256(
        f"{job_id}|{plan_id}|{tick}".encode("utf-8")).hexdigest()
    return f"obsreq-{digest[:12]}"


def submit_plan(job_id: str, plan: Mapping[str, Any], gate: str,
                authz: Mapping[str, Any],
                capabilities: Sequence[str], tick: int) -> ExecutionOutcome:
    """Verify gate + authorization, then mint an observation request."""
    if not isinstance(job_id, str) or not job_id:
        raise SubmissionRefusal("EMPTY_JOB: job id required")
    if not isinstance(plan, Mapping):
        raise SubmissionRefusal("EMPTY_PLAN: plan must be a mapping")
    plan_id = plan.get("plan_id")
    steps = plan.get("steps")
    if not isinstance(plan_id, str) or not plan_id:
        raise SubmissionRefusal("EMPTY_PLAN: plan_id required")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)) \
            or not steps:
        raise SubmissionRefusal("EMPTY_STEPS: plan needs steps")
    if not isinstance(tick, int) or tick < 0:
        raise SubmissionRefusal("BAD_TICK: tick must be non-negative")
    if gate != _GATE_ALLOW:
        return ExecutionOutcome(
            disposition="BLOCKED",
            job_transition="BLOCKED",
            reason=f"GATE_NOT_ALLOWED: gate decision {gate!r}",
            request={},
        )
    status = authz.get("status") if isinstance(authz, Mapping) else None
    if status == "MISSING":
        return ExecutionOutcome(
            disposition="WAITING_AUTHORIZATION",
            job_transition="WAITING_AUTHORIZATION",
            reason="authorization absent",
            request={},
        )
    if status == "DENIED":
        return ExecutionOutcome(
            disposition="BLOCKED",
            job_transition="BLOCKED",
            reason="AUTHORIZATION_DENIED",
            request={},
        )
    expires = authz.get("expires_tick")
    if status == "EXPIRED" or (
            status == "GRANTED" and isinstance(expires, int)
            and tick > expires):
        return ExecutionOutcome(
            disposition="EXPIRED",
            job_transition="EXPIRED",
            reason="authorization expired",
            request={},
        )
    if status != "GRANTED":
        return ExecutionOutcome(
            disposition="BLOCKED",
            job_transition="BLOCKED",
            reason=f"unknown authorization status {status!r}",
            request={},
        )
    capability = "baseline-observe"
    if capability not in list(capabilities or ()):
        return ExecutionOutcome(
            disposition="BLOCKED",
            job_transition="BLOCKED",
            reason="observation capability unavailable",
            request={},
            requires_observation=True,
        )
    described = [
        {"step_id": str(step.get("step_id", f"s{i + 1}")),
         "endpoint": str(step.get("endpoint", "")),
         "purpose": str(step.get("purpose", ""))}
        for i, step in enumerate(steps)
        if isinstance(step, Mapping)
    ]
    request = {
        "request_id": _request_id(job_id, plan_id, tick),
        "job_id": job_id,
        "case_id": str(plan.get("case_id", "")),
        "plan_id": plan_id,
        "steps": described,
        "authorized_by": str(authz.get("scope", "observation")),
        "capability": capability,
        "tick": tick,
    }
    return ExecutionOutcome(
        disposition="OBSERVATION_REQUESTED",
        job_transition="OBSERVATION_RUNNING",
        reason="authorized observation request created",
        request=request,
    )


def ingest_result(request: Mapping[str, Any], result: Mapping[str, Any],
                  seen_observation_ids: set[str] | None = None,
                  ) -> ExecutionOutcome:
    """Validate an observation result against its request."""
    if not isinstance(request, Mapping) or not request.get("request_id"):
        raise IngestionRefusal("request missing request_id")
    if not isinstance(result, Mapping):
        raise IngestionRefusal("result must be a mapping")
    if result.get("request_id") != request.get("request_id"):
        raise IngestionRefusal("result answers a different request")
    observation_id = result.get("observation_id")
    observed = result.get("observed_fields")
    if not isinstance(observation_id, str) or not observation_id:
        raise IngestionRefusal("result missing observation_id")
    if not isinstance(observed, Sequence) \
            or isinstance(observed, (str, bytes)) or not observed:
        raise IngestionRefusal("result carries no observed fields")
    seen = seen_observation_ids if seen_observation_ids is not None else set()
    if observation_id in seen:
        return ExecutionOutcome(
            disposition="DUPLICATE_OBSERVATION",
            job_transition="",
            reason=f"observation {observation_id} already ingested",
            request=dict(request),
        )
    return ExecutionOutcome(
        disposition="EVIDENCE_PENDING",
        job_transition="EVIDENCE_PENDING",
        reason=f"observation {observation_id} accepted",
        request=dict(request),
    )


def classify_failure(kind: str) -> str:
    """Map a failure kind to RETRYABLE or TERMINAL."""
    return "RETRYABLE" if kind in RETRYABLE else "TERMINAL"


def is_timed_out(start_tick: int, now_tick: int, timeout_ticks: int) -> bool:
    """True when an observation exceeded its tick budget."""
    return (now_tick - start_tick) > timeout_ticks


__all__ = ["REFUSAL_CODES", "classify_failure", "ingest_result",
           "is_timed_out", "submit_plan"]
