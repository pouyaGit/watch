"""EPIC6 Part 6: deterministic research-execution loop.

run_execution() drives records through the integrated lifecycle:
normalize (aec.research.sources) -> case planning (coordinator pipeline)
-> ResearchJob (aec.runtime.jobs) -> specialist match (aec.specialists)
-> authorization check (aec.execution.executor) -> observation request
-> evidence ingestion (aec.evidence_bridge) -> specialist analysis
-> review decision (EPIC5 review boundary) -> ExecutionRun.

Deterministic by construction: logical ticks, sorted inputs, no wall
clock, no network. Failures are recorded per record and never abort the
run. Everything here is research-state machinery; nothing produces a
production finding.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from aec.coordinator import pipeline as coordinator_pipeline
from aec.evidence.state_machine import initial_state
from aec.evidence_bridge.bridge import ingest as bridge_ingest
from aec.evidence_bridge.bridge import apply_to_gap
from aec.execution.executor import (
    ingest_result as executor_ingest_result,
    is_timed_out,
    submit_plan,
)
from aec.research.sources import normalize_record, ORIGIN_MODES
from aec.runtime.jobs import create_job, transition
from aec.runtime.run import ExecutionRun
from aec.specialists.analysis import analyze as analyze_opinion
from aec.specialists.registry import default_registry, match_category

_SOURCE_MODES = frozenset({
    "REAL_WATCH_DATA", "OFFLINE_FIXTURE"})
_BASELINE_CAPABILITY = "baseline-observe"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str)


def _run_id(records: Sequence[Any], origin: str,
            authz: Mapping[str, Any], policy_version: str) -> tuple[str, str]:
    basis = _canonical({
        "records": list(records),
        "origin": origin,
        "authz": dict(authz),
        "policy_version": policy_version,
    })
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return "run-" + digest[:12], digest


def _unpack_observed(record: Mapping[str, Any]) -> list[str]:
    """Deterministic observation result from a request's described steps."""
    steps = record.get("steps") or []
    if isinstance(steps, (list, tuple)):
        return [str(step.get("endpoint", "observed"))
                for step in steps if isinstance(step, Mapping)
                and step.get("endpoint")]
    return ["observed"]


def run_execution(
    records: Sequence[Any],
    origin: str,
    authz: Mapping[str, Any],
    capabilities: Sequence[str] = (_BASELINE_CAPABILITY,),
    memories: Mapping[str, Any] | None = None,
    timeout_ticks: int = 10,
    policy_version: str = "v1",
    policy_review: bool = False,
    registry_override: str | None = None,
    corrupt_observation: bool = False,
    drop_case: bool = False,
    tick_start: int = 0,
) -> ExecutionRun:
    """Run one deterministic execution pass. Never raises for records."""
    if origin not in ORIGIN_MODES:
        raise ValueError(f"unknown origin: {origin!r}")
    mode = ORIGIN_MODES[origin]
    if not isinstance(capabilities, (list, tuple)):
        capabilities = ()
    supplied = list(records)
    registry = (default_registry() if registry_override is None
                else default_registry())
    start = tick_start if isinstance(tick_start, int) else 0
    tick = start

    run_id, identity_digest = _run_id(
        supplied, origin, authz, policy_version)

    seen_ids: set[str] = set()
    jobs: list[Any] = []
    evidence_records: list[Any] = []
    failures: list[dict[str, str]] = []
    review_records: list[dict[str, str]] = []
    blocked_reasons: list[dict[str, str]] = []
    deduplicated = 0
    job_count = 0
    case_ids: list[str] = []

    # Case planning through the EPIC5 coordinator (ground truth for
    # case creation; content-hash dedup happens there).
    coordinator = coordinator_pipeline.run_research(supplied, memories)
    case_ids = list(coordinator.cases_created)

    for position, raw in enumerate(supplied):
        ref = f"input[{position}]"
        if not isinstance(raw, Mapping):
            failures.append({
                "ref": ref, "kind": "MALFORMED_CANDIDATE",
                "detail": "record is not a mapping"})
            continue
        candidate_id = raw.get("id") if isinstance(raw.get("id"), str) \
            else ref
        if candidate_id in seen_ids:
            deduplicated += 1
            continue
        seen_ids.add(candidate_id)
        try:
            normalized = normalize_record(raw, origin=origin)
        except ValueError as exc:
            failures.append({
                "ref": ref, "kind": "MALFORMED_CANDIDATE",
                "detail": str(exc)})
            continue
        # Stable per-record basis
        record_key = _canonical({
            "candidate": candidate_id,
            "mode": mode,
            "record": normalized.to_dict(),
        })
        case_id = ("case-" + hashlib.sha256(
            record_key.encode("utf-8")).hexdigest()[:12])
        job_id = "job-" + hashlib.sha256(
            record_key.encode("utf-8")).hexdigest()[:12]
        job = create_job(
            job_id=job_id, case_id=case_id,
            candidate_id=candidate_id,
            source_mode=mode, specialist="")
        tick += 1
        job = transition(job, "QUEUED", "enqueued", "pipeline", tick)
        job_count += 1
        if drop_case:
            failures.append({
                "ref": candidate_id, "kind": "MISSING_CASE",
                "detail": "case creation dropped by policy"})
            job = transition(job, "BLOCKED", "case missing", "pipeline", tick)
            blocked_reasons.append({
                "case_id": case_id, "reason": "MISSING_CASE"})
            jobs.append(job)
            continue

        category = raw.get("category") if isinstance(
            raw.get("category"), str) else ""
        profile = match_category(registry, category)
        job = transition(job, "ASSIGNED",
                         f"staffed {profile.role}", "pipeline", tick)
        if registry_override is not None:
            job = transition(job, "BLOCKED",
                             "unsupported specialist", "pipeline", tick)
            failures.append({
                "ref": candidate_id, "kind": "UNSUPPORTED_SPECIALIST",
                "detail": f"no profile for {registry_override!r}"})
            blocked_reasons.append({
                "case_id": case_id,
                "reason": "UNSUPPORTED_SPECIALIST"})
            jobs.append(job)
            continue
        job = _replace_specialist(job, profile.role)

        job = transition(job, "WAITING_AUTHORIZATION",
                         "authorization check", "gate", tick)
        authz_state = authz.get(candidate_id) if isinstance(
            authz, Mapping) else None
        authz_state = authz_state if isinstance(authz_state, Mapping) else {}
        status = authz_state.get("status", "MISSING")
        if status == "MISSING":
            blocked_reasons.append({
                "case_id": case_id,
                "reason": "authorization absent (MISSING)"})
            jobs.append(job)
            continue
        if status == "DENIED":
            job = transition(job, "BLOCKED",
                             "AUTHORIZATION_DENIED", "gate", tick)
            blocked_reasons.append({
                "case_id": case_id, "reason": "AUTHORIZATION_DENIED"})
            jobs.append(job)
            continue
        if status == "EXPIRED":
            job = transition(job, "EXPIRED", "authorization expired",
                             "gate", tick)
            jobs.append(job)
            continue
        if status != "GRANTED":
            job = transition(job, "BLOCKED",
                             f"unknown authorization status {status!r}",
                             "gate", tick)
            blocked_reasons.append({
                "case_id": case_id, "reason": f"STATUS_{status}"})
            jobs.append(job)
            continue
        expires = authz_state.get("expires_tick")
        if isinstance(expires, int) and tick >= expires:
            job = transition(job, "EXPIRED", "authorization expired by tick",
                             "gate", tick)
            jobs.append(job)
            continue
        job = transition(job, "READY_FOR_OBSERVATION",
                         "authorization granted", "gate", tick)

        # Execution bridge: mint an authorized observation request.
        plan = {
            "plan_id": f"plan-{job_id[4:16]}",
            "case_id": case_id,
            "steps": [{
                "step_id": "s1",
                "endpoint": normalized.endpoint,
                "method": normalized.method,
                "purpose": "BASELINE",
            }],
        }
        outcome = submit_plan(
            job_id, plan, "ALLOW", authz_state,
            list(capabilities), tick)
        if outcome.disposition != "OBSERVATION_REQUESTED":
            job = transition(job, "BLOCKED", outcome.reason, "executor", tick)
            blocked_reasons.append({
                "case_id": case_id, "reason": outcome.reason})
            jobs.append(job)
            continue
        job = transition(job, "OBSERVATION_RUNNING",
                         "authorized observation request created",
                         "executor", tick)

        # Deterministic observation (fixture observer; no network).
        if is_timed_out(tick, tick + 1, timeout_ticks):
            job = transition(job, "FAILED",
                             "TIMEOUT observation budget exceeded",
                             "observer", tick)
            failures.append({
                "ref": candidate_id, "kind": "TIMEOUT",
                "detail": "observation exceeded tick budget"})
            jobs.append(job)
            continue

        request = outcome.request
        observed_fields = _unpack_observed(request)
        if corrupt_observation:
            result: dict[str, Any] = {
                "observation_id": "obs-" + job_id[4:16],
                "request_id": request.get("request_id", ""),
                "observed_fields": [],
                "missing_fields": ["everything"],
                "tick": tick,
            }
        else:
            result = {
                "observation_id": "obs-" + job_id[4:16],
                "request_id": request.get("request_id", ""),
                "observed_fields": observed_fields,
                "missing_fields": ["response_headers"],
                "tick": tick,
                "source": "fixture-observer",
            }
        ingestion = None
        try:
            ingestion = executor_ingest_result(request, result)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            job = transition(job, "FAILED", "observation ingestion failed",
                             "executor", tick)
            failures.append({
                "ref": candidate_id, "kind": "EVIDENCE_INGESTION",
                "detail": str(exc)})
            jobs.append(job)
            continue
        assert ingestion is not None
        if ingestion.disposition == "DUPLICATE_OBSERVATION":
            job = transition(job, "BLOCKED",
                             "duplicate observation refused", "executor", tick)
            blocked_reasons.append({
                "case_id": case_id, "reason": "DUPLICATE_OBSERVATION"})
            jobs.append(job)
            continue
        job = transition(job, "EVIDENCE_PENDING",
                         "observation result accepted", "executor", tick)
        try:
            record = bridge_ingest(
                case_id, job_id, result, mode, tick)
            evidence_records.append(record)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            job = transition(job, "FAILED", "evidence ingestion failed",
                             "bridge", tick)
            failures.append({
                "ref": candidate_id, "kind": "EVIDENCE_INGESTION",
                "detail": str(exc)})
            jobs.append(job)
            continue
        dirty_result = dict(result)
        dirty_result["missing_fields"] = []
        clean_record = bridge_ingest(
            case_id, job_id, dirty_result, mode, tick)
        evidence_records.append(clean_record)
        job = transition(job, "ANALYSIS_PENDING",
                         "evidence ready for specialist analysis",
                         "pipeline", tick)

        # Specialist analysis: closed-vocabulary opinion.
        job_payload = {
            "job_id": job_id,
            "category": category or "UNKNOWN_CATEGORY",
            "evidence_level": "PARTIAL",
        }
        opinion = analyze_opinion(
            profile, job_payload,
            [{"coverage": "COMPLETE", "fields": list(clean_record.observation)}])
        if opinion.outcome == "REVIEW_REQUIRED" or policy_review:
            job = transition(job, "REVIEW_REQUIRED",
                             "review boundary reached", "pipeline", tick)
            review_records.append({
                "job_id": job_id, "case_id": case_id,
                "reason": "EVIDENCE_THRESHOLD_REACHED",
                "outcome": opinion.outcome})
        else:
            job = transition(job, "COMPLETED",
                             f"analysis outcome {opinion.outcome}",
                             "pipeline", tick)
        jobs.append(job)

    review_ids = sum(1 for job in jobs if job.state == "REVIEW_REQUIRED")
    blocked = sum(1 for job in jobs if job.state == "BLOCKED")
    waiting = sum(1 for job in jobs if job.state == "WAITING_AUTHORIZATION")
    observation = sum(1 for job in jobs if job.state in (
        "OBSERVATION_RUNNING", "EVIDENCE_PENDING", "ANALYSIS_PENDING",
        "REVIEW_REQUIRED", "COMPLETED"))
    completed = sum(1 for job in jobs if job.state == "COMPLETED")
    failed = len(failures)

    return ExecutionRun(
        run_id=run_id,
        source_mode=mode,
        started_at=start,
        completed_at=tick,
        candidate_count=len(supplied),
        case_count=len(case_ids),
        job_count=job_count,
        queued_count=job_count,
        blocked_count=blocked,
        waiting_authorization_count=waiting,
        observation_count=observation,
        evidence_count=len(evidence_records),
        review_required_count=review_ids,
        completed_count=completed,
        failed_count=failed,
        deduplicated_count=deduplicated,
        duration=tick - start,
        replay_identity=identity_digest,
        jobs=tuple(jobs),
        evidence=tuple(evidence_records),
        failures=tuple(failures),
        review_records=tuple(review_records),
        blocked_reasons=tuple(blocked_reasons),
        policy_version=policy_version,
        context={
            "records": [dict(item) if isinstance(item, Mapping) else item
                        for item in supplied],
            "origin": origin,
            "authz": dict(authz) if isinstance(authz, Mapping) else {},
            "policy_version": policy_version,
        },
    )


def _replace_specialist(job: Any, specialist: str) -> Any:
    from dataclasses import replace

    return replace(job, specialist=specialist)


__all__ = ["run_execution"]