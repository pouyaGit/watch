"""EPIC13 §16 — the acquisition run: plan, execute, re-evaluate.

This is the flow the Epic asks for, assembled from parts that already exist:

    candidate
      → chain identifies the missing evidence        (EPIC12 engine)
      → planner selects the acquisition action       (acquisition.plan)
      → authorization check                          (acquisition.executor)
      → budget check                                 (EPIC12 budget)
      → marker generated                             (acquisition.markers)
      → request constructed                          (acquisition.requests)
      → request executed                             (injected transport)
      → response captured, bounded, scope-checked    (acquisition.executor)
      → reflection detector                          (acquisition.detector)
      → observation persisted                        (EPIC12 observations)
      → EPIC11 evidence classification               (finding.integrity)
      → chain re-evaluated                           (EPIC12 engine)

Nothing here decides a verdict: the re-evaluation is the EPIC12 engine, which
is the EPIC11 gate over the rows.  This module only *acquires* and *reports*.

If the transport is unavailable, the run terminates as
``TRANSPORT_UNAVAILABLE`` with every planned action listed as blocked and no
observation produced — the honest outcome, and the one this runtime actually
produces today because the platform's live execution gate is closed.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from backend.research_agents.verification import engine as en

from . import capabilities as cap
from . import detector as dt
from . import executor as ex
from . import limits as lm
from . import plan as pl
from . import requests as rq
from . import transport as tr

SERVICE_RULE_VERSION = "epic13-acquisition-service-1"

#: how one acquisition run ended.
RUN_NO_REQUIREMENT = "NO_REQUIREMENT"
RUN_TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
RUN_UNAUTHORIZED = "UNAUTHORIZED"
RUN_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
RUN_REFLECTION_OBSERVED = "REFLECTION_OBSERVED"
RUN_REFLECTION_NOT_OBSERVED = "REFLECTION_NOT_OBSERVED"
RUN_INCONCLUSIVE = "INCONCLUSIVE"
RUN_MAX_ACTIONS_REACHED = "MAX_ACTIONS_REACHED"
RUN_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"

RUN_TERMINATIONS: tuple[str, ...] = (
    RUN_NO_REQUIREMENT, RUN_TRANSPORT_UNAVAILABLE, RUN_UNAUTHORIZED,
    RUN_BUDGET_EXHAUSTED, RUN_REFLECTION_OBSERVED,
    RUN_REFLECTION_NOT_OBSERVED, RUN_INCONCLUSIVE, RUN_MAX_ACTIONS_REACHED,
    RUN_CAPABILITY_UNAVAILABLE,
)


@dataclass
class AcquisitionRun:
    """Everything one acquisition run did, and everything it did not do."""

    candidate_id: str = ""
    objective_id: str = ""
    scope_ref: str = ""
    chain_id: str = ""
    vulnerability_class: str = ""
    termination: str = RUN_NO_REQUIREMENT
    reason: str = ""
    plan: dict[str, Any] = field(default_factory=dict)
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    evidence_rows: list[dict[str, Any]] = field(default_factory=list)
    produced_rows: list[dict[str, Any]] = field(default_factory=list)
    blocked: list[dict[str, Any]] = field(default_factory=list)
    unavailable: list[dict[str, Any]] = field(default_factory=list)
    chain_before: dict[str, Any] = field(default_factory=dict)
    chain_after: dict[str, Any] = field(default_factory=dict)
    verdict_before: str = ""
    verdict_after: str = ""
    verdict_reason_after: str = ""
    requests_sent: int = 0
    transport: dict[str, Any] = field(default_factory=dict)
    capability: dict[str, Any] = field(default_factory=dict)
    replay: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, int] = field(default_factory=dict)
    rule_version: str = SERVICE_RULE_VERSION

    @property
    def acquired(self) -> bool:
        """True when the run produced evidence (positive or negative)."""
        return self.termination in (RUN_REFLECTION_OBSERVED,
                                    RUN_REFLECTION_NOT_OBSERVED)

    @property
    def advanced(self) -> bool:
        """True when the chain state changed at all."""
        return self.chain_before != self.chain_after

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "objective_id": self.objective_id, "scope_ref": self.scope_ref,
            "chain_id": self.chain_id,
            "vulnerability_class": self.vulnerability_class,
            "termination": self.termination, "reason": self.reason,
            "plan": dict(self.plan), "outcomes": list(self.outcomes),
            "observations": list(self.observations),
            "evidence_rows": list(self.evidence_rows),
            "produced_rows": list(self.produced_rows),
            "blocked": list(self.blocked), "unavailable": list(self.unavailable),
            "chain_before": dict(self.chain_before),
            "chain_after": dict(self.chain_after),
            "verdict_before": self.verdict_before,
            "verdict_after": self.verdict_after,
            "verdict_reason_after": self.verdict_reason_after,
            "requests_sent": self.requests_sent,
            "transport": dict(self.transport),
            "capability": dict(self.capability), "replay": dict(self.replay),
            "limits": dict(self.limits), "rule_version": self.rule_version,
            "acquired": self.acquired, "advanced": self.advanced,
        }


def _authorization_ids(authorization: Any) -> tuple[str, ...]:
    """The authorization references an authorization object carries."""
    if authorization is None:
        return ()
    if isinstance(authorization, Mapping):
        raw = authorization.get("authorization_ids") or ()
        single = authorization.get("authorization_id") or ""
    else:
        raw = getattr(authorization, "authorization_ids", ()) or ()
        single = getattr(authorization, "authorization_id", "") or ""
    ids = [str(a) for a in list(raw) if str(a or "").strip()]
    if str(single or "").strip():
        ids.append(str(single))
    return tuple(dict.fromkeys(ids))


def _chain_field(chain_state: Any, name: str, default: Any = None) -> Any:
    if isinstance(chain_state, Mapping):
        return chain_state.get(name, default)
    return getattr(chain_state, name, default)


def run_acquisition_for_candidate(
        *, chain_state: Any, parameters: Sequence[Mapping[str, Any]] = (),
        rows: Iterable[Mapping[str, Any]] = (), transport: Any = None,
        authorization: Any = None, budget: Any = None,
        limits: Mapping[str, Any] | None = None, replay: Any = None,
        now_fn: Callable[[], float] = time.monotonic, candidate_id: str = "",
        objective_id: str = "", scope_ref: str = "",
        vulnerability_class: str = "", job_id: str = "",
        store: Any = None) -> AcquisitionRun:
    """Plan and execute acquisition for one candidate, then re-evaluate.

    The chain state carries the chain view only; the caller supplies the
    identity (candidate, objective, scope, class) it already holds, exactly as
    the EPIC12 loop does.
    """
    bounds = lm.limits_for(limits)
    run = AcquisitionRun(
        candidate_id=str(candidate_id or _chain_field(chain_state,
                                                      "candidate_id", "") or ""),
        objective_id=str(objective_id or _chain_field(chain_state,
                                                      "objective_id", "") or ""),
        scope_ref=str(scope_ref or _chain_field(chain_state, "scope_ref", "")
                      or ""),
        chain_id=str(_chain_field(chain_state, "chain_id", "") or ""),
        vulnerability_class=str(vulnerability_class or _chain_field(
            chain_state, "vulnerability_class", "") or ""),
        limits=bounds)
    run.chain_before = (chain_state.to_dict()
                        if hasattr(chain_state, "to_dict")
                        else dict(chain_state or {}))
    run.verdict_before = str(_chain_field(chain_state, "verdict", "") or "")
    run.capability = (cap.contract_for(run.vulnerability_class).to_dict()
                      if cap.contract_for(run.vulnerability_class) else {})

    planned = pl.plan_acquisition(
        chain_state=chain_state, parameters=parameters,
        authorization=authorization, limits=bounds, job_id=job_id,
        candidate_id=run.candidate_id, objective_id=run.objective_id,
        scope_ref=run.scope_ref, chain_id=run.chain_id)
    run.plan = planned.to_dict()
    run.blocked = list(planned.blocked)
    run.unavailable = list(planned.unavailable)

    resolved = tr.transport_for(transport)
    run.transport = {
        "name": str(getattr(resolved, "name", "") or ""),
        "available": bool(getattr(resolved, "available", False)),
        "status": (resolved.status() if hasattr(resolved, "status")
                   else {"available": bool(getattr(resolved, "available",
                                                    False))}),
    }

    if not planned.actions:
        if not list(parameters or []):
            run.termination = RUN_NO_REQUIREMENT
            run.reason = ("no observed parameter was supplied for this "
                          "candidate, so there is nothing acquisition could "
                          "exercise")
            return _persist_run(_re_evaluate(run, chain_state, rows,
                                              authorization), store)
        blocked_reasons = {str(b.get("blocked_reason") or "")
                           for b in planned.blocked}
        if "authorization_unavailable" in blocked_reasons:
            run.termination = RUN_UNAUTHORIZED
            run.reason = ("no authorization reference covers this target, so "
                          "no acquisition action could be planned")
            run.blocked = list(planned.blocked)
            return _persist_run(_re_evaluate(run, chain_state, rows,
                                              authorization), store)
        if run.unavailable:
            run.termination = RUN_CAPABILITY_UNAVAILABLE
            run.reason = ("the missing evidence cannot be acquired in this "
                          "runtime: " + "; ".join(
                              str(u.get("reason") or "")
                              for u in run.unavailable[:3]))
        else:
            run.termination = RUN_NO_REQUIREMENT
            run.reason = ("the chain reports no missing evidence that "
                          "acquisition could produce")
        return _persist_run(_re_evaluate(run, chain_state, rows,
                                          authorization), store)

    if not run.transport["available"]:
        run.termination = RUN_TRANSPORT_UNAVAILABLE
        run.reason = ("no authorized transport is available, so none of the "
                      f"{len(planned.actions)} planned acquisition(s) was "
                      "sent and no evidence was produced")
        for action in planned.actions:
            run.blocked.append({
                "action_id": str(getattr(action, "action_id", "") or ""),
                "action_type": str(getattr(action, "action_type", "") or ""),
                "parameter": str((getattr(action, "inputs", {}) or {})
                                 .get("parameter") or ""),
                "blocked_reason": ex.RESULT_TRANSPORT_UNAVAILABLE,
                "reason": run.reason})
        return _persist_run(_re_evaluate(run, chain_state, rows,
                                          authorization), store)

    evidence_rows = list(rows or [])
    for action in planned.actions:
        if budget is not None:
            try:
                budget.ensure("max_actions", 1,
                              reason=f"acquisition:{action.action_id}")
            except Exception as exc:  # noqa: BLE001
                run.termination = RUN_BUDGET_EXHAUSTED
                run.reason = f"the action budget refused the run: {exc}"
                break
        inputs = dict(getattr(action, "inputs", {}) or {})
        parameter_ref = rq.ParameterRef(
            url=str(inputs.get("url") or getattr(action, "target", "") or ""),
            parameter=str(inputs.get("parameter") or ""),
            method=str(inputs.get("method") or "GET"),
            location="query")
        outcome = ex.run_acquisition(
            action=action, parameter_ref=parameter_ref, transport=resolved,
            authorization=authorization, budget=budget, limits=bounds,
            replay=replay, now_fn=now_fn)
        if not outcome.evidential and not outcome.replay.get("reused"):
            run.blocked.append({
                "action_id": outcome.action_id,
                "action_type": outcome.action_type,
                "parameter": outcome.parameter,
                "blocked_reason": outcome.result,
                "reason": outcome.reason})
        if outcome.result == ex.RESULT_UNAUTHORIZED and \
                not _authorization_ids(authorization):
            run.blocked.append({
                "action_id": outcome.action_id,
                "action_type": outcome.action_type,
                "parameter": outcome.parameter,
                "blocked_reason": ex.RESULT_UNAUTHORIZED,
                "reason": outcome.reason})
        run.outcomes.append(outcome.to_dict())
        if outcome.request:
            run.requests_sent += 1
        if replay is not None and outcome.evidential and \
                not outcome.replay.get("reused"):
            try:
                replay.record(fingerprint=str(outcome.replay.get("fingerprint")
                                              or ""),
                              action_id=outcome.action_id,
                              result=outcome.result,
                              detection=outcome.detection,
                              context_class=outcome.context_class,
                              response=outcome.response,
                              parameter=outcome.parameter,
                              evidence_excerpt=outcome.evidence_excerpt)
            except Exception:  # noqa: BLE001 - a broken ledger is not evidence
                pass
        for observation in outcome.observations:
            run.observations.append(observation.to_dict())
            evidence_rows.append(observation.to_evidence_row())
            if store is not None:
                try:
                    store.record_observation(observation)
                except Exception:  # noqa: BLE001 - a broken store is reported
                    run.blocked.append({
                        "blocked_reason": "observation_not_persisted",
                        "reason": f"{observation.observation_id} could not be "
                                  f"recorded"})
        if store is not None:
            try:
                store.record_action(action)
            except Exception:  # noqa: BLE001
                run.blocked.append({
                    "blocked_reason": "action_not_persisted",
                    "reason": f"{action.action_id} could not be recorded"})

    if replay is not None and hasattr(replay, "report"):
        try:
            run.replay = replay.report()
        except Exception:  # noqa: BLE001
            run.replay = {}

    run.termination, run.reason = _summarise(run.outcomes, run.reason)
    run = _re_evaluate(run, chain_state, evidence_rows, authorization)
    return _persist_run(run, store)


def chain_summary(chain_state: Any) -> dict[str, Any]:
    """A compact, bounded view of a chain state for persistence and the UI.

    The full stage list is a projection, not evidence: what a stored record
    needs is the verdict, how far the chain got, and what is still missing.
    """
    if not isinstance(chain_state, Mapping):
        chain_state = (chain_state.to_dict() if hasattr(chain_state, "to_dict")
                       else {})
    return {
        "verdict": str(chain_state.get("verdict") or ""),
        "verdict_reason": str(chain_state.get("verdict_reason") or ""),
        "confirmed": bool(chain_state.get("confirmed")),
        "furthest_stage": chain_state.get("furthest_stage"),
        "satisfied_count": chain_state.get("satisfied_count"),
        "stage_count": chain_state.get("stage_count"),
        "next_stage": str(chain_state.get("next_stage") or ""),
        "next_stage_missing_types": list(
            chain_state.get("next_stage_missing_types") or []),
        "missing_evidence_types": list(
            chain_state.get("missing_evidence_types") or []),
        "blockers": list(chain_state.get("blockers") or []),
        "divergence": list(chain_state.get("divergence") or []),
    }


def _persist_run(run: AcquisitionRun, store: Any) -> AcquisitionRun:
    """Persist the acquisition run itself (EPIC13 §26).

    The stored record is deliberately compact: the chain is reduced to its
    verdict summary and only the rows this run produced are kept, so a record
    stays small enough to read and cannot become a body dump.
    """
    if store is None:
        return run
    try:
        store.record_acquisition({
            "candidate_id": run.candidate_id,
            "objective_id": run.objective_id,
            "scope_ref": run.scope_ref, "chain_id": run.chain_id,
            "vulnerability_class": run.vulnerability_class,
            "termination": run.termination, "reason": run.reason,
            "requests_sent": run.requests_sent,
            "outcomes": [dict(o) for o in run.outcomes],
            "observations": [dict(o) for o in run.observations],
            "produced_rows": [dict(r) for r in run.produced_rows],
            "blocked": [dict(b) for b in run.blocked],
            "unavailable": [dict(u) for u in run.unavailable],
            "chain_before": chain_summary(run.chain_before),
            "chain_after": chain_summary(run.chain_after),
            "verdict_before": run.verdict_before,
            "verdict_after": run.verdict_after,
            "verdict_reason_after": run.verdict_reason_after,
            "transport": dict(run.transport),
            "capability": dict(run.capability),
            "replay": dict(run.replay), "limits": dict(run.limits),
            "rule_version": run.rule_version,
        })
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        run.blocked.append({
            "blocked_reason": "acquisition_not_persisted",
            "reason": f"the acquisition run could not be recorded: "
                      f"{type(exc).__name__}"})
    return run


def _summarise(outcomes: Sequence[Mapping[str, Any]], default: str
               ) -> tuple[str, str]:
    """Map the action results onto one run termination (deterministic)."""
    if not outcomes:
        return RUN_NO_REQUIREMENT, default or "no acquisition action was run"
    results = [str(o.get("result") or "") for o in outcomes]
    if ex.RESULT_SUCCESS in results:
        reflected = [o for o in outcomes if o.get("reflected")]
        context = next((str(o.get("context_class") or "") for o in reflected
                        if str(o.get("context_class") or "")), "")
        detail = (f"reflection observed in context {context}"
                  if context else "reflection observed")
        return RUN_REFLECTION_OBSERVED, detail
    if ex.RESULT_NO_REFLECTION in results:
        return (RUN_REFLECTION_NOT_OBSERVED,
                "the controlled marker was not present in the response")
    if ex.RESULT_BUDGET_EXHAUSTED in results:
        return RUN_BUDGET_EXHAUSTED, "the budget refused an acquisition"
    if ex.RESULT_UNAUTHORIZED in results:
        return RUN_UNAUTHORIZED, "authorization refused the acquisition"
    if ex.RESULT_TRANSPORT_UNAVAILABLE in results:
        return (RUN_TRANSPORT_UNAVAILABLE,
                "the transport did not deliver a response")
    if ex.RESULT_CAPABILITY_UNAVAILABLE in results:
        return (RUN_CAPABILITY_UNAVAILABLE,
                "the acquisition action is not available in this runtime")
    if ex.RESULT_REDIRECT_OUT_OF_SCOPE in results:
        return (RUN_INCONCLUSIVE,
                "a redirect left the authorized scope, so the check stopped")
    if ex.RESULT_RESPONSE_LIMIT_EXCEEDED in results:
        return (RUN_INCONCLUSIVE,
                "the response exceeded the configured limit")
    if ex.RESULT_TIMEOUT in results:
        return RUN_INCONCLUSIVE, "the transport timed out"
    return RUN_INCONCLUSIVE, "the acquisition was inconclusive"


def authorization_context(authorization: Any, *, scope_ref: str = "",
                         job_id: str = "") -> Any:
    """Normalise an authorization into EPIC11's ``AuthorizationContext``.

    The acquisition layer accepts a plain mapping for convenience; the EPIC11
    gate consumes its own dataclass, so a mapping is converted here rather than
    being passed through and silently failing inside the engine.
    """
    if authorization is None or not isinstance(authorization, Mapping):
        return authorization
    try:
        from backend.research_agents.finding.integrity import contracts as ic
    except Exception:  # noqa: BLE001 - no contract module, no conversion
        return authorization
    ids = _authorization_ids(authorization)
    return ic.AuthorizationContext(
        scope_ref=str(authorization.get("scope_ref") or scope_ref or ""),
        authorization_ref=str(authorization.get("authorization_ref")
                              or (ids[0] if ids else "")),
        authorization_ids=tuple(ids),
        execution_mode=str(authorization.get("execution_mode") or ""),
        provenance={"source": "epic13_acquisition_service", "job_id": job_id})


def _re_evaluate(run: AcquisitionRun, chain_state: Any,
                 rows: Iterable[Mapping[str, Any]],
                 authorization: Any) -> AcquisitionRun:
    """Re-evaluate the chain over the acquired rows (EPIC12 engine)."""
    run.evidence_rows = [dict(r) for r in list(rows or [])]
    # the rows the run itself produced, i.e. excluding the pre-existing rows
    run.produced_rows = [dict(r) for r in run.evidence_rows
                         if str(r.get("id") or "").startswith("ev-obs-")]
    context = authorization_context(authorization, scope_ref=run.scope_ref)
    if not _authorization_ids(authorization or {}):
        # a run that had no authorization must not manufacture one for the
        # re-evaluation: doing so would *improve* the verdict's authorization
        # axis without a single authorized request being sent.
        context = None
    try:
        state = en.evaluate_chain(run.vulnerability_class,
                                  list(run.evidence_rows),
                                  authorization=context)
        run.chain_after = state.to_dict()
        run.verdict_after = str(state.verdict or "")
        run.verdict_reason_after = str(state.verdict_reason or "")
    except Exception as exc:  # noqa: BLE001 - a failed re-evaluation is honest
        run.chain_after = dict(run.chain_before)
        run.verdict_after = run.verdict_before
        run.verdict_reason_after = (
            f"re-evaluation failed: {type(exc).__name__}")
        run.blocked.append({
            "blocked_reason": "re_evaluation_failed",
            "reason": (f"the chain could not be re-evaluated "
                       f"({type(exc).__name__}); the acquired evidence was "
                       f"produced but not applied")})
    return run


def acquisition_document() -> dict[str, Any]:
    """The whole acquisition layer's contract, for docs and reports."""
    return {
        "rule_version": SERVICE_RULE_VERSION,
        "flow": ["chain", "missing evidence", "plan", "authorization",
                 "budget", "marker", "request", "transport", "response",
                 "detector", "context", "observation",
                 "EPIC11 classification", "chain re-evaluation"],
        "terminations": list(RUN_TERMINATIONS),
        "limits": lm.limits_document(),
        "transport": tr.transport_document(),
        "detector": dt.detector_document(),
        "plan": pl.plan_document(),
        "capability": cap.document(),
        "statements": [
            "Active Evidence Acquisition is not a generic scanner.",
            "Transport failure is not negative vulnerability evidence.",
            "A reflection is not a vulnerability.",
        ],
    }


__all__ = [
    "AcquisitionRun", "authorization_context", "RUN_BUDGET_EXHAUSTED", "RUN_CAPABILITY_UNAVAILABLE",
    "RUN_INCONCLUSIVE", "RUN_MAX_ACTIONS_REACHED", "RUN_NO_REQUIREMENT",
    "RUN_REFLECTION_NOT_OBSERVED", "RUN_REFLECTION_OBSERVED",
    "RUN_TERMINATIONS", "RUN_TRANSPORT_UNAVAILABLE", "RUN_UNAUTHORIZED",
    "SERVICE_RULE_VERSION", "acquisition_document",
    "run_acquisition_for_candidate",
]
