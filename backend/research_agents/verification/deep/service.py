"""EPIC15 §16/§21/§27 — deep verification orchestration.

One entry point that runs the safe part of deep verification and refuses
the unsafe part, with authorization checked at every stage and the
capability boundary reported explicitly:

1. capability check (browser lane closed → the execution half is refused
   before anything else; the DOM half is a bounded static analysis);
2. authorization check for the target/candidate/scope;
3. budget check (frozen ceilings, spend-only);
4. DOM trace over the served material (no browser, no network);
5. execution attempt (always refused in this runtime; an injected
   deterministic runner may be supplied for offline end-to-end tests);
6. exploitability assessment — separate from execution, never inferred;
7. trusted observations produced for the EPIC11 taxonomy / EPIC14
   provenance / EPIC12 chain.

This service produces **no verdict**.  The verdict authority is the
EPIC11 Evidence Gate, reached through the EPIC12 chain, exactly as
before.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.research_agents.finding.integrity import taxonomy as tx

from .budget import DeepBudget, budget_from_ceilings
from .capability import capability_document
from .dom import DomTrace, trace_dom_flow, trace_summary
from .execution import (  # noqa: F401
    ATTEMPT_STATES, AUTHORIZATION_MISSING, BROWSER_UNAVAILABLE,
    BUDGET_EXHAUSTED, NAVIGATION_BLOCKED, REDIRECT_OUT_OF_SCOPE,
    AttemptResult, attempt_execution, authorization_state,
    is_negative_security_evidence, is_observed, is_refusal)
from .exploitability import ExploitabilityAssessment, assess_exploitability
from .isolation import IsolationPolicy, check_navigation, isolation_policy
from .producer import DeepObservationProducer, producer_for

DEEP_VERIFICATION_VERSION = "epic15-deep-verification-1"

DEEP_OBSERVED = "DEEP_OBSERVED"
DEEP_NOT_OBSERVED = "DEEP_NOT_OBSERVED"
DEEP_NOT_TESTED = "DEEP_NOT_TESTED"
DEEP_BLOCKED = "DEEP_BLOCKED"
DEEP_CAPABILITY_UNAVAILABLE = "DEEP_CAPABILITY_UNAVAILABLE"
DEEP_INCONCLUSIVE = "DEEP_INCONCLUSIVE"

DEEP_STATES: tuple[str, ...] = (
    DEEP_OBSERVED, DEEP_NOT_OBSERVED, DEEP_NOT_TESTED, DEEP_BLOCKED,
    DEEP_CAPABILITY_UNAVAILABLE, DEEP_INCONCLUSIVE)

#: chain stages deep verification is responsible for (§4)
DEEP_STAGES: tuple[str, ...] = ("sink", "execution", "exploitability")

#: what the analyst should do next, per result state (§27)
NEXT_STEP: dict[str, str] = {
    DEEP_OBSERVED: ("evidence acquired: classification and the chain decide "
                    "the verdict"),
    DEEP_NOT_OBSERVED: ("instrumented run observed no sink/execution: the "
                        "chain records it as negative evidence"),
    DEEP_NOT_TESTED: ("no served material to analyse: acquire the response "
                      "through the authorized acquisition lane first"),
    DEEP_BLOCKED: "resolve the recorded authorization/navigation blocker",
    DEEP_CAPABILITY_UNAVAILABLE: ("browser execution is unavailable in this "
                                  "runtime (B5 containment pending); only "
                                  "deterministic DOM analysis can run"),
    DEEP_INCONCLUSIVE: "re-run with a bounded, instrumented attempt",
}


@dataclass(frozen=True)
class DeepVerificationResult:
    """The explicit outcome of one deep-verification run (§18/§27)."""

    state: str
    reason: str = ""
    candidate_id: str = ""
    action_id: str = ""
    scope_ref: str = ""
    target: str = ""
    parameter: str = ""
    marker: str = ""
    authorization_id: str = ""
    dom: dict[str, Any] = field(default_factory=dict)
    attempt: dict[str, Any] = field(default_factory=dict)
    exploitability: dict[str, Any] = field(default_factory=dict)
    evidence_types: tuple[str, ...] = ()
    observations: tuple[Any, ...] = ()
    next_step: str = ""
    capability: dict[str, Any] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    isolation: dict[str, Any] = field(default_factory=dict)
    rule_version: str = DEEP_VERIFICATION_VERSION

    @property
    def observed(self) -> bool:
        return self.state == DEEP_OBSERVED

    @property
    def produces_confirmation_evidence(self) -> bool:
        """Only a real PAYLOAD_EXECUTION observation could (§8)."""
        return tx.PAYLOAD_EXECUTION in self.evidence_types

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "candidate_id": self.candidate_id,
            "action_id": self.action_id,
            "scope_ref": self.scope_ref,
            "target": self.target,
            "parameter": self.parameter,
            "marker": self.marker,
            "authorization_id": self.authorization_id,
            "dom": dict(self.dom),
            "attempt": dict(self.attempt),
            "exploitability": dict(self.exploitability),
            "evidence_types": list(self.evidence_types),
            "next_step": self.next_step,
            "capability": dict(self.capability),
            "budget": dict(self.budget),
            "isolation": dict(self.isolation),
            "rule_version": self.rule_version,
        }


def _authorization_ref(authorization: Any) -> str:
    if isinstance(authorization, dict):
        return str(authorization.get("authorization_id") or "")
    return str(getattr(authorization, "authorization_id", "") or "")


def _authorized(authorization: Any) -> bool:
    if authorization is None:
        return False
    if isinstance(authorization, dict):
        if authorization.get("expired") is True:
            return False
        return bool(authorization.get("authorization_ids")
                    or authorization.get("authorization_id")
                    or authorization.get("scope_ref")
                    or authorization.get("scope"))
    return bool(getattr(authorization, "authorization_ids", None))


def deep_stage_for(chain_state: Any) -> str:
    """Which deep stage, if any, the chain is missing next (§4)."""
    try:
        missing = [str(s) for s in
                   (chain_state.next_stage_missing_types or ())]
    except AttributeError:
        missing = []
    wanted = {
        tx.DOM_SINK_IDENTIFIED: "sink",
        tx.PAYLOAD_EXECUTION: "execution",
        tx.EXPLOITABILITY_ESTABLISHED: "exploitability",
    }
    for item in missing:
        stage = wanted.get(item)
        if stage:
            return stage
    return ""


def deep_verify(*, candidate_id: str = "", scope_ref: str = "",
                target: str = "", parameter: str = "", marker: str = "",
                document: Any = None, authorization: Any = None,
                authorized_hosts: Any = (), budget: DeepBudget | None = None,
                runner: Callable[..., Any] | None = None,
                isolation: IsolationPolicy | None = None,
                action: Any = None, action_id: str = "",
                objective_id: str = "", job_id: str = "",
                session_id: str = "", category: str = "XSS",
                controlled_input: bool = True,
                impact_established: bool = False,
                impact_detail: str = "") -> DeepVerificationResult:
    """Run the safe half of deep verification; refuse the unsafe half."""
    spend = budget or budget_from_ceilings()
    policy = isolation or isolation_policy()
    lanes = capability_document()
    # deterministic identity when the caller supplies none: reproducible
    # from the candidate/scope/target/parameter, never random
    seed = "|".join([str(candidate_id), str(scope_ref), str(target),
                     str(parameter), str(marker)])
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    action_id = action_id or f"act-deep-{digest}"
    objective_id = objective_id or f"vo-deep-{digest}"
    producer = (producer_for(action, where=target) if action is not None
                else DeepObservationProducer(
                    action_id=action_id, candidate_id=candidate_id,
                    objective_id=objective_id, scope_ref=scope_ref,
                    job_id=job_id, where=target, category=category))
    auth_id = _authorization_ref(authorization) or producer.authorization_id

    def build(state: str, reason: str, *, dom=None, attempt=None,
              exploit=None, observations=(), evidence=()
              ) -> DeepVerificationResult:
        return DeepVerificationResult(
            state=state, reason=reason, candidate_id=candidate_id,
            action_id=producer.action_id, scope_ref=scope_ref, target=target,
            parameter=parameter, marker=marker, authorization_id=auth_id,
            dom=dom or {}, attempt=attempt or {},
            exploitability=exploit or {},
            evidence_types=tuple(evidence), observations=tuple(observations),
            next_step=NEXT_STEP.get(state, ""), capability=lanes,
            budget=spend.to_dict(), isolation=policy.to_dict())

    def blocked(state: str, reason: str) -> dict[str, Any]:
        return AttemptResult(state=state, reason=reason,
                             action_id=producer.action_id,
                             candidate_id=candidate_id).to_dict()

    # 1/2. capability + authorization, before any work
    if not _authorized(authorization):
        auth_state = authorization_state(authorization)
        return build(DEEP_BLOCKED, "authorization_missing_or_expired",
                     attempt=blocked(auth_state or AUTHORIZATION_MISSING,
                                     "authorization_missing_or_expired"))
    if not policy.isolated:
        return build(DEEP_BLOCKED, "isolation_policy_not_satisfied",
                     attempt=blocked(BROWSER_UNAVAILABLE,
                                     "isolation_policy_not_satisfied"))
    if target:
        decision = check_navigation(target, scope_ref=scope_ref,
                                    authorized_hosts=authorized_hosts)
        if not decision.allowed:
            blocked_state = (REDIRECT_OUT_OF_SCOPE
                             if decision.decision == "REDIRECT_OUT_OF_SCOPE"
                             else NAVIGATION_BLOCKED)
            blocked = AttemptResult(
                state=blocked_state, reason=decision.reason,
                detail={"navigation": decision.to_dict()},
                action_id=producer.action_id, candidate_id=candidate_id)
            return build(DEEP_BLOCKED, decision.reason,
                         attempt=blocked.to_dict())
    if spend.exhausted:
        return build(DEEP_BLOCKED, "budget_exhausted",
                     attempt=blocked(BUDGET_EXHAUSTED, "budget_exhausted"))

    observations: list[Any] = []
    evidence: list[str] = []

    # 4. DOM analysis (safe, deterministic, no browser)
    has_material = document is not None and str(document or "").strip() != ""
    trace: DomTrace = trace_dom_flow(document, parameter=parameter,
                                     marker=marker)
    dom_observation = producer.dom_sink_observation(
        trace, material_available=has_material, marker=marker)
    observations.append(dom_observation)
    if dom_observation.evidence_type:
        evidence.append(dom_observation.evidence_type)

    # 5. execution attempt (refused in this runtime, offline seam in tests)
    #    the attempt itself is consumed *after* the run, so the injected
    #    offline seam is not starved by the pre-check
    if spend.attempts_remaining <= 0:
        return build(DEEP_BLOCKED, "no_execution_attempts_remaining",
                     dom=trace_summary(trace),
                     observations=observations, evidence=evidence)
    attempt: AttemptResult = attempt_execution(
        action_id=producer.action_id, candidate_id=candidate_id,
        scope_ref=scope_ref, target=target, authorization=authorization,
        authorized_hosts=authorized_hosts, budget=spend, isolation=policy,
        runner=runner, session_id=session_id)
    spend.spend_attempt()
    spend.spend_navigation()
    spend.spend_runtime(float(attempt.detail.get("duration_seconds") or 0.0))
    execution_observation = producer.execution_observation(
        attempt, marker=marker, sink=trace.sink)
    observations.append(execution_observation)
    if execution_observation.evidence_type:
        evidence.append(execution_observation.evidence_type)

    # 6. exploitability — separate, never inferred from execution alone
    assessment: ExploitabilityAssessment = assess_exploitability(
        execution_observed=attempt.state == "EXECUTION_OBSERVED",
        controlled_input=controlled_input, sink=trace.sink,
        context=trace.kind, impact_established=impact_established,
        impact_detail=impact_detail)
    exploit_observation = producer.exploitability_observation(
        assessment, marker=marker)
    observations.append(exploit_observation)
    if exploit_observation.evidence_type:
        evidence.append(exploit_observation.evidence_type)

    # 7. state
    if attempt.state == "EXECUTION_OBSERVED":
        state = DEEP_OBSERVED
        reason = attempt.reason
    elif is_observed(attempt.state):
        state = DEEP_OBSERVED
        reason = attempt.reason
    elif attempt.negative_evidence:
        state = DEEP_NOT_OBSERVED
        reason = attempt.reason
    elif is_refusal(attempt.state):
        state = (DEEP_CAPABILITY_UNAVAILABLE
                 if attempt.state in ("BROWSER_UNAVAILABLE",
                                      "INSTRUMENTATION_UNAVAILABLE")
                 else DEEP_BLOCKED)
        reason = attempt.state
    elif not has_material:
        state = DEEP_NOT_TESTED
        reason = "no_served_material"
    else:
        state = DEEP_INCONCLUSIVE
        reason = attempt.state
    return build(state, reason, dom=trace_summary(trace),
                 attempt=attempt.to_dict(), exploit=assessment.to_dict(),
                 observations=observations, evidence=evidence)


def project_deep(result: DeepVerificationResult) -> dict[str, Any]:
    """The SOC view of one deep-verification run (§27)."""
    attempt = result.attempt or {}
    lanes = (result.capability or {}).get("lanes", {})
    browser = lanes.get("browser", {})
    dom = lanes.get("dom", {})
    state = result.state
    execution_view = ("observed" if attempt.get("state") == "EXECUTION_OBSERVED"
                      else "not_observed" if attempt.get("negative_evidence")
                      else "unavailable" if attempt.get("refused")
                      else "inconclusive")
    return {
        "deep_verification": True,
        "browser": "unavailable" if not browser.get("live_switch")
        else "available",
        "browser_blockers": browser.get("blockers", {}),
        "dom_analysis": dom.get("capability", ""),
        "authorization": result.authorization_id or "none",
        "source": (result.dom or {}).get("source", ""),
        "sink": (result.dom or {}).get("sink", ""),
        "instrumentation": {
            "method": (result.dom or {}).get("instrumentation_method", ""),
            "version": (result.dom or {}).get("instrumentation_version", ""),
        },
        "execution": execution_view,
        "exploitability": ("established"
                           if (result.exploitability or {}).get("established")
                           else "not_established"),
        "evidence": list(result.evidence_types),
        "state": state,
        "reason": result.reason,
        "next_step": result.next_step,
        "distinct_states": {
            "not_observed": state == DEEP_NOT_OBSERVED,
            "not_tested": state == DEEP_NOT_TESTED,
            "blocked": state == DEEP_BLOCKED,
            "capability_unavailable": state == DEEP_CAPABILITY_UNAVAILABLE,
        },
        "optimistic": False,
        "rule_version": DEEP_VERIFICATION_VERSION,
    }


__all__ = [
    "DEEP_BLOCKED", "DEEP_CAPABILITY_UNAVAILABLE", "DEEP_INCONCLUSIVE",
    "DEEP_NOT_OBSERVED", "DEEP_NOT_TESTED", "DEEP_OBSERVED", "DEEP_STAGES",
    "DEEP_STATES", "DEEP_VERIFICATION_VERSION", "DeepVerificationResult",
    "ATTEMPT_STATES", "deep_stage_for", "deep_verify", "project_deep",
]
