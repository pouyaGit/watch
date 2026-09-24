"""EPIC15 §16/§18 — the execution attempt and its result states.

Every execution attempt produces exactly one explicit state.  The
mandatory distinction (§18):

* a **refusal** (no browser, blocked navigation, expired authorization,
  timeout, exhausted budget, missing instrumentation, inconclusive) is
  *not* negative security evidence;
* ``EXECUTION_NOT_OBSERVED`` / ``DOM_SINK_NOT_OBSERVED`` are the **only**
  states that may become negative evidence, and only when the run
  genuinely reached the relevant point with instrumentation present.

No browser is created here.  A live attempt always refuses before any
browser, process or transport primitive — the platform's lane is closed
(``ai.execution.browser_executor.LIVE_BROWSER`` is a literal ``False``).
The only runner that can be supplied is an injected deterministic
offline harness, exactly as EPIC13 used an injected transport seam for
deterministic end-to-end tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from backend.research_agents.verification import actions as ac
from backend.research_agents.finding.integrity import taxonomy as tx

from .capability import BROWSER_EXECUTION_BLOCKED, browser_lane
from .isolation import (IsolationPolicy, NAVIGATION_ALLOWED, check_navigation,
                        isolation_policy)

EXECUTION_RULE_VERSION = "epic15-execution-1"

EXECUTION_OBSERVED = "EXECUTION_OBSERVED"
EXECUTION_NOT_OBSERVED = "EXECUTION_NOT_OBSERVED"
DOM_SINK_OBSERVED = "DOM_SINK_OBSERVED"
DOM_SINK_NOT_OBSERVED = "DOM_SINK_NOT_OBSERVED"
BROWSER_UNAVAILABLE = "BROWSER_UNAVAILABLE"
BROWSER_START_FAILED = "BROWSER_START_FAILED"
NAVIGATION_BLOCKED = "NAVIGATION_BLOCKED"
REDIRECT_OUT_OF_SCOPE = "REDIRECT_OUT_OF_SCOPE"
AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
TIMEOUT = "TIMEOUT"
BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
INSTRUMENTATION_UNAVAILABLE = "INSTRUMENTATION_UNAVAILABLE"
INCONCLUSIVE = "INCONCLUSIVE"

ATTEMPT_STATES: tuple[str, ...] = (
    EXECUTION_OBSERVED, EXECUTION_NOT_OBSERVED, DOM_SINK_OBSERVED,
    DOM_SINK_NOT_OBSERVED, BROWSER_UNAVAILABLE, BROWSER_START_FAILED,
    NAVIGATION_BLOCKED, REDIRECT_OUT_OF_SCOPE, AUTHORIZATION_MISSING,
    AUTHORIZATION_EXPIRED, TIMEOUT, BUDGET_EXHAUSTED,
    INSTRUMENTATION_UNAVAILABLE, INCONCLUSIVE)

#: states that may become negative security evidence (§18)
NEGATIVE_STATES: frozenset[str] = frozenset(
    {EXECUTION_NOT_OBSERVED, DOM_SINK_NOT_OBSERVED})

#: every other state is a refusal: it says nothing about the target
REFUSAL_STATES: frozenset[str] = frozenset(
    s for s in ATTEMPT_STATES if s not in NEGATIVE_STATES
    and s != EXECUTION_OBSERVED)


def is_negative_security_evidence(state: str) -> bool:
    """§18: only a genuine, instrumented observation may be negative."""
    return str(state or "") in NEGATIVE_STATES


def is_refusal(state: str) -> bool:
    """A refusal is never evidence about the target's security."""
    return str(state or "") in REFUSAL_STATES


def is_observed(state: str) -> bool:
    return str(state or "") in (EXECUTION_OBSERVED, DOM_SINK_OBSERVED)


def evidence_type_for(state: str) -> str:
    """The EPIC11 evidence type a state may contribute ('' for refusals)."""
    if state == EXECUTION_OBSERVED:
        return tx.PAYLOAD_EXECUTION
    if state == DOM_SINK_OBSERVED:
        return tx.DOM_SINK_IDENTIFIED
    if state in NEGATIVE_STATES:
        return tx.NEGATIVE_EVIDENCE
    return ""


@dataclass(frozen=True)
class AttemptResult:
    """The outcome of one execution attempt (§18)."""

    state: str
    reason: str = ""
    action_id: str = ""
    candidate_id: str = ""
    authorization_id: str = ""
    browser_id: str = ""
    session_id: str = ""
    navigations: int = 0
    redirects: int = 0
    duration_seconds: float = 0.0
    instrumentation_method: str = ""
    instrumentation_version: str = ""
    evidence_type: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    rule_version: str = EXECUTION_RULE_VERSION

    @property
    def refused(self) -> bool:
        return is_refusal(self.state)

    @property
    def negative_evidence(self) -> bool:
        return is_negative_security_evidence(self.state)

    @property
    def observed(self) -> bool:
        return is_observed(self.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "action_id": self.action_id,
            "candidate_id": self.candidate_id,
            "authorization_id": self.authorization_id,
            "browser_id": self.browser_id,
            "session_id": self.session_id,
            "navigations": self.navigations,
            "redirects": self.redirects,
            "duration_seconds": self.duration_seconds,
            "instrumentation_method": self.instrumentation_method,
            "instrumentation_version": self.instrumentation_version,
            "evidence_type": self.evidence_type,
            "refused": self.refused,
            "negative_evidence": self.negative_evidence,
            "observed": self.observed,
            "detail": dict(self.detail),
            "rule_version": self.rule_version,
        }


def authorization_state(authorization: Any) -> str:
    """AUTHORIZATION_MISSING / AUTHORIZATION_EXPIRED / "" for a valid one."""
    """Missing / expired / ok, from the existing authorization record."""
    if authorization is None:
        return AUTHORIZATION_MISSING
    if isinstance(authorization, dict):
        if authorization.get("expired") is True:
            return AUTHORIZATION_EXPIRED
        if not (authorization.get("authorization_ids")
                or authorization.get("authorization_id")
                or authorization.get("scope_ref")
                or authorization.get("scope")):
            return AUTHORIZATION_MISSING
        return ""
    ids = getattr(authorization, "authorization_ids", None)
    if not ids:
        return AUTHORIZATION_MISSING
    return ""


def attempt_execution(*, action_id: str = "", candidate_id: str = "",
                      scope_ref: str = "", target: str = "",
                      authorization: Any = None,
                      authorized_hosts: Any = (),
                      budget: Any = None,
                      isolation: IsolationPolicy | None = None,
                      runner: Callable[..., Any] | None = None,
                      session_id: str = "") -> AttemptResult:
    """Attempt one controlled execution observation, or refuse explicitly.

    Order of checks (all fail-closed, none skipped):

    1. authorization must be present and unexpired (absence is BLOCKED);
    2. the isolation policy must hold;
    3. the budget must have an attempt left;
    4. the target must satisfy the navigation/redirect policy;
    5. the platform browser lane must be open — it is not, so a live
       attempt refuses with ``BROWSER_UNAVAILABLE`` /
       ``BROWSER_EXECUTION_BLOCKED`` before any primitive;
    6. only then may an injected deterministic runner run.
    """
    policy = isolation or isolation_policy()
    lane = browser_lane()
    common = {
        "action_id": action_id,
        "candidate_id": candidate_id,
        "authorization_id": (str(
            (authorization or {}).get("authorization_id") or "")
            if isinstance(authorization, dict) else str(
            getattr(authorization, "authorization_id", "") or "")),
        "browser_id": str(lane.get("browser_id") or ""),
        "session_id": session_id,
    }
    # 1. authorization first: absence is reported as BLOCKED and never as a
    #    capability statement about the browser lane
    state = authorization_state(authorization)
    if state:
        return AttemptResult(state=state, reason="authorization_not_valid",
                             detail={"authorization": {
                                 "present": bool(authorization),
                                 "expired": bool(
                                     isinstance(authorization, dict)
                                     and authorization.get("expired"))}},
                             **common)
    # 2. isolation
    if not policy.isolated:
        return AttemptResult(state=BROWSER_UNAVAILABLE,
                             reason="isolation_policy_not_satisfied",
                             detail={"policy": policy.to_dict()}, **common)
    # 3. budget
    if budget is not None:
        remaining = getattr(budget, "attempts_remaining", None)
        if remaining is not None and int(remaining) <= 0:
            return AttemptResult(state=BUDGET_EXHAUSTED,
                                 reason="no_execution_attempts_remaining",
                                 **common)
        if getattr(budget, "exhausted", False):
            return AttemptResult(state=BUDGET_EXHAUSTED,
                                 reason="budget_exhausted", **common)
    # 4. navigation / redirect policy
    decision = check_navigation(target, scope_ref=scope_ref,
                                authorized_hosts=authorized_hosts)
    if not decision.allowed:
        blocked = (REDIRECT_OUT_OF_SCOPE
                   if decision.decision == "REDIRECT_OUT_OF_SCOPE"
                   else NAVIGATION_BLOCKED)
        return AttemptResult(state=blocked, reason=decision.reason,
                             detail={"navigation": decision.to_dict()},
                             **common)
    # 5. the platform lane: no runner exists in production and the live gate
    #    is a literal False, so the refusal happens before any primitive
    if runner is None:
        return AttemptResult(
            state=BROWSER_UNAVAILABLE,
            reason=BROWSER_EXECUTION_BLOCKED,
            detail={"lane": lane["state"], "blockers": lane["blockers"],
                    "runner": "none", "live_switch": lane["live_switch"],
                    "distinction": (
                        "OFFLINE/INJECTED validation is not REAL production "
                        "acquisition: the production lane is closed")},
            **common)
    # 6. an injected deterministic harness: offline validation only, and the
    #    result is labelled as such so the two can never be conflated
    if lane.get("live_switch"):
        return AttemptResult(
            state=BROWSER_UNAVAILABLE, reason="unexpected_live_lane",
            detail={"lane": lane["state"]}, **common)
    try:
        outcome = runner(target=target, scope_ref=scope_ref,
                         action_id=action_id, candidate_id=candidate_id,
                         session_id=session_id, authorization=authorization)
    except TimeoutError as exc:  # pragma: no cover - defensive
        return AttemptResult(state=TIMEOUT, reason=str(exc) or "timeout",
                             **common)
    except Exception as exc:  # a runner failure is never negative evidence
        return AttemptResult(state=BROWSER_START_FAILED,
                             reason=f"runner_error:{type(exc).__name__}",
                             **common)
    if not isinstance(outcome, dict):
        return AttemptResult(state=INCONCLUSIVE,
                             reason="runner_returned_no_outcome", **common)
    if not outcome.get("instrumented"):
        return AttemptResult(state=INSTRUMENTATION_UNAVAILABLE,
                             reason="no_instrumentation_in_the_run",
                             detail={"outcome": dict(outcome)}, **common)
    if outcome.get("timed_out"):
        return AttemptResult(state=TIMEOUT, reason="runner_timed_out",
                             detail={"outcome": dict(outcome)}, **common)
    executed = bool(outcome.get("execution_observed"))
    sink_seen = bool(outcome.get("sink_observed"))
    if executed:
        state = EXECUTION_OBSERVED
        reason = str(outcome.get("reason") or "controlled_marker_executed")
    elif sink_seen:
        state = DOM_SINK_OBSERVED
        reason = str(outcome.get("reason") or "sink_reached_without_execution")
    else:
        state = EXECUTION_NOT_OBSERVED
        reason = str(outcome.get("reason") or "instrumented_run_observed_none")
    return AttemptResult(
        state=state, reason=reason,
        navigations=int(outcome.get("navigations") or 0),
        redirects=int(outcome.get("redirects") or 0),
        duration_seconds=float(outcome.get("duration_seconds") or 0.0),
        instrumentation_method=str(outcome.get("instrumentation_method") or ""),
        instrumentation_version=str(
            outcome.get("instrumentation_version") or ""),
        evidence_type=evidence_type_for(state),
        detail={"outcome": dict(outcome)}, **common)
