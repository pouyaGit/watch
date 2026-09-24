"""EPIC13 §9/§16/§19 — the acquisition executor.

Runs one typed acquisition action end to end and produces *structured
observations* that EPIC11 classifies and the EPIC12 chain re-evaluates.  It
decides nothing itself: the verdict still comes from the EPIC11 gate.

Ordered steps, all of them fail-closed:

1. the action must be an acquisition action (SEND_MARKER, CHECK_REFLECTION,
   CLASSIFY_REFLECTION_CONTEXT)
2. authorization is re-checked *immediately before execution* (§12)
3. the budget is consumed before the request is built (§10/§16)
4. the marker is generated deterministically from the action id (§5)
5. the controlled request is built and re-scoped (§6)
6. replay control: an identical, still-valid acquisition is reused, not
   re-sent (§18)
7. the request goes to the injected transport — never to a network primitive
   in this package
8. the response is bounded, its redirects scope-checked, its headers scrubbed
9. the reflection detector runs (§7) and the context is classified (§8)
10. an observation is emitted — positive, negative or not-tested

The critical distinction this module enforces (§19):

    "the request failed"  is NOT  "reflection absent"

A transport failure, a timeout, an out-of-scope redirect, a truncated body or
an exhausted budget produce **no** negative evidence at all: the action is
BLOCKED/INCONCLUSIVE and the chain stays unresolved rather than being told
something false.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import observations as ob

from . import context as cx
from . import detector as dt
from . import limits as lm
from . import markers as mk
from . import requests as rq
from . import transport as tr

ACQUISITION_RULE_VERSION = "epic13-acquisition-executor-1"

#: the acquisition action set (a closed subset of EPIC12's catalog).
ACQUISITION_ACTIONS: tuple[str, ...] = (
    ac.SEND_MARKER, ac.CHECK_REFLECTION, ac.CLASSIFY_REFLECTION_CONTEXT,
)

#: §19 result vocabulary — every acquisition terminates with one of these.
RESULT_SUCCESS = "SUCCESS"
RESULT_NO_REFLECTION = "NO_REFLECTION"
RESULT_RESPONSE_UNAVAILABLE = "RESPONSE_UNAVAILABLE"
RESULT_TIMEOUT = "TIMEOUT"
RESULT_RESPONSE_LIMIT_EXCEEDED = "RESPONSE_LIMIT_EXCEEDED"
RESULT_REDIRECT_OUT_OF_SCOPE = "REDIRECT_OUT_OF_SCOPE"
RESULT_UNAUTHORIZED = "UNAUTHORIZED"
RESULT_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
RESULT_TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
RESULT_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
RESULT_INCONCLUSIVE = "INCONCLUSIVE"

ACQUISITION_RESULTS: tuple[str, ...] = (
    RESULT_SUCCESS, RESULT_NO_REFLECTION, RESULT_RESPONSE_UNAVAILABLE,
    RESULT_TIMEOUT, RESULT_RESPONSE_LIMIT_EXCEEDED,
    RESULT_REDIRECT_OUT_OF_SCOPE, RESULT_UNAUTHORIZED, RESULT_BUDGET_EXHAUSTED,
    RESULT_TRANSPORT_UNAVAILABLE, RESULT_CAPABILITY_UNAVAILABLE,
    RESULT_INCONCLUSIVE,
)

#: results that mean "we did not learn anything" — never negative evidence.
NON_EVIDENTIAL_RESULTS: frozenset[str] = frozenset(
    {RESULT_RESPONSE_UNAVAILABLE, RESULT_TIMEOUT, RESULT_RESPONSE_LIMIT_EXCEEDED,
     RESULT_REDIRECT_OUT_OF_SCOPE, RESULT_UNAUTHORIZED, RESULT_BUDGET_EXHAUSTED,
     RESULT_TRANSPORT_UNAVAILABLE, RESULT_CAPABILITY_UNAVAILABLE,
     RESULT_INCONCLUSIVE})

#: the excerpt persisted around a marker (never the whole body, §13).
EXCERPT_RADIUS = 60


class AcquisitionError(ValueError):
    """The acquisition could not be attempted (always fail closed)."""


@dataclass
class AcquisitionOutcome:
    """The full, auditable result of one acquisition action."""

    action_id: str = ""
    action_type: str = ""
    state: str = ac.ACTION_BLOCKED
    result: str = RESULT_TRANSPORT_UNAVAILABLE
    parameter: str = ""
    marker: str = ""
    reason: str = ""
    observations: list[Any] = field(default_factory=list)
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    context_class: str = ""
    redirects: list[dict[str, Any]] = field(default_factory=list)
    evidence_excerpt: str = ""
    authorization_id: str = ""
    transport: str = ""
    replay: dict[str, Any] = field(default_factory=dict)
    limits: dict[str, int] = field(default_factory=dict)
    rule_version: str = ACQUISITION_RULE_VERSION

    @property
    def ok(self) -> bool:
        return self.state == ac.ACTION_SUCCEEDED

    @property
    def evidential(self) -> bool:
        """True when this run may be read as evidence (positive or negative)."""
        return self.result in (RESULT_SUCCESS, RESULT_NO_REFLECTION)

    @property
    def reflected(self) -> bool:
        return bool(self.detection.get("reflected"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id, "action_type": self.action_type,
            "state": self.state, "result": self.result,
            "parameter": self.parameter, "marker": self.marker,
            "reason": self.reason,
            "observation_ids": [getattr(o, "observation_id", "")
                                for o in self.observations],
            "request": dict(self.request), "response": dict(self.response),
            "detection": dict(self.detection),
            "context_class": self.context_class,
            "redirects": list(self.redirects),
            "evidence_excerpt": self.evidence_excerpt,
            "authorization_id": self.authorization_id,
            "transport": self.transport, "replay": dict(self.replay),
            "limits": dict(self.limits), "rule_version": self.rule_version,
            "ok": self.ok, "evidential": self.evidential,
            "reflected": self.reflected,
        }


def _authorization_ids(authorization: Any) -> tuple[str, ...]:
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


def authorization_allows(action: Any, authorization: Any, *,
                         scope_ref: str = "") -> tuple[bool, str]:
    """Re-check authorization immediately before execution (§12).  Fail closed.

    Requires: at least one authorization id, the action's target inside the
    recorded scope, and — when the authorization declares an action set — the
    action type inside it.  Absent or ambiguous authorization is a refusal.
    """
    ids = _authorization_ids(authorization)
    if not ids:
        return False, "no authorization id covers this acquisition"
    declared = ()
    if isinstance(authorization, Mapping):
        declared = tuple(authorization.get("action_types") or ())
    else:
        declared = tuple(getattr(authorization, "action_types", ()) or ())
    if declared:
        allowed = {str(a).upper() for a in declared}
        if str(action.action_type).upper() not in allowed:
            return False, (f"authorization does not cover "
                           f"{action.action_type}")
    declared_scope = ""
    if isinstance(authorization, Mapping):
        declared_scope = str(authorization.get("scope_ref") or "")
    else:
        declared_scope = str(getattr(authorization, "scope_ref", "") or "")
    action_scope = str(getattr(action, "scope_ref", "") or "")
    scope = str(scope_ref or action_scope or "")
    if not scope:
        return False, "no scope ref is recorded for the acquisition"
    if declared_scope and action_scope and declared_scope != action_scope:
        return False, ("the authorization covers a different scope "
                       f"({declared_scope}) than the action ({action_scope})")
    target = str(getattr(action, "target", "") or "")
    if target and not ac.target_in_scope(target, scope):
        return False, "the action target is outside the recorded scope"
    if target and declared_scope and not ac.target_in_scope(target,
                                                           declared_scope):
        return False, "the action target is outside the authorized scope"
    return True, ""


def evidence_excerpt(body: str | None, marker: str, *,
                     radius: int = EXCERPT_RADIUS) -> str:
    """A bounded, scrubbed excerpt around the marker (never the whole body)."""
    text = str(body or "")
    if not text:
        return ""
    needle = str(marker or "")
    index = text.find(needle) if needle else -1
    if index < 0:
        window = text[:radius]
    else:
        start = max(0, index - radius)
        window = text[start:index + len(needle) + radius]
    try:
        from ai.evidence import scrubber
        window = str(scrubber.scrub_text(window))
    except Exception:  # noqa: BLE001 - redaction is best-effort only here
        pass
    return window[:radius * 2 + len(needle) + 8]


def scrub_response_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """Deterministically redact secret-shaped response headers (§13)."""
    raw = {str(k): str(v) for k, v in dict(headers or {}).items()}
    try:
        from ai.evidence import scrubber
        return {str(k): str(v) for k, v in scrubber.scrub_headers(raw).items()}
    except Exception:  # noqa: BLE001
        secret = ("set-cookie", "authorization", "token", "secret", "apikey",
                  "api-key", "session")
        return {k: ("[REDACTED]" if any(s in k.lower() for s in secret) else v)
                for k, v in raw.items()}


def check_redirects(response: tr.AcquisitionResponse, *,
                    scope_ref: str) -> tuple[bool, str, list[dict[str, Any]]]:
    """Scope-check every redirect hop.  An out-of-scope hop stops everything."""
    hops: list[dict[str, Any]] = []
    declared = [dict(h) for h in list(response.redirects or [])]
    header_location = ""
    try:
        header_location = str(
            dict(response.headers or {}).get("location") or "")
    except Exception:  # noqa: BLE001 - headers are untrusted input
        header_location = ""
    try:
        status = int(response.status_code or 0)
    except (TypeError, ValueError):
        status = 0
    is_redirect = 300 <= status < 400
    if not declared and header_location:
        declared = [{"location": header_location, "status": status}]
    for hop in declared:
        target = str(hop.get("location") or hop.get("url")
                     or hop.get("to") or "")
        in_scope = (bool(ac.target_in_scope(target, scope_ref))
                    if target else False)
        hops.append({"location": rq._redact_url(target), "in_scope": in_scope,
                     "status": int(hop.get("status") or 0)})
        if not target:
            # an unidentifiable destination cannot be proven in scope
            return False, ("a redirect hop had no identifiable destination, "
                           "so it cannot be proven in scope"), hops
        if not in_scope:
            return False, "a redirect left the authorized scope", hops
    if is_redirect and not hops:
        return False, ("the response was a redirect whose destination was not "
                       "reported, so it cannot be proven in scope"), hops
    # a transport may report where it actually ended up even when it declares
    # no hops: an off-scope final URL is an off-scope destination (§11).
    final_url = str(getattr(response, "final_url", "") or "")
    if final_url and not ac.target_in_scope(final_url, scope_ref):
        hops.append({"location": rq._redact_url(final_url), "in_scope": False,
                     "status": status})
        return False, ("the response came from outside the authorized scope, "
                       "so it cannot be trusted as evidence"), hops
    return True, "", hops


def _budget_check(budget: Any, resource: str, *, reason: str) -> str:
    """Consume one budget unit.  Returns "" when allowed, else the refusal."""
    if budget is None:
        return ""
    try:
        budget.ensure(resource, 1, reason=reason)
    except Exception as exc:  # noqa: BLE001 - any refusal refuses the work
        return f"{resource}:{type(exc).__name__}"
    return ""


def run_acquisition(*, action: Any, parameter_ref: rq.ParameterRef,
                    transport: Any = None, authorization: Any = None,
                    budget: Any = None, limits: Mapping[str, Any] | None = None,
                    replay: Any = None,
                    now_fn: Callable[[], float] = time.monotonic
                    ) -> AcquisitionOutcome:
    """Execute one acquisition action and record it for replay control (§18)."""
    outcome = _run_acquisition_core(
        action=action, parameter_ref=parameter_ref, transport=transport,
        authorization=authorization, budget=budget, limits=limits,
        replay=replay, now_fn=now_fn)
    _record_replay(outcome, replay)
    return outcome


def _reusable_hit(hit: Mapping[str, Any]) -> bool:
    """A stored acquisition may only be reused while it is still evidence.

    §18: a previous timeout, refusal or inconclusive read is *not* a reason to
    skip a request — only a conclusive positive or negative is.
    """
    if not bool(hit.get("reusable")):
        return False
    return str(hit.get("result") or "") in (RESULT_SUCCESS,
                                            RESULT_NO_REFLECTION)


def _record_replay(outcome: AcquisitionOutcome, replay: Any) -> None:
    """Teach the replay ledger what this acquisition learned (§18).

    Only a conclusive outcome is recorded: a timeout, an unavailable
    transport, or an inconclusive read must never become a reason to skip a
    future request.
    """
    if replay is None or outcome.replay.get("reused"):
        return
    if not outcome.evidential:
        return
    try:
        replay.record(
            fingerprint=str(outcome.replay.get("fingerprint") or ""),
            action_id=outcome.action_id, parameter=outcome.parameter,
            result=outcome.result, marker=outcome.marker,
            detection=dict(outcome.detection),
            evidence_excerpt=outcome.evidence_excerpt,
            authorization_id=outcome.authorization_id,
            rule_version=ACQUISITION_RULE_VERSION)
    except Exception:  # noqa: BLE001 - a broken ledger never blocks evidence
        outcome.replay["record_failed"] = True


def _run_acquisition_core(*, action: Any, parameter_ref: rq.ParameterRef,
                    transport: Any = None, authorization: Any = None,
                    budget: Any = None, limits: Mapping[str, Any] | None = None,
                    replay: Any = None,
                    now_fn: Callable[[], float] = time.monotonic
                    ) -> AcquisitionOutcome:
    """Execute one acquisition action.  Never raises; never fakes evidence."""
    bounds = lm.limits_for(limits)
    outcome = AcquisitionOutcome(
        action_id=str(getattr(action, "action_id", "") or ""),
        action_type=str(getattr(action, "action_type", "") or "").upper(),
        parameter=str(getattr(parameter_ref, "parameter", "") or ""),
        limits=bounds)

    if outcome.action_type not in ACQUISITION_ACTIONS:
        outcome.result = RESULT_CAPABILITY_UNAVAILABLE
        outcome.reason = (f"{outcome.action_type} is not an acquisition "
                          f"action")
        return outcome

    ok, why = authorization_allows(action, authorization,
                                   scope_ref=str(getattr(action, "scope_ref",
                                                         "") or ""))
    if not ok:
        outcome.result = RESULT_UNAUTHORIZED
        outcome.reason = why
        return outcome
    outcome.authorization_id = _authorization_ids(authorization)[0]

    refusal = _budget_check(budget, "max_requests",
                            reason=f"acquisition:{outcome.action_id}")
    if refusal:
        outcome.result = RESULT_BUDGET_EXHAUSTED
        outcome.reason = f"the request budget refused the acquisition: {refusal}"
        return outcome

    try:
        marker = mk.marker_for(outcome.action_id, outcome.parameter,
                               int(getattr(action, "attempt", 1) or 1),
                               limits=bounds)
    except mk.MarkerError as exc:
        outcome.result = RESULT_CAPABILITY_UNAVAILABLE
        outcome.reason = f"marker generation refused: {exc}"
        return outcome
    outcome.marker = marker

    fingerprint = replay_fingerprint(action=action,
                                     parameter_ref=parameter_ref,
                                     marker=marker)
    if replay is not None:
        try:
            hit = replay.lookup(fingerprint)
        except Exception:  # noqa: BLE001 - a broken replay store is not a hit
            hit = None
        if hit is not None and _reusable_hit(hit):
            outcome.state = ac.ACTION_SUCCEEDED
            outcome.result = str(hit.get("result") or RESULT_SUCCESS)
            outcome.reason = "an identical, still-valid acquisition was reused"
            outcome.replay = {"fingerprint": fingerprint, "reused": True,
                              "previous_action_id": str(hit.get("action_id")
                                                        or "")}
            outcome.detection = dict(hit.get("detection") or {})
            outcome.context_class = str(hit.get("context_class") or "")
            outcome.response = dict(hit.get("response") or {})
            return outcome
    outcome.replay = {"fingerprint": fingerprint, "reused": False}

    try:
        request = rq.build_request(
            action_id=outcome.action_id, parameter_ref=parameter_ref,
            marker=marker, scope_ref=str(getattr(action, "scope_ref", "") or ""),
            authorization_id=outcome.authorization_id,
            attempt=int(getattr(action, "attempt", 1) or 1), limits=bounds)
    except rq.RequestError as exc:
        outcome.result = RESULT_UNAUTHORIZED if exc.reason in (
            rq.REASON_OUT_OF_SCOPE,) else RESULT_CAPABILITY_UNAVAILABLE
        outcome.reason = f"the controlled request was refused: {exc.reason}"
        return outcome
    outcome.request = request.to_dict()

    resolved = tr.transport_for(transport)
    outcome.transport = str(getattr(resolved, "name", "") or "")
    if not bool(getattr(resolved, "available", False)):
        outcome.result = RESULT_TRANSPORT_UNAVAILABLE
        outcome.reason = ("no authorized transport is available, so no "
                          "request was sent and no evidence was produced")
        return outcome

    started = float(now_fn())
    try:
        response = resolved.send(request)
    except Exception as exc:  # noqa: BLE001 - a failure is never evidence
        outcome.result = RESULT_TRANSPORT_UNAVAILABLE
        outcome.reason = f"the transport raised {type(exc).__name__}"
        return outcome
    outcome.response = response.to_dict()
    outcome.response["headers"] = scrub_response_headers(response.headers)

    if response.outcome == tr.OUTCOME_TIMEOUT:
        outcome.result = RESULT_TIMEOUT
        outcome.reason = "the transport timed out; nothing was learned"
        return outcome
    if response.outcome in (tr.OUTCOME_TRANSPORT_UNAVAILABLE,
                            tr.OUTCOME_TRANSPORT_FAILED,
                            tr.OUTCOME_REFUSED):
        outcome.result = RESULT_TRANSPORT_UNAVAILABLE
        outcome.reason = (response.reason or
                          "the transport did not return a response")
        return outcome

    safe, why, hops = check_redirects(
        response, scope_ref=str(getattr(action, "scope_ref", "") or ""))
    outcome.redirects = hops
    if not safe:
        outcome.result = RESULT_REDIRECT_OUT_OF_SCOPE
        outcome.reason = why
        return outcome

    if response.outcome == tr.OUTCOME_RESPONSE_LIMIT_EXCEEDED:
        outcome.result = RESULT_RESPONSE_LIMIT_EXCEEDED
        outcome.reason = (response.reason or
                          "the response exceeded the configured limit")
        return outcome

    if response.body is None:
        outcome.result = RESULT_RESPONSE_UNAVAILABLE
        outcome.reason = "the transport returned no response body"
        return outcome

    detection = dt.detect(response.body, marker, truncated=response.truncated,
                          limits=bounds)
    outcome.detection = detection.to_dict()
    outcome.context_class = detection.context
    if detection.reflected:
        # an excerpt exists only to locate a reflection: an absence is
        # recorded as a detection summary, never as response content.
        outcome.evidence_excerpt = evidence_excerpt(response.body, marker)
    outcome.state = ac.ACTION_SUCCEEDED
    elapsed = max(0.0, float(now_fn()) - started)

    common = {
        "action_id": outcome.action_id,
        "candidate_id": str(getattr(action, "candidate_id", "") or ""),
        "objective_id": str(getattr(action, "objective_id", "") or ""),
        "scope_ref": str(getattr(action, "scope_ref", "") or ""),
        "where": request.url,
        "under_input": outcome.parameter,
        "under_request": str(outcome.request.get("url") or ""),
        "request_ref": str(response.response_ref or ""),
        "response_ref": str(response.response_ref or ""),
        "marker": marker,
        "job_id": str(getattr(action, "inputs", {}).get("job_id") or ""),
    }
    provenance = {
        "executor": "acquisition_executor",
        "rule_version": ACQUISITION_RULE_VERSION,
        "detector_version": detection.detector_version,
        "context_rule_version": cx.CONTEXT_RULE_VERSION,
        "marker_rule_version": mk.MARKER_RULE_VERSION,
        "transport": outcome.transport,
        "authorization_id": outcome.authorization_id,
        "status_code": response.status_code,
        "bytes_checked": detection.bytes_checked,
        "truncated": bool(response.truncated),
        "elapsed_seconds": round(elapsed, 3),
        "occurrence_count": detection.occurrence_count,
        "offsets": list(detection.offsets),
        "encoding": detection.encoding,
        "transformation": detection.transformation,
        "body_encoding": detection.body_encoding,
        "conclusive": detection.conclusive,
        "evidence_excerpt": outcome.evidence_excerpt,
        "dom_analysis": cx.DOM_ANALYSIS_UNAVAILABLE,
    }

    if detection.reflected and detection.conclusive:
        outcome.result = RESULT_SUCCESS
        outcome.reason = detection.reason
        outcome.observations.append(ob.positive(
            signal="reflection_observed",
            evidence_type="REFLECTION_OBSERVED",
            observed=(f"the controlled marker {marker} was present in the "
                      f"response for parameter {outcome.parameter} "
                      f"({detection.status}, {detection.occurrence_count} "
                      f"occurrence(s), context {detection.context or 'unknown'})"),
            what_happened="an authorized controlled request was sent and the "
                          "response contained the marker",
            context=detection.context, provenance=provenance, **common))
        if outcome.action_type == ac.CLASSIFY_REFLECTION_CONTEXT and \
                detection.context:
            outcome.observations.append(ob.positive(
                signal="output_context_identified",
                evidence_type="OUTPUT_CONTEXT_IDENTIFIED",
                observed=(f"the reflected marker sits in context "
                          f"{detection.context}"),
                what_happened="the reflection location was classified "
                              "deterministically",
                context=detection.context, provenance=provenance, **common))
        return outcome

    if detection.status == dt.ABSENT and detection.conclusive:
        outcome.result = RESULT_NO_REFLECTION
        outcome.reason = detection.reason
        outcome.observations.append(ob.negative(
            signal="reflection_not_observed",
            not_observed=(f"the controlled marker {marker} was not present in "
                          f"the response for parameter {outcome.parameter} "
                          f"({detection.bytes_checked} bytes checked)"),
            what_happened="an authorized controlled request was sent and the "
                          "response was searched for the marker",
            context="", provenance=provenance, **common))
        return outcome

    # inconclusive: truncated body, or an encoded form we cannot place
    outcome.result = RESULT_INCONCLUSIVE
    outcome.reason = detection.reason or "the reflection check was inconclusive"
    outcome.observations.append(ob.not_tested(
        signal="reflection_not_tested",
        not_observed=("the reflection check was inconclusive, so no negative "
                      "conclusion is drawn"),
        what_happened="an authorized controlled request was sent; the result "
                      "was not conclusive",
        provenance=provenance,
        # not_tested() carries under_request, not the *_ref keys
        **{k: v for k, v in common.items()
           if k not in ("request_ref", "response_ref")}))
    return outcome


def replay_fingerprint(*, action: Any, parameter_ref: rq.ParameterRef,
                       marker: str) -> str:
    """The identity of one acquisition (§18): re-planning is idempotent."""
    import hashlib

    seed = "|".join([
        str(getattr(action, "candidate_id", "") or ""),
        str(getattr(action, "action_type", "") or "").upper(),
        str(getattr(parameter_ref, "url", "") or ""),
        str(getattr(parameter_ref, "parameter", "") or ""),
        str(getattr(action, "scope_ref", "") or ""),
        str(marker)[:64],
    ])
    return "aq-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def executor_document() -> dict[str, Any]:
    """The executor's contract, for docs and reports."""
    return {
        "rule_version": ACQUISITION_RULE_VERSION,
        "actions": list(ACQUISITION_ACTIONS),
        "results": list(ACQUISITION_RESULTS),
        "non_evidential_results": sorted(NON_EVIDENTIAL_RESULTS),
        "statement": "transport failure is not negative vulnerability evidence",
        "authorization": "checked when planned and again immediately before "
                         "execution",
        "budget": "consumed before the request is built",
        "evidence": "positive / negative / not-tested observations only",
        "excerpt_radius": EXCERPT_RADIUS,
    }


__all__ = [
    "ACQUISITION_ACTIONS", "ACQUISITION_RESULTS", "ACQUISITION_RULE_VERSION",
    "AcquisitionError", "AcquisitionOutcome", "EXCERPT_RADIUS",
    "NON_EVIDENTIAL_RESULTS", "RESULT_BUDGET_EXHAUSTED",
    "RESULT_CAPABILITY_UNAVAILABLE", "RESULT_INCONCLUSIVE",
    "RESULT_NO_REFLECTION", "RESULT_REDIRECT_OUT_OF_SCOPE",
    "RESULT_RESPONSE_LIMIT_EXCEEDED", "RESULT_RESPONSE_UNAVAILABLE",
    "RESULT_SUCCESS", "RESULT_TIMEOUT", "RESULT_TRANSPORT_UNAVAILABLE",
    "RESULT_UNAUTHORIZED", "authorization_allows", "check_redirects",
    "evidence_excerpt", "executor_document", "replay_fingerprint",
    "run_acquisition", "scrub_response_headers",
]
