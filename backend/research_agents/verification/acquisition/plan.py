"""EPIC13 §2/§4 — from missing evidence to an authorized acquisition action.

    VerificationRequirement
            ↓
    AcquisitionPlan
            ↓
    AuthorizedAcquisitionAction   (an EPIC12 typed action, reused)

Every acquisition carries a reason: the plan records *which* missing evidence
item each action is meant to produce, and an action is never created for
evidence the runtime cannot acquire.  Those become explicit
``capability_unavailable`` entries instead, so "we cannot do this" is visible
rather than silently absent.

Per §17, a candidate with several parameters yields one action per parameter,
each with its own deterministic action id and its own marker, so evidence from
one parameter can never be read as evidence about another.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from backend.research_agents.verification import actions as ac
from backend.research_agents.verification.acquisition import limits as lm

from . import capabilities as cap
from . import limits as lm
from . import markers as mk
from . import requests as rq
from . import transport as tr

PLAN_RULE_VERSION = "epic13-acquisition-plan-1"

#: missing evidence type -> the acquisition action that can produce it.
ACQUISITION_FOR_EVIDENCE: dict[str, str] = {
    "REFLECTION_OBSERVED": ac.SEND_MARKER,
    "OUTPUT_CONTEXT_IDENTIFIED": ac.CLASSIFY_REFLECTION_CONTEXT,
}

#: evidence the runtime genuinely cannot acquire, with the reason.
UNAVAILABLE_EVIDENCE: dict[str, str] = {
    "PAYLOAD_EXECUTION": ("no payload-execution lane exists in this runtime: "
                          "the platform's live execution gate is closed and "
                          "this layer never synthesises execution evidence"),
    "EXPLOITABILITY_ESTABLISHED": ("exploitability requires observed execution "
                                   "or impact evidence, neither of which this "
                                   "runtime can produce"),
    "DOM_SINK_IDENTIFIED": ("DOM analysis is unavailable: no browser is "
                            "launched in this runtime "
                            "(DOM_ANALYSIS_UNAVAILABLE)"),
    "IMPACT_ESTABLISHED": ("impact evidence requires execution or a knowledge "
                           "reference; neither is acquirable here"),
}


def _field(chain_state: Any, name: str, default: Any = "") -> Any:
    """Read one field from a chain state (mapping or object), safely."""
    if isinstance(chain_state, Mapping):
        return chain_state.get(name, default)
    return getattr(chain_state, name, default)


@dataclass
class AcquisitionRequirement:
    """One missing evidence item that acquisition might produce."""

    candidate_id: str
    objective_id: str
    scope_ref: str
    evidence_type: str
    parameter: str = ""
    url: str = ""
    method: str = "GET"
    reason: str = ""
    action_type: str = ""
    available: bool = False
    unavailable_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "objective_id": self.objective_id, "scope_ref": self.scope_ref,
            "evidence_type": self.evidence_type, "parameter": self.parameter,
            "url": rq._redact_url(self.url), "method": self.method,
            "reason": self.reason, "action_type": self.action_type,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass
class AcquisitionPlan:
    """The planned acquisitions for one candidate (never executed here)."""

    candidate_id: str = ""
    objective_id: str = ""
    scope_ref: str = ""
    chain_id: str = ""
    actions: list[Any] = field(default_factory=list)
    requirements: list[AcquisitionRequirement] = field(default_factory=list)
    blocked: list[dict[str, Any]] = field(default_factory=list)
    unavailable: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    limits: dict[str, int] = field(default_factory=dict)
    rule_version: str = PLAN_RULE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "objective_id": self.objective_id, "scope_ref": self.scope_ref,
            "chain_id": self.chain_id,
            "actions": [a.to_dict() if hasattr(a, "to_dict") else dict(a)
                        for a in self.actions],
            "requirements": [r.to_dict() for r in self.requirements],
            "blocked": list(self.blocked), "unavailable": list(self.unavailable),
            "parameters": list(self.parameters), "limits": dict(self.limits),
            "rule_version": self.rule_version,
        }


def requirements_from_chain(chain_state: Any, *,
                            parameters: Sequence[Mapping[str, Any]] = (),
                            candidate_id: str = "", objective_id: str = "",
                            scope_ref: str = "", chain_id: str = "",
                            ) -> list[AcquisitionRequirement]:
    """Derive acquisition requirements from a chain's missing evidence.

    The chain state itself carries no candidate/objective identity (it is the
    chain view only), so the caller passes the identity it already holds; the
    chain state is consulted as a fallback.
    """
    candidate_id = str(candidate_id or _field(chain_state, "candidate_id"))
    objective_id = str(objective_id or _field(chain_state, "objective_id"))
    scope_ref = str(scope_ref or _field(chain_state, "scope_ref"))
    chain_id = str(chain_id or _field(chain_state, "chain_id"))
    # §16: the loop acquires the *next* missing evidence item, re-evaluates,
    # then acquires the next one.  Planning every missing item at once would
    # send requests for stages the current evidence has not reached yet.
    missing = list(getattr(chain_state, "next_stage_missing_types", ()) or ())
    if not missing:
        missing = list(getattr(chain_state, "missing_evidence_types", ()) or ())

    out: list[AcquisitionRequirement] = []
    for evidence_type in missing:
        wanted = str(evidence_type).upper()
        action_type = ACQUISITION_FOR_EVIDENCE.get(wanted, "")
        unavailable = UNAVAILABLE_EVIDENCE.get(wanted, "")
        if not action_type and not unavailable:
            unavailable = (f"no acquisition action is defined for {wanted}")
        if not action_type:
            out.append(AcquisitionRequirement(
                candidate_id=candidate_id, objective_id=objective_id,
                scope_ref=scope_ref, evidence_type=wanted,
                reason=f"required by chain {chain_id or '(unnamed)'}",
                available=False, unavailable_reason=unavailable))
            continue
        for parameter in list(parameters or [])[:1] or [{}]:
            name = str(dict(parameter).get("parameter")
                       or dict(parameter).get("name") or "")
            url = str(dict(parameter).get("url") or "")
            method = str(dict(parameter).get("method") or "GET").upper()
            out.append(AcquisitionRequirement(
                candidate_id=candidate_id, objective_id=objective_id,
                scope_ref=scope_ref, evidence_type=wanted, parameter=name,
                url=url, method=method,
                reason=(f"{wanted} is missing for chain "
                        f"{chain_id or '(unnamed)'}"),
                action_type=action_type, available=bool(url and name),
                unavailable_reason=("" if (url and name) else
                                    "no observed parameter/URL was supplied "
                                    "for this candidate")))
    return out


def plan_acquisition(*, chain_state: Any, parameters: Iterable[Mapping[str, Any]],
                     authorization: Any = None, limits: Mapping[str, Any] | None = None,
                     job_id: str = "", candidate_id: str = "",
                     objective_id: str = "", scope_ref: str = "",
                     chain_id: str = "") -> AcquisitionPlan:
    """Build the plan for one candidate.  Deterministic; nothing is sent."""
    bounds = lm.limits_for(limits)
    candidate_id = str(candidate_id or _field(chain_state, "candidate_id"))
    objective_id = str(objective_id or _field(chain_state, "objective_id"))
    scope_ref = str(scope_ref or _field(chain_state, "scope_ref"))
    chain_id = str(chain_id or _field(chain_state, "chain_id"))
    plan = AcquisitionPlan(
        candidate_id=candidate_id, objective_id=objective_id,
        scope_ref=scope_ref, chain_id=chain_id, limits=bounds)

    param_rows = [dict(p) for p in list(parameters or [])][
        :int(bounds.get("max_parameters", 8))]
    plan.parameters = [str(p.get("parameter") or p.get("name") or "")
                       for p in param_rows]

    requirements = requirements_from_chain(
        chain_state, parameters=param_rows, candidate_id=candidate_id,
        objective_id=objective_id, scope_ref=scope_ref, chain_id=chain_id)
    if not requirements:
        plan.blocked.append({
            "reason": "the chain reports no missing evidence that acquisition "
                      "could produce",
            "blocked_reason": "no_missing_evidence"})
    # a requirement with a parameter needs one requirement per parameter
    expanded: list[AcquisitionRequirement] = []
    for req in requirements:
        if req.action_type and req.available:
            for row in param_rows or [{}]:
                name = str(row.get("parameter") or row.get("name") or "")
                url = str(row.get("url") or "")
                expanded.append(AcquisitionRequirement(
                    candidate_id=req.candidate_id,
                    objective_id=req.objective_id, scope_ref=req.scope_ref,
                    evidence_type=req.evidence_type, parameter=name, url=url,
                    method=str(row.get("method") or "GET").upper(),
                    reason=req.reason, action_type=req.action_type,
                    available=bool(url and name),
                    unavailable_reason=("" if (url and name) else
                                        "no observed parameter/URL was "
                                        "supplied for this candidate")))
        else:
            expanded.append(req)
    plan.requirements = expanded

    # §12: authorization is checked when the acquisition is *planned*.  With
    # no authorization reference there is nothing to plan: every acquirable
    # requirement is recorded as blocked instead of being planned and then
    # refused at execution time.
    if not _authorization_ids(authorization):
        for req in expanded:
            if req.action_type and req.available:
                plan.blocked.append({
                    "evidence_type": req.evidence_type,
                    "parameter": req.parameter,
                    "blocked_reason": "authorization_unavailable",
                    "reason": ("no authorization reference covers this target, "
                               "so no acquisition action can be planned")})
        return plan

    # the acquisition that produces new evidence comes first: a plan must not
    # spend its action budget on classification before the reflection probe.
    priority = {ac.SEND_MARKER: 0, ac.CHECK_REFLECTION: 1}
    expanded = sorted(expanded, key=lambda r: priority.get(r.action_type, 2))

    seen: set[str] = set()
    for req in expanded:
        if not req.action_type:
            plan.unavailable.append({
                "evidence_type": req.evidence_type, "parameter": req.parameter,
                "reason": req.unavailable_reason or "capability unavailable"})
            continue
        if not req.available:
            plan.blocked.append({
                "evidence_type": req.evidence_type, "parameter": req.parameter,
                "blocked_reason": "no_observed_parameter",
                "reason": req.unavailable_reason})
            continue
        if len(plan.actions) >= int(bounds.get("max_actions", 3)):
            plan.blocked.append({
                "evidence_type": req.evidence_type, "parameter": req.parameter,
                "blocked_reason": "max_actions_reached",
                "reason": f"the plan already holds {len(plan.actions)} action(s)"})
            continue
        auth_ids = _authorization_ids(authorization)
        if auth_ids is None:  # pragma: no cover - defensive
            auth_ids = ()
        try:
            action = build_action(req, job_id=job_id,
                                  authorization_id=(auth_ids[0] if auth_ids
                                                    else ""))
        except Exception as exc:  # noqa: BLE001 - a refusal is not an action
            blocked_reason = type(exc).__name__
            detail = str(exc)[:200]
            if "authorization" in detail.lower():
                blocked_reason = "authorization_unavailable"
            plan.blocked.append({
                "evidence_type": req.evidence_type, "parameter": req.parameter,
                "blocked_reason": blocked_reason, "reason": detail})
            continue
        key = f"{action.action_id}|{req.parameter}"
        if key in seen:
            plan.blocked.append({
                "evidence_type": req.evidence_type, "parameter": req.parameter,
                "blocked_reason": "duplicate_action",
                "reason": "an identical action is already planned"})
            continue
        seen.add(key)
        plan.actions.append(action)
    return plan


def _authorization_ids(authorization: Any) -> tuple[str, ...]:
    """The authorization references a caller-supplied authorization carries."""
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


def build_action(requirement: AcquisitionRequirement, *,
                 job_id: str = "", authorization_id: str = "") -> Any:
    """Build one EPIC12 typed action for an acquisition requirement.

    An action whose safety class requires authorization (SEND_MARKER) cannot
    even be constructed without a reference: EPIC12's action model refuses it,
    and that refusal is the correct fail-closed behaviour (§12).
    """
    marker = mk.marker_for(
        ac.action_id_for(candidate_id=requirement.candidate_id,
                         objective_id=requirement.objective_id,
                         action_type=requirement.action_type, attempt=1,
                         salt=requirement.parameter),
        requirement.parameter, 1)
    action_id = ac.action_id_for(
        candidate_id=requirement.candidate_id,
        objective_id=requirement.objective_id,
        action_type=requirement.action_type, attempt=1,
        salt=requirement.parameter)
    return ac.VerificationAction(
        action_type=requirement.action_type,
        candidate_id=requirement.candidate_id,
        objective_id=requirement.objective_id,
        scope_ref=requirement.scope_ref,
        target=requirement.url,
        action_id=action_id,
        authorization_id=str(authorization_id or ""),
        inputs={"parameter": requirement.parameter, "url": requirement.url,
                "marker": marker, "method": requirement.method,
                "job_id": job_id,
                "required_evidence": requirement.evidence_type,
                "reason": requirement.reason},
        provenance={"planner": "epic13_acquisition_planner",
                    "rule_version": PLAN_RULE_VERSION,
                    "missing_evidence": requirement.evidence_type,
                    "marker": marker,
                    "marker_rule_version": mk.MARKER_RULE_VERSION})


def capability_matrix() -> list[dict[str, Any]]:
    """What acquisition can genuinely do per class (§21) — one source of truth."""
    return cap.capability_matrix()


def plan_document() -> dict[str, Any]:
    """The planning contract, for docs and reports."""
    return {
        "rule_version": PLAN_RULE_VERSION,
        "evidence_to_action": dict(ACQUISITION_FOR_EVIDENCE),
        "unavailable_evidence": dict(UNAVAILABLE_EVIDENCE),
        "per_parameter_isolation": True,
        "capability_matrix": capability_matrix(),
        "transport_methods": list(tr.ALLOWED_METHODS),
    }


__all__ = [
    "ACQUISITION_FOR_EVIDENCE", "AcquisitionPlan", "AcquisitionRequirement",
    "PLAN_RULE_VERSION", "UNAVAILABLE_EVIDENCE", "build_action",
    "capability_matrix", "plan_acquisition", "plan_document",
    "requirements_from_chain",
]
