"""backend/prod_intel/effectiveness.py — hunt/campaign operational learning.

DESCRIPTIVE operational intelligence only. Hard rules enforced here:

* every rate carries an EXPLICIT numerator and denominator semantics;
* a 0 denominator => ``rate=None`` + ``insufficient_population`` — never
  0%, never "0% conversion";
* no agent is labelled better/worse; no ranking score exists;
* correlation only — the output says so structurally;
* failed attempts are counted as failures, never as successful work.
"""

from __future__ import annotations

from typing import Any

from backend.prod_intel import sources
from backend.prod_intel.semantics import (
    DEFAULT_WINDOW_HOURS,
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    in_window,
    metric,
    rate,
    window_bounds,
)

_VERIF_BLOCKED = frozenset({"BLOCKED", "FAILED"})
_VERIF_COMPLETED = frozenset({"VERIFIED", "REJECTED", "INCONCLUSIVE",
                              "FAILED", "EXPIRED"})


def effectiveness(*, hours: float | int | None = DEFAULT_WINDOW_HOURS
                  ) -> dict[str, Any]:
    """Funnels + raw stage counts over persisted operational records."""
    iso_lower, window = window_bounds(hours)

    # ---------------- hunt operational stages ----------------------------
    hunt_env = sources.hunt_objectives()
    objs = hunt_env["data"] or [] if hunt_env["state"] == "ok" else []
    obj_created = len(objs)
    obj_resolved = sum(1 for o in objs if str(o.state) == "RESOLVED")
    obj_blocked = sum(1 for o in objs if str(o.state) == "BLOCKED")
    obj_rejected = sum(1 for o in objs if str(o.state) == "REJECTED")
    plans_created = sum(int(getattr(o, "plans_created", 0) or 0)
                         for o in objs)
    replans = 0
    _walk_unavailable: list[str] = []
    if objs and hunt_env["state"] == "ok":
        for o in objs[:200]:                       # bounded per-object read
            plans_env = sources.hunt_plans(o.objective_id)
            if plans_env["state"] == "ok":
                replans += sum(1 for p in plans_env["data"]
                               if int(getattr(p, "version", 1) or 1) > 1)
            else:
                _walk_unavailable.append(
                    f"plans:{o.objective_id}"
                    + (f" ({plans_env['reason']})"
                       if plans_env.get("reason") else ""))
    observations = sum(int(getattr(o, "observations_run", 0) or 0)
                       for o in objs)

    # authorizations: bounded walk over plans of enumerated objectives
    auth_requested = auth_granted = auth_denied = 0
    if hunt_env["state"] == "ok":
        for o in objs[:200]:
            plans_env = sources.hunt_plans(o.objective_id)
            if plans_env["state"] != "ok":
                _walk_unavailable.append(
                    f"plans:{o.objective_id}"
                    + (f" ({plans_env['reason']})"
                       if plans_env.get("reason") else ""))
                continue                            # cannot reach auths
            for p in (plans_env["data"] or []):
                auths_env = sources.hunt_authorizations(p.plan_id)
                if auths_env["state"] != "ok":
                    _walk_unavailable.append(
                        f"auths:{p.plan_id}"
                        + (f" ({auths_env['reason']})"
                           if auths_env.get("reason") else ""))
                    continue
                for a in (auths_env["data"] or []):
                    auth_requested += 1
                    if str(a.status).upper() == "GRANTED":
                        auth_granted += 1
                    else:
                        auth_denied += 1

    # an unreadable plans/authorizations walk must read unavailable —
    # zero authorization counts from a down store are not observations
    hunt_state = (UNAVAILABLE if _walk_unavailable
                  else OK if hunt_env["state"] == "ok" else UNAVAILABLE)
    hunt_stages = metric(
        {"objectives_created": obj_created, "objectives_resolved": obj_resolved,
         "objectives_blocked": obj_blocked, "objectives_rejected": obj_rejected,
         "plans_created": plans_created, "plans_replanned": replans,
         "authorizations_requested": auth_requested,
         "authorizations_granted": auth_granted,
         "authorizations_denied": auth_denied,
         "observations_produced": observations},
        source="hunt.store objectives/plans/authorizations",
        population="latest-revision hunt objectives (bounded ≤200) and "
                   "their plans/authorizations",
        aggregation="state counts + summed per-objective counters",
        time_range=window, state=hunt_state,
        reason=(hunt_env["reason"] or "") +
               (("; unreadable: " + ", ".join(sorted(set(_walk_unavailable))[:5]))
                if _walk_unavailable else ""),
        unavailable_walks=sorted(set(_walk_unavailable)))

    # ---------------- finding stages --------------------------------------
    cand_env = sources.candidates()
    cands = cand_env["data"] or [] if cand_env["state"] == "ok" else []
    cand_total = len(cands)
    cand_dedup = sum(1 for c in cands if str(c.lifecycle_state) == "DUPLICATE")
    cand_rejected = sum(1 for c in cands
                        if str(c.lifecycle_state) == "REJECTED")
    cand_states: dict[str, int] = {}
    for c in cands:
        cand_states[str(c.lifecycle_state)] = (
            cand_states.get(str(c.lifecycle_state), 0) + 1)

    ver_env = sources.verifications()
    vers = ver_env["data"] or [] if ver_env["state"] == "ok" else []
    ver_started = len(vers)
    ver_blocked = sum(1 for v in vers if str(v.state) in _VERIF_BLOCKED)
    ver_completed = sum(1 for v in vers if str(v.state) in _VERIF_COMPLETED)
    ver_states: dict[str, int] = {}
    for v in vers:
        ver_states[str(v.state)] = ver_states.get(str(v.state), 0) + 1

    fc_env = sources.finding_cases()
    fcases = fc_env["data"] or [] if fc_env["state"] == "ok" else []
    cases_created = len(fcases)
    cases_handed_off = sum(1 for c in fcases
                           if str(c.state) in ("HANDED_OFF", "READY_FOR_REVIEW"))
    case_states: dict[str, int] = {}
    for c in fcases:
        case_states[str(c.state)] = case_states.get(str(c.state), 0) + 1

    ev_env = sources.evidence()
    observations_recorded = len(ev_env["data"] or []) \
        if ev_env["state"] == "ok" else None

    # ---------------- explicit-denominator funnels -------------------------
    funnels = {
        "observation_to_candidate": rate(
            cand_total, int(observations_recorded or 0),
            source="runtime.evidence -> finding.candidates",
            numerator_semantics="candidate findings persisted",
            denominator_semantics="evidence rows recorded by the runtime "
                                  "(typed observations)",
            time_range=window),
        "candidate_to_verification": rate(
            ver_started, cand_total,
            source="finding.candidates -> finding.verifications",
            numerator_semantics="verification objectives created",
            denominator_semantics="candidate findings persisted",
            time_range=window),
        "verification_to_case": rate(
            cases_created, ver_started,
            source="finding.verifications -> finding.cases",
            numerator_semantics="finding case packages created",
            denominator_semantics="verification objectives created",
            time_range=window),
        "case_to_handoff": rate(
            cases_handed_off, cases_created,
            source="finding.cases (HANDED_OFF/READY_FOR_REVIEW)",
            numerator_semantics="cases in HANDED_OFF or READY_FOR_REVIEW",
            denominator_semantics="finding case packages created",
            time_range=window),
        "objective_to_observation": rate(
            observations, obj_created,
            source="hunt.store objectives.observations_run",
            numerator_semantics="observations_run summed across objectives",
            denominator_semantics="hunt objectives created",
            time_range=window),
        "authorization_grant": rate(
            auth_granted, auth_requested,
            source="hunt.store authorizations",
            numerator_semantics="authorization records with status GRANTED",
            denominator_semantics="authorization records requested",
            time_range=window),
    }

    # A funnel whose source store is unreadable is UNAVAILABLE — it must
    # not masquerade as "insufficient_population" (which would imply the
    # data said the population was zero).
    _funnel_deps = {
        "observation_to_candidate": (("runtime.evidence", ev_env),
                                     ("finding.candidates", cand_env)),
        "candidate_to_verification": (("finding.candidates", cand_env),
                                      ("finding.verifications", ver_env)),
        "verification_to_case": (("finding.verifications", ver_env),
                                 ("finding.cases", fc_env)),
        "case_to_handoff": (("finding.cases", fc_env),),
        "objective_to_observation": (("hunt.store", hunt_env),),
        "authorization_grant": (("hunt.store", hunt_env),),
    }
    for _fname, _deps in _funnel_deps.items():
        _down = [f"{label} ({e['reason']})" if e.get("reason") else label
                 for label, e in _deps if e["state"] != "ok"]
        if _down:
            funnels[_fname] = {
                **funnels[_fname],
                "rate": None,
                "state": UNAVAILABLE,
                "reason": "source unavailable: " + ", ".join(_down),
            }

    any_source = any(e["state"] == "ok" for e in
                     (cand_env, ver_env, fc_env, hunt_env, ev_env))
    return {
        "rule_version": "production-intelligence-v1",
        "window": window,
        "state": OK if any_source else UNAVAILABLE,
        "reason": "; ".join(e["reason"] for e in
                            (cand_env, ver_env, fc_env, hunt_env, ev_env)
                            if e["state"] != "ok")[:300],
        "hunt": hunt_stages,
        "finding": metric(
            {"candidates_produced": cand_total,
             "candidates_by_state": cand_states,
             "candidates_deduplicated": cand_dedup,
             "candidates_rejected": cand_rejected,
             "verifications_started": ver_started,
             "verifications_by_state": ver_states,
             "verifications_blocked": ver_blocked,
             "verifications_completed": ver_completed,
             "cases_created": cases_created,
             "cases_by_state": case_states,
             "cases_handed_off": cases_handed_off,
             "observations_recorded": observations_recorded},
            source="finding.store + runtime.evidence",
            population="persisted finding-family records + runtime evidence "
                       "rows",
            aggregation="counts by persisted state; failed/blocked rows "
                        "counted as failures, never as successful work",
            time_range=window,
            state=OK if (cand_env["state"] == "ok"
                         or ver_env["state"] == "ok") else UNAVAILABLE,
            reason=(cand_env["reason"] or "") + (ver_env["reason"] or "")),
        "funnels": funnels,
        "interpretation": (
            "descriptive operational measurement; denominators explicit; "
            "insufficient population stays insufficient; correlation is "
            "not causation; no agent quality ranking is produced"),
        "sufficient_population": {
            k: v["state"] == OK for k, v in funnels.items()},
    }
