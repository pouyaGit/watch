"""backend/soc/findings.py — Finding Verification & Triage projections.

Read-only SOC views over the finding store: candidate index, candidate
detail (hypothesis, evidence quality, missing evidence, related
candidates, verification objective/plan, gate decision, reasoning,
limitations) and the analyst case package.  Nothing here mutates state
and nothing invents a verdict — every field comes from persisted rows,
the authoritative gate record, or explicitly-labelled advisory output.
"""

from __future__ import annotations

from typing import Any

from backend.soc._util import _bounded, _text


def _store() -> Any:
    from backend.research_agents.finding.store import FindingStore
    from backend.research_agents.runtime_store import default_store

    store = default_store()
    return FindingStore(store.base), store


def _linked(cand: Any) -> list[str]:
    """Linked duplicate ids (persisted in the correlation dict — the
    CandidateFinding model has no separate linked_duplicates field)."""
    corr = cand.correlation if isinstance(cand.correlation, dict) else {}
    return [str(x) for x in (corr.get("linked_duplicates") or [])]


def _case_state_kind(state: str) -> str:
    if state in ("VERIFIED", "READY_FOR_REVIEW", "HANDED_OFF"):
        return "verified-case"
    if state in ("REJECTED", "INCONCLUSIVE", "DUPLICATE", "BLOCKED"):
        return f"candidate-case:{state.lower()}"
    return "candidate-case"


def _runtime_auth_ids(store: Any, job_id: str) -> list[str]:
    """Authoritative GRANTED authorization ids for a verification job.

    The hunt_authorization audit rows are the source of truth (round-2
    production fix: stored objectives written before harvest carry an
    empty list, so projections derive the real ids — never invent them).
    """
    if not job_id:
        return []
    try:
        ids = [str(r.get("auth_id") or "")
               for r in store.audit_events(limit=5000)
               if r.get("event") == "hunt_authorization"
               and str(r.get("job_id") or "") == job_id
               and r.get("auth_id")]
        return [x for x in dict.fromkeys(ids) if x]
    except Exception:  # noqa: BLE001 - honest empty, never invented
        return []


def _runtime_gate_case(store: Any, job_id: str) -> str:
    """Runtime case id the Evidence Gate created for this job
    (finding_verification_gate_decided audit row)."""
    if not job_id:
        return ""
    try:
        rows = store.audit_events(limit=5000)
    except Exception:  # noqa: BLE001 - honest empty
        return ""
    for row in reversed(rows):
        if (row.get("event") == "finding_verification_gate_decided"
                and str(row.get("job_id") or "") == job_id
                and row.get("case_id")):
            return str(row.get("case_id"))
    return ""


def findings_index() -> dict[str, Any]:
    """Candidates page: every persisted candidate, honest lifecycle."""
    rows: list[dict[str, Any]] = []
    state_counts: dict[str, int] = {}
    verified = duplicates = active = cases_total = 0
    try:
        fs, _runtime = _store()
        for cand in fs.list_candidates():
            vers = fs.list_verifications(candidate_id=cand.candidate_id)
            ver = vers[-1] if vers else None
            case = fs.cases_for_candidate(cand.candidate_id)
            state_counts[cand.lifecycle_state] = \
                state_counts.get(cand.lifecycle_state, 0) + 1
            if cand.lifecycle_state == "VERIFIED":
                verified += 1
            if cand.lifecycle_state == "DUPLICATE":
                duplicates += 1
            if cand.lifecycle_state in ("VERIFICATION_PLANNED",
                                        "VERIFICATION_PENDING",
                                        "VERIFYING"):
                active += 1
            if case is not None:
                cases_total += 1
            rows.append({
                "candidate_id": cand.candidate_id,
                "vulnerability_class": cand.vulnerability_class,
                "specialist": cand.specialist,
                "target": cand.target,
                "endpoint": cand.endpoint.get("url", "") if isinstance(
                    cand.endpoint, dict) else _text(cand.endpoint),
                "state": cand.lifecycle_state,
                "verification_state": ver.state if ver else "",
                "verification_id": ver.verification_id if ver else "",
                "gate_reason": (ver.gate_reason if ver else "") or "",
                "evidence_count": len(cand.evidence_refs or []),
                "missing_count": len(cand.missing_evidence or []),
                "duplicate_status": (
                    "duplicate of " + _text(cand.duplicate_of)
                    if cand.duplicate_of else (
                        f"canonical ({len(_linked(cand))} linked)"
                        if _linked(cand) else "")),
                "severity": cand.severity,
                "severity_provenance": cand.severity_provenance,
                "priority": int(cand.provenance.get("triage_priority", 0)
                                if isinstance(cand.provenance, dict) else 0),
                "case_id": case.case_id if case else "",
                "case_state": case.state if case else "",
                "last_verification": (
                    getattr(ver, "completed_at", "") if ver else "")
                or (ver.updated_at if ver else "") or cand.updated_at,
                "detail_url": f"/ui/soc/findings/{cand.candidate_id}",
            })
    except Exception as exc:  # noqa: BLE001 - honest degradation
        return {"count": 0, "candidates": [], "state_counts": {},
                "verified_count": 0, "duplicate_count": 0,
                "active_count": 0, "case_count": 0,
                "source_available": False,
                "error": f"{type(exc).__name__}: "
                         f"{_bounded(str(exc), 200)}"}
    return {
        "count": len(rows),
        "candidates": _bounded(rows, 100),
        "state_counts": state_counts,
        "verified_count": verified,
        "duplicate_count": duplicates,
        "active_count": active,
        "case_count": cases_total,
        "source_available": True,
    }


def _hunt_bundle(runtime_store: Any, job_id: str) -> dict[str, Any]:
    """Real Hunt Planner plans/observations for a verification job."""
    if not job_id:
        return {}
    try:
        from backend.research_agents.hunt.store import HuntStore

        hs = HuntStore(runtime_store.base)
        objs = hs.objectives_for_job(job_id)
        if not objs:
            return {}
        bundle = hs.objective_bundle(objs[-1].objective_id) or {}
        plans = bundle.get("plans") or []
        observations = bundle.get("observations") or []
        return {
            "objective_id": objs[-1].objective_id,
            "state": objs[-1].state,
            "hypothesis": objs[-1].hypothesis,
            "termination_reason": objs[-1].termination_reason,
            "termination_detail": objs[-1].termination_detail,
            "plans": [{
                "plan_id": _text(p.get("plan_id")),
                "target": _text(p.get("target")),
                "observation_types": list(p.get("observation_types")
                                          or [])[:6],
                "state": _text(p.get("state")),
            } for p in plans[:6]],
            "observations": [{
                "id": _text(o.get("id")),
                "type": _text(o.get("type")),
                "state": _text(o.get("state")),
                "result_ref": _text(o.get("result_ref")),
            } for o in observations[:10]],
        }
    except Exception:
        return {}


def finding_detail(candidate_id: str) -> dict[str, Any] | None:
    """Candidate detail: everything Phase 15 asks, from persisted state."""
    candidate_id = _text(candidate_id)
    if not candidate_id:
        return None
    try:
        fs, runtime = _store()
        cand = fs.get_candidate(candidate_id)
        if cand is None:
            return None
        vers = fs.list_verifications(candidate_id=candidate_id)
        ver = vers[-1] if vers else None
        case = fs.cases_for_candidate(candidate_id)
        correlations = fs.list_correlations(candidate_id=candidate_id)
        # lineage == persisted transition rows (store writes one per
        # transition; runtime audit.jsonl also carries the full
        # finding_lineage event — Phase 16)
        lineage = fs.lineage_for(candidate_id)
        transitions = [
            row for row in fs.all_transitions()
            if _text(row.get("kind")) in ("", "candidate")
            and _text(row.get("id")) == candidate_id
        ][:24]
    except Exception:
        return None

    # ---- evidence with deterministic quality metadata (Phase 9) -------
    evidence: list[dict[str, Any]] = []
    ver_job = ver.job_id if ver else ""
    try:
        from backend.research_agents.finding.quality import classify_batch

        rows = runtime.list_evidence(job_id=cand.source_job)
        if ver_job:
            rows = rows + runtime.list_evidence(job_id=ver_job)
        qualities = {q.evidence_id: q for q in classify_batch(
            rows, vulnerability_class=cand.vulnerability_class,
            verification_job_ids=[ver_job] if ver_job else [])}
        for row in rows:
            q = qualities.get(_text(row.get("id")))
            evidence.append({
                "id": _text(row.get("id")),
                "type": _text(row.get("type")),
                "category": _text(row.get("category")),
                "signal": _text(row.get("signal")),
                "label": _text(row.get("label")),
                "detail": _text(row.get("detail"), 300),
                "confidence": _text(row.get("confidence")),
                "observation_ref": _text(row.get("observation_ref")),
                "created_at": _text(row.get("created_at")),
                "job_id": _text(row.get("job_id")),
                "reliability": q.reliability_class if q else "",
                "directness": ("direct" if q and q.direct
                               else "indirect" if q else ""),
                "stance": q.stance if q else "",
                "verification_relevance": (q.verification_relevance
                                           if q else ""),
            })
    except Exception:
        evidence = []

    # ---- gate decision + reasoning (authoritative) --------------------
    gate: dict[str, Any] = {}
    decision_lineage: dict[str, Any] = {}
    for row in lineage:
        if str(row.get("kind") or "") == "candidate" and str(
                row.get("new") or "") in (
                "VERIFIED", "REJECTED", "INCONCLUSIVE", "BLOCKED"):
            decision_lineage = row
    if decision_lineage:
        gate = {
            "decision": _text(decision_lineage.get("new")),
            "gate_reason": _text(ver.gate_reason) if ver else "",
            "reason": _text(decision_lineage.get("reason")),
            "case_id": _text(decision_lineage.get("case_id")),
            "decided_at": _text(decision_lineage.get("at")),
        }
    if not gate and ver and ver.decision:
        gate = {"decision": ver.decision,
                "gate_reason": ver.gate_reason,
                "reason": ver.termination_reason, "case_id": "",
                "decided_at": ver.completed_at or ver.updated_at}
    if gate:
        # Round-2 production fix: transition rows carry no case id and the
        # gate's runtime case lives in the audit — resolve a real link
        # (runtime gate case first, then the finding case package) so the
        # detail page never shows an empty gate case for a decided gate.
        runtime_gate_case = _runtime_gate_case(
            runtime, ver.job_id if ver else "")
        gate["case_id"] = (str(gate.get("case_id") or "")
                           or runtime_gate_case
                           or _text(cand.case_id))
        gate["finding_case_id"] = _text(cand.case_id)
        gate["runtime_case_id"] = runtime_gate_case

    # ---- related candidates / duplicates -----------------------------
    related: list[dict[str, Any]] = []
    for corr in correlations:
        other = corr.get("right_id") if corr.get("left_id") \
            == candidate_id else corr.get("left_id")
        related.append({
            "other_candidate_id": _text(other),
            "relation": _text(corr.get("relation")),
            "reasons": [str(x) for x in (corr.get("reasons") or [])][:8],
            "canonical_id": _text(corr.get("canonical_id")),
        })
    linked = _linked(cand)

    # ---- hunt / verification plan (existing planner output) ----------
    hunt_bundle = _hunt_bundle(runtime, ver_job)

    # ---- advisory output, clearly labelled (never authoritative) ------
    advisor: dict[str, Any] = {}
    if ver and isinstance(ver.provenance, dict):
        raw = ver.provenance.get("advisor")
        if isinstance(raw, dict):
            advisor = {
                "advisory_only": True,
                "note": ("LLM advisory output. Not authoritative — the "
                         "Evidence Gate decided this candidate's state."),
                "candidate_interpretation": _text(
                    raw.get("candidate_interpretation"), 400),
                "missing_evidence": [str(x) for x in
                                     (raw.get("missing_evidence")
                                      or [])][:8],
                "verification_recommendations": [
                    str(x) for x in
                    (raw.get("verification_recommendations") or [])][:8],
                "conflicting_evidence": [str(x) for x in
                                         (raw.get("conflicting_evidence")
                                          or [])][:6],
                "related_cases": [str(x) for x in
                                  (raw.get("related_cases") or [])][:6],
                "confidence": _text(raw.get("confidence")),
                "blockers": [str(x) for x in
                             (raw.get("blockers") or [])][:6],
                "model_requested": _text(raw.get("model_requested")),
                "model_resolved": _text(raw.get("model_resolved")),
                "used": bool(raw.get("used")),
                "error": _text(raw.get("error")),
            }

    # ---- case package / handoff readiness ----------------------------
    package = case.package if case is not None else {}
    handoff = {}
    if case is not None:
        try:
            from backend.research_agents.finding.case_package import (
                handoff_view,
            )
            from backend.research_agents.finding.gate import (
                VerificationDecision,
            )
            # reconstruct ONLY from persisted, truthful state — an
            # undecided case yields an empty decision (never invented)
            dec_state = (ver.decision if ver is not None and ver.decision
                         else "") or (
                case.state if case.state in ("VERIFIED", "REJECTED",
                                             "INCONCLUSIVE", "BLOCKED")
                else "")
            decision = VerificationDecision(
                verification_state=dec_state,
                candidate_state=cand.lifecycle_state,
                reason=(ver.termination_reason if ver is not None
                        else "") or (
                    case.recommended_next_step and "package_ready"
                    or "verification_pending"),
                gate_reason=(ver.gate_reason if ver is not None else "")
                or case.gate_result,
                created_case=bool(case.gate_result),
            )
            handoff = handoff_view(case=case, candidate=cand,
                                   verification=ver, decision=decision)
        except Exception:
            handoff = {}

    missing = [dict(m) if isinstance(m, dict) else _text(m)
               for m in (cand.missing_evidence or [])]
    return {
        "candidate": cand.to_dict(),
        "candidate_id": cand.candidate_id,
        "hypothesis": cand.hypothesis,
        "state": cand.lifecycle_state,
        "verification": ver.to_dict() if ver else None,
        "case": case.to_dict() if case else None,
        "case_kind": _case_state_kind(case.state) if case else "",
        "gate": gate,
        "evidence": _bounded(evidence, 40),
        "evidence_count": len(evidence),
        "missing_evidence": _bounded(missing, 12),
        "related": _bounded(related, 20),
        "linked_duplicates": _bounded(linked, 20),
        "duplicate_of": _text(cand.duplicate_of),
        "hunt": hunt_bundle,
        "plan_ids": list(ver.plan_ids or []) if ver else [],
        "authorization_ids": (
            list(ver.authorization_ids or [])
            or _runtime_auth_ids(runtime, ver.job_id if ver else [])
        ) if ver else [],
        "observation_ids": list(ver.observation_ids or []) if ver else [],
        "lineage": _bounded(
            [{"stage": _text(row.get("kind") or "") + ":" +
              _text(row.get("new") or row.get("reason") or ""),
              "candidate_id": candidate_id,
              "verification_id": _text(row.get("verification_id")),
              "job_id": _text(row.get("job_id")),
              "case_id": _text(row.get("case_id")),
              "created_at": _text(row.get("at"))}
             for row in lineage], 30),
        "transitions": _bounded(
            [{"from_state": _text(row.get("old")),
              "to_state": _text(row.get("new")),
              "reason": _text(row.get("reason")),
              "created_at": _text(row.get("at"))}
             for row in transitions], 24),
        "advisor": advisor,
        "provenance": (cand.provenance if isinstance(
            cand.provenance, dict) else {}),
        "package": package or {},
        "handoff": handoff or {},
        "limitations": list(case.limitations) if case is not None
        else list(cand.provenance.get("limitations") or [])
        if isinstance(cand.provenance, dict) else [],
        "recommended_next_step": (case.recommended_next_step
                                  if case is not None else ""),
        "severity": cand.severity,
        "severity_provenance": cand.severity_provenance,
        "confidence_provenance": _text(
            getattr(cand, "confidence_provenance", "")
            or "research_result"),
        "research_history": {
            "source_job": cand.source_job,
            "verification_job": ver_job,
            "campaign_id": cand.source_campaign,
            "objective_id": cand.source_objective,
            "specialist": cand.specialist,
        },
        "handoff_ready": bool(case is not None and case.state in
                              ("READY_FOR_REVIEW", "HANDED_OFF")),
    }
