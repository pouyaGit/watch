"""backend/prod_intel/case_intel.py — analyst case/handoff package.

One complete, persisted-state-only package per case so an analyst (or a
future external specialist) never has to reconstruct lineage from
multiple screens. Supports both case families:

* finding family   ``fcase-*``  (FindingStore case packages)
* runtime family   ``case-*``   (evidence-gate runtime cases)

Truth rules: payloads/exploit details that are not actually stored and
authorized render ``unavailable``; ``what_was_verified`` comes from the
authoritative gate record, never from the LLM; limitations are echoed
from the persisted verification/case, never invented.
"""

from __future__ import annotations

from typing import Any

from backend.prod_intel import sources
from backend.prod_intel.semantics import (
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    metric,
)

_NOT_STORED = "unavailable — not stored in an authorized field"


def case_intelligence(case_id: str) -> dict[str, Any]:
    """Full analyst package for one case id (both families)."""
    cid = str(case_id or "").strip()
    if not cid:
        return {"case_id": "", "found": False, "state": NOT_OBSERVED,
                "reason": "empty case id"}
    if cid.startswith("fcase-"):
        return _finding_package(cid)
    if cid.startswith("case-"):
        return _runtime_package(cid)
    return {"case_id": cid, "found": False, "state": NOT_OBSERVED,
            "reason": "id matches no known case family "
                      "(expected fcase-* or case-*)"}


# ------------------------------------------------------------------ finding
def _finding_package(cid: str) -> dict[str, Any]:
    fc_env = sources.finding_cases()
    if fc_env["state"] != "ok":
        return {"case_id": cid, "found": False, "state": UNAVAILABLE,
                "reason": fc_env["reason"]}
    case = next((c for c in fc_env["data"] if c.case_id == cid), None)
    if case is None:
        return {"case_id": cid, "found": False, "state": NOT_OBSERVED,
                "reason": "case id not present in finding store"}

    cand_env = sources.candidates()
    cand = next((c for c in (cand_env["data"] or [])
                 if c.candidate_id == case.candidate_id), None)

    ver_env = sources.verifications()
    vers = [v for v in (ver_env["data"] or [])
            if v.candidate_id == case.candidate_id]
    primary = next((v for v in vers if v.verification_id
                    == case.verification_id), None) or (vers[-1] if vers
                                                        else None)

    # -- lineage ------------------------------------------------------------
    lineage = {
        "candidate": ({"candidate_id": case.candidate_id,
                       "state": cand.lifecycle_state if cand else "",
                       "created_at": cand.created_at if cand else "",
                       "duplicate_of": (cand.duplicate_of if cand else ""),
                       "link": f"/ui/soc/findings/{case.candidate_id}"}
                      if cand or True else None),
        "research_job": (str(cand.source_job) if cand else ""),
        "campaign": (str(cand.source_campaign) if cand else ""),
        "objective": (str(cand.source_objective) if cand else ""),
        "verifications": [
            {"verification_id": v.verification_id, "state": str(v.state),
             "gate_reason": str(v.gate_reason or ""),
             "decision": str(v.decision or ""),
             "authorization_ids": list(v.authorization_ids or ()),
             "plan_ids": list(v.plan_ids or ()),
             "observation_ids": list(v.observation_ids or ()),
             "created_at": v.created_at, "updated_at": v.updated_at}
            for v in vers],
        "case": {"case_id": case.case_id, "state": str(case.state),
                 "created_at": case.created_at,
                 "updated_at": case.updated_at},
    }

    # -- evidence: from candidate refs + verification current evidence ------
    ev_env = sources.evidence()
    known_ids = set(str(e.get("id") or "") for e in (ev_env["data"] or []))
    refs = list((cand.evidence_refs if cand else []) or [])
    if primary:
        for eid in (getattr(primary, "observation_ids", ()) or ()):
            if eid not in refs:
                refs.append(str(eid))
    evidence_rows = [e for e in (ev_env["data"] or [])
                     if str(e.get("id") or "") in set(refs)
                     or str(e.get("job_id") or "")
                     == str(cand.source_job if cand else "")]
    evidence = metric(
        [{"id": str(e.get("id") or ""), "type": str(e.get("type") or ""),
          "job_id": str(e.get("job_id") or ""),
          "confidence": str(e.get("confidence") or ""),
          "created_at": str(e.get("created_at") or ""),
          "detail_present": bool(e.get("detail"))}
         for e in evidence_rows[:40]],
        source="runtime.evidence + candidate.evidence_refs",
        population="persisted evidence rows referenced by this case's "
                   "candidate/job",
        aggregation="list, persisted detail only",
        time_range={"kind": "all_history"},
        state=OK if evidence_rows else NOT_OBSERVED,
        reason=ev_env["reason"] or "")

    # -- what was verified / not verified (authoritative gate record) -------
    if primary is not None:
        gate_reason = str(primary.gate_reason or "")
        decision = str(primary.decision or "")
        what_verified = (
            f"evidence gate decision {decision} ({gate_reason})"
            if decision else "no gate decision recorded")
        not_verified = ", ".join(
            str(m) for m in (getattr(primary, "missing_evidence", ())
                             or ())) or "no missing-evidence list recorded"
        limitations = list(str(x) for x in (case.limitations or ()))
        authorization_ids = list(primary.authorization_ids or ())
        plan_ids = list(primary.plan_ids or ())
    else:
        what_verified = "no verification recorded for this candidate"
        not_verified = "verification never started"
        limitations = list(str(x) for x in (case.limitations or ()))
        authorization_ids, plan_ids = [], []

    # -- knowledge lineage (persisted rows for the source job) --------------
    ku_env = sources.knowledge_use()
    job_id = str(cand.source_job if cand else "")
    knowledge = [str(k.get("document_id") or "")
                 for k in (ku_env["data"] or [])
                 if str(k.get("job_id") or "") == job_id] \
        if ku_env["state"] == "ok" else []

    # -- handoff state -------------------------------------------------------
    handoff_state = str(case.state)   # package is handoff-ready by family
    try:
        from backend.soc import handoff as soc_handoff
        rows = soc_handoff.handoff_index().get("reports") or []
        hrow = next((r for r in rows
                     if str(r.get("report_id") or "") == cid), None)
        if hrow is not None:
            handoff_state = str(hrow.get("status") or handoff_state)
    except Exception:
        pass                                   # handoff enrichment optional

    # -- timeline (persisted audit events touching these ids) ---------------
    audit_env = sources.audit()
    ids = {cid, case.candidate_id}
    if primary is not None:
        ids.add(primary.verification_id)
    if job_id:
        ids.add(job_id)
    timeline = []
    if audit_env["state"] == "ok":
        for row in audit_env["data"]:
            vals = {str(v) for v in row.values() if isinstance(v, str)}
            if ids & vals:
                timeline.append({
                    "at": str(row.get("ts") or row.get("at") or ""),
                    "event": str(row.get("event") or ""),
                    "reason": str(row.get("reason")
                                  or row.get("gate_reason") or ""),
                    "state": str(row.get("state") or ""),
                })
        timeline.sort(key=lambda r: r["at"])

    return {
        "case_id": cid,
        "family": "finding",
        "found": True,
        "state": OK,
        "title": str(case.title or ""),
        "target": str(case.target or ""),
        "endpoint": (case.endpoint if isinstance(case.endpoint, str)
                     else str(case.endpoint or "")),
        "vulnerability_class": str(case.vulnerability_class or ""),
        "scope_ref": str(case.scope_ref or ""),
        "severity": str(case.severity or ""),
        "severity_provenance": str(case.severity_provenance or ""),
        "confidence": (str(cand.confidence) if cand else ""),
        "confidence_provenance": (str(cand.confidence_provenance)
                                  if cand else ""),
        "lineage": lineage,
        "observations": metric(
            len(evidence_rows), source="runtime.evidence",
            population="evidence rows on this case's lineage",
            aggregation="count", time_range={"kind": "all_history"},
            state=OK if evidence_rows else NOT_OBSERVED),
        "evidence": evidence,
        "verification_result": {
            "state": str(primary.state) if primary else "not_started",
            "decision": str(primary.decision) if primary else "",
            "gate_reason": str(primary.gate_reason) if primary else "",
            "authorization_ids": authorization_ids,
            "plan_ids": plan_ids,
        },
        "what_was_verified": what_verified,
        "what_was_not_verified": not_verified,
        "verification_limitations": limitations,
        "knowledge_used": knowledge or [],
        "timeline": timeline[-40:],
        "handoff": {"state": handoff_state,
                    "recommended_next_step":
                        str(case.recommended_next_step or "")},
        "analyst_next_steps": str(case.recommended_next_step or "")
                              or _state_next_step(str(case.state)),
        "payload": _NOT_STORED,
        "rule_version": "production-intelligence-v1",
    }


def _state_next_step(state: str) -> str:
    return {
        "TRIAGED": "awaiting verification decision",
        "VERIFYING": "verification in progress — monitor gate outcome",
        "VERIFIED": "gate-verified — prepare analyst review",
        "READY_FOR_REVIEW": "analyst review required",
        "HANDED_OFF": "handed off — track external outcome",
        "BLOCKED": "verification blocked — see gate reason",
        "DUPLICATE": "duplicate of a canonical candidate — no separate "
                     "verification",
        "CLOSED": "closed",
        "REJECTED": "rejected by the evidence gate",
        "INCONCLUSIVE": "inconclusive — needs more authorized evidence",
        "CANDIDATE": "candidate created — triage pending",
    }.get(state, "review case state")


# ------------------------------------------------------------------- runtime
def _runtime_package(cid: str) -> dict[str, Any]:
    rc_env = sources.runtime_cases()
    if rc_env["state"] != "ok":
        return {"case_id": cid, "found": False, "state": UNAVAILABLE,
                "reason": rc_env["reason"]}
    row = next((c for c in rc_env["data"]
                if str(c.get("id") or "") == cid), None)
    if row is None:
        return {"case_id": cid, "found": False, "state": NOT_OBSERVED,
                "reason": "case id not present in runtime store"}

    job_id = str(row.get("job_id") or "")
    jobs_env = sources.jobs()
    job = next((j for j in (jobs_env["data"] or []) if j.id == job_id),
               None)
    ev_env = sources.evidence()
    ev_rows = [e for e in (ev_env["data"] or [])
               if str(e.get("job_id") or "") == job_id]
    ku_env = sources.knowledge_use()
    knowledge = [str(k.get("document_id") or "")
                 for k in (ku_env["data"] or [])
                 if str(k.get("job_id") or "") == job_id] \
        if ku_env["state"] == "ok" else []

    # gate record lives on the job result's structured evidence_gate
    gate_record: dict[str, Any] = {}
    try:
        from backend.research_agents.runtime_store import RuntimeStore
        state = RuntimeStore()._read_state()
        res = (state.get("results") or {}).get(job_id) or {}
        gate_record = dict((res.get("structured") or {})
                           .get("evidence_gate") or {})
    except Exception:
        gate_record = {}

    audit_env = sources.audit()
    timeline = []
    if audit_env["state"] == "ok":
        for row in audit_env["data"]:
            vals = {str(v) for v in row.values() if isinstance(v, str)}
            if {cid, job_id} & vals:
                timeline.append({
                    "at": str(row.get("ts") or row.get("at") or ""),
                    "event": str(row.get("event") or ""),
                    "reason": str(row.get("reason") or ""),
                })
        timeline.sort(key=lambda r: r["at"])

    return {
        "case_id": cid,
        "family": "runtime",
        "found": True,
        "state": OK,
        "title": str(row.get("title") or row.get("summary") or cid),
        "target": str(row.get("target")
                      or (job.subdomain if job else "")),
        "endpoint": str(row.get("endpoint")
                        or (job.url if job else "")),
        "vulnerability_class": str(row.get("category") or ""),
        "scope_ref": str(row.get("scope_ref") or ""),
        "severity": str(row.get("severity") or "UNASSESSED"),
        "severity_provenance": str(
            row.get("severity_provenance")
            or "unassessed_no_authoritative_rule"),
        "lineage": {
            "research_job": job_id,
            "job_status": str(job.status) if job else "",
            "specialist": str(row.get("specialist") or ""),
        },
        "evidence": metric(
            [{"id": str(e.get("id") or ""),
              "type": str(e.get("type") or ""),
              "confidence": str(e.get("confidence") or ""),
              "created_at": str(e.get("created_at") or "")}
             for e in ev_rows[:40]],
            source="runtime.evidence",
            population="evidence rows for this case's job",
            aggregation="list", time_range={"kind": "all_history"},
            state=OK if ev_rows else NOT_OBSERVED,
            reason=ev_env["reason"] or ""),
        "verification_result": {
            "state": "gate_record" if gate_record else "not_recorded",
            "decision": str(gate_record.get("reason") or ""),
            "authoritative": bool(gate_record.get("authoritative")),
            "created_case": bool(gate_record.get("created_case")),
            "confidence": str(gate_record.get("confidence") or ""),
        },
        "what_was_verified": (
            f"evidence gate: {gate_record.get('reason')}"
            if gate_record else "no gate record on the job result"),
        "what_was_not_verified": ", ".join(
            str(b) for b in (row.get("blockers") or ()))
            or "no blocker list recorded",
        "verification_limitations": list(row.get("limitations") or ()),
        "knowledge_used": knowledge or [],
        "timeline": timeline[-40:],
        "handoff": {"state": str(row.get("status") or ""),
                    "recommended_next_step":
                        str(row.get("recommended_next_step") or "")},
        "analyst_next_steps": str(row.get("recommended_next_step") or "")
                              or _state_next_step(str(row.get("status")
                                                       or "")),
        "payload": _NOT_STORED,
        "rule_version": "production-intelligence-v1",
    }
