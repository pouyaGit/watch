"""backend/soc/cases.py — SOC-3 case investigation adapters (read-only).

Builds the SOC case index and case-detail pages from the AEC case
explorer, the AEC execution-run evidence rows, and the investigation
evidence store.  Views only: no state changes, no verdict invention.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.soc._util import _bounded, _clean_case, _text

_ARTIFACT_LIMIT = 20


def _finding_next_action(case: Any, cand: Any, verified: bool) -> str:
    """State-truthful analyst label for a finding case row.

    Cycle-3 production fix: the old fallback said "awaiting verification"
    for ANY case without a stored next step — including DUPLICATE and
    BLOCKED cases, which are dead ends that must never present
    themselves as pending work (truthful-label rule).
    """
    state = str(getattr(case, "state", "") or "")
    if state == "DUPLICATE":
        canonical = ((cand.duplicate_of if cand else "")
                     or "its canonical candidate")
        return f"duplicate of {canonical} — no separate verification"
    if state == "BLOCKED":
        return "verification blocked — see finding detail"
    if state == "REJECTED":
        return "verification rejected — see finding detail"
    if state == "INCONCLUSIVE":
        return "verification inconclusive — see finding detail"
    if state == "CLOSED":
        return "closed"
    if getattr(case, "recommended_next_step", ""):
        return str(case.recommended_next_step)
    if verified:
        return "analyst review"
    return "awaiting verification"


def cases_index() -> dict[str, Any]:
    """SOC case list — every AEC case explorer row + detail links."""
    rows: list[dict[str, Any]] = []
    try:
        from backend.routers import aec

        view = aec.build_case_explorer_view()
        for row in view.get("cases", []):
            case = _clean_case(row)
            case["detail_url"] = f"/ui/soc/cases/{_text(row.get('case_id'))}"
            case["kind"] = _text(row.get("kind")) or "aec-case"
            rows.append(case)
    except Exception:
        rows = []
    # Agent Runtime v1 cases (evidence-gated creations), honest provenance
    try:
        from backend.research_agents.runtime_store import default_store

        store = default_store()
        if store.state_path.exists():
            for case in store.list_cases():
                rows.append({
                    "case_id": _text(case.get("id")),
                    "target": _text(case.get("target")),
                    "category": _text(case.get("category")),
                    "specialist": _text(case.get("specialist")),
                    "evidence_state": _text(case.get("confidence")),
                    "research_state": _text(case.get("status")),
                    "next_action": "analyst review",
                    "source": "agent-runtime",
                    "kind": "gate-case",
                    "severity": "",
                    "severity_provenance": "",
                    "execution_mode": _text(case.get("execution_mode")),
                    "detail_url": f"/ui/soc/cases/{_text(case.get('id'))}",
                })
    except Exception:
        pass
    # Finding Verification case packages: candidate vs VERIFIED distinct
    try:
        from backend.research_agents.finding.store import FindingStore

        fs = FindingStore(store.base)
        for case in fs.list_cases():
            cand = fs.get_candidate(case.candidate_id)
            verified = case.state in ("VERIFIED", "READY_FOR_REVIEW",
                                      "HANDED_OFF")
            rows.append({
                "case_id": case.case_id,
                "target": cand.target if cand else "",
                "category": (cand.vulnerability_class if cand else ""),
                "specialist": cand.specialist if cand else "",
                "evidence_state": (
                    f"{len((case.package or {}).get('evidence_ids') or [])}"
                    " verified refs"
                    if (case.package or {}).get("evidence_ids") else (
                        f"{len(cand.evidence_refs or [])} candidate refs"
                    if cand else "")),
                "research_state": case.state,
                "next_action": _finding_next_action(
                    case, cand, verified)[:160],
                "source": "finding-verification",
                "kind": "verified-case" if verified else "candidate-case",
                "severity": case.severity,
                "severity_provenance": case.severity_provenance,
                "execution_mode": "production",
                "detail_url": f"/ui/soc/findings/{case.candidate_id}",
            })
    except Exception:
        pass
    return {"count": len(rows), "cases": _bounded(rows, 100)}


def _resolution(case_id: str) -> tuple[dict | None, str]:
    """Resolve one case id to its AEC detail view (case + error)."""
    try:
        from backend.routers import aec

        detail = aec.build_case_detail_view(case_id)
        case = detail.get("case") if isinstance(detail, dict) else None
        # a resolved AEC id wins; anything else falls through to the store
        if isinstance(case, Mapping) and case.get("case_id"):
            return detail, ""
    except Exception:
        pass
    # fallback: an Agent Runtime v1 case (evidence-gated creation)
    runtime_detail = _runtime_case_detail(case_id)
    if runtime_detail is not None:
        return runtime_detail, ""
    return None, "not found"


def _runtime_case_detail(case_id: str) -> dict[str, Any] | None:
    """Build a case detail from the Agent Runtime store (responsible agent
    + research chain), or None when this id is not a runtime case."""

    try:
        from backend.research_agents.runtime_store import default_store

        store = default_store()
        case = store.get_case(case_id)
        if case is None:
            return None
        job = store.get(_text(case.get("job_id")))
        result = store.get_result(_text(case.get("job_id")))
        evidence = store.list_evidence(job_id=_text(case.get("job_id")))
    except Exception:
        return None
    chain: list[dict[str, Any]] = []
    if job is not None:
        chain.append({"step": "job", "ref": job.id, "status": job.status,
                      "mission": job.mission,
                      "authorization_ref": job.authorization_ref})
    if result is not None:
        chain.append({"step": "result", "ref": job.id if job else "",
                      "confidence": result.confidence,
                      "findings": len(result.findings),
                      "blockers": list(result.blockers),
                      "execution_mode": result.execution_mode})
    for row in evidence:
        chain.append({"step": "evidence", "ref": _text(row.get("id")),
                      "signal": _text(row.get("signal")),
                      "type": _text(row.get("type"))})
    research_intel: dict[str, Any] = {}
    if result is not None and isinstance(result.structured, dict):
        st = result.structured
        research_intel = {
            "contract": _text(st.get("contract")),
            "prompt_version": _text(st.get("prompt_version")),
            "knowledge_considered": list(st.get("knowledge_considered")
                                         or [])[:8],
            "prior_research_considered": list(
                st.get("prior_research_considered") or [])[:5],
            "memory_considered": list(st.get("memory_considered") or [])[:8],
            "hypotheses": list(st.get("hypotheses") or [])[:4],
            "evidence_missing": list(st.get("evidence_missing") or [])[:6],
            "negative_evidence": list(st.get("negative_evidence") or [])[:8],
            "recommended_next_observation": _text(
                st.get("recommended_next_observation"), 300),
            "research_recommendations": list(
                st.get("research_recommendations") or [])[:6],
            "evidence_gate": (st.get("evidence_gate")
                              if isinstance(st.get("evidence_gate"), dict)
                              else {}),
            "context_stats": (st.get("context_stats")
                              if isinstance(st.get("context_stats"), dict)
                              else {}),
            "intelligence_errors": list(
                st.get("intelligence_errors") or [])[:8],
            "lineage_digest": _text(
                (st.get("research_lineage") or {}).get("digest")),
            "hunt": (st.get("hunt")
                     if isinstance(st.get("hunt"), dict) else {}),
        }
        # full hunt plan/observation detail from the HuntStore
        try:
            from backend.research_agents.hunt.store import HuntStore
            hs = HuntStore(store.base)
            objs = hs.objectives_for_job(_text(case.get("job_id")))
            if objs:
                bundle = hs.objective_bundle(objs[-1].objective_id) or {}
                research_intel["hunt_detail"] = {
                    "objective_id": objs[-1].objective_id,
                    "state": objs[-1].state,
                    "hypothesis": objs[-1].hypothesis,
                    "termination_reason": objs[-1].termination_reason,
                    "termination_detail": objs[-1].termination_detail,
                    "plans": [{
                        "plan_id": p.get("plan_id"),
                        "version": p.get("version"),
                        "state": p.get("state"),
                        "observation_types": [
                            r.get("observation_type") for r in
                            (p.get("observations_requested") or [])],
                        "reason": _text(p.get("reason"), 300),
                    } for p in bundle.get("plans", []) or []],
                    "authorizations": [
                        {"auth_id": a.get("auth_id"),
                         "status": a.get("status")}
                        for a in bundle.get("authorizations", []) or []],
                    "observations": [
                        {"observation_id": o.get("observation_id"),
                         "types": list(o.get("observation_types") or []),
                         "outcome": o.get("outcome"),
                         "new_rows": o.get("new_rows")}
                        for o in bundle.get("observations", []) or []],
                }
        except Exception:  # noqa: BLE001 - honest absence
            pass
    return {
        "research_intel": research_intel,
        "case": {
            "case_id": _text(case.get("id")),
            "target": _text(case.get("target")),
            "category": _text(case.get("category")),
            "specialist": _text(case.get("specialist")),
            "hypothesis": _text(case.get("hypothesis")),
            "confidence": _text(case.get("confidence")),
            "status": _text(case.get("status")),
            "created_at": _text(case.get("created_at")),
            "source": "agent-runtime",
            "execution_mode": _text(case.get("execution_mode")),
        },
        "authorization_status": {
            "state": "recorded",
            "reference": _text(case.get("authorization_context")),
        },
        "research_history": [],
        "agent_chain": {
            "responsible_agent": _text(case.get("specialist")),
            "job_id": _text(case.get("job_id")),
            "observation_refs": list(case.get("observation_refs") or []),
            "evidence_refs": list(case.get("evidence_refs") or []),
            "chain": chain,
            "analysis": _text(case.get("analysis")),
            "execution_mode": _text(case.get("execution_mode")),
        },
    }


def _evidence_artifacts(case_id: str) -> list[dict[str, Any]]:
    """Real public evidence rows for this case (bounded)."""
    out: list[dict[str, Any]] = []
    try:
        from backend.routers import aec

        view = aec.get_evidence()
        for row in view.get("evidence", []) or []:
            if _text(row.get("case_id")) != case_id:
                continue
            out.append({
                "evidence_id": _text(row.get("evidence_id")),
                "evidence_level": _text(row.get("evidence_level")),
                "integrity": _text(row.get("integrity")),
                "redaction_status": _text(row.get("redaction_status")),
                "source": _text(row.get("source")),
                "source_mode": _text(row.get("source_mode")),
                "tick": row.get("tick"),
                "confidence": _text(row.get("confidence")),
            })
            if len(out) >= _ARTIFACT_LIMIT:
                break
    except Exception:
        pass
    return out


def case_detail(case_id: str) -> dict[str, Any] | None:
    """One SOC case page.  None when the case id does not resolve."""
    case_id = _text(case_id)
    if not case_id:
        return None
    detail, _err = _resolution(case_id)
    if detail is None:
        return None

    case = detail.get("case", {}) if isinstance(detail.get("case"), Mapping) else {}  # noqa: E501
    authz = detail.get("authorization_status")

    target = {
        "domain": _text(case.get("target")),
        "program": "",
        "endpoint": "",
        "method": "",
        "parameters": [],
        "technology": "",
        "category": _text(case.get("category")),
    }

    hypothesis = {
        "why": f"Case {case_id} was opened as a {target['category']} investigation "
               f"against {target['domain'] or 'an unknown target'}.",
        "research_history": [
            {
                "plan_id": _text(h.get("plan_id")),
                "step_count": h.get("step_count"),
            }
            for h in (detail.get("research_history") or [])
            if isinstance(h, Mapping)
        ],
    }

    suggested_analysis = {
        "attack_paths": [target["category"]] if target["category"] else [],
        "required_validation": _required_validation(detail),
        "payload_ideas": _payload_ideas(detail),
        "related_knowledge": _related_knowledge(target["category"]),
    }

    evidence = _evidence_artifacts(case_id)

    verdict = _verdict_state(case)

    return {
        "case_id": case_id,
        "research_intel": (detail.get("research_intel")
                           if isinstance(detail.get("research_intel"), Mapping)
                           else {}),
        "agent_chain": (detail.get("agent_chain")
                        if isinstance(detail.get("agent_chain"), Mapping)
                        else None),
        "source": _text(case.get("source")),
        "target": target,
        "hypothesis": hypothesis,
        "suggested_analysis": suggested_analysis,
        "evidence": evidence,
        "authorization_status": (
            {
                "state": _text(authz.get("state")) if isinstance(authz, Mapping) else "",  # noqa: E501
                "reference": _text(authz.get("reference")) if isinstance(authz, Mapping) else "",  # noqa: E501
            }
        ),
        "verdict": verdict,
        "audit_events": _bounded([
            {
                "timestamp": _text(e.get("timestamp")),
                "actor": _text(e.get("actor")),
                "action": _text(e.get("action")),
                "result": _text(e.get("result")),
            }
            for e in (detail.get("audit_events") or [])
            if isinstance(e, Mapping)
        ], 30),
    }


def _required_validation(detail: dict) -> list[str]:
    out: list[str] = []
    # honest signals from the AEC case state: evidence state + next action
    case = detail.get("case", {}) if isinstance(detail.get("case"), Mapping) else {}  # noqa: E501
    next_action = _text(case.get("next_action"))
    if next_action:
        out.append(f"next action: {next_action}")
    ev_state = _text(case.get("evidence_state"))
    if ev_state:
        out.append(f"evidence state: {ev_state}")
    return out


def _payload_ideas(detail: dict) -> list[dict[str, str]]:
    """Suggested probes & payload ideas — grounded in the missing
    evidence plan from the case, never invented, never exploit payloads."""
    case = detail.get("case", {}) if isinstance(detail.get("case"), Mapping) else {}  # noqa: E501
    ev_state = _text(case.get("evidence_state"))
    if not ev_state:
        return []
    # The OBSERVATION request specs live in the execution run context;
    # expose only the *required evidence* names, not raw payload text.
    import re
    ideas: list[dict[str, str]] = []
    for name in re.findall(r"[A-Za-z0-9_\- ]{3,48}", ev_state.replace("_", " ")):
        label = name.strip()
        if label and label not in {i["probe"] for i in ideas}:
            ideas.append({"probe": label, "kind": "required-evidence"})
        if len(ideas) >= 6:
            break
    if not ideas:
        ideas.append({"probe": "collect missing comparison artifact",
                      "kind": "required-evidence"})
    return ideas


def _related_knowledge(category: str) -> list[dict[str, str]]:
    """KB documents related by tag/category (read-only, metadata only)."""
    if not category:
        return []
    try:
        from backend import research_data as rd

        result = rd.list_kb(tag=category, limit=6)
        return [
            {
                "knowledge_id": _text(doc.get("knowledge_id")),
                "title": _text(doc.get("title")),
                "source_url": _text(doc.get("source_url")),
            }
            for doc in result.get("items", [])
        ]
    except Exception:
        return []


def _verdict_state(case: Mapping) -> str:
    """Honest verdict: only states the verification layer would ever set.

    The SOC UI must never claim a confirmed vulnerability unless the
    underlying verification says so (EPIC rules).  Fixture cases carry
    no such marker, so the honest answer is NOT_CLAIMED.
    """
    state = _text(case.get("research_state"))
    if state in ("COMPLETED", "VERIFIED", "CONFIRMED"):
        return "CONFIRMED"
    if state:
        return "NOT_CLAIMED"
    return "NOT_CLAIMED"