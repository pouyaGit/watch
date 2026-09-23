"""Analyst-ready case package (Phase 13) + read-only handoff view (14).

Package contents follow the spec exactly: title, target, scope,
endpoint/context, vulnerability class, authoritative verification result,
evidence + timeline, observations, research history, related candidates,
duplicate relationships, knowledge consulted, verification plan/outcome,
confidence provenance, severity provenance, limitations, recommended
analyst next step.

No exploit payload execution, no fabricated PoC, no secret leakage:
evidence is referenced by id/type/stance/label only; bodies are never
embedded; the read-only handoff view exposes verification status,
evidence, provenance, target, scope, research lineage, analyst notes and
limitations — never API keys, secrets, full databases or unauthorized
targets.  No external submission automation exists in this Epic.
"""

from __future__ import annotations

from typing import Any

from backend.research_agents.finding.models import (
    CandidateFinding,
    CasePackage,
    new_id,
)
from backend.research_agents.finding.quality import EvidenceQuality


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def ensure_case(store: Any, candidate: CandidateFinding, *,
                reason: str = "verification_bound") -> CasePackage:
    """Create the case package for a verification-bound candidate.

    Ordinary candidates never get a case (Phase 12): the store only
    accepts creation for verification-bound states.
    """
    existing = store.cases_for_candidate(candidate.candidate_id)
    if existing is not None:
        return existing
    case = CasePackage(
        case_id=new_id("fcase"),
        candidate_id=candidate.candidate_id,
        scope_ref=candidate.scope_ref,
        title=_bounded(
            f"{candidate.vulnerability_class} candidate on "
            f"{candidate.target or 'target'} "
            f"{candidate.endpoint or ''}", 160),
        vulnerability_class=candidate.vulnerability_class,
        target=candidate.target,
        endpoint=candidate.endpoint,
        severity=candidate.severity,
        severity_provenance=candidate.severity_provenance,
        provenance={
            "source": "finding_verification",
            "created_reason": _bounded(reason, 120),
            "source_job": candidate.source_job,
            "campaign_id": candidate.source_campaign,
            "objective_id": candidate.source_objective,
        },
    )
    return store.add_case(case)


def recommended_next_step_for(decision_state: str, reason: str,
                              missing: list[str]) -> str:
    """Deterministic analyst next step (never LLM-authored)."""
    if decision_state == "VERIFIED":
        return ("Review the authoritative verification and evidence "
                "timeline; reproduce within the authorized scope before "
                "any external report.")
    if decision_state == "REJECTED":
        return f"No action: rejected by the verification gate ({reason})."
    if decision_state == "BLOCKED":
        return (f"Verification blocked ({reason}); resolve the blocker "
                "before re-planning any observation.")
    if decision_state == "INCONCLUSIVE":
        gaps = ", ".join(str(m) for m in missing[:4]) or "unspecified"
        return (f"Evidence insufficient ({reason}); analyst may supply: "
                f"{gaps}.")
    return "Await the verification outcome."


def build_package(
    *,
    store: Any,
    runtime_store: Any,
    candidate: CandidateFinding,
    verification: Any,
    decision: Any,
    qualities: list[EvidenceQuality],
    knowledge_ids: list[str] | None = None,
    research_jobs: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the analyst package from REAL persisted state only."""
    # evidence timeline: candidate evidence + verification evidence,
    # ordered by observed timestamp, referenced by id (never bodies)
    source_rows = runtime_store.list_evidence(job_id=candidate.source_job)
    ver_rows = (runtime_store.list_evidence(job_id=verification.job_id)
                if verification.job_id else [])
    by_id = {q.evidence_id: q for q in qualities}
    timeline: list[dict[str, Any]] = []
    for row in list(source_rows) + list(ver_rows):
        q = by_id.get(str(row.get("id") or ""))
        timeline.append({
            "evidence_id": str(row.get("id") or ""),
            "type": str(row.get("type") or ""),
            "signal": _bounded(row.get("signal"), 80),
            "label": _bounded(row.get("detail"), 160),
            "stance": q.stance if q else "neutral",
            "reliability_class": q.reliability_class if q else "unclassified",
            "direct": bool(q.direct) if q else False,
            "job_id": str(row.get("job_id") or ""),
            "observed_at": str(row.get("created_at") or ""),
        })
    timeline.sort(key=lambda r: r["observed_at"])

    # correlation / duplicate relationships (real rows only)
    correlations = store.list_correlations(candidate_id=candidate.candidate_id)
    related = []
    for row in correlations[:10]:
        other = (row.get("right_id") if row.get("left_id")
                 == candidate.candidate_id else row.get("left_id"))
        other_c = store.get_candidate(str(other or ""))
        related.append({
            "candidate_id": str(other or ""),
            "relation": str(row.get("relation") or ""),
            "reasons": [str(x) for x in (row.get("reasons") or [])[:6]],
            "state": other_c.lifecycle_state if other_c else "unknown",
            "duplicate_of": other_c.duplicate_of if other_c else "",
        })

    gate = getattr(decision, "to_dict", dict)()
    decision_state = str(getattr(decision, "verification_state", ""))

    package = {
        "title": _bounded(
            f"{candidate.vulnerability_class} verification "
            f"{decision_state}: {candidate.target or 'target'}",
            160),
        "target": candidate.target,
        "scope": candidate.scope_ref,
        "endpoint_context": candidate.endpoint,
        "parameter": candidate.parameter,
        "vulnerability_class": candidate.vulnerability_class,
        "hypothesis": candidate.hypothesis,
        "authoritative_verification": gate,
        "evidence_timeline": timeline[:40],
        "evidence_ids": [r["evidence_id"] for r in timeline[:40]],
        "observations": list(verification.observation_ids or []),
        "research_history": {
            "source_jobs": list(dict.fromkeys(
                ([candidate.source_job] if candidate.source_job else [])
                + list(research_jobs or []))),
            "campaign_id": candidate.source_campaign,
            "objective_id": candidate.source_objective,
            "specialist": candidate.specialist,
        },
        "related_candidates": related,
        "duplicate_relationships": {
            "duplicate_of": candidate.duplicate_of,
            "linked_duplicates": list(
                (candidate.correlation or {}).get("linked_duplicates") or []),
            "canonical_id": candidate.canonical_id or candidate.candidate_id,
        },
        "knowledge_consulted": [str(k) for k in (knowledge_ids or [])[:10]],
        "verification_plan": {
            "verification_id": verification.verification_id,
            "plan_ids": list(verification.plan_ids or []),
            "authorization_ids": list(verification.authorization_ids or []),
            "allowed_observation_types": list(
                verification.allowed_observation_types or []),
            "required_evidence": list(verification.required_evidence or []),
            "missing_evidence": list(verification.missing_evidence or []),
        },
        "verification_outcome": {
            "state": verification.state,
            "decision": verification.decision,
            "gate_reason": verification.gate_reason,
            "job_id": verification.job_id,
        },
        "confidence_provenance": {
            "confidence": candidate.confidence,
            "provenance": candidate.confidence_provenance,
            "limitation": ("research-result confidence; verification "
                           "decided by the Evidence Gate, never by the "
                           "researcher or an LLM"),
        },
        "severity_provenance": {
            "severity": candidate.severity,
            "provenance": candidate.severity_provenance,
        },
        "advisor": dict((verification.provenance or {}).get("advisor")
                        or {}),
        "limitations": _limitations(decision_state, candidate,
                                    verification),
        "recommended_analyst_next_step": recommended_next_step_for(
            decision_state,
            str(getattr(decision, "reason", "")),
            list(verification.missing_evidence or [])),
    }
    return package


def _limitations(decision_state: str, candidate: Any,
                 verification: Any) -> list[str]:
    out = [
        "verification is read-only observation within the authorized "
        "scope; no exploit or payload was executed",
        "severity/exploitability/CVE applicability are never "
        "LLM-authored; UNASSESSED unless an authoritative record backs "
        "them",
        "LLM output (if any) was advisory and did not decide this "
        "outcome",
    ]
    if decision_state != "VERIFIED":
        out.append(f"outcome is {decision_state or 'pending'} — not a "
                   "confirmed vulnerability")
    if (candidate.confidence or "") != "high":
        out.append(f"research confidence is {candidate.confidence} "
                   "(research_result provenance)")
    return out


def handoff_view(*, case: CasePackage, candidate: CandidateFinding,
                 verification: Any, decision: Any) -> dict[str, Any]:
    """Read-only handoff exposure (Phase 14).

    Contains: verified status, evidence ids, provenance, target, scope,
    research lineage, analyst notes, limitations.  NEVER: API keys,
    internal secrets, unrestricted database contents, unauthorized
    targets.
    """
    package = dict(case.package or {})
    return {
        "case_id": case.case_id,
        "candidate_id": candidate.candidate_id,
        "title": case.title,
        "verified_status": case.state,
        "gate_result": case.gate_result,
        "vulnerability_class": case.vulnerability_class,
        "target": case.target,
        "scope": case.scope_ref,
        "endpoint_context": case.endpoint,
        "severity": case.severity,
        "severity_provenance": case.severity_provenance,
        "evidence_ids": list(package.get("evidence_ids") or [])[:20],
        "evidence_timeline": list(package.get("evidence_timeline") or [])[:20],
        "research_lineage": {
            "source_job": candidate.source_job,
            "verification_id": verification.verification_id,
            "verification_job": verification.job_id,
            "plan_ids": list(verification.plan_ids or []),
            "campaign_id": candidate.source_campaign,
            "objective_id": candidate.source_objective,
            "specialist": candidate.specialist,
        },
        "analyst_notes": list(package.get("limitations") or []),
        "recommended_next_step": case.recommended_next_step
        or str(package.get("recommended_analyst_next_step") or ""),
        "limitations": list(case.limitations or package.get("limitations")
                            or []),
        "provenance": dict(case.provenance or {}),
        "read_only": True,
        "exposure": "soc_handoff_read_only_no_secrets",
    }
