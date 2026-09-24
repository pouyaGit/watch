"""backend/soc/handoff.py — SOC-5 external analyst handoff (read-only).

A shareable, auth-gated, read-only view of an investigation report:
target, endpoint, context, evidence summary, agent reasoning, suggested
tests and questions for the analyst.  Built exclusively from the
investigation-engine report documents; no secrets, no mutation.

Future-ready: the detail route is structured so a tokenized variant can
be added later without an authentication bypass (the token would simply
resolve to the same read adapter).  A future ``/handoff/{token}`` would
be a separate, explicitly-authorized route — never a key-less alias of
the authenticated one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.soc._util import _bounded, _text

_SUGGESTION_LIMIT = 8
_INDEX_LIMIT = 100


def _reports() -> list[dict[str, Any]]:
    try:
        from backend.investigation_engine import service as inv

        result = inv.report_documents()
        return list(result.get("reports", [])) if isinstance(result, Mapping) else []  # noqa: E501
    except Exception:
        return []


def _source_available() -> bool:
    """Whether the investigation-report source is deployed in this runtime.

    Reported to the page so an empty handoff list can say *why* it is empty
    (source not deployed vs. no packages produced yet).  Purely
    observational: nothing is read, written or synthesised.
    """

    try:
        from backend.investigation_engine import service as inv  # noqa: F401

        return True
    except Exception:
        return False


def _report_document(job_id: str) -> dict | None:
    try:
        from backend.investigation_engine import service as inv

        return inv.report_document(job_id)
    except Exception:
        return None


def handoff_index() -> dict[str, Any]:
    """All handoff-eligible reports + finding case rows (read-only).

    Finding rows are appended AFTER the legacy bound is applied so the
    additive finding section can never be starved out of the list by the
    100-row cap on investigation reports.
    """
    legacy: list[dict[str, Any]] = []
    for report in _reports():
        if not isinstance(report, Mapping):
            continue
        job_id = _text(report.get("job_id"))
        if not job_id:
            continue
        legacy.append({
            "job_id": job_id,
            "report_id": _text(report.get("report_id")),
            "target": _text(report.get("target")),
            "subdomain": _text(report.get("subdomain")),
            "endpoint": _text(report.get("endpoint")),
            "category": _text(report.get("category")),
            "status": _text(report.get("status")),
            "agent": _text(report.get("agent")),
            "generated_at": _text(report.get("generated_at")),
            "view_url": f"/ui/soc/handoff/{job_id}",
        })
    finding_rows = _finding_handoff_rows()
    reports = _bounded(
        legacy, max(_INDEX_LIMIT - len(finding_rows), 0)) + finding_rows
    return {"count": len(legacy) + len(finding_rows),
            "reports": reports,
            "source_available": _source_available()}


def _finding_cases() -> tuple[Any, list[Any]]:
    """(FindingStore, case packages) or (None, []) — never raises."""
    try:
        from backend.research_agents.finding.store import FindingStore
        from backend.research_agents.runtime_store import default_store

        store = default_store()
        return FindingStore(store.base), FindingStore(store.base).list_cases()
    except Exception:
        return None, []


def _finding_handoff_rows() -> list[dict[str, Any]]:
    """Read-only handoff rows for finding case packages (Phase 14).

    Additive: only persisted case packages reach this list, keyed by
    their real verification/source job; no external-submission
    automation exists anywhere in this path.
    """
    rows: list[dict[str, Any]] = []
    try:
        fs, cases = _finding_cases()
        if fs is None:
            return rows
        for case in cases:
            cand = fs.get_candidate(case.candidate_id)
            if cand is None:
                continue
            vers = fs.list_verifications(candidate_id=cand.candidate_id)
            ver = vers[-1] if vers else None
            job_id = _text(ver.job_id if ver else "") or _text(
                cand.source_job)
            rows.append({
                "job_id": job_id,
                "report_id": _text(case.case_id),
                "target": _text(cand.target),
                "subdomain": _text(cand.target),
                "endpoint": _text(
                    (cand.endpoint or {}).get("url", ""))
                if isinstance(cand.endpoint, Mapping) else "",
                "category": _text(cand.vulnerability_class),
                "status": _text(case.state),
                "agent": _text(cand.specialist),
                "generated_at": _text(case.updated_at),
                "view_url": f"/ui/soc/findings/{cand.candidate_id}",
            })
    except Exception:
        return []
    return rows


def _explorer(candidate_id: str) -> dict[str, Any]:
    """EPIC17 §6: the ONE Evidence Explorer projection.

    The finding page, the case page and the handoff package all render
    this same read-model for the same candidate id (projection parity),
    resolved through the canonical store — never a per-page variant.
    """
    from backend.soc import findings as soc_findings

    return soc_findings.explorer_view(candidate_id)


def _finding_detail_for_job(job_id: str) -> dict[str, Any] | None:
    """Read-only handoff view of a finding case package for one job."""
    try:
        fs, cases = _finding_cases()
        if fs is None:
            return None
        for case in cases:
            cand = fs.get_candidate(case.candidate_id)
            if cand is None:
                continue
            vers = fs.list_verifications(candidate_id=cand.candidate_id)
            ver = vers[-1] if vers else None
            jobs = {_text(cand.source_job),
                    _text(ver.job_id if ver else "")}
            if job_id not in jobs:
                continue
            package = case.package or {}
            missing = [str((m or {}).get("description", m))
                       if isinstance(m, dict) else str(m)
                       for m in (cand.missing_evidence or [])]
            verified = case.state in ("VERIFIED", "READY_FOR_REVIEW",
                                      "HANDED_OFF")
            disclaimer = (
                "Authoritative verification: Evidence Gate VERIFIED "
                f"({case.gate_result})."
                if verified else
                f"Authoritative verification state: {case.state} — this "
                "candidate is NOT a confirmed vulnerability.")
            evidence_summary = [
                {"type": _text(e.get("type")),
                 "status": _text(e.get("state") or "recorded"),
                 "label": _text(e.get("label") or e.get("type")),
                 "timestamp": _text(e.get("created_at")),
                 "integrity_hash": "",
                 "status_code": None}
                for e in (package.get("evidence_timeline") or [])
                if isinstance(e, Mapping)][:20]
            return {
                "job_id": job_id,
                "report_id": _text(case.case_id),
                "verified_status": _text(case.state),
                # EPIC17 §6: identical projection to the finding/case pages.
                "explorer": _explorer(case.candidate_id),
                "verified": verified,
                "target": _text(cand.target),
                "endpoint": {
                    "url": _text((cand.endpoint or {}).get("url", ""))
                    if isinstance(cand.endpoint, Mapping) else "",
                    "method": _text((cand.endpoint or {}).get("method"))
                    if isinstance(cand.endpoint, Mapping) else "",
                    "parameter": _text(
                        (cand.endpoint or {}).get("parameter"))
                    if isinstance(cand.endpoint, Mapping) else "",
                    "subdomain": _text(cand.target),
                },
                "context": {
                    "why_interesting": [_text(cand.hypothesis)],
                    "disclaimer": disclaimer,
                },
                "evidence_summary": evidence_summary,
                "agent_reasoning": {
                    "agent": _text(cand.specialist),
                    "confidence": (
                        f"{_text(cand.confidence) or 'not_recorded'} "
                        f"(provenance: "
                        f"{_text(cand.confidence_provenance) or 'none'}; "
                        "the gate decides, not this value)"),
                    "strategy": [
                        _text(p) for p in
                        (case.recommended_next_step or "").split("; ")
                        if _text(p)][:4],
                    "researcher_notes": _text(
                        case.recommended_next_step, 400),
                },
                "suggested_tests": [
                    {"kind": "verification",
                     "suggestion": _text(
                         case.recommended_next_step or
                         "re-run authorized verification within scope",
                         400)},
                ] + [{"kind": "missing-evidence",
                      "suggestion": _text(m, 200)} for m in missing[:5]],
                "questions": [
                    f"Can you provide {m}?" for m in missing[:6]
                ] or ["No open evidence gaps recorded — validate the "
                      "gate-verified finding against the target."],
                "generated_at": _text(case.updated_at),
            }
    except Exception:
        return None
    return None


def _safe_suggestions(report: Mapping) -> list[dict[str, str]]:
    """Suggested tests: next verification step + real evidence gaps.

    Only metadata-style suggestions — never raw payloads, never
    un-redacted bodies, never secrets.
    """
    out: list[dict[str, str]] = []
    next_step = _text(report.get("next_verification_step"))
    if next_step:
        out.append({"kind": "verification", "suggestion": next_step})
    for field in ("missing_proof",):
        for item in (report.get(field) or []) if isinstance(report.get(field), list) else []:  # noqa: E501
            label = _text(item)
            if label:
                out.append({"kind": "missing-evidence",
                            "suggestion": label})
        if len(out) >= _SUGGESTION_LIMIT:
            break
    return out


def _evidence_summary(report: Mapping) -> list[dict[str, Any]]:
    """Aggregate evidence list: type/status/hash/label/timestamp only."""
    out: list[dict[str, Any]] = []
    for item in (report.get("evidence") or []) if isinstance(report.get("evidence"), list) else []:  # noqa: E501
        if not isinstance(item, Mapping):
            continue
        out.append({
            "type": _text(item.get("type")),
            "status": _text(item.get("status")),
            "label": _text(item.get("label")),
            "timestamp": _text(item.get("timestamp")),
            "integrity_hash": _text(item.get("hash")),
            "status_code": item.get("status_code"),
        })
    return _bounded(out, 20)


def _questions(report: Mapping) -> list[str]:
    """Questions for the external analyst (real gaps only)."""
    questions: list[str] = []
    for item in (report.get("missing_proof") or []) if isinstance(report.get("missing_proof"), list) else []:  # noqa: E501
        label = _text(item)
        if label:
            questions.append(f"Can you provide {label}?")
    if not questions:
        questions.append(
            "No open evidence gaps recorded — please validate the "
            "suggested tests against the target.")
    return questions


def handoff_detail(job_id: str) -> dict[str, Any] | None:
    """One handoff package.  None when the job id does not resolve."""
    job_id = _text(job_id)
    if not job_id:
        return None
    report = _report_document(job_id)
    if report is None:
        # finding case packages expose a read-only handoff for the same
        # job id (verification job or its source job)
        return _finding_detail_for_job(job_id)
    if not isinstance(report, Mapping):
        return None

    agent_ctx = report.get("agent_section")
    agent_ctx = agent_ctx if isinstance(agent_ctx, Mapping) else {}

    return {
        "job_id": job_id,
        "report_id": _text(report.get("report_id")),
        "target": _text(report.get("target")),
        "endpoint": {
            "url": _text(report.get("url")),
            "method": _text(report.get("method")),
            "parameter": _text(report.get("parameter")),
            "subdomain": _text(report.get("subdomain")),
        },
        "context": {
            "why_interesting": [
                _text(item) for item in
                (report.get("why_interesting") or [])
                if isinstance(report.get("why_interesting"), list)
            ],
            "disclaimer": _text(report.get("disclaimer")),
        },
        "evidence_summary": _evidence_summary(report),
        "agent_reasoning": {
            "agent": _text(agent_ctx.get("agent")) or _text(report.get("agent")),
            "confidence": _text(agent_ctx.get("confidence")),
            "strategy": [
                _text(item) for item in
                (agent_ctx.get("research_strategy") or [])
                if isinstance(agent_ctx.get("research_strategy"), list)
            ],
            "researcher_notes": _text(agent_ctx.get("researcher_notes")),
        },
        "suggested_tests": _safe_suggestions(report),
        "questions": _questions(report),
        "generated_at": _text(report.get("generated_at")),
    }