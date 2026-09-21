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


def _report_document(job_id: str) -> dict | None:
    try:
        from backend.investigation_engine import service as inv

        return inv.report_document(job_id)
    except Exception:
        return None


def handoff_index() -> dict[str, Any]:
    """All handoff-eligible investigation reports (read-only)."""
    reports: list[dict[str, Any]] = []
    for report in _reports():
        if not isinstance(report, Mapping):
            continue
        job_id = _text(report.get("job_id"))
        if not job_id:
            continue
        reports.append({
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
    return {"count": len(reports), "reports": _bounded(reports, _INDEX_LIMIT)}


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
        return None
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