"""
backend/research_leads.py — Stage R21 deterministic Research Lead projection.

Composes the existing R15-R20 research intelligence into a compact,
researcher-friendly "Research Lead": a single answer to *"why should a
researcher investigate this CVE against this program?"*.

Everything here is read-only, on-demand, and generated from the already
persisted local artifacts through the existing R15-R18 projections:

- R15 exploitability  -> ``research_data.cve_intelligence(cve)['exploitability']``
- R16 priority        -> queue item ``priority_class`` / ``priority_score``
- R17 asset relevance -> queue item ``relevance`` / ``relevance_score`` + reasons
- R18 research queue  -> the CVExprogram candidate (cve, program, queue_id,
                         score, blockers, unknown_factors, queue rank)
- R20 research tasks  -> ``research_tasks.task_by_queue()`` for task linkage

No algorithm is reimplemented here; leads are a projection (composition)
over the outputs the R15-R20 engines already produce. No Mongo, no network,
no LLM, no subprocess, no writes, no persistence store. A lead is generated
only from an existing R18 queue candidate, so a CVE with NO deterministic
relevance never yields a lead (mirrors R18).

A Research Lead is NEVER authoritative security evidence. Status and next-step
are research planning only.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

LEAD_RULE_VERSION = "r21-1"
LEAD_ID_PREFIX = "rl-"
LEAD_ID_RE = re.compile(r"^rl-[0-9a-f]{16}$")

# Research-only statuses (never VULNERABLE / VERIFIED / EXPLOITED / FINDING).
STATUS_LEAD = "RESEARCH_LEAD"
STATUS_BLOCKED = "RESEARCH_BLOCKED"
STATUS_COMPLETED = "RESEARCH_COMPLETED"

# Deterministic next-step vocabulary (research planning only).
NEXT_START = "START_RESEARCH"
NEXT_REVIEW_ASSET = "REVIEW_ASSET_MATCH"
NEXT_WAIT = "WAIT_FOR_MORE_EVIDENCE"
NEXT_COMPLETED = "RESEARCH_COMPLETED"

HIGHER_PRIORITY = frozenset({"CRITICAL_RESEARCH", "HIGH_RESEARCH"})
ELIGIBLE_RELEVANCE = frozenset({"LOW", "MEDIUM", "HIGH"})

MAX_LEADS = 100


def lead_id_for(cve: str, program: str) -> str:
    """Deterministic lead id for a CVExprogram research candidate.

    Same stable-hashing pattern as ``queue_id_for`` / ``task_id_for``. No
    randomness, no time, idempotent within a rule version.
    """
    basis = f"{LEAD_RULE_VERSION}\n{cve}\n{program}"
    return LEAD_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _exploitability_reasons(exploitability: Optional[dict]) -> list[tuple[str, str]]:
    """Positive R15 exploitability signals -> (code, human text).

    A reason is produced ONLY for an explicit positive value; UNKNOWN /
    absent values never yield a reason (unknown is never turned into a
    positive signal).
    """
    expl = exploitability or {}
    out: list[tuple[str, str]] = []
    if expl.get("public_poc") == "true":
        out.append(("PUBLIC_POC", "Public PoC available"))
    if expl.get("exploit_available") == "true":
        out.append(("EXPLOIT_AVAILABLE", "Exploit available"))
    if expl.get("authentication_required") == "false":
        out.append(("UNAUTHENTICATED", "Unauthenticated"))
    if expl.get("user_interaction_required") == "false":
        out.append(("NO_USER_INTERACTION", "No user interaction required"))
    if expl.get("exploit_complexity") == "low":
        out.append(("LOW_ATTACK_COMPLEXITY", "Low attack complexity"))
    return out


def _relevance_reasons(
    relevance_row: Optional[dict], matched_assets: list[str]
) -> list[tuple[str, str]]:
    """Positive R17 asset-relevance signals -> (code, human text).

    Only positive, explicit relevance reasons (or actually matched assets)
    produce a reason.
    """
    reason_texts = [str(r) for r in (relevance_row or {}).get("reasons") or []]
    out: list[tuple[str, str]] = []
    if any("technology match" in t for t in reason_texts):
        out.append(("TECHNOLOGY_OBSERVED", "Affected technology observed"))
    if any(
        "plugin" in t or "component" in t or "product match" in t
        for t in reason_texts
    ):
        out.append(("COMPONENT_OBSERVED", "Affected component observed"))
    if any("parameter" in t for t in reason_texts):
        out.append(("PARAMETER_OBSERVED", "Affected parameter observed"))
    if matched_assets:
        out.append(("PRODUCT_MATCHED", "Matching product/plugin observed"))
    return out


def _priority_reason(priority_class: str) -> list[tuple[str, str]]:
    if priority_class == "CRITICAL_RESEARCH":
        return [("CRITICAL_PRIORITY", "Critical research priority")]
    if priority_class == "HIGH_RESEARCH":
        return [("HIGH_PRIORITY", "High research priority")]
    return []
    return LEAD_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
def recommended_next_step(
    priority_class: str,
    relevance: str,
    blockers: list[str],
    task_status: Optional[str],
) -> str:
    """Deterministic research-next-step selection (documented in the report).

    Order of rules:
      1. A DONE research task means the research is complete.
      2. A BLOCKED research task means evidence is already insufficient.
      3. A strong queue candidate (critical/high research priority with a
         positive relevance class) is always START_RESEARCH, even when it
         carries informational hard blockers (e.g. asset version unknown) —
         the priority signal says "investigate now".  This is the explicit
         CVE-2026-1557 -> dell.com behaviour required by the stage.
      4. Otherwise, remaining hard blockers push to REVIEW_ASSET_MATCH
         (confirm the asset relationship before spending time).
      5. Everything else waits for more evidence.
    """
    if task_status == "DONE":
        return NEXT_COMPLETED
    if task_status == "BLOCKED":
        return NEXT_WAIT
    if priority_class in HIGHER_PRIORITY and relevance in ELIGIBLE_RELEVANCE:
        return NEXT_START
    if blockers:
        return NEXT_REVIEW_ASSET
    return NEXT_WAIT


def _build_lead(item: dict, intel: dict, task_id: Optional[str], task_status: Optional[str]) -> dict:
    """Project one R18 queue candidate into a Research Lead dict."""
    cve = item.get("cve") or ""
    program = item.get("program") or ""
    expl = intel.get("exploitability") or {}
    relevance_row = next(
        (row for row in (intel.get("relevance") or []) if row.get("program") == program),
        None,
    )
    matched_assets = list((relevance_row or {}).get("matched_assets") or [])

    exploitation = _exploitability_reasons(expl)
    relevance_raw = _relevance_reasons(relevance_row, matched_assets)
    priority_raw = _priority_reason(item.get("priority_class") or "")

    reasons: list[dict] = []
    for code, text in exploitation:
        reasons.append({"code": code, "text": text, "source": "exploitability"})
    for code, text in relevance_raw:
        reasons.append({"code": code, "text": text, "source": "relevance"})
    for code, text in priority_raw:
        reasons.append({"code": code, "text": text, "source": "priority"})
    if not reasons:
        reasons = [{
            "code": "NO_POSITIVE_SIGNAL",
            "text": "No positive research signal yet",
            "source": "unknown",
        }]

    blockers = list(item.get("blockers") or [])
    next_step = recommended_next_step(
        item.get("priority_class") or "",
        item.get("relevance") or "UNKNOWN",
        blockers,
        task_status,
    )
    if task_status == "DONE":
        status = STATUS_COMPLETED
    elif next_step in (NEXT_REVIEW_ASSET, NEXT_WAIT):
        status = STATUS_BLOCKED
    else:
        status = STATUS_LEAD

    expl_text = "; ".join(text for _, text in exploitation) or "No positive exploitability signal"
    if matched_assets:
        match_text = "; ".join(matched_assets)
    elif any(c in ("TECHNOLOGY_OBSERVED", "COMPONENT_OBSERVED")
             for c, _ in relevance_raw):
        match_text = "Affected technology/component observed"
    else:
        match_text = "No positive asset match signal"

    return {
        "lead_id": lead_id_for(cve, program),
        "cve_id": cve,
        "program": program,
        "queue_id": item.get("queue_id"),
        "task_id": task_id,
        "priority_score": int(item.get("priority_score") or 0),
        "priority_level": item.get("priority_class") or "INSUFFICIENT_DATA",
        "relevance_score": int(item.get("relevance_score") or 0),
        "relevance_level": item.get("relevance") or "UNKNOWN",
        "exploitability_summary": expl_text,
        "asset_match_summary": match_text,
        "reasons": reasons,
        "blockers": blockers,
        "recommended_next_step": next_step,
        "status": status,
        "rule_version": LEAD_RULE_VERSION,
        "created_at": "",
        "updated_at": "",
    }


def _queue_snapshot() -> list[dict]:
    """Read-only R18 queue snapshot (capped, deterministic rank order)."""
    from backend import research_data as rd
    return rd.list_research_queue(limit=MAX_LEADS, offset=0)["items"]


def _task_map() -> dict:
    """{queue_id: (task_id, status)} from the R20 local task store (read-only)."""
    from backend import research_tasks
    mapping: dict = {}
    try:
        items = research_tasks.list_tasks(limit=MAX_LEADS, offset=0)["items"]
    except Exception:
        return mapping
    for t in items:
        mapping[t["queue_id"]] = (t.get("task_id"), t.get("status"))
    return mapping


def build_leads() -> list[dict]:
    """Deterministic, idempotent composition of R15-R20 into Research Leads.

    Iterates the R18 queue in its deterministic rank order and enriches each
    candidate with R15 exploitability and R20 task linkage. No writes.
    """
    from backend import research_data as rd
    from backend import research_tasks

    leads: list[dict] = []
    queue = _queue_snapshot()
    if not queue:
        return leads
    tasks_by_queue = _task_map()
    try:
        existing = research_tasks.task_by_queue()  # queue_id -> task_id
    except Exception:
        existing = {}

    for item in queue:
        cve = item.get("cve") or ""
        program = item.get("program") or ""
        queue_id = item.get("queue_id")
        intel = {}
        try:
            intel = rd.cve_intelligence(cve)
        except Exception:
            intel = {"cve": cve, "available": False, "relevance": [], "queue": []}
        task_id, task_status = tasks_by_queue.get(queue_id, (None, None))
        if task_id is None:
            task_id = existing.get(queue_id)
        leads.append(_build_lead(item, intel, task_id, task_status))
    return leads


def list_leads(
    limit: int = 50,
    offset: int = 0,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Capped, deterministic leads slice (R18 rank order preserved)."""
    from backend.research_data import clamp_limit, normalize_cve

    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    items = build_leads()
    if cve:
        cve = normalize_cve(cve)
        items = [lead for lead in items if lead["cve_id"] == cve]
    if program:
        program = str(program).strip()
        items = [lead for lead in items if lead["program"] == program]
    total = len(items)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset : offset + limit],
    }


def get_lead(lead_id: str) -> dict:
    """One research lead by deterministic id (404 when absent)."""
    from backend.research_data import NotFoundError

    if not LEAD_ID_RE.match(str(lead_id).strip()):
        raise NotFoundError("expected a lead id like rl-0123456789abcdef")
    for lead in build_leads():
        if lead["lead_id"] == lead_id:
            return lead
    raise NotFoundError("no research lead with that id (no R18 queue candidate)")


def leads_summary() -> dict:
    """Compact dashboard counts: actionable / blocked / completed / top leads."""
    leads = build_leads()
    actionable = sum(1 for lead in leads if lead["status"] == STATUS_LEAD)
    blocked = sum(1 for lead in leads if lead["status"] == STATUS_BLOCKED)
    completed = sum(1 for lead in leads if lead["status"] == STATUS_COMPLETED)
    top = sorted(
        (lead for lead in leads if lead["status"] == STATUS_LEAD),
        key=lambda lead: (
            lead["priority_score"],
            lead["relevance_score"],
            lead["cve_id"],
            lead["program"],
        ),
        reverse=True,
    )[:3]
    return {
        "total": len(leads),
        "actionable": actionable,
        "blocked": blocked,
        "completed": completed,
        "top": top,
    }