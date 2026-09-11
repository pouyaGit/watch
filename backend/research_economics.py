"""backend/research_economics.py — Stage R25.3 read-only economic projection.

Composes the existing research pipeline into Money Score projections:

    R18 queue -> R21 leads -> R22 plans -> R15/R16 intelligence ->
    persisted CVE research payload -> R20 task state -> R23 result ->
    R24 loop result

and passes each candidate into the existing R25.2 engine
``ai.knowledge.economics.assess_economic_value``. No scoring logic lives
here: this module only gathers inputs, invokes the engine, and orders the
deterministic projections.

READ-ONLY: no writes, no persistence, no Mongo writes, no network, no DNS,
no LLM, no subprocess, no target interaction, no Nuclei, no PoC execution,
no 5B-5J, no findings, no alerts. A projection is research planning only —
never a confirmed finding.
"""

from __future__ import annotations

from typing import Any, Optional

MAX_ECONOMICS = 100

_ECONOMIC_RULE_VERSION = "r25-1"


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _intel_for(cve: str) -> dict:
    """R15/R16/R17 intelligence for one CVE (fail-soft)."""
    from backend import research_data as rd

    try:
        return rd.cve_intelligence(cve)
    except Exception:
        return {
            "cve": cve,
            "available": False,
            "knowledge_id": None,
            "exploitability": {},
            "cvss": {},
            "priority": {},
            "relevance": [],
            "queue": [],
            "vulnerability_types": [],
            "cwes": [],
            "research_only": True,
        }


def _payload_for(cve: str) -> dict:
    """Persisted <CVE>.cli.json research payload (fail-soft, read-only)."""
    from backend import research_data as rd

    try:
        payload, _ = rd._research_payload(cve)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _task_map() -> dict:
    """{queue_id: task dict} from the R20 local task store (read-only)."""
    from backend import research_tasks

    mapping: dict = {}
    try:
        items = research_tasks.list_tasks(limit=MAX_ECONOMICS, offset=0)["items"]
    except Exception:
        return mapping
    for task in items or []:
        if isinstance(task, dict) and task.get("queue_id"):
            mapping[task["queue_id"]] = task
    return mapping


def _plans_by_lead() -> dict:
    """{lead_id: plan} from the R22 projection (fail-soft, read-only)."""
    from backend import research_execution

    try:
        plans = research_execution.build_plans()
    except Exception:
        return {}
    mapping: dict = {}
    for plan in plans or []:
        if isinstance(plan, dict) and plan.get("lead_id"):
            mapping.setdefault(plan["lead_id"], plan)
    return mapping


def _r23_for(plan_id: str) -> Optional[dict]:
    """R23 agent result for one plan (None when absent; read-only)."""
    from ai.research_agent import storage

    if not plan_id:
        return None
    try:
        result = storage.load_result(plan_id, "r23-1")
    except Exception:
        return None
    return result if isinstance(result, dict) else None


def _r24_for(plan_id: str) -> Optional[dict]:
    """R24 discovery loop result for one plan (None when absent; read-only)."""
    from ai.research_agent import storage

    if not plan_id:
        return None
    try:
        loop = storage.load_research_loop(plan_id)
    except Exception:
        return None
    return loop if isinstance(loop, dict) else None


def _project_one(
    lead: Any,
    plans: dict,
    intel_by_cve: dict,
    payload_by_cve: dict,
    tasks_by_queue: dict,
) -> tuple[Optional[dict], Optional[dict]]:
    """Project one lead; return (projection, skip_record).

    Exactly one of the two is not None. Never raises for a malformed
    candidate: failures are recorded as deterministic skip records so one
    bad item cannot blank the queue.
    """
    from ai.knowledge.economics import assess_economic_value, economic_projection

    if not isinstance(lead, dict):
        return None, {"cve_id": "", "program": "", "lead_id": "",
                      "reason": "malformed lead (not a mapping)"}
    cve = _safe_str(lead.get("cve_id"))
    program = _safe_str(lead.get("program"))
    lead_id = _safe_str(lead.get("lead_id"))
    if not cve or not program:
        return None, {"cve_id": cve, "program": program, "lead_id": lead_id,
                      "reason": "lead missing cve_id/program"}
    try:
        if cve not in intel_by_cve:
            intel_by_cve[cve] = _intel_for(cve)
        if cve not in payload_by_cve:
            payload_by_cve[cve] = _payload_for(cve)
        intel = intel_by_cve[cve]
        payload = payload_by_cve[cve]
        plan = plans.get(lead_id)
        task = tasks_by_queue.get(lead.get("queue_id"))
        plan_id = _safe_str((plan or {}).get("plan_id"))
        r23 = _r23_for(plan_id)
        r24 = _r24_for(plan_id)
        value = assess_economic_value(lead, plan, intel, payload, task, r23, r24)
        return economic_projection(value), None
    except Exception as exc:
        return None, {"cve_id": cve, "program": program, "lead_id": lead_id,
                      "reason": f"{type(exc).__name__}: {exc}"[:200]}


def _project_all() -> tuple[list[dict], list[dict]]:
    """Project every R21 lead; return (items, skipped), both deterministic."""
    from backend import research_leads

    try:
        leads = research_leads.build_leads()
    except Exception:
        return [], [{"cve_id": "", "program": "", "lead_id": "",
                     "reason": "lead snapshot unavailable"}]
    plans = _plans_by_lead()
    tasks_by_queue = _task_map()
    intel_by_cve: dict = {}
    payload_by_cve: dict = {}
    items: list[dict] = []
    skipped: list[dict] = []
    for lead in leads or []:
        projection, skip = _project_one(
            lead, plans, intel_by_cve, payload_by_cve, tasks_by_queue)
        if projection is not None:
            items.append(projection)
        elif skip is not None:
            skipped.append(skip)
    items.sort(key=lambda e: (
        -int(e.get("money_score") if isinstance(e.get("money_score"), int) else 0),
        str(e.get("cve_id") or ""),
        str(e.get("program") or ""),
    ))
    skipped.sort(key=lambda s: (
        str(s.get("cve_id") or ""), str(s.get("program") or ""),
        str(s.get("lead_id") or ""), str(s.get("reason") or "")))
    return items, skipped


def build_economics() -> list[dict]:
    """Deterministic Money Score projections for all leads (no writes).

    Ordered: money_score DESC, CVE ID ASC, program ASC.
    """
    items, _ = _project_all()
    return items


def list_research_economics(
    limit: int = 50,
    offset: int = 0,
    cve: Optional[str] = None,
    program: Optional[str] = None,
) -> dict:
    """Capped, deterministic Money Score queue slice (money order preserved)."""
    from backend.research_data import clamp_limit, normalize_cve

    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    items, skipped = _project_all()
    if cve:
        cve = normalize_cve(cve)
        items = [e for e in items if e["cve_id"] == cve]
        skipped = [s for s in skipped if not s["cve_id"] or s["cve_id"] == cve]
    if program:
        program = str(program).strip()
        items = [e for e in items if e["program"] == program]
        skipped = [s for s in skipped if not s["program"] or s["program"] == program]
    total = len(items)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset: offset + limit],
        "skipped": skipped,
        "rule_version": _ECONOMIC_RULE_VERSION,
        "research_only": True,
    }


def get_research_economic_value(lead_id: str) -> dict:
    """One lead's economic projection by deterministic id (404 when absent)."""
    from backend.research_data import NotFoundError
    from backend.research_leads import LEAD_ID_RE

    if not LEAD_ID_RE.match(str(lead_id).strip()):
        raise NotFoundError("expected a lead id like rl-0123456789abcdef")
    for item in build_economics():
        if item["lead_id"] == lead_id:
            return item
    raise NotFoundError("no economic projection with that id (no R18 queue candidate)")


def economic_summary() -> dict:
    """Compact counts: total, by priority band, top money projections."""
    items = build_economics()
    by_priority: dict[str, int] = {}
    for item in items:
        band = str(item.get("priority") or "P5_DEFER")
        by_priority[band] = by_priority.get(band, 0) + 1
    return {
        "total": len(items),
        "by_priority": dict(sorted(by_priority.items())),
        "top": items[:3],
        "rule_version": _ECONOMIC_RULE_VERSION,
        "research_only": True,
    }
