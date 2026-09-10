"""
backend/research_execution.py — Stage R22 deterministic Research Execution Plan projection.

Turns the existing R21 Research Lead into a compact deterministic execution plan:
"what exactly should the researcher investigate next, in what order, and what
evidence should be reviewed?"

RESEARCH-ONLY: no network, no subprocess, no LLM, no Nuclei, no active
validation, no writes, no persistence, no findings. Everything is an on-demand
projection over local artifacts through the existing R15-R21 projections.

No algorithm is reimplemented here beyond sequencing; the data is composed from
R15 exploitability, R16 priority, R17 relevance, R18 queue, R20 task linkage
and the R21 lead itself.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

PLAN_RULE_VERSION = "r22-1"
PLAN_ID_PREFIX = "r22-"
PLAN_ID_RE = re.compile(r"^r22-[0-9a-f]{16}$")

# Allowed plan statuses (research planning only, never production finding terms)
PLAN_READY = "RESEARCH_PLAN_READY"
PLAN_BLOCKED = "RESEARCH_PLAN_BLOCKED"
PLAN_COMPLETED = "RESEARCH_PLAN_COMPLETED"

MAX_PLANS = 100

# Deterministic step precedence (removed steps preserve relative order)
STEP_ORDER = [
    "REVIEW_CVE_SUMMARY",
    "REVIEW_EXPLOITABILITY",
    "REVIEW_PUBLIC_POC",
    "REVIEW_REFERENCES",
    "REVIEW_TECHNOLOGY_MATCH",
    "REVIEW_COMPONENT_MATCH",
    "REVIEW_PARAMETER_MATCH",
    "REVIEW_VERSION",
    "REVIEW_ASSET_EVIDENCE",
    "REVIEW_RESEARCH_TASK",
]

STEP_META: dict[str, dict] = {
    "REVIEW_CVE_SUMMARY": {
        "title": "Review CVE summary",
        "purpose": "Review CVE description, severity and affected product context",
        "source": "research/cve",
    },
    "REVIEW_EXPLOITABILITY": {
        "title": "Review exploitability",
        "purpose": "Review authentication, privilege, user interaction and complexity signals",
        "source": "exploitability",
    },
    "REVIEW_PUBLIC_POC": {
        "title": "Review public PoC",
        "purpose": "Review public proof-of-concept or exploit availability",
        "source": "exploitability/public_poc",
    },
    "REVIEW_REFERENCES": {
        "title": "Review references",
        "purpose": "Review CVE references and vendor advisories",
        "source": "research/reference",
    },
    "REVIEW_TECHNOLOGY_MATCH": {
        "title": "Review technology match",
        "purpose": "Confirm affected technology observed in program assets",
        "source": "relevance/technology",
    },
    "REVIEW_COMPONENT_MATCH": {
        "title": "Review component match",
        "purpose": "Confirm affected component or plugin observed in assets",
        "source": "relevance/component",
    },
    "REVIEW_PARAMETER_MATCH": {
        "title": "Review parameter match",
        "purpose": "Review affected parameter and injection context",
        "source": "research/parameter",
    },
    "REVIEW_VERSION": {
        "title": "Review version",
        "purpose": "Review affected version range and asset version exposure",
        "source": "research/version",
    },
    "REVIEW_ASSET_EVIDENCE": {
        "title": "Review asset evidence",
        "purpose": "Review matched assets and program evidence",
        "source": "relevance/asset",
    },
    "REVIEW_RESEARCH_TASK": {
        "title": "Review research task",
        "purpose": "Review linked research task state and next action",
        "source": "research/task",
    },
}

EVIDENCE_ORDER = [
    "CVE_REFERENCE",
    "VENDOR_ADVISORY",
    "PUBLIC_POC",
    "EXPLOIT_REFERENCE",
    "AFFECTED_COMPONENT",
    "AFFECTED_PARAMETER",
    "AFFECTED_VERSION",
    "ASSET_TECHNOLOGY",
    "ASSET_COMPONENT",
    "ASSET_VERSION",
    "RESEARCH_TASK_CONTEXT",
]

EVIDENCE_META: dict[str, dict] = {
    "CVE_REFERENCE": {"description": "Review CVE reference(s)", "source": "research/reference", "required": True},
    "VENDOR_ADVISORY": {"description": "Review vendor advisory or bulletin", "source": "research/reference", "required": False},
    "PUBLIC_POC": {"description": "Review public proof-of-concept", "source": "exploitability/public_poc", "required": True},
    "EXPLOIT_REFERENCE": {"description": "Review exploit reference or detection rule", "source": "exploitability/exploit_available", "required": False},
    "AFFECTED_COMPONENT": {"description": "Review affected component or file", "source": "research/component", "required": True},
    "AFFECTED_PARAMETER": {"description": "Review affected parameter", "source": "research/parameter", "required": True},
    "AFFECTED_VERSION": {"description": "Review affected version range", "source": "research/version", "required": False},
    "ASSET_TECHNOLOGY": {"description": "Review asset technology evidence", "source": "relevance/technology", "required": True},
    "ASSET_COMPONENT": {"description": "Review asset component evidence", "source": "relevance/component", "required": False},
    "ASSET_VERSION": {"description": "Review asset version evidence", "source": "relevance/version", "required": False},
    "RESEARCH_TASK_CONTEXT": {"description": "Review research task context", "source": "research/task", "required": False},
}


def plan_id_for(cve: str, program: str) -> str:
    """Deterministic plan id for a CVE x program candidate."""
    basis = f"{PLAN_RULE_VERSION}\n{cve}\n{program}"
    return PLAN_ID_PREFIX + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _steps_for(lead: dict, intel: dict, payload: dict, doc, relevance_row: Optional[dict]) -> list[dict]:
    """Deterministic, explainable execution steps (only when supported)."""
    steps: list[dict] = []
    exp = intel.get("exploitability") or {}
    refs = []
    try:
        refs = (payload.get("research") or {}).get("references") or []
    except Exception:
        refs = []
    components = list(getattr(doc, "components", []) or []) if doc is not None else []
    parameters = list(getattr(doc, "parameters", []) or []) if doc is not None else []
    affected_versions = []
    try:
        affected_versions = (payload.get("research") or {}).get("affected_versions") or []
    except Exception:
        affected_versions = []

    # helpers
    def _emit(code: str, status: str = "READY"):
        meta = STEP_META[code]
        steps.append({
            "order": len(steps) + 1,
            "code": code,
            "title": meta["title"],
            "purpose": meta["purpose"],
            "source": meta["source"],
            "status": status,
        })

    # 1 REVIEW_CVE_SUMMARY — when CVE intel is available
    if intel.get("available"):
        _emit("REVIEW_CVE_SUMMARY")
    # 2 REVIEW_EXPLOITABILITY — when at least one exploitability field is known
    exploit_keys = ["authentication_required", "privilege_required", "user_interaction_required", "exploit_available", "public_poc", "active_exploitation", "exploit_complexity"]
    if any(exp.get(k) not in (None, "unknown", "") for k in exploit_keys):
        _emit("REVIEW_EXPLOITABILITY")
    # 3 REVIEW_PUBLIC_POC — only when public_poc == true (never on unknown)
    if exp.get("public_poc") == "true":
        _emit("REVIEW_PUBLIC_POC")
    # 4 REVIEW_REFERENCES — when references exist
    if refs:
        _emit("REVIEW_REFERENCES")
    # 5 REVIEW_TECHNOLOGY_MATCH — when technology match observed
    if relevance_row and any("technology match" in str(r) for r in (relevance_row.get("reasons") or [])):
        _emit("REVIEW_TECHNOLOGY_MATCH")
    # 6 REVIEW_COMPONENT_MATCH — only when component/product match observed in relevance (not just doc)
    if relevance_row and any(
        "plugin" in str(r) or "component" in str(r) or "product match" in str(r)
        for r in (relevance_row.get("reasons") or [])
    ):
        _emit("REVIEW_COMPONENT_MATCH")
    # 7 REVIEW_PARAMETER_MATCH — when affected parameter is known (doc.parameters)
    if parameters:
        _emit("REVIEW_PARAMETER_MATCH")
    # 8 REVIEW_VERSION — when affected version range is known
    if affected_versions:
        _emit("REVIEW_VERSION")
    # 9 REVIEW_ASSET_EVIDENCE — when matched assets exist
    if relevance_row and relevance_row.get("matched_assets"):
        _emit("REVIEW_ASSET_EVIDENCE")
    # 10 REVIEW_RESEARCH_TASK — when a task is linked
    if lead.get("task_id"):
        # informational if already done, otherwise ready
        st = "INFORMATIONAL" if lead.get("task_id") and intel.get("available") and False else "READY"
        # keep simple: READY when task exists
        _emit("REVIEW_RESEARCH_TASK", status="READY")
    return steps


def _evidence_targets_for(lead: dict, intel: dict, payload: dict, doc, relevance_row: Optional[dict]) -> list[dict]:
    """Deterministic evidence targets (what should be reviewed, not what was proven)."""
    targets: list[dict] = []
    exp = intel.get("exploitability") or {}
    refs = []
    try:
        refs = (payload.get("research") or {}).get("references") or []
    except Exception:
        refs = []
    components = list(getattr(doc, "components", []) or []) if doc is not None else []
    parameters = list(getattr(doc, "parameters", []) or []) if doc is not None else []
    affected_versions = []
    try:
        affected_versions = (payload.get("research") or {}).get("affected_versions") or []
    except Exception:
        affected_versions = []

    def _add(code: str):
        meta = EVIDENCE_META[code]
        targets.append({"code": code, "description": meta["description"], "source": meta["source"], "required": bool(meta["required"])})

    # CVE_REFERENCE — when CVE is available
    if intel.get("available"):
        _add("CVE_REFERENCE")
    # VENDOR_ADVISORY — when references look like advisory (wordfence/vendor/advisory/bulletin in refs)
    if refs:
        joined = " ".join(str(r).lower() for r in refs)
        if any(tok in joined for tok in ("wordfence", "vendor", "advisory", "bulletin", "trac.wordpress.org")):
            _add("VENDOR_ADVISORY")
        else:
            # still only when refs exist, emit vendor advisory as informational? spec says only when justified, so skip if not vendor-like
            pass
    # PUBLIC_POC — only when true
    if exp.get("public_poc") == "true":
        _add("PUBLIC_POC")
    # EXPLOIT_REFERENCE — when exploit_available true
    if exp.get("exploit_available") == "true":
        _add("EXPLOIT_REFERENCE")
    # AFFECTED_COMPONENT — when components identified
    if components:
        _add("AFFECTED_COMPONENT")
    # AFFECTED_PARAMETER — when parameters identified
    if parameters:
        _add("AFFECTED_PARAMETER")
    # AFFECTED_VERSION — when version range known
    if affected_versions:
        _add("AFFECTED_VERSION")
    # ASSET_TECHNOLOGY — when tech match observed
    if relevance_row and any("technology match" in str(r) for r in (relevance_row.get("reasons") or [])):
        _add("ASSET_TECHNOLOGY")
    # ASSET_COMPONENT — when component match observed
    if relevance_row and any("plugin" in str(r) or "component" in str(r) or "product match" in str(r) for r in (relevance_row.get("reasons") or [])):
        _add("ASSET_COMPONENT")
    # ASSET_VERSION — when asset version evidence not blocked? we have no positive version asset signal in current corpus, so omit unless not blocked
    # Only emit when version was expected and not blocked? For now, emit only if no blocker about version unknown and affected version exists and relevance suggests version?
    # Keep absent for current corpus (no positive asset version signal)
    # RESEARCH_TASK_CONTEXT — when task exists
    if lead.get("task_id"):
        _add("RESEARCH_TASK_CONTEXT")
    # Ensure deterministic order per EVIDENCE_ORDER
    order_index = {code: idx for idx, code in enumerate(EVIDENCE_ORDER)}
    targets.sort(key=lambda t: order_index.get(t["code"], 999))
    return targets


def _unknowns_for(lead: dict, intel: dict, payload: dict, doc, relevance_row: Optional[dict]) -> list[str]:
    """Explicitly preserve unresolved facts (never convert unknown into positive)."""
    out: list[str] = []
    exp = intel.get("exploitability") or {}
    components = list(getattr(doc, "components", []) or []) if doc is not None else []
    parameters = list(getattr(doc, "parameters", []) or []) if doc is not None else []
    affected_versions = []
    try:
        affected_versions = (payload.get("research") or {}).get("affected_versions") or []
    except Exception:
        affected_versions = []

    # exploitability unknowns — only when strictly unknown
    if exp.get("authentication_required") == "unknown":
        out.append("authentication requirement unknown")
    if exp.get("privilege_required") == "unknown":
        out.append("privilege requirement unknown")
    if exp.get("user_interaction_required") == "unknown":
        out.append("user interaction requirement unknown")
    if exp.get("exploit_available") == "unknown":
        out.append("exploit availability unknown")
    if exp.get("public_poc") == "unknown":
        out.append("public PoC unknown")
    if exp.get("active_exploitation") == "unknown":
        out.append("active exploitation unknown")
    if exp.get("exploit_complexity") == "unknown":
        out.append("exploit complexity unknown")
    # component / parameter / version unknowns
    if not components:
        out.append("affected component not identified")
    if not parameters:
        out.append("affected parameter unknown")
    if not affected_versions:
        out.append("affected version unknown")
    # asset-side unknowns from relevance unknown_factors and blockers that are informative
    # Preserve blocker phrasing as unknown when it indicates not observed
    for blocker in (lead.get("blockers") or []):
        # expose blockers that are unknown-like as unknowns as well for explicitness
        if blocker in ("affected plugin not observed", "asset component not observed", "asset version unknown", "only generic technology match"):
            # keep blocker text as unknown phrasing
            if blocker == "asset version unknown":
                if "asset version unknown" not in out:
                    out.append("asset version unknown")
            elif blocker == "affected plugin not observed":
                out.append("affected plugin not observed")
            elif blocker == "asset component not observed":
                out.append("asset component not observed")
            elif blocker == "only generic technology match":
                out.append("only generic technology match — asset specificity unknown")
    # relevance unknown_factors (deterministic)
    for uf in (relevance_row or {}).get("unknown_factors") or []:
        txt = str(uf).strip()
        if txt and txt not in out:
            out.append(txt)
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for item in out:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


# Deterministic recommended_start precedence (separate from steps[] display
# order, which always follows STEP_ORDER). Only a step actually present in
# steps[] may be chosen; UNKNOWN never yields a positive recommendation
# because steps[] itself is never emitted for UNKNOWN values.
RECOMMENDED_START_ORDER = [
    "REVIEW_PUBLIC_POC",
    "REVIEW_EXPLOITABILITY",
    "REVIEW_TECHNOLOGY_MATCH",
    "REVIEW_COMPONENT_MATCH",
    "REVIEW_PARAMETER_MATCH",
    "REVIEW_VERSION",
    "REVIEW_ASSET_EVIDENCE",
    "REVIEW_REFERENCES",
    "REVIEW_CVE_SUMMARY",
]


def _recommended_start_for(steps: list[dict]) -> Optional[str]:
    """Pick the most actionable emitted step per RECOMMENDED_START_ORDER.

    steps[] display order is untouched (always STEP_ORDER). This only selects
    which emitted step the researcher should start with. Returns None when
    there are no steps. Falls back to the first emitted step when none of the
    ranked codes match (e.g. a task-only plan), preserving the invariant that
    recommended_start always references an emitted step.
    """
    if not steps:
        return None
    present = {s.get("code") for s in steps}
    for code in RECOMMENDED_START_ORDER:
        if code in present:
            return code
    return steps[0].get("code")


def _build_plan(item: dict, intel: dict, payload: dict, doc, lead: dict) -> dict:
    cve = item.get("cve") or ""
    program = item.get("program") or ""
    relevance_row = next(
        (row for row in (intel.get("relevance") or []) if row.get("program") == program),
        None,
    )
    steps = _steps_for(lead, intel, payload, doc, relevance_row)
    evidence_targets = _evidence_targets_for(lead, intel, payload, doc, relevance_row)
    unknowns = _unknowns_for(lead, intel, payload, doc, relevance_row)
    blockers = list(lead.get("blockers") or [])
    # Recommended start is the most actionable emitted step (PoC-first),
    # NOT the first step in display order. steps[] order is unchanged.
    recommended_start = _recommended_start_for(steps)
    # Status derivation
    task_status = None
    # task_status is embedded in lead? we use lead's recommended_next? Instead use lead status
    # Derive from lead status and task linkage: DONE task -> COMPLETED
    if lead.get("status") == "RESEARCH_COMPLETED":
        status = PLAN_COMPLETED
    elif lead.get("status") == "RESEARCH_BLOCKED":
        status = PLAN_BLOCKED
    else:
        status = PLAN_READY
    # Override if lead has task_id with DONE semantics: check via research_tasks if needed; lead status already reflects it

    return {
        "plan_id": plan_id_for(cve, program),
        "lead_id": lead.get("lead_id"),
        "cve_id": cve,
        "program": program,
        "queue_id": item.get("queue_id"),
        "task_id": lead.get("task_id"),
        "priority_score": int(item.get("priority_score") or 0),
        "relevance_score": int(item.get("relevance_score") or 0),
        "status": status,
        "steps": steps,
        "evidence_targets": evidence_targets,
        "unknowns": unknowns,
        "blockers": blockers,
        "recommended_start": recommended_start,
        "rule_version": PLAN_RULE_VERSION,
        "metadata": {
            "priority_level": lead.get("priority_level"),
            "relevance_level": lead.get("relevance_level"),
            "recommended_next_step": lead.get("recommended_next_step"),
            "lead_status": lead.get("status"),
        },
    }


def build_plans() -> list[dict]:
    """Deterministic, idempotent plan projection over R21 leads (no writes)."""
    from backend import research_data as rd
    from backend import research_leads as rl

    leads = rl.build_leads()
    if not leads:
        return []
    # Map cve -> intel/payload/doc for efficiency (still local reads only)
    intel_by_cve: dict[str, dict] = {}
    payload_by_cve: dict[str, dict] = {}
    doc_by_cve: dict[str, object] = {}
    for lead in leads:
        cve = lead.get("cve_id") or ""
        if cve not in intel_by_cve:
            try:
                intel_by_cve[cve] = rd.cve_intelligence(cve)
            except Exception:
                intel_by_cve[cve] = {"cve": cve, "available": False, "relevance": [], "exploitability": {}}
        if cve not in payload_by_cve:
            try:
                payload, _ = rd._research_payload(cve)
                payload_by_cve[cve] = payload
            except Exception:
                payload_by_cve[cve] = {}
        if cve not in doc_by_cve:
            try:
                # reuse intel path to get doc via store
                from ai.knowledge.store import KnowledgeStore
                store = KnowledgeStore()
                docs = store.retrieve(tags=[f"cve:{cve}"])
                doc = next((d for d in docs if str(getattr(d, "source_url", "")).endswith(".cli.json")), None)
                doc_by_cve[cve] = doc
            except Exception:
                doc_by_cve[cve] = None

    # Build plans in lead rank order (deterministic)
    plans: list[dict] = []
    # Need queue item per lead for priority/relevance scores (use list_research_queue for queue_id mapping)
    queue_by_id: dict[str, dict] = {}
    try:
        queue_items = rd.list_research_queue(limit=MAX_PLANS, offset=0)["items"]
        for qi in queue_items:
            queue_by_id[qi.get("queue_id")] = qi
    except Exception:
        queue_by_id = {}

    for lead in leads:
        queue_id = lead.get("queue_id")
        item = queue_by_id.get(queue_id) or {
            "cve": lead.get("cve_id"),
            "program": lead.get("program"),
            "queue_id": queue_id,
            "priority_score": lead.get("priority_score"),
            "relevance_score": lead.get("relevance_score"),
        }
        cve = lead.get("cve_id") or ""
        intel = intel_by_cve.get(cve, {})
        payload = payload_by_cve.get(cve, {})
        doc = doc_by_cve.get(cve)
        plans.append(_build_plan(item, intel, payload, doc, lead))
    return plans


def list_plans(
    limit: int = 50,
    offset: int = 0,
    cve: Optional[str] = None,
    program: Optional[str] = None,
    lead: Optional[str] = None,
) -> dict:
    """Capped, deterministic plans slice (queue rank order preserved)."""
    from backend.research_data import clamp_limit, normalize_cve

    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    items = build_plans()
    if cve:
        cve = normalize_cve(cve)
        items = [p for p in items if p["cve_id"] == cve]
    if program:
        program = str(program).strip()
        items = [p for p in items if p["program"] == program]
    if lead:
        lead = str(lead).strip()
        # validate lead id shape loosely (rl- hex) but allow plan id too
        items = [p for p in items if p["lead_id"] == lead or p["plan_id"] == lead]
    total = len(items)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset: offset + limit],
    }


def get_plan(plan_id: str) -> dict:
    """One research execution plan by deterministic id (404 when absent)."""
    from backend.research_data import NotFoundError

    if not PLAN_ID_RE.match(str(plan_id).strip()):
        raise NotFoundError("expected a plan id like r22-0123456789abcdef")
    for plan in build_plans():
        if plan["plan_id"] == plan_id:
            return plan
    raise NotFoundError("no research plan with that id (no R18 queue candidate / R21 lead)")


def plans_summary() -> dict:
    """Compact dashboard counts: ready / blocked / completed / total."""
    plans = build_plans()
    ready = sum(1 for p in plans if p["status"] == PLAN_READY)
    blocked = sum(1 for p in plans if p["status"] == PLAN_BLOCKED)
    completed = sum(1 for p in plans if p["status"] == PLAN_COMPLETED)
    top = sorted(
        (p for p in plans if p["status"] == PLAN_READY),
        key=lambda p: (p["priority_score"], p["relevance_score"], p["cve_id"], p["program"]),
        reverse=True,
    )[:3]
    return {
        "total": len(plans),
        "ready": ready,
        "blocked": blocked,
        "completed": completed,
        "top": top,
    }
