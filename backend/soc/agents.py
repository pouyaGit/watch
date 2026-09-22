"""backend/soc/agents.py — SOC-2 AI agent intelligence adapters (read-only).

Builds per-agent pages from the real agent registries, the investigation
memory store, the knowledge base, research loop records (CVEs analyzed) and
the AEC case explorer.

Identity sources are layered and all of them are optional: the
research-agent registry is used when that runtime is deployed, otherwise
the engine's own deterministic specialist registry
(``ai.knowledge.specialist_registry``) supplies the declared agents, and an
environment with neither renders an explicit empty state.  Nothing here
writes, executes, or fabricates: every value is projected from a declared
field, and when a source is absent the block is simply empty.

Runtime status is derived, never defaulted:

* ``PLANNED`` — a definition exists but no agent runtime reports this agent,
  so it cannot be executing or accepting work (the deployed tree today);
* ``READY``   — the agent runtime is deployed and reports the agent able to
  accept work, with nothing executing;
* ``ACTIVE``  — the agent runtime reports jobs executing right now.

``IDLE`` is deliberately not used: the runtime exposes definition readiness,
queue depth and job counts, which cannot distinguish "idle with no work" from
"ready for work" — showing IDLE would be a guess.  Queue/active/total counters
are ``None`` (rendered as *not tracked*) whenever no runtime reports them, so a
missing runtime is never displayed as a zero-activity worker.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.soc._util import (
    _as_list,
    _bounded,
    _key_from_slug,
    _slug,
    _text,
)

_PAPERS_LIMIT = 12
_CVES_LIMIT = 12
_NOTES_LIMIT = 12
_CASES_LIMIT = 12
_KB_HARVEST_LIMIT = 40

# ---------------------------------------------------------------- status model
STATUS_PLANNED = "PLANNED"
STATUS_READY = "READY"
STATUS_ACTIVE = "ACTIVE"
STATUS_VALUES = (STATUS_PLANNED, STATUS_READY, STATUS_ACTIVE)

MEANING_PLANNED = (
    "definition exists — no agent runtime is deployed in this environment, "
    "so it cannot execute or accept work")
MEANING_PLANNED_REGISTERED = (
    "registered in the agent runtime but not marked ready")
MEANING_READY = (
    "the agent runtime is deployed and reports this agent able to accept "
    "work; nothing is executing right now")
MEANING_ACTIVE = "the agent runtime reports jobs executing right now"

_RUNTIME_SOURCE = "backend.research_agents.service"


def _runtime_status(tracked: bool, stats: Mapping[str, Any]) -> tuple[str, str]:
    """(status, meaning) derived from what the runtime actually reports.

    Nothing here falls back to a flattering default: without a runtime
    report the agent is PLANNED, whatever the definition claims.
    """
    if not tracked:
        return STATUS_PLANNED, MEANING_PLANNED
    if int(stats.get("active_jobs") or 0) > 0:
        return STATUS_ACTIVE, MEANING_ACTIVE
    if bool(stats.get("available")):
        return STATUS_READY, MEANING_READY
    return STATUS_PLANNED, MEANING_PLANNED_REGISTERED


def _runtime_block(deployed: bool) -> dict[str, Any]:
    """Page-level runtime banner (real, or an explicit absence)."""
    if deployed:
        return {
            "deployed": True,
            "source": _RUNTIME_SOURCE,
            "meaning": "queue, active-job and job counters come from "
                       f"{_RUNTIME_SOURCE}",
        }
    return {
        "deployed": False,
        "source": "",
        "meaning": "No agent runtime is deployed in this environment — queue, "
                   "active jobs and total jobs are not tracked for any agent",
    }


def _deployed_registry_agents() -> list[dict[str, Any]]:
    """Agent definitions from the optional research-agent runtime."""

    try:
        from backend.research_agents.registry import build_default_registry

        rows: list[dict[str, Any]] = []
        for agent in build_default_registry().list_agents():
            declared = agent.to_dict()
            if isinstance(declared, Mapping):
                rows.append(dict(declared))
        return rows
    except Exception:
        return []


def _engine_specialist_agents() -> list[dict[str, Any]]:
    """Declared agents from the engine's own specialist registry.

    Real, deterministic identities (``ai.knowledge.specialist_registry``)
    projected into the shape the SOC agent views consume:

      * ``evidence_types`` <- the agent's declared supported contexts
      * ``strategy``       <- the agent's declared supported capabilities

    No name, status, description or counter is invented; entries without a
    declared name are skipped rather than filled in.
    """

    try:
        from ai.knowledge import specialist_registry as sr
    except Exception:
        return []

    try:
        categories = tuple(sr.CANONICAL_SPECIALIST_ORDER)
    except Exception:
        return []

    rows: list[dict[str, Any]] = []
    for category in categories:
        key = _text(category).lower()
        if not key:
            continue
        try:
            identity = sr.specialist_identity(category) or {}
        except Exception:
            continue
        if not isinstance(identity, Mapping):
            continue
        name = _text(identity.get("agent_name"))
        if not name:
            continue
        rows.append({
            "key": key,
            "name": name,
            "category": key,
            "status": _text(identity.get("lifecycle_state")),
            "description": _text(identity.get("description")),
            "evidence_types": list(_as_list(identity.get("supported_contexts"))),
            "strategy": list(_as_list(identity.get("supported_capabilities"))),
        })
    return rows


def _registry_agents() -> list[dict[str, Any]]:
    """Registered specialist agents — first available real source wins."""

    rows = _deployed_registry_agents()
    if rows:
        return rows
    return _engine_specialist_agents()


def _runtime_report() -> tuple[bool, dict[str, dict[str, Any]]]:
    """(runtime deployed, per-key counters) from the real orchestration facade.

    Only ``backend.research_agents.service`` can report queue/job counters for
    these agents.  When it is absent (the deployed tree) or raises, the runtime
    is reported as *absent* and no counter is invented.
    """
    try:
        from backend.research_agents import service as ra

        payload = ra.agents_payload()
    except Exception:
        return False, {}
    if not isinstance(payload, Mapping):
        return False, {}
    out: dict[str, dict[str, Any]] = {}
    for entry in payload.get("agents", []) or []:
        if not isinstance(entry, Mapping):
            continue
        key = _text(entry.get("category")).lower()
        if not key:
            continue
        out[key] = {
            "queue": int(entry.get("queue") or 0),
            "active_jobs": int(entry.get("active_jobs") or 0),
            "job_count": int(entry.get("job_count") or 0),
            "available": bool(entry.get("available")),
        }
    return True, out


def _service_counts() -> dict[str, dict[str, Any]]:
    """Counters only (runtime presence is reported by ``_runtime_report``)."""

    return _runtime_report()[1]


def _declared_lifecycle(agent: Mapping[str, Any]) -> str:
    """The registry's own declared lifecycle/status, verbatim.

    Empty string when the definition declares none — never a substituted
    default, so the UI can say "not declared" truthfully.
    """

    return _text(agent.get("lifecycle_state")) or _text(agent.get("status"))


def _memory_summary() -> dict[str, Any]:
    """Real research-memory learning summary (empty-safe)."""
    try:
        from backend.investigation_engine.memory import ResearchMemory

        memory = ResearchMemory(path="ai_data/investigations/memory.json")
        return memory.learning_summary(limit=20)
    except Exception:
        return {"available": False, "total": 0, "by_agent": {},
                "by_category": {}, "by_status": {}, "false_positives": 0,
                "recent": [], "top_missing_evidence": []}


def _kb_documents() -> list[dict[str, Any]]:
    """Knowledge-base document metadata (read-only, bounded)."""
    try:
        from backend import research_data as rd

        result = rd.list_kb(limit=_KB_HARVEST_LIMIT)
        return list(result.get("items", []))
    except Exception:
        return []


def _cve_records() -> list[dict[str, Any]]:
    """Research loop records (CVEs studied by the research agent)."""
    import glob
    import json
    from pathlib import Path

    records: list[dict[str, Any]] = []
    for path in sorted(glob.glob("ai_data/research/agent/*.loop.json")):
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        cve = _text(payload.get("cve_id"))
        if not cve:
            continue
        records.append({
            "id": cve,
            "status": _text(payload.get("status")),
            "plan_id": _text(payload.get("plan_id")),
            "result_id": _text(payload.get("result_id")),
        })
        if len(records) >= _CVES_LIMIT:
            break
    return records


def _case_rows() -> list[dict[str, Any]]:
    """AEC case-explorer rows (read-only public view)."""
    try:
        from backend.routers import aec

        view = aec.build_case_explorer_view()
        return list(view.get("cases", []))
    except Exception:
        return []


def agents_index() -> dict[str, Any]:
    """Declared agents + runtime-derived status (never a defaulted status).

    Degrades to an empty index (never raises) when no identity source is
    available, so the page can render an explicit empty state.  Counters are
    ``None`` unless a runtime actually reports them: a missing runtime is
    shown as *not tracked*, never as a worker with zero jobs.
    """
    try:
        declared = _registry_agents()
    except Exception:
        declared = []
    runtime_deployed, counts = _runtime_report()
    agents: list[dict[str, Any]] = []
    for agent in declared:
        if not isinstance(agent, Mapping):
            continue
        key = _text(agent.get("key")).lower()
        stats = counts.get(key) or counts.get(_text(agent.get("category"))) or {}  # noqa: E501
        tracked = runtime_deployed and key in counts
        status, meaning = _runtime_status(tracked, stats)
        agents.append({
            "slug": _slug(key),
            "key": key,
            "name": _text(agent.get("name")),
            "purpose": _text(agent.get("description")),
            "role": _text(agent.get("category")),
            "status": status,
            "status_meaning": meaning,
            "declared_lifecycle": _declared_lifecycle(agent),
            "runtime_tracked": tracked,
            "queue": int(stats.get("queue") or 0) if tracked else None,
            "active_jobs": int(stats.get("active_jobs") or 0) if tracked else None,  # noqa: E501
            "job_count": int(stats.get("job_count") or 0) if tracked else None,
            "available": bool(stats.get("available")) if tracked else False,
        })
    agents.sort(key=lambda a: a["name"])
    return {"count": len(agents), "agents": agents,
            "runtime": _runtime_block(runtime_deployed)}


def _agent_knowledge(agent_key: str, agent_name: str) -> dict[str, list[str]]:
    """Knowledge areas: grounded in the real registry entry + KB + memory.

    vulnerability_areas -> the agent's declared evidence types.
    techniques          -> the agent's declared strategy steps.
    frameworks          -> technologies harvested from KB docs.
    topics              -> previous research topics from memory.
    """
    declared: dict[str, Any] = {}
    for agent in _registry_agents():
        if not isinstance(agent, Mapping):
            continue
        if _text(agent.get("key")).lower() == agent_key.lower():
            declared = dict(agent)
            break

    areas: list[str] = []
    for item in _as_list(declared.get("evidence_types")):
        if _text(item):
            areas.append(_text(item).lower())
    if not areas and agent_key:
        areas = [agent_key]

    techniques: list[str] = []
    for item in _as_list(declared.get("strategy")):
        if _text(item):
            techniques.append(_text(item))
    if not techniques:
        description = _text(declared.get("description"))
        techniques = [description] if description else []

    frameworks: list[str] = []
    for doc in _kb_documents():
        for tech in _as_list(doc.get("technologies")):
            name = _text(tech)
            if name and name not in frameworks:
                frameworks.append(name)

    topics: list[str] = []
    summary = _memory_summary()
    for entry in summary.get("recent", []):
        if _text(entry.get("agent")).lower() == agent_name.lower():
            topic = _text(entry.get("target")) or _text(entry.get("category"))
            if topic and topic not in topics:
                topics.append(topic)
    return {
        "vulnerability_areas": _bounded(areas, 8),
        "techniques": _bounded(techniques, 10),
        "frameworks": _bounded(frameworks, 10),
        "topics": _bounded(topics, 12),
    }


def _memory_source_available() -> bool:
    """Whether the agent-attributed research memory exists here (import only)."""

    try:
        from backend.investigation_engine.memory import ResearchMemory  # noqa: F401,E501

        return True
    except Exception:
        return False


def _agent_history(agent_name: str) -> dict[str, Any]:
    """Research history, split by attribution truth.

    ``papers``/``cves`` are platform-wide records (no agent attribution field
    exists in them); ``notes`` are the only agent-attributed records.  The
    ``scopes`` block tells the page which is which, and
    ``notes_source_available`` distinguishes "nothing recorded" from "the
    attributing store is not deployed".
    """
    papers: list[dict[str, Any]] = []
    for doc in _kb_documents():
        title = _text(doc.get("title"))
        if not title:
            continue
        papers.append({
            "title": title,
            "source_url": _text(doc.get("source_url")),
            "source_type": _text(doc.get("source_type")) or "",
            "indexed_at": _text(doc.get("indexed_at")),
            "knowledge_id": _text(doc.get("knowledge_id")),
        })
        if len(papers) >= _PAPERS_LIMIT:
            break

    notes: list[dict[str, Any]] = []
    summary = _memory_summary()
    for entry in summary.get("recent", []):
        if _text(entry.get("agent")).lower() != agent_name.lower():
            continue
        notes.append({
            "target": _text(entry.get("target")),
            "endpoint": _text(entry.get("endpoint")),
            "parameter": _text(entry.get("parameter")),
            "category": _text(entry.get("category")),
            "status": _text(entry.get("status")),
            "confidence": _text(entry.get("confidence")),
            "last_seen": _text(entry.get("last_seen")),
            "occurrences": int(entry.get("occurrences") or 0),
        })
        if len(notes) >= _NOTES_LIMIT:
            break

    return {
        "papers": papers,
        "cves": _cve_records(),
        "notes": notes,
        "scopes": {
            "papers": "platform-wide — knowledge-base documents, not "
                      "attributed to individual agents",
            "cves": "platform-wide — research-loop records, not attributed "
                    "to individual agents",
            "notes": "agent-attributed — research memory",
        },
        "notes_source_available": _memory_source_available(),
    }


def _agent_cases(agent_key: str) -> list[dict[str, Any]]:
    """Target cases for one agent, from the AEC case explorer."""
    out: list[dict[str, Any]] = []
    for row in _case_rows():
        # case explorers carry category + specialist; match the agent by
        # category (canonical) or by specialist label.
        cat = _text(row.get("category")).lower()
        specialist = _text(row.get("specialist")).lower()
        if cat != agent_key.lower() and agent_key.lower() not in specialist:
            continue
        out.append({
            "case_id": _text(row.get("case_id")),
            "target": _text(row.get("target")),
            "category": cat,
            "evidence_status": _text(row.get("evidence_state"))
            or _text(row.get("research_state")),
            "specialist": _text(row.get("specialist")),
            "next_action": _text(row.get("next_action")),
            "detail_url": f"/ui/soc/cases/{_text(row.get('case_id'))}",
        })
        if len(out) >= _CASES_LIMIT:
            break
    return out


def agent_detail(slug: str) -> dict[str, Any] | None:
    """One agent page.  None when the slug does not resolve."""
    key = _key_from_slug(slug)
    if not key:
        return None
    try:
        declared = _registry_agents()
    except Exception:
        declared = []
    found = None
    for agent in declared:
        if not isinstance(agent, Mapping):
            continue
        if _text(agent.get("key")).lower() == key:
            found = agent
            break
    if found is None:
        return None
    name = _text(found.get("name"))
    runtime_deployed, counts = _runtime_report()
    tracked = runtime_deployed and key in counts
    stats = counts.get(key) or {}
    status, meaning = _runtime_status(tracked, stats)
    declared_lifecycle = _declared_lifecycle(found) or "NOT DECLARED"
    can_execute = tracked and bool(stats.get("available"))
    runtime = _runtime_block(runtime_deployed)
    runtime.update({
        "tracked": tracked,
        "queue": int(stats.get("queue") or 0) if tracked else None,
        "active_jobs": int(stats.get("active_jobs") or 0) if tracked else None,
        "job_count": int(stats.get("job_count") or 0) if tracked else None,
        "available": bool(stats.get("available")) if tracked else False,
    })
    if can_execute:
        capability_now = (
            "The deployed agent runtime reports this agent able to accept "
            "work; counters below come from that runtime.")
        capability_planned = "Declared capabilities can be dispatched by the deployed runtime."  # noqa: E501
    else:
        capability_now = (
            "Not executable in this deployment: execution, queueing and "
            "scheduling for this agent are not implemented in any deployed "
            "runtime, so it cannot be running work.")
        capability_planned = (
            "These capabilities are declared in the agent registry only; "
            "they are planned, not implemented, in this deployment.")
    knowledge = _agent_knowledge(key, name)
    history = _agent_history(name)
    return {
        "identity": {
            "slug": slug,
            "key": key,
            "name": name,
            "purpose": _text(found.get("description")),
            "role": _text(found.get("category")),
            "status": status,
            "status_meaning": meaning,
            "declared_lifecycle": declared_lifecycle,
            "research_only": bool(found.get("research_only", True)),
            "description": _text(found.get("description")),
        },
        "runtime": runtime,
        "capability": {
            "can_execute_now": can_execute,
            "now": capability_now,
            "declared": list(knowledge.get("techniques") or []),
            "planned": capability_planned,
        },
        "knowledge": knowledge,
        "history": history,
        "target_cases": _agent_cases(key),
        "cases_scope": "association by vulnerability category (AEC case "
                       "explorer) — it does not mean this agent executed "
                       "the case",
        "sources": {
            "identity": (
                _RUNTIME_SOURCE.replace(".service", ".registry")
                if runtime_deployed
                else "ai.knowledge.specialist_registry — engine specialist definitions"  # noqa: E501
            ),
            "runtime": runtime["source"],
            "knowledge_base": "backend.research_data — platform-wide, not attributed to individual agents",  # noqa: E501
            "research_memory": (
                "backend.investigation_engine.memory — agent-attributed"
                if history["notes_source_available"] else ""
            ),
            "cases": "AEC case explorer — association by vulnerability category",  # noqa: E501
        },
        "counters": {
            "queue": runtime["queue"],
            "active_jobs": runtime["active_jobs"],
            "job_count": runtime["job_count"],
            "available": runtime["available"],
        },
    }