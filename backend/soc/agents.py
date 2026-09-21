"""backend/soc/agents.py — SOC-2 AI agent intelligence adapters (read-only).

Builds per-agent pages from the real research-agent registry, the
investigation memory store, the knowledge base, research loop records
(CVEs analyzed) and the AEC case explorer.

Nothing here writes, executes, or fabricates.  When a source is absent
the block is simply empty.
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


def _registry_agents() -> list[dict[str, Any]]:
    """Registered specialist agents (real definitions)."""
    from backend.research_agents.registry import build_default_registry

    return [
        a.to_dict() for a in build_default_registry().list_agents()
    ]


def _service_counts() -> dict[str, dict[str, int]]:
    """Per-agent runtime counters from the real orchestration facade."""
    try:
        from backend.research_agents import service as ra

        payload = ra.agents_payload()
        out: dict[str, dict[str, int]] = {}
        for entry in payload.get("agents", []):
            key = _text(entry.get("category")).lower()
            out[key] = {
                "queue": int(entry.get("queue") or 0),
                "active_jobs": int(entry.get("active_jobs") or 0),
                "job_count": int(entry.get("job_count") or 0),
                "available": bool(entry.get("available")),
            }
        return out
    except Exception:
        return {}


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
    """All registered AI agents with identity + live counters."""
    agents: list[dict[str, Any]] = []
    counts = _service_counts()
    for agent in _registry_agents():
        key = _text(agent.get("key")).lower()
        stats = counts.get(key) or counts.get(_text(agent.get("category"))) or {}  # noqa: E501
        agents.append({
            "slug": _slug(_text(agent.get("key"))),
            "key": _text(agent.get("key")),
            "name": _text(agent.get("name")),
            "purpose": _text(agent.get("description")),
            "role": _text(agent.get("category")),
            "status": _text(agent.get("status")) or "ready",
            "queue": int(stats.get("queue") or 0),
            "active_jobs": int(stats.get("active_jobs") or 0),
            "job_count": int(stats.get("job_count") or 0),
            "available": bool(stats.get("available", True)),
        })
    agents.sort(key=lambda a: a["name"])
    return {"count": len(agents), "agents": agents}


def _agent_knowledge(agent_key: str, agent_name: str) -> dict[str, list[str]]:
    """Knowledge areas: grounded in the real registry entry + KB + memory.

    vulnerability_areas -> the agent's declared evidence types.
    techniques          -> the agent's declared strategy steps.
    frameworks          -> technologies harvested from KB docs.
    topics              -> previous research topics from memory.
    """
    declared: dict[str, Any] = {}
    for agent in _registry_agents():
        if _text(agent.get("key")).lower() == agent_key.lower():
            declared = agent
            break

    areas: list[str] = []
    for item in _as_list(declared.get("evidence_types")):
        if _text(item):
            areas.append(_text(item).lower())
    if not areas:
        areas = [agent_key]

    techniques: list[str] = []
    for item in _as_list(declared.get("strategy")):
        if _text(item):
            techniques.append(_text(item))
    if not techniques:
        techniques = [_text(declared.get("description"))]

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


def _agent_history(agent_name: str) -> dict[str, list[dict[str, Any]]]:
    """Research history: papers, CVEs analyzed, internal notes."""
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
    found = None
    for agent in _registry_agents():
        if _text(agent.get("key")).lower() == key:
            found = agent
            break
    if found is None:
        return None
    name = _text(found.get("name"))
    counts = _service_counts().get(key) or {}
    return {
        "identity": {
            "slug": slug,
            "key": key,
            "name": name,
            "purpose": _text(found.get("description")),
            "role": _text(found.get("category")),
            "status": _text(found.get("status")) or "ready",
            "description": _text(found.get("description")),
        },
        "knowledge": _agent_knowledge(key, name),
        "history": _agent_history(name),
        "target_cases": _agent_cases(key),
        "counters": {
            "queue": int(counts.get("queue") or 0),
            "active_jobs": int(counts.get("active_jobs") or 0),
            "job_count": int(counts.get("job_count") or 0),
            "available": bool(counts.get("available", True)),
        },
    }