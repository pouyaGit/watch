"""backend/research_agents/intelligence/learning.py — Phase 2 learning loop.

Consumes a COMPLETED research job and extracts reusable research memory.
The authoritative outcome always comes from the deterministic evidence
gate (``decision``), never from the LLM:

- gate created a case  -> VERIFIED ``confirmed_historical_result`` (the only
  producer of VERIFIED items anywhere in the system),
- gate did not create a case -> hypotheses become REJECTED negative
  research memory carrying the gate reason,
- LLM hypotheses are at most INFERRED,
- observations produce OBSERVED patterns (including observed absence),
- knowledge/capability reads produce RESEARCHED items,
- honest job failures produce a RESEARCHED research_recommendation
  recording the failure reason.

Extraction is pure (``extract``) so tests can assert state transitions
without touching disk; ``learn`` applies dedup + append and raises
``MemoryUnavailable`` on storage failure (never a fake memory).
"""

from __future__ import annotations

from typing import Any

from backend.research_agents.intelligence.memory import (
    MemoryItem,
    MemoryStore,
    make_item,
    scrub_text,
    should_append,
)

# States the LLM path may ever reach (never VERIFIED).
ADVISORY_MAX_STATE = "INFERRED"


def _job_target(job: Any) -> str:
    return str(getattr(job, "subdomain", "") or getattr(job, "program", "")
               or "")


def _provenance_refs(rows: list[dict[str, Any]], key: str = "ref") -> list[str]:
    refs: list[str] = []
    for row in rows:
        ref = str(row.get(key) or row.get("_id") or "").strip()
        if ref and ref not in refs:
            refs.append(ref)
        if len(refs) >= 8:
            break
    return refs


def extract(
    *,
    job: Any,
    capability: Any,
    decision: Any,
    analysis: dict[str, Any],
    observations: list[dict[str, Any]],
    knowledge: list[dict[str, Any]],
    case_id: str = "",
) -> list[MemoryItem]:
    """Pure gate-authoritative extraction of memory items (validated)."""
    category = str(getattr(job, "agent_category", "") or "")
    agent = str(getattr(job, "assigned_agent", "") or "")
    target = _job_target(job)
    program = str(getattr(job, "program", "") or "")
    job_id = str(getattr(job, "id", "") or "")
    if not job_id:
        raise ValueError("learning requires a job id")
    out: list[MemoryItem] = []

    def add(**kw: Any) -> None:
        out.append(make_item(
            category=category, agent=agent, target=target, program=program,
            provenance_job=job_id, **kw))

    # -- OBSERVED: structural facts from the observation set --------------
    params: list[str] = []
    statuses: dict[str, int] = {}
    techs: list[str] = []
    db_style = 0
    paths: list[str] = []
    for row in observations:
        for p in (row.get("params") or [])[:12]:
            name = scrub_text(p, 40)
            if name and name not in params:
                params.append(name)
        status = row.get("status")
        if isinstance(status, int) and status:
            statuses[str(status)] = statuses.get(str(status), 0) + 1
        tech = scrub_text(row.get("tech"), 60)
        if tech and tech not in techs:
            techs.append(tech)
        if row.get("db_error_style"):
            db_style += 1
        path = scrub_text(row.get("path"), 80)
        if path and path not in paths:
            paths.append(path)
    obs_refs = _provenance_refs(observations)
    if params:
        add(kind="parameter_pattern", state="OBSERVED",
            subject_key="params:" + ",".join(sorted(params)[:10]),
            text=("observation set exposes parameters: "
                  + ", ".join(sorted(params)[:12])),
            confidence="observed",
            provenance_source="observation_store", provenance_refs=obs_refs)
    if statuses:
        dist = ", ".join(f"{k}x{v}" for k, v in sorted(statuses.items()))
        add(kind="observed_behavior", state="OBSERVED",
            subject_key="status:" + dist,
            text=f"stored responses show status distribution {dist}",
            confidence="observed",
            provenance_source="observation_store", provenance_refs=obs_refs)
    if techs:
        add(kind="technology", state="OBSERVED",
            subject_key="tech:" + ",".join(sorted(techs)[:6]),
            text=("technology signals recorded in observations: "
                  + ", ".join(sorted(techs)[:6])),
            confidence="observed",
            provenance_source="observation_store", provenance_refs=obs_refs)
    if paths:
        heads = sorted({"/".join(p.split("/")[:2]) or "/" for p in paths})
        add(kind="endpoint_pattern", state="OBSERVED",
            subject_key="paths:" + ",".join(heads[:8]),
            text=("endpoint shapes observed: " + ", ".join(heads[:8])),
            confidence="observed",
            provenance_source="observation_store", provenance_refs=obs_refs)
    if not observations:
        add(kind="negative_evidence", state="OBSERVED",
            subject_key="no-observations",
            text="observation store returned no rows for this scope",
            confidence="observed",
            provenance_source="observation_store", provenance_refs=[])

    # -- RESEARCHED: knowledge actually read + capability contract --------
    for doc in knowledge[:8]:
        doc_id = scrub_text(doc.get("id"), 80)
        if not doc_id:
            continue
        add(kind="source_reference", state="RESEARCHED",
            subject_key=f"kb:{doc_id}",
            text=scrub_text(doc.get("title") or doc_id, 240),
            confidence="reference",
            provenance_source="knowledge_read", provenance_refs=[doc_id])
    req = getattr(capability, "evidence_requirements", None)
    for ev_type in (getattr(req, "required_types", None) or ())[:6]:
        add(kind="evidence_requirement", state="RESEARCHED",
            subject_key=f"requires:{ev_type}",
            text=(f"case creation for this specialist requires evidence "
                  f"type {ev_type} (min {getattr(req, 'min_evidence_refs', 0)} "
                  f"refs"
                  + (", high confidence"
                     if getattr(req, "require_high_confidence", False)
                     else "") + ")"),
            confidence="declared",
            provenance_source="capability",
            provenance_refs=[str(getattr(capability, "agent_name", ""))])
    add(kind="vulnerability_class", state="RESEARCHED",
        subject_key=f"class:{category}",
        text=scrub_text(getattr(capability, "specialization", "")
                        or capability.category, 300),
        confidence="declared",
        provenance_source="capability",
        provenance_refs=[str(getattr(capability, "agent_name", ""))])

    # -- OBSERVED negative evidence from deterministic blockers ------------
    for blocker in (analysis.get("blockers") or [])[:6]:
        text = scrub_text(blocker, 200)
        if not text:
            continue
        add(kind="negative_evidence", state="OBSERVED",
            subject_key="blocker:" + text[:80],
            text=f"deterministic analysis recorded: {text}",
            confidence="observed",
            provenance_source="deterministic_analysis", provenance_refs=[])

    # -- INFERRED: LLM/advisory hypotheses (never verified by text) --------
    hypotheses: list[dict[str, Any]] = list(analysis.get("hypotheses") or [])
    if not hypotheses and analysis.get("hypothesis"):
        hypotheses = [{"hypothesis": analysis.get("hypothesis")}]
    for hyp in hypotheses[:3]:
        text = scrub_text(hyp.get("hypothesis"), 300)
        if not text:
            continue
        add(kind="hypothesis", state="INFERRED",
            subject_key="hyp:" + text[:80], text=text,
            confidence="advisory",
            provenance_source=("llm_advisory"
                               if analysis.get("analysis_via") == "llm"
                               else "deterministic_analysis"),
            provenance_refs=[str(analysis.get("prompt_version") or "")],
            limitations=("LLM/deterministic hypothesis; only the evidence "
                         "gate can verify or reject it"))

    # -- GATE OUTCOME: the authoritative part ------------------------------
    created = bool(getattr(decision, "create", False))
    reason = str(getattr(decision, "reason", "") or "unknown")
    if created and case_id:
        add(kind="confirmed_historical_result", state="VERIFIED",
            subject_key=f"case:{case_id}",
            text=(f"evidence gate created case {case_id} for this research "
                  f"job (reason={reason}, confidence="
                  f"{analysis.get('confidence', 'unknown')})"),
            confidence=str(analysis.get("confidence", "unknown")),
            provenance_source="evidence_gate",
            provenance_refs=[case_id] + [
                e for e in (analysis.get("evidence_refs") or [])][:6],
            limitations="verified by deterministic evidence gate rules")
    elif not created:
        for hyp in hypotheses[:3]:
            text = scrub_text(hyp.get("hypothesis"), 300)
            if not text:
                continue
            add(kind="rejected_hypothesis", state="REJECTED",
                subject_key="rej:" + text[:80],
                text=(f"not established by the evidence gate "
                      f"(reason={reason}): {text}"),
                confidence="rejected_by_gate",
                provenance_source="evidence_gate",
                provenance_refs=[reason],
                limitations=("negative research memory; the hypothesis was "
                             "not established — this is not a disproof"))
    return out


def learn(
    store: MemoryStore,
    *,
    job: Any,
    capability: Any,
    decision: Any,
    analysis: dict[str, Any],
    observations: list[dict[str, Any]],
    knowledge: list[dict[str, Any]],
    case_id: str = "",
) -> dict[str, Any]:
    """Extract + dedup + persist; raises MemoryUnavailable on store failure."""
    items = extract(job=job, capability=capability, decision=decision,
                     analysis=analysis, observations=observations,
                     knowledge=knowledge, case_id=case_id)
    heads = {i.id: i for i in store.heads()}
    fresh = [i for i in items if should_append(heads.get(i.id), i)]
    written = store.append(fresh) if fresh else 0
    return {
        "extracted": len(items),
        "appended": written,
        "ids": [i.id for i in fresh],
        "states": sorted({i.state for i in fresh}),
    }


def learn_from_failure(
    store: MemoryStore,
    *,
    job: Any,
    capability: Any,
    error: str,
) -> dict[str, Any]:
    """Honest negative memory for an exhausted/failed research attempt."""
    category = str(getattr(job, "agent_category", "") or "")
    item = make_item(
        kind="research_recommendation", state="RESEARCHED",
        subject_key="failure:" + scrub_text(error, 60),
        text=(f"prior research attempt failed honestly: "
              f"{scrub_text(error, 160)} — deterministic retry policy "
              f"applies; do not assume any conclusion"),
        category=category, agent=str(getattr(job, "assigned_agent", "") or ""),
        target=_job_target(job),
        program=str(getattr(job, "program", "") or ""),
        confidence="recorded",
        provenance_job=str(getattr(job, "id", "") or ""),
        provenance_source="runtime_failure",
        provenance_refs=[scrub_text(error, 80)],
        limitations="failure record; no research conclusion",
    )
    heads = {i.id: i for i in store.heads()}
    fresh = [i for i in [item] if should_append(heads.get(i.id), i)]
    written = store.append(fresh) if fresh else 0
    return {"extracted": 1, "appended": written,
            "ids": [i.id for i in fresh],
            "states": [i.state for i in fresh]}


__all__ = ["ADVISORY_MAX_STATE", "extract", "learn", "learn_from_failure"]
