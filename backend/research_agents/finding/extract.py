"""Deterministic candidate extraction (Phase 2).

Turns a completed research result into zero or more CandidateFinding
signals.  Extraction is purely deterministic: it never verifies, never
inflates confidence, and preserves exact evidence references, hypothesis,
missing evidence and provenance.

A research result that says "potential reflected XSS pattern" yields a
candidate in state DETECTED with ``confidence`` copied from the research
result (provenance ``research_result``) — never VERIFIED.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from backend.research_agents.finding.models import (
    CandidateFinding,
    new_id,
    validate_scope_ref,
)

MAX_CANDIDATES_PER_JOB = 10
MAX_SIGNALS = 12
MAX_EVIDENCE_REFS = 20
MAX_MISSING = 10

# evidence types that count as supporting signal material (never proof)
SIGNAL_EVIDENCE_TYPES = frozenset(
    {"observation", "knowledge", "prior_research", "negative"})


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _unique(values: Iterable[str], cap: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        text = _bounded(raw, 200)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
        if len(out) >= cap:
            break
    return out


@dataclass
class ExtractionResult:
    candidates: list[CandidateFinding]
    skipped: list[str]      # honest reasons nothing was extracted
    counts: dict[str, int]


def extract_candidates(
    *,
    job: Any,
    result: Any,
    evidence_rows: list[dict[str, Any]],
    capability: Any,
    scope_ref: str,
    target: dict[str, Any] | None = None,
    source_campaign: str = "",
    source_objective: str = "",
    max_candidates: int = MAX_CANDIDATES_PER_JOB,
) -> ExtractionResult:
    """Deterministically extract candidate signals from one research result.

    Inputs honored: research result, hypotheses, evidence, observations,
    specialist capability, campaign/objective context.  Everything else is
    refused (fail closed: no result → no candidates).
    """
    skipped: list[str] = []
    target = target or {}
    try:
        scope_ref = validate_scope_ref(scope_ref)
    except Exception as exc:  # noqa: BLE001
        return ExtractionResult([], [f"invalid_scope:{exc}"], {"candidates": 0})

    if result is None:
        return ExtractionResult([], ["no_result"], {"candidates": 0})

    structured = getattr(result, "structured", None) or {}
    if not isinstance(structured, dict):
        structured = {}

    category = str(getattr(capability, "category", "")
                   or getattr(job, "agent_category", "") or "").upper()
    if not category:
        return ExtractionResult([], ["unknown_capability"], {"candidates": 0})

    # hypotheses: structured first, deterministic fallback = signals/findings
    raw_hypotheses: list[str] = []
    for hyp in (structured.get("hypotheses") or [])[:8]:
        if isinstance(hyp, dict):
            raw_hypotheses.append(_bounded(hyp.get("hypothesis"), 400))
        else:
            raw_hypotheses.append(_bounded(hyp, 400))
    if not raw_hypotheses:
        raw_hypotheses = [_bounded(f, 400)
                          for f in (getattr(result, "findings", ()) or ())[:4]]
    if not raw_hypotheses:
        raw_hypotheses = [_bounded(f, 400)
                          for f in (structured.get("signals", ()) or ())[:4]]
    raw_hypotheses = [h for h in raw_hypotheses if h]
    if not raw_hypotheses:
        skipped.append("no_hypothesis_in_result")

    confidence = str(getattr(result, "confidence", "")
                     or structured.get("confidence", "") or "insufficient")
    if confidence not in ("high", "medium", "low", "insufficient"):
        confidence = "insufficient"   # never invent a confidence bucket

    # exact evidence references (job-linked only — never foreign evidence)
    job_evidence = [e for e in evidence_rows
                    if str(e.get("job_id") or "") == str(getattr(job, "id", ""))]
    evidence_ids = _unique((str(e.get("id") or "") for e in job_evidence),
                           MAX_EVIDENCE_REFS)
    evidence_ids = [e for e in evidence_ids if e]

    # missing evidence: structured evidence_missing + hunt gaps, honest copy
    missing: list[str] = []
    for item in (structured.get("evidence_missing") or [])[:8]:
        # structured rows are strings OR {code,reason,text} objects —
        # both shapes occur in production; never crash on either
        if isinstance(item, dict):
            text = item.get("code") or item.get("reason") \
                or item.get("text") or ""
        else:
            text = item
        missing.append(_bounded(text, 200))
    hunt = structured.get("hunt") or {}
    if isinstance(hunt, dict):
        missing.append(_bounded(hunt.get("termination_reason")
                                if str(hunt.get("state") or "") == "BLOCKED"
                                else "", 200))
    missing = _unique([m for m in missing if m], MAX_MISSING)

    signals: list[str] = _unique(
        [f"research_result:{confidence}"]
        + [f"evidence:{len(job_evidence)}"]
        + [f"signal:{_bounded(s, 80)}"
           for s in (structured.get("signals") or [])[:6]]
        + [f"hypothesis:{category}-class"], MAX_SIGNALS)

    if not raw_hypotheses:
        return ExtractionResult([], skipped, {"candidates": 0})

    provenance = {
        "source": "extraction",
        "source_job": str(getattr(job, "id", "")),
        "source_campaign": source_campaign,
        "source_objective": source_objective,
        "specialist": str(getattr(job, "assigned_agent", "")
                          or getattr(capability, "agent_name", "")),
        "confidence_provenance": "research_result",
        "prompt_version": str(structured.get("prompt_version") or ""),
        "model_requested": str(structured.get("requested_model") or ""),
        "model_resolved": str(structured.get("resolved_model") or ""),
        "rule_version": "finding-extract-1",
    }

    candidates: list[CandidateFinding] = []
    for hypothesis in raw_hypotheses[:max_candidates]:
        candidates.append(CandidateFinding(
            candidate_id=new_id("cand"),
            source_job=str(getattr(job, "id", "")),
            source_campaign=source_campaign,
            source_objective=source_objective,
            specialist=provenance["specialist"],
            scope_ref=scope_ref,
            target=_bounded(target.get("subdomain") or target.get("program")
                             or getattr(job, "subdomain", "") or "", 120),
            endpoint=_bounded(target.get("url") or getattr(job, "url", "")
                               or "", 300),
            parameter=_bounded(getattr(job, "parameter", "") or "", 120),
            vulnerability_class=category,
            hypothesis=hypothesis,
            lifecycle_state="DETECTED",
            confidence=confidence,
            confidence_provenance="research_result",
            supporting_signals=signals,
            evidence_refs=evidence_ids,
            missing_evidence=missing,
            provenance=dict(provenance),
        ))

    if len(raw_hypotheses) > max_candidates:
        skipped.append(
            f"candidate_cap:{len(raw_hypotheses)}->{max_candidates}")
    return ExtractionResult(
        candidates=candidates, skipped=skipped,
        counts={"candidates": len(candidates),
                "hypotheses": len(raw_hypotheses),
                "evidence_refs": len(evidence_ids),
                "missing": len(missing)})
