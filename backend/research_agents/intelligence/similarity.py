"""backend/research_agents/intelligence/similarity.py — Phase 5.

Prior-case / prior-research similarity from bounded STRUCTURED signals
only.  Output rows always carry per-signal reason codes, provenance and
the standing limitation that **similarity is never proof**.

Four distinct classes are preserved and never merged:

- ``similar_observation``        (historical job/observation overlap)
- ``similar_hypothesis``         (prior advisory hypothesis memory)
- ``similar_verified_case``      (a gate-created case)
- ``similar_rejected_hypothesis``(negative memory from the gate)

Nothing here contacts targets or the LLM; it is deterministic matching
over already-persisted records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.intelligence.memory import scrub_text

SIMILARITY_LIMITATION = ("similarity is a research aid, never proof or "
                         "evidence about the current target")

_STOP = {"the", "and", "for", "with", "via", "this", "that", "from",
         "not", "are", "was", "were", "has", "have"}


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for raw in str(text or "").lower().replace("/", " ").split():
        word = raw.strip(".,;:()[]{}'\"")
        if len(word) > 2 and word not in _STOP:
            out.add(word)
    return out


def _path_shape(url: str) -> tuple[str, ...]:
    path = str(url or "")
    if "://" in path:
        path = path.split("://", 1)[1]
        path = path.split("/", 1)[1] if "/" in path else ""
    return tuple(seg for seg in path.split("/") if seg)[:4]


@dataclass
class RelatedRecord:
    kind: str
    ref: str
    score: int
    reasons: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    category: str = ""
    limitations: str = SIMILARITY_LIMITATION

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "ref": self.ref, "score": int(self.score),
            "reasons": list(self.reasons), "provenance": dict(self.provenance),
            "text": self.text, "category": self.category,
            "limitations": self.limitations,
        }


def _field(obj: Any, key: str, default: Any = "") -> Any:
    """Prior records may be ResearchJob objects or plain dicts."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def find_related(
    *,
    job: Any,
    capability: Any,
    history_jobs: list[Any],
    cases: list[dict[str, Any]],
    memory_hits: list[Any],
    limit: int = 5,
    scan: int = 60,
) -> list[RelatedRecord]:
    """Deterministic bounded similarity over prior jobs, cases, memory."""
    limit = max(0, int(limit))
    scan = max(1, int(scan))
    category = str(getattr(job, "agent_category", "") or "")
    program = str(getattr(job, "program", "") or "")
    target = str(getattr(job, "subdomain", "") or "")
    job_id = str(getattr(job, "id", "") or "")
    focus_param = str(getattr(job, "parameter", "") or "")
    shape = _path_shape(getattr(job, "url", "") or "")
    job_tokens = _tokens(" ".join((
        str(getattr(job, "mission", "") or ""),
        str(getattr(job, "parameter", "") or ""),
        str(getattr(job, "endpoint", "") or ""),
    )))
    out: list[RelatedRecord] = []

    # -- prior jobs -> similar_observation --------------------------------
    for prior in list(history_jobs)[-scan:]:
        pid = str(_field(prior, "id") or "")
        if not pid or pid == job_id:
            continue
        reasons: list[str] = []
        score = 0
        if target and _field(prior, "subdomain") == target:
            score += 2
            reasons.append("same_target_scope")
        if program and _field(prior, "program") == program:
            score += 1
            reasons.append("same_program")
        if _field(prior, "agent_category") == category:
            score += 1
            reasons.append("same_specialist")
        prior_param = str(_field(prior, "parameter") or "")
        if focus_param and prior_param and focus_param == prior_param:
            score += 2
            reasons.append(f"same_parameter:{focus_param}")
        if shape and _path_shape(_field(prior, "url")) == shape:
            score += 1
            reasons.append("same_endpoint_shape")
        if score >= 3:
            out.append(RelatedRecord(
                kind="similar_observation", ref=pid, score=score,
                reasons=reasons,
                provenance={"source": "prior_job", "refs": [pid]},
                text=scrub_text(_field(prior, "mission"), 160),
                category=str(_field(prior, "agent_category") or ""),
            ))

    # -- cases -> similar_verified_case -----------------------------------
    for case in cases[-scan:]:
        cid = str(case.get("id") or "")
        if not cid:
            continue
        reasons = []
        score = 0
        if str(case.get("category") or "") == category:
            score += 2
            reasons.append("same_vulnerability_class")
        if target and str(case.get("target") or "") == target:
            score += 2
            reasons.append("same_target_scope")
        if program and program in str(case.get("authorization_context") or ""):
            score += 1
            reasons.append("same_program")
        if shape and _path_shape(str(case.get("endpoint") or "")) == shape:
            score += 1
            reasons.append("same_endpoint_shape")
        overlap = sorted(job_tokens & _tokens(
            f"{case.get('hypothesis', '')} {case.get('analysis', '')}"))
        if overlap:
            score += min(2, len(overlap))
            reasons.append("hypothesis_token_overlap:" + ",".join(overlap[:3]))
        if score >= 3:
            out.append(RelatedRecord(
                kind="similar_verified_case", ref=cid, score=score,
                reasons=reasons,
                provenance={"source": "case_store", "refs": [cid]},
                text=scrub_text(case.get("hypothesis"), 160),
                category=str(case.get("category") or ""),
            ))

    # -- memory -> similar_hypothesis / similar_rejected_hypothesis --------
    for item in memory_hits:
        if item.state not in ("INFERRED", "REJECTED"):
            continue
        if item.category and item.category != category \
                and item.state == "INFERRED":
            continue
        reasons = []
        score = 0
        if item.category == category:
            score += 2
            reasons.append("same_specialist_memory")
        if target and item.target and item.target == target:
            score += 2
            reasons.append("same_target_memory")
        overlap = sorted(job_tokens & _tokens(item.text))
        if overlap:
            score += min(3, len(overlap))
            reasons.append("text_token_overlap:" + ",".join(overlap[:3]))
        if score < 2:
            continue
        kind = ("similar_rejected_hypothesis" if item.state == "REJECTED"
                else "similar_hypothesis")
        out.append(RelatedRecord(
            kind=kind, ref=item.id, score=score, reasons=reasons,
            provenance={"source": "research_memory",
                        "refs": [item.id, item.provenance.get("job_id", "")]},
            text=item.text, category=item.category,
        ))

    out.sort(key=lambda r: (-r.score, r.kind, r.ref))
    return out[:limit] if limit else []


__all__ = ["RelatedRecord", "SIMILARITY_LIMITATION", "find_related"]
