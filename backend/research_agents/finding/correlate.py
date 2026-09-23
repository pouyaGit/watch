"""Bounded candidate correlation (Phase 4).

Structured signals only: normalized target, scope_ref, endpoint shape,
parameter names, vulnerability class, evidence references, source
objective/campaign, historical candidates.  Semantic similarity alone can
NEVER produce SAME_CANDIDATE or POSSIBLE_DUPLICATE — token/semantic
overlap is not used at all here (intelligence/similarity remains the
research aid; its own limitation still applies).

Four classes are preserved and never merged:
    SAME_CANDIDATE | RELATED_CANDIDATE | POSSIBLE_DUPLICATE | INDEPENDENT

Every correlation carries reason codes + provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.models import CandidateFinding

CORRELATION_RULE_VERSION = "finding-correlate-1"
MAX_COMPARISONS = 500          # bounded history window (rule 27)


def _norm_target(value: str) -> str:
    text = str(value or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    return text.split(":", 1)[0]


def _endpoint_url(endpoint: Any) -> str:
    """Candidate.endpoint is a dict {url, method, parameter} (or a raw
    string on older rows) — normalize to the URL string."""
    if isinstance(endpoint, dict):
        return str(endpoint.get("url") or "")
    return str(endpoint or "")


def _endpoint_param(endpoint: Any) -> str:
    if isinstance(endpoint, dict):
        return str(endpoint.get("parameter") or "")
    return ""


def _endpoint_shape(value: str) -> tuple[str, ...]:
    """Path segments only (host never participates — no target widening)."""
    text = str(value or "")
    if "://" in text:
        text = "/" + text.split("://", 1)[1].split("/", 1)[1] \
            if "/" in text.split("://", 1)[1] else "/"
    segs = [s for s in text.split("/") if s][:4]
    return tuple(segs)


@dataclass
class CorrelationResult:
    left_id: str
    right_id: str
    relation: str                  # SAME_CANDIDATE|RELATED_CANDIDATE|
                                    # POSSIBLE_DUPLICATE|INDEPENDENT
    reasons: list[str]
    score: int                      # 0..100 structured score (labeled heuristic)
    provenance: dict[str, Any] = field(default_factory=dict)
    limitations: str = ("structured-signal correlation only; never semantic "
                        "identity, never proof about the target")

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_id": self.left_id, "right_id": self.right_id,
            "relation": self.relation, "reasons": list(self.reasons),
            "score": self.score, "provenance": dict(self.provenance),
            "rule_version": CORRELATION_RULE_VERSION,
            "limitations": self.limitations,
        }


def correlate_pair(left: CandidateFinding,
                   right: CandidateFinding) -> CorrelationResult:
    """Deterministic structured correlation of two candidates."""
    if left.candidate_id == right.candidate_id:
        return CorrelationResult(left.candidate_id, right.candidate_id,
                                 "INDEPENDENT", ["self_comparison"], 0,
                                 {"rule_version": CORRELATION_RULE_VERSION})
    reasons: list[str] = []
    structured_hits = 0

    same_scope = left.scope_ref == right.scope_ref
    if same_scope:
        reasons.append("same_scope_ref")
        structured_hits += 1

    same_class = (left.vulnerability_class
                  == right.vulnerability_class)
    if same_class:
        reasons.append("same_vulnerability_class")
        structured_hits += 1

    shape_l = _endpoint_shape(_endpoint_url(left.endpoint))
    shape_r = _endpoint_shape(_endpoint_url(right.endpoint))
    same_shape = bool(shape_l) and shape_l == shape_r
    if same_shape:
        reasons.append("same_endpoint_shape:" + "/".join(shape_l))
        structured_hits += 1

    param_l = _endpoint_param(left.endpoint).strip().lower()
    param_r = _endpoint_param(right.endpoint).strip().lower()
    same_param = bool(param_l) and param_l == param_r
    if same_param:
        reasons.append(f"same_parameter:{param_l}")
        structured_hits += 1

    tgt_l, tgt_r = _norm_target(left.target), _norm_target(right.target)
    if tgt_l and tgt_l == tgt_r:
        reasons.append("same_normalized_target")
        structured_hits += 1

    shared_evidence = sorted(
        set(left.evidence_refs or []) & set(right.evidence_refs or []))
    if shared_evidence:
        reasons.append(f"shared_evidence_refs:{len(shared_evidence)}")
        structured_hits += 1

    if left.source_objective and left.source_objective == right.source_objective:
        reasons.append("same_source_objective")
    if left.source_campaign and left.source_campaign == right.source_campaign:
        reasons.append("same_source_campaign")

    if not reasons:
        return CorrelationResult(left.candidate_id, right.candidate_id,
                                 "INDEPENDENT", ["no_structured_overlap"], 0,
                                 {"rule_version": CORRELATION_RULE_VERSION})

    # -- class decision (deterministic thresholds) --------------------------
    # SAME_CANDIDATE requires identity on the four core structured signals:
    # scope + class + endpoint shape + parameter (evidence overlap can
    # substitute for the parameter signal only when BOTH params exist as
    # different values? no — substitution never allowed; keep it strict).
    if same_scope and same_class and same_shape and same_param:
        relation = "SAME_CANDIDATE"
    elif same_scope and same_class and same_shape and (
            same_param or shared_evidence or (tgt_l and tgt_l == tgt_r)):
        relation = "POSSIBLE_DUPLICATE"
    elif structured_hits >= 2:
        relation = "RELATED_CANDIDATE"
    else:
        relation = "INDEPENDENT"

    score = min(100, structured_hits * 20
                + (10 if shared_evidence else 0))
    return CorrelationResult(
        left.candidate_id, right.candidate_id, relation, reasons, score,
        {"rule_version": CORRELATION_RULE_VERSION,
         "left_created": left.created_at, "right_created": right.created_at})


def correlate_all(candidates: Iterable[CandidateFinding],
                  *, max_comparisons: int = MAX_COMPARISONS
                  ) -> list[CorrelationResult]:
    """Bounded all-pairs structured correlation over persisted candidates."""
    items = [c for c in candidates
             if c.lifecycle_state != "DUPLICATE"][:200]
    out: list[CorrelationResult] = []
    comparisons = 0
    for i, left in enumerate(items):
        for right in items[i + 1:]:
            if comparisons >= max_comparisons:
                return out
            comparisons += 1
            out.append(correlate_pair(left, right))
    return out


def duplicates_of(candidate: CandidateFinding,
                  others: Iterable[CandidateFinding]) -> list[str]:
    """Candidates that correlate to `candidate` as dup-class relations."""
    hits: list[str] = []
    for other in others:
        if other.candidate_id == candidate.candidate_id:
            continue
        result = correlate_pair(candidate, other)
        if result.relation in ("SAME_CANDIDATE", "POSSIBLE_DUPLICATE"):
            hits.append(other.candidate_id)
    return hits
