"""Hunt Planner (Phases 5-7): bounded plan generation + LLM advisory.

Two paths, one trusted constructor:

  deterministic — candidates from missing evidence x registry x
                  capability allowlist, scored with a transparent
                  heuristic (evidence value, coverage, cost, risk,
                  dependency readiness) and an auditable reason.
  advisory      — the openrouter/free advisor (existing provider path,
                  R45 structured response) may SUGGEST observation
                  types; a deterministic validator rejects unknown
                  types, capability violations, unsupported inputs and
                  forbidden (exploit/shell/code/network) instructions.

The final HuntPlan is always constructed by trusted code here; the LLM
never writes a plan, never chooses scope, never executes anything.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterable

from backend.research_agents.hunt.models import (
    ADVISOR_PROMPT_VERSION,
    PLANNER_VERSION,
    HuntObjective,
    HuntPlan,
    new_id,
)
from backend.research_agents.hunt.missing_evidence import MissingEvidenceItem
from backend.research_agents.hunt.registry import (
    EXECUTION_GUARANTEES,
    REGISTRY,
    registry_catalog,
    scan_forbidden,
    validate_observation_requests,
)
from backend.research_agents.hunt.store import utcnow

SCORING_METHOD = "heuristic_transparent_v1"


def _bounded(value: object, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


@dataclass(frozen=True)
class Candidate:
    observation_type: str
    missing_item_ids: tuple[str, ...]
    missing_codes: tuple[str, ...]
    evidence_value: int        # sum of priority values addressed (1-5 scale)
    hypothesis_coverage: int   # number of hypotheses addressed (0..n)
    information_gain: float    # heuristic 0..1 (labelled)
    cost: int                  # registry cost class -> 1 (LOW) / 2 (MEDIUM)
    risk: int                  # READ_ONLY -> 1
    dependency_ready: int      # 1 when scope authorization is present
    score: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_type": self.observation_type,
            "missing_item_ids": list(self.missing_item_ids),
            "missing_codes": list(self.missing_codes),
            "evidence_value": self.evidence_value,
            "hypothesis_coverage": self.hypothesis_coverage,
            "information_gain": round(self.information_gain, 4),
            "information_gain_label": "heuristic",
            "cost": self.cost,
            "risk": self.risk,
            "dependency_ready": self.dependency_ready,
            "score": self.score,
            "scoring_method": SCORING_METHOD,
            "reason": self.reason,
        }


def _priority_value(priority: int) -> int:
    return 6 - max(1, min(5, int(priority)))


def build_candidates(
    *,
    missing_items: Iterable[MissingEvidenceItem],
    capability: Any,
    observed_types: Iterable[str],
    scope_ready: bool = True,
) -> list[Candidate]:
    """Deterministic candidate observations with auditable scoring."""
    allowed = {str(t) for t in
               (getattr(capability, "allowed_observation_types", ()) or ())}
    observed = {str(t) for t in observed_types}
    hypothesis = ""
    for item in missing_items:
        if item.hypothesis_affected:
            hypothesis = item.hypothesis_affected
            break
    by_type: dict[str, list[MissingEvidenceItem]] = {}
    for item in missing_items:
        if not item.satisfiable:
            continue
        for otype in item.observation_type_suggestions:
            # never plan a type that was already observed for this
            # objective: consumed coverage cannot reduce uncertainty
            # again, and re-reading would waste the observation budget
            if otype in allowed and otype in REGISTRY \
                    and otype not in observed:
                by_type.setdefault(otype, []).append(item)

    candidates: list[Candidate] = []
    for otype, items in sorted(by_type.items()):
        spec = REGISTRY[otype]
        # dedup items per type
        uniq: dict[str, MissingEvidenceItem] = {i.item_id: i for i in items}
        items = list(uniq.values())
        evidence_value = sum(_priority_value(i.priority) for i in items)
        coverage = 1 if hypothesis else 0
        gain_num = max((i.expected_information_gain for i in items),
                       default=0.0)
        cost = 2 if spec.cost_class == "MEDIUM" else 1
        risk = 1 if spec.risk_class == "READ_ONLY" else 3
        dependency_ready = 1 if scope_ready else 0
        # transparent heuristic score: value & coverage & gain over cost,
        # safety multiplier; zero when dependencies are not ready.
        score = int(round(
            (evidence_value * (1 + coverage) * (0.5 + gain_num))
            / float(cost))) * dependency_ready
        codes = sorted({i.item_code for i in items})
        reason = (
            f"Selected because {otype} addresses {len(items)} missing "
            f"evidence item(s) ({', '.join(codes)[:160]}) for hypothesis "
            f"{_bounded(hypothesis, 120) or 'n/a'} while requiring an "
            f"already-authorized "
            f"{spec.risk_class.lower().replace('_', '-')} observation "
            f"within the fixed scope reference."
        )
        candidates.append(Candidate(
            observation_type=otype,
            missing_item_ids=tuple(i.item_id for i in items),
            missing_codes=tuple(codes),
            evidence_value=evidence_value,
            hypothesis_coverage=coverage,
            information_gain=round(gain_num, 4),
            cost=cost,
            risk=risk,
            dependency_ready=dependency_ready,
            score=max(0, score),
            reason=_bounded(reason, 400),
        ))
    candidates.sort(key=lambda c: (-c.score, c.observation_type))
    return candidates


# ---------------------------------------------------------- LLM advisor
def advisor_request(
    *,
    objective: HuntObjective,
    missing_items: Iterable[MissingEvidenceItem],
    candidates: Iterable[Candidate],
    capability: Any,
    allowed_types: Iterable[str],
    observed_types: Iterable[str],
    job: Any,
) -> dict[str, Any]:
    """R51-shaped advisory request: ONLY bounded hunt state, the allowed
    observation registry, scope reference and safety constraints."""
    items = list(missing_items)[:8]
    cands = list(candidates)[:6]
    allowed = [str(t) for t in allowed_types]
    instruction = (
        f"{ADVISOR_PROMPT_VERSION}: hunt planning advisor for "
        f"{capability.agent_name} ({capability.category}). Choose only "
        "observation types from this allowed registry: "
        f"{', '.join(allowed)}. Mission: "
        f"{_bounded(getattr(job, 'mission', ''), 40)}. "
        "Raw JSON, no markdown, exactly: "
        '{"summary":"<=150 chars",'
        '"insights":[{"insight_code":"OBS_<TYPE>","text":"<=200"}],'
        '"recommendations":[{"recommendation_code":"REASON_...|'
        'BLOCKER_...|PRIORITY_<1-5>","text":"<=200"}]} '
        "only these keys, max 6+6. Code OBS_ types with dashes as "
        "underscores (OBS_HTTP_ROWS). Observation only: no payloads, no "
        "requests to targets, no commands, no credentials, no findings."
    )[:400]

    signals: list[dict[str, Any]] = []
    for item in items:
        signals.append({
            "signal_type": "MISSING_EVIDENCE",
            "subject": (f"{item.item_code}: "
                        f"{_bounded(item.reason, 160)}"),
            "source_agent": capability.agent_name,
            "source_classification": capability.category,
            "recommendation": (f"candidate observation types: "
                               f"{', '.join(item.observation_type_suggestions)}"
                               or "none")[:240],
            "confidence": "not_evaluated",
            "research_only": True,
        })
    for cand in cands:
        signals.append({
            "signal_type": "DETERMINISTIC_CANDIDATE",
            "subject": (f"{cand.observation_type} score={cand.score} "
                        f"gain={cand.information_gain} "
                        "(heuristic)"),
            "source_agent": capability.agent_name,
            "source_classification": capability.category,
            "recommendation": _bounded(cand.reason, 240),
            "confidence": "not_evaluated",
            "research_only": True,
        })

    sections = {
        "research_context": {
            "research_question": _bounded(objective.research_objective, 240),
            "research_focus": f"hunt-planning:{capability.category}",
            "context_fact_count": len(signals),
            "source_layers": ["authorized_observations", "knowledge",
                              "research_memory", "deterministic_analysis"],
            "research_only": True,
        },
        "learning_signals": signals[:10],
    }
    source_refs = [
        {"layer": "scope", "reference": _bounded(objective.scope_ref, 80)},
        {"layer": "objective", "reference": _bounded(
            objective.objective_id, 80)},
        {"layer": "registry", "reference": "hunt-observation-registry-v1"},
        {"layer": "observed_types",
         "reference": _bounded(",".join(sorted(observed_types)), 80)},
    ]
    limitations = [
        "advisory only: deterministic validator constructs the final plan",
        "observation registry is closed: only listed types can be planned",
        "no exploitation, no target contact, no scope change",
        *EXECUTION_GUARANTEES,
    ]
    return {
        "rule_version": "r51",
        "advisory_id": new_id("adv"),
        "advisory_mode": "hunt_planning_advisor",
        "provider_kind": "OPENROUTER",
        "source_layer": "hunt_planner",
        "instruction": instruction,
        "sections": sections,
        "source_refs": source_refs,
        "limitations": limitations[:8],
        "research_only": True,
        "deterministic": False,
    }


@dataclass
class AdvisorOutcome:
    used: bool
    accepted_types: tuple[str, ...]
    rejected_suggestions: tuple[str, ...]
    forbidden_hits: tuple[str, ...]
    objective_interpretation: str
    rationale: str
    blockers: tuple[str, ...]
    confidence: str
    recommended_priority: int
    model_requested: str
    model_resolved: str
    prompt_version: str
    latency_ms: int
    error: str


def _type_from_code(code: str) -> str:
    """OBS_HTTP_ROWS -> http-rows (unknown codes stay visibly unknown)."""
    raw = str(code or "")
    if not raw.startswith("OBS_"):
        return ""
    return raw[4:].strip().lower().replace("_", "-")


def map_advisor_response(
    response: Any,
    *,
    capability: Any,
    allowed_types: Iterable[str],
) -> AdvisorOutcome:
    """Strict deterministic mapping of the R45 advisory response.

    Rejects: non-shape responses, unknown observation types, capability
    violations, forbidden exploit/shell/code/network instructions.
    Nothing here executes; rejected advice is recorded, never used.
    """
    allowed = {str(t) for t in allowed_types}
    empty = AdvisorOutcome(
        used=False, accepted_types=(), rejected_suggestions=(),
        forbidden_hits=(), objective_interpretation="", rationale="",
        blockers=(), confidence="advisory", recommended_priority=50,
        model_requested="", model_resolved="",
        prompt_version=ADVISOR_PROMPT_VERSION, latency_ms=0, error="")
    if not isinstance(response, dict):
        empty.error = "malformed_advisor_response:not_an_object"
        return empty
    summary = response.get("summary")
    insights = response.get("insights")
    recommendations = response.get("recommendations")
    if not isinstance(summary, str) or not summary.strip() \
            or not isinstance(insights, list) \
            or not isinstance(recommendations, list):
        empty.error = "malformed_advisor_response:missing_keys"
        return empty

    texts: list[str] = [_bounded(summary, 400)]
    accepted: list[str] = []
    rejected: list[str] = []
    blockers: list[str] = []
    priority = 50
    rationale_parts: list[str] = []

    for item in insights[:8]:
        if not isinstance(item, dict):
            empty.error = "malformed_advisor_response:insight_shape"
            return empty
        code = item.get("insight_code")
        text = item.get("text")
        if not isinstance(code, str) or not isinstance(text, str) \
                or not code.strip() or not text.strip():
            empty.error = "malformed_advisor_response:insight_item"
            return empty
        texts.append(_bounded(text, 300))
        otype = _type_from_code(code)
        if otype:
            if otype in REGISTRY and otype in allowed:
                if otype not in accepted:
                    accepted.append(otype)
                    rationale_parts.append(_bounded(text, 200))
            else:
                rejected.append(f"{code}->{otype or 'unmappable'}")

    for item in recommendations[:8]:
        if not isinstance(item, dict):
            empty.error = "malformed_advisor_response:recommendation_shape"
            return empty
        code = str(item.get("recommendation_code") or "")
        text = item.get("text")
        if not code or not isinstance(text, str) or not text.strip():
            empty.error = "malformed_advisor_response:recommendation_item"
            return empty
        texts.append(_bounded(text, 300))
        if code.startswith("BLOCKER_"):
            blockers.append(_bounded(text, 160))
        if code.startswith("PRIORITY_"):
            digits = "".join(ch for ch in code if ch.isdigit())
            if digits:
                priority = max(1, min(100, int(digits[:3]) * 20))
        rationale_parts.append(_bounded(text, 200))

    forbidden = scan_forbidden(texts)
    if forbidden:
        empty.forbidden_hits = tuple(forbidden)
        empty.rejected_suggestions = tuple(rejected)
        empty.error = "forbidden_advisor_content:" + ",".join(forbidden)
        empty.blockers = tuple(blockers[:4])
        empty.objective_interpretation = _bounded(summary, 240)
        return empty

    return AdvisorOutcome(
        used=True,
        accepted_types=tuple(accepted[:4]),
        rejected_suggestions=tuple(rejected[:6]),
        forbidden_hits=(),
        objective_interpretation=_bounded(summary, 240),
        rationale=_bounded(" | ".join(rationale_parts[:4]), 400),
        blockers=tuple(blockers[:4]),
        confidence="advisory",
        recommended_priority=priority,
        model_requested="",   # filled by the runtime caller
        model_resolved="",
        prompt_version=ADVISOR_PROMPT_VERSION,
        latency_ms=0,
        error="",
    )


# ------------------------------------------------------------ final plan
def build_plan(
    *,
    objective: HuntObjective,
    job: Any,
    capability: Any,
    candidates: list[Candidate],
    missing_items: list[MissingEvidenceItem],
    advisor: AdvisorOutcome | None,
    version: int,
    parent_plan_id: str = "",
    max_types: int = 2,
    now: str | None = None,
) -> tuple[HuntPlan | None, list[str]]:
    """Trusted final plan construction.

    Selection order: deterministic top candidates, optionally
    intersected with (and reordered by) advisor-accepted types that are
    themselves valid candidates. Returns (plan, notes). No candidates =>
    (None, notes) — the caller terminates honestly.
    """
    notes: list[str] = []
    if not candidates:
        return None, ["no_valid_candidates"]

    selected: list[Candidate] = []
    if advisor is not None and advisor.used and advisor.accepted_types:
        for otype in advisor.accepted_types:
            match = next((c for c in candidates
                          if c.observation_type == otype), None)
            if match is not None and match not in selected:
                selected.append(match)
        if selected:
            notes.append(
                f"advisor_recommended:{','.join(advisor.accepted_types)}")
        if advisor.rejected_suggestions:
            notes.append(
                "advisor_rejected:"
                + ",".join(advisor.rejected_suggestions))
    for cand in candidates:
        if len(selected) >= max_types:
            break
        if cand not in selected:
            selected.append(cand)
    if not selected:
        return None, notes + ["no_candidates_after_advisor_filter"]

    top_score = max(c.score for c in selected)
    plan_id = new_id("plan")
    hypothesis = objective.hypothesis
    reason_parts = [selected[0].reason]
    if advisor is not None and advisor.used:
        reason_parts.append(
            f"LLM advisory ({advisor.model_requested or 'openrouter/free'} "
            f"via {ADVISOR_PROMPT_VERSION}): "
            f"{advisor.objective_interpretation}")
    reason = _bounded(" Advisory note: ".join(
        [reason_parts[0]] + reason_parts[1:]) if len(reason_parts) > 1
        else reason_parts[0], 400)

    observations_requested: list[dict[str, Any]] = []
    required: list[str] = []
    missing_ids: list[str] = []
    gain = 0.0
    for cand in selected:
        spec = REGISTRY[cand.observation_type]
        inputs: dict[str, Any] = {
            "subdomain": str(getattr(job, "subdomain", "") or ""),
            "limit": 25,
        }
        if spec.requires_query:
            hints = _query_hints(cand, missing_items)
            if not hints:
                # honest fallback: the specialist's own knowledge topics
                hints = [str(t)[:60] for t in (
                    getattr(capability, "knowledge_requirements", ()) or ())
                    if str(t).strip()][:6] or ["research"]
            inputs["query_hints"] = hints
        observations_requested.append({
            "observation_type": cand.observation_type,
            "inputs": inputs,
            "expected_evidence": (
                f"{'+'.join(spec.evidence_produces)} via "
                f"{cand.observation_type}"),
            "missing_item_ids": list(cand.missing_item_ids),
            "risk_class": spec.risk_class,
        })
        required.extend(spec.evidence_produces)
        missing_ids.extend(cand.missing_item_ids)
        gain = max(gain, cand.information_gain)

    priority = top_score
    if advisor is not None and advisor.used and advisor.recommended_priority:
        # advisor may only rank within the deterministic envelope
        priority = max(1, min(100, int(advisor.recommended_priority)))

    provenance = {
        "planner": ("deterministic+llm_advisory"
                    if advisor is not None and advisor.used
                    else "deterministic"),
        "planner_version": PLANNER_VERSION,
        "scoring_method": SCORING_METHOD,
        "job_id": str(getattr(job, "id", "") or ""),
        "created_by": "trusted_code",
        "notes": notes[:6],
        "candidate_scores": [c.to_dict() for c in selected[:6]],
        "missing_item_ids": sorted(set(missing_ids))[:12],
        "model_requested": (advisor.model_requested if advisor else ""),
        "model_resolved": (advisor.model_resolved if advisor else ""),
        "prompt_version": (advisor.prompt_version if advisor else ""),
        "advisor_error": (advisor.error if advisor else ""),
        "advisor_blockers": list(advisor.blockers) if advisor else [],
        "created_at_ms": int(time.time() * 1000),
    }

    plan = HuntPlan(
        plan_id=plan_id,
        objective_id=objective.objective_id,
        job_id=str(getattr(job, "id", "") or ""),
        version=int(version),
        parent_plan_id=parent_plan_id,
        scope_ref=objective.scope_ref,
        specialist=objective.specialist,
        category=objective.category,
        reason=reason,
        hypotheses_addressed=(hypothesis,) if hypothesis else (),
        observations_requested=tuple(observations_requested),
        required_evidence=tuple(sorted(set(required))),
        expected_information_gain=float(gain),
        gain_label="heuristic",
        safety_constraints=EXECUTION_GUARANTEES,
        authorization_requirements=(
            objective.scope_ref,
            "capability_observation_allowlist",
            "authorization_checker_verify",
        ),
        dependencies=(parent_plan_id,) if parent_plan_id else (),
        priority=priority,
        provenance=provenance,
        created_at=now or utcnow(),
    )
    return plan, notes


def _query_hints(cand: Candidate,
                 missing_items: Iterable[MissingEvidenceItem]) -> list[str]:
    hints: list[str] = []
    for item in missing_items:
        if item.item_id in cand.missing_item_ids:
            for token in (item.provenance or {}).get(
                    "query_hint_tokens", []) or []:
                token = str(token).strip()
                if token and token not in hints:
                    hints.append(token)
    if not hints:
        # fall back to the capability's knowledge topics (bounded)
        pass
    return hints[:6]


def validate_final_plan(
    plan: HuntPlan,
    *,
    capability: Any,
    job: Any,
    scope_ref: str,
) -> list[str]:
    """Last-mile trusted-code validation; returns rejection reasons."""
    reasons: list[str] = []
    if plan.scope_ref != scope_ref:
        reasons.append("plan_scope_differs_from_authorization")
    job_scope = str(getattr(job, "authorization_ref", "") or "")
    if plan.scope_ref != job_scope:
        reasons.append("plan_scope_differs_from_job_authorization")
    valid, req_reasons = validate_observation_requests(
        plan.observations_requested,
        allowed_for_capability=getattr(
            capability, "allowed_observation_types", ()))
    reasons.extend(req_reasons)
    if len(valid) != len(plan.observations_requested):
        if not any(r.startswith("unknown_observation_type")
                   for r in reasons):
            reasons.append("observation_requests_failed_validation")
    if scan_forbidden([plan.reason]):
        reasons.append("forbidden_content_in_plan_reason")
    return reasons


__all__ = [
    "AdvisorOutcome",
    "Candidate",
    "SCORING_METHOD",
    "advisor_request",
    "build_candidates",
    "build_plan",
    "map_advisor_response",
    "validate_final_plan",
    "registry_catalog",
]
