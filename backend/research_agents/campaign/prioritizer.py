"""Phase 4: deterministic campaign prioritizer.

Orders executable candidate objectives with an explicit reason for every
ordering decision.  Heuristic scoring is labeled ``heuristic`` — no claim
of mathematical optimality.  The LLM advisor may REORDER this list only
after validation (see advisor.validate_recommendation); it never produces
the final order by itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

PRIORITIZER_VERSION = "campaign-prioritizer-heuristic-v1"
SCORING_METHOD = "heuristic_transparent_v1"


@dataclass
class RankedObjective:
    objective_id: str
    score: int
    tier: str                     # blocking|ready|informed
    reasons: list[str] = field(default_factory=list)
    score_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"objective_id": self.objective_id,
                "score": self.score, "tier": self.tier,
                "reasons": list(self.reasons),
                "score_breakdown": dict(self.score_breakdown)}


@dataclass
class PrioritizationResult:
    version: str
    scoring_method: str
    ordered: list[RankedObjective]
    excluded: list[dict[str, str]]     # objective_id -> reason
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "scoring_method": self.scoring_method,
            "ordered": [r.to_dict() for r in self.ordered],
            "excluded": list(self.excluded),
            "generated_at": self.generated_at,
        }

    @property
    def order(self) -> list[str]:
        return [r.objective_id for r in self.ordered]


def _age_hours(created_at: str, now_iso: str) -> float:
    try:
        from datetime import datetime
        a = datetime.fromisoformat(created_at)
        b = datetime.fromisoformat(now_iso)
        return max(0.0, (b - a).total_seconds() / 3600.0)
    except (TypeError, ValueError):
        return 0.0


def prioritize(
    candidates: Iterable[Any],
    *,
    dep_results: dict[str, dict[str, Any]],
    missing_by_objective: dict[str, list[Any]],
    previous_research: dict[str, dict[str, Any]],
    specialist_available: dict[str, bool],
    attempts: dict[str, int] | None = None,
    now_iso: str,
    budget_remaining: dict[str, int] | None = None,
    risk_class: dict[str, str] | None = None,
    scope_relevance: dict[str, float] | None = None,
) -> PrioritizationResult:
    """Order executable objectives. Every input from Phase 4 contributes a
    labeled component; ``excluded`` records why a candidate is not ordered.

    Inputs:
      candidates          -> iterable of CampaignObjective
      dep_results         -> objective_id -> resolve_dependencies() output
      missing_by_objective-> objective_id -> [MissingEvidenceItem, ...]
      previous_research   -> objective_id -> {"count": n, "confidence": c}
      specialist_available-> category -> bool
      attempts            -> objective_id -> attempt count
      budget_remaining    -> resource -> remaining (for cost reason only)
      risk_class          -> objective_id -> "high|medium|low"
      scope_relevance     -> objective_id -> 0.0..1.0
    """

    from backend.research_agents.campaign.models import utcnow

    attempts = attempts or {}
    budget_remaining = budget_remaining or {}
    risk_class = risk_class or {}
    scope_relevance = scope_relevance or {}
    now = now_iso or utcnow()
    candidates = list(candidates)   # iterated twice (rank + sort)

    ranked: list[RankedObjective] = []
    excluded: list[dict[str, str]] = []

    for obj in candidates:
        dep = dep_results.get(obj.objective_id) or {}
        if not dep.get("ready"):
            excluded.append({
                "objective_id": obj.objective_id,
                "reason": f"dependencies_{dep.get('effect', 'unknown')}",
            })
            continue
        available = specialist_available.get(obj.category, False)
        if not available:
            excluded.append({
                "objective_id": obj.objective_id,
                "reason": "specialist_unavailable",
            })
            continue
        if obj.state not in ("QUEUED", "READY"):
            excluded.append({
                "objective_id": obj.objective_id,
                "reason": f"state_{obj.state}_not_scheduled",
            })
            continue

        breakdown: dict[str, int] = {}
        reasons: list[str] = []

        # declared priority (dominant, honest: operator-set)
        breakdown["priority"] = int(obj.priority)
        reasons.append(f"priority={obj.priority}")

        # missing evidence: more open missing-evidence items => more value
        missing = missing_by_objective.get(obj.objective_id) or []
        gain = min(30, 5 * len(missing))
        breakdown["missing_evidence"] = gain
        if missing:
            reasons.append(f"missing_evidence_items={len(missing)} (+{gain})")

        # evidence value from objective's evidence requirements
        req = obj.evidence_requirements or {}
        min_refs = int(req.get("min_evidence_refs", 0) or 0)
        req_types = req.get("required_types") or []
        value = min(15, 3 * min_refs + 2 * len(req_types))
        breakdown["evidence_value"] = value
        if value:
            reasons.append(f"evidence_value=+{value}")

        # previous research: less prior confidence => higher marginal value;
        # some prior research => cheaper (small bonus either way, labeled)
        prev = previous_research.get(obj.objective_id) or {}
        prior_count = int(prev.get("count", 0) or 0)
        prior_conf = str(prev.get("confidence", "") or "")
        prior_score = 0
        if prior_count == 0:
            prior_score = 10
            reasons.append("no_prior_research (+10)")
        else:
            prior_score = 4 if prior_conf in ("high", "medium") else 7
            reasons.append(
                f"prior_research count={prior_count} conf={prior_conf or 'n/a'}"
                f" (+{prior_score})")
        breakdown["previous_research"] = prior_score

        # dependency state: satisfied is normal; informational-preferred
        # ordering bonus is tiny and labeled
        dep_state = 5 if dep.get("effect") == "satisfied" else 0
        breakdown["dependency_state"] = dep_state
        if dep_state:
            reasons.append("dependencies_satisfied (+5)")

        # resource cost: prefer objectives whose needed budget remains
        cost = 0
        obs_left = budget_remaining.get("observations")
        if obs_left is not None:
            if int(obs_left) <= 0:
                cost = -20
                reasons.append("no_observation_budget (-20)")
            else:
                cost = 3
                reasons.append("observation_budget_available (+3)")
        breakdown["resource_cost"] = cost

        # risk class: higher research risk => investigate sooner
        rc = str(risk_class.get(obj.objective_id, "medium"))
        rc_score = {"high": 8, "medium": 4, "low": 1}.get(rc, 4)
        breakdown["risk_class"] = rc_score
        reasons.append(f"risk_class={rc} (+{rc_score})")

        # freshness: older objectives gain (bounded)
        age = _age_hours(obj.created_at, now)
        fresh = min(12, int(age // 6))     # +2 per 6h, capped at +12
        breakdown["freshness"] = fresh
        if fresh:
            reasons.append(f"age={age:.1f}h (+{fresh})")

        # scope relevance: within-campaign objectives are all in-scope;
        # a fractional relevance signal can be supplied by the caller
        rel = float(scope_relevance.get(obj.objective_id, 1.0))
        rel_score = int(round(10 * max(0.0, min(1.0, rel))))
        breakdown["scope_relevance"] = rel_score
        reasons.append(f"scope_relevance={rel_score}/10")

        # previous attempts: penalize churn (honest retry pressure)
        att = int(attempts.get(obj.objective_id, obj.attempts or 0))
        att_score = -4 * att
        breakdown["previous_attempts"] = att_score
        if att:
            reasons.append(f"attempts={att} ({att_score})")

        # objective age as explicit tiebreaker input
        breakdown["objective_age_hours_x10"] = int(age * 10)

        total = sum(v for k, v in breakdown.items()
                    if k != "objective_age_hours_x10")
        ranked.append(RankedObjective(
            objective_id=obj.objective_id,
            score=total,
            tier="ready",
            reasons=reasons,
            score_breakdown=breakdown,
        ))

    # deterministic ordering: score desc, then declared priority (via
    # breakdown), then age (oldest first), then id — fully reproducible
    def sort_key(r: RankedObjective):
        obj = next(o for o in candidates if o.objective_id == r.objective_id)
        return (-r.score, -int(obj.priority),
                -r.score_breakdown.get("objective_age_hours_x10", 0),
                r.objective_id)

    ranked.sort(key=sort_key)

    return PrioritizationResult(
        version=PRIORITIZER_VERSION,
        scoring_method=SCORING_METHOD,
        ordered=ranked,
        excluded=excluded,
        generated_at=now,
    )


__all__ = ["prioritize", "PrioritizationResult", "RankedObjective",
           "PRIORITIZER_VERSION", "SCORING_METHOD"]
