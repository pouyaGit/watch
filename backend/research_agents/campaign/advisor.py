"""Phase 5: LLM campaign advisory layer (openrouter/free, advisory only).

The advisor receives BOUNDED campaign information through the SAME R51
provider envelope as the hunt advisor (advisory_id 16-hex, RESEARCH_PRIORITY,
MULTI layer, R44/R45 source refs, closed limitations codes, worst-case
canonical request <= MAX_CONTEXT_CHARS — all proven by sanitize tests).

The structured response is ADVISORY: trusted code validates every field
(objective exists / belongs to campaign / scope matches / specialist
exists / executable / deps satisfied / budget available / not terminal /
not already running).  Any invalid recommendation is REJECTED whole and
the deterministic order stands.  The advisor may only REORDER validated
candidates — it can never add an objective, widen scope, or bypass the
authorization boundary.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from ai.schemas.llm_advisory_input import ADVISORY_INPUT_LIMITATIONS
from ai.schemas.llm_provider import (SOURCE_REF_LAYER_R44,
                                     SOURCE_REF_LAYER_R45)

ADVISOR_PROMPT_VERSION = "campaign-advisor-v1"
RULE_VERSION = "r51"


def _bounded(value: Any, limit: int) -> str:
    return str(value or "")[:max(0, int(limit))]


# ---------------------------------------------------------------------------
# request (Phase 5: bounded information only)
# ---------------------------------------------------------------------------

def advisor_request(
    *,
    campaign: Any,
    ordered: list[Any],
    dep_results: dict[str, dict[str, Any]],
    budget_report: dict[str, Any],
    executable_ids: Iterable[str],
    specialists: dict[str, str],
    job: Any = None,
) -> dict[str, Any]:
    """Bounded R51 advisory request about objective ordering.

    Carries: campaign objective, authorized scope (as a scope REFERENCE,
    no target URLs), objective summaries, research state, dependency
    states, budget remaining, specialist capabilities.  Never carries
    unrestricted database contents, evidence rows, secrets, or target
    URLs.
    """

    executable = {str(x) for x in executable_ids}
    instruction = _bounded(
        "You are advising which authorized research objective to execute "
        "next in a bounded security campaign. This is advisory only: no "
        "observation, request, command, or finding is produced by your "
        "response. Respond with the standard advisory object: summary, "
        "insights (insight_code + text), recommendations "
        "(recommendation_code + text). Use recommendation_code "
        "OBJECTIVE_PRIORITY_<1-5> to reorder and BLOCKER_* to flag "
        "blockers; name objective ids only as obj ids already present in "
        "the context. No URLs, no commands, no credentials, no exploit "
        "steps.", 400)

    signals: list[dict[str, Any]] = []
    for obj in ordered[:5]:   # one slot reserved for BUDGET_STATE

        dep = dep_results.get(obj.objective_id) or {}
        specialist = specialists.get(obj.objective_id, "")
        signals.append({
            "signal_type": "OBJECTIVE_SUMMARY",
            "subject": _bounded(
                f"{obj.objective_id} {obj.category} prio={obj.priority} "
                f"dep={dep.get('effect', '?')}", 100),
            "source_agent": _bounded(specialist or "unselected", 60),
            "source_classification": _bounded(obj.category, 40),
            "recommendation": _bounded(obj.research_question, 160),
            "confidence": "not_evaluated",
            "research_only": True,
        })
    signals.append({
        "signal_type": "BUDGET_STATE",
        "subject": _bounded(
            "remaining: " + ",".join(
                f"{k}={v}" for k, v in
                sorted((budget_report.get("remaining") or {}).items())[:8]),
            140),
        "source_agent": "campaign-orchestrator",
        "source_classification": _bounded(campaign.category
                                          if hasattr(campaign, "category")
                                          else "CAMPAIGN", 40),
        "recommendation": _bounded(
            "executable: " + ",".join(sorted(executable)), 160),
        "confidence": "not_evaluated",
        "research_only": True,
    })

    sections = {
        "research_context": {
            "research_question": _bounded(
                campaign.campaign_objective, 160),
            "research_focus": _bounded(
                f"campaign-prioritization:{campaign.program}", 80),
            "context_fact_count": len(signals),
            "source_layers": ["authorized_observations", "knowledge",
                              "research_memory", "deterministic_analysis"],
            "research_only": True,
        },
        # objective summaries are capped at 5 so the BUDGET_STATE
        # signal (always appended last) always survives the size cap.
        "learning_signals": signals[:6],
    }

    source_refs = [
        {"layer": SOURCE_REF_LAYER_R45,
         "reference": _bounded(campaign.scope_ref, 40).lower() or "none"},
        {"layer": SOURCE_REF_LAYER_R45,
         "reference": _bounded(
             f"campaign:{campaign.campaign_id}", 40).lower()},
        {"layer": SOURCE_REF_LAYER_R45,
         "reference": "campaign-prioritizer-heuristic-v1"},
        {"layer": SOURCE_REF_LAYER_R44,
         "reference": "campaign-dependency-graph-v1"},
    ]
    limitations = list(ADVISORY_INPUT_LIMITATIONS)[:8]

    return {
        "rule_version": RULE_VERSION,
        # schema ADVISORY_ID_RE = adv- + 16 hex (production-proven)
        "advisory_id": f"adv-{uuid.uuid4().hex[:16]}",
        "advisory_mode": "RESEARCH_PRIORITY",
        "provider_kind": "OPENROUTER",
        "source_layer": "MULTI",
        "instruction": instruction,
        "sections": sections,
        "source_refs": source_refs,
        "limitations": limitations,
        "research_only": True,
        "deterministic": False,
    }


# ---------------------------------------------------------------------------
# response validation (Phase 5: trusted code checks everything)
# ---------------------------------------------------------------------------

@dataclass
class AdvisorOutcome:
    used: bool = False
    recommended_objective: str = ""
    rationale: str = ""
    expected_information_value: str = ""
    blockers: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    recommended_specialist: str = ""
    confidence: str = "advisory"
    alternative_objectives: list[str] = field(default_factory=list)
    reordered: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    model_requested: str = "openrouter/free"
    model_resolved: str = ""
    latency_ms: int = 0
    prompt_version: str = ADVISOR_PROMPT_VERSION
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "recommended_objective": self.recommended_objective,
            "rationale": self.rationale,
            "expected_information_value": self.expected_information_value,
            "blockers": list(self.blockers),
            "dependencies": list(self.dependencies),
            "recommended_specialist": self.recommended_specialist,
            "confidence": self.confidence,
            "alternative_objectives": list(self.alternative_objectives),
            "reordered": list(self.reordered),
            "rejected": list(self.rejected),
            "model_requested": self.model_requested,
            "model_resolved": self.model_resolved,
            "latency_ms": self.latency_ms,
            "prompt_version": self.prompt_version,
            "error": self.error,
        }


def validate_recommendation(
    recommended_id: str,
    *,
    campaign_id: str,
    scope_ref: str,
    objectives_by_id: dict[str, Any],
    executable_ids: set[str],
    specialists: dict[str, str],
    budget_ok: bool,
    running_ids: set[str],
) -> tuple[bool, str]:
    """Every Phase-5 check; returns (ok, reason). Fail closed."""

    if not recommended_id:
        return False, "no objective recommended"
    obj = objectives_by_id.get(recommended_id)
    if obj is None:
        return False, f"objective {recommended_id} does not exist"
    if str(obj.campaign_id) != str(campaign_id):
        return False, "objective belongs to a different campaign"
    if str(obj.scope_ref) != str(scope_ref):
        return False, "objective scope does not match campaign scope"
    if recommended_id not in executable_ids:
        return False, "objective is not executable (state/dependencies)"
    if recommended_id in running_ids:
        return False, "objective already running"
    if getattr(obj, "is_terminal", False) or obj.state in (
            "RESOLVED", "REJECTED", "EXPIRED", "FAILED", "CANCELLED"):
        return False, "objective is terminal"
    # ``specialists`` maps objective_id -> selected specialist agent name
    # (what the selector actually produced for each executable objective).
    if not str((specialists or {}).get(recommended_id) or "").strip():
        return False, "no specialist selected for objective"
    if not budget_ok:
        return False, "campaign budget exhausted"
    return True, "valid"


def map_advisor_response(
    response: Any,
    *,
    campaign_id: str,
    scope_ref: str,
    objectives_by_id: dict[str, Any],
    executable_ids: set[str],
    deterministic_order: list[str],
    specialists: dict[str, str],
    budget_ok: bool,
    running_ids: set[str] | None = None,
) -> AdvisorOutcome:
    """Strict, deterministic mapping + validation of the advisory response.

    On ANY shape/semantic failure: error set, used=False, deterministic
    order stands.  On success: ``reordered`` is a permutation of the
    deterministic order with the validated recommendation moved to the
    front — never an objective outside the executable set.
    """

    running_ids = running_ids or set()
    out = AdvisorOutcome()
    if not isinstance(response, dict):
        out.error = "malformed_advisor_response:not_an_object"
        return out
    summary = response.get("summary")
    insights = response.get("insights")
    recommendations = response.get("recommendations")
    if not isinstance(summary, str) or not summary.strip() \
            or not isinstance(insights, list) \
            or not isinstance(recommendations, list):
        out.error = "malformed_advisor_response:missing_keys"
        return out

    out.rationale = _bounded(summary, 300)
    texts = [out.rationale]
    priority_hint = 0

    for item in insights[:8]:
        if not isinstance(item, dict):
            out.error = "malformed_advisor_response:insight_shape"
            return out
        code = str(item.get("insight_code") or "")
        text = str(item.get("text") or "")
        if not code.strip() or not text.strip():
            out.error = "malformed_advisor_response:insight_item"
            return out
        texts.append(_bounded(text, 240))
        upper = code.upper()
        if upper.startswith("INFO_VALUE"):
            out.expected_information_value = _bounded(text, 200)
        elif upper.startswith("DEPENDENCY_"):
            out.dependencies.append(_bounded(text, 160))
        elif upper.startswith("CONFIDENCE_"):
            digits = "".join(ch for ch in upper if ch.isdigit())
            out.confidence = ("high" if digits and int(digits) >= 4
                              else "medium" if digits else "advisory")

    recommended_id = ""
    for item in recommendations[:8]:
        if not isinstance(item, dict):
            out.error = "malformed_advisor_response:recommendation_shape"
            return out
        code = str(item.get("recommendation_code") or "")
        text = str(item.get("text") or "")
        if not code.strip() or not text.strip():
            out.error = "malformed_advisor_response:recommendation_item"
            return out
        texts.append(_bounded(text, 240))
        upper = code.upper()
        if upper.startswith("BLOCKER_"):
            out.blockers.append(_bounded(text, 160))
        elif upper.startswith("OBJECTIVE_PRIORITY_"):
            digits = "".join(ch for ch in upper if ch.isdigit())
            priority_hint = int(digits[:1]) if digits else 0
        elif upper.startswith("SPECIALIST_"):
            out.recommended_specialist = _bounded(text, 60)
        # objective id discovery: code TEXT carrying an obj-<hex> id
        for token in text.replace(",", " ").split():
            tok = token.strip(".:;()")
            if tok in objectives_by_id:
                if not recommended_id:
                    recommended_id = tok
                elif tok != recommended_id and tok not in out.alternative_objectives:
                    out.alternative_objectives.append(tok)

    # forbidden content scan (same closed patterns as the hunt advisor)
    from backend.research_agents.hunt.registry import scan_forbidden
    forbidden = scan_forbidden(texts)
    if forbidden:
        out.error = "forbidden_advisor_content:" + ",".join(forbidden)
        out.rejected = list(forbidden)
        return out

    if not recommended_id:
        # no objective named: advisory cannot reorder, but is still
        # recorded (honest: used=False, rationale kept)
        out.error = "no_objective_recommended"
        return out

    ok, reason = validate_recommendation(
        recommended_id,
        campaign_id=campaign_id,
        scope_ref=scope_ref,
        objectives_by_id=objectives_by_id,
        executable_ids=executable_ids,
        specialists=specialists,
        budget_ok=budget_ok,
        running_ids=running_ids,
    )
    if not ok:
        out.rejected.append(f"{recommended_id}: {reason}")
        out.error = f"invalid_recommendation:{reason}"
        return out

    out.recommended_objective = recommended_id
    # advisor may reorder ONLY within the deterministic executable order:
    # move validated recommendation to front, keep the rest as-is.
    rest = [oid for oid in deterministic_order if oid != recommended_id]
    reordered = [recommended_id] + rest
    # sanity: the permutation must contain exactly the deterministic set
    if sorted(reordered) != sorted(deterministic_order):
        out.error = "reorder_would_change_candidate_set"
        out.rejected.append(recommended_id)
        return out
    out.reordered = reordered
    if priority_hint:
        out.confidence = out.confidence or "advisory"
    out.used = True
    return out


def apply_advisory(
    deterministic: list[str],
    outcome: AdvisorOutcome,
) -> list[str]:
    """Final order: advisory reorder when valid, else deterministic."""

    if outcome.used and outcome.reordered:
        allowed = set(deterministic)
        if set(outcome.reordered) == allowed and outcome.reordered:
            return list(outcome.reordered)
    return list(deterministic)


__all__ = [
    "advisor_request", "map_advisor_response", "validate_recommendation",
    "apply_advisory", "AdvisorOutcome", "ADVISOR_PROMPT_VERSION",
]
