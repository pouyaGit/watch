"""Deterministic candidate triage (Phase 3).

Triage is pure function over persisted state: evidence completeness and
quality, confidence provenance, duplicate likelihood, scope validity,
endpoint/class context, previous verification attempts, existing cases,
specialist support and research freshness.  The LLM is NEVER the triage
authority — at most the verification advisor may comment afterwards
(Phase 10), and its comment cannot change this output.

Output: triage state, priority, missing evidence, duplicate candidates,
recommended verification path, reason codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.finding.models import CandidateFinding

TRIAGE_RULE_VERSION = "finding-triage-1"

# freshness: research older than this is stale (seconds)
FRESH_WINDOW = 7 * 24 * 3600
FRESH_WARN = 24 * 3600

RECOMMEND_VERIFY = "verify_via_hunt_planner"
RECOMMEND_MORE = "collect_missing_evidence"
RECOMMEND_STOP = "no_verification_path"


@dataclass
class TriageDecision:
    candidate_id: str
    state: str                 # TRIAGED|NEEDS_EVIDENCE|REJECTED|BLOCKED
    priority: int              # 0..100 heuristic (labeled)
    missing_evidence: list[str]
    duplicate_candidates: list[str]
    recommended_path: str
    required_observation_types: list[str]
    reason_codes: list[str]
    specialist_support: bool
    freshness: str             # fresh|aging|stale
    limitations: str = ("heuristic triage score; never a finding, never "
                        "proof — verification goes through the Evidence Gate")
    rule_version: str = TRIAGE_RULE_VERSION


def _age_seconds(iso_ts: str, now_ts: float) -> float | None:
    try:
        from datetime import datetime
        created = datetime.fromisoformat(str(iso_ts))
        return max(0.0, now_ts - created.timestamp())
    except Exception:  # noqa: BLE001
        return None


def triage_candidate(
    *,
    candidate: CandidateFinding,
    evidence_rows: list[dict[str, Any]],
    capability: Any,
    existing_case_ids: list[str] | None = None,
    duplicate_candidates: list[str] | None = None,
    previous_attempts: int = 0,
    verification_exists: bool = False,
    now_ts: float | None = None,
) -> TriageDecision:
    """Deterministic triage for one candidate (never LLM-decided)."""
    import time
    now = now_ts if now_ts is not None else time.time()
    reasons: list[str] = []

    # -- scope validity (fail closed) --------------------------------------
    scope = str(candidate.scope_ref or "")
    if not (scope.startswith("watch:scope:") or scope.startswith("fixture:")):
        return TriageDecision(
            candidate.candidate_id, "REJECTED", 0,
            list(candidate.missing_evidence), [], RECOMMEND_STOP, [],
            ["invalid_scope"], False, "stale")

    # -- evidence completeness / quality -----------------------------------
    job_evidence = [e for e in evidence_rows
                    if str(e.get("job_id") or "") == str(candidate.source_job)]
    observed = [e for e in job_evidence
                if str(e.get("type") or "") == "observation"]
    direct = [e for e in observed
              if str(e.get("observation_ref") or "")]
    req = getattr(capability, "evidence_requirements", None)
    min_refs = int(getattr(req, "min_evidence_refs", 2) or 2)
    required_types = tuple(getattr(req, "required_types", ("observation",))
                           or ("observation",))
    have_types = {str(e.get("type") or "") for e in job_evidence}
    missing_types = [t for t in required_types if t not in have_types]

    complete = len(observed) >= min_refs and not missing_types
    if complete:
        reasons.append("evidence_complete")
    else:
        reasons.append("evidence_incomplete")
    if missing_types:
        reasons.append(f"missing_evidence_type:{missing_types[0]}")
    if direct:
        reasons.append("direct_observation_present")

    # -- confidence provenance ---------------------------------------------
    conf = str(candidate.confidence or "insufficient")
    prov = str(candidate.confidence_provenance or "")
    if prov != "research_result":
        # unknown provenance => fail closed to insufficient
        conf = "insufficient"
        reasons.append("confidence_provenance_untrusted")
    else:
        reasons.append(f"confidence_provenance:{prov}")
    if conf == "high":
        reasons.append("research_confidence_high")
    elif conf == "insufficient":
        reasons.append("research_confidence_insufficient")

    # -- duplicate likelihood (structured correlation output) --------------
    duplicates = [str(x) for x in (duplicate_candidates or []) if x]
    dup_likelihood = "none"
    if duplicates:
        relation = str((candidate.correlation or {}).get("relation") or "")
        if relation == "SAME_CANDIDATE" or \
                str(candidate.correlation.get("strongest") or "") == "SAME_CANDIDATE":
            dup_likelihood = "high"
        elif relation == "POSSIBLE_DUPLICATE":
            dup_likelihood = "medium"
        else:
            dup_likelihood = "low"
        reasons.append(f"duplicate_likelihood:{dup_likelihood}")
    else:
        reasons.append("duplicate_likelihood:none")

    # -- existing cases -----------------------------------------------------
    if existing_case_ids:
        reasons.append("existing_cases_present")

    # -- specialist support --------------------------------------------------
    supported = capability is not None and bool(
        getattr(capability, "category", ""))
    reasons.append("specialist_supported" if supported
                   else "specialist_unavailable")

    # -- freshness ------------------------------------------------------------
    age = _age_seconds(candidate.created_at, now)
    if age is None:
        freshness = "stale"
        reasons.append("freshness_unknown")
    elif age > FRESH_WINDOW:
        freshness = "stale"
        reasons.append("research_stale")
    elif age > FRESH_WARN:
        freshness = "aging"
        reasons.append("research_aging")
    else:
        freshness = "fresh"
        reasons.append("research_fresh")

    # -- previous verification attempts ----------------------------------------
    if previous_attempts > 0:
        reasons.append(f"prior_attempts:{previous_attempts}")

    # -- missing evidence list (deterministic) -----------------------------------
    missing: list[str] = []
    if missing_types:
        missing.extend(f"evidence_type:{t}" for t in missing_types)
    if len(observed) < min_refs:
        missing.append(f"observation_count:{len(observed)}/{min_refs}")
    missing = list(dict.fromkeys(
        missing + list(candidate.missing_evidence or [])))[:10]

    # -- decision ------------------------------------------------------------
    # duplicates short-circuit (handled by dedupe; triage never verifies them)
    if dup_likelihood == "high" and duplicates:
        return TriageDecision(
            candidate.candidate_id, "REJECTED", 0, missing, duplicates,
            RECOMMEND_STOP, [],
            reasons + ["duplicate_of_canonical"], supported, freshness)

    if not supported:
        return TriageDecision(
            candidate.candidate_id, "BLOCKED", 10, missing, duplicates,
            RECOMMEND_STOP, [], reasons + ["no_specialist_capability"],
            False, freshness)

    # heuristic priority score — explicitly labeled heuristic
    score = 0
    score += {"high": 40, "medium": 25, "low": 10,
              "insufficient": 0}.get(conf, 0)
    score += 20 if complete else 0
    score += 10 if direct else 0
    score += 10 if freshness == "fresh" else (5 if freshness == "aging" else 0)
    score -= 25 if previous_attempts >= 2 else (10 if previous_attempts else 0)
    score -= 15 if existing_case_ids else 0
    score -= 15 if dup_likelihood == "medium" else 0
    score = max(0, min(100, score))

    required_types_for_path = list(missing_types) or list(required_types)
    if complete:
        state = "NEEDS_EVIDENCE" if missing else "TRIAGED"
        path = RECOMMEND_VERIFY
    else:
        state = "NEEDS_EVIDENCE"
        path = RECOMMEND_MORE if missing else RECOMMEND_VERIFY

    if verification_exists:
        reasons.append("verification_already_exists")
        state = "TRIAGED" if state == "TRIAGED" else state

    return TriageDecision(
        candidate_id=candidate.candidate_id,
        state=state,
        priority=score,
        missing_evidence=missing,
        duplicate_candidates=duplicates,
        recommended_path=path,
        required_observation_types=required_types_for_path,
        reason_codes=reasons,
        specialist_support=supported,
        freshness=freshness,
    )
