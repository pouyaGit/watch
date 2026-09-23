"""Verification Objective helpers (Phase 6/7) — reuse, never replace.

- ``build_verification_job`` mirrors campaign ``build_objective_job`` but
  is candidate-driven; the job's ``candidate_id``/``authorization_ref``
  fields link runtime execution back to this layer (scope == candidate
  scope, enforced by the store and again by AuthorizationChecker).
- ``precheck_authorization`` uses the EXISTING ``AuthorizationChecker``
  (the same fail-closed boundary every observation passes) — this layer
  adds no new authorization authority.
- Observation planning is NEVER done here: the existing Hunt Planner
  builds the plan inside the worker run (rule 18), constrained by
  ``capability.allowed_observation_types`` (rule 14/17).
"""

from __future__ import annotations

import uuid
from typing import Any

from backend.research_agents.finding.models import (
    CandidateFinding,
    VerificationObjective,
    new_id,
    utcnow,
)

REQUIRED_EVIDENCE_MIN = 2


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def allowed_types_for(capability: Any) -> list[str]:
    """Capability-scoped observation allowlist (registry intersection)."""
    from backend.research_agents.hunt.registry import ALLOWED_TYPES
    declared = {str(t).lower()
                for t in (getattr(capability, "allowed_observation_types",
                                  ()) or ())}
    if not declared:
        return list(ALLOWED_TYPES)
    return sorted(t for t in ALLOWED_TYPES if str(t).lower() in declared)


def required_evidence_for(capability: Any) -> list[str]:
    req = getattr(capability, "evidence_requirements", None)
    types = list(getattr(req, "required_types", ("observation",))
                 or ("observation",))
    min_refs = int(getattr(req, "min_evidence_refs", REQUIRED_EVIDENCE_MIN)
                   or REQUIRED_EVIDENCE_MIN)
    out = [f"evidence_type:{t}" for t in types]
    out.append(f"observation_count:{min_refs}")
    return out


def create_verification(
    *,
    store: Any,
    candidate: CandidateFinding,
    capability: Any,
    missing_evidence: list[str] | None = None,
    budget: dict[str, int] | None = None,
    provenance: dict[str, Any] | None = None,
) -> VerificationObjective:
    """Create + persist a bounded Verification Objective for a candidate."""
    allowed = allowed_types_for(capability)
    ver = VerificationObjective(
        verification_id=new_id("ver"),
        candidate_id=candidate.candidate_id,
        scope_ref=candidate.scope_ref,          # store re-checks equality
        vulnerability_class=candidate.vulnerability_class,
        hypothesis=candidate.hypothesis,
        required_evidence=required_evidence_for(capability),
        current_evidence=list(candidate.evidence_refs or []),
        missing_evidence=list(missing_evidence
                              or candidate.missing_evidence or []),
        allowed_observation_types=allowed,
        state="CREATED",
        budget=dict(budget or {}),
        provenance={
            "source": "finding_verification",
            "source_job": candidate.source_job,
            "campaign_id": candidate.source_campaign,
            "objective_id": candidate.source_objective,
            "specialist": str(getattr(capability, "agent_name", "")
                              or candidate.specialist),
            "rule_version": "finding-verify-1",
            **(provenance or {}),
        },
    )
    store.add_verification(ver)
    ver = store.transition_verification(ver.verification_id, "READY",
                                        reason="verification_planned")
    ver = store.transition_verification(
        ver.verification_id, "AUTHORIZATION_REQUIRED",
        reason="authorization_required_before_observation")
    return ver


def build_verification_job(
    *,
    candidate: CandidateFinding,
    verification: VerificationObjective,
    agent_name: str,
    config: Any,
) -> Any:
    """Construct the RuntimeStore job that executes one verification."""
    from backend.research_agents.models import JobStatus, ResearchJob

    if verification.scope_ref != candidate.scope_ref:
        raise ValueError("verification scope must equal candidate scope")
    category = str(candidate.vulnerability_class).upper()
    mission = (
        f"[finding verification {verification.verification_id} "
        f"candidate {candidate.candidate_id}] "
        f"{_bounded(verification.hypothesis, 240)} | required: "
        f"{_bounded(','.join(verification.missing_evidence[:4]), 160)}")
    reasons = [
        f"candidate:{candidate.candidate_id}",
        f"verification:{verification.verification_id}",
        "finding-verification:authorized-verification-run",
    ]
    return ResearchJob(
        id=f"job-{category.lower()}-{uuid.uuid4().hex[:10]}",
        candidate_id=candidate.candidate_id,
        category=category,
        endpoint=str(candidate.endpoint or verification.scope_ref),
        parameter=str(candidate.parameter or ""),
        priority_score=0,
        status=JobStatus.QUEUED.value,
        assigned_agent=agent_name,
        created_at=utcnow(),
        updated_at=utcnow(),
        agent_category=category,
        reasons=tuple(reasons),
        program="",
        subdomain=str(candidate.target or ""),
        url=str(candidate.endpoint or ""),
        mission=mission,
        authorization_ref=verification.scope_ref,
        timeout_seconds=int(getattr(config, "job_timeout", 300)),
        execution_mode=str(getattr(config, "execution_mode", "production")),
    )


def precheck_authorization(job: Any) -> tuple[bool, str]:
    """Existing fail-closed scope boundary, called BEFORE enqueue.

    Returns (authorized, reason_or_scope).  Denials are honest strings —
    never exceptions escaping to callers.
    """
    from backend.research_agents.runtime import (
        AuthorizationChecker,
        AuthorizationDenied,
    )
    try:
        ref = AuthorizationChecker().verify(job)
        return True, ref
    except AuthorizationDenied as exc:
        return False, str(getattr(exc, "args", [exc])[0])
    except Exception as exc:  # noqa: BLE001 - fail closed
        return False, f"authorization_error:{type(exc).__name__}"
