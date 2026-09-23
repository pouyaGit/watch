"""Phase 15: campaign audit lineage (no secrets).

Chain: campaign -> objective -> prioritization -> agent selection ->
hunt plan -> authorization -> observation -> evidence -> gate -> learning
-> objective result -> campaign state -> next objective.

Campaign-level rows go through the SAME runtime audit stream
(``store.record_audit_event``) with ``event`` names prefixed
``campaign_``, carrying both campaign and (when known) job/plan/auth ids
so the full lineage is reconstructable from one append-only file.
"""
from __future__ import annotations

from typing import Any


def campaign_event(stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Build an audit event; every campaign lineage row is campaign_*
    prefixed. Secrets are never accepted (payload is text/ids/ints only)."""

    safe: dict[str, Any] = {}
    for key, value in payload.items():
        text = str(value)
        # defense in depth: never persist anything key/credential-shaped
        lowered = text.lower()
        if any(bad in lowered for bad in
               ("sk-or-", "bearer ", "api_key=", "authorization:",
                "openrouter_api")):
            text = "[REDACTED]"
        if isinstance(value, (int, float, bool)) or value is None:
            safe[key] = value
        else:
            safe[key] = text[:600]
    return {"event": f"campaign_{stage}", **safe}


LINEAGE_STAGES: tuple[str, ...] = (
    "started",            # campaign created/activated
    "objective_selected", # prioritization + selection
    "specialist_selected",
    "objective_started",  # job enqueued for objective
    "hunt_summary",       # plans/auths/obs read back from real stores
    "objective_terminal", # objective reached terminal state + gate reason
    "context_recorded",   # cross-objective context items persisted
    "budget_consumed",    # budget before/after (mirrors budget ledger)
    "advisor_outcome",    # LLM advisory result (valid/rejected)
    "paused", "resumed",
    "reprioritized",      # deterministic order for the next objective
    "terminated",         # termination record fields
    "lease_refused",      # duplicate coordinator attempt
)


def lineage_row(*, campaign_id: str, objective_id: str = "",
                job_id: str = "", specialist: str = "",
                requested_model: str = "", resolved_model: str = "",
                prompt_version: str = "", prioritizer_version: str = "",
                planner_version: str = "", budget_before: Any = None,
                budget_after: Any = None, authorization_result: str = "",
                evidence_result: str = "", termination_reason: str = "",
                plan_ids: Any = None, auth_ids: Any = None,
                observation_ids: Any = None, case_id: str = "",
                stage: str, extra: dict[str, Any] | None = None,
                ) -> dict[str, Any]:
    """One fully-populated lineage row (Phase 15 field list)."""

    row: dict[str, Any] = {
        "campaign_id": campaign_id,
        "objective_id": objective_id,
        "job_id": job_id,
        "specialist": specialist,
        "requested_model": requested_model,
        "resolved_model": resolved_model,
        "prompt_version": prompt_version,
        "prioritizer_version": prioritizer_version,
        "planner_version": planner_version,
        "budget_before": budget_before if budget_before is not None else {},
        "budget_after": budget_after if budget_after is not None else {},
        "authorization_result": authorization_result,
        "evidence_result": evidence_result,
        "termination_reason": termination_reason,
        "plan_ids": list(plan_ids or []),
        "authorization_ids": list(auth_ids or []),
        "observation_ids": list(observation_ids or []),
        "case_id": case_id,
    }
    if extra:
        row.update(extra)
    return campaign_event(stage, row)


__all__ = ["campaign_event", "lineage_row", "LINEAGE_STAGES"]
