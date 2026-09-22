"""Hunt audit lineage events (Phase 14).

Every planner decision is reconstructable from append-only audit rows:
objective -> research state -> missing evidence -> candidates ->
deterministic scoring -> LLM advice -> validated plan -> authorization ->
execution -> observation -> evidence -> gate -> learning -> next plan /
termination. Rows carry structural facts only — ids, counts, versions,
reasons — never raw model text beyond bounded interpretations, never
secrets.
"""

from __future__ import annotations

from typing import Any

from backend.research_agents.hunt.executor import HUNT_RULE_VERSION
from backend.research_agents.intelligence.memory import scrub_text


def hunt_audit_event(stage: str, *, job_id: str | None = None,
                     **payload: Any) -> dict[str, Any]:
    """Append-only audit row for one hunt stage (store appends).

    ``stage`` values that already start with ``hunt_`` are used verbatim
    (hunt_lineage, hunt_lineage_final, hunt_authorization); any other
    stage is prefixed to keep the event namespace disjoint from the
    intelligence_* events.
    """
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, list):
            clean[key] = [scrub_text(v, 80) for v in value][:20]
        elif isinstance(value, dict):
            clean[key] = {scrub_text(str(k), 60): scrub_text(v, 160)
                          for k, v in value.items()}
        else:
            clean[key] = scrub_text(value, 200)
    embedded = payload.pop("job_id", None)
    resolved = job_id if job_id is not None else embedded
    event = stage if str(stage).startswith("hunt_") else f"hunt_{stage}"
    return {
        "event": event,
        "job_id": scrub_text(resolved, 80),
        "rule_version": HUNT_RULE_VERSION,
        **clean,
    }


__all__ = ["hunt_audit_event"]
