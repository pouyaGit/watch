"""backend/soc — AI Security Operations Center UI adapters (SOC-1..SOC-5).

Read-only projections over existing Watch state.  Every function in this
package builds a *view* from existing sources:

- ``backend.research_agents``  (registry + service payloads)
- ``backend.research_data``    (knowledge base, research records)
- ``backend.investigation_engine`` (memory, evidence store, reports)
- ``backend.routers.aec``     (AEC view builders, reused read-only)
- ``ai.knowledge.ai_activity_status`` (real runtime activity status)

Absolute rules:
- Never write: no file writes, no store mutations, no queue enqueues.
- Never execute: no jobs dispatched, no observations, no probes.
- No schema changes: sources are consumed as-is.
- Agents/cases/evidence absent in the underlying data render as empty
  blocks, never invented.
"""

from __future__ import annotations

from backend.soc.agents import agent_detail, agents_index
from backend.soc.activity import activity_payload
from backend.soc.cases import case_detail, cases_index
from backend.soc.handoff import handoff_detail, handoff_index
from backend.soc.overview import overview_payload

__all__ = [
    "agents_index",
    "agent_detail",
    "cases_index",
    "case_detail",
    "activity_payload",
    "handoff_index",
    "handoff_detail",
    "overview_payload",
]