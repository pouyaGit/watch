"""backend/research_agents/intelligence/lineage.py — Phase 10.

Research-trace helpers: every intelligence stage contributes ids/counts
to a lineage record persisted with the research result, and the same
stages append append-only audit events, so the complete chain

  job -> authorization -> observations -> knowledge retrieval -> memory
  retrieval -> prior research -> prompt/model -> LLM -> validation ->
  gate -> learning -> recommendation -> result -> case

can be reconstructed from ``audit.jsonl`` + the persisted result.

Lineage content is structural only (ids, counts, versions, reasons) —
never raw model text, never secrets.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.research_agents.intelligence.memory import scrub_text

LINEAGE_RULE_VERSION = "research-lineage-v1"


def build_lineage(
    *,
    job_id: str,
    knowledge_ids: list[str],
    memory_ids: list[str],
    related_ids: list[str],
    prompt_version: str,
    provider: str,
    model: str,
    gate_reason: str,
    gate_confidence: str,
    case_id: str,
    learned_ids: list[str],
    recommendation_ids: list[str],
    context_stats: dict[str, Any] | None = None,
    intelligence_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Deterministic lineage record embedded in the research result."""
    def bounded(values: list[str]) -> list[str]:
        return [scrub_text(v, 80) for v in values if str(v).strip()][:20]

    stages = {
        "job": scrub_text(job_id, 80),
        "knowledge_selected": bounded(knowledge_ids),
        "memory_retrieved": bounded(memory_ids),
        "prior_research_matched": bounded(related_ids),
        "prompt": {"version": scrub_text(prompt_version, 60),
                   "provider": scrub_text(provider, 40),
                   "model": scrub_text(model, 60)},
        "evidence_gate": {"reason": scrub_text(gate_reason, 80),
                          "confidence": scrub_text(gate_confidence, 40),
                          "case_id": scrub_text(case_id, 60)},
        "memory_learned": bounded(learned_ids),
        "recommendations_generated": bounded(recommendation_ids),
    }
    digest_src = json.dumps(stages, sort_keys=True, default=str)
    return {
        "rule_version": LINEAGE_RULE_VERSION,
        "stages": stages,
        "context_stats": dict(context_stats or {}),
        "intelligence_errors": [scrub_text(e, 160)
                                for e in (intelligence_errors or [])][:8],
        "digest": hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:24],
    }


def audit_event(stage: str, *, job_id: str, **payload: Any) -> dict[str, Any]:
    """Append-only audit row for one intelligence stage (store appends)."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, list):
            clean[key] = [scrub_text(v, 80) for v in value][:20]
        elif isinstance(value, dict):
            clean[key] = {scrub_text(k, 60): scrub_text(v, 160)
                          for k, v in value.items()}
        else:
            clean[key] = scrub_text(value, 200)
    return {
        "event": f"intelligence_{stage}",
        "job_id": scrub_text(job_id, 80),
        "rule_version": LINEAGE_RULE_VERSION,
        **clean,
    }


__all__ = ["LINEAGE_RULE_VERSION", "audit_event", "build_lineage"]
