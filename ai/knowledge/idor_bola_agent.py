"""IDOR/BOLA specialist agent knowledge facade (Stage R46).

Convenience facade that re-exports the R46 specialist knowledge engine and
provides the aggregate entry point:

    identity planner   -> ai.knowledge.idor_bola_agent_identity
    context analyzer   -> ai.knowledge.idor_bola_context_analyzer
    hypothesis planner -> ai.knowledge.idor_bola_hypothesis_planner
    evidence planner   -> ai.knowledge.idor_bola_evidence_planner
    result exporter    -> ai.knowledge.idor_bola_agent_result_export

The components remain the canonical definitions; this module only aggregates
them for discoverability. It analyzes already-supplied structured context and
never executes, bypasses, scans or contacts anything.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

from ai.knowledge import idor_bola_agent_identity as _identity
from ai.knowledge import idor_bola_agent_result_export as _export
from ai.knowledge import idor_bola_context_analyzer as _context
from ai.knowledge import idor_bola_evidence_planner as _evidence
from ai.knowledge import idor_bola_hypothesis_planner as _hypothesis
from ai.knowledge.idor_bola_agent_identity import *  # noqa: F401,F403
from ai.knowledge.idor_bola_agent_result_export import *  # noqa: F401,F403
from ai.knowledge.idor_bola_context_analyzer import *  # noqa: F401,F403
from ai.knowledge.idor_bola_evidence_planner import *  # noqa: F401,F403
from ai.knowledge.idor_bola_hypothesis_planner import *  # noqa: F401,F403
from ai.knowledge.idor_bola_agent_result_export import (
    export_idor_bola_agent_result as run_idor_bola_agent,
)

IDOR_BOLA_AGENT_KNOWLEDGE_FACADE_RULE_VERSION = "r46-1..r46-5"
RULE_VERSION = IDOR_BOLA_AGENT_KNOWLEDGE_FACADE_RULE_VERSION

IDOR_BOLA_AGENT_KNOWLEDGE_MODULES: tuple[str, ...] = (
    "ai/knowledge/idor_bola_agent_identity.py",
    "ai/knowledge/idor_bola_context_analyzer.py",
    "ai/knowledge/idor_bola_hypothesis_planner.py",
    "ai/knowledge/idor_bola_evidence_planner.py",
    "ai/knowledge/idor_bola_agent_result_export.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _export.__all__
        + [
            "run_idor_bola_agent",
            "IDOR_BOLA_AGENT_KNOWLEDGE_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "IDOR_BOLA_AGENT_KNOWLEDGE_MODULES",
        ]
    )
)
