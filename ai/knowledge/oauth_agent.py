"""OAuth specialist agent knowledge facade (Stage R48).

Convenience facade that re-exports the R48 specialist knowledge engine and
provides the aggregate entry point:

    identity planner   -> ai.knowledge.oauth_agent_identity
    context analyzer   -> ai.knowledge.oauth_context_analyzer
    hypothesis planner -> ai.knowledge.oauth_hypothesis_planner
    evidence planner   -> ai.knowledge.oauth_evidence_planner
    result exporter    -> ai.knowledge.oauth_agent_result_export

The components remain the canonical definitions; this module only
aggregates them for discoverability. It analyzes already-supplied
structured context and never executes, follows redirects, exchanges
tokens or contacts anything.

No I/O, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

from ai.knowledge import (
    oauth_agent_identity as _identity,
)
from ai.knowledge import (
    oauth_agent_result_export as _export,
)
from ai.knowledge import (
    oauth_context_analyzer as _context,
)
from ai.knowledge import (
    oauth_evidence_planner as _evidence,
)
from ai.knowledge import (
    oauth_hypothesis_planner as _hypothesis,
)
from ai.knowledge.oauth_agent_identity import *  # noqa: F401,F403
from ai.knowledge.oauth_agent_result_export import *  # noqa: F401,F403
from ai.knowledge.oauth_context_analyzer import *  # noqa: F401,F403
from ai.knowledge.oauth_evidence_planner import *  # noqa: F401,F403
from ai.knowledge.oauth_hypothesis_planner import *  # noqa: F401,F403
from ai.knowledge.oauth_agent_result_export import (
    export_oauth_agent_result as run_oauth_agent,
)

OAUTH_AGENT_KNOWLEDGE_FACADE_RULE_VERSION = "r48-1..r48-5"
RULE_VERSION = OAUTH_AGENT_KNOWLEDGE_FACADE_RULE_VERSION

OAUTH_AGENT_KNOWLEDGE_MODULES: tuple[str, ...] = (
    "ai/knowledge/oauth_agent_identity.py",
    "ai/knowledge/oauth_context_analyzer.py",
    "ai/knowledge/oauth_hypothesis_planner.py",
    "ai/knowledge/oauth_evidence_planner.py",
    "ai/knowledge/oauth_agent_result_export.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _export.__all__
        + [
            "run_oauth_agent",
            "OAUTH_AGENT_KNOWLEDGE_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "OAUTH_AGENT_KNOWLEDGE_MODULES",
        ]
    )
)
