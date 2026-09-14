"""API security specialist agent knowledge facade (Stage R49).

Convenience facade that re-exports the R49 specialist knowledge engine and
provides the aggregate entry point:

    identity planner   -> ai.knowledge.api_security_agent_identity
    context analyzer   -> ai.knowledge.api_security_context_analyzer
    hypothesis planner -> ai.knowledge.api_security_hypothesis_planner
    evidence planner   -> ai.knowledge.api_security_evidence_planner
    result exporter    -> ai.knowledge.api_security_agent_result_export

The components remain the canonical definitions; this module only
aggregates them for discoverability. It analyzes already-supplied
structured context and never calls, probes, fuzzes or contacts anything.

No I/O, no network, no API call, no LLM, no Mongo, no execution of any
kind is represented here.
"""

from __future__ import annotations

from ai.knowledge import (
    api_security_agent_identity as _identity,
)
from ai.knowledge import (
    api_security_agent_result_export as _export,
)
from ai.knowledge import (
    api_security_context_analyzer as _context,
)
from ai.knowledge import (
    api_security_evidence_planner as _evidence,
)
from ai.knowledge import (
    api_security_hypothesis_planner as _hypothesis,
)
from ai.knowledge.api_security_agent_identity import *  # noqa: F401,F403
from ai.knowledge.api_security_agent_result_export import *  # noqa: F401,F403
from ai.knowledge.api_security_context_analyzer import *  # noqa: F401,F403
from ai.knowledge.api_security_evidence_planner import *  # noqa: F401,F403
from ai.knowledge.api_security_hypothesis_planner import *  # noqa: F401,F403
from ai.knowledge.api_security_agent_result_export import (
    export_api_security_agent_result as run_api_security_agent,
)

API_SECURITY_AGENT_KNOWLEDGE_FACADE_RULE_VERSION = "r49-1..r49-5"
RULE_VERSION = API_SECURITY_AGENT_KNOWLEDGE_FACADE_RULE_VERSION

API_SECURITY_AGENT_KNOWLEDGE_MODULES: tuple[str, ...] = (
    "ai/knowledge/api_security_agent_identity.py",
    "ai/knowledge/api_security_context_analyzer.py",
    "ai/knowledge/api_security_hypothesis_planner.py",
    "ai/knowledge/api_security_evidence_planner.py",
    "ai/knowledge/api_security_agent_result_export.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _export.__all__
        + [
            "run_api_security_agent",
            "API_SECURITY_AGENT_KNOWLEDGE_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "API_SECURITY_AGENT_KNOWLEDGE_MODULES",
        ]
    )
)
