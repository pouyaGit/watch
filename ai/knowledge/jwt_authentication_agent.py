"""JWT/authentication specialist agent knowledge facade (Stage R47).

Convenience facade that re-exports the R47 specialist knowledge engine and
provides the aggregate entry point:

    identity planner   -> ai.knowledge.jwt_authentication_agent_identity
    context analyzer   -> ai.knowledge.jwt_authentication_context_analyzer
    hypothesis planner -> ai.knowledge.jwt_authentication_hypothesis_planner
    evidence planner   -> ai.knowledge.jwt_authentication_evidence_planner
    result exporter    -> ai.knowledge.jwt_authentication_agent_result_export

The components remain the canonical definitions; this module only aggregates
them for discoverability. It analyzes already-supplied structured context and
never executes, forges, bypasses, tests credentials or contacts anything.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

from ai.knowledge import (
    jwt_authentication_agent_identity as _identity,
)
from ai.knowledge import (
    jwt_authentication_agent_result_export as _export,
)
from ai.knowledge import (
    jwt_authentication_context_analyzer as _context,
)
from ai.knowledge import (
    jwt_authentication_evidence_planner as _evidence,
)
from ai.knowledge import (
    jwt_authentication_hypothesis_planner as _hypothesis,
)
from ai.knowledge.jwt_authentication_agent_identity import *  # noqa: F401,F403
from ai.knowledge.jwt_authentication_agent_result_export import *  # noqa: F401,F403
from ai.knowledge.jwt_authentication_context_analyzer import *  # noqa: F401,F403
from ai.knowledge.jwt_authentication_evidence_planner import *  # noqa: F401,F403
from ai.knowledge.jwt_authentication_hypothesis_planner import *  # noqa: F401,F403
from ai.knowledge.jwt_authentication_agent_result_export import (
    export_jwt_authentication_agent_result as run_jwt_authentication_agent,
)

JWT_AUTHENTICATION_AGENT_KNOWLEDGE_FACADE_RULE_VERSION = "r47-1..r47-5"
RULE_VERSION = JWT_AUTHENTICATION_AGENT_KNOWLEDGE_FACADE_RULE_VERSION

JWT_AUTHENTICATION_AGENT_KNOWLEDGE_MODULES: tuple[str, ...] = (
    "ai/knowledge/jwt_authentication_agent_identity.py",
    "ai/knowledge/jwt_authentication_context_analyzer.py",
    "ai/knowledge/jwt_authentication_hypothesis_planner.py",
    "ai/knowledge/jwt_authentication_evidence_planner.py",
    "ai/knowledge/jwt_authentication_agent_result_export.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _export.__all__
        + [
            "run_jwt_authentication_agent",
            "JWT_AUTHENTICATION_AGENT_KNOWLEDGE_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "JWT_AUTHENTICATION_AGENT_KNOWLEDGE_MODULES",
        ]
    )
)
