"""OAuth specialist agent schema facade (Stage R48).

Convenience facade that re-exports the R48 specialist schema components:

    identity           -> ai.schemas.oauth_agent_identity
    context analysis   -> ai.schemas.oauth_context_analysis
    hypothesis         -> ai.schemas.oauth_hypothesis
    evidence plan      -> ai.schemas.oauth_evidence_plan
    agent result       -> ai.schemas.oauth_agent_result

The components remain the canonical definitions; this module only
aggregates them for discoverability. No I/O, no network, no LLM, no Mongo,
no execution of any kind is represented here.
"""

from __future__ import annotations

from ai.schemas import oauth_agent_identity as _identity
from ai.schemas import oauth_agent_result as _result
from ai.schemas import oauth_context_analysis as _context
from ai.schemas import oauth_evidence_plan as _evidence
from ai.schemas import oauth_hypothesis as _hypothesis
from ai.schemas.oauth_agent_identity import *  # noqa: F401,F403
from ai.schemas.oauth_agent_result import *  # noqa: F401,F403
from ai.schemas.oauth_context_analysis import *  # noqa: F401,F403
from ai.schemas.oauth_evidence_plan import *  # noqa: F401,F403
from ai.schemas.oauth_hypothesis import *  # noqa: F401,F403

OAUTH_AGENT_SCHEMA_FACADE_RULE_VERSION = "r48-1..r48-5"
RULE_VERSION = OAUTH_AGENT_SCHEMA_FACADE_RULE_VERSION

OAUTH_AGENT_SCHEMA_MODULES: tuple[str, ...] = (
    "ai/schemas/oauth_agent_identity.py",
    "ai/schemas/oauth_context_analysis.py",
    "ai/schemas/oauth_hypothesis.py",
    "ai/schemas/oauth_evidence_plan.py",
    "ai/schemas/oauth_agent_result.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _result.__all__
        + [
            "OAUTH_AGENT_SCHEMA_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "OAUTH_AGENT_SCHEMA_MODULES",
        ]
    )
)
