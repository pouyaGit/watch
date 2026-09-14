"""API security specialist agent schema facade (Stage R49).

Convenience facade that re-exports the R49 specialist schema components:

    identity           -> ai.schemas.api_security_agent_identity
    context analysis   -> ai.schemas.api_security_context_analysis
    hypothesis         -> ai.schemas.api_security_hypothesis
    evidence plan      -> ai.schemas.api_security_evidence_plan
    agent result       -> ai.schemas.api_security_agent_result

The components remain the canonical definitions; this module only
aggregates them for discoverability. No I/O, no network, no API call, no
LLM, no Mongo, no execution of any kind is represented here.
"""

from __future__ import annotations

from ai.schemas import api_security_agent_identity as _identity
from ai.schemas import api_security_agent_result as _result
from ai.schemas import api_security_context_analysis as _context
from ai.schemas import api_security_evidence_plan as _evidence
from ai.schemas import api_security_hypothesis as _hypothesis
from ai.schemas.api_security_agent_identity import *  # noqa: F401,F403
from ai.schemas.api_security_agent_result import *  # noqa: F401,F403
from ai.schemas.api_security_context_analysis import *  # noqa: F401,F403
from ai.schemas.api_security_evidence_plan import *  # noqa: F401,F403
from ai.schemas.api_security_hypothesis import *  # noqa: F401,F403

API_SECURITY_AGENT_SCHEMA_FACADE_RULE_VERSION = "r49-1..r49-5"
RULE_VERSION = API_SECURITY_AGENT_SCHEMA_FACADE_RULE_VERSION

API_SECURITY_AGENT_SCHEMA_MODULES: tuple[str, ...] = (
    "ai/schemas/api_security_agent_identity.py",
    "ai/schemas/api_security_context_analysis.py",
    "ai/schemas/api_security_hypothesis.py",
    "ai/schemas/api_security_evidence_plan.py",
    "ai/schemas/api_security_agent_result.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _result.__all__
        + [
            "API_SECURITY_AGENT_SCHEMA_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "API_SECURITY_AGENT_SCHEMA_MODULES",
        ]
    )
)
