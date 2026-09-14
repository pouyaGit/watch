"""JWT/authentication specialist agent schema facade (Stage R47).

Convenience facade that re-exports the R47 specialist schema components:

    identity           -> ai.schemas.jwt_authentication_agent_identity
    context analysis   -> ai.schemas.jwt_authentication_context_analysis
    hypothesis         -> ai.schemas.jwt_authentication_hypothesis
    evidence plan      -> ai.schemas.jwt_authentication_evidence_plan
    agent result       -> ai.schemas.jwt_authentication_agent_result

The components remain the canonical definitions; this module only aggregates
them for discoverability. No I/O, no network, no LLM, no Mongo, no execution
of any kind is represented here.
"""

from __future__ import annotations

from ai.schemas import jwt_authentication_agent_identity as _identity
from ai.schemas import jwt_authentication_agent_result as _result
from ai.schemas import jwt_authentication_context_analysis as _context
from ai.schemas import jwt_authentication_evidence_plan as _evidence
from ai.schemas import jwt_authentication_hypothesis as _hypothesis
from ai.schemas.jwt_authentication_agent_identity import *  # noqa: F401,F403
from ai.schemas.jwt_authentication_agent_result import *  # noqa: F401,F403
from ai.schemas.jwt_authentication_context_analysis import *  # noqa: F401,F403
from ai.schemas.jwt_authentication_evidence_plan import *  # noqa: F401,F403
from ai.schemas.jwt_authentication_hypothesis import *  # noqa: F401,F403

JWT_AUTHENTICATION_AGENT_SCHEMA_FACADE_RULE_VERSION = "r47-1..r47-5"
RULE_VERSION = JWT_AUTHENTICATION_AGENT_SCHEMA_FACADE_RULE_VERSION

JWT_AUTHENTICATION_AGENT_SCHEMA_MODULES: tuple[str, ...] = (
    "ai/schemas/jwt_authentication_agent_identity.py",
    "ai/schemas/jwt_authentication_context_analysis.py",
    "ai/schemas/jwt_authentication_hypothesis.py",
    "ai/schemas/jwt_authentication_evidence_plan.py",
    "ai/schemas/jwt_authentication_agent_result.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _result.__all__
        + [
            "JWT_AUTHENTICATION_AGENT_SCHEMA_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "JWT_AUTHENTICATION_AGENT_SCHEMA_MODULES",
        ]
    )
)
