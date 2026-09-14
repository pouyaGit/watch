"""IDOR/BOLA specialist agent schema facade (Stage R46).

Convenience facade that re-exports the R46 specialist schema components:

    identity           -> ai.schemas.idor_bola_agent_identity
    context analysis   -> ai.schemas.idor_bola_context_analysis
    hypothesis         -> ai.schemas.idor_bola_hypothesis
    evidence plan      -> ai.schemas.idor_bola_evidence_plan
    agent result       -> ai.schemas.idor_bola_agent_result

The components remain the canonical definitions; this module only aggregates
them for discoverability. No I/O, no network, no LLM, no Mongo, no execution
of any kind is represented here.
"""

from __future__ import annotations

from ai.schemas import idor_bola_agent_identity as _identity
from ai.schemas import idor_bola_agent_result as _result
from ai.schemas import idor_bola_context_analysis as _context
from ai.schemas import idor_bola_evidence_plan as _evidence
from ai.schemas import idor_bola_hypothesis as _hypothesis
from ai.schemas.idor_bola_agent_identity import *  # noqa: F401,F403
from ai.schemas.idor_bola_agent_result import *  # noqa: F401,F403
from ai.schemas.idor_bola_context_analysis import *  # noqa: F401,F403
from ai.schemas.idor_bola_evidence_plan import *  # noqa: F401,F403
from ai.schemas.idor_bola_hypothesis import *  # noqa: F401,F403

IDOR_BOLA_AGENT_SCHEMA_FACADE_RULE_VERSION = "r46-1..r46-5"
RULE_VERSION = IDOR_BOLA_AGENT_SCHEMA_FACADE_RULE_VERSION

IDOR_BOLA_AGENT_SCHEMA_MODULES: tuple[str, ...] = (
    "ai/schemas/idor_bola_agent_identity.py",
    "ai/schemas/idor_bola_context_analysis.py",
    "ai/schemas/idor_bola_hypothesis.py",
    "ai/schemas/idor_bola_evidence_plan.py",
    "ai/schemas/idor_bola_agent_result.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _result.__all__
        + [
            "IDOR_BOLA_AGENT_SCHEMA_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "IDOR_BOLA_AGENT_SCHEMA_MODULES",
        ]
    )
)
