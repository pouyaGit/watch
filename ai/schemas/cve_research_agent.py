"""CVE research specialist agent schema facade (Stage R50).

Convenience facade that re-exports the R50 specialist schema components:

    identity           -> ai.schemas.cve_research_agent_identity
    context analysis   -> ai.schemas.cve_research_context_analysis
    hypothesis         -> ai.schemas.cve_research_hypothesis
    evidence plan      -> ai.schemas.cve_research_evidence_plan
    agent result       -> ai.schemas.cve_research_agent_result

The components remain the canonical definitions; this module only
aggregates them for discoverability. No I/O, no network, no CVE lookup,
no LLM, no Mongo, no execution of any kind is represented here.
"""

from __future__ import annotations

from ai.schemas import cve_research_agent_identity as _identity
from ai.schemas import cve_research_agent_result as _result
from ai.schemas import cve_research_context_analysis as _context
from ai.schemas import cve_research_evidence_plan as _evidence
from ai.schemas import cve_research_hypothesis as _hypothesis
from ai.schemas.cve_research_agent_identity import *  # noqa: F401,F403
from ai.schemas.cve_research_agent_result import *  # noqa: F401,F403
from ai.schemas.cve_research_context_analysis import *  # noqa: F401,F403
from ai.schemas.cve_research_evidence_plan import *  # noqa: F401,F403
from ai.schemas.cve_research_hypothesis import *  # noqa: F401,F403

CVE_RESEARCH_AGENT_SCHEMA_FACADE_RULE_VERSION = "r50-1..r50-5"
RULE_VERSION = CVE_RESEARCH_AGENT_SCHEMA_FACADE_RULE_VERSION

CVE_RESEARCH_AGENT_SCHEMA_MODULES: tuple[str, ...] = (
    "ai/schemas/cve_research_agent_identity.py",
    "ai/schemas/cve_research_context_analysis.py",
    "ai/schemas/cve_research_hypothesis.py",
    "ai/schemas/cve_research_evidence_plan.py",
    "ai/schemas/cve_research_agent_result.py",
)

__all__ = list(
    dict.fromkeys(
        _identity.__all__
        + _context.__all__
        + _hypothesis.__all__
        + _evidence.__all__
        + _result.__all__
        + [
            "CVE_RESEARCH_AGENT_SCHEMA_FACADE_RULE_VERSION",
            "RULE_VERSION",
            "CVE_RESEARCH_AGENT_SCHEMA_MODULES",
        ]
    )
)
