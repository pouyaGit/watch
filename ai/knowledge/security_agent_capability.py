"""Stage R38.2 deterministic security agent capability planner (pure engine).

Defines WHAT a future security specialist agent conceptually may do:

    "Which analysis-only capabilities may this agent use, and which
     execution capabilities are explicitly prohibited?"

Hard boundaries encoded here:

- Framework/model only: no agent runtime, vulnerability scanning, HTTP,
  crawling, fuzzing, Nuclei, payloads, exploits, browser automation,
  subprocess, shell, queues, schedulers, autonomous loops, tool execution,
  external APIs, LLM calls, embeddings, Mongo persistence, database writes,
  plugin loading or dynamic imports.
- Execution is impossible by construction: every capability plan explicitly
  lists all five prohibited execution capabilities, and a plan can never
  allow a prohibited code.
- Pure and offline; deterministic closed mapping; read-only inputs.
"""

from __future__ import annotations

from ai.schemas.security_agent_capability import (
    ALLOWED_CAPABILITIES,
    CAP_ANALYZE_CONTEXT,
    CAP_ANALYZE_PATTERN,
    CAP_CREATE_HYPOTHESIS,
    CAP_GENERATE_EXPLANATION,
    CAP_RANK_FINDINGS,
    CAP_REQUEST_EVIDENCE,
    CAPABILITY_PARTIAL,
    CAPABILITY_UNKNOWN,
    CAPABILITY_VALID,
    PROHIBITED_CAPABILITIES,
    SECURITY_AGENT_CAPABILITY_RULE_VERSION,
    SecurityAgentCapabilityPlan,
    security_agent_capability_plan_projection,
)
from ai.schemas.security_agent_identity import (
    CATEGORY_CVE_RESEARCH,
    CATEGORY_IDOR,
    CATEGORY_JWT,
    CATEGORY_OAUTH,
    CATEGORY_RECON,
    CATEGORY_SQLI,
    CATEGORY_SSRF,
    CATEGORY_UNKNOWN,
    CATEGORY_XSS,
)

SECURITY_AGENT_CAPABILITY_PLANNER_RULE_VERSION = "r38-2"
RULE_VERSION = SECURITY_AGENT_CAPABILITY_PLANNER_RULE_VERSION

# category -> allowed analysis-only capabilities (fixed order)
CATEGORY_CAPABILITIES: dict[str, tuple] = {
    CATEGORY_XSS: (
        CAP_ANALYZE_CONTEXT,
        CAP_ANALYZE_PATTERN,
        CAP_CREATE_HYPOTHESIS,
        CAP_REQUEST_EVIDENCE,
        CAP_GENERATE_EXPLANATION,
    ),
    CATEGORY_SSRF: (
        CAP_ANALYZE_CONTEXT,
        CAP_ANALYZE_PATTERN,
        CAP_CREATE_HYPOTHESIS,
        CAP_REQUEST_EVIDENCE,
    ),
    CATEGORY_SQLI: (
        CAP_ANALYZE_CONTEXT,
        CAP_ANALYZE_PATTERN,
        CAP_CREATE_HYPOTHESIS,
        CAP_REQUEST_EVIDENCE,
    ),
    CATEGORY_IDOR: (
        CAP_ANALYZE_CONTEXT,
        CAP_ANALYZE_PATTERN,
        CAP_CREATE_HYPOTHESIS,
    ),
    CATEGORY_JWT: (
        CAP_ANALYZE_CONTEXT,
        CAP_ANALYZE_PATTERN,
        CAP_CREATE_HYPOTHESIS,
    ),
    CATEGORY_OAUTH: (
        CAP_ANALYZE_CONTEXT,
        CAP_ANALYZE_PATTERN,
        CAP_CREATE_HYPOTHESIS,
    ),
    CATEGORY_CVE_RESEARCH: (
        CAP_ANALYZE_PATTERN,
        CAP_REQUEST_EVIDENCE,
        CAP_GENERATE_EXPLANATION,
        CAP_RANK_FINDINGS,
    ),
    CATEGORY_RECON: (
        CAP_ANALYZE_CONTEXT,
        CAP_REQUEST_EVIDENCE,
    ),
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def plan_security_agent_capabilities(category: object = None) -> dict:
    """Build the deterministic capability contract for a category.

    Unknown/missing categories yield ``UNKNOWN`` capability state with an
    empty allowed set, but still explicitly list every prohibited execution
    capability.
    """

    resolved = _upper(category)
    allowed = CATEGORY_CAPABILITIES.get(resolved)
    if allowed is None:
        state = CAPABILITY_UNKNOWN
        allowed = ()
    elif allowed:
        state = CAPABILITY_VALID
    else:
        state = CAPABILITY_PARTIAL

    plan = SecurityAgentCapabilityPlan(
        rule_version=SECURITY_AGENT_CAPABILITY_RULE_VERSION,
        agent_category=resolved if resolved in CATEGORY_CAPABILITIES else (
            CATEGORY_UNKNOWN
        ),
        allowed_capabilities=list(allowed)[: len(ALLOWED_CAPABILITIES)],
        prohibited_capabilities=list(PROHIBITED_CAPABILITIES),
        capability_state=state,
        research_only=True,
    )
    return security_agent_capability_plan_projection(plan)


__all__ = [
    "SECURITY_AGENT_CAPABILITY_PLANNER_RULE_VERSION",
    "RULE_VERSION",
    "CATEGORY_CAPABILITIES",
    "plan_security_agent_capabilities",
]
