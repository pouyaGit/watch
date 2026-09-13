"""Stage R38.5 deterministic security agent result validator (pure engine).

Normalizes and validates the standard descriptive result contract for future
security specialist agents:

    "What did this agent conceptually conclude, and within which bounded
     limitations?"

Hard boundaries encoded here:

- Framework/model only: results are descriptive research summaries. There
  are no exploit outputs, no payload storage, no execution logs, no tool or
  runtime activity.
- No overclaiming: unknown results force UNKNOWN confidence/findings; failed
  results downgrade HIGH/MEDIUM confidence and suppress findings; created/
  analyzing results suppress findings (nothing concluded yet).
- Pure and offline; deterministic; read-only inputs.
"""

from __future__ import annotations

from ai.schemas.evidence_confidence import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)
from ai.schemas.security_agent_result import (
    AGENT_RESULT_STATUSES,
    EVIDENCE_SUMMARIES,
    EVIDENCE_UNKNOWN,
    FINDINGS_NONE,
    FINDINGS_SUMMARIES,
    FINDINGS_UNKNOWN,
    LIMITATION_CONFIDENCE_DOWNGRADED,
    LIMITATION_FINDINGS_SUPPRESSED,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_RESULT_UNKNOWN,
    SECURITY_AGENT_RESULT_RULE_VERSION,
    STATUS_ANALYZING,
    STATUS_COMPLETED,
    STATUS_CREATED,
    STATUS_FAILED,
    STATUS_UNKNOWN,
    SecurityAgentResultPlan,
    security_agent_result_plan_projection,
)

SECURITY_AGENT_RESULT_VALIDATOR_RULE_VERSION = "r38-5"
RULE_VERSION = SECURITY_AGENT_RESULT_VALIDATOR_RULE_VERSION


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def validate_security_agent_result(
    agent_name: object = None,
    status: object = None,
    confidence: object = None,
    findings_summary: object = None,
    evidence_summary: object = None,
    limitations: object = None,
) -> dict:
    """Normalize the deterministic descriptive agent result (read-only).

    Closed inputs outside their vocabularies resolve to ``UNKNOWN``. Unknown
    results force UNKNOWN confidence/findings; failed results downgrade
    HIGH/MEDIUM confidence to LOW and suppress findings; created/analyzing
    results suppress findings. Every result explicitly records that no
    execution was performed.
    """

    resolved_status = _upper(status)
    if resolved_status not in AGENT_RESULT_STATUSES:
        resolved_status = STATUS_UNKNOWN

    resolved_confidence = _upper(confidence)
    if resolved_confidence not in CONFIDENCE_LEVELS:
        resolved_confidence = CONFIDENCE_UNKNOWN

    resolved_findings = _upper(findings_summary)
    if resolved_findings not in FINDINGS_SUMMARIES:
        resolved_findings = FINDINGS_UNKNOWN

    resolved_evidence = _upper(evidence_summary)
    if resolved_evidence not in EVIDENCE_SUMMARIES:
        resolved_evidence = EVIDENCE_UNKNOWN

    codes: list[str] = [LIMITATION_NO_EXECUTION_PERFORMED]
    if resolved_status == STATUS_UNKNOWN:
        resolved_confidence = CONFIDENCE_UNKNOWN
        resolved_findings = FINDINGS_UNKNOWN
        resolved_evidence = EVIDENCE_UNKNOWN
        codes.append(LIMITATION_RESULT_UNKNOWN)
    elif resolved_status == STATUS_FAILED:
        if resolved_confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM):
            resolved_confidence = CONFIDENCE_LOW
            codes.append(LIMITATION_CONFIDENCE_DOWNGRADED)
        resolved_findings = FINDINGS_NONE
        codes.append(LIMITATION_FINDINGS_SUPPRESSED)
    elif resolved_status in (STATUS_CREATED, STATUS_ANALYZING):
        resolved_findings = FINDINGS_NONE
        codes.append(LIMITATION_FINDINGS_SUPPRESSED)

    for extra in limitations or ():
        code = _upper(extra)
        if code in (
            LIMITATION_RESULT_UNKNOWN,
            LIMITATION_CONFIDENCE_DOWNGRADED,
            LIMITATION_FINDINGS_SUPPRESSED,
            LIMITATION_NO_EXECUTION_PERFORMED,
        ) and code not in codes:
            codes.append(code)

    plan = SecurityAgentResultPlan(
        rule_version=SECURITY_AGENT_RESULT_RULE_VERSION,
        agent_name=_text(agent_name),
        status=resolved_status,
        confidence=resolved_confidence,
        findings_summary=resolved_findings,
        evidence_summary=resolved_evidence,
        limitations=codes,
        research_only=True,
    )
    return security_agent_result_plan_projection(plan)


__all__ = [
    "SECURITY_AGENT_RESULT_VALIDATOR_RULE_VERSION",
    "RULE_VERSION",
    "validate_security_agent_result",
]
