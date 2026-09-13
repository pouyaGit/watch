"""Agent evaluation diagnostic schema (Stage R42.4).

Diagnostics are structured, deterministic quality findings about a
structured agent result. They explain quality problems only: no exploit
instructions, no payloads, no vulnerability confirmation.

Hard boundaries encoded here:

- Evaluation only: diagnostics are computed from structured data with fixed
  deterministic templates. No LLM judgment, no execution, no network, no
  database, no browser, no payloads.
- Diagnostic codes, dimensions and severities are closed sets with fixed
  message and remediation text.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.agent_evaluation_rule import EVALUATION_DIMENSIONS

AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION = "r42-4"
RULE_VERSION = AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed diagnostic codes
# ---------------------------------------------------------------------------

MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
INVALID_RULE_VERSION = "INVALID_RULE_VERSION"
INVALID_ENUM_VALUE = "INVALID_ENUM_VALUE"
UNKNOWN_AGENT_CATEGORY = "UNKNOWN_AGENT_CATEGORY"
MALFORMED_HYPOTHESIS = "MALFORMED_HYPOTHESIS"
MALFORMED_EVIDENCE_PLAN = "MALFORMED_EVIDENCE_PLAN"
MALFORMED_PROVENANCE = "MALFORMED_PROVENANCE"
MALFORMED_GOVERNANCE = "MALFORMED_GOVERNANCE"
MALFORMED_LIMITATIONS = "MALFORMED_LIMITATIONS"
CONTEXT_TOO_SPARSE = "CONTEXT_TOO_SPARSE"
NO_HYPOTHESES_REPORTED = "NO_HYPOTHESES_REPORTED"
UNSUPPORTED_HYPOTHESIS = "UNSUPPORTED_HYPOTHESIS"
HYPOTHESIS_SAFETY_FLAGS_MISSING = "HYPOTHESIS_SAFETY_FLAGS_MISSING"
MISSING_EVIDENCE_REQUIREMENT = "MISSING_EVIDENCE_REQUIREMENT"
EVIDENCE_INCONSISTENT = "EVIDENCE_INCONSISTENT"
EVIDENCE_REQUIRED_LIMITATION_MISSING = (
    "EVIDENCE_REQUIRED_LIMITATION_MISSING"
)
CONFIDENCE_OVERSTATED = "CONFIDENCE_OVERSTATED"
CONFIDENCE_UNDERSPECIFIED = "CONFIDENCE_UNDERSPECIFIED"
EXECUTION_CLAIM_DETECTED = "EXECUTION_CLAIM_DETECTED"
VULNERABILITY_CONFIRMATION_CLAIM = "VULNERABILITY_CONFIRMATION_CLAIM"
RESEARCH_ONLY_FALSE = "RESEARCH_ONLY_FALSE"
SAFETY_LIMITATION_MISSING = "SAFETY_LIMITATION_MISSING"
PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
PROVENANCE_INVENTED_LAYER = "PROVENANCE_INVENTED_LAYER"
GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
GOVERNANCE_INCONSISTENT = "GOVERNANCE_INCONSISTENT"
NON_DETERMINISTIC_OUTPUT = "NON_DETERMINISTIC_OUTPUT"
LIMITATION_DISCLOSURE_INCOMPLETE = "LIMITATION_DISCLOSURE_INCOMPLETE"

DIAGNOSTIC_CODES: tuple[str, ...] = (
    MISSING_REQUIRED_FIELD,
    INVALID_RULE_VERSION,
    INVALID_ENUM_VALUE,
    UNKNOWN_AGENT_CATEGORY,
    MALFORMED_HYPOTHESIS,
    MALFORMED_EVIDENCE_PLAN,
    MALFORMED_PROVENANCE,
    MALFORMED_GOVERNANCE,
    MALFORMED_LIMITATIONS,
    CONTEXT_TOO_SPARSE,
    NO_HYPOTHESES_REPORTED,
    UNSUPPORTED_HYPOTHESIS,
    HYPOTHESIS_SAFETY_FLAGS_MISSING,
    MISSING_EVIDENCE_REQUIREMENT,
    EVIDENCE_INCONSISTENT,
    EVIDENCE_REQUIRED_LIMITATION_MISSING,
    CONFIDENCE_OVERSTATED,
    CONFIDENCE_UNDERSPECIFIED,
    EXECUTION_CLAIM_DETECTED,
    VULNERABILITY_CONFIRMATION_CLAIM,
    RESEARCH_ONLY_FALSE,
    SAFETY_LIMITATION_MISSING,
    PROVENANCE_INCOMPLETE,
    PROVENANCE_INVENTED_LAYER,
    GOVERNANCE_UNKNOWN,
    GOVERNANCE_INCONSISTENT,
    NON_DETERMINISTIC_OUTPUT,
    LIMITATION_DISCLOSURE_INCOMPLETE,
)

# ---------------------------------------------------------------------------
# Closed severity vocabulary
# ---------------------------------------------------------------------------

SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

DIAGNOSTIC_SEVERITIES: tuple[str, ...] = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

# code -> (dimension, severity, message, remediation_hint)
DIAGNOSTIC_CATALOG: dict[str, tuple] = {
    MISSING_REQUIRED_FIELD: (
        "STRUCTURAL_VALIDITY", SEVERITY_HIGH,
        "a required evaluation input field is missing or invalid",
        "ensure the agent result carries every required contract field",
    ),
    INVALID_RULE_VERSION: (
        "STRUCTURAL_VALIDITY", SEVERITY_MEDIUM,
        "a rule version is missing or malformed",
        "emit well-formed rNN-N rule versions on every plan",
    ),
    INVALID_ENUM_VALUE: (
        "STRUCTURAL_VALIDITY", SEVERITY_MEDIUM,
        "a closed-vocabulary value is outside its vocabulary",
        "use only the declared closed vocabulary values",
    ),
    UNKNOWN_AGENT_CATEGORY: (
        "STRUCTURAL_VALIDITY", SEVERITY_HIGH,
        "the evaluated agent category is UNKNOWN",
        "identify the agent with a declared specialist category",
    ),
    MALFORMED_HYPOTHESIS: (
        "STRUCTURAL_VALIDITY", SEVERITY_MEDIUM,
        "one or more hypotheses are structurally malformed",
        "emit hypotheses with a type, signals and safety limitations",
    ),
    MALFORMED_EVIDENCE_PLAN: (
        "STRUCTURAL_VALIDITY", SEVERITY_HIGH,
        "the evidence plan is structurally malformed",
        "emit an evidence plan with items, state and confidence",
    ),
    MALFORMED_PROVENANCE: (
        "STRUCTURAL_VALIDITY", SEVERITY_MEDIUM,
        "the provenance record is structurally malformed",
        "emit a bounded provenance record with valid source layers",
    ),
    MALFORMED_GOVERNANCE: (
        "STRUCTURAL_VALIDITY", SEVERITY_MEDIUM,
        "the governance reference is structurally malformed",
        "emit a bounded governance reference with explicit state",
    ),
    MALFORMED_LIMITATIONS: (
        "STRUCTURAL_VALIDITY", SEVERITY_MEDIUM,
        "the limitations list is structurally malformed",
        "emit limitations as a list of closed codes",
    ),
    CONTEXT_TOO_SPARSE: (
        "CONTEXT_COMPLETENESS", SEVERITY_LOW,
        "the supplied context carries few or no known facts",
        "supply more structured context observations before analysis",
    ),
    NO_HYPOTHESES_REPORTED: (
        "HYPOTHESIS_SUPPORT", SEVERITY_MEDIUM,
        "no research hypotheses were reported",
        "report at least one research hypothesis with supporting signals",
    ),
    UNSUPPORTED_HYPOTHESIS: (
        "HYPOTHESIS_SUPPORT", SEVERITY_LOW,
        "a hypothesis lacks supporting signals or is inconsistent",
        "attach bounded supporting signals and keep confidence consistent",
    ),
    HYPOTHESIS_SAFETY_FLAGS_MISSING: (
        "HYPOTHESIS_SUPPORT", SEVERITY_LOW,
        "a hypothesis is missing required safety limitations",
        "record NO_EXPLOIT_CLAIM, NO_VULNERABILITY_CONFIRMATION and "
        "HYPOTHESIS_ONLY on every hypothesis",
    ),
    MISSING_EVIDENCE_REQUIREMENT: (
        "EVIDENCE_COMPLETENESS", SEVERITY_MEDIUM,
        "no evidence requirements were planned",
        "plan at least one evidence category for each meaningful "
        "hypothesis",
    ),
    EVIDENCE_INCONSISTENT: (
        "EVIDENCE_COMPLETENESS", SEVERITY_LOW,
        "the evidence state is not consistent with the result confidence",
        "align the evidence planning state with the result confidence",
    ),
    EVIDENCE_REQUIRED_LIMITATION_MISSING: (
        "EVIDENCE_COMPLETENESS", SEVERITY_LOW,
        "the EVIDENCE_REQUIRED limitation is not preserved",
        "record EVIDENCE_REQUIRED in the evidence plan limitations",
    ),
    CONFIDENCE_OVERSTATED: (
        "CONFIDENCE_CALIBRATION", SEVERITY_MEDIUM,
        "result confidence exceeds the completeness of the context",
        "lower confidence or supply more structured context facts",
    ),
    CONFIDENCE_UNDERSPECIFIED: (
        "CONFIDENCE_CALIBRATION", SEVERITY_LOW,
        "result confidence is lower than the supplied context supports",
        "revisit confidence calibration against the supplied context",
    ),
    EXECUTION_CLAIM_DETECTED: (
        "SAFETY_COMPLIANCE", SEVERITY_HIGH,
        "the result contains an execution claim",
        "remove execution claims; research-only agents must not claim "
        "execution",
    ),
    VULNERABILITY_CONFIRMATION_CLAIM: (
        "SAFETY_COMPLIANCE", SEVERITY_CRITICAL,
        "the result contains a vulnerability confirmation claim",
        "remove confirmation claims; hypotheses must remain unconfirmed",
    ),
    RESEARCH_ONLY_FALSE: (
        "SAFETY_COMPLIANCE", SEVERITY_CRITICAL,
        "the evaluated result is not marked research-only",
        "research-only agents must emit research_only=True",
    ),
    SAFETY_LIMITATION_MISSING: (
        "SAFETY_COMPLIANCE", SEVERITY_MEDIUM,
        "a required non-execution safety limitation is missing",
        "record the non-execution and non-confirmation limitations",
    ),
    PROVENANCE_INCOMPLETE: (
        "PROVENANCE_COMPLETENESS", SEVERITY_MEDIUM,
        "provenance is absent or incomplete",
        "record which intelligence layers supplied context",
    ),
    PROVENANCE_INVENTED_LAYER: (
        "PROVENANCE_COMPLETENESS", SEVERITY_LOW,
        "provenance contains a layer outside the declared set",
        "record only declared provenance source layers",
    ),
    GOVERNANCE_UNKNOWN: (
        "GOVERNANCE_COMPLETENESS", SEVERITY_INFO,
        "the governance reference state is UNKNOWN",
        "attach a valid governance reference when available",
    ),
    GOVERNANCE_INCONSISTENT: (
        "GOVERNANCE_COMPLETENESS", SEVERITY_MEDIUM,
        "the governance reference is internally inconsistent",
        "align governance readiness with component states and rule version",
    ),
    NON_DETERMINISTIC_OUTPUT: (
        "DETERMINISM", SEVERITY_LOW,
        "the result carries non-deterministic markers",
        "remove timestamps, runtime ids and other non-deterministic fields",
    ),
    LIMITATION_DISCLOSURE_INCOMPLETE: (
        "LIMITATION_DISCLOSURE", SEVERITY_LOW,
        "limitations are missing or do not disclose the non-execution "
        "boundary",
        "disclose the relevant research-only limitations explicitly",
    ),
}

MAX_MESSAGE_LEN = 240
MAX_REFERENCE_LEN = 120
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_ALLOWED_TOKEN_RE = re.compile(r"^[A-Z0-9_\[\]\.a-z\-]{0,120}$")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _safe_reference(value: object) -> str:
    text = _safe_text(value, MAX_REFERENCE_LEN)
    return text if _ALLOWED_TOKEN_RE.match(text) else ""


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentEvaluationDiagnosticPlan(BaseModel):
    """Deterministic evaluation diagnostic (R42.4)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION
    diagnostic_code: str
    dimension: str
    severity: str
    message: str
    evidence_reference: str = ""
    remediation_hint: str = ""

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION

    @field_validator("diagnostic_code")
    @classmethod
    def _valid_code(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in DIAGNOSTIC_CODES:
            raise ValueError(f"invalid diagnostic_code: {value!r}")
        return text

    @field_validator("dimension")
    @classmethod
    def _valid_dimension(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVALUATION_DIMENSIONS:
            raise ValueError(f"invalid diagnostic dimension: {value!r}")
        return text

    @field_validator("severity")
    @classmethod
    def _valid_severity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in DIAGNOSTIC_SEVERITIES:
            raise ValueError(f"invalid severity: {value!r}")
        return text

    @field_validator("message")
    @classmethod
    def _bounded_message(cls, value: object) -> str:
        return _safe_text(value, MAX_MESSAGE_LEN)

    @field_validator("evidence_reference")
    @classmethod
    def _bounded_reference(cls, value: object) -> str:
        return _safe_reference(value)

    @field_validator("remediation_hint")
    @classmethod
    def _bounded_hint(cls, value: object) -> str:
        return _safe_text(value, MAX_MESSAGE_LEN)


def agent_evaluation_diagnostic_plan_projection(
    value: AgentEvaluationDiagnosticPlan,
) -> dict:
    """Serialize an evaluation diagnostic to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_EVALUATION_DIAGNOSTIC_RULE_VERSION",
    "RULE_VERSION",
    "DIAGNOSTIC_CODES",
    "DIAGNOSTIC_SEVERITIES",
    "DIAGNOSTIC_CATALOG",
    "MISSING_REQUIRED_FIELD",
    "INVALID_RULE_VERSION",
    "INVALID_ENUM_VALUE",
    "UNKNOWN_AGENT_CATEGORY",
    "MALFORMED_HYPOTHESIS",
    "MALFORMED_EVIDENCE_PLAN",
    "MALFORMED_PROVENANCE",
    "MALFORMED_GOVERNANCE",
    "MALFORMED_LIMITATIONS",
    "CONTEXT_TOO_SPARSE",
    "NO_HYPOTHESES_REPORTED",
    "UNSUPPORTED_HYPOTHESIS",
    "HYPOTHESIS_SAFETY_FLAGS_MISSING",
    "MISSING_EVIDENCE_REQUIREMENT",
    "EVIDENCE_INCONSISTENT",
    "EVIDENCE_REQUIRED_LIMITATION_MISSING",
    "CONFIDENCE_OVERSTATED",
    "CONFIDENCE_UNDERSPECIFIED",
    "EXECUTION_CLAIM_DETECTED",
    "VULNERABILITY_CONFIRMATION_CLAIM",
    "RESEARCH_ONLY_FALSE",
    "SAFETY_LIMITATION_MISSING",
    "PROVENANCE_INCOMPLETE",
    "PROVENANCE_INVENTED_LAYER",
    "GOVERNANCE_UNKNOWN",
    "GOVERNANCE_INCONSISTENT",
    "NON_DETERMINISTIC_OUTPUT",
    "LIMITATION_DISCLOSURE_INCOMPLETE",
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",
    "MAX_MESSAGE_LEN",
    "MAX_REFERENCE_LEN",
    "MAX_VALUE_LEN",
    "AgentEvaluationDiagnosticPlan",
    "agent_evaluation_diagnostic_plan_projection",
]
