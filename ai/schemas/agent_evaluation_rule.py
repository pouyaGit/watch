"""Agent evaluation rule schema (Stage R42.2).

Closed vocabulary for the deterministic evaluation rules and the
per-dimension outcome of those rules.

Hard boundaries encoded here:

- Evaluation only: rules operate exclusively on structured, already-produced
  agent result data. No execution, no network, no SQL, no database, no
  browser, no LLM judgment, no payloads, no exploit verification.
- Dimensions and rule codes are closed sets; malformed outcomes are
  rejected by pydantic validation.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

AGENT_EVALUATION_RULE_RULE_VERSION = "r42-2"
RULE_VERSION = AGENT_EVALUATION_RULE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed dimension vocabulary
# ---------------------------------------------------------------------------

DIMENSION_STRUCTURAL_VALIDITY = "STRUCTURAL_VALIDITY"
DIMENSION_CONTEXT_COMPLETENESS = "CONTEXT_COMPLETENESS"
DIMENSION_HYPOTHESIS_SUPPORT = "HYPOTHESIS_SUPPORT"
DIMENSION_EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"
DIMENSION_CONFIDENCE_CALIBRATION = "CONFIDENCE_CALIBRATION"
DIMENSION_SAFETY_COMPLIANCE = "SAFETY_COMPLIANCE"
DIMENSION_PROVENANCE_COMPLETENESS = "PROVENANCE_COMPLETENESS"
DIMENSION_GOVERNANCE_COMPLETENESS = "GOVERNANCE_COMPLETENESS"
DIMENSION_DETERMINISM = "DETERMINISM"
DIMENSION_LIMITATION_DISCLOSURE = "LIMITATION_DISCLOSURE"

EVALUATION_DIMENSIONS: tuple[str, ...] = (
    DIMENSION_STRUCTURAL_VALIDITY,
    DIMENSION_CONTEXT_COMPLETENESS,
    DIMENSION_HYPOTHESIS_SUPPORT,
    DIMENSION_EVIDENCE_COMPLETENESS,
    DIMENSION_CONFIDENCE_CALIBRATION,
    DIMENSION_SAFETY_COMPLIANCE,
    DIMENSION_PROVENANCE_COMPLETENESS,
    DIMENSION_GOVERNANCE_COMPLETENESS,
    DIMENSION_DETERMINISM,
    DIMENSION_LIMITATION_DISCLOSURE,
)

# ---------------------------------------------------------------------------
# Closed rule-code vocabulary
# ---------------------------------------------------------------------------

RULE_REQUIRED_FIELDS_PRESENT = "REQUIRED_FIELDS_PRESENT"
RULE_RULE_VERSIONS_VALID = "RULE_VERSIONS_VALID"
RULE_ENUM_VALUES_VALID = "ENUM_VALUES_VALID"
RULE_AGENT_CATEGORY_KNOWN = "AGENT_CATEGORY_KNOWN"
RULE_HYPOTHESES_STRUCTURALLY_VALID = "HYPOTHESES_STRUCTURALLY_VALID"
RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID = "EVIDENCE_PLAN_STRUCTURALLY_VALID"
RULE_PROVENANCE_STRUCTURALLY_VALID = "PROVENANCE_STRUCTURALLY_VALID"
RULE_GOVERNANCE_STRUCTURALLY_VALID = "GOVERNANCE_STRUCTURALLY_VALID"
RULE_LIMITATIONS_STRUCTURALLY_VALID = "LIMITATIONS_STRUCTURALLY_VALID"

RULE_CONTEXT_PRESENT = "CONTEXT_PRESENT"
RULE_CONTEXT_FACTS_SUFFICIENT = "CONTEXT_FACTS_SUFFICIENT"

RULE_HYPOTHESES_PRESENT = "HYPOTHESES_PRESENT"
RULE_SIGNALS_PRESENT = "SIGNALS_PRESENT"
RULE_TYPE_CONFIDENCE_CONSISTENT = "TYPE_CONFIDENCE_CONSISTENT"
RULE_HYPOTHESIS_SAFETY_FLAGS = "HYPOTHESIS_SAFETY_FLAGS"

RULE_EVIDENCE_ITEMS_PRESENT = "EVIDENCE_ITEMS_PRESENT"
RULE_EVIDENCE_REQUIRED_PRESERVED = "EVIDENCE_REQUIRED_PRESERVED"
RULE_EVIDENCE_STATE_CONSISTENT = "EVIDENCE_STATE_CONSISTENT"

RULE_CONFIDENCE_MATCHES_CONTEXT = "CONFIDENCE_MATCHES_CONTEXT"

RULE_RESEARCH_ONLY = "RESEARCH_ONLY"
RULE_SAFETY_LIMITATIONS_PRESENT = "SAFETY_LIMITATIONS_PRESENT"
RULE_NO_EXECUTION_CLAIMS = "NO_EXECUTION_CLAIMS"
RULE_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"

RULE_PROVENANCE_PRESENT = "PROVENANCE_PRESENT"
RULE_PROVENANCE_STATE_CONSISTENT = "PROVENANCE_STATE_CONSISTENT"
RULE_PROVENANCE_LAYERS_VALID = "PROVENANCE_LAYERS_VALID"

RULE_GOVERNANCE_PRESENT = "GOVERNANCE_PRESENT"
RULE_GOVERNANCE_STATE_VISIBLE = "GOVERNANCE_STATE_VISIBLE"
RULE_GOVERNANCE_CONSISTENT = "GOVERNANCE_CONSISTENT"

RULE_OUTPUT_DETERMINISTIC = "OUTPUT_DETERMINISTIC"

RULE_LIMITATIONS_PRESENT = "LIMITATIONS_PRESENT"
RULE_NON_EXECUTION_DISCLOSED = "NON_EXECUTION_DISCLOSED"

EVALUATION_RULES: tuple[str, ...] = (
    RULE_REQUIRED_FIELDS_PRESENT,
    RULE_RULE_VERSIONS_VALID,
    RULE_ENUM_VALUES_VALID,
    RULE_AGENT_CATEGORY_KNOWN,
    RULE_HYPOTHESES_STRUCTURALLY_VALID,
    RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID,
    RULE_PROVENANCE_STRUCTURALLY_VALID,
    RULE_GOVERNANCE_STRUCTURALLY_VALID,
    RULE_LIMITATIONS_STRUCTURALLY_VALID,
    RULE_CONTEXT_PRESENT,
    RULE_CONTEXT_FACTS_SUFFICIENT,
    RULE_HYPOTHESES_PRESENT,
    RULE_SIGNALS_PRESENT,
    RULE_TYPE_CONFIDENCE_CONSISTENT,
    RULE_HYPOTHESIS_SAFETY_FLAGS,
    RULE_EVIDENCE_ITEMS_PRESENT,
    RULE_EVIDENCE_REQUIRED_PRESERVED,
    RULE_EVIDENCE_STATE_CONSISTENT,
    RULE_CONFIDENCE_MATCHES_CONTEXT,
    RULE_RESEARCH_ONLY,
    RULE_SAFETY_LIMITATIONS_PRESENT,
    RULE_NO_EXECUTION_CLAIMS,
    RULE_NO_VULNERABILITY_CONFIRMATION,
    RULE_PROVENANCE_PRESENT,
    RULE_PROVENANCE_STATE_CONSISTENT,
    RULE_PROVENANCE_LAYERS_VALID,
    RULE_GOVERNANCE_PRESENT,
    RULE_GOVERNANCE_STATE_VISIBLE,
    RULE_GOVERNANCE_CONSISTENT,
    RULE_OUTPUT_DETERMINISTIC,
    RULE_LIMITATIONS_PRESENT,
    RULE_NON_EXECUTION_DISCLOSED,
)

MAX_REASONS = 8
MAX_RULES = 32
MAX_REFERENCE_LEN = 120
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _bounded_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_codes(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in allowed:
            raise ValueError(f"invalid closed code: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AgentEvaluationDimensionOutcome(BaseModel):
    """Deterministic outcome of the rules for one evaluation dimension."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = AGENT_EVALUATION_RULE_RULE_VERSION
    dimension: str
    score: int
    passed_rules: list[str] = Field(default_factory=list)
    failed_rules: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    diagnostics: list[dict] = Field(default_factory=list)

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return AGENT_EVALUATION_RULE_RULE_VERSION

    @field_validator("dimension")
    @classmethod
    def _valid_dimension(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVALUATION_DIMENSIONS:
            raise ValueError(f"invalid evaluation dimension: {value!r}")
        return text

    @field_validator("score")
    @classmethod
    def _valid_score(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid dimension score: {value!r}")
        if value < 0 or value > 100:
            raise ValueError(f"dimension score out of range: {value!r}")
        return value

    @field_validator("passed_rules", "failed_rules")
    @classmethod
    def _valid_rules(cls, value: list) -> list[str]:
        return _require_codes(value, EVALUATION_RULES, MAX_RULES)

    @field_validator("reasons")
    @classmethod
    def _valid_reasons(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item)
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_REASONS:
                break
        return out

    @field_validator("diagnostics")
    @classmethod
    def _valid_diagnostics(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if not isinstance(item, dict):
                continue
            code = _safe_text(item.get("diagnostic_code"))
            reference = _safe_text(
                item.get("evidence_reference"), MAX_REFERENCE_LEN
            )
            if code:
                out.append(
                    {
                        "diagnostic_code": code,
                        "evidence_reference": reference,
                    }
                )
            if len(out) >= MAX_REASONS:
                break
        return out


def agent_evaluation_dimension_outcome_projection(
    value: AgentEvaluationDimensionOutcome,
) -> dict:
    """Serialize a dimension outcome to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "AGENT_EVALUATION_RULE_RULE_VERSION",
    "RULE_VERSION",
    "DIMENSION_STRUCTURAL_VALIDITY",
    "DIMENSION_CONTEXT_COMPLETENESS",
    "DIMENSION_HYPOTHESIS_SUPPORT",
    "DIMENSION_EVIDENCE_COMPLETENESS",
    "DIMENSION_CONFIDENCE_CALIBRATION",
    "DIMENSION_SAFETY_COMPLIANCE",
    "DIMENSION_PROVENANCE_COMPLETENESS",
    "DIMENSION_GOVERNANCE_COMPLETENESS",
    "DIMENSION_DETERMINISM",
    "DIMENSION_LIMITATION_DISCLOSURE",
    "EVALUATION_DIMENSIONS",
    "EVALUATION_RULES",
    "RULE_REQUIRED_FIELDS_PRESENT",
    "RULE_RULE_VERSIONS_VALID",
    "RULE_ENUM_VALUES_VALID",
    "RULE_AGENT_CATEGORY_KNOWN",
    "RULE_HYPOTHESES_STRUCTURALLY_VALID",
    "RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID",
    "RULE_PROVENANCE_STRUCTURALLY_VALID",
    "RULE_GOVERNANCE_STRUCTURALLY_VALID",
    "RULE_LIMITATIONS_STRUCTURALLY_VALID",
    "RULE_CONTEXT_PRESENT",
    "RULE_CONTEXT_FACTS_SUFFICIENT",
    "RULE_HYPOTHESES_PRESENT",
    "RULE_SIGNALS_PRESENT",
    "RULE_TYPE_CONFIDENCE_CONSISTENT",
    "RULE_HYPOTHESIS_SAFETY_FLAGS",
    "RULE_EVIDENCE_ITEMS_PRESENT",
    "RULE_EVIDENCE_REQUIRED_PRESERVED",
    "RULE_EVIDENCE_STATE_CONSISTENT",
    "RULE_CONFIDENCE_MATCHES_CONTEXT",
    "RULE_RESEARCH_ONLY",
    "RULE_SAFETY_LIMITATIONS_PRESENT",
    "RULE_NO_EXECUTION_CLAIMS",
    "RULE_NO_VULNERABILITY_CONFIRMATION",
    "RULE_PROVENANCE_PRESENT",
    "RULE_PROVENANCE_STATE_CONSISTENT",
    "RULE_PROVENANCE_LAYERS_VALID",
    "RULE_GOVERNANCE_PRESENT",
    "RULE_GOVERNANCE_STATE_VISIBLE",
    "RULE_GOVERNANCE_CONSISTENT",
    "RULE_OUTPUT_DETERMINISTIC",
    "RULE_LIMITATIONS_PRESENT",
    "RULE_NON_EXECUTION_DISCLOSED",
    "MAX_REASONS",
    "MAX_RULES",
    "MAX_REFERENCE_LEN",
    "MAX_VALUE_LEN",
    "AgentEvaluationDimensionOutcome",
    "agent_evaluation_dimension_outcome_projection",
]
