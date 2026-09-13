"""SQLi hypothesis schema (Stage R41.3).

A :class:`SQLIHypothesisPlan` is a deterministic research hypothesis about
possible SQL-injection-relevant behavior. It answers the research question:

    "Which SQLi review hypothesis follows from the observed context?"

Hard boundaries encoded here:

- Research hypothesis only: no exploit claim, no vulnerability confirmation,
  no SQL payload, no executable injection string, no database command, no
  exploitation instruction, no SQL/database/network execution.
- Closed vocabularies: hypothesis type, supporting signals, confidence,
  priority and limitations are closed sets.
- Confidence and priority reuse the shared evidence-confidence vocabulary.
- Bounded, privacy-safe, JSON serializable.

No I/O, no SQL, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SQLI_HYPOTHESIS_RULE_VERSION = "r41-3"
RULE_VERSION = SQLI_HYPOTHESIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

TYPE_QUERY_CONSTRUCTION_REVIEW = "QUERY_CONSTRUCTION_REVIEW"
TYPE_PARAMETERIZATION_REVIEW = "PARAMETERIZATION_REVIEW"
TYPE_INPUT_HANDLING_REVIEW = "INPUT_HANDLING_REVIEW"
TYPE_TYPE_HANDLING_REVIEW = "TYPE_HANDLING_REVIEW"
TYPE_ORM_QUERY_REVIEW = "ORM_QUERY_REVIEW"
TYPE_RAW_QUERY_REVIEW = "RAW_QUERY_REVIEW"
TYPE_ERROR_SIGNAL_REVIEW = "ERROR_SIGNAL_REVIEW"
TYPE_BOOLEAN_DIFFERENTIAL_REVIEW = "BOOLEAN_DIFFERENTIAL_REVIEW"
TYPE_TIMING_SIGNAL_REVIEW = "TIMING_SIGNAL_REVIEW"
TYPE_ORDER_BY_INJECTION_REVIEW = "ORDER_BY_INJECTION_REVIEW"
TYPE_IDENTIFIER_HANDLING_REVIEW = "IDENTIFIER_HANDLING_REVIEW"
TYPE_STORED_PROCEDURE_REVIEW = "STORED_PROCEDURE_REVIEW"
TYPE_DATABASE_SPECIFIC_REVIEW = "DATABASE_SPECIFIC_REVIEW"
TYPE_UNKNOWN = "UNKNOWN"

HYPOTHESIS_TYPES: tuple[str, ...] = (
    TYPE_QUERY_CONSTRUCTION_REVIEW,
    TYPE_PARAMETERIZATION_REVIEW,
    TYPE_INPUT_HANDLING_REVIEW,
    TYPE_TYPE_HANDLING_REVIEW,
    TYPE_ORM_QUERY_REVIEW,
    TYPE_RAW_QUERY_REVIEW,
    TYPE_ERROR_SIGNAL_REVIEW,
    TYPE_BOOLEAN_DIFFERENTIAL_REVIEW,
    TYPE_TIMING_SIGNAL_REVIEW,
    TYPE_ORDER_BY_INJECTION_REVIEW,
    TYPE_IDENTIFIER_HANDLING_REVIEW,
    TYPE_STORED_PROCEDURE_REVIEW,
    TYPE_DATABASE_SPECIFIC_REVIEW,
    TYPE_UNKNOWN,
)

SIGNAL_INPUT_QUERY = "INPUT_QUERY"
SIGNAL_INPUT_BODY = "INPUT_BODY"
SIGNAL_INPUT_HEADER = "INPUT_HEADER"
SIGNAL_INPUT_COOKIE = "INPUT_COOKIE"
SIGNAL_INPUT_PATH = "INPUT_PATH"
SIGNAL_PARAM_STRING = "PARAM_STRING"
SIGNAL_PARAM_INTEGER = "PARAM_INTEGER"
SIGNAL_PARAM_BOOLEAN = "PARAM_BOOLEAN"
SIGNAL_PARAM_SORT = "PARAM_SORT"
SIGNAL_PARAM_FILTER = "PARAM_FILTER"
SIGNAL_PARAM_SEARCH = "PARAM_SEARCH"
SIGNAL_PARAM_IDENTIFIER = "PARAM_IDENTIFIER"
SIGNAL_FLOW_DIRECT_QUERY = "FLOW_DIRECT_QUERY"
SIGNAL_FLOW_QUERY_BUILDER = "FLOW_QUERY_BUILDER"
SIGNAL_FLOW_ORM = "FLOW_ORM"
SIGNAL_FLOW_STORED_PROCEDURE = "FLOW_STORED_PROCEDURE"
SIGNAL_FLOW_RAW_QUERY = "FLOW_RAW_QUERY"
SIGNAL_QUERY_WHERE = "QUERY_WHERE"
SIGNAL_QUERY_ORDER_BY = "QUERY_ORDER_BY"
SIGNAL_QUERY_LIMIT = "QUERY_LIMIT"
SIGNAL_QUERY_OFFSET = "QUERY_OFFSET"
SIGNAL_QUERY_SELECT = "QUERY_SELECT"
SIGNAL_QUERY_INSERT = "QUERY_INSERT"
SIGNAL_QUERY_UPDATE = "QUERY_UPDATE"
SIGNAL_QUERY_DELETE = "QUERY_DELETE"
SIGNAL_DB_MYSQL = "DB_MYSQL"
SIGNAL_DB_POSTGRESQL = "DB_POSTGRESQL"
SIGNAL_DB_MSSQL = "DB_MSSQL"
SIGNAL_DB_SQLITE = "DB_SQLITE"
SIGNAL_DB_ORACLE = "DB_ORACLE"
SIGNAL_HANDLING_PARAMETERIZED = "HANDLING_PARAMETERIZED"
SIGNAL_HANDLING_SANITIZED = "HANDLING_SANITIZED"
SIGNAL_HANDLING_ESCAPED = "HANDLING_ESCAPED"
SIGNAL_HANDLING_CONCATENATED = "HANDLING_CONCATENATED"
SIGNAL_HANDLING_RAW = "HANDLING_RAW"
SIGNAL_TYPE_STRONG = "TYPE_STRONG"
SIGNAL_TYPE_WEAK = "TYPE_WEAK"
SIGNAL_TYPE_CAST = "TYPE_CAST"
SIGNAL_TYPE_NONE_OBSERVED = "TYPE_NONE_OBSERVED"
SIGNAL_ERROR_DATABASE_OBSERVED = "ERROR_DATABASE_OBSERVED"
SIGNAL_ERROR_APPLICATION_ONLY = "ERROR_APPLICATION_ONLY"
SIGNAL_ERROR_NONE_OBSERVED = "ERROR_NONE_OBSERVED"
SIGNAL_BEHAVIOR_DIFFERENTIAL = "BEHAVIOR_DIFFERENTIAL"
SIGNAL_BEHAVIOR_TIMING_RELEVANT = "BEHAVIOR_TIMING_RELEVANT"
SIGNAL_BEHAVIOR_BOOLEAN_RELEVANT = "BEHAVIOR_BOOLEAN_RELEVANT"
SIGNAL_BEHAVIOR_NONE_OBSERVED = "BEHAVIOR_NONE_OBSERVED"
SIGNAL_CONTEXT_UNKNOWN = "CONTEXT_UNKNOWN"

SQLI_SIGNALS: tuple[str, ...] = (
    SIGNAL_INPUT_QUERY,
    SIGNAL_INPUT_BODY,
    SIGNAL_INPUT_HEADER,
    SIGNAL_INPUT_COOKIE,
    SIGNAL_INPUT_PATH,
    SIGNAL_PARAM_STRING,
    SIGNAL_PARAM_INTEGER,
    SIGNAL_PARAM_BOOLEAN,
    SIGNAL_PARAM_SORT,
    SIGNAL_PARAM_FILTER,
    SIGNAL_PARAM_SEARCH,
    SIGNAL_PARAM_IDENTIFIER,
    SIGNAL_FLOW_DIRECT_QUERY,
    SIGNAL_FLOW_QUERY_BUILDER,
    SIGNAL_FLOW_ORM,
    SIGNAL_FLOW_STORED_PROCEDURE,
    SIGNAL_FLOW_RAW_QUERY,
    SIGNAL_QUERY_WHERE,
    SIGNAL_QUERY_ORDER_BY,
    SIGNAL_QUERY_LIMIT,
    SIGNAL_QUERY_OFFSET,
    SIGNAL_QUERY_SELECT,
    SIGNAL_QUERY_INSERT,
    SIGNAL_QUERY_UPDATE,
    SIGNAL_QUERY_DELETE,
    SIGNAL_DB_MYSQL,
    SIGNAL_DB_POSTGRESQL,
    SIGNAL_DB_MSSQL,
    SIGNAL_DB_SQLITE,
    SIGNAL_DB_ORACLE,
    SIGNAL_HANDLING_PARAMETERIZED,
    SIGNAL_HANDLING_SANITIZED,
    SIGNAL_HANDLING_ESCAPED,
    SIGNAL_HANDLING_CONCATENATED,
    SIGNAL_HANDLING_RAW,
    SIGNAL_TYPE_STRONG,
    SIGNAL_TYPE_WEAK,
    SIGNAL_TYPE_CAST,
    SIGNAL_TYPE_NONE_OBSERVED,
    SIGNAL_ERROR_DATABASE_OBSERVED,
    SIGNAL_ERROR_APPLICATION_ONLY,
    SIGNAL_ERROR_NONE_OBSERVED,
    SIGNAL_BEHAVIOR_DIFFERENTIAL,
    SIGNAL_BEHAVIOR_TIMING_RELEVANT,
    SIGNAL_BEHAVIOR_BOOLEAN_RELEVANT,
    SIGNAL_BEHAVIOR_NONE_OBSERVED,
    SIGNAL_CONTEXT_UNKNOWN,
)

LIMITATION_NO_EXPLOIT_CLAIM = "NO_EXPLOIT_CLAIM"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_HYPOTHESIS_ONLY = "HYPOTHESIS_ONLY"
LIMITATION_EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"

SQLI_HYPOTHESIS_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXPLOIT_CLAIM,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_HYPOTHESIS_ONLY,
    LIMITATION_EVIDENCE_REQUIRED,
    LIMITATION_INSUFFICIENT_CONTEXT,
)

MAX_SIGNALS = 8
MAX_LIMITATIONS = 5
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


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


def sanitize_sqli_hypothesis_plan(value: object) -> dict:
    """Project an R41.3 hypothesis onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "hypothesis_type": TYPE_UNKNOWN,
            "supporting_signals": [],
            "confidence": "UNKNOWN",
            "priority": "UNKNOWN",
            "limitations": [],
            "research_only": True,
        }
    hypothesis_type = _safe_text(
        value.get("hypothesis_type")
    ).strip().upper()
    if hypothesis_type not in HYPOTHESIS_TYPES:
        hypothesis_type = TYPE_UNKNOWN
    confidence = _safe_text(value.get("confidence")).strip().upper()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "UNKNOWN"
    priority = _safe_text(value.get("priority")).strip().upper()
    if priority not in CONFIDENCE_LEVELS:
        priority = "UNKNOWN"
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "hypothesis_type": hypothesis_type,
        "supporting_signals": [
            signal
            for signal in (
                _safe_text(item) for item in value.get("supporting_signals")
                or ()
            )
            if signal in SQLI_SIGNALS
        ][:MAX_SIGNALS],
        "confidence": confidence,
        "priority": priority,
        "limitations": [
            code
            for code in (
                _safe_text(item) for item in value.get("limitations") or ()
            )
            if code in SQLI_HYPOTHESIS_LIMITATIONS
        ][:MAX_LIMITATIONS],
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SQLIHypothesisPlan(BaseModel):
    """Deterministic research-only SQLi hypothesis (R41.3)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SQLI_HYPOTHESIS_RULE_VERSION
    hypothesis_type: str
    supporting_signals: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    priority: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SQLI_HYPOTHESIS_RULE_VERSION

    @field_validator("hypothesis_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {value!r}")
        return text

    @field_validator("supporting_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_codes(value, SQLI_SIGNALS, MAX_SIGNALS)

    @field_validator("confidence", "priority")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence/priority: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _require_codes(
            value, SQLI_HYPOTHESIS_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("sqli hypotheses are research-only")
        return True


def sqli_hypothesis_plan_projection(value: SQLIHypothesisPlan) -> dict:
    """Serialize a SQLi hypothesis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SQLI_HYPOTHESIS_RULE_VERSION",
    "RULE_VERSION",
    "TYPE_QUERY_CONSTRUCTION_REVIEW",
    "TYPE_PARAMETERIZATION_REVIEW",
    "TYPE_INPUT_HANDLING_REVIEW",
    "TYPE_TYPE_HANDLING_REVIEW",
    "TYPE_ORM_QUERY_REVIEW",
    "TYPE_RAW_QUERY_REVIEW",
    "TYPE_ERROR_SIGNAL_REVIEW",
    "TYPE_BOOLEAN_DIFFERENTIAL_REVIEW",
    "TYPE_TIMING_SIGNAL_REVIEW",
    "TYPE_ORDER_BY_INJECTION_REVIEW",
    "TYPE_IDENTIFIER_HANDLING_REVIEW",
    "TYPE_STORED_PROCEDURE_REVIEW",
    "TYPE_DATABASE_SPECIFIC_REVIEW",
    "TYPE_UNKNOWN",
    "HYPOTHESIS_TYPES",
    "SQLI_SIGNALS",
    "LIMITATION_NO_EXPLOIT_CLAIM",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_HYPOTHESIS_ONLY",
    "LIMITATION_EVIDENCE_REQUIRED",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "SQLI_HYPOTHESIS_LIMITATIONS",
    "MAX_SIGNALS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_sqli_hypothesis_plan",
    "SQLIHypothesisPlan",
    "sqli_hypothesis_plan_projection",
]
