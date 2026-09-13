"""SQLi context analysis schema (Stage R41.2).

An :class:`SQLIContextAnalysisPlan` is the deterministic, descriptive
classification of SQL-injection-relevant research context. It answers the
research question:

    "Is there SQLi-relevant input, and was unsafe query construction
     evidence observed?"

Hard boundaries encoded here:

- Research intelligence only: no SQL execution, no database connection, no
  HTTP/network request, no payload, no fuzzing, no parameter brute forcing,
  no browser, no socket, no subprocess, no sqlmap. Nothing is performed.
- A parameter, a search box, a database or an ORM is NOT evidence of SQLi:
  the model explicitly separates ``SQLi-relevant input`` from observed
  unsafe query construction evidence, and confidence is capped unless
  construction evidence is present.
- Closed vocabularies: every classification field is a closed set; unknown
  and malformed values remain ``UNKNOWN`` and are never promoted.
- Bounded, privacy-safe, JSON serializable.

No I/O, no SQL, no network, no LLM, no Mongo, no execution of any kind is
represented here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS

SQLI_CONTEXT_ANALYSIS_RULE_VERSION = "r41-2"
RULE_VERSION = SQLI_CONTEXT_ANALYSIS_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

INPUT_QUERY = "QUERY"
INPUT_BODY = "BODY"
INPUT_HEADER = "HEADER"
INPUT_COOKIE = "COOKIE"
INPUT_PATH = "PATH"
INPUT_UNKNOWN = "UNKNOWN"

INPUT_LOCATIONS: tuple[str, ...] = (
    INPUT_QUERY,
    INPUT_BODY,
    INPUT_HEADER,
    INPUT_COOKIE,
    INPUT_PATH,
    INPUT_UNKNOWN,
)

PARAM_STRING = "STRING"
PARAM_INTEGER = "INTEGER"
PARAM_BOOLEAN = "BOOLEAN"
PARAM_SORT = "SORT"
PARAM_FILTER = "FILTER"
PARAM_SEARCH = "SEARCH"
PARAM_IDENTIFIER = "IDENTIFIER"
PARAM_UNKNOWN = "UNKNOWN"

PARAMETER_TYPES: tuple[str, ...] = (
    PARAM_STRING,
    PARAM_INTEGER,
    PARAM_BOOLEAN,
    PARAM_SORT,
    PARAM_FILTER,
    PARAM_SEARCH,
    PARAM_IDENTIFIER,
    PARAM_UNKNOWN,
)

FLOW_DIRECT_QUERY = "DIRECT_QUERY"
FLOW_QUERY_BUILDER = "QUERY_BUILDER"
FLOW_ORM = "ORM"
FLOW_STORED_PROCEDURE = "STORED_PROCEDURE"
FLOW_RAW_QUERY = "RAW_QUERY"
FLOW_UNKNOWN = "UNKNOWN"

DATA_FLOWS: tuple[str, ...] = (
    FLOW_DIRECT_QUERY,
    FLOW_QUERY_BUILDER,
    FLOW_ORM,
    FLOW_STORED_PROCEDURE,
    FLOW_RAW_QUERY,
    FLOW_UNKNOWN,
)

QCTX_WHERE = "WHERE"
QCTX_ORDER_BY = "ORDER_BY"
QCTX_LIMIT = "LIMIT"
QCTX_OFFSET = "OFFSET"
QCTX_SELECT = "SELECT"
QCTX_INSERT = "INSERT"
QCTX_UPDATE = "UPDATE"
QCTX_DELETE = "DELETE"
QCTX_UNKNOWN = "UNKNOWN"

QUERY_CONTEXTS: tuple[str, ...] = (
    QCTX_WHERE,
    QCTX_ORDER_BY,
    QCTX_LIMIT,
    QCTX_OFFSET,
    QCTX_SELECT,
    QCTX_INSERT,
    QCTX_UPDATE,
    QCTX_DELETE,
    QCTX_UNKNOWN,
)

DB_MYSQL = "MYSQL"
DB_POSTGRESQL = "POSTGRESQL"
DB_MSSQL = "MSSQL"
DB_SQLITE = "SQLITE"
DB_ORACLE = "ORACLE"
DB_UNKNOWN = "UNKNOWN"

DATABASE_CONTEXTS: tuple[str, ...] = (
    DB_MYSQL,
    DB_POSTGRESQL,
    DB_MSSQL,
    DB_SQLITE,
    DB_ORACLE,
    DB_UNKNOWN,
)

HANDLING_PARAMETERIZED = "PARAMETERIZED"
HANDLING_SANITIZED = "SANITIZED"
HANDLING_ESCAPED = "ESCAPED"
HANDLING_CONCATENATED = "CONCATENATED"
HANDLING_RAW = "RAW"
HANDLING_UNKNOWN = "UNKNOWN"

INPUT_HANDLING_STATES: tuple[str, ...] = (
    HANDLING_PARAMETERIZED,
    HANDLING_SANITIZED,
    HANDLING_ESCAPED,
    HANDLING_CONCATENATED,
    HANDLING_RAW,
    HANDLING_UNKNOWN,
)

TYPE_STRONG = "STRONG"
TYPE_WEAK = "WEAK"
TYPE_CAST = "CAST"
TYPE_NONE_OBSERVED = "NONE_OBSERVED"
TYPE_UNKNOWN = "UNKNOWN"

TYPE_HANDLING_STATES: tuple[str, ...] = (
    TYPE_STRONG,
    TYPE_WEAK,
    TYPE_CAST,
    TYPE_NONE_OBSERVED,
    TYPE_UNKNOWN,
)

ERROR_DATABASE_OBSERVED = "DATABASE_ERROR_OBSERVED"
ERROR_APPLICATION_ONLY = "APPLICATION_ERROR_ONLY"
ERROR_NO_ERROR_OBSERVED = "NO_ERROR_OBSERVED"
ERROR_UNKNOWN = "UNKNOWN"

ERROR_BEHAVIORS: tuple[str, ...] = (
    ERROR_DATABASE_OBSERVED,
    ERROR_APPLICATION_ONLY,
    ERROR_NO_ERROR_OBSERVED,
    ERROR_UNKNOWN,
)

SIGNAL_DIFFERENTIAL = "DIFFERENTIAL"
SIGNAL_TIMING_RELEVANT = "TIMING_RELEVANT"
SIGNAL_BOOLEAN_RELEVANT = "BOOLEAN_RELEVANT"
SIGNAL_NONE_OBSERVED = "NONE_OBSERVED"
SIGNAL_UNKNOWN = "UNKNOWN"

BEHAVIORAL_SIGNALS: tuple[str, ...] = (
    SIGNAL_DIFFERENTIAL,
    SIGNAL_TIMING_RELEVANT,
    SIGNAL_BOOLEAN_RELEVANT,
    SIGNAL_NONE_OBSERVED,
    SIGNAL_UNKNOWN,
)

MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def sanitize_sqli_context_analysis_plan(value: object) -> dict:
    """Project an R41.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "input_location": INPUT_UNKNOWN,
            "parameter_type": PARAM_UNKNOWN,
            "data_flow": FLOW_UNKNOWN,
            "query_context": QCTX_UNKNOWN,
            "database_context": DB_UNKNOWN,
            "input_handling": HANDLING_UNKNOWN,
            "type_handling": TYPE_UNKNOWN,
            "error_behavior": ERROR_UNKNOWN,
            "behavioral_signal": SIGNAL_UNKNOWN,
            "context_confidence": "UNKNOWN",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "input_location": _closed(
            value.get("input_location"), INPUT_LOCATIONS, INPUT_UNKNOWN
        ),
        "parameter_type": _closed(
            value.get("parameter_type"), PARAMETER_TYPES, PARAM_UNKNOWN
        ),
        "data_flow": _closed(
            value.get("data_flow"), DATA_FLOWS, FLOW_UNKNOWN
        ),
        "query_context": _closed(
            value.get("query_context"), QUERY_CONTEXTS, QCTX_UNKNOWN
        ),
        "database_context": _closed(
            value.get("database_context"), DATABASE_CONTEXTS, DB_UNKNOWN
        ),
        "input_handling": _closed(
            value.get("input_handling"),
            INPUT_HANDLING_STATES,
            HANDLING_UNKNOWN,
        ),
        "type_handling": _closed(
            value.get("type_handling"), TYPE_HANDLING_STATES, TYPE_UNKNOWN
        ),
        "error_behavior": _closed(
            value.get("error_behavior"), ERROR_BEHAVIORS, ERROR_UNKNOWN
        ),
        "behavioral_signal": _closed(
            value.get("behavioral_signal"),
            BEHAVIORAL_SIGNALS,
            SIGNAL_UNKNOWN,
        ),
        "context_confidence": _closed(
            value.get("context_confidence"),
            CONFIDENCE_LEVELS,
            "UNKNOWN",
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SQLIContextAnalysisPlan(BaseModel):
    """Deterministic descriptive SQLi context analysis (R41.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = SQLI_CONTEXT_ANALYSIS_RULE_VERSION
    input_location: str = INPUT_UNKNOWN
    parameter_type: str = PARAM_UNKNOWN
    data_flow: str = FLOW_UNKNOWN
    query_context: str = QCTX_UNKNOWN
    database_context: str = DB_UNKNOWN
    input_handling: str = HANDLING_UNKNOWN
    type_handling: str = TYPE_UNKNOWN
    error_behavior: str = ERROR_UNKNOWN
    behavioral_signal: str = SIGNAL_UNKNOWN
    context_confidence: str = "UNKNOWN"
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return SQLI_CONTEXT_ANALYSIS_RULE_VERSION

    @field_validator("input_location")
    @classmethod
    def _valid_input(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in INPUT_LOCATIONS:
            raise ValueError(f"invalid input_location: {value!r}")
        return text

    @field_validator("parameter_type")
    @classmethod
    def _valid_parameter(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PARAMETER_TYPES:
            raise ValueError(f"invalid parameter_type: {value!r}")
        return text

    @field_validator("data_flow")
    @classmethod
    def _valid_flow(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in DATA_FLOWS:
            raise ValueError(f"invalid data_flow: {value!r}")
        return text

    @field_validator("query_context")
    @classmethod
    def _valid_query_context(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in QUERY_CONTEXTS:
            raise ValueError(f"invalid query_context: {value!r}")
        return text

    @field_validator("database_context")
    @classmethod
    def _valid_database(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in DATABASE_CONTEXTS:
            raise ValueError(f"invalid database_context: {value!r}")
        return text

    @field_validator("input_handling")
    @classmethod
    def _valid_handling(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in INPUT_HANDLING_STATES:
            raise ValueError(f"invalid input_handling: {value!r}")
        return text

    @field_validator("type_handling")
    @classmethod
    def _valid_type_handling(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in TYPE_HANDLING_STATES:
            raise ValueError(f"invalid type_handling: {value!r}")
        return text

    @field_validator("error_behavior")
    @classmethod
    def _valid_error(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ERROR_BEHAVIORS:
            raise ValueError(f"invalid error_behavior: {value!r}")
        return text

    @field_validator("behavioral_signal")
    @classmethod
    def _valid_signal(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in BEHAVIORAL_SIGNALS:
            raise ValueError(f"invalid behavioral_signal: {value!r}")
        return text

    @field_validator("context_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid context_confidence: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("sqli context analyses are research-only")
        return True


def sqli_context_analysis_plan_projection(
    value: SQLIContextAnalysisPlan,
) -> dict:
    """Serialize a SQLi context analysis to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "SQLI_CONTEXT_ANALYSIS_RULE_VERSION",
    "RULE_VERSION",
    "INPUT_QUERY",
    "INPUT_BODY",
    "INPUT_HEADER",
    "INPUT_COOKIE",
    "INPUT_PATH",
    "INPUT_UNKNOWN",
    "INPUT_LOCATIONS",
    "PARAM_STRING",
    "PARAM_INTEGER",
    "PARAM_BOOLEAN",
    "PARAM_SORT",
    "PARAM_FILTER",
    "PARAM_SEARCH",
    "PARAM_IDENTIFIER",
    "PARAM_UNKNOWN",
    "PARAMETER_TYPES",
    "FLOW_DIRECT_QUERY",
    "FLOW_QUERY_BUILDER",
    "FLOW_ORM",
    "FLOW_STORED_PROCEDURE",
    "FLOW_RAW_QUERY",
    "FLOW_UNKNOWN",
    "DATA_FLOWS",
    "QCTX_WHERE",
    "QCTX_ORDER_BY",
    "QCTX_LIMIT",
    "QCTX_OFFSET",
    "QCTX_SELECT",
    "QCTX_INSERT",
    "QCTX_UPDATE",
    "QCTX_DELETE",
    "QCTX_UNKNOWN",
    "QUERY_CONTEXTS",
    "DB_MYSQL",
    "DB_POSTGRESQL",
    "DB_MSSQL",
    "DB_SQLITE",
    "DB_ORACLE",
    "DB_UNKNOWN",
    "DATABASE_CONTEXTS",
    "HANDLING_PARAMETERIZED",
    "HANDLING_SANITIZED",
    "HANDLING_ESCAPED",
    "HANDLING_CONCATENATED",
    "HANDLING_RAW",
    "HANDLING_UNKNOWN",
    "INPUT_HANDLING_STATES",
    "TYPE_STRONG",
    "TYPE_WEAK",
    "TYPE_CAST",
    "TYPE_NONE_OBSERVED",
    "TYPE_UNKNOWN",
    "TYPE_HANDLING_STATES",
    "ERROR_DATABASE_OBSERVED",
    "ERROR_APPLICATION_ONLY",
    "ERROR_NO_ERROR_OBSERVED",
    "ERROR_UNKNOWN",
    "ERROR_BEHAVIORS",
    "SIGNAL_DIFFERENTIAL",
    "SIGNAL_TIMING_RELEVANT",
    "SIGNAL_BOOLEAN_RELEVANT",
    "SIGNAL_NONE_OBSERVED",
    "SIGNAL_UNKNOWN",
    "BEHAVIORAL_SIGNALS",
    "MAX_VALUE_LEN",
    "sanitize_sqli_context_analysis_plan",
    "SQLIContextAnalysisPlan",
    "sqli_context_analysis_plan_projection",
]
