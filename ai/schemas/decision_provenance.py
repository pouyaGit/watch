"""Decision provenance schema (Stage R37.1).

A :class:`DecisionProvenancePlan` is the deterministic, read-only record of
WHY an authorization decision exists. It answers the governance question:

    "Which upstream sources and signals produced this decision?"

Hard boundaries encoded here:

- Governance/audit only: no execution runtime, workers, dispatch, scheduler,
  subprocess, shell, browser, network, Mongo persistence or LLM call is
  represented or created.
- No persistence and no database IDs: ``decision_id`` is a deterministic
  content token computed from bounded closed inputs, never a stored id.
- Bounded, privacy-safe, JSON serializable: only closed codes and bounded
  sanitized source snapshots are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.execution_authorization_plan import (
    sanitize_execution_authorization_plan,
    sanitize_source_orchestration_export,
    sanitize_source_strategy_export,
)

DECISION_PROVENANCE_RULE_VERSION = "r37-1"
RULE_VERSION = DECISION_PROVENANCE_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

SIGNAL_STRATEGY = "STRATEGY"
SIGNAL_ORCHESTRATION = "ORCHESTRATION"
SIGNAL_AUTHORIZATION = "AUTHORIZATION"
SIGNAL_POLICY = "POLICY"
SIGNAL_RISK = "RISK"
SIGNAL_APPROVAL = "APPROVAL"
SIGNAL_BOUNDARY = "BOUNDARY"

CONTRIBUTING_SIGNALS: tuple[str, ...] = (
    SIGNAL_STRATEGY,
    SIGNAL_ORCHESTRATION,
    SIGNAL_AUTHORIZATION,
    SIGNAL_POLICY,
    SIGNAL_RISK,
    SIGNAL_APPROVAL,
    SIGNAL_BOUNDARY,
)

PROVENANCE_COMPLETE = "COMPLETE"
PROVENANCE_PARTIAL = "PARTIAL"
PROVENANCE_UNKNOWN = "UNKNOWN"

PROVENANCE_STATES: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_SIGNALS = 7
MAX_VALUE_LEN = 160

DECISION_ID_PREFIX = "dp-"
DECISION_ID_RE = re.compile(r"^dp-[0-9a-f]{16}$")

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_signals(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in CONTRIBUTING_SIGNALS and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _require_signals(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if not text:
            continue
        if text not in CONTRIBUTING_SIGNALS:
            raise ValueError(f"invalid contributing signal: {text!r}")
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_decision_provenance_plan(value: object) -> dict:
    """Project an R37.1 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "decision_id": "",
            "source_strategy": {},
            "source_orchestration": {},
            "source_authorization": {},
            "contributing_signals": [],
            "provenance_state": "",
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "decision_id": _safe_text(value.get("decision_id")),
        "source_strategy": sanitize_source_strategy_export(
            value.get("source_strategy")
        ),
        "source_orchestration": sanitize_source_orchestration_export(
            value.get("source_orchestration")
        ),
        "source_authorization": sanitize_execution_authorization_plan(
            value.get("source_authorization")
        ),
        "contributing_signals": _bounded_signals(
            value.get("contributing_signals"), MAX_SIGNALS
        ),
        "provenance_state": _safe_text(value.get("provenance_state")),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class DecisionProvenancePlan(BaseModel):
    """Deterministic decision provenance record (R37.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = DECISION_PROVENANCE_RULE_VERSION
    decision_id: str
    source_strategy: dict = Field(default_factory=dict)
    source_orchestration: dict = Field(default_factory=dict)
    source_authorization: dict = Field(default_factory=dict)
    contributing_signals: list[str] = Field(default_factory=list)
    provenance_state: str
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return DECISION_PROVENANCE_RULE_VERSION

    @field_validator("decision_id")
    @classmethod
    def _valid_decision_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not DECISION_ID_RE.match(text):
            raise ValueError(f"malformed decision_id: {value!r}")
        return text

    @field_validator("source_strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> dict:
        return sanitize_source_strategy_export(value)

    @field_validator("source_orchestration")
    @classmethod
    def _bounded_orchestration(cls, value: object) -> dict:
        return sanitize_source_orchestration_export(value)

    @field_validator("source_authorization")
    @classmethod
    def _bounded_authorization(cls, value: object) -> dict:
        return sanitize_execution_authorization_plan(value)

    @field_validator("contributing_signals")
    @classmethod
    def _valid_signals(cls, value: list) -> list[str]:
        return _require_signals(value, MAX_SIGNALS)

    @field_validator("provenance_state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PROVENANCE_STATES:
            raise ValueError(f"invalid provenance_state: {value!r}")
        return text

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("decision provenance plans are research-only")
        return True


def decision_provenance_plan_projection(
    value: DecisionProvenancePlan,
) -> dict:
    """Serialize a decision provenance plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "DECISION_PROVENANCE_RULE_VERSION",
    "RULE_VERSION",
    "CONTRIBUTING_SIGNALS",
    "PROVENANCE_STATES",
    "SIGNAL_STRATEGY",
    "SIGNAL_ORCHESTRATION",
    "SIGNAL_AUTHORIZATION",
    "SIGNAL_POLICY",
    "SIGNAL_RISK",
    "SIGNAL_APPROVAL",
    "SIGNAL_BOUNDARY",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "DECISION_ID_PREFIX",
    "DECISION_ID_RE",
    "MAX_SIGNALS",
    "MAX_VALUE_LEN",
    "DecisionProvenancePlan",
    "sanitize_decision_provenance_plan",
    "decision_provenance_plan_projection",
]
