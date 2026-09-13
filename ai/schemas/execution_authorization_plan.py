"""Execution authorization schema (Stage R36.2).

An :class:`ExecutionAuthorizationPlan` is the deterministic authorization
decision inside the R36 execution-safety boundary:

    "Is this candidate authorized, limited, gated or blocked?"

Hard boundaries encoded here:

- Planning/authorization only: the decision is a closed planning label. No
  execution runtime, worker queue, scheduler, dispatch, subprocess, shell
  command, browser, network, Mongo persistence or LLM call is represented or
  created.
- Authorization is authoritative: risk is a separate dimension and can never
  convert a BLOCK into an ALLOW or bypass HUMAN_APPROVAL_REQUIRED.
- Bounded, privacy-safe, JSON serializable: only closed codes and bounded
  sanitized source snapshots are retained.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.execution_policy import EXECUTION_POLICIES

EXECUTION_AUTHORIZATION_RULE_VERSION = "r36-2"
RULE_VERSION = EXECUTION_AUTHORIZATION_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

DECISION_ALLOW = "ALLOW"
DECISION_ALLOW_WITH_LIMITS = "ALLOW_WITH_LIMITS"
DECISION_REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
DECISION_BLOCK = "BLOCK"
DECISION_UNKNOWN = "UNKNOWN"

AUTHORIZATION_DECISIONS: tuple[str, ...] = (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_LIMITS,
    DECISION_REQUIRE_HUMAN_APPROVAL,
    DECISION_BLOCK,
    DECISION_UNKNOWN,
)

REASON_ACTIVE_VALID = "ACTIVE_ALLOWED_VALID"
REASON_RESEARCH_LIMITS = "RESEARCH_ONLY_LIMITS"
REASON_PASSIVE_LIMITS = "PASSIVE_ONLY_LIMITS"
REASON_HUMAN_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
REASON_POLICY_BLOCKED = "POLICY_BLOCKED"
REASON_MALFORMED = "MALFORMED_CONTEXT"
REASON_UNKNOWN_POLICY = "UNKNOWN_POLICY"

AUTHORIZATION_REASONS: tuple[str, ...] = (
    REASON_ACTIVE_VALID,
    REASON_RESEARCH_LIMITS,
    REASON_PASSIVE_LIMITS,
    REASON_HUMAN_REQUIRED,
    REASON_POLICY_BLOCKED,
    REASON_MALFORMED,
    REASON_UNKNOWN_POLICY,
)

LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_PASSIVE_ONLY = "PASSIVE_ONLY"
LIMITATION_HUMAN_APPROVAL = "HUMAN_APPROVAL_REQUIRED"
LIMITATION_BLOCKED = "BLOCKED"
LIMITATION_UNKNOWN_CONTEXT = "UNKNOWN_CONTEXT"

AUTHORIZATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_PASSIVE_ONLY,
    LIMITATION_HUMAN_APPROVAL,
    LIMITATION_BLOCKED,
    LIMITATION_UNKNOWN_CONTEXT,
)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

MAX_LIMITATIONS = 4
MAX_VALUE_LEN = 160

_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _closed(value: object, allowed: tuple) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else ""


def sanitize_source_strategy_export(value: object) -> dict:
    """Project an R34.4 strategy export onto a fixed bounded key set."""

    export = value if isinstance(value, dict) else {}
    strategy = export.get("strategy")
    strategy = strategy if isinstance(strategy, dict) else {}
    path = export.get("path")
    path = path if isinstance(path, dict) else {}
    budget = export.get("budget")
    budget = budget if isinstance(budget, dict) else {}
    return {
        "rule_version": _safe_text(export.get("rule_version")),
        "ready": bool(export.get("ready")),
        "strategy_type": _safe_text(
            strategy.get("strategy_type") or export.get("strategy_type")
        ),
        "confidence_level": _safe_text(
            strategy.get("confidence_level")
            or export.get("confidence_level")
        ),
        "primary_path": _safe_text(
            path.get("primary_path") or export.get("primary_path")
        ),
        "budget_state": _safe_text(
            budget.get("budget_state") or export.get("budget_state")
        ),
        "research_only": True,
    }


def sanitize_source_orchestration_export(value: object) -> dict:
    """Project an R35.4 orchestration export onto a fixed bounded key set."""

    export = value if isinstance(value, dict) else {}
    roles = export.get("roles")
    roles = roles if isinstance(roles, dict) else {}
    coordination = export.get("coordination")
    coordination = coordination if isinstance(coordination, dict) else {}
    workflow = export.get("workflow")
    workflow = workflow if isinstance(workflow, dict) else {}
    nodes = workflow.get("nodes")
    nodes = nodes if isinstance(nodes, (list, tuple)) else ()
    return {
        "rule_version": _safe_text(export.get("rule_version")),
        "ready": bool(export.get("ready")),
        "primary_role": _safe_text(
            roles.get("primary_role") or export.get("primary_role")
        ),
        "coordination_mode": _safe_text(
            coordination.get("coordination_mode")
            or export.get("coordination_mode")
        ),
        "nodes": [
            _safe_text(node) for node in list(nodes)[:5] if _safe_text(node)
        ],
        "research_only": True,
    }


def _bounded_limitations(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if text in AUTHORIZATION_LIMITATIONS and text not in out:
            out.append(text)
        if len(out) >= MAX_LIMITATIONS:
            break
    return out


def sanitize_execution_authorization_plan(value: object) -> dict:
    """Project an R36.2 plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "decision": "",
            "decision_reason": "",
            "policy": "",
            "limitations": [],
            "source_strategy": {},
            "source_orchestration": {},
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "decision": _closed(value.get("decision"),
                            AUTHORIZATION_DECISIONS),
        "decision_reason": _safe_text(value.get("decision_reason")),
        "policy": _closed(value.get("policy"), EXECUTION_POLICIES),
        "limitations": _bounded_limitations(value.get("limitations")),
        "source_strategy": sanitize_source_strategy_export(
            value.get("source_strategy")
        ),
        "source_orchestration": sanitize_source_orchestration_export(
            value.get("source_orchestration")
        ),
        "research_only": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class ExecutionAuthorizationPlan(BaseModel):
    """Deterministic execution authorization decision (R36.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = EXECUTION_AUTHORIZATION_RULE_VERSION
    decision: str
    decision_reason: str
    policy: str
    limitations: list[str] = Field(default_factory=list)
    source_strategy: dict = Field(default_factory=dict)
    source_orchestration: dict = Field(default_factory=dict)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return EXECUTION_AUTHORIZATION_RULE_VERSION

    @field_validator("decision")
    @classmethod
    def _valid_decision(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_DECISIONS:
            raise ValueError(f"invalid decision: {value!r}")
        return text

    @field_validator("decision_reason")
    @classmethod
    def _valid_reason(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AUTHORIZATION_REASONS:
            raise ValueError(f"invalid decision_reason: {value!r}")
        return text

    @field_validator("policy")
    @classmethod
    def _valid_policy(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EXECUTION_POLICIES:
            raise ValueError(f"invalid policy: {value!r}")
        return text

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = _safe_text(item)
            if not text:
                continue
            if text not in AUTHORIZATION_LIMITATIONS:
                raise ValueError(f"invalid limitation: {text!r}")
            if text not in out:
                out.append(text)
            if len(out) >= MAX_LIMITATIONS:
                break
        return out

    @field_validator("source_strategy")
    @classmethod
    def _bounded_strategy(cls, value: object) -> dict:
        return sanitize_source_strategy_export(value)

    @field_validator("source_orchestration")
    @classmethod
    def _bounded_orchestration(cls, value: object) -> dict:
        return sanitize_source_orchestration_export(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("execution authorization is research-only")
        return True


def execution_authorization_plan_projection(
    value: ExecutionAuthorizationPlan,
) -> dict:
    """Serialize an execution authorization plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "EXECUTION_AUTHORIZATION_RULE_VERSION",
    "RULE_VERSION",
    "AUTHORIZATION_DECISIONS",
    "AUTHORIZATION_REASONS",
    "AUTHORIZATION_LIMITATIONS",
    "DECISION_ALLOW",
    "DECISION_ALLOW_WITH_LIMITS",
    "DECISION_REQUIRE_HUMAN_APPROVAL",
    "DECISION_BLOCK",
    "DECISION_UNKNOWN",
    "REASON_ACTIVE_VALID",
    "REASON_RESEARCH_LIMITS",
    "REASON_PASSIVE_LIMITS",
    "REASON_HUMAN_REQUIRED",
    "REASON_POLICY_BLOCKED",
    "REASON_MALFORMED",
    "REASON_UNKNOWN_POLICY",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_PASSIVE_ONLY",
    "LIMITATION_HUMAN_APPROVAL",
    "LIMITATION_BLOCKED",
    "LIMITATION_UNKNOWN_CONTEXT",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "ExecutionAuthorizationPlan",
    "sanitize_source_strategy_export",
    "sanitize_source_orchestration_export",
    "sanitize_execution_authorization_plan",
    "execution_authorization_plan_projection",
]
