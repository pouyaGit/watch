"""Unified multi-agent collaboration result schema (Stage R43.5).

The final deterministic, research-only collaboration artifact. It answers:

    "How do multiple structured security research results relate,
     support, overlap or conflict?"

Hard boundaries encoded here:

- Collaboration only: results are combined and attributed; no execution, no
  network, no database, no browser, no LLM, no payloads, no scanning.
- Attribution is preserved: every hypothesis, evidence requirement and
  ranking keeps its source agent.
- The collaboration priority score represents research/collaboration
  priority only. It is NOT severity, CVSS, exploitability or vulnerability
  probability.
- ``deterministic`` and ``research_only`` are always true.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    rating_for_score,
)
from ai.schemas.collaboration_conflict import (
    sanitize_collaboration_conflict,
)
from ai.schemas.collaboration_evidence import (
    sanitize_collaboration_evidence_plan,
)
from ai.schemas.hypothesis_correlation import (
    sanitize_hypothesis_group,
)
from ai.schemas.multi_agent_collaboration_input import (
    sanitize_collaboration_diagnostic,
    sanitize_participating_agent,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION = "r43-6"
RULE_VERSION = MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Fixed ranking weights (percent, total 100) — not runtime configurable
# ---------------------------------------------------------------------------

FACTOR_SPECIALIST_CONFIDENCE = "SPECIALIST_CONFIDENCE"
FACTOR_HYPOTHESIS_PRIORITY = "HYPOTHESIS_PRIORITY"
FACTOR_EVALUATION_QUALITY = "EVALUATION_QUALITY"
FACTOR_EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"
FACTOR_PROVENANCE_COMPLETENESS = "PROVENANCE_COMPLETENESS"
FACTOR_GOVERNANCE_STATE = "GOVERNANCE_STATE"
FACTOR_SAFETY_STATE = "SAFETY_STATE"

RANKING_FACTORS: tuple[str, ...] = (
    FACTOR_SPECIALIST_CONFIDENCE,
    FACTOR_HYPOTHESIS_PRIORITY,
    FACTOR_EVALUATION_QUALITY,
    FACTOR_EVIDENCE_COMPLETENESS,
    FACTOR_PROVENANCE_COMPLETENESS,
    FACTOR_GOVERNANCE_STATE,
    FACTOR_SAFETY_STATE,
)

RANKING_WEIGHTS: dict[str, int] = {
    FACTOR_SPECIALIST_CONFIDENCE: 20,
    FACTOR_HYPOTHESIS_PRIORITY: 20,
    FACTOR_EVALUATION_QUALITY: 25,
    FACTOR_EVIDENCE_COMPLETENESS: 10,
    FACTOR_PROVENANCE_COMPLETENESS: 5,
    FACTOR_GOVERNANCE_STATE: 5,
    FACTOR_SAFETY_STATE: 15,
}

TOTAL_RANKING_WEIGHT = sum(RANKING_WEIGHTS.values())

SAFETY_BUCKET_SAFE = 0
SAFETY_BUCKET_DEGRADED = 1
SAFETY_BUCKET_FAILED = 2

SAFETY_BUCKETS: tuple[int, ...] = (
    SAFETY_BUCKET_SAFE,
    SAFETY_BUCKET_DEGRADED,
    SAFETY_BUCKET_FAILED,
)

UNGATED_SCORE = 100
FAILED_SAFETY_CEILING = 39
DEGRADED_SAFETY_CEILING = 74

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

GOVERNANCE_CONSISTENT_REFERENCED = "CONSISTENT_REFERENCED"
GOVERNANCE_MIXED = "MIXED"
GOVERNANCE_UNKNOWN = "UNKNOWN"

GOVERNANCE_SUMMARY_STATES: tuple[str, ...] = (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

PROVENANCE_COMPLETE = "COMPLETE"
PROVENANCE_PARTIAL = "PARTIAL"
PROVENANCE_UNKNOWN = "UNKNOWN"

PROVENANCE_SUMMARY_STATES: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_UNKNOWN,
)

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_EVIDENCE_COLLECTED = "NO_EVIDENCE_COLLECTED"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_AGENTS_EXECUTED = "NO_AGENTS_EXECUTED"
LIMITATION_COLLABORATION_QUALITY_ONLY = "COLLABORATION_QUALITY_ONLY"

COLLABORATION_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_EVIDENCE_COLLECTED,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_AGENTS_EXECUTED,
    LIMITATION_COLLABORATION_QUALITY_ONLY,
)

MAX_AGENTS = 12
MAX_GROUPS = 24
MAX_CONFLICTS = 24
MAX_RANKINGS = 12
MAX_DIAGNOSTICS = 32
MAX_LIMITATIONS = 6
MAX_VALUE_LEN = 160

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:MAX_VALUE_LEN]


def _bounded_limitations(value: object) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in COLLABORATION_LIMITATIONS and text not in out:
            out.append(text)
        if len(out) >= MAX_LIMITATIONS:
            break
    return out


def sanitize_collaboration_ranking(value: object) -> dict:
    """Project a collaboration ranking onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "agent_id": "",
            "agent_category": "UNKNOWN",
            "priority_score": 0,
            "priority_rating": "CRITICAL",
            "rank": 0,
            "factors": {},
            "safety_state": "FAILED",
            "safety_bucket": SAFETY_BUCKET_FAILED,
            "evaluation_present": False,
        }
    category = _safe_text(value.get("agent_category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = "UNKNOWN"
    score = value.get("priority_score")
    if isinstance(score, bool) or not isinstance(score, int):
        score = 0
    score = max(0, min(100, score))
    rating = _safe_text(value.get("priority_rating")).strip().upper()
    if rating not in EVALUATION_RATINGS:
        rating = rating_for_score(score)
    factors: dict = {}
    for key in RANKING_FACTORS:
        raw = (value.get("factors") or {}).get(key)
        if isinstance(raw, bool) or not isinstance(raw, int):
            raw = 0
        factors[key] = max(0, min(100, raw))
    bucket = value.get("safety_bucket")
    if isinstance(bucket, bool) or not isinstance(bucket, int):
        bucket = SAFETY_BUCKET_FAILED
    bucket = max(SAFETY_BUCKET_SAFE, min(SAFETY_BUCKET_FAILED, bucket))
    rank = value.get("rank")
    if isinstance(rank, bool) or not isinstance(rank, int) or rank < 0:
        rank = 0
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "agent_id": _safe_text(value.get("agent_id")),
        "agent_category": category,
        "priority_score": score,
        "priority_rating": rating,
        "rank": rank,
        "factors": factors,
        "safety_state": _safe_text(
            value.get("safety_state")
        ).strip().upper(),
        "safety_bucket": bucket,
        "evaluation_present": bool(value.get("evaluation_present", False))
        is True,
    }


def sanitize_collaboration_governance_summary(value: object) -> dict:
    if not isinstance(value, dict):
        return {
            "referenced_agents": [],
            "unknown_agents": [],
            "ready_agents": [],
            "not_ready_agents": [],
            "governance_state": GOVERNANCE_UNKNOWN,
        }
    state = _safe_text(value.get("governance_state")).strip().upper()
    if state not in GOVERNANCE_SUMMARY_STATES:
        state = GOVERNANCE_UNKNOWN
    return {
        "referenced_agents": [
            _safe_text(item)
            for item in value.get("referenced_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "unknown_agents": [
            _safe_text(item)
            for item in value.get("unknown_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "ready_agents": [
            _safe_text(item)
            for item in value.get("ready_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "not_ready_agents": [
            _safe_text(item)
            for item in value.get("not_ready_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "governance_state": state,
    }


def sanitize_collaboration_provenance_summary(value: object) -> dict:
    if not isinstance(value, dict):
        return {
            "source_layers": [],
            "complete_agents": [],
            "partial_agents": [],
            "unknown_agents": [],
            "provenance_state": PROVENANCE_UNKNOWN,
        }
    state = _safe_text(value.get("provenance_state")).strip().upper()
    if state not in PROVENANCE_SUMMARY_STATES:
        state = PROVENANCE_UNKNOWN
    return {
        "source_layers": [
            _safe_text(item).strip().upper()
            for item in value.get("source_layers") or ()
            if _safe_text(item)
        ][:12],
        "complete_agents": [
            _safe_text(item)
            for item in value.get("complete_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "partial_agents": [
            _safe_text(item)
            for item in value.get("partial_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "unknown_agents": [
            _safe_text(item)
            for item in value.get("unknown_agents") or ()
            if _safe_text(item)
        ][:MAX_AGENTS],
        "provenance_state": state,
    }


def sanitize_collaboration_shared_context_summary(value: object) -> dict:
    if not isinstance(value, dict):
        return {
            "asset_reference_present": False,
            "blocks_present": [],
            "block_count": 0,
            "fact_count": 0,
            "source_layers": [],
            "research_only": True,
        }
    block_count = value.get("block_count")
    if isinstance(block_count, bool) or not isinstance(block_count, int):
        block_count = 0
    fact_count = value.get("fact_count")
    if isinstance(fact_count, bool) or not isinstance(fact_count, int):
        fact_count = 0
    return {
        "asset_reference_present": bool(
            value.get("asset_reference_present", False)
        ) is True,
        "blocks_present": [
            _safe_text(item)
            for item in value.get("blocks_present") or ()
            if _safe_text(item)
        ][:12],
        "block_count": max(0, min(12, block_count)),
        "fact_count": max(0, min(256, fact_count)),
        "source_layers": [
            _safe_text(item).strip().upper()
            for item in value.get("source_layers") or ()
            if _safe_text(item)
        ][:12],
        "research_only": True,
    }


def sanitize_multi_agent_collaboration_result(value: object) -> dict:
    """Project an R43.6 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "collaboration_rule_version": "",
            "collaboration_id": "",
            "participating_agents": [],
            "hypothesis_groups": [],
            "merged_evidence": sanitize_collaboration_evidence_plan(None),
            "conflicts": [],
            "collaboration_rankings": [],
            "shared_context_summary": (
                sanitize_collaboration_shared_context_summary(None)
            ),
            "governance_summary": (
                sanitize_collaboration_governance_summary(None)
            ),
            "provenance_summary": (
                sanitize_collaboration_provenance_summary(None)
            ),
            "collaboration_diagnostics": [],
            "deterministic": True,
            "research_only": True,
            "limitations": list(COLLABORATION_LIMITATIONS),
        }
    agents: list[dict] = []
    for item in value.get("participating_agents") or ():
        if isinstance(item, dict):
            agents.append(sanitize_participating_agent(item))
        if len(agents) >= MAX_AGENTS:
            break
    groups: list[dict] = []
    for item in value.get("hypothesis_groups") or ():
        if isinstance(item, dict):
            groups.append(sanitize_hypothesis_group(item))
        if len(groups) >= MAX_GROUPS:
            break
    conflicts: list[dict] = []
    for item in value.get("conflicts") or ():
        if isinstance(item, dict):
            conflicts.append(sanitize_collaboration_conflict(item))
        if len(conflicts) >= MAX_CONFLICTS:
            break
    rankings: list[dict] = []
    for item in value.get("collaboration_rankings") or ():
        if isinstance(item, dict):
            rankings.append(sanitize_collaboration_ranking(item))
        if len(rankings) >= MAX_RANKINGS:
            break
    diagnostics: list[dict] = []
    for item in value.get("collaboration_diagnostics") or ():
        if isinstance(item, dict):
            projected = sanitize_collaboration_diagnostic(item)
            if projected and projected not in diagnostics:
                diagnostics.append(projected)
        if len(diagnostics) >= MAX_DIAGNOSTICS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "collaboration_rule_version": _safe_text(
            value.get("collaboration_rule_version")
        ),
        "collaboration_id": _safe_text(value.get("collaboration_id")),
        "participating_agents": agents,
        "hypothesis_groups": groups,
        "merged_evidence": sanitize_collaboration_evidence_plan(
            value.get("merged_evidence")
        ),
        "conflicts": conflicts,
        "collaboration_rankings": rankings,
        "shared_context_summary": (
            sanitize_collaboration_shared_context_summary(
                value.get("shared_context_summary")
            )
        ),
        "governance_summary": sanitize_collaboration_governance_summary(
            value.get("governance_summary")
        ),
        "provenance_summary": sanitize_collaboration_provenance_summary(
            value.get("provenance_summary")
        ),
        "collaboration_diagnostics": diagnostics,
        "deterministic": bool(value.get("deterministic", True)) is True,
        "research_only": bool(value.get("research_only", True)) is True,
        "limitations": _bounded_limitations(value.get("limitations")),
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CollaborationRankingPlan(BaseModel):
    """Deterministic collaboration priority ranking (R43.5)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION
    agent_id: str = ""
    agent_category: str = "UNKNOWN"
    priority_score: int = 0
    priority_rating: str = "CRITICAL"
    rank: int = 0
    factors: dict = Field(default_factory=dict)
    safety_state: str = "FAILED"
    safety_bucket: int = SAFETY_BUCKET_FAILED
    evaluation_present: bool = False

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION

    @field_validator("agent_id")
    @classmethod
    def _bounded_agent(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("agent_category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid agent_category: {value!r}")
        return text

    @field_validator("priority_score")
    @classmethod
    def _valid_score(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid priority_score: {value!r}")
        if value < 0 or value > 100:
            raise ValueError(f"priority_score out of range: {value!r}")
        return value

    @field_validator("priority_rating")
    @classmethod
    def _valid_rating(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVALUATION_RATINGS:
            raise ValueError(f"invalid priority_rating: {value!r}")
        return text

    @field_validator("rank")
    @classmethod
    def _valid_rank(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid rank: {value!r}")
        if value < 0 or value > MAX_RANKINGS:
            raise ValueError(f"rank out of range: {value!r}")
        return value

    @field_validator("factors")
    @classmethod
    def _valid_factors(cls, value: object) -> dict:
        if not isinstance(value, dict):
            raise ValueError(f"invalid factors: {value!r}")
        out: dict = {}
        for key in RANKING_FACTORS:
            raw = value.get(key, 0)
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise ValueError(f"invalid factor value: {key!r}")
            if raw < 0 or raw > 100:
                raise ValueError(f"factor out of range: {key!r}")
            out[key] = raw
        return out

    @field_validator("safety_state")
    @classmethod
    def _valid_safety(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in ("PASS", "DEGRADED", "FAILED"):
            raise ValueError(f"invalid safety_state: {value!r}")
        return text

    @field_validator("safety_bucket")
    @classmethod
    def _valid_bucket(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid safety_bucket: {value!r}")
        if value not in SAFETY_BUCKETS:
            raise ValueError(f"safety_bucket out of range: {value!r}")
        return value


class MultiAgentCollaborationResultPlan(BaseModel):
    """Final deterministic collaboration result (R43.6)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION
    collaboration_rule_version: str = (
        MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION
    )
    collaboration_id: str = ""
    participating_agents: list[dict] = Field(default_factory=list)
    hypothesis_groups: list[dict] = Field(default_factory=list)
    merged_evidence: dict = Field(default_factory=dict)
    conflicts: list[dict] = Field(default_factory=list)
    collaboration_rankings: list[dict] = Field(default_factory=list)
    shared_context_summary: dict = Field(default_factory=dict)
    governance_summary: dict = Field(default_factory=dict)
    provenance_summary: dict = Field(default_factory=dict)
    collaboration_diagnostics: list[dict] = Field(default_factory=list)
    deterministic: bool = True
    research_only: bool = True
    limitations: list[str] = Field(default_factory=list)

    @field_validator("rule_version", "collaboration_rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION

    @field_validator("collaboration_id")
    @classmethod
    def _bounded_id(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("participating_agents")
    @classmethod
    def _valid_agents(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_participating_agent(item))
            if len(out) >= MAX_AGENTS:
                break
        return out

    @field_validator("hypothesis_groups")
    @classmethod
    def _valid_groups(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_hypothesis_group(item))
            if len(out) >= MAX_GROUPS:
                break
        return out

    @field_validator("merged_evidence")
    @classmethod
    def _valid_evidence(cls, value: object) -> dict:
        return sanitize_collaboration_evidence_plan(value)

    @field_validator("conflicts")
    @classmethod
    def _valid_conflicts(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_collaboration_conflict(item))
            if len(out) >= MAX_CONFLICTS:
                break
        return out

    @field_validator("collaboration_rankings")
    @classmethod
    def _valid_rankings(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                out.append(sanitize_collaboration_ranking(item))
            if len(out) >= MAX_RANKINGS:
                break
        return out

    @field_validator("shared_context_summary")
    @classmethod
    def _valid_context_summary(cls, value: object) -> dict:
        return sanitize_collaboration_shared_context_summary(value)

    @field_validator("governance_summary")
    @classmethod
    def _valid_governance_summary(cls, value: object) -> dict:
        return sanitize_collaboration_governance_summary(value)

    @field_validator("provenance_summary")
    @classmethod
    def _valid_provenance_summary(cls, value: object) -> dict:
        return sanitize_collaboration_provenance_summary(value)

    @field_validator("collaboration_diagnostics")
    @classmethod
    def _valid_diagnostics(cls, value: list) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            if isinstance(item, dict):
                projected = sanitize_collaboration_diagnostic(item)
                if projected and projected not in out:
                    out.append(projected)
            if len(out) >= MAX_DIAGNOSTICS:
                break
        return out

    @field_validator("deterministic", "research_only")
    @classmethod
    def _forced_true(cls, value: object) -> bool:
        if not value:
            raise ValueError(
                "collaboration results are deterministic and research-only"
            )
        return True

    @field_validator("limitations")
    @classmethod
    def _valid_limitations(cls, value: list) -> list[str]:
        return _bounded_limitations(value)


def collaboration_ranking_plan_projection(
    value: CollaborationRankingPlan,
) -> dict:
    """Serialize a collaboration ranking to a deterministic dict."""

    return value.model_dump(mode="json")


def multi_agent_collaboration_result_plan_projection(
    value: MultiAgentCollaborationResultPlan,
) -> dict:
    """Serialize a collaboration result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "MULTI_AGENT_COLLABORATION_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "RANKING_FACTORS",
    "RANKING_WEIGHTS",
    "TOTAL_RANKING_WEIGHT",
    "FACTOR_SPECIALIST_CONFIDENCE",
    "FACTOR_HYPOTHESIS_PRIORITY",
    "FACTOR_EVALUATION_QUALITY",
    "FACTOR_EVIDENCE_COMPLETENESS",
    "FACTOR_PROVENANCE_COMPLETENESS",
    "FACTOR_GOVERNANCE_STATE",
    "FACTOR_SAFETY_STATE",
    "SAFETY_BUCKET_SAFE",
    "SAFETY_BUCKET_DEGRADED",
    "SAFETY_BUCKET_FAILED",
    "SAFETY_BUCKETS",
    "UNGATED_SCORE",
    "FAILED_SAFETY_CEILING",
    "DEGRADED_SAFETY_CEILING",
    "GOVERNANCE_SUMMARY_STATES",
    "GOVERNANCE_CONSISTENT_REFERENCED",
    "GOVERNANCE_MIXED",
    "GOVERNANCE_UNKNOWN",
    "PROVENANCE_SUMMARY_STATES",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "COLLABORATION_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_EVIDENCE_COLLECTED",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_AGENTS_EXECUTED",
    "LIMITATION_COLLABORATION_QUALITY_ONLY",
    "MAX_AGENTS",
    "MAX_GROUPS",
    "MAX_CONFLICTS",
    "MAX_RANKINGS",
    "MAX_DIAGNOSTICS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "sanitize_collaboration_ranking",
    "sanitize_collaboration_governance_summary",
    "sanitize_collaboration_provenance_summary",
    "sanitize_collaboration_shared_context_summary",
    "sanitize_multi_agent_collaboration_result",
    "CollaborationRankingPlan",
    "MultiAgentCollaborationResultPlan",
    "collaboration_ranking_plan_projection",
    "multi_agent_collaboration_result_plan_projection",
]
