"""Finding correlation result schema (Stage R54.2).

Defines deterministic finding-correlation clusters and the R54 correlation
result that groups them. It answers:

    "Which structured findings are correlated, and how?"

Hard boundaries encoded here:

- Research correlation only: clusters are descriptive groupings of research
  finding candidates. They never confirm a vulnerability and never collapse
  findings into a single finding: every member remains independently
  addressable through its stable finding id.
- Preservation: finding references, relationships, clusters and the
  container preserve provenance, governance, limitations and the upstream
  finding ids; nothing is rewritten or discarded.
- Confidence safety: every cluster and the container force
  ``confidence_effect = NONE``; correlation never upgrades finding
  confidence.
- Deterministic: cluster/container ids are content tokens; ordering is
  canonical; no timestamps, UUIDs, pids or randomness.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.schemas.finding_correlation import (
    CORRELATION_LIMITATIONS,
    CORRELATION_SIGNALS,
    MAX_SHARED_ITEMS,
    MAX_SIGNALS,
    RELATIONSHIP_TYPES,
    FindingRelationshipPlan,
    sanitize_finding_reference,
    sanitize_finding_relationship,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

FINDING_CORRELATION_RESULT_RULE_VERSION = "r54-2"
RULE_VERSION = FINDING_CORRELATION_RESULT_RULE_VERSION

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NO_RELATIONSHIPS = "NO_RELATIONSHIPS"
STATUS_FAILED = "FAILED"

CORRELATION_STATUSES: tuple[str, ...] = (
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_NO_RELATIONSHIPS,
    STATUS_FAILED,
)

SKIP_MALFORMED_FINDING = "MALFORMED_FINDING"
SKIP_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
SKIP_UNSAFE_CONFIRMATION = "UNSAFE_CONFIRMATION"
SKIP_NON_RESEARCH_ONLY = "NON_RESEARCH_ONLY"
SKIP_DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
SKIP_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"

FINDING_SKIP_REASONS: tuple[str, ...] = (
    SKIP_MALFORMED_FINDING,
    SKIP_UNSUPPORTED_CATEGORY,
    SKIP_UNSAFE_CONFIRMATION,
    SKIP_NON_RESEARCH_ONLY,
    SKIP_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED,
)

ERROR_INVALID_INPUT = "INVALID_INPUT"
ERROR_MALFORMED_FINDING = "MALFORMED_FINDING"
ERROR_DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
ERROR_UNSUPPORTED_CATEGORY = "UNSUPPORTED_CATEGORY"
ERROR_SAFETY_BLOCKED = "SAFETY_BLOCKED"
ERROR_LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
ERROR_UNKNOWN = "UNKNOWN_ERROR"

CORRELATION_ERROR_CATEGORIES: tuple[str, ...] = (
    ERROR_INVALID_INPUT,
    ERROR_MALFORMED_FINDING,
    ERROR_DUPLICATE_IDENTITY,
    ERROR_UNSUPPORTED_CATEGORY,
    ERROR_SAFETY_BLOCKED,
    ERROR_LIMIT_EXCEEDED,
    ERROR_UNKNOWN,
)

CORRELATION_ID_PREFIX = "fci-"
CORRELATION_ID_RE = re.compile(r"^fci-[0-9a-f]{16}$")
CLUSTER_ID_PREFIX = "fcg-"
CLUSTER_ID_RE = re.compile(r"^fcg-[0-9a-f]{16}$")

GOVERNANCE_SUMMARY_STATES: tuple[str, ...] = (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)

MAX_FINDINGS = 8
MAX_RELATIONSHIPS = 28
MAX_CLUSTERS = 8
MAX_ITEMS = 16
MAX_SKIPPED = 16
MAX_ERRORS = 16
MAX_LIMITATIONS = 24
MAX_VALUE_LEN = 160
MAX_MESSAGE_LEN = 240

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _safe_text(value: object, limit: int = MAX_VALUE_LEN) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _closed(value: object, allowed: tuple, fallback: str) -> str:
    text = _safe_text(value).strip().upper()
    return text if text in allowed else fallback


def _bounded_strings(value: object, limit: int, max_len: int = 120) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item, max_len)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_finding_ids(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if FINDING_ID_RE.match(text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ordered_limitations(codes: object) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in CORRELATION_LIMITATIONS:
            found.add(text)
    return [code for code in CORRELATION_LIMITATIONS if code in found]


# ---------------------------------------------------------------------------
# Cluster / skip / error / summary projections
# ---------------------------------------------------------------------------


def sanitize_correlation_cluster(value: object) -> dict:
    """Project a correlation cluster onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "cluster_id": "",
            "relationship_type": "UNKNOWN",
            "member_finding_ids": [],
            "cluster_size": 0,
            "signals": [],
            "shared_context_values": [],
            "shared_hypothesis_types": [],
            "shared_evidence_requirements": [],
            "confidence_effect": "NONE",
            "limitations": [],
            "research_only": True,
        }
    members = _bounded_finding_ids(
        value.get("member_finding_ids"), MAX_FINDINGS
    )
    shared_context_values: list[dict] = []
    for item in value.get("shared_context_values") or ():
        if not isinstance(item, dict):
            continue
        key = _safe_text(item.get("key"), 80)
        if not re.match(r"^[a-z][a-z0-9_]{0,60}$", key):
            continue
        projected = {"key": key, "value": _safe_text(item.get("value"))}
        if projected not in shared_context_values:
            shared_context_values.append(projected)
        if len(shared_context_values) >= MAX_SHARED_ITEMS:
            break
    size = value.get("cluster_size")
    if isinstance(size, bool) or not isinstance(size, int):
        size = len(members)
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "cluster_id": _safe_text(value.get("cluster_id")),
        "relationship_type": _closed(
            value.get("relationship_type"),
            RELATIONSHIP_TYPES,
            "UNKNOWN",
        ),
        "member_finding_ids": members,
        "cluster_size": max(0, min(MAX_FINDINGS, size)),
        "signals": _bounded_tokens_safe(value.get("signals"), MAX_SIGNALS),
        "shared_context_values": shared_context_values,
        "shared_hypothesis_types": _bounded_strings(
            value.get("shared_hypothesis_types"), MAX_SHARED_ITEMS
        ),
        "shared_evidence_requirements": _bounded_strings(
            value.get("shared_evidence_requirements"), MAX_SHARED_ITEMS
        ),
        "confidence_effect": "NONE",
        "limitations": _ordered_limitations(value.get("limitations")),
        "research_only": True,
    }


def _bounded_tokens_safe(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in CORRELATION_SIGNALS and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def sanitize_correlation_skip(value: object) -> dict:
    """Project one skipped finding onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    finding_id = _safe_text(value.get("finding_id"))
    if finding_id and not FINDING_ID_RE.match(finding_id):
        finding_id = ""
    reason = _closed(
        value.get("reason"), FINDING_SKIP_REASONS, SKIP_MALFORMED_FINDING
    )
    return {
        "finding_id": finding_id,
        "category": _safe_text(value.get("category")).strip().upper(),
        "agent_id": _safe_text(value.get("agent_id")),
        "reason": reason,
    }


def sanitize_correlation_error(value: object) -> dict:
    """Project one correlation error onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    category = _safe_text(value.get("error_category")).strip().upper()
    if category not in CORRELATION_ERROR_CATEGORIES:
        return {}
    return {
        "stage": _safe_text(value.get("stage")).strip().upper(),
        "error_category": category,
        "finding_id": _safe_text(value.get("finding_id")),
        "category": _safe_text(value.get("category")).strip().upper(),
        "message": _safe_text(value.get("message"), MAX_MESSAGE_LEN),
    }


def sanitize_correlation_governance_summary(value: object) -> dict:
    """Project the aggregated governance summary onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "governance_state": GOVERNANCE_UNKNOWN,
            "referenced_finding_ids": [],
            "unknown_finding_ids": [],
            "ready_finding_ids": [],
            "not_ready_finding_ids": [],
            "research_only": True,
        }
    return {
        "governance_state": _closed(
            value.get("governance_state"),
            GOVERNANCE_SUMMARY_STATES,
            GOVERNANCE_UNKNOWN,
        ),
        "referenced_finding_ids": _bounded_finding_ids(
            value.get("referenced_finding_ids"), MAX_FINDINGS
        ),
        "unknown_finding_ids": _bounded_finding_ids(
            value.get("unknown_finding_ids"), MAX_FINDINGS
        ),
        "ready_finding_ids": _bounded_finding_ids(
            value.get("ready_finding_ids"), MAX_FINDINGS
        ),
        "not_ready_finding_ids": _bounded_finding_ids(
            value.get("not_ready_finding_ids"), MAX_FINDINGS
        ),
        "research_only": True,
    }


def sanitize_correlation_provenance(value: object) -> dict:
    """Project aggregated correlation provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "finding_rule_version": "",
            "orchestration_ids": [],
            "finding_count": 0,
            "relationship_count": 0,
            "cluster_count": 0,
            "source_categories": [],
            "source_agent_ids": [],
            "deterministic": True,
            "research_only": True,
        }
    orchestration_ids = _bounded_strings(
        value.get("orchestration_ids"), MAX_ITEMS
    )
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "orchestration_ids": orchestration_ids,
        "finding_count": _bounded_count(value.get("finding_count"), 0, 64),
        "relationship_count": _bounded_count(
            value.get("relationship_count"), 0, 64
        ),
        "cluster_count": _bounded_count(value.get("cluster_count"), 0, 64),
        "source_categories": _bounded_strings(
            value.get("source_categories"), MAX_ITEMS
        ),
        "source_agent_ids": _bounded_strings(
            value.get("source_agent_ids"), MAX_ITEMS
        ),
        "deterministic": True,
        "research_only": True,
    }


def _bounded_count(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FindingCorrelationClusterPlan(BaseModel):
    """Deterministic cluster of correlated findings (R54.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_CORRELATION_RESULT_RULE_VERSION
    cluster_id: str
    relationship_type: str
    member_finding_ids: list[str] = Field(default_factory=list)
    cluster_size: int = 0
    signals: list[str] = Field(default_factory=list)
    shared_context_values: list[dict] = Field(default_factory=list)
    shared_hypothesis_types: list[str] = Field(default_factory=list)
    shared_evidence_requirements: list[str] = Field(default_factory=list)
    confidence_effect: str = "NONE"
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_CORRELATION_RESULT_RULE_VERSION

    @field_validator("cluster_id")
    @classmethod
    def _valid_cluster_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not CLUSTER_ID_RE.match(text):
            raise ValueError(f"malformed cluster_id: {value!r}")
        return text

    @field_validator("relationship_type")
    @classmethod
    def _valid_type(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in RELATIONSHIP_TYPES:
            raise ValueError(f"invalid relationship_type: {value!r}")
        return text

    @field_validator("member_finding_ids")
    @classmethod
    def _valid_members(cls, value: object) -> list[str]:
        out = _bounded_finding_ids(value, MAX_FINDINGS)
        if len(out) < 2:
            raise ValueError("a correlation cluster needs two members")
        return out

    @field_validator("cluster_size")
    @classmethod
    def _valid_size(cls, value: object) -> int:
        return _bounded_count(value, 0, MAX_FINDINGS)

    @field_validator("signals")
    @classmethod
    def _valid_signals(cls, value: object) -> list[str]:
        return _bounded_tokens_safe(value, MAX_SIGNALS)

    @field_validator("confidence_effect")
    @classmethod
    def _no_confidence_effect(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NONE":
            raise ValueError("correlation never changes finding confidence")
        return "NONE"

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("correlation clusters are research-only")
        return True


class FindingCorrelationResultPlan(BaseModel):
    """Deterministic R54 finding-correlation result (R54.2)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = FINDING_CORRELATION_RESULT_RULE_VERSION
    correlation_rule_version: str = (
        FINDING_CORRELATION_RESULT_RULE_VERSION
    )
    relationship_rule_version: str = ""
    correlation_id: str = ""
    status: str = STATUS_NO_RELATIONSHIPS
    finding_references: list[dict] = Field(default_factory=list)
    relationships: list[dict] = Field(default_factory=list)
    clusters: list[dict] = Field(default_factory=list)
    skipped_findings: list[dict] = Field(default_factory=list)
    errors: list[dict] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    governance_summary: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    confidence_effect: str = "NONE"
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version", "correlation_rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return FINDING_CORRELATION_RESULT_RULE_VERSION

    @field_validator("relationship_rule_version")
    @classmethod
    def _bounded_relationship_rule(cls, value: object) -> str:
        return _safe_text(value)

    @field_validator("correlation_id")
    @classmethod
    def _valid_correlation_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not CORRELATION_ID_RE.match(text):
            raise ValueError(f"malformed correlation_id: {value!r}")
        return text

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CORRELATION_STATUSES:
            raise ValueError(f"invalid correlation status: {value!r}")
        return text

    @field_validator("finding_references")
    @classmethod
    def _bounded_finding_references(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_finding_reference(item)
            if projected["finding_id"]:
                out.append(projected)
            if len(out) >= MAX_FINDINGS:
                break
        return out

    @field_validator("relationships")
    @classmethod
    def _bounded_relationships(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            try:
                projected = FindingRelationshipPlan(
                    **sanitize_finding_relationship(item)
                ).model_dump(mode="json")
            except ValueError:
                continue
            out.append(projected)
            if len(out) >= MAX_RELATIONSHIPS:
                break
        return out

    @field_validator("clusters")
    @classmethod
    def _bounded_clusters(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            try:
                projected = FindingCorrelationClusterPlan(
                    **sanitize_correlation_cluster(item)
                ).model_dump(mode="json")
            except ValueError:
                continue
            out.append(projected)
            if len(out) >= MAX_CLUSTERS:
                break
        return out

    @field_validator("skipped_findings")
    @classmethod
    def _bounded_skipped(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_correlation_skip(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_SKIPPED:
                break
        return out

    @field_validator("errors")
    @classmethod
    def _bounded_errors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            projected = sanitize_correlation_error(item)
            if projected and projected not in out:
                out.append(projected)
            if len(out) >= MAX_ERRORS:
                break
        return out

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_correlation_provenance(value)

    @field_validator("governance_summary")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_correlation_governance_summary(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_limitations(value)[:MAX_LIMITATIONS]

    @field_validator("confidence_effect")
    @classmethod
    def _no_confidence_effect(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NONE":
            raise ValueError("correlation never changes finding confidence")
        return "NONE"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("correlation results are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("correlation results are deterministic")
        return True


def sanitize_finding_correlation_result(value: object) -> dict:
    """Project an R54 result onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "correlation_rule_version": "",
            "relationship_rule_version": "",
            "correlation_id": "",
            "status": STATUS_NO_RELATIONSHIPS,
            "finding_references": [],
            "relationships": [],
            "clusters": [],
            "skipped_findings": [],
            "errors": [],
            "provenance": sanitize_correlation_provenance(None),
            "governance_summary": sanitize_correlation_governance_summary(
                None
            ),
            "limitations": [],
            "confidence_effect": "NONE",
            "research_only": True,
            "deterministic": True,
        }
    finding_references: list[dict] = []
    for item in value.get("finding_references") or ():
        projected = sanitize_finding_reference(item)
        if projected["finding_id"]:
            finding_references.append(projected)
        if len(finding_references) >= MAX_FINDINGS:
            break
    relationships: list[dict] = []
    for item in value.get("relationships") or ():
        try:
            projected = FindingRelationshipPlan(
                **sanitize_finding_relationship(item)
            ).model_dump(mode="json")
        except ValueError:
            continue
        relationships.append(projected)
        if len(relationships) >= MAX_RELATIONSHIPS:
            break
    clusters: list[dict] = []
    for item in value.get("clusters") or ():
        try:
            projected = FindingCorrelationClusterPlan(
                **sanitize_correlation_cluster(item)
            ).model_dump(mode="json")
        except ValueError:
            continue
        clusters.append(projected)
        if len(clusters) >= MAX_CLUSTERS:
            break
    skipped: list[dict] = []
    for item in value.get("skipped_findings") or ():
        projected = sanitize_correlation_skip(item)
        if projected and projected not in skipped:
            skipped.append(projected)
        if len(skipped) >= MAX_SKIPPED:
            break
    errors: list[dict] = []
    for item in value.get("errors") or ():
        projected = sanitize_correlation_error(item)
        if projected and projected not in errors:
            errors.append(projected)
        if len(errors) >= MAX_ERRORS:
            break
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "relationship_rule_version": _safe_text(
            value.get("relationship_rule_version")
        ),
        "correlation_id": _safe_text(value.get("correlation_id")),
        "status": _closed(
            value.get("status"),
            CORRELATION_STATUSES,
            STATUS_NO_RELATIONSHIPS,
        ),
        "finding_references": finding_references,
        "relationships": relationships,
        "clusters": clusters,
        "skipped_findings": skipped,
        "errors": errors,
        "provenance": sanitize_correlation_provenance(
            value.get("provenance")
        ),
        "governance_summary": sanitize_correlation_governance_summary(
            value.get("governance_summary")
        ),
        "limitations": _ordered_limitations(value.get("limitations"))[
            :MAX_LIMITATIONS
        ],
        "confidence_effect": "NONE",
        "research_only": True,
        "deterministic": True,
    }


def finding_correlation_result_plan_projection(
    value: FindingCorrelationResultPlan,
) -> dict:
    """Serialize an R54 result to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "FINDING_CORRELATION_RESULT_RULE_VERSION",
    "RULE_VERSION",
    "CORRELATION_STATUSES",
    "CORRELATION_ERROR_CATEGORIES",
    "CORRELATION_LIMITATIONS",
    "FINDING_SKIP_REASONS",
    "GOVERNANCE_SUMMARY_STATES",
    "STATUS_COMPLETED",
    "STATUS_PARTIAL",
    "STATUS_NO_RELATIONSHIPS",
    "STATUS_FAILED",
    "SKIP_MALFORMED_FINDING",
    "SKIP_UNSUPPORTED_CATEGORY",
    "SKIP_UNSAFE_CONFIRMATION",
    "SKIP_NON_RESEARCH_ONLY",
    "SKIP_DUPLICATE_IDENTITY",
    "SKIP_LIMIT_EXCEEDED",
    "ERROR_INVALID_INPUT",
    "ERROR_MALFORMED_FINDING",
    "ERROR_DUPLICATE_IDENTITY",
    "ERROR_UNSUPPORTED_CATEGORY",
    "ERROR_SAFETY_BLOCKED",
    "ERROR_LIMIT_EXCEEDED",
    "ERROR_UNKNOWN",
    "CORRELATION_ID_PREFIX",
    "CORRELATION_ID_RE",
    "CLUSTER_ID_PREFIX",
    "CLUSTER_ID_RE",
    "MAX_FINDINGS",
    "MAX_RELATIONSHIPS",
    "MAX_CLUSTERS",
    "MAX_ITEMS",
    "MAX_SKIPPED",
    "MAX_ERRORS",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "MAX_MESSAGE_LEN",
    "sanitize_correlation_cluster",
    "sanitize_correlation_skip",
    "sanitize_correlation_error",
    "sanitize_correlation_governance_summary",
    "sanitize_correlation_provenance",
    "sanitize_finding_correlation_result",
    "FindingCorrelationClusterPlan",
    "FindingCorrelationResultPlan",
    "finding_correlation_result_plan_projection",
]
