"""Stage R54.4 deterministic finding correlation builder (pure engine).

Consumes structured R53 finding-intelligence output and produces a
deterministic finding-correlation result:

    R53 finding intelligence (or standalone R53 findings)
      -> bounded finding references (stable finding ids)
      -> pairwise relationship classification (R54.3 rules)
      -> deterministic clusters (duplicate/conflicting/related)
      -> provenance, governance summary and limitations
      -> finding correlation result

Hard boundaries encoded here:

- Research correlation only: R54 never executes anything, never confirms a
  vulnerability and never merges, rewrites or deletes findings. Every
  original finding, evidence reference, hypothesis reference, provenance
  reference, governance reference and limitation remains addressable through
  its stable finding id.
- No confidence inflation: the result and every cluster force
  ``confidence_effect = NONE``; upstream finding confidence is preserved
  untouched (R54 is read-only over its inputs).
- Reuse, never duplicate: findings are normalized through the R53 finding
  sanitizer; relationship vocabulary and R43 conflict semantics are reused.
- Fail closed: ambiguous (both orchestration-level and standalone inputs),
  malformed, unsupported or non-research-only inputs are rejected or
  skipped with structured reasons.
- Deterministic: content-derived ids only; canonical ordering; no
  timestamps, UUIDs, pids or randomness.
- Pure and offline: no I/O, no network, no DNS, no subprocess, no shell, no
  browser, no scanner, no database, no LLM, no wall-clock time.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

import hashlib
import json

from ai.knowledge.finding_correlation_rules import (
    analyze_pair,
    finding_facts,
)
from ai.schemas.finding_assessment import CONFIRMATION_NOT_CONFIRMED
from ai.schemas.finding_correlation import (
    CORRELATION_LIMITATIONS,
    FINDING_CORRELATION_RULE_VERSION,
    LIMITATION_CONFIDENCE_NOT_UPGRADED,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_DUPLICATE_RELATIONSHIP,
    LIMITATION_EVIDENCE_INCOMPLETE,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_PROVENANCE_UNAVAILABLE,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_SHARED_CONTEXT,
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_ID_PREFIX,
    RELATIONSHIP_PRECEDENCE,
    RELATIONSHIP_RELATED,
    RELATIONSHIP_UNKNOWN,
    FindingReferencePlan,
    FindingRelationshipPlan,
)
from ai.schemas.finding_correlation_result import (
    CLUSTER_ID_PREFIX,
    CORRELATION_ID_PREFIX,
    ERROR_DUPLICATE_IDENTITY,
    ERROR_INVALID_INPUT,
    ERROR_LIMIT_EXCEEDED,
    ERROR_MALFORMED_FINDING,
    ERROR_SAFETY_BLOCKED,
    ERROR_UNSUPPORTED_CATEGORY,
    ERROR_UNKNOWN,
    FINDING_CORRELATION_RESULT_RULE_VERSION,
    MAX_CLUSTERS,
    MAX_FINDINGS,
    SKIP_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED,
    SKIP_MALFORMED_FINDING,
    SKIP_NON_RESEARCH_ONLY,
    SKIP_UNSAFE_CONFIRMATION,
    SKIP_UNSUPPORTED_CATEGORY,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_RELATIONSHIPS,
    STATUS_PARTIAL,
    FindingCorrelationClusterPlan,
    FindingCorrelationResultPlan,
    finding_correlation_result_plan_projection,
    sanitize_correlation_error,
    sanitize_correlation_skip,
)
from ai.schemas.finding_evidence import COMPLETENESS_COMPLETE
from ai.schemas.finding_result import (
    FINDING_RESULT_RULE_VERSION,
    sanitize_finding,
)
from ai.schemas.multi_agent_collaboration_result import (
    GOVERNANCE_CONSISTENT_REFERENCED,
    GOVERNANCE_MIXED,
    GOVERNANCE_UNKNOWN,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES, CATEGORY_UNKNOWN

FINDING_CORRELATION_BUILDER_RULE_VERSION = "r54-4"
RULE_VERSION = FINDING_CORRELATION_BUILDER_RULE_VERSION

SUPPORTED_CATEGORIES: tuple[str, ...] = tuple(
    category for category in AGENT_CATEGORIES if category != CATEGORY_UNKNOWN
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_CONFIDENCE_NOT_UPGRADED,
)

_SKIP_TO_ERROR: dict[str, str] = {
    SKIP_MALFORMED_FINDING: ERROR_MALFORMED_FINDING,
    SKIP_UNSUPPORTED_CATEGORY: ERROR_UNSUPPORTED_CATEGORY,
    SKIP_UNSAFE_CONFIRMATION: ERROR_SAFETY_BLOCKED,
    SKIP_NON_RESEARCH_ONLY: ERROR_SAFETY_BLOCKED,
    SKIP_DUPLICATE_IDENTITY: ERROR_DUPLICATE_IDENTITY,
    SKIP_LIMIT_EXCEEDED: ERROR_LIMIT_EXCEEDED,
}


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _error(
    error_category: str,
    finding_id: str = "",
    category: str = "",
    message: str = "",
) -> dict:
    return sanitize_correlation_error(
        {
            "stage": "FINDING_CORRELATION",
            "error_category": error_category,
            "finding_id": finding_id,
            "category": category,
            "message": message,
        }
    )


def _skip(
    finding_id: str, category: str, agent_id: str, reason: str
) -> dict:
    return sanitize_correlation_skip(
        {
            "finding_id": finding_id,
            "category": category,
            "agent_id": agent_id,
            "reason": reason,
        }
    )


def _ordered_limitations(codes: list[str]) -> list[str]:
    return [code for code in CORRELATION_LIMITATIONS if code in codes]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _raw_finding_safety(raw: object) -> str:
    """Fail-closed safety check on the raw finding before sanitization."""

    if not isinstance(raw, dict):
        return SKIP_MALFORMED_FINDING
    raw_research_only = raw.get("research_only")
    if raw_research_only is not None and raw_research_only is not True:
        return SKIP_NON_RESEARCH_ONLY
    identity = raw.get("identity")
    if isinstance(identity, dict):
        category = _upper(identity.get("category"))
        if category and category not in SUPPORTED_CATEGORIES:
            return SKIP_UNSUPPORTED_CATEGORY
    assessment = raw.get("assessment")
    if isinstance(assessment, dict):
        confirmation = _upper(assessment.get("confirmation_state"))
        if confirmation and confirmation != CONFIRMATION_NOT_CONFIRMED:
            return SKIP_UNSAFE_CONFIRMATION
    return ""


def _normalize_finding(raw: object) -> tuple[dict, dict, str]:
    """Sanitize one finding and derive its correlation reference + facts."""

    reason = _raw_finding_safety(raw)
    if reason:
        return {}, {}, reason
    sanitized = sanitize_finding(raw)
    identity = sanitized.get("identity") or {}
    finding_id = _text(identity.get("finding_id"))
    category = _upper(identity.get("category"))
    if (
        sanitized.get("rule_version") != FINDING_RESULT_RULE_VERSION
        or not finding_id
        or not category
    ):
        return {}, {}, SKIP_MALFORMED_FINDING
    if category not in SUPPORTED_CATEGORIES:
        return {}, {}, SKIP_UNSUPPORTED_CATEGORY
    ref = _finding_reference(sanitized)
    facts = finding_facts(sanitized)
    facts["governance_ready"] = (
        _upper((sanitized.get("governance") or {}).get("ready")) == "TRUE"
    )
    return ref, facts, ""


def _finding_reference(sanitized: dict) -> dict:
    identity = sanitized.get("identity") or {}
    context = sanitized.get("context") or {}
    evidence = sanitized.get("evidence") or {}
    assessment = sanitized.get("assessment") or {}
    hypotheses = sanitized.get("hypotheses") or {}
    provenance = sanitized.get("provenance") or {}
    governance = sanitized.get("governance") or {}
    component = context.get("endpoint_component") or {}
    planned = list(evidence.get("planned_requirements") or ())
    merged = [
        _upper(item.get("evidence_category"))
        for item in evidence.get("merged_requirements") or ()
        if isinstance(item, dict) and _upper(item.get("evidence_category"))
    ]
    requirement_count = len(
        {item for item in planned if item} | set(merged)
    )
    plan = FindingReferencePlan(
        rule_version=FINDING_CORRELATION_RULE_VERSION,
        finding_id=identity.get("finding_id"),
        finding_rule_version=_text(sanitized.get("rule_version")),
        category=identity.get("category"),
        specialist_name=_text(identity.get("specialist_name")),
        agent_id=_text(identity.get("agent_id")),
        state=_upper(sanitized.get("state")),
        confirmation_state=_upper(assessment.get("confirmation_state"))
        or CONFIRMATION_NOT_CONFIRMED,
        confidence=_upper(assessment.get("confidence")) or "UNKNOWN",
        evidence_state=_upper(evidence.get("evidence_state")) or "UNKNOWN",
        evidence_completeness=_upper(
            evidence.get("evidence_completeness")
        )
        or "UNKNOWN",
        evidence_origin=_upper(evidence.get("evidence_origin"))
        or "UNKNOWN",
        context_fact_count=context.get("context_fact_count") or 0,
        hypothesis_count=hypotheses.get("hypothesis_count") or 0,
        evidence_requirement_count=requirement_count,
        component_name=_text(component.get("component_name")),
        component_version=_text(component.get("component_version")),
        endpoint_reference=_text(component.get("endpoint_reference")),
        orchestration_id=_text(provenance.get("orchestration_id")),
        governance_state=_upper(governance.get("reference_state"))
        or "UNKNOWN",
    )
    return plan.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Relationships and clusters
# ---------------------------------------------------------------------------


def _relationship_id(
    relationship_type: str,
    source_id: str,
    target_id: str,
    signals: list[str],
) -> str:
    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": FINDING_CORRELATION_RULE_VERSION,
                "relationship_type": relationship_type,
                "source_finding_id": source_id,
                "target_finding_id": target_id,
                "signals": list(signals),
            }
        ).encode("utf-8")
    ).hexdigest()
    return RELATIONSHIP_ID_PREFIX + digest[:16]


def _relationship_limitations(
    analysis: dict, first: dict, second: dict
) -> list[str]:
    relationship_type = analysis["relationship_type"]
    limitations = list(_BASE_LIMITATIONS)
    if relationship_type == RELATIONSHIP_UNKNOWN:
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)
    if relationship_type == RELATIONSHIP_CONFLICTING:
        limitations.append(LIMITATION_CONFLICT_PRESENT)
    if relationship_type == RELATIONSHIP_DUPLICATE:
        limitations.append(LIMITATION_DUPLICATE_RELATIONSHIP)
    if (
        analysis["shared_context_values"]
        or analysis["shared_hypothesis_types"]
        or analysis["shared_hypothesis_signals"]
        or analysis["shared_evidence_requirements"]
        or analysis["shared_component_name"]
        or analysis["shared_endpoint_reference"]
    ):
        limitations.append(LIMITATION_SHARED_CONTEXT)
    if (
        _upper(first.get("evidence_completeness"))
        != COMPLETENESS_COMPLETE
        or _upper(second.get("evidence_completeness"))
        != COMPLETENESS_COMPLETE
    ):
        limitations.append(LIMITATION_EVIDENCE_INCOMPLETE)
    if not first.get("orchestration_id") and not second.get(
        "orchestration_id"
    ):
        limitations.append(LIMITATION_PROVENANCE_UNAVAILABLE)
    if (
        _upper(first.get("governance_state")) != "REFERENCED"
        and _upper(second.get("governance_state")) != "REFERENCED"
    ):
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)
    return _ordered_limitations(limitations)


def _build_relationship(first: dict, second: dict) -> dict:
    analysis = analyze_pair(first, second)
    source, target = (
        (first, second)
        if first["finding_id"] <= second["finding_id"]
        else (second, first)
    )
    plan = FindingRelationshipPlan(
        rule_version=FINDING_CORRELATION_RULE_VERSION,
        relationship_id=_relationship_id(
            analysis["relationship_type"],
            source["finding_id"],
            target["finding_id"],
            analysis["signals"],
        ),
        relationship_type=analysis["relationship_type"],
        source_finding_id=source["finding_id"],
        target_finding_id=target["finding_id"],
        source_agent_id=source.get("agent_id") or "",
        target_agent_id=target.get("agent_id") or "",
        signals=analysis["signals"],
        score=analysis["score"],
        shared_context_values=analysis["shared_context_values"],
        shared_hypothesis_types=analysis["shared_hypothesis_types"],
        shared_hypothesis_signals=analysis["shared_hypothesis_signals"],
        shared_evidence_requirements=(
            analysis["shared_evidence_requirements"]
        ),
        shared_component_name=analysis["shared_component_name"],
        shared_endpoint_reference=analysis[
            "shared_endpoint_reference"
        ],
        conflict_details=analysis["conflict_details"],
        confidence_effect="NONE",
        limitations=_relationship_limitations(analysis, first, second),
        research_only=True,
    )
    return plan.model_dump(mode="json")


def _cluster_id(
    relationship_type: str, members: list[str], signals: list[str]
) -> str:
    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": FINDING_CORRELATION_RESULT_RULE_VERSION,
                "relationship_type": relationship_type,
                "member_finding_ids": list(members),
                "signals": list(signals),
            }
        ).encode("utf-8")
    ).hexdigest()
    return CLUSTER_ID_PREFIX + digest[:16]


def _build_clusters(
    facts: list[dict], relationships: list[dict]
) -> list[dict]:
    """Deterministic clusters (R43 semantics: singleton RELATED merges)."""

    index_of = {
        fact["finding_id"]: index for index, fact in enumerate(facts)
    }
    size = len(facts)
    parent = list(range(size))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int) -> None:
        root_first = find(first)
        root_second = find(second)
        if root_first != root_second:
            parent[max(root_first, root_second)] = min(
                root_first, root_second
            )

    pair_types: dict[tuple[int, int], str] = {}
    pair_signals: dict[tuple[int, int], list[str]] = {}
    pair_shared: dict[tuple[int, int], dict] = {}
    for relationship in relationships:
        first = index_of.get(relationship["source_finding_id"])
        second = index_of.get(relationship["target_finding_id"])
        if first is None or second is None:
            continue
        key = (min(first, second), max(first, second))
        pair_types[key] = relationship["relationship_type"]
        pair_signals[key] = list(relationship["signals"])
        pair_shared[key] = {
            "context": relationship["shared_context_values"],
            "hypothesis_types": relationship["shared_hypothesis_types"],
            "evidence": relationship["shared_evidence_requirements"],
        }

    for (first, second), relationship_type in sorted(pair_types.items()):
        if relationship_type in (
            RELATIONSHIP_DUPLICATE,
            RELATIONSHIP_CONFLICTING,
        ):
            union(first, second)
    for (first, second), relationship_type in sorted(pair_types.items()):
        if relationship_type != RELATIONSHIP_RELATED:
            continue
        root_first = find(first)
        root_second = find(second)
        if root_first == root_second:
            continue
        first_size = sum(
            1 for index in range(size) if find(index) == root_first
        )
        second_size = sum(
            1 for index in range(size) if find(index) == root_second
        )
        if first_size == 1 and second_size == 1:
            union(first, second)

    members_by_root: dict[int, list[int]] = {}
    for index in range(size):
        members_by_root.setdefault(find(index), []).append(index)

    clusters: list[dict] = []
    for root in sorted(members_by_root):
        indexes = members_by_root[root]
        if len(indexes) < 2:
            continue
        inner_keys = [
            (first, second)
            for first in indexes
            for second in indexes
            if first < second and (first, second) in pair_types
        ]
        inner_types = [pair_types[key] for key in inner_keys]
        if not inner_types:
            continue
        relationship_type = max(
            inner_types,
            key=lambda item: RELATIONSHIP_PRECEDENCE.get(item, 0),
        )
        signals: list[str] = []
        for key in inner_keys:
            for signal in pair_signals.get(key) or ():
                if signal not in signals:
                    signals.append(signal)
        members = sorted(
            facts[index]["finding_id"] for index in indexes
        )
        shared_context: list[dict] = []
        first_shared = pair_shared.get(inner_keys[0], {}).get(
            "context"
        ) or []
        for value in first_shared:
            if all(
                value
                in (pair_shared.get(key, {}).get("context") or [])
                for key in inner_keys
            ):
                shared_context.append(value)

        hypotheses_sets = [
            set(facts[index].get("hypothesis_types") or ())
            for index in indexes
        ]
        shared_hypotheses = sorted(
            set.intersection(*hypotheses_sets) if hypotheses_sets else set()
        )
        evidence_sets = [
            set(facts[index].get("evidence_requirements") or ())
            for index in indexes
        ]
        shared_evidence = sorted(
            set.intersection(*evidence_sets) if evidence_sets else set()
        )

        limitations = list(_BASE_LIMITATIONS)
        if relationship_type == RELATIONSHIP_CONFLICTING:
            limitations.append(LIMITATION_CONFLICT_PRESENT)
        if relationship_type == RELATIONSHIP_DUPLICATE:
            limitations.append(LIMITATION_DUPLICATE_RELATIONSHIP)
        if shared_context or shared_hypotheses or shared_evidence:
            limitations.append(LIMITATION_SHARED_CONTEXT)
        if any(
            _upper(facts[index].get("evidence_completeness"))
            != COMPLETENESS_COMPLETE
            for index in indexes
        ):
            limitations.append(LIMITATION_EVIDENCE_INCOMPLETE)
        if not any(
            facts[index].get("orchestration_id") for index in indexes
        ):
            limitations.append(LIMITATION_PROVENANCE_UNAVAILABLE)
        if not any(
            _upper(facts[index].get("governance_state")) == "REFERENCED"
            for index in indexes
        ):
            limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)

        plan = FindingCorrelationClusterPlan(
            rule_version=FINDING_CORRELATION_RESULT_RULE_VERSION,
            cluster_id=_cluster_id(
                relationship_type, members, signals
            ),
            relationship_type=relationship_type,
            member_finding_ids=members,
            cluster_size=len(members),
            signals=signals,
            shared_context_values=shared_context,
            shared_hypothesis_types=shared_hypotheses,
            shared_evidence_requirements=shared_evidence,
            confidence_effect="NONE",
            limitations=_ordered_limitations(limitations),
            research_only=True,
        )
        clusters.append(plan.model_dump(mode="json"))

    clusters.sort(
        key=lambda cluster: (
            -RELATIONSHIP_PRECEDENCE.get(
                cluster["relationship_type"], 0
            ),
            cluster["cluster_id"],
        )
    )
    return clusters[:MAX_CLUSTERS]


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


def _governance_summary(
    facts: list[dict],
) -> dict:
    referenced: list[str] = []
    unknown: list[str] = []
    ready: list[str] = []
    not_ready: list[str] = []
    for fact in facts:
        finding_id = fact["finding_id"]
        if _upper(fact.get("governance_state")) == "REFERENCED":
            referenced.append(finding_id)
            if fact.get("governance_ready"):
                ready.append(finding_id)
            else:
                not_ready.append(finding_id)
        else:
            unknown.append(finding_id)
    if referenced and unknown:
        state = GOVERNANCE_MIXED
    elif referenced:
        state = GOVERNANCE_CONSISTENT_REFERENCED
    else:
        state = GOVERNANCE_UNKNOWN
    return {
        "governance_state": state,
        "referenced_finding_ids": referenced,
        "unknown_finding_ids": unknown,
        "ready_finding_ids": ready,
        "not_ready_finding_ids": not_ready,
        "research_only": True,
    }


def _correlation_id(
    facts: list[dict],
    relationships: list[dict],
    clusters: list[dict],
) -> str:
    digest = hashlib.sha256(
        _canonical(
            {
                "rule_version": FINDING_CORRELATION_RESULT_RULE_VERSION,
                "findings": [
                    {
                        "finding_id": fact["finding_id"],
                        "state": fact.get("state"),
                        "confidence": fact.get("confidence"),
                    }
                    for fact in sorted(
                        facts, key=lambda item: item["finding_id"]
                    )
                ],
                "relationships": [
                    {
                        "source_finding_id": item["source_finding_id"],
                        "target_finding_id": item["target_finding_id"],
                        "relationship_type": item["relationship_type"],
                        "signals": item["signals"],
                    }
                    for item in relationships
                ],
                "clusters": [
                    {
                        "cluster_id": item["cluster_id"],
                        "member_finding_ids": item["member_finding_ids"],
                    }
                    for item in clusters
                ],
            }
        ).encode("utf-8")
    ).hexdigest()
    return CORRELATION_ID_PREFIX + digest[:16]


def _container(
    *,
    facts: list[dict],
    relationships: list[dict],
    clusters: list[dict],
    skipped: list[dict],
    errors: list[dict],
    fatal: bool = False,
) -> dict:
    if fatal:
        status = STATUS_FAILED
    elif len(facts) < 2:
        status = STATUS_NO_RELATIONSHIPS
    elif errors or skipped:
        status = STATUS_PARTIAL
    else:
        status = STATUS_COMPLETED

    ordered_relationships = sorted(
        relationships,
        key=lambda item: (
            -RELATIONSHIP_PRECEDENCE.get(item["relationship_type"], 0),
            item["source_finding_id"],
            item["target_finding_id"],
        ),
    )
    ordered_facts = sorted(facts, key=lambda item: item["finding_id"])

    limitations = list(_BASE_LIMITATIONS)
    if len(facts) < 2:
        limitations.append(LIMITATION_CORRELATION_UNAVAILABLE)
    if any(
        item["relationship_type"] == RELATIONSHIP_CONFLICTING
        for item in ordered_relationships
    ):
        limitations.append(LIMITATION_CONFLICT_PRESENT)
    if any(
        item["relationship_type"] == RELATIONSHIP_DUPLICATE
        for item in ordered_relationships
    ):
        limitations.append(LIMITATION_DUPLICATE_RELATIONSHIP)
    if any(
        item["relationship_type"]
        in (RELATIONSHIP_RELATED, RELATIONSHIP_DUPLICATE)
        for item in ordered_relationships
    ):
        limitations.append(LIMITATION_SHARED_CONTEXT)
    if any(
        item["relationship_type"] == RELATIONSHIP_UNKNOWN
        for item in ordered_relationships
    ):
        limitations.append(LIMITATION_INSUFFICIENT_CONTEXT)
    if any(
        _upper(fact.get("evidence_completeness"))
        != COMPLETENESS_COMPLETE
        for fact in ordered_facts
    ):
        limitations.append(LIMITATION_EVIDENCE_INCOMPLETE)
    if not any(fact.get("orchestration_id") for fact in ordered_facts):
        limitations.append(LIMITATION_PROVENANCE_UNAVAILABLE)
    governance = _governance_summary(ordered_facts)
    if governance["governance_state"] == GOVERNANCE_UNKNOWN:
        limitations.append(LIMITATION_GOVERNANCE_UNKNOWN)

    finding_rule_versions = sorted(
        {
            _text(fact.get("finding_rule_version"))
            for fact in ordered_facts
            if _text(fact.get("finding_rule_version"))
        }
    )
    plan = FindingCorrelationResultPlan(
        rule_version=FINDING_CORRELATION_RESULT_RULE_VERSION,
        correlation_rule_version=FINDING_CORRELATION_RESULT_RULE_VERSION,
        relationship_rule_version=FINDING_CORRELATION_RULE_VERSION,
        correlation_id=_correlation_id(
            ordered_facts, ordered_relationships, clusters
        ),
        status=status,
        finding_references=[
            fact["reference"] for fact in ordered_facts
        ],
        relationships=ordered_relationships,
        clusters=clusters,
        skipped_findings=skipped,
        errors=errors,
        provenance={
            "rule_version": FINDING_CORRELATION_RESULT_RULE_VERSION,
            "finding_rule_version": (
                finding_rule_versions[0]
                if len(finding_rule_versions) == 1
                else ""
            ),
            "orchestration_ids": sorted(
                {
                    _text(fact.get("orchestration_id"))
                    for fact in ordered_facts
                    if _text(fact.get("orchestration_id"))
                }
            ),
            "finding_count": len(ordered_facts),
            "relationship_count": len(ordered_relationships),
            "cluster_count": len(clusters),
            "source_categories": sorted(
                {
                    _upper(fact.get("category"))
                    for fact in ordered_facts
                    if _upper(fact.get("category"))
                }
            ),
            "source_agent_ids": sorted(
                {
                    _text(fact.get("agent_id"))
                    for fact in ordered_facts
                    if _text(fact.get("agent_id"))
                }
            ),
            "deterministic": True,
            "research_only": True,
        },
        governance_summary=governance,
        limitations=_ordered_limitations(limitations),
        confidence_effect="NONE",
        research_only=True,
        deterministic=True,
    )
    return finding_correlation_result_plan_projection(plan)


def _fatal_result(errors: list[dict]) -> dict:
    return _container(
        facts=[],
        relationships=[],
        clusters=[],
        skipped=[],
        errors=errors,
        fatal=True,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate(
    finding_intelligence: object = None,
    findings: object = None,
) -> dict:
    """Correlate structured R53 findings deterministically (read-only).

    Supply either one R53 finding-intelligence result or a standalone list of
    R53 findings. Supplying both (or an ambiguous input) fails closed with
    ``INVALID_INPUT``. R54 preserves every finding: it classifies
    relationships and clusters without merging, rewriting or deleting
    anything.
    """

    # ------------------------------------------------------------------
    # Input validation (fail closed)
    # ------------------------------------------------------------------
    if finding_intelligence is not None and not isinstance(
        finding_intelligence, dict
    ):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="finding_intelligence must be a mapping",
                )
            ]
        )
    if findings is not None and not isinstance(findings, (list, tuple)):
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message="findings must be a list",
                )
            ]
        )
    if finding_intelligence is not None and findings is not None:
        return _fatal_result(
            [
                _error(
                    ERROR_INVALID_INPUT,
                    message=(
                        "supply either finding_intelligence or findings, "
                        "not both"
                    ),
                )
            ]
        )

    if finding_intelligence is not None:
        rule_version = _text(finding_intelligence.get("rule_version"))
        if rule_version != FINDING_RESULT_RULE_VERSION:
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message=(
                            "finding_intelligence is not an R53 result"
                        ),
                    )
                ]
            )
        raw_findings = finding_intelligence.get("findings")
        if not isinstance(raw_findings, (list, tuple)):
            return _fatal_result(
                [
                    _error(
                        ERROR_INVALID_INPUT,
                        message="finding_intelligence.findings must be a "
                        "list",
                    )
                ]
            )
    else:
        raw_findings = list(findings or [])

    # ------------------------------------------------------------------
    # Normalize findings (stable finding ids; no list-position identity)
    # ------------------------------------------------------------------
    facts: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    seen_ids: list[str] = []

    for raw in raw_findings:
        reference, fact, reason = _normalize_finding(raw)
        raw_dict = raw if isinstance(raw, dict) else {}
        raw_identity = raw_dict.get("identity") or {}
        finding_id = _text(raw_identity.get("finding_id")) or _text(
            reference.get("finding_id")
        )
        category = _upper(raw_identity.get("category")) or _text(
            reference.get("category")
        )
        agent_id = _text(raw_identity.get("agent_id")) or _text(
            reference.get("agent_id")
        )
        if reason:
            skipped.append(
                _skip(finding_id, category, agent_id, reason)
            )
            errors.append(
                _error(
                    _SKIP_TO_ERROR.get(reason, ERROR_UNKNOWN),
                    finding_id,
                    category,
                    "finding is not a supported correlation source",
                )
            )
            continue
        if finding_id in seen_ids:
            skipped.append(
                _skip(
                    finding_id,
                    category,
                    agent_id,
                    SKIP_DUPLICATE_IDENTITY,
                )
            )
            errors.append(
                _error(
                    ERROR_DUPLICATE_IDENTITY,
                    finding_id,
                    category,
                    "the same finding identity was supplied twice",
                )
            )
            continue
        if len(facts) >= MAX_FINDINGS:
            skipped.append(
                _skip(
                    finding_id,
                    category,
                    agent_id,
                    SKIP_LIMIT_EXCEEDED,
                )
            )
            errors.append(
                _error(
                    ERROR_LIMIT_EXCEEDED,
                    finding_id,
                    category,
                    "finding limit reached",
                )
            )
            continue
        seen_ids.append(finding_id)
        fact["reference"] = reference
        facts.append(fact)

    # Canonical order by stable finding id (never by list position).
    facts.sort(key=lambda item: item["finding_id"])

    # ------------------------------------------------------------------
    # Pairwise relationships and clusters
    # ------------------------------------------------------------------
    relationships: list[dict] = []
    for first in range(len(facts)):
        for second in range(first + 1, len(facts)):
            relationships.append(
                _build_relationship(facts[first], facts[second])
            )
    clusters = _build_clusters(facts, relationships)

    return _container(
        facts=facts,
        relationships=relationships,
        clusters=clusters,
        skipped=skipped,
        errors=errors,
    )


def correlate_finding_intelligence(
    finding_intelligence: object = None,
) -> dict:
    """Alias: correlate one R53 finding-intelligence result."""

    return correlate(finding_intelligence=finding_intelligence)


def correlate_findings(findings: object = None) -> dict:
    """Alias: correlate a standalone list of R53 findings."""

    return correlate(findings=findings)


def export_finding_correlation(
    finding_intelligence: object = None,
    findings: object = None,
) -> dict:
    """Alias for :func:`correlate` (project naming pattern)."""

    return correlate(
        finding_intelligence=finding_intelligence,
        findings=findings,
    )


__all__ = [
    "FINDING_CORRELATION_BUILDER_RULE_VERSION",
    "RULE_VERSION",
    "SUPPORTED_CATEGORIES",
    "correlate",
    "correlate_finding_intelligence",
    "correlate_findings",
    "export_finding_correlation",
]
