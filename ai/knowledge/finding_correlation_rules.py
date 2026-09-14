"""Stage R54.3 deterministic finding correlation rules (pure engine).

Classifies the relationship between two R53 research findings and derives
the bounded, interpretable correlation signals:

    "How are these two structured findings related?"

Hard boundaries encoded here:

- Research correlation only: relationships describe structured research
  artifacts. They never confirm a vulnerability, never execute anything and
  never merge, rewrite or delete findings.
- Reused vocabulary: relationship types reuse the R43 correlation vocabulary
  and conflict types reuse the R43 collaboration-conflict vocabulary.
- Conservative: conflicts require explicitly contradictory observations or
  explicit R43 conflict semantics; confidence disagreement alone never
  produces ``CONFLICTING``. Generic technology names never create a
  relationship. Insufficient structure yields ``UNKNOWN``, never a guess.
- No confidence inflation: correlation signals never modify finding
  confidence; the score is a bounded explainability aid derived only from
  declared signal weights.
- Deterministic: identical findings always produce identical signals,
  classifications and scores.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no subprocess, no
  browser, no scanner, no wall-clock time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.collaboration_conflict_analyzer import EVIDENCE_BANDS
from ai.schemas.collaboration_conflict import (
    CONFLICT_CONFIDENCE,
    CONFLICT_CONTEXT,
    CONFLICT_EVIDENCE_STATE,
    CONFLICT_GOVERNANCE,
    CONFLICT_HYPOTHESIS,
    CONFLICT_PROVENANCE,
    CONFLICT_SAFETY,
)
from ai.schemas.finding_correlation import (
    CORRELATION_SIGNALS,
    MAX_RELATIONSHIP_SCORE,
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_INDEPENDENT,
    RELATIONSHIP_RELATED,
    RELATIONSHIP_UNKNOWN,
    SIGNAL_CATEGORY_FAMILY,
    SIGNAL_CONFIDENCE_CONFLICT,
    SIGNAL_CONFIDENCE_DIVERGENCE,
    SIGNAL_CONTEXT_CONFLICT,
    SIGNAL_EVIDENCE_STATE_CONFLICT,
    SIGNAL_EVIDENCE_STATE_DIVERGENCE,
    SIGNAL_IDENTICAL_FINDING_ID,
    SIGNAL_INSUFFICIENT_STRUCTURE,
    SIGNAL_NO_SHARED_SIGNAL,
    SIGNAL_R43_MATERIAL_CONFLICT,
    SIGNAL_R43_RELATED_GROUP,
    SIGNAL_SAME_AGENT,
    SIGNAL_SAME_CATEGORY,
    SIGNAL_SAME_ORCHESTRATION,
    SIGNAL_SHARED_COMPONENT,
    SIGNAL_SHARED_CONTEXT_VALUE,
    SIGNAL_SHARED_ENDPOINT,
    SIGNAL_SHARED_EVIDENCE_REQUIREMENT,
    SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT,
    SIGNAL_SHARED_HYPOTHESIS_SIGNAL,
    SIGNAL_SHARED_HYPOTHESIS_TYPE,
    SIGNAL_WEIGHTS,
)
from ai.schemas.hypothesis_correlation import CONFIDENCE_BANDS

FINDING_CORRELATION_RULES_RULE_VERSION = "r54-3"
RULE_VERSION = FINDING_CORRELATION_RULES_RULE_VERSION

#: Context keys that are too generic to establish relatedness or conflict on
#: their own (research confidence and the generic input location).
GENERIC_CONTEXT_KEYS: frozenset[str] = frozenset(
    {"context_confidence", "input_location"}
)

#: Hypothesis signal prefixes that mirror generic context facts (input
#: location) and are too generic to establish relatedness on their own.
GENERIC_HYPOTHESIS_SIGNAL_PREFIXES: tuple[str, ...] = ("INPUT_",)

#: Fixed authorization/authentication/API family. Family membership is a
#: supporting signal only: it never creates a relationship by itself.
AUTHORIZATION_FAMILY: frozenset[str] = frozenset(
    {"IDOR", "JWT", "OAUTH", "RECON"}
)

CATEGORY_FAMILIES: tuple[frozenset[str], ...] = (AUTHORIZATION_FAMILY,)

#: R43 conflict types that are material on their own.
MATERIAL_CONFLICT_TYPES_ALWAYS: frozenset[str] = frozenset(
    {CONFLICT_CONTEXT, CONFLICT_SAFETY}
)

#: R43 conflict types that are material only with an UNRESOLVED resolution;
#: RECONCILABLE/UNKNOWN resolutions stay divergence signals.
MATERIAL_CONFLICT_TYPES_UNRESOLVED: frozenset[str] = frozenset(
    {CONFLICT_CONFIDENCE, CONFLICT_HYPOTHESIS, CONFLICT_EVIDENCE_STATE}
)

#: R43 conflict types that are never material for a finding-level conflict;
#: they record completeness/consistency differences instead.
NON_MATERIAL_CONFLICT_TYPES: frozenset[str] = frozenset(
    {CONFLICT_GOVERNANCE, CONFLICT_PROVENANCE}
)

MATERIAL_CONFLICT_TYPES: frozenset[str] = (
    MATERIAL_CONFLICT_TYPES_ALWAYS | MATERIAL_CONFLICT_TYPES_UNRESOLVED
)

R43_RELATED_GROUP_TYPE = "RELATED"
R43_DUPLICATE_GROUP_TYPE = "DUPLICATE"

MATERIAL_RESOLUTION = "UNRESOLVED"


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _string_list(value: object, limit: int = 24) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _text(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _band(table: dict, value: object) -> int:
    return table.get(_upper(value), 0)


def _confidence_band(value: object) -> int:
    return CONFIDENCE_BANDS.get(_upper(value), 0)


def _evidence_band(value: object) -> int:
    return EVIDENCE_BANDS.get(_upper(value), 0)


# ---------------------------------------------------------------------------
# Finding fact normalization
# ---------------------------------------------------------------------------


def finding_facts(finding: object) -> dict:
    """Normalize one sanitized R53 finding into deterministic comparison facts.

    Read-only: no value is inferred and no input is mutated.
    """

    if not isinstance(finding, dict):
        finding = {}
    identity = finding.get("identity") or {}
    assessment = finding.get("assessment") or {}
    context = finding.get("context") or {}
    evidence = finding.get("evidence") or {}
    hypotheses = finding.get("hypotheses") or {}
    correlation = finding.get("correlation") or {}
    provenance = finding.get("provenance") or {}
    governance = finding.get("governance") or {}

    context_values: dict[str, str] = {}
    for fact in context.get("affected_context") or ():
        if not isinstance(fact, dict):
            continue
        key = _text(fact.get("key"))
        value = _text(fact.get("value"))
        if key and key not in GENERIC_CONTEXT_KEYS and value:
            context_values[key] = value

    references = [
        item
        for item in hypotheses.get("references") or ()
        if isinstance(item, dict)
    ]
    hypothesis_types = [
        _upper(item.get("hypothesis_type"))
        for item in references
        if _upper(item.get("hypothesis_type"))
        and _upper(item.get("hypothesis_type")) != "UNKNOWN"
    ]
    hypothesis_fingerprints = [
        _text(item.get("fingerprint"))
        for item in references
        if _text(item.get("fingerprint"))
    ]
    hypothesis_signals: list[str] = []
    for item in references:
        for signal in item.get("supporting_signals") or ():
            text = _upper(signal)
            if (
                text
                and "UNKNOWN" not in text
                and not text.startswith(GENERIC_HYPOTHESIS_SIGNAL_PREFIXES)
                and text not in hypothesis_signals
            ):
                hypothesis_signals.append(text)

    evidence_requirements: list[str] = []
    for item in evidence.get("planned_requirements") or ():
        text = _upper(item)
        if text and text != "UNKNOWN" and text not in evidence_requirements:
            evidence_requirements.append(text)
    for item in evidence.get("merged_requirements") or ():
        if not isinstance(item, dict):
            continue
        text = _upper(item.get("evidence_category"))
        if text and text != "UNKNOWN" and text not in evidence_requirements:
            evidence_requirements.append(text)

    component = context.get("endpoint_component") or {}
    conflicts: list[dict] = []
    for item in correlation.get("conflicts") or ():
        if not isinstance(item, dict):
            continue
        conflicts.append(
            {
                "conflict_type": _upper(item.get("conflict_type")),
                "resolution_state": _upper(item.get("resolution_state")),
                "subjects": _string_list(item.get("subjects")),
                "conflicting_fields": _string_list(
                    item.get("conflicting_fields")
                ),
            }
        )
    related_agents: list[str] = []
    duplicate_agents: list[str] = []
    for group in correlation.get("groups") or ():
        if not isinstance(group, dict):
            continue
        group_type = _upper(group.get("correlation_type"))
        for agent in group.get("participating_agents") or ():
            text = _text(agent)
            if not text:
                continue
            if group_type == R43_RELATED_GROUP_TYPE and (
                text not in related_agents
            ):
                related_agents.append(text)
            if group_type == R43_DUPLICATE_GROUP_TYPE and (
                text not in duplicate_agents
            ):
                duplicate_agents.append(text)

    component_name = _upper(component.get("component_name"))
    endpoint_reference = _upper(component.get("endpoint_reference"))
    component_version = _text(component.get("component_version"))

    has_structure = bool(
        context_values
        or hypothesis_types
        or hypothesis_fingerprints
        or evidence_requirements
        or component_name
        or endpoint_reference
    )

    return {
        "finding_id": _text(identity.get("finding_id")),
        "category": _upper(identity.get("category")),
        "specialist_name": _text(identity.get("specialist_name")),
        "agent_id": _text(identity.get("agent_id")),
        "state": _upper(finding.get("state")),
        "confidence": _upper(assessment.get("confidence")) or "UNKNOWN",
        "status": _upper(assessment.get("state")) or _upper(
            finding.get("state")
        ),
        "evidence_state": _upper(evidence.get("evidence_state")) or "UNKNOWN",
        "evidence_completeness": (
            _upper(evidence.get("evidence_completeness")) or "UNKNOWN"
        ),
        "evidence_origin": _upper(evidence.get("evidence_origin"))
        or "UNKNOWN",
        "context_values": context_values,
        "hypothesis_types": hypothesis_types,
        "hypothesis_fingerprints": hypothesis_fingerprints,
        "hypothesis_signals": hypothesis_signals,
        "evidence_requirements": evidence_requirements,
        "component_name": component_name,
        "component_version": component_version,
        "endpoint_reference": endpoint_reference,
        "orchestration_id": _text(provenance.get("orchestration_id")),
        "conflicts": conflicts,
        "related_agents": related_agents,
        "duplicate_agents": duplicate_agents,
        "governance_state": _upper(governance.get("reference_state"))
        or "UNKNOWN",
        "finding_rule_version": _text(finding.get("rule_version")),
        "has_structure": has_structure,
    }


# ---------------------------------------------------------------------------
# Signal detection
# ---------------------------------------------------------------------------


def _shared(first: list, second: list, limit: int = 12) -> list:
    out: list = []
    for item in first:
        if item in second and item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def _r43_conflict_records(
    first: dict, second: dict
) -> list[dict]:
    """Deduplicated R43 conflict records that reference the other agent."""

    records: list[dict] = []
    for source, other_agent in (
        (first, second["agent_id"]),
        (second, first["agent_id"]),
    ):
        if not other_agent:
            continue
        for record in source.get("conflicts") or ():
            if other_agent not in (record.get("subjects") or ()):
                continue
            key = (
                record.get("conflict_type"),
                record.get("resolution_state"),
                tuple(record.get("conflicting_fields") or ()),
            )
            if any(
                (
                    item.get("conflict_type"),
                    item.get("resolution_state"),
                    tuple(item.get("conflicting_fields") or ()),
                )
                == key
                for item in records
            ):
                continue
            records.append(record)
    return records


def analyze_pair(first: object, second: object) -> dict:
    """Analyze one ordered pair of findings (read-only).

    Both arguments are normalized fact dicts from :func:`finding_facts`.
    The result is a deterministic analysis structure containing the detected
    signals, shared observations, conflict details and the classified
    relationship.
    """

    first = first if isinstance(first, dict) else {}
    second = second if isinstance(second, dict) else {}

    same_id = bool(first.get("finding_id")) and (
        first.get("finding_id") == second.get("finding_id")
    )
    same_category = bool(first.get("category")) and (
        first.get("category") == second.get("category")
    )
    same_agent = bool(first.get("agent_id")) and (
        first.get("agent_id") == second.get("agent_id")
    )
    same_orchestration = bool(first.get("orchestration_id")) and (
        first.get("orchestration_id") == second.get("orchestration_id")
    )

    first_context = first.get("context_values") or {}
    second_context = second.get("context_values") or {}
    shared_context_values = [
        {"key": key, "value": first_context[key]}
        for key in sorted(first_context)
        if key in second_context and first_context[key] == second_context[key]
    ]
    conflicting_context_keys = sorted(
        key
        for key in first_context
        if key in second_context and first_context[key] != second_context[key]
    )

    shared_hypothesis_types = _shared(
        first.get("hypothesis_types") or [],
        second.get("hypothesis_types") or [],
    )
    shared_hypothesis_signals = _shared(
        first.get("hypothesis_signals") or [],
        second.get("hypothesis_signals") or [],
    )
    shared_hypothesis_fingerprints = _shared(
        first.get("hypothesis_fingerprints") or [],
        second.get("hypothesis_fingerprints") or [],
    )
    shared_evidence_requirements = _shared(
        first.get("evidence_requirements") or [],
        second.get("evidence_requirements") or [],
    )

    shared_component_name = ""
    if first.get("component_name") and (
        first.get("component_name") == second.get("component_name")
    ):
        shared_component_name = first["component_name"]
    shared_endpoint_reference = ""
    if first.get("endpoint_reference") and (
        first.get("endpoint_reference") == second.get("endpoint_reference")
    ):
        shared_endpoint_reference = first["endpoint_reference"]

    first_family = _family_of(first.get("category"))
    second_family = _family_of(second.get("category"))
    category_family = bool(
        first_family and second_family and first_family == second_family
    )

    r43_related = bool(
        (second.get("agent_id") and second.get("agent_id")
         in (first.get("related_agents") or ()))
        or (first.get("agent_id") and first.get("agent_id")
            in (second.get("related_agents") or ()))
    )
    r43_duplicate = bool(
        (second.get("agent_id") and second.get("agent_id")
         in (first.get("duplicate_agents") or ()))
        or (first.get("agent_id") and first.get("agent_id")
            in (second.get("duplicate_agents") or ()))
    )

    r43_records = _r43_conflict_records(first, second)
    material_records = [
        record
        for record in r43_records
        if _is_material_conflict(record)
    ]

    evidence_state_gap = abs(
        _evidence_band(first.get("evidence_state"))
        - _evidence_band(second.get("evidence_state"))
    )
    evidence_scope_overlap = bool(
        same_category
        or shared_evidence_requirements
        or shared_context_values
        or conflicting_context_keys
    )
    evidence_state_conflict = bool(
        evidence_state_gap >= 2 and evidence_scope_overlap
    )
    evidence_state_divergence = bool(
        evidence_state_gap >= 2 and not evidence_state_conflict
    )

    confidence_gap = abs(
        _confidence_band(first.get("confidence"))
        - _confidence_band(second.get("confidence"))
    )
    # Confidence disagreement alone never conflicts: it becomes material only
    # with an actual contradictory observation.
    confidence_conflict = bool(
        confidence_gap >= 2 and conflicting_context_keys
    )
    confidence_divergence = bool(
        confidence_gap >= 2
        or any(
            record.get("conflict_type") == CONFLICT_CONFIDENCE
            for record in r43_records
        )
    )

    insufficient = not (
        first.get("has_structure") and second.get("has_structure")
    )

    duplicate = _is_duplicate(
        first,
        second,
        same_id=same_id,
        same_category=same_category,
        same_agent=same_agent,
        r43_duplicate=r43_duplicate,
        shared_hypothesis_fingerprints=shared_hypothesis_fingerprints,
        shared_hypothesis_types=shared_hypothesis_types,
        shared_evidence_requirements=shared_evidence_requirements,
        shared_component_name=shared_component_name,
        shared_endpoint_reference=shared_endpoint_reference,
    )
    related = bool(
        shared_context_values
        or shared_component_name
        or shared_endpoint_reference
        or shared_hypothesis_types
        or shared_hypothesis_signals
        or shared_evidence_requirements
        or r43_related
    )
    conflicting = bool(
        material_records
        or conflicting_context_keys
        or evidence_state_conflict
        or confidence_conflict
    )

    if conflicting:
        relationship_type = RELATIONSHIP_CONFLICTING
    elif duplicate:
        relationship_type = RELATIONSHIP_DUPLICATE
    elif related:
        relationship_type = RELATIONSHIP_RELATED
    elif insufficient:
        relationship_type = RELATIONSHIP_UNKNOWN
    else:
        relationship_type = RELATIONSHIP_INDEPENDENT

    signals = _build_signals(
        same_id=same_id,
        same_category=same_category,
        same_agent=same_agent,
        same_orchestration=same_orchestration,
        shared_hypothesis_fingerprints=shared_hypothesis_fingerprints,
        shared_hypothesis_types=shared_hypothesis_types,
        shared_hypothesis_signals=shared_hypothesis_signals,
        shared_evidence_requirements=shared_evidence_requirements,
        shared_context_values=shared_context_values,
        shared_component_name=shared_component_name,
        shared_endpoint_reference=shared_endpoint_reference,
        category_family=category_family,
        r43_related=r43_related,
        material_records=material_records,
        conflicting_context_keys=conflicting_context_keys,
        evidence_state_conflict=evidence_state_conflict,
        evidence_state_divergence=evidence_state_divergence,
        confidence_conflict=confidence_conflict,
        confidence_divergence=confidence_divergence,
        insufficient=insufficient,
        relationship_type=relationship_type,
    )

    conflict_details = _conflict_details(
        material_records=material_records,
        conflicting_context_keys=conflicting_context_keys,
        evidence_state_conflict=evidence_state_conflict,
        confidence_conflict=confidence_conflict,
        r43_records=r43_records,
    )

    return {
        "relationship_type": relationship_type,
        "signals": signals,
        "score": relational_score(signals),
        "shared_context_values": shared_context_values,
        "shared_hypothesis_types": shared_hypothesis_types,
        "shared_hypothesis_signals": shared_hypothesis_signals,
        "shared_evidence_requirements": shared_evidence_requirements,
        "shared_component_name": shared_component_name,
        "shared_endpoint_reference": shared_endpoint_reference,
        "conflict_details": conflict_details,
        "same_category": same_category,
        "same_agent": same_agent,
        "same_orchestration": same_orchestration,
        "evidence_gap": evidence_state_gap,
        "confidence_gap": confidence_gap,
    }


def _family_of(category: object) -> frozenset[str] | None:
    resolved = _upper(category)
    for family in CATEGORY_FAMILIES:
        if resolved in family:
            return family
    return None


def _is_material_conflict(record: dict) -> bool:
    conflict_type = _upper(record.get("conflict_type"))
    resolution = _upper(record.get("resolution_state"))
    if conflict_type in MATERIAL_CONFLICT_TYPES_ALWAYS:
        return True
    if conflict_type in MATERIAL_CONFLICT_TYPES_UNRESOLVED:
        return resolution == MATERIAL_RESOLUTION
    return False


def _is_duplicate(
    first: dict,
    second: dict,
    *,
    same_id: bool,
    same_category: bool,
    same_agent: bool,
    r43_duplicate: bool,
    shared_hypothesis_fingerprints: list,
    shared_hypothesis_types: list,
    shared_evidence_requirements: list,
    shared_component_name: str,
    shared_endpoint_reference: str,
) -> bool:
    if same_id:
        return True
    if same_category and same_agent:
        return True
    if r43_duplicate:
        return True
    if shared_hypothesis_fingerprints and (
        same_category
        or shared_component_name
        or shared_endpoint_reference
    ):
        return True
    if (
        same_category
        and shared_hypothesis_types
        and shared_evidence_requirements
        and set(first.get("hypothesis_types") or ())
        == set(second.get("hypothesis_types") or ())
        and set(first.get("evidence_requirements") or ())
        == set(second.get("evidence_requirements") or ())
        and (first.get("context_values") or {})
        == (second.get("context_values") or {})
    ):
        return True
    return False


def _build_signals(
    *,
    same_id: bool,
    same_category: bool,
    same_agent: bool,
    same_orchestration: bool,
    shared_hypothesis_fingerprints: list,
    shared_hypothesis_types: list,
    shared_hypothesis_signals: list,
    shared_evidence_requirements: list,
    shared_context_values: list,
    shared_component_name: str,
    shared_endpoint_reference: str,
    category_family: bool,
    r43_related: bool,
    material_records: list,
    conflicting_context_keys: list,
    evidence_state_conflict: bool,
    evidence_state_divergence: bool,
    confidence_conflict: bool,
    confidence_divergence: bool,
    insufficient: bool,
    relationship_type: str,
) -> list[str]:
    detected: list[str] = []
    if same_id:
        detected.append(SIGNAL_IDENTICAL_FINDING_ID)
    if same_category:
        detected.append(SIGNAL_SAME_CATEGORY)
    if same_agent:
        detected.append(SIGNAL_SAME_AGENT)
    if same_orchestration:
        detected.append(SIGNAL_SAME_ORCHESTRATION)
    if shared_hypothesis_fingerprints:
        detected.append(SIGNAL_SHARED_HYPOTHESIS_FINGERPRINT)
    if shared_hypothesis_types:
        detected.append(SIGNAL_SHARED_HYPOTHESIS_TYPE)
    if shared_hypothesis_signals:
        detected.append(SIGNAL_SHARED_HYPOTHESIS_SIGNAL)
    if shared_evidence_requirements:
        detected.append(SIGNAL_SHARED_EVIDENCE_REQUIREMENT)
    if shared_context_values:
        detected.append(SIGNAL_SHARED_CONTEXT_VALUE)
    if shared_component_name:
        detected.append(SIGNAL_SHARED_COMPONENT)
    if shared_endpoint_reference:
        detected.append(SIGNAL_SHARED_ENDPOINT)
    if category_family:
        detected.append(SIGNAL_CATEGORY_FAMILY)
    if r43_related:
        detected.append(SIGNAL_R43_RELATED_GROUP)
    if material_records:
        detected.append(SIGNAL_R43_MATERIAL_CONFLICT)
    if conflicting_context_keys:
        detected.append(SIGNAL_CONTEXT_CONFLICT)
    if evidence_state_conflict:
        detected.append(SIGNAL_EVIDENCE_STATE_CONFLICT)
    elif evidence_state_divergence:
        detected.append(SIGNAL_EVIDENCE_STATE_DIVERGENCE)
    if confidence_conflict:
        detected.append(SIGNAL_CONFIDENCE_CONFLICT)
    elif confidence_divergence:
        detected.append(SIGNAL_CONFIDENCE_DIVERGENCE)
    if insufficient and relationship_type == RELATIONSHIP_UNKNOWN:
        detected.append(SIGNAL_INSUFFICIENT_STRUCTURE)
    if relationship_type == RELATIONSHIP_INDEPENDENT:
        detected.append(SIGNAL_NO_SHARED_SIGNAL)
    return [
        signal for signal in CORRELATION_SIGNALS if signal in detected
    ]


def _conflict_details(
    *,
    material_records: list,
    conflicting_context_keys: list,
    evidence_state_conflict: bool,
    confidence_conflict: bool,
    r43_records: list,
) -> list[dict]:
    details: list[dict] = []
    for record in material_records:
        details.append(
            {
                "conflict_type": record.get("conflict_type"),
                "resolution_state": record.get("resolution_state"),
                "conflicting_fields": record.get("conflicting_fields") or [],
            }
        )
    if conflicting_context_keys:
        details.append(
            {
                "conflict_type": CONFLICT_CONTEXT,
                "resolution_state": MATERIAL_RESOLUTION,
                "conflicting_fields": conflicting_context_keys,
            }
        )
    if evidence_state_conflict:
        details.append(
            {
                "conflict_type": CONFLICT_EVIDENCE_STATE,
                "resolution_state": MATERIAL_RESOLUTION,
                "conflicting_fields": ["evidence_state"],
            }
        )
    if confidence_conflict:
        details.append(
            {
                "conflict_type": CONFLICT_CONFIDENCE,
                "resolution_state": MATERIAL_RESOLUTION,
                "conflicting_fields": ["confidence", "context_analysis"],
            }
        )
    if not details:
        for record in r43_records:
            if _upper(record.get("conflict_type")) in (
                NON_MATERIAL_CONFLICT_TYPES
                | MATERIAL_CONFLICT_TYPES_UNRESOLVED
            ):
                details.append(
                    {
                        "conflict_type": record.get("conflict_type"),
                        "resolution_state": record.get(
                            "resolution_state"
                        ),
                        "conflicting_fields": record.get(
                            "conflicting_fields"
                        )
                        or [],
                    }
                )
    deduped: list[dict] = []
    for detail in details:
        if detail not in deduped:
            deduped.append(detail)
    return deduped[:8]


def relational_score(signals: object) -> int:
    """Bounded interpretable score derived only from declared weights."""

    total = 0
    for signal in signals or ():
        total += SIGNAL_WEIGHTS.get(_upper(signal), 0)
    return max(0, min(MAX_RELATIONSHIP_SCORE, total))


__all__ = [
    "FINDING_CORRELATION_RULES_RULE_VERSION",
    "RULE_VERSION",
    "GENERIC_CONTEXT_KEYS",
    "GENERIC_HYPOTHESIS_SIGNAL_PREFIXES",
    "AUTHORIZATION_FAMILY",
    "CATEGORY_FAMILIES",
    "MATERIAL_CONFLICT_TYPES",
    "MATERIAL_CONFLICT_TYPES_ALWAYS",
    "MATERIAL_CONFLICT_TYPES_UNRESOLVED",
    "NON_MATERIAL_CONFLICT_TYPES",
    "finding_facts",
    "analyze_pair",
    "relational_score",
]
