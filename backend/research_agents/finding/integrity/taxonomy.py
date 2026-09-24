"""Evidence taxonomy (EPIC11 §4) — normalize raw evidence rows into
claim-grade evidence types.

Why this module exists: the persisted observation rows carry a *storage*
``type`` (``observation``/``knowledge``) plus a free-form ``signal``.  The
previous gate counted rows and storage types, so 20 parameter-inventory
rows satisfied ">= 2 observation rows" and were treated as proof of a
reflected-XSS hypothesis.  Normalizing each row to a closed evidence type
with an explicit *stage* is what makes "parameter exists" impossible to
confuse with "XSS exists".

Rules:
- The vocabulary is closed.  An unrecognised signal maps to
  ``UNCLASSIFIED_OBSERVATION`` (recorded, never silently promoted) — an
  unclassified row satisfies no stage requirement anywhere.
- A row may carry an explicit ``evidence_type``; it is honored only when
  it is a member of the closed vocabulary (untrusted input never widens
  the vocabulary).
- Duplicate evidence events are collapsed deterministically (§17.K): the
  same observation persisted by two runs is ONE observation, and every
  duplicate records which row it duplicates.  Duplicates never increase
  support.
- Provenance travels with every item: job, agent, execution mode,
  observation reference, category, confidence, observed timestamp.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

TAXONOMY_RULE_VERSION = "epic11-evidence-taxonomy-1"

# ------------------------------------------------------------- vocabulary (closed)

# Stage 1 — observed surface
PARAMETER_OBSERVED = "PARAMETER_OBSERVED"
URL_OBSERVED = "URL_OBSERVED"
REQUEST_OBSERVED = "REQUEST_OBSERVED"
RESPONSE_OBSERVED = "RESPONSE_OBSERVED"
# Stage 2 — controlled input
CONTROLLED_INPUT_SENT = "CONTROLLED_INPUT_SENT"
# Stage 3 — reflection / context / sink
REFLECTION_OBSERVED = "REFLECTION_OBSERVED"
OUTPUT_CONTEXT_IDENTIFIED = "OUTPUT_CONTEXT_IDENTIFIED"
DOM_SINK_IDENTIFIED = "DOM_SINK_IDENTIFIED"
# Stage 4 — exploitability / execution
PAYLOAD_EXECUTION = "PAYLOAD_EXECUTION"
EXPLOITABILITY_ESTABLISHED = "EXPLOITABILITY_ESTABLISHED"
# Stage 5 — impact
IMPACT_ESTABLISHED = "IMPACT_ESTABLISHED"
# Auxiliary (gate requirements / integrity bookkeeping) — never vulnerability stages
AUTHORIZATION_CONFIRMED = "AUTHORIZATION_CONFIRMED"
NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
KNOWLEDGE_REFERENCE = "KNOWLEDGE_REFERENCE"
UNCLASSIFIED_OBSERVATION = "UNCLASSIFIED_OBSERVATION"

EVIDENCE_TYPES: tuple[str, ...] = (
    PARAMETER_OBSERVED, URL_OBSERVED, REQUEST_OBSERVED, RESPONSE_OBSERVED,
    CONTROLLED_INPUT_SENT, REFLECTION_OBSERVED, OUTPUT_CONTEXT_IDENTIFIED,
    DOM_SINK_IDENTIFIED, PAYLOAD_EXECUTION, EXPLOITABILITY_ESTABLISHED,
    IMPACT_ESTABLISHED, AUTHORIZATION_CONFIRMED, NEGATIVE_EVIDENCE,
    KNOWLEDGE_REFERENCE, UNCLASSIFIED_OBSERVATION,
)
EVIDENCE_TYPE_SET = frozenset(EVIDENCE_TYPES)

# The five verification stages (§5) + 0 for auxiliary types.
STAGE_OBSERVED = 1
STAGE_CONTROLLED = 2
STAGE_REFLECTION = 3
STAGE_EXPLOITABILITY = 4
STAGE_IMPACT = 5
STAGE_AUXILIARY = 0

EVIDENCE_STAGE: dict[str, int] = {
    PARAMETER_OBSERVED: STAGE_OBSERVED,
    URL_OBSERVED: STAGE_OBSERVED,
    REQUEST_OBSERVED: STAGE_OBSERVED,
    RESPONSE_OBSERVED: STAGE_OBSERVED,
    CONTROLLED_INPUT_SENT: STAGE_CONTROLLED,
    REFLECTION_OBSERVED: STAGE_REFLECTION,
    OUTPUT_CONTEXT_IDENTIFIED: STAGE_REFLECTION,
    DOM_SINK_IDENTIFIED: STAGE_REFLECTION,
    PAYLOAD_EXECUTION: STAGE_EXPLOITABILITY,
    EXPLOITABILITY_ESTABLISHED: STAGE_EXPLOITABILITY,
    IMPACT_ESTABLISHED: STAGE_IMPACT,
    AUTHORIZATION_CONFIRMED: STAGE_AUXILIARY,
    NEGATIVE_EVIDENCE: STAGE_AUXILIARY,
    KNOWLEDGE_REFERENCE: STAGE_AUXILIARY,
    UNCLASSIFIED_OBSERVATION: STAGE_AUXILIARY,
}

STAGE_LABELS: dict[int, str] = {
    STAGE_AUXILIARY: "auxiliary",
    STAGE_OBSERVED: "parameter/URL observed",
    STAGE_CONTROLLED: "controlled input/testing performed",
    STAGE_REFLECTION: "reflection or relevant sink/context evidence",
    STAGE_EXPLOITABILITY: "exploitability / execution evidence",
    STAGE_IMPACT: "impact evidence",
}

# Stage-4 types: the ONLY evidence that may support "confirmed vulnerability".
CONFIRMATION_EVIDENCE = frozenset(
    {PAYLOAD_EXECUTION, EXPLOITABILITY_ESTABLISHED})

# ------------------------------------------------- signal registry (closed)

SIGNAL_TO_TYPE: dict[str, str] = {
    # stage 1
    "xss_parameter_inventory": PARAMETER_OBSERVED,
    "parameter_inventory": PARAMETER_OBSERVED,
    "param_inventory": PARAMETER_OBSERVED,
    "parameter_observed": PARAMETER_OBSERVED,
    "ssrf_url_parameter": PARAMETER_OBSERVED,
    "idor_object_reference_pattern": PARAMETER_OBSERVED,
    "url_observed": URL_OBSERVED,
    "url_inventory": URL_OBSERVED,
    "url_row": URL_OBSERVED,
    "oauth_endpoint_observed": URL_OBSERVED,
    "surface_row": URL_OBSERVED,
    "request_observed": REQUEST_OBSERVED,
    "http_request_observed": REQUEST_OBSERVED,
    "response_observed": RESPONSE_OBSERVED,
    "http_response_observed": RESPONSE_OBSERVED,
    "sqli_error_style_observation": RESPONSE_OBSERVED,
    "jwt_shaped_token_observed": RESPONSE_OBSERVED,
    "technology_signal": RESPONSE_OBSERVED,
    # stage 2
    "controlled_input_sent": CONTROLLED_INPUT_SENT,
    "controlled_probe_sent": CONTROLLED_INPUT_SENT,
    "probe_sent": CONTROLLED_INPUT_SENT,
    "controlled_input": CONTROLLED_INPUT_SENT,
    # stage 3
    "reflection_observed": REFLECTION_OBSERVED,
    "reflected_marker": REFLECTION_OBSERVED,
    "marker_reflected": REFLECTION_OBSERVED,
    "reflection_confirmed": REFLECTION_OBSERVED,
    "output_context_identified": OUTPUT_CONTEXT_IDENTIFIED,
    "unsafe_output_context": OUTPUT_CONTEXT_IDENTIFIED,
    "context_identified": OUTPUT_CONTEXT_IDENTIFIED,
    "unencoded_reflection_context": OUTPUT_CONTEXT_IDENTIFIED,
    "dom_sink_identified": DOM_SINK_IDENTIFIED,
    "dom_sink": DOM_SINK_IDENTIFIED,
    "sink_identified": DOM_SINK_IDENTIFIED,
    # stage 4
    "payload_execution": PAYLOAD_EXECUTION,
    "payload_executed": PAYLOAD_EXECUTION,
    "execution_observed": PAYLOAD_EXECUTION,
    "marker_executed": PAYLOAD_EXECUTION,
    "exploitability_established": EXPLOITABILITY_ESTABLISHED,
    "exploit_proven": EXPLOITABILITY_ESTABLISHED,
    # stage 5
    "impact_established": IMPACT_ESTABLISHED,
    "impact_proven": IMPACT_ESTABLISHED,
    # auxiliary
    "authorization_confirmed": AUTHORIZATION_CONFIRMED,
    "scope_authorized": AUTHORIZATION_CONFIRMED,
    "authorization_verified": AUTHORIZATION_CONFIRMED,
    "knowledge_reference": KNOWLEDGE_REFERENCE,
}

# Signals that ARE negative evidence by construction.
NEGATIVE_SIGNALS: frozenset[str] = frozenset(
    {"negative", "contradiction", "contradicting", "disproved", "rejected",
     "reflection_not_observed", "reflection_absent", "payload_execution_"
     "not_observed", "dom_sink_not_identified", "no_reflection"})

# Signals that state "this was never attempted" (NOT_TESTED, §11) — the
# distinction from NOT_OBSERVED is preserved, never collapsed.
NOT_TESTED_SIGNALS: frozenset[str] = frozenset(
    {"not_tested", "untested", "not_attempted", "not_performed",
     "reflection_not_tested", "payload_execution_not_performed",
     "execution_not_performed", "exploitability_not_established",
     "impact_not_established", "severity_not_assessed"})

NOT_OBSERVED = "NOT_OBSERVED"
NOT_TESTED = "NOT_TESTED"

# Storage types that are never stage evidence.
_NON_OBSERVATION_TYPES: dict[str, str] = {
    "knowledge": KNOWLEDGE_REFERENCE,
    "prior_research": KNOWLEDGE_REFERENCE,
    "prior_recommendation": KNOWLEDGE_REFERENCE,
    "llm_insight": KNOWLEDGE_REFERENCE,
    "memory": KNOWLEDGE_REFERENCE,
}

_SLUG = re.compile(r"[^a-z0-9]+")


def _signal_slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    return _SLUG.sub("_", text).strip("_")


def _fingerprint(row: dict[str, Any]) -> str:
    """Deterministic identity of one observation (dedupe key, §17.K)."""
    ref = str(row.get("observation_ref") or "").strip()
    if ref:
        return ref.lower()
    seed = "|".join([
        _signal_slug(row.get("signal")),
        " ".join(str(row.get("detail") or "").split())[:200].lower(),
        _signal_slug(row.get("category")),
    ])
    return "fp:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


@dataclass
class EvidenceItem:
    """One normalized evidence item with full provenance."""

    evidence_id: str
    evidence_type: str
    stage: int
    raw_type: str
    raw_signal: str
    category: str = ""
    job_id: str = ""
    observation_ref: str = ""
    confidence: str = ""
    execution_mode: str = ""
    observed_at: str = ""
    negative_kind: str = ""              # NOT_OBSERVED | NOT_TESTED
    duplicate_of: str = ""               # evidence_id of the retained row
    unclassified_reason: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    rule_version: str = TAXONOMY_RULE_VERSION

    @property
    def is_duplicate(self) -> bool:
        return bool(self.duplicate_of)

    @property
    def is_negative(self) -> bool:
        return self.evidence_type == NEGATIVE_EVIDENCE

    @property
    def is_stage_evidence(self) -> bool:
        return (self.stage > 0
                and self.evidence_type not in (NEGATIVE_EVIDENCE,
                                               KNOWLEDGE_REFERENCE))

    @property
    def is_confirmation_evidence(self) -> bool:
        return self.evidence_type in CONFIRMATION_EVIDENCE

    def observation_key(self) -> str:
        return self.provenance.get("observation_key") or self.evidence_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "stage": self.stage,
            "stage_label": STAGE_LABELS.get(self.stage, "auxiliary"),
            "raw_type": self.raw_type,
            "raw_signal": self.raw_signal,
            "category": self.category,
            "job_id": self.job_id,
            "observation_ref": self.observation_ref,
            "confidence": self.confidence,
            "execution_mode": self.execution_mode,
            "observed_at": self.observed_at,
            "negative_kind": self.negative_kind,
            "duplicate_of": self.duplicate_of,
            "unclassified_reason": self.unclassified_reason,
            "provenance": dict(self.provenance),
            "rule_version": self.rule_version,
        }


MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
MALFORMED_ROW_REASON = "malformed_evidence_row"


def _coerce_row(row: Any) -> tuple[dict[str, Any], str]:
    """Best-effort mapping view of ONE raw row.

    A non-mapping, a string, a number or an object whose iteration blows
    up must NEVER raise into the gate: it is returned as an empty mapping
    with an explicit malformed reason, which classifies as
    ``MALFORMED_EVIDENCE`` and therefore satisfies no claim (§11/§14).
    """
    if row is None:
        return {}, ""
    if isinstance(row, dict):
        return row, ""
    try:
        return dict(row), ""
    except (TypeError, ValueError, AttributeError):
        pass
    getter = getattr(row, "__dict__", None)
    if isinstance(getter, dict):
        return dict(getter), ""
    return {}, MALFORMED_ROW_REASON


def classify_row(row: dict[str, Any]) -> EvidenceItem:
    """Normalize ONE raw evidence row.  Never invents precision."""
    row, malformed = _coerce_row(row)
    if malformed:
        digest = hashlib.sha1(repr(row).encode("utf-8", "replace")).hexdigest()
        return EvidenceItem(
            evidence_id=f"ev-malformed-{digest[:12]}",
            evidence_type=MALFORMED_EVIDENCE,
            stage=STAGE_AUXILIARY,
            raw_type="", raw_signal="",
            unclassified_reason=malformed,
            provenance={"source": "evidence_taxonomy",
                        "malformed": malformed,
                        "observation_key": f"malformed:{digest[:12]}",
                        "rule_version": TAXONOMY_RULE_VERSION})
    raw_type = _signal_slug(row.get("type"))
    raw_signal = _signal_slug(row.get("signal"))
    declared = str(row.get("evidence_type") or "").strip().upper()
    unclassified_reason = ""

    evidence_type = ""
    negative_kind = ""
    if raw_signal in NOT_TESTED_SIGNALS:
        evidence_type = NEGATIVE_EVIDENCE
        negative_kind = NOT_TESTED
    elif raw_signal in NEGATIVE_SIGNALS or raw_type == "negative":
        evidence_type = NEGATIVE_EVIDENCE
        negative_kind = NOT_OBSERVED
    elif declared in EVIDENCE_TYPE_SET:
        # explicit stamp: honored only inside the closed vocabulary
        evidence_type = declared
    elif raw_signal in SIGNAL_TO_TYPE:
        evidence_type = SIGNAL_TO_TYPE[raw_signal]
    elif raw_type in _NON_OBSERVATION_TYPES:
        evidence_type = _NON_OBSERVATION_TYPES[raw_type]
    else:
        evidence_type = UNCLASSIFIED_OBSERVATION
        unclassified_reason = (
            f"unrecognised_signal:{raw_signal}" if raw_signal
            else f"unrecognised_evidence:{raw_type or 'unknown'}")

    if declared and declared != evidence_type and evidence_type not in (
            NEGATIVE_EVIDENCE,):
        # explicit stamp the registry disagrees with: registry wins for
        # negative/not-tested rows, otherwise the stamp is authoritative
        evidence_type = declared if declared in EVIDENCE_TYPE_SET \
            else evidence_type

    stage = EVIDENCE_STAGE.get(evidence_type, STAGE_AUXILIARY)
    evidence_id = str(row.get("id") or "")
    return EvidenceItem(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        stage=stage,
        raw_type=raw_type,
        raw_signal=raw_signal,
        category=_signal_slug(row.get("category")).upper(),
        job_id=str(row.get("job_id") or ""),
        observation_ref=str(row.get("observation_ref") or ""),
        confidence=str(row.get("confidence") or ""),
        execution_mode=str(row.get("execution_mode") or ""),
        observed_at=str(row.get("created_at") or ""),
        negative_kind=negative_kind,
        unclassified_reason=unclassified_reason,
        provenance={
            "source": "evidence_taxonomy",
            "rule_version": TAXONOMY_RULE_VERSION,
            "observation_key": _fingerprint(row),
            "agent": str(row.get("agent") or ""),
            "authorization_ref": str(row.get("authorization_ref") or ""),
            "scope_ref": str(row.get("scope_ref") or ""),
            "evidence_job": str(row.get("job_id") or ""),
        },
    )


def classify_rows(rows: Iterable[dict[str, Any]]) -> list[EvidenceItem]:
    """Normalize + deterministically collapse duplicate evidence events.

    The first occurrence of an observation keeps the row identity; every
    later occurrence is marked ``duplicate_of`` that row.  Callers must
    use the non-duplicate items when counting support (§17.K).
    """
    items = [classify_row(r) for r in (rows or [])]
    seen: dict[str, str] = {}
    for item in items:
        key = f"{item.evidence_type}|{item.provenance.get('observation_key')}"
        kept = seen.get(key)
        if kept is None:
            seen[key] = item.evidence_id
        else:
            item.duplicate_of = kept
    return items


def unique_items(items: Iterable[EvidenceItem]) -> list[EvidenceItem]:
    return [i for i in items if not i.is_duplicate]


def items_by_type(items: Iterable[EvidenceItem]) -> dict[str, list[EvidenceItem]]:
    out: dict[str, list[EvidenceItem]] = {}
    for item in items:
        out.setdefault(item.evidence_type, []).append(item)
    return out


def stage_reached(items: Iterable[EvidenceItem]) -> int:
    """Highest verification stage with at least one non-duplicate item."""
    reached = 0
    for item in items:
        if item.is_duplicate or not item.is_stage_evidence:
            continue
        reached = max(reached, item.stage)
    return reached


def negative_evidence(items: Iterable[EvidenceItem]) -> list[dict[str, Any]]:
    """Negative facts, keeping NOT_TESTED distinct from NOT_OBSERVED (§11)."""
    out: list[dict[str, Any]] = []
    for item in items:
        if not item.is_negative:
            continue
        out.append({
            "evidence_id": item.evidence_id,
            "kind": item.negative_kind or NOT_OBSERVED,
            "signal": item.raw_signal,
            "label": "not tested" if item.negative_kind == NOT_TESTED
                     else "not observed",
            "job_id": item.job_id,
            "observed_at": item.observed_at,
        })
    return out


__all__ = [
    "AUTHORIZATION_CONFIRMED", "CONFIRMATION_EVIDENCE",
    "CONTROLLED_INPUT_SENT", "DOM_SINK_IDENTIFIED", "EVIDENCE_STAGE",
    "EVIDENCE_TYPES", "EVIDENCE_TYPE_SET", "EXPLOITABILITY_ESTABLISHED",
    "EvidenceItem", "IMPACT_ESTABLISHED", "KNOWLEDGE_REFERENCE",
    "NEGATIVE_EVIDENCE", "NEGATIVE_SIGNALS", "NOT_OBSERVED", "NOT_TESTED",
    "NOT_TESTED_SIGNALS", "OUTPUT_CONTEXT_IDENTIFIED", "PARAMETER_OBSERVED",
    "PAYLOAD_EXECUTION", "REFLECTION_OBSERVED", "REQUEST_OBSERVED",
    "RESPONSE_OBSERVED", "SIGNAL_TO_TYPE", "STAGE_AUXILIARY",
    "STAGE_CONTROLLED", "STAGE_EXPLOITABILITY", "STAGE_IMPACT",
    "STAGE_LABELS", "STAGE_OBSERVED", "STAGE_REFLECTION",
    "TAXONOMY_RULE_VERSION", "UNCLASSIFIED_OBSERVATION", "URL_OBSERVED",
    "classify_row", "classify_rows", "items_by_type", "negative_evidence",
    "stage_reached", "unique_items",
]
