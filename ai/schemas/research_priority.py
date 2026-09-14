"""Research priority schema (Stage R55.1).

Defines the bounded, deterministic research-priority plan for one R53
research finding candidate (optionally enriched with R54 correlation
intelligence and R44 learning context). It answers:

    "Which research finding should be investigated first, and why?"

Hard boundaries encoded here:

- Research ordering only: priority is a research-prioritization signal. It is
  never vulnerability confirmation, exploitation, attack planning, payload
  generation, execution, severity certification or bug-bounty submission.
- Priority is not truth: a plan always forces ``confidence_effect = NONE`` and
  ``confirmation_state = NOT_CONFIRMED``; a high priority never upgrades
  finding confidence and multiple agreeing findings never inflate it.
- Severity is never computed: it can only mirror an explicitly structured
  upstream CVSS context (``severity_source = CVSS_CONTEXT``); otherwise it
  stays ``UNKNOWN`` with ``NOT_ASSESSED``.
- Impact stays potential unless an upstream structured contract explicitly
  carries an observed impact state; business impact is never asserted.
- Closed vocabularies only: priority bands, factor codes, factor values,
  reason codes and limitation codes are closed sets; no free-form LLM
  reasoning exists.
- Every score is bounded (0-100) and explainable through explicit factor
  contributions; there are no opaque magic numbers.
- Bounded, privacy-safe, JSON serializable.

No I/O, no network, no LLM, no Mongo, no execution of any kind is represented
here.
"""

from __future__ import annotations

import re

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
)

from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
)
from ai.schemas.cve_research_context_analysis import (
    CVSS_SEVERITIES,
    CVSS_UNKNOWN,
)
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS
from ai.schemas.finding_assessment import (
    CONFIRMATION_NOT_CONFIRMED,
    FINDING_STATES,
    IMPACT_STATES,
    SEVERITY_SOURCE_NOT_ASSESSED,
    SEVERITY_SOURCES,
    STATE_INSUFFICIENT_EVIDENCE,
)
from ai.schemas.llm_advisory_input import (
    ADVISORY_SAFETY_STATES,
    SAFETY_UNKNOWN,
)
from ai.schemas.finding_evidence import (
    EVIDENCE_COMPLETENESS_LEVELS,
    EVIDENCE_ORIGINS,
)
from ai.schemas.finding_identity import FINDING_ID_RE
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

RESEARCH_PRIORITY_RULE_VERSION = "r55-1"
RULE_VERSION = RESEARCH_PRIORITY_RULE_VERSION

# ---------------------------------------------------------------------------
# Priority bands (closed)
# ---------------------------------------------------------------------------

BAND_CRITICAL = "CRITICAL"
BAND_HIGH = "HIGH"
BAND_MEDIUM = "MEDIUM"
BAND_LOW = "LOW"
BAND_DEFERRED = "DEFERRED"

PRIORITY_BANDS: tuple[str, ...] = (
    BAND_CRITICAL,
    BAND_HIGH,
    BAND_MEDIUM,
    BAND_LOW,
    BAND_DEFERRED,
)

#: Deterministic rank used only for stable ordering (DEFERRED is unranked).
PRIORITY_BAND_RANK: dict[str, int] = {
    BAND_CRITICAL: 4,
    BAND_HIGH: 3,
    BAND_MEDIUM: 2,
    BAND_LOW: 1,
    BAND_DEFERRED: 0,
}

#: Documented score thresholds. ``band_for_score`` never returns DEFERRED:
#: DEFERRED is a safety-gate status, never a low-score side effect.
CRITICAL_MIN_SCORE = 80
HIGH_MIN_SCORE = 65
MEDIUM_MIN_SCORE = 45

MAX_PRIORITY_SCORE = 100
MAX_FACTORS = 16
MAX_REASONS = 16
MAX_CORRELATION_SOURCES = 8
MAX_LIST = 16
MAX_LIMITATIONS = 24
MAX_VALUE_LEN = 160

# ---------------------------------------------------------------------------
# Factor codes (closed)
# ---------------------------------------------------------------------------

FACTOR_EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"
FACTOR_CONTEXT_COMPLETENESS = "CONTEXT_COMPLETENESS"
FACTOR_FINDING_STATE = "FINDING_STATE"
FACTOR_UPSTREAM_CONFIDENCE = "UPSTREAM_CONFIDENCE"
FACTOR_IMPACT_SIGNAL = "IMPACT_SIGNAL"
FACTOR_SEVERITY_SIGNAL = "SEVERITY_SIGNAL"
FACTOR_CORRELATION_CONTEXT = "CORRELATION_CONTEXT"
FACTOR_CONFLICT_CONSTRAINT = "CONFLICT_CONSTRAINT"
FACTOR_LEARNING_SIGNAL = "LEARNING_SIGNAL"
FACTOR_LEARNING_CONSTRAINT = "LEARNING_CONSTRAINT"
FACTOR_GOVERNANCE_CONSTRAINT = "GOVERNANCE_CONSTRAINT"
FACTOR_PROVENANCE_COMPLETENESS = "PROVENANCE_COMPLETENESS"
FACTOR_SAFETY_ELIGIBILITY = "SAFETY_ELIGIBILITY"

PRIORITY_FACTOR_CODES: tuple[str, ...] = (
    FACTOR_EVIDENCE_COMPLETENESS,
    FACTOR_CONTEXT_COMPLETENESS,
    FACTOR_FINDING_STATE,
    FACTOR_UPSTREAM_CONFIDENCE,
    FACTOR_IMPACT_SIGNAL,
    FACTOR_SEVERITY_SIGNAL,
    FACTOR_CORRELATION_CONTEXT,
    FACTOR_CONFLICT_CONSTRAINT,
    FACTOR_LEARNING_SIGNAL,
    FACTOR_LEARNING_CONSTRAINT,
    FACTOR_GOVERNANCE_CONSTRAINT,
    FACTOR_PROVENANCE_COMPLETENESS,
    FACTOR_SAFETY_ELIGIBILITY,
)

# ---------------------------------------------------------------------------
# Factor value vocabularies (closed, per factor code)
# ---------------------------------------------------------------------------

CONTEXT_COMPLETE = "CONTEXT_COMPLETE"
CONTEXT_PARTIAL = "CONTEXT_PARTIAL"
CONTEXT_MISSING = "CONTEXT_MISSING"

CONTEXT_FACTOR_VALUES: tuple[str, ...] = (
    CONTEXT_COMPLETE,
    CONTEXT_PARTIAL,
    CONTEXT_MISSING,
)

CORRELATION_CONFLICTING = "CORRELATION_CONFLICTING"
CORRELATION_DUPLICATE_REDUNDANT = "CORRELATION_DUPLICATE_REDUNDANT"
CORRELATION_DUPLICATE_REPRESENTATIVE = (
    "CORRELATION_DUPLICATE_REPRESENTATIVE"
)
CORRELATION_RELATED = "CORRELATION_RELATED"
CORRELATION_INDEPENDENT = "CORRELATION_INDEPENDENT"
CORRELATION_UNKNOWN = "CORRELATION_UNKNOWN"
CORRELATION_UNAVAILABLE = "CORRELATION_UNAVAILABLE"

CORRELATION_FACTOR_VALUES: tuple[str, ...] = (
    CORRELATION_CONFLICTING,
    CORRELATION_DUPLICATE_REDUNDANT,
    CORRELATION_DUPLICATE_REPRESENTATIVE,
    CORRELATION_RELATED,
    CORRELATION_INDEPENDENT,
    CORRELATION_UNKNOWN,
    CORRELATION_UNAVAILABLE,
)

LEARNING_REQUIRE_MORE_EVIDENCE = "LEARNING_REQUIRE_MORE_EVIDENCE"
LEARNING_STRENGTHEN_HYPOTHESES = "LEARNING_STRENGTHEN_HYPOTHESES"
LEARNING_AVOID_DUPLICATION = "LEARNING_AVOID_DUPLICATION"
LEARNING_REVIEW_GOVERNANCE = "LEARNING_REVIEW_GOVERNANCE"
LEARNING_REVIEW_PROVENANCE = "LEARNING_REVIEW_PROVENANCE"
LEARNING_SAFETY_BOUNDARY = "LEARNING_SAFETY_BOUNDARY"
LEARNING_PRESERVE_PATTERN = "LEARNING_PRESERVE_PATTERN"
LEARNING_CALIBRATE_CONFIDENCE = "LEARNING_CALIBRATE_CONFIDENCE"
LEARNING_IMPROVE_CONTEXT = "LEARNING_IMPROVE_CONTEXT"
LEARNING_UNRECOGNIZED = "LEARNING_UNRECOGNIZED"
LEARNING_UNAVAILABLE = "LEARNING_UNAVAILABLE"

LEARNING_FACTOR_VALUES: tuple[str, ...] = (
    LEARNING_REQUIRE_MORE_EVIDENCE,
    LEARNING_STRENGTHEN_HYPOTHESES,
    LEARNING_AVOID_DUPLICATION,
    LEARNING_REVIEW_GOVERNANCE,
    LEARNING_REVIEW_PROVENANCE,
    LEARNING_SAFETY_BOUNDARY,
    LEARNING_PRESERVE_PATTERN,
    LEARNING_CALIBRATE_CONFIDENCE,
    LEARNING_IMPROVE_CONTEXT,
    LEARNING_UNRECOGNIZED,
    LEARNING_UNAVAILABLE,
)

GOVERNANCE_READY = "GOVERNANCE_READY"
GOVERNANCE_NOT_READY = "GOVERNANCE_NOT_READY"
GOVERNANCE_UNKNOWN_VALUE = "GOVERNANCE_UNKNOWN"

GOVERNANCE_FACTOR_VALUES: tuple[str, ...] = (
    GOVERNANCE_READY,
    GOVERNANCE_NOT_READY,
    GOVERNANCE_UNKNOWN_VALUE,
)

PROVENANCE_COMPLETE = "PROVENANCE_COMPLETE"
PROVENANCE_PARTIAL = "PROVENANCE_PARTIAL"
PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"

PROVENANCE_FACTOR_VALUES: tuple[str, ...] = (
    PROVENANCE_COMPLETE,
    PROVENANCE_PARTIAL,
    PROVENANCE_INCOMPLETE,
)

BAND_CAP_LOW = "BAND_CAP_LOW"
BAND_CAP_MEDIUM = "BAND_CAP_MEDIUM"

CONSTRAINT_FACTOR_VALUES: tuple[str, ...] = (
    BAND_CAP_LOW,
    BAND_CAP_MEDIUM,
)

SAFETY_ELIGIBLE = "SAFETY_ELIGIBLE"
SAFETY_DEFERRED_VALUE = "SAFETY_DEFERRED"

SAFETY_FACTOR_VALUES: tuple[str, ...] = (
    SAFETY_ELIGIBLE,
    SAFETY_DEFERRED_VALUE,
)

FACTOR_VALUE_VOCABULARIES: dict[str, tuple[str, ...]] = {
    FACTOR_EVIDENCE_COMPLETENESS: EVIDENCE_COMPLETENESS_LEVELS,
    FACTOR_CONTEXT_COMPLETENESS: CONTEXT_FACTOR_VALUES,
    FACTOR_FINDING_STATE: FINDING_STATES,
    FACTOR_UPSTREAM_CONFIDENCE: CONFIDENCE_LEVELS,
    FACTOR_IMPACT_SIGNAL: IMPACT_STATES,
    FACTOR_SEVERITY_SIGNAL: CVSS_SEVERITIES,
    FACTOR_CORRELATION_CONTEXT: CORRELATION_FACTOR_VALUES,
    FACTOR_CONFLICT_CONSTRAINT: CONSTRAINT_FACTOR_VALUES,
    FACTOR_LEARNING_SIGNAL: LEARNING_FACTOR_VALUES,
    FACTOR_LEARNING_CONSTRAINT: CONSTRAINT_FACTOR_VALUES,
    FACTOR_GOVERNANCE_CONSTRAINT: CONSTRAINT_FACTOR_VALUES,
    FACTOR_PROVENANCE_COMPLETENESS: PROVENANCE_FACTOR_VALUES,
    FACTOR_SAFETY_ELIGIBILITY: SAFETY_FACTOR_VALUES,
}

#: Bounded contribution range of a single factor (relative points).
MIN_FACTOR_CONTRIBUTION = -100
MAX_FACTOR_CONTRIBUTION = 100

# ---------------------------------------------------------------------------
# Reason codes (closed)
# ---------------------------------------------------------------------------

REASON_COMPLETE_EVIDENCE = "COMPLETE_EVIDENCE"
REASON_PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
REASON_MISSING_EVIDENCE = "MISSING_EVIDENCE"
REASON_UNKNOWN_EVIDENCE = "UNKNOWN_EVIDENCE"
REASON_STRONG_CONTEXT = "STRONG_CONTEXT"
REASON_PARTIAL_CONTEXT = "PARTIAL_CONTEXT"
REASON_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
REASON_CONFIRMED_OBSERVED_STATE = "CONFIRMED_OBSERVED_STATE"
REASON_EVIDENCE_SUPPORTED_STATE = "EVIDENCE_SUPPORTED_STATE"
REASON_RESEARCH_CANDIDATE_STATE = "RESEARCH_CANDIDATE_STATE"
REASON_NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
REASON_INSUFFICIENT_EVIDENCE_STATE = "INSUFFICIENT_EVIDENCE_STATE"
REASON_CONFLICTED_STATE = "CONFLICTED_STATE"
REASON_HIGH_UPSTREAM_CONFIDENCE = "HIGH_UPSTREAM_CONFIDENCE"
REASON_MEDIUM_UPSTREAM_CONFIDENCE = "MEDIUM_UPSTREAM_CONFIDENCE"
REASON_LOW_UPSTREAM_CONFIDENCE = "LOW_UPSTREAM_CONFIDENCE"
REASON_UNKNOWN_UPSTREAM_CONFIDENCE = "UNKNOWN_UPSTREAM_CONFIDENCE"
REASON_OBSERVED_IMPACT = "OBSERVED_IMPACT"
REASON_POTENTIAL_IMPACT = "POTENTIAL_IMPACT"
REASON_IMPACT_UNKNOWN = "IMPACT_UNKNOWN"
REASON_CVSS_CONTEXT_AVAILABLE = "CVSS_CONTEXT_AVAILABLE"
REASON_SEVERITY_NOT_ASSESSED = "SEVERITY_NOT_ASSESSED"
REASON_CONFLICT_REQUIRES_REVIEW = "CONFLICT_REQUIRES_REVIEW"
REASON_DUPLICATE_RESEARCH_REDUCTION = "DUPLICATE_RESEARCH_REDUCTION"
REASON_DUPLICATE_REPRESENTATIVE = "DUPLICATE_REPRESENTATIVE"
REASON_RELATED_FINDINGS_CONTEXT = "RELATED_FINDINGS_CONTEXT"
REASON_INDEPENDENT_FINDINGS = "INDEPENDENT_FINDINGS"
REASON_UNKNOWN_CORRELATION = "UNKNOWN_CORRELATION"
REASON_CORRELATION_UNAVAILABLE = "CORRELATION_UNAVAILABLE"
REASON_LEARNING_SIGNAL_REQUIRES_EVIDENCE = (
    "LEARNING_SIGNAL_REQUIRES_EVIDENCE"
)
REASON_LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS = (
    "LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS"
)
REASON_LEARNING_SIGNAL_AVOID_DUPLICATION = (
    "LEARNING_SIGNAL_AVOID_DUPLICATION"
)
REASON_LEARNING_SIGNAL_REVIEW_GOVERNANCE = (
    "LEARNING_SIGNAL_REVIEW_GOVERNANCE"
)
REASON_LEARNING_SIGNAL_REVIEW_PROVENANCE = (
    "LEARNING_SIGNAL_REVIEW_PROVENANCE"
)
REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY = (
    "LEARNING_SIGNAL_SAFETY_BOUNDARY"
)
REASON_LEARNING_SIGNAL_PRESERVE_PATTERN = (
    "LEARNING_SIGNAL_PRESERVE_PATTERN"
)
REASON_LEARNING_SIGNAL_CALIBRATE_CONFIDENCE = (
    "LEARNING_SIGNAL_CALIBRATE_CONFIDENCE"
)
REASON_LEARNING_SIGNAL_IMPROVE_CONTEXT = (
    "LEARNING_SIGNAL_IMPROVE_CONTEXT"
)
REASON_LEARNING_SIGNAL_UNRECOGNIZED = "LEARNING_SIGNAL_UNRECOGNIZED"
REASON_LEARNING_UNAVAILABLE = "LEARNING_UNAVAILABLE"
REASON_GOVERNANCE_LIMITATION = "GOVERNANCE_LIMITATION"
REASON_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
REASON_SAFETY_DEFERRED = "SAFETY_DEFERRED"
REASON_UNSAFE_CONFIRMATION = "UNSAFE_CONFIRMATION"
REASON_NON_RESEARCH_ONLY = "NON_RESEARCH_ONLY"
REASON_SAFETY_FAILURE = "SAFETY_FAILURE"
REASON_FORBIDDEN_CLAIM = "FORBIDDEN_CLAIM"
REASON_INVALID_PROVENANCE = "INVALID_PROVENANCE"
REASON_INVALID_GOVERNANCE = "INVALID_GOVERNANCE"

PRIORITY_REASONS: tuple[str, ...] = (
    REASON_SAFETY_DEFERRED,
    REASON_UNSAFE_CONFIRMATION,
    REASON_NON_RESEARCH_ONLY,
    REASON_SAFETY_FAILURE,
    REASON_FORBIDDEN_CLAIM,
    REASON_INVALID_PROVENANCE,
    REASON_INVALID_GOVERNANCE,
    REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY,
    REASON_COMPLETE_EVIDENCE,
    REASON_PARTIAL_EVIDENCE,
    REASON_MISSING_EVIDENCE,
    REASON_UNKNOWN_EVIDENCE,
    REASON_STRONG_CONTEXT,
    REASON_PARTIAL_CONTEXT,
    REASON_INSUFFICIENT_CONTEXT,
    REASON_CONFIRMED_OBSERVED_STATE,
    REASON_EVIDENCE_SUPPORTED_STATE,
    REASON_RESEARCH_CANDIDATE_STATE,
    REASON_NEEDS_MORE_EVIDENCE,
    REASON_INSUFFICIENT_EVIDENCE_STATE,
    REASON_CONFLICTED_STATE,
    REASON_HIGH_UPSTREAM_CONFIDENCE,
    REASON_MEDIUM_UPSTREAM_CONFIDENCE,
    REASON_LOW_UPSTREAM_CONFIDENCE,
    REASON_UNKNOWN_UPSTREAM_CONFIDENCE,
    REASON_OBSERVED_IMPACT,
    REASON_POTENTIAL_IMPACT,
    REASON_IMPACT_UNKNOWN,
    REASON_CVSS_CONTEXT_AVAILABLE,
    REASON_SEVERITY_NOT_ASSESSED,
    REASON_CONFLICT_REQUIRES_REVIEW,
    REASON_DUPLICATE_RESEARCH_REDUCTION,
    REASON_DUPLICATE_REPRESENTATIVE,
    REASON_RELATED_FINDINGS_CONTEXT,
    REASON_INDEPENDENT_FINDINGS,
    REASON_UNKNOWN_CORRELATION,
    REASON_CORRELATION_UNAVAILABLE,
    REASON_LEARNING_SIGNAL_REQUIRES_EVIDENCE,
    REASON_LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS,
    REASON_LEARNING_SIGNAL_AVOID_DUPLICATION,
    REASON_LEARNING_SIGNAL_REVIEW_GOVERNANCE,
    REASON_LEARNING_SIGNAL_REVIEW_PROVENANCE,
    REASON_LEARNING_SIGNAL_PRESERVE_PATTERN,
    REASON_LEARNING_SIGNAL_CALIBRATE_CONFIDENCE,
    REASON_LEARNING_SIGNAL_IMPROVE_CONTEXT,
    REASON_LEARNING_SIGNAL_UNRECOGNIZED,
    REASON_LEARNING_UNAVAILABLE,
    REASON_GOVERNANCE_LIMITATION,
    REASON_PROVENANCE_INCOMPLETE,
)

DEFERRAL_CODES: tuple[str, ...] = (
    REASON_NON_RESEARCH_ONLY,
    REASON_UNSAFE_CONFIRMATION,
    REASON_SAFETY_FAILURE,
    REASON_FORBIDDEN_CLAIM,
    REASON_INVALID_PROVENANCE,
    REASON_INVALID_GOVERNANCE,
    REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY,
)

# ---------------------------------------------------------------------------
# Limitations (closed)
# ---------------------------------------------------------------------------

LIMITATION_NO_EXECUTION_PERFORMED = "NO_EXECUTION_PERFORMED"
LIMITATION_NO_NETWORK_REQUESTS = "NO_NETWORK_REQUESTS"
LIMITATION_NO_VULNERABILITY_CONFIRMATION = "NO_VULNERABILITY_CONFIRMATION"
LIMITATION_NO_EXPLOIT_GENERATION = "NO_EXPLOIT_GENERATION"
LIMITATION_RESEARCH_ONLY = "RESEARCH_ONLY"
LIMITATION_PRIORITY_NOT_CONFIDENCE = "PRIORITY_NOT_CONFIDENCE"
LIMITATION_CONFIDENCE_NOT_UPGRADED = "CONFIDENCE_NOT_UPGRADED"
LIMITATION_NOT_CONFIRMED = "NOT_CONFIRMED"
LIMITATION_PRIORITY_RANKING_ONLY = "PRIORITY_RANKING_ONLY"
LIMITATION_SEVERITY_NOT_ASSESSED = "SEVERITY_NOT_ASSESSED"
LIMITATION_IMPACT_NOT_OBSERVED = "IMPACT_NOT_OBSERVED"
LIMITATION_EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
LIMITATION_INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
LIMITATION_CORRELATION_UNAVAILABLE = "CORRELATION_UNAVAILABLE"
LIMITATION_CORRELATION_INCOMPLETE = "CORRELATION_INCOMPLETE"
LIMITATION_CONFLICT_PRESENT = "CONFLICT_PRESENT"
LIMITATION_DUPLICATE_RELATIONSHIP = "DUPLICATE_RELATIONSHIP"
LIMITATION_GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"
LIMITATION_GOVERNANCE_NOT_READY = "GOVERNANCE_NOT_READY"
LIMITATION_PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
LIMITATION_LEARNING_UNAVAILABLE = "LEARNING_UNAVAILABLE"
LIMITATION_LEARNING_GOVERNANCE_REVIEW = "LEARNING_GOVERNANCE_REVIEW"
LIMITATION_SAFETY_DEFERRED = "SAFETY_DEFERRED"

PRIORITY_LIMITATIONS: tuple[str, ...] = (
    LIMITATION_NO_EXECUTION_PERFORMED,
    LIMITATION_NO_NETWORK_REQUESTS,
    LIMITATION_NO_VULNERABILITY_CONFIRMATION,
    LIMITATION_NO_EXPLOIT_GENERATION,
    LIMITATION_RESEARCH_ONLY,
    LIMITATION_PRIORITY_NOT_CONFIDENCE,
    LIMITATION_CONFIDENCE_NOT_UPGRADED,
    LIMITATION_NOT_CONFIRMED,
    LIMITATION_PRIORITY_RANKING_ONLY,
    LIMITATION_SAFETY_DEFERRED,
    LIMITATION_SEVERITY_NOT_ASSESSED,
    LIMITATION_IMPACT_NOT_OBSERVED,
    LIMITATION_EVIDENCE_INCOMPLETE,
    LIMITATION_INSUFFICIENT_CONTEXT,
    LIMITATION_CORRELATION_UNAVAILABLE,
    LIMITATION_CORRELATION_INCOMPLETE,
    LIMITATION_CONFLICT_PRESENT,
    LIMITATION_DUPLICATE_RELATIONSHIP,
    LIMITATION_GOVERNANCE_UNKNOWN,
    LIMITATION_GOVERNANCE_NOT_READY,
    LIMITATION_LEARNING_GOVERNANCE_REVIEW,
    LIMITATION_PROVENANCE_INCOMPLETE,
    LIMITATION_LEARNING_UNAVAILABLE,
)

# ---------------------------------------------------------------------------
# Conflict / learning / provenance vocabularies
# ---------------------------------------------------------------------------

CONFLICT_PRESENT = "CONFLICT_PRESENT"
CONFLICT_NONE = "NO_CONFLICT"
CONFLICT_UNKNOWN = "UNKNOWN"

CONFLICT_STATES: tuple[str, ...] = (
    CONFLICT_PRESENT,
    CONFLICT_NONE,
    CONFLICT_UNKNOWN,
)

REFERENCE_REFERENCED = "REFERENCED"
REFERENCE_UNKNOWN = "UNKNOWN"

GOVERNANCE_READY_READY = "READY"
GOVERNANCE_READY_NOT_READY = "NOT_READY"
GOVERNANCE_READY_UNKNOWN = "UNKNOWN"

GOVERNANCE_READY_STATES: tuple[str, ...] = (
    GOVERNANCE_READY_READY,
    GOVERNANCE_READY_NOT_READY,
    GOVERNANCE_READY_UNKNOWN,
)

SOURCE_KIND_FINDING = "R53_FINDING"
SOURCE_KIND_REFERENCE = "R54_REFERENCE"

SOURCE_KINDS: tuple[str, ...] = (
    SOURCE_KIND_FINDING,
    SOURCE_KIND_REFERENCE,
)

MAX_CONFLICT_SOURCES = 8

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


def _bounded_ids(value: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item)
        if FINDING_ID_RE.match(text) and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return max(minimum, min(maximum, value))


def _bounded_tokens(value: object, allowed: tuple, limit: int) -> list[str]:
    out: list[str] = []
    for item in value or ():
        text = _safe_text(item).strip().upper()
        if text in allowed and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ordered_codes(codes: object, allowed: tuple, limit: int) -> list[str]:
    found = set()
    for item in codes or ():
        text = _safe_text(item).strip().upper()
        if text in allowed:
            found.add(text)
    return [code for code in allowed if code in found][:limit]


def band_for_score(score: object) -> str:
    """Deterministic band for a bounded 0-100 priority score.

    ``DEFERRED`` is never returned here: it is assigned only by the safety
    eligibility gate, never by a low score.
    """

    if isinstance(score, bool) or not isinstance(score, int):
        return BAND_LOW
    bounded = max(0, min(MAX_PRIORITY_SCORE, score))
    if bounded >= CRITICAL_MIN_SCORE:
        return BAND_CRITICAL
    if bounded >= HIGH_MIN_SCORE:
        return BAND_HIGH
    if bounded >= MEDIUM_MIN_SCORE:
        return BAND_MEDIUM
    return BAND_LOW


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def sanitize_priority_factor(value: object) -> dict:
    """Project one priority factor onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {}
    factor = _safe_text(value.get("factor")).strip().upper()
    allowed = FACTOR_VALUE_VOCABULARIES.get(factor)
    if not allowed:
        return {}
    factor_value = _safe_text(value.get("value")).strip().upper()
    if factor_value not in allowed:
        return {}
    return {
        "factor": factor,
        "value": factor_value,
        "contribution": _bounded_int(
            value.get("contribution"),
            MIN_FACTOR_CONTRIBUTION,
            MAX_FACTOR_CONTRIBUTION,
        ),
    }


def sanitize_priority_factors(value: object) -> list[dict]:
    """Project a bounded list of priority factors (order preserved)."""

    out: list[dict] = []
    for item in value or ():
        projected = sanitize_priority_factor(item)
        if projected and projected not in out:
            out.append(projected)
        if len(out) >= MAX_FACTORS:
            break
    return out


def sanitize_correlation_summary(value: object) -> dict:
    """Project the correlation context of one finding onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "present": False,
            "relationship_types": [],
            "conflict_count": 0,
            "duplicate_count": 0,
            "related_count": 0,
            "independent_count": 0,
            "unknown_count": 0,
            "embedded_conflict_count": 0,
            "duplicate_cluster_size": 0,
            "conflict_sources": [],
            "relationship_ids": [],
            "research_only": True,
        }
    return {
        "present": bool(value.get("present")) is True,
        "relationship_types": _bounded_strings(
            value.get("relationship_types"), MAX_LIST
        ),
        "conflict_count": _bounded_int(
            value.get("conflict_count"), 0, MAX_LIST
        ),
        "duplicate_count": _bounded_int(
            value.get("duplicate_count"), 0, MAX_LIST
        ),
        "related_count": _bounded_int(
            value.get("related_count"), 0, MAX_LIST
        ),
        "independent_count": _bounded_int(
            value.get("independent_count"), 0, MAX_LIST
        ),
        "unknown_count": _bounded_int(
            value.get("unknown_count"), 0, MAX_LIST
        ),
        "embedded_conflict_count": _bounded_int(
            value.get("embedded_conflict_count"), 0, MAX_LIST
        ),
        "duplicate_cluster_size": _bounded_int(
            value.get("duplicate_cluster_size"), 0, MAX_LIST
        ),
        "conflict_sources": _bounded_ids(
            value.get("conflict_sources"), MAX_CONFLICT_SOURCES
        ),
        "relationship_ids": _bounded_strings(
            value.get("relationship_ids"), MAX_LIST, 80
        ),
        "research_only": True,
    }


def sanitize_learning_summary(value: object) -> dict:
    """Project the advisory learning context onto fixed bounded keys."""

    if not isinstance(value, dict):
        return {
            "available": False,
            "recommendation_types": [],
            "recommendation_ids": [],
            "advisory_only": True,
        }
    return {
        "available": bool(value.get("available")) is True,
        "recommendation_types": _bounded_strings(
            value.get("recommendation_types"), MAX_LIST
        ),
        "recommendation_ids": _bounded_strings(
            value.get("recommendation_ids"), MAX_LIST, 80
        ),
        "advisory_only": True,
    }


def sanitize_priority_provenance(value: object) -> dict:
    """Project finding-level priority provenance onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "source_kind": "",
            "finding_rule_version": "",
            "correlation_rule_version": "",
            "orchestration_id": "",
            "source_stages": [],
            "evaluation_rating": "",
            "hard_gate_state": "",
            "safety_state": SAFETY_UNKNOWN,
            "deterministic": True,
            "research_only": True,
        }
    source_kind = _safe_text(value.get("source_kind")).strip().upper()
    if source_kind not in SOURCE_KINDS:
        source_kind = ""
    evaluation_rating = _safe_text(
        value.get("evaluation_rating")
    ).strip().upper()
    if evaluation_rating not in EVALUATION_RATINGS:
        evaluation_rating = ""
    hard_gate_state = _safe_text(
        value.get("hard_gate_state")
    ).strip().upper()
    if hard_gate_state not in HARD_GATE_STATES:
        hard_gate_state = ""
    return {
        "source_kind": source_kind,
        "finding_rule_version": _safe_text(
            value.get("finding_rule_version")
        ),
        "correlation_rule_version": _safe_text(
            value.get("correlation_rule_version")
        ),
        "orchestration_id": _safe_text(value.get("orchestration_id")),
        "source_stages": _bounded_strings(
            value.get("source_stages"), MAX_LIST
        ),
        "evaluation_rating": evaluation_rating,
        "hard_gate_state": hard_gate_state,
        "safety_state": _closed(
            value.get("safety_state"), ADVISORY_SAFETY_STATES, SAFETY_UNKNOWN
        ),
        "deterministic": True,
        "research_only": True,
    }


def sanitize_priority_governance(value: object) -> dict:
    """Project the finding-level R37 governance reference onto fixed keys."""

    if not isinstance(value, dict):
        return {
            "rule_version": "",
            "reference_state": REFERENCE_UNKNOWN,
            "ready_state": GOVERNANCE_READY_UNKNOWN,
            "research_only": True,
        }
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "reference_state": _closed(
            value.get("reference_state"),
            (REFERENCE_REFERENCED, REFERENCE_UNKNOWN),
            REFERENCE_UNKNOWN,
        ),
        "ready_state": _closed(
            value.get("ready_state"),
            GOVERNANCE_READY_STATES,
            GOVERNANCE_READY_UNKNOWN,
        ),
        "research_only": True,
    }


def sanitize_research_priority(value: object) -> dict:
    """Project an R55 priority plan onto its fixed bounded key set."""

    if not isinstance(value, dict):
        return _default_priority_plan()
    category = _safe_text(value.get("category")).strip().upper()
    if category not in AGENT_CATEGORIES:
        category = ""
    return {
        "rule_version": _safe_text(value.get("rule_version")),
        "finding_id": _safe_text(value.get("finding_id")),
        "category": category,
        "specialist_name": _safe_text(value.get("specialist_name")),
        "agent_id": _safe_text(value.get("agent_id")),
        "state": _closed(
            value.get("state"),
            FINDING_STATES,
            STATE_INSUFFICIENT_EVIDENCE,
        ),
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "confidence": _closed(
            value.get("confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "confidence_effect": "NONE",
        "evidence_state": _safe_text(
            value.get("evidence_state")
        ).strip().upper(),
        "evidence_completeness": _closed(
            value.get("evidence_completeness"),
            EVIDENCE_COMPLETENESS_LEVELS,
            "UNKNOWN",
        ),
        "evidence_origin": _closed(
            value.get("evidence_origin"),
            EVIDENCE_ORIGINS,
            "UNKNOWN",
        ),
        "severity": _closed(
            value.get("severity"), CVSS_SEVERITIES, CVSS_UNKNOWN
        ),
        "severity_source": _closed(
            value.get("severity_source"),
            SEVERITY_SOURCES,
            SEVERITY_SOURCE_NOT_ASSESSED,
        ),
        "impact_state": _closed(
            value.get("impact_state"), IMPACT_STATES, "UNKNOWN"
        ),
        "impact_confidence": _closed(
            value.get("impact_confidence"), CONFIDENCE_LEVELS, "UNKNOWN"
        ),
        "priority_score": _bounded_int(
            value.get("priority_score"), 0, MAX_PRIORITY_SCORE
        ),
        "priority_band": _closed(
            value.get("priority_band"), PRIORITY_BANDS, BAND_DEFERRED
        ),
        "priority_factors": sanitize_priority_factors(
            value.get("priority_factors")
        ),
        "priority_reasons": _ordered_codes(
            value.get("priority_reasons"), PRIORITY_REASONS, MAX_REASONS
        ),
        "correlation_summary": sanitize_correlation_summary(
            value.get("correlation_summary")
        ),
        "conflict_state": _closed(
            value.get("conflict_state"), CONFLICT_STATES, CONFLICT_UNKNOWN
        ),
        "learning_summary": sanitize_learning_summary(
            value.get("learning_summary")
        ),
        "ranking_position": _bounded_int(
            value.get("ranking_position"), 0, MAX_LIST
        ),
        "provenance": sanitize_priority_provenance(value.get("provenance")),
        "governance": sanitize_priority_governance(value.get("governance")),
        "limitations": _ordered_codes(
            value.get("limitations"), PRIORITY_LIMITATIONS, MAX_LIMITATIONS
        ),
        "research_only": True,
        "deterministic": True,
    }


def _default_priority_plan() -> dict:
    return {
        "rule_version": "",
        "finding_id": "",
        "category": "",
        "specialist_name": "",
        "agent_id": "",
        "state": STATE_INSUFFICIENT_EVIDENCE,
        "confirmation_state": CONFIRMATION_NOT_CONFIRMED,
        "confidence": "UNKNOWN",
        "confidence_effect": "NONE",
        "evidence_state": "UNKNOWN",
        "evidence_completeness": "UNKNOWN",
        "evidence_origin": "UNKNOWN",
        "severity": CVSS_UNKNOWN,
        "severity_source": SEVERITY_SOURCE_NOT_ASSESSED,
        "impact_state": "UNKNOWN",
        "impact_confidence": "UNKNOWN",
        "priority_score": 0,
        "priority_band": BAND_DEFERRED,
        "priority_factors": [],
        "priority_reasons": [],
        "correlation_summary": sanitize_correlation_summary(None),
        "conflict_state": CONFLICT_UNKNOWN,
        "learning_summary": sanitize_learning_summary(None),
        "ranking_position": 0,
        "provenance": sanitize_priority_provenance(None),
        "governance": sanitize_priority_governance(None),
        "limitations": [],
        "research_only": True,
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class PriorityFactorPlan(BaseModel):
    """One documented priority factor contribution (R55.1)."""

    model_config = ConfigDict(extra="forbid")

    factor: str
    value: str
    contribution: int = 0

    @field_validator("factor")
    @classmethod
    def _valid_factor(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PRIORITY_FACTOR_CODES:
            raise ValueError(f"invalid factor: {value!r}")
        return text

    @field_validator("value")
    @classmethod
    def _valid_value(cls, value: object, info: ValidationInfo) -> str:
        text = _safe_text(value).strip().upper()
        allowed = FACTOR_VALUE_VOCABULARIES.get(info.data.get("factor"))
        if not allowed or text not in allowed:
            raise ValueError(f"invalid factor value: {value!r}")
        return text

    @field_validator("contribution")
    @classmethod
    def _bounded_contribution(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid contribution: {value!r}")
        if not (
            MIN_FACTOR_CONTRIBUTION
            <= value
            <= MAX_FACTOR_CONTRIBUTION
        ):
            raise ValueError(f"contribution out of range: {value!r}")
        return value


class ResearchPriorityPlan(BaseModel):
    """Deterministic research priority of one finding candidate (R55.1)."""

    model_config = ConfigDict(extra="forbid")

    rule_version: str = RESEARCH_PRIORITY_RULE_VERSION
    finding_id: str
    category: str = ""
    specialist_name: str = ""
    agent_id: str = ""
    state: str = ""
    confirmation_state: str = CONFIRMATION_NOT_CONFIRMED
    confidence: str = "UNKNOWN"
    confidence_effect: str = "NONE"
    evidence_state: str = "UNKNOWN"
    evidence_completeness: str = "UNKNOWN"
    evidence_origin: str = "UNKNOWN"
    severity: str = CVSS_UNKNOWN
    severity_source: str = SEVERITY_SOURCE_NOT_ASSESSED
    impact_state: str = "UNKNOWN"
    impact_confidence: str = "UNKNOWN"
    priority_score: int = 0
    priority_band: str = BAND_DEFERRED
    priority_factors: list[dict] = Field(default_factory=list)
    priority_reasons: list[str] = Field(default_factory=list)
    correlation_summary: dict = Field(default_factory=dict)
    conflict_state: str = CONFLICT_UNKNOWN
    learning_summary: dict = Field(default_factory=dict)
    ranking_position: int = 0
    provenance: dict = Field(default_factory=dict)
    governance: dict = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    research_only: bool = True
    deterministic: bool = True

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: object) -> str:
        return RESEARCH_PRIORITY_RULE_VERSION

    @field_validator("finding_id")
    @classmethod
    def _valid_finding_id(cls, value: object) -> str:
        text = _safe_text(value)
        if not FINDING_ID_RE.match(text):
            raise ValueError(f"malformed finding_id: {value!r}")
        return text

    @field_validator("category")
    @classmethod
    def _valid_category(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in AGENT_CATEGORIES:
            raise ValueError(f"invalid category: {value!r}")
        return text

    @field_validator("state")
    @classmethod
    def _valid_state(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in FINDING_STATES:
            raise ValueError(f"invalid finding state: {value!r}")
        return text

    @field_validator("confirmation_state")
    @classmethod
    def _never_confirmed(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != CONFIRMATION_NOT_CONFIRMED:
            raise ValueError("prioritized findings are never confirmed")
        return CONFIRMATION_NOT_CONFIRMED

    @field_validator("confidence", "impact_confidence")
    @classmethod
    def _valid_confidence(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {value!r}")
        return text

    @field_validator("evidence_completeness")
    @classmethod
    def _valid_completeness(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_COMPLETENESS_LEVELS:
            raise ValueError(f"invalid completeness: {value!r}")
        return text

    @field_validator("evidence_origin")
    @classmethod
    def _valid_origin(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in EVIDENCE_ORIGINS:
            raise ValueError(f"invalid evidence origin: {value!r}")
        return text

    @field_validator("severity")
    @classmethod
    def _valid_severity(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CVSS_SEVERITIES:
            raise ValueError(f"invalid severity: {value!r}")
        return text

    @field_validator("severity_source")
    @classmethod
    def _valid_severity_source(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in SEVERITY_SOURCES:
            raise ValueError(f"invalid severity_source: {value!r}")
        return text

    @field_validator("impact_state")
    @classmethod
    def _valid_impact(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in IMPACT_STATES:
            raise ValueError(f"invalid impact_state: {value!r}")
        return text

    @field_validator("priority_score")
    @classmethod
    def _valid_score(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid priority_score: {value!r}")
        if value < 0 or value > MAX_PRIORITY_SCORE:
            raise ValueError(f"priority_score out of range: {value!r}")
        return value

    @field_validator("priority_band")
    @classmethod
    def _valid_band(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in PRIORITY_BANDS:
            raise ValueError(f"invalid priority_band: {value!r}")
        return text

    @field_validator("priority_factors")
    @classmethod
    def _bounded_factors(cls, value: object) -> list[dict]:
        out: list[dict] = []
        for item in value or ():
            try:
                projected = PriorityFactorPlan(
                    **sanitize_priority_factor(item)
                ).model_dump(mode="json")
            except (TypeError, ValueError):
                continue
            if projected not in out:
                out.append(projected)
            if len(out) >= MAX_FACTORS:
                break
        return out

    @field_validator("priority_reasons")
    @classmethod
    def _bounded_reasons(cls, value: object) -> list[str]:
        return _ordered_codes(value, PRIORITY_REASONS, MAX_REASONS)

    @field_validator("correlation_summary")
    @classmethod
    def _bounded_correlation(cls, value: object) -> dict:
        return sanitize_correlation_summary(value)

    @field_validator("conflict_state")
    @classmethod
    def _valid_conflict(cls, value: object) -> str:
        text = _safe_text(value).strip().upper()
        if text not in CONFLICT_STATES:
            raise ValueError(f"invalid conflict_state: {value!r}")
        return text

    @field_validator("learning_summary")
    @classmethod
    def _bounded_learning(cls, value: object) -> dict:
        return sanitize_learning_summary(value)

    @field_validator("ranking_position")
    @classmethod
    def _bounded_position(cls, value: object) -> int:
        return _bounded_int(value, 0, MAX_LIST)

    @field_validator("provenance")
    @classmethod
    def _bounded_provenance(cls, value: object) -> dict:
        return sanitize_priority_provenance(value)

    @field_validator("governance")
    @classmethod
    def _bounded_governance(cls, value: object) -> dict:
        return sanitize_priority_governance(value)

    @field_validator("limitations")
    @classmethod
    def _bounded_limitations(cls, value: object) -> list[str]:
        return _ordered_codes(
            value, PRIORITY_LIMITATIONS, MAX_LIMITATIONS
        )

    @field_validator("confidence_effect")
    @classmethod
    def _no_confidence_effect(cls, value: object) -> str:
        if _safe_text(value).strip().upper() != "NONE":
            raise ValueError("priority never changes finding confidence")
        return "NONE"

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: object) -> bool:
        if not value:
            raise ValueError("research priorities are research-only")
        return True

    @field_validator("deterministic")
    @classmethod
    def _deterministic(cls, value: object) -> bool:
        if value is not True:
            raise ValueError("research priorities are deterministic")
        return True


def research_priority_plan_projection(value: ResearchPriorityPlan) -> dict:
    """Serialize a research priority plan to a deterministic dict."""

    return value.model_dump(mode="json")


__all__ = [
    "RESEARCH_PRIORITY_RULE_VERSION",
    "RULE_VERSION",
    "PRIORITY_BANDS",
    "PRIORITY_BAND_RANK",
    "BAND_CRITICAL",
    "BAND_HIGH",
    "BAND_MEDIUM",
    "BAND_LOW",
    "BAND_DEFERRED",
    "CRITICAL_MIN_SCORE",
    "HIGH_MIN_SCORE",
    "MEDIUM_MIN_SCORE",
    "MAX_PRIORITY_SCORE",
    "MAX_FACTORS",
    "MAX_REASONS",
    "MAX_CORRELATION_SOURCES",
    "MAX_LIST",
    "MAX_LIMITATIONS",
    "MAX_VALUE_LEN",
    "PRIORITY_FACTOR_CODES",
    "FACTOR_EVIDENCE_COMPLETENESS",
    "FACTOR_CONTEXT_COMPLETENESS",
    "FACTOR_FINDING_STATE",
    "FACTOR_UPSTREAM_CONFIDENCE",
    "FACTOR_IMPACT_SIGNAL",
    "FACTOR_SEVERITY_SIGNAL",
    "FACTOR_CORRELATION_CONTEXT",
    "FACTOR_CONFLICT_CONSTRAINT",
    "FACTOR_LEARNING_SIGNAL",
    "FACTOR_LEARNING_CONSTRAINT",
    "FACTOR_GOVERNANCE_CONSTRAINT",
    "FACTOR_PROVENANCE_COMPLETENESS",
    "FACTOR_SAFETY_ELIGIBILITY",
    "FACTOR_VALUE_VOCABULARIES",
    "MIN_FACTOR_CONTRIBUTION",
    "MAX_FACTOR_CONTRIBUTION",
    "CONTEXT_FACTOR_VALUES",
    "CONTEXT_COMPLETE",
    "CONTEXT_PARTIAL",
    "CONTEXT_MISSING",
    "CORRELATION_FACTOR_VALUES",
    "CORRELATION_CONFLICTING",
    "CORRELATION_DUPLICATE_REDUNDANT",
    "CORRELATION_DUPLICATE_REPRESENTATIVE",
    "CORRELATION_RELATED",
    "CORRELATION_INDEPENDENT",
    "CORRELATION_UNKNOWN",
    "CORRELATION_UNAVAILABLE",
    "LEARNING_FACTOR_VALUES",
    "LEARNING_REQUIRE_MORE_EVIDENCE",
    "LEARNING_STRENGTHEN_HYPOTHESES",
    "LEARNING_AVOID_DUPLICATION",
    "LEARNING_REVIEW_GOVERNANCE",
    "LEARNING_REVIEW_PROVENANCE",
    "LEARNING_SAFETY_BOUNDARY",
    "LEARNING_PRESERVE_PATTERN",
    "LEARNING_CALIBRATE_CONFIDENCE",
    "LEARNING_IMPROVE_CONTEXT",
    "LEARNING_UNRECOGNIZED",
    "LEARNING_UNAVAILABLE",
    "GOVERNANCE_FACTOR_VALUES",
    "GOVERNANCE_READY",
    "GOVERNANCE_NOT_READY",
    "GOVERNANCE_UNKNOWN_VALUE",
    "PROVENANCE_FACTOR_VALUES",
    "PROVENANCE_COMPLETE",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_INCOMPLETE",
    "BAND_CAP_LOW",
    "BAND_CAP_MEDIUM",
    "CONSTRAINT_FACTOR_VALUES",
    "SAFETY_ELIGIBLE",
    "SAFETY_DEFERRED_VALUE",
    "SAFETY_FACTOR_VALUES",
    "PRIORITY_REASONS",
    "DEFERRAL_CODES",
    "REASON_SAFETY_DEFERRED",
    "REASON_UNSAFE_CONFIRMATION",
    "REASON_NON_RESEARCH_ONLY",
    "REASON_SAFETY_FAILURE",
    "REASON_FORBIDDEN_CLAIM",
    "REASON_INVALID_PROVENANCE",
    "REASON_INVALID_GOVERNANCE",
    "REASON_LEARNING_SIGNAL_SAFETY_BOUNDARY",
    "REASON_COMPLETE_EVIDENCE",
    "REASON_PARTIAL_EVIDENCE",
    "REASON_MISSING_EVIDENCE",
    "REASON_UNKNOWN_EVIDENCE",
    "REASON_STRONG_CONTEXT",
    "REASON_PARTIAL_CONTEXT",
    "REASON_INSUFFICIENT_CONTEXT",
    "REASON_CONFIRMED_OBSERVED_STATE",
    "REASON_EVIDENCE_SUPPORTED_STATE",
    "REASON_RESEARCH_CANDIDATE_STATE",
    "REASON_NEEDS_MORE_EVIDENCE",
    "REASON_INSUFFICIENT_EVIDENCE_STATE",
    "REASON_CONFLICTED_STATE",
    "REASON_HIGH_UPSTREAM_CONFIDENCE",
    "REASON_MEDIUM_UPSTREAM_CONFIDENCE",
    "REASON_LOW_UPSTREAM_CONFIDENCE",
    "REASON_UNKNOWN_UPSTREAM_CONFIDENCE",
    "REASON_OBSERVED_IMPACT",
    "REASON_POTENTIAL_IMPACT",
    "REASON_IMPACT_UNKNOWN",
    "REASON_CVSS_CONTEXT_AVAILABLE",
    "REASON_SEVERITY_NOT_ASSESSED",
    "REASON_CONFLICT_REQUIRES_REVIEW",
    "REASON_DUPLICATE_RESEARCH_REDUCTION",
    "REASON_DUPLICATE_REPRESENTATIVE",
    "REASON_RELATED_FINDINGS_CONTEXT",
    "REASON_INDEPENDENT_FINDINGS",
    "REASON_UNKNOWN_CORRELATION",
    "REASON_CORRELATION_UNAVAILABLE",
    "REASON_LEARNING_SIGNAL_REQUIRES_EVIDENCE",
    "REASON_LEARNING_SIGNAL_STRENGTHEN_HYPOTHESIS",
    "REASON_LEARNING_SIGNAL_AVOID_DUPLICATION",
    "REASON_LEARNING_SIGNAL_REVIEW_GOVERNANCE",
    "REASON_LEARNING_SIGNAL_REVIEW_PROVENANCE",
    "REASON_LEARNING_SIGNAL_PRESERVE_PATTERN",
    "REASON_LEARNING_SIGNAL_CALIBRATE_CONFIDENCE",
    "REASON_LEARNING_SIGNAL_IMPROVE_CONTEXT",
    "REASON_LEARNING_SIGNAL_UNRECOGNIZED",
    "REASON_LEARNING_UNAVAILABLE",
    "REASON_GOVERNANCE_LIMITATION",
    "REASON_PROVENANCE_INCOMPLETE",
    "PRIORITY_LIMITATIONS",
    "LIMITATION_NO_EXECUTION_PERFORMED",
    "LIMITATION_NO_NETWORK_REQUESTS",
    "LIMITATION_NO_VULNERABILITY_CONFIRMATION",
    "LIMITATION_NO_EXPLOIT_GENERATION",
    "LIMITATION_RESEARCH_ONLY",
    "LIMITATION_PRIORITY_NOT_CONFIDENCE",
    "LIMITATION_CONFIDENCE_NOT_UPGRADED",
    "LIMITATION_NOT_CONFIRMED",
    "LIMITATION_PRIORITY_RANKING_ONLY",
    "LIMITATION_SAFETY_DEFERRED",
    "LIMITATION_SEVERITY_NOT_ASSESSED",
    "LIMITATION_IMPACT_NOT_OBSERVED",
    "LIMITATION_EVIDENCE_INCOMPLETE",
    "LIMITATION_INSUFFICIENT_CONTEXT",
    "LIMITATION_CORRELATION_UNAVAILABLE",
    "LIMITATION_CORRELATION_INCOMPLETE",
    "LIMITATION_CONFLICT_PRESENT",
    "LIMITATION_DUPLICATE_RELATIONSHIP",
    "LIMITATION_GOVERNANCE_UNKNOWN",
    "LIMITATION_GOVERNANCE_NOT_READY",
    "LIMITATION_LEARNING_GOVERNANCE_REVIEW",
    "LIMITATION_PROVENANCE_INCOMPLETE",
    "LIMITATION_LEARNING_UNAVAILABLE",
    "CONFLICT_STATES",
    "CONFLICT_PRESENT",
    "CONFLICT_NONE",
    "CONFLICT_UNKNOWN",
    "REFERENCE_REFERENCED",
    "REFERENCE_UNKNOWN",
    "GOVERNANCE_READY_STATES",
    "GOVERNANCE_READY_READY",
    "GOVERNANCE_READY_NOT_READY",
    "GOVERNANCE_READY_UNKNOWN",
    "SOURCE_KINDS",
    "SOURCE_KIND_FINDING",
    "SOURCE_KIND_REFERENCE",
    "band_for_score",
    "sanitize_priority_factor",
    "sanitize_priority_factors",
    "sanitize_correlation_summary",
    "sanitize_learning_summary",
    "sanitize_priority_provenance",
    "sanitize_priority_governance",
    "sanitize_research_priority",
    "PriorityFactorPlan",
    "ResearchPriorityPlan",
    "research_priority_plan_projection",
]
