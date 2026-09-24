"""EPIC12 — structured verification observations (§7).

An observation is only useful if it answers, deterministically and without
prose: **what** happened, **where**, **under which input**, **under which
request**, **what was observed**, **what was not observed**, and **which
evidence class** it belongs to.  "Looks reflected." is not an observation.

Every observation carries the closed EPIC11 ``evidence_type`` stamp so the
authoritative taxonomy classifies it the same way every time, and a
deterministic ``observation_ref`` so duplicate observations collapse in the
taxonomy's dedupe (they can never be counted twice as two unique observations).

Negative results are first-class (§9): ``negative=True`` produces a
``NEGATIVE_EVIDENCE`` row (``type="negative"``), and ``not_tested=True`` produces
a ``NOT_TESTED`` row — the distinction is preserved, never collapsed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from backend.research_agents.finding.integrity import taxonomy as tx

OBSERVATION_RULE_VERSION = "epic12-verification-observation-1"

#: Deterministic confidence — derived from the artifact that carries it.
CONFIDENCE_DETERMINISTIC = "deterministic"
CONFIDENCE_OBSERVED = "observed"
CONFIDENCE_UNKNOWN = "unknown"

CONFIDENCE_CLASSES: tuple[str, ...] = (
    CONFIDENCE_DETERMINISTIC, CONFIDENCE_OBSERVED, CONFIDENCE_UNKNOWN)

#: Signals used for negative results.  ``type="negative"`` is the authoritative
#: trigger in the EPIC11 taxonomy (raw_type == "negative" -> NEGATIVE_EVIDENCE /
#: NOT_OBSERVED), so a chain-specific slug is safe and never needs a taxonomy
#: change.  Where EPIC11 already declares the slug we use its exact spelling.
NEGATIVE_SIGNAL_SUFFIX = "_not_observed"
NOT_TESTED_SIGNAL = "not_tested"


class ObservationError(ValueError):
    """Raised when an observation would misstate what was observed."""


def _slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    out = []
    for ch in text:
        out.append(ch if ch.isalnum() else "_")
    return "".join(out).strip("_")


def observation_id_for(*, action_id: str, signal: str, where: str = "",
                       marker: str = "") -> str:
    """Deterministic observation identity (dedupe key for the taxonomy)."""
    seed = "|".join([str(action_id), _slug(signal), str(where)[:120],
                     str(marker)[:120]])
    return "obs-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


@dataclass
class VerificationObservation:
    """One structured verification observation (§7)."""

    signal: str
    action_id: str
    candidate_id: str
    objective_id: str
    scope_ref: str
    category: str = ""
    evidence_type: str = ""
    what_happened: str = ""
    where: str = ""
    under_input: str = ""
    under_request: str = ""
    observed: str = ""
    not_observed: str = ""
    context: str = ""
    marker: str = ""
    request_ref: str = ""
    response_ref: str = ""
    confidence: str = CONFIDENCE_UNKNOWN
    job_id: str = ""
    negative: bool = False
    not_tested: bool = False
    observation_id: str = ""
    observed_at: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.signal = _slug(self.signal)
        if not self.signal:
            raise ObservationError("signal is required")
        for key in ("action_id", "candidate_id", "objective_id"):
            if not str(getattr(self, key) or "").strip():
                raise ObservationError(f"{key} is required")
        self.category = str(self.category or "").strip().upper()
        declared = str(self.evidence_type or "").strip().upper()
        if declared and declared not in tx.EVIDENCE_TYPE_SET:
            raise ObservationError(
                f"evidence_type outside the closed EPIC11 vocabulary: "
                f"{declared!r}")
        self.evidence_type = declared
        # EPIC14 §13: a trusted producer cannot relabel an observation.  If
        # the signal maps to an authoritative type, the declared type must
        # agree with it — a caller may not take PARAMETER_OBSERVED and stamp
        # it REFLECTION_OBSERVED or PAYLOAD_EXECUTION.
        authoritative = tx.SIGNAL_TO_TYPE.get(self.signal)
        if declared and authoritative and declared != authoritative:
            raise ObservationError(
                "the declared evidence_type disagrees with the authoritative "
                f"classification of signal {self.signal!r}: "
                f"{declared!r} != {authoritative!r} (EPIC14 trust boundary)")
        if self.negative and self.not_tested:
            raise ObservationError(
                "an observation cannot be both not-observed and not-tested")
        if not (self.negative or self.not_tested) and not declared:
            raise ObservationError(
                "a positive observation must declare its EPIC11 evidence_type")
        if self.confidence not in CONFIDENCE_CLASSES:
            raise ObservationError(
                f"unknown confidence class: {self.confidence!r}")
        if self.negative and not self.not_observed:
            raise ObservationError(
                "a negative observation must state what was NOT observed")
        if self.positive and not self.observed:
            raise ObservationError(
                "a positive observation must state what WAS observed")
        if not self.observation_id:
            self.observation_id = observation_id_for(
                action_id=self.action_id, signal=self.signal, where=self.where,
                marker=self.marker)
        if not self.observed_at:
            from backend.research_agents.finding.models import utcnow
            self.observed_at = utcnow()
        self.provenance.setdefault("rule_version", OBSERVATION_RULE_VERSION)

    # ------------------------------------------------------------- helpers

    @property
    def positive(self) -> bool:
        return not (self.negative or self.not_tested)

    @property
    def evidence_class(self) -> str:
        """The class this observation belongs to, for reporting."""
        if self.not_tested:
            return tx.NOT_TESTED
        if self.negative:
            return tx.NEGATIVE_EVIDENCE
        return self.evidence_type

    @property
    def stage(self) -> int:
        if not self.positive:
            return tx.STAGE_AUXILIARY
        return tx.EVIDENCE_STAGE.get(self.evidence_type, tx.STAGE_AUXILIARY)

    def to_evidence_row(self) -> dict[str, Any]:
        """The EPIC11-consumable evidence row.

        ``observation_ref`` is the deterministic observation id, so the
        taxonomy's fingerprint collapses duplicates instead of counting them
        as separate unique observations.
        """
        row: dict[str, Any] = {
            "id": f"ev-{self.observation_id}",
            "type": "negative" if self.negative else "observation",
            "signal": self.signal,
            "category": self.category,
            "confidence": self.confidence,
            "observation_ref": self.observation_id,
            "observed_at": self.observed_at,
            "detail": (self.not_observed if self.negative else self.observed)[:300],
            # structured answers (§7) — carried on the evidence row itself
            "what_happened": self.what_happened,
            "where": self.where,
            "under_input": self.under_input,
            "under_request": self.under_request,
            "observed": self.observed,
            "not_observed": self.not_observed,
            "context": self.context,
            "marker": self.marker,
            "request_ref": self.request_ref,
            "response_ref": self.response_ref,
            "action_id": self.action_id,
            "objective_id": self.objective_id,
            "evidence_type": self.evidence_type,
            "negative": self.negative,
            "not_tested": self.not_tested,
            "provenance": dict(self.provenance),
        }
        if self.evidence_type:
            # the authoritative classification of this signal, never a
            # relabelled stronger type (EPIC14 §13)
            row["evidence_type"] = self.evidence_type
            row["authoritative_evidence_type"] = tx.SIGNAL_TO_TYPE.get(
                self.signal, self.evidence_type)
            row["provenance_class"] = tx.provenance_class_for(row)
        if self.job_id:
            row["job_id"] = self.job_id
        if self.not_tested:
            row["signal"] = NOT_TESTED_SIGNAL
        return row

    def to_dict(self) -> dict[str, Any]:
        out = self.to_evidence_row()
        out["observation_id"] = self.observation_id
        out["candidate_id"] = self.candidate_id
        out["scope_ref"] = self.scope_ref
        out["evidence_class"] = self.evidence_class
        out["stage"] = self.stage
        out["negative"] = self.negative
        out["not_tested"] = self.not_tested
        out["rule_version"] = OBSERVATION_RULE_VERSION
        return out


def positive(*, signal: str, evidence_type: str, action_id: str,
             candidate_id: str, objective_id: str, scope_ref: str,
             observed: str, what_happened: str = "", where: str = "",
             under_input: str = "", under_request: str = "",
             context: str = "", marker: str = "", request_ref: str = "",
             response_ref: str = "", category: str = "XSS",
             confidence: str = CONFIDENCE_DETERMINISTIC,
             job_id: str = "", provenance: dict[str, Any] | None = None
             ) -> VerificationObservation:
    """Build a positive observation (evidence WAS observed)."""
    return VerificationObservation(
        signal=signal, action_id=action_id, candidate_id=candidate_id,
        objective_id=objective_id, scope_ref=scope_ref, category=category,
        evidence_type=evidence_type, what_happened=what_happened, where=where,
        under_input=under_input, under_request=under_request, observed=observed,
        context=context, marker=marker, request_ref=request_ref,
        response_ref=response_ref, confidence=confidence, job_id=job_id,
        provenance=dict(provenance or {}))


def negative(*, signal: str, action_id: str, candidate_id: str,
             objective_id: str, scope_ref: str, not_observed: str,
             what_happened: str = "", where: str = "", under_input: str = "",
             under_request: str = "", context: str = "", marker: str = "",
             request_ref: str = "", response_ref: str = "",
             category: str = "XSS",
             confidence: str = CONFIDENCE_DETERMINISTIC,
             job_id: str = "", provenance: dict[str, Any] | None = None
             ) -> VerificationObservation:
    """Build a negative observation (we checked; it was not observed, §9)."""
    return VerificationObservation(
        signal=signal, action_id=action_id, candidate_id=candidate_id,
        objective_id=objective_id, scope_ref=scope_ref, category=category,
        what_happened=what_happened, where=where, under_input=under_input,
        under_request=under_request, not_observed=not_observed,
        context=context, marker=marker,
        request_ref=request_ref, response_ref=response_ref,
        confidence=confidence, job_id=job_id, negative=True,
        provenance=dict(provenance or {}))


def not_tested(*, signal: str, action_id: str, candidate_id: str,
               objective_id: str, scope_ref: str, not_observed: str,
               what_happened: str = "", where: str = "",
               under_input: str = "", under_request: str = "",
               context: str = "", marker: str = "",
               category: str = "XSS", job_id: str = "",
               provenance: dict[str, Any] | None = None
               ) -> VerificationObservation:
    """Build a NOT_TESTED observation (the check never ran, §11)."""
    return VerificationObservation(
        signal=signal, action_id=action_id, candidate_id=candidate_id,
        objective_id=objective_id, scope_ref=scope_ref, category=category,
        what_happened=what_happened, where=where, under_input=under_input,
        under_request=under_request, context=context, marker=marker,
        not_observed=not_observed,
        confidence=CONFIDENCE_UNKNOWN, job_id=job_id, not_tested=True,
        provenance=dict(provenance or {}))


__all__ = [
    "CONFIDENCE_CLASSES", "CONFIDENCE_DETERMINISTIC", "CONFIDENCE_OBSERVED",
    "CONFIDENCE_UNKNOWN", "NEGATIVE_SIGNAL_SUFFIX", "NOT_TESTED_SIGNAL",
    "OBSERVATION_RULE_VERSION", "ObservationError", "VerificationObservation",
    "negative", "not_tested", "observation_id_for", "positive",
]
