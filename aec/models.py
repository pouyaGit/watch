"""Data models for the AEC-1 offline pilot selector (Task T1).

Pure data: no I/O, no transport, no verdicts. A :class:`CaseRef` is a
normalised view of one existing research case; a :class:`SelectionDecision` is
the selector's per-case outcome; a :class:`SelectionResult` is the complete,
serialisable selection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from aec import (
    CATEGORY_RISK,
    EVIDENCE_LEVEL_CURRENT,
    EVIDENCE_LEVEL_TARGET,
    SELECTION_RULE_VERSION,
)

_CANDIDATE_SUFFIX = "_CANDIDATE"


def normalise_category(value: object) -> str:
    """``IDOR_CANDIDATE`` -> ``idor``; unknown values are lower-cased verbatim."""
    text = str(value or "").strip()
    if text.upper().endswith(_CANDIDATE_SUFFIX):
        text = text[: -len(_CANDIDATE_SUFFIX)]
    return text.strip().lower()


def risk_category_for(category: object) -> str:
    """Inherent risk class of the case itself (never a severity, never a verdict)."""
    return CATEGORY_RISK.get(normalise_category(category), "R0_UNCLASSIFIED")


def _text(value: object) -> str:
    return str(value or "").strip()


def _text_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (_text(value),) if value.strip() else ()
    if isinstance(value, Iterable):
        return tuple(_text(item) for item in value if _text(item))
    return ()


@dataclass(frozen=True)
class EvidenceGap:
    """What evidence a case still needs, and at which ladder level.

    ``not_listed_missing`` is deliberately **not** called "present": the
    investigation report's ``missing_evidence`` list is the only evidence
    statement the corpus makes, so evidence that is merely absent from that
    list is *not claimed to exist*. What is held is visible in
    ``artifacts_collected`` / ``artifacts_missing``, taken from the stored
    artifact statuses.
    """

    required: tuple[str, ...]
    missing: tuple[str, ...]
    not_listed_missing: tuple[str, ...]
    artifacts_collected: tuple[str, ...] = ()
    artifacts_missing: tuple[str, ...] = ()
    level_current: str = EVIDENCE_LEVEL_CURRENT
    level_target: str = EVIDENCE_LEVEL_TARGET

    @classmethod
    def build(
        cls,
        required: object,
        missing: object = None,
        artifacts: object = None,
    ) -> "EvidenceGap":
        required_items = _text_tuple(required)
        missing_items = _text_tuple(missing)
        # ``missing`` is authoritative when present; otherwise everything is missing.
        if not missing_items and required_items:
            missing_items = required_items
        not_listed = tuple(item for item in required_items if item not in missing_items)
        collected, artifact_gaps = _artifact_status(artifacts)
        return cls(
            required=required_items,
            missing=missing_items,
            not_listed_missing=not_listed,
            artifacts_collected=collected,
            artifacts_missing=artifact_gaps,
        )

    @property
    def is_complete(self) -> bool:
        """True only when nothing is stated missing and no stored artifact gaps."""
        return not self.missing and not self.artifacts_missing

    def to_dict(self) -> dict[str, Any]:
        return {
            "level_current": self.level_current,
            "level_target": self.level_target,
            "required": list(self.required),
            "missing": list(self.missing),
            "not_listed_missing": list(self.not_listed_missing),
            "artifacts_collected": list(self.artifacts_collected),
            "artifacts_missing": list(self.artifacts_missing),
        }


def _artifact_status(artifacts: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split stored artifacts into (collected, missing) by their status field."""
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, str):
        return (), ()
    collected: list[str] = []
    missing: list[str] = []
    for artifact in artifacts:
        if isinstance(artifact, Mapping):
            name = _text(artifact.get("type") or artifact.get("kind"))
            status = _text(artifact.get("status")).upper()
        else:
            name, status = _text(artifact), ""
        if not name:
            continue
        if status == "MISSING":
            if name not in missing:
                missing.append(name)
        elif name not in collected:
            collected.append(name)
    return tuple(collected), tuple(missing)


def _locations_from_plan(plan: object) -> tuple[str, ...]:
    """Collect request locations from a report's plan steps (defensive)."""
    if not isinstance(plan, Mapping):
        return ()
    steps = plan.get("steps")
    if not isinstance(steps, Sequence):
        return ()
    locations: list[str] = []
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        request = step.get("request")
        if isinstance(request, Mapping):
            location = _text(request.get("location")).lower()
            if location and location not in locations:
                locations.append(location)
    return tuple(locations)


@dataclass(frozen=True)
class CaseRef:
    """Normalised view of one existing research case (input to the selector)."""

    case_id: str
    job_id: str
    program: str
    host: str
    endpoint: str
    parameter: str
    method: str
    category: str
    confidence: str
    url: str
    evidence_gap: EvidenceGap
    locations: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    technology: tuple[str, ...] = ()
    report_id: str = ""

    @classmethod
    def from_report(cls, report: Mapping[str, Any]) -> "CaseRef":
        """Build from an investigation report document (as written by the runtime)."""
        if not isinstance(report, Mapping):
            raise TypeError("CaseRef.from_report accepts a mapping (report document)")
        job_id = _text(report.get("job_id"))
        if not job_id:
            raise ValueError("report is missing job_id; cannot identify the case")
        return cls(
            case_id=job_id,
            job_id=job_id,
            report_id=_text(report.get("report_id")),
            program=_text(report.get("program")),
            host=_text(report.get("subdomain")),
            endpoint=_text(report.get("endpoint")),
            parameter=_text(report.get("parameter")),
            method=_text(report.get("method")).upper(),
            category=normalise_category(report.get("category")),
            confidence=_text(report.get("confidence")).upper(),
            url=_text(report.get("url")),
            evidence_gap=EvidenceGap.build(
                report.get("evidence_required"),
                report.get("missing_evidence"),
                report.get("artifacts"),
            ),
            locations=_locations_from_plan(report.get("plan")),
            reasons=_text_tuple(report.get("reasons")),
            technology=_text_tuple(report.get("technology")),
        )

    @property
    def risk_category(self) -> str:
        return risk_category_for(self.category)

    @property
    def endpoint_key(self) -> tuple[str, str, str]:
        """Identity used for duplicate detection."""
        return (self.host.lower(), self.endpoint, self.parameter.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "job_id": self.job_id,
            "report_id": self.report_id,
            "program": self.program,
            "host": self.host,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "category": self.category,
            "confidence": self.confidence,
            "url": self.url,
            "risk_category": self.risk_category,
            "evidence_gap": self.evidence_gap.to_dict(),
            "reasons": list(self.reasons),
            "technology": list(self.technology),
            "locations": list(self.locations),
        }


@dataclass(frozen=True)
class SelectionDecision:
    """One case's outcome: selected (with an order) or excluded (with a reason)."""

    case: CaseRef
    decision: str  # "SELECTED" or an exclusion reason
    family: str = ""
    order: int = 0
    note: str = ""

    # -- convenience passthroughs (used by tests and report rendering) ------
    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def job_id(self) -> str:
        return self.case.job_id

    @property
    def program(self) -> str:
        return self.case.program

    @property
    def host(self) -> str:
        return self.case.host

    @property
    def endpoint(self) -> str:
        return self.case.endpoint

    @property
    def parameter(self) -> str:
        return self.case.parameter

    @property
    def method(self) -> str:
        return self.case.method

    @property
    def category(self) -> str:
        return self.case.category

    @property
    def confidence(self) -> str:
        return self.case.confidence

    @property
    def reason(self) -> str:
        return self.decision

    @property
    def risk_category(self) -> str:
        return self.case.risk_category

    @property
    def evidence_gap(self) -> EvidenceGap:
        return self.case.evidence_gap

    @property
    def selected(self) -> bool:
        return self.order > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "case_id": self.case_id,
            "job_id": self.job_id,
            "report_id": self.case.report_id,
            "program": self.program,
            "host": self.host,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "category": self.category,
            "confidence": self.confidence,
            "family": self.family,
            "risk_category": self.risk_category,
            "reason": self.decision,
            "note": self.note,
            "evidence_gap": self.evidence_gap.to_dict(),
        }


@dataclass
class SelectionResult:
    """Complete selection: selected cases, excluded cases, limits, counts."""

    selected: list[SelectionDecision] = field(default_factory=list)
    excluded: list[SelectionDecision] = field(default_factory=list)
    family_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    host_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    limits: dict[str, Any] = field(default_factory=dict)
    rule_version: str = SELECTION_RULE_VERSION
    generated_at_utc: str | None = None
    generated_from: dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "total": len(self.selected) + len(self.excluded),
            "selected": len(self.selected),
            "excluded": len(self.excluded),
        }

    @property
    def hosts(self) -> list[str]:
        seen: list[str] = []
        for decision in self.selected:
            if decision.host not in seen:
                seen.append(decision.host)
        return seen

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule_version": self.rule_version,
            "counts": self.counts,
            "limits": dict(self.limits),
            "hosts": self.hosts,
            "family_counts": {k: dict(v) for k, v in sorted(self.family_counts.items())},
            "host_counts": {k: dict(v) for k, v in sorted(self.host_counts.items())},
            "selected": [d.to_dict() for d in self.selected],
            "excluded": [d.to_dict() for d in self.excluded],
            "generated_from": dict(self.generated_from),
        }
        if self.generated_at_utc is not None:
            payload["generated_at_utc"] = self.generated_at_utc
        return payload


__all__ = [
    "CaseRef",
    "EvidenceGap",
    "SelectionDecision",
    "SelectionResult",
    "normalise_category",
    "risk_category_for",
]
