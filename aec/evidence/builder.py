"""Artifact builder (EPIC 2): observation plan → evidence artifact drafts.

Each plan step becomes one draft whose kind mirrors the step purpose
(BASELINE → baseline, COMPARISON → comparison, CONTEXT_CAPTURE →
context). Known plan dimensions become ``collected_fields``; the step's
targeted record type becomes the outstanding ``missing_fields`` entry.
Drafts describe record shapes only — they carry no observed values.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aec.evidence.models import EvidenceArtifactDraft
from aec.observation_plan import ObservationPlanDraft

BUILDER_VERSION = "aec-evidence-builder/v1"

#: Closed refusal vocabulary. No free-form refusal reasons.
REFUSAL_CODES = frozenset({
    "INVALID_PLAN",
    "EMPTY_PLAN",
    "MISSING_CASE",
    "UNSUPPORTED_PURPOSE",
})

PURPOSE_TO_KIND = {
    "BASELINE": "baseline",
    "COMPARISON": "comparison",
    "CONTEXT_CAPTURE": "context",
}


@dataclass(frozen=True)
class BuildOutcome:
    """Result of building: drafts or a closed-vocabulary refusal."""

    ok: bool
    artifacts: tuple[EvidenceArtifactDraft, ...]
    refusal_code: str | None
    refusal_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "refusal_code": self.refusal_code,
            "refusal_detail": self.refusal_detail,
        }


def _refuse(code: str, detail: str) -> BuildOutcome:
    assert code in REFUSAL_CODES, f"outside closed vocabulary: {code!r}"
    return BuildOutcome(ok=False, artifacts=(), refusal_code=code, refusal_detail=detail)


def _text(value: object) -> str:
    return str(value or "").strip()


def _fixed_names(step: Mapping[str, Any]) -> tuple[str, ...]:
    names: list[str] = []
    fixed = step.get("fixed_variables", ())
    if isinstance(fixed, str):
        return ()
    try:
        pairs = list(fixed)
    except TypeError:
        return ()
    for pair in pairs:
        try:
            name = pair[0]
        except (TypeError, IndexError, KeyError):
            continue
        if isinstance(name, str) and name.strip() and name not in names:
            names.append(name)
    return tuple(names)


def build_artifacts(source: object) -> BuildOutcome:
    """Build artifact drafts for every step of an observation plan.

    Accepts a plan object or its plain-data round-trip. Pure and
    deterministic: equal plans always yield equal drafts.
    """
    document: Mapping[str, Any] | None
    if isinstance(source, ObservationPlanDraft):
        document = source.to_dict()
    elif isinstance(source, Mapping):
        document = source
    else:
        document = None
    if document is None:
        return _refuse("INVALID_PLAN", f"expected a plan, got {type(source).__name__}")
    steps = document.get("steps")
    if not isinstance(steps, (list, tuple)) or not steps:
        return _refuse("EMPTY_PLAN", "plan carries no steps")
    case_id = _text(document.get("case_id"))
    if not case_id:
        return _refuse("MISSING_CASE", "plan names no case")
    plan_id = _text(document.get("plan_id")) or f"plan-{case_id}"

    drafts: list[EvidenceArtifactDraft] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, Mapping):
            return _refuse("INVALID_PLAN", f"step {index} is not a mapping")
        kind = PURPOSE_TO_KIND.get(_text(step.get("purpose")).upper())
        if kind is None:
            return _refuse(
                "UNSUPPORTED_PURPOSE", f"step {index} has purpose {step.get('purpose')!r}"
            )
        artifact_type = _text(step.get("expected_artifact_type")) or "context"
        step_id = _text(step.get("step_id")) or f"{plan_id}-s{index:02d}"
        drafts.append(
            EvidenceArtifactDraft(
                artifact_id=f"{plan_id}:s{index:02d}:{kind}",
                plan_id=plan_id,
                case_id=case_id,
                observation_ref=step_id,
                artifact_kind=kind,
                artifact_type=artifact_type,
                collected_fields=_fixed_names(step),
                missing_fields=(artifact_type,),
                provenance=(
                    ("plan_id", plan_id),
                    ("case_id", case_id),
                    ("observation_ref", step_id),
                    ("builder", BUILDER_VERSION),
                ),
            )
        )
    return BuildOutcome(ok=True, artifacts=tuple(drafts), refusal_code=None)


__all__ = [
    "BUILDER_VERSION",
    "PURPOSE_TO_KIND",
    "REFUSAL_CODES",
    "BuildOutcome",
    "build_artifacts",
]
