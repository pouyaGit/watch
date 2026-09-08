"""Deterministic TestPlan → Artifact Readiness Report (Phase 4F).

Read-only orchestration layer answering one question::

    Given a TestPlan, what artifacts are available for it, are
    their bindings correct, and do they pass structural,
    integrity, and provenance checks?

    TestPlan
        |
        v
    Artifact Retrieval (Phase 4E read API)
        |
        +--> available artifacts
        +--> binding validation
        +--> provenance audit (reused, never duplicated)
        +--> integrity state (reused, never duplicated)
        |
        v
    TestPlanReadinessReport (INFORMATIONAL ONLY)

STRICTLY READ-ONLY. This module never generates, mutates,
deletes, replaces, executes, or reclassifies artifacts. It
never calls an LLM, never touches the network, never spawns
subprocesses, never invokes verifiers or executors, never
creates findings, never assigns verdicts, and never decides
scope. Artifact bytes remain inert.

- Required artifact types derive ONLY from the closed
  TestPlan category/execution vocabulary and the existing
  TestPlan Builder triple semantics. Prose (objective,
  descriptions, evidence text) is never consulted. Unknown
  category/execution combinations yield INCONCLUSIVE, never a
  guess.
- READY means only: required stored artifacts exist and pass
  the defined structural/integrity/provenance checks. It is
  NOT vulnerability confirmation, NOT scope authorization, and
  NOT execution permission. The report carries no
  execution/scope/authorization fields, under any name.
- Corruption is surfaced explicitly via the reused Phase 4E/4D
  checks and always prevents READY. Nothing is repaired,
  removed, or reconstructed.
- All outputs are deterministically ordered (artifact_id and
  sorted type/failure lists). Repeated invocation against
  unchanged storage yields equal reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ai.knowledge.artifact_store import (
    ArtifactStore,
    ArtifactStoreError,
    StoredArtifact,
)
from ai.researcher.artifact_retrieval import (
    audit_provenance,
    get_by_test_plan_id,
    verify_all,
)
from ai.schemas.test_plan import TestPlan

ReadinessOutcome = Literal["READY", "NOT_READY", "INCONCLUSIVE"]

# ------------------------------------------------------------------
# Deterministic requirement mapping.
#
# Derived ONLY from the closed TestPlan category/execution
# vocabulary and the triples the existing TestPlan Builder can
# emit (see _derive_triple in ai/researcher/test_plan_builder.py):
#
#   nuclei_cve / nuclei_scan      -> nuclei_template
#   xss_*    / http+browser verif -> xss_payload
#   http_probe / http_signature   -> http_request_spec
#
# Prose is never consulted. Unknown values are unsupported, never
# guessed.
# ------------------------------------------------------------------

_REQUIRED_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "nuclei_cve": ("nuclei_template",),
    "nuclei_generic": ("nuclei_template",),
    "xss_reflected": ("xss_payload",),
    "xss_stored": ("xss_payload",),
    "xss_dom": ("xss_payload",),
    "xss_generic": ("xss_payload",),
    "http_probe": ("http_request_spec",),
    "http_signature": ("http_request_spec",),
}

_REQUIRED_BY_EXECUTION: dict[str, tuple[str, ...]] = {
    "nuclei_scan": ("nuclei_template",),
    "http_verification": ("xss_payload",),
    "browser_verification": ("xss_payload",),
    "http_probe": ("http_request_spec",),
}


class TestPlanReadinessError(ValueError):
    """Base error for deterministic readiness misuse/failure."""


@dataclass(frozen=True)
class ArtifactReadinessEntry:
    """Per-artifact readiness state (descriptive only)."""

    artifact_id: str
    artifact_type: str
    content_hash: str
    binding_ok: bool
    provenance_outcome: str
    failures: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class TestPlanReadinessReport:
    """Informational readiness verdict for one TestPlan.

    ``outcome`` answers only whether the required stored
    artifact set is structurally ready. It carries no
    execution, scope, verdict, or finding semantics.
    """

    test_plan_id: str
    outcome: ReadinessOutcome
    artifact_count: int
    artifacts: tuple[ArtifactReadinessEntry, ...] = field(
        default_factory=tuple
    )
    required_artifact_types: tuple[str, ...] = field(default_factory=tuple)
    available_artifact_types: tuple[str, ...] = field(default_factory=tuple)
    missing_artifact_types: tuple[str, ...] = field(default_factory=tuple)
    binding_failures: tuple[str, ...] = field(default_factory=tuple)
    integrity_failures: tuple[str, ...] = field(default_factory=tuple)
    provenance_failures: tuple[str, ...] = field(default_factory=tuple)


def required_artifact_types_for(
    test_category: object, execution_type: object
) -> tuple[str, ...]:
    """Closed deterministic requirement mapping (no prose, no LLM).

    Returns the sorted union of the category-derived and
    execution-derived requirements. Returns ``()`` when neither
    field maps — the caller treats that as unsupported
    (INCONCLUSIVE), never as "nothing required".
    """

    required: set[str] = set()
    if isinstance(test_category, str):
        required.update(_REQUIRED_BY_CATEGORY.get(test_category, ()))
    if isinstance(execution_type, str):
        required.update(_REQUIRED_BY_EXECUTION.get(execution_type, ()))
    return tuple(sorted(required))


def _check_inputs(store: object, test_plan: object) -> None:
    if not isinstance(store, ArtifactStore):
        raise TypeError(
            "readiness operates only on ArtifactStore, not "
            f"{type(store).__name__}; raw paths or dicts are never "
            "accepted"
        )
    if not isinstance(test_plan, TestPlan):
        raise TypeError(
            "readiness accepts only TestPlan, not "
            f"{type(test_plan).__name__}; raw dicts, JSON, paths, "
            "and filenames are never coerced"
        )


def _binding_failures_for(
    stored: StoredArtifact, test_plan: TestPlan
) -> tuple[str, ...]:
    """Exact binding comparison; absent plan bindings never fabricated."""

    reference = stored.reference
    failures: list[str] = []
    if reference.test_plan_id != test_plan.test_plan_id:
        failures.append(
            f"test_plan binding mismatch for {reference.artifact_id}: "
            f"artifact binds {reference.test_plan_id!r}"
        )
    if reference.hypothesis_id != test_plan.hypothesis_id:
        failures.append(
            f"hypothesis binding mismatch for {reference.artifact_id}"
        )
    # Optional bindings: compare only where the plan carries them.
    if test_plan.match_id is not None:
        if reference.match_id != test_plan.match_id:
            failures.append(
                f"match binding mismatch for {reference.artifact_id}"
            )
    if test_plan.snapshot_hash is not None:
        if reference.snapshot_hash != test_plan.snapshot_hash:
            failures.append(
                f"snapshot binding mismatch for {reference.artifact_id}"
            )
    return tuple(failures)


def build_readiness_report(
    store: object, test_plan: object
) -> TestPlanReadinessReport:
    """Build the deterministic readiness report for one TestPlan.

    Pure read path: retrieval via the Phase 4E read API,
    provenance via the reused ``audit_provenance``, integrity
    via the reused store/sweep checks. Corruption surfaces as
    explicit failures and always prevents READY.
    """

    _check_inputs(store, test_plan)
    assert isinstance(store, ArtifactStore)
    assert isinstance(test_plan, TestPlan)

    required = required_artifact_types_for(
        test_plan.test_category, test_plan.execution_type
    )
    binding_failures: list[str] = []
    integrity_failures: list[str] = []
    provenance_failures: list[str] = []
    entries: list[ArtifactReadinessEntry] = []
    unsupported = not required

    try:
        retrieved = get_by_test_plan_id(store, test_plan.test_plan_id)
    except ArtifactStoreError as exc:
        # Enumeration itself is blocked by corruption: surface it
        # explicitly (including what the sweep attributes) instead
        # of guessing. Required presence cannot be established.
        integrity_failures.append(f"artifact retrieval failed: {exc}")
        try:
            sweep = verify_all(store)
            for failure in sweep.failures:
                integrity_failures.append(
                    f"sweep {failure.kind} {failure.subject}: "
                    f"{failure.detail}"
                )
        except ArtifactStoreError as sweep_exc:
            integrity_failures.append(f"integrity sweep failed: {sweep_exc}")
        retrieved = ()

    for stored in retrieved:
        reference = stored.reference
        binding_only = list(_binding_failures_for(stored, test_plan))
        failures: list[str] = list(binding_only)
        if reference.artifact_type not in required:
            failures.append(
                f"artifact type mismatch for {reference.artifact_id}: "
                f"{reference.artifact_type!r} is not required for "
                f"{test_plan.test_category!r}/"
                f"{test_plan.execution_type!r}"
            )
        audit = audit_provenance(stored)
        if audit.outcome == "FAIL":
            for check in audit.checks:
                if check.outcome == "FAIL":
                    failures.append(
                        f"provenance {check.name} failed for "
                        f"{reference.artifact_id}: {check.detail}"
                    )
        entries.append(
            ArtifactReadinessEntry(
                artifact_id=reference.artifact_id,
                artifact_type=reference.artifact_type,
                content_hash=reference.content_hash,
                binding_ok=not binding_only,
                provenance_outcome=audit.outcome,
                failures=tuple(failures),
            )
        )

    entries.sort(key=lambda item: item.artifact_id)
    for entry in entries:
        binding_failures.extend(
            item
            for item in entry.failures
            if "binding mismatch" in item or "type mismatch" in item
        )
        provenance_failures.extend(
            item for item in entry.failures if item.startswith("provenance ")
        )

    available = sorted(
        {
            entry.artifact_type
            for entry in entries
            if entry.artifact_type in required and entry.binding_ok
            and entry.provenance_outcome != "FAIL"
        }
    )
    missing = tuple(sorted(set(required) - set(available)))

    if unsupported:
        outcome: ReadinessOutcome = "INCONCLUSIVE"
        integrity_failures.append(
            f"unsupported execution semantics for "
            f"{test_plan.test_category!r}/"
            f"{test_plan.execution_type!r}: requirement indeterminate"
        )
    elif integrity_failures or binding_failures or missing or provenance_failures:
        outcome = "NOT_READY"
    elif any(
        entry.provenance_outcome == "INCONCLUSIVE" for entry in entries
    ):
        outcome = "INCONCLUSIVE"
    else:
        outcome = "READY"

    return TestPlanReadinessReport(
        test_plan_id=test_plan.test_plan_id,
        outcome=outcome,
        artifact_count=len(entries),
        artifacts=tuple(entries),
        required_artifact_types=required,
        available_artifact_types=tuple(available),
        missing_artifact_types=missing,
        binding_failures=tuple(sorted(binding_failures)),
        integrity_failures=tuple(sorted(integrity_failures)),
        provenance_failures=tuple(sorted(provenance_failures)),
    )


__all__ = [
    "ReadinessOutcome",
    "ArtifactReadinessEntry",
    "TestPlanReadinessError",
    "TestPlanReadinessReport",
    "build_readiness_report",
    "required_artifact_types_for",
]
