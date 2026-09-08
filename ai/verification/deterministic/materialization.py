"""Finding materialization boundary (Phase 5I) — RETIRED SEAM (Phase 5K).

Phase 5K severance (P0-2 / P0-3):

- 5I outputs ``ClassificationResult`` ONLY. 5I never materializes
  findings.
- 5J (``ai.finding``) is the ONLY finding-materialization authority
  (CONFIRMED-only).
- The historical 5I ``materialize_finding`` helper is HARD-BLOCKED:
  calling it raises deterministically and can never produce a
  finding (including for POTENTIAL).
- The historical 5I seam shape has been renamed to
  ``DeprecatedSeamFinding`` with a distinct internal schema version
  (``5i-materialized-finding/v1``) so it can never be confused with
  the authoritative 5J ``SealedFinding`` (``sealed-finding/v1``).
  The old ``SealedFinding`` name no longer exists on this module;
  accessing it raises loudly (fail closed, no silent alias).

THIS MODULE IS NOT A PRODUCTION FINDING PATH. No production code
may import it for finding authority.
"""

from __future__ import annotations

from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict

from ai.verification.deterministic.result import ClassificationResult

__all__ = [
    "MATERIALIZATION_SCHEMA_VERSION",
    "DeprecatedSeamFinding",
    "MaterializationSeamDisabledError",
    "materialize_finding",
    "PRODUCTION_FINDING_PIPELINE_ACTIVE",
]

#: Distinct internal seam version. Deliberately NOT "sealed-finding/v1":
#: exactly one authoritative ``sealed-finding/v1`` exists (5J,
#: ``ai.finding.sealed.SealedFinding``).
MATERIALIZATION_SCHEMA_VERSION = "5i-materialized-finding/v1"

#: Explicit default-deny production flag. 5I ships the SEAM ONLY:
#: no production pipeline imports this module, no live path exists.
PRODUCTION_FINDING_PIPELINE_ACTIVE = False


class DeprecatedSeamFinding(BaseModel):
    """Retired 5I seam shape (NOT an authoritative finding).

    Historical, seam-only record of what the pre-5K helper used to
    emit. It is NOT a security finding, MUST NOT be persisted as
    one, and MUST NOT be consumed by 5J or any production path.
    Kept under an explicit seam-only name + seam-only schema
    version so cross-validation against the authoritative 5J
    ``SealedFinding`` fails loudly in both directions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_schema_version: Literal["5i-materialized-finding/v1"] = (
        MATERIALIZATION_SCHEMA_VERSION
    )
    finding_id: str
    classification_hash: str
    evidence_id: str
    execution_id: str
    authorization_id: str
    program_name: str
    target_host: str
    target_scheme: str
    target_effective_port: int
    target_path_scope: str
    artifact_id: str
    artifact_content_hash: str
    test_plan_id: str
    hypothesis_id: str | None = None
    match_id: str | None = None
    evidence_bindings_hash: str
    evidence_observations_hash: str
    evidence_content_hash: str
    verifier_version: str
    rule_id: str
    observation_schema_version: str
    artifact_schema_version: str
    policy_version: str
    outcome: str
    confirmation_state: str | None = None
    oracle_channels: tuple[str, ...] = ()
    severity: str
    reason_code: str


class MaterializationSeamDisabledError(RuntimeError):
    """Deterministic error raised by the retired 5I seam."""


def materialize_finding(
    classification: ClassificationResult,
    seam: object = None,
) -> NoReturn:
    """Retired 5I finding seam — HARD-BLOCKED (Phase 5K).

    Always raises :class:`MaterializationSeamDisabledError`.
    5I is classification-only; findings materialize exclusively
    through 5J (``ai.finding.materialize``, CONFIRMED-only).

    The signature is kept compatible so any stale caller fails
    closed with this deterministic error (never a finding, never
    ``None``-as-control-flow that a caller could misread).
    """
    raise MaterializationSeamDisabledError(
        "5I materialize_finding seam is disabled (Phase 5K): "
        "5I outputs ClassificationResult only; "
        "5J owns finding materialization."
    )


def __getattr__(name: str):  # PEP 562 — fail closed on the old name.
    if name == "SealedFinding":
        raise AttributeError(
            "ai.verification.deterministic.materialization.SealedFinding "
            "was retired in Phase 5K (P0-3). The 5I seam shape is now "
            "DeprecatedSeamFinding ('5i-materialized-finding/v1', "
            "non-authoritative). The authoritative finding is "
            "ai.finding.sealed.SealedFinding ('sealed-finding/v1')."
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
