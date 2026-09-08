"""Phase 5I — Deterministic Verifier (offline, evidence-only).

Verdict-free sealed evidence (5H) in; deterministic classification
out. The verifier is the ONLY security classification authority for
CONFIRMED / POTENTIAL / UNKNOWN, severity, and finding eligibility.

Structural security properties (all test-enforced):

- Input is ONLY a typed ``VerifierInput`` (handoff + envelope bytes +
  pinned versions). Caller verdict/finding/severity/confidence/LLM
  fields cannot enter the classifier (``extra="forbid"``).
- Every observation is re-derived from sealed bytes; advisory
  booleans, executor status, Nuclei text, and LLM hints are never
  authority.
- The integrity/provenance gate runs in the frozen architecture
  order; FIRST FAILURE WINS; gate failure is a blocked/rejected
  state, never a negative security result.
- ``NOT_VULNERABLE`` is UNREACHABLE: no two-control negative-evidence
  schema exists; targeting it raises (implementation invariant).
- No network, DNS, browser, subprocess, Nuclei, LLM, MongoDB, or live
  execution of any kind. This package never calls a live execution
  path and never imports legacy execute-and-judge code.

This package is PURE and DETERMINISTIC: same sealed envelope bytes +
same pinned versions => byte-identical classification result.
"""

from __future__ import annotations

from ai.verification.deterministic.models import (
    ARTIFACT_SCHEMA_VERSION,
    FORBIDDEN_AUTHORITY_FIELDS,
    IncompleteEvidence,
    OBSERVATION_SCHEMA_VERSION,
    POLICY_VERSION,
    RULES_VERSION,
    RejectReason,
    VERIFIER_VERSION,
    VerifierAuditEvent,
    VerifierInput,
    VerifierInvariantError,
)
from ai.verification.deterministic.result import (
    CONFIRMED,
    FINDING_ELIGIBLE_OUTCOMES,
    NOT_VULNERABLE,
    OUTCOME_CONFIRMED,
    OUTCOME_NOT_VULNERABLE,
    OUTCOME_POTENTIAL,
    OUTCOME_UNKNOWN,
    POTENTIAL,
    UNKNOWN,
    ClassificationResult,
    compute_result_hash,
    deterministic_finding_id,
)
from ai.verification.deterministic.gate import (
    VERIFIED,
    GateOutcome,
    verify_handoff_evidence,
)
from ai.verification.deterministic.verified_read import (
    IndexClaims,
    StoreVerifiedRead,
    VerifiedEvidence,
    VerifiedRead,
    read_verified_input,
)
from ai.verification.deterministic.registry import (
    SUPPORTED_RULES,
    resolve_rule,
)
from ai.verification.deterministic.severity import resolve_severity
from ai.verification.deterministic.classifier import classify_evidence
from ai.verification.deterministic.materialization import (
    PRODUCTION_FINDING_PIPELINE_ACTIVE,
    DeprecatedSeamFinding,
    MaterializationSeamDisabledError,
    materialize_finding,
)
from ai.verification.deterministic.pipeline import (
    VerificationOutcome,
    verify_handoff,
)

__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "CONFIRMED",
    "DeprecatedSeamFinding",
    "FORBIDDEN_AUTHORITY_FIELDS",
    "FINDING_ELIGIBLE_OUTCOMES",
    "GateOutcome",
    "IncompleteEvidence",
    "IndexClaims",
    "NOT_VULNERABLE",
    "OBSERVATION_SCHEMA_VERSION",
    "OUTCOME_CONFIRMED",
    "OUTCOME_NOT_VULNERABLE",
    "OUTCOME_POTENTIAL",
    "OUTCOME_UNKNOWN",
    "POLICY_VERSION",
    "POTENTIAL",
    "PRODUCTION_FINDING_PIPELINE_ACTIVE",
    "RejectReason",
    "RULES_VERSION",
    "SUPPORTED_RULES",
    "UNKNOWN",
    "VERIFIED",
    "VERIFIER_VERSION",
    "ClassificationResult",
    "MaterializationSeamDisabledError",
    "StoreVerifiedRead",
    "VerificationOutcome",
    "VerifiedEvidence",
    "VerifiedRead",
    "VerifierAuditEvent",
    "VerifierInput",
    "VerifierInvariantError",
    "classify_evidence",
    "compute_result_hash",
    "deterministic_finding_id",
    "materialize_finding",
    "read_verified_input",
    "resolve_rule",
    "resolve_severity",
    "verify_handoff",
    "verify_handoff_evidence",
]


def __getattr__(name: str):  # PEP 562 — fail closed on the retired name.
    if name == "SealedFinding":
        raise AttributeError(
            "ai.verification.deterministic.SealedFinding was retired "
            "in Phase 5K (P0-3). The 5I seam shape is now "
            "DeprecatedSeamFinding ('5i-materialized-finding/v1', "
            "non-authoritative). The authoritative finding is "
            "ai.finding.sealed.SealedFinding ('sealed-finding/v1')."
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
