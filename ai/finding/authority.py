"""5I authority/provenance gate for 5J (Phase 5J, offline, deterministic).

A correctly hashed ``ClassificationResult`` alone is NOT proof it came
from the 5I deterministic verifier: the result type is a plain frozen
data model, so a caller can hand-build a self-consistent instance.
This gate hardens the boundary WITHOUT network signatures or external
services by demanding the full conjunction:

1. Real ``ClassificationResult`` TYPE (``extra="forbid"`` frozen model;
   dicts, duck-types, and legacy finding shapes are rejected).
2. Canonical result hash reproduction (``compute_result_hash``).
3. Pinned 5I version tuple (verifier / policy / observation-schema /
   artifact-schema) — any skew is a downgrade attempt.
4. Registry compatibility: ``rule_id`` parses as ``base/vN`` and
   resolves in the frozen 5I ``SUPPORTED_RULES`` with matching rule
   version, and the rule is finding-eligible on CONFIRMED.
5. Structural validity: closed outcome/detail/state/channel vocabularies,
   ID formats, 64-hex hashes, bounded single-line reason.
6. Against a FRESH sealed record: full binding-axis equality, triple
   integrity, rule coverage of the record's execution class, and
   severity-triple equality with a locally recomputed 5I policy
   resolution (caller severity can never survive this).

A hand-built forgery can clear (1)–(5) only by copying genuine values;
it then dies at (6) because the attacker cannot fabricate sealed 5H
evidence whose triple matches (SHA-256 preimage) — and with trusted
production infrastructure the evidence reader serves only genuinely
sealed rows. A malicious/faulty seam can only force fail-closed
(NO FINDING): every returned byte is re-verified, never trusted.

This gate NEVER classifies: it performs equality/registry/policy
lookups only. No observation inspection, no verdict logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.evidence.builder import verify_record
from ai.schemas import evidence as ev
from ai.verification.deterministic.models import (
    ARTIFACT_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    POLICY_VERSION,
    VERIFIER_VERSION,
)
from ai.verification.deterministic.registry import (
    SUPPORTED_RULES,
    resolve_rule,
)
from ai.verification.deterministic.result import (
    RESULT_SCHEMA_VERSION,
    ClassificationResult,
    compute_result_hash,
)
from ai.verification.deterministic.severity import resolve_severity

__all__ = [
    "AUTHORITY_OK",
    "AuthorityDecision",
    "verify_authority_structure",
    "verify_authority_binding",
    "vulnerability_class_for",
]

AUTHORITY_OK = "AUTHORITY_OK"

_EVIDENCE_ID_RE = ev._EVIDENCE_ID_RE
_EXECUTION_ID_RE = ev._EXECUTION_ID_RE
_AUTHZ_ID_RE = ev._AUTHZ_ID_RE
_ART_ID_RE = ev._ART_ID_RE
_TP_ID_RE = ev._TP_ID_RE
_SHA256_RE = ev._SHA256_RE

_ALLOWED_OUTCOMES = frozenset(
    {"CONFIRMED", "POTENTIAL", "UNKNOWN", "NOT_VULNERABLE"}
)
_ALLOWED_DETAILS = frozenset(
    {
        "oracle_execution_proof",
        "stored_round_execution_proof",
        "meaningful_http_reflection",
        "sink_reached_advisory",
        "storage_attributed",
        "nuclei_advisory_weak",
        "insufficient_evidence",
        "gate_blocked",
        "negative_schema_absent",
    }
)
_ALLOWED_STATES = frozenset(
    {
        "REFLECTION",
        "SINK_REACHED",
        "JAVASCRIPT_EXECUTION",
        "OBSERVABLE_EFFECT",
        "STORAGE_ATTRIBUTED",
    }
)
_ALLOWED_CHANNELS = frozenset({"E1", "E2", "E3"})
_ALLOWED_SEVERITIES = frozenset(
    {"UNSET", "critical", "high", "medium", "low", "info"}
)


@dataclass(frozen=True)
class AuthorityDecision:
    """Deterministic authority outcome (never a verdict)."""

    authorized: bool
    reason: str


def _parse_rule_display(rule_id: object) -> tuple[str, int] | None:
    """Split ``base/vN`` display ids (None when malformed)."""
    if not isinstance(rule_id, str) or "/v" not in rule_id:
        return None
    base, _, version = rule_id.rpartition("/v")
    if not base or not version.isdigit():
        return None
    return base, int(version)


def vulnerability_class_for(record: ev.EvidenceRecord) -> str:
    """Sealed-bound class projection (consistency check ONLY).

    Exact mirror of the frozen 5I classifier projection. Used solely
    to recompute the expected 5I severity triple for equality
    comparison — never to decide vulnerability. Any drift from the 5I
    mapping fails closed (severity mismatch), it can never mint a
    finding.
    """
    cls = record.execution_class
    if cls in ("http_probe", "http_verification"):
        return "reflected_xss"
    if cls == "nuclei_scan":
        return "nuclei_advisory"
    phase = (
        record.derivation_binding.execution_phase
        if record.derivation_binding is not None
        else None
    )
    if phase == "stored_read" or record.execution_stage == "read":
        return "stored_xss"
    return "reflected_xss"


def verify_authority_structure(
    classification: object,
) -> AuthorityDecision:
    """Structure/registry/provenance checks needing no evidence read."""
    if not isinstance(classification, ClassificationResult):
        return AuthorityDecision(
            False, "AUTHORITY_NOT_CLASSIFICATION_RESULT"
        )
    try:
        compute_result_hash(classification)
    except Exception:
        return AuthorityDecision(False, "AUTHORITY_HASH_MISMATCH")
    if classification.result_schema_version != RESULT_SCHEMA_VERSION:
        return AuthorityDecision(
            False, "AUTHORITY_VERSION_PIN_MISMATCH"
        )
    if (
        classification.verifier_version != VERIFIER_VERSION
        or classification.policy_version != POLICY_VERSION
        or classification.observation_schema_version
        != OBSERVATION_SCHEMA_VERSION
        or classification.artifact_schema_version
        != ARTIFACT_SCHEMA_VERSION
    ):
        return AuthorityDecision(
            False, "AUTHORITY_VERSION_PIN_MISMATCH"
        )
    parsed = _parse_rule_display(classification.rule_id)
    if parsed is None:
        return AuthorityDecision(False, "AUTHORITY_RULE_UNKNOWN")
    base, version = parsed
    spec = SUPPORTED_RULES.get(base)
    if (
        spec is None
        or spec.rule_version != version
        or spec.verifier_version != VERIFIER_VERSION
        or spec.policy_version != POLICY_VERSION
        or not spec.finding_eligible_on_confirmed
    ):
        return AuthorityDecision(False, "AUTHORITY_RULE_UNKNOWN")
    if classification.outcome not in _ALLOWED_OUTCOMES:
        return AuthorityDecision(False, "AUTHORITY_STRUCTURE_INVALID")
    if classification.outcome_detail not in _ALLOWED_DETAILS:
        return AuthorityDecision(False, "AUTHORITY_STRUCTURE_INVALID")
    if (
        classification.confirmation_state is not None
        and classification.confirmation_state not in _ALLOWED_STATES
    ):
        return AuthorityDecision(False, "AUTHORITY_STRUCTURE_INVALID")
    if any(c not in _ALLOWED_CHANNELS for c in classification.oracle_channels):
        return AuthorityDecision(False, "AUTHORITY_STRUCTURE_INVALID")
    if classification.severity not in _ALLOWED_SEVERITIES:
        return AuthorityDecision(False, "AUTHORITY_STRUCTURE_INVALID")
    reason = classification.reason_code
    if (
        not isinstance(reason, str)
        or not reason
        or len(reason) > 120
        or "\n" in reason
        or "\r" in reason
    ):
        return AuthorityDecision(False, "AUTHORITY_STRUCTURE_INVALID")
    id_checks = (
        ("evidence_id", _EVIDENCE_ID_RE, classification.evidence_id),
        ("execution_id", _EXECUTION_ID_RE, classification.execution_id),
        ("authorization_id", _AUTHZ_ID_RE, classification.authorization_id),
        ("artifact_id", _ART_ID_RE, classification.artifact_id),
        ("test_plan_id", _TP_ID_RE, classification.test_plan_id),
    )
    for _, pattern, value in id_checks:
        if not isinstance(value, str) or not pattern.match(value):
            return AuthorityDecision(
                False, "AUTHORITY_STRUCTURE_INVALID"
            )
    hash_checks = (
        classification.artifact_content_hash,
        classification.evidence_bindings_hash,
        classification.evidence_observations_hash,
        classification.evidence_content_hash,
    )
    for value in hash_checks:
        if not isinstance(value, str) or not _SHA256_RE.match(value):
            return AuthorityDecision(
                False, "AUTHORITY_STRUCTURE_INVALID"
            )
    return AuthorityDecision(True, AUTHORITY_OK)


def verify_authority_binding(
    classification: ClassificationResult,
    record: object,
) -> AuthorityDecision:
    """Bind a structure-authorized result to a FRESH sealed record.

    The caller must have performed a NEW verified read; this function
    re-verifies the returned bytes from scratch (triple recomputation,
    SEALED+complete) and demands full axis equality plus registry
    coverage plus severity-triple equality with a locally recomputed
    5I policy resolution. FIRST mismatch wins, fail closed.
    """
    if not isinstance(classification, ClassificationResult):
        return AuthorityDecision(
            False, "AUTHORITY_NOT_CLASSIFICATION_RESULT"
        )
    if not isinstance(record, ev.EvidenceRecord):
        return AuthorityDecision(False, "AUTHORITY_EVIDENCE_INVALID")
    try:
        verify_record(record)
    except Exception:
        return AuthorityDecision(
            False, "AUTHORITY_EVIDENCE_UNVERIFIABLE"
        )
    if record.lifecycle != "SEALED" or not record.complete:
        return AuthorityDecision(
            False, "AUTHORITY_EVIDENCE_UNVERIFIABLE"
        )
    target = record.target
    # Frozen-5H note: the seal triple covers ``target.program_name``
    # but NOT the top-level ``record.program_name`` handle. Both must
    # therefore be checked: internal consistency here, equality with
    # the classification below. A row whose two program names diverge
    # is refused even when its triple verifies.
    if record.program_name != target.program_name:
        return AuthorityDecision(False, "AUTHORITY_BINDING_MISMATCH")
    axes = (
        (classification.evidence_id, record.evidence_id),
        (classification.execution_id, record.execution_id),
        (classification.authorization_id, record.authorization_id),
        (classification.program_name, record.program_name),
        (classification.target_host, target.host),
        (classification.target_scheme, target.scheme),
        (classification.target_effective_port, target.effective_port),
        (classification.target_path_scope, target.path_scope),
        (classification.artifact_id, record.artifact_id),
        (
            classification.artifact_content_hash,
            record.artifact_content_hash,
        ),
        (classification.test_plan_id, record.test_plan_id),
        (classification.hypothesis_id, record.hypothesis_id),
        (classification.match_id, record.match_id),
        (
            classification.evidence_bindings_hash,
            record.bindings_hash,
        ),
        (
            classification.evidence_observations_hash,
            record.observations_hash,
        ),
        (
            classification.evidence_content_hash,
            record.content_hash,
        ),
        (
            classification.verifier_version,
            VERIFIER_VERSION,
        ),
        (
            classification.policy_version,
            POLICY_VERSION,
        ),
    )
    for claimed, sealed in axes:
        if claimed != sealed:
            return AuthorityDecision(False, "AUTHORITY_BINDING_MISMATCH")
    parsed = _parse_rule_display(classification.rule_id)
    if parsed is None:
        return AuthorityDecision(False, "AUTHORITY_RULE_UNKNOWN")
    base, _ = parsed
    spec = resolve_rule(
        base,
        execution_class=record.execution_class,
        observation_schema_version=(
            classification.observation_schema_version
        ),
        artifact_schema_version=(
            classification.artifact_schema_version
        ),
        policy_version=classification.policy_version,
    )
    if spec is None or not spec.finding_eligible_on_confirmed:
        return AuthorityDecision(False, "AUTHORITY_RULE_UNKNOWN")
    expected = resolve_severity(
        vulnerability_class=vulnerability_class_for(record),
        rule_id=base,
        outcome=classification.outcome,
        policy_version=classification.policy_version,
    )
    if (
        classification.severity != expected.severity
        or classification.severity_unset_reason != expected.unset_reason
    ):
        return AuthorityDecision(False, "AUTHORITY_SEVERITY_MISMATCH")
    snapshot = record.snapshot_binding
    if (
        snapshot is None
        or not isinstance(snapshot.scope_lists_hash, str)
        or not _SHA256_RE.match(snapshot.scope_lists_hash)
    ):
        return AuthorityDecision(False, "AUTHORITY_BINDING_MISMATCH")
    if base == "xss-stored-round" and record.execution_stage == "read":
        browser = record.browser
        if (
            browser is None
            or not browser.round_id
            or not browser.submit_evidence_ref
        ):
            return AuthorityDecision(
                False, "AUTHORITY_ROUND_LINKAGE_MISSING"
            )
    return AuthorityDecision(True, AUTHORITY_OK)
